# ClawDefender Performance Guide

## Performance Targets

| Component | Metric | Target | Notes |
|-----------|--------|--------|-------|
| Proxy message relay | P95 overhead per pass-through | < 1ms | Measured from stdin read to child stdin write |
| Policy evaluation | Per-evaluation latency with 50 rules | < 100us | First-match-wins linear scan |
| Audit logging | Added latency to proxy path | 0ms (async) | Channel-based, never blocks proxy |
| SLM inference | P95 on Apple Silicon | < 200ms | Metal acceleration, 1024 token context |
| Sensor (eslogger) | CPU during cargo build | < 5% | Pre-filter drops 90-95% of events |
| Memory | RSS stability over 4 hours | No growth | All buffers bounded |

## Architecture Overview

### Proxy Hot Path

The proxy message relay is the most latency-sensitive path:

```
Client stdin -> StreamParser -> classify() -> [policy evaluate] -> serialize -> Child stdin
```

**Classification** (`classify()` in `classifier/rules.rs`):
- O(1) string match on the JSON-RPC method field
- No allocations for Pass/Log classifications
- Only `tools/call`, `resources/read`, and `sampling/createMessage` go to policy Review

**Policy Evaluation** (`engine.rs:evaluate()`):
- Linear scan: session_rules first, then file_rules
- First match wins, so common allow rules should be early
- Context extraction is O(1) field access from the parsed event
- Glob patterns are currently compiled per-match (see PERF-001 in bugs/performance.md)

**Serialization** (`serialize_message()`):
- Uses `serde_json::to_vec` which allocates a `Vec<u8>`
- The `RawJsonRpcMessage` type supports transparent byte forwarding as a future optimization

### Audit Logging (Zero Proxy Latency)

The audit logger uses a dedicated writer thread with an unbounded `std::sync::mpsc` channel:

```
Proxy thread -> mpsc::Sender<WriterCommand> -> Writer thread -> BufWriter<File>
```

- `try_send()` is used in the proxy path, never blocking
- If the channel is full, audit records are silently dropped (acceptable)
- Writer thread flushes every 100 records or every 1 second
- Log rotation happens on the writer thread, never blocking the proxy
- File I/O is buffered via `BufWriter`

### SLM Inference

- Inference is async and **never blocks** the proxy decision path
- SLM output is advisory only; policy decisions are made independently
- Concurrency: Semaphore(1) ensures only one inference runs at a time
- Bounded queue: MAX_QUEUED=10, excess requests return low-risk default
- Default context window reduced to 1024 tokens (sufficient for typical MCP event prompts)
- Metal GPU acceleration enabled by default on macOS

### Sensor Pre-Filter

The eslogger pre-filter (`EventPreFilter`) drops 90-95% of events before they enter the pipeline:

1. **PID filter**: Drops PID 0 (kernel) and PID 1 (launchd) - O(1)
2. **Process name filter**: HashSet lookup on executable basename - O(1)
3. **Team ID filter**: Drops com.apple.* signed processes - O(1) prefix check
4. **Path prefix filter**: Linear scan of ~3 prefixes with allowlist HashSet - O(k)
5. **Open flags filter**: Drops read-only opens (flags == 0) - O(1)
6. **Debounce**: HashMap-based, cleans up every 10,000 events - O(1) amortized

Channel capacity: 10,000 events. Uses `try_send()` with drop-on-full semantics.

### Correlation Engine

- Pending correlations are bounded at 10,000 entries
- Time-windowed: correlations complete when their window expires via `tick()`
- PID matching is O(p*k) where p=pending, k=avg associated PIDs (typically 1)
- OS events matched by direct PID or child PPID

## Memory Management

### Bounded Buffers

| Buffer | Location | Bound | Overflow Behavior |
|--------|----------|-------|-------------------|
| StreamParser buf | `parser.rs` | 20 MB | Cleared with error log |
| JSON-RPC message | `parser.rs` | 10 MB | Rejected |
| JSON nesting depth | `parser.rs` | 128 levels | Rejected |
| Proxy child_tx channel | `stdio.rs` | 512 messages | Backpressure via await |
| Proxy client_tx channel | `stdio.rs` | 512 messages | Backpressure via await |
| Audit channel (proxy) | `stdio.rs` | 1024 records | try_send drops on full |
| Eslogger event channel | `process.rs` | 10,000 events | try_send drops on full |
| SLM inference queue | `engine.rs` | 10 queued | Returns low-risk default |
| Correlation pending | `correlation/mod.rs` | 10,000 entries | Oldest force-completed |
| Debounce map | `filter.rs` | Cleanup every 10k events | Entries > 5s removed |

### Memory Leak Prevention

- All channels are bounded or have drop-on-full semantics
- Correlation engine evicts oldest entries when at capacity
- Debounce map has periodic cleanup (every 10,000 events, entries > 5s old)
- StreamParser buffer has a hard 20 MB limit with auto-clear
- Session rules are prepended to the rule list (no accumulation issue as they're few)

## Benchmark Methodology

### Proxy Throughput Benchmark

Measures the overhead of the proxy message relay path (classify + policy evaluate + serialize):

```rust
// In crates/clawdefender-mcp-proxy/src/proxy/stdio.rs tests
#[tokio::test]
async fn bench_proxy_throughput() {
    let proxy = StdioProxy::with_engine("echo".into(), vec![], DefaultPolicyEngine::empty());
    let start = std::time::Instant::now();
    let iterations = 10_000;
    for i in 0..iterations {
        let msg = make_tools_call_request(&format!("tool_{}", i % 100));
        let mut child_buf: Vec<u8> = Vec::new();
        let mut client_buf: Vec<u8> = Vec::new();
        proxy.handle_client_message(msg, &mut child_buf, &mut client_buf).await.unwrap();
    }
    let elapsed = start.elapsed();
    let per_msg = elapsed / iterations;
    // Target: < 1ms per message
    assert!(per_msg < Duration::from_millis(1));
}
```

### Policy Evaluation Benchmark

Measures policy evaluation with 50 rules:

```rust
// In crates/clawdefender-core/src/policy/engine.rs tests
#[test]
fn bench_policy_evaluation_50_rules() {
    // Build a policy with 50 rules
    let mut toml = String::new();
    for i in 0..49 {
        toml.push_str(&format!(
            "[rules.rule_{i}]\ndescription = \"Rule {i}\"\naction = \"allow\"\n\
             message = \"ok\"\npriority = {i}\n\n[rules.rule_{i}.match]\n\
             tool_name = [\"tool_{i}*\"]\n\n"
        ));
    }
    toml.push_str("[rules.catch_all]\ndescription = \"Catch all\"\naction = \"log\"\n\
                   message = \"logged\"\npriority = 100\n\n[rules.catch_all.match]\nany = true\n");

    let rules = parse_policy_toml(&toml).unwrap();
    assert_eq!(rules.len(), 50);

    let engine = DefaultPolicyEngine { policy_path: PathBuf::new(), session_rules: vec![], file_rules: rules };
    let event = make_tool_call_event("unknown_tool"); // worst case: falls through all rules

    let start = std::time::Instant::now();
    let iterations = 10_000;
    for _ in 0..iterations {
        let _ = engine.evaluate(&event);
    }
    let elapsed = start.elapsed();
    let per_eval = elapsed / iterations;
    // Target: < 100us per evaluation with 50 rules
    assert!(per_eval < Duration::from_micros(100));
}
```

## Optimization History

### Applied Optimizations

1. **PERF-002**: Regex patterns in `sanitize_explanation()` now use `std::sync::LazyLock` for one-time compilation
2. **PERF-008**: Correlation engine pending Vec now bounded at 10,000 entries with automatic eviction
3. **PERF-010**: SLM default context_size reduced from 2048 to 1024 tokens

### Planned Optimizations

1. **PERF-001**: Pre-compile glob patterns at rule load time (requires MatchCriteria struct change)
2. **PERF-003**: Use RawJsonRpcMessage transparent forwarding for Pass/Log classified messages
3. **PERF-004**: Lazy raw_message construction in McpEvent
4. **PERF-005**: HashMap index for exact tool name matches in policy evaluation
5. **PERF-006**: Cache event_summary String computation per message
