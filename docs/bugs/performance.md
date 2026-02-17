# Performance Issues Found

## P1: Critical Hot Path Issues

### PERF-001: Glob patterns recompiled on every policy evaluation
**File:** `crates/clawdefender-core/src/policy/rule.rs:98-106`
**Impact:** O(n*m) glob compilation per evaluation where n=rules, m=patterns per rule
**Details:** `pattern_matches()` and `glob_matches()` call `GlobMatcher::new(pattern)` on every invocation, which compiles the glob pattern each time. For 50 rules with 2 patterns each, this is 100 glob compilations per evaluation.
**Fix:** Pre-compile glob patterns when rules are loaded (at parse time or engine load). Store `GlobMatcher` instances inside `MatchCriteria` instead of raw strings.
**Status:** DOCUMENTED - requires struct change

### PERF-002: Regex compiled on every sanitize_explanation call
**File:** `crates/clawdefender-slm/src/analyzer.rs:272-277`
**Impact:** Two regex compilations per SLM output parse
**Details:** `sanitize_explanation()` calls `Regex::new()` twice (for URLs and code blocks) on every invocation. These are static patterns that should be compiled once.
**Fix:** Use `std::sync::LazyLock` (or `once_cell::sync::Lazy`) to compile regexes once.
**Status:** FIXED

### PERF-003: Full JSON deserialization for pass-through messages
**File:** `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs:617-623`
**Impact:** Every message is fully deserialized then re-serialized even for Classification::Pass
**Details:** The proxy parses every JSON-RPC message into `JsonRpcMessage`, then for pass-through messages, re-serializes it with `serialize_message()`. For non-Review messages (handshakes, notifications, list requests), the original bytes could be forwarded directly.
**Fix:** The `RawJsonRpcMessage` type was added to the parser to support transparent forwarding. The relay loop should use `raw_bytes_with_newline()` for Pass/Log classifications instead of re-serializing.
**Status:** PARTIALLY FIXED (RawJsonRpcMessage exists but relay loop uses next_message)

### PERF-004: build_mcp_event clones raw_message unnecessarily
**File:** `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs:978`
**Impact:** Full serde_json::to_value clone of every reviewed message
**Details:** `build_mcp_event()` calls `serde_json::to_value(msg)` which serializes the entire message to a Value, creating a deep copy. This is used for audit records but is wasteful for the policy evaluation path.
**Fix:** Make `raw_message` in McpEvent lazy or optional. Policy evaluation only needs the EventContext (tool_name, resource_path, method), not the raw JSON.
**Status:** DOCUMENTED

## P2: Medium Priority Issues

### PERF-005: Policy evaluation is O(n) linear scan
**File:** `crates/clawdefender-core/src/policy/engine.rs:180-185`
**Impact:** Linear scan over all rules for every evaluation
**Details:** The evaluate loop chains session_rules and file_rules and iterates until a match is found. With 50 rules, worst case is 50 iterations. This is acceptable for the target (<100us with 50 rules) but could be improved with a trie or HashMap for exact-match tool names.
**Fix:** For the common case of exact tool name matches, build a HashMap<String, PolicyAction> index. Fall back to linear scan for glob/regex patterns.
**Status:** DOCUMENTED - not critical at current rule counts

### PERF-006: event_summary allocates a new String on every call
**File:** `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs:1032-1041`
**Impact:** Multiple String allocations per reviewed message (called 2-4 times per message)
**Details:** `event_summary()` is called multiple times per message: for debug logging, for audit records, for UI prompts, for SLM context tracking. Each call allocates a new String.
**Fix:** Compute event_summary once and reuse it, or use Cow<str>.
**Status:** DOCUMENTED

### PERF-007: Correlation engine pending Vec uses linear scan for PID matching
**File:** `crates/clawdefender-core/src/correlation/mod.rs:99-109`
**Impact:** O(p*k) per OS event where p=pending correlations, k=avg associated PIDs
**Details:** `submit_os_event()` iterates all pending correlations and checks each correlation's `associated_pids` Vec with `contains()`. With many concurrent MCP events and rapid OS events, this could become a bottleneck.
**Fix:** Use a HashMap<u32, Vec<usize>> mapping PIDs to pending correlation indices for O(1) PID lookup.
**Status:** DOCUMENTED - acceptable at expected scale

### PERF-008: Correlation engine pending Vec is unbounded
**File:** `crates/clawdefender-core/src/correlation/mod.rs:43-45`
**Impact:** Memory growth if tick() is not called frequently enough
**Details:** The `pending` Vec grows without bound. If the daemon stops calling `tick()` (e.g., during heavy load), pending correlations accumulate. There is no maximum pending limit.
**Fix:** Add a max_pending constant (e.g., 10000). When exceeded, force-complete the oldest correlations.
**Status:** DOCUMENTED

## P3: Low Priority / Informational

### PERF-009: Audit logger uses std::sync::mpsc (blocking)
**File:** `crates/clawdefender-core/src/audit/logger.rs:162`
**Impact:** Minimal - unbounded channel means send never blocks
**Details:** The FileAuditLogger uses `std::sync::mpsc::channel` (unbounded) for async writes to a dedicated writer thread. This is fine for audit logging since the writer thread drains faster than records arrive, and the unbounded channel prevents blocking the proxy. However, under extreme load, memory usage could grow.
**Fix:** Consider adding a bounded channel with try_send and drop-on-full semantics. Current design is acceptable since audit writes are fast (just JSON serialization + buffered write).
**Status:** ACCEPTABLE

### PERF-010: SLM context_size defaults to 2048 tokens
**File:** `crates/clawdefender-slm/src/engine.rs:47`
**Impact:** Higher memory usage and potentially slower inference for short prompts
**Details:** The default context window is 2048 tokens. For typical MCP event analysis prompts (which are 100-300 tokens), this over-allocates KV cache memory. Reducing to 1024 would halve KV cache memory with no impact on output quality for the expected prompt sizes.
**Fix:** Reduce default to 1024. Users can override via config if needed.
**Status:** FIXED

### PERF-011: eslogger event_path clones Strings for debounce keys
**File:** `crates/clawdefender-sensor/src/eslogger/filter.rs:160-173`
**Impact:** String allocation per event for debounce keying
**Details:** `event_path()` clones the path string from the event for use as a HashMap key. This is unavoidable for the HashMap-based debounce approach but is a per-event allocation.
**Fix:** Could use a hash of (pid, path) as the key instead, but the current approach is simple and the cleanup every 10000 events prevents unbounded growth.
**Status:** ACCEPTABLE

### PERF-012: Proxy audit records constructed with many None fields
**File:** `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs:1044-1072`
**Impact:** Negligible - struct initialization cost
**Details:** `build_audit_record()` constructs AuditRecord with 18+ fields, most set to None. This is a pattern issue, not a performance issue. Consider using a builder or Default impl.
**Status:** ACCEPTABLE (cosmetic)
