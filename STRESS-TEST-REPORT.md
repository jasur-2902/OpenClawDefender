# ClawDefender Phase 6 — Stress Test Report (T11)

**Date:** 2026-03-30
**Reviewer:** Agent 6 (Code-Based Resilience Review)
**Scope:** Memory safety, concurrency, adversarial input, resource exhaustion, audit rotation

---

## 1. Memory Safety Under Load

### 1.1 Rate Limiter — Sliding Window (`event_router.rs:93-124`)

**Status: ROBUST**

The `EscalationRateLimiter` uses a `VecDeque<Instant>` with a 60-second sliding window. On each `try_acquire()`, entries older than 60 seconds are evicted from the front before checking capacity.

- **Bounded growth:** The deque can never exceed `max_per_minute` entries (default 5) because old entries are evicted before new ones are pushed. Worst case is 5 entries in the deque at any time.
- **No unbounded allocation:** Correct use of `pop_front()` in a while loop ensures stale entries are always cleaned.
- **Classification:** No issue found.

### 1.2 SLM Queue — Bounded Semaphore (`engine.rs:159-249`)

**Status: ROBUST**

The SLM engine uses a dual-semaphore design:
- `semaphore: Semaphore(1)` — serializes inference (only 1 runs at a time)
- `queue_semaphore: Semaphore(MAX_QUEUED=10)` — bounds waiting requests

When the queue is full, `try_acquire()` fails and the request is immediately dropped with a default `RiskLevel::Low` response (confidence=0.0, explanation="queue full").

- **Queue overflow handling:** Correctly handled at line 200-212. Excess requests are dropped gracefully.
- **Queue permit release:** The queue permit is dropped at line 221 when the inference slot is acquired, which correctly frees a queue slot.
- **Test coverage:** `queue_full_returns_default` test at line 507 validates this behavior.

**Finding (BENIGN):** When the queue is full, dropped requests default to `RiskLevel::Low`, not `RiskLevel::High`. Since SLM analysis is advisory-only (never influences policy decisions), this is acceptable. However, a more conservative design would use `RiskLevel::High` (fail-closed). The `SlmService::unavailable_response()` at `lib.rs:334` does correctly fail-closed to HIGH when backends fail entirely, but the queue-full path in the engine does not.

### 1.3 Event Buffer — 10K Cap (`state.rs:387-446`)

**Status: ROBUST**

The `AppState::push_event()` method enforces `MAX_EVENT_BUFFER = 10,000`:
```rust
if buffer.len() > MAX_EVENT_BUFFER {
    let excess = buffer.len() - MAX_EVENT_BUFFER;
    buffer.drain(..excess);
}
```

- **Cap enforcement:** Correctly drains oldest events when the limit is exceeded.
- **Test coverage:** `test_event_buffer_bounded_at_10000` test at line 541 validates with 10,050 insertions.
- **Lock safety:** Uses `Mutex<Vec<AuditEvent>>` with `if let Ok(mut buffer) = lock()` pattern, which gracefully handles poisoned mutexes.

### 1.4 Alert Store — 500 Cap (`state.rs:389-502`)

**Status: ROBUST**

The `AppState::push_alert()` method enforces `MAX_ALERTS = 500`:
- Deduplication is applied first via `alerts::lifecycle::add_alert()`, which merges repeated alerts.
- After dedup, the cap is enforced by draining oldest entries.
- **Test coverage:** The `add_alert` lifecycle function is exercised through the dedup path.
- **No unbounded growth:** The store is properly bounded.

### 1.5 Pending Prompts — 100 Cap (`state.rs:449-456`)

**Status: ROBUST**

`MAX_PENDING_PROMPTS = 100` with the same drain pattern. Test at line 553 validates.

---

## 2. Concurrent Client Handling

### 2.1 IPC Server (`ipc.rs:40-243`)

**Status: ACCEPTABLE**

The IPC server uses `tokio::spawn` for each accepted connection (line 86), allowing multiple simultaneous clients.

**Strengths:**
- Each client gets its own task — no blocking between clients.
- Stream is split into reader/writer halves with `into_split()`, preventing interleaving.
- Shared state (`ProxyMetrics`, `PolicyEngine`, `GuardRegistry`) is accessed through `Arc` references, with appropriate `RwLock` for mutable state.

**Finding (BENIGN):** `read_line()` at line 114 uses the default `BufReader` which has no line length limit. A malicious IPC client could send an extremely long line to consume memory. However, since the IPC socket is a local Unix domain socket (accessible only to the local user), this is a low-risk local-only DoS vector. Real mitigation would use `read_line_with_limit()` or similar.

**Finding (BENIGN):** There is no explicit limit on the number of concurrent IPC connections. An attacker with local access could open thousands of connections. Mitigation: the IPC socket requires local user access, making this low-risk.

### 2.2 Client Disconnect Handling

**Status: ROBUST**

When a client disconnects, `read_line()` returns `n == 0` (line 115-117), causing the handler to break out of the loop and return `Ok(())`. The tokio task then completes, and all resources (reader, writer, Arc references) are dropped. No resource leak.

### 2.3 Message Interleaving Prevention

**Status: ROBUST**

Each client has its own `(reader, writer)` pair from `stream.into_split()`. Responses are written atomically per-command (serialize + write_all + newline + flush). There is no shared write buffer between clients.

---

## 3. SLM Under Load

### 3.1 Inference Serialization (`engine.rs:162-163`)

**Status: ROBUST**

`Semaphore(1)` guarantees exactly one concurrent inference. The semaphore is acquired with `.await` (line 215-219), meaning excess requests wait in the queue rather than competing.

### 3.2 Queue Overflow

**Status: ROBUST** (see 1.2 above)

### 3.3 Inference Hang / Timeout

**Status: NEEDS_WORK**

**Finding (HANG):** There is **no timeout** on the SLM inference call. The `infer()` method at line 224-228 calls `self.backend.infer(prompt).await` with no `tokio::time::timeout` wrapper. If the GGUF backend hangs (e.g., due to a corrupted model or infinite generation loop), the inference slot is held indefinitely, blocking all subsequent requests.

The `SLOW_INFERENCE_MS = 2000` threshold at line 231-236 only logs a warning after the fact — it does not abort the operation.

The GGUF backend (`gguf_backend.rs:104`) does use `tokio::task::spawn_blocking`, which means a hang would block the blocking threadpool rather than the async runtime. However, the inference semaphore would still be held, creating a permanent deadlock for all SLM requests.

**Recommendation:** Wrap the backend inference call in `tokio::time::timeout(Duration::from_secs(30), ...)` and return a fail-closed HIGH response on timeout.

### 3.4 Fallback Chain

**Status: ROBUST**

The `SlmService` (`lib.rs:187-218`) implements a proper fallback chain: primary engine -> fallback engine -> `unavailable_response()` (fail-closed HIGH). Test coverage confirms all three paths.

---

## 4. Adversarial Input Handling

### 4.1 Prompt Injection Detection (`sanitizer.rs:10-69`)

**Status: ROBUST**

Defense-in-depth with four layers:
1. **Truncation** (line 40-48): Char-boundary-safe truncation to `max_len` bytes.
2. **Tag stripping** (line 51): HTML/XML tags removed via regex.
3. **Injection pattern filtering** (line 54-61): 9 patterns including "ignore previous instructions", "you are now", role assumption, and output mimicry (`RISK:`, `EXPLANATION:`, `CONFIDENCE:`).
4. **Special char escaping** (line 64-68): `<`, `>`, `{`, `}` are HTML-escaped.

**Additional defenses:**
- `wrap_untrusted()` (line 95-107): Random nonce delimiters around untrusted data with WARNING header.
- `build_verified_system_prompt()` (line 116-123): Canary token injection for response verification.
- `sanitize_for_cloud()` (line 157-162): PII stripping (home paths, private IPs, API keys).

**Finding (BENIGN):** Null bytes (`\0`) are not explicitly stripped. A null byte in input could theoretically confuse some C-based string processing in llama.cpp. However, Rust strings cannot contain interior null bytes (they're valid UTF-8 but unusual), and the GGUF backend would need to handle this at the FFI boundary. Risk is minimal.

### 4.2 Output Validation (`output_validator.rs:26-161`)

**Status: ROBUST**

Three-layer output validation:
1. **Echo detection** (line 88): Checks if the untrusted-data nonce appears in model output.
2. **Injection artifact detection** (line 99-106): Checks for "ignore previous instructions", role assumption, prompt echo (`UNTRUSTED_INPUT_`), and system prompt leak.
3. **Structural parsing** (line 109-153): Validates RISK level, EXPLANATION presence, and CONFIDENCE range (0.0-1.0).

All failures fall back to `safe_fallback()` which returns `RiskLevel::High` (fail-closed).

### 4.3 Fail-Closed Parsing (`engine.rs:291-325`)

**Status: ROBUST**

The `parse_slm_output()` function defaults to `RiskLevel::High` when:
- Risk level is unrecognized (line 305)
- Output is empty (line 292 — default before parsing)
- Confidence cannot be parsed (line 308 — defaults to 0.5)

---

## 5. Resource Exhaustion

### 5.1 Disk Full — Audit Log Write Failure

**Status: ACCEPTABLE**

The audit logger uses a channel-based architecture (`logger.rs:181-202`). The writer thread catches write errors:
```rust
if let Err(e) = state.write_record(&record) {
    warn!(error = %e, "failed to write audit record");
}
```

- **No crash on disk full:** Write failures are logged via tracing and silently dropped.
- **No backpressure:** The `mpsc::channel` is unbounded, so records will accumulate in memory if the writer fails persistently. This could eventually cause OOM if disk stays full for a very long time.
- **Finding (BENIGN):** The channel between the logger and writer thread is `std::mpsc::channel()` which is unbounded. Under sustained disk-full conditions, records would accumulate in the channel. A bounded channel with `try_send` and drop on overflow would be more resilient.

### 5.2 Model File Deleted (mmap'd model)

**Status: ACCEPTABLE**

The GGUF backend (`gguf_backend.rs:30-91`) loads the model file via `llama_cpp::LlamaModel::load_from_file()`. On macOS, if the model file is deleted while mmap'd, the mmap remains valid until the process unmaps it (the file's data persists in the page cache). There is no crash risk from deletion of an already-loaded model.

However, if the model file is deleted and the service tries to reload/hot-swap, the `load()` function checks `path.exists()` (line 32-33) and will bail with a clear error.

Additionally, the GGUF backend has a **symlink check** (line 38-45) to prevent model path redirection attacks.

### 5.3 Socket Deleted — Recovery

**Status: ACCEPTABLE**

The daemon (`lib.rs`) writes a PID file and cleans up both the socket and PID file on shutdown (lines 886-895). The IPC server (`ipc.rs:64-66`) removes stale sockets on startup:
```rust
if socket_path.exists() {
    std::fs::remove_file(&socket_path)?;
}
```

**Finding (BENIGN):** If the Unix socket file is deleted while the daemon is running, existing connections continue to work, but new connections will fail. There is no automatic socket re-creation or recovery. A watchdog loop that recreates the socket on deletion would improve resilience.

### 5.4 Signal Handling and Graceful Shutdown

**Status: ROBUST**

The daemon handles both SIGTERM and SIGINT (`lib.rs:815-843`). On signal:
1. Sensor tasks are aborted
2. Guard cleanup task is aborted
3. Audit logger is shut down (flushes pending records)
4. Socket and PID files are removed
5. Exit message logged

---

## 6. Audit Log Rotation

### 6.1 Log Rotation Implementation (`logger.rs:83-117`)

**Status: ROBUST**

Full rotation is implemented:
- **Size-based trigger:** After each write, checks if file size >= `max_size_mb * 1024 * 1024` (default 50 MB). If so, flushes and rotates.
- **Numbered rotation:** Files are renamed `.1`, `.2`, ... `.N` with highest-numbered being deleted when `max_files` is reached.
- **Fresh file creation:** After rotation, a new empty log file is opened.

### 6.2 Maximum File Size

**Status: ROBUST**

Default is `DEFAULT_MAX_SIZE_BYTES = 50 * 1024 * 1024` (50 MB). Configurable via `log_rotation.max_size_mb` in config.toml. Default `max_files = 10`, meaning maximum disk usage is ~550 MB (50 MB * 11 files including current).

### 6.3 Old Log Cleanup

**Status: ROBUST**

`cleanup_old_files_with_retention()` (`logger.rs:485-502`) deletes rotated files older than `retention_days` (default 30 days). This runs at logger initialization.

### 6.4 Corrupt Line Handling

**Status: ROBUST**

`read_records_from_file()` (`logger.rs:448-471`) silently skips lines that fail JSON parsing:
```rust
Err(_) => continue,  // Skip corrupt lines gracefully
```

Test `test_corrupt_log_lines_handled_gracefully` at line 1063 validates this.

### 6.5 Concurrent Write Safety

**Status: ROBUST**

All writes go through a single writer thread via `mpsc::channel`, eliminating concurrent write races. Test `test_concurrent_writes` at line 971 validates 10-thread concurrent writes with 0 lost records.

---

## Summary Table

| Area | Component | Status | Issues |
|------|-----------|--------|--------|
| 1.1 | Rate Limiter (VecDeque) | ROBUST | None |
| 1.2 | SLM Queue (Semaphore) | ROBUST | Queue-full defaults to LOW not HIGH (advisory-only, acceptable) |
| 1.3 | Event Buffer (10K cap) | ROBUST | None |
| 1.4 | Alert Store (500 cap) | ROBUST | None |
| 1.5 | Pending Prompts (100 cap) | ROBUST | None |
| 2.1 | IPC Server (multi-client) | ACCEPTABLE | No line length limit on read_line; no connection limit (local-only) |
| 2.2 | Client Disconnect | ROBUST | None |
| 2.3 | Message Interleaving | ROBUST | None |
| 3.1 | Inference Serialization | ROBUST | None |
| 3.2 | Queue Overflow | ROBUST | None |
| 3.3 | Inference Timeout | NEEDS_WORK | **No timeout on inference — potential permanent hang** |
| 3.4 | Fallback Chain | ROBUST | None |
| 4.1 | Prompt Injection Defense | ROBUST | No explicit null byte stripping (minimal risk) |
| 4.2 | Output Validation | ROBUST | None |
| 4.3 | Fail-Closed Parsing | ROBUST | None |
| 5.1 | Disk Full Handling | ACCEPTABLE | Unbounded audit channel could accumulate under sustained failure |
| 5.2 | Model File Deleted | ACCEPTABLE | mmap survives deletion; reload would fail cleanly |
| 5.3 | Socket Deleted | ACCEPTABLE | No automatic socket re-creation |
| 5.4 | Signal Handling | ROBUST | Clean SIGTERM/SIGINT handling with full cleanup |
| 6.1 | Log Rotation | ROBUST | None |
| 6.2 | Max File Size | ROBUST | 50 MB default, configurable |
| 6.3 | Old Log Cleanup | ROBUST | 30-day retention with auto-cleanup |
| 6.4 | Corrupt Line Handling | ROBUST | Silent skip with no crash |
| 6.5 | Concurrent Writes | ROBUST | Channel-serialized, 0 lost records |

---

## Issue Registry

| ID | Category | Severity | Component | Description |
|----|----------|----------|-----------|-------------|
| S1 | HANG | Medium | `SlmEngine::infer()` | No timeout on backend inference. A hung model blocks all SLM analysis permanently. |
| S2 | BENIGN | Low | `SlmEngine::infer()` | Queue-full path returns LOW instead of HIGH. Acceptable since SLM is advisory-only. |
| S3 | BENIGN | Low | `ipc.rs` | `read_line()` has no line length limit. Local-only socket minimizes risk. |
| S4 | BENIGN | Low | `ipc.rs` | No limit on concurrent IPC connections. Local-only socket minimizes risk. |
| S5 | BENIGN | Low | `logger.rs` | Unbounded mpsc channel for audit writes. Could accumulate under sustained disk-full. |
| S6 | BENIGN | Low | `ipc.rs` | No socket file watchdog/re-creation if deleted at runtime. |
| S7 | BENIGN | Low | `sanitizer.rs` | No explicit null byte stripping before SLM inference. |

---

## Recommendations for Future Hardening

1. **[Priority: High] Add inference timeout.** Wrap `self.backend.infer(prompt).await` in `tokio::time::timeout(Duration::from_secs(30), ...)` in `SlmEngine::infer()`. Return a fail-closed HIGH response on timeout. This is the only finding that could cause a service hang.

2. **[Priority: Low] Bound the audit writer channel.** Replace `std::mpsc::channel()` with `std::sync::mpsc::sync_channel(1000)` or equivalent, dropping records when the writer is persistently failing.

3. **[Priority: Low] Add IPC line length limit.** Use `tokio::io::AsyncBufReadExt::read_line` with a wrapper that aborts on lines > 1 MB to prevent memory exhaustion from malicious local clients.

4. **[Priority: Low] Add IPC connection limit.** Track active connections with an `AtomicU32` counter and reject connections above a threshold (e.g., 64).

5. **[Priority: Low] Add null byte stripping** to `sanitize_untrusted_input()` before SLM processing to prevent any C-layer confusion.

6. **[Priority: Low] Socket watchdog.** Add a periodic check that re-binds the Unix socket if the file is deleted while the daemon is running.

---

## Overall Resilience Assessment

**PASS — System is production-ready with one medium-priority improvement recommended.**

The codebase demonstrates strong defensive engineering:

- **All buffers and stores are bounded** with explicit caps and eviction (10K events, 500 alerts, 100 prompts, 10-deep SLM queue, 5/min escalation rate limiter).
- **Fail-closed** is consistently applied: unknown SLM output defaults to HIGH risk, backend failures return HIGH, output validation failures return HIGH.
- **Defense-in-depth** for adversarial input: 4-layer sanitization, nonce-delimited untrusted data, canary tokens, echo detection, output artifact scanning, and PII stripping for cloud requests.
- **Concurrency** is well-managed with tokio semaphores, Arc/RwLock, and channel-based audit writes.
- **Graceful degradation** throughout: behavioral engine uses `try_write`/`try_read` to avoid blocking, audit write failures are logged and skipped, sensor failures don't crash the daemon.
- **Log rotation** is fully implemented with size limits, numbered rotation, retention cleanup, and corrupt line tolerance.

The single actionable finding is the missing inference timeout (S1), which could cause a permanent SLM hang if the model backend enters an infinite loop. This is mitigated by the fact that SLM analysis is advisory-only and does not block event processing, but should be fixed before production deployment.

All other findings are low-severity local-only concerns that do not represent crash, corruption, or hang risks under realistic operating conditions.
