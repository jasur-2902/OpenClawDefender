# Performance Optimization Signoff

**Date:** 2026-05-03
**Status:** QA Review Complete — Ready for Manual Verification
**Branch:** mainline

---

## 1. Summary of Optimizations

Eight workstreams were implemented to reduce CPU, memory, disk I/O, and battery drain across the ClawDefender daemon, sensor, SLM engine, and desktop client.

### WS-1: Event Budget System

**New file:** `crates/clawdefender-sensor/src/eslogger/budget.rs`

Caps how many eslogger events per second the daemon processes using priority-based sampling. The `EventBudget` struct tracks a 5-second rolling rate and classifies load into five tiers:

| Tier   | Raw rate (events/sec) | Budget (non-critical events/sec) |
|--------|-----------------------|---------------------------------|
| Idle   | < 10                  | Unlimited                       |
| Normal | 10-50                 | Unlimited                       |
| Busy   | 50-200                | 50                              |
| Heavy  | 200-1000              | 30                              |
| Flood  | 1000+                 | 10                              |

Security-critical events (exec, fork, connect, kextload, setuid/setgid, authentication, injection vectors, sensitive path access) **always** bypass the budget. Close events are dropped when any sampling tier is active. Tier recalculation occurs every 64 events to minimize per-event overhead. A deterministic 1-in-N sampler handles over-budget events. `BudgetStats` exposes current rate, processed rate, tier, and drop counts to the UI.

**Tests:** 20 unit tests covering tier transitions, priority bypass, sensitive path matching, custom limits, and stats accuracy.

### WS-2: Lazy 3-Tier Event Pipeline

**New file:** `crates/clawdefender-core/src/behavioral/classifier.rs`
**Modified:** `crates/clawdefender-daemon/src/event_router.rs`

Introduces a Tier 1 classifier (`tier1_classify`) that runs on every correlated event in < 10us using O(1) field checks and substring matching against ~40 sensitive path fragments stored in a `LazyLock<Vec>`. Events are classified into three priorities:

- **High:** Network connections, process exec, privilege escalation (setuid/setgid), kextload, authentication, injection vectors (get_task/trace/proc_check), and sensitive path access (SSH keys, AWS creds, .env, LaunchAgents, shell profiles, MCP configs, honeypots).
- **Mcp:** Any event with an MCP component.
- **Routine:** Everything else (~80% of events during normal development).

The event router was modified so that `Routine` events skip the entire behavioral analysis pipeline (anomaly scoring, kill chain detection, decision engine, SLM inference) while still being logged to audit and sent to the UI.

**Tests:** 25 unit tests covering all event types, sensitive path matching, priority precedence, and helper functions.

### WS-3: SLM Inference Throttle

**New file:** `crates/clawdefender-slm/src/scheduler.rs`
**Modified:** `crates/clawdefender-slm/src/engine.rs`

Demand-driven SLM scheduling with adaptive batch timing:

- **Knowledge base fast-path:** Pre-checks clusters against known patterns (IDE file watches, temp files = Routine; SSH key access, kill chains, high anomaly >= 0.9 = Suspicious) before queueing for inference. Suspicious patterns win over Routine in conflict (fail-closed).
- **System load classification:** Idle/Light/Moderate/Heavy/Critical with corresponding batch delays of 3s/5s/10s/30s/60s.
- **Battery-aware pausing:** On battery with moderate+ CPU load, SLM is paused entirely. On battery with idle CPU, uses 30s batch interval. Low battery restricts to idle-only processing at 60s intervals.
- **Cooldown enforcement:** 2s minimum between batches.
- **Queue management:** Bounded VecDeque (32 max), drops oldest on overflow.
- **Concurrency:** Semaphore(1) serializes inference; bounded queue semaphore (10 max) prevents unbounded waiting.
- **Memory reclaim:** After 5 minutes idle, `advise_memory_reclaim()` signals the backend to release KV cache / mmap pages.
- **Lock-free stats:** AtomicU64 counters for inference calls, skipped events, latency, and batch counts.

**Tests:** 28 unit tests covering load classification, knowledge base matching, scheduler state transitions, battery behavior, queue overflow, and stats tracking.

### WS-4: Memory Optimization

**Modified:** `crates/clawdefender-core/src/behavioral/killchain.rs`, `crates/clawdefender-core/src/behavioral/learning.rs`, `crates/clawdefender-core/src/behavioral/profile.rs`, `crates/clawdefender-core/src/audit/logger.rs`

Key reductions:
- **Kill chain detector:** Added `evict_inactive_servers()` to remove per-server state after 30 minutes of inactivity, preventing unbounded memory growth from transient MCP servers.
- **Learning engine:** Added `evict_stale_profiles()` to remove profiles after 24 hours of inactivity.
- **Audit channel:** Bounded `sync_channel` with `AUDIT_CHANNEL_CAPACITY = 500` prevents unbounded memory growth if the writer thread falls behind.
- **SLM engine:** 5-minute idle memory reclaim advisory for model mmap pages.

### WS-5: Disk I/O Optimization

**Modified:** `crates/clawdefender-core/src/audit/logger.rs`, `crates/clawdefender-core/src/behavioral/persistence.rs`

- **Audit batcher:** Buffers up to 100 events OR 10 seconds (whichever comes first) before flushing. High-priority events (block/suspicious) flush immediately. Uses `BufWriter` for buffered I/O.
- **Profile batch writes:** New `ProfileBatcher` buffers profile updates in a `HashMap<String, ServerProfile>` and writes them to SQLite in a single transaction every 30 seconds. Deduplicates updates (latest snapshot wins). Flushes on drop for clean shutdown.
- **Transaction batching:** `save_profiles_batch()` wraps all profile writes in a single SQLite BEGIN/COMMIT transaction.

**Tests:** Unit tests for batcher queuing, deduplication, flush timing, and drop behavior.

### WS-6: Timer Consolidation

**New file:** `crates/clawdefender-daemon/src/scheduler.rs`

Replaces independent `tokio::spawn` timer loops with a unified `Scheduler` that ticks every 500ms and checks which tasks are due:

- **ScheduledTask:** Per-task intervals for PluggedIn/Battery/LowBattery power states. `Duration::ZERO` disables a task for that power state.
- **PowerState detection:** Parses `pmset -g batt` output on macOS to detect AC/Battery/LowBattery (< 20%).
- **Pre-built daemon tasks:**
  - Process tree refresh: 5s (AC) / 15s (battery) / 30s (low battery)
  - Guard PID cleanup: 5s / 15s / 30s
  - Power state check: 30s (all states)
- **Coalesced wakeups:** Single 500ms tick replaces multiple independent timers, reducing CPU wake-ups.

**Tests:** 11 unit tests covering task scheduling, power state parsing, interval scaling, enable/disable, and battery thresholds.

### WS-7: Performance UI Controls

**Modified:** `clients/clawdefender-app/src/pages/Settings.tsx`, `clients/clawdefender-app/src/types/index.ts`, `clients/clawdefender-app/src-tauri/src/commands.rs`, `clients/clawdefender-app/src-tauri/src/tray.rs`

- **MonitoringMode enum:** `full | balanced | light | minimal` — configurable from Settings page.
- **PerformanceStats interface:** CPU %, memory (total/model/buffers), events/sec (processed/total), sampling %, disk writes/sec.
- **Tauri commands:** `get_monitoring_mode`, `set_monitoring_mode`, `get_performance_stats`, `pause_monitoring`, `resume_monitoring`.
- **PauseStatus:** Supports timed pause with countdown.
- **Tray menu:** Pause/Resume protection toggle with daemon stop/start.

---

## 2. Benchmark Targets

All figures are **estimated based on code analysis**. Values represent expected steady-state behavior after optimizations are active. Manual measurement is required to confirm.

| Scenario | Metric | Target | Expected After Optimization | Rationale |
|----------|--------|--------|-----------------------------|-----------|
| Idle Mac, no activity | CPU % | < 1% | ~0.5-1% | Budget system stays in Idle tier (no sampling overhead). Scheduler ticks every 500ms but tasks are infrequent. No SLM inference. |
| Idle Mac, no activity | Memory (RSS) no model | < 80 MB | ~60-70 MB | Bounded audit channel (500), profile eviction after 24h, kill chain eviction after 30 min. |
| Idle Mac, no activity | Memory (RSS) with 1B model | < 1.2 GB | ~1.0-1.1 GB | mmap'd model file + reduced buffers. 5-minute idle reclaim advisory frees KV cache. |
| Normal dev (editor + terminal) | CPU % | < 3% | ~1.5-2.5% | Tier 1 classifier skips ~80% of events (Routine). Budget in Normal tier (unlimited but low volume). SLM batches every 3-5s. |
| Normal dev | Events/sec processed | varies | ~20-50 of 50-100 total | Routine events skip behavioral pipeline. Only High/Mcp events (~20%) get full analysis. |
| Normal dev | Disk writes/sec | < 5 | ~2-3 | Audit batches 100 events / 10s. Profile writes every 30s. |
| Heavy build (cargo build) | CPU % | < 8% | ~3-6% | Budget transitions to Busy/Heavy tier, caps non-critical events at 30-50/sec. SLM pauses or uses 30s batch interval. |
| Heavy build | Events/sec (raw) | varies | 500-2000 | cargo build generates massive file I/O (target/ directory). |
| Heavy build | Events/sec (processed) | < 50/sec | 30-50 | Budget-limited. Tier 1 classifies target/ paths as Routine. |
| Heavy build | Sampling rate | varies | ~95-97% dropped | Only 30-50 of 500-2000 raw events processed. Security events (exec, connect) always pass. |
| SLM inference burst | GPU spike duration | < 3 sec | ~1-2 sec | 2s cooldown between batches. Bounded queue (10 max). Single-inference semaphore. |
| Battery, normal dev | CPU % | < 2% | ~1-1.5% | Scheduler intervals 2-4x slower. SLM pauses under moderate+ load. Battery batch interval = 30s. |
| Battery, normal dev | Disk writes/sec | < 2 | ~0.5-1 | Extended flush intervals. Profile writes still every 30s but fewer events trigger updates. |
| After 30 min continuous use | Memory growth | < 10% | ~3-5% | Kill chain eviction (30 min), profile eviction (24h), bounded channels, SLM idle reclaim (5 min). |

---

## 3. Critical Test Plan

### T1: Idle CPU Verification

**Objective:** Confirm daemon CPU usage stays below 1% with no user activity.
**Steps:**
1. Launch daemon with no MCP servers active.
2. Wait 2 minutes for initialization to settle.
3. Monitor CPU usage via Activity Monitor or `top -pid <daemon_pid>` for 5 minutes.
4. Verify average CPU < 1%, no spikes > 2%.

**Pass criteria:** Average CPU < 1% over 5 minutes. Event budget tier stays Idle.

### T2: Build Overhead Test

**Objective:** Verify daemon CPU stays below 8% during a heavy build.
**Steps:**
1. Start a fresh `cargo build` in a large workspace (e.g., the clawai repo itself).
2. Monitor daemon CPU via `top` throughout the build.
3. Check event budget stats via `get_performance_stats` Tauri command.
4. Verify sampling is active (Busy or Heavy tier) and processed events < 50/sec.

**Pass criteria:** Daemon CPU < 8%. Sampling active. No dropped security events (exec/connect).

### T3: Memory Stability Test

**Objective:** Confirm memory does not grow unboundedly over 30+ minutes.
**Steps:**
1. Start daemon with 1-2 MCP servers active.
2. Record initial RSS.
3. Run normal development activity for 30 minutes.
4. Record RSS at 10-minute intervals.
5. Verify growth < 10% from initial.

**Pass criteria:** RSS growth < 10% over 30 minutes. Profile and kill chain eviction logs visible.

### T4: Battery Mode Verification

**Objective:** Confirm power-aware behavior when switching to battery.
**Steps:**
1. Start on AC power, verify normal operation.
2. Unplug from AC (or simulate via test harness).
3. Verify scheduler intervals increase (check logs for "Power state changed").
4. Verify SLM pauses under moderate+ CPU load.
5. Verify disk writes decrease.

**Pass criteria:** Log shows power state transition. SLM scheduler state shows PAUSED under load. Polling intervals visibly increase.

### T5: Sampling Under Load Test

**Objective:** Verify security-critical events are never dropped during high load.
**Steps:**
1. Generate high event volume (e.g., `find / -name '*.txt'` to trigger file open flood).
2. Simultaneously trigger security events: SSH key access, exec, network connection.
3. Check audit log for all security events.
4. Check budget stats for drop count on non-critical events.

**Pass criteria:** All security events (exec, connect, SSH key access) appear in audit log. Budget stats show sampling active with drops only on non-critical events.

### T6: Detection Quality Preservation

**Objective:** Confirm that Tier 1 classification and event budget do not cause false negatives.
**Steps:**
1. Simulate an MCP-based attack sequence: tool call -> read ~/.ssh/id_rsa -> network connect to external host.
2. Verify all events are classified as High or Mcp by Tier 1.
3. Verify full behavioral pipeline processes the sequence.
4. Verify kill chain detection fires.
5. Verify SLM inference is triggered (or knowledge base fast-path classifies as Suspicious).

**Pass criteria:** Attack sequence detected. No events dropped by budget. Full pipeline execution confirmed via audit records.

---

## 4. Architecture Diagram

```
                         +-----------------------+
                         |  macOS Endpoint       |
                         |  Security (eslogger)  |
                         +-----------+-----------+
                                     |
                              raw OS events
                                     |
                         +-----------v-----------+
                         |  EVENT BUDGET [WS-1]  |
                         |  BudgetTier:          |
                         |  Idle/Normal/Busy/    |
                         |  Heavy/Flood          |
                         |                       |
                         |  Always: exec,fork,   |
                         |  connect,sensitive     |
                         |  Drop: close (busy+)  |
                         |  Sample: over-budget   |
                         +-----------+-----------+
                                     |
                           filtered events
                                     |
                         +-----------v-----------+
                         |  CORRELATION ENGINE   |
                         |  (OS + MCP matching)  |
                         +-----------+-----------+
                                     |
                         correlated events
                                     |
                    +----------------v----------------+
                    |  TIER 1 CLASSIFIER [WS-2]       |
                    |  O(1) priority classification    |
                    |                                  |
                    |  High: exec,connect,sensitive    |
                    |  Mcp: has MCP component          |
                    |  Routine: ~80% of events         |
                    +-----+----------------+----------+
                          |                |
                     High/Mcp          Routine
                          |                |
          +---------------v-----+    +----v-----------+
          | BEHAVIORAL PIPELINE |    | AUDIT + UI     |
          |                     |    | (log only,     |
          | - Anomaly scoring   |    |  skip analysis)|
          | - Kill chain detect |    +----------------+
          | - Decision engine   |
          +----------+----------+
                     |
              escalation needed?
                     |
          +----------v----------+
          | SLM SCHEDULER [WS-3]|
          |                     |
          | Knowledge base      |
          | fast-path check     |
          |   |                 |
          |   +-> Known pattern |
          |   |   (skip SLM)   |
          |   |                 |
          |   +-> Unknown:      |
          |       queue batch   |
          |                     |
          | Adaptive timing:    |
          | - CPU load aware    |
          | - Battery aware     |
          | - 2s cooldown       |
          +----------+----------+
                     |
          +----------v----------+
          | SLM ENGINE [WS-3]   |
          | Semaphore(1)        |
          | Queue(10 max)       |
          | Idle memory reclaim |
          +---------------------+

  +-----------------+    +------------------+    +------------------+
  | AUDIT BATCHER   |    | PROFILE BATCHER  |    | UNIFIED          |
  | [WS-5]          |    | [WS-5]           |    | SCHEDULER [WS-6] |
  |                 |    |                  |    |                  |
  | 100 events or   |    | HashMap dedup    |    | 500ms tick       |
  | 10s flush       |    | 30s SQLite txn   |    | Power-aware      |
  | Priority: immed |    | Flush on drop    |    | intervals        |
  +-----------------+    +------------------+    +------------------+

  +-----------------------------------------------------+
  | PERFORMANCE UI [WS-7]                               |
  |                                                     |
  | Settings: MonitoringMode (full/balanced/light/min)  |
  | Tray: Pause/Resume protection                       |
  | Stats: CPU, memory, events/sec, disk writes         |
  +-----------------------------------------------------+
```

---

## 5. Files Changed

### New Files (4)

| File | Workstream | Description |
|------|-----------|-------------|
| `crates/clawdefender-sensor/src/eslogger/budget.rs` | WS-1 | Event budget system with tiered sampling |
| `crates/clawdefender-core/src/behavioral/classifier.rs` | WS-2 | Tier 1 event priority classifier |
| `crates/clawdefender-slm/src/scheduler.rs` | WS-3 | SLM inference throttle and demand scheduler |
| `crates/clawdefender-daemon/src/scheduler.rs` | WS-6 | Unified power-aware task scheduler |

### Modified Files — Backend (15)

| File | Workstream | Change |
|------|-----------|--------|
| `crates/clawdefender-sensor/src/eslogger/mod.rs` | WS-1 | Integrated EventBudget into eslogger event loop |
| `crates/clawdefender-sensor/src/eslogger/parser.rs` | WS-1 | Pass event type/path to budget check |
| `crates/clawdefender-sensor/src/eslogger/process.rs` | WS-1 | Budget integration in process handler |
| `crates/clawdefender-sensor/src/lib.rs` | WS-1 | Export budget module |
| `crates/clawdefender-sensor/src/correlation/engine.rs` | WS-2 | Forward priority metadata |
| `crates/clawdefender-core/src/behavioral/mod.rs` | WS-2 | Export classifier module |
| `crates/clawdefender-daemon/src/event_router.rs` | WS-2 | Tier 1 classification gate in event processing loop |
| `crates/clawdefender-core/src/behavioral/killchain.rs` | WS-4 | Inactive server eviction (30 min timeout) |
| `crates/clawdefender-core/src/behavioral/learning.rs` | WS-4 | Stale profile eviction (24h timeout) |
| `crates/clawdefender-core/src/behavioral/profile.rs` | WS-4 | Profile memory cap support |
| `crates/clawdefender-core/src/audit/logger.rs` | WS-5 | Batched writes (100 events / 10s), bounded channel (500), priority flush |
| `crates/clawdefender-core/src/behavioral/persistence.rs` | WS-5 | ProfileBatcher with 30s SQLite transaction batching |
| `crates/clawdefender-core/src/config/settings.rs` | WS-7 | MonitoringMode settings |
| `crates/clawdefender-slm/src/engine.rs` | WS-3 | Memory reclaim advisory, idle detection, bounded queue |
| `crates/clawdefender-slm/src/pipeline.rs` | WS-3 | SLM scheduler integration |
| `crates/clawdefender-slm/src/lib.rs` | WS-3 | Export scheduler module |
| `crates/clawdefender-daemon/src/lib.rs` | WS-5, WS-6 | ProfileBatcher integration, scheduler integration |

### Modified Files — Frontend (10)

| File | Workstream | Change |
|------|-----------|--------|
| `clients/clawdefender-app/src-tauri/src/commands.rs` | WS-7 | Tauri commands for monitoring mode, perf stats, pause/resume |
| `clients/clawdefender-app/src-tauri/src/tray.rs` | WS-7 | Pause/Resume protection in tray menu |
| `clients/clawdefender-app/src-tauri/src/lib.rs` | WS-7 | Register new commands |
| `clients/clawdefender-app/src-tauri/src/state.rs` | WS-7 | State fields for monitoring mode |
| `clients/clawdefender-app/src-tauri/src/event_stream.rs` | WS-7 | Perf stats event forwarding |
| `clients/clawdefender-app/src-tauri/src/score/factors.rs` | WS-7 | Score factor adjustments |
| `clients/clawdefender-app/src/pages/Settings.tsx` | WS-7 | Performance section with monitoring mode selector |
| `clients/clawdefender-app/src/types/index.ts` | WS-7 | MonitoringMode, PerformanceStats, PauseStatus types |
| `clients/clawdefender-app/src-tauri/src/conversation/executor.rs` | WS-7 | Monitoring mode integration |
| `clients/clawdefender-app/src-tauri/src/monitor.rs` | WS-7 | Monitor integration |

---

## 6. Known Limitations and Future Improvements

### Known Limitations

1. **Budget sensitive path matching is linear scan.** The `is_budget_sensitive_path` function in `budget.rs` iterates over ~20 prefixes per event. At current list sizes this is negligible (< 1us), but scaling to hundreds of patterns would benefit from a trie or Aho-Corasick automaton.

2. **Tier 1 classifier uses substring matching.** The `SENSITIVE_PATH_FRAGMENTS` list uses `contains()` checks rather than a compiled data structure. This is O(n*m) where n is the number of fragments and m is the path length. Adequate for ~40 fragments but not scalable to arbitrary numbers.

3. **CPU sampling uses `sysctl vm.loadavg` as a proxy.** This gives 1-minute load average, not instantaneous CPU percentage. The SLM scheduler may react slowly to sudden load spikes. A future improvement would use `host_processor_info()` for per-second CPU sampling.

4. **Power state detection shells out to `pmset`.** Each check spawns a subprocess. At the current 30-second interval this is acceptable, but a direct IOKit API binding would eliminate the overhead.

5. **Profile batcher uses `Mutex` for thread safety.** Under extremely high contention (unlikely in practice), this could become a bottleneck. A lock-free or sharded approach would scale better.

6. **No GPU-aware throttling.** The SLM scheduler monitors CPU but not GPU utilization. On Apple Silicon where the SLM uses Metal, GPU contention with other apps is not detected.

7. **Monitoring mode UI is not yet connected to all backend subsystems.** The `set_monitoring_mode` command adjusts settings, but the full mapping of mode -> budget limits, SLM intervals, and poll frequencies requires completion.

### Future Improvements

1. **Aho-Corasick for path matching.** Replace linear scans in both `budget.rs` and `classifier.rs` with a compiled multi-pattern matcher for O(n) total matching regardless of pattern count.

2. **IOKit direct power state.** Replace `pmset` subprocess with direct IOKit `IOPMPowerSource` API calls for lower-overhead, higher-frequency power state checks.

3. **Per-process CPU attribution.** Use `proc_pid_rusage()` to measure the daemon's own CPU consumption rather than system-wide load, enabling more precise self-throttling.

4. **Adaptive event budget via ML.** Train a lightweight model on observed event patterns to predict optimal budget tiers rather than using static rate thresholds.

5. **Profile compression.** Compress serialized profiles before SQLite storage to reduce both memory and disk footprint for long-running servers.

6. **SLM model hot-swap.** Allow switching between model sizes based on power state (e.g., 0.5B on battery, 1B on AC) without restarting the daemon.

7. **Telemetry dashboard.** Expose budget stats, classifier hit rates, SLM scheduler state, and memory usage via a real-time metrics endpoint for debugging and tuning.

---

## Appendix: Test Coverage Summary

| Module | Test Count | Coverage Areas |
|--------|-----------|----------------|
| `budget.rs` | 20 | Tier transitions, priority bypass, sensitive paths, custom limits, stats |
| `classifier.rs` | 25 | All OS event types, sensitive paths, priority precedence, helpers |
| `scheduler.rs` (SLM) | 28 | Load tiers, knowledge base patterns, queue management, battery behavior, stats |
| `scheduler.rs` (daemon) | 11 | Task scheduling, power state parsing, interval scaling, enable/disable |
| `persistence.rs` (batcher) | 3 | Queue/flush, deduplication, drop flush |
| `engine.rs` (SLM) | 17 | Parsing, inference, stats, queue full, heuristic backend |
| **Total** | **104** | |

All tests are unit tests that run without external dependencies (no daemon, no model, no macOS APIs).
