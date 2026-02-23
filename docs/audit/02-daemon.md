# Section 2: Daemon (`clawdefender-daemon`) Audit

## 2.1 Overview

The `clawdefender-daemon` crate is the main orchestrator of the ClawDefender system. It ties together all subsystems: MCP proxy, policy engine, audit logger, sensor subsystem (process tree, eslogger, FSEvents), correlation engine, event router, behavioral engine, threat intelligence, network policy, guard registry, SLM service, swarm analysis, TUI/headless mode, and signal handling.

**Crate type**: Binary (`clawdefender-daemon`) + Library (`clawdefender_daemon`)

**Dependencies**: clawdefender-core, clawdefender-mcp-proxy, clawdefender-sensor, clawdefender-slm, clawdefender-swarm, clawdefender-tui, clawdefender-mcp-server, clawdefender-guard, clawdefender-threat-intel, tokio, tracing, clap, serde_json, chrono, notify, libc

**Source files**:
- `src/main.rs` — CLI entry point (117 lines)
- `src/lib.rs` — Daemon struct, initialization, `run()`, `run_proxy()` (~2600+ lines)
- `src/ipc.rs` — Unix domain socket IPC server (259 lines)
- `src/event_router.rs` — Correlated event fan-out (79 lines)
- `src/mock_network_extension.rs` — Mock macOS Network Extension (413 lines)
- `tests/guard_integration.rs` — Guard registry integration tests (341 lines)
- `tests/network_integration.rs` — Network subsystem integration tests (652 lines)

---

## 2.2 Module-by-Module Analysis

### 2.2.1 `main.rs` — CLI Entry Point

| Function | Classification | Notes |
|---|---|---|
| `main()` | ✅ REAL | Parses CLI args (clap), sets up tracing (file or stderr), loads config, dispatches to `Daemon::run()` or `Daemon::run_proxy()` |
| `expand_tilde()` | ✅ REAL | Expands `~/` to `$HOME` |
| `dirs_fallback()` | ✅ REAL | Resolves relative path under `$HOME`, falls back to `/tmp` |

**CLI subcommands**:
- `Run` (default) — Standalone daemon mode (IPC, sensors, audit)
- `Proxy { server_command }` — MCP proxy mode (intercepts JSON-RPC)

**Flags**: `--config`, `--tui`, `--policy`

### 2.2.2 `lib.rs` — Daemon Struct & Orchestration

#### Daemon::new() — Constructor

| Component | Classification | Notes |
|---|---|---|
| Policy engine loading | ✅ REAL | Loads from TOML file via `DefaultPolicyEngine::load()`, falls back to empty |
| Sensor config loading | ✅ REAL | Loads from TOML, falls back to defaults |
| Audit logger creation | ✅ REAL | `FileAuditLogger::new()` with rotation config |
| Behavioral engine init | ✅ REAL | Opens SQLite profile store, loads existing profiles into `LearningEngine`, initializes `AnomalyScorer`, `KillChainDetector`, `DecisionEngine`, `InjectionDetector` |
| Threat intel init | ✅ REAL | Creates `FeedCache`, populates baseline, loads IoC database from disk, creates `BlocklistMatcher`, `RulePackManager`, `TelemetryAggregator`, `FeedClient` |
| Network policy init | ✅ REAL | Creates `NetworkPolicyEngine` with parsed rules, `DnsFilter` populated from IoC domains, `DnsCache`, mock network extension |
| Guard registry | ✅ REAL | Creates empty `GuardRegistry::new()` |

#### Daemon::run() — Standalone Mode

| Step | Classification | Notes |
|---|---|---|
| PID file write | ✅ REAL | Writes PID to `~/.local/share/clawdefender/clawdefender.pid` |
| Channel creation | ✅ REAL | Creates mpsc channels for prompts, events, audit, correlated events |
| MCP server spawn | ✅ REAL | Spawns HTTP MCP server on configured port (if enabled) |
| Guard PID cleanup task | ✅ REAL | Background task every 5s calling `cleanup_dead_pids()` |
| Guard REST API server | ✅ REAL | Spawns `run_api_server()` on configured port (if enabled) |
| Audit writer task | ✅ REAL | Background task reading from audit channel and writing via `FileAuditLogger::log()` |
| Sensor subsystem | ✅ REAL | Calls `start_sensor_subsystem()` |
| Policy hot-reload | ✅ REAL | File watcher via `notify` crate, debounced reload |
| IPC server | ✅ REAL | Spawns Unix domain socket IPC server |
| TUI / headless | ✅ REAL | Spawns TUI if terminal, headless prompt handler otherwise |
| Signal handling | ✅ REAL | SIGTERM, SIGINT via `tokio::signal::unix`, Ctrl-C on non-unix |
| Cleanup | ✅ REAL | Aborts tasks, drops senders, flushes audit (3s timeout), removes socket + PID file |

#### Daemon::run_proxy() — MCP Proxy Mode

| Step | Classification | Notes |
|---|---|---|
| All standalone steps | ✅ REAL | Same as `run()` plus proxy-specific setup |
| SLM service init | ✅ REAL | Creates `SlmService` with config; degrades gracefully if no model |
| Noise filter + context tracker | ✅ REAL | Creates `NoiseFilter` and `ContextTracker` |
| Swarm commander init | ✅ REAL | Creates `Commander` with LLM client + cost tracker if API key found |
| Chat server init | ✅ REAL | Creates `ChatManager` (SQLite) + `ChatServer` if swarm active |
| Proxy config | ✅ REAL | Creates `StdioProxy` with full config, SLM context, swarm context, threat intel context |
| Proxy run | ✅ REAL | Runs proxy with `tokio::select!` for signals |

#### start_sensor_subsystem()

| Sensor | Classification | Notes |
|---|---|---|
| Process tree refresh | ✅ REAL | Initial refresh + periodic refresh timer |
| Correlation engine | ✅ REAL | Creates `CorrelationEngine` with config, spawns as task |
| Event router | ✅ REAL | Routes correlated events to audit + UI |
| eslogger | ✅ REAL | Checks FDA, spawns `EsloggerManager`, pipes OS events to correlation engine |
| EnhancedFsWatcher | ✅ REAL | Watches configured paths, converts FS events to OS events for correlation |
| Sensor config watcher | ✅ REAL | File watcher for sensor.toml changes (logs reload, but does not actually reload sensor config at runtime) |

#### Helper Functions

| Function | Classification | Notes |
|---|---|---|
| `spawn_policy_watcher()` | ✅ REAL | Uses `notify` crate, debounces 200ms, calls `engine.reload()` |
| `spawn_file_watcher()` | ⚠️ PARTIAL | Watches file changes but only logs "reload pending" -- does not actually reload sensor config |
| `pid_file_path()` | ✅ REAL | Returns `~/.local/share/clawdefender/clawdefender.pid` |
| `write_pid_file()` | ✅ REAL | Writes PID, creates parent dirs |
| `remove_pid_file()` | ✅ REAL | Removes PID file |

### 2.2.3 `ipc.rs` — IPC Server

| Function | Classification | Notes |
|---|---|---|
| `run_ipc_server()` | ✅ REAL | Binds Unix socket, accepts connections, spawns per-client handlers |
| `handle_client()` | ✅ REAL | JSON-line protocol over Unix socket; dispatches to handlers |
| `handle_guard_request()` | ✅ REAL | Full implementation of guard register/deregister/stats/health |

**IPC Commands handled**:

| Command | Classification | Notes |
|---|---|---|
| `"status"` | ✅ REAL | Returns live `ProxyMetrics` (messages_total, allowed, blocked, prompted, logged) |
| `"reload"` | ✅ REAL | Calls `policy_engine.reload()`, returns ok/error |
| `"shutdown"` | ✅ REAL | Sends response, then sends SIGTERM to self for graceful shutdown |
| `GuardRequest::GuardRegister` | ✅ REAL | Converts permission types, calls `registry.register()`, returns guard_id |
| `GuardRequest::GuardDeregister` | ✅ REAL | Looks up guard by agent_name+pid, calls `registry.deregister()` |
| `GuardRequest::GuardStatsQuery` | ⚠️ PARTIAL | Returns stats but `blocked_details`, `anomaly_alerts`, `monitored_operations` are always empty/zero |
| `GuardRequest::GuardHealthCheck` | ⚠️ PARTIAL | Always returns `Active` status regardless of actual guard health; ignores individual guard states |
| Unknown commands | ✅ REAL | Returns JSON error response |

### 2.2.4 `event_router.rs` — Event Router

| Function | Classification | Notes |
|---|---|---|
| `EventRouter::new()` | ✅ REAL | Stores config + channel senders |
| `EventRouter::run()` | ✅ REAL | Spawns task: forwards to audit via `to_audit_record()`, forwards to UI, flags high-severity uncorrelated events |
| Escalation to SLM/Swarm | ⚠️ PARTIAL | Logs debug message for high-severity events but does NOT actually send to SLM or swarm for analysis |

### 2.2.5 `mock_network_extension.rs` — Mock Network Extension

| Function | Classification | Notes |
|---|---|---|
| `MockNetworkExtension::new()` | ✅ REAL | Creates instance with config |
| `update_blocked_hosts()` | ✅ REAL | Updates IoC blocklist |
| `stats()` | ✅ REAL | Returns statistics |
| `evaluate_connect()` | ✅ REAL | Full 5-step evaluation (non-agent -> localhost -> IoC -> cache -> default), well-documented security model |
| `prune_caches()` | ✅ REAL | Prunes expired PID + policy cache entries |
| `new_shared()` | ✅ REAL | Creates Arc<RwLock<>> wrapper |
| `spawn_cache_pruner()` | ✅ REAL | Background task for periodic pruning |

**Important**: This is explicitly a MOCK -- it cannot actually block network connections. It only logs what would happen. This is by design for development/testing until a real macOS Network Extension is implemented.

---

## 2.3 Hardcoded Values & Concerns

| Location | Issue | Severity |
|---|---|---|
| `lib.rs:262-270` | Ed25519 verifier key is all-zeros (`"0000...0000"`) -- feed signature verification will always fail | HIGH -- threat intel feed updates are effectively unsigned |
| `lib.rs:657` | Guard API `token: String::new()` -- API server has empty auth token | HIGH -- Guard REST API has no authentication |
| `lib.rs:1006` | Same empty token issue in `run_proxy()` path | HIGH -- same as above |
| `ipc.rs:253` | `GuardHealthCheck` always returns `Active` | LOW -- may mask unhealthy guards |
| `ipc.rs:228-240` | `GuardStatsQuery` returns empty `blocked_details`, zero `anomaly_alerts`, empty `monitored_operations` | MEDIUM -- stats are incomplete |
| `event_router.rs:67-74` | High-severity event escalation only logs, does not route to SLM/swarm | MEDIUM -- analysis pipeline not connected for sensor events |
| `lib.rs:571-575` | Sensor config file watcher only logs changes, does not actually reload config | LOW -- requires daemon restart for sensor config changes |

---

## 2.4 Markers Found

| Type | Count | Details |
|---|---|---|
| `todo!()` | 0 | None found |
| `unimplemented!()` | 0 | None found |
| `FIXME` | 0 | None found |
| `TODO` | 0 | None found |
| `HACK` | 0 | None found |
| `#[allow(dead_code)]` | 2 | `Daemon` struct (lib.rs:61), `PidCacheEntry` (mock_network_extension.rs:65) |

---

## 2.5 Signal Handling

| Signal | Implementation | Classification |
|---|---|---|
| SIGTERM | ✅ REAL | `tokio::signal::unix::SignalKind::terminate()` -- triggers graceful shutdown |
| SIGINT | ✅ REAL | `tokio::signal::unix::SignalKind::interrupt()` -- triggers graceful shutdown |
| SIGHUP | ❌ MISSING | Not handled -- could be used for config reload |
| Ctrl-C (non-unix) | ✅ REAL | `tokio::signal::ctrl_c()` fallback |
| Self-SIGTERM (via IPC) | ✅ REAL | IPC `"shutdown"` command sends `libc::kill(self, SIGTERM)` |

---

## 2.6 Config Loading

| Config | Classification | Notes |
|---|---|---|
| `ClawConfig` | ✅ REAL | Loaded from TOML file, all fields parsed with defaults |
| `SensorConfig` | ✅ REAL | Separate TOML file, graceful fallback to defaults |
| Policy file | ✅ REAL | Loaded via `DefaultPolicyEngine::load()`, hot-reloaded via file watcher |
| Behavioral config | ✅ REAL | Nested in `ClawConfig`, controls thresholds and auto-block |
| Threat intel config | ✅ REAL | Nested in `ClawConfig`, controls feed URL, intervals, auto-apply |
| Network policy config | ✅ REAL | Nested in `ClawConfig`, controls default action, rate limits, etc. |
| Guard API config | ✅ REAL | Nested in `ClawConfig`, port + enabled flag |
| MCP server config | ✅ REAL | Nested in `ClawConfig`, HTTP port + enabled flag |
| Swarm config | ✅ REAL | Nested in `ClawConfig`, budget limits, chat port, escalation threshold |
| SLM config | ✅ REAL | Nested in `ClawConfig`, model path, context size, temperature, GPU, threads |

---

## 2.7 Proxy Management

The daemon manages the MCP proxy via `StdioProxy`:
- ✅ REAL: Creates `StdioProxy` with policy engine, audit sender, UI bridge
- ✅ REAL: Injects SLM context (service + noise filter + context tracker)
- ✅ REAL: Injects swarm context (commander + escalation threshold) if available
- ✅ REAL: Injects threat intel context (IoC database) if available
- ✅ REAL: Runs proxy in `tokio::select!` alongside signal handlers
- ✅ REAL: Graceful shutdown on signal

---

## 2.8 Event System

| Component | Classification | Notes |
|---|---|---|
| OS events (eslogger) | ✅ REAL | Piped to correlation engine via `CorrelationInput::Os` |
| FS events (FSEvents) | ✅ REAL | Converted to `OsEvent`, piped to correlation engine |
| Correlated events | ✅ REAL | `CorrelationEngine` produces `CorrelatedEvent`s |
| Event routing | ✅ REAL | `EventRouter` fans out to audit logger + UI |
| SLM/swarm escalation | ⚠️ PARTIAL | Flagged in logs but not actually routed for analysis |
| MCP events from proxy | ✅ REAL | Handled within StdioProxy (separate crate) |

---

## 2.9 Behavioral Engine Integration

| Component | Classification | Notes |
|---|---|---|
| LearningEngine | ✅ REAL | Initialized with config, loads profiles from SQLite store |
| AnomalyScorer | ✅ REAL | Created, stored in Daemon struct |
| KillChainDetector | ✅ REAL | Created, stored in Daemon struct |
| DecisionEngine | ✅ REAL | Configured with thresholds from config |
| InjectionDetector | ✅ REAL | Configured with threshold + patterns path |
| ProfileStore | ✅ REAL | SQLite persistence, falls back to in-memory |
| Runtime integration | ⚠️ PARTIAL | All components are initialized and stored, but the daemon `run()` and `run_proxy()` methods do not directly use them at runtime for OS/FS events. The behavioral analysis is used within the proxy for MCP messages (handled by mcp-proxy crate). |

---

## 2.10 Guard System

| Component | Classification | Notes |
|---|---|---|
| GuardRegistry | ✅ REAL | In-memory registry with register/deregister/list/check_action/stats/cleanup |
| Guard IPC handler | ✅ REAL | Full request/response handling |
| Guard REST API | ✅ REAL | Spawned on configured port (but with empty auth token) |
| Guard PID cleanup | ✅ REAL | Background task every 5s removes guards for dead PIDs |
| Guard policy enforcement | ✅ REAL | `check_action()` evaluates against registered permissions |

---

## 2.11 Test Coverage

| Test File | Tests | Classification |
|---|---|---|
| `lib.rs` (unit tests) | ~30+ tests | ✅ REAL — covers config parsing, daemon creation, behavioral init, threat intel init, network policy init, serialization, event routing, audit records |
| `tests/guard_integration.rs` | 15 tests | ✅ REAL — covers guard register/deregister/list/stats/cleanup, serialization, policy scoping |
| `tests/network_integration.rs` | 13 tests | ✅ REAL — covers full network flow, DNS filter, rate limiter, kill chain, mock extension, log aggregation, guard allowlist |

---

## 2.12 Summary Classification

| Category | Status | Details |
|---|---|---|
| Daemon startup/init | ✅ REAL | All subsystems initialized from config |
| Standalone mode (`run`) | ✅ REAL | Full implementation with all subsystems |
| Proxy mode (`run_proxy`) | ✅ REAL | Full implementation with MCP proxy |
| IPC server | ✅ REAL | 5 command types, all functional |
| Signal handling | ✅ REAL | SIGTERM + SIGINT handled |
| Config loading | ✅ REAL | TOML-based, all sections parsed |
| Policy hot-reload | ✅ REAL | File watcher with debounce |
| Sensor subsystem | ✅ REAL | Process tree, eslogger, FSEvents, correlation |
| Event routing | ⚠️ PARTIAL | Routes to audit + UI, but escalation to SLM/swarm not connected |
| Behavioral engine | ⚠️ PARTIAL | Fully initialized but not integrated into runtime OS event processing |
| Guard system | ✅ REAL | Full lifecycle, but REST API lacks authentication |
| Mock network extension | ✅ REAL | Full evaluation logic, but explicitly cannot block connections |
| Threat intel feed verification | 🔶 STUBBED | Ed25519 key is all-zeros; signature checks will always fail |
| Sensor config hot-reload | ⚠️ PARTIAL | Watches file but only logs changes; no actual reload |

**Overall daemon verdict**: The daemon is substantially implemented with real, working code. The primary gaps are: (1) the threat intel feed verifier uses a dummy key, (2) the Guard REST API has no authentication, (3) the event router does not forward high-severity events to SLM/swarm for analysis, and (4) the behavioral engine is initialized but not actively used for OS/FS event analysis at the daemon level.

---

## Appendix B: IPC Protocol Audit

### B.1 Unix Socket IPC (JSON-line protocol)

| Message Type | Direction | Status | Notes |
|---|---|---|---|
| `"status"` | Client -> Daemon | ✅ Implemented | Returns live ProxyMetrics (total, allowed, blocked, prompted, logged) |
| `"reload"` | Client -> Daemon | ✅ Implemented | Triggers policy engine reload, returns ok/error |
| `"shutdown"` | Client -> Daemon | ✅ Implemented | Returns ack, sends SIGTERM to self for graceful shutdown |
| `GuardRegister` | Client -> Daemon | ✅ Implemented | Registers guard with permissions, returns guard_id |
| `GuardDeregister` | Client -> Daemon | ✅ Implemented | Deregisters guard by agent_name + pid |
| `GuardStatsQuery` | Client -> Daemon | ⚠️ Partial | Returns basic stats but blocked_details/anomaly_alerts/monitored_operations always empty |
| `GuardHealthCheck` | Client -> Daemon | ⚠️ Partial | Always returns Active regardless of actual state |
| Unknown command | Client -> Daemon | ✅ Implemented | Returns `{"error": "unknown command"}` |

### B.2 IPC Protocol Types (defined in clawdefender-core)

These types are defined in `clawdefender_core::ipc::protocol` and are serialization-tested:

| Type | Direction | Status | Notes |
|---|---|---|---|
| `DaemonRequest::ProxyRegister` | Client -> Daemon | ✅ Serialization tested | Registers a proxy instance |
| `DaemonRequest::Shutdown` | Client -> Daemon | ✅ Serialization tested | Request daemon shutdown |
| `DaemonRequest::PromptResponse` | Client -> Daemon | ✅ Serialization tested | User decision for prompted actions |
| `DaemonRequest::NetworkPolicyQuery` | Client -> Daemon | ✅ Serialization tested | Query network policy decision |
| `DaemonRequest::NetworkStatus` | Client -> Daemon | ✅ Serialization tested | Query network subsystem status |
| `DaemonResponse::StatusReport` | Daemon -> Client | ✅ Serialization tested | Returns all subsystem statuses |
| `DaemonResponse::Error` | Daemon -> Client | ✅ Serialization tested | Error response |
| `DaemonResponse::NetworkPolicyResult` | Daemon -> Client | ✅ Serialization tested | Network policy decision result |
| `DaemonResponse::NetworkStatusReport` | Daemon -> Client | ✅ Serialization tested | Network status with extension/filter/rules/mock info |

**Note**: The `DaemonRequest`/`DaemonResponse` types are defined and serialization-tested, but the Unix socket IPC handler (`ipc.rs`) only handles the simple string commands (`status`, `reload`, `shutdown`) and `GuardRequest` messages. The richer `DaemonRequest`/`DaemonResponse` protocol types are not yet handled by the IPC server. This suggests an incomplete migration from the simpler protocol to a structured one.

### B.3 Guard IPC Messages

| Message Type | Direction | Status | Notes |
|---|---|---|---|
| `GuardRequest::GuardRegister` | Client -> Daemon | ✅ Implemented | Full permission conversion, registry integration |
| `GuardRequest::GuardDeregister` | Client -> Daemon | ✅ Implemented | Lookup by agent_name + pid, deregister |
| `GuardRequest::GuardStatsQuery` | Client -> Daemon | ⚠️ Partial | Missing detailed blocked_details |
| `GuardRequest::GuardHealthCheck` | Client -> Daemon | ⚠️ Partial | Always Active |
| `GuardResponse::GuardRegistered` | Daemon -> Client | ✅ Implemented | Returns guard_id |
| `GuardResponse::GuardDeregistered` | Daemon -> Client | ✅ Implemented | Acknowledgement |
| `GuardResponse::GuardStatsResponse` | Daemon -> Client | ⚠️ Partial | Some fields hardcoded |
| `GuardResponse::GuardHealthResponse` | Daemon -> Client | ⚠️ Partial | Always Active |
| `GuardResponse::Error` | Daemon -> Client | ✅ Implemented | Error with message |
