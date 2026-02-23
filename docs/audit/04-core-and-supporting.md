# Section 4: Core & Supporting Crates Audit

**Auditor**: Agent 4 -- Core & Supporting Crates Auditor
**Date**: 2026-02-23
**Scope**: `clawdefender-core`, `clawdefender-sensor`, `clawdefender-swarm`, `clawdefender-guard`, `clawdefender-scanner`, `clawdefender-certify`, `clawdefender-mcp-server`, `clawdefender-tui`

---

## 4.1 clawdefender-core

**Description**: Core type system, policy engine, audit subsystem, behavioral baseline engine, event correlation, DNS filtering, network policy, and shared configuration types.

**Cargo.toml**: 12 dependencies including `rusqlite` (bundled SQLite), `regex`, `aho-corasick`, `glob`, `serde`, `chrono`, `uuid`. No async runtime dependency -- the core crate is runtime-agnostic.

### 4.1.1 Event System (`event/`)

**Status**: REAL IMPLEMENTATION -- production-quality.

- `Event` trait (`event/mod.rs`): A `Send + Sync` trait with `timestamp()`, `source()`, `severity()`, `to_audit_record()`, and `as_any()` for downcasting. Clean design.
- `McpEvent` (`event/mcp.rs`): Fully typed MCP events covering `ToolCall`, `ResourceRead`, `SamplingRequest`, `ListRequest`, `Notification`, `Other`. Each variant carries parsed fields (tool name, arguments, URI, etc.). Implements `Event` trait with severity classification (SamplingRequest = High, ToolCall = Medium, etc.).
- `OsEvent` (`event/os.rs`): Covers `Exec`, `Open`, `Close`, `Rename`, `Unlink`, `Connect`, `Fork`, `Exit`, `PtyGrant`, `SetMode`. Each carries relevant fields (pid, ppid, process_path, signing_id, team_id). Severity mapping is reasonable (Exec/Connect = Medium, Unlink = Medium, etc.).
- `CorrelatedEvent` (`event/correlation.rs`): Links MCP events to OS events with status `Matched`/`Uncorrelated`/`Pending`.
- `Severity` enum: 5 levels from `Info` to `Critical`, derives `Ord` for comparison.

**Assessment**: Solid, well-typed event system. No stubs. All event types are fully populated with fields needed for policy matching and audit logging.

### 4.1.2 Policy Engine (`policy/`)

**Status**: REAL IMPLEMENTATION -- production-quality with comprehensive tests.

- `PolicyEngine` trait: `evaluate(&dyn Event) -> PolicyAction`, `reload()`, `add_session_rule()`, `add_permanent_rule()`.
- `DefaultPolicyEngine`: Loads rules from TOML, sorts by priority, first-match-wins evaluation. Session rules take precedence over file rules.
- `PolicyAction`: `Allow`, `Block`, `Prompt(String)`, `Log`. Default when no rules match is `Log`.
- `MatchCriteria`: Supports `tool_names`, `resource_paths`, `methods`, `event_types` (all glob-pattern-capable), and `any` catch-all. AND logic for multiple criteria.
- `PolicyRule.matches()`: Thorough implementation with glob caching (thread-local `HashMap`), tilde expansion, path canonicalization.
- Path canonicalization (`matcher.rs:canonicalize_path`): Rejects null bytes, expands `~`, resolves symlinks via `std::fs::canonicalize`, resolves `.`/`..` segments, collapses repeated `/`, strips trailing `/`. This is a critical security feature preventing path traversal attacks like `/project/../etc/passwd`.
- `GlobMatcher`: Uses `require_literal_separator` so `*` doesn't cross directory boundaries.
- `RegexMatcher`: Has a 256KB size limit to prevent ReDoS.
- TOML parsing: Validates glob patterns at load time, rejects unknown actions.
- `add_permanent_rule()`: Serializes rule to TOML fragment and appends to disk file, then reloads in-memory rules.
- **15 unit tests** for the engine, **16 unit tests** for rule matching and parsing, **7 tests** for matcher/canonicalization, **3 performance benchmarks** (4-rule first match, 4-rule catch-all, 50-rule worst case with 100us target).

**Assessment**: Production-ready. Path canonicalization and symlink resolution are implemented. Glob caching is thread-local for thread-safety. No TOCTOU issues in policy evaluation. The `add_permanent_rule` has a minor risk of corrupting the TOML file on concurrent writes but this is a single-process operation.

### 4.1.3 Audit Subsystem (`audit/`)

**Status**: REAL IMPLEMENTATION -- production-quality with comprehensive tests.

- `AuditRecord`: 28-field struct covering all aspects of an event: timestamp, source, summary, details, rule matched, action taken, session ID, direction, server/client names, JSON-RPC method, tool name, arguments, classification, policy info, user decision, proxy latency, SLM analysis, swarm analysis, behavioral data, injection scan, threat intel, network connection. Uses `skip_serializing_if = "Option::is_none"` for optional fields.
- `AuditLogger` trait: `log()`, `query()`, `stats()`. Thread-safe (`Send + Sync`).
- `FileAuditLogger` (`audit/logger.rs`): Channel-based async writer on a dedicated thread. Buffered I/O with flush every 100 records or 1 second. Log rotation by file size (default 50MB). Retention cleanup (delete rotated files older than 30 days). Session tracking (start/end records with UUID). Concurrent-write safe via `mpsc::channel`. Drop impl logs session-end and joins writer thread.
- `AuditFilter`: Filter by time range, source, action, with limit.
- `AuditStats`: Aggregate stats with counts by action, by source, unique servers/tools, top blocked tools/paths.
- `query.rs`: Standalone query/aggregation functions that search current + rotated files. Supports since/until, server name, action, method filters.
- **20 unit tests** covering: write/read roundtrip, filtering by source/action/timestamp/limit, rotation, max files, concurrent writes, session start/end, 1000-record stress test, corrupt line handling, enhanced fields roundtrip, stats aggregation.

**Assessment**: Production-ready. The channel-based writer is a sound design for non-blocking audit logging. The `thread::sleep(20ms)` in query for flush propagation is a minor concern for tests but acceptable in production.

### 4.1.4 Behavioral Baseline Engine (`behavioral/`)

**Status**: REAL IMPLEMENTATION.

Modules:
- `anomaly.rs`: Anomaly scoring with dimensional analysis (tool usage, file access, network, temporal patterns).
- `decision.rs`: Decision engine with configurable thresholds, auto-blocking, calibration.
- `injection_detector.rs`: Prompt injection detection using pattern matching (Aho-Corasick + regex).
- `killchain.rs`: Attack pattern detection (kill chain analysis).
- `learning.rs`: Learning phase engine with event/time thresholds.
- `persistence.rs`: SQLite-backed profile storage.
- `profile.rs`: Server, tool, file, network, and temporal profiles.
- `update.rs`: Profile updater using exponential moving averages.

**Assessment**: Substantial real implementation. The behavioral system has learning, detection, and persistence layers. Not a stub.

### 4.1.5 Event Correlation (`correlation/`)

**Status**: REAL IMPLEMENTATION.

- `CorrelationEngine`: Links MCP events to OS events by PID matching (direct + child process). Time-window-based correlation. Caps at 10,000 pending correlations with LRU eviction. Flush for clean shutdown. Lifetime statistics.
- **13 unit tests** covering: matched, uncorrelated, multiple OS events, direct/child PID match, concurrent MCP events, flush, time window, stats, unique IDs.

**Assessment**: Production-ready. The PID-based correlation is a sound approach for linking MCP tool calls to their OS-level side effects.

### 4.1.6 Configuration (`config/`)

**Status**: REAL IMPLEMENTATION.

- `ClawConfig`: 18+ configurable sections covering daemon socket, audit log, log rotation, eslogger, SLM, API keys, swarm, UI, telemetry, policy, sensor, MCP server, behavioral, injection detector, guard API, threat intel, network policy.
- `SensorConfig`: Separate sensor config with eslogger, fsevents, correlation, process tree sections.
- All sections have sensible defaults. TOML parsing with `serde`. Falls back to defaults when file doesn't exist.

**Assessment**: Comprehensive and well-structured configuration system.

### 4.1.7 Other Modules

- `rate_limit.rs`: Prompt rate limiter preventing prompt fatigue attacks. Per-server counters with configurable window. Once blocked, stays blocked for session. **8 unit tests**.
- `ipc/protocol.rs`: Unix domain socket IPC with `UiRequest`/`UiResponse`/`UserDecision` types.
- `dns/`: DNS filtering, caching, exfiltration detection, domain intelligence. 5 source files.
- `network_policy/`: Network policy engine with rules, rate limiter. 4 source files + security tests.
- `network_log.rs`: Network connection logging types.

---

## 4.2 clawdefender-sensor

**Description**: OS-level sensors for process and filesystem monitoring on macOS.

**Cargo.toml**: Depends on `clawdefender-core`, `tokio`, `nix` (process/signal), `notify` (fs watcher), `sysinfo`, `futures`, `unicode-normalization`.

### 4.2.1 SensorManager

**Status**: REAL IMPLEMENTATION.

- Unified manager combining eslogger, process tree, and filesystem watcher.
- `start()`: Creates an `mpsc::channel`, starts FsWatcher on given paths, spawns async task to convert `FsEvent` -> `OsEvent`, refreshes process tree.
- `is_agent(pid)`: Checks process tree for known AI agent processes.

### 4.2.2 Eslogger Integration (`eslogger/`)

- `parser.rs`: Parses eslogger JSON output into typed events.
- `process.rs`: `EsloggerManager` -- manages the `eslogger` child process on macOS.
- `filter.rs`: `EventPreFilter` for excluding noisy processes/paths before processing.
- `types.rs`: `EsloggerEvent`, `EsloggerProcess` types with path sanitization.

### 4.2.3 Other Modules

- `fsevents/`: FSEvents watcher with debouncing, path classification (sensitivity tiers), eslogger correlation.
- `proctree/`: Process tree tracking with agent identification. `AgentInfo` and `Confidence` types.
- `correlation/`: Sensor-level correlation engine with severity classification and rules.
- `limits.rs`: Resource monitoring and limits.

**Tests**: `evasion_tests.rs` and `sensor_integration_tests.rs`.

**Assessment**: Real implementation. The macOS-specific eslogger integration is the core value proposition. The sensor pipeline (eslogger -> parser -> filter -> event -> channel -> daemon) is fully wired.

---

## 4.3 clawdefender-swarm

**Description**: Multi-agent swarm coordination for cloud-based AI risk analysis.

**Cargo.toml**: Depends on `reqwest` (HTTP), `sha2`/`hex` (hashing), `rusqlite` (cost tracking), `axum`/`tower` (chat server), `security-framework` (macOS keychain).

### 4.3.1 Commander (`commander.rs`)

**Status**: REAL IMPLEMENTATION.

- Dispatches to 3 specialist agents (Hawk, Forensics, Internal Affairs) in parallel.
- Each specialist gets a tailored prompt built from event data.
- Results are synthesized using rule-based logic:
  - Any CRITICAL -> final CRITICAL
  - 2+ HIGH -> final HIGH
  - 1 HIGH with others LOW/MEDIUM -> downgraded to MEDIUM (single dissent)
  - Otherwise: median risk level
- Cost tracking per specialist call with `CostTracker` (SQLite-backed).
- Default model: `claude-sonnet-4-20250514`.
- Overall timeout: 10 seconds. Fallback responses on timeout/error.
- **13 unit tests** covering synthesis logic and integration with mock LLM client.

### 4.3.2 Other Modules

- `llm_client.rs`: `LlmClient` trait with `complete()` method. `MockLlmClient` for testing. Real HTTP client for production.
- `keychain.rs`: macOS Keychain integration for API key storage. `security-framework` crate.
- `cost.rs`: `CostTracker` with SQLite persistence, `PricingTable`, `BudgetConfig` (daily/monthly limits).
- `data_minimizer.rs`: Strips PII from event data before sending to cloud.
- `output_sanitizer.rs`: Sanitizes LLM output before displaying to user.
- `audit_hasher.rs`: Hashes audit records for integrity verification.
- `chat.rs` + `chat_server.rs`: Interactive chat interface using axum.
- `prompts.rs`: Specialist prompt templates and response parsing.

**Tests**: `e2e_pipeline_tests.rs`, `security_tests.rs`.

**Assessment**: Production-ready. The swarm is advisory-only (explicitly documented in code: "SAFETY: Swarm verdict is advisory only. Never modifies policy decisions."). The synthesis logic is conservative (single dissent downgrades). Cost tracking with budget limits is a nice production feature.

---

## 4.4 clawdefender-guard

**Description**: Agent self-protection guard -- a Rust SDK for AI agents to declare permissions and enforce them.

**Cargo.toml**: Depends on `hyper`/`http-body-util`/`hyper-util` (HTTP server), `sha2`, `dirs`, `semver`, `libc`.

### 4.4.1 AgentGuard (`guard.rs`)

**Status**: REAL IMPLEMENTATION.

- Builder pattern: `GuardBuilder::new(name).permissions(...).mode(...).build()`.
- Two modes: `Enforce` (blocks disallowed actions) and `Monitor` (logs but allows).
- `activate()`: Tries daemon connection, falls back to embedded `FallbackEngine`. Runs self-test.
- `check_action(tool, target) -> ActionResult`: Evaluates against `FallbackEngine` with `PermissionSet`. Returns `Allow`, `Block(reason)`, or `Monitored`.
- `suggest_permissions()`: Analyzes monitored operations and suggests minimal permission set.
- Stats tracking: operations allowed/blocked, blocked details with timestamps.
- Drop impl calls `deactivate()`.

### 4.4.2 Other Modules

- `api.rs` + `api_auth.rs`: HTTP REST API for guard management with authentication.
- `connection.rs`: Daemon connection management.
- `fallback.rs`: `FallbackEngine` -- embedded permission checking without daemon.
- `installer/`: MCP guard installer with platform detection, version management, download.
- `openapi.rs`: OpenAPI spec generation.
- `policy_gen.rs`: Generates policy TOML from declared permissions.
- `registry.rs`: Agent registration tracking.
- `selftest.rs`: Self-test to verify enforcement works.
- `types.rs`: `PermissionSet`, `ShellPolicy`, `NetworkPolicy`, `GuardMode`, etc.
- `webhooks.rs`: Webhook integration for notifications.

**Tests**: `api_tests.rs`, `guard_tests.rs`, `installer_tests.rs`, `integration_tests.rs`, `perf_tests.rs`, `security_tests.rs` (6 test files).

**Assessment**: Production-ready. The guard SDK provides a clean API for agent developers. The dual mode (enforce/monitor) is good for gradual adoption. The `suggest_permissions()` feature for generating minimal permissions from monitoring data is clever. Note: daemon communication (`GuardRegister`/`GuardDeregister`) is stubbed with comments "In a full implementation, we'd send..." -- the core permission checking works via the embedded `FallbackEngine`.

---

## 4.5 clawdefender-scanner

**Description**: Security scanner framework with sandbox and attack modules for MCP servers.

**Cargo.toml**: Depends on `tempfile`, `async-trait`, `libc`, `rand`.

### 4.5.1 Scanner (`scanner.rs`)

**Status**: REAL IMPLEMENTATION.

- `Scanner`: Modular design with pluggable `ScanModule` trait.
- 6 default modules:
  1. `PathTraversalModule`: Tests for path traversal vulnerabilities.
  2. `PromptInjectionModule`: Tests for prompt injection attacks.
  3. `ExfiltrationModule`: Tests for data exfiltration.
  4. `CapabilityEscalationModule`: Tests for capability escalation.
  5. `DependencyAuditModule`: Audits dependencies.
  6. `FuzzingModule`: Fuzz testing.
- `ScanClient`: Starts MCP server process, initializes, discovers tools/resources.
- `Sandbox`: Isolates scanner operations with controlled env vars.
- `EvidenceCollector`: Collects OS events, files, network connections, canary detection.
- `Finding`: Rich finding type with `Severity`, `CVSS`, `Category`, evidence, reproduction steps.
- Post-processing: `deduplicate_findings()`, `correlate_findings()`, `compute_delta()` (baseline comparison), `exit_code_for_findings()` (CI/CD integration).

**Tests**: `scanner_tests.rs`, `integration_tests.rs`.

**Assessment**: Production-ready. The scanner follows established security scanner patterns with modular architecture, evidence collection, baseline comparison, and CI/CD exit codes. Finding deduplication and cross-referencing are nice touches.

---

## 4.6 clawdefender-certify

**Description**: "Claw Compliant" certification harness -- tests MCP servers for compliance with ClawDefender.

**Cargo.toml**: Minimal dependencies (core, tokio, serde, tracing, chrono, uuid, toml).

### 4.6.1 CertificationRunner

**Status**: REAL IMPLEMENTATION.

- 3 certification levels:
  - **Level 1 (Transparent)**: Server survives ClawDefender proxy behavior (blocking, delays).
  - **Level 2 (Cooperative)**: Server integrates with ClawDefender SDK (guard).
  - **Level 3 (Proactive)**: Server declares security posture via manifest.
- `McpHarness`: Manages MCP server child process over stdio JSON-RPC. Full request/response with timeout, notifications, tool calls.
- Report generation in JSON and text format.
- `compute_overall_level()`: Returns highest level that passes (0-3).

### 4.6.2 McpHarness (`harness.rs`)

**Status**: REAL IMPLEMENTATION.

- Starts child process with piped stdin/stdout/stderr.
- Channel-based async I/O for stdin/stdout.
- JSON-RPC request/response with ID matching.
- Methods: `initialize()`, `list_tools()`, `call_tool()`, `send_notification()`, `send_raw()`, `shutdown()`.
- Timeouts on all operations (15s default).

**Tests**: `certification_tests.rs`.

**Assessment**: Production-ready. The certification framework provides a concrete way for MCP server developers to verify compliance. The three-level model (transparent/cooperative/proactive) is well-designed.

---

## 4.7 clawdefender-mcp-server

**Description**: An MCP server that other MCP servers or agents can call to declare intent, request permission, and report actions.

**Cargo.toml**: Depends on `axum` (HTTP), `rand`, `hex`, `dirs`.

### 4.7.1 McpServer

**Status**: REAL IMPLEMENTATION.

- `McpServer`: Holds policy engine, audit logger, server info, and 3 rate limiters.
- Rate limiting:
  - Permission requests: 10/60s per server (prompt flooding prevention).
  - checkIntent: 100/60s per caller.
  - reportAction: 1000/60s per server.
- Transport: stdio and HTTP (axum).
- Authentication: optional token-based HTTP auth.

### 4.7.2 Tools (`tools.rs`)

**Status**: REAL IMPLEMENTATION.

4 tools:
1. **checkIntent**: Builds synthetic MCP event, evaluates against policy, returns allowed/risk/explanation/suggestions. Does not perform the action.
2. **requestPermission**: Evaluates against policy. If allowed with session scope, creates a session rule for future checks. If Prompt, currently denies (UI integration pending).
3. **reportAction**: Records after-the-fact audit entry for actions already performed.
4. **getPolicy**: Queries policy engine for matching rules.

**Security notes**:
- `requestPermission` session rules use exact paths (no wildcards): "SECURITY: The rule uses the exact resource path requested -- no wildcards."
- Input validation referenced: "The resource has already been validated by validate_resource_path_exact() in the protocol handler."

### 4.7.3 Other Modules

- `auth.rs`: HTTP authentication.
- `protocol.rs`: JSON-RPC protocol handling.
- `suggestions.rs`: Suggests alternatives when actions are blocked.
- `transport/stdio.rs` + `transport/http.rs`: Dual transport support.
- `types.rs`: Request/response types, action types, risk levels.
- `validation.rs`: Input validation for all tool parameters.

**Tests**: `mcp_server_integration_tests.rs`, `sdk_flow_tests.rs`, `security_tests.rs`, `bench_tests.rs`.

**Assessment**: Production-ready. The MCP server inverts the security model from adversarial monitoring to cooperative participation. The rate limiting is well-configured. The session rule creation in `requestPermission` is carefully scoped (exact paths only).

---

## Summary Table

| Crate | Status | Lines (est.) | Test Files | Real vs Stub |
|-------|--------|-------------|------------|--------------|
| clawdefender-core | Production | ~4,500 | 7 | 100% Real |
| clawdefender-sensor | Production | ~2,000 | 2 | 100% Real |
| clawdefender-swarm | Production | ~1,800 | 2 | 100% Real |
| clawdefender-guard | Production | ~2,200 | 6 | ~95% Real (daemon comms stubbed) |
| clawdefender-scanner | Production | ~1,500 | 2 | 100% Real |
| clawdefender-certify | Production | ~800 | 1 | 100% Real |
| clawdefender-mcp-server | Production | ~1,200 | 4 | ~95% Real (UI prompt pending) |
| clawdefender-tui | Production | ~1,180 | 0 (inline) | 100% Real |

---

## 4.8 clawdefender-tui

**Description**: Terminal UI for ClawDefender interactive prompts, event monitoring dashboard, and headless mode.

**Cargo.toml**: Depends on `clawdefender-core`, `clawdefender-swarm`, `ratatui`, `crossterm`, `tokio`, `chrono`, `serde_json`.

**Source files**: `lib.rs` (~1,180 lines), `prompt.rs` (~192 lines).

### 4.8.1 TUI Dashboard (`lib.rs`)

**Status**: REAL IMPLEMENTATION -- production-quality with extensive tests.

- **Layout**: Header (status bar) + Pending Approvals panel + Event Log + Footer (keybindings).
- **UiMode**: `Normal`, `PromptFocused`, `LogViewing` -- tab-switchable focus.
- **TuiState**: Owns all state directly (no shared locks). Receives prompts and events via `tokio::sync::mpsc` channels.
- **Event log**: Capped at 200 events with FIFO eviction. Scrollable with j/k or Up/Down keys. Auto-scroll disabled when user scrolls manually.
- **Status bar**: Shows uptime, total events, blocked count, active server count, SLM status (model name + avg latency), Swarm status (active/disabled).
- **Prompt panel**: Displays up to 3 pending prompts with countdown timer. Shows:
  - Server name, tool name, arguments (truncated to 60 chars)
  - Policy rule and message
  - SLM enrichment (risk level with color coding, confidence %, explanation) or "Analyzing..." spinner
  - Swarm enrichment (risk level, recommended action, explanation)
  - Decision keys: [A]llow once, [S]ession, [P]olicy, [D]eny, [C]hat
- **Keybindings**: q/Ctrl+C quit, Tab toggle focus, Up/Down navigate prompts, a/s/p/d/c for decisions.
- **Headless mode** (`run_headless`): Auto-denies all prompted requests when no TTY is available.

### 4.8.2 Prompt System (`prompt.rs`)

**Status**: REAL IMPLEMENTATION.

- `PendingPrompt`: Carries a `tokio::sync::oneshot::Sender<UserDecision>` so the proxy/daemon can `await` the user's decision without polling.
- `SlmEnrichment`: risk_level, explanation, confidence.
- `SwarmEnrichment`: risk_level, explanation, recommended_action, specialist_summaries. Marked "SAFETY: advisory only."
- Timeout with auto-deny: `is_expired()` checks elapsed time, `expire_prompts()` auto-denies timed-out prompts.
- `resolve()`: Consumes the oneshot sender. Second call returns false (idempotent).

### 4.8.3 Tests

**30+ inline unit tests** covering:
- State defaults, event cap at MAX_EVENTS (200), prompt mode switching
- Prompt navigation (next/prev/wrap-around), resolve by index, resolve middle, resolve last resets mode
- Prompt expiration with auto-deny, timeout auto-deny
- Scroll up/down with bounds checking, user_scrolled flag
- Key handling (quit, Ctrl+C, prompt decisions a/s/p/d), toggle focus
- SLM enrichment apply (existing and nonexistent prompt)
- Noise-filtered prompts (no spinner), events with risk levels
- Headless auto-deny integration test
- Format uptime, stats defaults

**Assessment**: Production-ready. The TUI is well-structured with clean separation of state, rendering, and input handling. The oneshot channel pattern for prompt responses is sound -- no polling or shared state. The headless mode is a good fallback for CI/CD or non-interactive environments.

## Key Findings

### Strengths

1. **Type-safe event system**: All events are strongly typed with proper `Serialize`/`Deserialize` and `Event` trait implementations.
2. **Path traversal protection**: Canonicalization with symlink resolution, null byte rejection, and `..` resolution before policy matching.
3. **ReDoS protection**: Regex matchers have 256KB size limits.
4. **Prompt fatigue protection**: Rate limiter blocks servers that flood with prompt-triggering calls.
5. **Advisory-only AI analysis**: Both SLM and swarm verdicts are explicitly advisory -- they enrich audit logs but never modify policy decisions.
6. **Comprehensive audit logging**: Every event is recorded with full context. Channel-based async writer prevents blocking. Log rotation and retention cleanup.
7. **Cost controls**: Cloud swarm has daily/monthly budget limits with SQLite-backed cost tracking.
8. **Data minimization**: PII stripping before sending to cloud providers.
9. **Extensive test coverage**: All crates have unit and integration tests. Security-focused tests exist for core, guard, scanner, swarm, and MCP server.

### Concerns

1. **Guard daemon communication**: The `activate()` method notes "In a full implementation, we'd send GuardRegister here." The fallback engine works, but daemon-connected mode doesn't send policy to the daemon.
2. **requestPermission UI integration**: When policy says `Prompt`, the MCP server currently denies the request instead of forwarding to the user. This is noted in code.
3. **Thread-local glob cache**: Glob patterns are cached per-thread, not globally. In a multi-threaded scenario, patterns are recompiled per thread. This is correct but not maximally efficient.
4. **query() flush timing**: `thread::sleep(20ms)` in audit query to wait for writer flush is a timing-based synchronization. Could use a condition variable or oneshot channel for guaranteed flush completion.
5. **FallbackEngine recreation**: `check_action()` in `guard.rs` creates a new `FallbackEngine` on every call. Could be cached.

### Security Notes

- Path canonicalization prevents TOCTOU path traversal.
- Glob matching uses `require_literal_separator` to prevent overly broad `*` matches.
- Session rules from `requestPermission` use exact paths only -- no glob expansion.
- Rate limiters protect against prompt flooding, intent flooding, and report flooding.
- All AI analysis (SLM + swarm) is advisory-only with explicit safety comments in code.
