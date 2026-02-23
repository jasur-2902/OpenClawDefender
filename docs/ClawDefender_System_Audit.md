# ClawDefender System Audit

## Date: 2026-02-23
## Audited by: 10 AI agents (workspace, daemon, mcp-proxy, core, slm, tauri-commands, frontend, config, build-test, synthesis)

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total crates | 16 (15 workspace members + 1 excluded Tauri app) |
| Total binaries | 9 (daemon, proxy, CLI, Tauri app, mock-mcp-server, mock-eslogger, 3 fuzz targets) |
| Total GUI pages | 12 (Dashboard, Settings, Onboarding, AuditLog, Behavioral, Guards, NetworkLog, PolicyEditor, Scanner, SystemHealth, ThreatIntel, Timeline) |
| Total Tauri commands | 75 |
| Total Rust LoC | ~92,984 (source) + ~15,231 (tests) |
| Total test functions | ~1,596 Rust `#[test]` + SDK tests (Python, TypeScript) |
| Fully functional | ~82% |
| Stubbed/mock | ~6% |
| Partial | ~10% |
| Missing/not started | ~2% (Network Extension integration, some daemon-connected guard comms) |
| Broken | 0% |

**Narrative Summary:** ClawDefender is a substantially real, production-approaching security system for monitoring and controlling MCP (Model Context Protocol) AI agent tool use. The core proxy pipeline -- JSON-RPC interception, policy evaluation, audit logging, and user prompting -- is fully implemented and production-quality. The behavioral analysis engine, threat intelligence system, SLM integration, and cloud swarm analysis are all real implementations with meaningful logic. The Tauri GUI is functional with 84% of commands being fully real.

The primary gaps are: (1) several placeholder security values (all-zeros Ed25519 key, empty updater pubkey, empty Guard API auth token), (2) the macOS Network Extension is not integrated (mock only), (3) some frontend UI controls are local-only state without backend persistence, and (4) feed data contains synthetic test entries. No crates are dead or broken. Zero `todo!()` or `unimplemented!()` macros exist in the codebase.

---

## 1. Workspace Structure

### 1.1 Root Configuration

- **Resolver:** 2
- **Members:** 15 crates (+ 1 excluded Tauri app)
- **Release profile:** LTO=fat, codegen-units=1, strip=true, opt-level="z", panic=abort
- **Edition:** 2021
- **License:** Apache-2.0 OR MIT

### 1.2 Crate Inventory

| Crate | Path | Type | LoC (src) | LoC (tests) | Classification |
|-------|------|------|-----------|-------------|----------------|
| clawdefender-core | `crates/clawdefender-core` | Library | 20,216 | 4,685 | ✅ REAL |
| clawdefender-scanner | `crates/clawdefender-scanner` | Library | 8,711 | 827 | ✅ REAL |
| clawdefender-app (Tauri) | `clients/clawdefender-app/src-tauri` | App | 8,382 | 0 | ✅ REAL |
| clawdefender-threat-intel | `crates/clawdefender-threat-intel` | Library | 7,304 | 0 (inline) | ✅ REAL |
| clawdefender-guard | `crates/clawdefender-guard` | Library | 7,272 | 3,521 | ✅ REAL |
| clawdefender-slm | `crates/clawdefender-slm` | Library | 6,497 | 839 | ✅ REAL |
| clawdefender-cli | `clients/clawdefender-cli` | Binary | 6,190 | 0 | ✅ REAL |
| clawdefender-sensor | `crates/clawdefender-sensor` | Library | 6,041 | 974 | ✅ REAL |
| clawdefender-swarm | `crates/clawdefender-swarm` | Library | 5,017 | 746 | ✅ REAL |
| clawdefender-mcp-proxy | `crates/clawdefender-mcp-proxy` | Lib+Binary | 4,961 | 574 | ✅ REAL |
| clawdefender-daemon | `crates/clawdefender-daemon` | Lib+Binary | 4,473 | 992 | ✅ REAL |
| clawdefender-mcp-server | `crates/clawdefender-mcp-server` | Library | 3,887 | 1,664 | ✅ REAL |
| clawdefender-certify | `crates/clawdefender-certify` | Library | 1,837 | 409 | ✅ REAL |
| clawdefender-tui | `crates/clawdefender-tui` | Library | 1,369 | 0 | ✅ REAL |
| mock-mcp-server | `tests/mock-mcp-server` | Binary | 264 | 0 | ✅ REAL (test) |
| mock-eslogger | `tests/mock-eslogger` | Binary | 309 | 0 | ✅ REAL (test) |

**All 16 crates are REAL implementations. No stubs, no skeletons.**

### 1.3 Non-Rust Components

| Component | Path | Language | LoC |
|-----------|------|----------|-----|
| macOS Network Extension | `extensions/clawdefender-network` | Swift | 1,434 |
| Python SDK | `sdks/python/` | Python | 1,159 |
| Python Agent SDK | `sdks/python-agent/` | Python | 1,185 |
| TypeScript SDK | `sdks/typescript/` | TypeScript | 1,016 |
| TypeScript Agent SDK | `sdks/typescript-agent/` | TypeScript | 1,161 |
| GUI Frontend | `clients/clawdefender-app/src/` | React/TypeScript | ~5,000+ |

### 1.4 Inter-Crate Dependency Map

```
clawdefender-core  <--  ALL workspace crates except threat-intel (foundation)

clawdefender-threat-intel  <--  daemon, mcp-proxy, CLI (standalone)

clawdefender-slm       <--  daemon, mcp-proxy, CLI, Tauri app
clawdefender-swarm     <--  daemon, mcp-proxy, tui, CLI
clawdefender-sensor    <--  daemon, fuzz
clawdefender-mcp-proxy <--  daemon, CLI, fuzz
clawdefender-tui       <--  daemon
clawdefender-mcp-server <-- daemon, CLI
clawdefender-guard     <--  daemon
clawdefender-certify   <--  CLI
clawdefender-scanner   <--  CLI

Top-level consumers:
  - daemon (9 workspace deps -- central hub)
  - CLI (8 workspace deps -- CLI frontend)
  - Tauri app (1 workspace dep: slm only -- significant logic duplication)
```

---

## 2. Daemon

The daemon (`clawdefender-daemon`) is the central orchestrator, tying together sensors, proxy, policy engine, behavioral analysis, threat intelligence, network policy, guard registry, SLM, swarm analysis, TUI, and IPC.

### Classification Summary

| Component | Status | Notes |
|-----------|--------|-------|
| Startup/initialization | ✅ REAL | All subsystems initialized from config |
| Standalone mode (`run`) | ✅ REAL | IPC, sensors, audit, guard, signal handling |
| Proxy mode (`run_proxy`) | ✅ REAL | Full MCP proxy with SLM + swarm + threat intel |
| IPC server | ✅ REAL | 5 command types over Unix domain socket |
| Signal handling | ✅ REAL | SIGTERM + SIGINT with graceful shutdown |
| Config loading | ✅ REAL | TOML-based with hot-reload for policy |
| Policy hot-reload | ✅ REAL | File watcher with 200ms debounce |
| Sensor subsystem | ✅ REAL | Process tree, eslogger, FSEvents, correlation |
| Event routing | ⚠️ PARTIAL | Routes to audit + UI, but SLM/swarm escalation only logs |
| Behavioral engine | ⚠️ PARTIAL | Fully initialized but not integrated into runtime OS event processing |
| Guard system | ✅ REAL | Full lifecycle, but REST API lacks authentication |
| Mock network extension | ✅ REAL | Full evaluation logic, cannot actually block connections |
| Threat intel feed verification | 🔶 STUBBED | Ed25519 key is all-zeros |
| Sensor config hot-reload | ⚠️ PARTIAL | Watches file but only logs, no actual reload |

### Critical Issues

| Location | Issue | Severity |
|----------|-------|----------|
| `lib.rs:262-270` | Ed25519 verifier key is all-zeros -- feed signature verification always fails | HIGH |
| `lib.rs:657` | Guard API `token: String::new()` -- REST API has no authentication | HIGH |
| `event_router.rs:67-74` | High-severity escalation only logs, does not route to SLM/swarm | MEDIUM |
| `lib.rs:571-575` | Sensor config watcher only logs changes, no actual reload | LOW |

**UPDATE (Phase A fix):** The event pipeline break has been resolved. Session-start/session-end
records now include server_name and source from the proxy. The FileAuditLogger accepts
optional metadata (server_name, source_name) via `with_metadata()`. Tool-call events
have always been correctly enriched -- they were not appearing because no tool calls
had been made through the proxy during testing.

---

## 3. MCP Proxy

The MCP proxy (`clawdefender-mcp-proxy`) is the most critical security component. It sits between MCP clients and servers, intercepting every JSON-RPC message.

### Architecture

1. **Stdio proxy** (`stdio.rs`, 1580+ lines): Spawns child MCP server, bidirectional relay with classification -> policy -> forward/block pipeline
2. **HTTP proxy** (`http.rs`): Axum-based reverse proxy with SSE relay + JSON-RPC interception
3. **JSON-RPC parser**: Spec-compliant with 10MB message limit, 128-depth limit, 20MB buffer limit
4. **Classifier**: Pass (initialize, ping, notifications), Log (list operations), Review (tools/call, resources/read, sampling), Block (reserved)

### Key Capabilities

- ✅ REAL: Full JSON-RPC 2.0 interception and classification
- ✅ REAL: Policy evaluation with Allow/Block/Prompt/Log actions
- ✅ REAL: User prompting via UI bridge with timeout and flood protection
- ✅ REAL: Dynamic session rules from user decisions
- ✅ REAL: Advisory-only SLM analysis (never influences policy)
- ✅ REAL: Advisory-only swarm escalation (never influences policy)
- ✅ REAL: Threat intel IoC matching on reviewed events
- ✅ REAL: Enriched audit records with risk classification
- ✅ REAL: Raw byte forwarding preserves exact message formatting
- ✅ REAL: Symlink check on audit log path

### Security Hardening

- JSON depth limits prevent stack overflow
- Message size limits prevent OOM
- Buffer overflow protection
- Pending prompt count limit prevents prompt flooding
- Block responses use standard JSON-RPC error code -32001
- No-UI-bridge fallback: allows with warning (security trade-off, documented)

**43 functions audited: 43 REAL, 0 PARTIAL, 0 STUBBED, 0 MISSING, 0 BROKEN**

---

## 4. Core Library

The core crate (`clawdefender-core`, 20,216 LoC) is the foundation, providing:

### Event System (✅ REAL)
- `Event` trait with `McpEvent`, `OsEvent`, `CorrelatedEvent`
- MCP events: ToolCall, ResourceRead, SamplingRequest, ListRequest, Notification, Other
- OS events: Exec, Open, Close, Rename, Unlink, Connect, Fork, Exit, PtyGrant, SetMode

### Policy Engine (✅ REAL)
- First-match-wins evaluation with session rules taking precedence
- Glob and regex matching with path canonicalization (symlink resolution, null byte rejection, `..` resolution)
- Thread-local glob cache, 256KB regex size limit (ReDoS prevention)
- TOML-based with hot-reload and permanent rule append-to-disk

### Behavioral Baseline Engine (✅ REAL)
- Anomaly scoring with dimensional analysis (tool usage, file access, network, temporal patterns)
- Kill chain detection, prompt injection detection (Aho-Corasick + regex)
- Learning phase engine with event/time thresholds
- SQLite-backed profile persistence with exponential moving averages

### Audit Subsystem (✅ REAL)
- 28-field `AuditRecord` with skip_serializing_if for optional fields
- Channel-based async writer (flush every 100 records or 1 second)
- Log rotation by size (default 50MB), retention cleanup (30 days)
- Query/aggregation functions across current + rotated files

### Other Modules (✅ REAL)
- Correlation engine: PID-based MCP-to-OS event linking (10K cap with LRU eviction)
- DNS filtering and exfiltration detection
- Network policy engine with rate limiting
- Prompt rate limiter preventing prompt fatigue attacks
- Comprehensive configuration system (18+ sections)

---

## 5. SLM Engine

The SLM crate (`clawdefender-slm`, 6,497 LoC) provides small-language-model inference for security analysis.

### Backends

| Backend | Status | Notes |
|---------|--------|-------|
| GGUF (llama.cpp) | ✅ REAL | `llama_cpp` integration, GPU support, symlink rejection, `spawn_blocking` |
| Cloud (Anthropic/OpenAI/Google) | ✅ REAL | Real HTTP API calls, proper auth, token tracking |
| Mock | ✅ REAL (test utility) | Clean separation, only used when no real backend available |

### Feature Flags (only crate with feature flags)

| Flag | Purpose | Enabled By |
|------|---------|-----------|
| `gguf` | Local GGUF inference via llama_cpp | **Nobody** (dead code in all builds) |
| `cloud` | Cloud API backends via reqwest | Tauri app only |
| `download` | Model downloading with SHA-256 verification | Tauri app only |

### Key Capabilities
- ✅ REAL: Model registry with 5 GGUF models (HuggingFace URLs valid)
- ✅ REAL: Full download system with resume, cancellation, disk space check, HTTPS-only
- ✅ REAL: Prompt injection prevention (truncation, XML stripping, 9 pattern filters, nonce delimiters, canary tokens)
- ✅ REAL: Output validation (echo attack detection, injection artifact detection)
- ✅ REAL: Noise filtering with 5 built-in profiles + custom TOML rules
- ⚠️ PARTIAL: Model hot-swapping (config persists, no live swap mechanism)

### Issues
- 🔶 SHA-256 checksums for model files are all-zeros (placeholder) -- verification skipped
- `gguf` feature is defined but never enabled by any consumer

---

## 6. macOS Sensor

The sensor crate (`clawdefender-sensor`, 6,041 LoC) provides OS-level monitoring on macOS.

### Components

| Component | Status | Notes |
|-----------|--------|-------|
| EsloggerManager | ✅ REAL | Manages eslogger child process, parses JSON output |
| EventPreFilter | ✅ REAL | Excludes noisy processes/paths before processing |
| FSEvents watcher | ✅ REAL | Debouncing, path classification (sensitivity tiers) |
| Process tree | ✅ REAL | Agent identification with confidence scoring |
| Correlation engine | ✅ REAL | Sensor-level correlation with severity classification |
| SensorManager | ✅ REAL | Unified manager combining all subsystems |

The sensor pipeline (eslogger -> parser -> filter -> event -> channel -> daemon) is fully wired and functional.

---

## 7. Cloud Swarm

The swarm crate (`clawdefender-swarm`, 5,017 LoC) provides multi-agent cloud AI risk analysis.

### Architecture
- 3 specialist agents (Hawk, Forensics, Internal Affairs) dispatched in parallel
- Conservative synthesis: any CRITICAL -> CRITICAL, 2+ HIGH -> HIGH, single dissent downgrades
- 10-second overall timeout with fallback responses
- **SAFETY: Advisory-only** -- explicitly never modifies policy decisions

### Key Features
- ✅ REAL: LLM client with HTTP requests to cloud providers
- ✅ REAL: macOS Keychain integration for API key storage
- ✅ REAL: SQLite-backed cost tracking with daily/monthly budget limits
- ✅ REAL: Data minimization (PII stripping) before cloud transmission
- ✅ REAL: Output sanitization of LLM responses
- ✅ REAL: Interactive chat interface via axum

---

## 8. SDK (Not a Separate Crate)

SDKs are non-Rust packages in `sdks/`:

| SDK | Language | LoC | Purpose |
|-----|----------|-----|---------|
| Python SDK | Python | 1,159 | MCP proxy client for server developers |
| Python Agent SDK | Python | 1,185 | Agent guard integration |
| TypeScript SDK | TypeScript | 1,016 | MCP proxy client |
| TypeScript Agent SDK | TypeScript | 1,161 | Agent guard integration |

All SDKs have test suites but are **not wired into CI pipelines**.

---

## 9. Scanner, Guard, Certify, TUI, MCP Server

### Scanner (`clawdefender-scanner`, 8,711 LoC) -- ✅ REAL
- 6 pluggable scan modules: PathTraversal, PromptInjection, Exfiltration, CapabilityEscalation, DependencyAudit, Fuzzing
- Evidence collection, finding deduplication, baseline comparison, CI/CD exit codes

### Guard (`clawdefender-guard`, 7,272 LoC) -- ✅ REAL
- Builder pattern API for agent developers
- Enforce/Monitor dual mode
- Embedded FallbackEngine for standalone operation
- `suggest_permissions()` from monitoring data
- ⚠️ PARTIAL: Daemon communication stubbed ("In a full implementation, we'd send GuardRegister here")

### Certify (`clawdefender-certify`, 1,837 LoC) -- ✅ REAL
- 3 certification levels: Transparent, Cooperative, Proactive
- Full MCP harness with JSON-RPC request/response
- Report generation in JSON and text format

### TUI (`clawdefender-tui`, 1,369 LoC) -- ✅ REAL
- Ratatui-based dashboard: header, pending approvals, event log, footer
- Oneshot channel pattern for prompt responses (no polling)
- Headless mode with auto-deny for CI/CD
- 30+ inline unit tests

### MCP Server (`clawdefender-mcp-server`, 3,887 LoC) -- ✅ REAL
- 4 tools: checkIntent, requestPermission, reportAction, getPolicy
- Three-tier rate limiting (permission 10/60s, intent 100/60s, report 1000/60s)
- Constant-time token comparison, 256-bit random token generation
- Input validation: null bytes, bidi chars, glob metachar rejection
- ⚠️ PARTIAL: `requestPermission` with Prompt action denies (no UI bridge access)

---

## 10. Threat Intelligence

The threat-intel crate (`clawdefender-threat-intel`, 7,304 LoC) is a standalone crate (does not depend on core).

### Components

| Component | Status | Notes |
|-----------|--------|-------|
| Feed client (HTTP + incremental) | ✅ REAL | SHA-256 hash comparison, only downloads changed files |
| Ed25519 signature verification | ✅ REAL (placeholder key) | Code is real, embedded public key is all-zeros |
| Key rotation support | ✅ REAL | `next_public_key` in manifest for graceful transitions |
| Offline fallback + bundled baseline | ✅ REAL | `include_str!` embeds baseline data |
| Blocklist matching engine | ✅ REAL | Name, version (semver), SHA-256, npm package matching |
| IoC database + engine | ✅ REAL | 9 indicator types, Aho-Corasick for domains, HashSet for IPs/hashes |
| Community rule packs | ✅ REAL | Install/uninstall/update lifecycle, conflict detection |
| Kill chain pattern loader | ✅ REAL | Feed JSON parsing, built-in merge, hot-reload |
| Injection signature loader | ✅ REAL | 10 multilingual patterns, regex validation |
| Behavioral profile seeder | ✅ REAL | Pre-seeded profiles for known MCP servers |
| Telemetry (opt-in, anonymous) | ✅ REAL | Aggregate counts only, no PII |
| Feed data files | ⚠️ PARTIAL | Realistic structure but entries marked `[SYNTHETIC/TEST]` |

---

## 11. GUI App -- Backend (Tauri Commands)

The Tauri backend (`clients/clawdefender-app/src-tauri/`) has 75 registered commands in `lib.rs`.

### Command Classification Summary

| Classification | Count | Percentage |
|---------------|-------|-----------|
| ✅ REAL | 63 | 84% |
| ⚠️ PARTIAL | 3 | 4% |
| 🔶 STUBBED (honest) | 5 | 7% |
| 🔶 STUBBED (static/zeroed) | 2 | 3% |
| 🚫 BROKEN | 0 | 0% |
| ❌ MISSING | 0 | 0% |

### Supporting Modules (all ✅ REAL)
- **state.rs** (468 lines): AppState with bounded buffers (10K events, 100 prompts)
- **ipc_client.rs** (324 lines): Unix socket IPC with fresh connections per request
- **event_stream.rs** (690 lines): Audit log file watcher with symlink detection
- **daemon.rs** (152 lines): Daemon lifecycle management (start/stop/detect)
- **tray.rs** (409 lines): System tray with colored shield icon (green/amber/red)
- **scanner.rs** (1,166 lines): 5 real scanner modules running in-process

### Notable Stubs
- `list_guards` returns `vec![]` (guards are daemon in-memory only)
- `get_network_extension_status` returns `mock_mode: true` (honest)
- `activate_network_extension` / `deactivate_network_extension` return descriptive error
- `get_cloud_usage` returns zeroed stats (per-session tracking only)

---

## 12. GUI App -- Frontend (Pages & Components)

**Stack:** React 19 + TypeScript 5 + Vite 6 + Tailwind CSS 4 + Zustand 5 + react-router-dom 7

### Page Classification

| Page | Classification | Notes |
|------|---------------|-------|
| Dashboard | ✅ REAL | 8 data fetches + 3 event listeners |
| Settings (1502 lines) | ✅ REAL (1 stub) | Analysis Frequency dropdown is local-only |
| Onboarding | ✅ REAL (1 stub) | showInMenuBar checkbox in step 5 not persisted |
| AuditLog | ✅ REAL | Searchable, sortable, filterable table |
| Behavioral | ⚠️ PARTIAL | Auto-block toggle + threshold slider are local-only |
| Guards | ⚠️ PARTIAL | Guard toggle is local-only, no backend persistence |
| NetworkLog | ✅ REAL | No polling (one-shot fetch) |
| PolicyEditor | ⚠️ PARTIAL | Duplicate/toggle/reorder local-only; hit counts are `Math.random()` |
| Scanner | ✅ REAL | Full scan lifecycle with fixes |
| SystemHealth | ✅ REAL | 8 live diagnostic checks |
| ThreatIntel | ✅ REAL | All 6 data fetches + 3 actions work |
| Timeline | ✅ REAL | Virtualized rendering + real-time events + SLM analysis |

### Component Classification

| Component | Classification | Notes |
|-----------|---------------|-------|
| Sidebar | ✅ REAL | Missing /health link |
| NotificationLayer | ⚠️ PARTIAL | Event listeners real, Review/Trust/Kill actions stubbed |
| PromptWindow | ✅ REAL | Full prompt flow + SLM analysis + keyboard shortcuts |
| AlertWindow | ⚠️ PARTIAL | Display real, Kill/ViewTimeline actions stubbed |
| AutoBlockToast | ⚠️ PARTIAL | Display real, Review/Trust actions stubbed |
| RuleEditorModal | ✅ REAL | Full add/edit with Tauri commands |
| SecurityLevelChooser | ✅ REAL | Template application works |
| TemplateBrowser | ✅ REAL | With graceful fallback |

---

## 13. Settings & Configuration

### Settings Persistence Issues

| ID | Issue | Severity |
|----|-------|----------|
| S13-1 | Analysis Frequency not persisted (React state only) | Medium |
| S13-2 | Event Retention setting written to config but `FileAuditLogger` uses hardcoded 30 days | Medium |
| S13-3 | Log Level written to config but daemon reads env var from LaunchAgent plist | Low |
| S13-4 | Security Level dropdown always defaults to "balanced", never reads current policy | Medium |
| S13-5 | Active model not persisted across daemon restarts | Low |
| S13-6 | Config changes don't trigger daemon reload (only policy changes do) | Medium |
| S13-7 | Export writes to hardcoded `~/Desktop/` path | Low |
| S13-8 | Updater pubkey is empty -- unsigned updates accepted | HIGH |

---

## 14. CLI Tools

### CLI Binary (`clawdefender`)
- **22 top-level commands** with extensive subcommands, all routing to real implementations
- Supports 5 MCP clients: Claude Desktop, Cursor, VS Code, Windsurf, DXT Extensions
- All logging goes to stderr (critical for proxy mode)

| Command | Status |
|---------|--------|
| `init`, `wrap`, `unwrap`, `proxy` | ✅ REAL |
| `status`, `policy`, `log`, `doctor` | ✅ REAL |
| `model`, `config`, `usage`, `chat` | ✅ REAL |
| `daemon`, `behavioral`, `profile` | ✅ REAL |
| `certify`, `serve`, `guard` | ✅ REAL |
| `feed`, `rules`, `ioc`, `telemetry` | ✅ REAL |
| `network`, `reputation`, `scan` | ✅ REAL |

### Daemon Binary (`clawdefender-daemon`)
- `run` (default): Standalone daemon mode
- `proxy -- <cmd>`: MCP proxy mode
- Flags: `--config`, `--tui`, `--policy`

---

## 15. Build System & DevOps

### CI/CD Pipelines

| Pipeline | Trigger | Scope |
|----------|---------|-------|
| `ci.yml` | Push to main, all PRs | fmt, clippy, test, doc (macOS + Ubuntu) |
| `security-audit.yml` | Push to main + weekly cron | cargo audit + cargo deny |
| `release.yml` | Tag push (`v*`) | Universal binary, ad-hoc codesign, GitHub Release |
| `build-app.yml` | Push to branch + tag | TypeScript lint, Tauri build, DMG |

### Build Infrastructure
- 26 `just` commands covering dev, test, lint, audit, release, packaging, fuzzing
- `cargo-deny`: blocks vulnerabilities, copyleft, unknown registries, wildcards
- 3 fuzz targets: JSON-RPC parser, policy engine, eslogger parser
- Install/uninstall shell scripts with SHA-256 verification
- Homebrew formula (SHA-256 placeholder -- never published)

### Version Inconsistencies

| Location | Version |
|----------|---------|
| Workspace `Cargo.toml` | 0.1.0 |
| `tauri.conf.json` | 0.3.0 |
| `package.json` | 0.10.0 |
| Homebrew cask | 0.10.0 |
| Homebrew formula | 0.1.0 |

---

## 16. Configuration Files

### Core Configuration (`~/.config/clawdefender/config.toml`)

18+ configurable sections: daemon socket, audit log, log rotation, eslogger, SLM, API keys, swarm, UI, telemetry, policy, sensor, MCP server, behavioral, injection detector, guard API, threat intel, network policy.

Key defaults: audit log rotation at 50MB (10 files), SLM context 2048 tokens, swarm daily budget $1.00 / monthly $20.00, threat intel feed every 6 hours, behavioral learning threshold 100 events.

### Policy Files

| File | Purpose |
|------|---------|
| `policies/default.toml` | Blocks credentials, prompts shell/network, allows project reads |
| `policies/injection_patterns.toml` | 18 regex patterns for prompt injection (severity 0.4-0.8) |
| `policies/killchain_patterns.toml` | 6 multi-step kill chain patterns |
| `policies/templates/strict.toml` | Maximum security |
| `policies/templates/development.toml` | Balanced development |
| `policies/templates/audit-only.toml` | Logs everything, blocks nothing |
| `policies/templates/data-science.toml` | Jupyter/pip-friendly |

### Tauri Configuration

- **CSP:** `default-src 'self'` with localhost connect and unsafe-inline styles
- **Bundle targets:** DMG + .app for macOS 13.0+
- **Capabilities:** `shell:allow-execute` (broad -- allows arbitrary shell commands)
- **Updater:** GitHub releases endpoint, **empty pubkey** (signatures not enforced)

---

## 17. Data Files & Storage

### Runtime Data Layout (`~/.local/share/clawdefender/`)

| File/Directory | Format | Purpose |
|----------------|--------|---------|
| `audit.jsonl` | JSON Lines | Audit log (28-field records) |
| `audit.jsonl.1-10` | JSON Lines | Rotated audit logs |
| `clawdefender.sock` | Unix socket | Daemon-UI IPC |
| `clawdefender.pid` | Plain text | Daemon PID file |
| `server-token` | Plain text | MCP server auth token |
| `profiles.db` | SQLite | Behavioral profiles |
| `swarm_usage.db` | SQLite | Cloud API cost tracking |
| `chat.db` | SQLite | Chat history |
| `models/*.gguf` | GGUF binary | Downloaded AI models |
| `threat-intel/` | JSON files | Threat intelligence cache |
| `model_config.toml` | TOML | Active model configuration |

### Data Integrity

| Store | Mechanism |
|-------|-----------|
| Audit log | Channel-based async writes, buffered I/O, rotation, retention |
| Profiles DB | SQLite ACID transactions |
| Model files | SHA-256 verification on download |
| Threat feed | Manifest SHA-256 checksums, Ed25519 signatures |
| API keys | macOS Keychain (OS-level encryption) |
| Config files | TOML parsing with defaults fallback |

### Storage Issues

| ID | Issue | Severity |
|----|-------|----------|
| D17-1 | Import settings validates JSON structure but not TOML content safety | Medium |
| D17-2 | Server token stored as plain text file (should verify 0600 permissions) | Medium |
| D17-3 | No encryption at rest for profiles.db | Low |
| D17-4 | PID file not cleaned on crash (no flock mechanism) | Low |
| D17-5 | Updater pubkey empty -- unsigned updates accepted | HIGH |
| D17-6 | Logger RETENTION_DAYS hardcoded to 30, ignoring user setting | Medium |

---

## 18. Security Posture

### What ClawDefender Actually Provides

**Strong security properties:**

1. **MCP tool call interception** -- Every JSON-RPC message between MCP clients and servers is parsed, classified, and evaluated against policy. This is real and well-implemented.
2. **Policy-based access control** -- First-match-wins policy engine with glob/regex matching, path canonicalization (symlink resolution, null byte rejection, `..` handling). Production-quality.
3. **User-in-the-loop prompting** -- Prompted actions require explicit user approval with configurable timeout and auto-deny. Prompt flooding prevention via rate limiter.
4. **Audit trail** -- Comprehensive 28-field audit records with rotation, retention, and query capabilities. Every action is logged.
5. **Path traversal prevention** -- Symlink resolution via `std::fs::canonicalize`, glob separator enforcement, null byte rejection. Applied across proxy, scanner, Tauri commands.
6. **Prompt injection detection** -- Multi-layer: Aho-Corasick + regex patterns, multilingual (10 languages), canary tokens, nonce delimiters.
7. **Kill chain detection** -- Multi-step attack pattern recognition (credential theft, persistence, data staging, shell escape).
8. **Advisory AI analysis** -- SLM and swarm verdicts explicitly cannot influence policy decisions (multiple SAFETY comments in code). This is a correct security property.
9. **Data minimization** -- PII stripped before cloud transmission. Environment variable names sent to SLM, never values.
10. **Rate limiting** -- Three-tier rate limits on MCP server tools. Per-server prompt rate limiter.
11. **macOS Keychain** -- API keys stored in OS-level encrypted keychain, not in config files.
12. **Supply chain hygiene** -- cargo-deny blocks vulnerabilities, copyleft, unknown registries, wildcards.

**Significant security gaps:**

1. **All-zeros Ed25519 public key** (`crates/clawdefender-threat-intel/src/signature.rs`, `crates/clawdefender-daemon/src/lib.rs:262-270`): The embedded verification key is `"0000...0000"`. Signature verification will always fail, meaning threat feed updates are effectively unsigned. Any attacker who can MITM the feed URL can inject arbitrary blocklist entries, rule packs, IoCs, and kill chain patterns. **Severity: HIGH**

2. **Empty Guard REST API auth token** (`crates/clawdefender-daemon/src/lib.rs:657`): The Guard API server starts with `token: String::new()`. Any process on the local machine can register/deregister guards, modify the registry, and bypass agent self-protection. **Severity: HIGH**

3. **Empty Tauri updater pubkey** (`clients/clawdefender-app/src-tauri/tauri.conf.json`): The updater plugin has `"pubkey": ""`, meaning update signature verification is disabled. Unsigned updates could be pushed to users. **Severity: HIGH**

4. **Server token in plain text** (`~/.local/share/clawdefender/server-token`): The MCP server auth token is stored as a plain text file. While file permissions may restrict access, there is no explicit permission check in the code. **Severity: MEDIUM**

5. **Model SHA-256 checksums are placeholders** (`crates/clawdefender-slm/src/model_registry.rs`): All model checksums are `"0".repeat(64)`. The downloader code explicitly skips verification when checksums are all-zeros. A compromised model download could execute arbitrary inference. **Severity: MEDIUM**

6. **Feed data is synthetic** (`threat-feed/feed/v1/blocklist.json`): Blocklist entries are marked `[SYNTHETIC/TEST]`. Users relying on threat intelligence will get no real protection from known threats. **Severity: MEDIUM**

7. **No-UI-bridge fallback allows** (`crates/clawdefender-mcp-proxy/src/proxy/stdio.rs`): When no UI bridge is available and policy says Prompt, the proxy allows the request with a warning log. This is documented but means headless proxy operation defaults to permissive for prompted actions. **Severity: MEDIUM**

8. **Broad Tauri shell permission** (`clients/clawdefender-app/src-tauri/capabilities/default.json`): `shell:allow-execute` allows the Tauri app to execute arbitrary shell commands. If the web frontend is compromised (XSS), this could be exploited. **Severity: MEDIUM**

9. **Network Extension is mock-only**: The macOS Network Extension exists as Swift code but is not integrated. Network filtering is simulated in Rust, logging what would happen but never actually blocking connections. **Severity: LOW** (honestly communicated to users)

10. **No code signing configured**: Release pipeline uses ad-hoc codesign. Developer ID signing and Apple notarization are scaffolded but commented out. **Severity: LOW** (pre-release)

### Security Assessment Verdict

ClawDefender provides **real, meaningful security** for the MCP tool call interception use case. The proxy pipeline, policy engine, audit system, and behavioral analysis are production-quality. However, **three HIGH-severity placeholder values** (Ed25519 key, Guard API token, updater pubkey) must be fixed before any production deployment. These are the difference between a genuinely secured system and one that only appears secure.

---

## 19. Test Coverage

### Test Counts by Crate

| Crate | Unit Tests | Integration Files | Total #[test] |
|-------|-----------|-------------------|---------------|
| clawdefender-core | ~330 | 7 | 452 |
| clawdefender-slm | ~156 | 3 | 187 |
| clawdefender-guard | ~31 | 6 | 166 |
| clawdefender-scanner | ~115 | 2 | 165 |
| clawdefender-sensor | ~96 | 2 | 117 |
| clawdefender-threat-intel | ~116 | 0 (inline) | 116 |
| clawdefender-swarm | ~75 | 2 | 95 |
| clawdefender-daemon | ~57 | 2 | 87 |
| clawdefender-mcp-proxy | ~77 | 1 | 77 |
| clawdefender-cli | ~41 | 0 | 41 |
| clawdefender-mcp-server | ~27 | 3 | 38 |
| clawdefender-tui | ~33 | 0 | 33 |
| clawdefender-certify | ~5 | 1 | 22 |
| **TOTAL** | | | **~1,596** |

### Test Infrastructure
- 3 fuzz targets (JSON-RPC parser, policy engine, eslogger parser)
- 2 mock servers (mock-mcp-server, mock-eslogger with 5 scenarios)
- Security-focused test files in core, guard, swarm, mcp-server, scanner, behavioral
- Evasion detection tests in sensor crate
- Prompt injection tests in SLM and behavioral crates
- 3 `#[ignore]` integration tests requiring full workspace build

### Coverage Gaps
- No CI for SDK tests (Python, TypeScript)
- No CI for frontend tests (Vitest configured but not in pipeline)
- No code coverage reporting tool configured
- CLI has no integration tests for daemon, doctor, status subcommands
- Tauri app `commands.rs` has unit tests but no integration test suite

---

## 20. Missing Features Roadmap

### P0 -- Critical (Security issues, things users think work but don't)

| # | What | Where | Effort | Dependencies |
|---|------|-------|--------|-------------|
| P0-1 | Replace all-zeros Ed25519 public key with real production key | `crates/clawdefender-threat-intel/src/signature.rs` (EMBEDDED_PUBLIC_KEY_HEX), `crates/clawdefender-daemon/src/lib.rs:262-270` | S | Generate keypair, set up signing pipeline |
| P0-2 | Implement Guard REST API authentication | `crates/clawdefender-daemon/src/lib.rs:657,1006` | S | Read token from `server-token` file or generate one |
| P0-3 | Set Tauri updater public key | `clients/clawdefender-app/src-tauri/tauri.conf.json` | S | Generate signing keypair for release pipeline |
| P0-4 | Replace model registry SHA-256 placeholder checksums | `crates/clawdefender-slm/src/model_registry.rs` | S | Download each model, compute SHA-256 |
| P0-5 | Replace synthetic threat feed data with real threat intelligence | `threat-feed/feed/v1/blocklist.json` and related files | M | Curate real MCP threat data |
| P0-6 | Fix version inconsistencies across workspace | `Cargo.toml`, `tauri.conf.json`, `package.json`, Homebrew formulas | S | Decide canonical version, update `just bump-version` |

### P1 -- High (Core features that are stubbed or disconnected)

| # | What | Where | Effort | Dependencies |
|---|------|-------|--------|-------------|
| P1-1 | Connect event router SLM/swarm escalation | `crates/clawdefender-daemon/src/event_router.rs:67-74` | M | Wire SLM service and swarm commander into event router |
| P1-2 | Integrate behavioral engine into runtime OS event processing | `crates/clawdefender-daemon/src/lib.rs` | M | Feed OS/FS events through anomaly scorer and decision engine |
| P1-3 | Implement Guard daemon communication (register/deregister via IPC) | `crates/clawdefender-guard/src/guard.rs` activate() | M | Implement IPC client in guard crate |
| P1-4 | Wire `list_guards` Tauri command to daemon | `clients/clawdefender-app/src-tauri/src/commands.rs` | M | Add IPC endpoint for guard enumeration |
| P1-5 | Implement DaemonRequest/DaemonResponse IPC protocol | `crates/clawdefender-daemon/src/ipc.rs` | M | Types exist and are serialization-tested, handler not implemented |
| P1-6 | Implement sensor config hot-reload | `crates/clawdefender-daemon/src/lib.rs:571-575` | S | File watcher exists, add actual reload logic |
| P1-7 | Fix event_retention_days to be read by FileAuditLogger | `crates/clawdefender-core/src/audit/logger.rs` | S | Replace `RETENTION_DAYS` constant with config value |
| P1-8 | Fix config changes to trigger daemon reload | `clients/clawdefender-app/src-tauri/src/commands.rs` | S | Send reload IPC after config writes |
| P1-9 | Persist frontend toggles to backend (Behavioral auto-block, Guards toggle, PolicyEditor operations) | Frontend pages + new Tauri commands | M | Define Tauri commands for each toggle |

### P2 -- Medium (Incomplete features, nice-to-haves)

| # | What | Where | Effort | Dependencies |
|---|------|-------|--------|-------------|
| P2-1 | Implement macOS Network Extension integration | `extensions/clawdefender-network/`, daemon mock replacement | L | Code signing, System Extension entitlements, Apple approval |
| P2-2 | Persist Analysis Frequency setting | `clients/clawdefender-app/src/pages/Settings.tsx` | S | Add config key + Tauri command |
| P2-3 | Persist showInMenuBar in onboarding | `clients/clawdefender-app/src/pages/Onboarding.tsx` | S | Write to config.toml |
| P2-4 | Fix PolicyEditor hit counts (replace Math.random with real data) | `clients/clawdefender-app/src/pages/PolicyEditor.tsx` | S | Track rule hit counts in daemon |
| P2-5 | Add /health link to Sidebar | `clients/clawdefender-app/src/components/Sidebar.tsx` | S | None |
| P2-6 | Implement NotificationLayer action handlers (Kill, ViewTimeline, Review, Trust) | `clients/clawdefender-app/src/components/NotificationLayer.tsx` | M | New Tauri commands |
| P2-7 | Implement SLM model hot-swapping (live swap without service restart) | `crates/clawdefender-slm/src/lib.rs` | M | None |
| P2-8 | Fix Security Level dropdown to read current policy template | `clients/clawdefender-app/src/pages/Settings.tsx` | S | Infer template from current rules |
| P2-9 | Implement PolicyEditor local operations (duplicate, toggle, reorder) with backend persistence | Frontend + Tauri commands | M | New policy engine capabilities |
| P2-10 | Add polling to NetworkLog page | `clients/clawdefender-app/src/pages/NetworkLog.tsx` | S | None |
| P2-11 | Add code coverage reporting to CI | `.github/workflows/ci.yml` | S | Add llvm-cov or tarpaulin |
| P2-12 | Wire SDK and frontend tests into CI | `.github/workflows/ci.yml` | S | Add pytest and vitest steps |

### P3 -- Low (Polish, optimization)

| # | What | Where | Effort | Dependencies |
|---|------|-------|--------|-------------|
| P3-1 | Set up Apple code signing and notarization | `.github/workflows/release.yml` | M | Apple Developer account |
| P3-2 | Publish Homebrew formula with real SHA-256 | `Formula/clawdefender.rb` | S | First official release |
| P3-3 | Extract duplicated code between stdio.rs and http.rs in mcp-proxy | `crates/clawdefender-mcp-proxy/src/proxy/` | S | None |
| P3-4 | Add SIGHUP handling for config reload in daemon | `crates/clawdefender-daemon/src/main.rs` | S | None |
| P3-5 | Fix GuardStatsQuery to return real blocked_details | `crates/clawdefender-daemon/src/ipc.rs:228-240` | S | None |
| P3-6 | Fix GuardHealthCheck to return actual per-guard health | `crates/clawdefender-daemon/src/ipc.rs:253` | S | None |
| P3-7 | Cache FallbackEngine in guard.rs check_action() | `crates/clawdefender-guard/src/guard.rs` | S | None |
| P3-8 | Replace export_settings hardcoded Desktop path with file picker | Tauri command | S | None |
| P3-9 | Replace alert() calls in frontend with styled notifications | Scanner.tsx, NetworkLog.tsx | S | None |
| P3-10 | Add loading spinners to Dashboard initial data load | `clients/clawdefender-app/src/pages/Dashboard.tsx` | S | None |
| P3-11 | Enable `gguf` feature in at least one consumer or remove dead code | `crates/clawdefender-slm/src/gguf_backend.rs` | S | None |
| P3-12 | Fix hardcoded daemon version "0.10.0" in monitor.rs and get_system_info | Tauri backend | S | Read actual version from daemon |

---

## Appendix A: Complete Tauri Command Audit

| # | Command | Classification | Connects To | Notes |
|---|---------|---------------|-------------|-------|
| 1 | `get_daemon_status` | ✅ REAL | IPC + filesystem | Falls back to cache, then defaults |
| 2 | `start_daemon` | ✅ REAL | Process spawn + IPC | 15s polling for connectivity |
| 3 | `stop_daemon` | ✅ REAL | IPC + PID file | SIGTERM via IPC or PID |
| 4 | `detect_mcp_clients` | ✅ REAL | Filesystem | Reads 4 client config paths |
| 5 | `list_mcp_servers` | ✅ REAL | Filesystem | Detects mcpServers/servers keys |
| 6 | `wrap_server` | ✅ REAL | Filesystem | Creates backup, idempotent |
| 7 | `unwrap_server` | ✅ REAL | Filesystem | Creates backup, idempotent |
| 8 | `get_policy` | ✅ REAL | Filesystem | Creates default if missing |
| 9 | `add_rule` | ✅ REAL | Filesystem + IPC | Input validation + dedup check |
| 10 | `update_rule` | ✅ REAL | Filesystem + IPC | Verifies rule exists |
| 11 | `delete_rule` | ✅ REAL | Filesystem + IPC | Verifies rule exists |
| 12 | `reload_policy` | ✅ REAL | IPC | Sends "reload" to daemon |
| 13 | `list_templates` | 🔶 STUBBED | None | 4 hardcoded templates (rules are real) |
| 14 | `apply_template` | ✅ REAL | Filesystem + IPC | Real policy rule generation |
| 15 | `get_recent_events` | ✅ REAL | State + filesystem | Deduplication, bounded reads |
| 16 | `get_profiles` | ✅ REAL | SQLite DB | Reads profiles.db read-only |
| 17 | `get_behavioral_status` | ⚠️ PARTIAL | SQLite DB | `total_anomalies` hardcoded 0 |
| 18 | `list_guards` | 🔶 STUBBED | None | Returns empty vec (documented) |
| 19 | `start_scan` | ✅ REAL | State + filesystem | 5 real scanner modules |
| 20 | `get_scan_progress` | ✅ REAL | State | Reads from active_scans |
| 21 | `get_scan_results` | ✅ REAL | State + filesystem | In-memory + disk fallback |
| 22 | `apply_scan_fix` | ⚠️ PARTIAL | Filesystem | Only wrap_server + guidance |
| 23 | `run_doctor` | ✅ REAL | IPC + filesystem | 8 live system checks |
| 24 | `get_system_info` | ✅ REAL | Process + IPC | sw_vers for macOS |
| 25 | `respond_to_prompt` | ✅ REAL | State + filesystem + IPC | Creates persistent allow rules |
| 26 | `check_onboarding_complete` | ✅ REAL | State | In-memory flag |
| 27 | `complete_onboarding` | ✅ REAL | State + filesystem | Persists flag file |
| 28 | `get_settings` | ✅ REAL | Filesystem | Falls back to defaults |
| 29 | `update_settings` | ✅ REAL | Filesystem + IPC | Preserves unknown sections |
| 30 | `export_settings` | ✅ REAL | Filesystem | Strips secrets |
| 31 | `import_settings_from_content` | ✅ REAL | Filesystem | Validates, creates backups |
| 32 | `get_feed_status` | ✅ REAL | Filesystem | Reads manifest + IoC files |
| 33 | `force_feed_update` | ✅ REAL | CLI subprocess | Shells to `clawdefender feed update` |
| 34 | `get_blocklist_matches` | ✅ REAL | Filesystem | Cross-references with MCP servers |
| 35 | `get_rule_packs` | ✅ REAL | Filesystem | Reads rules directory |
| 36 | `install_rule_pack` | ✅ REAL | CLI subprocess | Input validation on ID |
| 37 | `uninstall_rule_pack` | ✅ REAL | Filesystem | Path traversal prevention |
| 38 | `get_ioc_stats` | ✅ REAL | Filesystem | Categorizes indicators |
| 39 | `check_server_reputation` | ✅ REAL | Filesystem | Blocklist lookup |
| 40 | `get_telemetry_status` | ✅ REAL | Filesystem | Reads config.toml |
| 41 | `toggle_telemetry` | ✅ REAL | Filesystem | Writes config.toml |
| 42 | `get_telemetry_preview` | ✅ REAL | Filesystem | Aggregates audit data |
| 43 | `get_network_extension_status` | 🔶 STUBBED | None | Returns mock_mode: true |
| 44 | `activate_network_extension` | 🔶 STUBBED | None | Returns descriptive error |
| 45 | `deactivate_network_extension` | 🔶 STUBBED | None | Returns descriptive error |
| 46 | `get_network_settings` | ✅ REAL | Filesystem | Reads config.toml |
| 47 | `update_network_settings` | ✅ REAL | Filesystem | Writes config.toml |
| 48 | `get_network_connections` | ✅ REAL | Filesystem | Reads audit.jsonl network events |
| 49 | `get_network_summary` | ✅ REAL | Filesystem | Aggregates network events |
| 50 | `get_network_traffic_by_server` | ✅ REAL | Filesystem | Groups by server |
| 51 | `export_network_log` | ✅ REAL | Filesystem | CSV or JSON, path validation |
| 52 | `kill_agent_process` | ✅ REAL | libc::kill | PID validation, SIGTERM->SIGKILL |
| 53 | `enable_autostart` | ✅ REAL | tauri_plugin_autostart | macOS LaunchAgent |
| 54 | `disable_autostart` | ✅ REAL | tauri_plugin_autostart | macOS LaunchAgent |
| 55 | `is_autostart_enabled` | ✅ REAL | tauri_plugin_autostart | macOS LaunchAgent |
| 56 | `save_api_key` | ✅ REAL | macOS Keychain | Provider validation |
| 57 | `clear_api_key` | ✅ REAL | macOS Keychain | Provider validation |
| 58 | `has_cloud_api_key` | ✅ REAL | macOS Keychain | Provider validation |
| 59 | `test_api_connection` | ✅ REAL | HTTP + Keychain | Real API test call |
| 60 | `get_cloud_usage` | 🔶 STUBBED | None | Returns zeroed stats |
| 61 | `get_cloud_providers` | ✅ REAL | Registry | Provider list |
| 62 | `download_model` | ✅ REAL | HTTP + filesystem | Progress-tracked download |
| 63 | `download_custom_model` | ✅ REAL | HTTP + filesystem | Arbitrary URL download |
| 64 | `get_download_progress` | ✅ REAL | State | Progress tracker |
| 65 | `cancel_download` | ✅ REAL | State | Cancellation token |
| 66 | `delete_model` | ✅ REAL | Filesystem | Path traversal prevention |
| 67 | `get_model_catalog` | ✅ REAL | Registry | Static catalog |
| 68 | `get_installed_models` | ✅ REAL | Filesystem | Lists downloaded models |
| 69 | `get_system_capabilities` | ✅ REAL | System info | RAM, GPU, arch |
| 70 | `activate_model` | ✅ REAL | Filesystem + State | Loads GGUF model |
| 71 | `activate_cloud_provider` | ✅ REAL | Keychain + State | Validates key exists |
| 72 | `deactivate_model` | ✅ REAL | State + filesystem | Clears active model |
| 73 | `get_active_model` | ✅ REAL | State | Live stats from engine |
| 74 | `list_available_models` | ✅ REAL | Registry + State + FS | Combined catalog + cloud |
| 75 | `get_slm_status` | ✅ REAL | State | Model info + backend type |

---

## Appendix B: Complete IPC Protocol Audit

### B.1 Unix Socket IPC (Implemented)

| Message Type | Direction | Status | Notes |
|-------------|-----------|--------|-------|
| `"status"` | Client -> Daemon | ✅ Implemented | Returns live ProxyMetrics |
| `"reload"` | Client -> Daemon | ✅ Implemented | Triggers policy engine reload |
| `"shutdown"` | Client -> Daemon | ✅ Implemented | Returns ack, sends SIGTERM to self |
| `GuardRegister` | Client -> Daemon | ✅ Implemented | Full permission conversion |
| `GuardDeregister` | Client -> Daemon | ✅ Implemented | Lookup by agent_name + pid |
| `GuardStatsQuery` | Client -> Daemon | ⚠️ Partial | blocked_details/anomaly_alerts always empty |
| `GuardHealthCheck` | Client -> Daemon | ⚠️ Partial | Always returns Active |
| Unknown command | Client -> Daemon | ✅ Implemented | Returns error JSON |

### B.2 DaemonRequest/DaemonResponse Protocol (Defined but NOT handled by IPC)

| Type | Direction | Status | Notes |
|------|-----------|--------|-------|
| `DaemonRequest::ProxyRegister` | Client -> Daemon | ✅ Serialization tested | Not wired to IPC handler |
| `DaemonRequest::Shutdown` | Client -> Daemon | ✅ Serialization tested | Not wired to IPC handler |
| `DaemonRequest::PromptResponse` | Client -> Daemon | ✅ Serialization tested | Not wired to IPC handler |
| `DaemonRequest::NetworkPolicyQuery` | Client -> Daemon | ✅ Serialization tested | Not wired to IPC handler |
| `DaemonRequest::NetworkStatus` | Client -> Daemon | ✅ Serialization tested | Not wired to IPC handler |
| `DaemonResponse::StatusReport` | Daemon -> Client | ✅ Serialization tested | Not wired to IPC handler |
| `DaemonResponse::Error` | Daemon -> Client | ✅ Serialization tested | Not wired to IPC handler |
| `DaemonResponse::NetworkPolicyResult` | Daemon -> Client | ✅ Serialization tested | Not wired to IPC handler |
| `DaemonResponse::NetworkStatusReport` | Daemon -> Client | ✅ Serialization tested | Not wired to IPC handler |

**Note:** The typed DaemonRequest/DaemonResponse protocol exists and is serialization-tested, but the IPC server only handles simple string commands and GuardRequest messages. This suggests an incomplete migration to a structured protocol.

### B.3 Tauri Event Protocol

| Event Channel | Direction | Status |
|--------------|-----------|--------|
| `clawdefender://event` | Backend -> Frontend | ✅ Implemented |
| `clawdefender://prompt` | Backend -> Frontend | ✅ Implemented |
| `clawdefender://alert` | Backend -> Frontend | ✅ Implemented |
| `clawdefender://auto-block` | Backend -> Frontend | ✅ Implemented |
| `clawdefender://status-change` | Backend -> Frontend | ✅ Implemented |
| `clawdefender://navigate` | Backend -> Frontend | ✅ Implemented |
| `clawdefender://theme-changed` | Backend -> Frontend | ✅ Implemented |

---

## Appendix C: Feature Flag Matrix

Only `clawdefender-slm` defines feature flags. All other crates have zero feature flags.

| Crate | Feature | What It Enables | Default? | Used in Source? | Enabled By |
|-------|---------|----------------|----------|----------------|-----------|
| clawdefender-slm | `cloud` | Cloud LLM backend via reqwest | No | Yes (`lib.rs:15`) | Tauri app |
| clawdefender-slm | `download` | Model downloader (reqwest, sha2, futures-util, tokio-util, uuid, libc) | No | Yes (`lib.rs:18`, `model_manager.rs:102`) | Tauri app |
| clawdefender-slm | `gguf` | Local GGUF inference via llama_cpp | No | Yes (`lib.rs:21`, `lib.rs:77`) | **NOBODY** |

### Feature Flag Observations

1. **`gguf` feature is defined and code-gated but never enabled.** The `gguf_backend.rs` (197 LoC) is dead code in all current build configurations.
2. **`cloud` and `download` are only enabled by the Tauri app.** The daemon, CLI, and mcp-proxy only get the rule-based/mock engine.
3. **Platform-conditional dependency:** `clawdefender-swarm` has `cfg(target_os = "macos")` for `security-framework` (keychain access).

---

*End of ClawDefender System Audit*
*Generated: 2026-02-23 by synthesis agent from 9 sub-audit reports*
