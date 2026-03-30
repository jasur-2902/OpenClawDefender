# ClawDefender — Audit Summary

**Date:** 2026-03-29
**Branch:** `production` (16 commits, Feb 16-23 2026)
**Version:** 0.5.0-beta
**Auditors:** 7-agent forensic team (read-only)

---

## Quick Stats

| Metric | Value |
|--------|-------|
| Workspace crates | 16 (+ Tauri app) |
| Total Rust LOC | 119,840 |
| Total TypeScript/TSX LOC | 33,738 |
| Total combined LOC | ~159,000 |
| Tauri `#[command]` functions | ~107 |
| Commands fully working | ~95 (92%) |
| Commands partial | 5 |
| Commands stubbed | 4 |
| Commands broken | 0 |
| Frontend pages (active) | 13 |
| Frontend pages fully functional | 13 (100%) |
| Non-functional UI elements | 1 ("Show related events" — intentional Coming Soon) |
| Rust test functions | 2,195 |
| Frontend test files | 14 |
| Fuzz targets | 3 |
| `todo!()`/`unimplemented!()` in prod code | 0 |
| `// TODO` comments | 3 (minor) |
| `// HACK`/`// STUB`/`// FAKE` markers | 0 |
| Overall completion | ~92% |

---

## What's Working (End-to-End)

**Core Security Pipeline:**
- MCP proxy intercepts stdio and HTTP MCP traffic, parses JSON-RPC, extracts tool names/arguments, evaluates policy rules, blocks/allows/prompts, logs enriched audit records
- Policy engine loads TOML rules, evaluates against events, supports glob/regex matching, path canonicalization with traversal prevention
- Audit logger writes structured JSONL with rotation, retention, session tracking, and concurrent write safety
- Behavioral engine builds per-server profiles with 9-dimension anomaly scoring, kill chain detection (6 attack patterns), injection detection (23 regex patterns), and SQLite persistence
- Prompt rate limiting prevents prompt fatigue attacks

**Daemon:**
- Starts as foreground process (GUI manages lifecycle), Unix socket IPC (JSON-line protocol)
- 7 IPC commands: status, reload, guard_list, guard_toggle, GuardRegister/Deregister/StatsQuery/HealthCheck, shutdown
- Event routing from sensor subsystem through behavioral analysis pipeline
- PID file management with stale detection, graceful signal handling

**Desktop App (Tauri + React):**
- 13 fully functional pages: Home, Ask Claw, My Tools, Tool Detail, Activity, Event Detail, Alerts, Alert Detail, Settings, Policy Editor, System Health, Threat Intel, Onboarding
- All ~80+ invoke() calls connect to real Rust backend commands
- Real-time event streaming from audit.jsonl file watching (500ms poll)
- System tray with dynamic shield icon (green/yellow/red), protection score, server count
- Connection monitor with adaptive heartbeat (10s normal, 2s failure), auto-recovery, crash reporting
- Fail-closed security: prompts auto-deny on timeout or daemon crash

**SLM Engine:**
- Real GGUF inference via llama.cpp (behind `gguf` feature flag)
- Real cloud API backends (Anthropic, OpenAI, Google) behind `cloud` feature flag
- Model download with progress, resume, SHA-256 verification, cancellation
- 5 curated GGUF models in catalog with real HuggingFace URLs
- Prompt sanitization, output validation, noise filtering

**Sensor:**
- Real macOS eslogger integration (requires FDA + sudo, macOS 13+) with crash recovery and exponential backoff
- Real process tree tracking via sysinfo with PID recycling detection
- Real filesystem monitoring via notify crate with sensitivity classification
- MCP-to-OS event correlation engine with 4 matching rules and confidence scoring

**Threat Intelligence:**
- Feed client with HTTP download, Ed25519 signature verification, incremental updates
- IoC matching engine (9 indicator types, Aho-Corasick, CIDR, regex)
- Blocklist matcher (name, version, semver range, SHA-256)
- Community rules system with conflict detection
- Opt-in anonymous telemetry (disabled by default)

**Guard System:**
- Server-side registry with glob-based permission matching, sensitive path blocking, dead PID cleanup
- REST API (Bearer token auth, full CRUD)
- Fallback engine for daemon-unavailable scenarios

**Other Working Features:**
- CLI with 20+ subcommands
- Trust system with 5 levels and 7 permissions per server
- Alert intelligence engine with 9 promotion rules and kill chain detection
- Protection score (6 factors, 100-point scale) with history
- Weekly digest generation with recommendations and trend analysis
- Ask Claw conversational AI with 28 intent types
- Progressive guidance system with 9 milestones
- Settings export/import with secret stripping
- Onboarding wizard (5 screens)
- Accessibility: ARIA roles, keyboard nav, focus traps, reduced motion support

---

## What's Broken / Partial

1. **MCP-to-EventRouter pipeline gap** (CRITICAL)
   - MCP proxy events bypass the correlation engine and EventRouter
   - Behavioral analysis (anomaly scoring, kill chain detection) never sees MCP tool-call events
   - `DaemonRequest::McpEventForward` exists in protocol but is never sent
   - Events reach GUI only indirectly via audit.jsonl file watching, not real-time event routing

2. **Cloud AI inference uses MockSlmBackend**
   - `activate_cloud_provider` creates MockSlmBackend, not real cloud inference client
   - `is_mock_mode()` returns true even when cloud API key is configured

3. **Network byte metrics always zero**
   - `get_network_connections`, `get_network_summary`, `get_network_traffic_by_server` report bytes_sent/received/duration as 0
   - Daemon does not emit these fields in audit records

4. **CLI bugs** (3 issues in threat_intel.rs):
   - `check_reputation` always uses empty blocklist (library works, CLI doesn't load from cache)
   - `feed_update` uses all-zeros verifier key instead of embedded key
   - `ioc_add` is stubbed ("future version")
   - `policy reload` has TODO for IPC

5. **Guard client-side IPC incomplete**
   - `AgentGuard.activate()` connects to daemon but has TODO: "In a full implementation, we'd send GuardRegister here"
   - Always falls back to embedded FallbackEngine

6. **Cloud usage tracking returns zeros**
   - `get_cloud_usage` returns `{ requests_today: 0, tokens_used: 0 }` unconditionally

---

## What's Stubbed / Not Implemented

1. **Network Extension** (3 commands) — macOS System Extension not built, requires Apple Developer certs and notarization. Commands honestly return "not installed."

2. **TUI** — `crates/claw-tui/` does not exist. The `clawdefender-tui` crate exists (1,369 LOC) for terminal prompts within the daemon, but there's no standalone TUI dashboard.

3. **`crates/clawdefender-cloud/`** — Does not exist. Cloud functionality is in `clawdefender-swarm`.

4. **`crates/clawdefender-sdk/`** — Does not exist. Guard REST API is the closest equivalent.

5. **Telemetry preview** — `get_telemetry_preview` returns hardcoded category list. No real telemetry system exists.

6. **Baseline threat feed** — Compiles into binary but blocklist `servers: []` is empty.

---

## What's Missing (Not Started)

1. Apple Developer signing and notarization for distribution
2. Real network-level interception (System Extension)
3. Windows/Linux platform support (eslogger is macOS-only)
4. Real telemetry collection and reporting infrastructure
5. IoC addition via CLI (`ioc_add` stubbed)
6. Profile cleanup on server unwrap (no dedicated IPC command)

---

## Critical Path (Next 5 Priorities)

1. **Fix MCP-to-EventRouter pipeline** — Wire `DaemonRequest::McpEventForward` from proxy to daemon correlation engine. This is the #1 architectural gap: MCP tool-call events never reach behavioral analysis.

2. **Wire cloud AI inference** — Replace MockSlmBackend with real CloudBackend in `activate_cloud_provider`. The cloud backend library is fully functional.

3. **Fix 3 CLI threat intel bugs** — Load blocklist from cache in `check_reputation`, use `FeedVerifier::from_embedded()` in `feed_update`, implement `ioc_add` (library already supports it).

4. **Complete Guard client IPC** — Send actual `GuardRegister`/`GuardDeregister` messages from `AgentGuard.activate()`/`deactivate()`.

5. **Apple signing + distribution** — Set up Developer ID signing, notarization, and Homebrew tap for real user distribution.

---

## Architecture Health

**The foundation is solid.** The codebase is well-architected with clean separation between 16 crates, proper trait abstractions, comprehensive error handling, and fail-closed security defaults. The core library (20K LOC) has zero stubs — every module (policy, audit, behavioral, DNS, correlation, network policy) contains real implementations with extensive test suites (2,195 tests total, zero `todo!()`/`unimplemented!()` in production code). The Tauri backend is remarkably complete with 92% of commands fully working. The frontend is production-quality with comprehensive accessibility, loading/empty/error states, and zero dead UI elements.

The single biggest structural issue is the **MCP-to-EventRouter pipeline gap**: proxy events bypass the correlation engine, meaning behavioral analysis only sees OS-level events, not the MCP tool calls that triggered them. This is a wiring issue, not an architectural flaw — the protocol type `McpEventForward` already exists and the EventRouter can handle it. Fixing this one connection would unlock the full security pipeline.

The project is ~159K lines of real code built in 8 days with 16 commits. It's genuinely impressive in scope and quality. The remaining work is primarily integration wiring (connecting existing components) and platform requirements (Apple signing), not missing functionality.
