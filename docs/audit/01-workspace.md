# 01 - Workspace Structure Audit

**Auditor:** Agent 1 (Workspace & Crate Auditor)
**Date:** 2026-02-23
**Scope:** Full workspace at `/Users/jasur/workspace/clawai/`

---

## Summary

| Metric | Value |
|---|---|
| Workspace members | 15 (+ 1 excluded Tauri app) |
| Total Rust LoC (excl. target/) | ~92,984 |
| Binaries produced | 7 (daemon, proxy, CLI, mock-mcp-server, mock-eslogger, 3 fuzz targets) |
| Feature-gated crates | 1 (clawdefender-slm) |
| SDKs | 4 (Python, Python-Agent, TypeScript, TypeScript-Agent) |
| Extensions | 1 (Swift network extension, 1,434 LoC) |

---

## Section 1: Workspace Structure

### 1.1 Root Cargo.toml

- **Resolver:** 2
- **Members:** 15 crates
- **Excluded:** `clients/clawdefender-app/src-tauri` (Tauri GUI app, independent build)
- **Profile release:** LTO=fat, codegen-units=1, strip=true, opt-level="z", panic=abort

### 1.2 Workspace Dependencies (shared versions)

| Dependency | Version | Notable Features |
|---|---|---|
| serde | 1 | derive |
| serde_json | 1 | - |
| tokio | 1 | full |
| tracing | 0.1 | - |
| tracing-subscriber | 0.3 | env-filter, json |
| chrono | 0.4 | serde |
| anyhow | 1 | - |
| thiserror | 2 | - |
| clap | 4 | derive |
| toml | 0.8 | - |
| glob | 0.3 | - |
| regex | 1 | - |
| aho-corasick | 1 | - |
| uuid | 1 | v4 |
| ratatui | 0.29 | - |
| crossterm | 0.28 | event-stream |

---

## Section 2: Crate-by-Crate Analysis

### 2.1 `clawdefender-core` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-core` |
| Type | Library |
| LoC (src) | 20,216 |
| LoC (tests) | 4,685 |
| Description | Core types, policy engine, and shared infrastructure |

**Key modules:** policy engine (681 LoC), behavioral analysis (killchain 1,514, anomaly 1,213, injection detector 1,121, decision 854, learning 541, update 506), audit logger (1,146), config/settings (787), network policy (engine 444, tests 683+451), DNS exfiltration (249+345 tests), correlation (433), network log (438), audit query (565).

**Dependencies:** serde, serde_json, chrono, toml, glob, regex, aho-corasick, anyhow, thiserror, tracing, uuid, rusqlite (bundled).

**Feature flags:** None defined.

**Depended on by:** Every other workspace crate (12 crates + fuzz). This is the foundational crate.

---

### 2.2 `clawdefender-mcp-proxy` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-mcp-proxy` |
| Type | Library + Binary (`clawdefender-mcp-proxy`) |
| LoC (src) | 4,961 |
| LoC (tests) | 574 |
| Description | MCP protocol proxy with JSON-RPC interception |

**Key modules:** stdio proxy (2,363 LoC -- largest file), HTTP proxy (531), JSON-RPC parser (579), types (291), classifier rules (317).

**Workspace deps:** clawdefender-core, clawdefender-slm, clawdefender-swarm, clawdefender-threat-intel.

**External deps:** axum 0.8, reqwest 0.12 (stream), hyper 1.

**Feature flags:** None defined.

**Depended on by:** daemon, CLI, fuzz.

---

### 2.3 `clawdefender-sensor` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-sensor` |
| Type | Library |
| LoC (src) | 6,041 |
| LoC (tests) | 974 |
| Description | OS-level sensors for process and filesystem monitoring |

**Key modules:** correlation engine (836), fsevents (559 + debouncer 321), eslogger process (539), filter (427), parser (233), types (312), proctree (478 + agent_id 449), correlation rules (422), severity (208), limits (153).

**Workspace deps:** clawdefender-core. Dev-dep on clawdefender-daemon.

**External deps:** nix 0.29 (process, signal), notify 7, sysinfo 0.33, futures 0.3, tokio-stream 0.1, unicode-normalization 0.1.

**Feature flags:** None defined.

**Depended on by:** daemon, fuzz.

---

### 2.4 `clawdefender-slm` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-slm` |
| Type | Library |
| LoC (src) | 6,497 |
| LoC (tests) | 839 |
| Description | Small language model integration for policy decisions |

**Key modules:** downloader (868), noise filter (727), analyzer (628), model registry (584), cloud backend (552), engine (537), lib (391), model manager (273), profiles (245), output validator (221), context (218), sanitizer (217), gguf backend (197).

**Workspace deps:** clawdefender-core.

**External deps:** reqwest (optional), sha2 (optional), futures-util (optional), tokio-util (optional), uuid (optional), libc (optional), llama_cpp (optional), num_cpus.

**Feature flags:** See Appendix C. This is the ONLY crate with feature flags.
- `cloud` -- enables reqwest for cloud LLM backend
- `download` -- enables model downloading (reqwest, sha2, futures-util, tokio-util, uuid, libc)
- `gguf` -- enables local GGUF inference via llama_cpp
- Default: none enabled

**`#[cfg(feature)]` usage in source:**
- `lib.rs:15` -- `#[cfg(feature = "cloud")]` gates cloud module
- `lib.rs:18` -- `#[cfg(feature = "download")]` gates download module
- `lib.rs:21` -- `#[cfg(feature = "gguf")]` gates gguf module
- `lib.rs:77` -- `#[cfg(feature = "gguf")]` in engine match
- `model_manager.rs:102` -- `#[cfg(feature = "download")]` gates download fn

**Depended on by:** daemon, mcp-proxy, CLI, Tauri app.

**Note:** Tauri app enables `cloud` + `download` features. No workspace crate enables `gguf`.

---

### 2.5 `clawdefender-swarm` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-swarm` |
| Type | Library |
| LoC (src) | 5,017 |
| LoC (tests) | 746 |
| Description | Multi-agent swarm coordination |

**Key modules:** prompts (728), chat server (622), cost tracking (614), chat (544), commander (496), LLM client (426), keychain (312), output sanitizer (196), data minimizer (163), audit hasher (156).

**Workspace deps:** clawdefender-core.

**External deps:** async-trait, reqwest (json), sha2, hex, rusqlite (bundled), axum 0.8, tower 0.5, http-body-util. macOS: security-framework 3.

**Feature flags:** None defined.

**Depended on by:** daemon, mcp-proxy, tui, CLI.

---

### 2.6 `clawdefender-tui` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-tui` |
| Type | Library |
| LoC (src) | 1,369 |
| LoC (tests) | 0 |
| Description | Terminal UI for interactive prompts and dashboards |

**Key modules:** lib.rs (1,178 -- main TUI rendering), prompt.rs (191).

**Workspace deps:** clawdefender-core, clawdefender-swarm.

**External deps:** ratatui, crossterm.

**Feature flags:** None defined.

**Depended on by:** daemon only.

**Note:** No tests directory exists. Smallest crate by LoC.

---

### 2.7 `clawdefender-daemon` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-daemon` |
| Type | Library + Binary (`clawdefender-daemon`) |
| LoC (src) | 4,473 |
| LoC (tests) | 992 |
| Description | Daemon orchestrating sensors, proxy, and policy engine |

**Key modules:** lib.rs (2,613 -- main orchestration), mock network extension (413), IPC (259), main.rs (117), event router (79).

**Workspace deps:** clawdefender-core, clawdefender-mcp-proxy, clawdefender-sensor, clawdefender-slm, clawdefender-swarm, clawdefender-tui, clawdefender-mcp-server, clawdefender-guard, clawdefender-threat-intel. (9 workspace deps -- the central hub)

**External deps:** notify 7, libc 0.2.

**Feature flags:** None defined.

**Depended on by:** sensor (dev-dep only). This is a top-level binary.

---

### 2.8 `clawdefender-mcp-server` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-mcp-server` |
| Type | Library |
| LoC (src) | 3,887 |
| LoC (tests) | 1,664 |
| Description | MCP server for AI agent intent declaration and permission |

**Key modules:** protocol (667), tools (613), types (202), suggestions (194), validation (174), lib (138), auth (124), transport/http (66), transport/stdio (41).

**Workspace deps:** clawdefender-core.

**External deps:** axum 0.8, rand 0.9, hex 0.4, dirs 6.

**Feature flags:** None defined.

**Depended on by:** daemon, CLI.

---

### 2.9 `clawdefender-certify` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-certify` |
| Type | Library |
| LoC (src) | 1,837 |
| LoC (tests) | 409 |
| Description | Claw Compliant certification harness for MCP servers |

**Key modules:** level1 (265), level3 (249), harness (236), level2 (220), manifest (212), report (124), lib (122).

**Workspace deps:** clawdefender-core.

**External deps:** (only workspace deps -- no unique externals).

**Feature flags:** None defined.

**Depended on by:** CLI only.

---

### 2.10 `clawdefender-scanner` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-scanner` |
| Type | Library |
| LoC (src) | 8,711 |
| LoC (tests) | 827 |
| Description | Security scanner framework with sandbox and attack modules |

**Key modules (attack modules):** dependency audit (1,366), capability escalation (1,102), prompt injection (1,051), fuzzing (868), path traversal (741), exfiltration (721). **Framework:** finding (641), scanner (398), client (316), report (228), progress (170), sandbox (149), evidence (89).

**Workspace deps:** clawdefender-core.

**External deps:** async-trait, tempfile (runtime dep), libc, rand 0.8.

**Feature flags:** None defined.

**Depended on by:** CLI only.

---

### 2.11 `clawdefender-guard` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-guard` |
| Type | Library |
| LoC (src) | 7,272 |
| LoC (tests) | 3,521 |
| Description | Agent self-protection guard |

**Key modules:** registry (676), installer/mod (427), API (394), guard (299), policy gen (230), webhooks (208), fallback (207), installer/download (200), types (176), installer/detect (170), installer/uninstall (158), installer/platform (156), connection (122), api auth (107), installer/version (89), selftest (65), openapi (42).

**Workspace deps:** clawdefender-core.

**External deps:** hyper 1 (server, http1), http-body-util, hyper-util (tokio), sha2, async-trait, dirs 5, semver, libc.

**Feature flags:** None defined.

**Depended on by:** daemon only.

---

### 2.12 `clawdefender-threat-intel` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `crates/clawdefender-threat-intel` |
| Type | Library |
| LoC (src) | 7,304 |
| LoC (tests) | 0 (tests are inline in src/*.rs test modules) |
| Description | Threat intelligence feed client |

**Key modules:** IoC engine (451), IoC tests (646), IoC database (278), IoC types (196), blocklist matching (361), blocklist tests (323), patterns/injection loader (338), patterns/killchain loader (237), patterns/profile seeder (229), patterns/types (233), patterns/tests (431), telemetry/aggregator (191), telemetry/tests (382), rules/conflict (211), rules/tests (289), client (289), signature (225), cache (215), lib (420), types (252).

**Workspace deps:** None (does not depend on clawdefender-core -- standalone crate).

**External deps:** ed25519-dalek 2 (signature verification), reqwest (rustls-tls, json), sha2, dirs 5.

**Feature flags:** None defined.

**Depended on by:** daemon, mcp-proxy, CLI.

---

### 2.13 `clawdefender-cli` -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `clients/clawdefender-cli` |
| Type | Binary (`clawdefender`) |
| LoC (src) | 6,190 |
| LoC (tests) | 0 (no tests/ directory) |
| Description | CLI client for interacting with the daemon |

**Subcommands:** wrap (679), mod/routing (573), threat-intel (459), doctor (435), policy (426), unwrap (370), init (335), guard (314), daemon (284), model (253), network (225), behavioral (204), profile (199), scan (133), usage (113), status (113), log (113), config (108), chat (100), serve (34), proxy (13).

**Workspace deps:** clawdefender-core, clawdefender-mcp-proxy, clawdefender-slm, clawdefender-swarm, clawdefender-mcp-server, clawdefender-certify, clawdefender-scanner, clawdefender-threat-intel (8 workspace deps).

**External deps:** open 5, libc 0.2.

**Feature flags:** None defined.

**Note:** No test directory. Second-largest consumer of workspace crates (after daemon).

---

### 2.14 `mock-mcp-server` -- CLASSIFICATION: REAL (test utility)

| Field | Value |
|---|---|
| Path | `tests/mock-mcp-server` |
| Type | Binary (`mock-mcp-server`) |
| LoC | 264 |
| Description | Mock MCP server for integration testing |
| publish | false |

**Dependencies:** serde, serde_json only (no workspace deps).

---

### 2.15 `mock-eslogger` -- CLASSIFICATION: REAL (test utility)

| Field | Value |
|---|---|
| Path | `tests/mock-eslogger` |
| Type | Binary (`mock-eslogger`) -- assumed (single main.rs) |
| LoC | 309 |
| Description | Mock eslogger for integration testing |
| publish | false |

**Dependencies:** serde, serde_json, chrono, clap.

---

### 2.16 `clawdefender-app` (Tauri GUI -- EXCLUDED from workspace) -- CLASSIFICATION: REAL

| Field | Value |
|---|---|
| Path | `clients/clawdefender-app/src-tauri` |
| Type | Library (staticlib + cdylib + rlib) + Tauri app |
| LoC (src) | 8,382 |
| Version | 0.3.0 (independent of workspace 0.1.0) |
| Description | ClawDefender MCP Security Monitor (Tauri desktop app) |

**Key modules:** commands.rs (4,575 -- Tauri commands), scanner (1,165), event stream (690), state (556), tray (409), IPC client (324), lib (281), daemon (151), monitor (77), events (76), windows (72), main (6).

**Workspace deps:** clawdefender-slm (with features = ["cloud", "download"]).

**Tauri plugins:** shell, autostart, notification, updater, process.

**External deps:** tauri 2, rusqlite (bundled), dirs 5, libc.

**Note:** Only depends on clawdefender-slm, not on core or any other workspace crate. This means the Tauri app has significant duplicated logic (its own commands.rs is 4,575 lines).

---

## Section 3: Non-Rust Components

### 3.1 Network Extension (Swift)

| Field | Value |
|---|---|
| Path | `extensions/clawdefender-network` |
| Language | Swift (Swift Package) |
| LoC | 1,434 |
| Type | macOS Network Extension (Content Filter + DNS Proxy) |

**Files:** FilterDataProvider (157), FilterControlProvider (186), DNSProxyProvider (260), DaemonBridge (264), PolicyEvaluator (138), ProcessResolver (88), FlowLogger (102), Types (126), main (113).

### 3.2 Fuzz Targets

| Field | Value |
|---|---|
| Path | `fuzz/` |
| LoC | 55 |
| Targets | fuzz_jsonrpc_parser, fuzz_policy_engine, fuzz_eslogger_parser |
| publish | false |

**Deps:** libfuzzer-sys, clawdefender-mcp-proxy, clawdefender-core, clawdefender-sensor.

### 3.3 SDKs

| SDK | Path | Language | LoC |
|---|---|---|---|
| Python | `sdks/python/` | Python | 1,159 |
| Python Agent | `sdks/python-agent/` | Python | 1,185 |
| TypeScript | `sdks/typescript/` | TypeScript | 1,016 |
| TypeScript Agent | `sdks/typescript-agent/` | TypeScript | 1,161 |

---

## Section 4: Binaries Produced

| Binary | Source Crate | Path |
|---|---|---|
| `clawdefender-daemon` | clawdefender-daemon | `crates/clawdefender-daemon/src/main.rs` |
| `clawdefender-mcp-proxy` | clawdefender-mcp-proxy | `crates/clawdefender-mcp-proxy/src/main.rs` |
| `clawdefender` | clawdefender-cli | `clients/clawdefender-cli/src/main.rs` |
| `mock-mcp-server` | mock-mcp-server | `tests/mock-mcp-server/src/main.rs` |
| `mock-eslogger` | mock-eslogger | `tests/mock-eslogger/src/main.rs` |
| `fuzz_jsonrpc_parser` | clawdefender-fuzz | `fuzz/fuzz_targets/fuzz_jsonrpc_parser.rs` |
| `fuzz_policy_engine` | clawdefender-fuzz | `fuzz/fuzz_targets/fuzz_policy_engine.rs` |
| `fuzz_eslogger_parser` | clawdefender-fuzz | `fuzz/fuzz_targets/fuzz_eslogger_parser.rs` |
| Tauri app bundle | clawdefender-app | `clients/clawdefender-app/src-tauri/` |

---

## Section 5: Inter-Crate Dependency Map

```
clawdefender-core  <--  ALL workspace crates except threat-intel
                        (core is the foundation)

clawdefender-threat-intel  <--  daemon, mcp-proxy, CLI
                               (standalone -- does NOT depend on core)

clawdefender-slm       <--  daemon, mcp-proxy, CLI, Tauri app
clawdefender-swarm     <--  daemon, mcp-proxy, tui, CLI
clawdefender-sensor    <--  daemon, fuzz
clawdefender-mcp-proxy <--  daemon, CLI, fuzz
clawdefender-tui       <--  daemon
clawdefender-mcp-server <-- daemon, CLI
clawdefender-guard     <--  daemon
clawdefender-certify   <--  CLI
clawdefender-scanner   <--  CLI

Top-level consumers (not depended on by others):
  - clawdefender-daemon (9 workspace deps -- central hub)
  - clawdefender-cli (8 workspace deps -- CLI frontend)
  - clawdefender-app (1 workspace dep: slm only -- Tauri GUI)
```

---

## Section 6: Dead Crate Analysis

**All workspace crates are depended upon by at least one top-level binary.** No dead crates found.

| Crate | Consumers | Verdict |
|---|---|---|
| clawdefender-certify | CLI only | Active (niche but used) |
| clawdefender-scanner | CLI only | Active (niche but used) |
| clawdefender-tui | daemon only | Active |
| clawdefender-guard | daemon only | Active |
| mock-mcp-server | test utility | Active (integration tests) |
| mock-eslogger | test utility | Active (integration tests) |

**Potential concern:** `clawdefender-tui` has no tests and only 1,369 LoC. It is functional but may be under-tested.

**Potential concern:** `clawdefender-cli` has no test directory despite being 6,190 LoC.

---

## Section 7: Classification Summary

| Crate | LoC (src) | LoC (tests) | Classification |
|---|---|---|---|
| clawdefender-core | 20,216 | 4,685 | REAL |
| clawdefender-mcp-proxy | 4,961 | 574 | REAL |
| clawdefender-sensor | 6,041 | 974 | REAL |
| clawdefender-slm | 6,497 | 839 | REAL |
| clawdefender-swarm | 5,017 | 746 | REAL |
| clawdefender-tui | 1,369 | 0 | REAL |
| clawdefender-daemon | 4,473 | 992 | REAL |
| clawdefender-mcp-server | 3,887 | 1,664 | REAL |
| clawdefender-certify | 1,837 | 409 | REAL |
| clawdefender-scanner | 8,711 | 827 | REAL |
| clawdefender-guard | 7,272 | 3,521 | REAL |
| clawdefender-threat-intel | 7,304 | 0 (inline) | REAL |
| clawdefender-cli | 6,190 | 0 | REAL |
| clawdefender-app (Tauri) | 8,382 | 0 | REAL |
| mock-mcp-server | 264 | 0 | REAL (test util) |
| mock-eslogger | 309 | 0 | REAL (test util) |
| **TOTAL** | **~92,984** | **~15,231** | |

**Verdict: All 16 crates are REAL -- substantial implementation with no stubs or skeletons.**

---

## Appendix C: Feature Flag Matrix

Only `clawdefender-slm` defines feature flags. All other crates have zero feature flags.

| Crate | Feature | What It Enables | Default? | Used in Source? | Enabled By |
|---|---|---|---|---|---|
| clawdefender-slm | `cloud` | Cloud LLM backend via reqwest | No | Yes (`lib.rs:15`) | Tauri app |
| clawdefender-slm | `download` | Model downloader (reqwest, sha2, futures-util, tokio-util, uuid, libc) | No | Yes (`lib.rs:18`, `model_manager.rs:102`) | Tauri app |
| clawdefender-slm | `gguf` | Local GGUF inference via llama_cpp | No | Yes (`lib.rs:21`, `lib.rs:77`) | **NOBODY** |

### Feature Flag Observations

1. **`gguf` feature is defined and code-gated but never enabled by any workspace consumer.** The `gguf_backend.rs` (197 LoC) module exists but is dead code in all current build configurations. This is likely intentional (optional local inference) but worth noting.

2. **`cloud` and `download` are only enabled by the Tauri app** (`clients/clawdefender-app/src-tauri/Cargo.toml`). The daemon, CLI, and mcp-proxy all depend on `clawdefender-slm` without enabling any features, meaning they only get the rule-based/local engine, not cloud or download capabilities.

3. **No crate uses `cfg(target_os)` feature gating** except `clawdefender-swarm` which has a `cfg(target_os = "macos")` dependency on `security-framework` (not a feature flag, but platform-conditional).

---

*End of workspace audit.*
