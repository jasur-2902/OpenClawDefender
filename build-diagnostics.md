# ClawDefender Build Diagnostics Report

**Date:** 2026-03-29
**Branch:** production
**Workspace version:** 0.5.0-beta

---

## Executive Summary

| Category   | Errors | Warnings |
|------------|--------|----------|
| DEPENDENCY | 0      | 7 (duplicate crate versions) |
| FEATURE    | 0      | 0        |
| CODE       | 0      | 25       |
| SYSTEM     | 0      | 0        |
| **Total**  | **0**  | **32**   |

**All workspace crates and the Tauri app build successfully with zero errors.** The project is in a compilable state. There are 25 code warnings (mostly dead code in the Tauri app) and 7 duplicate dependency version pairs.

---

## Build Commands Executed

| Command | Result |
|---------|--------|
| `cargo check --workspace` | PASS (1 warning) |
| `cargo build -p clawdefender-daemon` | PASS (1 warning, same as above) |
| `cargo build -p clawdefender-cli` | PASS (1 warning, same as above) |
| `cargo build -p clawdefender-slm --features "gguf,cloud,download"` | PASS (clean) |
| `cargo test --workspace --no-run` | PASS (4 warnings in test code) |
| `cargo check` (Tauri app, separate workspace) | PASS (20 warnings) |
| `cargo build` (Tauri app) | PASS (20 warnings) |

**Note:** `cargo build -p clawdefender-daemon --features gguf` fails with "package does not contain this feature" because the daemon does not expose `gguf` as its own feature -- it hardcodes `features = ["gguf"]` on its `clawdefender-slm` dependency in Cargo.toml. This is intentional, not a bug.

---

## Detailed Warnings

### Category: CODE -- Unused Import (Workspace)

| # | Crate | File:Line | Warning | Severity |
|---|-------|-----------|---------|----------|
| 1 | clawdefender-slm | `crates/clawdefender-slm/src/model_manager.rs:5` | unused import: `bail` | Warning |

**Analysis:** `bail!` macro was imported but is not used after a prior refactor removed the code that called it. Safe to remove.

### Category: CODE -- Unused Import (Test Code)

| # | Crate | File:Line | Warning | Severity |
|---|-------|-----------|---------|----------|
| 2 | clawdefender-threat-intel | `crates/clawdefender-threat-intel/src/telemetry/tests.rs:5` | unused import: `std::collections::HashMap` | Warning |
| 3 | clawdefender-cli | `clients/clawdefender-cli/src/commands/wrap.rs:436` | unused import: `backup_config` | Warning |
| 4 | clawdefender-cli | `clients/clawdefender-cli/src/commands/wrap.rs:459` | unused variable: `ext` | Warning |
| 5 | clawdefender-core | `crates/clawdefender-core/tests/behavioral_e2e_test.rs:61` | function `make_os_connect` is never used | Warning |

**Analysis:** Minor test/dev code hygiene issues. No impact on production builds.

### Category: CODE -- Dead Code in Tauri App (20 warnings)

The Tauri app (`clients/clawdefender-app/src-tauri`) has 20 dead-code warnings. These indicate new modules/functions that were written but not yet wired into the main app flow:

| # | File:Line | Item | Type |
|---|-----------|------|------|
| 6 | `src/commands.rs:1651` | `validate_server_command` | unused function |
| 7 | `src/commands.rs:1668` | `parse_scan_findings_count` | unused function |
| 8 | `src/conversation/context.rs:49` | `MAX_HISTORY` | unused constant |
| 9 | `src/conversation/context.rs:57` | `ConversationContext::new` | unused method |
| 10 | `src/conversation/context.rs:69` | `ConversationContext::add_turn` | unused method |
| 11 | `src/conversation/context.rs:97` | `ConversationContext::update_from_classification` | unused method |
| 12 | `src/conversation/context.rs:105` | `ConversationContext::resolve_entity` | unused method |
| 13 | `src/conversation/context.rs:129` | `ConversationContext::resolve_pronouns` | unused method |
| 14 | `src/conversation/context.rs:157` | `ConversationContext::detect_follow_up` | unused method |
| 15 | `src/conversation/context.rs:185` | `ConversationContext::last_intent` | unused method |
| 16 | `src/conversation/context.rs:193` | `ConversationContext::reset` | unused method |
| 17 | `src/conversation/context.rs:201` | `ConversationContext::update_last_entities` | unused method |
| 18 | `src/conversation/rate_limiter.rs:15` | `RateLimiter` struct | never constructed |
| 19 | `src/conversation/rate_limiter.rs:25+` | `RateLimiter` methods (5 items) | never used |
| 20 | `src/conversation/synthesizer.rs:1067` | `build_llm_prompt` | unused function |
| 21 | `src/conversation/synthesizer.rs:1103` | `verify_llm_response` | unused function |
| 22 | `src/conversation/synthesizer.rs:1108` | `strip_canary` | unused function |
| 23 | `src/conversation/synthesizer.rs:1114` | `LlmPrompt` struct | never constructed |
| 24 | `src/conversation/formatter.rs:181` | `format_file_size` | unused function |
| 25 | `src/conversation/templates.rs:146` | `LLM_SYSTEM_PROMPT` | unused constant |
| 26 | `src/conversation/templates.rs:255` | `HELP_EXAMPLES` | unused constant |
| 27 | `src/guidance/triggers.rs:39` | `check_score_drop` | unused function |
| 28 | `src/humanizer/context.rs:5` | `BehavioralContextData` struct | never constructed |
| 29 | `src/humanizer/context.rs:54` | `generate_behavioral_context_with_count` | unused function |
| 30 | `src/humanizer/templates.rs:28` | `EventPattern::OutOfTerritory` variant | never constructed |
| 31 | `src/monitor.rs:30` | `LAST_KNOWN_UPTIME` static | never used |
| 32 | `src/monitor.rs:305` | `last_known_uptime` | unused function |
| 33 | `src/monitor.rs:310` | `set_last_known_uptime` | unused function |

**Analysis:** These are mostly conversation/AI integration modules that have been implemented but not yet called from the main app logic. The `conversation/` module (context, rate_limiter, synthesizer, formatter, templates) is entirely unused. The `humanizer/` and `guidance/` modules are partially unused. The `monitor.rs` uptime tracking functions are unused. This is new code staged for future integration, not regression.

---

## Duplicate Dependencies

The following crates have multiple versions compiled into the workspace. Most are transitive and benign (different semver-major), but some could be unified:

| Crate | Versions | Cause | Impact |
|-------|----------|-------|--------|
| `dirs` | 5.0.1, 6.0.0 | `clawdefender-guard` and `clawdefender-threat-intel` use v5; `clawdefender-mcp-server` uses v6 | Minor binary bloat. Could unify to v6. |
| `dirs-sys` | 0.4.1, 0.5.0 | Transitive from `dirs` split | Follows from `dirs` duplication |
| `itertools` | 0.12.1, 0.13.0 | v0.12 from `bindgen` (build dep for llama_cpp); v0.13 from `ratatui` | Benign -- different semver, build vs runtime |
| `hashbrown` | 0.14.5, 0.15.5, 0.16.1 | Transitive from `rusqlite`, `ratatui`, `indexmap` | Benign, all transitive |
| `rand` | 0.8.5, 0.9.2 | `clawdefender-scanner` uses v0.8; `clawdefender-mcp-server` uses v0.9 | Could unify to v0.9 |
| `getrandom` | 0.2.17, 0.3.4, 0.4.1 | Transitive from different `rand`/`uuid` versions | Follows from `rand` split |
| `thiserror` | 1.0.69, 2.0.18 | v1 from `llama_cpp` (transitive); v2 from workspace | Cannot unify (llama_cpp upstream) |
| `core-foundation` | 0.9.4, 0.10.1 | macOS system crate, transitive | Cannot unify (upstream) |
| `rustix` | 0.38.44, 1.1.3 | Different semver-major, transitive | Cannot unify |
| `unicode-width` | 0.1.14, 0.2.0 | Transitive from `ratatui` ecosystem | Cannot unify |

**Actionable:** Only `dirs` (v5 -> v6) and `rand` (v0.8 -> v0.9) could potentially be unified in workspace crate code. The rest are driven by upstream transitive dependencies.

---

## Workspace Crate Structure

### Workspace Members (Cargo.toml)

```
crates/
  clawdefender-core          (lib) - Foundation: policy, config, audit, behavioral analysis
  clawdefender-mcp-proxy     (lib+bin) - MCP protocol proxy
  clawdefender-sensor        (lib) - System event sensing (ES, filesystem)
  clawdefender-slm           (lib) - Small language model integration [features: gguf, cloud, download]
  clawdefender-swarm         (lib) - Multi-agent orchestration
  clawdefender-tui           (lib) - Terminal UI
  clawdefender-daemon        (lib+bin) - Main daemon orchestrator
  clawdefender-mcp-server    (lib) - MCP server implementation
  clawdefender-certify       (lib) - Configuration certification
  clawdefender-scanner       (lib) - Security scanner
  clawdefender-guard         (lib) - Runtime guards and enforcement
  clawdefender-threat-intel  (lib) - Threat intelligence feeds

clients/
  clawdefender-cli           (bin) - CLI client

tests/
  mock-mcp-server            (bin) - Test mock MCP server
  mock-eslogger              (bin) - Test mock ES logger
```

### Excluded from Workspace

```
clients/clawdefender-app/src-tauri  - Tauri desktop GUI app (separate Cargo workspace)
```

### Internal Dependency Graph

```
clawdefender-core (foundation - depended on by ALL other crates)
  |
  +-- clawdefender-slm [features: gguf, cloud, download]
  |     depends on: core
  |
  +-- clawdefender-sensor
  |     depends on: core
  |
  +-- clawdefender-guard
  |     depends on: core
  |
  +-- clawdefender-certify
  |     depends on: core
  |
  +-- clawdefender-scanner
  |     depends on: core
  |
  +-- clawdefender-mcp-server
  |     depends on: core
  |
  +-- clawdefender-threat-intel
  |     depends on: (no core dep -- standalone with chrono, serde, etc.)
  |
  +-- clawdefender-swarm
  |     depends on: core
  |
  +-- clawdefender-tui
  |     depends on: core, swarm
  |
  +-- clawdefender-mcp-proxy
  |     depends on: core, slm, swarm, threat-intel
  |
  +-- clawdefender-daemon (top-level orchestrator)
  |     depends on: core, mcp-proxy, sensor, slm[gguf], swarm, tui,
  |                 mcp-server, guard, threat-intel
  |
  +-- clawdefender-cli (top-level client)
        depends on: core, mcp-proxy, slm[gguf], swarm, mcp-server,
                    certify, scanner, threat-intel
```

### Feature Flag Chain

```
clawdefender-slm:
  default = []
  gguf    = ["llama_cpp"]       -- Native GGUF model inference via llama.cpp
  cloud   = ["reqwest"]         -- Cloud API calls
  download = ["reqwest", "sha2", "futures-util", "tokio-util", "uuid", "libc"]

clawdefender-daemon -> clawdefender-slm [gguf]  (hardcoded in Cargo.toml)
clawdefender-cli    -> clawdefender-slm [gguf]  (hardcoded in Cargo.toml)
clawdefender-mcp-proxy -> clawdefender-slm []   (no features, default only)
```

**Note:** The `cloud` and `download` features of `clawdefender-slm` are NOT enabled by any workspace consumer. They must be explicitly requested when building the SLM crate standalone. This means model downloading and cloud inference are only available in standalone SLM builds, not in the daemon or CLI. This may be intentional or an oversight.

---

## Platform / System Notes

- **llama_cpp (v0.3.2):** Builds successfully on macOS (Darwin 25.4.0, Apple Silicon). Uses `bindgen` + `clang-sys` at build time, compiles `llama_cpp_sys` from source via CMake. Requires Xcode Command Line Tools. Metal/Accelerate support is compiled in automatically on macOS.
- **rusqlite (v0.32.1):** Builds `libsqlite3-sys` from bundled source. No system SQLite dependency required.
- **No linker errors** observed on current platform.
- **No missing system libraries** detected.

---

## Recommendations

1. **Low priority -- Clean up unused import:** Remove `bail` from `crates/clawdefender-slm/src/model_manager.rs:5`
2. **Low priority -- Clean up test warnings:** Fix 4 minor unused import/variable warnings in test code
3. **Consider -- Wire up Tauri dead code or suppress:** The 20 warnings in the Tauri app are all dead code from new modules. Either wire them into the app or add `#[allow(dead_code)]` annotations
4. **Consider -- Unify `dirs` to v6:** Update `clawdefender-guard` and `clawdefender-threat-intel` from `dirs` v5 to v6
5. **Consider -- Unify `rand` to v0.9:** Update `clawdefender-scanner` from `rand` v0.8 to v0.9
6. **Consider -- Propagate `cloud`/`download` features:** If model downloading should work from the daemon or CLI, those crates need to enable the `download` and/or `cloud` features on their `clawdefender-slm` dependency
