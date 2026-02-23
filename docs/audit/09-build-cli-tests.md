# ClawDefender Audit Report: Build System, CLI Tools & Test Coverage

---

## Section 14: CLI Tools

### 14.1 CLI Binary (`clawdefender-cli`)

**Binary name:** `clawdefender`
**Entry point:** `clients/clawdefender-cli/src/main.rs`
**Framework:** clap v4 (derive macros)
**Global option:** `--config <PATH>` to override config file (default: `~/.config/clawdefender/config.toml`)

All logging goes to stderr (critical for proxy mode where stdout is JSON-RPC).

#### Top-Level Commands

| Command | Description | Implementation Status |
|---------|-------------|----------------------|
| `init` | Initialize config directory with defaults | Real (`commands/init.rs`) |
| `wrap <server> [--client] [--all]` | Inject ClawDefender proxy into MCP client config | Real (`commands/wrap.rs`) |
| `unwrap <server> [--client]` | Restore original MCP server config | Real (`commands/unwrap.rs`) |
| `proxy -- <cmd> [args]` | Run as stdio MCP proxy (called by wrapped configs) | Real, async (`commands/proxy.rs`) |
| `status` | Check ClawDefender and MCP client status | Real (`commands/status.rs`) |
| `policy {list,add,test,reload,template-list,template-apply,suggest}` | Manage policy rules | Real (`commands/policy.rs`) |
| `log [--blocked] [--server] [--source] [--agent] [--stats] [-n]` | View audit log with filters | Real (`commands/log.rs`) |
| `doctor` | Diagnostic checks on installation | Real (`commands/doctor.rs`) |
| `model {download,list,set,off,on,stats}` | Manage local SLM models | Real (`commands/model.rs`) |
| `config {set-api-key,get-api-key,remove-api-key,list-api-keys}` | Manage API keys and cloud LLM config | Real (`commands/config.rs`) |
| `usage [--detail] [--reset]` | View cloud swarm token usage and costs | Real (`commands/usage.rs`) |
| `chat <event_id> [--list]` | Chat with AI security analyst about flagged events | Real, async (`commands/chat.rs`) |
| `daemon {start,stop,status,restart}` | Manage daemon lifecycle | Real (`commands/daemon.rs`) |
| `behavioral {status,calibrate,stats}` | Manage behavioral baseline engine | Real (`commands/behavioral.rs`) |
| `profile {list,show,reset,export}` | Manage behavioral profiles per server | Real (`commands/profile_cmd.rs`) |
| `certify -- <cmd> [--json] [--output]` | Run Claw Compliant certification | Real, async (delegates to `clawdefender-certify`) |
| `serve [--stdio] [--http-port]` | Start ClawDefender's own MCP server | Real, async (`commands/serve.rs`) |
| `guard {list,show,kill,test}` | Manage agent guards | Real (`commands/guard.rs`) |
| `feed {status,update,verify}` | Manage threat intelligence feeds | Real (`commands/threat_intel.rs`) |
| `rules {list,install,uninstall,update}` | Manage community rule packs | Real (`commands/threat_intel.rs`) |
| `ioc {status,add,test}` | Manage IoC database | Real (`commands/threat_intel.rs`) |
| `telemetry {status,preview,enable,disable}` | Manage anonymous telemetry | Real (`commands/threat_intel.rs`) |
| `network {...}` | Manage network policy, DNS filter, connection rules | Real (`commands/network.rs`) |
| `reputation <server>` | Check server reputation against blocklist | Real (`commands/threat_intel.rs`) |
| `scan -- <cmd> [--timeout] [--modules] [--json] [--html] [--output] [--threshold] [--baseline] [--list-modules]` | Run security scan against MCP server | Real, async (`commands/scan.rs`) |

**Total: 22 top-level commands** with extensive subcommands. All route to real implementations.

#### Supported MCP Clients (Auto-Detection)

The CLI discovers and wraps MCP servers in these clients:
- **Claude Desktop** (macOS: `~/Library/Application Support/Claude/config.json`)
- **Cursor** (`~/.cursor/mcp.json`)
- **VS Code** (`~/.vscode/mcp.json`)
- **Windsurf** (`~/.codeium/windsurf/mcp_config.json`)
- **DXT Extensions** (Claude Desktop extension format via `extensions-installations.json`)

Auto-detection handles both `mcpServers` and `servers` key formats for Cursor compatibility.

#### CLI Helper Functions (`commands/mod.rs`)

- `honeypot_dir()` -- returns honeypot canary directory path
- DXT extension discovery: `find_dxt_extension()`, `list_dxt_extensions()`, `is_dxt_wrapped()`
- Client config management: `known_clients()`, `find_client_config()`, `read_config()`, `write_config()`, `backup_config()`
- `is_wrapped()` -- checks both `_clawdefender_original` and legacy `_clawai_original`
- `detect_servers_key()` -- handles `mcpServers` vs `servers`

### 14.2 Daemon Binary (`clawdefender-daemon`)

**Binary name:** `clawdefender-daemon`
**Entry point:** `crates/clawdefender-daemon/src/main.rs`
**Framework:** clap v4 (derive macros)

#### Daemon CLI Arguments

| Argument | Description |
|----------|-------------|
| `-c / --config <PATH>` | Config file path (default: `~/.config/clawdefender/config.toml`) |
| `--tui` | Enable terminal UI dashboard |
| `--policy <PATH>` | Override policy file path |

#### Daemon Subcommands

| Subcommand | Description |
|------------|-------------|
| `run` (default) | Run daemon in standalone mode (IPC server, sensors, audit) |
| `proxy -- <cmd> [args]` | Proxy an MCP server, intercepting JSON-RPC messages |

Logging behavior: when `--tui` is enabled, logs go to `~/.local/share/clawdefender/daemon.log` (file). Otherwise, logs go to stderr. Verbosity controlled by `CLAWDEFENDER_LOG` env var.

---

## Section 15: Build System & DevOps

### 15.1 Workspace Configuration (`Cargo.toml`)

- **Resolver:** 2
- **Members:** 14 crates + 2 test helpers
- **Excluded:** `clients/clawdefender-app/src-tauri` (separate build)
- **Version:** 0.1.0 (workspace-wide)
- **Edition:** 2021
- **License:** Apache-2.0 OR MIT

#### Release Profile

```toml
[profile.release]
lto = "fat"
codegen-units = 1
strip = true
opt-level = "z"       # optimize for binary size
panic = "abort"
```

This is an aggressive size-optimized release profile. `opt-level = "z"` prioritizes small binary size over speed. `panic = "abort"` eliminates unwind tables. `lto = "fat"` enables full cross-crate link-time optimization. `strip = true` removes debug symbols.

### 15.2 Rust Toolchain (`rust-toolchain.toml`)

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

Pinned to stable channel. No MSRV specified.

### 15.3 Justfile Commands

| Command | Description |
|---------|-------------|
| `just dev` | `cargo build --workspace` |
| `just test` | `cargo test --workspace` |
| `just lint` | `cargo fmt --check` + `cargo clippy --workspace -- -D warnings` |
| `just audit` | `cargo audit` + `cargo deny check` |
| `just release` | `cargo build --workspace --release` |
| `just build-release` | Alias for `release` |
| `just install` | Build release + copy binaries to `/usr/local/bin` |
| `just install-local` | Build release + install + run `clawdefender init` |
| `just package` | Build release tarball with SHA-256 checksum in `dist/` |
| `just integration-test` | Build workspace + run e2e proxy test + mcp proxy test |
| `just clean` | `cargo clean` + remove `dist/` |
| `just docs` | `cargo doc --workspace --no-deps --open` |
| `just build-menubar` | `swift build` for macOS menu bar app |
| `just fuzz-jsonrpc` | Run JSON-RPC parser fuzzer (requires nightly) |
| `just fuzz-policy` | Run policy engine fuzzer (requires nightly) |
| `just bump-version VERSION` | Update version in workspace Cargo.toml |
| `just build-daemon` | Build just the daemon |
| `just build-app` | Build daemon (release) + npm build + Tauri build |
| `just dev-app` | Build daemon + CLI debug + run Tauri dev mode |
| `just build-sidecar` | Build daemon + copy to Tauri sidecar location |
| `just build-dmg` | Full DMG build pipeline |
| `just build-dmg-target TARGET` | DMG for specific target triple |
| `just build-extension` | Build Swift network extension |
| `just build-all` | Build workspace + Swift extension |
| `just test-network` | Run all network-related tests |
| `just preflight` | lint + test (pre-commit check) |

**Total: 26 just commands** covering development, testing, packaging, and deployment.

### 15.4 cargo-deny Configuration (`deny.toml`)

```toml
[advisories]
vulnerability = "deny"    # Block known vulnerabilities
unmaintained = "warn"     # Warn on unmaintained deps

[licenses]
unlicensed = "deny"
copyleft = "deny"
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-DFS-2016", "Zlib", "Unicode-3.0"]

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

Good supply chain hygiene: blocks unknown registries, denies copyleft, denies wildcards.

### 15.5 CI/CD Pipelines (`.github/workflows/`)

#### `ci.yml` -- Main CI
- **Trigger:** Push to `main`, all PRs
- **Matrix:** macOS-latest, Ubuntu-latest
- **Steps:** fmt check, clippy, `cargo test --workspace`, `cargo doc`
- **Caching:** cargo registry + git + target

#### `security-audit.yml` -- Security Audit
- **Trigger:** Push to `main` + weekly cron (Monday midnight)
- **Steps:** `cargo audit` + `cargo deny check`
- Runs on Ubuntu only

#### `release.yml` -- Release Pipeline
- **Trigger:** Tag push (`v*`)
- **Build:** Cross-compiles for both `aarch64-apple-darwin` and `x86_64-apple-darwin`
- **Universal binary:** Creates macOS universal binary via `lipo`
- **Code signing:** Ad-hoc codesign (Developer ID signing commented out, not yet configured)
- **Output:** Tarball + SHA-256 checksum uploaded to GitHub Release
- **Note:** Apple notarization support scaffolded but commented out

#### `build-app.yml` -- GUI App Build
- **Trigger:** Push to `clawdefender-v0.3` branch + tag push
- **Steps:** TypeScript lint, npm install, Tauri build
- **Output:** DMG uploaded as artifact; GitHub Release created on tag push
- **Platform:** macOS 14 (Apple Silicon)

### 15.6 Build Scripts

- **`clients/clawdefender-app/src-tauri/build.rs`** -- Standard `tauri_build::build()` call. No custom build logic.
- No other `build.rs` files in any crate.

### 15.7 Install/Uninstall Scripts (`scripts/`)

#### `scripts/install.sh`
- macOS-only check (Darwin, version >= 13)
- Architecture check (arm64, aarch64, x86_64)
- Downloads latest release from GitHub
- SHA-256 checksum verification
- Installs `clawdefender` + `clawdefender-daemon` to `/usr/local/bin`
- Runs `clawdefender init` after install
- Clean temp directory on exit (trap)

#### `scripts/uninstall.sh`
- Prompts to unwrap all MCP servers before removal
- Stops and removes LaunchAgent (`com.clawdefender.daemon.plist`)
- Removes binaries from `/usr/local/bin`
- Optionally removes config (`~/.config/clawdefender/`) and audit logs (`~/.local/share/clawdefender/`)

### 15.8 Homebrew Distribution

#### `Formula/clawdefender.rb` (CLI Formula)
- Downloads universal macOS binary tarball from GitHub
- Installs `clawdefender` + `clawdefender-daemon`
- Runs `clawdefender init` post-install
- SHA-256 is a placeholder (`"PLACEHOLDER"`)
- Version: 0.1.0

#### `Homebrew/clawdefender-app.rb` (GUI Cask)
- Downloads DMG from GitHub releases
- Installs ClawDefender.app
- Version: 0.10.0
- SHA-256 set to `:no_check`
- Zap cleanup for app support directories

### 15.9 Tauri App Configuration (`tauri.conf.json`)

- **Product name:** ClawDefender
- **Identifier:** `com.clawdefender.desktop`
- **Version:** 0.3.0 (note: differs from workspace 0.1.0 and cask 0.10.0)
- **Window:** 1200x800 default, 800x600 minimum, centered, resizable
- **CSP:** `default-src 'self'` with localhost connect and unsafe-inline styles
- **Bundle targets:** DMG + .app
- **macOS minimum:** 13.0
- **Entitlements:** `Entitlements.plist`
- **Signing identity:** null (not configured)
- **Updater plugin:** Configured with GitHub releases endpoint, empty public key
- **Tauri plugins used:** autostart, notification, process, shell, updater

### 15.10 Frontend Build (`package.json`)

- **Build tool:** Vite 6
- **Framework:** React 19 + TypeScript 5
- **CSS:** Tailwind CSS v4
- **State:** Zustand v5
- **Routing:** react-router-dom v7
- **Test:** Vitest
- **Scripts:** `dev`, `build` (`tsc && vite build`), `preview`, `test`

### 15.11 macOS Extensions (`extensions/`)

**`extensions/clawdefender-network/`** -- Swift macOS Network Extension

- **Type:** Network Extension (Content Filter + DNS Proxy Provider)
- **Build:** Swift Package Manager (`Package.swift`)
- **Source files:**
  - `DNSProxyProvider.swift` -- DNS proxy for AI traffic
  - `FilterControlProvider.swift` -- Content filter control
  - `FilterDataProvider.swift` -- Content filter data examination
  - `DaemonBridge.swift` -- Communication bridge to Rust daemon
  - `FlowLogger.swift` -- Network flow logging
  - `PolicyEvaluator.swift` -- Network policy evaluation
  - `ProcessResolver.swift` -- Process identification for network flows
  - `Types.swift` -- Shared type definitions
  - `main.swift` -- Entry point
- **Entitlements:** `ClawDefenderNetwork.entitlements`

### 15.12 Developer SDKs (`sdks/`)

#### `sdks/python/` -- Python SDK (MCP Proxy Client)
- Package for Python MCP server developers
- Modules: `client.py`, `connection.py`, `context.py`, `decorators.py`, `exceptions.py`, `types.py`
- Tests: `test_async.py`, `test_client.py`, `test_connection.py`, `test_context.py`, `test_decorators.py`

#### `sdks/python-agent/` -- Python Agent Guard SDK
- Higher-level agent integration
- Modules: `connection.py`, `decorators.py`, `exceptions.py`, `fallback.py`, `guard.py`, `installer.py`, `monitor.py`, `types.py`
- Tests: `test_decorators.py`, `test_fallback.py`, `test_guard.py`, `test_installer.py`, `test_monitor.py`, `test_security.py`

#### `sdks/typescript-agent/` -- TypeScript Agent Guard SDK
- Modules: `connection.ts`, `fallback.ts`, `guard.ts`, `hooks.ts`, `index.ts`, `installer.ts`, `middleware.ts`, `monitor.ts`, `types.ts`, `wrappers.ts`
- Tests: `fallback.test.ts`, `guard.test.ts` (and likely more)
- Test framework: Jest

### 15.13 Documentation (`docs/`)

Extensive documentation covering:
- **Architecture:** `architecture.md`, `network-architecture.md`
- **ADRs:** 6 Architecture Decision Records (001-006)
- **Guides:** SLM, swarm, behavioral, guard, scanner, sensor, GUI, menubar, network extension, REST API, MCP protocol, threat intelligence
- **Security:** threat model, behavioral security, SLM security, swarm security, guard security, SDK security, sensor security, vulnerability catalog
- **Release notes:** v1 through v12
- **Integration guides:** Aider, Claude Desktop, Cursor, OpenHands, SWE-Agent
- **Bug tracking:** `docs/bugs/` directory with known issues
- **Manual test plans:** `docs/manual-tests/`
- **PR templates:** `docs/integrations/pr-templates/`

### 15.14 Version Inconsistencies

| Location | Version |
|----------|---------|
| Workspace `Cargo.toml` | 0.1.0 |
| `tauri.conf.json` | 0.3.0 |
| `package.json` | 0.10.0 |
| `Homebrew/clawdefender-app.rb` | 0.10.0 |
| `Formula/clawdefender.rb` | 0.1.0 |

These version numbers are inconsistent across the project. The `just bump-version` command only updates the workspace `Cargo.toml`.

---

## Section 19: Test Coverage

### 19.1 Test Counts by Crate

| Crate | Unit Tests (inline) | Integration Test Files | Total `#[test]` Count |
|-------|---------------------|----------------------|----------------------|
| `clawdefender-core` | ~330 (across 17 source files) | 7 files | 452 |
| `clawdefender-slm` | ~156 (across 13 source files) | 3 files | 187 |
| `clawdefender-guard` | ~31 (across 8 source files) | 6 files | 166 |
| `clawdefender-scanner` | ~115 (across 6 source files) | 2 files | 165 |
| `clawdefender-sensor` | ~96 (across 10 source files) | 2 files | 117 |
| `clawdefender-threat-intel` | ~116 (across 14 source files) | 0 files | 116 |
| `clawdefender-swarm` | ~75 (across 10 source files) | 2 files | 95 |
| `clawdefender-daemon` | ~57 (across 2 source files) | 2 files | 87 |
| `clawdefender-mcp-proxy` | ~77 (across 5 source files) | 1 file | 77 |
| `clawdefender-cli` | ~41 (across 5 source files) | 0 files | 41 |
| `clawdefender-mcp-server` | ~27 (across 3 source files) | 3 files | 38 |
| `clawdefender-tui` | ~33 (across 2 source files) | 0 files | 33 |
| `clawdefender-certify` | ~5 (across 1 source file) | 1 file | 22 |

**Total Rust `#[test]` functions: ~1,596**

### 19.2 Ignored Tests

3 tests are marked `#[ignore]` across the entire workspace:
- `crates/clawdefender-mcp-proxy/tests/e2e_proxy_test.rs` (1) -- E2E proxy test requiring workspace build
- `crates/clawdefender-core/tests/mcp_proxy_test.rs` (1) -- MCP proxy integration test
- `tests/integration/mcp_proxy_test.rs` (1) -- Top-level integration test

These are integration tests that require the full workspace to be built first. They are run via `just integration-test`.

### 19.3 Integration Test Files

#### Per-Crate Integration Tests (`tests/` directories)

| Crate | Test File | Focus |
|-------|-----------|-------|
| `clawdefender-core` | `behavioral_e2e.rs` | Behavioral engine end-to-end |
| | `behavioral_e2e_test.rs` | Behavioral engine scenarios |
| | `behavioral_harness.rs` | Test harness utilities |
| | `behavioral_harness_test.rs` | Harness validation |
| | `behavioral_security_tests.rs` | Behavioral security edge cases |
| | `security_tests.rs` | Core security tests |
| | `mcp_proxy_test.rs` | MCP proxy integration (ignored) |
| `clawdefender-mcp-proxy` | `e2e_proxy_test.rs` | End-to-end proxy test (ignored) |
| `clawdefender-daemon` | `guard_integration.rs` | Guard integration |
| | `network_integration.rs` | Network integration |
| `clawdefender-sensor` | `evasion_tests.rs` | Sensor evasion detection |
| | `sensor_integration_tests.rs` | Sensor integration |
| `clawdefender-slm` | `integration_tests.rs` | SLM integration |
| | `injection_tests.rs` | Prompt injection detection |
| | `download_integration_test.rs` | Model download |
| `clawdefender-swarm` | `e2e_pipeline_tests.rs` | Swarm pipeline E2E |
| | `security_tests.rs` | Swarm security |
| `clawdefender-guard` | `guard_tests.rs` | Guard functionality (60 tests) |
| | `integration_tests.rs` | Guard integration (26 tests) |
| | `security_tests.rs` | Guard security (18 tests) |
| | `installer_tests.rs` | Auto-installer (26 tests) |
| | `api_tests.rs` | REST API tests |
| | `perf_tests.rs` | Performance benchmarks |
| `clawdefender-scanner` | `scanner_tests.rs` | Scanner module tests (27 tests) |
| | `integration_tests.rs` | Scanner integration (23 tests) |
| `clawdefender-certify` | `certification_tests.rs` | Certification tests (17 tests) |
| `clawdefender-mcp-server` | `security_tests.rs` | MCP server security |
| | `mcp_server_integration_tests.rs` | Server integration |
| | `sdk_flow_tests.rs` | SDK flow validation |
| | `bench_tests.rs` | Benchmarks |

### 19.4 Mock Servers (`tests/`)

#### `tests/mock-mcp-server/`
Full mock MCP server for integration testing. Handles:
- `initialize` -- returns protocol version and capabilities
- `tools/list` -- returns `read_file`, `write_file`, `run_command`
- `tools/call` -- returns mock result
- `resources/list` -- returns mock resources
- `resources/read` -- returns mock content
- `sampling/createMessage` -- returns mock LLM completion
- Notifications (no-id messages) handled correctly

#### `tests/mock-eslogger/`
Configurable mock eslogger binary for sensor testing. Supports scenarios:
- `basic` -- Realistic event sequence (exec, connect, open, fork, exit)
- `crash` -- Emits events then exits with non-zero code
- `hang` -- Emits events then becomes unresponsive
- `burst` -- Rapid-fire events for rate-limiting tests
- `mixed` -- Two-server interleaved event sequence

Supports configurable delay, count, PID/PPID.

### 19.5 Fuzz Testing (`fuzz/`)

Three cargo-fuzz targets using `libfuzzer-sys`:

| Target | Crate Tested | What It Fuzzes |
|--------|--------------|----------------|
| `fuzz_jsonrpc_parser` | `clawdefender-mcp-proxy` | JSON-RPC message parsing from arbitrary bytes |
| `fuzz_policy_engine` | `clawdefender-core` | Policy TOML parsing via `parse_policy_toml()` |
| `fuzz_eslogger_parser` | `clawdefender-core` | eslogger event deserialization (`OsEvent`) |

All targets verify no-panic behavior on malformed input. Requires nightly toolchain.

### 19.6 SDK Tests (Non-Rust)

#### Python SDK (`sdks/python/tests/`)
- `test_async.py`, `test_client.py`, `test_connection.py`, `test_context.py`, `test_decorators.py`
- Framework: pytest

#### Python Agent SDK (`sdks/python-agent/tests/`)
- `test_decorators.py`, `test_fallback.py`, `test_guard.py`, `test_installer.py`, `test_monitor.py`, `test_security.py`
- Framework: pytest

#### TypeScript Agent SDK (`sdks/typescript-agent/tests/`)
- `fallback.test.ts`, `guard.test.ts`
- Framework: Jest

#### Frontend (`clients/clawdefender-app/`)
- Test command: `vitest run`
- Framework: Vitest

### 19.7 Examples (`examples/`)

| Example | Language | Description |
|---------|----------|-------------|
| `minimal-guard/python.py` | Python | Minimal guard integration |
| `minimal-guard/typescript.ts` | TypeScript | Minimal guard integration |
| `minimal-integration/python_example.py` | Python | Basic SDK usage |
| `minimal-integration/typescript_example.ts` | TypeScript | Basic SDK usage |
| `openclaw-integration/bot.py` | Python | OpenClaw bot integration |
| `python-guarded-agent/main.py` | Python | Full guarded agent example |
| `typescript-guarded-agent/main.ts` | TypeScript | Full guarded agent example |
| `python-mcp-server/` | Python | Complete MCP server with ClawDefender config |
| `typescript-mcp-server/` | TypeScript | Complete MCP server with ClawDefender config |

### 19.8 Test Quality Assessment

**Strengths:**
1. **High test count:** ~1,596 Rust tests across 14 crates
2. **Security-focused testing:** Dedicated security test files in core, guard, swarm, mcp-server, scanner, and behavioral
3. **Behavioral engine:** Extremely well-tested with 452 tests in core alone, including E2E, harness, and security tests
4. **Fuzz testing:** Three fuzz targets covering critical parsing paths (JSON-RPC, policy TOML, eslogger events)
5. **Mock infrastructure:** Well-built mock MCP server and mock eslogger with multiple scenarios
6. **SDK testing:** All three SDKs (Python, Python-Agent, TypeScript-Agent) have test suites
7. **Evasion testing:** Sensor crate has dedicated evasion detection tests
8. **Injection testing:** Both SLM and behavioral crates test prompt injection scenarios

**Weaknesses/Gaps:**
1. **No CI for SDKs:** Python and TypeScript SDK tests are not wired into CI workflows
2. **No CI for frontend tests:** Vitest is configured but not run in CI (build-app.yml only runs TypeScript check, not tests)
3. **Ignored integration tests:** 3 tests require manual invocation via `just integration-test`
4. **TUI crate:** 33 tests but no integration tests (hard to test terminal UIs)
5. **Threat-intel crate:** All 116 tests are inline unit tests, no integration test files
6. **No code coverage reporting:** No coverage tool (tarpaulin, llvm-cov) configured in CI
7. **Homebrew formula:** SHA-256 placeholder in `Formula/clawdefender.rb`, indicating the formula has never been published
8. **No property-based testing** beyond the fuzz targets
9. **CLI integration tests:** Only wrap/unwrap/init/model commands have tests; no tests for daemon, doctor, status, etc.

### 19.9 Overall Test Health: GOOD

The test coverage is substantial for a project of this complexity. The behavioral engine and security subsystems are particularly well-tested. The main gaps are in CI integration for SDK/frontend tests and lack of code coverage metrics. The fuzz testing infrastructure is a positive signal for security-critical parsing code.

---

*Generated: 2026-02-23*
*Audit scope: Build system, CLI tools, test coverage, CI/CD, packaging, extensions, SDKs*
