# Agent 6 — Config & Paths Audit Report

## Standard Path Convention

The project uses these standard directories:

| Category | Path | Contents |
|----------|------|----------|
| Config | `~/.config/clawdefender/` | config.toml, policy.toml, noise.toml, sensor.toml, honeypot/, window-geometry.json |
| Data | `~/.local/share/clawdefender/` | audit.jsonl, profiles.db, clawdefender.pid, clawdefender.sock, daemon.log, model_config.toml, server-token, score_history.db, conversations.db, guidance_state.json, known_servers.json, swarm_usage.db, chat.db |
| Data subdirs | `~/.local/share/clawdefender/` | models/, threat-intel/, crashes/, scans/, exports/, behavioral/ |
| Binary install | `~/.clawdefender/` | bin/clawdefender (self-installer only) |
| Legacy marker | `~/.clawdefender/onboarding_complete` | Onboarding completion flag |

Fallback when `HOME` is not set: `/tmp/clawdefender/` (data) or `/tmp/clawdefender.pid` (PID file).

---

## Issues Found and Fixed

### Issue 1: `threat_intel` vs `threat-intel` (underscore vs hyphen)

**Files:** `clients/clawdefender-app/src-tauri/src/scanner.rs`

The scanner used `threat_intel/blocklist.json` and `threat_intel/feed_meta.json` (underscore) while every other file in the codebase uses `threat-intel/` (hyphen).

**Fix:** Changed both occurrences in scanner.rs from `threat_intel` to `threat-intel`.

- Line 628: `threat_intel/blocklist.json` -> `threat-intel/blocklist.json`
- Line 780: `threat_intel/feed_meta.json` -> `threat-intel/feed_meta.json`

**Impact:** The scanner would silently fail to find the blocklist and feed metadata, causing threat intelligence checks during scans to be skipped.

---

### Issue 2: `known_servers.json` path conflict

**Files:**
- `clients/clawdefender-app/src-tauri/src/wrap_flow.rs` (was `~/.clawdefender/known_servers.json`)
- `clients/clawdefender-app/src-tauri/src/tools/detection.rs` (was `~/.local/share/clawdefender/known_servers.json`)

Two different modules stored/read `known_servers.json` from different base directories.

**Fix:** Changed wrap_flow.rs to use `~/.local/share/clawdefender/known_servers.json` to match the standard data directory.

**Impact:** Servers wrapped via `wrap_flow` would be invisible to `tools/detection` and vice versa, causing the app to show inconsistent server state.

---

### Issue 3: `guidance_state.json` in wrong directory

**File:** `clients/clawdefender-app/src-tauri/src/guidance/storage.rs`

Used `~/.clawdefender/guidance_state.json` instead of the standard data directory.

**Fix:** Changed to `~/.local/share/clawdefender/guidance_state.json`.

**Impact:** Guidance state was stored in a non-standard location, would not be included in standard data-dir backups, and would not be cleaned up by the uninstaller's data-dir removal.

---

### Issue 4: `exports/` directory in wrong base

**File:** `clients/clawdefender-app/src-tauri/src/commands.rs`

Used `~/.clawdefender/exports` for export output.

**Fix:** Changed to `~/.local/share/clawdefender/exports`. Also fixed the corresponding test.

**Impact:** Exports were written to a non-standard location.

---

### Issue 5: `dirs::data_dir()` returns wrong path on macOS

**Files:**
- `crates/clawdefender-mcp-server/src/auth.rs`
- `crates/clawdefender-guard/src/api_auth.rs`
- `crates/clawdefender-threat-intel/src/cache.rs`
- `clients/clawdefender-app/src-tauri/src/conversation/storage.rs`
- `clients/clawdefender-app/src-tauri/src/windows.rs`

The `dirs` crate's `data_dir()`, `data_local_dir()`, and `config_dir()` functions return macOS-native paths on macOS:
- `dirs::data_dir()` -> `~/Library/Application Support/`
- `dirs::config_dir()` -> `~/Library/Application Support/`

But the project convention is:
- Data: `~/.local/share/clawdefender/`
- Config: `~/.config/clawdefender/`

These modules would write to `~/Library/Application Support/clawdefender/` on macOS while every other module writes to `~/.local/share/clawdefender/`. This means the server-token, conversations database, threat-intel cache, and window geometry would end up in the wrong location.

**Fix:** Replaced all `dirs::data_dir()`, `dirs::data_local_dir()`, and `dirs::config_dir()` calls with explicit `$HOME/.local/share/clawdefender/` and `$HOME/.config/clawdefender/` path construction using `std::env::var("HOME")`.

**Impact:** On macOS, the server-token file would be written to `~/Library/Application Support/clawdefender/server-token` but the daemon reads it from `~/.local/share/clawdefender/server-token`, causing authentication failures between the MCP server and daemon. Similarly, conversations and threat-intel cache would be stored in an unreachable location.

---

## Verified: No Issues Found

### Default Policy TOML (`policies/default.toml`)

- Valid TOML syntax (parses successfully)
- All actions are valid: `block`, `prompt`, `allow`, `log`
- All rules have required fields: `description`, `action`, `message`, `priority`, `match` section
- Match criteria use valid field names: `resource_path`, `tool_name`, `method`, `any`
- Glob patterns in resource_path are valid
- Priority ordering is correct (block < prompt < allow < log catch-all)
- Existing unit test `test_default_policy_parses` confirms parsing

### Init Script Default Policy (`clients/clawdefender-cli/src/commands/init.rs`)

- The `DEFAULT_POLICY` constant is valid TOML
- Includes block_honeypot, block_ssh_keys, prompt_shell, log_all rules
- Action values are all valid
- Existing unit test `test_default_policy_parses` confirms

### Init Script Default Config (`clients/clawdefender-cli/src/commands/init.rs`)

- The `DEFAULT_CONFIG` constant is valid TOML
- Contains `[log_rotation]`, `[eslogger]`, and `[ui]` sections
- Commented-out paths (`policy_path`, `audit_log_path`) match standard locations
- Existing unit test `test_default_config_parses` confirms

### Config Defaults (`crates/clawdefender-core/src/config/settings.rs`)

- `default_socket_path()` -> `~/.local/share/clawdefender/clawdefender.sock` (correct)
- `default_audit_log_path()` -> `~/.local/share/clawdefender/audit.jsonl` (correct)
- `default_policy_path()` -> `~/.config/clawdefender/policy.toml` (correct)
- `default_sensor_config_path()` -> `~/.config/clawdefender/sensor.toml` (correct)
- `dirs_next_fallback()` uses `$HOME` with `/tmp/` fallback (correct pattern)
- Install script output messages match: "Configuration: ~/.config/clawdefender/" and "Audit logs: ~/.local/share/clawdefender/"

### Install Script (`scripts/install.sh`)

- Runs `clawdefender init` which creates both config and data directories
- Output messages reference correct paths
- Does not create directories itself (delegates to `clawdefender init`)

### Daemon PID file

- `crates/clawdefender-daemon/src/lib.rs:1583` -> `~/.local/share/clawdefender/clawdefender.pid`
- `clients/clawdefender-cli/src/commands/daemon.rs:192` -> `~/.local/share/clawdefender/clawdefender.pid`
- Both fallback to `/tmp/clawdefender.pid` when HOME is unset (consistent)

### Legacy `~/.clawdefender/` Usage

The `~/.clawdefender/` directory is used only for:
1. **Self-installer binary**: `~/.clawdefender/bin/clawdefender` + PATH export (installer/mod.rs)
2. **Onboarding marker**: `~/.clawdefender/onboarding_complete` (state.rs)
3. **Uninstaller**: Correctly removes `~/.clawdefender/`, `~/.config/clawdefender/`, and `~/.local/share/clawdefender/`

These are intentional legacy paths for the self-install mechanism and are correctly handled.

---

## Remaining Notes

- The `dirs` crate is still a dependency in 4 crates but the path-critical calls have been replaced. The `dirs` crate is still used for `dirs::home_dir()` which returns the correct home directory on all platforms. The `home_dir()` usage is safe.
- All `/tmp/clawdefender*` fallback paths are consistent and only used when `$HOME` is not set.
- Test files correctly use `tempfile::TempDir` with relative subpaths matching the standard layout.
