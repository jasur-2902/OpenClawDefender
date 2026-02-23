# Phase C: Every Control Works

This document summarizes the changes made in Phase C to ensure every UI control
in the ClawDefender desktop application is wired to a real backend action with
persistent state.

## Test Results

Full workspace test suite: **1,774 passed, 0 failed, 15 ignored** (1,789 total).

Quality gates verified:
- Zero `Math.random()` calls in frontend source
- Zero stubbed `console.log` handlers
- All new Tauri commands registered in `lib.rs`

## New Tauri Commands

### `duplicate_rule`
**File:** `src-tauri/src/commands.rs:885`

Duplicates an existing policy rule. Creates a copy with a `-copy` suffix (or
`-copy-2`, `-copy-3`, etc. if the name already exists). The copy's description
is appended with "(copy)". Triggers a daemon reload after writing.

**Parameters:** `rule_name: String`

### `toggle_rule`
**File:** `src-tauri/src/commands.rs:944`

Toggles the `enabled` boolean on a policy rule. Reads the current value and
writes the inverse. Triggers a daemon reload after writing.

**Parameters:** `rule_name: String`

### `reorder_rules`
**File:** `src-tauri/src/commands.rs:986`

Reorders policy rules by assigning priority values based on the provided list
order. The first item receives the highest priority (`N * 10`), decreasing by
10 for each subsequent item. Triggers a daemon reload after writing.

**Parameters:** `rule_names: Vec<String>`

## New Config Keys

All keys are read from and written to `~/.config/clawdefender/config.toml`.

| Section        | Key                    | Type    | Default      | Description                          |
|----------------|------------------------|---------|--------------|--------------------------------------|
| `[behavioral]` | `auto_block`           | bool    | `false`      | Automatically block anomalous agents |
| `[behavioral]` | `anomaly_threshold`    | float   | `0.7`        | Anomaly score threshold (0.0-1.0)    |
| `[slm]`        | `analysis_frequency`   | string  | `"all"`      | How often SLM analyzes tool calls    |

## Settings That Now Persist

All settings are written to `config.toml` via the `update_settings` Tauri
command and read back on app launch via `get_settings`. The following 11
settings are saved across sections:

### `[ui]` section
1. `theme` -- UI theme (dark/light)
2. `notifications` -- Enable/disable notifications
3. `auto_start_daemon` -- Auto-start daemon on launch
4. `minimize_to_tray` -- Minimize to system tray
5. `log_level` -- Logging verbosity (debug/info/warn/error)
6. `event_retention_days` -- Days to retain event logs (minimum 1)

### `[network_policy]` section
7. `prompt_timeout_seconds` -- Seconds before a user prompt times out

### `[behavioral]` section
8. `auto_block` -- Auto-block anomalous agents
9. `anomaly_threshold` -- Anomaly detection sensitivity

### `[slm]` section
10. `analysis_frequency` -- SLM analysis frequency

### Inferred (not stored)
11. `security_level` -- Inferred at read time by comparing active policy rules against known templates

### Additional persisted state
- Onboarding completion flag: written to a dedicated flag file
- API keys: saved/cleared via `save_api_key` / `clear_api_key` commands
- Network settings: saved via `update_network_settings` command
- Autostart: toggled via `enable_autostart` / `disable_autostart` commands
- Policy rules: each add/update/delete/duplicate/toggle/reorder writes to `policy.toml`
- Security templates: applied via `apply_template` which writes policy rules
- Telemetry preference: toggled via `toggle_telemetry`
- Model management: activate/deactivate/delete via dedicated commands
- Import settings: `import_settings_from_content` replaces config from exported file

## Security Review Findings and Fixes

1. **No `Math.random()` usage** -- All random values in the codebase use
   cryptographically appropriate sources (Rust-side `rand` crate). The frontend
   contains zero calls to `Math.random()`.

2. **No stubbed handlers** -- Every button and action in the UI invokes a real
   Tauri command. No `console.log("TODO")` or placeholder stubs remain.

3. **Input sanitization** -- Rule names are sanitized via `sanitize_rule_key()`
   before being used as TOML keys, preventing injection of special characters.

4. **Validation** -- `event_retention_days` is validated to be >= 1, preventing
   accidental deletion of all logs. Settings are validated before persistence.

5. **Daemon reload** -- All policy-mutating commands call `try_reload_daemon()`
   to ensure the running daemon picks up changes immediately.

6. **Config directory creation** -- `update_settings` creates parent directories
   if they do not exist, preventing write failures on first run.
