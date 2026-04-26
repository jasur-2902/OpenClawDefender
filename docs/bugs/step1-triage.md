# Rookbot Bug Triage Report

Generated: 2026-02-25

---

## Bug 1: Guards Page -- Toggle Only Updates Local State; Backend Returns Empty

**Severity: BROKEN**

### Files and Line Numbers

- `clients/clawdefender-app/src/pages/Guards.tsx` (working tree, lines 100-107) -- toggle onClick handler only calls `setGuards()` to flip `enabled` in React state. No `invoke()` call to Tauri backend.
- `clients/clawdefender-app/src-tauri/src/commands.rs` line 1460 -- `list_guards()` returns `Ok(vec![])` unconditionally. Comment on line 1455-1458 says: "Guards are in-memory only in the daemon's GuardRegistry. There is no way to enumerate registered guards from outside the daemon, so we return an empty list."
- `crates/clawdefender-daemon/src/ipc.rs` lines 126-265 -- The daemon IPC server handles `GuardRequest::GuardRegister`, `GuardDeregister`, `GuardStatsQuery`, and `GuardHealthCheck`, but there is **no `list` or `enumerate` IPC command** exposed. The `registry.list().await` method exists and is used internally (lines 229, 247, 274), but no IPC message type triggers a full guard listing for external clients.

### Root Cause

The daemon's `GuardRegistry` supports `list()` but the IPC protocol has no message type for "list all guards." The Tauri GUI has no way to query the daemon for registered guards, so `list_guards` returns empty. Even if guards were listed, the toggle only mutates local React state -- there is no `toggle_guard` Tauri command, and the daemon IPC has no enable/disable guard message type.

### Affected User Flow

Users visiting the Guards page always see "No Active Guards" even when guards are registered via the SDK. If guards somehow appeared, toggling them would have no effect beyond the current render cycle.

### Recommended Fix

1. Add a `"list_guards"` IPC message handler in the daemon's `ipc.rs` that calls `registry.list().await` and returns serialized guard info.
2. In `commands.rs`, replace the empty `list_guards()` with an IPC call to the daemon.
3. Add a `"toggle_guard"` IPC command in the daemon and a corresponding `toggle_guard` Tauri command.
4. Update Guards.tsx to call `invoke("toggle_guard", ...)` on toggle click.

---

## Bug 2: Notification Setting -- Written to Config but Correctly Read

**Severity: NOT A BUG (verified working)**

### Files and Line Numbers

- `clients/clawdefender-app/src-tauri/src/commands.rs` line 2384 -- `update_settings()` writes `ui.notifications` to config.toml.
- `clients/clawdefender-app/src-tauri/src/commands.rs` line 2334 -- `get_settings()` reads `ui.notifications` back.
- `clients/clawdefender-app/src-tauri/src/event_stream.rs` lines 313-327 -- `notifications_enabled_in_config()` reads `~/.config/rookbot/config.toml`, parses `[ui].notifications`, and returns the boolean.
- `clients/clawdefender-app/src-tauri/src/event_stream.rs` lines 331-349 -- `send_native_notification()` calls `notifications_enabled_in_config()` as its first check and returns early if false.
- `clients/clawdefender-app/src-tauri/src/event_stream.rs` lines 361, 421 -- Both alert and prompt notification paths call `send_native_notification()`.

### Root Cause

This setting IS correctly wired end-to-end. The notification toggle in Settings writes `[ui].notifications` to config.toml, and the event stream reader checks this value before sending native macOS notifications. The setting works as intended.

### Affected User Flow

None -- this feature works correctly.

### Recommended Fix

No fix needed.

---

## Bug 3: Event Retention -- Config Value Not Passed to Logger (on HEAD)

**Severity: DEGRADED**

### Files and Line Numbers

- `crates/clawdefender-core/src/audit/logger.rs` line 29 -- `const DEFAULT_RETENTION_DAYS: i64 = 30;` hardcoded.
- `crates/clawdefender-core/src/audit/logger.rs` lines 267-278 -- `FileAuditLogger::with_retention()` accepts a `retention_days` parameter.
- `crates/clawdefender-daemon/src/lib.rs` line 123 (on HEAD) -- Uses `FileAuditLogger::new()` which uses the hardcoded 30-day default. Does NOT call `with_retention()`.
- `crates/clawdefender-core/src/config/settings.rs` (on HEAD) -- `ClawConfig` struct does NOT have an `event_retention_days` field.
- `clients/clawdefender-app/src-tauri/src/commands.rs` line 2270 -- GUI defaults to `event_retention_days: 30`.
- `clients/clawdefender-app/src-tauri/src/commands.rs` line 2388 -- GUI writes `event_retention_days` to config.toml `[ui]` section.

### Root Cause

On HEAD (committed code), the daemon creates the logger with `FileAuditLogger::new()` which uses the hardcoded 30-day default. The GUI writes `event_retention_days` to `[ui]` in config.toml, but the daemon does not read it. The `ClawConfig` struct lacks this field entirely.

**Note:** The working tree (unstaged changes) contains a fix that adds `event_retention_days` to `ClawConfig` and calls `with_retention()` in the daemon. However, this fix writes retention to the top-level config while the GUI writes it to `[ui].event_retention_days`. These may be misaligned.

### Affected User Flow

Users can change "Event Retention Days" in Settings. The value is saved to config.toml but the daemon ignores it and always uses 30 days.

### Recommended Fix

1. Add `event_retention_days` to `ClawConfig` (already done in working tree).
2. Ensure daemon reads it and passes to `FileAuditLogger::with_retention()` (already done in working tree).
3. Verify the config key path aligns between GUI writes (`[ui].event_retention_days`) and daemon reads (top-level `event_retention_days`).

---

## Bug 4: Network Settings -- Saved to Config but No Runtime Effect

**Severity: DISHONEST**

### Files and Line Numbers

- `clients/clawdefender-app/src/pages/Settings.tsx` lines 150-155, 1296-1310, 1378-1379 -- Network toggles for `dns_enabled`, `filter_all_processes`, `block_doh` are rendered as interactive controls.
- `clients/clawdefender-app/src-tauri/src/commands.rs` lines 3196-3265 -- `get_network_settings()` reads from config.toml, `update_network_settings()` writes back. Settings are persisted correctly.
- `clients/clawdefender-app/src-tauri/src/commands.rs` lines 3170-3180 -- `get_network_extension_status()` always returns:
  ```rust
  Ok(NetworkExtensionStatus {
      loaded: false,
      filter_active: false,
      dns_active: false,
      filtering_count: 0,
      mock_mode: true,  // Honest about mock mode
  })
  ```
- `clients/clawdefender-app/src-tauri/src/commands.rs` lines 3182-3190 -- `activate_network_extension()` and `deactivate_network_extension()` both return errors explaining the extension is not installed.
- `clients/clawdefender-app/src/pages/Settings.tsx` line 1270 -- The UI does show `mock_mode` warning text and line 1249 says "Network Extension is not installed."

### Root Cause

The macOS Network Extension requires a signed system extension with special Apple entitlements. It is not implemented. The network settings toggles (`dns_enabled`, `filter_all_processes`, `block_doh`) are saved to config.toml but have zero runtime effect since the network filtering engine does not exist. However, the UI partially discloses this via the `mock_mode` indicator.

### Affected User Flow

Users can toggle network settings and they appear saved, but no network filtering/DNS interception actually occurs. The mock_mode banner is shown but the toggles still appear interactive, which is misleading.

### Recommended Fix

1. Disable/gray out network toggles when `mock_mode` is true.
2. Add a clear disclaimer that these settings will take effect when the Network Extension is installed.
3. Alternatively, hide the entire network settings section when mock_mode is true.

---

## Bug 5: Active Model Persistence -- Already Implemented

**Severity: NOT A BUG (verified working)**

### Files and Line Numbers

- `clients/clawdefender-app/src-tauri/src/state.rs` lines 324-325 -- `active_model_info: Mutex<Option<ActiveModelInfo>>` is in-memory only.
- `clients/clawdefender-app/src-tauri/src/commands.rs` line 4060 (in `activate_model`) -- Calls `save_active_config(&config_to_save)` to persist to disk.
- `crates/clawdefender-slm/src/model_registry.rs` lines 417-437 -- `load_active_config()` reads from `~/.config/rookbot/active_model.toml`, `save_active_config()` writes to it.
- `clients/clawdefender-app/src-tauri/src/lib.rs` lines 60-177 -- On app startup, `load_active_config()` is called and the model is re-loaded from the persisted config. Handles `LocalCatalog`, `LocalCustom`, and `CloudApi` variants.

### Root Cause

While `active_model_info` in `AppState` is in-memory, the model selection IS persisted to `~/.config/rookbot/active_model.toml` via `model_registry::save_active_config()`. On startup, `lib.rs` reads this config and re-activates the model. This is working as designed.

### Affected User Flow

None -- model persistence works correctly across restarts.

### Recommended Fix

No fix needed.

---

## Bug 6: Atomic Config Writes -- All Writes Use Direct `std::fs::write`

**Severity: DEGRADED**

### Files and Line Numbers

All `std::fs::write` calls in `commands.rs` that write to config.toml or policy.toml:

| Line | Target File | Context |
|------|-------------|---------|
| 400 | MCP client JSON configs | `wrap_server()` -- writes MCP client config |
| 475 | MCP client JSON configs | `unwrap_server()` -- writes MCP client config |
| 568 | policy.toml | `save_policy_doc()` -- writes policy rules |
| 2443 | config.toml | `update_settings()` -- writes app settings |
| 2596 | config.toml | `import_settings_from_content()` -- imports config |
| 2600 | policy.toml | `import_settings_from_content()` -- imports policy |
| 3052 | config.toml | `save_api_key()` / `clear_api_key()` area |
| 3263 | config.toml | `update_network_settings()` -- writes network config |

Additional non-config writes (lower risk):
- Line 1726: scan results JSON (non-critical)
- Line 2247: onboarding flag file (non-critical)
- Line 2510: settings export to Desktop (non-critical)
- Line 3575/3582: network log CSV/JSON export (non-critical)

Also in `model_registry.rs` line 435: `save_active_config()` uses `std::fs::write` for `active_model.toml`.

### Root Cause

Every config/policy write uses `std::fs::write()` directly, which is not atomic. If the process is killed or the system crashes during the write, the file can be left truncated or corrupted. The standard safe pattern is write-to-temp-then-rename (atomic on POSIX filesystems).

**Note:** `save_policy_doc()` at line 559-567 does create a `.bak` backup before writing, which provides partial crash recovery but is not truly atomic.

### Affected User Flow

Power loss, app crash, or `kill -9` during any settings save could corrupt config.toml or policy.toml. On next startup, the daemon or GUI would fail to parse the config.

### Recommended Fix

1. Create an `atomic_write(path, content)` helper that writes to a temp file in the same directory, then uses `std::fs::rename()`.
2. Replace all `std::fs::write` calls for config.toml and policy.toml with this helper.
3. Keep backup file creation as an additional safety net.

---

## Bug 7: SLM Mock Backend -- Always Returns RiskLevel::Low

**Severity: DISHONEST**

### Files and Line Numbers

- `crates/clawdefender-slm/src/engine.rs` lines 332-379 -- `MockSlmBackend` struct and implementation. The `infer()` method returns a hardcoded response: `"RISK: low\nCONFIDENCE: 0.9\nEXPLANATION: This operation appears safe."` Always `RiskLevel::Low`.
- `crates/clawdefender-slm/src/lib.rs` lines 105-113 -- When compiled without `gguf` feature but with a model path that exists, falls back to `MockSlmBackend`. Logs a message mentioning mock backend.
- `crates/clawdefender-slm/src/lib.rs` lines 253-258 -- When disabled, `disabled_response()` also returns `RiskLevel::Low` with explanation "SLM disabled".
- `clients/clawdefender-app/src-tauri/src/lib.rs` lines 149-165 -- CloudApi model activation uses `MockSlmBackend` with a cosmetic model name, so cloud models also get mock inference.

### Cargo.toml Feature Flags

| Binary/Crate | Has `gguf` feature? |
|---|---|
| `clients/clawdefender-app/src-tauri/Cargo.toml` | YES -- `features = ["cloud", "download", "gguf"]` |
| `clients/clawdefender-cli/Cargo.toml` | YES -- `features = ["gguf"]` |
| `crates/clawdefender-daemon/Cargo.toml` | YES -- `features = ["gguf"]` |

### Root Cause

All three main binaries (GUI, CLI, daemon) DO enable the `gguf` feature, so when a real GGUF model file exists, the real `GgufBackend` is used. The mock backend is only used when:
1. No model file exists at the configured path (falls through to disabled mode, not mock).
2. The `gguf` feature is disabled at compile time (not the case for any shipped binary).
3. Cloud API models -- `lib.rs` line 149-165 uses `MockSlmBackend` for cloud provider models instead of making real API calls.

The actual risk is that **cloud API models use the mock backend** -- any user who selects a cloud provider model gets `RiskLevel::Low` for everything while the UI shows the cloud model as "active." There is no warning that the cloud backend is faking inference.

### Affected User Flow

1. User selects a cloud model (e.g., Anthropic Claude) as their AI provider.
2. UI shows the cloud model as active with a name like "Claude Sonnet (Anthropic)".
3. All risk assessments silently return `RiskLevel::Low` via MockSlmBackend.
4. User believes AI analysis is running but it is not.

### Recommended Fix

1. Add a visible "Mock Mode" or "No Real Inference" indicator in the UI when MockSlmBackend is in use.
2. For cloud models, either implement real API calls or clearly label the model as "Preview / Not Connected."
3. The Dashboard and Scanner pages should warn when risk scores come from mock inference.

---

## Summary Table

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | Guards page returns empty, toggle is local-only | BROKEN | Needs IPC + Tauri commands |
| 2 | Notification setting | **NOT A BUG** | Working correctly |
| 3 | Event retention days ignored by daemon | DEGRADED | Partially fixed in working tree |
| 4 | Network settings saved but no runtime effect | DISHONEST | Needs UI disclosure improvements |
| 5 | Active model persistence | **NOT A BUG** | Working correctly |
| 6 | Non-atomic config/policy writes | DEGRADED | Needs atomic write helper |
| 7 | SLM mock backend for cloud models | DISHONEST | Needs UI warnings + real cloud backend |
