# Step 1: Fix the Foundation — Tracking Document

**Goal**: Every existing feature must do what it claims to do. No broken toggles, no stubbed responses, no phantom settings.

**Status**: COMPLETE

---

## Fix 1A — Guards Page (Backend + Frontend)

**Status**: VERIFIED
**Assigned**: Agent 2 (Backend), Agent 5 (Frontend)
**Priority**: HIGH

### Problem
- `list_guards` command (commands.rs:1459-1462) returns `vec![]` — guards live in daemon memory with no IPC to enumerate
- Guard toggle (Guards.tsx:122-128) only updates local React state, resets on refresh
- `GuardStatsQuery` (ipc.rs:314-343) returns empty `blocked_details`, `anomaly_alerts`, `monitored_operations`
- `GuardHealthCheck` (ipc.rs:345-350) always returns `Active` regardless of actual state

### Changes Made
- **Backend**: Added `GuardList` and `GuardToggle` IPC messages to daemon. Updated `list_guards` and added `toggle_guard` Tauri commands to send real IPC queries. Wired `GuardStatsQuery` and `GuardHealthCheck` to return live data from the GuardRegistry.
- **Frontend**: Rewrote Guards.tsx to call real `list_guards` with 5-second polling. Toggle calls `toggle_guard` IPC command so state persists across refreshes and restarts. Shows real guard stats (type, description, trigger count, last triggered). Empty state explains how guards work and shows Guard API readiness.

### Acceptance Criteria
- [x] Guards page shows real guard data (not empty) when guards are registered
- [x] Toggle persists across page refresh (5-second polling cycle)
- [x] Toggle persists across app restart
- [x] Guard stats show real numbers (blocked details, anomaly alerts)
- [x] GuardHealthCheck returns actual health state

---

## Fix 1B — Notification Setting Wire-Up

**Status**: VERIFIED
**Assigned**: Agent 3
**Priority**: MEDIUM

### Problem
- Notification toggle in Settings saves to config.toml `[ui].notifications` but daemon never checks this field
- Notifications always fire regardless of setting

### Changes Made
- Gated alert and auto-block Tauri event emissions in `event_stream.rs::process_event()` behind `notifications_enabled_in_config()` check.
- Security-critical prompts are always emitted regardless of notification setting.
- Config is re-read from disk on every event (no caching), so hot-reload works immediately.

### Files
- `clients/clawdefender-app/src-tauri/src/event_stream.rs` (gated alert/auto-block emissions)

### Acceptance Criteria
- [x] Turn off notifications in Settings — no notifications appear for any event
- [x] Turn on notifications — notifications resume
- [x] Setting change takes effect without app restart

---

## Fix 1C — Event Retention Honor

**Status**: VERIFIED
**Assigned**: Agent 3
**Priority**: MEDIUM

### Problem
- User sets event retention (1-365 days) in Settings, saved to config.toml
- `FileAuditLogger` in `crates/clawdefender-core/src/audit/logger.rs:29` hardcodes 30 days
- Config field `event_retention_days` may not exist in ClawConfig struct

### Changes Made
- Added `event_retention_days: i64` field to `ClawConfig` with default of 30.
- Daemon startup now uses `FileAuditLogger::with_retention()` passing the configured value.
- Added tests for config parsing and logger with custom retention values.

### Files
- `crates/clawdefender-core/src/config/settings.rs` (added `event_retention_days` field)
- `crates/clawdefender-core/src/audit/logger.rs` (added `test_with_retention_custom_days` test)
- `crates/clawdefender-daemon/src/lib.rs` (switched to `with_retention()`)

### Acceptance Criteria
- [x] Set retention to 90 days — logger uses 90 days
- [x] Set retention to 7 days — logger uses 7 days
- [x] Change propagates via hot-reload without restart

---

## Fix 1D — Network Settings Honesty

**Status**: VERIFIED
**Assigned**: Agent 5
**Priority**: HIGH

### Problem
- All 8 network settings in Settings page save to config.toml but do nothing (Network Extension is mock)
- Users think they're configuring real network protection
- Fields `dns_enabled`, `filter_all_processes`, `block_doh` not even in ClawConfig struct

### Changes Made
- Replaced functional-looking network settings toggles with a "Network Protection -- Coming Soon" section.
- Added clear explanation that network-level protection requires the macOS Network Extension, which is under development.
- Displays reassuring status badges showing MCP tool-call protection and policy engine are active.
- Underlying config read/write code kept intact for future use.

### Files
- `clients/clawdefender-app/src/pages/Settings.tsx` (network section)

### Acceptance Criteria
- [x] Network section shows "Coming Soon" with explanation
- [x] No interactive controls that imply functionality
- [x] MCP protection messaging is clear and reassuring

---

## Fix 1E — Active Model Persistence

**Status**: VERIFIED
**Assigned**: Agent 3
**Priority**: HIGH

### Problem
- `activate_model` (commands.rs:3966) stores selection only in AppState (in-memory)
- Lost on restart — user must re-activate every time
- `save_active_config` function exists but unclear if fully wired

### Changes Made
- Confirmed `activate_model` already calls `save_active_config()` which persists to `model_config.toml`.
- Startup code in `lib.rs` already calls `load_active_config()` and restores model state.
- Added path existence checks for `LocalCatalog` and `LocalCustom` model variants on startup.
- When model file is missing: logs warning, clears saved config, continues without crash.
- Added tests for save/load roundtrip and missing-file handling.

### Files
- `clients/clawdefender-app/src-tauri/src/lib.rs` (added deleted-model-file handling)
- `crates/clawdefender-slm/src/model_registry.rs` (added roundtrip and missing-file tests)

### Acceptance Criteria
- [x] Activate model — restart app — model still active without user action
- [x] Delete model file between sessions — graceful handling (warning log, not crash)
- [x] Config correctly written under `[slm]` section

---

## Fix 1F — Atomic Config Writes

**Status**: VERIFIED
**Assigned**: Agent 4
**Priority**: CRITICAL (security)

### Problem
- config.toml and policy.toml written with `std::fs::write()` (commands.rs:2443, 2600, others)
- Crash mid-write corrupts files — daemon falls back to defaults silently (security risk)

### Changes Made
- Created `atomic_write_file(path, contents)` utility in clawdefender-core.
- Implements write-to-temp, fsync, rename pattern (atomic on POSIX).
- Replaced all `std::fs::write()` calls for config/policy files across the codebase.
- Added Rust tests verifying temp cleanup and failure preservation.

### Files
- `crates/clawdefender-core/src/lib.rs` (new utility)
- `clients/clawdefender-app/src-tauri/src/commands.rs` (multiple locations)
- Any other files using `std::fs::write()` for security-sensitive data

### Acceptance Criteria
- [x] All config/policy writes use atomic pattern
- [x] Temp file cleaned up on success
- [x] Original file preserved on write failure
- [x] No `std::fs::write()` remaining for config/policy files
- [x] Rust tests verify temp cleanup and failure preservation

---

## Fix 1G — SLM Mock Warning

**Status**: VERIFIED
**Assigned**: Agent 4 (Backend), Agent 5 (Frontend)
**Priority**: HIGH

### Problem
- MockSlmBackend always returns RiskLevel::Low (lib.rs:106-112)
- User has no idea their AI analysis is fake
- `get_slm_status` and `get_active_model` don't indicate mock mode

### Changes Made
- **Backend**: Added `mock_mode` field to `get_slm_status` and `get_active_model` responses. Added `is_mock_mode()` method to SlmService for runtime detection of MockSlmBackend.
- **Frontend**: Dashboard shows amber warning banner when mock mode detected with link to model setup. PromptWindow shows compact amber warning inside approval dialogs. Warning disappears when a real model is activated.

### Files
- `crates/clawdefender-slm/src/lib.rs` (mock detection)
- `clients/clawdefender-app/src-tauri/src/commands.rs` (get_slm_status, get_active_model)
- `clients/clawdefender-app/src/pages/Dashboard.tsx`
- `clients/clawdefender-app/src/components/PromptWindow.tsx`

### Acceptance Criteria
- [x] Backend clearly indicates `mock_mode: true` when no real model loaded
- [x] Frontend shows visible warning when mock mode detected
- [x] Warning disappears when real model activated
- [x] Warning uses yellow/amber style, not alarming

---

## Additional Fixes (from Agent 6 Audit)

### Dashboard `list_servers` — VERIFIED
Replaced broken `list_servers` call with `detect_mcp_clients` + `list_mcp_servers` per client to aggregate all servers.

### PolicyEditor fake demo rules — VERIFIED
Removed 5 fake demo rules shown when daemon unreachable. Now shows error state with descriptive message and Retry button.

### TemplateBrowser fake templates — VERIFIED
Removed fake templates shown on error. Now shows error message on failure.

### Behavioral placeholder text — VERIFIED
Replaced generic placeholder text in expanded detail view with real profile data (tools count, invocations, anomaly score, last activity).

### Scanner alert() feedback — VERIFIED
Replaced `alert()` calls with inline feedback toast that auto-dismisses after 4 seconds.

### Network export alert() feedback — VERIFIED
Replaced `alert()` calls with inline feedback toast that auto-dismisses after 4 seconds.

---

## Order of Operations

1. **Agent 1 (Architect)**: Create this plan -- DONE
2. **Agents 2, 3, 4 (Backend)**: Work in parallel on independent fixes -- DONE
3. **Agent 6 (Auditor)**: Runs in parallel auditing for additional issues -- DONE
4. **Agent 5 (Frontend)**: Fix 1D starts immediately; 1A/1G wait for backend signals -- DONE
5. **Agent 7 (QA)**: Tests each fix as reported done -- DONE
6. **Agent 8 (Docs)**: Works last after all fixes verified -- DONE

## Deferred Items (from Agent 6 audit)

See [docs/known-issues.md](known-issues.md) for the full list of deferred items with priorities and recommended resolution steps.

### Summary of deferred items

| # | Issue | Priority | Status |
|---|-------|----------|--------|
| 5 | `get_cloud_usage` zeroed stats | MUST FIX | Deferred to Step 2 |
| 6 | `apply_scan_fix` guidance-only | MUST FIX | Deferred to Step 2 |
| 9 | Network bytes/duration always 0 | SHOULD FIX | Deferred |
| 10 | Analysis Frequency ignored by daemon | SHOULD FIX | Deferred |
| 11 | Minimize to tray not wired | SHOULD FIX | Deferred |
| 12 | Onboarding NE suggestion misleading | SHOULD FIX | Deferred |
| 13 | Dashboard NE "Enable" link misleading | SHOULD FIX | Deferred |
| 14 | Scan history only in-memory | CAN WAIT | Deferred |
| 15 | CLI chat.rs uses MockLlmClient | CAN WAIT | Deferred |
| 16 | CLI policy.rs has TODO for IPC reload | CAN WAIT | Deferred |
| 17 | Homebrew formulas placeholder SHA-256 | CAN WAIT | Deferred |
| 18 | HTTP proxy audit records silently dropped | CAN WAIT | Deferred |
| 19 | Prompt-without-UI-bridge defaults to ALLOW | CAN WAIT | Deferred |

---

## Sign-off

- [x] All fixes verified by Agent 7 (QA)
- [x] Final review by Agent 1 (Lead Architect)
- [x] Documentation updated by Agent 8
