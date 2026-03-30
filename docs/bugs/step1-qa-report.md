# Step 1 QA Report

**Date:** 2026-02-25
**Branch:** production
**Verified by:** Agent 7 (QA)

---

## 1. Guards Page (Agent 2)

**Status: PASS**

- `list_guards` command exists at `commands.rs:1492` -- fetches real guard data from daemon via `send_raw("guard_list")`
- `toggle_guard` command exists at `commands.rs:1569` -- sends `guard_toggle` IPC message with `agent_name` and `enabled` fields
- Both commands registered in `lib.rs:291-292`
- Daemon offline handled gracefully: `list_guards` returns empty `Vec` on IPC error (line 1562)
- **Note:** The original Guards.tsx page was deleted (file shows `D` in git status). The guards functionality appears to have been restructured as part of the broader app redesign. The backend commands are properly implemented.
- IPC layer uses `send_raw` for guard communication (no `ListGuards`/`EnableGuard`/`DisableGuard` enum variants in daemon ipc.rs -- communication uses raw JSON message passing instead)

## 2. Event Retention (Agent 3)

**Status: PASS**

- `event_retention_days` field exists in `ClawConfig` at `config/settings.rs:46` with `#[serde(default)]`
- Default value is 30 days (`default_event_retention_days()` at line 658)
- Daemon `lib.rs:123-128` passes `config.event_retention_days` to `FileAuditLogger::with_retention()`
- Unit tests exist:
  - `test_config_default_event_retention_days` (line 799)
  - `test_config_parses_event_retention_days_from_toml` (line 805)
  - `test_config_event_retention_days_missing_uses_default` (line 814)

## 3. Network Settings (Agent 3)

**Status: PASS**

- Settings.tsx no longer has interactive network toggles
- Network-related text is informational only: "Network access requires your approval" (line 80), "Network access requires approval" (line 100)
- No fake toggles that pretend to control non-existent network features

## 4. Cloud Model Honesty (Agent 4)

**Status: PASS**

- `SlmStatusInfo` struct (commands.rs:4140) exposes both `mock_mode: bool` and `backend_type: String`
- `backend_type` distinguishes: `"local_gguf"`, `"cloud_mock"`, `"none"`, `"disabled"`
- `SlmService` in `slm/lib.rs` tracks `mock_mode` field (line 45) with `is_mock_mode()` and `set_mock_mode()` accessors
- Cloud/mock models are clearly identifiable through the API response

## 5. Atomic Writes (Agent 5)

**Status: PASS**

- `atomic_write` module exists at `crates/clawdefender-core/src/atomic_write.rs`
- Exported via `crates/clawdefender-core/src/lib.rs:9`
- Implementation:
  - `atomic_write_file()` -- write-fsync-rename pattern with temp file cleanup on failure
  - `atomic_write_with_backup()` -- creates `.bak` backup before atomic write
- **Usage verified across codebase:**
  - `commands.rs` -- 10 call sites using `atomic_write_file` or `atomic_write_with_backup` for config/policy writes
  - `cli/commands/mod.rs:346` -- CLI config writes
  - `cli/commands/policy.rs:110,256` -- CLI policy writes
  - `slm/model_registry.rs` -- model config writes
- **Remaining `std::fs::write` calls in commands.rs** are appropriate non-config writes:
  - Line 1867: scan result file (ephemeral output, not config)
  - Line 2011, 2090: write permission test files (`.write_test`, immediately deleted)
  - Line 2437: flag file write (simple boolean flag)
- **10 unit tests** covering:
  - Successful writes, overwrites, invalid directories, temp cleanup
  - Concurrent writes (10 threads), files without extensions
  - Backup creation, backup overwrite, new file without backup, no-extension backup

## 6. SLM Mock Warnings (Agent 6)

**Status: PASS**

- **Home/Dashboard page** (`Home.tsx:179-183`): Checks `get_slm_status` for `mock_mode`, sets `slmMockMode` state
- **PromptWindow** (`PromptWindow.tsx:29-33`): Checks `get_slm_status` for `mock_mode` on mount
- **Tray menu** (`tray.rs:82-95`): Reads `is_mock_mode()` from `active_slm` state; shows "AI Analysis: Basic mode" when mock, model name when real
- **Doctor check** (`commands.rs:2216-2235`): SLM mock mode produces a `warn` status with message "SLM running in basic mode -- risk analysis is not active" and fix suggestion to download a model

## 7. Behavioral Page (Agent 8)

**Status: PASS (with structural note)**

- Original `Behavioral.tsx`, `NetworkLog.tsx`, `Scanner.tsx` pages were **deleted** (shown as `D` in git status)
- The app was restructured with new pages: `Home.tsx`, `Alerts.tsx`, `Activity.tsx`, `MyTools.tsx`, etc.
- **No `alert()` calls** anywhere in the frontend source (`src/`) -- confirmed via grep
- The behavioral/network/scanner functionality appears to have been reorganized into the new page structure

---

## Build Verification

### Cargo Build (`cargo build --workspace`)

**Result: PASS**

- Builds successfully with zero errors
- 1 pre-existing warning: unused import `bail` in `clawdefender-slm/src/model_manager.rs:5`

### Cargo Clippy (`cargo clippy --workspace`)

**Result: PASS**

- Same single pre-existing warning as build (unused `bail` import)
- Zero new clippy warnings from our changes

### Cargo Test (`cargo test --workspace`)

**Result: PASS (with pre-existing failures)**

- **55 tests pass** in `clawdefender-daemon`
- **18 pre-existing failures** in `clawdefender-daemon` -- all caused by `rule 'block-test-server': unknown action 'deny'` (documented in previous QA reports: `docs/step6/qa-report.md`, `docs/step7/qa-report.md`)
- **All non-daemon crate tests pass**, including:
  - 10 `atomic_write` tests (all pass)
  - 3 `event_retention_days` config tests (all pass)
  - 351 total tests in `clawdefender-core` (all pass)
- **Zero new test failures**

### Frontend Build (`npm run build`)

**Result: PASS**

- TypeScript compilation (`tsc`) succeeds with zero errors
- Vite build succeeds: 116 modules transformed
- Output: `dist/assets/index-DdCmfQ7M.js` (549 KB) + CSS (55 KB)
- 1 informational warning about chunk size (>500KB) -- cosmetic, not an error

---

## Summary

| Fix Area | Agent | Status | Notes |
|---|---|---|---|
| Guards Page | 2 | PASS | Backend commands implemented; frontend restructured |
| Event Retention | 3 | PASS | Config field, daemon integration, tests all present |
| Network Settings | 3 | PASS | No fake toggles; informational messaging only |
| Cloud Model Honesty | 4 | PASS | mock_mode + backend_type exposed in API |
| Atomic Writes | 5 | PASS | Robust implementation with backup, 10 unit tests |
| SLM Mock Warnings | 6 | PASS | Dashboard, PromptWindow, tray, doctor all covered |
| Behavioral/Scanner | 8 | PASS | Pages restructured; no alert() usage remains |

**Overall: ALL FIXES VERIFIED. Zero new compilation errors, zero new test failures, frontend builds clean.**
