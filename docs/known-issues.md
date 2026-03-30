# Known Issues — Deferred from Step 1

Items identified during the Step 1 audit (Agent 6) that were not addressed in the foundation fix cycle. Organized by priority.

---

## MUST FIX

These issues involve user-facing dishonesty where the UI implies functionality that does not exist.

### 1. `get_cloud_usage` returns zeroed stats

- **File**: `clients/clawdefender-app/src-tauri/src/commands.rs:3826`
- **Description**: The `get_cloud_usage` command returns a struct with all zero values. Any UI showing cloud usage will always display $0 spent, regardless of actual usage.
- **Impact**: Users relying on cost tracking see incorrect data.
- **Fix**: Wire the command to the real `CostTracker` SQLite database in clawdefender-swarm, or remove the command and any UI that calls it.
- **Recommended step**: Step 2

### 2. `apply_scan_fix` for add_policy_rule only returns guidance string

- **File**: `clients/clawdefender-app/src-tauri/src/commands.rs:1802`
- **Description**: When the fix action is `add_policy_rule`, the command returns a text string suggesting what to do rather than actually adding the rule. The Scanner UI shows this via an inline toast, which appears as success but no rule is created.
- **Impact**: Users believe a fix was applied when it was not.
- **Fix**: Actually add the policy rule programmatically, or change the button text to "View Suggestion" to set correct expectations.
- **Recommended step**: Step 2

---

## SHOULD FIX

Polish issues that are not dishonest but result in poor user experience.

### 3. Network connection bytes/duration always show 0

- **File**: `clients/clawdefender-app/src/pages/NetworkLog.tsx:128-144`, `commands.rs:3361`
- **Description**: The UI faithfully displays "0 B" and "0ms" for all network connections because the Network Extension is not active.
- **Fix**: Hide bytes/duration columns when the network extension is not active, or show "N/A" instead of zero values.
- **Recommended step**: Step 2 or Step 3

### 4. Analysis Frequency setting saved but daemon ignores it

- **File**: `clients/clawdefender-app/src/pages/Settings.tsx` (AI Model section)
- **Description**: The `[slm].analysis_frequency` value is saved to config but the daemon does not read or honor it. Users see a functional-looking slider that has no effect.
- **Fix**: Wire the daemon to honor the analysis frequency setting, or remove the slider from the UI.
- **Recommended step**: Step 2

### 5. Show in Menu Bar setting saved but not wired

- **File**: `clients/clawdefender-app/src/pages/Settings.tsx`
- **Description**: The `minimize_to_tray` toggle is persisted to config but window close behavior is not affected by it.
- **Fix**: Read the setting in the window close handler and implement minimize-to-tray behavior, or remove the toggle.
- **Recommended step**: Step 2

### 6. Onboarding suggests enabling non-functional Network Protection

- **File**: `clients/clawdefender-app/src/pages/Onboarding.tsx:966-971`
- **Description**: The final onboarding step suggests "enable Network Protection in Settings" but network protection is fully stubbed.
- **Fix**: Remove the suggestion or change to "Coming soon" to align with the Settings page treatment (Fix 1D).
- **Recommended step**: Step 2

### 7. Dashboard Network Protection card links to non-functional settings

- **File**: `clients/clawdefender-app/src/pages/Dashboard.tsx:432-436`
- **Description**: Shows "Enable in Settings" when Network Extension is inactive, leading to the stub settings section. This contradicts the "Coming Soon" treatment applied in Fix 1D.
- **Fix**: Show "Coming Soon" instead of the "Enable in Settings" link, or remove the link entirely.
- **Recommended step**: Step 2

---

## CAN WAIT

Cosmetic or low-impact issues that can be addressed in later development cycles.

### 8. Scan history only in-memory

- **File**: `clients/clawdefender-app/src/pages/Scanner.tsx:89-97`
- **Description**: The scan history list is lost on page navigation. Persisted results exist on disk but the list is built from in-memory state only.
- **Fix**: Load scan history from persisted scan files on component mount.
- **Recommended step**: Step 3

### 9. CLI chat.rs uses MockLlmClient

- **File**: `crates/clawdefender-swarm/src/chat.rs:25`
- **Description**: The CLI chat command uses MockLlmClient. Not user-facing in the GUI app.
- **Fix**: Wire to real LLM client when available.
- **Recommended step**: Step 3

### 10. CLI policy.rs has TODO for IPC reload

- **File**: `crates/clawdefender-mcp-proxy/src/cli/policy.rs:174`
- **Description**: There is a TODO for IPC reload after policy changes via CLI. May already be wired elsewhere.
- **Fix**: Verify and wire if needed.
- **Recommended step**: Step 3

### 11. Homebrew formulas have placeholder SHA-256

- **File**: `Formula/clawdefender.rb`
- **Description**: SHA-256 checksums are placeholder values. Low priority until release builds are ready.
- **Fix**: Generate real checksums from release artifacts.
- **Recommended step**: Before first public release

### 12. HTTP proxy audit records silently dropped

- **File**: `crates/clawdefender-mcp-proxy/src/proxy/http.rs:73`
- **Description**: The audit receiver is immediately dropped, so audit records from the HTTP proxy path are lost. Low priority as the stdio proxy is the primary path.
- **Fix**: Wire the receiver to the audit logger.
- **Recommended step**: Step 3

### 13. Prompt-without-UI-bridge defaults to ALLOW

- **File**: `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs:650-658`
- **Description**: When running in headless mode without a UI bridge, prompts are silently allowed. This is a security concern for headless deployments.
- **Fix**: Add a `--headless-deny` flag that defaults to denying prompts when no UI is available.
- **Recommended step**: Step 2 or Step 3
