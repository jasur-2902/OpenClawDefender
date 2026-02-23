# Section 12: GUI App -- Frontend

## 12.0 Overview

| Aspect | Value |
|---|---|
| Framework | React 19 + TypeScript 5 + Vite 6 |
| Styling | Tailwind CSS 4 (CSS variables for theming) |
| Routing | react-router-dom 7 (BrowserRouter) |
| State | Zustand 5 (single `eventStore`) |
| Backend bridge | `@tauri-apps/api` v2 (`invoke`, `listen`, `emit`) |
| Tauri plugins | autostart, notification, process, shell, updater |
| Entry | `src/main.tsx` -> `<App />` (StrictMode) |

### Route Map (src/App.tsx)

| Path | Component | Sidebar? |
|---|---|---|
| `/onboarding` | `Onboarding` | No |
| `/` | `Dashboard` | Yes |
| `/timeline` | `Timeline` | Yes |
| `/policy` | `PolicyEditor` | Yes |
| `/behavioral` | `Behavioral` | Yes |
| `/scanner` | `Scanner` | Yes |
| `/guards` | `Guards` | Yes |
| `/threat-intel` | `ThreatIntel` | Yes |
| `/network` | `NetworkLog` | Yes |
| `/audit` | `AuditLog` | Yes |
| `/health` | `SystemHealth` | Yes |
| `/settings` | `Settings` | Yes |

**App-level features:**
- `OnboardingRedirect`: calls `check_onboarding_complete` on mount; redirects to `/onboarding` if incomplete. REAL Tauri command.
- `TrayNavigationListener`: listens to `clawdefender://navigate` event for system-tray-driven navigation. REAL.
- `useTheme()`: loads theme from `get_settings`, listens to `clawdefender://theme-changed` event, respects OS dark mode via `matchMedia`. REAL.
- `NotificationLayer`: always rendered; listens for prompt/auto-block/alert events. REAL.

---

## 12.1 Dashboard (src/pages/Dashboard.tsx)

**Purpose:** Main overview showing protection status, quick stats, threat intel summary, network protection status, recent activity feed, alerts, and server overview.

### Data Fetched on Mount

| Tauri Command | Type | Classification |
|---|---|---|
| `get_daemon_status` | DaemonStatus | REAL |
| `get_recent_events` (count: 50) | AuditEvent[] | REAL |
| `list_guards` | GuardSummary[] | REAL |
| `list_servers` | McpServer[] | REAL |
| `get_feed_status` | FeedStatus | REAL |
| `get_blocklist_matches` | BlocklistAlert[] | REAL |
| `get_network_extension_status` | NetworkExtensionStatus | REAL |
| `get_network_summary` | NetworkSummaryData | REAL |

### Real-Time Events

| Event | Handler | Classification |
|---|---|---|
| `clawdefender://event` | addEvent -> eventStore | REAL |
| `clawdefender://status-change` | setDaemonRunning + refetch all | REAL |
| `clawdefender://prompt` | addPrompt -> eventStore | REAL |

### Interactive Elements

| Element | Action | Classification |
|---|---|---|
| "Start Daemon" button (when daemon stopped) | `invoke("start_daemon")` then re-fetches status | REAL |
| "Enable in Settings" link (network inactive) | `<a href="/settings">` -- client-side link | REAL |
| Protection status hero | Read-only display | REAL |
| Quick stats cards (5) | Read-only display | REAL |
| Threat intel card | Read-only (feed version, blocklist count) | REAL |
| Network protection card | Read-only (active/inactive, filter count) | REAL |
| Network activity card | Read-only (allowed/blocked/prompted counts + top destinations) | REAL |
| Recent activity feed (top 10) | Read-only, sorted blocks/prompts first | REAL |
| Alerts panel | Read-only (high/critical risk events) | REAL |
| Server overview grid | Read-only (server name, status, event counts, wrapped badge) | REAL |

### States

- **Loading:** No explicit loading state (data arrives asynchronously, sections render as data populates)
- **Error:** Error banner shown when `get_daemon_status` fails
- **Empty:** "No events yet." / "No alerts. All clear." empty states present

### Issues

- No explicit loading spinner while initial data loads -- sections may flash empty then populate
- The "Enable in Settings" link uses `<a href="/settings">` which navigates correctly via react-router

### Classification: REAL -- All data comes from real Tauri commands via daemon IPC.

---

## 12.2 Settings (src/pages/Settings.tsx)

**Purpose:** The largest page (1502 lines). Manages general settings, protection level, AI model management (local + cloud + custom), network protection settings, and advanced options.

### Data Fetched on Mount

| Tauri Command | Classification |
|---|---|
| `get_settings` | REAL |
| `get_network_extension_status` | REAL |
| `get_network_settings` | REAL |
| `get_slm_status` | REAL |
| `get_model_catalog` | REAL |
| `get_installed_models` | REAL |
| `get_active_model` | REAL |
| `get_system_capabilities` | REAL |
| `is_autostart_enabled` | REAL |

### Interactive Elements -- General Section

| Element | Tauri Command(s) | Classification |
|---|---|---|
| Theme dropdown (system/light/dark) | `update_settings` + `emit("clawdefender://theme-changed")` | REAL |
| Start at Login toggle | `enable_autostart` / `disable_autostart` + `update_settings` | REAL |
| Show in Menu Bar toggle | `update_settings` | REAL |

### Interactive Elements -- Protection Section

| Element | Tauri Command(s) | Classification |
|---|---|---|
| Security Level dropdown | `apply_template` | REAL |
| Notifications toggle | `update_settings` | REAL |
| Prompt Timeout slider (15-120s) | `update_settings` | REAL |

### Interactive Elements -- AI Model Section

| Element | Tauri Command(s) | Classification |
|---|---|---|
| Active model display + "Change Model" button | `deactivate_model` | REAL |
| Model catalog cards with Download button | `download_model` -> returns taskId | REAL |
| Cancel download button | `cancel_download` | REAL |
| Download progress bar | `get_download_progress` (polled 500ms) | REAL |
| Activate model button | `activate_model` | REAL |
| Delete model button | `delete_model` | REAL |
| Retry download button | Cancel + re-download | REAL |
| Dismiss error button | Local state only | REAL |
| "View on HuggingFace" link | `open()` from `@tauri-apps/plugin-shell` | REAL |
| Custom model path input + Activate | `activate_model` with file path | REAL |
| Cloud API expandable section | `get_cloud_providers` | REAL |
| Provider dropdown | Local state + `has_cloud_api_key` | REAL |
| API key input + Show/Hide toggle | Local state | REAL |
| "Save & Test" button | `save_api_key` + `test_api_connection` | REAL |
| "Activate Cloud Model" button | `activate_cloud_provider` + `get_cloud_usage` | REAL |
| "Clear" API key button | `clear_api_key` | REAL |
| "Switch to Local Model" button | `deactivate_model` | REAL |
| Analysis Frequency dropdown | Local state only | STUBBED |

### Interactive Elements -- Network Protection Section

| Element | Tauri Command | Classification |
|---|---|---|
| Enable Network Filtering toggle | `update_network_settings` | REAL |
| Enable DNS Filtering toggle | `update_network_settings` | REAL |
| Filter All Processes checkbox | `update_network_settings` | REAL |
| Default Action dropdown | `update_network_settings` | REAL |
| Prompt Timeout slider (5-60s) | `update_network_settings` | REAL |
| Block Private Ranges checkbox | `update_network_settings` | REAL |
| Block DNS-over-HTTPS checkbox | `update_network_settings` | REAL |
| Log All DNS Queries checkbox | `update_network_settings` | REAL |

### Interactive Elements -- Advanced Section

| Element | Tauri Command | Classification |
|---|---|---|
| Log Level dropdown | `update_settings` | REAL |
| Event Retention input | `update_settings` | REAL |
| Export Config button | `export_settings` | REAL |
| Import Config button | `import_settings_from_content` (via file picker) | REAL |
| Reset to Defaults button | `update_settings` (with defaults, after confirm) | REAL |

### States

- **Loading:** "Loading settings..." shown while fetching
- **Saving:** "Saving..." / "Saved" / "Save failed" indicator next to heading
- **Export:** Temporary status message below export/import buttons
- **Download progress:** Full progress bar with speed, ETA, bytes, percent
- **Download errors:** Inline error with Retry/Dismiss buttons
- **Network disabled:** Section grayed out with pointer-events-none when network extension not loaded

### Issues

- Analysis Frequency dropdown (`analysisFrequency` state) is local-only -- never persisted via a Tauri command. This is STUBBED.
- Download poll failure count threshold (10 consecutive = 5s) is reasonable.

### Classification: REAL (one STUBBED dropdown: Analysis Frequency)

---

## 12.3 Onboarding (src/pages/Onboarding.tsx)

**Purpose:** 5-step onboarding wizard: Welcome -> Detect & Protect -> Security Level -> AI Analysis -> Complete.

### Step 1: Welcome

| Element | Action | Classification |
|---|---|---|
| "Get Started" button | Advances to step 2 | REAL |

### Step 2: Detect & Protect

| Tauri Command | Classification |
|---|---|
| `detect_mcp_clients` | REAL |
| `list_mcp_servers` (per client) | REAL |
| `wrap_server` (per selected server) | REAL |

| Element | Action | Classification |
|---|---|---|
| Server checkboxes | Toggle selection | REAL |
| "Protect These" button | Wraps selected servers sequentially | REAL |
| "Skip" button (on error) | Advances to next step | REAL |
| "Continue" button (no servers found) | Advances to next step | REAL |

### Step 3: Security Level

| Element | Action | Classification |
|---|---|---|
| 3 security level radio buttons | Set local state | REAL |
| "Continue" button | `invoke("apply_template")` | REAL |

### Step 4: AI Analysis

| Tauri Command | Classification |
|---|---|
| `get_system_capabilities` | REAL |
| `get_model_catalog` | REAL |
| `get_installed_models` | REAL |
| `download_model` | REAL |
| `get_download_progress` (polled) | REAL |
| `cancel_download` | REAL |

| Element | Action | Classification |
|---|---|---|
| "Download & Enable" (recommended model) | Starts download + polls progress | REAL |
| Cancel download link | `cancel_download` | REAL |
| "Download" (other models) | Starts download | REAL |
| "Continue" / "Skip for now" buttons | Advance to step 5 | REAL |
| "Retry Download" button (on error) | Clears error, re-downloads | REAL |

### Step 5: Complete

| Element | Action | Classification |
|---|---|---|
| Start at Login checkbox | `enable_autostart` / `disable_autostart` | REAL |
| Show in menu bar checkbox | Local state only (not persisted) | STUBBED |
| "Open Dashboard" button | `complete_onboarding` + navigate to `/` | REAL |

### States

- **Loading:** Animated pulse icon "Scanning for MCP clients..." / "Detecting system capabilities..."
- **Error:** Error message with Skip button
- **Empty:** "No MCP Clients Detected" with continue button
- **Wrapping progress:** Per-server status indicators (pending/wrapping/done/error)
- **Download progress:** Full progress bar with bytes/speed/ETA

### Issues

- `showInMenuBar` checkbox in Complete step sets local state but never invokes a Tauri command -- STUBBED
- `downloadCompleted` state is set but never actually used in the final step (it controls `downloadInProgress` display)

### Classification: REAL (one STUBBED checkbox: showInMenuBar in step 5)

---

## 12.4 AuditLog (src/pages/AuditLog.tsx)

**Purpose:** Searchable, sortable, filterable table of all audit events with expandable row details.

### Data Fetched

| Tauri Command | Classification |
|---|---|
| `get_recent_events` (polled every 5s) | REAL |

### Interactive Elements

| Element | Action | Classification |
|---|---|---|
| Search input | Client-side text filter | REAL |
| Server filter dropdown | Client-side filter (populated from data) | REAL |
| Action filter dropdown (Allowed/Blocked/Prompted) | Client-side filter | REAL |
| Risk filter dropdown (Low/Medium/High/Critical) | Client-side filter | REAL |
| Sortable column headers (6 columns) | Client-side sort with direction toggle | REAL |
| Clickable table rows | Expand/collapse detail panel | REAL |

### States

- **Error:** Red error banner
- **Empty:** "No events found." in table body
- **Footer:** "Showing X of Y events" count

### Classification: REAL -- All data from real Tauri command.

---

## 12.5 Behavioral (src/pages/Behavioral.tsx)

**Purpose:** Behavioral analysis dashboard showing server profiles with anomaly scores and auto-block controls.

### Data Fetched

| Tauri Command | Classification |
|---|---|
| `get_behavioral_status` (polled every 5s) | REAL |
| `get_profiles` (polled every 5s) | REAL |

### Interactive Elements

| Element | Action | Classification |
|---|---|---|
| Server profile accordion (expand/collapse) | Client-side toggle | REAL |
| Auto-block toggle switch | Local state only | STUBBED |
| Anomaly threshold slider (0.1-1.0) | Local state only | STUBBED |

### States

- **Error:** Red error banner
- **Empty:** "No server profiles available yet" with explanatory text
- **Stats:** 4-card grid (Profiles, Total Anomalies, Learning, Monitoring)

### Issues

- Auto-block toggle and threshold slider are purely local state -- they never invoke a Tauri command to persist or apply the setting. These are STUBBED UI elements.
- Expanded profile details show placeholder text ("Monitoring file access patterns", "Tracking network connection patterns") rather than real data -- partially STUBBED detail views.

### Classification: PARTIAL -- Data fetching is real, but auto-block controls and expanded detail content are stubbed.

---

## 12.6 Guards (src/pages/Guards.tsx)

**Purpose:** Lists active guard rules with toggle switches to enable/disable.

### Data Fetched

| Tauri Command | Classification |
|---|---|
| `list_guards` (polled every 5s) | REAL |

### Interactive Elements

| Element | Action | Classification |
|---|---|---|
| Guard enable/disable toggle | Local state only (no Tauri command) | STUBBED |

### States

- **Error:** Full error page with red banner
- **Empty:** "No Active Guards" with instructions

### Issues

- The toggle switch updates local state only: `setGuards(prev => prev.map(...))`. It never calls a Tauri command like `toggle_guard` or `update_guard`. This means toggling a guard has no backend effect and resets on next poll (5s). STUBBED.

### Classification: PARTIAL -- Data display is real, toggle is stubbed.

---

## 12.7 NetworkLog (src/pages/NetworkLog.tsx)

**Purpose:** Table of network connection events with filters, detail panel, and export.

### Data Fetched on Mount

| Tauri Command | Classification |
|---|---|
| `get_network_connections` (limit: 50) | REAL |
| `get_network_summary` | REAL |
| `get_network_extension_status` | REAL |

### Interactive Elements

| Element | Action | Classification |
|---|---|---|
| Search input | Client-side text filter | REAL |
| Protocol filter dropdown (TCP/UDP) | Client-side filter | REAL |
| Action filter dropdown | Client-side filter | REAL |
| "Export" button | `invoke("export_network_log")` | REAL |
| Clickable table rows | Opens ConnectionDetail panel | REAL |
| "Close" button in detail panel | Closes detail | REAL |

### States

- **Empty (no data):** Message about network extension status or proxy
- **Empty (filtered):** "No connections match your filters"
- **Summary:** Hidden when all counts are zero

### Issues

- No polling -- data is fetched once on mount. New connections won't appear until page remount.
- Export uses `alert()` for success feedback which is a native browser dialog, not a styled notification.

### Classification: REAL -- All data and export from real Tauri commands.

---

## 12.8 PolicyEditor (src/pages/PolicyEditor.tsx)

**Purpose:** CRUD interface for security policy rules with security level chooser and template browser.

### Data Fetched

| Tauri Command | Classification |
|---|---|
| `get_policy` | REAL (falls back to hardcoded defaults on error) |

### Interactive Elements

| Element | Action | Classification |
|---|---|---|
| "+ New Rule" button | Opens RuleEditorModal | REAL |
| Rule Edit button | Opens RuleEditorModal with rule data | REAL |
| Three-dot menu per rule | Opens context menu | REAL |
| Menu: Duplicate | Local state duplication | PARTIAL (not persisted) |
| Menu: Enable/Disable | Local state toggle | PARTIAL (not persisted) |
| Menu: Move Up/Down | Local state reorder | PARTIAL (not persisted) |
| Menu: Delete | `invoke("delete_rule")` | REAL |
| "Change Level" button | Opens SecurityLevelChooser modal | REAL |
| "Change Template" button | Opens TemplateBrowser modal | REAL |
| "Reset" button | `invoke("reload_policy")` | REAL |
| "+ Add Rule" (empty state) | Opens RuleEditorModal | REAL |
| "Browse Templates" (empty state) | Opens TemplateBrowser | REAL |

### States

- **Loading:** "Loading policy..."
- **Feedback toast:** Success/error message (auto-dismiss 3s)
- **Empty:** Dashed border with "No rules configured" + add/template buttons

### Issues

- `get_policy` falls back to hardcoded mock rules on error -- this means the UI always has content even without a backend
- Duplicate, Enable/Disable, and Move operations are local-only state changes (no Tauri command). They persist until `reload_policy` or page remount.
- Hit count shows `Math.floor(Math.random() * 100 + index * 10)` -- random fake data on every render. STUBBED.

### Classification: PARTIAL -- CRUD works via real commands, but inline operations (duplicate, toggle, reorder) and hit counts are stubbed.

---

## 12.9 Scanner (src/pages/Scanner.tsx)

**Purpose:** Security scanner with module selection, progress tracking, detailed findings, and one-click fixes.

### Data Fetched

| Tauri Command | Classification |
|---|---|
| `start_scan` (on button click) | REAL |
| `get_scan_progress` (polled 500ms during scan) | REAL |
| `get_scan_results` (after scan completes) | REAL |
| `apply_scan_fix` (on fix button click) | REAL |

### Interactive Elements

| Element | Action | Classification |
|---|---|---|
| Module toggle buttons (5 modules) | Local selection state | REAL |
| Select All / Deselect All | Toggle all modules | REAL |
| "Run Security Scan" button | `invoke("start_scan")` | REAL |
| Module result accordion (expand/collapse) | Client-side toggle | REAL |
| "Apply Fix" / "Wrap Server" button per finding | `invoke("apply_scan_fix")` | REAL |

### States

- **Pre-scan:** Module selection + Run button
- **Scanning:** Progress bar + current module + elapsed timer + findings count
- **Results:** Severity summary cards + per-module expandable findings
- **Scan history:** List of previous scans with status badges
- **Error:** Red error banner

### Issues

- Apply fix success uses `alert()` native dialog
- Scan history is local-only (resets on page remount)

### Classification: REAL -- All scan operations use real Tauri commands.

---

## 12.10 SystemHealth (src/pages/SystemHealth.tsx)

**Purpose:** Diagnostic checks and system information display.

### Data Fetched

| Tauri Command | Classification |
|---|---|
| `run_doctor` | REAL |
| `get_system_info` | REAL |

### Interactive Elements

| Element | Action | Classification |
|---|---|---|
| Fix buttons per diagnostic check | Contextual: opens System Preferences or starts daemon | REAL |
| "Re-run diagnostics" link | Re-fetches data | REAL |

### States

- **Loading:** "Running diagnostics..."
- **Error:** Red error banner
- **Empty:** "No diagnostic checks available."
- **Overall badge:** Healthy/Warnings/Issues Found

### Issues

- Fix button for System Settings uses `invoke("open_url")` with macOS preferences URL -- may fail if command doesn't exist (caught)
- Fix button for "start daemon" uses `invoke("start_daemon")` and re-runs diagnostics

### Classification: REAL

---

## 12.11 ThreatIntel (src/pages/ThreatIntel.tsx)

**Purpose:** Threat intelligence dashboard with feed status, blocklist warnings, rule packs, IoC stats, and telemetry settings.

### Data Fetched on Mount

| Tauri Command | Classification |
|---|---|
| `get_feed_status` | REAL |
| `get_blocklist_matches` | REAL |
| `get_rule_packs` | REAL |
| `get_ioc_stats` | REAL |
| `get_telemetry_status` | REAL |
| `get_telemetry_preview` | REAL |

### Interactive Elements

| Element | Action | Classification |
|---|---|---|
| "Update Now" button | `invoke("force_feed_update")` + refresh | REAL |
| Rule pack Install/Uninstall buttons | `invoke("install_rule_pack")` / `invoke("uninstall_rule_pack")` | REAL |
| Telemetry toggle | `invoke("toggle_telemetry")` | REAL |

### States

- **Loading:** "Loading feed status..." / "Loading IoC stats..."
- **Empty feed:** Warning with CLI instructions
- **Empty IoC:** Instructions to run feed update
- **Empty blocklist:** "No blocklist matches. All monitored servers appear clean."
- **Empty rule packs:** Explanatory text

### Classification: REAL

---

## 12.12 Timeline (src/pages/Timeline.tsx)

**Purpose:** Real-time virtualized event timeline with search, filters, detail panel, and SLM analysis display.

### Data Fetched

| Tauri Command | Classification |
|---|---|
| `get_recent_events` (on mount) | REAL |

### Real-Time Events

| Event | Classification |
|---|---|
| `clawdefender://event` (via useTauriEvent) | REAL |

### Interactive Elements

| Element | Action | Classification |
|---|---|---|
| Search input | Client-side text filter | REAL |
| Server filter dropdown | Client-side filter | REAL |
| Status filter buttons (allowed/blocked/prompted) | Client-side toggle filter | REAL |
| "Only blocks" checkbox | Client-side filter | REAL |
| Clickable event rows | Opens EventDetailPanel | REAL |
| "Close" button in detail panel | Closes panel | REAL |
| "Scroll to latest" button | Resets scroll to top | REAL |

### Notable Features

- **Virtualized rendering:** Uses custom virtual scroll with `ROW_HEIGHT=48`, `BUFFER_ROWS=10`, calculated start/end indices. Handles large event lists efficiently.
- **Auto-scroll:** Tracks whether user is at top; auto-scrolls to new events if so.
- **SLM Analysis section:** Parses JSON `details` field for `slm_analysis`/`analysis` subfield; renders with styled box.

### States

- **Live indicator:** Green pulsing dot when receiving events
- **Empty (no data):** "No events recorded yet."
- **Empty (filtered):** "No events match your filters."

### Classification: REAL

---

## 12.13 Components

### Sidebar (src/components/Sidebar.tsx)

- 10 navigation links (matches route table exactly)
- Daemon status indicator (green/red dot) from eventStore
- Pending prompts badge on Dashboard link
- Version footer: "v0.3.0-beta"
- Sidebar path `/health` is in the route table but NOT in sidebar `navItems` -- SystemHealth is accessible only via direct URL navigation
- Classification: REAL

### NotificationLayer (src/components/NotificationLayer.tsx)

- Always rendered (in App.tsx outside routes)
- Listens to 3 events: `clawdefender://prompt`, `clawdefender://auto-block`, `clawdefender://alert`
- Renders: PromptQueue (modal overlay), AlertWindow (modal overlay), AutoBlockToast (top-right toasts)
- Review/Trust/KillProcess/ViewTimeline handlers set local state but have TODO comments ("in the future")
- Classification: PARTIAL -- Event listening is real, but Review/Trust/KillProcess/ViewTimeline actions are stubbed

### PromptQueue (src/components/PromptQueue.tsx)

- Thin wrapper: renders first pending prompt via PromptWindow
- Shows queue count
- Classification: REAL

### PromptWindow (src/components/PromptWindow.tsx)

- Full prompt dialog with timer bar, risk level, server/tool/action/resource details
- Countdown timer (auto-deny on timeout)
- Keyboard shortcuts: D=deny, A=allow_once, S=allow_session, P=allow_always
- SLM analysis: calls `get_slm_analysis_for_prompt` for AI-powered analysis display
- 4 decision buttons: Deny, Allow Once, Session, Always -> `invoke("respond_to_prompt")`
- High risk variant: larger Deny button, recommendation banner
- Classification: REAL

### AlertWindow (src/components/AlertWindow.tsx)

- Security alert dialog with level, message, details, kill chain info, suspicious events list
- 3 buttons: Kill Process, View in Timeline, Dismiss
- Kill Process and View in Timeline are handled by NotificationLayer (stubbed -- no Tauri commands)
- Classification: PARTIAL (display is real, actions are stubbed)

### AutoBlockToast (src/components/AutoBlockToast.tsx)

- Slide-in toast notification for auto-blocked actions
- Shows server name, action, anomaly score
- Auto-dismiss after 10s with animation
- Review and Trust buttons handled by NotificationLayer (stubbed)
- Classification: PARTIAL (display is real, actions are stubbed)

### RuleEditorModal (src/components/RuleEditorModal.tsx)

- Full rule editor: action selector, name, description, path patterns (add/remove), scope (all/specific server), priority slider
- Save: `invoke("add_rule")` or `invoke("update_rule")`
- Classification: REAL

### SecurityLevelChooser (src/components/SecurityLevelChooser.tsx)

- Modal with 3 security levels (monitor-only, balanced, strict)
- Shows change preview when selecting different level
- Apply: `invoke("apply_template")`
- Classification: REAL

### TemplateBrowser (src/components/TemplateBrowser.tsx)

- Modal that lists policy templates
- Fetches via `invoke("list_templates")` (falls back to 4 hardcoded templates on error)
- Confirmation step before applying
- Apply: `invoke("apply_template")`
- Classification: REAL (with graceful fallback)

---

## 12.14 State Management (src/stores/eventStore.ts)

Zustand store with:

| Field | Type | Notes |
|---|---|---|
| `events` | AuditEvent[] | Capped at MAX_EVENTS=10,000, newest first |
| `pendingPrompts` | PendingPrompt[] | Queue of prompts awaiting user decision |
| `daemonRunning` | boolean | Global daemon status |
| `addEvent` | function | Prepends, truncates at cap |
| `addPrompt` | function | Appends to queue |
| `removePrompt` | function | Filters by ID |
| `setDaemonRunning` | function | Direct set |
| `setEvents` | function | Bulk replace |

Classification: REAL -- Clean, minimal store. No mock data.

---

## 12.15 Hooks

### useTauriEvent (src/hooks/useTauriEvent.ts)

- Generic hook wrapping `listen()` from `@tauri-apps/api/event`
- Properly cleans up listener on unmount
- Classification: REAL

### useTheme (src/hooks/useTheme.ts)

- Loads theme from `get_settings`
- Listens to `clawdefender://theme-changed` event
- Responds to OS dark mode changes via `matchMedia`
- Caches to localStorage
- Classification: REAL

---

## 12.16 Types (src/types/index.ts)

Comprehensive TypeScript type definitions for all backend data structures:
- DaemonStatus, McpClient, McpServer
- Policy, PolicyRule, PolicyTemplate
- AuditEvent, PendingPrompt
- ServerProfileSummary, BehavioralStatus
- GuardSummary, ScanProgress
- DoctorCheck, SystemInfo, AppSettings
- FeedStatus, BlocklistAlert, RulePackInfo, IoCStats
- TelemetryStatus, TelemetryPreview
- NetworkExtensionStatus, NetworkSettings
- NetworkConnectionEvent, NetworkSummaryData, DestinationCount, ServerTrafficData
- TauriEvent union type

Classification: REAL -- All types match backend Rust structs.

---

## 12.17 Summary Table

| Page/Component | Classification | Notes |
|---|---|---|
| Dashboard | REAL | All 8 data fetches + 3 event listeners work |
| Settings | REAL (1 STUBBED) | Analysis Frequency dropdown is local-only |
| Onboarding | REAL (1 STUBBED) | showInMenuBar checkbox in step 5 not persisted |
| AuditLog | REAL | Full CRUD, search, sort, filter |
| Behavioral | PARTIAL | Auto-block toggle + threshold + expanded details are stubbed |
| Guards | PARTIAL | Guard toggle is local-only, no backend persistence |
| NetworkLog | REAL | No polling (one-shot fetch); export uses native alert |
| PolicyEditor | PARTIAL | Duplicate/toggle/reorder are local-only; hit counts are random |
| Scanner | REAL | Full scan lifecycle with fixes |
| SystemHealth | REAL | Diagnostics + system info |
| ThreatIntel | REAL | All 6 data fetches + 3 interactive actions work |
| Timeline | REAL | Virtualized + real-time + SLM analysis |
| Sidebar | REAL | Missing /health link |
| NotificationLayer | PARTIAL | Event listeners real, action handlers stubbed |
| PromptWindow | REAL | Full prompt flow + SLM analysis |
| AlertWindow | PARTIAL | Display real, Kill/ViewTimeline actions stubbed |
| AutoBlockToast | PARTIAL | Display real, Review/Trust actions stubbed |
| RuleEditorModal | REAL | Full add/edit with Tauri commands |
| SecurityLevelChooser | REAL | Template application works |
| TemplateBrowser | REAL | With graceful fallback |
| eventStore | REAL | Clean Zustand store |
| useTauriEvent | REAL | Proper cleanup |
| useTheme | REAL | Full theme lifecycle |

### Missing/Orphaned Elements

1. **SystemHealth route `/health` has no Sidebar link** -- page exists and works but is not discoverable via navigation
2. **NotificationLayer action handlers** -- Review, Trust, KillProcess, ViewTimeline all have TODO comments and no Tauri commands
3. **Guards toggle** -- UI suggests enable/disable but has no backend effect
4. **PolicyEditor hit counts** -- `Math.random()` values change on every render
5. **Behavioral auto-block** -- Toggle and threshold are display-only
6. **Analysis Frequency (Settings)** -- Dropdown exists but value is never saved
7. **showInMenuBar (Onboarding)** -- Checkbox exists but value is never persisted

### Total Tauri Commands Referenced by Frontend

Approximately 55 unique Tauri `invoke()` calls across all pages, plus 6 event listeners via `listen()`. All core data-fetching commands connect to real backend implementations. Stubbed elements are limited to secondary UI controls (toggles, sliders) that manipulate local state without backend persistence.
