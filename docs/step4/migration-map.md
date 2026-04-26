# Step 4: Page Migration Map & Navigation Spec

**Version**: 1.0
**Date**: 2026-02-25
**Author**: Agent 1 (Information Architecture Lead)

---

## 1. Current Page Audit

### 1.1 Dashboard (`src/pages/Dashboard.tsx`, 665 lines)

**Data displayed:**
- Protection status hero (daemon running, blocked count, pending prompts)
- Quick stats row: events today, blocked, pending prompts, servers, active guards
- Threat intelligence card (feed version, blocklist warnings, entries count)
- Network protection card (filter active/inactive, connections filtered)
- Network activity card (allowed/blocked/prompted counts, top destinations)
- Recent activity feed (last 10 events, prioritized by decision severity)
- Alerts panel (critical/high risk events, max 5)
- Server overview grid (name, status, event count, wrapped badge)
- SLM status (loaded model name, mock mode warning)

**Tauri commands (reads):**
- `get_daemon_status` -> DaemonStatus
- `get_recent_events` (count: 50) -> AuditEvent[]
- `list_guards` -> GuardSummary[]
- `detect_mcp_clients` -> McpClient[]
- `list_mcp_servers` (per client) -> McpServer[]
- `get_feed_status` -> FeedStatus
- `get_blocklist_matches` -> BlocklistAlert[]
- `get_network_extension_status` -> NetworkExtensionStatus
- `get_network_summary` -> NetworkSummaryData
- `get_slm_status` -> { loaded, model_name, mock_mode }

**Tauri commands (mutations):**
- `start_daemon`

**Tauri events listened:**
- `clawdefender://event` (AuditEvent)
- `clawdefender://status-change` ({ daemon_running })
- `clawdefender://prompt` (PendingPrompt)

**Zustand stores:** eventStore (events, pendingPrompts, daemonRunning)

**User question answered:** "Am I protected? What's happening right now?"

**Duplication:**
- `serverColors`, `getServerColor`, `normalizeDecision`, `formatTime`, `StatusBadge` all duplicated in Timeline
- Protection status logic duplicated conceptually in Sidebar daemon indicator
- Network summary duplicated in NetworkLog
- Feed status/blocklist duplicated in ThreatIntel

**Issues/Stubbed:**
- No protection score calculation (just a binary protected/warning/danger)
- Alert filtering is primitive (just risk_level == critical/high from event list)
- Server overview has no click-through to server detail
- No grouping or collapsing of events
- Hardcoded color strings (not using design system tokens consistently)

---

### 1.2 Timeline (`src/pages/Timeline.tsx`, 606 lines)

**Data displayed:**
- Live event stream with virtualized scrolling (ROW_HEIGHT=48)
- Event detail panel (full event fields + JSON details + SLM analysis)
- Filter bar: search, server dropdown, decision toggle buttons, "only blocks" checkbox
- Live indicator, event count, auto-scroll

**Tauri commands (reads):**
- `get_recent_events` -> AuditEvent[]

**Tauri events listened:**
- `clawdefender://event` (AuditEvent)

**Zustand stores:** eventStore (events)

**User question answered:** "What are my AI tools doing right now?"

**Duplication:**
- `serverColors`, `getServerColor`, `normalizeDecision`, `truncateResource` all duplicated from Dashboard
- `DecisionBadge`, `RiskBadge` similar to Dashboard's `StatusBadge`
- `EventDetailPanel` similar to AuditLog's expanded row

**Issues/Stubbed:**
- Accepts `filterMessage` via navigation state (from NotificationLayer)
- `extractSlmAnalysis` / `SlmAnalysisSection` is Timeline-only (good, should be reused)
- No date separator or event grouping
- No pagination (loads all events at once, relies on virtualization)

---

### 1.3 Onboarding (`src/pages/Onboarding.tsx`, 1068 lines)

**Data displayed:**
- 5-step wizard: Welcome -> Detect & Protect -> Security Level -> AI Analysis -> Complete
- Server detection and wrapping UI
- Security level chooser (permissive/balanced/strict)
- AI model catalog, download with progress, system capabilities
- Completion preferences (start at login, show in menu bar)

**Tauri commands (reads):**
- `detect_mcp_clients` -> McpClient[]
- `list_mcp_servers` (per client) -> McpServer[]
- `get_system_capabilities` -> SystemCapabilities
- `get_model_catalog` -> CatalogModel[]
- `get_installed_models` -> InstalledModelInfo[]
- `get_download_progress` (polling) -> DownloadProgress

**Tauri commands (mutations):**
- `wrap_server` (client, server)
- `apply_template` (name)
- `download_model` (modelId) -> taskId
- `cancel_download` (taskId)
- `enable_autostart`
- `disable_autostart`
- `get_settings` -> AppSettings
- `update_settings` (settings)
- `complete_onboarding`

**User question answered:** "How do I set up Rookbot?"

**Duplication:**
- Security level definitions duplicated between here and SecurityLevelChooser component
- Model download UI duplicated between here and Settings page (nearly identical)
- `formatBytes` duplicated in Settings and Scanner

**Issues/Stubbed:**
- Does not use constants from `messages.ts` ONBOARDING_WELCOME etc. (hardcoded strings)
- AI download step has complex polling logic that could be shared with Settings
- No way to return to onboarding after completion

---

### 1.4 PolicyEditor (`src/pages/PolicyEditor.tsx`, 361 lines)

**Data displayed:**
- Rule list with action icon, name, pattern, priority, enabled state
- Security level indicator with change button
- Template section with change/reset buttons
- Feedback toast for operations

**Tauri commands (reads):**
- `get_policy` -> Policy

**Tauri commands (mutations):**
- `delete_rule` (ruleName)
- `duplicate_rule` (ruleName)
- `toggle_rule` (ruleName)
- `reorder_rules` (ruleNames)
- `reload_policy`

**Modal components used:**
- `RuleEditorModal` (add_rule, update_rule)
- `SecurityLevelChooser` (apply_template)
- `TemplateBrowser` (list_templates, apply_template)

**User question answered:** "What rules control my AI tools' behavior?"

**Duplication:**
- Security level UI duplicated with Onboarding step 3
- Template browsing overlaps with Onboarding

**Issues/Stubbed:**
- Navigation state `highlightServer` / `highlightAction` from NotificationLayer auto-block review
- No search/filter for rules
- No import/export

---

### 1.5 Settings (`src/pages/Settings.tsx`, ~1600 lines)

**Data displayed:**
- Daemon control (start/stop, autostart toggle)
- General settings (security level, minimize to tray, notification sound, log level)
- AI Model management (active model info, catalog, download, switch, delete, cloud providers, API keys)
- Network protection (extension status, enable/disable, domain whitelist/blacklist)
- Advanced section (config paths, export config, danger zone with reset/clear)
- Behavioral analysis settings (auto-block, threshold)

**Tauri commands (reads):**
- `get_settings` -> AppSettings
- `get_daemon_status` -> DaemonStatus
- `get_slm_status` -> SlmStatus
- `get_active_model_info` -> ActiveModelInfo
- `get_system_capabilities` -> SystemCapabilities
- `get_model_catalog` -> CatalogModel[]
- `get_installed_models` -> InstalledModelInfo[]
- `get_download_progress` (polling) -> DownloadProgress
- `get_cloud_providers` -> CloudProvider[]
- `get_cloud_usage_stats` -> CloudUsageStats
- `get_network_extension_status` -> NetworkExtensionStatus
- `get_network_settings` -> NetworkSettings

**Tauri commands (mutations):**
- `update_settings` (settings)
- `start_daemon`, `stop_daemon`
- `enable_autostart`, `disable_autostart`
- `download_model` (modelId), `cancel_download` (taskId)
- `switch_model` (modelId), `delete_model` (modelId), `unload_model`
- `set_cloud_api_key` (provider, apiKey)
- `set_cloud_model` (provider, modelId)
- `test_cloud_connection` (provider)
- `enable_network_extension`, `disable_network_extension`
- `update_network_settings` (settings)
- `export_config`, `reset_config`, `clear_all_data`
- `apply_template` (name)

**Tauri events emitted:**
- `theme-changed` (via emit())

**User question answered:** "How do I configure Rookbot?"

**Duplication:**
- Model management UI almost identical to Onboarding step 4
- Daemon start/stop duplicated with Dashboard
- Security level chooser duplicated with PolicyEditor
- Network status display duplicated with Dashboard
- `formatBytes` duplicated with Scanner and Onboarding

**Issues/Stubbed:**
- Massive file (~1600 lines), needs decomposition
- scrollTo navigation state from Dashboard "Enable in Settings" link
- Cloud provider section has full API key management
- Danger zone (reset/clear) with confirmation dialogs

---

### 1.6 Behavioral (`src/pages/Behavioral.tsx`, 280 lines)

**Data displayed:**
- Behavioral analysis status (enabled/disabled badge)
- Stats: profiles count, total anomalies, learning servers, monitoring servers
- Server profiles list with expandable detail (tools count, total calls, anomaly score, last activity)
- Auto-block control (toggle + anomaly threshold slider)

**Tauri commands (reads):**
- `get_behavioral_status` -> BehavioralStatus
- `get_profiles` -> ServerProfileSummary[]
- `get_settings` -> AppSettings

**Tauri commands (mutations):**
- `update_settings` (settings) -- for behavioral_auto_block and behavioral_threshold

**User question answered:** "How are my AI tools behaving? Are any anomalous?"

**Duplication:**
- Auto-block toggle and threshold overlap with Settings behavioral section
- Server profile concept overlaps with Dashboard server overview

**Issues/Stubbed:**
- 5-second polling interval for data refresh
- No per-tool breakdown within a server profile
- No anomaly history/timeline per server

---

### 1.7 Scanner (`src/pages/Scanner.tsx`, 584 lines)

**Data displayed:**
- Module selector (5 modules: MCP Config Audit, Policy Strength, Server Reputation, System Posture, Behavioral Anomaly)
- Scan progress (percent, module count, findings count, elapsed time)
- Results: severity summary cards, per-module expandable findings with fix suggestions
- Scan history list
- One-click fix buttons for applicable findings

**Tauri commands (reads):**
- `get_scan_progress` (scanId) -> ScanProgress
- `get_scan_results` (scanId) -> ScanResult

**Tauri commands (mutations):**
- `start_scan` (serverCommand, modules, timeout) -> scanId
- `apply_scan_fix` (client, server, actionType)

**User question answered:** "Are there security issues with my setup?"

**Duplication:**
- `formatBytes` duplicated from Onboarding and Settings
- Severity cards pattern similar to Dashboard stats

**Issues/Stubbed:**
- Scan history is in-memory only (resets on page reload)
- No scheduled/automatic scanning
- Fix actions may fail silently

---

### 1.8 Guards (`src/pages/Guards.tsx`, 156 lines)

**Data displayed:**
- Guard list with name, type badge, description, trigger count, last triggered
- Enable/disable toggle per guard
- Empty state explaining how guards work

**Tauri commands (reads):**
- `list_guards` -> GuardSummary[]

**Tauri commands (mutations):**
- `toggle_guard` (guardName, enabled)

**User question answered:** "What automated protections are active?"

**Duplication:**
- Guard count shown on Dashboard (stat card)
- 5-second polling interval same as Behavioral

**Issues/Stubbed:**
- No guard creation UI (SDK-only registration)
- No guard detail view with history
- Empty state is informational but not actionable

---

### 1.9 AuditLog (`src/pages/AuditLog.tsx`, 308 lines)

**Data displayed:**
- Sortable table: time, server, tool, resource, action, risk level
- Expandable row detail (event ID, type, action, decision, details)
- Filters: search, server dropdown, decision dropdown, risk level dropdown
- Sort by any column

**Tauri commands (reads):**
- `get_recent_events` -> AuditEvent[]

**User question answered:** "What exactly happened? Give me the raw data."

**Duplication:**
- Nearly identical data to Timeline but in table format
- `normalizeDecision`, `normalizeRiskLevel` duplicated from Timeline
- Filter logic duplicated from Timeline
- 5-second polling interval

**Issues/Stubbed:**
- No export capability
- No pagination (loads all events)
- Expanded row detail is less rich than Timeline's EventDetailPanel (no SLM analysis)

---

### 1.10 SystemHealth (`src/pages/SystemHealth.tsx`, 194 lines)

**Data displayed:**
- Diagnostic checks list (pass/warn/fail) with fix buttons
- System information table (OS, version, arch, daemon version, app version, config dir, log dir)
- Overall health badge

**Tauri commands (reads):**
- `run_doctor` -> DoctorCheck[]
- `get_system_info` -> SystemInfo

**Tauri commands (mutations):**
- `open_url` (for system settings fix)
- `start_daemon` (for "start daemon" fix)

**User question answered:** "Is Rookbot itself working correctly?"

**Duplication:**
- Daemon start duplicated with Dashboard and Settings
- System info partially shown in Settings advanced section

**Issues/Stubbed:**
- Fix buttons have hardcoded behavior (URL open, daemon start)
- No auto-refresh after fix
- No health history

---

### 1.11 ThreatIntel (`src/pages/ThreatIntel.tsx`, 360 lines)

**Data displayed:**
- Feed status card (version, entries, last updated, next check, update button)
- Blocklist warnings list
- Community rule packs browser (install/uninstall)
- IoC database stats (network, file, behavioral, total)
- Anonymous telemetry toggle with preview

**Tauri commands (reads):**
- `get_feed_status` -> FeedStatus
- `get_blocklist_matches` -> BlocklistAlert[]
- `get_rule_packs` -> RulePackInfo[]
- `get_ioc_stats` -> IoCStats
- `get_telemetry_status` -> TelemetryStatus
- `get_telemetry_preview` -> TelemetryPreview

**Tauri commands (mutations):**
- `force_feed_update`
- `install_rule_pack` (id)
- `uninstall_rule_pack` (id)
- `toggle_telemetry` (enabled)

**User question answered:** "What threats does Rookbot know about?"

**Duplication:**
- Feed status + blocklist matches duplicated from Dashboard threat intel card
- Telemetry settings could be in Settings

**Issues/Stubbed:**
- Empty state when feed not initialized suggests running CLI command
- IoC database empty state same issue
- No IoC detail view

---

### 1.12 NetworkLog (`src/pages/NetworkLog.tsx`, 470 lines)

**Data displayed:**
- Summary card (allowed/blocked/prompted counts, last 24h)
- Connection table: time, server, destination, port, protocol, action, bytes, duration
- Connection detail panel (server, PID, destination, protocol, TLS, decision, reason, rule, bytes, duration, signals: IoC match, anomaly score, behavioral, kill chain)
- Filters: search, protocol, action
- Export button

**Tauri commands (reads):**
- `get_network_connections` (limit: 50) -> NetworkConnectionEvent[]
- `get_network_summary` -> NetworkSummaryData
- `get_network_extension_status` -> NetworkExtensionStatus

**Tauri commands (mutations):**
- `export_network_log` (format, range) -> path

**User question answered:** "What network connections are my AI tools making?"

**Duplication:**
- Network summary duplicated from Dashboard
- Network extension status duplicated from Dashboard and Settings
- Decision badge pattern duplicated everywhere

**Issues/Stubbed:**
- No real-time updates (loads once)
- Export is JSON only
- Kill chain and behavioral fields in connection detail are advanced

---

### 1.13 AskClaw (`src/pages/AskClaw.tsx`, 869 lines)

**Data displayed:**
- Conversational chat interface with Claw
- Rich data cards: status summary, event list, server list, metric, risk assessment, scan summary
- Action buttons on responses (navigate, tauri_command, follow_up, copy_to_clipboard)
- Confirmation flow for destructive actions
- File/URL drag-and-drop analysis
- Context-sensitive suggestion chips
- Message history with arrow-up recall

**Tauri commands (reads/mutations):**
- `ask_claw` (input, contextJson) -> response JSON
- `confirm_action` (actionJson, state) -> response JSON
- `analyze_config` (path) -> result JSON
- `analyze_file` (path) -> result JSON
- `analyze_url` (url) -> result JSON

**Zustand stores:** conversationStore, eventStore (daemonRunning)

**User question answered:** "I have a question or want to do something via conversation."

**Duplication:**
- `DecisionBadge`, `StatusBadge` patterns duplicated from other pages
- Server list card similar to Dashboard server overview

**Issues/Stubbed:**
- Uses messages.ts ASK_CLAW constants (good)
- New conversation resets store
- History persisted via conversationStore

---

## 2. Shared Components Audit

### 2.1 Sidebar (`src/components/Sidebar.tsx`, 95 lines)
- 11 nav items with unicode icons, fixed width 56 (w-56)
- Daemon running indicator, pending prompts badge on Dashboard
- Version footer
- **Issues:** Not collapsible, no badge counts on other items, hardcoded nav items

### 2.2 PromptWindow (`src/components/PromptWindow.tsx`, 287 lines)
- Approval dialog for pending prompts (deny, allow_once, allow_session, allow_always)
- Timer bar with countdown, keyboard shortcuts, SLM analysis progressive loading
- High-risk variant with deny emphasized
- **Commands:** `respond_to_prompt`, `get_slm_analysis_for_prompt`, `get_slm_status`

### 2.3 PromptQueue (`src/components/PromptQueue.tsx`, 14 lines)
- Renders first pending prompt via PromptWindow, shows queue count

### 2.4 AlertWindow (`src/components/AlertWindow.tsx`, 145 lines)
- Security alert overlay with kill chain info, suspicious events list
- Actions: Kill Process, View in Timeline, Dismiss
- **Not currently wired to any real data** -- only triggered by `clawdefender://alert` event

### 2.5 NotificationLayer (`src/components/NotificationLayer.tsx`, 135 lines)
- Global overlay manager for prompts, alerts, auto-block toasts
- **Commands:** `add_rule` (for trust action), `kill_agent_process`
- **Events:** `clawdefender://prompt`, `clawdefender://auto-block`, `clawdefender://alert`

### 2.6 AutoBlockToast (`src/components/AutoBlockToast.tsx`, 104 lines)
- Slide-in toast for auto-blocked actions with review/trust buttons
- **Issues:** Shows raw anomaly score (violates design system cardinal rule)

### 2.7 RuleEditorModal (`src/components/RuleEditorModal.tsx`, 235 lines)
- Create/edit policy rules: action, name, description, patterns, scope, priority
- **Commands:** `add_rule`, `update_rule`

### 2.8 SecurityLevelChooser (`src/components/SecurityLevelChooser.tsx`, 132 lines)
- Modal to switch security levels (monitor-only, balanced, strict)
- **Commands:** `apply_template`

### 2.9 TemplateBrowser (`src/components/TemplateBrowser.tsx`, 136 lines)
- Modal to browse and apply policy templates with confirmation
- **Commands:** `list_templates`, `apply_template`

### 2.10 Conversation Components (`src/components/conversation/`)
- `AskClawButton.tsx` - Quick-access button to navigate to Ask Claw with pre-populated question
- `ConfirmationCard.tsx` - Inline confirm/cancel card for destructive actions
- `DragDropZone.tsx` - File and URL drop target wrapper
- `ConversationFeed.tsx`, `ConversationInput.tsx`, `QuickActions.tsx` - Sub-components (may be unused, AskClaw page appears self-contained)
- `types.ts` - Shared conversation types

---

## 3. Page Migration Map

| New Page | Route | Absorbs From | What It Shows | Primary User Question |
|----------|-------|-------------|---------------|----------------------|
| **Home** | `/` | Dashboard (redesigned) | Protection score, status summary, today's stats, recent Claw messages, pending actions, server overview | "Am I protected? Is anything wrong?" |
| **Ask Claw** | `/ask-claw` | AskClaw (already built) | Conversational interface with rich data cards, actions, drag-drop | "I have a question or want to do something" |
| **My Tools** | `/tools` | Behavioral, Guards, server parts of Dashboard & Settings | Per-server cards with trust levels, permissions, activity, health, guard status | "What are my AI tools and how are they behaving?" |
| **Activity** | `/activity` | Timeline + AuditLog (merged) | Unified human-readable event feed with grouping, search, filters, detail panel | "What have my AI tools been doing?" |
| **Alerts** | `/alerts` | Dashboard alerts panel, NetworkLog threats, kill chain displays, Scanner findings | Threats, blocks, items needing attention, threat stories, scan results | "Has anything bad happened?" |
| **Settings** | `/settings` | Settings (simplified), PolicyEditor, SystemHealth (advanced), ThreatIntel (advanced) | Simple settings by default, advanced mode toggle for power users | "How do I configure this?" |

### 3.1 Detailed Migration Per Current Page

#### Dashboard -> Home
- Protection status hero -> **Home**: protection score (new calculation using factors from `PROTECTION_SCORE_FACTORS`)
- Quick stats row -> **Home**: today's stats section
- Threat intel card -> **Settings** (advanced > Threat Intel)
- Network protection card -> **Settings** (advanced > Network)
- Network activity card -> **Alerts** (network threat summary)
- Recent activity feed -> **Home**: "Recent from Claw" messages section (top 5 human-readable)
- Alerts panel -> **Alerts** page
- Server overview -> **My Tools** page (expanded)
- SLM status -> **Home**: part of protection score factors
- `start_daemon` button -> **Home**: primary CTA when daemon not running

#### Timeline -> Activity
- Entire page -> **Activity**: primary view (virtualized event list)
- Event detail panel -> **Activity**: detail view (reusable component)
- SLM analysis section -> **Activity**: detail view enrichment
- Filter bar -> **Activity**: enhanced filters
- Live indicator -> **Activity**: preserved

#### AuditLog -> Activity
- Table view -> **Activity**: alternate "table mode" toggle (list vs table)
- Sort functionality -> **Activity**: sort controls
- Expanded row detail -> **Activity**: merged into shared detail panel
- Risk level filter -> **Activity**: added to filter bar

#### Onboarding -> Onboarding (unchanged)
- Stays as standalone flow at `/onboarding`
- Post-completion redirects to new Home (`/`)
- **Update needed:** Use `messages.ts` constants (ONBOARDING_WELCOME, etc.)

#### PolicyEditor -> Settings
- Rule list, CRUD operations -> **Settings** > Policy sub-section
- Security level chooser -> **Settings** > simple mode top-level
- Template browser -> **Settings** > Policy sub-section
- Highlight from notification -> **Settings** > Policy with scroll-to

#### Behavioral -> My Tools
- Server profiles list -> **My Tools**: per-server cards (behavioral tab/section)
- Anomaly scores -> **My Tools**: visual indicator per server (no raw numbers per design system)
- Auto-block control -> **Settings** > simple mode toggle
- Stats -> **My Tools**: aggregate stats header

#### Scanner -> Alerts (results) + Settings (trigger)
- Scan trigger/module selector -> **Settings** > advanced > Scanner section
- Scan results/findings -> **Alerts**: scan findings appear as alert cards
- Fix buttons -> **Alerts**: action buttons on finding cards
- Scan history -> **Settings** > advanced > Scanner section

#### Guards -> My Tools
- Guard list -> **My Tools**: guards tab/section within server cards or separate guards section
- Guard toggle -> **My Tools**: inline toggle
- Guard empty state -> **My Tools**: empty state from `EMPTY_STATES.guards`

#### SystemHealth -> Settings
- Diagnostic checks -> **Settings** > advanced > System Health section
- System info -> **Settings** > advanced > System Health section
- Fix buttons -> **Settings** > inline fix actions

#### ThreatIntel -> Settings
- Feed status -> **Settings** > advanced > Threat Intel section
- Blocklist warnings -> **Alerts**: blocklist matches appear as alert cards
- Rule packs -> **Settings** > advanced > Threat Intel section
- IoC stats -> **Settings** > advanced > Threat Intel section
- Telemetry -> **Settings** > simple mode toggle

#### NetworkLog -> Alerts
- Connection table -> **Alerts** > network sub-tab or filter
- Connection detail -> **Alerts** > detail view for network events
- Summary stats -> **Alerts** > network summary header
- Export -> **Alerts** > export action
- Kill chain / behavioral signals -> **Alerts** > threat story enrichment

---

## 4. Three-Level Detail Depth

### 4.1 Event (AuditEvent)

| Level | Content |
|-------|---------|
| **Glance** | `[time] [server] [tool]: [decision badge]` -- e.g. "2:34 PM  filesystem-server  read_file: Allowed" |
| **Summary** | Time, server (colored), tool name, action description, resource (truncated), decision badge, risk badge. 1 row ~48px. |
| **Full Detail** | All fields: event ID, timestamp (full), server, event type, tool, action, resource (full path), decision, risk level, details (formatted JSON), SLM analysis (if available). Expandable panel. |

### 4.2 Server Profile (McpServer + ServerProfileSummary)

| Level | Content |
|-------|---------|
| **Glance** | `[name] [status dot] [event count]` -- e.g. "filesystem-server (running) 42 events" |
| **Summary** | Name, status badge (running/stopped/error), wrapped badge, event count, anomaly indicator (green/amber/red dot -- no number), tools count, last activity time. Card ~120px. |
| **Full Detail** | All summary fields plus: behavioral status (learning/monitoring/anomalous), per-tool breakdown, anomaly score dimensions (displayed as bar chart, no raw numbers), guard assignments, total calls, activity timeline mini-chart. Side panel or sub-page. |

### 4.3 Policy Rule (PolicyRule)

| Level | Content |
|-------|---------|
| **Glance** | `[action icon] [name] [pattern preview]` -- e.g. "X Block file writes  /home/**/*.env" |
| **Summary** | Action icon+color, name, pattern, priority badge, enabled state, description (1 line). Row ~56px. |
| **Full Detail** | All fields: name, description, action, patterns (all), resource scope, priority slider, enabled toggle, edit/delete/duplicate actions. Modal or inline expand. |

### 4.4 Scan Result (ScanFinding)

| Level | Content |
|-------|---------|
| **Glance** | `[severity badge] [description]` -- e.g. "HIGH  Unwrapped MCP server detected" |
| **Summary** | Severity badge, category tag, description, affected resource, fix suggestion (1 line). Row ~64px. |
| **Full Detail** | All summary fields plus: module name, fix action button (if available), full resource path, related events. Expandable within module group. |

### 4.5 Alert (high-risk event, blocklist match, kill chain)

| Level | Content |
|-------|---------|
| **Glance** | `[threat level icon] [one-liner from notification template]` -- e.g. "ShieldX  An agent tried to read your SSH private key. I paused it." |
| **Summary** | Threat level icon + color, one-liner, server name, time, expanded description (3 lines), action buttons (Review, Dismiss). Card ~100px. |
| **Full Detail** | All summary fields plus: full expanded explanation, educational context, kill chain visualization (if applicable), related events timeline, suspicious events list, recommended actions, SLM analysis. Full panel. |

### 4.6 Guard (GuardSummary)

| Level | Content |
|-------|---------|
| **Glance** | `[type badge] [name] [enabled/disabled]` -- e.g. "input  Prompt Injection Guard  enabled" |
| **Summary** | Type badge (input/output/network/filesystem), name, description (1 line), trigger count, last triggered, enable toggle. Card ~72px. |
| **Full Detail** | All summary fields plus: full description, trigger history, configuration details, associated policy rules. Expandable or side panel. |

---

## 5. Navigation Behavior

### 5.1 Sidebar Structure

```
+---------------------------+
| Rookbot              |   <- Brand, collapsible to icon
|---------------------------|
| [daemon dot] Running      |   <- Status indicator
|---------------------------|
|  Home                     |   <- /
|  Ask Claw                 |   <- /ask-claw
|  My Tools          [2]    |   <- /tools (badge: new tools detected)
|  Activity                 |   <- /activity
|  Alerts            [3]    |   <- /alerts (badge: unresolved count)
|  Settings                 |   <- /settings
|---------------------------|
| [shield] Score: 85        |   <- Protection score compact
| v0.5.0-beta               |
+---------------------------+
```

**Behavior:**
- 6 nav items with icons and labels
- Collapsible to icon-only mode (persisted in settings)
- Badge counts:
  - **Alerts**: unresolved alert count (critical + high risk events + blocklist matches)
  - **My Tools**: count of newly detected but un-wrapped servers
- Sidebar footer: daemon status indicator + protection score compact display
- Active item: highlighted with accent color background
- Hover: bg-tertiary with text-primary transition

### 5.2 URL Routing

| Route | Page | Sub-routes |
|-------|------|------------|
| `/` | Home | -- |
| `/ask-claw` | Ask Claw | -- |
| `/tools` | My Tools | `/tools/:serverName` (server detail) |
| `/activity` | Activity | `/activity/:eventId` (event detail) |
| `/alerts` | Alerts | `/alerts/:alertId` (alert detail) |
| `/settings` | Settings | `/settings/policy`, `/settings/health`, `/settings/threat-intel`, `/settings/network`, `/settings/models` |
| `/onboarding` | Onboarding | -- |

### 5.3 Old Route Redirects

| Old Route | New Route |
|-----------|-----------|
| `/timeline` | `/activity` |
| `/behavioral` | `/tools` |
| `/guards` | `/tools` |
| `/audit` | `/activity` |
| `/network` | `/alerts` |
| `/health` | `/settings/health` |
| `/policy` | `/settings/policy` |
| `/threat-intel` | `/settings/threat-intel` |
| `/scanner` | `/settings` (with scanner section visible) |

### 5.4 Page Transitions

- **Crossfade**: 150ms ease-out opacity transition between pages
- **Implementation**: Wrap `<Routes>` in a transition container with CSS `transition: opacity 150ms ease-out`
- No slide or scale animations (per design system: "subtle, controlled")

### 5.5 Global Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Cmd+K | Focus Ask Claw input (navigate to /ask-claw if not there) |
| Cmd+1-6 | Navigate to page 1-6 |
| Escape | Close any open modal/panel |

---

## 6. Empty States

| Page | Constant | Notes |
|------|----------|-------|
| Home (no events) | `EMPTY_STATES.dashboard` | "All quiet so far." |
| Activity (no events) | `EMPTY_STATES.activity` | "Nothing here yet." |
| Activity (no filter match) | `EMPTY_STATES.searchResults` | "Nothing matched your search." |
| Alerts (no alerts) | `EMPTY_STATES.alerts` | "No threats detected." |
| My Tools (no servers) | `EMPTY_STATES.myTools` | "No servers connected." with Scan/Add CTAs |
| My Tools > Guards | `EMPTY_STATES.guards` | "No guards active." |
| Settings > Scanner | `EMPTY_STATES.scanner` | "No scans yet." |

**New constants needed** (to add to `messages.ts`):

```typescript
export const EMPTY_STATES_NEW = {
  homeNoMessages: {
    headline: "I am keeping watch.",
    body: "When something needs your attention, you will see it here.",
  },
  settingsPolicy: {
    headline: "No rules configured.",
    body: "Add a rule or apply a template to define how I handle AI tool requests.",
    cta: "Add Rule",
    ctaSecondary: "Browse Templates",
  },
  settingsThreatIntel: {
    headline: "Threat feed not set up.",
    body: "Update the threat feed to get the latest known attack patterns and indicators.",
    cta: "Update Feed",
  },
} as const;
```

---

## 7. Tauri Command Registry (Complete)

All `invoke()` calls discovered across all pages and components:

### Read Commands
| Command | Return Type | Used By |
|---------|-------------|---------|
| `get_daemon_status` | DaemonStatus | Dashboard, Settings |
| `get_recent_events` | AuditEvent[] | Dashboard, Timeline, AuditLog |
| `list_guards` | GuardSummary[] | Dashboard, Guards |
| `detect_mcp_clients` | McpClient[] | Dashboard, Onboarding |
| `list_mcp_servers` | McpServer[] | Dashboard, Onboarding |
| `get_feed_status` | FeedStatus | Dashboard, ThreatIntel |
| `get_blocklist_matches` | BlocklistAlert[] | Dashboard, ThreatIntel |
| `get_network_extension_status` | NetworkExtensionStatus | Dashboard, NetworkLog, Settings |
| `get_network_summary` | NetworkSummaryData | Dashboard, NetworkLog |
| `get_slm_status` | SlmStatus | Dashboard, PromptWindow, Settings |
| `get_settings` | AppSettings | Behavioral, Onboarding, Settings |
| `get_behavioral_status` | BehavioralStatus | Behavioral |
| `get_profiles` | ServerProfileSummary[] | Behavioral |
| `get_policy` | Policy | PolicyEditor |
| `get_scan_progress` | ScanProgress | Scanner |
| `get_scan_results` | ScanResult | Scanner |
| `get_system_capabilities` | SystemCapabilities | Onboarding, Settings |
| `get_model_catalog` | CatalogModel[] | Onboarding, Settings |
| `get_installed_models` | InstalledModelInfo[] | Onboarding, Settings |
| `get_download_progress` | DownloadProgress | Onboarding, Settings |
| `get_network_connections` | NetworkConnectionEvent[] | NetworkLog |
| `get_network_settings` | NetworkSettings | Settings |
| `get_cloud_providers` | CloudProvider[] | Settings |
| `get_cloud_usage_stats` | CloudUsageStats | Settings |
| `get_active_model_info` | ActiveModelInfo | Settings |
| `run_doctor` | DoctorCheck[] | SystemHealth |
| `get_system_info` | SystemInfo | SystemHealth |
| `list_templates` | PolicyTemplate[] | TemplateBrowser |
| `get_rule_packs` | RulePackInfo[] | ThreatIntel |
| `get_ioc_stats` | IoCStats | ThreatIntel |
| `get_telemetry_status` | TelemetryStatus | ThreatIntel |
| `get_telemetry_preview` | TelemetryPreview | ThreatIntel |
| `get_slm_analysis_for_prompt` | SlmAnalysis | PromptWindow |

### Mutation Commands
| Command | Parameters | Used By |
|---------|-----------|---------|
| `start_daemon` | -- | Dashboard, SystemHealth, Settings |
| `stop_daemon` | -- | Settings |
| `respond_to_prompt` | promptId, decision | PromptWindow |
| `wrap_server` | client, server | Onboarding |
| `apply_template` | name | Onboarding, PolicyEditor, SecurityLevelChooser, TemplateBrowser, Settings |
| `download_model` | modelId | Onboarding, Settings |
| `cancel_download` | taskId | Onboarding, Settings |
| `switch_model` | modelId | Settings |
| `delete_model` | modelId | Settings |
| `unload_model` | -- | Settings |
| `enable_autostart` | -- | Onboarding, Settings |
| `disable_autostart` | -- | Onboarding, Settings |
| `update_settings` | settings | Onboarding, Behavioral, Settings |
| `complete_onboarding` | -- | Onboarding |
| `add_rule` | rule | RuleEditorModal, NotificationLayer |
| `update_rule` | rule | RuleEditorModal |
| `delete_rule` | ruleName | PolicyEditor |
| `duplicate_rule` | ruleName | PolicyEditor |
| `toggle_rule` | ruleName | PolicyEditor |
| `reorder_rules` | ruleNames | PolicyEditor |
| `reload_policy` | -- | PolicyEditor |
| `toggle_guard` | guardName, enabled | Guards |
| `start_scan` | serverCommand, modules, timeout | Scanner |
| `apply_scan_fix` | client, server, actionType | Scanner |
| `export_network_log` | format, range | NetworkLog |
| `force_feed_update` | -- | ThreatIntel |
| `install_rule_pack` | id | ThreatIntel |
| `uninstall_rule_pack` | id | ThreatIntel |
| `toggle_telemetry` | enabled | ThreatIntel |
| `set_cloud_api_key` | provider, apiKey | Settings |
| `set_cloud_model` | provider, modelId | Settings |
| `test_cloud_connection` | provider | Settings |
| `enable_network_extension` | -- | Settings |
| `disable_network_extension` | -- | Settings |
| `update_network_settings` | settings | Settings |
| `export_config` | -- | Settings |
| `reset_config` | -- | Settings |
| `clear_all_data` | -- | Settings |
| `kill_agent_process` | pid | NotificationLayer |
| `ask_claw` | input, contextJson | AskClaw |
| `confirm_action` | actionJson, state | AskClaw |
| `analyze_config` | path | AskClaw |
| `analyze_file` | path | AskClaw |
| `analyze_url` | url | AskClaw |

### Tauri Events
| Event | Payload | Listened By |
|-------|---------|-------------|
| `clawdefender://event` | AuditEvent | Dashboard, Timeline |
| `clawdefender://status-change` | { daemon_running } | Dashboard |
| `clawdefender://prompt` | PendingPrompt | Dashboard, NotificationLayer |
| `clawdefender://auto-block` | AutoBlockInfo | NotificationLayer |
| `clawdefender://alert` | AlertData | NotificationLayer |
| `theme-changed` | (emitted by Settings) | -- |

---

## 8. Shared Utilities to Extract

These utilities are duplicated across 2+ pages and should be extracted into shared modules:

| Utility | Currently In | Extract To |
|---------|-------------|------------|
| `serverColors` + `getServerColor` | Dashboard, Timeline | `src/utils/serverColor.ts` |
| `normalizeDecision` | Dashboard, Timeline, AuditLog | `src/utils/normalize.ts` |
| `normalizeRiskLevel` | Timeline, AuditLog | `src/utils/normalize.ts` |
| `formatTime` / `formatTimestamp` | Dashboard, Timeline, AuditLog, Behavioral, Guards, ThreatIntel, NetworkLog | `src/utils/formatTime.ts` |
| `formatBytes` | Onboarding, Scanner, Settings, NetworkLog | `src/utils/formatBytes.ts` |
| `truncateResource` | Dashboard, Timeline | `src/utils/truncateResource.ts` |
| `DecisionBadge` / `StatusBadge` | Dashboard, Timeline, AuditLog, NetworkLog, AskClaw | `src/components/shared/DecisionBadge.tsx` |
| `RiskBadge` | Timeline, AuditLog | `src/components/shared/RiskBadge.tsx` |
| `EventDetailPanel` | Timeline (full), AuditLog (inline) | `src/components/shared/EventDetailPanel.tsx` |
| `StatCard` | Dashboard | `src/components/shared/StatCard.tsx` |

---

## 9. Known Issues & Broken Features

1. **AutoBlockToast shows raw anomaly score** -- violates design system cardinal rule ("user never sees anomaly score numbers")
2. **Onboarding does not use messages.ts constants** -- hardcoded strings for welcome, scan, security level
3. **AuditLog has no SLM analysis** -- Timeline has it but AuditLog's expanded row doesn't
4. **Scanner history is in-memory only** -- lost on page reload
5. **NetworkLog has no real-time updates** -- loads once, no polling or event subscription
6. **AlertWindow is not connected to real data** -- only triggered by events, never by page state
7. **Guards page has no creation UI** -- only SDK registration
8. **No protection score calculation** -- Dashboard shows binary status, not the scored model from messages.ts
9. **Settings page is ~1600 lines** -- needs decomposition into sub-components
10. **Multiple pages use 5s polling intervals** -- should use event-driven updates where possible
11. **formatBytes duplicated 4 times** -- needs extraction
12. **No date separators or event grouping** in Timeline or AuditLog
13. **No export capability** in AuditLog (NetworkLog has it)
14. **Sidebar not collapsible** -- design spec requires icon-only mode
15. **No page transitions** -- currently hard-cuts between routes
