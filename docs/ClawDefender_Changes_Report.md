# ClawDefender — Changes & New Features Report
## Compared against: `docs/ClawDefender_System_Audit.md` (2026-02-24)
## Date: 2026-02-26
## Analyzed by: 3-agent automated analysis team

---

## Executive Summary

Since the system audit on 2026-02-24, ClawDefender has undergone a **major redesign** of the Mac GUI application. The changes represent a fundamental shift from a complex security-dashboard-heavy interface to a **streamlined, AI-first Mac-native experience** focused on conversational assistance, real-time activity monitoring, and intelligent alerting.

### Key Metrics

| Metric | Audit (Feb 24) | Current (Feb 26) | Delta |
|--------|----------------|-------------------|-------|
| GUI Pages | 12 | 13 (8 new, 5 kept) | -7 removed, +8 added |
| Tauri Rust Modules | ~10 | ~23 | +13 new modules |
| Frontend Components | ~15 | ~65+ | +50 new components |
| Zustand Stores | 1 (eventStore) | 6 | +5 new stores |
| Custom Hooks | 0 | 5 | +5 |
| Frontend Tests | 0 | 5 test suites | +5 |
| Design Tokens | None | Full token system | New |
| Tauri Commands | 82 | ~97+ | +15 new |
| Tauri Event Types | ~8 | 10 | +2 guidance events |

### Architectural Shift

| Aspect | Before (Audit) | After (Current) |
|--------|---------------|-----------------|
| **Paradigm** | Dashboard-centric security console | AI-first conversational companion |
| **Primary Interface** | Dashboard with widgets | "Ask Claw" conversational AI |
| **Event Display** | Raw technical data | Humanized natural language |
| **State Management** | Scattered | 6 domain-specific Zustand stores |
| **Routing** | Static pages | Lazy-loaded with Suspense + redirects |
| **User Education** | None | Progressive guidance system (nudges, overlays, toasts) |
| **Crash Recovery** | None | Crash reports + audit log integrity repair |
| **File Safety** | Direct writes | Atomic writes with backups |
| **Performance** | Standard rendering | Virtual scrolling, event batching, TTL caching |

---

## 1. Navigation & Page Architecture Overhaul

### Pages Removed (7)

| Page | What It Was | Replacement |
|------|-------------|-------------|
| `Dashboard.tsx` | Complex security dashboard with widgets | `Home.tsx` — clean status overview |
| `Timeline.tsx` | Chronological event timeline | `Activity.tsx` — virtualized feed with humanization |
| `Behavioral.tsx` | Behavioral analysis visualization | Folded into `MyTools.tsx` |
| `Scanner.tsx` | File/process scanner UI | Folded into `Alerts.tsx` |
| `Guards.tsx` | Guard rule management | Folded into `MyTools.tsx` |
| `AuditLog.tsx` | Audit log viewer | Merged into `Activity.tsx` |
| `NetworkLog.tsx` | Network traffic log | Merged into `Alerts.tsx` |

### Pages Added (8)

| Page | Lines | Purpose |
|------|-------|---------|
| `Home.tsx` | 627 | Protection score ring, 7-day sparkline, quick stats (events/blocked/anomaly/guards), server overview, pending actions, recent Claw messages |
| `Activity.tsx` | 480 | Virtual-scrolled event feed with multi-faceted filtering (text, server, status, risk, time, correlation, notable), period headers, event grouping, live indicator |
| `Alerts.tsx` | 291 | Intelligent alert management with severity hierarchy, AI recommendations with "Do it" buttons, recently handled history grouped by day |
| `AlertDetail.tsx` | — | Deep-dive into individual alerts with correlation context and resolution options |
| `AskClaw.tsx` | 100+ | Conversational AI interface with rich message rendering (markdown, status badges, action buttons), confirmation cards, drag-drop context upload, suggestion pills |
| `EventDetail.tsx` | — | Detailed view of individual events with correlation timeline and kill chain visualization |
| `MyTools.tsx` | — | MCP server inventory with trust levels, anomaly scores, approval status, filtering/search |
| `ToolDetail.tsx` | — | Per-server detail view with behavioral profile, event history, trust level, permissions |

### Pages Modified (5)

| Page | Changes |
|------|---------|
| `Onboarding.tsx` | Simplified flow, Mac-native styling, migration detection, connection status integration |
| `PolicyEditor.tsx` | Redesigned with debounced auto-save, better rule editing, removed template browser dependency |
| `Settings.tsx` | Reorganized into tabbed sections via new settings/ components, daemon control |
| `SystemHealth.tsx` | Updated metrics display, new connection status awareness |
| `ThreatIntel.tsx` | Updated to work with new store architecture |

### Route Structure

```
/                    → Home (dashboard)
/ask                 → Ask Claw (conversational AI)
/tools               → MCP server management
/tools/:id           → Server detail
/activity            → Event feed
/activity/:id        → Event detail
/alerts              → Alert management
/alerts/:id          → Alert detail
/settings            → Settings
/settings/policy     → Policy editor
/settings/health     → System health
/settings/threat-intel → Threat intelligence
/onboarding          → Setup wizard (standalone, no sidebar)

Redirects from old routes:
/dashboard   → /
/timeline    → /activity
/behavioral  → /tools
/guards      → /tools
/audit       → /activity
/network     → /alerts
/scanner     → /alerts
/health      → /settings/health
/ask-claw    → /ask
/policy      → /settings/policy
/threat-intel → /settings/threat-intel
```

---

## 2. New Backend Modules (13 Tauri/Rust Modules)

### 2.1 Alert System (`src-tauri/src/alerts/`)

Real-time threat alerting with intelligence.

| File | Purpose |
|------|---------|
| `engine.rs` | `IntelligentAlert` structs with severity levels (critical/high/medium/low/info) |
| `dedup.rs` | Deduplicates similar alerts within time windows |
| `lifecycle.rs` | Tracks alert state transitions: new → acknowledged → resolved |
| `kill_chain.rs` | Detects multi-step attack patterns across events |

**Integration**: Event stream → alert engine → dedup → frontend via Tauri events.

### 2.2 Conversation Engine (`src-tauri/src/conversation/`)

Multi-turn AI conversation backend for "Ask Claw".

| File | Purpose |
|------|---------|
| `storage.rs` | SQLite-backed `ConversationStore` with message persistence |
| `analysis.rs` | Intent extraction and entity recognition |
| `executor.rs` | Action execution based on conversation context |
| `synthesizer.rs` | Response generation from context |
| `formatter.rs` | Response formatting |
| `templates.rs` | Natural language response templates |

**8 Tauri commands**: `save_conversation_message`, `load_conversation`, `list_conversations`, `search_conversations`, `delete_conversation`, `create_new_conversation`, `get_latest_conversation_id`, `update_conversation_summary`.

**Tests**: Adversarial tests for prompt injection resistance.

### 2.3 Correlation Engine (`src-tauri/src/correlation/`)

Finds relationships between events to identify attack chains.

- Correlates events by tool, server, time window, and resource patterns
- Groups into correlated clusters for kill chain detection
- Integration: Takes stream of AuditEvents → grouped correlation clusters
- Tests included

### 2.4 Crash Reporter (`src-tauri/src/crash_report.rs`)

Privacy-safe crash telemetry.

| Function | Purpose |
|----------|---------|
| `save_crash_report()` | Write JSON crash report to `~/.local/share/clawdefender/crashes/` |
| `list_crash_reports()` | List all pending crash reports |
| `get_crash_report()` | Retrieve specific report by ID |
| `dismiss_crash_report()` | Delete/acknowledge report |

**Data collected**: timestamp, app_version, os_version, arch, crash_type, details only.
**Data NOT collected**: audit logs, file paths, policy rules, API keys, behavioral data.

### 2.5 Digest System (`src-tauri/src/digest/`)

Converts raw event stream into human-readable periodic summaries.

| File | Purpose |
|------|---------|
| `generator.rs` | Builds digestible summaries from events |
| `recommendations.rs` | Generates security recommendations |
| `trends.rs` | Analyzes patterns (activity spikes, new tools, etc.) |

### 2.6 Guidance Engine (`src-tauri/src/guidance/`)

Progressive security education system.

| File | Purpose |
|------|---------|
| `commands.rs` | Tauri command layer |
| `milestones.rs` | Tracks user progress (first event, first block, etc.) |
| `storage.rs` | Persists guidance state |
| `triggers.rs` | Time-based and event-based milestone triggers |

**Tests included.**

### 2.7 Humanizer (`src-tauri/src/humanizer/`)

Converts technical security events into natural language.

| File | Purpose |
|------|---------|
| `humanizer.rs` | `event.action="execute_command"` → `"Ran a shell command"` |
| `display_names.rs` | Human-readable names for tools and servers |
| `context.rs` | Contextual descriptions |
| `templates.rs` | Natural language templates |

### 2.8 Integrity Checker (`src-tauri/src/integrity.rs`)

Audit log repair at startup.

1. Opens `~/.local/share/clawdefender/audit.jsonl`
2. Reads last 64KB (max single JSON line size)
3. Checks if last line is valid JSON
4. If invalid, finds the last valid newline and truncates
5. Logs repair action

**Called at app startup before reading any events.**

### 2.9 Scoring System (`src-tauri/src/score/`)

Real-time behavioral risk assessment.

| File | Purpose |
|------|---------|
| `calculator.rs` | Computes risk scores from event attributes |
| `factors.rs` | Individual scoring factors (shell_exec weight=0.8, file_write=0.6, etc.) |
| `history.rs` | Historical score tracking (7-day snapshots) |
| `events.rs` | Event listener that triggers score recalculation (debounced) |

**Integration**: Event stream → score update → frontend dashboard via `clawdefender://score-changed`.

### 2.10 Summaries (`src-tauri/src/summaries.rs`)

Server profile summaries via `get_server_summary()` Tauri command.

Returns:
- `territory`: Top directories accessed (grouped by 2-level depth)
- `common_tools`: Top 5 tools used (with percentages)
- `network_summary`: Usage pattern (Never/Regular/Rare)
- `activity_pattern`: Hourly distribution, peak times, anomaly detection
- `learning_status`: Progress from learning (0-100 events) to active
- `trust_recommendation`: Categorized as trusted/standard/cautious/restricted
- `notable_observations`: Bullets like "accessed 25 directories", "never went to network"

**20+ comprehensive tests.**

### 2.11 Tool Management (`src-tauri/src/tools/`)

MCP tool discovery and lifecycle management.

| File | Purpose |
|------|---------|
| `capabilities.rs` | Parse tool's exposed capabilities |
| `card.rs` | UI card representation |
| `detection.rs` | Polls for new servers every 60 seconds |
| `health.rs` | Tool health status (working/failed/stale) |

**Integration**: `start_connection_monitor()` spawns detection thread, emits `clawdefender://new-tool-detected` event.

### 2.12 Trust System (`src-tauri/src/trust/`)

Multi-tiered permission system.

| File | Purpose |
|------|---------|
| `levels.rs` | `TrustLevel` enum: Trusted, Standard, Cautious, Restricted, Minimal |
| `permissions.rs` | 6 categories (ToolCall, FileRead, FileWrite, ShellExec, Network, SensitivePaths) × actions (allow/prompt/block per level) |
| `generator.rs` | Builds TOML policy rules from trust level |
| `reader.rs` | Parses and validates policy rules |

### 2.13 Wrap Flow (`src-tauri/src/wrap_flow.rs`)

Orchestrates wrapping/unwrapping tools with reputation checks.

| Function | Purpose |
|----------|---------|
| `wrap_and_initialize()` | Wrap → reputation check → apply trust rules → reload daemon |
| `unwrap_and_cleanup()` | Unwrap → remove trust rules → optionally clear behavioral profile |
| `wrap_multiple()` | Batch wrap multiple servers |
| `protect_new_tool()` | Wrap + add to `known_servers.json` |

**Trust rule pipeline**:
```
New tool detected → detect_new_servers() emits event
  → UI shows wrap prompt
  → wrap_and_initialize()
    → check_server_reputation()
    → apply trust level rules (7 permission categories)
    → atomic_write_file() to policy.toml
    → reload daemon
  → add to known_servers.json
```

**23 tests** covering rule generation, sanitization, permission levels, serialization.

---

## 3. Modified Backend Files

### 3.1 `lib.rs` (Tauri App Entry)

Massively expanded setup flow now calls:
- `integrity::check_and_repair_audit_log()` — fix truncated entries from crashes
- `monitor::start_connection_monitor()` — watchdog with crash detection
- `event_stream::start_event_stream()` — file watcher for audit.jsonl
- `score::events::start_score_listeners()` — risk score recalculation
- `tools::detection::detect_new_servers()` — background polling every 60s
- `daemon::is_daemon_running()` — check for existing daemon before starting new one
- `guidance::triggers::start_guidance_timer()` — time-based milestone checks
- `windows::restore_window_geometry()` — restore saved position/size
- AI model loading in background thread

### 3.2 `commands.rs`
New commands for all 13 new modules. Key additions: `count_wrapped_servers()`, `get_daemon_status()`, `start_daemon()`, `stop_daemon()`.

### 3.3 `daemon.rs`
Seamless daemon lifecycle: `is_daemon_running()` checks PID file + socket, `start_daemon_process()` spawns detached with setsid, reconnection logic prevents duplicate daemons.

### 3.4 `event_stream.rs`
Polls audit.jsonl every 500ms, converts DaemonAuditRecord → AuditEvent, backfills max 100 lines on startup, pending prompt expiration (fail-closed default).

### 3.5 `state.rs`
New types: `ActiveModelInfo` (AI model metadata with mock_mode flag), `AuditEvent`, `PendingPrompt` (with timeout), `DaemonStatus`, `McpClient`, `McpServer`.

### 3.6 `ipc_client.rs`
Extended IPC protocol for new command types with better serialization.

### 3.7 `monitor.rs`
Background watchdog for connection health with crash detection and auto-restart.

### 3.8 `tray.rs`
Updated system tray with alert count and navigation.

### 3.9 `windows.rs`
New: `restore_window_geometry()`, `save_window_geometry()`, `hide_main_window()` (macOS hide-on-close behavior).

---

## 4. Core Crate Changes

### 4.1 `clawdefender-core/atomic_write.rs` (NEW)

Safe file writes using write-fsync-rename pattern.

| Function | Purpose |
|----------|---------|
| `atomic_write_file()` | Write to temp file, fsync, rename (atomic on POSIX) |
| `atomic_write_with_backup()` | Same + automatic `.bak` backup |

**9 tests** covering success, corruption prevention, cleanup, concurrency. Used by `wrap_flow.rs` for policy TOML writes.

### 4.2 `clawdefender-slm`

- **lib.rs**: `SlmService` now supports mock mode detection with `is_mock_mode()` for UI visibility
- **gguf_backend.rs**: Improvements to GGUF model loading and inference
- **model_registry.rs**: Enhanced registry with download, switch, and configuration
- **Cargo.toml**: Feature-gated backends:
  - `cloud`: reqwest — Anthropic/OpenAI APIs
  - `download`: reqwest + sha2 + futures-util — model downloading
  - `gguf`: llama_cpp — local inference

**Feature flag matrix**:
| Crate | Features | Inference |
|-------|----------|-----------|
| `clawdefender-mcp-proxy` | None | Mock (always Low risk) |
| `clawdefender-daemon` | `gguf` | Real inference |
| `clawdefender-cli` | `gguf` | Real inference |
| `clawdefender-app` | `cloud` + `download` + `gguf` | Full stack |

### 4.3 `clawdefender-daemon`

- **ipc.rs**: New `AiSubsystemContext` with slm_service, behavioral_enabled, behavioral_profile_count, learning_engine, decision_engine references
- **lib.rs**: Updated to pass AI context through IPC setup via `run_ipc_server_with_ai()`

### 4.4 Other Core Changes

- **audit/logger.rs**: Enhanced logging with new event categories
- **config/settings.rs**: New fields for digest intervals, trust thresholds, conversation settings, crash reporting
- **guard/registry.rs**: Updated guard types and categorization

---

## 5. Frontend State Management (6 Zustand Stores)

### 5.1 `appStore.ts` — Core App State
- Daemon status, connection state (connected/reconnecting/disconnected)
- Protection score (simple int + full ProtectionScore with factors)
- Score history (7-day snapshots for sparkline)
- TTL caching (30s for score/history)
- Guidance system state (inline hints + overlay data)
- Restart reminder banner

### 5.2 `eventStore.ts` — Event Stream (Modified)
- Max 10,000 `HumanizedEvent` objects in memory
- Event batching (100ms flush) to avoid React re-render storms
- `HumanizedEvent` extends `AuditEvent` with: `one_liner`, `expanded_explanation`, `educational_aside`, `behavioral_context`, `risk_level`, `action_taken`, `is_notable`, `correlation_id`, `kill_chain_id`
- Notable filter toggle
- Daily counters (today's events, today's blocked)

### 5.3 `alertStore.ts` — Intelligent Alerts
- Active alerts (IntelligentAlert[])
- Alert stats (resolved_this_week, blocked_this_week)
- Unresolved count (sidebar badge)
- Methods: `fetchAlerts()`, `dismissAlert()`, `resolveAlert()`, `dismissAll()`, `fetchHistory()`

### 5.4 `conversationStore.ts` — Ask Claw Conversations
- Conversation ID, messages, conversation list
- Context tracking (current page, last server, last event, entities)
- Message intents: `proactive.alert`, `status.*`, `explain.*`, `control.block`, `control.allow`
- Methods: `loadLatestConversation()`, `startNewConversation()`, `addUserMessage()`, `addClawResponse()`, `injectAlert()`, `searchConversations()`

### 5.5 `serverStore.ts` — MCP Server Inventory
- Server list with name, client, status, trust level, anomaly score, wrapped flag
- TTL cache (30s)
- `hasNewUnwrapped` flag for onboarding nudge

### 5.6 `toolStore.ts` — Tool Management
- Tool inventory, approval status, trust scores, usage stats

---

## 6. Frontend Component Architecture

### 6.1 Layout & Shell

| Component | Purpose |
|-----------|---------|
| `Layout.tsx` | App shell: sidebar + header + content + banners + modals. Page crossfade (150ms). Real-time event listeners setup once. |
| `Sidebar.tsx` | 6 nav links (Home, Ask, Tools, Activity, Alerts, Settings) + alert badge + daemon indicator + collapse toggle |
| `ConnectionStatus.tsx` | Daemon connection indicator (connected/reconnecting/disconnected) |
| `UpdateBanner.tsx` | App update notification with dismiss + update buttons |
| `PageHeader.tsx` | Consistent page headers with breadcrumbs and actions |
| `EmptyState.tsx` | Consistent empty state displays with illustrations |
| `ErrorBanner.tsx` | Dismissible error notifications |
| `LoadingSkeleton.tsx` | Skeleton loading states for async content |
| `MigrationScreen.tsx` | Data migration UI for version upgrades |

### 6.2 Feature Component Groups

| Directory | Key Components |
|-----------|---------------|
| `components/home/` | `ProtectionScoreRing` (circular SVG gauge), `QuickStatCard`, `ScoreBreakdown` (drawer modal with factor details + fix actions), `ServerMiniCard` |
| `components/activity/` | `ActivityFilters` (multi-filter UI), `EventRow` (32px compact / 52px expanded), `GroupedEventRow` (accordion), `CorrelationTimeline` (kill chain visualization), `CoverageInsight` |
| `components/alerts/` | `AlertCard` (colored by severity), `ThreatStory` (narrative explanation), `RecommendationCard` (with "Do it" + "Dismiss" buttons) |
| `components/conversation/` | `MessageBubble` (user vs claw), `ActionButton` (execute/navigate/copy), `ConfirmationCard`, `DragDropZone` |
| `components/guidance/` | `GuidanceAnchor` (inline hints), `GuidanceToastContainer` (auto-dismiss toasts), `PromptOverlay` (full-screen guidance modal) |
| `components/notifications/` | `ToastContainer` (max 5 toasts, auto-dismiss 4s), `NotificationLayer`, `AlertWindow`, `PromptQueue`, `PromptWindow` |
| `components/settings/` | Tabbed settings panels (General, Daemon, Notifications, Advanced) |
| `components/tools/` | Tool cards, trust indicators, permission displays, approval controls |
| `components/shared/` | Reusable primitives (buttons, badges, inputs, modals, tabs, dropdowns) |
| `components/prompts/` | User prompt dialogs for MCP tool approval decisions |

### 6.3 Deleted Components

| Component | Replacement |
|-----------|-------------|
| `RuleEditorModal.tsx` | Integrated into PolicyEditor redesign |
| `SecurityLevelChooser.tsx` | Replaced by per-tool trust controls in MyTools |
| `TemplateBrowser.tsx` | Templates managed differently in PolicyEditor |

---

## 7. Tauri IPC Interface

### New Tauri Commands (~15 new)

**Conversation (8)**:
`save_conversation_message`, `load_conversation`, `list_conversations`, `search_conversations`, `delete_conversation`, `create_new_conversation`, `get_latest_conversation_id`, `update_conversation_summary`

**Score & Metrics**:
`get_protection_score`, `get_score_history`, `execute_fix_action`

**Alerts**:
`get_active_alerts_cmd`, `get_alert_stats_cmd`, `get_alert_history_cmd`, `dismiss_alert_cmd`, `resolve_alert_cmd`, `dismiss_all_alerts`, `get_recommendations_cmd`, `execute_recommendation_cmd`, `dismiss_recommendation_cmd`

**Tools & Summary**:
`get_server_summary`, `get_humanized_events`, `get_slm_status`, `record_page_visit`

### Tauri Events (Real-Time)

| Event | Payload | Purpose |
|-------|---------|---------|
| `clawdefender://event` | `AuditEvent` | Raw security event |
| `clawdefender://score-changed` | `ProtectionScore` | Score update |
| `clawdefender://status-change` | `bool` | Daemon running/stopped |
| `clawdefender://prompt` | `PendingPrompt` | User action required |
| `clawdefender://alert` | — | Alert update (triggers refetch) |
| `clawdefender://navigate` | `string` | Tray menu navigation |
| `clawdefender://guidance-hint` | `GuidanceHint` | Inline nudge |
| `clawdefender://guidance-overlay` | `GuidanceOverlay` | Modal guidance |
| `clawdefender://guidance-toast` | `GuidanceToast` | Toast guidance |
| `clawdefender:refresh` | — | Force refresh (Cmd+R) |

---

## 8. Design System

### 8.1 New Design Token System (`tokens.css`)

Single source of truth with 60+ CSS custom properties:

- **Colors**: bg (primary/secondary/tertiary/sunken), text (primary/secondary/muted), border (default/subtle), semantic (accent, safe, danger, warning, info)
- **Animations**: Duration variables (fast 100ms, normal 150ms, moderate 200ms, slow 300ms) + easing functions
- **Shadows**: 4 shadow levels with dark/light variants
- **Border Radius**: sm(4px), md(6px), lg(8px), full(9999px)
- **Z-Index Scale**: base(0), dropdown(10), sticky(20), overlay(30), modal(40), toast(50), prompt(60)
- **Theme Switching**: Dark mode default, `[data-theme="light"]` overrides, `@media (prefers-color-scheme)` fallback

### 8.2 Tailwind Configuration

- All colors reference CSS variables (full separation)
- Custom animations: `analysis-pulse`, `skeleton-shimmer`, `spin`, `indeterminate`
- System font stack: SF Pro Text (macOS), Segoe UI (Windows), system-ui fallback

### 8.3 Global CSS

- Scrollbar styling with token variables
- Accessibility: `focus-visible` vs `focus:not(:focus-visible)` for keyboard-only navigation
- `.sr-only` utility class for screen reader text
- `prefers-reduced-motion` media query support

---

## 9. Hooks, Utilities & Services

### Custom Hooks (5 new)

| Hook | Purpose |
|------|---------|
| `useDebouncedSave` | Debounces save operations (PolicyEditor auto-save) |
| `useFocusTrap` | Traps keyboard focus within modals (accessibility) |
| `useKeyboardShortcuts` | Global shortcuts: Cmd+K (search), Cmd+, (settings), Cmd+R (refresh), Cmd+1-6 (pages), Cmd+W (close), Cmd+Q (quit) |
| `useTauriEvent` | Generic typed hook for Tauri event listeners |
| `useTheme` | Dark/light theme management |

### Utilities

| Module | Purpose |
|--------|---------|
| `eventGrouper` | Groups events by period (Today, Yesterday, This Week, Earlier) |
| `threatLevel` | Maps risk_level → color/severity |
| `serverColor` | Color scheme for different servers |
| `formatTime` | Relative time ("2m ago", "1h ago") |
| `dateUtils` | Date parsing, formatting |
| `textUtils` | Text truncation, normalization |
| `alertGenerator` | Generate alert objects from events |
| `normalize` | Clean/normalize data |

### Services Layer

New abstraction between stores and Tauri commands. Centralizes `invoke()` calls with error handling and retry logic.

### Constants

Centralized configuration: event type enumerations, default values, route definitions, empty state messages, keyboard shortcut help text, Ask Claw prompts.

---

## 10. Frontend Testing (NEW)

Previously: **0 frontend tests** (vitest configured but unused).

Now: **5 test suites**

| Test File | Coverage |
|-----------|----------|
| `activity.test.ts` | Event filtering, grouping, real-time updates |
| `alerts.test.ts` | Alert list, severity filtering, acknowledgment flow |
| `askClaw.test.ts` | Conversation UI, message sending, response rendering |
| `migration.test.ts` | Version migration, data preservation |
| `settings.test.ts` | Settings tabs, value persistence, daemon control |

---

## 11. Performance Optimizations (NEW)

| Optimization | Detail |
|-------------|--------|
| **Lazy Page Loading** | All pages use `React.lazy()` + `Suspense` with `LoadingSkeleton` fallback |
| **Virtual Scrolling** | Activity feed: 52px row height, 400px buffer, only visible rows rendered |
| **Event Batching** | 100ms batch flush prevents React re-render storms |
| **TTL Caching** | 30s cache on score/servers prevents redundant IPC calls |
| **Code Splitting** | Manual chunks: vendor (React/Router/Zustand) + Tauri (6 plugins) |
| **Memoization** | `useMemo` for filtered events/groups, `useCallback` for handlers |

---

## 12. CLI Changes

### DXT Extension Support (NEW)

| Function | Purpose |
|----------|---------|
| `dxt_installations_path()` | Find Claude Desktop's `extensions-installations.json` |
| `find_dxt_extension()` | Locate a specific DXT extension |
| `list_dxt_extensions()` | List all installed DXT extensions |
| `is_dxt_wrapped()` | Check if extension is wrapped (via `_clawdefender_original` marker) |

Supports: Claude Desktop, Cursor, VS Code, Windsurf. Platform-specific paths (macOS: Library/Application Support, Linux: .config).

### MCP Client Registry

`known_clients()` and `find_client_config()` with auto-detection. Handles both `mcpServers` and legacy `servers` keys (Cursor compatibility).

### Policy Commands (7 subcommands)

`list`, `add` (interactive), `test` (JSON fixture), `reload` (IPC signal), `template-list` (4 built-in), `template-apply` (with auto-backup), `suggest` (mine audit logs for patterns, ≥5 frequency → allow, ≥2 block).

---

## 13. Cargo.toml Changes

**App version**: Bumped to **0.5.0-beta** (major feature release).

**New dependencies/features**:
- Tauri 2 with full feature set (tray-icon, image-png)
- Plugins: shell, autostart, notification, updater, process
- `clawdefender-slm` with features `["cloud", "download", "gguf"]`
- SQLite bundled for behavior DB

---

## 14. TypeScript Types Expansion

`types/index.ts` expanded to **627 lines** covering:

1. **Core**: DaemonStatus, McpClient, McpServer, Policy, PolicyRule, PolicyTemplate
2. **Events**: AuditEvent, PendingPrompt, NetworkConnectionEvent (40+ types)
3. **Behavioral**: ServerProfileSummary, BehavioralStatus
4. **Trust**: TrustLevel ("trusted"/"standard"/"cautious"/"restricted"), ServerCapabilities, ToolCardData, PermissionState
5. **Intelligence**: CorrelationResult, HumanizedEvent (one_liner + expanded + educational_aside), KillChainNarrative, IntelligentAlert, WeeklyDigest
6. **Scoring**: ProtectionScore, BackendScoreFactor, FixAction, ScoreSnapshot
7. **Onboarding**: OnboardingState, ToolInfo, WrapResult, ProtectionLevel

---

## 15. Known Issues Carried Forward

From the audit, these issues remain relevant:

1. **SLM Mock Fallback**: MCP proxy builds with NO SLM features → mock backend (always returns Low risk). Only the app and daemon have real inference.
2. **Network Extension**: Still exists only as a mock (no Swift build steps in Vite/Cargo config).

---

## 16. Summary of What's Genuinely New

### Entirely New Systems (12)
1. Conversation engine with SQLite persistence and prompt injection resistance
2. Crash telemetry collection (privacy-safe)
3. Real-time behavioral risk scoring with factor weighting
4. Progressive guidance system with milestones and triggers
5. Natural language humanization layer
6. Multi-tiered trust framework (5 levels × 6 permission categories)
7. Wrap/unwrap orchestration with reputation integration
8. Atomic file write safety module
9. Alert deduplication and lifecycle management
10. Event correlation engine for attack chain detection
11. Server profiling and summarization
12. MCP tool auto-discovery and health monitoring

### Previously Existed but Significantly Expanded (6)
1. Event streaming — now with integrity repair, prompt expiration, batching
2. Daemon management — seamless reconnection, PID-based detection
3. State management — 6 stores replacing scattered state
4. IPC — extended for AI subsystem context
5. SLM — mock mode detection, graceful fallback
6. CLI — DXT extensions, multi-client support, policy suggestions

---

*Report compiled by 3-agent automated analysis team (rust-analyzer, frontend-analyzer, config-analyzer) on 2026-02-26*
