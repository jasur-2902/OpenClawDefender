# Step 4: Progress Tracker

**Started**: 2026-02-25
**Status**: In Progress

---

## Agent Assignments

### Agent 1: Information Architecture Lead -- COMPLETE
- [x] Audit all 13 pages (Dashboard, Timeline, Onboarding, PolicyEditor, Settings, Behavioral, Scanner, Guards, AuditLog, SystemHealth, ThreatIntel, NetworkLog, AskClaw)
- [x] Audit all 10+ shared components
- [x] Document all Tauri commands (34 read, 38 mutation, 5 events)
- [x] Produce migration map (`docs/step4/migration-map.md`)
- [x] Define three-level detail depth for 6 data types
- [x] Define navigation behavior (sidebar, routing, redirects, transitions)
- [x] Define empty states with message constants
- [x] Identify shared utilities to extract (10 items)
- [x] Document 15 known issues

**Deliverable**: `docs/step4/migration-map.md` (this is the authoritative reference for all agents)

---

### Agent 2: Navigation Shell
**Scope**: Rebuild sidebar, routing, layout, page transitions, global stores

**Tasks**:
- [ ] Create new `Sidebar.tsx` with 6 nav items, collapsible to icon-only, badge counts
- [ ] Add sidebar footer: daemon status + protection score compact
- [ ] Set up React Router with new routes: `/`, `/ask-claw`, `/tools`, `/tools/:serverName`, `/activity`, `/activity/:eventId`, `/alerts`, `/alerts/:alertId`, `/settings`, `/settings/policy`, `/settings/health`, `/settings/threat-intel`, `/settings/network`, `/settings/models`
- [ ] Add redirect routes: `/timeline` -> `/activity`, `/behavioral` -> `/tools`, `/guards` -> `/tools`, `/audit` -> `/activity`, `/network` -> `/alerts`, `/health` -> `/settings/health`, `/policy` -> `/settings/policy`, `/threat-intel` -> `/settings/threat-intel`
- [ ] Implement page transition wrapper (150ms crossfade)
- [ ] Add global keyboard shortcuts (Cmd+K, Cmd+1-6, Escape)
- [ ] Create layout shell with sidebar + content area
- [ ] Update `NotificationLayer` to use new route paths for navigation

**Dependencies**: Migration map (Agent 1) -- DONE
**Blocked by**: None

---

### Agent 3: Home Screen
**Scope**: Build the redesigned Home page with protection score, stats, server overview

**Tasks**:
- [ ] Create new `Home.tsx` page replacing Dashboard
- [ ] Implement protection score calculation using `PROTECTION_SCORE_FACTORS` from messages.ts:
  - Factor: unwrapped servers (detect_mcp_clients + list_mcp_servers, check wrapped status)
  - Factor: threat intel outdated (get_feed_status, check last_updated age)
  - Factor: SLM not active (get_slm_status, check loaded)
  - Factor: FDA not granted (run_doctor or get_system_info)
  - Factor: unresolved alerts (get_recent_events, filter critical/high)
- [ ] Protection score hero section using `PROTECTION_SCORE_LEVELS` and `PROTECTION_SCORE_EXPLAINER`
- [ ] Today's stats row (events, blocked, servers, guards) using shared `StatCard`
- [ ] "Recent from Claw" section: last 5 human-readable messages (use notification templates from messages.ts)
- [ ] Pending actions section: pending prompts + unresolved alerts
- [ ] Server overview grid (compact, links to /tools/:name)
- [ ] Empty state using `EMPTY_STATES.dashboard`
- [ ] "Start Daemon" CTA when daemon not running (using `ERROR_MESSAGES.daemonNotRunning`)
- [ ] SLM mock mode warning banner

**Commands needed**: `get_daemon_status`, `get_recent_events`, `list_guards`, `detect_mcp_clients`, `list_mcp_servers`, `get_feed_status`, `get_slm_status`, `get_blocklist_matches`, `start_daemon`
**Events**: `clawdefender://event`, `clawdefender://status-change`, `clawdefender://prompt`
**Dependencies**: Navigation shell (Agent 2), shared components (Agent 7)
**Blocked by**: Agent 2 (routing)

---

### Agent 4: Activity Feed
**Scope**: Merge Timeline + AuditLog into unified Activity page

**Tasks**:
- [ ] Create new `Activity.tsx` page
- [ ] Implement unified event list with virtualized scrolling (from Timeline)
- [ ] Add list/table view toggle (list = Timeline style, table = AuditLog style)
- [ ] Merge filter bars: search, server dropdown, decision toggle, risk level dropdown, "only blocks" checkbox
- [ ] Implement sort controls (from AuditLog: timestamp, server, tool, resource, action, risk)
- [ ] Reuse shared `EventDetailPanel` component (from Timeline, with SLM analysis)
- [ ] Add date separators between event groups
- [ ] Add event count display (filtered / total)
- [ ] Live indicator with auto-scroll
- [ ] Support navigation state: `filterMessage` (from NotificationLayer)
- [ ] Empty states: `EMPTY_STATES.activity` and `EMPTY_STATES.searchResults`
- [ ] Sub-route `/activity/:eventId` for deep-linking to event detail

**Commands needed**: `get_recent_events`
**Events**: `clawdefender://event`
**Dependencies**: Navigation shell (Agent 2), shared components (Agent 7)
**Blocked by**: Agent 2 (routing)

---

### Agent 5: Alerts Page
**Scope**: Build alerts with threat stories, recommendations, resolution flow

**Tasks**:
- [ ] Create new `Alerts.tsx` page
- [ ] Aggregate alerts from multiple sources:
  - High/critical risk events (from `get_recent_events`)
  - Blocklist matches (from `get_blocklist_matches`)
  - Network blocked connections (from `get_network_connections`, filter blocked)
  - Kill chain detections (from events with kill_chain field)
  - Scan findings (critical/high from last scan result)
- [ ] Alert card component using notification templates from `NOTIFICATION_TEMPLATES`
  - One-liner (glance level)
  - Expanded description (summary level)
  - Educational context (full detail level)
- [ ] Threat story visualization for kill chain patterns
- [ ] Action buttons per alert: Review, Dismiss, Block Server, View in Activity
- [ ] Unresolved count for sidebar badge
- [ ] Network sub-section with summary stats (allowed/blocked/prompted)
- [ ] Connection detail panel (from NetworkLog) for network alerts
- [ ] Export functionality (from NetworkLog's `export_network_log`)
- [ ] Empty state using `EMPTY_STATES.alerts`
- [ ] Sub-route `/alerts/:alertId` for deep-linking

**Commands needed**: `get_recent_events`, `get_blocklist_matches`, `get_network_connections`, `get_network_summary`, `export_network_log`
**Dependencies**: Navigation shell (Agent 2), shared components (Agent 7)
**Blocked by**: Agent 2 (routing)

---

### Agent 6: Settings Redesign
**Scope**: Simple/advanced mode, relocated sub-pages

**Tasks**:
- [ ] Create new `Settings.tsx` with simple/advanced mode toggle
- [ ] **Simple mode** (visible by default):
  - Daemon control (start/stop, autostart)
  - Security level quick-switch (from SecurityLevelChooser)
  - Auto-block toggle + threshold (from Behavioral)
  - Telemetry toggle (from ThreatIntel)
  - AI model status (loaded/not loaded, link to models sub-page)
  - Notification preferences (sound, minimize to tray)
- [ ] **Advanced mode** (toggle reveals):
  - Sub-page: `/settings/policy` -- PolicyEditor (full rule CRUD, templates)
  - Sub-page: `/settings/health` -- SystemHealth (diagnostics, system info)
  - Sub-page: `/settings/threat-intel` -- ThreatIntel (feed, rule packs, IoC stats)
  - Sub-page: `/settings/network` -- Network protection (extension, domain lists)
  - Sub-page: `/settings/models` -- Full AI model management (catalog, download, switch, cloud providers)
  - Scanner trigger section
  - Danger zone (reset config, clear data, export config)
  - Log level, config paths
- [ ] Navigation within Settings: sub-nav tabs or sidebar within the page
- [ ] Decompose current 1600-line Settings.tsx into sub-components:
  - `SettingsSimple.tsx`
  - `SettingsPolicy.tsx` (absorbs PolicyEditor)
  - `SettingsHealth.tsx` (absorbs SystemHealth)
  - `SettingsThreatIntel.tsx` (absorbs ThreatIntel)
  - `SettingsNetwork.tsx`
  - `SettingsModels.tsx`
  - `SettingsDangerZone.tsx`
- [ ] Handle scrollTo navigation state from Home "Enable in Settings" link
- [ ] Handle highlightServer/highlightAction from NotificationLayer

**Commands needed**: All Settings + PolicyEditor + SystemHealth + ThreatIntel commands (see migration map section 7)
**Dependencies**: Navigation shell (Agent 2), shared components (Agent 7)
**Blocked by**: Agent 2 (routing)

---

### Agent 7: Component Migration & Cleanup
**Scope**: Extract shared components, consolidate stores, fix known issues

**Tasks**:
- [ ] Extract shared utilities (see migration map section 8):
  - `src/utils/serverColor.ts` (serverColors + getServerColor)
  - `src/utils/normalize.ts` (normalizeDecision + normalizeRiskLevel)
  - `src/utils/formatTime.ts` (formatTime / formatTimestamp)
  - `src/utils/formatBytes.ts` (formatBytes)
  - `src/utils/truncateResource.ts` (truncateResource)
- [ ] Extract shared components:
  - `src/components/shared/DecisionBadge.tsx` (consolidate 5 implementations)
  - `src/components/shared/RiskBadge.tsx` (consolidate 2 implementations)
  - `src/components/shared/EventDetailPanel.tsx` (from Timeline, with SLM analysis)
  - `src/components/shared/StatCard.tsx` (from Dashboard)
  - `src/components/shared/EmptyState.tsx` (generic, uses EMPTY_STATES constants)
- [ ] Fix AutoBlockToast: remove raw anomaly score display, use threat level label instead
- [ ] Update Onboarding to use messages.ts constants (ONBOARDING_WELCOME, ONBOARDING_SCAN_RESULTS, etc.)
- [ ] Update NotificationLayer navigation targets to new routes
- [ ] Delete removed pages after migration is complete:
  - `src/pages/Dashboard.tsx` (replaced by Home)
  - `src/pages/Timeline.tsx` (merged into Activity)
  - `src/pages/AuditLog.tsx` (merged into Activity)
  - `src/pages/Behavioral.tsx` (merged into My Tools)
  - `src/pages/Guards.tsx` (merged into My Tools)
  - `src/pages/SystemHealth.tsx` (merged into Settings)
  - `src/pages/ThreatIntel.tsx` (merged into Settings)
  - `src/pages/NetworkLog.tsx` (merged into Alerts)
  - `src/pages/PolicyEditor.tsx` (merged into Settings)
  - `src/pages/Scanner.tsx` (split into Alerts + Settings)
- [ ] Clean up unused imports and types after migration

**Dependencies**: All page agents (3-6) should be mostly done before deletion
**Blocked by**: None for extraction; Agents 3-6 for deletion

---

### Agent 8: QA
**Scope**: Verify build, migration completeness, navigation, all pages, design compliance, performance

**Tasks**:
- [ ] Verify TypeScript build passes with zero errors
- [ ] Verify all 6 new pages render without crashes
- [ ] Verify all old routes redirect correctly (9 redirects)
- [ ] Verify all Tauri commands are still called (none lost in migration)
- [ ] Verify all Tauri events are still listened to (5 events)
- [ ] Verify sidebar badge counts update correctly
- [ ] Verify page transitions work (150ms crossfade)
- [ ] Verify keyboard shortcuts (Cmd+K, Cmd+1-6, Escape)
- [ ] Verify empty states show correct copy from messages.ts
- [ ] Verify no raw anomaly scores are shown to user
- [ ] Verify design system compliance: colors use CSS variables, typography follows scale, animations are 150-200ms
- [ ] Verify NotificationLayer works with new routes
- [ ] Verify PromptWindow still functions (prompt queue, keyboard shortcuts, timer)
- [ ] Verify Onboarding flow completes and redirects to new Home
- [ ] Performance: check no regressions in Activity page virtualization
- [ ] Performance: check Settings page load time (was 1600 lines, now decomposed)

**Dependencies**: All agents (2-7) complete
**Blocked by**: Agents 2-7

---

### Agent 9: Accessibility & Polish
**Scope**: Keyboard nav, screen reader, contrast, responsive, animations, error states

**Tasks**:
- [ ] Verify all interactive elements are keyboard-accessible (tab order, focus indicators)
- [ ] Verify all pages have correct ARIA landmarks (nav, main, aside)
- [ ] Verify all images/icons have alt text or aria-hidden
- [ ] Verify all form controls have labels (visible or sr-only)
- [ ] Verify color contrast meets WCAG AA (4.5:1 for text, 3:1 for large text)
- [ ] Verify screen reader announces page transitions
- [ ] Verify live regions for real-time updates (role="log", aria-live)
- [ ] Verify focus management: modals trap focus, return focus on close
- [ ] Verify responsive layout: sidebar collapses at narrow widths
- [ ] Verify error states: all API failures show user-friendly messages from ERROR_MESSAGES
- [ ] Verify loading states: skeleton screens or spinners for all async operations
- [ ] Verify reduced motion preference: disable animations when prefers-reduced-motion
- [ ] Polish: consistent spacing using design system scale
- [ ] Polish: hover states on all clickable elements
- [ ] Polish: transition timing consistency (150ms for interactions, 200ms for layout)

**Dependencies**: All agents (2-7) complete
**Blocked by**: Agents 2-7

---

## Execution Order

```
Agent 1 (done) ----+
                   |
                   v
              Agent 2 (Navigation Shell) ----+----> Agent 7 (shared components, in parallel)
                   |                         |
                   v                         v
            +------+-------+          Agent 7 extraction
            |      |       |          (utilities + components)
            v      v       v
         Agent 3  Agent 4  Agent 5  Agent 6
         (Home)   (Activity)(Alerts)(Settings)
            |      |       |       |
            +------+-------+-------+
                   |
                   v
              Agent 7 (cleanup + deletion)
                   |
                   v
            +------+------+
            |             |
            v             v
         Agent 8       Agent 9
         (QA)          (A11y)
```

**Critical path**: Agent 1 -> Agent 2 -> Agents 3-6 (parallel) -> Agent 7 cleanup -> Agents 8-9 (parallel)

**Agent 7 runs in two phases**:
1. **Phase 1** (parallel with Agents 3-6): Extract shared utilities and components. Other agents import from these.
2. **Phase 2** (after Agents 3-6): Delete old pages, clean up unused code.
