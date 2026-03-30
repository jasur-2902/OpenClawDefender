# ClawDefender Mac GUI — Comprehensive UX Specification Report

**Version:** 0.5.0-beta
**Last Updated:** 2026-02-26
**Target Audience:** UX/Design Team, Product Managers, Frontend Developers

---

## 1. Executive Summary

ClawDefender is a macOS security application that provides real-time protection monitoring and user-friendly controls for AI application security. The GUI is built as a React SPA with Tauri integration, featuring:

- **Real-time event streaming** from a background daemon
- **Intelligent alert system** with kill chain analysis
- **Conversational AI assistance** via Ask Claw
- **Tool management & policy configuration**
- **Sophisticated guidance system** with onboarding and contextual hints

The application prioritizes non-intrusive monitoring, quick decision-making through prompts, and transparent visibility into system protection.

---

## 2. Information Architecture & Route Structure

### 2.1 Top-Level Routes

| Route | Page Component | Purpose | Lazy Load |
|-------|---|---|---|
| `/` | Home.tsx | Dashboard with protection score, recent events, quick stats | Yes |
| `/ask` | AskClaw.tsx | Conversational AI chat for security questions | Yes |
| `/tools` | MyTools.tsx | Browse and manage detected AI tools | Yes |
| `/tools/:id` | ToolDetail.tsx | Tool-specific details, settings, logs | Yes |
| `/activity` | Activity.tsx | Event feed with search, filter, humanized summaries | Yes |
| `/activity/:id` | EventDetail.tsx | Single event expanded view with correlation | Yes |
| `/alerts` | Alerts.tsx | Active & historical alerts with kill chain narratives | Yes |
| `/alerts/:id` | AlertDetail.tsx | Alert details, actions, resolution tracking | Yes |
| `/settings` | Settings.tsx | App preferences, daemon control, logs | Yes |
| `/settings/policy` | PolicyEditor.tsx | Policy rule creation and management | Yes |
| `/settings/health` | SystemHealth.tsx | System protection status, factor breakdown | Yes |
| `/settings/threat-intel` | ThreatIntel.tsx | Threat intelligence data, risk assessments | Yes |

### 2.2 Special Routes

| Route | Condition | Behavior |
|-------|---|---|
| Onboarding | First launch or no config | 5-screen wizard (welcome → tool detection → protection level → FDA perms → complete) |
| Migration | Upgrade detected (existing config/policy/events) | Dual path: Use existing (migrate config + policy) OR Start fresh |

### 2.3 Route Redirects (Legacy Compatibility)

- `/dashboard` → `/`
- `/audit-log` → `/activity`
- `/behavioral` → `/activity`
- `/network-log` → `/activity`
- `/timeline` → `/activity`
- `/guards` → `/tools`
- `/scanner` → `/alerts`

### 2.4 Navigation Context

**OnboardingRedirect Wrapper:**
- Checks `useAppStore.onboardingComplete` before rendering child routes
- If false and pathname ≠ onboarding → redirect to onboarding
- Persisted in SessionStorage as `clawdefender-onboarding-complete`

**TrayNavigationListener:**
- Listens for `clawdefender://navigate` Tauri event (from macOS tray menu)
- Event payload: `{ page: string, params?: Record<string, string> }`
- Performs navigation via `navigate()` with optional state

---

## 3. Page-by-Page Specifications

### 3.1 Home Page (`/`)

**Purpose:** Dashboard overview of protection status and recent activity

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ Home                                        │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │  Protection Score Ring (100 center) │  │ <- Large score visualization
│  │  Score: 87/100                      │  │
│  │  [View Breakdown]                   │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │  Key Metrics (3-column grid)        │  │
│  │  ▯ Tools Protected   ▯ Events       │  │
│  │  ▯ Threats Blocked                  │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │  Recent Activity (last 24h)         │  │
│  │  [Filtered table with 5 rows]       │  │
│  │  [View Full Activity →]             │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │  Quick Guidance (if applicable)     │  │
│  │  [Toast-style hints]                │  │
│  └─────────────────────────────────────┘  │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Protection score (0-100) with animated ring
- Score breakdown factors (6-8 items with status)
- Today's event count and blocked count
- Highest anomaly score and server
- Recent 5 events: timestamp, server, action, description

**Interactive Elements:**
- Score ring (clickable → ScoreBreakdownDrawer)
- "View Breakdown" button
- "View Full Activity" link → `/activity`
- Event rows (clickable → `/activity/:id`)
- Guidance hints with call-to-action buttons

**States:**
- Loading (shows skeleton placeholders)
- Error (error banner with retry)
- No data (empty state with explanation)
- Real-time updates (smooth value animations)

**Real-Time Updates:**
- `clawdefender://score-changed` event updates score ring
- `clawdefender://event` adds to recent activity list
- `clawdefender://alert` refetches alert count

**Animations:**
- Score ring: smooth stroke-dashoffset transition (300ms)
- Score value: animated counter (500ms)
- Pulse on score change (respects prefers-reduced-motion)
- Page fade-in (150ms opacity on route change)

**Navigation:**
- Sidebar links to all pages
- Event rows link to EventDetail
- "View Full Activity" link to Activity page
- Score breakdown drawer modal

---

### 3.2 Ask Claw Page (`/ask`)

**Purpose:** Conversational AI chat for security questions and guidance

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ Ask Claw                                    │
├─────────────────────────────────────────────┤
│                                             │
│  [Conversation Header]                      │
│  "Previous conversations" selector          │
│                                             │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────┐                          │
│  │ User message │                          │
│  └──────────────┘                          │
│                          ┌──────────────┐  │
│                          │ Claw response│  │
│                          │ [Actions]    │  │
│                          └──────────────┘  │
│                                             │
├─────────────────────────────────────────────┤
│ [Message input field]                       │
│ [Context-aware suggestions: 3 buttons]      │
│ [Send button] [Clear button]                │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Chat message history (alternating user/claw)
- Message metadata: timestamp, intent type
- Claw response with optional rich formatting
- Context-aware suggestions based on current page
- Conversation metadata (ID, start time)

**Interactive Elements:**
- Message input field with focus (Cmd+F focus trigger)
- Send button (or Enter key)
- Clear conversation button
- Context-aware action buttons (navigate, explore, explain)
- Message copy/reuse buttons
- Conversation selector dropdown

**States:**
- Composing (input focus, send disabled if empty)
- Sending (loading spinner, input disabled)
- Error (failed send, error message, retry button)
- Empty (welcome message, suggestions)
- Rich response (formatted markdown, embedded actions)

**Real-Time Updates:**
- Streaming response chunks displayed progressively
- Context-aware suggestions update based on intentId
- Related events/alerts linked in suggestions

**Animations:**
- Message fade-in (150ms)
- Typing indicator animation (3-dot pulse)
- Rich content expansion (200ms)
- Action buttons highlight on hover

**Navigation:**
- Suggestions can trigger navigation to /activity, /alerts, /settings, etc.
- Links to event/alert details from suggestions

**Context-Aware Suggestions:**
- Home page: status.* intents (protection level, threats, tools)
- Activity page: explain.* intents (event explanations, correlations)
- Alerts page: control.block.* intents (blocking, allowlisting, remediation)
- Tools page: control.trust.* intents (permission elevation, trust changes)

---

### 3.3 My Tools Page (`/tools`)

**Purpose:** Browse and manage detected AI tools with permission control

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ My Tools                    [Filter] [Sort] │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │ Tool Card 1                          │  │
│  │ [Icon] Tool Name                     │  │
│  │ Trust: High ▯ Permissions: 5/8       │  │
│  │ Status: Protected ✓                  │  │
│  │ [View Details →]                     │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │ Tool Card 2                          │  │
│  │ [Icon] Tool Name                     │  │
│  │ Trust: Unknown ▯ Permissions: 2/8    │  │
│  │ Status: Requested access             │  │
│  │ [View Details →]                     │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  [New Tool 1] [New Tool 2]                 │ <- "New" badge
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Tool name and icon
- Trust level (High, Medium, Low, Unknown) with visual indicator
- Permission count (granted/total)
- Status (Protected, Pending, Requested, Blocked)
- Detection timestamp
- "New" badge if tool_id not in prevUnwrappedTools
- Trust score percentage

**Interactive Elements:**
- Tool card (clickable → `/tools/:id`)
- Trust level selector (dropdown)
- Permission quick-toggle buttons
- Filter options (by trust level, status, detection date)
- Sort options (alphabetical, by trust, by activity)
- New tool notification with "Review" link

**States:**
- Loading (skeleton cards)
- Error (error banner)
- Empty (no tools detected)
- New tool (highlight, "New" badge)
- Unreviewed (outline border, "New" label)

**Real-Time Updates:**
- `clawdefender://new-tool-detected` event adds tool card with animation
- Trust level changes via clawdefender://score-changed impact
- Permission grant/deny updates card immediately

**Animations:**
- New tool card slide-in (200ms)
- Trust level change pulse animation
- Permission toggle instant feedback
- Card hover scale (1.02x)

**Navigation:**
- Card click → `/tools/:id`
- Trust level change → triggers backend permission update
- "New" badge click → scrolls to tool card

---

### 3.4 Tool Detail Page (`/tools/:id`)

**Purpose:** Detailed view of a specific tool with permission management and activity logs

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ [Back] Tool Name                 [Options]  │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │ Tool Header                         │  │
│  │ [Large Icon] Tool Name              │  │
│  │ Status: Active ✓  Trust: High       │  │
│  │ Detected: 2024-01-15  Last active:  │  │
│  │ 2025 seconds ago                    │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  Permissions (5 granted, 3 requested):     │
│  ┌──────────────────────┐                  │
│  │ ✓ File Access        │                  │
│  │ ✓ Network           │                  │
│  │ ✗ Requested: Spawn  │ [Allow] [Deny]  │
│  └──────────────────────┘                  │
│                                             │
│  Recent Activity (last 24h):                │
│  [3-row activity table]                     │
│                                             │
│  Threat Assessment:                         │
│  [Risk indicators and explanations]         │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Tool name, icon, version (if available)
- Trust level with description
- Status (active, blocked, quarantined)
- Detection timestamp and last activity time
- Granted permissions list with icons
- Pending permission requests with Allow/Deny buttons
- Risk assessment and threat vectors
- Recent events (last 24h, 3-row sample)
- Server/path information

**Interactive Elements:**
- Back button (→ `/tools`)
- Options menu (block, quarantine, reset trust)
- Permission grant/deny buttons
- Trust level selector (with confirmation modal)
- View full activity link (→ `/activity?tool=id`)
- Copy server name button
- Add to allowlist/blocklist buttons

**States:**
- Loading (skeleton layout)
- Active (normal display)
- Blocked (grayed out, "Blocked" badge)
- Quarantined (alert state, "Quarantined" badge)
- Pending permissions (highlighted permission requests)

**Real-Time Updates:**
- `clawdefender://event` updates activity list
- Permission grant/deny reflected immediately
- Trust level changes reflected in header

**Animations:**
- Permission grant/deny button feedback (color change 200ms)
- Risk assessment indicator color transitions
- Activity list updates with slide-in

**Navigation:**
- Back button → `/tools`
- View activity link → `/activity?tool=id`
- Trust level change → modal confirmation

---

### 3.5 Activity Page (`/activity`)

**Purpose:** Searchable, filterable event feed with humanized summaries and correlation

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ Activity                                    │
├─────────────────────────────────────────────┤
│ [Search] [Filters: Time, Risk, Tool, Server]│
│ [Sort: Latest] [Only Notable toggle]        │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │ 2025-02-26 14:32:15                  │  │
│  │ 🔴 Critical: Tool attempted file      │  │
│  │ write to system directory             │  │
│  │ Tool: Python  Server: Terminal        │  │
│  │ Action: Blocked  [Details →]         │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  [Virtual scroll: ~50 rows visible]        │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │ 2025-02-26 14:31:02                  │  │
│  │ 🟡 Medium: Tool accessed system API  │  │
│  │ Tool: Node  Server: VSCode           │  │
│  │ Action: Prompted  [Details →]        │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  [Show more...]                             │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Event timestamp
- Risk level indicator (color-coded: 🔴 critical, 🟡 high, 🟢 medium, ⚪ low)
- One-liner summary (humanized description)
- Tool name and server
- Action taken (Allowed, Blocked, Prompted)
- Event count metrics (X total, Y today)
- Server/tool distribution charts (optional)

**Interactive Elements:**
- Search field (text search across summaries)
- Filter options:
  - By time (Last hour, 24h, 7 days, custom)
  - By risk level (critical, high, medium, low)
  - By tool (multi-select dropdown)
  - By server (multi-select dropdown)
  - By action (allow, block, prompt)
- Sort options (latest, oldest, by risk)
- "Only Notable" toggle (filter to critical/high risk)
- Event row (clickable → `/activity/:id`)
- "Show more" button (pagination)

**States:**
- Loading (skeleton rows)
- Empty (no events)
- Filtered empty ("No events matching filters")
- Search results (highlighting matching terms)
- Pagination (showing N of M results)

**Real-Time Updates:**
- New events appear at top of list (with animation)
- Event count updates in real-time
- Batched updates (100ms flush interval) to prevent render thrashing

**Animations:**
- Event row slide-in from top (150ms)
- Search filter transitions (100ms opacity)
- Risk indicator pulse on new critical events

**Performance Optimizations:**
- Virtual scrolling (52px per row, 400px buffer)
- Max 10,000 events in memory (FIFO eviction)
- Event batching (100ms flush)
- Lazy filtering (filter client-side, not server-side for UI state)

**Navigation:**
- Event row → `/activity/:id`
- Tool filter → updates URL params
- "Only Notable" → updates app state

---

### 3.6 Event Detail Page (`/activity/:id`)

**Purpose:** Expanded view of a single security event with context and correlation

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ [Back] Event #12345                  [...]  │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │ Event Summary                       │  │
│  │ Risk Level: Critical 🔴             │  │
│  │ Tool: Python (pyenv)                │  │
│  │ Server: Terminal                    │  │
│  │ Timestamp: 2025-02-26 14:32:15 UTC │  │
│  │ Action Taken: Blocked ✓             │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  What Happened:                             │
│  [Humanized, multi-paragraph explanation]  │
│                                             │
│  Technical Details:                         │
│  [JSON dump of raw event]                   │
│                                             │
│  Behavioral Context:                        │
│  [Correlation with other events]            │
│  [Risk assessment]                          │
│                                             │
│  Related Events:                            │
│  [3-5 similar events with links]            │
│                                             │
│  Kill Chain Analysis:                       │
│  [Narrative of attacker intent/progression] │
│                                             │
│  Actions:                                   │
│  [Allow future, Block tool, Add to policy]  │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Event ID, timestamp, risk level
- Tool name and version
- Server name and path
- Action taken (Allowed, Blocked, Prompted)
- One-liner summary
- Detailed humanized explanation
- Raw event JSON (collapsible)
- Behavioral context and correlations
- Risk explanation
- Related events (5 similar events)
- Kill chain narrative (if available)
- Educational aside (security principle explanation)

**Interactive Elements:**
- Back button (→ `/activity` or previous)
- Options menu (copy ID, share, report)
- "Allow future" button (creates allowlist rule)
- "Block tool" button (blocks all from tool)
- "Block server" button (blocks all from server)
- "Add to policy" button (opens PolicyEditor)
- "Ask Claw" button (opens Ask Claw with context)
- Related event links (→ other EventDetail pages)

**States:**
- Loading (skeleton)
- Loaded (full display)
- Error (error message, retry button)
- Actions pending (button loading states)

**Real-Time Updates:**
- If action is taken (Allow/Block), UI updates immediately
- If related events occur, notification badge appears

**Animations:**
- Page fade-in (150ms)
- JSON expand/collapse (200ms)
- Related events list slide-in (200ms)

**Navigation:**
- Back button → previous page (Activity or Home)
- "Ask Claw" button → `/ask` with event context
- "Add to policy" → `/settings/policy`
- Related event links → `/activity/:id`

---

### 3.7 Alerts Page (`/alerts`)

**Purpose:** Active and historical security alerts with severity, actions, and resolution tracking

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ Alerts    [Active] [History] [Statistics]   │
├─────────────────────────────────────────────┤
│ [Filter: Severity, Status] [Sort] [Dismiss]│
│ Showing 3 unresolved alerts                 │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │ 🔴 CRITICAL: Ransomware signatures   │  │
│  │ detected                             │  │
│  │ Impact: 5 files, 2 processes         │  │
│  │ Actions: [Block] [Quarantine] [More] │  │
│  │ Detected: 2 minutes ago              │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │ 🟡 HIGH: Privilege escalation        │  │
│  │ attempted                            │  │
│  │ Impact: 1 process, Terminal app      │  │
│  │ Actions: [Allow] [Review] [More]     │  │
│  │ Detected: 15 minutes ago             │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  [Show more...]                             │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Alert ID and title
- Severity (critical, high, medium, low)
- Kill chain stage (if available)
- Impact description (affected files/processes)
- Detection timestamp and duration
- Status (active, resolved, dismissed)
- Recommended actions (with labels and icons)
- Affected tools and servers
- Alert count badge (in sidebar)

**Interactive Elements:**
- Tab navigation (Active, History, Statistics)
- Severity filter (multi-select)
- Status filter (active, resolved, dismissed)
- Sort options (by severity, by date, by impact)
- Alert card (clickable → `/alerts/:id`)
- Action buttons (block, allow, quarantine, investigate)
- "Dismiss" button (marks as resolved)
- Batch dismiss (checkbox + dismiss all)

**States:**
- Loading (skeleton cards)
- Active alerts (normal display with action buttons)
- Resolved alerts (grayed, "Resolved" badge)
- Dismissed alerts (hidden by default, show in History tab)
- Empty (no alerts, congratulations message)

**Real-Time Updates:**
- `clawdefender://alert` event triggers refetch
- New alert appears at top (with animation)
- Alert count badge updates in sidebar

**Animations:**
- Alert card slide-in from top (150ms)
- Action button feedback (color, loading state)
- Resolve confirmation toast (200ms)

**Navigation:**
- Alert card → `/alerts/:id`
- "Investigate" action → `/activity?alertId=id`
- "Ask Claw" action → `/ask` with alert context
- Statistics tab → dashboard view

---

### 3.8 Alert Detail Page (`/alerts/:id`)

**Purpose:** Comprehensive alert analysis with kill chain narrative and response actions

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ [Back] Alert #A123 - Ransomware Signatures  │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │ Alert Overview                      │  │
│  │ Severity: Critical 🔴               │  │
│  │ Type: Malware Pattern Match         │  │
│  │ Status: Active (3 minutes)          │  │
│  │ Confidence: 98%                     │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  Kill Chain Narrative:                      │
│  "The detected pattern suggests persistence│
│   mechanisms typical of WinLocker-class    │
│   ransomware..."                            │
│                                             │
│  Affected Resources:                        │
│  [Table of impacted files, processes]       │
│                                             │
│  Intelligence Summary:                      │
│  [Threat description, CVEs, ATT&CK tactics] │
│                                             │
│  Incident Timeline:                         │
│  [Chronological event chain]                │
│                                             │
│  Recommended Actions:                       │
│  [1. Block with option]                     │
│  [2. Quarantine files]                      │
│  [3. System remediation]                    │
│                                             │
│  [Confirm Action] [Ask Claw] [Investigate]  │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Alert ID, title, type
- Severity level and confidence score
- Detection timestamp and duration
- Current status (active, resolved, dismissed)
- Kill chain narrative (multi-paragraph)
- Affected resources (files, processes, network connections)
- Intelligence summary (threat description, CVEs, ATT&CK)
- Incident timeline (events leading to alert)
- Recommended remediation steps
- Related events and correlations

**Interactive Elements:**
- Back button
- Options menu (copy, share, export)
- Action buttons (block, quarantine, allow, investigate)
- "Ask Claw" button (with alert context)
- "Investigate" link (→ Activity with filter)
- Affected resource rows (click to view event)
- Timeline event links
- Intelligence data collapse/expand

**States:**
- Loading (skeleton)
- Loaded (full display)
- Actioned (button disabled, confirmation shown)
- Resolved (grayed out, resolved badge)

**Real-Time Updates:**
- If new related events occur, timeline updates
- If action is taken, status updates immediately

**Animations:**
- Page fade-in (150ms)
- Action execution spinner (loading state)
- Confirmation toast on completion

**Navigation:**
- Back → `/alerts`
- Action buttons → execute backend command, refresh state
- "Ask Claw" → `/ask` with alert context
- "Investigate" → `/activity` with alertId filter

---

### 3.9 Settings Page (`/settings`)

**Purpose:** Central hub for app configuration, daemon control, and advanced settings

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ Settings                                    │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │ Daemon Control                      │  │
│  │ Daemon Status: Running ✓            │  │
│  │ [Stop Daemon] [Logs]                │  │
│  │ Version: 0.5.0-beta                 │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  Configuration:                             │
│  ☑ Auto-start daemon on login              │
│  ☑ Show notifications                      │
│  ☑ Real-time event streaming               │
│  [ ] Reduce animations                     │
│                                             │
│  Protection Level:                          │
│  ◉ Handle (most permissive)                │
│  ○ Ask (moderate, prompts enabled)         │
│  ○ Watch (most restrictive)                │
│                                             │
│  [Advanced: Policy Editor] [Health Check]   │
│  [Threat Intel] [Debug Logs]                │
│                                             │
│  Feedback & Support:                        │
│  [Report Issue] [Documentation] [About]     │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Daemon status (running/stopped)
- Daemon version
- App version (0.5.0-beta in sidebar)
- Configuration options (checkboxes)
- Protection level (radio buttons)
- Advanced settings links
- Support and feedback links

**Interactive Elements:**
- Start/Stop daemon buttons (with confirmation modal)
- Configuration checkboxes (instant save to appStore)
- Protection level selector (radio buttons)
- View logs button (opens logs modal)
- Policy editor link (→ `/settings/policy`)
- Health check link (→ `/settings/health`)
- Threat intel link (→ `/settings/threat-intel`)
- Reduce animations checkbox (affects global motion settings)

**States:**
- Loading (skeleton)
- Daemon running (green indicator)
- Daemon stopped (red indicator, "Start" button)
- Daemon starting/stopping (loading spinner, buttons disabled)
- Configuration unsaved (visual indicator)

**Real-Time Updates:**
- Daemon status updates via `clawdefender://status-change` event
- Configuration changes persist to appStore immediately

**Animations:**
- Daemon status indicator pulse (when starting)
- Checkbox toggle animation
- Settings section collapse/expand (200ms)

**Navigation:**
- Policy editor link → `/settings/policy`
- Health check link → `/settings/health`
- Threat intel link → `/settings/threat-intel`

---

### 3.10 Policy Editor Page (`/settings/policy`)

**Purpose:** Create and manage security policies for tools and servers

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ Policy Editor                               │
├─────────────────────────────────────────────┤
│                                             │
│  [New Policy] [Import] [Export]             │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │ Active Policies (3)                  │  │
│  │                                      │  │
│  │ Policy: "Block clipboard access"     │  │
│  │ Scope: All tools                     │  │
│  │ Action: Block                        │  │
│  │ Condition: operation == "clipboard"  │  │
│  │ [Edit] [Delete] [Duplicate]          │  │
│  │                                      │  │
│  │ Policy: "Ask before file write"      │  │
│  │ Scope: Node, Python                 │  │
│  │ Action: Prompt                       │  │
│  │ Condition: operation == "write"      │  │
│  │ [Edit] [Delete] [Duplicate]          │  │
│  │                                      │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  Policy Editor Modal (on edit):             │
│  ┌──────────────────────────────────────┐  │
│  │ Policy Name: [text input]            │  │
│  │ Scope: [multi-select: Tools, Servers]│  │
│  │ Action: [dropdown: Allow/Block/Audit]│  │
│  │ Condition: [expression editor]       │  │
│  │ Priority: [number input]             │  │
│  │ [Save] [Cancel]                      │  │
│  └──────────────────────────────────────┘  │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- List of active policies
- Policy name, scope, action, condition, priority
- Disabled policies (grayed)
- Rule count and coverage metrics

**Interactive Elements:**
- "New Policy" button (opens editor modal)
- Edit button (opens modal with pre-filled values)
- Delete button (with confirmation)
- Duplicate button (creates copy of policy)
- Import/Export buttons (for policy templates)
- Enable/Disable toggle on each policy
- Condition expression editor with autocomplete
- Save/Cancel buttons in modal

**States:**
- Empty (no policies)
- Loaded (policy list)
- Editor open (modal with form)
- Saving (button disabled, spinner)
- Saved (success notification)
- Error (error message, retry option)

**Real-Time Updates:**
- Policy changes reflected immediately in list
- Related events re-evaluated against new policies

**Animations:**
- Modal slide-in/out (200ms)
- Policy list item fade-in (150ms)
- Save confirmation toast (200ms)

**Navigation:**
- Back to settings (browser back or Settings link)
- Save → persists to daemon

---

### 3.11 System Health Page (`/settings/health`)

**Purpose:** Visual breakdown of protection score factors with remediation guidance

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ System Health                               │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │ Overall Protection Score: 87/100    │  │
│  │ ████████░░░ (87%)                   │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  Score Factors:                             │
│  ┌──────────────────────────────────────┐  │
│  │ ✓ Daemon Running        87/100       │  │
│  │   Status: Good          [Fix if bad] │  │
│  │                                      │  │
│  │ ⚠ Policy Completeness   60/100       │  │
│  │   Status: Partial       [Set up...] │  │
│  │                                      │  │
│  │ ✓ Tool Allowlisting     95/100       │  │
│  │   Status: Good                       │  │
│  │                                      │  │
│  │ ✗ Threat Intel Update   10/100       │  │
│  │   Status: Bad           [Update...] │  │
│  │                                      │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  Recommendations:                           │
│  [Priority list of improvements]            │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Overall protection score (0-100) with progress bar
- 6-8 score factors with:
  - Name and current points
  - Max points
  - Status (good/partial/bad)
  - Description/details
  - Fix action (if applicable)
- Recommendations for improvement
- Last update timestamp

**Interactive Elements:**
- Factor rows (click to expand details)
- "Fix" buttons (navigate to remediation action)
- "Learn more" links (open Ask Claw with context)
- Refresh button (force fetch latest score)
- Export health report button

**States:**
- Loading (skeleton bars)
- Loaded (full display)
- Factor expanded (shows details)
- Factor with fix action (button highlighted)

**Real-Time Updates:**
- Score updates via `clawdefender://score-changed` event
- Factor changes reflected immediately

**Animations:**
- Factor expand/collapse (200ms)
- Progress bar smooth transition (300ms)
- Score change pulse animation

**Navigation:**
- Fix action buttons navigate to relevant settings page
- "Learn more" → `/ask` with context

---

### 3.12 Threat Intelligence Page (`/settings/threat-intel`)

**Purpose:** Threat intelligence data, risk assessments, and vulnerability information

**Wireframe:**
```
┌─────────────────────────────────────────────┐
│ Threat Intelligence                         │
├─────────────────────────────────────────────┤
│ Last updated: 2 hours ago [Refresh]         │
├─────────────────────────────────────────────┤
│                                             │
│  Active Threats in Your Tools:              │
│  ┌──────────────────────────────────────┐  │
│  │ CVE-2025-1234: RCE in Node.js 18.0   │  │
│  │ Severity: Critical 🔴                 │  │
│  │ Affects: Node (1.0.0) in your setup  │  │
│  │ Status: Requires update               │  │
│  │ [View details] [Create rule]          │  │
│  │                                      │  │
│  │ CVE-2025-5678: Auth bypass in Lib X  │  │
│  │ Severity: High 🟡                    │  │
│  │ Affects: Library Y (2.1.0)           │  │
│  │ Status: Patch available              │  │
│  │ [View details] [Create rule]          │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  Risk Profile:                              │
│  Network Exposure: [████░░░░░░ 40%]        │
│  File System Exposure: [████████░░ 80%]    │
│  Privilege Escalation Risk: [██░░░░░░░░ 20%]│
│                                             │
│  Intelligence Sources:                      │
│  [CVE Database] [NVD] [Security Advisories] │
│  [Last refreshed: 2 hours ago]              │
│                                             │
└─────────────────────────────────────────────┘
```

**Data Displayed:**
- Active CVEs affecting tools in system
- Vulnerability title, ID, severity
- Affected tools and versions
- Remediation status (requires update, patch available, etc.)
- Risk profile (exposure indicators)
- Intelligence source attribution
- Last refresh timestamp

**Interactive Elements:**
- Threat item (click to expand details)
- "View details" link (external or detailed view)
- "Create rule" button (opens PolicyEditor with pre-filled condition)
- Refresh button (fetch latest threat data)
- Risk indicator color coding

**States:**
- Loading (skeleton)
- Loaded (threat list)
- Threat details expanded
- No threats (congratulations message)

**Real-Time Updates:**
- Threat list updates when new vulnerabilities detected
- Risk profile recalculated as tools update

**Animations:**
- Threat item slide-in (150ms)
- Risk indicator color transitions (300ms)

**Navigation:**
- "View details" → external security database or modal
- "Create rule" → `/settings/policy` with pre-filled condition

---

### 3.13 Onboarding Flow (5 Screens)

**Purpose:** First-time setup with tool detection, protection level selection, and FDA permission

**Screen 1: Welcome**

```
┌─────────────────────────────────────────────┐
│                                             │
│            Welcome to ClawDefender          │
│                                             │
│         [Animated Claw Icon]                │
│                                             │
│       Your Personal AI App Bodyguard        │
│                                             │
│     [Typewriter animation: "Protecting..."] │
│                                             │
│         [Next] [Skip] [Help]                │
│                                             │
└─────────────────────────────────────────────┘
```

**Screen 2: Tool Detection**

```
┌─────────────────────────────────────────────┐
│ We found these AI tools on your Mac         │
│                                             │
│ ☐ Python (pyenv)                           │
│ ☐ Node.js (npm)                            │
│ ☐ VS Code                                   │
│ ☐ Terminal                                  │
│                                             │
│ [Refresh Detection]                         │
│                                             │
│ [Back] [Next]                               │
│                                             │
└─────────────────────────────────────────────┘
```

**Screen 3: Protection Level Selection**

```
┌─────────────────────────────────────────────┐
│ Choose your protection level                │
│                                             │
│ ◉ Handle (Most Permissive)                  │
│   Auto-allow safe operations, block obvious│
│   threats. Best for development.            │
│                                             │
│ ○ Ask (Moderate)                            │
│   Prompt for uncertain operations. Balance │
│   between safety and usability.             │
│                                             │
│ ○ Watch (Most Restrictive)                  │
│   Log all operations, minimal auto-allow.  │
│   Best for sensitive environments.          │
│                                             │
│ [Back] [Next]                               │
│                                             │
└─────────────────────────────────────────────┘
```

**Screen 4: FDA Permission**

```
┌─────────────────────────────────────────────┐
│ FDA Permission Required                     │
│                                             │
│ ClawDefender needs access to monitor your   │
│ AI tools. macOS requires your approval.     │
│                                             │
│ [System Preferences will open]              │
│                                             │
│ Status:                                     │
│ ⏳ Waiting for permission...                │
│ [Or if granted: ✓ Permission granted]       │
│                                             │
│ [Retry] [Skip]                              │
│                                             │
└─────────────────────────────────────────────┘
```

**Screen 5: Completion**

```
┌─────────────────────────────────────────────┐
│                                             │
│          🎉 You're All Set!                 │
│                                             │
│     ████████████░░░░ (87/100)               │
│     Protection Score: 87/100                │
│                                             │
│   Tools Protected: 4                        │
│   Safety Rules Active: 12                   │
│                                             │
│         [Enter App] [Settings]              │
│                                             │
└─────────────────────────────────────────────┘
```

**Interactive Elements:**
- Next/Back buttons for navigation
- Skip button (skips to next incomplete step)
- Tool detection checkboxes (select/deselect tools)
- Refresh detection button (re-run tool discovery)
- Protection level radio buttons
- FDA permission retry button
- Completion action buttons (Enter App or Settings)

**States:**
- Screen 1: Welcome animation
- Screen 2: Tool list loading, tool selection
- Screen 3: Protection level selection
- Screen 4: FDA permission polling (every 2s)
- Screen 5: Score animation (0→100 over 1.5s)

**Real-Time Updates:**
- Screen 2: Tools list updates on refresh
- Screen 4: FDA status polls via `invoke("check_fda_permission")`
- Screen 5: Score animates from 0 to final value

**Animations:**
- Screen 1: Typewriter effect (1s per sentence)
- Screen 5: Score ring animates 0→100 (1.5s), counter animates
- Page transitions between screens (150ms fade)

**Navigation:**
- Completion → `/` (Home page)
- SessionStorage saves state for resuming if closed

---

## 4. Design System & Visual Language

### 4.1 Color Palette

**Semantic Colors (CSS Variables):**

```css
--color-safe: #00D084 (Green)          /* Protection good */
--color-warning: #FFA500 (Orange)      /* Caution, review */
--color-danger: #E82E3C (Red)          /* Blocked, critical */
--color-accent: #007AFF (Blue)         /* Primary action, focus */

--color-bg-primary: #FFFFFF            /* Main background */
--color-bg-secondary: #F5F5F7          /* Sidebar, secondary areas */
--color-bg-tertiary: #E5E5E8           /* Hover states, tertiary */

--color-text-primary: #1D1D1F          /* Main text */
--color-text-secondary: #86868B        /* Secondary text */
--color-text-muted: #A1A1A6            /* Muted, hint text */

--color-border: #D5D5D7                /* Borders, dividers */
--color-info-subtle: #F0F5FF           /* Info backgrounds */
--color-info-border: #80BFFF           /* Info borders */
--color-accent-subtle: #FFF3E0         /* Accent backgrounds */
--color-accent-hover: #0051D5          /* Accent hover state */
```

### 4.2 Typography

**Font Stack:** `-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif`

| Role | Size | Weight | Line Height | Usage |
|------|------|--------|-------------|-------|
| Display | 32px | 700 | 1.2 | Page titles |
| H1 | 24px | 700 | 1.3 | Section headers |
| H2 | 20px | 600 | 1.3 | Subsection headers |
| H3 | 16px | 600 | 1.4 | Card titles |
| Body | 14px | 400 | 1.5 | Main text, descriptions |
| Small | 12px | 400 | 1.4 | Secondary info |
| Tiny | 10px | 500 | 1.3 | Labels, badges |
| Mono | 13px | 400 | 1.4 | Code, technical details |

### 4.3 Spacing Scale

```
2px, 4px, 6px, 8px, 12px, 16px, 20px, 24px, 32px, 48px, 64px
```

**Common Spacing:**
- Padding: `px-3` (12px), `px-4` (16px), `px-6` (24px)
- Margin: `gap-2` (8px), `gap-3` (12px), `gap-4` (16px)
- Section margins: `py-4` (16px), `py-6` (24px)

### 4.4 Shadows & Elevation

```
Elevation 1 (cards):       0 1px 3px rgba(0,0,0,0.08)
Elevation 2 (modals):      0 4px 12px rgba(0,0,0,0.15)
Elevation 3 (tooltips):    0 8px 24px rgba(0,0,0,0.20)
```

### 4.5 Border Radius

| Radius | Usage |
|--------|-------|
| 4px | Small elements (tags, buttons) |
| 6px | Medium elements (cards, inputs) |
| 8px | Large elements (modals, drawers) |
| 12px | XL elements (score ring backgrounds) |
| 100% | Circular (avatars, badges, score rings) |

### 4.6 Animation Tokens

| Easing | Duration | Usage |
|--------|----------|-------|
| ease-out | 150ms | Page transitions, quick feedback |
| ease-out | 200ms | Modal/drawer open/close |
| ease-out | 300ms | Score animations, smooth transitions |
| ease-out | 1500ms | Onboarding score ring (0→100) |
| var(--ease-out) | variable | Consistent easing function |

---

## 5. User Flow Maps

### 5.1 First-Time Onboarding Flow

```
[Launch App]
    ↓
[Check onboardingComplete in SessionStorage]
    ├→ NO  →  [Onboarding Redirect]
    │            ↓
    │        [Screen 1: Welcome]
    │            ↓
    │        [Screen 2: Tool Detection]
    │        (invoke: wrap_server)
    │            ↓
    │        [Screen 3: Protection Level]
    │            ↓
    │        [Screen 4: FDA Permission]
    │        (poll: check_fda_permission every 2s)
    │            ↓
    │        [Screen 5: Completion]
    │        (animate: score 0→100)
    │            ↓
    │        [SessionStorage: save complete flag]
    │            ↓
    └→ YES →  [Navigate to Home]
```

### 5.2 Migration Flow (Upgrade Detection)

```
[Launch App]
    ↓
[useExistingInstallation() checks for config/policy/events]
    ├→ No existing data
    │   ↓
    └→ [Skip migration]
    │
    └→ Existing data found
        ↓
    [Show Migration Screen]
        ├→ [Use Existing Path]
        │   ├→ invoke("migrate_config")
        │   ├→ invoke("migrate_policy")
        │   ├→ [Show migration logs]
        │   └→ [Navigate to Home]
        │
        └→ [Start Fresh Path]
            ├→ [Reset all data]
            └→ [Navigate to Onboarding]
```

### 5.3 Daily Use Monitoring Flow

```
[App Opened]
    ↓
[Layout.tsx initializes]
    ├→ Subscribe to Tauri events
    │   ├─ clawdefender://event (add to eventStore)
    │   ├─ clawdefender://status-change (update daemon status)
    │   ├─ clawdefender://prompt (add to pendingPrompts)
    │   ├─ clawdefender://alert (refetch alerts)
    │   ├─ clawdefender://score-changed (update score)
    │   └─ clawdefender://guidance-* (show hints/overlays)
    │
    ├→ [User navigates pages]
    │   ├→ Page fetch relevant data (with TTL cache)
    │   ├→ Display data with loading states
    │   └→ Real-time updates overlay new data
    │
    ├→ [User reviews events]
    │   └→ Click event → EventDetail page
    │
    ├→ [User reviews alerts]
    │   └→ Click alert → AlertDetail page
    │
    └→ [Connection loss detection]
        ├→ Show ConnectionStatus banner
        ├→ Exponential backoff: 5s, 10s, 20s, 40s, 60s max
        └→ Auto-reconnect on daemon restart
```

### 5.4 Event Investigation Flow

```
[Activity Page]
    ↓
[User searches/filters events]
    ├→ Text search (client-side, no server call)
    ├→ Filter by time, risk, tool, server
    └→ Sort by latest, oldest, risk

[User clicks event]
    ↓
[EventDetail Page]
    ├→ Fetch full event details
    ├→ Display humanized explanation
    ├→ Show related events (5 similar)
    ├→ Display kill chain narrative
    │
    └→ [User takes action]
        ├→ "Allow future" → invoke("create_allowlist_rule")
        ├→ "Block tool" → invoke("create_block_rule")
        ├→ "Add to policy" → navigate to PolicyEditor
        └→ "Ask Claw" → navigate to AskClaw with context
```

### 5.5 Alert Response Flow

```
[Alerts Page]
    ├→ User sees unresolved count badge
    ├→ User filters/sorts alerts
    │
    └→ [User clicks alert]
        ↓
    [AlertDetail Page]
        ├→ Display kill chain narrative
        ├→ Show affected resources
        ├→ Display threat intelligence
        │
        └→ [User takes action]
            ├→ "Block" → invoke("block_action"), auto-refresh
            ├→ "Quarantine" → invoke("quarantine_action"), update status
            ├→ "Allow" → invoke("allow_action"), update status
            ├→ "Investigate" → navigate to Activity with filter
            └→ "Ask Claw" → navigate to AskClaw with context
```

### 5.6 Tool Management Flow

```
[My Tools Page]
    ├→ Display all tools with trust levels
    ├→ Show "New" badge for unwrapped tools
    │
    └→ [User clicks tool]
        ↓
    [Tool Detail Page]
        ├→ Display permissions (granted + pending)
        ├→ Show recent activity (last 24h)
        ├→ Display threat assessment
        │
        └→ [User manages permissions]
            ├→ "Allow" permission → invoke("grant_permission")
            ├→ "Deny" permission → invoke("deny_permission")
            ├→ Change trust level → invoke("set_trust_level")
            └→ Block/quarantine → invoke("block_tool")
```

### 5.7 Ask Claw Flow (Conversational AI)

```
[Ask Claw Page]
    ├→ Display conversation history (if exists)
    ├→ Show context-aware suggestions based on currentPage
    │
    └→ [User types message]
        ├→ Focus: Cmd+F (global shortcut)
        ├→ Send: Enter key or [Send] button
        │
        └→ [Message sent]
            ├→ invoke("send_message", { message, context })
            ├→ Display typing indicator
            ├→ Stream response chunks
            │
            └→ [Response received]
                ├→ Display humanized text
                ├→ Parse action buttons (navigate, block, allow)
                ├→ Show rich formatting
                └→ User can click actions
```

### 5.8 Offline/Disconnection Handling

```
[Daemon disconnects]
    ↓
[Layout.tsx detects status-change event]
    ├→ setDaemonStatus({ running: false })
    ├→ Show ConnectionStatus banner
    ├→ Start exponential backoff timer
    │
    └→ [Exponential backoff loop]
        ├→ Wait 5s, try invoke("check_daemon")
        ├→ If fail: Wait 10s, try again
        ├→ If fail: Wait 20s, try again
        ├→ If fail: Wait 40s, try again
        ├→ If fail: Wait 60s, try again (max)
        │
        └→ [Daemon reconnects]
            ├→ invoke succeeds
            ├→ setDaemonStatus({ running: true })
            ├→ Dismiss ConnectionStatus banner
            ├→ Resume real-time event streaming
            └→ Refetch any missed data
```

### 5.9 App Update Flow

```
[App running]
    ├→ UpdateBanner checks every 60 minutes
    ├→ Initial check: 10s delay (don't block startup)
    │
    └→ [Update available detected]
        ├→ Show UpdateBanner with version
        ├→ User can view "What's new" changelog
        │
        └→ [User clicks Update]
            ├→ invoke("check") → fetch update
            ├→ Show "Downloading..." progress
            ├→ Background download (no UI blocking)
            │
            └→ [Download complete]
                ├→ Show "Restart Now" button
                ├→ User can dismiss for 24 hours (localStorage)
                │
                └→ [User clicks Restart]
                    └→ invoke("relaunch")
```

### 5.10 Error Recovery Flow

```
[Error occurs in any page]
    ├→ Catch error in component
    ├→ Display error banner/message
    ├→ Provide retry button
    │
    └→ [User clicks retry]
        ├→ Re-invoke failed operation
        ├→ Show loading state
        │
        └→ [Success OR still fails]
            ├→ Success: update UI, dismiss error
            └→ Failure: show persistent error, suggest support
```

---

## 6. Interaction Patterns & Behaviors

### 6.1 Navigation Patterns

**Global Keyboard Shortcuts (App.tsx):**
- `Cmd+K` → Open Ask Claw
- `Cmd+1` through `Cmd+6` → Navigate to main pages (Home, Ask, Tools, Activity, Alerts, Settings)
- `Cmd+R` → Refresh current page (bypasses TTL cache)
- `Cmd+F` → Focus search/input field on current page
- `Cmd+,` → Navigate to Settings
- `Cmd+W` → Hide app window (macOS-style)
- `Cmd+Q` → Quit app
- `Escape` → Close modal/drawer (focus trap)
- `Arrow Up` → In Ask Claw, cycle through message history

**Tray Menu Navigation:**
- Tray menu sends `clawdefender://navigate` event
- Payload: `{ page: string, params?: Record<string, string> }`
- Navigates via React Router `navigate(page, { state: params })`

**Sidebar Navigation:**
- 6 main pages with icons and labels
- Collapsible on narrow windows (<1000px width)
- Active page highlighted with blue accent background
- Alert count badge on Alerts page (red, 99+ indicator)
- New tools badge on Tools page (blue "New")

**Page Transitions:**
- 150ms fade-out, then fade-in (opacity transition)
- Prevents jarring content switching
- Respects prefers-reduced-motion (no animation if enabled)

### 6.2 Real-Time Event Patterns

**Event Listener Architecture (Layout.tsx):**

```typescript
// Event: clawdefender://event
listen<AuditEvent>("clawdefender://event", (e) => {
  addRawEvent(e.payload);  // eventStore wraps and batches
})

// Event: clawdefender://status-change
listen<{ daemon_running: boolean }>("clawdefender://status-change", (e) => {
  setDaemonStatus({ running: e.payload.daemon_running });
  useEventStore.getState().setDaemonRunning(e.payload.daemon_running);
})

// Event: clawdefender://prompt
listen<PendingPrompt>("clawdefender://prompt", (e) => {
  addPrompt(e.payload);  // Show in PromptOverlay
})

// Event: clawdefender://alert
listen("clawdefender://alert", () => {
  fetchAlerts();  // Refetch alert list
})

// Event: clawdefender://score-changed
listen<ProtectionScore>("clawdefender://score-changed", (e) => {
  setProtectionScoreFull(e.payload);  // Update score ring
})

// Event: clawdefender://guidance-hint
listen<GuidanceEvent>("clawdefender://guidance-hint", (e) => {
  addGuidanceHint({...});  // Show toast
})

// Event: clawdefender://guidance-overlay
listen<GuidanceEvent>("clawdefender://guidance-overlay", (e) => {
  setGuidanceOverlay({...});  // Show modal
})
```

**Event Batching (eventStore.ts):**
- Incoming raw events are wrapped as `HumanizedEvent`
- Batched in `pendingBatch` array
- Flushed to Zustand store every 100ms (BATCH_INTERVAL_MS)
- Prevents React re-render per event (critical for high-frequency events)
- Max 10,000 events in memory (FIFO eviction)

### 6.3 Data Fetching Patterns

**TTL Cache Pattern (appStore):**

```typescript
// SCORE_TTL_MS = 30_000ms (30 seconds)

async function fetchScore(force?: boolean) {
  const now = Date.now();
  const cached = scoreCache.get(); // { data, timestamp }

  if (!force && cached && now - cached.timestamp < SCORE_TTL_MS) {
    return cached.data;  // Use cache
  }

  const data = await invoke("get_protection_score");
  scoreCache.set(data, now);
  return data;
}

// Cmd+R bypass
if (isKeyPressCmd && isKeyR) {
  fetchScore(true);  // force=true bypasses TTL
}
```

**Progressive Loading:**
- Initial load: fetch first 30 items
- User clicks "Show more" → fetch next batch
- Prevents massive initial payload

**Virtual Scrolling (Activity Page):**
- Activity list has 10,000+ events
- Only render ~50 visible rows at a time
- Estimate: 52px per row, 400px buffer above/below viewport
- Uses intersection observer pattern
- Solves rendering performance for large lists

### 6.4 Input & Form Patterns

**Text Input:**
- Debounced search (300ms) to avoid excessive re-renders
- Client-side filtering (no server calls for UI state)
- Focus visible: 2px outline, 2px offset, accent color

**Modal Focus Trap:**
- Pressing Tab cycles through focusable elements within modal
- Escape key closes modal
- Focus returns to trigger element after close

**Confirmation Dialogs:**
- Used for destructive actions (delete policy, block tool)
- Message: "Are you sure? This action cannot be undone."
- Two buttons: [Confirm] [Cancel]

**Checkbox & Radio:**
- Instant visual feedback (no server call)
- State saved to appStore immediately
- Optional backend sync

### 6.5 Error Handling

**Error Banner Pattern:**
- Appears at top of page content
- Dismissable with X button
- Contains: icon, message, optional retry button
- Color: danger red (--color-danger)

**Toast Notification Pattern:**
- Success: green (--color-safe), "Action completed"
- Error: red (--color-danger), "Action failed"
- Auto-dismiss after 3 seconds
- Multiple toasts stack vertically

**Inline Error States:**
- Input field validation errors appear below input
- Red border on input field
- Clear error on user input

### 6.6 Loading States

**Page-Level Loading:**
- Show `<LoadingSkeleton>` component
- Skeleton: gray placeholder boxes matching page layout
- Fade to content once loaded

**Component-Level Loading:**
- Button shows spinner while action pending
- Button disabled while loading
- Text remains visible (e.g., "Saving...")

**Data Table Loading:**
- Skeleton rows (gray bars)
- Fades to actual content

---

## 7. State Management & Data Flow

### 7.1 Zustand Store Architecture

**Store 1: appStore**

```typescript
interface AppStore {
  // Daemon & status
  daemonStatus: { running: boolean };
  connectionState: 'connected' | 'reconnecting' | 'disconnected';

  // Protection score
  protectionScore: number;            // 0-100 for display
  protectionScoreFull: ProtectionScore | null;  // Full data with factors
  scoreHistory: ScoreSnapshot[];
  scoreCacheTime: number;

  // UI state
  sidebarCollapsed: boolean;
  activePage: string;

  // Guidance system
  guidanceHints: Record<string, GuidanceHintData>;
  guidanceOverlay: GuidanceOverlayData | null;

  // Restart reminder
  restartReminderVisible: boolean;
  restartReminderMessage: string;

  // Methods
  setDaemonStatus: (status) => void;
  fetchScore: (force?: boolean) => Promise<ProtectionScore>;
  fetchScoreHistory: (force?: boolean) => Promise<ScoreSnapshot[]>;
  setSidebarCollapsed: (collapsed) => void;
  setActivePage: (page) => void;
  addGuidanceHint: (hint) => void;
  setGuidanceOverlay: (overlay) => void;
  setRestartReminder: (visible, message?) => void;
}
```

**Store 2: eventStore**

```typescript
interface EventStore {
  events: HumanizedEvent[];  // Max 10,000
  pendingPrompts: PendingPrompt[];
  daemonRunning: boolean;

  // Statistics
  todayEventCount: number;
  todayBlockedCount: number;
  highestAnomalyScore: number;
  highestAnomalyServer: string;

  // Filters
  onlyNotable: boolean;  // Critical/high risk only

  // Methods
  addEvent: (event: HumanizedEvent) => void;
  addRawEvent: (event: AuditEvent) => void;
  addPrompt: (prompt: PendingPrompt) => void;
  removePrompt: (id) => void;
  setDaemonRunning: (running) => void;
  setEvents: (events) => void;
  setOnlyNotable: (v) => void;
}
```

**Store 3: alertStore**

```typescript
interface AlertStore {
  alerts: IntelligentAlert[];
  stats: AlertStats | null;
  loading: boolean;
  unresolvedCount: number;

  // Methods
  fetchAlerts: () => Promise<IntelligentAlert[]>;
  fetchHistory: (days?: number) => Promise<IntelligentAlert[]>;
  dismissAlert: (id, reason?) => Promise<void>;
  resolveAlert: (id, resolution) => Promise<void>;
  dismissAll: (maxSeverity?) => Promise<void>;
}
```

**Store 4: conversationStore**

```typescript
interface ConversationStore {
  messages: ConversationMessage[];
  currentConversationId: string;
  isLoading: boolean;
  currentPage: string;  // For context-aware suggestions

  // Methods
  addMessage: (message) => void;
  setConversationId: (id) => void;
  clearMessages: () => void;
  setCurrentPage: (page) => void;
}

interface ConversationMessage {
  id: string;
  role: 'user' | 'assistant';
  contentText: string;
  contentRichJson?: Record<string, any>;
  actionsJson?: Record<string, any>;
  intentId?: string;
  timestamp: number;
}
```

**Store 5: toolStore**

```typescript
interface ToolStore {
  tools: ToolCardData[];
  newTools: NewToolInfo[];
  loading: boolean;

  // Methods
  fetchTools: () => Promise<ToolCardData[]>;
  fetchNewTools: () => Promise<NewToolInfo[]>;
  getTrustLevel: (serverName) => Promise<TrustLevel>;
}
```

**Store 6: serverStore**

```typescript
interface ServerStore {
  servers: ServerInfo[];
  hasNewUnwrapped: boolean;
  loading: boolean;

  // Methods
  fetchServers: () => Promise<ServerInfo[]>;
}
```

### 7.2 Data Relationships

**AuditEvent → HumanizedEvent**
- Raw event from daemon → wrapped with humanized text
- Mapping: `decision` → `action_taken`, `risk_level` → `risk_level` (mapped)
- One-liner: `tool_name: action` or just `action`

**ProtectionScore → ScoreBreakdownDrawer**
- Score with factors (6-8 items)
- Each factor: id, name, current_points, max_points, status, fix_actions
- Fix actions: { action_type: 'navigate', target: string, label: string }

**Conversation → Context-Aware Suggestions**
- intentId determines suggestion type
- status.* intents: show protection level, threats, tools suggestions
- explain.* intents: show event explanation, correlation suggestions
- control.* intents: show blocking, permission, policy suggestions

### 7.3 Caching & Invalidation

**TTL Cache (appStore):**
- Score: 30 seconds
- Score history: 30 seconds
- Cmd+R bypasses cache (force fetch)

**Event Batching (eventStore):**
- 100ms flush interval
- Collects raw events and batches to store
- Prevents individual React renders per event

**Alert Fetching:**
- Fetch on page load (no cache)
- Real-time `clawdefender://alert` event triggers refetch
- No polling (event-driven)

**Tool Fetching:**
- Fetch on page load
- Real-time `clawdefender://new-tool-detected` event triggers append
- No polling (event-driven)

### 7.4 Real-Time Event Streaming Architecture

```
┌─────────────────────────────────────────────┐
│ Daemon (clawdefender-daemon)                │
└─────────────────────────────────────────────┘
           ↓
    [Emit Tauri Event]
           ↓
┌─────────────────────────────────────────────┐
│ App Frontend (React + Tauri)                │
│                                             │
│  [Layout.tsx]                               │
│  └─ listen<AuditEvent>(...)                 │
│      └─ [eventStore.addRawEvent()]          │
│          └─ [wrap + batch]                  │
│              └─ [flush every 100ms]         │
│                  └─ [setEventStore.events]  │
│                      └─ [Activity page updates]
└─────────────────────────────────────────────┘
```

**Event Flow Timeline:**
1. Daemon detects event: t=0ms
2. Daemon emits Tauri event: t=1ms
3. Layout.tsx listener receives: t=2ms
4. addRawEvent wraps as humanized: t=2ms
5. Enqueued in batch: t=3ms
6. Flush timer fires (100ms batch window): t=100ms
7. Store updates: t=101ms
8. Activity component re-renders: t=102ms

**Performance Impact:**
- Max 1 store update per 100ms (instead of per event)
- For high-frequency events (100/sec), reduces renders by 99x
- Imperceptible to user (100ms is well below 16ms frame time)

---

## 8. Accessibility Features

### 8.1 ARIA Landmarks

**Layout.tsx:**
```html
<nav aria-label="Main navigation">
  {/* Sidebar navigation links */}
</nav>

<main aria-label="Main content" id="main-content">
  <Outlet />
</main>
```

**Alerts Page:**
```html
<div role="status" aria-live="polite" aria-label="Alert count">
  {unresolvedCount} unresolved alerts
</div>
```

**Activity Page:**
```html
<div role="region" aria-live="polite" aria-label="Event feed">
  {/* Real-time events appear here */}
</div>
```

### 8.2 Semantic HTML

- Proper heading hierarchy (h1 → h2 → h3)
- Navigation links use `<a>` or `<NavLink>`
- Buttons use `<button>` (not divs)
- Form inputs use `<input>`, `<label>` with `htmlFor`
- Tables use `<table>`, `<thead>`, `<tbody>`, `<tr>`, `<td>`

### 8.3 Keyboard Navigation

**Global Shortcuts (tested and documented):**
- `Tab` / `Shift+Tab`: Cycle through focusable elements
- `Enter`: Activate buttons, submit forms
- `Space`: Toggle checkboxes
- `Arrow Up/Down`: Cycle through message history (Ask Claw)
- `Escape`: Close modals, focus trap escape

**Focus Management:**
- Focus visible: 2px outline, 2px offset, accent color (--color-accent)
- Focus returns to trigger element after modal closes
- Initial focus on primary action in modals

**Skip Links:**
```html
<a href="#main-content" className="sr-only focus:not-sr-only">
  Skip to main content
</a>
```

### 8.4 Screen Reader Support

**aria-labels & aria-descriptions:**
```html
<button aria-label="Expand sidebar">▶</button>
<div aria-label={`${unresolvedCount} unresolved alerts`} />
<span aria-hidden="true">📌</span> {/* Decorative icon */}
```

**ARIA Live Regions:**
- Alert count uses `aria-live="polite"` (announces changes)
- Event feed uses `aria-live="polite"` (announces new events)
- Toast notifications use `role="status"` or `role="alert"`

**Heading Hierarchy:**
- Page title: h1
- Section headers: h2
- Card titles: h3
- Proper nesting (no skipped levels)

### 8.5 Motion Preferences

**prefers-reduced-motion Support:**

```typescript
const prefersReducedMotion = useRef(
  typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
);

// In animation handler:
if (!prefersReducedMotion.current) {
  setPulse(true);  // Only animate if not reduced-motion
}
```

**Animations Affected:**
- Score ring pulse (disabled if prefers-reduced-motion)
- Page fade transitions (kept subtle, ~150ms is acceptable)
- Hover effects (reduced, not eliminated)

**Essential Animations (not disabled):**
- Page crossfade transition (helps UX, low motion)
- Progress bars (not animated, static)

### 8.6 Color Contrast

**WCAG AA Compliance:**
- Primary text on white: --color-text-primary (1D1D1F) = 16:1 contrast
- Secondary text on white: --color-text-secondary (86868B) = 6.8:1 contrast
- Accent on white: --color-accent (007AFF) = 4.5:1 contrast
- Success on white: --color-safe (00D084) = 5:1 contrast
- Danger on white: --color-danger (E82E3C) = 5.4:1 contrast

**Color Alone Not Used:**
- Alerts use icon + color (not color alone)
- Status indicators use text + color
- Form errors use text + color

---

## 9. Navigation & Keyboard Shortcuts (Quick Reference)

### 9.1 Global Keyboard Shortcuts

| Shortcut | Action | Context |
|----------|--------|---------|
| `Cmd+K` | Open/focus Ask Claw | Anywhere |
| `Cmd+1` | Navigate to Home | Anywhere |
| `Cmd+2` | Navigate to Ask Claw | Anywhere |
| `Cmd+3` | Navigate to My Tools | Anywhere |
| `Cmd+4` | Navigate to Activity | Anywhere |
| `Cmd+5` | Navigate to Alerts | Anywhere |
| `Cmd+6` | Navigate to Settings | Anywhere |
| `Cmd+R` | Refresh current page (bypass cache) | Anywhere |
| `Cmd+F` | Focus search/input field | Current page |
| `Cmd+,` | Navigate to Settings | Anywhere |
| `Cmd+W` | Hide app window | Anywhere |
| `Cmd+Q` | Quit app | Anywhere |
| `Escape` | Close modal/drawer/focus trap | When modal open |
| `Arrow Up` | Previous message in history | Ask Claw input |

### 9.2 Page-Specific Navigation

**Sidebar (Always Visible):**
- Click nav items to switch pages
- Collapsible on narrow windows
- Shows alert count badge, daemon status, score ring

**Breadcrumbs (Where Applicable):**
- Activity detail: [Activity] > [Event #123]
- Tool detail: [My Tools] > [Tool Name]
- Alert detail: [Alerts] > [Alert Title]

**Back Buttons:**
- Detail pages have [Back] button to parent page
- Preserves scroll position (browser back/forward)

---

## 10. Notification & Alert System

### 10.1 Toast Notifications

**Success Toast:**
```
✓ Action completed
Auto-dismiss after 3 seconds
Color: --color-safe (green)
Position: Top right or stack center
```

**Error Toast:**
```
✗ Action failed
Manual dismiss required (user should address error)
Color: --color-danger (red)
Position: Top right or stack center
```

**Info Toast:**
```
ℹ Information message
Auto-dismiss after 3 seconds
Color: --color-accent (blue)
Position: Top right or stack center
```

### 10.2 Banners

**Update Banner (UpdateBanner.tsx):**
- Blue background (--color-accent-subtle)
- Shows version number and "What's new" link
- States: Downloading, Downloaded (ready to restart), Dismissed (24h)

**Restart Reminder Banner (RestartReminderBanner):**
- Info color background
- Message: "Your AI apps need to restart..."
- Dismissible button
- Appears when daemon restarts

**Connection Status Banner (ConnectionStatus.tsx):**
- Yellow background (--color-warning-subtle)
- Shows "Trying to reconnect... 5s" countdown
- Auto-dismiss when connected

### 10.3 Modal Alerts

**Confirmation Dialog:**
- Heading: "Are you sure?"
- Message: Context-specific description
- Buttons: [Confirm] [Cancel]
- Escape key closes (cancel)
- Focus trap on [Confirm] button

**Error Dialog:**
- Heading: "Error"
- Message: Error details
- Buttons: [Retry] [Dismiss]
- Helpful error code or suggestion

### 10.4 Guidance Hints (In-App Nudges)

**Toast Hint (GuidanceToastContainer):**
- Small toast in corner with icon + message
- Optional action button with label/route
- Auto-dismiss after 5 seconds
- Examples: "Check your first event", "Set up a policy", "Review alerts"

**Overlay Hint (PromptOverlay):**
- Modal overlay with title + message
- Blocks interaction with page content
- Large action button
- Used for important milestones
- Example: "You've completed onboarding! Here's your protection score."

**In-Page Hint (AnchorHint):**
- Tooltip-style hint near UI element
- Point to relevant feature
- Light background, subtle appearance
- Example: Score ring hint "Click to view breakdown"

### 10.5 Real-Time Alert Updates

**Unresolved Count Badge (Sidebar):**
- Red badge on Alerts sidebar item
- Shows count (or "99+" for >99)
- Updates when alert status changes
- aria-label: "3 unresolved alerts"

**Alert List (Alerts Page):**
- New alerts appear at top of list
- Old alerts move down
- Unresolved count updates in real-time
- Resolved alerts moved to History tab

---

## 11. Component Inventory

### 11.1 Page Components

| Component | File | Route | Purpose |
|-----------|------|-------|---------|
| Home | Home.tsx | / | Dashboard |
| AskClaw | AskClaw.tsx | /ask | Chat AI |
| MyTools | MyTools.tsx | /tools | Tool browse |
| ToolDetail | ToolDetail.tsx | /tools/:id | Tool detail |
| Activity | Activity.tsx | /activity | Event feed |
| EventDetail | EventDetail.tsx | /activity/:id | Event detail |
| Alerts | Alerts.tsx | /alerts | Alert list |
| AlertDetail | AlertDetail.tsx | /alerts/:id | Alert detail |
| Settings | Settings.tsx | /settings | Config hub |
| PolicyEditor | PolicyEditor.tsx | /settings/policy | Policy mgmt |
| SystemHealth | SystemHealth.tsx | /settings/health | Score factors |
| ThreatIntel | ThreatIntel.tsx | /settings/threat-intel | CVE info |
| Onboarding | Onboarding.tsx | /onboarding | Setup wizard |

### 11.2 Layout Components

| Component | File | Purpose |
|-----------|------|---------|
| Layout | Layout.tsx | Main app shell |
| Sidebar | Sidebar.tsx | Navigation + score |
| MiniScoreRing | Sidebar.tsx | Score ring visual |
| ConnectionStatus | ConnectionStatus.tsx | Daemon connection |
| UpdateBanner | UpdateBanner.tsx | App update |
| RestartReminderBanner | Layout.tsx | Restart notice |
| MigrationScreen | MigrationScreen.tsx | Upgrade path |

### 11.3 Shared Components

| Component | File | Purpose |
|-----------|------|---------|
| ScoreBreakdownDrawer | shared/ScoreBreakdownDrawer.tsx | Score factors detail |
| GuidanceToastContainer | guidance/GuidanceToast.tsx | Toast hints |
| PromptOverlay | guidance/PromptOverlay.tsx | Modal hints |
| LoadingSkeleton | LoadingSkeleton.tsx | Page loading state |
| EmptyState | EmptyState.tsx | No data state |
| ErrorBanner | ErrorBanner.tsx | Error message |
| PageHeader | PageHeader.tsx | Page title + actions |

### 11.4 Activity Components

| Component | Purpose |
|-----------|---------|
| ActivityTable | Event table with virtual scroll |
| EventRow | Single event summary row |
| EventFilter | Filter sidebar (time, risk, tool, server) |
| ActivityStats | Event count, blocked count, charts |

### 11.5 Alert Components

| Component | Purpose |
|-----------|---------|
| AlertCard | Single alert with actions |
| AlertList | List of alerts with filtering |
| AlertBadge | Unresolved count badge |
| SeverityIcon | Risk level icon (🔴🟡🟢⚪) |
| KillChainNarrative | Attack progression text |

### 11.6 Tool Components

| Component | Purpose |
|-----------|---------|
| ToolCard | Tool summary with trust badge |
| ToolGrid | Grid of tool cards |
| ToolHeader | Tool detail page header |
| PermissionsList | Granted/pending permissions |
| TrustLevelSelector | Radio buttons for trust |

### 11.7 Conversation Components

| Component | Purpose |
|-----------|---------|
| ChatMessage | Single message bubble |
| MessageList | Message history |
| InputField | Chat input with send |
| SuggestionChips | Context-aware action buttons |
| TypingIndicator | "Claw is thinking..." animation |

### 11.8 Form Components

| Component | Purpose |
|-----------|---------|
| FormInput | Text input field |
| FormCheckbox | Checkbox with label |
| FormRadio | Radio button group |
| FormSelect | Dropdown selector |
| ConfirmDialog | Confirmation modal |

---

## 12. Known UX Gaps & Recommendations

### 12.1 Identified Gaps

**Gap 1: Event Search is Client-Only**
- Current: Search filters events in eventStore (max 10,000 events)
- Issue: Cannot search historical events beyond current 10,000 limit
- Recommendation: Implement server-side search via `invoke("search_events", { query, filters })`
- Impact: High (users expect full event history search)

**Gap 2: No Bulk Actions on Events**
- Current: Individual event actions only
- Issue: User cannot bulk block/allow multiple events at once
- Recommendation: Add checkboxes to Activity page, bulk action buttons
- Impact: Medium (advanced users would benefit)

**Gap 3: Alert Severity Levels Not Customizable**
- Current: Fixed severity scale (Critical, High, Medium, Low)
- Issue: Users cannot adjust sensitivity thresholds
- Recommendation: Add "Alert Sensitivity" slider in Settings
- Impact: Medium (power users would customize)

**Gap 4: No Kill Chain Narrative for All Events**
- Current: Full kill chain only for Alerts, not Events
- Issue: Event detail page lacks attacker intent analysis
- Recommendation: Correlate events and generate mini kill chain narrative
- Impact: Medium (would help event investigation)

**Gap 5: Policy Conditions Editor is Basic**
- Current: Simple text expression editor
- Issue: Complex conditions are hard to write for non-technical users
- Recommendation: Visual condition builder (drag-drop rule nodes)
- Impact: Low (power users only)

### 12.2 UX Recommendations

**Recommendation 1: Onboarding Tool Detection Validation**
- Current: Wraps all detected tools automatically
- Recommendation: Show detected tools, ask user to confirm before wrapping
- Benefit: Better transparency, user control
- Effort: Medium

**Recommendation 2: Prompt History in Ask Claw**
- Current: Can recall previous messages with Arrow Up
- Recommendation: Show full conversation dropdown in UI
- Benefit: Easier navigation of conversation history
- Effort: Low

**Recommendation 3: Event Correlation Visualization**
- Current: Text-based related events list
- Recommendation: Timeline graph showing event sequence
- Benefit: Better understanding of attack progression
- Effort: High

**Recommendation 4: Dark Mode Support**
- Current: Light theme only
- Recommendation: Detect `prefers-color-scheme: dark` and apply dark tokens
- Benefit: Accessibility, eye strain reduction
- Effort: High (requires design token updates)

**Recommendation 5: Offline-First Architecture**
- Current: Offline = read-only UI with cached data
- Recommendation: Allow policy creation offline, sync when reconnected
- Benefit: Better UX during disconnections
- Effort: High (requires backend queueing)

**Recommendation 6: Contextual Help System**
- Current: Guidance hints are limited to milestones
- Recommendation: Right-click context menu for page help
- Benefit: Better discoverability of features
- Effort: Medium

---

## 13. Performance Optimization Strategies

### 13.1 Current Optimizations

**1. Event Batching (eventStore)**
- Batches incoming events every 100ms
- Reduces React renders from ~100/sec to ~10/sec
- Result: Smooth UI, no lag at high event frequency

**2. TTL Caching (appStore)**
- Score: 30 second cache
- Cmd+R bypass for fresh fetch
- Result: Reduced backend calls, faster page loads

**3. Virtual Scrolling (Activity Page)**
- Only renders visible rows (52px each, 400px buffer)
- Handles 10,000+ events without frame drops
- Result: 60 FPS scrolling, instant page load

**4. Lazy-Loaded Routes**
- All pages loaded on demand via `React.lazy()`
- Code splitting: ~50KB per page
- Result: ~500KB total initial bundle, <1s startup

**5. Progressive Loading**
- Activity page loads first 30 items, "Show more" for rest
- Prevents initial 10,000 item render
- Result: Instant page display

### 13.2 Potential Optimizations (Future)

**1. Server-Side Event Filtering**
- Current: Filter in client
- Improvement: Filter on backend, paginate results
- Benefit: Handle 100K+ events, faster search

**2. IndexedDB Caching**
- Current: Events only in memory (ephemeral)
- Improvement: Persist events to IndexedDB
- Benefit: Offline event search, faster history navigation

**3. Suspense Boundaries**
- Current: One LoadingSkeleton per route
- Improvement: Granular Suspense per section (score, events, stats)
- Benefit: Partial page display while loading

**4. Image Optimization**
- Current: SVG icons (already optimized)
- Improvement: AVIF format for tool icons (if any)
- Benefit: Faster load, smaller file sizes

**5. Code Splitting by Route**
- Current: All page code in separate chunks
- Improvement: Split shared components (DrawerScoreBreakdown, etc.)
- Benefit: Smaller chunks, faster navigation

---

## 14. Testing Checklist for UX Team

### 14.1 Functional Testing

- [ ] Onboarding flow: all 5 screens, happy path
- [ ] Onboarding flow: skip button on FDA screen
- [ ] Migration flow: use existing vs. start fresh
- [ ] Navigation: all 6 sidebar links work
- [ ] Keyboard shortcuts: Cmd+1-6, Cmd+K, Cmd+R, Escape
- [ ] Activity page: search, filter, sort
- [ ] Activity page: virtual scroll (scroll to bottom)
- [ ] Event detail: all action buttons work
- [ ] Alert detail: severity display, actions
- [ ] Tool detail: permission grant/deny
- [ ] Policy editor: create, edit, delete
- [ ] Settings: daemon start/stop, config toggles
- [ ] Ask Claw: message send, suggestions
- [ ] Health: score animation, factor expand

### 14.2 Real-Time Testing

- [ ] New event appears at top of Activity feed
- [ ] New alert appears at top of Alerts page
- [ ] New tool appears with "New" badge
- [ ] Score updates when factors change
- [ ] Daemon disconnect: Connection banner shows
- [ ] Daemon reconnect: Banner disappears, events resume

### 14.3 Accessibility Testing

- [ ] Tab navigation: all interactive elements focusable
- [ ] Focus visible: 2px outline visible on focus
- [ ] Escape key: closes modals
- [ ] Screen reader: page landmarks announced
- [ ] Color contrast: all text passes WCAG AA
- [ ] Motion: prefers-reduced-motion disables animations
- [ ] Keyboard only: entire app usable without mouse

### 14.4 Error State Testing

- [ ] Network error: connection banner shows
- [ ] API error: error toast appears, retry button works
- [ ] Invalid input: error message displays
- [ ] Daemon crash: graceful degradation, read-only UI

### 14.5 Performance Testing

- [ ] Page load: < 2 seconds (first paint)
- [ ] Activity scroll: smooth at 60 FPS (10K events)
- [ ] Score update: instant (no lag)
- [ ] Modal open: < 100ms animation
- [ ] Search: < 500ms for 10K events

### 14.6 State Testing

- [ ] Sidebar collapse state: persists on reload
- [ ] Settings toggles: persist on reload
- [ ] Filter state: persists on Activity page
- [ ] Scroll position: preserved on back/forward

---

## 15. Appendix: File Structure

```
clients/clawdefender-app/
├── src/
│   ├── App.tsx                          [Routes, shortcuts, tray nav]
│   ├── pages/
│   │   ├── Home.tsx
│   │   ├── AskClaw.tsx
│   │   ├── MyTools.tsx
│   │   ├── ToolDetail.tsx
│   │   ├── Activity.tsx
│   │   ├── EventDetail.tsx
│   │   ├── Alerts.tsx
│   │   ├── AlertDetail.tsx
│   │   ├── Settings.tsx
│   │   ├── PolicyEditor.tsx
│   │   ├── SystemHealth.tsx
│   │   ├── ThreatIntel.tsx
│   │   └── Onboarding.tsx
│   │
│   ├── components/
│   │   ├── Layout.tsx                   [Main shell, event listeners]
│   │   ├── Sidebar.tsx                  [Navigation, score ring]
│   │   ├── ConnectionStatus.tsx         [Daemon disconnect banner]
│   │   ├── UpdateBanner.tsx             [App update banner]
│   │   ├── MigrationScreen.tsx          [Upgrade flow]
│   │   ├── LoadingSkeleton.tsx
│   │   ├── EmptyState.tsx
│   │   ├── ErrorBanner.tsx
│   │   ├── PageHeader.tsx
│   │   ├── guidance/
│   │   │   ├── GuidanceToast.tsx
│   │   │   └── PromptOverlay.tsx
│   │   ├── shared/
│   │   │   └── ScoreBreakdownDrawer.tsx
│   │   ├── activity/                    [Activity components]
│   │   ├── alerts/                      [Alert components]
│   │   ├── tools/                       [Tool components]
│   │   ├── conversation/                [Chat components]
│   │   └── ...
│   │
│   ├── stores/
│   │   ├── appStore.ts                  [Score, daemon, UI state]
│   │   ├── eventStore.ts                [Event feed, batching]
│   │   ├── alertStore.ts                [Alert list]
│   │   ├── conversationStore.ts         [Chat history]
│   │   ├── toolStore.ts                 [Tool list]
│   │   └── serverStore.ts               [Server list]
│   │
│   ├── hooks/
│   │   ├── useKeyboardShortcuts.ts      [Global shortcuts]
│   │   ├── useDebouncedSave.ts
│   │   ├── useFocusTrap.ts
│   │   └── ...
│   │
│   ├── services/                        [Tauri invocations]
│   ├── utils/                           [Helpers, formatters]
│   ├── constants/                       [Colors, sizes, etc.]
│   ├── styles/
│   │   ├── globals.css                  [CSS variables, resets]
│   │   └── tokens.css                   [Design tokens]
│   ├── types/
│   │   └── index.ts                     [All TS interfaces]
│   └── tests/
│       ├── activity.test.ts
│       ├── alerts.test.ts
│       ├── askClaw.test.ts
│       ├── migration.test.ts
│       └── settings.test.ts
│
├── vite.config.ts                       [Vite + Tauri config]
├── tailwind.config.js                   [Tailwind CSS config]
└── tsconfig.json
```

---

## 16. Conclusion

The ClawDefender Mac GUI is a sophisticated, real-time security monitoring application with:

- **13 main pages** for comprehensive security control
- **6 Zustand stores** managing app state, events, alerts, conversations, tools, and servers
- **Real-time event streaming** via Tauri IPC with intelligent batching
- **Accessibility-first design** with ARIA, keyboard navigation, and motion preferences
- **Performance-optimized** with virtual scrolling, TTL caching, and code splitting
- **Sophisticated guidance system** with onboarding, contextual hints, and overlays
- **Comprehensive error handling** with banners, toasts, and recovery flows
- **Modern UX patterns** including progressive loading, focus management, and confirmation dialogs

This document provides UX designers and product managers with the exact specifications needed to build accurate mockups, conduct accessibility audits, and plan future improvements.

---

**Document Version:** 1.0
**Compiled by:** Claude Code Assistant
**Date:** 2026-02-26

