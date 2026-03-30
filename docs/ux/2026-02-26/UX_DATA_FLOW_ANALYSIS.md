# ClawDefender UX Data Flow Analysis

**For:** UX Team
**Date:** February 26, 2026
**Scope:** Data layer architecture, state management, loading behaviors, caching, real-time updates, and offline behavior

---

## Overview

ClawDefender's GUI uses Zustand for state management with five core stores: `appStore`, `eventStore`, `alertStore`, `conversationStore`, and `serverStore`. Data flows through Tauri IPC commands and real-time event listeners. This document maps every piece of data the UI needs, how it's fetched, cached, and what UX states emerge.

---

## 1. CORE STORES & DATA SHAPES

### 1.1 appStore — Daemon Status, Protection Score, Guidance

**File:** `/src/stores/appStore.ts`

#### Daemon & Connection State
```typescript
daemonStatus: {
  running: boolean
  version?: string
}
connectionState: "connected" | "reconnecting" | "disconnected"
```

**Source:** Backend daemon heartbeat (via IPC)
**Update Trigger:** Status changes trigger `setDaemonStatus()`
**UI Implications:**
- Green indicator in menu bar when `running === true`
- Reconnecting state shows spinner/pulse
- Disconnected state blocks most UI interactions

#### Protection Score
```typescript
protectionScore: number              // 0-100, simple display number
protectionScoreFull: ProtectionScore | null  // Rich details

ProtectionScore {
  total: number
  label: string ("Full" | "High" | "Medium" | "Low")
  color: string
  factors: BackendScoreFactor[]
  computed_at: string (ISO timestamp)
  change_from_last: number | null  // +5, -3, etc.
}

BackendScoreFactor {
  id: string
  name: string
  description: string
  max_points: number
  current_points: number
  status: "full" | "partial" | "empty"
  fix_actions: FixAction[]  // [{ label, action_type, target, params }]
  details: string
}
```

**Fetch Pattern:**
- Command: `invoke("get_protection_score")`
- TTL: **30 seconds** — cached locally
- Cache Bypass: Call with `force: true` to skip TTL check
- Failed Fetch: Keeps previous state silently

**Score History (Sparkline)**
```typescript
scoreHistory: ScoreSnapshot[]  // 7-day history for chart

ScoreSnapshot {
  id: number
  score: number
  factors_json: string
  computed_at: string
}
```

- TTL: 30 seconds
- Fetched with `invoke("get_score_history", { days: 7 })`

#### Guidance System (Onboarding Hints)
```typescript
guidanceHints: Record<string, GuidanceHintData>  // Keyed by anchorId

GuidanceHintData {
  milestoneId: string
  message: string
  anchorId: string
  actionLabel?: string
  actionRoute?: string
}

guidanceOverlay: GuidanceOverlayData | null

GuidanceOverlayData {
  milestoneId: string
  title: string
  message: string
}
```

**UI Usage:** Inline anchors on pages + overlay prompts during onboarding

#### Restart Reminder Banner
```typescript
restartReminderVisible: boolean
restartReminderMessage: string
```

**Trigger:** After onboarding or guard activation — notify user to restart AI tools

---

### 1.2 eventStore — Live Event Feed

**File:** `/src/stores/eventStore.ts`

#### Event Data
```typescript
events: HumanizedEvent[]  // Ring buffer, max 10,000
todayEventCount: number   // Stats for badge
todayBlockedCount: number // Stat for badge
highestAnomalyScore: number
highestAnomalyServer: string
onlyNotable: boolean  // Filter toggle

HumanizedEvent {
  event_id: string
  timestamp: string
  server_display_name: string
  client_name: string | null
  one_liner: string         // e.g., "Claude read config.json"
  expanded_explanation: string
  educational_aside: string | null
  behavioral_context: string
  risk_level: "dangerous" | "suspicious" | "unusual" | "normal" | "blocked" | "info"
  risk_explanation: string
  action_taken: "Allowed" | "Blocked" | "Prompted" | "AutoBlocked"
  action_reason: string
  is_notable: boolean
  correlation_id: string | null
  kill_chain_id: string | null
  raw_event: AuditEvent  // Raw backend event
}
```

#### Real-Time Event Ingestion
- **Incoming Events:** Two paths:
  1. **Raw Events** via `clawdefender://event` Tauri listener → `addRawEvent()` → wraps as minimal HumanizedEvent
  2. **Pre-humanized Events** via `clawdefender://humanized-event` → `addEvent()` directly

- **Batching:** Events batch every **100ms** before store update
  - Prevents React re-render spam
  - Batched events prepended to front of list
  - If list exceeds 10,000, truncate at 10,000

- **Raw Event Wrapping:** Maps risk levels and decisions to UI-friendly strings:
  - `risk_level: "critical"` → `"dangerous"`
  - `risk_level: "high"` → `"suspicious"`
  - Decision `"blocked" | "deny"` → `action_taken: "Blocked"`

#### Pending Prompts
```typescript
pendingPrompts: PendingPrompt[]

PendingPrompt {
  id: string
  timestamp: string
  server_name: string
  tool_name: string
  action: string
  resource: string
  risk_level: "low" | "medium" | "high" | "critical"
  context: string
  timeout_seconds: number
}
```

**UI:** PromptQueue component renders these with action buttons (Allow/Block/Always)
**Removal:** `removePrompt(id)` fires after user responds

#### Daemon Running Indicator
```typescript
daemonRunning: boolean
```

Synced with appStore's daemon status.

---

### 1.3 alertStore — Intelligent Alerts

**File:** `/src/stores/alertStore.ts`

#### Alert Data
```typescript
alerts: IntelligentAlert[]
stats: AlertStats | null
loading: boolean
unresolvedCount: number

IntelligentAlert {
  id: string
  alert_type: string
  severity: string  // "dangerous" | "suspicious" | "unusual" | "info"
  status: string
  title: string
  description: string
  recommendation: string
  source_events: string[]  // IDs of events that triggered this
  server_name: string | null
  created_at: string
  updated_at: string
  resolved_at: string | null
  resolved_by: string | null
  dedup_key: string  // For deduplication
  dedup_count: number  // How many times this pattern appeared
  actions: AlertAction[]  // Clickable actions
  kill_chain: KillChainNarrative | null

AlertStats {
  total_active: number
  dangerous_count: number
  suspicious_count: number
  unusual_count: number
  info_count: number
  resolved_this_week: number
  blocked_this_week: number
  avg_resolution_minutes: number
}
```

#### Fetch Pattern
- `fetchAlerts()`: Command `get_active_alerts_cmd` — loads all active alerts
- `fetchStats()`: Command `get_alert_stats_cmd` — non-critical, silent fail
- `fetchHistory(days)`: Command `get_alert_history_cmd` — past alerts
- No caching — always fresh fetch
- Refresh triggers on: dismiss, resolve, or user initiates

#### Deduplication Strategy
- Alerts with same `dedup_key` within time window count as one
- `dedup_count` shows how many times pattern appeared
- Prevents alert spam (e.g., 100 identical blocks = 1 alert with count=100)

---

### 1.4 conversationStore — AI Chat History & Context

**File:** `/src/stores/conversationStore.ts`

#### Conversation Data
```typescript
conversationId: string | null
messages: ConversationMessage[]
isLoading: boolean
error: string | null

ConversationMessage {
  id: string
  role: "user" | "claw"
  contentText: string
  contentRichJson?: string  // Structured data (alerts, actions)
  actionsJson?: string      // Clickable actions embedded in response
  intentId?: string         // "proactive.alert" for system alerts
  entitiesJson?: string     // Named entities extracted from context
  timestamp: string
}

ConversationSummary {
  id: string
  createdAt: string
  updatedAt: string
  summary?: string
  messageCount: number
  lastMessagePreview?: string
}
```

#### Context Tracking
```typescript
currentPage: string | null     // e.g., "/alerts"
lastServer: string | null      // e.g., "fs-server"
lastEvent: string | null       // e.g., event_id of last viewed event
lastEntities: Record<string, string>  // Custom entities the user cares about

getContextJson(): string  // Returns all context as JSON for API calls
```

**Usage:** When user asks Claw a question, context is sent so AI knows:
- Which page they're on
- Which server/event they were last viewing
- Custom tracked entities

#### Conversation Lifecycle
- `loadLatestConversation()`: Auto-loads last conversation on app startup
- `startNewConversation()`: Creates blank conversation
- `addUserMessage(text)`: Optimistic local add, persisted to backend
- `addClawResponse(msg)`: AI response added to conversation
- `listConversations(limit: 50)`: Lists all past conversations
- `deleteConversation(id)`: Removes conversation
- `searchConversations(query)`: Full-text search

#### Proactive Alerts
```typescript
injectAlert(text, richJson?, actionsJson?): Promise<void>
```

Backend can push alerts directly into conversation (e.g., "Threat detected on fs-server").
These appear as `claw` messages with `intentId: "proactive.alert"`.

---

### 1.5 serverStore — MCP Server Status

**File:** `/src/stores/serverStore.ts`

#### Server Data
```typescript
servers: ServerInfo[]
hasNewUnwrapped: boolean
_fetchedAt: number  // TTL tracking

ServerInfo {
  name: string
  clientName: string
  wrapped: boolean
  status: string
  eventCount: number
  trustLevel?: string
  anomalyScore?: number
}
```

#### Fetch Pattern
- Command: `invoke("detect_mcp_clients")` → find all MCP clients
- For each client: `invoke("list_mcp_servers", { clientName })`
- TTL: **30 seconds**
- Updates `hasNewUnwrapped` flag (true if any server.wrapped === false)

#### Data Implication
- Users see which servers are protected (wrapped) vs. unmonitored
- Badge shows "2 unwrapped servers" to prompt wrapping action

---

## 2. DATA FLOW PER PAGE

### 2.1 Home / Dashboard

**File:** `/src/pages/Home.tsx`

**Data Needed:**
- Protection score + history (for sparkline)
- Recent events (last 10)
- Active alerts (summary counts)
- Server count (total, wrapped, unwrapped)
- Today's stats (event count, blocked count)

**Load Pattern:**
1. On mount: `appStore.fetchScore()`, `appStore.fetchScoreHistory()`
2. Real-time: Listen to `clawdefender://humanized-event` and `clawdefender://intelligent-alert`
3. Subscribe to eventStore, alertStore

**Loading States:**
- Score loading: Show skeleton or spinner in score box
- Events: Optimistic UI (can be empty)
- Alerts: Batch loading, no separate loading state

**Empty State:**
- All zeros / no events → "All quiet so far. I am watching your AI tools."

---

### 2.2 Activity / Event Timeline

**File:** `/src/pages/Activity.tsx`

**Data Needed:**
- All events from eventStore
- Grouped + humanized
- Filtering: by server, risk level, status, search

**Load Pattern:**
1. On mount: Preload score (for context)
2. Real-time: Event stream (already in eventStore)
3. Optional: Full refresh from backend if stale

**Grouping:** `eventGrouper.ts` groups events by:
- Time period (right_now, earlier_today, yesterday, this_week, older)
- Then by: server + tool + action + path prefix within 30s window
- Special: Kill chains grouped by `kill_chain_id`
- Special: Prompt sequences grouped if prompt + outcome within 60s

**Filter Logic:**
```
Available filters:
- Search (text across server, tool, action, resource, details)
- Server (multi-select)
- Status (allowed, blocked, prompted)
- Risk (dangerous, suspicious, unusual)
- onlyNotable (toggle)
```

**Virtual Scrolling:**
- 10,000 event max
- Groups render, not individual events (keeps DOM lean)
- Each group is collapsible to show children

**Empty State:**
- No events → "Nothing here yet. This is where you will see a live feed..."

---

### 2.3 Alerts Page

**File:** `/src/pages/Alerts.tsx`

**Data Needed:**
- Active alerts (always fresh)
- Alert stats
- Filters: severity, status, type
- Recent resolved alerts

**Load Pattern:**
1. On mount: `alertStore.fetchAlerts()` + `fetchStats()`
2. Real-time: `clawdefender://intelligent-alert` listener
3. Refresh: User manually, or every N seconds

**Sorting:**
- Primary: severity (dangerous → suspicious → unusual → info)
- Secondary: recency (newer first)

**Actions:**
- `dismissAlert(id)` — removes from view
- `resolveAlert(id, resolution)` — marks resolved
- `dismissAll(maxSeverity)` — batch dismiss (e.g., dismiss all "unusual" and below)

**Empty State:**
- No alerts → "No threats detected. That is a good thing."

**Stats Display:**
- Counts by severity, resolved this week, blocked this week, avg resolution time

---

### 2.4 Ask Claw (Conversation AI)

**File:** `/src/pages/AskClaw.tsx`

**Data Needed:**
- Current conversation (messages)
- All past conversations (for sidebar list)
- Search results from conversation search
- Context (current page, last event, entities)

**Load Pattern:**
1. On mount: `conversationStore.loadLatestConversation()`
2. On user message: `addUserMessage(text)` → optimistic update + API call
3. AI responds: `addClawResponse(msg)` + persist
4. On tab switch: Update `currentPage` in context

**Context Sent to AI:**
```json
{
  "conversationId": "conv-123",
  "currentPage": "/alerts",
  "lastServer": "fs-server",
  "lastEvent": "evt-456",
  "lastEntities": { "custom_key": "value" },
  "messageCount": 42
}
```

**Empty State:**
- First time: Show greeting + suggestions
- After question: Context-aware suggestions ("What happened today?", "Show me threats", etc.)

---

### 2.5 My Tools / Server Management

**File:** `/src/pages/MyTools.tsx`

**Data Needed:**
- Server list (from serverStore)
- Per-server details: trust level, event count, behavioral status
- Wrap status + new server flag

**Load Pattern:**
1. On mount: `serverStore.fetchServers()`
2. Real-time: Trust level changes, new servers detected
3. TTL: 30 seconds

**Per-Server Card (ToolCardData):**
```typescript
server_name: string
client_name: string
client_app: string
is_wrapped: boolean
trust_level: TrustLevel  // "trusted" | "standard" | "cautious" | "restricted"
trust_customized: boolean
behavioral_status: string
learning_progress: number  // 0-100 (%)
event_count_today: number
blocked_count_today: number
last_unusual_activity: string | null
anomaly_score_current: number
capabilities: ServerCapabilities
health_warnings: HealthWarning[]
guard_name: string | null
guard_enabled: boolean | null
scan_status: string | null
scan_findings_count: number | null
```

**Empty State:**
- No servers: "No servers connected. I protect AI tools by wrapping their MCP servers."

---

### 2.6 Settings Page

**File:** `/src/pages/Settings.tsx`

**Data Needed:**
- App settings (persisted)
- Daemon version
- Network extension status
- Model status (SLM download progress)
- Telemetry status

**Load Pattern:**
- Settings load from persistent storage
- Daemon info fetched on mount
- Model status polled during download

---

### 2.7 System Health / Doctor

**File:** `/src/pages/SystemHealth.tsx`

**Data Needed:**
- Doctor checks (pass/warn/fail)
- System info (OS, arch, versions)
- Network extension status
- FDA status
- Model status

**Load Pattern:**
1. On mount: Fetch all checks
2. Polling: For in-progress checks (scan, download)

---

## 3. LOADING PATTERNS & INDICATORS

### 3.1 Page-Level Loading

| Page | Trigger | Indicator | Timeout |
|------|---------|-----------|---------|
| Home | Score fetch | Skeleton in score box | 5s |
| Activity | Events (streaming) | Optimistic, no indicator | N/A |
| Alerts | Alert fetch | Loading state → list | 5s |
| Ask Claw | Load conversation | Spinner in messages | 5s |
| My Tools | Server detect | Spinner in card list | 10s |
| Settings | App init | Lazy load, no indicator | N/A |

### 3.2 Caching Layers

**appStore (Protection Score):**
- TTL: 30 seconds
- Bypass: Pass `force: true`
- Miss behavior: Keeps stale data silently

**serverStore:**
- TTL: 30 seconds
- Miss behavior: Keeps stale data

**alertStore:**
- No cache — always fresh
- But batch updates (every ~100ms)

**eventStore:**
- Real-time streaming with 100ms batch
- No cache invalidation (streaming data)

**conversationStore:**
- Not cached — loaded on demand
- Recent conversation auto-loaded on startup

### 3.3 Error Handling

**Silent Failures (data-critical):**
- Score fetch fails → keep previous score
- History fetch fails → no sparkline data
- Alert fetch fails → keep previous alerts

**Error Toasts (user-facing):**
- Server detect fails → show "Could not detect servers" banner
- Conversation load fails → "Could not load conversation"
- Tauri IPC errors → "Something went wrong" generic error

---

## 4. REAL-TIME UPDATES & SUBSCRIPTIONS

### 4.1 Tauri Event Listeners

**notificationRouter.ts** sets up listeners:

```
clawdefender://humanized-event
  → eventStore.addEvent()
  → notificationRouter routes by severity

clawdefender://intelligent-alert
  → alertStore receives
  → notificationRouter routes

clawdefender://prompt
  → eventStore.addPrompt()
  → PromptQueue renders

clawdefender://status-change
  → appStore.setDaemonStatus()
```

### 4.2 Real-Time Behavior

**Events:**
- Arrive every millisecond (fast)
- Batched every 100ms
- Prepended to eventStore.events
- Max 10,000 cap enforced

**Alerts:**
- Arrive less frequently (backend generates on pattern detection)
- Immediately added to alertStore
- Trigger notifications based on severity

**Prompts:**
- High priority (block until resolved)
- Timeout: `timeout_seconds` (usually 30s)
- Auto-block if timeout expires

**Status:**
- Rare (daemon start/stop)
- Immediate UI update

---

## 5. OFFLINE / DISCONNECTED BEHAVIOR

### 5.1 Connection States

```
appStore.connectionState:
  "connected"    — All features work
  "reconnecting" — UI grayed, error banner shown
  "disconnected" — Retry dialog, limited functionality
```

### 5.2 Offline Capabilities

**Still Works:**
- View past events (in memory)
- View past alerts (in memory)
- View conversation history
- Read protection score (cached)

**Doesn't Work:**
- New events won't arrive
- Can't send prompts
- Can't save new conversation messages
- Can't fetch fresh data (scores, servers)

### 5.3 Reconnection

- Auto-retry every 3-5s
- Show spinner in status bar
- Clear error once reconnected

---

## 6. USER PREFERENCES & PERSISTENCE

### 6.1 Local Storage

**AppSettings (persisted to disk):**
```typescript
{
  theme: "dark" | "light" | "system"
  notifications_enabled: boolean
  auto_start_daemon: boolean
  minimize_to_tray: boolean
  log_level: "trace" | "debug" | "info" | "warn" | "error"
  prompt_timeout_seconds: number
  event_retention_days: number
  behavioral_auto_block: boolean
  behavioral_threshold: number
  analysis_frequency: string
  security_level: string
}
```

**Zustand Store Persistence:**
- appStore: sidebar collapsed state
- conversationStore: current conversation + context
- Others: Not persisted (ephemeral)

### 6.2 Synced State

**Conversation Context** (cross-page):
- Current page tracked in conversationStore
- Last viewed server/event
- Custom entities user tagged
- Sent with every Claw question

---

## 7. EVENT BATCHING & PERFORMANCE

### 7.1 Event Batch Mechanics

**Batch Accumulator:**
```
Raw events arrive (per millisecond)
→ enqueueBatchedEvent()
→ pendingBatch[] accumulates
→ Timer fires after 100ms
→ flushBatch() to store
→ React re-render once per batch
```

**Benefits:**
- 1000 events/sec → 10 batches/sec (vs. 1000 re-renders)
- Reduced DOM churn
- Smooth scrolling in Activity view

**Max Capacity:**
- Ring buffer: 10,000 events max
- Older events dropped when limit hit
- `todayEventCount` + `todayBlockedCount` track summary

### 7.2 Grouping Performance

**eventGrouper.ts** processes 10,000 events in < 1s:
1. Partition by time period
2. Extract kill chains by ID
3. Extract prompt sequences
4. Cluster remaining by (server, tool, action, path_prefix)
5. Generate summary text

**Cost:** O(n) with small constant factors

---

## 8. DATA TYPE SHAPES & ENUMS

### 8.1 Risk Levels

**Backend:** `"low"` | `"medium"` | `"high"` | `"critical"`
**Frontend:** `"dangerous"` | `"suspicious"` | `"unusual"` | `"normal"` | `"blocked"` | `"info"`

**Mapping:**
```
critical → dangerous
high → suspicious
medium → unusual
low → normal
blocked (action) → "blocked"
info (special) → "info"
```

**Threshold Scoring:**
- anomalyScore >= 0.9 → dangerous
- anomalyScore >= 0.7 → suspicious
- anomalyScore >= 0.4 → unusual
- anomalyScore < 0.4 → normal

### 8.2 Alert Severity

`"dangerous"` | `"suspicious"` | `"unusual"` | `"info"`

Notification Priority Matrix:
| Severity | Priority | UI |
|----------|----------|-----|
| dangerous | prompt_with_sound | Modal + beep |
| suspicious | prompt | Modal |
| unusual | banner | Slide-in 8s |
| info | in_feed | Timeline only |

### 8.3 Trust Levels

`"trusted"` | `"standard"` | `"cautious"` | `"restricted"`

Per server, determines:
- Default action (allow/prompt/block)
- Learning vs. monitoring mode
- Guard activation

### 8.4 Decision Types

Raw: `"allow"` | `"block"` | `"deny"` | `"prompt"` | `"allowed"` | `"blocked"` | `"prompted"` | `"denied"`
Normalized: `"allowed"` | `"blocked"` | `"prompted"`

**Rendered Labels:**
- Allowed → "Allowed"
- Blocked → "Blocked"
- Prompted → "Awaiting your decision"
- AutoBlocked → "Auto-blocked"

### 8.5 Action Types

```
Tool calls: read_file, write_file, run_command, fetch, sample_llm, etc.
System actions: network_connection, process_spawn, etc.
```

---

## 9. EMPTY VS. POPULATED STATES

### State Conditions by Page

| Page | Empty Condition | Partial Condition | Populated Condition |
|------|---|---|---|
| Home | No events, no alerts, score=0 | Some data but incomplete | Full dashboard |
| Activity | eventStore.events.length === 0 | Some events, no notable | Full feed, grouped events |
| Alerts | alerts.length === 0 && stats.total === 0 | Some low-severity | High/dangerous alerts |
| Ask Claw | No messages + first time | Some messages | Active conversation |
| My Tools | servers.length === 0 | Some unwrapped | All servers wrapped |
| System Health | All checks failing | Some warnings | All checks passing |

### Empty State Messages (constants/messages.ts)

```
dashboard: "All quiet so far..."
activity: "Nothing here yet..."
alerts: "No threats detected. That is a good thing."
myTools: "No servers connected..."
askClaw: "Hey. I'm Claw. Ask me anything..."
```

---

## 10. CONVERSATION CONTEXT & AI KNOWLEDGE

### 10.1 Context Available to AI

When user asks Claw a question:

```json
{
  "conversationId": "uuid",
  "currentPage": "/alerts",
  "lastServer": "fs-server",
  "lastEvent": "evt-12345",
  "lastEntities": {
    "selected_alert_id": "alert-abc",
    "filter_server": "fs-server"
  },
  "messageCount": 15
}
```

### 10.2 AI Response Structure

```typescript
ConversationMessage {
  role: "claw"
  contentText: string  // Plain text answer
  contentRichJson?: {
    sections: [
      {
        title: "What happened",
        content: "..."
      }
    ]
  }
  actionsJson?: {
    buttons: [
      {
        label: "View event",
        action: "navigate",
        target: "/activity?event=evt-12345"
      }
    ]
  }
}
```

---

## 11. NOTIFICATION & ALERT ROUTING (notificationRouter.ts)

### Priority System

1. **Prompt (Highest):** User must answer
2. **Dangerous Alert:** macOS notification + in-app alert card
3. **Suspicious Alert:** macOS notification
4. **Auto-Blocked Event:** Toast (suppressed if on Activity page)
5. **Info Alert:** Toast (suppressed if on Alerts page)
6. **Normal Events:** Silent (feed only)

### Rate Limiting

```
If > 10 events in 5s window:
  Suppress individual toasts
  Show single "A lot is happening right now" batch toast
  Link to Activity page
```

### Window Focus

- If window focused: Don't send macOS notifications
- Suppress duplicate notifications (rate window)

---

## 12. DATA MUTATION PATTERNS

### Optimistic Updates

**Conversations:**
```
User sends message
→ addUserMessage() → optimistic add to state
→ await invoke('save_conversation_message')
→ If fails, error toast but local state kept
```

**Prompts:**
```
User clicks "Allow"
→ removePrompt() → immediate UI removal
→ await invoke('resolve_prompt')
→ If fails, could re-add (not implemented)
```

### Pessimistic Updates

**Alerts:**
```
User clicks "Dismiss"
→ await invoke('dismiss_alert_cmd')
→ Only then: fetchAlerts() → reload all
```

**Servers:**
```
User wraps server
→ await invoke('wrap_mcp_server')
→ Only then: fetchServers() → reload list
```

---

## 13. FAILURE RECOVERY

### Automatic Retries

**None implemented** — single attempt per user action

### Manual Retries

User must explicitly:
- Click "Retry" button on error toast
- Refresh page
- Close and reopen sidebar/modal

### Graceful Degradation

| Component | Failure | Fallback |
|-----------|---------|----------|
| Score history | Fetch fails | No sparkline, show "—" |
| Alert fetch | Times out | Keep previous alerts |
| Server detect | Permission denied | Show error, suggest fix |
| Conversation load | Corrupted JSON | Show error toast |

---

## 14. PERFORMANCE IMPLICATIONS FOR UX

### Smooth Features

- **Activity Timeline:** Groups + virtual scroll handle 10k events
- **Event Batching:** 100ms flush prevents jank
- **Real-time:** No polling, event-driven

### Potential Jank

- **Score Fetch:** 30s TTL, sync call blocks briefly
- **Alert Load:** Full re-fetch on every dismiss (N alerts)
- **Server Detect:** 30s TTL + backend detection latency

### Memory Limits

- **Max Events:** 10,000 (ring buffer)
- **Event Strings:** Could grow unbounded if event descriptions large
- **Conversation Messages:** No hard limit (could grow with long chats)

---

## 15. SUMMARY TABLE: WHAT TO DESIGN FOR

| Aspect | Key Detail | UX Implication |
|--------|-----------|-----------------|
| **Daemon Disconnection** | Real-time, shows `reconnecting` state | Spinner + "trying to reconnect" message |
| **Score Loading** | 30s cache, silent fail | May show stale score, show timestamp |
| **Event Stream** | 100ms batches, 10k max | Smooth scrolling, old events drop silently |
| **Alerts** | No cache, always fresh | "Refreshing..." on dismiss, then reload |
| **Conversations** | Optimistic user message add | Message appears immediately |
| **Prompts** | High priority, timeout 30s | Modal overlay, countdown timer |
| **Empty States** | Per-page conditions | Show helpful CTA (e.g., "Scan for Tools") |
| **Rate Limiting** | 10+ events/5s → batch toast | Single notification, link to Activity |
| **Offline** | Connection state visible | Gray out interactive features |
| **Context Tracking** | Page + event + entities | Claw remembers what you were looking at |

---

## 16. CONSTANTS & MAGIC NUMBERS

**File:** `/src/constants/messages.ts`

### TTL & Timings
- SCORE_TTL_MS: 30 seconds
- SERVER_TTL_MS: 30 seconds
- BATCH_INTERVAL_MS: 100 milliseconds (event batching)
- GROUP_WINDOW_MS: 30 seconds (event clustering)
- RATE_WINDOW_MS: 5 seconds (notification batching)
- RATE_THRESHOLD: 10 events (trigger batch notification)
- FIVE_MINUTES: 5 * 60 * 1000 (time period cutoff)
- DEDUP_WINDOW_MS: 5 minutes (alert deduplication)
- MAX_EVENTS: 10,000 (ring buffer limit)
- PROMPT_TIMEOUT_SECONDS: 30 (default)

### Notification Messages

See `/src/constants/messages.ts` for:
- NOTIFICATION_BATCH — "A lot is happening right now"
- PROMPT_ACTIONS_LOW_RISK — Allow/Block options
- PROMPT_ACTIONS_HIGH_RISK — Block/Allow swapped (block default)
- PROMPT_TIMEOUT_MESSAGE — "No response — I blocked this for now"
- EMPTY_STATES — Per-page empty state text
- ERROR_MESSAGES — Error toast text with CTA
- THREAT_LEVEL_INFO — Threat level descriptions

---

## 17. NEXT STEPS FOR UX

### Design Gaps to Address

1. **Score Stale Data Warning:** Show timestamp, "Last updated 2m ago"
2. **Alert Refresh Feedback:** Loading spinner during re-fetch
3. **Event Overflow:** How to indicate 10k cap reached? (e.g., badge "Older events dropped")
4. **Disconnection UX:** Clearer messaging on reconnecting state
5. **Conversation Context Visual:** Show which page/server context was sent with question
6. **Prompt Timeout Countdown:** Visual timer on prompt modal
7. **Empty State CTAs:** Make "Scan for Tools" etc. actionable (not just text)

### Recommended Patterns

1. **Skeleton Loading:** Score, alerts, server list while fetching
2. **Stale Data Badges:** Show "Last updated 5m ago" for cached data
3. **Batch Notifications:** "12 events just happened" with action link
4. **Rate Limit Feedback:** "Filtering notifications" spinner during burst
5. **Context Breadcrumbs:** "Asking about Activity page > fs-server"
6. **Auto-Refresh Indicators:** Pulse or badge showing data auto-refreshed

---

## Appendix: File Quick Reference

| File | Responsibility |
|------|---|
| `/src/stores/appStore.ts` | Daemon status, scores, guidance |
| `/src/stores/eventStore.ts` | Event stream, batching, prompts |
| `/src/stores/alertStore.ts` | Intelligent alerts, stats |
| `/src/stores/conversationStore.ts` | Chat history, context |
| `/src/stores/serverStore.ts` | MCP server list |
| `/src/services/notificationRouter.ts` | Real-time event routing |
| `/src/constants/messages.ts` | All user-facing strings |
| `/src/utils/threatLevel.ts` | Score-to-level mapping |
| `/src/utils/eventGrouper.ts` | Event clustering logic |
| `/src/utils/alertGenerator.ts` | Alert generation & dedup |
| `/src/types/index.ts` | All data type definitions |

---

**End of Document**
