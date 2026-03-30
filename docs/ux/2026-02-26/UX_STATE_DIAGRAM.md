# ClawDefender Data & State Diagram

Visual reference for data flow and state management.

---

## 1. STORE DEPENDENCY GRAPH

```
┌─────────────────────────────────────────────────────────────┐
│                      Tauri IPC Layer                         │
│  (invoke commands + listen event listeners)                  │
└─────────────────────────────────────────────────────────────┘
          ↓                    ↓                    ↓
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   appStore       │  │   eventStore     │  │  alertStore      │
│  - daemon status │  │  - events (10k)  │  │  - alerts        │
│  - connection    │  │  - prompts       │  │  - stats         │
│  - scores (TTL)  │  │  - today counts  │  │  - loading flag  │
│  - guidance      │  │  - batching 100ms│  │                  │
└──────────────────┘  └──────────────────┘  └──────────────────┘
          ↓                    ↓                    ↓
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ conversationStore │  │  serverStore     │  │  Notification    │
│  - messages      │  │  - servers list  │  │  Router          │
│  - context       │  │  - wrapped flags │  │  (rating limits) │
│  - conversation  │  │  - trust levels  │  │                  │
│    ID            │  │  - TTL 30s       │  │                  │
└──────────────────┘  └──────────────────┘  └──────────────────┘
          ↓                    ↓                    ↓
┌──────────────────────────────────────────────────────────────┐
│                    React Components                           │
│  (Home, Activity, Alerts, AskClaw, MyTools, Settings)        │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. REAL-TIME EVENT FLOW

```
Backend Daemon
     ↓
     ├→ emit clawdefender://humanized-event
     │   ↓
     │   eventStore.addEvent() or addRawEvent()
     │   ↓
     │   Batch Accumulator (100ms)
     │   ↓
     │   useEventStore.setState() → React re-render once
     │   ↓
     │   Events prepended to list (LIFO)
     │   ↓
     │   Activity page subscribers notified
     │
     ├→ emit clawdefender://intelligent-alert
     │   ↓
     │   alertStore receives
     │   ↓
     │   notificationRouter routes by severity
     │   ├→ dangerous   → macOS notification + modal alert
     │   ├→ suspicious  → macOS notification
     │   ├→ unusual     → in-app banner 8s
     │   └→ info        → timeline only
     │
     ├→ emit clawdefender://prompt
     │   ↓
     │   eventStore.addPrompt()
     │   ↓
     │   PromptQueue renders modal
     │   ↓
     │   User responds or timeout (30s)
     │   ↓
     │   removePrompt() + event logged
     │
     └→ emit clawdefender://status-change
         ↓
         appStore.setConnectionState()
         ↓
         Connection indicator updates
```

---

## 3. PAGE DATA LOADING SEQUENCE

### Home/Dashboard (On Mount)
```
1. [Parallel]
   - appStore.fetchScore() [TTL 30s, 30s max stale]
   - appStore.fetchScoreHistory() [TTL 30s]
   - subscribeToEventStore() [real-time]
   - subscribeToAlertStore() [real-time]
   - subscribeToServerStore() [already cached]

2. [Result] Show skeleton while score loads
           Show cached data + real-time updates

3. [Error] Keep stale data, silently fail
```

### Activity Timeline (On Mount)
```
1. eventStore already populated from real-time stream
2. groupEvents() on render (every 100ms batch)
3. Apply filters (server, status, risk, search, notable)
4. Render groups (time periods as sections)
5. Virtualize long lists

[Real-time] New events arrive every 100ms → re-group → re-render
```

### Alerts (On Mount)
```
1. [Serial]
   - alertStore.fetchAlerts() [no cache]
   - alertStore.fetchStats() [non-critical]

2. [Parallel]
   - subscribeToAlertStore() [real-time updates]
   - listen clawdefender://intelligent-alert

3. [Result] Show loading spinner
           Update counts & list on arrival
           Apply sorting (severity → recency)

4. [User Action]
   - dismissAlert(id) → fetchAlerts() again
   - resolveAlert(id, reason) → fetchAlerts() again
```

### Ask Claw (On Mount)
```
1. conversationStore.loadLatestConversation() [auto-load]

2. [If empty]
   Show empty state with suggestions

3. [On user message]
   - addUserMessage(text) [optimistic add]
   - await invoke('save_conversation_message')
   - [If fails] error toast but keep local message

4. [On AI response]
   - addClawResponse(msg) [add to messages]
   - persist in background

5. [Context updates]
   On page change → setCurrentPage()
   On event click → setLastEvent()
   On server click → setLastServer()
   → All sent with next question
```

### My Tools (On Mount)
```
1. serverStore.fetchServers() [TTL 30s]
   - invoke detect_mcp_clients
   - For each client: invoke list_mcp_servers
   - Update hasNewUnwrapped flag

2. [Result] Show spinner
           Display servers + wrapped status
           Show badge if unwrapped

3. [No cache miss] Re-fetch every 30s auto
```

---

## 4. CACHING TTL TIMELINE

```
Time →
App starts

0s ┌─ appStore.fetchScore() ─────────────────────────┐ [max 30s]
   │ _scoreFetchedAt = 0                              │
   │                                                   │
5s │ User visits Home → score cached + display         │
   │                                                   │
25s│ Still cached, no re-fetch                         │
   │                                                   │
30s└─ TTL expired, stale ────────────────────────────┘
   │ Next page view triggers new fetch
   │ Meanwhile: show stale score with "updated 30s ago"
   │
35s│ New score arrives → update + refresh timestamp
   │
60s│ TTL expired again ───────────────────────────────
   │
70s│ User force-refreshes → invoke fetch with force=true
   └──────────────────────────────────────────────────
```

---

## 5. EVENT BATCHING TIMELINE

```
Backend sends events:
t=1000ms: event-1 → pendingBatch[0]
t=1005ms: event-2 → pendingBatch[1]
t=1010ms: event-3 → pendingBatch[2]
         ... [up to 100 per second] ...
t=1080ms: batchTimer fires
         ↓
         flushBatch() → pendingBatch has [event-1..event-N]
         ↓
         useEventStore.setState({
           events: [event-N, ..., event-1, ...previous],
           todayEventCount += N,
           todayBlockedCount += blocked_count
         })
         ↓
         React re-render (1 render for ~80 events)
         ↓
         Activity page updates with grouped events
         ↓
         [Start new batch timer]
```

**Benefit:** 1000 events/sec → 10 batches/sec → smooth UI

---

## 6. ALERT GENERATION & DEDUP FLOW

```
Raw event arrives (e.g., SSH key read attempt)
     ↓
Backend generates IntelligentAlert
     ↓
Backend emits clawdefender://intelligent-alert
     ↓
alertStore.alerts ← new alert
     ↓
dedupKey = "fs-server:read_file"
     ↓
Is there a recent alert with same dedupKey?
     ├→ YES: dedup_count++, updated_at = now [NO new alert]
     └→ NO: add as new alert with dedup_count=1
     ↓
notificationRouter routes by severity
     ├→ dangerous → macOS notification
     ├→ suspicious → macOS notification
     ├→ unusual → banner
     └→ info → silent
     ↓
Alerts page updates in real-time
```

**Result:** Identical patterns within time window = 1 alert with count

---

## 7. GROUPING ALGORITHM (Events)

```
Input: HumanizedEvent[] (LIFO, max 10,000)

Step 1: Partition by TimePeriod
        right_now [<5m]
        earlier_today [today but >5m]
        yesterday
        this_week [7 days]
        older [>7 days]
          ↓

Step 2: For each period, extract special groups
        Kill chains (by kill_chain_id)
        Prompt sequences (prompt + outcome <60s, same server)
        Remaining events
          ↓

Step 3: Cluster remaining by key
        key = server + tool + action + pathPrefix
        window = 30s
        If 2+ events match key within 30s → grouped
        If 1 event → single
          ↓

Step 4: Generate summary text
        "fs-server read 5 files in ~/project"
        "You were asked about net-server and blocked it"
        "Threat story: code-server attempted credential theft — 2 blocked"
          ↓

Output: EventGroup[]
        [
          { type: "kill_chain", period: "right_now", count: 3, ... },
          { type: "grouped", period: "right_now", count: 5, ... },
          { type: "prompt_sequence", period: "earlier_today", count: 2, ... },
          ...
        ]
```

---

## 8. CONNECTION STATE MACHINE

```
                      ┌─────────────────────┐
                      │    disconnected     │
                      │  (gray icon)        │
                      │  [Error banner]     │
                      └─────────────────────┘
                             ↑
                             │ daemon.running = false
                             │
                    ┌────────┴────────┐
                    │                 │
               [Init]              [Stop]
                    │                 │
                    ↓                 │
            ┌─────────────────────┐  │
            │  reconnecting       │──┘
            │  (spinner in status)│
            │  [Reconnecting msg] │
            └─────────────────────┘
                    ↑
                    │ daemon.running = true
                    │
                    ↓
            ┌─────────────────────┐
            │  connected          │
            │  (green icon)       │
            │  [All features OK]  │
            └─────────────────────┘
                    ↓
               [IPC fail]
               [timeout]
                    ↓
            back to reconnecting
```

---

## 9. NOTIFICATION ROUTING DECISION TREE

```
Event/Alert arrives
    ↓
    ├─ Is it a prompt?
    │  └→ YES: PromptQueue renders modal [HIGHEST PRIORITY]
    │
    ├─ Is alert severity "dangerous"?
    │  └→ YES:
    │     ├→ If window NOT focused:
    │     │  └→ macOS notification (with sound)
    │     └→ AlertWindow in NotificationLayer (in-app)
    │
    ├─ Is alert severity "suspicious"?
    │  └→ YES:
    │     ├→ If window NOT focused:
    │     │  └→ macOS notification (no sound)
    │     └→ (silent)
    │
    ├─ Is event action_taken "AutoBlocked"?
    │  └→ YES:
    │     ├→ If currentVisiblePage === "activity":
    │     │  └→ SUPPRESS (already visible)
    │     └→ Toast (5s) with review link
    │
    ├─ Is alert severity "info"?
    │  └→ YES:
    │     ├→ If currentVisiblePage === "alerts":
    │     │  └→ SUPPRESS (already visible)
    │     └→ Toast (8s)
    │
    └─ Otherwise:
       └→ Silent (timeline entry only)

[Rate Limiting Check]
If > 10 events in 5s window:
  └→ Suppress individual toasts
  └→ Show batch notification: "A lot is happening now"
  └→ Link to Activity page
```

---

## 10. CONVERSATION CONTEXT FLOW

```
User navigates app
     ↓
conversationStore tracks:
  - currentPage: "/alerts" → setCurrentPage()
  - lastEvent: "evt-123" → setLastEvent()
  - lastServer: "fs-server" → setLastServer()
  - lastEntities: { "alert_id": "alert-abc" } → updateEntities()
     ↓
User asks Claw a question
     ↓
addUserMessage(text) → optimistic add to UI
     ↓
Prepare API call with context:
  {
    "conversationId": "conv-xyz",
    "currentPage": "/alerts",
    "lastServer": "fs-server",
    "lastEvent": "evt-123",
    "lastEntities": { "alert_id": "alert-abc" },
    "messageCount": 42
  }
     ↓
invoke('send_conversation_message', { text, context })
     ↓
AI backend receives context
     ↓
AI generates contextual response
  "I see you're on the Alerts page and looking at fs-server.
   That event shows a suspicious pattern..."
     ↓
addClawResponse(msg) → add to messages
     ↓
User sees response + context-aware suggestions:
  ["Show me more about fs-server", "What else has it done?", "Block this server"]
```

---

## 11. EMPTY STATE CONDITIONS

```
Page              Condition for Empty              Message
─────────────────────────────────────────────────────────────
Home              No events + no alerts + score=0   "All quiet so far..."
Activity          events.length === 0               "Nothing here yet..."
Alerts            alerts.length === 0 +             "No threats detected..."
                  stats.total === 0
Ask Claw          messages.length === 0 +           "Hey. I'm Claw..."
                  isFirstTime
My Tools          servers.length === 0              "No servers connected..."
System Health     allChecks.fail                    [Show doctor checks list]
Scanner           noScans                           "No scans yet..."
Guards            guards.length === 0               "No guards active..."
```

---

## 12. OFFLINE STATE IMPACT MATRIX

```
Feature                Online    Reconnecting    Offline
────────────────────────────────────────────────────────
View cached events     ✓         ✓              ✓
View cached score      ✓         ✓              ✓
View conversations     ✓         ✓              ✓
─────────────────────────────────────────────────────────
Receive new events     ✓         ✗              ✗
Receive alerts         ✓         ✗              ✗
Receive prompts        ✓         ✗              ✗
Respond to prompts     ✓         ✗              ✗
─────────────────────────────────────────────────────────
Fetch fresh data       ✓         [retrying]     [queued]
Save messages          ✓         ✗              [queued]
Interact with UI       ✓         [limited]      [limited]
─────────────────────────────────────────────────────────
```

---

## 13. PERFORMANCE BUDGET TIMELINE

```
Page Load
0ms  ┌─ Render skeleton
     │
100ms ├─ Show cached data
      │
300ms ├─ Fetch network requests initiated
      │
1000ms├─ [TARGET] All data loaded, spinner removed
      │
2000ms└─ [TIMEOUT] Show error state / keep stale

Real-time Updates
0ms   ┌─ Event arrives
      │
100ms ├─ [Batched] Accumulate with others
      │
200ms ├─ [Batched] Flush to store
      │
250ms └─ [TARGET] Re-render complete, smooth

Grouping (10k events)
0ms   ┌─ groupEvents() called
      │
500ms ├─ [50% done] Partition + clustering
      │
1000ms└─ [TARGET] Groups ready, render (should be < 1s)
```

---

## 14. SYNC WATERFALL

```
[User clicks "Dismiss Alert"]
     ↓ invoke('dismiss_alert_cmd', { alertId })
     ├─ Backend removes alert
     └─ [Wait for response]
     ↓
[Backend responds: success]
     ↓ alertStore.fetchAlerts() [reload all]
     ├─ [Network round trip 200-500ms]
     ├─ Backend queries DB
     └─ [Wait for response]
     ↓
[New alert list arrives]
     ↓ useAlertStore.setState({ alerts })
     ├─ React re-render
     ├─ Alerts page updates
     ├─ Stats update
     └─ [Total round trip: ~1s]
     ↓
[Done] Alert no longer visible
```

**Pattern:** Pessimistic (wait for response, then reload)

---

## 15. SHARED VS. UNIQUE STATE

```
appStore (Global)
  └─ daemonStatus (shared across all pages)
  └─ connectionState (shown in header)
  └─ protectionScore (displayed everywhere)
  └─ guidanceHints (shown inline on pages)

eventStore (Global)
  └─ events (shared by Activity, Home, Ask Claw context)
  └─ pendingPrompts (shown in PromptQueue overlay)
  └─ todayEventCount (badge on Activity icon)

alertStore (Global)
  └─ alerts (shown on Alerts page)
  └─ stats (shown on Alerts + Home)

conversationStore (Global)
  └─ messages (Ask Claw page only)
  └─ context (sent with questions)

serverStore (Global)
  └─ servers (My Tools page + Home badge)

Page-Level State (Local)
  └─ Filter selections (Activity page)
  └─ Search input (Search modal)
  └─ Modal open/close (Settings page)
  └─ Tab selection (System Health page)
```

---

**End of Diagrams**
