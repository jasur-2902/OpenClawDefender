# Step 9 Performance Baseline Report

Static analysis of the Rookbot Tauri desktop app. Each section identifies the current implementation, bottlenecks, and recommended fixes ranked by impact.

---

## 1. App Launch Analysis

**Target:** < 1s to interactive window.

### Current Implementation

The `run()` function in `src-tauri/src/lib.rs:29-412` performs setup synchronously inside `tauri::Builder::setup()`:

1. `tray::setup_tray()` -- builds tray icon and menu (line 42)
2. `monitor::start_connection_monitor()` -- spawns background thread (line 47)
3. `event_stream::start_event_stream()` -- spawns file-watcher thread (line 50)
4. `score::events::start_score_listeners()` -- registers event listeners (line 53)
5. `tokio::spawn` for MCP tool detection polling (lines 56-73)
6. `daemon::is_daemon_running()` + `daemon::start_daemon_process()` -- **synchronous process check + spawn** (lines 76-91)
7. **SLM model loading** -- `clawdefender_slm::SlmService::new()` loads GGUF model from disk (lines 94-249). This is the **heaviest operation** and runs synchronously in setup, blocking window display.
8. `guidance::triggers::start_guidance_timer()` (line 253)
9. Window close event handler registration (lines 256-265)

### Bottlenecks

| Issue | Severity | Location |
|-------|----------|----------|
| **SLM model loading blocks window** | **HIGH** | `lib.rs:94-249` -- `SlmService::new()` loads a GGUF model (potentially 100s of MB) synchronously during setup. The main window cannot render until `setup()` returns. |
| Daemon auto-start is synchronous | MEDIUM | `lib.rs:76-91` -- `is_daemon_running()` does a process check, `start_daemon_process()` spawns the daemon. Both are blocking. |
| Tray menu builds counts (reads config files) | LOW | `tray.rs:36-104` -- `collect_tray_data()` reads AppState; initial build is lightweight but still runs on setup path. |

### Recommendations

1. **[HIGH] Move SLM loading to a background task.** Spawn `tokio::spawn` or `std::thread::spawn` for the model loading at `lib.rs:94`. Set the `active_slm` state once loading completes. The GUI should show a "Loading AI model..." indicator. This alone could save 2-10+ seconds on startup depending on model size.

2. **[MEDIUM] Move daemon auto-start to a background task.** Wrap lines 76-91 in `tokio::spawn(async move { ... })`. The connection monitor already polls for daemon connectivity, so the GUI doesn't need to block on this.

3. **[LOW] Defer MCP tool detection polling.** The 60s polling at line 56 already has `tokio::time::sleep(60s)` as first operation, so it doesn't block. No change needed.

### Verdict: **FAILS TARGET** -- SLM loading can block startup for several seconds.

---

## 2. Navigation / Route Splitting

### Current Implementation

`src/App.tsx:1-168` imports all page components eagerly at the top of the file:

```tsx
import { Home } from "./pages/Home";
import { AskClaw } from "./pages/AskClaw";
import { MyTools } from "./pages/MyTools";
// ... 10+ more static imports
```

All pages are rendered via `<Routes>` with no `React.lazy()` or code splitting. The entire app is a single JS bundle.

`vite.config.ts` has no `build.rollupOptions.output.manualChunks` configuration.

### Bottlenecks

| Issue | Severity | Location |
|-------|----------|----------|
| **No route-based code splitting** | **HIGH** | `App.tsx:1-18` -- all 13+ pages loaded eagerly in one bundle |
| No manual chunk configuration in Vite | MEDIUM | `vite.config.ts` -- no `build.rollupOptions` |

### Recommendations

1. **[HIGH] Convert page imports to React.lazy() with Suspense.** This is the single biggest frontend performance win. Example:
   ```tsx
   const Home = lazy(() => import("./pages/Home"));
   const Activity = lazy(() => import("./pages/Activity"));
   ```
   Wrap `<Routes>` in `<Suspense fallback={<LoadingSkeleton />}>`.

2. **[MEDIUM] Add Vite manual chunks.** Split vendor libs (react, react-dom, zustand, react-router-dom) into a separate chunk for better caching:
   ```ts
   build: {
     rollupOptions: {
       output: {
         manualChunks: {
           vendor: ['react', 'react-dom', 'react-router-dom', 'zustand'],
         }
       }
     }
   }
   ```

### Verdict: **FAILS TARGET** -- initial JS bundle includes all pages.

---

## 3. Activity Feed / Virtual Scrolling

### Current Implementation

`src/pages/Activity.tsx:62-459` implements **custom virtual scrolling** with:
- `ROW_HEIGHT_ESTIMATE = 52` (line 24)
- `BUFFER_PX = 400` (line 25)
- `scrollTop` / `containerHeight` state tracked via `onScroll` + `ResizeObserver` (lines 247-270)
- Visible window calculated: `startIdx` to `endIdx` with buffer (lines 237-245)
- Absolute positioning with `top: startIdx * ROW_HEIGHT_ESTIMATE` (lines 408-416)

No `@tanstack/react-virtual` or similar library in `package.json`.

### Bottlenecks

| Issue | Severity | Location |
|-------|----------|----------|
| Custom virtual scroll lacks variable-height support | LOW | `Activity.tsx:24` -- fixed `ROW_HEIGHT_ESTIMATE = 52` assumes uniform rows; grouped rows may differ |
| No scroll debouncing | MEDIUM | `Activity.tsx:259-270` -- `handleScroll` fires on every scroll event, calling `setScrollTop()` each time, triggering re-render |
| `filteredEvents` recomputed on every scroll | LOW | Mitigated by `useMemo` (line 136) -- only recomputes when filter deps change |

### Recommendations

1. **[MEDIUM] Throttle scroll handler.** Use `requestAnimationFrame` or a throttle wrapper (16ms) on `handleScroll` to batch scroll updates:
   ```tsx
   const handleScroll = useCallback(() => {
     if (rafRef.current) return;
     rafRef.current = requestAnimationFrame(() => {
       rafRef.current = null;
       // actual scroll handling...
     });
   }, []);
   ```

2. **[LOW] Consider @tanstack/react-virtual for better variable-height support.** The custom implementation works but is fragile with grouped rows that may have different heights.

### Verdict: **MEETS TARGET** -- virtual scrolling is implemented; minor optimizations recommended.

---

## 4. Prompt Window

### Current Implementation

Prompts are **NOT** separate Tauri windows. The `windows.rs:26-43` defines `create_prompt_window()` but it's marked `#[allow(dead_code)]` and never called from `lib.rs`.

Instead, prompts are rendered as an **overlay in the main window** via `NotificationLayer.tsx:98-102`:
```tsx
{hasPrompts && (
  <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
    <PromptContainer />
  </div>
)}
```

The `PromptWindow.tsx` component renders inline. It fires two IPC calls on mount:
1. `get_slm_status` (line 31) -- mock mode check
2. `get_slm_analysis_for_prompt` (line 39) -- AI analysis

### Bottlenecks

| Issue | Severity | Location |
|-------|----------|----------|
| Prompts only visible when main window is visible | MEDIUM | `NotificationLayer.tsx:98` -- if the user minimized the window, they cannot see or respond to the prompt. Native notifications exist but cannot accept responses. |
| `get_slm_analysis_for_prompt` may be slow | MEDIUM | `PromptWindow.tsx:38-49` -- if a real SLM model is loaded, inference could take 1-5+ seconds, during which the user sees a spinner |
| Countdown timer runs at 250ms interval | LOW | `PromptWindow.tsx:72-83` -- 4 updates/second is fine but the `respond` dependency in the effect could cause unnecessary effect re-registrations |

### Recommendations

1. **[MEDIUM] Pre-create a hidden prompt window.** Create a separate Tauri window at startup (hidden), and show it when a prompt arrives. This ensures prompts are visible even when the main window is minimized. The `windows.rs` code already has `create_prompt_window()` ready.

2. **[LOW] Pre-fetch SLM analysis.** When the event_stream detects a "prompted" event, immediately kick off the SLM analysis so it's ready when the PromptWindow renders.

### Verdict: **PARTIALLY MEETS TARGET** -- renders quickly but has visibility concerns.

---

## 5. Event Stream

### Current Implementation

`src-tauri/src/event_stream.rs:513-628`:
- Spawns a **dedicated std::thread** (not tokio) for the polling loop
- Polls `audit.jsonl` file every **500ms** (`POLL_INTERVAL`, line 59)
- Checks file size via `fs::metadata()`, reads only new bytes via `seek()` (lines 573-625)
- Parses JSONL lines, converts to `AuditEvent`, calls `process_event()` for each

Backfill: On startup, reads last 100 lines (`BACKFILL_LIMIT`, line 62) via `read_last_n_lines()` which uses a ring buffer.

### Bottlenecks

| Issue | Severity | Location |
|-------|----------|----------|
| **`process_event` reads config.toml on EVERY event** | **HIGH** | `event_stream.rs:357` calls `notifications_enabled_in_config()` which reads and parses `~/.config/rookbot/config.toml` from disk on every single event. Also called again at line 311 within the same function. |
| **`process_event` clones entire event buffer for alert engine** | **HIGH** | `event_stream.rs:448-452` -- `state.event_buffer.lock().map(\|buf\| buf.clone())` clones up to 10,000 `AuditEvent` objects on every incoming event for the alert intelligence engine. |
| File polling (500ms) vs filesystem watching | LOW | Polling is simple and reliable; `notify` crate would reduce latency but adds complexity. 500ms is acceptable for a security tool. |
| Events processed one-by-one (no batching) | LOW | Each new line triggers a full `process_event()` pipeline. Batching would help during burst traffic. |

### Recommendations

1. **[HIGH] Cache `notifications_enabled_in_config()`.** Read the config once and cache it. Refresh the cache on a timer (e.g., every 30s) or when a settings-change event fires. Currently the function does file I/O + TOML parsing on every single event.
   - File: `event_stream.rs:311-327`
   - Impact: Removes 2 file reads + 2 TOML parses per event

2. **[HIGH] Pass event buffer reference or summary to alert engine instead of full clone.** At minimum, pass a slice reference. If that's not possible due to lock scope, maintain a separate bounded ring buffer for the alert engine that only tracks the last N events' risk levels and timestamps.
   - File: `event_stream.rs:447-474`
   - Impact: Avoids cloning up to 10,000 structs (each with multiple String fields) on every event

3. **[LOW] Batch events during burst processing.** Collect all new lines in a single poll cycle, then process them together to reduce per-event overhead.

### Verdict: **FAILS TARGET** -- per-event config reads and full buffer clones are significant bottlenecks.

---

## 6. Daemon Status Polling (Connection Monitor)

### Current Implementation

`src-tauri/src/monitor.rs:1-77`:
- Spawns a **std::thread** that polls every **3 seconds** (`POLL_INTERVAL`, line 13)
- Each poll: `state.ipc_client.check_connection()` (creates a new Unix socket connection)
- If connected: `state.ipc_client.query_status()` (creates another new Unix socket connection)
- Calls `count_wrapped_servers()` every poll (reads 5 config files from disk)
- Only emits frontend event on state **change** (line 66) -- good

### Bottlenecks

| Issue | Severity | Location |
|-------|----------|----------|
| **Two separate socket connections per poll** | **HIGH** | `monitor.rs:25-30` -- `check_connection()` connects and immediately drops, then `query_status()` connects again. Each `DaemonConnection::connect()` in `ipc_client.rs:89-110` does a full Unix socket connect + clone + set timeouts. |
| **`count_wrapped_servers()` reads 5 JSON files every 3 seconds** | **HIGH** | `monitor.rs:26` calls `count_wrapped_servers()` (defined in `commands.rs:9-48`) which reads up to 5 config files, parses each as JSON, and iterates all servers. This runs every 3 seconds regardless of whether configs changed. |
| 3-second interval creates 2 socket connections + 5 file reads per cycle | MEDIUM | ~40 file reads/minute + ~40 socket operations/minute |

### Recommendations

1. **[HIGH] Combine `check_connection` + `query_status` into a single socket call.** Just call `query_status()` directly; if it fails, the daemon is not connected. This halves socket operations.
   ```rust
   let (connected, status) = match state.ipc_client.query_status() {
       Ok(metrics) => (true, build_status(metrics, wrapped)),
       Err(_) => (false, build_disconnected_status(wrapped)),
   };
   ```

2. **[HIGH] Cache `count_wrapped_servers()` result.** Store it in AppState and only refresh when a wrap/unwrap command is executed, or on a much longer timer (e.g., 60s). Config files rarely change.

3. **[MEDIUM] Increase poll interval to 5 seconds.** 3 seconds is aggressive for a status check. The GUI can still receive real-time events via the event stream.

### Verdict: **FAILS TARGET** -- excessive I/O per poll cycle.

---

## 7. IPC Commands (Frequently Called)

### Current Implementation

`src-tauri/src/commands.rs` (6000+ lines) contains all Tauri command handlers.

**Most frequently called commands:**

| Command | How Called | I/O Cost |
|---------|-----------|----------|
| `get_daemon_status` (line 51) | Home page mount + 30s poll | 1 IPC socket + `count_wrapped_servers()` (5 file reads) |
| `get_humanized_events` (line 4980) | Activity page mount | Clones event buffer + `spawn_blocking(read_profiles_from_db)` (SQLite) |
| `get_recent_events` (line 1177) | Fallback for event fetching | Clones buffer + potentially reads audit.jsonl (256KB chunk) |
| `detect_mcp_clients` (line 162) | Home page mount + 30s poll | 8 file existence checks + up to 4 JSON file reads |
| `get_protection_score` (line ~various) | Home page mount + real-time events | Computation over cached state |
| `list_guards` | Home page mount + 30s poll | Reads from guard registry |

### Bottlenecks

| Issue | Severity | Location |
|-------|----------|----------|
| **`get_daemon_status` calls `count_wrapped_servers()` synchronously** | **HIGH** | `commands.rs:55` -- every status check reads 5 config files |
| **`get_humanized_events` clones full event buffer under lock** | MEDIUM | `commands.rs:4985-4993` -- clones up to 10,000 events while holding the Mutex, then does a `spawn_blocking` for DB read |
| **Home page fires 5+ IPC calls on mount** | MEDIUM | `Home.tsx:160-166,138-147,150-157` -- `get_daemon_status`, `detect_mcp_clients`, `list_guards`, `get_protection_score`, `get_score_history`, `get_slm_status` all fire in parallel on every Home mount |
| `detect_mcp_clients` reads filesystem on every call | MEDIUM | `commands.rs:162-246` -- checks 8+ file paths, reads 4+ JSON configs |

### Recommendations

1. **[HIGH] Cache `count_wrapped_servers()` in AppState.** Invalidate only on wrap/unwrap operations.

2. **[MEDIUM] Add a combined "home data" IPC command.** Instead of 5-6 separate IPC calls from Home.tsx, create a single `get_home_data` command that returns daemon status, client info, guard list, and score in one call. This reduces IPC round-trips from 5+ to 1.

3. **[MEDIUM] Use `iter().rev().skip().take()` without cloning the full buffer.** In `get_humanized_events`, collect only the needed slice instead of cloning the entire Vec.

### Verdict: **FAILS TARGET** -- per-call file I/O is excessive for frequently-called commands.

---

## 8. Tray Menu

### Current Implementation

`src-tauri/src/tray.rs:1-495`:
- `setup_tray()` called once at startup (line 173)
- `tray_poll_loop()` runs every **3 seconds** (line 311-318), calling `update_tray()`
- `update_tray()` calls `collect_tray_data()` which reads from AppState (Mutex locks), then **rebuilds the entire menu** every time (line 160)
- Also triggered by `clawdefender://score-changed` events (line 267)
- `collect_tray_data()` iterates the entire event buffer to count today's blocked events (lines 58-75) -- iterates up to 10,000 events, parsing timestamps

### Bottlenecks

| Issue | Severity | Location |
|-------|----------|----------|
| **Full event buffer iteration every 3 seconds** | **HIGH** | `tray.rs:58-75` -- iterates ALL events (up to 10,000), parsing each timestamp with `chrono::DateTime::parse_from_rfc3339()`, just to count blocked events in last 24h |
| Menu rebuilt every 3 seconds | MEDIUM | `tray.rs:160` -- Tauri v2 menus are immutable, so a full rebuild is required. But this could be skipped if data hasn't changed. |
| Two 3-second pollers running independently | LOW | Both `monitor.rs` and `tray.rs` run at 3s intervals. They could share a single timer. |

### Recommendations

1. **[HIGH] Maintain `blocked_today` as an incremental counter in AppState.** Instead of iterating the entire event buffer, increment the counter in `process_event()` when a blocked event is seen. Reset it at midnight.

2. **[MEDIUM] Skip menu rebuild if data unchanged.** Store previous `TrayMenuData` and compare before rebuilding. Most 3-second intervals will have identical data.

3. **[LOW] Merge tray and monitor polling into a single 5-second timer.** Avoids redundant thread wakeups.

### Verdict: **FAILS TARGET** -- tray poll causes O(n) event buffer scan every 3 seconds.

---

## 9. Bundle Size

### Current Implementation

`package.json` dependencies:
```
react ^19, react-dom ^19, react-router-dom ^7, zustand ^5
@tauri-apps/api ^2, tailwindcss ^4
@tauri-apps/plugin-autostart ^2, plugin-notification ^2, plugin-process ^2, plugin-shell ^2, plugin-updater ^2
```

- **No heavy charting libraries** (Recharts, Chart.js, D3) -- sparkline is hand-drawn SVG
- **No heavy UI libraries** (Material UI, Ant Design, Chakra)
- Zustand is ~1KB minified
- Total dependency count is very lean

`tailwind.config.js` has `content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"]` -- proper purge config for Tailwind CSS 4.

`vite.config.ts` -- no code splitting, no chunk optimization, no tree-shaking hints.

### Bottlenecks

| Issue | Severity | Location |
|-------|----------|----------|
| No code splitting (covered in Section 2) | HIGH | `vite.config.ts` |
| No vendor chunk separation | MEDIUM | `vite.config.ts` |

### Recommendations

1. **[HIGH] Add route-based code splitting** (covered in Section 2).
2. **[MEDIUM] Add vendor chunk in Vite config** (covered in Section 2).
3. **[LOW] Verify Tailwind CSS purge works in production.** The `content` config looks correct for Tailwind v4.

### Verdict: **MOSTLY MEETS TARGET** -- dependencies are lean; code splitting is the main gap.

---

## 10. Memory Considerations

### Current Implementation

**Event buffer bounded:** `state.rs:384` -- `MAX_EVENT_BUFFER = 10,000` events. `push_event()` drains oldest when exceeded (line 442). Test confirms this at line 528.

**Pending prompts bounded:** `state.rs:387` -- `MAX_PENDING_PROMPTS = 100`.

**Frontend event store bounded:** `eventStore.ts:4` -- `MAX_EVENTS = 10,000`. Truncated via `events.length = MAX_EVENTS`.

**Alert state:** `state.rs:413` -- `alert_state: Mutex<Vec<IntelligentAlert>>` is unbounded. `auto_expire_alerts` runs periodically but there is no hard cap.

**Scan trackers:** `state.rs:405` -- `active_scans: Mutex<HashMap<String, ScanTracker>>` grows with each scan. Old completed scans are never cleaned up.

### Bottlenecks

| Issue | Severity | Location |
|-------|----------|----------|
| **Full buffer clone in `process_event`** (repeated from Section 5) | **HIGH** | `event_stream.rs:448-452` -- clones all 10,000 events every time |
| **Full buffer clone in `get_recent_events`** | MEDIUM | `commands.rs:1184-1188` -- `buf.clone()` clones entire Vec |
| **Full buffer clone in `get_humanized_events`** | MEDIUM | `commands.rs:4985-4993` -- similar full clone |
| Alert state unbounded | MEDIUM | `state.rs:413` -- no MAX_ALERTS constant |
| Scan trackers never pruned | LOW | `state.rs:405` -- completed scans persist forever in memory |
| `blocked_today` in tray iterates all events | HIGH | `tray.rs:58-75` (repeated from Section 8) |

### Recommendations

1. **[HIGH] Avoid full event buffer clones.** For `get_humanized_events`, use a `MappedMutexGuard` or collect into a smaller Vec inside the lock scope without cloning the full buffer:
   ```rust
   let events: Vec<AuditEvent> = state.event_buffer.lock()
       .map_err(|e| format!("Lock error: {}", e))?
       .iter().rev().skip(offset).take(count).cloned().collect();
   ```
   (This is already the pattern used -- but the issue is that `.iter().rev().skip().take().cloned().collect()` still clones N items individually. The real problem is the `process_event` full clone.)

2. **[MEDIUM] Cap alert_state to a maximum (e.g., 500).** Add a `MAX_ALERTS` constant and prune oldest resolved alerts when exceeded.

3. **[LOW] Prune completed scans after 1 hour.** Add a timestamp to `ScanTracker` and clean up in the monitor loop.

### Verdict: **PARTIALLY MEETS TARGET** -- buffers are bounded but clone patterns waste memory.

---

## Summary: Issues by Priority

### HIGH Priority (Fix First)

| # | Issue | File | Impact |
|---|-------|------|--------|
| 1 | SLM model loading blocks app startup | `lib.rs:94-249` | Startup blocked 2-10+ seconds |
| 2 | No route-based code splitting | `App.tsx:1-18` | Entire app loaded as single bundle |
| 3 | `notifications_enabled_in_config()` reads disk on every event | `event_stream.rs:311,357` | 2 file reads + 2 TOML parses per event |
| 4 | Full event buffer clone in `process_event` alert engine | `event_stream.rs:448-452` | Clones 10K events per incoming event |
| 5 | `count_wrapped_servers()` reads 5 files per call, called every 3s | `commands.rs:9-48`, `monitor.rs:26` | 100+ file reads/minute |
| 6 | Monitor creates 2 socket connections per 3s poll | `monitor.rs:25-30` | 40 unnecessary socket ops/minute |
| 7 | Tray iterates entire event buffer every 3s | `tray.rs:58-75` | O(10K) iteration with timestamp parsing |

### MEDIUM Priority

| # | Issue | File | Impact |
|---|-------|------|--------|
| 8 | Daemon auto-start blocks setup | `lib.rs:76-91` | Minor startup delay |
| 9 | No Vite vendor chunk splitting | `vite.config.ts` | Suboptimal caching |
| 10 | Home page fires 5+ IPC calls on mount | `Home.tsx:160-191` | Burst of IPC traffic on navigation |
| 11 | Scroll handler fires on every scroll event | `Activity.tsx:259-270` | Excessive re-renders during scroll |
| 12 | Prompt window is in-app overlay, not visible when minimized | `NotificationLayer.tsx:98` | Security prompts may be missed |
| 13 | `get_humanized_events` clones buffer under lock | `commands.rs:4985-4993` | Lock contention + memory waste |
| 14 | Tray menu rebuilt every 3s even when data unchanged | `tray.rs:160` | Unnecessary menu object churn |
| 15 | Alert state unbounded | `state.rs:413` | Potential slow memory growth |

### LOW Priority

| # | Issue | File | Impact |
|---|-------|------|--------|
| 16 | Custom virtual scroll lacks variable-height rows | `Activity.tsx:24` | Minor visual glitches |
| 17 | Scan trackers never pruned | `state.rs:405` | Very slow memory growth |
| 18 | Two independent 3s pollers could be merged | `monitor.rs`, `tray.rs` | Extra thread wakeups |
| 19 | SLM analysis not pre-fetched for prompts | `PromptWindow.tsx:38` | 1-5s delay on prompt render |

---

## Recommendations for Agent 2 (Frontend)

1. **Convert all page imports to `React.lazy()` with `<Suspense>`** (App.tsx)
2. **Add Vite `build.rollupOptions.output.manualChunks`** for vendor splitting (vite.config.ts)
3. **Throttle Activity scroll handler with `requestAnimationFrame`** (Activity.tsx)
4. **Consider consolidating Home page IPC calls** into a single `get_home_data` command
5. **Add loading skeleton to Suspense fallback** for route transitions

## Recommendations for Agent 3 (Backend)

1. **Move SLM model loading to background task** in lib.rs setup
2. **Move daemon auto-start to background task** in lib.rs setup
3. **Cache `notifications_enabled_in_config()`** -- read once, refresh on timer/event
4. **Cache `count_wrapped_servers()`** in AppState -- invalidate on wrap/unwrap
5. **Eliminate full event buffer clone** in `process_event`'s alert engine call
6. **Combine `check_connection` + `query_status`** into single socket call in monitor
7. **Maintain `blocked_today` counter incrementally** instead of iterating buffer in tray
8. **Add `MAX_ALERTS` cap** to alert_state
9. **Skip tray menu rebuild** when data is unchanged
10. **Prune completed scan trackers** after 1 hour
