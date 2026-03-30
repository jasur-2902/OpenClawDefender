# ClawDefender Mac GUI — Complete UX Flow Analysis

**Date:** February 2026
**Version:** 1.0
**Scope:** Navigation, user journeys, accessibility, interaction patterns, and notification flows

---

## Table of Contents

1. [Complete Navigation Map](#complete-navigation-map)
2. [User Journeys](#user-journeys)
3. [Keyboard Shortcuts & Input Handling](#keyboard-shortcuts--input-handling)
4. [Focus Management & Accessibility](#focus-management--accessibility)
5. [Tray Menu Structure](#tray-menu-structure)
6. [Window Behavior](#window-behavior)
7. [Notification Patterns](#notification-patterns)
8. [Error Recovery & Offline Behavior](#error-recovery--offline-behavior)
9. [Redirect Strategy](#redirect-strategy)
10. [Screen Reader Support](#screen-reader-support)

---

## Complete Navigation Map

### Primary Routes (App Shell with Sidebar)

The app uses a **main layout** (`Layout.tsx`) with a persistent left sidebar. All routes inside `<Layout />` display the sidebar + main content + footer status bars.

#### Main Navigation Items
| Path | Label | Icon | Badge | Notes |
|------|-------|------|-------|-------|
| `/` | Home | ⌂ | None | Landing dashboard after onboarding |
| `/ask` | Ask Claw | ✉ | None | AI conversation interface |
| `/tools` | My Tools | ⚒ | "New" | MCP server management & wrapping |
| `/tools/:id` | Tool Detail | — | — | Individual tool details (nested) |
| `/activity` | Activity | ◾ | None | Event timeline & detailed event inspection |
| `/activity/:id` | Event Detail | — | — | Single event analysis (nested) |
| `/alerts` | Alerts | ⚠ | Count | Security alerts, badge shows unresolved count |
| `/alerts/:id` | Alert Detail | — | — | Single alert detail view (nested) |
| `/settings` | Settings | ⚙ | None | Global settings hub |
| `/settings/policy` | Policy Editor | — | — | Security policy rules |
| `/settings/health` | System Health | — | — | Protection score factors & recommendations |
| `/settings/threat-intel` | Threat Intel | — | — | Threat intelligence dashboard |

#### Full-Screen Routes (No Sidebar)
| Path | Notes |
|------|-------|
| `/onboarding` | 5-screen wizard; full-screen only, no sidebar; lazy-loaded |

### Detail Routes (Nested Navigation)
- **`/tools/:id`** — Shows individual MCP server/tool, wrapping status, capabilities
- **`/activity/:id`** — Deep dive into single event with full context and relationships
- **`/alerts/:id`** — Full alert with event sequence, kill chain, suspicious patterns

### Deep Linking & Tray Navigation

**Tray Menu Actions → App Navigation:**
- **Open Dashboard** → Shows main window, navigates to `/` (home)
- **View Timeline** → Shows window, emits event → routes to `/activity` (via `clawdefender://navigate` IPC event)
- **View Audit** → Legacy route `/audit` → redirects to `/activity`
- **Ask Claw** → Shows window, emits event → routes to `/ask` (via `clawdefender://navigate` IPC event)

**Tray sends:** `app.emit("clawdefender://navigate", "/activity")`
**Frontend listens:** `TrayNavigationListener` component in `App.tsx` watches for `clawdefender://navigate` events

---

## User Journeys

### 1. First-Time Setup (Onboarding)

**Flow:** Completely separate full-screen wizard, no sidebar. Triggered when `check_onboarding_complete()` returns `false`.

**Screens (Sequential with Transitions):**

```
Screen 1: Welcome
├─ Icon animation (fade in, 300ms)
├─ Headline types out (char-by-char, 30ms per char)
├─ Body fades in (after headline + 200ms)
├─ CTA fades in (after body + 200ms)
└─ Enter or "Let's Go" → Screen 2

Screen 2: Detect & Wrap AI Tools
├─ Load detection state from sessionStorage
├─ If first visit:
│  ├─ Show loading spinner ("Looking for AI tools...")
│  ├─ Call detect_mcp_clients → list_mcp_servers (for each client)
│  ├─ Get capabilities for each server
│  └─ Display found tools in checklist
├─ User selects tools to protect (default: all checked)
├─ "Protect These" button:
│  ├─ For each selected, unwrapped tool:
│  │  ├─ Show per-tool progress (spinning indicator)
│  │  ├─ Call wrap_server
│  │  └─ Mark success/failure
│  ├─ Already-wrapped tools marked as success
│  └─ Show completion count
├─ "Skip for now" → Screen 3 (skip wrapping)
└─ Can go back to Screen 1

Screen 3: Protection Level Chooser
├─ Radio buttons: "Keep Watch" (observe only)
│                "Stay Sharp" (balanced, default)
│                "Lock It Down" (all prompts)
├─ "Start protecting":
│  ├─ Call apply_template (template name from selected level)
│  └─ → Screen 4 (check FDA status)
└─ Can go back to Screen 2

Screen 4: Full Disk Access (FDA)
├─ Show why FDA helps + what happens if skipped
├─ "Open System Settings":
│  ├─ Call open_system_preferences_fda
│  ├─ Fallback: invoke shell command with x-apple.systempreferences URL
│  └─ Start polling check_fda_status every 2s
├─ If granted:
│  ├─ Show success message
│  ├─ Wait 1.5s
│  └─ Auto-advance to Screen 5
├─ "Skip for now" (or Escape key):
│  └─ → Screen 5 (skip FDA, mark fdaSkipped)
└─ Can go back to Screen 3

Screen 5: Complete
├─ Fetch get_protection_score
├─ Animate score ring from 0→final (1.5s, ease-out cubic)
├─ Show score breakdown (factors & current points)
├─ Display summary:
│  ├─ Number of servers protected
│  ├─ Protection level label
│  ├─ FDA status (if granted)
│  └─ Restart reminder (if tools were wrapped)
├─ "Open ClawDefender":
│  ├─ Call complete_onboarding
│  ├─ Call enable_autostart
│  ├─ Clear sessionStorage
│  └─ Navigate to "/" with replace=true
└─ ✅ Onboarding complete — GUI shows main dashboard

State Persistence: sessionStorage key `clawdefender_onboarding_state`
- Saved after every screen transition
- Survives page reload but lost on browser close
- Allows resuming if the process is interrupted

Motion & Animation:
- Respects prefers-reduced-motion media query
- Slide transitions: ±60px offset + opacity fade (200ms)
- Icon typing: 30ms per character
- Score ring: 1.5s easing with requestAnimationFrame
```

### 2. Migration from Older Version

**Trigger:** Onboarding detected + `check_existing_installation()` returns data + not already onboarded

**Screen: MigrationScreen**
```
[Icon] Existing installation found
Description: Found your existing configuration and data

[Summary Box]
├─ Settings (if config_found)
├─ Policy rules (if policy_found, show rule count)
├─ Event history (if event_count > 0, show count)
├─ Behavioral profiles (if profiles_found)
└─ AI models (if models.length > 0, show count)

[Actions]
├─ "Use my existing settings"
│  ├─ Call migrate_config
│  ├─ Call migrate_policy
│  ├─ Show success message + changes
│  └─ → continue_onboarding & navigate to "/"
└─ "Start fresh"
   └─ Reset state & return to normal onboarding

Error handling: If migration fails, show error banner + option to retry
```

### 3. Daily Monitoring Workflow

**Entry Point:** User opens app or brings main window to focus (tray click)

**Dashboard (Home page):**
```
Main content area shows:
├─ Hero metric (e.g., "45 AI interactions monitored today")
├─ Protection score card (large, clickable → opens ScoreBreakdownDrawer)
├─ Quick stat blocks:
│  ├─ Servers protected
│  ├─ Actions blocked
│  ├─ Pending approvals
│  └─ Key risks detected
├─ Activity summary (recent events)
├─ Recommended actions (if any)
└─ [Learn more] links

Sidebar always visible:
├─ Top: Collapsible header (shows/hides app name)
├─ Daemon status indicator (green running / red stopped)
├─ Nav items with active state highlighting
├─ Alerts badge (red, counts unresolved)
├─ Tools badge (blue "New" if new tools available)
└─ Footer: Mini score ring (clickable → opens score breakdown)
```

**Typical Session:**
1. Quick check of home dashboard
2. If alert badge visible → Click `/alerts` to see & triage alerts
3. If pending prompts → Handle in overlay (fixed position, z-50)
4. Review activity `/activity` if curious about specific events
5. Adjust policies `/settings/policy` as needed
6. Close (Cmd+W minimizes to tray, Cmd+Q quits with confirmation)

### 4. Responding to a Security Alert

**Detection Path:**
1. Backend daemon detects suspicious pattern
2. Emits `clawdefender://alert` event with `AlertData`
3. `NotificationLayer` receives in `handleAlert` callback
4. Alert added to state, triggers overlay render

**UI Flow:**
```
Overlay appears (modal, z-40, blurred background):
├─ AlertWindow component
│  ├─ Header bar: "SECURITY ALERT" + level (critical/warning)
│  ├─ Main message + details
│  ├─ Kill chain pattern info (if present)
│  ├─ Suspicious events list (scrollable, max-h-40)
│  ├─ Action buttons:
│  │  ├─ "Kill Process" (calls kill_agent_process IPC)
│  │  ├─ "View in Timeline" (navigates to /activity, filters by message)
│  │  └─ "Dismiss" (removes alert, can be re-triggered by new events)
│  └─ ARIA labels: role="alert", aria-live="assertive"

After action:
├─ Kill Process → Daemon terminates PID, alert dismissed
├─ View Timeline → Navigate to /activity, alert dismissed
├─ Dismiss → Alert removed, overlay closes
└─ Next alert in queue appears (if any)
```

**Keyboard Behavior:**
- Escape key closes overlay
- No keyboard navigation inside alert (button focus traps)

### 5. Approving/Denying a Tool Action (Prompt Flow)

**Detection Path:**
1. Daemon detects MCP tool wanting to execute action
2. Creates `PendingPrompt` with timeout (usually 30s)
3. Emits `clawdefender://prompt` event
4. Frontend's `Layout` listens and calls `addPrompt`

**UI Flow:**
```
Overlay appears (modal, z-50, higher than alerts, blurred background):
├─ PromptQueue component manages queue
│  ├─ Shows first (active) prompt only
│  ├─ Queued prompts (index 1+) auto-expire if timeout reached
│  └─ Expired queued prompts auto-denied via respond_to_prompt

PromptWindow (active prompt):
├─ Risk indicator (color: low/medium/high/critical)
├─ High-risk warning banner (dark red, "ClawDefender recommends DENYING")
├─ Timer bar at top (animated, color shifts with remaining time)
│  ├─ Green (remaining > 10s)
│  ├─ Amber (5-10s)
│  └─ Red (< 5s)
├─ Details section:
│  ├─ Server name (e.g., "claude.ai")
│  ├─ Tool name (e.g., "file_write")
│  ├─ Action (e.g., "write_to_file")
│  ├─ Resource (path, truncated with … in middle for long paths)
│  └─ Context (if available)
├─ SLM Analysis (if model loaded):
│  ├─ Loading state: spinner + "Analyzing with local AI..."
│  ├─ Result: box with analysis text + recommendation
│  └─ Mock mode warning (if no model loaded)
├─ Action buttons:
│  │ [High-risk layout — stacked buttons]
│  │ ├─ Full width "Deny (D)" button (dark red, auto-focused)
│  │ └─ 3-column grid: "Allow Once (A)" | "Session (S)" | "Always (P)"
│  │
│  │ [Normal layout — 4-column grid]
│  │ ├─ "Deny (D)" | "Allow Once (A)" | "Session (S)" | "Always (P)"
│  │ └─ All same height (min-h-[44px])
│
├─ Queue indicator (bottom, if more prompts pending):
│  └─ "{queueCount} more pending"
│
└─ Timer behavior:
   ├─ Countdown every 250ms
   ├─ On 10s & 5s: SR announcement ("10 seconds remaining")
   ├─ Timer expires:
   │  ├─ Automatically calls respond("deny")
   │  └─ Shows next queued prompt

Decision mapping:
├─ "Deny" (D) → { decision: "deny" } → Block action
├─ "Allow Once" (A) → { decision: "allow_once" } → Allow this time only
├─ "Session" (S) → { decision: "allow_session" } → Allow for app lifetime
└─ "Always" (P) → { decision: "allow_always" } → Remember, allow forever

Focus behavior:
├─ Tab key trapped within buttons (useFocusTrap hook)
├─ Initial focus: "Deny" (high-risk) or "Deny" (normal)
├─ Shift+Tab at first element → wraps to last
├─ Tab at last element → wraps to first
└─ On dismiss: focus restored to previous element (usually sidebar)

Accessibility:
├─ role="alertdialog"
├─ aria-labelledby="prompt-title"
├─ aria-describedby="prompt-description" (hidden, full text)
├─ aria-label on buttons (full context, includes risk level + server)
├─ Keyboard shortcut hints in button text (D/A/S/P)
└─ Screen reader announces full decision text + consequences

Keyboard shortcuts (global, any focused element):
├─ D → respond("deny")
├─ A → respond("allow_once")
├─ S → respond("allow_session")
├─ P → respond("allow_always")
└─ Escape → (not mapped in PromptWindow; overlay closes only on dismissal)
```

### 6. Managing MCP Servers/Tools

**Entry Point:** `/tools` (My Tools)

```
Page structure:
├─ Header: "My Tools" + "New" badge (if hasNewUnwrapped)
├─ Toolbar:
│  ├─ Search/filter input
│  ├─ Sort dropdown (e.g., by name, status, risk)
│  └─ "Add Tool" button
├─ Tool grid/list:
│  ├─ Each tool card shows:
│  │  ├─ Tool name + server name
│  │  ├─ Status badge (protected/unwrapped/error)
│  │  ├─ Capabilities (read files, write files, run commands, network)
│  │  ├─ Recent activity summary
│  │  └─ [View Details] link
│  └─ Empty state (if no tools found)

[Tool Detail Page] `/tools/:id`:
├─ Header: Tool name + status
├─ Tabs or sections:
│  ├─ Overview (status, capabilities, recent activity)
│  ├─ Permissions (what this tool is allowed to do)
│  ├─ Activity (recent uses/blocks)
│  ├─ Actions (wrap, unwrap, delete, etc.)
│  └─ Settings (if applicable)

Interaction flow:
├─ Click tool card → navigate to /tools/:id
├─ Inside detail:
│  ├─ Review current policies
│  ├─ Modify allowed actions
│  ├─ View recent usage
│  ├─ Wrap/unwrap (if applicable)
│  └─ Delete server config (if unused)
└─ [Back] link or browser back → return to /tools

"New" badge logic:
├─ Shown if ServerStore.hasNewUnwrapped = true
├─ Indicates new tools available from detection scan
├─ Clicking "Wrap" clears flag
└─ Manually marked as reviewed in settings
```

### 7. Editing Security Policy

**Entry Point:** `/settings/policy`

```
Page structure:
├─ Header: "Security Policy"
├─ Intro: "Define what actions are blocked by default"
├─ Sections by category:
│  ├─ File Operations
│  │  ├─ "Read from system directories" → toggle + detail
│  │  ├─ "Write to system directories" → toggle + detail
│  │  └─ "Delete files" → toggle + detail
│  ├─ Process Management
│  │  ├─ "Execute shell commands" → toggle + detail
│  │  ├─ "Modify process environment" → toggle + detail
│  │  └─ "Access system processes" → toggle + detail
│  ├─ Network
│  │  ├─ "Connect to external hosts" → toggle + detail
│  │  ├─ "Access local network" → toggle + detail
│  │  └─ "DNS lookups" → toggle + detail
│  └─ ... (more categories)
│
├─ Per-tool overrides:
│  ├─ Select tool dropdown
│  ├─ Override specific rules (inherit defaults or custom)
│  └─ [Save] button

Interaction:
├─ Toggle switches (with onFocus styling)
├─ Edit detail text (modal or inline form)
├─ On change:
│  ├─ Visual feedback (switch animates)
│  ├─ Debounced save (500ms idle before calling save_policy)
│  └─ Toast notification on success/error
└─ Esc key closes any open editor

Notification router state:
├─ If highlight params passed: scroll-to & focus that rule
└─ Auto-block toast can link to this page with highlight params
```

### 8. Viewing Event Details

**Entry Point:** `/activity` → click event → `/activity/:id`

```
Activity List Page (`/activity`):
├─ Toolbar:
│  ├─ Date range picker
│  ├─ Severity filter (all/warning/error/blocked)
│  ├─ Server filter (dropdown)
│  └─ Search box (searches action + resource)
├─ Timeline view:
│  ├─ Chronological list of events
│  ├─ Each event shows:
│  │  ├─ Timestamp (HH:MM:SS)
│  │  ├─ Severity icon (colored)
│  │  ├─ Server name
│  │  ├─ Action summary
│  │  ├─ Resource (truncated)
│  │  └─ Status (allowed/blocked/pending)
│  └─ Click event → navigate to /activity/:id
└─ Pagination or infinite scroll (if many events)

Event Detail Page (`/activity/:id`):
├─ Header: Event title + severity badge + timestamp
├─ Full context section:
│  ├─ Server (name + icon)
│  ├─ Action (what was attempted)
│  ├─ Resource (full path, file/URL, etc.)
│  ├─ Result (allowed/blocked/pending)
│  ├─ Duration (if applicable)
│  └─ Related events (links)
├─ Details panel:
│  ├─ Raw event data (expandable JSON)
│  ├─ Correlation info (related events, sequences)
│  ├─ Risk assessment (why it was flagged)
│  └─ Policy that matched (if blocked)
├─ Actions:
│  ├─ [Create Rule] button (pre-fills policy editor)
│  ├─ [Export] button (download event data)
│  └─ [Related Events] link → filter /activity page
└─ [Back] link or browser back → /activity

Keyboard navigation:
├─ Tab moves focus through details & action buttons
├─ Escape closes any expanded sections
└─ Cmd+K opens Ask Claw with event context (future)
```

### 9. Migration Workflow (for Existing Installation)

**Trigger:** First run + existing installation detected + not yet onboarded

```
Sequence:
1. App.tsx OnboardingRedirect checks onboarding status
2. If not complete AND installation found → show MigrationScreen
3. User chooses:
   a. "Use my existing settings":
      ├─ Call migrate_config → updates ~/.clawdefender/config.json for v2 format
      ├─ Call migrate_policy → updates ~/.clawdefender/policy.json for v2 format
      ├─ Show migration log (changes made)
      ├─ Call complete_onboarding
      └─ Navigate to "/" (main dashboard)

   b. "Start fresh":
      ├─ Don't call migrate functions
      ├─ Close MigrationScreen
      └─ Return to normal onboarding (Screen 1)

If migration fails:
├─ Show error banner with message
├─ Allow retry or skip
└─ Proceed with onboarding anyway
```

---

## Keyboard Shortcuts & Input Handling

### Global Shortcuts (Always Active)

Handled in `App.tsx` `GlobalKeyboardShortcuts` component:

| Shortcut | Action | Details |
|----------|--------|---------|
| **Cmd+K** | Open Ask Claw | Navigate to `/ask`, focus input field |
| **Cmd+,** | Open Settings | Navigate to `/settings` |
| **Cmd+F** | Focus search/filter | Finds `[data-search-input]`, `[data-filter-input]`, or standard search inputs |
| **Cmd+R** | Refresh page data | Dispatches `clawdefender:refresh` event; pages listen with `useRefreshShortcut` hook |
| **Cmd+1** through **Cmd+6** | Quick nav to pages | Maps: 1→Home, 2→Ask, 3→Tools, 4→Activity, 5→Alerts, 6→Settings |
| **Cmd+W** | Hide to tray | Calls `getCurrentWindow().hide()` |
| **Cmd+Q** | Quit app | Shows confirmation dialog; if confirmed, calls `exit(0)` |
| **Escape** | Close modals/overlays | Finds `[data-modal-overlay]` or `[role="dialog"]`, clicks close button |

### Prompt Window Shortcuts (When Prompt Visible)

Handled in `PromptWindow` `useEffect`:

| Key | Action | Effect |
|-----|--------|--------|
| **D** | Deny | Calls `respond("deny")` |
| **A** | Allow Once | Calls `respond("allow_once")` |
| **S** | Allow Session | Calls `respond("allow_session")` |
| **P** | Allow Always | Calls `respond("allow_always")` |

**Note:** Disabled if input/textarea is focused (checks `e.target instanceof HTMLInputElement`)

### Tab Focus Management

- **PromptWindow:** Focus trap; Tab cycles through buttons only; Shift+Tab reverses
- **Modals/Drawers:** useFocusTrap hook; returns focus on close
- **Regular pages:** Tab order follows DOM order; sidebar focusable

### Search & Filter

- **Cmd+F** finds input with priority: `[data-search-input]` > `[data-filter-input]` > standard `input[type="search"]`
- Each page implements its own search (Activity, Alerts, Tools)
- Debounced filtering (instant visual feedback, API calls batched)

---

## Focus Management & Accessibility

### useFocusTrap Hook

**Location:** `/hooks/useFocusTrap.ts`

**Behavior:**
```typescript
useFocusTrap(active: boolean, options?: { initialFocusSelector?: string })
// Returns: ref to attach to container

When active = true:
├─ Finds all focusable elements (buttons, links, inputs, etc.)
├─ Sets focus to initialFocusSelector OR first focusable element
├─ Traps Tab/Shift+Tab to cycle within focusable elements
├─ On deactivate: restores focus to element that had focus before

Focusable selector:
'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]),
 textarea:not([disabled]), [tabindex]:not([tabindex="-1"]):not([disabled])'

Visibility check: el.offsetParent !== null (hidden elements excluded)
```

**Usage Examples:**
- **PromptWindow:** `useFocusTrap(true, { initialFocusSelector: "[data-action='deny']" })`
- **Modals/Drawers:** `useFocusTrap(true)` (auto-focuses first element)

### Tab Order & Sidebar

**Sidebar Navigation:**
- NavLink components use `end={item.path === "/"}` for exact matching
- `aria-current="page"` set when link is active
- Focus visible outline: `focus-visible:outline-2 focus-visible:outline-offset-2` (blue accent color)
- Minimum hit target: 44px tall (meet WCAG AAA standards)

**Header Area:**
- Skip link: `<a href="#main-content">Skip to main content</a>` (sr-only, visible on focus)
- Positioned absolutely, z-100, appears when focused

### Color Contrast & WCAG

**Design tokens:**
- Primary text: CSS variable `--color-text-primary` (high contrast on `--color-bg-primary`)
- Button text: White (`text-white`) on colored backgrounds (red/green/amber)
- Disabled state: Reduced opacity + `cursor-not-allowed`
- Focus rings: `outline-[var(--color-accent)]` (bright, visible)

**Button sizing:**
- Minimum height: 44px × 44px (touch-friendly on Mac trackpad)
- Padding standardized: `px-3 py-2` minimum

---

## Tray Menu Structure

**File:** `/src-tauri/src/tray.rs`

### Menu Hierarchy

```
▼ ClawDefender — Score: 65 (Protected)
  ├─ 4 servers protected [info item, disabled]
  ├─ Protection Score: 65/100 [info item, disabled]
  ├─ ⚠ 2 prompts waiting [info item, disabled, if pending > 0]
  ├─ 12 blocked today [info item, disabled]
  ├─ AI Model: Llama2 [info item, disabled, or "AI Analysis: Basic mode" if mock]
  ├─ ──────────────────── [separator]
  ├─ Open Dashboard…
  ├─ View Timeline…
  ├─ View Audit…
  ├─ ──────────────────── [separator]
  ├─ Ask Claw…
  ├─ ──────────────────── [separator]
  ├─ Pause Protection (or "Resume Protection" if stopped)
  ├─ ──────────────────── [separator]
  └─ Quit ClawDefender

Menu actions:
├─ Open Dashboard → show main window, navigate to "/"
├─ View Timeline → show window, emit navigate to "/timeline" (redirects to /activity)
├─ View Audit → show window, emit navigate to "/audit" (redirects to /activity)
├─ Ask Claw → show window, emit navigate to "/ask-claw" (redirects to /ask)
├─ Pause/Resume → call daemon.stop_daemon_process() / daemon.start_daemon_process()
└─ Quit → stop daemon (if GUI started it), exit(0)

Tray icon (Retina 44×44 shield):
├─ Status: Protected (green #34D399) | Warning (amber #FBBF24) | Error (red #EF4444)
├─ Border: Darker shade of fill color
├─ Shape: Shield with flat top, tapered bottom, pointed tip
├─ Anti-aliasing: 2px edges (smooth on Retina)

Tooltip: "ClawDefender — Score: 65. Protected" (or "Warning" / "Not Running")

Tray click behavior: Show/focus main window

Background poller:
├─ Runs every 3 seconds
├─ Reads AppState (daemon status, cached metrics)
├─ Rebuilds menu only if data changed
├─ Updates icon + tooltip on score change or connection change
```

---

## Window Behavior

### Main Window (`main`)

**File:** `/src-tauri/src/windows.rs`

```
Initial creation (if not exists):
├─ Title: "ClawDefender"
├─ Size: 1200×800 (min: 800×600)
├─ Position: centered on screen
├─ Resizable: yes
├─ Created with: WebviewWindowBuilder

Window actions:
├─ .show() — bring to front
├─ .set_focus() — gain keyboard focus
├─ .hide() — minimize to tray (not close)

Geometry persistence:
├─ File: ~/.config/clawdefender/window-geometry.json
├─ Saved on every resize/move event
├─ Loaded on app startup
├─ Validation: rejects insane sizes (< 400×300 or > 10000×10000)
├─ Format: { x, y, width, height }

Lifecycle:
├─ App startup:
│  ├─ Try load geometry from disk
│  ├─ If valid, restore position + size
│  └─ If invalid/missing, center on screen with default size
├─ Window move/resize: call save_window_geometry
├─ Cmd+W: hide window (not close)
└─ Cmd+Q: show confirmation, then close main window + exit daemon
```

### Floating Windows (Not Currently Used)

**create_prompt_window()** and **create_alert_window()** are defined but not actively used (prompts/alerts handled via overlay in main window instead).

```
If implemented:
├─ Title: "Security Prompt" / "Security Alert"
├─ Size: 480×400 / 500×450 (fixed, not resizable)
├─ Position: centered
├─ Behavior: always_on_top(true)
└─ Created on demand, shown/focused if exists, destroyed on response
```

### Window Hide Strategy

- **Cmd+W** → Hide main window (stays in memory, stays in tray)
- **Cmd+Q** → Quit app entirely (daemon also stops if GUI started it)
- **Window X button** → (Not explicitly handled; likely closes window)
- **Tray click** → Show + focus main window

---

## Notification Patterns

**File:** `/src/components/NotificationLayer.tsx`, `/src/services/notificationRouter.ts`

### Notification Types & Priority

```
Priority 1: PROMPT (Approval Request)
├─ Overlay in main window (z-50)
├─ Full focus trap, blocks interaction
├─ Modal backdrop (black 60%, blur)
├─ Display: PromptWindow component
├─ Duration: 30s timeout (auto-deny on expiration)
├─ Example: "Claude wants to write to /tmp/file.txt"

Priority 2: ALERT (Security Threat)
├─ Overlay in main window (z-40, below prompts)
├─ Modal backdrop (black 50%, blur)
├─ Display: AlertWindow component
├─ Can show kill process / view timeline buttons
├─ Example: "Suspicious command execution detected"

Priority 3: TOAST (Informational, Auto-Block, Updates)
├─ Fixed position (bottom-right or top)
├─ Non-blocking, interactive
├─ Auto-dismiss after 5-8 seconds (configurable)
├─ Can have action button (e.g., "Review" → navigate)
├─ Uses ToastContainer + useToastStore (Zustand)
├─ Example: "Auto-blocked: claude.ai – write_to_file (3 times)"

Priority 4: BANNER (Connection, Update, Restart Reminder)
├─ Inline in app shell (below sidebar, sticky at top of content)
├─ Non-modal, part of layout flow
├─ Dismiss button optional
├─ Examples:
│  ├─ ConnectionStatus (orange, "Reconnecting to monitoring service…")
│  ├─ UpdateBanner (blue, "ClawDefender v0.5.1 is available")
│  ├─ RestartReminderBanner (blue, "AI apps need to restart to pick up protection")
│  └─ ErrorBanner (red/orange, "Something went wrong")

Priority 5: OS NOTIFICATION (macOS System Notification)
├─ Only sent for dangerous alerts if window NOT focused
├─ Uses @tauri-apps/plugin-notification
├─ Includes sound
├─ Example: Desktop notification with alert summary
```

### Notification Router Logic

**Rate Limiting:**
- Tracks event timestamps in 5s sliding window
- If > 10 events in 5s: suppress individual toasts, show batch notification instead
- Batch toast: "{count} events in the last few seconds" + [View] link

**Foreground Suppression:**
- If window has focus: only show in-app toast
- If window NOT focused: show OS notification (macOS system) + optional in-app toast

**Auto-Block Toast Pattern:**
```
Backend emits: clawdefender://auto-block { server_name, action, ... }
Frontend router:
├─ Creates toast: "Auto-blocked: {server_name} — {action}"
├─ Severity: warning
├─ Action button: "Review" → navigate to /settings/policy
│  └─ Pass highlight params: { highlightServer, highlightAction }
└─ Duration: 5000ms (5s)
```

### Toast Container

**Location:** `/components/notifications/ToastContainer.tsx`

**Store:** Zustand state `useToastStore`

```
Toast object:
{
  id: string (auto-generated)
  title: string
  severity: "success" | "warning" | "error" | "info"
  duration?: number (ms, default 5000)
  action?: { label: string; onClick: () => void }
  onDismiss?: () => void
}

Container behavior:
├─ Fixed position (bottom-right, e.g., `bottom-4 right-4`)
├─ Max stack: usually 3 toasts
├─ Auto-dismiss after duration (if set)
├─ Each toast has dismiss button (×)
├─ On dismiss: call onDismiss callback, remove from stack

z-index: 40 (below prompts at z-50, above page content)
```

---

## Error Recovery & Offline Behavior

### Connection Status Handling

**File:** `/components/ConnectionStatus.tsx`

**States:**
```
1. CONNECTED
   └─ No banner shown (good state)

2. RECONNECTING
   ├─ Orange banner (warning color)
   ├─ Text: "Reconnecting to monitoring service…"
   ├─ Shows "Last updated: {time ago}"
   ├─ Countdown timer: "Retrying in {n}s"
   ├─ Action: "Retry now" button (manual retry)
   │
   └─ Exponential backoff:
      ├─ First retry: 5s
      ├─ Max retry: 60s
      ├─ Backoff factor: 2x each time
      └─ Reset to 5s on successful reconnect

3. DISCONNECTED
   ├─ Orange banner
   ├─ Text: "Live updates paused"
   └─ Retry button available
```

**Reconnect Logic:**
- Calls `get_daemon_status` every retry interval
- If returns `{ running: true }`: state → CONNECTED, banner disappears
- If still fails: schedules next retry with exponential backoff

### Daemon Crash/Stop Handling

**Trigger:** Daemon process terminates unexpectedly

**UI Changes:**
- Sidebar: daemon status indicator turns red ("Stopped")
- ConnectionStatus banner appears (orange, reconnecting mode)
- All real-time events pause (prompts/alerts still shown, but no new events)
- Tray icon: changes to red (Error status)
- Tray menu: "Pause Protection" button becomes "Resume Protection"

**Recovery Path:**
1. Tray → "Resume Protection" → calls daemon.start_daemon_process()
2. OR: ConnectionStatus "Retry now" button triggers reconnect loop
3. Once daemon is back: full UI update, icon turns green again

### Failed Actions & Error States

**Pattern: useDebouncedSave**

```typescript
const { trigger, saving } = useDebouncedSave(saveFn, 500);

// On field change:
trigger(newValue);
// → Shows saving state (spinner/disabled)
// → After 500ms idle: calls saveFn
// → saveFn error is caught (caller should handle)
// → Retry only on user request
```

**Form Validation:**
- Policy editor: saves changes incrementally
- Settings: validates input before saving
- Tool wrapping: shows per-tool progress + error state

**Error Display:**
- Inline error messages (red text near field)
- Toast notification with action (e.g., "Retry" button)
- Banner if critical (e.g., daemon offline)

### Missing Commands / Backend Errors

**Pattern:**

```javascript
try {
  const result = await invoke("some_command", { /* args */ });
} catch (e) {
  // Expected: daemon/command not available
  // Fallback: proceed with sensible default
  // Log: console.error (dev only)
  // User sees: no error (graceful degradation)
}
```

**Examples:**
- `check_fda_status` might not exist in older daemon → skip FDA screen
- `get_protection_score` returns mock data if daemon unavailable
- `detect_mcp_clients` failure → show "Could not scan, continue anyway" button

---

## Redirect Strategy

**File:** `App.tsx` (Route definitions)

### Old Route → New Route Mapping

| Old Path | New Path | Reason |
|----------|----------|--------|
| `/timeline` | `/activity` | Renamed to "Activity" |
| `/behavioral` | `/tools` | Behavioral analysis merged into tools list |
| `/guards` | `/tools` | Guards → MCP servers/tools |
| `/audit` | `/activity` | Audit log → activity timeline |
| `/network` | `/alerts` | Network alerts → security alerts |
| `/health` | `/settings/health` | Moved to settings subsection |
| `/ask-claw` | `/ask` | Shortened URL |
| `/policy` | `/settings/policy` | Moved to settings subsection |
| `/scanner` | `/alerts` | Scanner → alerts view |
| `/threat-intel` | `/settings/threat-intel` | Moved to settings subsection |

**Implementation:**
```javascript
<Route path="/timeline" element={<Navigate to="/activity" replace />} />
<Route path="/behavioral" element={<Navigate to="/tools" replace />} />
// ... etc
```

**Behavior:**
- `<Navigate to="..." replace />` — replaces history entry (no back button to old URL)
- Tray menu still emits old paths (`/timeline`, `/audit`, `/ask-claw`) → routes redirect silently

---

## Screen Reader Support

### ARIA Labels & Roles

**Sidebar:**
```html
<nav aria-label="Main navigation">
  <NavLink aria-current="page">Home</NavLink>
  <!-- Current page gets aria-current="page" -->
</nav>

<!-- Status indicator -->
<div role="status" aria-label="Daemon running">
  <!-- Visual indicator + text -->
</div>
```

**Onboarding:**
```html
<div aria-label="Onboarding step 3 of 5: Protection level" role="region">
  <!-- Screen content -->
</div>

<!-- Progress bar -->
<div role="progressbar" aria-valuenow="3" aria-valuemin="0" aria-valuemax="5"
     aria-label="Onboarding progress: step 3 of 5">
  <!-- Visual progress bar -->
</div>
```

**Prompts & Alerts:**
```html
<!-- Prompt -->
<div role="alertdialog" aria-labelledby="prompt-title" aria-describedby="prompt-description">
  <!-- Full description in sr-only for context -->
  <div id="prompt-description" class="sr-only">
    {server} wants to use {tool} to {action} on {resource}. Risk: {level}.
  </div>
</div>

<!-- Alert -->
<div role="alert" aria-live="assertive">
  {alert message}
</div>
```

**Buttons:**
```html
<!-- Prompt action buttons -->
<button aria-label="Deny — block this high risk request from claude.ai (keyboard shortcut: D)">
  Deny (D)
</button>

<!-- Sidebar protection score -->
<button aria-label="Protection score: 65. Click for details.">
  <!-- Score ring SVG -->
</button>
```

### Live Regions

**aria-live="polite":**
- Sidebar alert badge: announces unresolved count when changes
- ConnectionStatus banner: announces reconnection status
- Toast notifications: announce new messages

**aria-live="assertive":**
- Prompt window: announces timer milestones (10s, 5s remaining)
- Alert window: initial alert message (high priority)

### Screen Reader Announcements

**Onboarding:**
- Icon animations are `aria-hidden="true"` (visual only)
- Headline: full text in `aria-label` even though text is typed out
- Progress bar: announces "step X of 5"

**Protection Score:**
- Ring: "Protection score: {value}. Click for details."
- Score breakdown drawer: "Score factors" list with `role="list"` and `role="listitem"`

**Tool Selection (Onboarding):**
```html
<label role="listitem">
  <input type="checkbox" aria-label="Protect {tool} via {client}" />
  <!-- Tool name + capabilities -->
</label>
```

**Activity Timeline:**
- Each event is focusable link: "Event: {type}, {summary}, {time}"
- List of events: `role="list"` with `role="listitem"` per event

### SR-Only Content

**Pattern:**
```html
<span class="sr-only">{full description}</span>
<!-- Visual content (truncated, icons, etc.) -->
```

**Uses:**
- Skip link: "Skip to main content"
- Event descriptions: full context for accessibility
- Prompt context: full decision text before buttons
- Keyboard shortcuts: hint text in buttons

**CSS:**
```css
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
}

.sr-only:focus {
  /* Not sr-only — make visible on focus */
  position: static;
  width: auto;
  height: auto;
  overflow: visible;
  clip: auto;
  white-space: normal;
}
```

### Color Alone Not Used

- Risk levels shown with: icon + color + text label
- Status indicators: icon + color + text ("Daemon Running")
- Disabled buttons: opacity + `cursor-not-allowed` + disabled attribute
- Alerts: banner color + icon + text + role="alert"

### Keyboard Navigation

- All interactive elements focusable (buttons, links, inputs)
- Tab order: follows DOM order (left sidebar first, then main content)
- Modals: focus trap (Tab cycles within modal only)
- Escape key closes modals (handled by App.tsx GlobalKeyboardShortcuts)

### Reduced Motion Support

**Pattern:**
```javascript
const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

if (prefersReduced) {
  // Skip animations
  setAnimatedScore(finalValue);
} else {
  // Run 1.5s ease-out animation
  requestAnimationFrame(animate);
}
```

**Applied to:**
- Onboarding animations (icon fade, text typing, screen transitions)
- Protection score ring animation
- Sidebar score pulse (on score change)
- Toast slide-in animations

---

## Summary: Key Design Patterns

### Single-Page Application with Client-Side Routing
- React Router v6 with lazy-loaded pages
- Sidebar + main content layout persists across routes
- Deep links work (tray menu can navigate to any route)

### Event-Driven Real-Time Updates
- Tauri IPC events: `clawdefender://event`, `clawdefender://prompt`, `clawdefender://alert`, etc.
- Zustand stores subscribe and update UI in real-time
- No polling for main user flows

### Modular Overlays
- Prompts & alerts as overlays, not separate windows
- Queue system for concurrent prompts
- Auto-dimissing notifications (toasts)

### Accessibility-First
- WCAG AAA contrast, 44px touch targets
- Full keyboard support (global shortcuts, local focus management)
- Screen reader support with ARIA labels, live regions, sr-only content

### Graceful Degradation
- Commands fail gracefully (try/catch, show fallback or skip)
- Daemon offline doesn't crash UI (reconnect banner appears)
- Missing features don't block critical functions

### Motion & Preferences
- All animations respect `prefers-reduced-motion`
- Smooth transitions between pages (crossfade, 150ms)
- Progress indication (spinners, progress bars)

---

## File & Component Cross-Reference

### Core Files
- **App.tsx** — Routing, onboarding redirect, global keyboard shortcuts, tray navigation
- **Layout.tsx** — App shell, sidebar, banners, event subscriptions, guidance system
- **Sidebar.tsx** — Navigation items, badges, protection score, score breakdown
- **Onboarding.tsx** — 5-screen wizard with state persistence
- **MigrationScreen.tsx** — Existing installation migration

### Notification & Interaction
- **NotificationLayer.tsx** — Overlay routing (prompts, alerts, toasts)
- **PromptWindow.tsx** — Approval dialog with timer, keyboard shortcuts, SLM analysis
- **PromptQueue.tsx** — Queue management, auto-expire old prompts
- **AlertWindow.tsx** — Security alert display with kill process / timeline buttons
- **ConnectionStatus.tsx** — Daemon connection state with exponential backoff retry
- **UpdateBanner.tsx** — App update availability + download + restart
- **ErrorBanner.tsx** — Generic error/warning/info banner

### Hooks
- **useFocusTrap.ts** — Tab focus trapping for modals
- **useKeyboardShortcuts.ts** — (Not used; shortcut logic in App.tsx)
- **useDebouncedSave.ts** — Batched saves with debounce

### Services & State
- **notificationRouter.ts** — Route events to prompts vs. toasts vs. OS notifications
- **eventStore.ts** — Zustand store for events, prompts, activities
- **appStore.ts** — App state (daemon status, theme, sidebar, guidance)
- **alertStore.ts** — Alert list & counts

### Tauri Backend
- **tray.rs** — Tray icon + menu, status updates, background poller
- **windows.rs** — Window creation, geometry persistence, hide/show logic
- **ipc.rs** — IPC command handlers (invoke from frontend)

---

## End of Analysis

This document captures the complete UX architecture of ClawDefender's Mac GUI as of the current codebase snapshot. Refer to this for:
- **Design team:** Interaction flows, accessibility standards, notification patterns
- **QA & Testing:** User journeys, edge cases (offline, migration, timeouts)
- **Developers:** Routing structure, event flow, focus management, backward compatibility
- **Product:** Feature walkthrough, keyboard shortcuts, notification priorities

