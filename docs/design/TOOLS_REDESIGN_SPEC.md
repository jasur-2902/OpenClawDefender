# My Tools Page Redesign -- UX Specification

**Status**: Draft
**Author**: PM Agent
**Date**: 2026-04-27
**Scope**: Complete redesign of `src/pages/MyTools.tsx` and related components

---

## 1. Design Philosophy

The current My Tools page only shows tools that have MCP servers configured. If a user has Claude Desktop installed but no MCP servers, the page shows "No tools found" -- misleading, because RookBot already detects the tool and monitors its processes via eslogger.

**New paradigm**: Detect tool -> show it with process monitoring -> MCP servers are an OPTIONAL upgrade that adds per-server tool call monitoring.

This page is the FIRST page users see after onboarding. It must feel alive and valuable even without MCP servers configured.

---

## 2. Page Layout

```
+------------------------------------------------------------------+
| My Tools                                              [Rescan]   |
| Monitoring 3 AI tools on this Mac                                |
+------------------------------------------------------------------+
|                                                                  |
| +-- Summary Bar -----------------------------------------------+ |
| | 3 detected | 2 running | 1 with MCP servers | 4 unwrapped   | |
| +--------------------------------------------------------------+ |
|                                                                  |
| +-- Tool Card Grid (single column, stacked) -------------------+ |
| | [Claude Desktop card]                                        | |
| | [Cursor card]                                                | |
| | [VS Code card]                                               | |
| +--------------------------------------------------------------+ |
|                                                                  |
+------------------------------------------------------------------+
```

### 2.1 Header

- **Title**: `SectionTitle` with text "My Tools"
- **Subtitle**: Dynamic, computed from tool state:
  - `"Monitoring {n} AI tool{s} on this Mac"` when tools are detected
  - `"Scanning for AI tools..."` during scan phase
  - `"No AI tools found"` when nothing detected
- **Rescan button**: `Btn kind="ghost" size="sm" icon="refresh"` -- right-aligned, hidden during scan

### 2.2 Summary Bar

Displayed between the header and card grid. Only shown when at least 1 tool is detected.

A horizontal row of stat pills using the existing `Badge` component:

| Stat | Color | Example |
|------|-------|---------|
| Detected count | `var(--ink-2)` | "3 detected" |
| Running count | `var(--green)` | "2 running" |
| MCP servers count | `var(--accent)` | "1 with MCP servers" (or "No MCP servers" in `--ink-3`) |
| Unwrapped count | `var(--amber)` | "4 unwrapped" (only if > 0) |

**Layout**: `display: flex; gap: 8; flexWrap: wrap; padding: 12px 0; marginBottom: 8px`

### 2.3 Card Grid

- **Layout**: Single column, full width. `display: flex; flexDirection: column; gap: 14`
- **Rationale**: Cards contain rich multi-row content (process stats, MCP servers list). Single column gives more horizontal space. Two-column layout was used for the old compact tiles; the new cards are too content-rich for that.
- **Sorting**: Active tools first, then not-running tools sorted by last active time (most recent first)
- **Max width**: `1080px`, centered with `margin: 0 auto`

---

## 3. Tool Card Design

Each card represents a detected AI tool (client), NOT an individual MCP server. This is the fundamental shift from the current design.

### 3.1 Card Shell

Uses the existing `Card` component pattern but as a custom button element for navigation:

```
background: var(--bg-1)
border: 1px solid var(--line)
borderRadius: var(--radius-lg)  /* 14px */
padding: 20px
cursor: pointer
hover: border-color -> var(--line-strong)
```

### 3.2 Card States

Three distinct visual states:

#### State A: Active (tool is running)

```
+---------------------------------------------------------------+
|  [icon]  Claude Desktop                            Active (*)  |
|          Anthropic's desktop app                               |
|                                                                |
|  Process Monitoring     * Watching (PID 4521 + 3 children)     |
|  Files accessed today   47 files                               |
|  Network connections    12 (api.anthropic.com, cdn....)        |
|  MCP Servers            None detected . What's this?           |
|                                                                |
|  [View Activity]  [View Profile]                               |
+---------------------------------------------------------------+
```

#### State B: Active with MCP Servers

```
+---------------------------------------------------------------+
|  [icon]  Claude Desktop                            Active (*)  |
|          Anthropic's desktop app                               |
|                                                                |
|  Process Monitoring     * Watching (PID 4521 + 3 children)     |
|  Files accessed today   47 files                               |
|  Network connections    12                                     |
|                                                                |
|  MCP Servers (2):                                              |
|    * filesystem       Wrapped . 34 tool calls today            |
|    ! brave-search     Unwrapped . [Protect]                    |
|                                                                |
|  [View Activity]  [View Profile]  [View Tool Calls]            |
+---------------------------------------------------------------+
```

#### State C: Not Running

```
+---------------------------------------------------------------+
|  [icon]  VS Code                                Not Running    |
|          With MCP extension                                    |
|                                                                |
|  Process Monitoring     (-) Not running                        |
|  Last active            Yesterday at 4:32 PM                   |
|  MCP Servers            None detected . What's this?           |
|                                                                |
|  [View History]                                                |
+---------------------------------------------------------------+
```

### 3.3 Not Installed State

Tools that are not installed are NOT shown as cards. They only appear in the empty state (section 7) and during scan animation. This keeps the page clean and focused on tools that actually exist on the system.

---

## 4. Card Content Specification

### 4.1 Card Header Row

```
display: flex; alignItems: center; gap: 12; marginBottom: 14
```

**Left icon**: 40x40px rounded square (`borderRadius: 9`) with tool-specific icon. Uses a neutral background `var(--bg-2)` with `border: 1px solid var(--line)`. Contains the `Rook` chess piece (reused from design system) at 26px, colored by status:
- Active: `var(--green)`
- Not running: `var(--ink-3)`

**Tool name**: `fontSize: 15; fontWeight: 600; color: var(--ink-0)`

**Tool description**: Below the name. `fontSize: 12; color: var(--ink-2)`. One of:
- "Anthropic's desktop app" (Claude Desktop)
- "AI-first code editor" (Cursor)
- "With MCP extension" (VS Code)
- "Codeium's AI IDE" (Windsurf)
- "CLI for Claude" (Claude Code)

**Status badge**: Right-aligned. Uses `Badge` component:
- Active: `Badge color="var(--green)"` with `Dot color="var(--green)" size={6} pulse` + text "Active"
- Not Running: `Badge color="var(--ink-3)"` with text "Not Running"

### 4.2 Process Monitoring Section

A vertical list of key-value rows using a custom layout (NOT the `KV` component, because we need richer value formatting).

**Row layout**:
```
display: flex; alignItems: baseline; padding: 6px 0
Label:  fontSize: 12.5; color: var(--ink-2); width: 160px; flexShrink: 0
Value:  fontSize: 12.5; color: var(--ink-0); fontFamily: var(--font-mono)
```

**Row: Process Monitoring**
- Label: "Process Monitoring"
- Value (active): `Dot color="var(--green)" size={7} pulse` + `"Watching (PID {pid} + {n} children)"` in `var(--ink-0)`
- Value (not running): `Dot color="var(--ink-3)" size={7}` + `"Not running"` in `var(--ink-3)`

**Row: Files accessed today** (only when active)
- Label: "Files accessed today"
- Value: `"{count} files"` -- number in `var(--ink-0)`, "files" in `var(--ink-2)`
- If count is 0: `"No file access"` in `var(--ink-3)`

**Row: Network connections** (only when active)
- Label: "Network connections"
- Value: `"{count}"` in `var(--ink-0)`
- If destinations available, append truncated list: `"(api.anthropic.com, cdn...)"` in `var(--ink-3)`, `fontSize: 11`
- If count is 0: `"No connections"` in `var(--ink-3)`

**Row: Last active** (only when NOT running)
- Label: "Last active"
- Value: Relative time string. Examples: `"Yesterday at 4:32 PM"`, `"2 hours ago"`, `"Never"` in `var(--ink-3)` if truly never seen

**Row: MCP Servers** (when NO MCP servers)
- Label: "MCP Servers"
- Value: `"None detected"` in `var(--ink-3)` + `" . "` + link-styled text `"What's this?"` in `var(--accent)` (navigates to help/docs overlay)

### 4.3 MCP Server Section

Only rendered when the tool has MCP servers (servers_count > 0). Replaces the "MCP Servers: None detected" row.

**Section header**:
```
fontSize: 12.5; color: var(--ink-2); fontWeight: 500
marginTop: 10; marginBottom: 6
Text: "MCP Servers ({count}):"
```

**Server rows**: Each server is a sub-row inside the card:

```
display: flex; alignItems: center; gap: 8; padding: 5px 8px
background: var(--bg-2); borderRadius: var(--radius-sm); marginBottom: 4
```

Each row contains:
1. **Status dot**: `Dot` component
   - Wrapped: `color="var(--green)" size={6}`
   - Unwrapped: `color="var(--amber)" size={6}`
2. **Server name**: `fontSize: 12; fontWeight: 500; fontFamily: var(--font-mono); color: var(--ink-0)`
3. **Status text** (flex: 1):
   - Wrapped: `"Wrapped"` in `var(--green)` + `" . "` + `"{n} tool calls today"` in `var(--ink-2)` -- `fontSize: 11`
   - Unwrapped: `"Unwrapped"` in `var(--amber)` -- `fontSize: 11`
4. **Action** (right-aligned):
   - Unwrapped servers: `Btn kind="accent" size="sm"` with text "Protect"
   - Wrapped servers: no button (or a subtle ghost chevron for detail nav)

### 4.4 Action Buttons Row

Bottom of the card. `display: flex; gap: 8; marginTop: 14; paddingTop: 12; borderTop: 1px solid var(--line-soft)`

Buttons use `Btn kind="soft" size="sm"`:

**Active tool (no MCP servers)**:
- "View Activity" -- navigates to `/activity?tool={client_id}`
- "View Profile" -- navigates to `/tools/{client_id}/profile`

**Active tool (with MCP servers)**:
- "View Activity" -- navigates to `/activity?tool={client_id}`
- "View Profile" -- navigates to `/tools/{client_id}/profile`
- "View Tool Calls" -- navigates to `/activity?tool={client_id}&source=mcp`

**Not running tool**:
- "View History" -- navigates to `/activity?tool={client_id}`

---

## 5. Scan Flow

### 5.1 Initial Scan (first launch / rescan)

The scan flow is largely preserved from the current `ScanChecklist` component but updated to reflect the new paradigm:

1. **Phase: Scanning** -- `ScanChecklist` is displayed, header subtitle changes to "Scanning for AI tools..."
2. The scan calls `detect_mcp_clients` (existing backend) which returns all 5 tools with `detected: bool`
3. Each tool row animates sequentially (current behavior, 400ms stagger)
4. **Updated row results**:
   - "Found" now shows: `"{display_name} detected"` (not `"N servers"`)
   - "Not found" shows: `"Not installed"` (same as current)
5. **Phase: Complete** -- Scan summary appears, then the new tool card grid renders

### 5.2 Scan Summary Update

After scan completes, the `ScanSummaryBar` should show:
- `"{n} tools detected"` (not "tools found with servers")
- `"{m} with MCP servers"` (secondary stat)
- `"{k} unwrapped"` (if applicable)

### 5.3 Rescan Button

- Appears in the page header, right-aligned
- `Btn kind="ghost" size="sm" icon="refresh"` with text "Rescan"
- Hidden during active scan
- On click: sets scanPhase to "scanning", reruns the scan flow

---

## 6. Data Flow & Backend Integration

### 6.1 New Backend Command: `get_detected_tools_with_stats`

A new Tauri command that returns tool-level data (not server-level). This is the primary data source for the redesigned page.

**Input**: None

**Output**: `DetectedTool[]` where:

```typescript
interface DetectedTool {
  client_id: string;           // "claude", "cursor", "vscode", "windsurf", "claude_code"
  display_name: string;        // "Claude Desktop", "Cursor", etc.
  description: string;         // "Anthropic's desktop app", etc.
  detected: boolean;           // true if config path exists on disk
  config_path: string;         // path to config file

  // Process monitoring
  is_running: boolean;         // true if process is active
  pid: number | null;          // main process PID (null if not running)
  child_count: number;         // number of child processes in tree

  // Activity stats (today, from event store)
  files_accessed_today: number;
  network_connections_today: number;
  top_destinations: string[];  // up to 3 most-contacted domains
  last_active: string | null;  // ISO timestamp of last activity

  // MCP servers
  servers: McpServerInfo[];
}

interface McpServerInfo {
  name: string;
  wrapped: boolean;
  tool_calls_today: number;
  status: "running" | "stopped" | "error";
}
```

**Implementation approach**: Combines data from:
1. `detect_mcp_clients()` -- for detection status and config paths
2. Process tree (sysinfo refresh) -- for PID, child count, running status
3. Event store (audit.jsonl) -- for file access counts, network counts
4. `list_mcp_servers()` -- for MCP server details per client

### 6.2 New Frontend Store: `useToolsPageStore`

Replaces the current `useToolStore` usage in `MyTools.tsx`. The store manages:

```typescript
interface ToolsPageStore {
  detectedTools: DetectedTool[];
  loading: boolean;
  error: string | null;
  scanPhase: "idle" | "scanning" | "complete";

  fetchDetectedTools: () => Promise<void>;
  setScanPhase: (phase: ScanPhase) => void;
}
```

### 6.3 Polling & Real-time Updates

- **Poll interval**: 30 seconds (same as current `POLL_INTERVAL`)
- **Tauri events**: Listen for `rookbot://new-tool-detected` (existing) to trigger immediate refresh
- **Process status**: Refreshed on each poll (process tree is ephemeral)
- **Event counts**: Computed from the event store filter by today's date and client_id

---

## 7. Empty States

### 7.1 No Tools Installed (post-scan)

When scan completes and zero tools are detected:

```
+---------------------------------------------------------------+
|                                                                |
|                     [Rook icon, 48px, --ink-3]                 |
|                                                                |
|              No AI tools found on this Mac                     |
|                                                                |
|  RookBot monitors AI coding tools. Install one of the          |
|  supported tools below, then scan again.                       |
|                                                                |
|  +-- Supported Tools List --------------------------------+    |
|  |  Claude Desktop  --  Anthropic's desktop app           |    |
|  |  Cursor           --  AI-first code editor             |    |
|  |  VS Code          --  With MCP extension               |    |
|  |  Windsurf         --  Codeium's AI IDE                 |    |
|  |  Claude Code      --  CLI for Claude                   |    |
|  +--------------------------------------------------------+    |
|                                                                |
|                      [Scan again]                              |
|                                                                |
+---------------------------------------------------------------+
```

This is structurally identical to the current `EmptyToolsState` (hasScanned=true) -- no changes needed except updating the descriptive copy to remove the MCP server requirement:

**Old**: "RookBot monitors MCP servers inside AI coding tools. Install one of the supported tools below, add an MCP server, then scan again."

**New**: "RookBot monitors AI coding tools. Install one of the supported tools below, then scan again."

### 7.2 Pre-scan (idle, no tools loaded yet)

Same as current `EmptyToolsState` (hasScanned=false) with updated copy:

**Old**: "I don't see any AI tools installed. I support Claude Desktop, Cursor, VS Code, and Windsurf."

**New**: "Scan to detect AI tools on this Mac. I support Claude Desktop, Cursor, VS Code, Windsurf, and Claude Code."

### 7.3 All Detected but None Running

Not an "empty state" -- the cards are still shown with "Not Running" status. The summary bar reflects `"0 running"`.

---

## 8. Process Monitoring Display

### 8.1 How PID & Children Are Shown

The process monitoring row shows a human-readable summary of the process tree:

**Format**: `"Watching (PID {mainPid} + {childCount} children)"`

Examples:
- `"Watching (PID 4521 + 3 children)"` -- Claude Desktop with node, renderer, etc.
- `"Watching (PID 8912)"` -- No children (e.g., Claude Code CLI)
- `"Watching (PID 4521 + 12 children)"` -- VS Code / Electron apps

When `childCount === 0`, omit the `"+ N children"` part.

### 8.2 File Access Count

Computed by filtering the event store:
- Filter: `source_type === "os"` AND `event_type` contains file-related actions (open, create, rename, unlink, write, etc.)
- Filter: `client_name === tool.client_id` (attributed via process tree)
- Filter: timestamp is within today (midnight to now)
- Count distinct events

### 8.3 Network Connection Count

Computed by filtering the event store or calling `get_network_connections`:
- Filter: attributed to this tool's process tree
- Filter: timestamp within today
- Count distinct connections
- Extract top 3 destination domains for display

### 8.4 Last Active Timestamp

For tools that are not currently running:
- The most recent event timestamp attributed to this tool's process tree
- Formatted as: "Yesterday at 4:32 PM", "2 hours ago", "Apr 25 at 9:15 AM", etc.
- If no events ever recorded: `"Never"` in `var(--ink-3)`

---

## 9. Refresh & Polling

### 9.1 Polling Strategy

| Data | Interval | Source |
|------|----------|--------|
| Tool detection + process status | 30s | `get_detected_tools_with_stats` |
| File/network counts | 30s | Returned in same command |
| MCP server wrap status | 30s | Returned in same command |

### 9.2 Real-time Event Listener

Listen to Tauri event `rookbot://new-tool-detected` for immediate refresh when a new tool appears. This is already wired in the current implementation.

### 9.3 Optimistic Updates

When a user clicks "Protect" on an unwrapped MCP server:
1. Immediately update the server's `wrapped` status to `true` in local state (optimistic)
2. Call `wrap_server` Tauri command
3. On success: no-op (already updated)
4. On failure: revert to `wrapped: false`, show error toast

---

## 10. Component Structure

### 10.1 New Components

#### `ToolClientCard` (replaces `ToolTile`)
**File**: `src/components/tools/ToolClientCard.tsx`

**Props**:
```typescript
interface ToolClientCardProps {
  tool: DetectedTool;
  onProtectServer?: (serverName: string) => void;
}
```

**Responsibility**: Renders a single tool card with all states (active, not running). Contains the process monitoring section, MCP server list, and action buttons.

#### `ProcessMonitorRow`
**File**: `src/components/tools/ProcessMonitorRow.tsx`

**Props**:
```typescript
interface ProcessMonitorRowProps {
  label: string;
  children: React.ReactNode;
}
```

**Responsibility**: A labeled row in the process monitoring section. Simple flex layout with fixed-width label and flexible value.

#### `McpServerRow`
**File**: `src/components/tools/McpServerRow.tsx`

**Props**:
```typescript
interface McpServerRowProps {
  server: McpServerInfo;
  onProtect?: () => void;
}
```

**Responsibility**: Renders a single MCP server sub-row within a tool card. Shows status dot, name, wrap status, and protect button.

#### `ToolsSummaryBar` (replaces `ScanSummaryBar` for post-scan view)
**File**: `src/components/tools/ToolsSummaryBar.tsx`

**Props**:
```typescript
interface ToolsSummaryBarProps {
  detectedCount: number;
  runningCount: number;
  mcpServerCount: number;
  unwrappedCount: number;
}
```

**Responsibility**: Horizontal row of stat badges shown above the card grid.

### 10.2 Modified Components

#### `MyTools` page (`src/pages/MyTools.tsx`)
- Remove `ToolTile` inline component
- Replace 2-column grid with single-column card list
- Switch data source from `useToolStore.tools` (server-level) to `useToolsPageStore.detectedTools` (client-level)
- Update header subtitle to be dynamic
- Integrate `ToolsSummaryBar`

#### `EmptyToolsState` (`src/components/EmptyToolsState.tsx`)
- Update copy to remove MCP server requirement
- Add "Claude Code" to supported tools list (already there)
- No structural changes needed

#### `ScanChecklist` (`src/components/ScanChecklist.tsx`)
- Update "found" row to show `"{display_name} detected"` instead of `"{N} servers"`
- Still shows server count as secondary info: `"detected (2 MCP servers)"` when servers_count > 0

### 10.3 Preserved Components (no changes)

- `Card`, `Badge`, `Btn`, `Dot`, `Icon`, `SectionTitle`, `KV` -- design system unchanged
- `ScanErrorState` -- error handling flow unchanged
- `ToolCard` (old) -- kept for backward compatibility on `ToolDetail` page, but no longer used on My Tools

### 10.4 New Types

Add to `src/types/index.ts`:

```typescript
export interface DetectedTool {
  client_id: string;
  display_name: string;
  description: string;
  detected: boolean;
  config_path: string;
  is_running: boolean;
  pid: number | null;
  child_count: number;
  files_accessed_today: number;
  network_connections_today: number;
  top_destinations: string[];
  last_active: string | null;
  servers: McpServerInfo[];
}

export interface McpServerInfo {
  name: string;
  wrapped: boolean;
  tool_calls_today: number;
  status: "running" | "stopped" | "error";
}
```

---

## 11. Navigation & Routing

### 11.1 Card Click Behavior

Clicking the card body navigates to a tool detail page:
- Route: `/tools/{client_id}` (e.g., `/tools/claude`)
- This requires updating `ToolDetail.tsx` to support client-level views (currently keyed on `server_name`)

### 11.2 Action Button Navigation

| Button | Route | Query Params |
|--------|-------|-------------|
| View Activity | `/activity` | `?tool={client_id}` |
| View Profile | `/tools/{client_id}/profile` | -- |
| View Tool Calls | `/activity` | `?tool={client_id}&source=mcp` |
| View History | `/activity` | `?tool={client_id}` |

### 11.3 "What's this?" Link

The "What's this?" text next to "None detected" on the MCP Servers row opens a help overlay or navigates to a documentation section explaining:
- What MCP servers are
- How they enhance monitoring
- How to add one to their tool

Implementation: For v1, navigate to an external docs URL or show an inline tooltip. Use `Btn kind="ghost" size="sm"` styled as inline text link.

---

## 12. Visual Refinements

### 12.1 Color Usage Summary

| Element | Color Token |
|---------|-------------|
| Active status dot | `var(--green)` with `pulse` |
| Active badge text | `var(--green)` |
| Not running status dot | `var(--ink-3)` |
| Not running badge text | `var(--ink-3)` |
| Wrapped server dot | `var(--green)` |
| Unwrapped server dot | `var(--amber)` |
| "Protect" button | `Btn kind="accent"` |
| File/network count numbers | `var(--ink-0)` |
| File/network count labels | `var(--ink-2)` |
| "What's this?" link | `var(--accent)` |
| Card border (default) | `var(--line)` |
| Card border (hover) | `var(--line-strong)` |

### 12.2 Typography Summary

| Element | Size | Weight | Family | Color |
|---------|------|--------|--------|-------|
| Tool name | 15px | 600 | UI | `--ink-0` |
| Tool description | 12px | 400 | UI | `--ink-2` |
| Status badge | 10.5px | 600 | UI | varies |
| KV label | 12.5px | 400 | UI | `--ink-2` |
| KV value | 12.5px | 400 | Mono | `--ink-0` |
| MCP section header | 12.5px | 500 | UI | `--ink-2` |
| Server name | 12px | 500 | Mono | `--ink-0` |
| Server status | 11px | 400 | UI | varies |
| Action buttons | 12px | 500 | UI | via `Btn` |

### 12.3 Spacing Summary

| Element | Value |
|---------|-------|
| Page padding | 24px |
| Card padding | 20px |
| Card gap (between cards) | 14px |
| Card border radius | 14px (`--radius-lg`) |
| Header margin-bottom | 22px (via `SectionTitle`) |
| Summary bar margin-bottom | 8px |
| KV row padding | 6px 0 |
| KV label width | 160px |
| MCP server row padding | 5px 8px |
| MCP server row gap | 4px |
| Action buttons row margin-top | 14px |
| Action buttons row padding-top | 12px |
| Action buttons gap | 8px |

---

## 13. Accessibility

- All cards are `<button>` elements (or `role="article"` with `tabIndex={0}`) for keyboard navigation
- Status badges use `role="status"` with descriptive `aria-label`
- Pulsing dots include `aria-hidden="true"` (decorative)
- MCP server "Protect" buttons have `aria-label="Protect {serverName} MCP server"`
- Summary bar items are read as a single group with `aria-label="Tool monitoring summary"`
- "What's this?" link includes `aria-label="Learn about MCP servers"`

---

## 14. Migration Path

### Phase 1: Backend command
1. Implement `get_detected_tools_with_stats` Tauri command
2. Add process tree lookup for known client binaries
3. Aggregate event store counts per client

### Phase 2: Frontend components
1. Add `DetectedTool` / `McpServerInfo` types to `src/types/index.ts`
2. Create `ToolClientCard`, `ProcessMonitorRow`, `McpServerRow`, `ToolsSummaryBar`
3. Create `useToolsPageStore` (or extend `useToolStore`)

### Phase 3: Page assembly
1. Rewrite `MyTools.tsx` to use new store and components
2. Update `EmptyToolsState` copy
3. Update `ScanChecklist` result display
4. Wire up navigation and action buttons

### Phase 4: Polish
1. Test all states (no tools, tools without MCP, tools with MCP, mixed)
2. Verify polling and real-time updates
3. Ensure accessibility compliance
4. Update any tests in `src/tests/` that reference the old page structure
