# Scan Tools UX Specification

> My Tools page — scan flow, states, copy, and component structure.

---

## 1. Supported AI Tools & Config Paths

| Tool | Config Paths |
|------|-------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json`, `config.json` |
| Cursor | `~/.cursor/mcp.json`, `mcp_config.json` |
| VS Code | `~/.vscode/mcp.json`, `~/Library/Application Support/Code/User/settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Claude Code | `~/.claude.json`, `~/.claude/settings.json` |

---

## 2. Scanning State (user clicks "Scan for tools")

### Behavior
When the user clicks "Scan for tools", the empty state or button is replaced by a **ScanChecklist** panel. Each supported tool appears as a row in a vertical checklist. Rows animate in sequence (staggered ~400ms apart) to create a real-time "checking now" effect.

### ScanChecklist Layout

```
┌──────────────────────────────────────────────────────────────────┐
│  Scanning your system...                                         │
│  Looking for AI tools with MCP server configurations.            │
│                                                                  │
│  ● [spinner]  Claude Desktop                                     │
│               ~/Library/Application Support/Claude/               │
│                                                                  │
│  ○            Cursor                      (dimmed — waiting)     │
│               ~/.cursor/                                          │
│                                                                  │
│  ○            VS Code                     (dimmed — waiting)     │
│               ~/.vscode/                                          │
│                                                                  │
│  ○            Windsurf                    (dimmed — waiting)     │
│               ~/.codeium/windsurf/                                │
│                                                                  │
│  ○            Claude Code                 (dimmed — waiting)     │
│               ~/.claude/                                          │
└──────────────────────────────────────────────────────────────────┘
```

### Row States

Each checklist row transitions through these states:

| State | Left Icon | Name Color | Path Color | Right Side |
|-------|-----------|-----------|------------|------------|
| **waiting** | Dot (var(--ink-3), 8px) | var(--ink-3) | var(--ink-3) | — |
| **checking** | Spinning Dot (var(--accent), pulse=true, 8px) + css spin animation | var(--ink-0) | var(--ink-2) | "Checking..." in var(--ink-3), fontSize 11 |
| **found** | Icon "check" (var(--green), 14px) | var(--ink-0) | var(--ink-2) | Badge: "X servers" in green |
| **not_found** | Icon "x" (var(--ink-3), 14px) | var(--ink-3) | var(--ink-3) | "Not installed" in var(--ink-3), fontSize 11 |
| **error** | Icon "alert" (var(--amber), 14px) | var(--ink-2) | var(--ink-3) | "Permission denied" or error text in var(--amber), fontSize 11 |

### Timing & Animation

- Each tool starts in **waiting** state.
- Tools transition to **checking** one at a time, top to bottom, with a 400ms stagger.
- Each check takes its real async duration (typically <200ms for file existence checks), but is clamped to a minimum of 300ms display time so the user can see each step.
- When a check completes, the row immediately transitions to **found**, **not_found**, or **error**.
- The next tool transitions to **checking** after the previous one resolves.
- Total scan should complete in under 3 seconds for all 5 tools.

### Copy

- **Heading**: "Scanning your system..."
- **Subheading**: "Looking for AI tools with MCP server configurations."
- **Checking label** (right side): "Checking..."
- **Not found label**: "Not installed"
- **Error labels**: "Permission denied" | "Could not read config" | "Access error"

---

## 3. Results State — Scan Complete Summary

After all 5 checks resolve, the checklist panel fades out (150ms) and is replaced by a **ScanSummary** bar plus the tool grid (or empty state).

### Summary Bar (shown for 10 seconds, then fades to subtle or stays permanently)

#### Tools found:

```
┌──────────────────────────────────────────────────────────────────┐
│  [check icon]  Found 3 tools with 7 MCP servers                  │
│                2 servers need wrapping                   [Wrap all]│
└──────────────────────────────────────────────────────────────────┘
```

- Background: `var(--green-soft)`
- Border: `1px solid color-mix(in oklch, var(--green) 30%, transparent)`
- Icon: "check" in `var(--green)`, 16px
- Primary text: **"Found X tools with Y MCP servers"** — fontSize 12.5, fontWeight 600, color var(--ink-0)
- Secondary text: **"Z servers need wrapping"** — fontSize 12.5, color var(--ink-2), only shown if Z > 0
- Action button: `<Btn kind="primary" size="sm">Wrap all</Btn>` — only shown if unwrapped servers exist

#### No tools found:
(Transitions directly to Empty State in section 5 — no summary bar.)

#### Errors during scan:

```
┌──────────────────────────────────────────────────────────────────┐
│  [alert icon]  Scan completed with errors                        │
│                Some config files could not be read       [Details]│
└──────────────────────────────────────────────────────────────────┘
```

- Background: `var(--amber)` at 8% opacity
- Border: `1px solid color-mix(in oklch, var(--amber) 30%, transparent)`
- Icon: "alert" in `var(--amber)`, 16px
- Primary text: **"Scan completed with errors"** — fontWeight 600
- Secondary text: **"Some config files could not be read"**
- Action: `<Btn kind="ghost" size="sm">Details</Btn>` — opens a small expandable section listing each error

---

## 4. Results State — Tools Found (Tool Grid)

The existing `ToolTile` component and 2-column grid remain unchanged. No modifications needed — the current card design is good.

The grid appears after the scan summary with a 200ms fade-in.

---

## 5. Results State — No Tools Found (Empty State)

When the scan completes and no tools are found, show a helpful, guiding empty state.

### Layout

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│                     [shield icon, 48px]                           │
│                                                                  │
│               No AI tools found on this Mac                      │
│                                                                  │
│     RookBot monitors MCP servers inside AI coding tools.         │
│     Install one of the supported tools below, add an MCP         │
│     server, then scan again.                                     │
│                                                                  │
│     ┌──────────────────────────────────────────────────┐         │
│     │  Claude Desktop     — Anthropic's desktop app    │         │
│     │  Cursor             — AI-first code editor       │         │
│     │  VS Code            — With MCP extension         │         │
│     │  Windsurf           — Codeium's AI IDE           │         │
│     │  Claude Code        — CLI for Claude              │         │
│     └──────────────────────────────────────────────────┘         │
│                                                                  │
│                    [ Scan again ]                                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Copy

- **Heading**: "No AI tools found on this Mac"
  - fontSize 15, fontWeight 600, color var(--ink-0)
- **Body**: "RookBot monitors MCP servers inside AI coding tools. Install one of the supported tools below, add an MCP server, then scan again."
  - fontSize 12.5, color var(--ink-2), maxWidth 400px, centered
- **Tool list**: Each row is a small `<div>` with:
  - Tool name in fontWeight 600, color var(--ink-1), fontSize 12.5
  - Dash separator
  - Description in color var(--ink-3), fontSize 12.5
  - The list is inside a subtle Card (background var(--bg-1), border var(--line), borderRadius 10, padding 12)
  - Rows separated by 8px vertical gap
- **Button**: `<Btn kind="primary" onClick={handleScan}>Scan again</Btn>`

### Design Notes
- No "broken" language — keep tone neutral and helpful.
- The tool list serves as both education ("what do we support?") and a subtle call-to-action.
- No external links (desktop app cannot guarantee browser availability), just tool names and descriptions.

---

## 6. Error State — Permission / Access Errors

### Per-tool errors (during scan)
Handled inline in the ScanChecklist rows (see section 2, **error** row state). The user sees exactly which tool had an issue and a short reason.

### Full scan failure (backend unreachable or exception)
If the entire scan operation throws (not individual tool checks), show:

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│                     [alert icon, 40px, amber]                    │
│                                                                  │
│               Scan could not complete                            │
│                                                                  │
│     RookBot needs file access permission to read AI tool         │
│     config files. Open System Settings > Privacy & Security >    │
│     Full Disk Access and make sure RookBot is enabled.           │
│                                                                  │
│                    [ Try again ]                                  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Copy

- **Heading**: "Scan could not complete"
  - fontSize 15, fontWeight 600, color var(--ink-0)
- **Body**: "RookBot needs file access permission to read AI tool config files. Open System Settings > Privacy & Security > Full Disk Access and make sure RookBot is enabled."
  - fontSize 12.5, color var(--ink-2), maxWidth 400px, centered
- **Button**: `<Btn kind="primary" onClick={handleScan}>Try again</Btn>`

---

## 7. Component Structure

### New Components

#### `ScanChecklist`

Location: `src/components/ScanChecklist.tsx`

```tsx
interface ScanChecklistProps {
  onComplete: (result: ScanResult) => void;
}

interface ScanResult {
  toolsFound: number;
  serversFound: number;
  unwrappedCount: number;
  errors: ScanToolError[];
}

interface ScanToolError {
  toolName: string;
  message: string;
}
```

**Responsibilities:**
- Renders the 5-row checklist
- Manages the staggered checking animation via `useEffect` + sequential async calls
- Calls `onComplete` when all checks finish with aggregated results
- Each row calls the backend to check a specific tool (or the existing `fetchTools` is called once, and rows animate for visual effect while awaiting the single backend response)

**Internal state:**
```tsx
type CheckStatus = "waiting" | "checking" | "found" | "not_found" | "error";

interface ToolCheckState {
  name: string;            // "Claude Desktop", "Cursor", etc.
  configDir: string;       // "~/Library/Application Support/Claude/"
  status: CheckStatus;
  serverCount?: number;    // populated when found
  errorMessage?: string;   // populated on error
}
```

#### `ScanChecklistRow`

Location: inline within `ScanChecklist.tsx` (not exported)

```tsx
interface ScanChecklistRowProps {
  name: string;
  configDir: string;
  status: CheckStatus;
  serverCount?: number;
  errorMessage?: string;
}
```

**Rendering rules:**
- Left icon: Dot, spinning Dot, Icon("check"), Icon("x"), or Icon("alert") depending on status
- Name: bold tool name
- Path: monospace config directory path below the name
- Right side: varies by status (see section 2 table)

#### `ScanSummaryBar`

Location: `src/components/ScanSummaryBar.tsx`

```tsx
interface ScanSummaryBarProps {
  toolsFound: number;
  serversFound: number;
  unwrappedCount: number;
  errors: ScanToolError[];
  onWrapAll?: () => void;
  onViewErrors?: () => void;
}
```

**Rendering rules:**
- Green bar if tools found without errors
- Amber bar if errors occurred
- Hidden (not rendered) if zero tools found and no errors (empty state handles this)

#### `EmptyToolsState`

Location: `src/components/EmptyToolsState.tsx`

```tsx
interface EmptyToolsStateProps {
  onScan: () => void;
  hasScanned: boolean;   // true after first scan — changes copy slightly
}
```

**Rendering rules:**
- If `hasScanned === false`: shows the current simple "No tools found" + "Scan for tools" button (initial page load)
- If `hasScanned === true`: shows the full helpful empty state with tool list (after a scan returned zero results)

#### `ScanErrorState`

Location: `src/components/ScanErrorState.tsx`

```tsx
interface ScanErrorStateProps {
  onRetry: () => void;
  errorMessage?: string;
}
```

### Modified Components

#### `MyTools.tsx` — state machine

Add a `scanPhase` state to orchestrate the flow:

```tsx
type ScanPhase = "idle" | "scanning" | "complete";
```

- **idle**: Shows the tool grid (if tools exist) or the initial empty state. "Scan for tools" button visible.
- **scanning**: Shows `ScanChecklist`. Tool grid and empty state hidden.
- **complete**: Shows `ScanSummaryBar` + tool grid, OR `EmptyToolsState` with `hasScanned=true`, OR `ScanErrorState`.

The phase transitions:
1. User clicks "Scan for tools" → `scanPhase = "scanning"`
2. `ScanChecklist` calls `onComplete` → `scanPhase = "complete"`, store refreshed
3. If scan throws → `scanPhase = "complete"` with error flag

### Existing Components Used (no changes)

- `Btn` — primary, ghost, soft, sm/md sizes
- `Icon` — check, x, alert, shield, tools
- `Badge` — for server count in found rows
- `Dot` — for waiting/checking indicator with pulse
- `Card` — for the supported tools list in empty state
- `SectionTitle` — page header (already in place)

---

## 8. CSS Animations Needed

### Spinner for "checking" state
Use the existing `cd-pulse` class for the dot, or add a small spin keyframe:

```css
@keyframes cd-spin {
  to { transform: rotate(360deg); }
}
.cd-spin {
  animation: cd-spin 0.8s linear infinite;
}
```

### Row fade-in
Each row transitions from `opacity: 0.4` (waiting) to `opacity: 1` (checking/found/error) with `transition: opacity 0.3s ease`.

### Panel transitions
- Checklist → results: `opacity` transition, 150ms.
- Results fade-in: 200ms delay after checklist fades.

---

## 9. Interaction Summary

```
[Page loads]
    │
    ├── Tools in store? ──yes──► Show tool grid (current behavior)
    │                            + "Rescan" ghost button in header
    │
    └── No tools? ──────────────► Show EmptyToolsState (hasScanned=false)
                                   "No tools found" + "Scan for tools" button
                                          │
                                    [User clicks Scan]
                                          │
                                          ▼
                                   ScanChecklist (animated checklist)
                                          │
                                    [All checks done]
                                          │
                              ┌───────────┼───────────┐
                              │           │           │
                          Tools found  Nothing    Full error
                              │        found         │
                              ▼           │           ▼
                        ScanSummaryBar    │     ScanErrorState
                        + Tool grid       │     "Scan could not complete"
                                          ▼     + "Try again"
                                   EmptyToolsState
                                   (hasScanned=true)
                                   with supported tools list
                                   + "Scan again"
```

---

## 10. Rescan Behavior

When tools already exist in the grid, add a subtle rescan control to the page header area:

```tsx
<SectionTitle sub="Each MCP server is wrapped at the eBPF layer.">
  My Tools
</SectionTitle>
{/* Rescan button — shown when not in scanning phase */}
{scanPhase !== "scanning" && (
  <Btn kind="ghost" size="sm" icon="refresh" onClick={() => setScanPhase("scanning")}>
    Rescan
  </Btn>
)}
```

This replaces the hidden auto-polling scan with an explicit user-initiated action that provides full visual feedback.

---

## 11. Accessibility Notes

- All icons have `aria-label` or are decorative (`aria-hidden="true"`) with text labels alongside.
- Checklist rows use `role="listitem"` inside a `role="list"` container.
- Status changes announced via `aria-live="polite"` region containing a visually hidden summary like "Checking Cursor" → "Cursor: 3 servers found".
- Buttons have clear focus states via existing Btn component styling.
- Color is never the only indicator of status — text labels accompany all color-coded states.
