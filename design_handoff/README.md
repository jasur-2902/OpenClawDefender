# Handoff: Rookbot GUI

## Overview

Rookbot is the **user-facing application** that sits on top of the existing OpenRookbot Rust + eBPF daemon. The daemon already produces the events, verdicts, and policy enforcement (process exec hooks, network/DNS filtering, AI cold-path verdicts via the `claw-wall` userland service). This GUI surfaces what the daemon produces in a calm, consumer-friendly way — designed for everyday users, not just security pros.

The conceptual spine of the design is **chess**. Rookbot plays the role of the Rook, defending the user (King) against threats (opposing pieces). This metaphor shows up in the Home hero (a live mini chessboard whose state reflects security posture), in posture phrasing ("Defenders in position", "Pawn advanced", "Check", "Mate threatened"), and in My Tools (each MCP tool is rendered as the chess piece that best matches its capability — filesystem = Rook, network = Bishop, shell execution = Knight, metadata = Pawn).

## About the Design Files

The files in this bundle are **design references created in HTML / inline-Babel React** — prototypes that show intended look and behavior. They are not production code to copy directly.

The job is to **recreate these designs in Rookbot's actual GUI environment**, using its established patterns and libraries. Since the existing repo is a Rust daemon with a terminal UI and no shipped GUI yet, the implementer should choose the most appropriate framework for a desktop AI security app — recommended options, in order:

1. **Tauri + React/TypeScript** — Rust-native, smallest binary, can call into the existing Rust crates directly, cross-platform.
2. **SwiftUI** (macOS) / native Windows app — best OS integration but platform-locked.
3. **Electron + React** — fastest path if the team prefers it, but heavier.

The visual language was tuned to feel like an Apple HIG app (Settings.app, Family.app), so SwiftUI or Tauri+SF-Symbols mapping will feel most native.

## Fidelity

**High-fidelity.** All colors, typography, spacing, radii, and interactions are final. The implementer should reproduce them pixel-perfect, then bind to real daemon data. Sample data lives in `data.js` and should be replaced with live IPC calls to the `claw-wall` daemon (RingBuf for events, JSON-RPC or similar for verdicts and config).

## Files in this bundle

| File | Role |
|---|---|
| `Rookbot.html` | Entry HTML — loads React 18 + Babel + every JSX file in order |
| `styles.css` | Design tokens (CSS variables) + global resets + animations |
| `data.js` | Mock data for events, alerts, MCP servers, scan stages, etc. |
| `atoms.jsx` | Shared primitives: `Rook`, `Dot`, `Badge`, `Icon`, `Btn`, `Card`, `Sparkline`, `Ring`, etc. |
| `chess.jsx` | Chess primitives: `ChessPiece`, `MiniBoard`, `postureBoard()`, `posturePhrase()`, `capabilityPiece()` |
| `shell.jsx` | App shell: `Sidebar`, `StatusHeader`, `TrayMenu` |
| `ask-rook-dock.jsx` | Bottom-of-Home pill that expands into a chat sheet |
| `screens-1.jsx` | `ScreenHome`, `ScreenActivity` |
| `screens-2.jsx` | `ScreenEventDetail`, `ScreenAlertDetail`, `ScreenAlerts` |
| `screens-3.jsx` | `ScreenScan`, `ScreenAsk`, `ScreenTools` |
| `screens-4.jsx` | `ScreenSettings`, `ScreenTransparency`, `ScreenOnboarding` |
| `app.jsx` | Top-level app: routing, posture state, live event simulator, tweak hue |
| `tweaks-panel.jsx` | Dev-time tweak overlay (skip in production) |
| `macos-window.jsx` | macOS window chrome (presentation only — drop in real app) |

## Design Tokens

Defined as CSS custom properties in `styles.css`. The exact values:

### Color — light theme (Apple HIG-style)

| Token | Value | Use |
|---|---|---|
| `--accent` | `oklch(0.62 0.18 220)` (≈ `#4a8fdc`) | Primary, links, active nav, defender Rook tint |
| `--accent-soft` | `oklch(0.62 0.18 220 / 0.10)` | Hover backgrounds, subtle fills |
| `--accent-line` | `oklch(0.62 0.18 220 / 0.30)` | Accent borders |
| `--bg-0` | `oklch(0.965 0.003 250)` (≈ `#f4f5f7`) | Sidebar, window chrome, app background |
| `--bg-1` | `oklch(1 0 0)` (`#ffffff`) | Content surface, cards |
| `--bg-2` | `oklch(0.965 0.003 250)` | Sunken / groove |
| `--bg-3` | `oklch(0.93 0.004 250)` | Divider strip |
| `--bg-4` | `oklch(0.88 0.005 250)` | Inactive controls |
| `--line` | `oklch(0.90 0.004 250)` | Card borders, hairlines |
| `--line-soft` | `oklch(0.94 0.003 250)` | Inner row separators |
| `--line-strong` | `oklch(0.82 0.005 250)` | Hover borders |
| `--ink-0` | `oklch(0.18 0.01 250)` | Primary text |
| `--ink-1` | `oklch(0.32 0.012 250)` | Secondary text |
| `--ink-2` | `oklch(0.50 0.012 250)` | Tertiary / metadata |
| `--ink-3` | `oklch(0.62 0.012 250)` | Quaternary / placeholders |
| `--ink-4` | `oklch(0.74 0.010 250)` | Disabled |
| `--green` | `oklch(0.62 0.16 152)` | Trusted, allowed, normal |
| `--amber` | `oklch(0.72 0.15 78)` | Watching, elevated, advisory |
| `--red` | `oklch(0.60 0.20 22)` | Blocked, threats, critical |
| `--violet` | `oklch(0.58 0.18 295)` | AI / cloud reasoning |

### Typography

- **UI font:** `-apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Inter", system-ui, sans-serif`
- **Mono font:** `"SF Mono", "JetBrains Mono", ui-monospace, Menlo, monospace` — used for IDs, IPs, ports, file paths
- **Type scale:**
  - Page H1: 30px / 700 / -0.6 letter-spacing
  - Section title: 20px / 600 / -0.3
  - Card title: 13.5px / 600
  - Body: 14px / 400 / 1.5 line-height
  - Small/secondary: 13px / 400
  - Metadata: 12px / 400
  - Caption: 11px / 600 (uppercase, +0.5 letter-spacing for section headers)

### Spacing

- Card padding: 16px (compact), 18px (default), 20–24px (spacious)
- Card gap: 10–14px between sibling cards, 24px between sections
- Page padding: 28px horizontal, 40–56px top, 24–48px bottom
- Page max width: 640px (Home, single-column reading), 1080px (dense screens)

### Radius

- `--radius-xs` = 4px (chips, very small badges)
- `--radius-sm` = 6px (buttons, badges)
- `--radius-md` = 10px (input fields, small cards)
- `--radius-lg` = 14px (cards)
- `--radius-xl` = 22px (hero containers)
- 999px for pill buttons and the Ask Rook dock

### Shadow

- `--shadow-sm` = `0 1px 2px oklch(0 0 0 / 0.06)` (cards at rest)
- `--shadow-md` = `0 4px 16px oklch(0 0 0 / 0.08)` (Ask Rook dock pill)
- `--shadow-lg` = `0 16px 40px oklch(0 0 0 / 0.10)` (tray menu)
- Sheet (chat overlay): `0 24px 64px oklch(0 0 0 / 0.20), 0 4px 12px oklch(0 0 0 / 0.08)`

## Screens / Views

### 1. Home (`ScreenHome`)

**Purpose** — One-glance answer to "am I OK right now?". Calm, consumer-friendly. Looks like Settings.app, not a SOC dashboard.

**Layout** — Centered single column, max-width 640px, padding 44px top / 28px sides.

**Components, top to bottom:**

1. **Hero card** (chessboard scene)
   - White card with 1px border, radius 18, padding 20px 28px, shadow-sm
   - Inside: 5×5 mini chessboard, tile size 36px
     - White Rook (blue accent tint) at b3, drop-shadow
     - White King (ink-0 tint) at c3
     - Threat pieces appear based on posture (see below)
     - Light tiles `--bg-2`, dark tiles use `color-mix(in oklch, var(--ink-3) 10%, var(--bg-2))`
     - Outer border 1px `oklch(0 0 0 / 0.10)`, inset 1px white highlight, radius 8
   - Below board: tiny posture chip — colored dot + uppercase 11px label ("DEFENDERS IN POSITION", "PAWN ADVANCED", "CHECK", "MATE THREATENED")
2. **H1 headline** — 30px / 700 / -0.6 — the plain-language version ("You're protected", "Something needs your attention", etc.)
3. **Subline** — 16px ink-2, lh 1.5, max 440px — one sentence of explanation
4. **Action row** — primary "Start scan" pill button (accent fill, white text, 38px tall, 999px radius), secondary "View activity" ghost button
5. **Latest alert** card if present — clickable, opens AlertDetail
6. **Activity summary list** — Settings.app-style rounded list ("12 things blocked today", "3 apps wrapped", "Last scan: 2 hours ago"), each row clickable
7. **Ask Rook dock** — sticky-bottom pill, 999px radius, white bg with shadow-md, chat icon in accent-soft square + placeholder + ⌘K kbd hint

**Posture states & board scenes** (defined in `chess.jsx > postureBoard()`):

| Posture | Board state | Phrase |
|---|---|---|
| `low` | Just King + Rook | "All quiet" / "No pieces in play" |
| `normal` | King + Rook | "You're protected" / "Defenders in position" |
| `elevated` | + black Pawn at e1 (far corner) | "Something needs your attention" / "Pawn advanced" |
| `high` | + red Knight at d3 (adjacent), pulsing red glow | "Active threat detected" / "Check" |
| `critical` | + red Queen at d3 + red Bishop at e5, both pulsing | "Confirmed attack in progress" / "Mate threatened" |

**Behavior** — Posture cycles via the tray menu (top-right). The board re-renders. Red enemy pieces have a pulsing red radial-gradient halo (`@keyframes cdPulse`, 1.8s ease-in-out infinite).

### 2. Activity (`ScreenActivity`)

**Purpose** — Pro-level feed of every event from the daemon RingBuf. Used by power users.

**Layout** — Full-width, header bar (filters), then a virtualized table.

**Components:**
- Header bar: live toggle (pulse dot + "Live" / "Paused"), kind dropdown (`exec | network | dns | file`), server dropdown, "Only what matters" toggle
- Table columns: time (mono), verdict pill (allowed/blocked/flagged), event kind icon, summary, server/process (mono), duration

**Behavior** — `events` prop is prepended every 4.2s in dev mock; replace with daemon RingBuf subscription. Click a row → EventDetail.

### 3. Event Detail (`ScreenEventDetail`)

**Layout** — Centered, max 1080px, back button + header + 2-column body.

**Components** — Verdict pill, severity, timestamp, "what happened" plain-language explanation, syscall name in mono, raw JSON drawer (collapsed by default), AI reasoning card with model badge ("local-llama-7b" or "claude-haiku-4-5"), correlated-event rail.

### 4. Alerts (`ScreenAlerts`)

**Purpose** — Mail-app-style grouped list.

**Layout** — Single column, max 720px, padding 40px top.

**Components:**
- Section headers: small dot + uppercase label "CRITICAL · 2", "HIGH · 5", etc.
- Rounded list (`--bg-1`, 1px border, radius 12, shadow-sm)
- Each row: 8px severity dot, title (14/600), timestamp on right, summary (13/ink-2), metadata row (server name · status · event count), chevron right

**No left-border accent strip** — that pattern was rejected as AI-cliché.

### 5. Alert Detail (`ScreenAlertDetail`)

**Layout** — Single column, max 1080px.

**Components** — Severity badge, alert ID (mono), timestamp, kill chain timeline (each step is one event in mono notation), recommended actions (accent buttons), correlated events rail.

### 6. Scans (`ScreenScan`)

**Purpose** — Live AI investigation console.

**Layout** — 2-column: left = stage progress (5 cards, sequential, shimmer animation while running), right = live feed (mono, JetBrains Mono, ascending log lines, blinking accent caret).

**Components** — Stage cards have stage number, name, dynamic findings count. Below stages: triaged-findings list with severity dots. Bottom: "Run another scan" + "Export report" buttons.

### 7. Ask Rook (`ScreenAsk`)

**Layout** — 2-column: left sidebar history (chat list), right pane (header + scrollable messages + composer at bottom).

**Components** — User bubbles right-aligned (accent fill, white text), Rook bubbles left-aligned (bg-2, ink-0) with rook glyph avatar. "Powered by Claude" badge when cloud reasoning is invoked. Tool-use chips inline.

**Ask Rook Dock** — Reusable component (`ask-rook-dock.jsx`). Renders as a sticky pill at bottom of any screen; on click, dims the screen with a backdrop and slides up a centered chat sheet (640×min(620, 100vh-80px)). Esc closes. "Open full chat" link in sheet header navigates to ScreenAsk. First-open shows 3 suggestion chips: "What happened today?", "Should I worry about FileManager?", "Run a quick checkup".

### 8. My Tools (`ScreenTools`)

**Purpose** — One card per wrapped MCP server.

**Layout** — 2-column grid, gap 12px.

**Card components:**
- 40×40 piece tile: `--bg-2`, 1px line, radius 9, contains a `<ChessPiece>` whose kind is chosen by `capabilityPiece(server.capabilities)`:
  - `filesystem` → Rook
  - `network` / `api:github` → Bishop
  - `shell` → Knight
  - `metadata` / `git` → Pawn
  - The piece is colored by trust state (`trusted` = green, `watching` = amber, `untrusted` = red)
- Server name + client name (mono)
- Trust badge (top right of header row)
- Stats row (mono): events count, anomaly score (color-coded), wrapped/exposed status
- Capability chips (mono, bg-2 chips)

### 9. Settings: AI Analysis (`ScreenSettings`)

Active model selector (segmented: "local 7B", "local 13B", "Claude haiku-4-5"), tier table, cold-path threshold slider, "Send anonymized telemetry" toggle.

### 10. Activity Log / Transparency (`ScreenTransparency`)

Cost meter, count of cloud calls today, list of every cloud-bound prompt/response with redaction preview.

## Interactions & Behavior

### Routing

State-machine in `app.jsx`. Routes: `home`, `activity`, `event` (`{eventId}`), `alerts`, `alertDetail` (`{alertId}`), `scan`, `ask`, `tools`, `transparency`, `settings`, `onboarding`. `goto(name, params)` is the single navigation call.

### Animations (defined in `styles.css`)

| Class | Duration | Use |
|---|---|---|
| `.cd-pulse` | 1.6s | Live indicators (dot, threat halo) |
| `.cd-pulse-dot` | 1.6s | Ripple ring around a dot |
| `.cd-slide-in` | 0.32s `cubic-bezier(.2,.7,.2,1)` | Fly-in for new feed rows, tray menu |
| `.cd-shimmer` | 2s | Running scan stages |
| `.cd-spin` | 0.9s | Loading spinners |
| `.cd-caret` | 1s steps(1) | Terminal caret in scan feed |
| `.cd-sheet-in` | 0.24s `cubic-bezier(.2,.8,.2,1)` | Ask Rook chat sheet slide-up |
| `.cd-typing-dot` | 1.1s ease-in-out | Three-dot typing indicator in chat |

### Live data simulation

`app.jsx` has an interval that prepends a synthetic event every 4.2s. Replace with subscription to the daemon's RingBuf.

### Posture override

The tray menu has a hidden 5-button row to set posture for design demo. Remove in production; posture should be derived from real signals (active alerts × severity weights).

## State Management

### App-level state (in `app.jsx`)

- `route: { name, ...params }` — current screen
- `collapsed: bool` — sidebar collapsed
- `trayOpen: bool`
- `posture: "low" | "normal" | "elevated" | "high" | "critical"`
- `liveMode: bool` — pause/resume the event stream
- `filterMatter: bool` — "Only what matters" filter
- `filterKind: "all" | "exec" | "network" | "dns" | "file"`
- `filterServer: "all" | <serverId>`
- `events: Event[]` — current event window

### Per-screen state

`ScreenScan` keeps its own `running`, `stages`, `feed`. `ScreenAsk` and `AskRookDock` keep `messages`, `input`, `thinking`. Replace mock send with real Claude API or local model invocation.

### Real bindings (when implementing)

| UI prop | Daemon source |
|---|---|
| `events` | RingBuf subscription |
| `alerts` | Aggregator over events (server-side or app-side) |
| `servers` | `claw-wall` config + runtime stats |
| `verdict` per event | eBPF map result |
| `posture` | Computed: weighted sum of active alert severities |

## Assets

- **No external images.** Everything is SVG (drawn fresh) or CSS.
- **Chess pieces** — flat SVG silhouettes in `chess.jsx` (`ChessPiece` component supports `king`, `queen`, `rook`, `bishop`, `knight`, `pawn`).
- **Rook glyph** (used in logo, tray, dock avatar) — defined inline in `atoms.jsx` as `<Rook>`. ViewBox 0 0 45 45, two-path crenellated castle.
- **Icons** — defined inline in `atoms.jsx` as `<Icon name=…>`. 24×24 viewBox, stroke-based. Names: `home, activity, alert, scan, chat, tools, settings, audit, sidebar, check, x, chevron, shield, sparkles, cloud, lock, search, send, wrench, eye, pause, play, refresh`.

If you replace icons with SF Symbols (macOS) or Phosphor / Lucide (cross-platform), preserve the names so screen JSX stays readable.

## Notes for the implementer

- **The chess metaphor is load-bearing** for the visual identity — keep the chessboard hero, posture phrasing, and tool pieces. Do not regress to a generic "shield + traffic light" dashboard.
- **Apple-app calm, not SOC dashboard.** Resist the urge to add chart density, gauges, or telemetry walls to Home. Density belongs in Activity / Event Detail / Transparency only.
- **Mono font for facts, sans for prose.** IDs, IPs, ports, hashes, file paths in `var(--font-mono)`. Everything else in the UI font.
- **Verdict colors are non-negotiable:** green = allowed, amber = flagged/advisory, red = blocked, violet = AI/cloud-reasoning. Reuse across all screens.
- **Replace `data.js`** with real daemon IPC calls before shipping.
- **Drop `tweaks-panel.jsx` and `macos-window.jsx`** for production — they are dev/preview-only.
