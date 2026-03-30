# ClawDefender Mac GUI — UX Specification
## For the UX/UI Design Team
## Date: 2026-02-26
## Version: 0.5.0-beta

---

# Table of Contents

1. [App Overview & Identity](#1-app-overview--identity)
2. [Information Architecture](#2-information-architecture)
3. [Design System Reference](#3-design-system-reference)
4. [Page-by-Page Specifications](#4-page-by-page-specifications)
5. [Component Inventory](#5-component-inventory)
6. [User Flow Maps](#6-user-flow-maps)
7. [Interaction Patterns](#7-interaction-patterns)
8. [State & Loading Patterns](#8-state--loading-patterns)
9. [Navigation & Keyboard Shortcuts](#9-navigation--keyboard-shortcuts)
10. [Notification & Alert System](#10-notification--alert-system)
11. [Accessibility](#11-accessibility)
12. [Data Shapes Reference](#12-data-shapes-reference)
13. [Known UX Gaps & Recommendations](#13-known-ux-gaps--recommendations)

---

# 1. App Overview & Identity

## What is ClawDefender?

ClawDefender is a **macOS desktop security application** that monitors and controls AI agents communicating via the Model Context Protocol (MCP). It sits between AI assistants (Claude Desktop, Cursor, VS Code, Windsurf) and MCP tool servers, intercepting every request to enforce security policies.

## Design Philosophy

The app has been redesigned around three principles:

1. **AI-first** — The primary interface is "Ask Claw", a conversational AI assistant that explains security events in plain language and takes actions on the user's behalf
2. **Human-friendly** — All technical security events are "humanized" into natural language with educational context
3. **Mac-native** — System tray integration, hide-on-close, keyboard shortcuts, dark mode by default, SF Pro Text font

## Target Users

- Developers using AI coding assistants who want visibility into what MCP tools are doing
- Security-conscious users who want to control tool permissions
- Non-security-experts who need guidance understanding threats

## App Shell

```
┌──────────────────────────────────────────────────┐
│  [Update Banner - conditional]                    │
│  [Restart Reminder Banner - conditional]          │
│  [Connection Status Banner - when disconnected]   │
├────────┬─────────────────────────────────────────┤
│        │  [Page Header]                           │
│  Side  │                                          │
│  bar   │  [Page Content]                          │
│        │                                          │
│  Nav   │                                          │
│  links │                                          │
│        │                                          │
│  [●]   │                                          │
│  daemon│                                          │
│  status│                                          │
├────────┴─────────────────────────────────────────┤
│  [Guidance Toast Container]                       │
│  [Prompt Overlay - modal, when active]            │
└──────────────────────────────────────────────────┘
```

**Exception**: The Onboarding page renders full-screen without the sidebar/shell.

---

# 2. Information Architecture

## Site Map

```
ClawDefender
├── / (Home) ← Default landing
│
├── /ask (Ask Claw) ← AI Conversational Assistant
│
├── /tools (My Tools) ← MCP Server Management
│   └── /tools/:id (Tool Detail)
│
├── /activity (Activity) ← Event Feed
│   └── /activity/:id (Event Detail)
│
├── /alerts (Alerts) ← Intelligent Alerts
│   └── /alerts/:id (Alert Detail)
│
├── /settings (Settings)
│   ├── /settings/policy (Policy Editor)
│   ├── /settings/health (System Health)
│   └── /settings/threat-intel (Threat Intelligence)
│
└── /onboarding (First-Run Setup) ← Full-screen, no sidebar
```

## Sidebar Navigation (6 items)

| Position | Icon | Label | Route | Badge |
|----------|------|-------|-------|-------|
| 1 | House | Home | `/` | — |
| 2 | Chat bubble | Ask Claw | `/ask` | — |
| 3 | Wrench | My Tools | `/tools` | — |
| 4 | List | Activity | `/activity` | — |
| 5 | Bell | Alerts | `/alerts` | Unresolved count (red dot) |
| 6 | Gear | Settings | `/settings` | — |

**Sidebar footer**: Daemon status indicator (green dot = running, red = stopped)

**Sidebar behavior**: Collapsible via toggle button. When collapsed, shows icons only.

## Legacy Route Redirects

| Old Route | New Route |
|-----------|-----------|
| `/dashboard` | `/` |
| `/timeline` | `/activity` |
| `/behavioral` | `/tools` |
| `/guards` | `/tools` |
| `/audit` | `/activity` |
| `/network` | `/alerts` |
| `/scanner` | `/alerts` |
| `/health` | `/settings/health` |
| `/ask-claw` | `/ask` |
| `/policy` | `/settings/policy` |
| `/threat-intel` | `/settings/threat-intel` |

---

# 3. Design System Reference

## 3.1 Color Palette

### Dark Mode (Default)

| Token | Hex | Usage |
|-------|-----|-------|
| `--color-bg-primary` | `#0f0f0f` | Main app background |
| `--color-bg-secondary` | `#1a1a1a` | Cards, elevated surfaces |
| `--color-bg-tertiary` | `#252525` | Hover states, nested cards |
| `--color-bg-sunken` | `#0a0a0a` | Recessed areas, inputs |
| `--color-text-primary` | `#e5e5e5` | Body text |
| `--color-text-secondary` | `#a3a3a3` | Labels, secondary text |
| `--color-text-muted` | `#6b7280` | Placeholders, disabled text |
| `--color-border` | `#2a2a2a` | Card borders, dividers |
| `--color-border-subtle` | `#1f1f1f` | Subtle separators |
| `--color-accent` | `#38bdf8` | Primary actions, links, active states (cyan) |
| `--color-accent-hover` | `#7dd3fc` | Accent hover state |
| `--color-accent-active` | `#0ea5e9` | Accent active/pressed state |
| `--color-accent-subtle` | `rgba(56,189,248,0.12)` | Accent background tint |
| `--color-safe` | `#22c55e` | Allowed events, healthy status, trusted |
| `--color-safe-light` | `#4ade80` | Safe hover/light variant |
| `--color-warning` | `#f59e0b` | Warnings, cautious trust level |
| `--color-warning-light` | `#fbbf24` | Warning hover/light variant |
| `--color-danger` | `#ef4444` | Blocked events, critical alerts, errors |
| `--color-danger-light` | `#f87171` | Danger hover/light variant |
| `--color-info` | `#3b82f6` | Informational badges, prompts |
| `--color-info-light` | `#60a5fa` | Info hover/light variant |

Each semantic color also has subtle background variants at 10% and 15% opacity for badges and highlights.

### Light Mode

| Token | Hex |
|-------|-----|
| `--color-bg-primary` | `#ffffff` |
| `--color-bg-secondary` | `#f8f9fa` |
| `--color-bg-tertiary` | `#f0f1f3` |
| `--color-bg-sunken` | `#e5e7eb` |
| `--color-text-primary` | `#1a1a1a` |
| `--color-text-secondary` | `#6b7280` |
| `--color-text-muted` | `#9ca3af` |
| `--color-border` | `#e5e7eb` |
| `--color-border-subtle` | `#f3f4f6` |
| `--color-accent` | `#0284c7` |
| `--color-accent-hover` | `#0369a1` |
| `--color-accent-active` | `#075985` |
| `--color-safe` | `#16a34a` |
| `--color-danger` | `#dc2626` |
| `--color-warning` | `#d97706` |
| `--color-info` | `#2563eb` |

### Severity Colors (Used in alerts, events, badges)

| Level | Color Token | Usage |
|-------|-------------|-------|
| Critical/Dangerous | `--color-danger` (#ef4444) | Critical alerts, blocked events |
| High/Suspicious | `#f97316` (orange-500) | High-severity alerts |
| Medium/Unusual | `--color-warning` (#f59e0b) | Medium alerts, unusual events |
| Low/Normal | `--color-safe` (#22c55e) | Normal events, allowed actions |
| Info | `--color-info` (#3b82f6) | Informational alerts |

### Trust Level Colors

| Trust Level | Visual Treatment |
|-------------|-----------------|
| Trusted | Green badge, shield icon |
| Standard | Blue badge |
| Cautious | Yellow/amber badge |
| Restricted | Orange badge |
| Minimal | Red badge |

## 3.2 Typography

| Token | Size | Line Height | Common Usage |
|-------|------|-------------|-------------|
| `text-xs` | 0.6875rem (11px) | 1rem | Badges, timestamps, meta labels |
| `text-sm` | 0.8125rem (13px) | 1.25rem | Body text, descriptions, most content |
| `text-base` | 0.9375rem (15px) | 1.5rem | Card titles, emphasized text |
| `text-lg` | 1.0625rem (17px) | 1.75rem | Section headings |
| `text-xl` | 1.25rem (20px) | 1.75rem | Sub-page titles |
| `text-2xl` | 1.5rem (24px) | 2rem | Page titles |
| `text-3xl` | 1.875rem (30px) | 2.25rem | Hero numbers (score display) |
| `text-4xl` | 2.25rem (36px) | 2.5rem | Large score ring number |

**Font weights**: Regular (400), Medium (500), Semibold (600), Bold (700)

**Font stacks**:
- Sans: `-apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif`
- Mono: `"SF Mono", SFMono-Regular, ui-monospace, Menlo, Monaco, Consolas, monospace`

## 3.3 Spacing Scale

Uses Tailwind's default spacing (4px base unit):
- `1` = 4px, `2` = 8px, `3` = 12px, `4` = 16px, `5` = 20px, `6` = 24px, `8` = 32px

**Common patterns**:
- Card padding: `p-4` (16px) or `p-6` (24px)
- Section gap: `space-y-4` (16px) or `space-y-6` (24px)
- Grid gap: `gap-4` (16px)
- Page horizontal padding: `px-6` (24px)

## 3.4 Shadows

| Token | Value (Dark) | Usage |
|-------|-------------|-------|
| `--shadow-card` | `0 1px 3px rgba(0,0,0,0.3)` | Card elevation |
| `--shadow-dropdown` | `0 4px 12px rgba(0,0,0,0.4)` | Dropdowns, popovers |
| `--shadow-modal` | `0 8px 32px rgba(0,0,0,0.5)` | Modals, drawers |
| `--shadow-toast` | `0 4px 16px rgba(0,0,0,0.4)` | Toast notifications |

## 3.5 Border Radii

| Token | Value | Usage |
|-------|-------|-------|
| `--radius-sm` | 4px | Badges, small elements |
| `--radius-md` | 6px | Inputs, buttons |
| `--radius-lg` | 8px | Cards, modals |
| `--radius-full` | 9999px | Pills, avatars, circular buttons |

## 3.6 Z-Index Layers

| Layer | Value | Elements |
|-------|-------|----------|
| Base | 0 | Page content |
| Dropdown | 10 | Dropdowns, popovers, filter panels |
| Sticky | 20 | Sticky headers, period headers |
| Overlay | 30 | Overlay backgrounds |
| Modal | 40 | Modals, drawers, score breakdown |
| Toast | 50 | Toast notifications |
| Prompt | 60 | Security prompts (highest priority) |

## 3.7 Animations

| Name | Duration | Easing | Usage |
|------|----------|--------|-------|
| Page transition | 150ms | ease | Page content crossfade on route change |
| `skeleton-shimmer` | 1.5s | linear, infinite | Loading skeleton shimmer effect |
| `analysis-pulse` | 2s | ease-in-out, infinite | Score ring pulse while calculating |
| `spin` | 1s | linear, infinite | Loading spinners |
| `indeterminate` | 1.2s | ease-in-out, infinite | Progress bar indeterminate state |
| Hover transition | 100ms (fast) | ease | Button/card hover color changes |
| Dropdown open | 150ms (normal) | ease-out | Dropdown/popover appearance |
| Modal enter | 200ms (moderate) | ease-out | Modal slide-up + fade |
| Toast slide | 300ms (slow) | ease-out | Toast slide-in from right |

**Reduced motion**: All animations respect `prefers-reduced-motion: reduce` — duration set to 0ms.

## 3.8 Scrollbar Styling

```
Dark:  Track #1a1a1a, Thumb #3f3f46, Hover #52525b
Light: Track #f9fafb, Thumb #d1d5db, Hover #9ca3af
Width: 8px, Border-radius: 4px
```

---

# 4. Page-by-Page Specifications

## 4.1 Home Page (`/`)

**Purpose**: At-a-glance security status and quick actions.

### Layout
```
┌─────────────────────────────────────────────┐
│ [Mock Mode Warning Banner — conditional]     │
│                                              │
│ ┌──────────────────┐  ┌──────────────────┐  │
│ │  Protection       │  │  7-Day Sparkline │  │
│ │  Score Ring       │  │  Chart           │  │
│ │  [72]             │  │  ~~~~/\~~~       │  │
│ │  ▲ +3 from yday   │  │                  │  │
│ └──────────────────┘  └──────────────────┘  │
│                                              │
│ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐        │
│ │Events│ │Blocked│ │Anomaly│ │Guards│        │
│ │Today │ │Today  │ │Score  │ │Active│        │
│ │  47  │ │   3   │ │ 0.82  │ │  12  │        │
│ └──────┘ └──────┘ └──────┘ └──────┘        │
│                                              │
│ ── Recent Messages from Claw ──              │
│ ┌────────────────────────────────────────┐  │
│ │ "I noticed unusual file access from..." │  │
│ │ "Your protection score improved..."     │  │
│ └────────────────────────────────────────┘  │
│                                              │
│ ── Server Overview ──                        │
│ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐        │
│ │Claude│ │Cursor│ │VSCode│ │ ... → │        │
│ │ ●OK  │ │ ●OK  │ │ ●Warn│ │scroll│        │
│ └──────┘ └──────┘ └──────┘ └──────┘        │
│                                              │
│ ── Pending Actions ──                        │
│ ┌────────────────────────────────────────┐  │
│ │ ⚠ Behavioral learning incomplete [Fix] │  │
│ │ ⚠ 2 servers not wrapped          [Fix] │  │
│ └────────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### Sections

1. **Mock Mode Banner** (conditional)
   - Shows when SLM is in mock mode (basic pattern matching, not real AI)
   - Yellow warning banner: "AI analysis is running in basic mode..."
   - Dismiss button

2. **Protection Score Ring**
   - Large circular SVG gauge (0-100)
   - Color: green (70-100), yellow (40-69), red (0-39)
   - Label below: "Good" / "Fair" / "Needs Attention"
   - Change delta: "▲ +3 from yesterday" or "▼ -5"
   - Click → opens Score Breakdown drawer

3. **7-Day Sparkline**
   - Mini line chart showing score trend over 7 days
   - Dots at each data point
   - Click → opens Score Breakdown drawer

4. **Quick Stat Cards** (4-column grid, responsive → 2-col on small)
   - Events Today: count of today's events
   - Blocked Today: count of blocked events (red if >0)
   - Highest Anomaly: max anomaly score + server name
   - Active Guards: count of behavioral guards

5. **Recent Claw Messages** (max 5)
   - Last 5 messages from Claw with intent "proactive.alert"
   - Each shows: message text (truncated), timestamp
   - Click → navigates to `/ask`
   - Hidden when no messages

6. **Server Overview** (horizontal scroll)
   - Mini cards for each MCP server
   - Each card: server name, status dot (green/yellow/red), trust level badge
   - Click → navigates to `/tools/:name`

7. **Pending Actions** (from score factors with status != "full")
   - Each shows: icon, description, [Fix] button
   - Fix button → navigates to relevant page or invokes Tauri command

8. **Score Breakdown Drawer** (modal overlay)
   - Triggered by clicking score ring or sparkline
   - Lists all protection factors:
     - Factor name, status (full/partial/missing), percentage bar
     - Details text explaining the factor
     - Fix actions (buttons with navigate or invoke actions)
   - Close: click outside, Escape key, or X button

### States
- **Loading**: Skeleton placeholders for score ring and stat cards
- **Empty** (first run, no events): Welcome message with guidance, "Get Started" CTA
- **Disconnected**: Connection status banner shows at top, data shows last known values

### Real-time Updates
- Score ring updates on `clawdefender://score-changed` event
- Stat cards update on `clawdefender://event` events
- Server list refreshes on new events
- Force refresh: Cmd+R

---

## 4.2 Ask Claw (`/ask`)

**Purpose**: Conversational AI assistant for security Q&A, status queries, and actions.

### Layout
```
┌─────────────────────────────────────────────┐
│ Ask Claw                    [New Chat] [▾]  │
├─────────────────────────────────────────────┤
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │ 🛡️ Hey! I'm Claw. Ask me anything   │   │
│  │    about your security setup.         │   │
│  └──────────────────────────────────────┘   │
│                                              │
│       ┌────────────────────────────────┐    │
│       │ What does this event mean?     │    │
│       └────────────────────────────────┘    │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │ That event shows Cursor's filesystem │   │
│  │ server accessing /etc/passwd...      │   │
│  │                                      │   │
│  │ [Block this server] [See details]    │   │
│  └──────────────────────────────────────┘   │
│                                              │
│  ┌─ Suggestion pills ──────────────────┐   │
│  │ [Show my status] [What was blocked?] │   │
│  │ [Explain last alert] [Help]          │   │
│  └─────────────────────────────────────┘   │
│                                              │
│  ┌─────────────────────────────────────┐   │
│  │ Type a message...              [→]  │   │
│  └─────────────────────────────────────┘   │
│  [Drop files here for context]              │
└─────────────────────────────────────────────┘
```

### Sections

1. **Header**
   - Title: "Ask Claw"
   - [New Chat] button — starts fresh conversation
   - Dropdown [▾] — list of previous conversations (load by ID)

2. **Message Thread** (scrollable, auto-scrolls to bottom)
   - **User messages**: Right-aligned bubbles, `bg-accent` tint
   - **Claw messages**: Left-aligned bubbles, `bg-secondary`
     - Rich content: Markdown rendering (bold, links, lists)
     - Status badges: colored pills (good=green, warning=amber, error=red)
     - Action buttons: row of buttons after message
       - Types: `tauri_command` (execute action), `navigate` (go to page), `follow_up` (ask follow-up), `copy_to_clipboard`
     - Confirmation cards: yellow-bordered card with "Are you sure?" + Confirm/Cancel
   - **Proactive alerts**: Claw-initiated messages (intent: "proactive.alert") with yellow border

3. **Suggestion Pills** (context-aware)
   - Row of pill buttons with pre-written questions
   - Context varies based on last message intent:
     - `afterStatus`: "What needs fixing?", "Show blocked events"
     - `afterBlock`: "Why was it blocked?", "Unblock this"
     - `afterExplain`: "Block it", "Show more like this"
     - `default`: "Show my status", "What was blocked?", "Help"
   - Click → sends as user message

4. **Message Input**
   - Text input with placeholder "Type a message..."
   - Send button (arrow icon, accent color)
   - Enter to send, Shift+Enter for newline

5. **Drag & Drop Zone**
   - Dashed border area below input
   - "Drop files here for context"
   - Accepts files for context enrichment

### Message Intent Types

| Intent | Source | Visual Treatment |
|--------|--------|-----------------|
| `proactive.alert` | Claw-initiated | Yellow left border, bell icon |
| `status.*` | Status responses | Green/yellow/red badges |
| `explain.*` | Event explanations | Expandable detail sections |
| `control.block` | Block confirmation | Confirmation card pattern |
| `control.allow` | Allow confirmation | Confirmation card pattern |
| `follow_up` | Conversation continuation | Normal bubble |

### States
- **Loading**: Typing indicator (3 bouncing dots) while Claw generates response
- **Empty** (new conversation): Welcome message + default suggestion pills
- **Error**: Error banner if Claw can't respond

---

## 4.3 My Tools (`/tools`)

**Purpose**: Inventory of all MCP servers with trust levels and management.

### Layout
```
┌─────────────────────────────────────────────┐
│ My Tools                                     │
│ Manage your MCP servers and their permissions│
├─────────────────────────────────────────────┤
│ [Search tools...]  [Filter: All ▾]          │
│                                              │
│ ┌───────────────────────────────────────┐   │
│ │ 🟢 filesystem-server     [Trusted]    │   │
│ │    Claude Desktop · 142 events         │   │
│ │    Anomaly: 0.12 · Last: 2m ago       │   │
│ ├───────────────────────────────────────┤   │
│ │ 🟡 browser-server        [Standard]   │   │
│ │    Cursor · 87 events                  │   │
│ │    Anomaly: 0.45 · Last: 15m ago      │   │
│ ├───────────────────────────────────────┤   │
│ │ 🔴 shell-executor        [Restricted] │   │
│ │    VS Code · 23 events                 │   │
│ │    Anomaly: 0.89 · Last: 1h ago       │   │
│ └───────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

### Data per server card
- Status dot (green/yellow/red based on health)
- Server name
- Trust level badge (Trusted/Standard/Cautious/Restricted/Minimal)
- Client name (Claude Desktop, Cursor, etc.)
- Event count
- Anomaly score
- Last activity relative time
- Wrapped/unwrapped indicator

### Interactive Elements
- Search input (filters by name)
- Filter dropdown (All, Trusted, Needs Attention, Unwrapped)
- Click card → navigate to `/tools/:id`

### States
- **Empty**: "No MCP servers detected" + guidance on how to add servers
- **Loading**: Skeleton cards

---

## 4.4 Tool Detail (`/tools/:id`)

**Purpose**: Deep-dive into a specific MCP server.

### Layout
```
┌─────────────────────────────────────────────┐
│ ← Back to My Tools                           │
│ filesystem-server                            │
│ Claude Desktop · Trusted                      │
├─────────────────────────────────────────────┤
│ ┌─────────┐ ┌─────────┐ ┌─────────┐        │
│ │ Events  │ │ Anomaly │ │ Trust   │        │
│ │   142   │ │  0.12   │ │ Trusted │        │
│ └─────────┘ └─────────┘ └─────────┘        │
│                                              │
│ ── Summary ──                                │
│ Territory: src/, docs/, config/              │
│ Top tools: read_file (45%), write_file (30%) │
│ Network: Never accessed                      │
│ Status: Active (learning complete)           │
│ Recommendation: Trusted                      │
│                                              │
│ ── Permissions ──                            │
│ Tool calls: ✅ Allow                         │
│ File read: ✅ Allow                          │
│ File write: ⚠️ Prompt                        │
│ Shell exec: 🔴 Block                        │
│ Network: 🔴 Block                           │
│ Sensitive paths: ⚠️ Prompt                   │
│                                              │
│ ── Recent Events ──                          │
│ [Event list filtered to this server]         │
│                                              │
│ [Change Trust Level ▾]  [Unwrap Server]     │
└─────────────────────────────────────────────┘
```

### Sections
1. **Header**: Back button, server name, client, trust badge
2. **Quick Stats**: Events, anomaly score, trust level
3. **Server Summary**: Territory, top tools, network usage, learning status, trust recommendation, notable observations
4. **Permissions Table**: 6 permission categories with current action (Allow/Prompt/Block)
5. **Recent Events**: Filtered event list for this server
6. **Actions**: Change trust level dropdown, unwrap server button (destructive, requires confirmation)

---

## 4.5 Activity (`/activity`)

**Purpose**: Real-time event feed with comprehensive filtering.

### Layout
```
┌─────────────────────────────────────────────┐
│ Activity                    🔴 Live · 1,247 │
├─────────────────────────────────────────────┤
│ ┌───────────────────────────────────────┐   │
│ │🔍 Search events...                    │   │
│ │[Server ▾][Status ▾][Risk ▾][Time ▾]  │   │
│ │[☐ Only notable] [☐ Correlated only]   │   │
│ └───────────────────────────────────────┘   │
│                                              │
│ ── Today ────────────────────────────────   │
│ │ 🟢 Read file: src/main.rs              │  │
│ │    filesystem-server · Claude · 2m ago  │  │
│ │ 🔴 BLOCKED: Shell command execution     │  │
│ │    shell-server · Cursor · 5m ago       │  │
│ │ 🟡 Prompted: Write to /etc/hosts        │  │
│ │    filesystem-server · VS Code · 12m    │  │
│ │ ┌ 5 similar events from Claude ─────┐  │  │
│ │ │ Read file (×5) · filesystem-server │  │  │
│ │ └───────────────────────────────────┘  │  │
│                                              │
│ ── Yesterday ────────────────────────────   │
│ │ ...                                     │  │
│                                              │
│ [↑ 12 new events]  ← floating chip         │
└─────────────────────────────────────────────┘
```

### Filter Bar
| Filter | Type | Options |
|--------|------|---------|
| Search | Text input | Searches: one_liner, explanation, server, tool_name, resource |
| Server | Multi-select dropdown | All detected servers |
| Status | Multi-select | Allowed, Blocked, Prompted, AutoBlocked |
| Risk | Multi-select | Dangerous, Suspicious, Unusual, Normal |
| Time | Single-select | Last hour, Today, Yesterday, This week |
| Only notable | Checkbox toggle | Hides routine/normal events |
| Correlated only | Checkbox toggle | Shows only correlated attack chain events |

### Event Row (two variants)

**Standard Event Row (52px)**:
- Left: Risk color dot (green/yellow/orange/red)
- Main: One-liner description (humanized)
- Meta: Server name, client name, relative time
- Right: Action badge (Allowed/Blocked/Prompted)
- Click → navigate to `/activity/:id`

**Grouped Event Row**:
- Collapsed: "5 similar events from Claude Desktop" with expand chevron
- Expanded: Shows individual events

### Period Headers (sticky)
- "Today", "Yesterday", "This Week", "Earlier"
- Stick to top of scroll container

### Live Indicator
- Red spinning dot + "Live" text when events are streaming
- Shows total filtered count: "1,247 events"

### New Events Chip
- Floating chip appears when user has scrolled down
- "[↑ 12 new events]" — click to scroll to top
- Auto-scroll behavior: follows new events if user is at top

### Virtual Scrolling
- Row height: 52px
- Buffer: 400px above and below viewport
- Only visible rows are rendered

### States
- **Loading**: Skeleton rows
- **Empty**: "No events yet" + guidance text about how events appear
- **Empty filtered**: "No events match your filters" + clear filters button

---

## 4.6 Event Detail (`/activity/:id`)

**Purpose**: Full context for a single security event.

### Layout
```
┌─────────────────────────────────────────────┐
│ ← Back to Activity                           │
│                                              │
│ 🔴 Shell command execution blocked           │
│ shell-server · Cursor · Feb 26, 2:15 PM     │
├─────────────────────────────────────────────┤
│                                              │
│ ── What happened ──                          │
│ The shell-server tried to execute `rm -rf    │
│ /tmp/cache` through Cursor's MCP connection. │
│                                              │
│ ── Why it was blocked ──                     │
│ Shell execution is blocked for this server   │
│ based on your "Cautious" trust level policy. │
│                                              │
│ ── Educational note ──                       │
│ Shell commands can modify your system. Only  │
│ grant shell access to servers you trust.     │
│                                              │
│ ── Correlation Timeline ──                   │
│ [Kill chain visualization if correlated]     │
│                                              │
│ ── Raw Details ──                            │
│ Event ID: evt_abc123                         │
│ Tool: execute_command                        │
│ Resource: /tmp/cache                         │
│ Decision: blocked                            │
│ Risk Level: dangerous                        │
│ Anomaly Score: 0.92                         │
│                                              │
│ [Ask Claw about this] [Change policy]       │
└─────────────────────────────────────────────┘
```

### Sections
1. **Header**: Back button, humanized title, severity color, server/client/time
2. **What Happened**: `expanded_explanation` field — natural language
3. **Why It Was Blocked/Allowed**: Policy reason
4. **Educational Note**: `educational_aside` field (optional, collapsible)
5. **Correlation Timeline**: If event is part of a kill chain, shows timeline visualization
6. **Raw Details**: Technical fields in key-value table
7. **Actions**: "Ask Claw about this" (navigates to /ask with context), "Change policy" (navigates to /settings/policy)

---

## 4.7 Alerts (`/alerts`)

**Purpose**: Intelligent alert management with AI recommendations.

### Layout
```
┌─────────────────────────────────────────────┐
│ Alerts                                       │
│ This week: 12 resolved · 8 blocked           │
├─────────────────────────────────────────────┤
│                                              │
│ ── Needs Attention (3) ──                    │
│ ┌────────────────────────────────────────┐  │
│ │ 🔴 CRITICAL: Kill chain detected       │  │
│ │ shell-server attempted reconnaissance   │  │
│ │ followed by file exfiltration           │  │
│ │ Recommendation: Block and review        │  │
│ │ [Dismiss] [View Details]               │  │
│ ├────────────────────────────────────────┤  │
│ │ 🟠 HIGH: Unusual network access        │  │
│ │ filesystem-server accessed external IP  │  │
│ │ [Dismiss] [View Details]               │  │
│ └────────────────────────────────────────┘  │
│                                              │
│ ── Recommendations ──                        │
│ ┌────────────────────────────────────────┐  │
│ │ 💡 Tighten shell-server permissions     │  │
│ │ This server has executed 12 commands    │  │
│ │ [Do it] [Dismiss]                      │  │
│ └────────────────────────────────────────┘  │
│                                              │
│ ── Recently Handled ──────────────────────   │
│ Today:                                       │
│ │ ✅ Resolved: Unusual file access (12h ago) │
│ Yesterday:                                   │
│ │ ✅ Dismissed: Low-risk warning (1d ago)    │
│                                              │
│ [Dismiss All Low-Priority]                   │
└─────────────────────────────────────────────┘
```

### Alert Card
- Left border colored by severity
- Severity badge (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- Title (humanized)
- Description
- Server and tool info
- Recommendation text
- Time (relative)
- Actions: [Dismiss] [View Details] (navigates to `/alerts/:id`)

### Recommendation Card
- Light bulb icon
- Description of recommendation
- [Do it] button (accent, executes recommendation via Tauri)
- [Dismiss] button (ghost)

### Alert Severity Sorting
- Critical and High → "Needs Attention" section
- Medium and Low → Can be bulk-dismissed via "Dismiss All Low-Priority"

### States
- **Empty**: "All clear! No active alerts." + historical stats (resolved/blocked this week)
- **Loading**: Skeleton cards

---

## 4.8 Alert Detail (`/alerts/:id`)

**Purpose**: Full alert context with resolution options.

### Sections
1. **Header**: Back button, alert title, severity badge, timestamp
2. **Alert Description**: Detailed explanation
3. **Related Events**: Events that triggered this alert
4. **Correlation Context**: If part of a kill chain, shows the full chain
5. **Recommendation**: AI-generated remediation steps
6. **Actions**: [Resolve] (with reason input), [Dismiss], [Ask Claw]

---

## 4.9 Settings (`/settings`)

**Purpose**: App configuration organized in tabs.

### Tab Structure
```
┌─────────────────────────────────────────────┐
│ Settings                                     │
├─────────────────────────────────────────────┤
│ [General] [Daemon] [Notifications] [Advanced]│
├─────────────────────────────────────────────┤
│                                              │
│ (Tab content varies — see below)             │
│                                              │
└─────────────────────────────────────────────┘
```

**General Tab**: Theme toggle, font size, language (future)
**Daemon Tab**: Start/Stop daemon, daemon status, PID, uptime, auto-start toggle
**Notifications Tab**: Enable/disable OS notifications, alert threshold, sound
**Advanced Tab**: Data directory, clear cache, export logs, reset to defaults

### Sub-routes
- `/settings/policy` → Policy Editor page
- `/settings/health` → System Health page
- `/settings/threat-intel` → Threat Intelligence page

---

## 4.10 Policy Editor (`/settings/policy`)

**Purpose**: View and edit security policy rules.

### Layout
```
┌─────────────────────────────────────────────┐
│ ← Settings                                   │
│ Policy Editor                                │
│ Auto-saving...                               │
├─────────────────────────────────────────────┤
│ ┌───────────────────────────────────────┐   │
│ │ Rule: filesystem-server / tool-call    │   │
│ │ Action: Allow    Priority: 100         │   │
│ │ Match: tools/call with read_file       │   │
│ │ [Edit] [Delete]                        │   │
│ ├───────────────────────────────────────┤   │
│ │ Rule: shell-server / shell-exec        │   │
│ │ Action: Block    Priority: 200         │   │
│ │ Match: tools/call with execute_*       │   │
│ │ [Edit] [Delete]                        │   │
│ └───────────────────────────────────────┘   │
│                                              │
│ [+ Add Rule] [Apply Template ▾] [Reload]    │
└─────────────────────────────────────────────┘
```

### Features
- Auto-save with debounce (saves after 500ms of no edits)
- "Auto-saving..." indicator during save
- Rule cards with inline editing
- Add rule button opens inline form
- Template dropdown (audit-only, data-science, development, strict)
- Reload button (signals daemon to reload policy)

---

## 4.11 System Health (`/settings/health`)

**Purpose**: Daemon and system monitoring.

### Displayed Metrics
- Daemon status (Running/Stopped with uptime)
- PID
- Servers proxied count
- Events processed count
- Memory usage
- CPU usage
- SLM status (model loaded, mock mode indicator)
- Behavioral profiles count
- Audit log size

### Actions
- Start/Stop daemon
- View crash reports (if any)
- Export diagnostic info

---

## 4.12 Threat Intelligence (`/settings/threat-intel`)

**Purpose**: Threat database and AI model management.

### Sections
- Threat feed status (last updated)
- Known threat indicators count
- AI model info (model type, file path, mock mode)
- Model management (download, switch models)

---

## 4.13 Onboarding (`/onboarding`)

**Purpose**: First-run setup wizard. Full-screen, no sidebar.

### Flow Steps

**Step 1: Welcome**
```
┌─────────────────────────────────────────────┐
│                                              │
│           🛡️ Welcome to ClawDefender         │
│                                              │
│     Protect your AI tools with intelligent   │
│     security monitoring                      │
│                                              │
│              [Get Started →]                 │
│                                              │
└─────────────────────────────────────────────┘
```

**Step 2: Detect MCP Clients**
- Scans for installed MCP clients (Claude Desktop, Cursor, etc.)
- Shows detected clients with checkmarks
- "Scanning..." spinner during detection

**Step 3: Wrap Servers**
- Lists detected MCP servers
- Each server: checkbox + name + client
- "Wrap selected servers" button
- Progress indicator during wrapping

**Step 4: Set Trust Levels**
- For each wrapped server, choose trust level
- Visual trust level selector (5 levels with descriptions)

**Step 5: Complete**
- "You're all set!" confirmation
- Summary of what was configured
- [Open Dashboard →] button

### Migration Screen (conditional)
- Shows when existing installation detected from older version
- "We detected an existing ClawDefender installation"
- Option to migrate settings or start fresh

---

# 5. Component Inventory

## 5.1 Layout Components

| Component | Props | Description |
|-----------|-------|-------------|
| `Layout` | — | App shell: sidebar + banners + content outlet + global listeners |
| `Sidebar` | — | Nav links (6), alert badge, daemon indicator, collapse toggle |
| `PageHeader` | `title`, `subtitle`, `actions` | Consistent page header with optional action buttons |
| `ConnectionStatus` | — | Banner: "Connected" / "Reconnecting..." / "Disconnected" |
| `UpdateBanner` | — | "Update available" banner with dismiss + update buttons |
| `ErrorBanner` | `message`, `onDismiss` | Dismissible red error banner |
| `MigrationScreen` | — | Full-screen migration prompt for version upgrades |

## 5.2 Loading & Empty States

| Component | Props | Description |
|-----------|-------|-------------|
| `LoadingSkeleton` | `rows`, `type` | Skeleton shimmer placeholders (card, row, circle variants) |
| `EmptyState` | `icon`, `title`, `message`, `action` | Centered illustration + text + optional CTA button |

## 5.3 Home Page Components

| Component | Props | Description |
|-----------|-------|-------------|
| `ProtectionScoreRing` | `score`, `label`, `change`, `onClick` | Circular SVG gauge (0-100) with color bands |
| `QuickStatCard` | `label`, `value`, `color`, `onClick` | Small stat box |
| `ScoreBreakdown` | `factors`, `onClose` | Modal drawer listing all score factors with fix actions |
| `ServerMiniCard` | `server`, `onClick` | Horizontal scroll card with server status |

## 5.4 Activity Components

| Component | Props | Description |
|-----------|-------|-------------|
| `ActivityFilters` | `filters`, `onChange` | Multi-filter bar (search, dropdowns, toggles) |
| `EventRow` | `event`, `compact`, `onClick` | Single event row: color dot + one-liner + meta + badge |
| `GroupedEventRow` | `events`, `label`, `onExpand` | Collapsible group: "N similar events from..." |
| `CorrelationTimeline` | `events`, `killChainId` | Horizontal timeline of correlated events |
| `CoverageInsight` | `servers` | Shows monitoring coverage status |

## 5.5 Alert Components

| Component | Props | Description |
|-----------|-------|-------------|
| `AlertCard` | `alert`, `onDismiss`, `onView` | Severity-colored card with actions |
| `ThreatStory` | `narrative` | Narrative explanation of a threat |
| `RecommendationCard` | `rec`, `onExecute`, `onDismiss` | AI recommendation with "Do it" + "Dismiss" |

## 5.6 Conversation Components

| Component | Props | Description |
|-----------|-------|-------------|
| `MessageBubble` | `message`, `role` | Chat bubble (user=right/accent, claw=left/secondary) |
| `ActionButton` | `action`, `onClick` | Button in Claw response (navigate/execute/copy/follow-up) |
| `ConfirmationCard` | `message`, `onConfirm`, `onCancel` | Yellow-bordered "Are you sure?" card |
| `DragDropZone` | `onDrop` | Dashed border file drop area |
| `SuggestionPills` | `suggestions`, `onClick` | Row of pre-written question pill buttons |
| `TypingIndicator` | — | Three bouncing dots animation |

## 5.7 Guidance Components

| Component | Props | Description |
|-----------|-------|-------------|
| `GuidanceAnchor` | `anchorId` | Invisible positioning element for inline hints |
| `GuidanceToastContainer` | — | Queue of auto-dismissing guidance toasts |
| `PromptOverlay` | `title`, `message`, `actions` | Full-screen modal for first-time guidance |

## 5.8 Notification Components

| Component | Props | Description |
|-----------|-------|-------------|
| `ToastContainer` | — | Max 5 toasts, auto-dismiss 4s, types: success/warning/danger/info |
| `NotificationLayer` | — | Global notification dispatcher |
| `AlertWindow` | `alert` | Urgent alert dialog |
| `PromptQueue` | — | Queue of user-action-required security prompts |
| `PromptWindow` | `prompt`, `onAllow`, `onDeny` | Individual prompt dialog (Allow/Deny/More info) |

## 5.9 Settings Components

| Component | Props | Description |
|-----------|-------|-------------|
| Settings tabs | — | General, Daemon, Notifications, Advanced panels |

## 5.10 Tool Components

| Component | Props | Description |
|-----------|-------|-------------|
| Tool card | `server` | Server card with trust badge, status, metrics |
| Trust badge | `level` | Colored badge (Trusted/Standard/Cautious/Restricted/Minimal) |
| Permission display | `permissions` | 6-row table of permission categories with status icons |

## 5.11 Shared Primitives

| Component | Variants | Description |
|-----------|----------|-------------|
| Button | primary, secondary, ghost, danger | Standard button with hover/focus states |
| Badge | severity colors, trust colors | Small colored label |
| Modal | standard, drawer | Overlay with backdrop, focus trap, Escape to close |
| Dropdown | single-select, multi-select | Popover with checkable options |
| Input | text, search | Text input with optional icon |
| Toggle | on/off | Switch toggle |
| Tabs | horizontal | Tab bar with active indicator |

---

# 6. User Flow Maps

## 6.1 First-Time Setup

```
App Launch
  → Onboarding check (is_onboarding_complete?)
  │
  ├─ FALSE → /onboarding
  │   → Welcome screen
  │   → Detect MCP clients
  │   → Wrap servers
  │   → Set trust levels
  │   → Complete → mark onboarding done → redirect to /
  │
  ├─ Migration detected → MigrationScreen
  │   → Migrate / Start fresh → /onboarding or /
  │
  └─ TRUE → / (Home)
```

## 6.2 Daily Monitoring

```
App Launch → / (Home)
  │
  ├─ Check score ring → good? → glance at stats → done
  │
  ├─ Score low → click ring → Score Breakdown
  │   → See failing factors → click [Fix] → navigate to fix
  │
  ├─ Pending actions visible → click [Fix]
  │   → Navigate to relevant page (wrap servers, edit policy, etc.)
  │
  ├─ Recent Claw message → click → /ask
  │   → Continue conversation about the alert
  │
  └─ Server card looks wrong → click → /tools/:id
      → Review permissions, events, trust level
```

## 6.3 Responding to a Security Alert

```
Alert arrives (Tauri event: clawdefender://alert)
  │
  ├─ Alert badge appears on Sidebar (Alerts link)
  │
  ├─ If critical → OS notification + in-app toast
  │
  └─ User navigates to /alerts
      → See "Needs Attention" section
      → Click alert → /alerts/:id
        → Read description, related events, recommendation
        ├─ [Resolve] → enter reason → alert resolved
        ├─ [Dismiss] → alert dismissed
        └─ [Ask Claw] → /ask with alert context
```

## 6.4 Security Prompt Decision

```
MCP server makes sensitive request
  │
  → Daemon intercepts, sends prompt to GUI
  → PromptWindow appears (z-index: 60, above everything)
  │
  ┌────────────────────────────────────┐
  │ 🔒 Permission Request              │
  │                                    │
  │ filesystem-server wants to write   │
  │ to /etc/hosts                      │
  │                                    │
  │ Server: filesystem-server          │
  │ Client: Claude Desktop             │
  │ Tool: write_file                   │
  │ Resource: /etc/hosts               │
  │                                    │
  │ [Allow]  [Allow Once]  [Deny]     │
  │                                    │
  │ Timeout: 28s remaining            │
  └────────────────────────────────────┘
  │
  ├─ User clicks Allow → request proceeds
  ├─ User clicks Deny → request blocked
  └─ Timeout (30s) → request blocked (fail-closed)
```

## 6.5 Conversation with Claw

```
User navigates to /ask
  │
  ├─ Previous conversation? → auto-loads latest
  │   (or) New → shows welcome message + default suggestions
  │
  → User types question (or clicks suggestion pill)
  → Message appears in thread (right-aligned)
  → Typing indicator shows (3 bouncing dots)
  → Claw response appears (left-aligned)
    │
    ├─ Plain text → rendered with markdown
    ├─ With actions → action buttons below message
    │   ├─ navigate → goes to page
    │   ├─ tauri_command → executes action (may show confirmation)
    │   ├─ follow_up → inserts follow-up question
    │   └─ copy_to_clipboard → copies text
    │
    └─ With confirmation → ConfirmationCard appears
        → [Confirm] → executes action
        → [Cancel] → dismisses
```

## 6.6 Managing an MCP Server

```
/tools → click server card → /tools/:id
  │
  ├─ Review summary (territory, tools, network, learning status)
  ├─ Review permissions (6 categories)
  │
  ├─ Change trust level → dropdown → select new level
  │   → Policy rules regenerated → daemon reloaded
  │
  └─ Unwrap server → confirmation dialog → unwrap
      → Trust rules removed → daemon reloaded
```

---

# 7. Interaction Patterns

## 7.1 Button Patterns

| Variant | Background | Text | Hover | Usage |
|---------|-----------|------|-------|-------|
| Primary | `accent` (#6366f1) | white | darken 10% | Main CTAs |
| Secondary | `bg-tertiary` | `text-primary` | lighten | Secondary actions |
| Ghost | transparent | `text-secondary` | `bg-tertiary` | Tertiary actions, dismiss |
| Danger | `danger` (#ef4444) | white | darken 10% | Destructive actions |

## 7.2 Card Patterns

- **Standard card**: `bg-secondary`, `border`, `rounded-lg`, `shadow-card`
- **Elevated card**: `bg-secondary`, `shadow-dropdown`, no border
- **Interactive card**: Standard + `hover:bg-tertiary` + `cursor-pointer`
- **Alert card**: Standard + left border colored by severity (4px)

## 7.3 Modal Patterns

- **Backdrop**: `bg-black/50`, z-index: overlay (30)
- **Modal**: `bg-secondary`, `rounded-lg`, `shadow-modal`, z-index: modal (40)
- **Entry**: fade-in 200ms + slide-up
- **Exit**: fade-out 150ms
- **Close**: Click backdrop, Escape key, or X button
- **Focus**: Trapped within modal (useFocusTrap)

## 7.4 Drawer Pattern (Score Breakdown)

- Slides in from right
- Width: ~400px
- Same backdrop + z-index as modal
- Close: click outside, Escape, X button

## 7.5 Toast Pattern

- Position: top-right, stacked
- Max visible: 5
- Auto-dismiss: 4 seconds
- Entry: slide-in from right (300ms)
- Exit: fade-out (150ms)
- Types with colors: success (green), warning (amber), danger (red), info (blue)
- Manual dismiss: X button

## 7.6 Filter Patterns

- **Dropdown filters**: Click to open popover, checkable items, apply on select
- **Toggle filters**: Checkbox-style toggles (e.g., "Only notable")
- **Search input**: Debounced (300ms), icon left, clear button right
- **Active filter indicator**: Colored pill showing active filter count

## 7.7 Loading Patterns

| Context | Pattern |
|---------|---------|
| Page load | LoadingSkeleton (shimmer animation) |
| Data fetch | Inline spinner or skeleton |
| Button action | Button disabled + spinner inside |
| Long operation | Indeterminate progress bar |
| Claw thinking | Typing indicator (3 bouncing dots) |

## 7.8 Empty State Patterns

| Context | Content |
|---------|---------|
| Activity (no events) | Shield icon + "No events yet" + guidance text |
| Alerts (all clear) | Checkmark icon + "All clear!" + weekly stats |
| Tools (no servers) | Wrench icon + "No servers detected" + how-to text |
| Conversation (new) | Claw avatar + welcome message + suggestion pills |
| Search (no results) | Search icon + "No results" + clear filters button |

---

# 8. State & Loading Patterns

## 8.1 Data Loading per Page

| Page | Data Source | Load Trigger | Cache TTL | Refresh |
|------|-----------|-------------|-----------|---------|
| Home | appStore (score, history), eventStore, serverStore, conversationStore | On mount | 30s | Cmd+R or event |
| Ask Claw | conversationStore | On mount (latest) | None | Manual |
| My Tools | serverStore | On mount | 30s | Cmd+R |
| Tool Detail | serverStore + invoke | On mount | None | Cmd+R |
| Activity | invoke (humanized events) + eventStore (live) | On mount (500 initial) | None | Live stream |
| Alerts | alertStore | On mount | None | On `clawdefender://alert` event |
| Settings | appStore (daemon status) | On mount | None | On status change |

## 8.2 Real-time Updates

| Data | Update Mechanism | Frequency | Visual Feedback |
|------|-----------------|-----------|-----------------|
| Events | Tauri event + 100ms batch | ~500ms polling | Live dot indicator, new event chip |
| Protection score | Tauri event | On score change | Score ring animates to new value |
| Daemon status | Tauri event | On status change | Sidebar dot changes color |
| Alerts | Tauri event | On alert change | Badge count updates, toast notification |
| Prompts | Tauri event | On new prompt | PromptWindow appears (z-60) |

## 8.3 Data Limits

| Data | Max Items | Behavior When Exceeded |
|------|-----------|----------------------|
| Events in memory | 10,000 | Oldest pruned |
| Events initial load | 500 | Paginate for more |
| Toasts visible | 5 | Oldest dismissed |
| Conversation messages | Unlimited | SQLite-backed |
| Score history | 7 days | Rolling window |

## 8.4 Disconnected Behavior

When daemon connection is lost:
- ConnectionStatus banner shows "Disconnected" (red)
- Existing data remains visible (stale but shown)
- Actions that need daemon (wrap, unwrap, policy reload) show error
- Auto-reconnect attempted
- When reconnected, banner shows "Reconnecting..." → "Connected" → auto-dismiss

## 8.5 Cache Invalidation

| Cache | TTL | Force Bypass |
|-------|-----|-------------|
| Protection score | 30 seconds | Cmd+R or `force: true` |
| Score history | 30 seconds | Cmd+R |
| Server list | 30 seconds | Cmd+R |

---

# 9. Navigation & Keyboard Shortcuts

## 9.1 Global Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd+K` | Focus search (on pages with search) |
| `Cmd+,` | Navigate to Settings |
| `Cmd+R` | Force refresh current page (bypass TTL cache) |
| `Cmd+1` | Navigate to Home |
| `Cmd+2` | Navigate to Ask Claw |
| `Cmd+3` | Navigate to My Tools |
| `Cmd+4` | Navigate to Activity |
| `Cmd+5` | Navigate to Alerts |
| `Cmd+6` | Navigate to Settings |
| `Cmd+W` | Hide window (macOS hide-on-close) |
| `Cmd+Q` | Quit application |
| `Escape` | Close modal/drawer/overlay |

## 9.2 System Tray Menu

```
ClawDefender
├── Show Window
├── ─────────────
├── Status: Running (●)
├── Score: 72/100
├── ─────────────
├── Dashboard      → navigate to /
├── Activity       → navigate to /activity
├── Alerts (3)     → navigate to /alerts
├── ─────────────
├── Start Daemon / Stop Daemon
├── ─────────────
└── Quit ClawDefender
```

**Tray icon**: Shows ClawDefender logo. May show badge for unresolved alerts.

## 9.3 Window Behavior

| Action | Behavior |
|--------|----------|
| Close button (red) | Hides window (macOS convention), does NOT quit |
| Minimize (yellow) | Minimizes to dock |
| Fullscreen (green) | Standard macOS fullscreen |
| Reopen from tray | "Show Window" or click tray icon |
| Quit | Cmd+Q or tray "Quit ClawDefender" |
| Geometry | Saved on close/move/resize, restored on next launch |

---

# 10. Notification & Alert System

## 10.1 Notification Hierarchy

| Priority | Type | Visual | Z-Index | Dismissal |
|----------|------|--------|---------|-----------|
| 1 (Highest) | Security Prompt | PromptWindow modal | 60 | User action or timeout (30s) |
| 2 | Guidance Overlay | Full-screen modal | 40 | User action |
| 3 | Alert Notification | Toast (top-right) | 50 | Auto (4s) or manual |
| 4 | Update Banner | Persistent banner | 20 | Manual dismiss |
| 5 | Connection Status | Persistent banner | 20 | Auto when resolved |
| 6 | Restart Reminder | Blue banner | 20 | Manual dismiss |
| 7 | Guidance Toast | Toast (top-right) | 50 | Auto or manual |
| 8 (Lowest) | Guidance Hint | Inline tooltip | 10 | Click outside |

## 10.2 Security Prompt UX

Security prompts are the most critical UI element — they represent real-time decisions about allowing or blocking MCP server actions.

**Design requirements**:
- Always on top (z-index: 60)
- Cannot be dismissed without action (Allow/Deny)
- Shows countdown timer (default 30s)
- Fail-closed: if timer expires, request is denied
- Shows context: server name, client name, tool, resource
- Queue: multiple prompts queue, shown one at a time

---

# 11. Accessibility

## 11.1 Keyboard Navigation

- Full tab navigation through all interactive elements
- `focus-visible` ring (2px accent color) for keyboard users only
- No focus ring for mouse clicks (`focus:not(:focus-visible)`)
- Focus trap in modals (Tab cycles within modal)
- Escape closes modals/dropdowns/overlays

## 11.2 Screen Reader Support

- `role="log"` on Activity event container
- `aria-live="polite"` on dynamic content (event counts, status updates)
- `.sr-only` class for screen-reader-only labels
- Semantic HTML (nav, main, aside, button, dialog)
- ARIA labels on icon-only buttons

## 11.3 Reduced Motion

- `prefers-reduced-motion: reduce` → all animations disabled (duration: 0ms)
- Skeleton shimmer, score pulse, toast slide, page transition all respect this

## 11.4 Color Contrast

- Text on backgrounds meets WCAG AA (4.5:1 for normal text, 3:1 for large)
- Severity indicators use both color AND text labels (not color-only)
- Trust badges use both color AND text

---

# 12. Data Shapes Reference

Key data types the UX team needs to design for:

## ProtectionScore
```
{
  total: 72,              // 0-100
  label: "Good",          // "Good" | "Fair" | "Needs Attention"
  color: "green",         // "green" | "yellow" | "red"
  change_from_last: 3,    // delta from yesterday (-n to +n)
  factors: [
    {
      id: "policy_compliance",
      name: "Policy Compliance",
      status: "full",       // "full" | "partial" | "missing"
      details: "All rules configured correctly",
      fix_actions: []
    },
    {
      id: "behavioral_learning",
      name: "Behavioral Learning",
      status: "partial",
      details: "3 of 5 servers have profiles",
      fix_actions: [
        { label: "View servers", action_type: "navigate", target: "/tools" }
      ]
    }
  ]
}
```

## HumanizedEvent
```
{
  id: "evt_abc123",
  timestamp: "2026-02-26T14:15:00Z",
  event_type: "tool_call",
  server_name: "filesystem-server",
  tool_name: "read_file",
  action: "allowed",
  decision: "allowed",
  risk_level: "normal",        // "dangerous" | "suspicious" | "unusual" | "normal" | "info"
  resource: "/src/main.rs",
  anomaly_score: 0.12,
  // Humanized fields:
  one_liner: "Read file: src/main.rs",
  expanded_explanation: "The filesystem-server read the contents of src/main.rs through Claude Desktop.",
  educational_aside: "File reads are generally safe as they don't modify your system.",
  behavioral_context: "This is normal behavior for this server.",
  action_taken: "Allowed",     // "Allowed" | "Blocked" | "Prompted" | "AutoBlocked"
  is_notable: false,
  correlation_id: null,
  kill_chain_id: null
}
```

## IntelligentAlert
```
{
  id: "alert_xyz789",
  severity: "high",            // "critical" | "high" | "medium" | "low" | "info" | "unusual"
  title: "Unusual network access detected",
  description: "filesystem-server accessed an external IP address...",
  server: "filesystem-server",
  tool: "fetch_url",
  created_at: "2026-02-26T14:00:00Z",
  updated_at: "2026-02-26T14:00:00Z",
  resolved_at: null,           // null = active, timestamp = resolved
  recommendation: "Review the server's network permissions and consider restricting access."
}
```

## ConversationMessage
```
{
  id: "msg_001",
  role: "claw",                // "user" | "claw"
  contentText: "Your protection score is 72/100, which is Good.",
  contentRichJson: "...",      // Optional rich rendering
  actionsJson: "[{\"label\":\"View details\",\"type\":\"navigate\",\"target\":\"/\"}]",
  intentId: "status.score",
  entitiesJson: "...",
  timestamp: "2026-02-26T14:30:00Z"
}
```

## ServerInfo
```
{
  name: "filesystem-server",
  clientName: "Claude Desktop",
  wrapped: true,
  status: "healthy",           // "healthy" | "warning" | "error" | "stale"
  eventCount: 142,
  trustLevel: "trusted",       // "trusted" | "standard" | "cautious" | "restricted" | "minimal"
  anomalyScore: 0.12
}
```

## PendingPrompt
```
{
  id: "prompt_001",
  server_name: "filesystem-server",
  client_name: "Claude Desktop",
  tool_name: "write_file",
  resource: "/etc/hosts",
  method: "tools/call",
  timeout_seconds: 30,
  created_at: "2026-02-26T14:15:00Z"
}
```

---

# 13. Known UX Gaps & Recommendations

## 13.1 Current Gaps

| Gap | Impact | Recommendation |
|-----|--------|---------------|
| No onboarding progress indicator | Users don't know how many steps remain | Add step dots or progress bar (Step 2 of 5) |
| No dark/light mode toggle in UI | Users must use system preferences | Add toggle in Settings → General |
| No search on Alerts page | Can't find specific past alerts | Add search input like Activity page |
| No pagination on Activity | Only 500 events loaded initially | Add "Load more" or infinite scroll |
| No undo on alert dismiss | Accidental dismiss is permanent | Add "Undo" toast after dismiss (5s window) |
| Tool Detail back navigation | Back button goes to /tools, not browser back | Use router history for true back |
| No conversation search in sidebar | Must go to /ask to search conversations | Add quick search in conversation dropdown |
| No batch operations on events | Can't dismiss/export multiple events | Add checkbox selection + batch actions |
| Prompt timeout not clearly urgent | 30s timer may not be noticed | Add pulsing/shaking animation at 10s remaining |
| No offline mode | App is useless without daemon | Show cached data with "last updated" timestamps |

## 13.2 Suggested Enhancements

1. **Onboarding video/animation** — Short animated intro showing what ClawDefender does
2. **Keyboard command palette** — Cmd+K opens command palette (not just search) for power users
3. **Notification center** — Slide-out panel showing all recent notifications
4. **Quick actions from tray** — Right-click tray for common actions (pause monitoring, open alerts)
5. **Event export** — Export events as CSV/JSON for external analysis
6. **Dashboard customization** — Drag-and-drop dashboard widgets
7. **Conversational onboarding** — Use Ask Claw to guide setup instead of wizard steps
8. **Animated transitions** — Page transitions between routes (slide left/right based on nav direction)
9. **Sound effects** — Optional sound for critical alerts and blocked events
10. **Multi-window** — Detachable panels (e.g., Activity feed in separate window while using Ask Claw)

---

*Report compiled by 4-agent analysis team (pages-analyzer, design-system-analyzer, flow-analyzer, data-analyzer) on 2026-02-26*
