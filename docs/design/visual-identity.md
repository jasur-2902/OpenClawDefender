# ClawDefender Visual Identity System

This document defines the complete visual language for ClawDefender. Every color, type choice, spacing value, and animation exists to express Claw's personality: calm, observant, direct, honest, warm. When in doubt, choose the quieter option.

---

## 1. Color System

ClawDefender follows a dark-first design (matching macOS developer preferences) with a carefully designed light mode. Colors are defined as CSS custom properties and extended into Tailwind.

### 1.1 Base Colors

| Role | CSS Variable | Dark Mode | Light Mode | Usage |
|------|-------------|-----------|------------|-------|
| Background | `--color-bg-primary` | `#0f0f0f` | `#ffffff` | App background, main canvas |
| Surface | `--color-bg-secondary` | `#1a1a1a` | `#f8f9fa` | Cards, sidebar, panels |
| Surface raised | `--color-bg-tertiary` | `#252525` | `#f0f1f3` | Hover states, nested cards, dropdowns |
| Surface sunken | `--color-bg-sunken` | `#0a0a0a` | `#edeef0` | Inset areas, code blocks, well |
| Text primary | `--color-text-primary` | `#e5e5e5` | `#1a1a1a` | Headings, body text, primary labels |
| Text secondary | `--color-text-secondary` | `#a3a3a3` | `#6b7280` | Descriptions, captions, timestamps |
| Text muted | `--color-text-muted` | `#6b7280` | `#9ca3af` | Placeholder text, disabled labels, hints |
| Border default | `--color-border` | `#2a2a2a` | `#e5e7eb` | Card borders, dividers, separators |
| Border subtle | `--color-border-subtle` | `#1f1f1f` | `#f0f1f3` | Light separation between sections |

### 1.2 Status Colors

Each status has five variants: primary (icons, bold text), light (background fills), dark (emphasized text on light bg), subtle (badge backgrounds), and border (left-accent on alert cards).

#### Green -- Safe / Allowed / Healthy

| Variant | CSS Variable | Dark Mode | Light Mode | Usage |
|---------|-------------|-----------|------------|-------|
| Primary | `--color-safe` | `#22c55e` | `#16a34a` | Status icons, inline indicators |
| Light | `--color-safe-light` | `rgba(34,197,94,0.10)` | `rgba(22,163,74,0.08)` | Background fills, row highlights |
| Dark | `--color-safe-dark` | `#4ade80` | `#15803d` | Emphasized text on colored bg |
| Subtle | `--color-safe-subtle` | `rgba(34,197,94,0.15)` | `rgba(22,163,74,0.12)` | Badge/pill backgrounds |
| Border | `--color-safe-border` | `#22c55e` | `#16a34a` | Left accent on safe alert cards |

#### Red -- Dangerous / Blocked / Threat

| Variant | CSS Variable | Dark Mode | Light Mode | Usage |
|---------|-------------|-----------|------------|-------|
| Primary | `--color-danger` | `#ef4444` | `#dc2626` | Status icons, inline indicators |
| Light | `--color-danger-light` | `rgba(239,68,68,0.10)` | `rgba(220,38,38,0.08)` | Background fills, row highlights |
| Dark | `--color-danger-dark` | `#f87171` | `#b91c1c` | Emphasized text on colored bg |
| Subtle | `--color-danger-subtle` | `rgba(239,68,68,0.15)` | `rgba(220,38,38,0.12)` | Badge/pill backgrounds |
| Border | `--color-danger-border` | `#ef4444` | `#dc2626` | Left accent on danger alert cards |

#### Amber -- Suspicious / Warning / Caution

| Variant | CSS Variable | Dark Mode | Light Mode | Usage |
|---------|-------------|-----------|------------|-------|
| Primary | `--color-warning` | `#f59e0b` | `#d97706` | Status icons, inline indicators |
| Light | `--color-warning-light` | `rgba(245,158,11,0.10)` | `rgba(217,119,6,0.08)` | Background fills, row highlights |
| Dark | `--color-warning-dark` | `#fbbf24` | `#b45309` | Emphasized text on colored bg |
| Subtle | `--color-warning-subtle` | `rgba(245,158,11,0.15)` | `rgba(217,119,6,0.12)` | Badge/pill backgrounds |
| Border | `--color-warning-border` | `#f59e0b` | `#d97706` | Left accent on warning alert cards |

#### Blue -- Informational / Learning / Unusual

| Variant | CSS Variable | Dark Mode | Light Mode | Usage |
|---------|-------------|-----------|------------|-------|
| Primary | `--color-info` | `#3b82f6` | `#2563eb` | Status icons, inline indicators |
| Light | `--color-info-light` | `rgba(59,130,246,0.10)` | `rgba(37,99,235,0.08)` | Background fills, row highlights |
| Dark | `--color-info-dark` | `#60a5fa` | `#1d4ed8` | Emphasized text on colored bg |
| Subtle | `--color-info-subtle` | `rgba(59,130,246,0.15)` | `rgba(37,99,235,0.12)` | Badge/pill backgrounds |
| Border | `--color-info-border` | `#3b82f6` | `#2563eb` | Left accent on info alert cards |

### 1.3 Accent Color -- ClawDefender Brand

The accent is a restrained teal-blue that reads as trustworthy and technical without being corporate. It sits between blue and cyan -- distinctive from the pure blue used for informational status.

| Variant | CSS Variable | Dark Mode | Light Mode | Usage |
|---------|-------------|-----------|------------|-------|
| Primary | `--color-accent` | `#38bdf8` | `#0284c7` | Interactive elements, links, active nav |
| Hover | `--color-accent-hover` | `#7dd3fc` | `#0369a1` | Hover state for interactive elements |
| Active | `--color-accent-active` | `#0ea5e9` | `#075985` | Active/pressed state |
| Subtle | `--color-accent-subtle` | `rgba(56,189,248,0.12)` | `rgba(2,132,199,0.08)` | Selected row, active sidebar item bg |
| Text | `--color-accent-text` | `#7dd3fc` | `#0369a1` | Link text, breadcrumb active |

### 1.4 CSS Custom Properties Block

```css
:root {
  /* Base */
  --color-bg-primary: #0f0f0f;
  --color-bg-secondary: #1a1a1a;
  --color-bg-tertiary: #252525;
  --color-bg-sunken: #0a0a0a;
  --color-text-primary: #e5e5e5;
  --color-text-secondary: #a3a3a3;
  --color-text-muted: #6b7280;
  --color-border: #2a2a2a;
  --color-border-subtle: #1f1f1f;

  /* Accent */
  --color-accent: #38bdf8;
  --color-accent-hover: #7dd3fc;
  --color-accent-active: #0ea5e9;
  --color-accent-subtle: rgba(56, 189, 248, 0.12);
  --color-accent-text: #7dd3fc;

  /* Safe (green) */
  --color-safe: #22c55e;
  --color-safe-light: rgba(34, 197, 94, 0.10);
  --color-safe-dark: #4ade80;
  --color-safe-subtle: rgba(34, 197, 94, 0.15);
  --color-safe-border: #22c55e;

  /* Danger (red) */
  --color-danger: #ef4444;
  --color-danger-light: rgba(239, 68, 68, 0.10);
  --color-danger-dark: #f87171;
  --color-danger-subtle: rgba(239, 68, 68, 0.15);
  --color-danger-border: #ef4444;

  /* Warning (amber) */
  --color-warning: #f59e0b;
  --color-warning-light: rgba(245, 158, 11, 0.10);
  --color-warning-dark: #fbbf24;
  --color-warning-subtle: rgba(245, 158, 11, 0.15);
  --color-warning-border: #f59e0b;

  /* Info (blue) */
  --color-info: #3b82f6;
  --color-info-light: rgba(59, 130, 246, 0.10);
  --color-info-dark: #60a5fa;
  --color-info-subtle: rgba(59, 130, 246, 0.15);
  --color-info-border: #3b82f6;
}

[data-theme="light"] {
  /* Base */
  --color-bg-primary: #ffffff;
  --color-bg-secondary: #f8f9fa;
  --color-bg-tertiary: #f0f1f3;
  --color-bg-sunken: #edeef0;
  --color-text-primary: #1a1a1a;
  --color-text-secondary: #6b7280;
  --color-text-muted: #9ca3af;
  --color-border: #e5e7eb;
  --color-border-subtle: #f0f1f3;

  /* Accent */
  --color-accent: #0284c7;
  --color-accent-hover: #0369a1;
  --color-accent-active: #075985;
  --color-accent-subtle: rgba(2, 132, 199, 0.08);
  --color-accent-text: #0369a1;

  /* Safe (green) */
  --color-safe: #16a34a;
  --color-safe-light: rgba(22, 163, 74, 0.08);
  --color-safe-dark: #15803d;
  --color-safe-subtle: rgba(22, 163, 74, 0.12);
  --color-safe-border: #16a34a;

  /* Danger (red) */
  --color-danger: #dc2626;
  --color-danger-light: rgba(220, 38, 38, 0.08);
  --color-danger-dark: #b91c1c;
  --color-danger-subtle: rgba(220, 38, 38, 0.12);
  --color-danger-border: #dc2626;

  /* Warning (amber) */
  --color-warning: #d97706;
  --color-warning-light: rgba(217, 119, 6, 0.08);
  --color-warning-dark: #b45309;
  --color-warning-subtle: rgba(217, 119, 6, 0.12);
  --color-warning-border: #d97706;

  /* Info (blue) */
  --color-info: #2563eb;
  --color-info-light: rgba(37, 99, 235, 0.08);
  --color-info-dark: #1d4ed8;
  --color-info-subtle: rgba(37, 99, 235, 0.12);
  --color-info-border: #2563eb;
}
```

### 1.5 Tailwind Extend Config

```js
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        bg: {
          primary: "var(--color-bg-primary)",
          secondary: "var(--color-bg-secondary)",
          tertiary: "var(--color-bg-tertiary)",
          sunken: "var(--color-bg-sunken)",
        },
        text: {
          primary: "var(--color-text-primary)",
          secondary: "var(--color-text-secondary)",
          muted: "var(--color-text-muted)",
        },
        border: {
          DEFAULT: "var(--color-border)",
          subtle: "var(--color-border-subtle)",
        },
        accent: {
          DEFAULT: "var(--color-accent)",
          hover: "var(--color-accent-hover)",
          active: "var(--color-accent-active)",
          subtle: "var(--color-accent-subtle)",
          text: "var(--color-accent-text)",
        },
        safe: {
          DEFAULT: "var(--color-safe)",
          light: "var(--color-safe-light)",
          dark: "var(--color-safe-dark)",
          subtle: "var(--color-safe-subtle)",
          border: "var(--color-safe-border)",
        },
        danger: {
          DEFAULT: "var(--color-danger)",
          light: "var(--color-danger-light)",
          dark: "var(--color-danger-dark)",
          subtle: "var(--color-danger-subtle)",
          border: "var(--color-danger-border)",
        },
        warning: {
          DEFAULT: "var(--color-warning)",
          light: "var(--color-warning-light)",
          dark: "var(--color-warning-dark)",
          subtle: "var(--color-warning-subtle)",
          border: "var(--color-warning-border)",
        },
        info: {
          DEFAULT: "var(--color-info)",
          light: "var(--color-info-light)",
          dark: "var(--color-info-dark)",
          subtle: "var(--color-info-subtle)",
          border: "var(--color-info-border)",
        },
      },
    },
  },
  plugins: [],
};
```

---

## 2. Typography

### 2.1 Font Stack

ClawDefender uses the system font stack. On macOS this resolves to San Francisco. No custom fonts are loaded.

```css
font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
```

For monospaced content (code paths, event IDs, tool names):
```css
font-family: "SF Mono", SFMono-Regular, ui-monospace, Menlo, Monaco, Consolas, monospace;
```

### 2.2 Size Scale

| Tailwind Class | Size | Line Height | Use Case |
|---------------|------|-------------|----------|
| `text-xs` | 11px / 0.6875rem | 1rem | Timestamps, badge labels, fine print |
| `text-sm` | 13px / 0.8125rem | 1.25rem | Table cells, secondary descriptions, sidebar labels |
| `text-base` | 15px / 0.9375rem | 1.5rem | Body text, card content, form labels |
| `text-lg` | 17px / 1.0625rem | 1.75rem | Card titles, section headers within a page |
| `text-xl` | 20px / 1.25rem | 1.75rem | Page titles, modal headers |
| `text-2xl` | 24px / 1.5rem | 2rem | Large stat numbers, welcome heading |
| `text-3xl` | 30px / 1.875rem | 2.25rem | Hero stat on dashboard (event count) |
| `text-4xl` | 36px / 2.25rem | 2.5rem | Reserved -- only for onboarding splash |

Note: Sizes are tuned slightly for macOS app context where 15px is the comfortable body size (matching SF Pro Text at standard resolution).

### 2.3 Font Weight

| Tailwind Class | Weight | Usage |
|---------------|--------|-------|
| `font-normal` (400) | Default | Body text, descriptions, table cells |
| `font-medium` (500) | Emphasis | Labels, sidebar items, card titles, active nav |
| `font-semibold` (600) | Strong emphasis | Page titles, stat numbers, section headings |

Rules:
- Never use `font-bold` (700) or `font-extrabold` in body content. Claw does not shout.
- `font-semibold` is the maximum weight for any text element.
- Monospaced text is always `font-normal`.

### 2.4 Letter Spacing

| Tailwind Class | Usage |
|---------------|-------|
| `tracking-normal` | Default for all body text |
| `tracking-tight` | Headings `text-2xl` and above |
| `tracking-wide` | All-caps labels only (e.g., section dividers like "SERVERS", "RECENT EVENTS") |

### 2.5 Line Height

| Tailwind Class | Usage |
|---------------|-------|
| `leading-snug` (1.375) | Headings, card titles |
| `leading-normal` (1.5) | Body text, descriptions |
| `leading-relaxed` (1.625) | Long-form text blocks (Ask Claw responses, explanations) |

---

## 3. Iconography

ClawDefender uses **Lucide React** icons (`lucide-react` package). Lucide provides clean, consistent 24x24 SVG icons with 2px stroke width -- closely matching SF Symbols aesthetics.

### 3.1 Icon Sizing

| Context | Size | Tailwind Class |
|---------|------|---------------|
| Inline with text (badges, labels) | 14px | `w-3.5 h-3.5` |
| Standard UI (buttons, list items) | 16px | `w-4 h-4` |
| Navigation sidebar | 18px | `w-[18px] h-[18px]` |
| Card header icons | 20px | `w-5 h-5` |
| Empty state illustrations | 48px | `w-12 h-12` |

All icons use `stroke-width={1.75}` for a slightly lighter feel than the Lucide default of 2.

### 3.2 Status Icons

| Status | Icon | Lucide Name | Color Variable |
|--------|------|-------------|---------------|
| Safe / Normal | Shield with checkmark | `ShieldCheck` | `--color-safe` |
| Dangerous / Blocked | Shield with X | `ShieldX` | `--color-danger` |
| Suspicious / Warning | Warning triangle | `AlertTriangle` | `--color-warning` |
| Unusual / Info | Eye | `Eye` | `--color-info` |
| Blocked (action) | Circle with slash | `Ban` | `--color-danger` |
| Allowed (action) | Circle with check | `CheckCircle` | `--color-safe` |
| Learning | Brain | `Brain` | `--color-info` |

### 3.3 Navigation Icons

| Section | Icon | Lucide Name |
|---------|------|-------------|
| Dashboard | Layout grid | `LayoutDashboard` |
| Ask Claw | Message circle | `MessageCircle` |
| My Tools | Wrench | `Wrench` |
| Activity | Activity pulse | `Activity` |
| Alerts | Bell | `Bell` |
| Settings | Sliders | `SlidersHorizontal` |

### 3.4 Action Icons

| Action | Icon | Lucide Name |
|--------|------|-------------|
| Block | Ban circle | `Ban` |
| Allow | Check circle | `CheckCircle` |
| Scan | Search/radar | `ScanSearch` |
| Refresh | Rotate | `RotateCw` |
| Settings | Gear | `Settings` |
| Expand | Chevron down | `ChevronDown` |
| Collapse | Chevron up | `ChevronUp` |
| External link | Arrow up-right | `ExternalLink` |
| Copy | Copy | `Copy` |
| More actions | Ellipsis | `MoreHorizontal` |
| Close | X | `X` |
| Back | Arrow left | `ArrowLeft` |
| Filter | Filter | `Filter` |
| Sort | Arrow up-down | `ArrowUpDown` |

---

## 4. Spacing and Layout

### 4.1 Grid System

```
+------------------+-------------------------------------------+
|     Sidebar      |              Content Area                 |
|    w-[220px]     |              flex-1                       |
|    px-3 py-4     |              px-6 py-6                    |
|                  |                                           |
|  Logo + nav      |    Page header                            |
|                  |    Content body                           |
|                  |                                           |
|                  |    max-w-[1200px] for readability          |
+------------------+-------------------------------------------+
```

| Element | Value | Notes |
|---------|-------|-------|
| Sidebar width | `w-[220px]` | Fixed. Collapses to icons at `w-[56px]` on small windows. |
| Sidebar padding | `px-3 py-4` | |
| Content padding | `px-6 py-6` | `px-4 py-4` on viewports under 768px |
| Content max width | `max-w-[1200px]` | Centered with `mx-auto` |
| Page header margin bottom | `mb-6` | Space between title row and content |

### 4.2 Spacing Scale

Use Tailwind's default scale. Preferred values for consistency:

| Token | px | Usage |
|-------|-----|-------|
| `1` | 4px | Inline icon-to-text gap |
| `1.5` | 6px | Tight list item padding |
| `2` | 8px | Badge padding, compact gaps |
| `3` | 12px | Card internal element spacing |
| `4` | 16px | Card padding, standard gap between elements |
| `6` | 24px | Gap between cards in a grid, section spacing |
| `8` | 32px | Major section separation |
| `12` | 48px | Page-level vertical rhythm |
| `16` | 64px | Large empty space, hero spacing |

### 4.3 Card Design

#### Standard Card
```
rounded-lg
border border-[var(--color-border)]
bg-[var(--color-bg-secondary)]
p-4
```

#### Alert Card (left accent border)
```
rounded-lg
border border-[var(--color-border)]
border-l-[3px] border-l-[var(--color-{status}-border)]
bg-[var(--color-bg-secondary)]
p-4
```
Where `{status}` is `safe`, `danger`, `warning`, or `info`.

#### Stat Card
```
rounded-lg
border border-[var(--color-border)]
bg-[var(--color-bg-secondary)]
p-4
```
Layout: Large number (`text-2xl font-semibold`) on top, label (`text-sm text-[var(--color-text-secondary)]`) below. Optional status dot or trend indicator inline with the number.

#### Server Card
```
rounded-lg
border border-[var(--color-border)]
bg-[var(--color-bg-secondary)]
p-4
hover:bg-[var(--color-bg-tertiary)]
transition-colors duration-150
cursor-pointer
```
Layout: Server name (`text-base font-medium`) + status badge on one row, metadata (`text-sm text-secondary`) below.

### 4.4 Density

- **Default (spacious)**: `gap-4` between items, `p-4` card padding. Used for Dashboard, Settings.
- **Compact**: `gap-2` between items, `p-3` card padding, `text-sm` body text. Used for Activity log, Event lists, detailed table views.

The user does not toggle density -- it is set per-view by the design.

---

## 5. Animation and Motion

Claw is calm. Motion exists to orient the user, not to entertain. Every animation should feel like a quiet inhale -- present but not attention-seeking.

### 5.1 Timing Tokens

| Token | Duration | Easing | Usage |
|-------|----------|--------|-------|
| `--duration-fast` | `100ms` | `ease-out` | Hover color changes, focus rings |
| `--duration-normal` | `150ms` | `ease-out` | Fade-in, list item additions |
| `--duration-moderate` | `200ms` | `ease-out` | Slide transitions, toast entrance |
| `--duration-slow` | `300ms` | `ease-in-out` | Status color crossfades, page transitions |

### 5.2 Page Transitions

Navigating between pages (Dashboard to Activity, etc.):
```css
.page-enter {
  opacity: 0;
  transform: translateY(4px);
}
.page-enter-active {
  opacity: 1;
  transform: translateY(0);
  transition: opacity 200ms ease-out, transform 200ms ease-out;
}
.page-exit {
  opacity: 1;
}
.page-exit-active {
  opacity: 0;
  transition: opacity 100ms ease-in;
}
```

The incoming page fades in with a subtle 4px upward shift. The outgoing page fades out quickly (100ms) so there is no stacking delay.

### 5.3 Status Color Transitions

When a server's status changes (e.g., normal to suspicious), the status color crossfades over 300ms:
```css
.status-indicator {
  transition: color 300ms ease-in-out, background-color 300ms ease-in-out;
}
```

No flashing. No pulsing. The color simply becomes the new color.

### 5.4 Tray Icon -- Analysis Pulse

When Claw is actively analyzing (e.g., during a scan or processing a flagged event), the tray icon uses a subtle opacity pulse:

```css
@keyframes analysis-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
}

.tray-icon-analyzing {
  animation: analysis-pulse 2s ease-in-out infinite;
}
```

- Duration: 2 seconds per cycle (heartbeat rhythm, not frantic)
- Opacity range: 1.0 to 0.6 (noticeable but not alarming)
- Easing: ease-in-out for organic feel
- Stops immediately when analysis is complete (no fade-out of the animation itself)

When idle, the tray icon is static at full opacity.

### 5.5 Loading States

**Content loading -- skeleton screens:**
```css
@keyframes skeleton-shimmer {
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}

.skeleton {
  background: linear-gradient(
    90deg,
    var(--color-bg-tertiary) 25%,
    var(--color-bg-secondary) 50%,
    var(--color-bg-tertiary) 75%
  );
  background-size: 200% 100%;
  animation: skeleton-shimmer 1.5s ease-in-out infinite;
  border-radius: 4px;
}
```

Use skeleton screens for: dashboard cards, server list, event list, chat history.

**Active operations -- spinner:**
Spinners are reserved for actions the user initiated where they are waiting for completion: starting the daemon, running a scan, sending a message to Claw.

```css
@keyframes spin {
  to { transform: rotate(360deg); }
}

.spinner {
  width: 16px;
  height: 16px;
  border: 2px solid var(--color-border);
  border-top-color: var(--color-accent);
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}
```

### 5.6 Prompt Window

The prompt window slides down from the menu bar area:
```css
.prompt-enter {
  opacity: 0;
  transform: translateY(-8px);
}
.prompt-enter-active {
  opacity: 1;
  transform: translateY(0);
  transition: opacity 200ms ease-out, transform 200ms ease-out;
}
.prompt-exit-active {
  opacity: 0;
  transform: translateY(-8px);
  transition: opacity 150ms ease-in, transform 150ms ease-in;
}
```

### 5.7 Toast Notifications

Toasts slide in from the right:
```css
.toast-enter {
  opacity: 0;
  transform: translateX(16px);
}
.toast-enter-active {
  opacity: 1;
  transform: translateX(0);
  transition: opacity 200ms ease-out, transform 200ms ease-out;
}
.toast-exit-active {
  opacity: 0;
  transform: translateX(16px);
  transition: opacity 150ms ease-in, transform 150ms ease-in;
}
```

Auto-dismiss after 5 seconds (informational) or persist until dismissed (warnings/errors).

### 5.8 List Item Additions

New items in event lists or server lists fade in with a vertical shift:
```css
.list-item-enter {
  opacity: 0;
  transform: translateY(6px);
}
.list-item-enter-active {
  opacity: 1;
  transform: translateY(0);
  transition: opacity 150ms ease-out, transform 150ms ease-out;
}
```

### 5.9 Motion Rules

- No bouncing, shaking, flashing, or jittering. Ever.
- No spring physics or overshoot. Ease-out for entrances, ease-in for exits.
- Users with `prefers-reduced-motion` get instant transitions (duration: 0ms).
- Maximum one animation per element at a time.

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```

---

## 6. Component Style Guide

### 6.1 Buttons

#### Primary (accent)
```
bg-[var(--color-accent)] text-white
px-4 py-2 rounded-md text-sm font-medium
hover:bg-[var(--color-accent-hover)]
active:bg-[var(--color-accent-active)]
disabled:opacity-40 disabled:cursor-not-allowed
transition-colors duration-100
```
Usage: Main CTA per section. "Start Daemon", "Send", "Apply".

#### Secondary (gray)
```
bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)]
px-4 py-2 rounded-md text-sm font-medium
border border-[var(--color-border)]
hover:bg-[var(--color-bg-sunken)]
active:opacity-80
disabled:opacity-40 disabled:cursor-not-allowed
transition-colors duration-100
```
Usage: Secondary actions. "Cancel", "Close", "Reset".

#### Danger
```
bg-[var(--color-danger)] text-white
px-4 py-2 rounded-md text-sm font-medium
hover:opacity-90
active:opacity-80
disabled:opacity-40 disabled:cursor-not-allowed
transition-colors duration-100
```
Usage: Destructive actions. "Block Server", "Delete Rule".

#### Ghost
```
bg-transparent text-[var(--color-text-secondary)]
px-3 py-1.5 rounded-md text-sm font-medium
hover:bg-[var(--color-bg-tertiary)] hover:text-[var(--color-text-primary)]
active:opacity-80
disabled:opacity-40 disabled:cursor-not-allowed
transition-colors duration-100
```
Usage: Toolbar actions, inline actions. "View Details", "Copy".

#### Small variant
Add `px-3 py-1.5 text-xs` to any button type for compact contexts (table rows, badge-adjacent).

### 6.2 Badges / Pills

All badges: `inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium`

| Badge | Background | Text Color | Icon |
|-------|-----------|------------|------|
| Dangerous | `bg-[var(--color-danger-subtle)]` | `text-[var(--color-danger-dark)]` | `ShieldX` 12px |
| Suspicious | `bg-[var(--color-warning-subtle)]` | `text-[var(--color-warning-dark)]` | `AlertTriangle` 12px |
| Unusual | `bg-[var(--color-info-subtle)]` | `text-[var(--color-info-dark)]` | `Eye` 12px |
| Normal | `bg-[var(--color-safe-subtle)]` | `text-[var(--color-safe-dark)]` | `ShieldCheck` 12px |
| Blocked | `bg-[var(--color-danger-subtle)]` | `text-[var(--color-danger-dark)]` | `Ban` 12px |
| Allowed | `bg-[var(--color-safe-subtle)]` | `text-[var(--color-safe-dark)]` | `CheckCircle` 12px |

### 6.3 Toggle Switches

```
/* Track */
w-9 h-5 rounded-full
bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]
transition-colors duration-150

/* Track (active) */
bg-[var(--color-accent)] border-[var(--color-accent)]

/* Thumb */
w-3.5 h-3.5 rounded-full bg-white
shadow-sm
transform transition-transform duration-150
translate-x-0.5 (off) / translate-x-[18px] (on)
```

### 6.4 Input Fields

```
w-full
bg-[var(--color-bg-primary)] text-[var(--color-text-primary)]
px-3 py-2 rounded-md text-sm
border border-[var(--color-border)]
placeholder:text-[var(--color-text-muted)]
focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)] focus:ring-offset-0 focus:border-transparent
disabled:opacity-50 disabled:cursor-not-allowed
transition-colors duration-100
```

#### Dropdown / Select
Same base styles as input, plus:
```
appearance-none
bg-[url('data:image/svg+xml,...')] bg-no-repeat bg-right-3 bg-center
pr-8
```
Use a chevron-down SVG as the dropdown indicator.

### 6.5 Cards

#### Standard Card
```html
<div class="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
  <!-- content -->
</div>
```

#### Alert Card (with left accent)
```html
<div class="rounded-lg border border-[var(--color-border)] border-l-[3px] border-l-[var(--color-danger-border)] bg-[var(--color-bg-secondary)] p-4">
  <div class="flex items-start gap-3">
    <ShieldX class="w-5 h-5 text-[var(--color-danger)] mt-0.5 shrink-0" />
    <div>
      <p class="text-sm font-medium text-[var(--color-text-primary)]">Title</p>
      <p class="text-sm text-[var(--color-text-secondary)] mt-1">Description</p>
    </div>
  </div>
</div>
```

#### Stat Card
```html
<div class="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
  <p class="text-2xl font-semibold tracking-tight text-[var(--color-text-primary)]">847</p>
  <p class="text-sm text-[var(--color-text-secondary)] mt-1">Events today</p>
</div>
```

### 6.6 Progress Indicators

#### Determinate Progress Bar
```
/* Track */
w-full h-1.5 rounded-full bg-[var(--color-bg-tertiary)]

/* Fill */
h-full rounded-full bg-[var(--color-accent)]
transition-[width] duration-300 ease-out
```

#### Indeterminate Progress
```css
@keyframes indeterminate {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(200%); }
}

.progress-indeterminate {
  width: 40%;
  animation: indeterminate 1.2s ease-in-out infinite;
}
```

### 6.7 Empty States

Empty states use a single line-art icon (48px, `text-[var(--color-text-muted)]`), a short heading, and an optional action button. No illustrations, no cartoons, no emoji.

```html
<div class="flex flex-col items-center justify-center py-16 text-center">
  <ShieldCheck class="w-12 h-12 text-[var(--color-text-muted)] mb-4" strokeWidth={1.5} />
  <p class="text-base font-medium text-[var(--color-text-primary)]">No alerts</p>
  <p class="text-sm text-[var(--color-text-secondary)] mt-1 max-w-[280px]">
    Everything is quiet. Claw is watching.
  </p>
</div>
```

Messaging should be positive and calm:
- No alerts: "Everything is quiet. Claw is watching."
- No servers: "No MCP servers detected yet. Start an AI tool and I will find them."
- No events: "No activity recorded yet. Events will appear here as your AI tools work."
- No search results: "Nothing matched your search."

---

## Appendix: Quick Reference

### Color CSS Variables (Complete List)

```
--color-bg-primary
--color-bg-secondary
--color-bg-tertiary
--color-bg-sunken
--color-text-primary
--color-text-secondary
--color-text-muted
--color-border
--color-border-subtle
--color-accent
--color-accent-hover
--color-accent-active
--color-accent-subtle
--color-accent-text
--color-safe / -light / -dark / -subtle / -border
--color-danger / -light / -dark / -subtle / -border
--color-warning / -light / -dark / -subtle / -border
--color-info / -light / -dark / -subtle / -border
```

### Animation Timing

```
--duration-fast: 100ms
--duration-normal: 150ms
--duration-moderate: 200ms
--duration-slow: 300ms
```

### Icon Library

Package: `lucide-react`
Stroke width: `1.75`
Default size: `16px` (`w-4 h-4`)
