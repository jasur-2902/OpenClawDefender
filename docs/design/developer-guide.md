# ClawDefender Developer Guide

This guide explains how to use the design system infrastructure when building ClawDefender UI components.

---

## Where to Find the Design System

- **Visual identity** (colors, typography, animation): `docs/design/visual-identity.md`
- **Threat communication** (threat levels, message templates): `docs/design/threat-communication.md`
- **Onboarding copy**: `docs/design/onboarding-copy.md`
- **Runtime messages**: `docs/design/runtime-messages.md`
- **Character brief** (voice and tone): `docs/design/character-brief.md`

---

## Design Tokens (CSS Custom Properties)

All design tokens are defined in:

```
clients/clawdefender-app/src/styles/tokens.css
```

This file is imported automatically via `globals.css`. It provides:

- Color variables for both dark mode (`:root`) and light mode (`[data-theme="light"]`)
- Animation duration tokens (`--duration-fast`, `--duration-normal`, etc.)
- Shadow tokens (`--shadow-card`, `--shadow-dropdown`, etc.)
- Border radius tokens (`--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-full`)
- Z-index scale (`--z-base` through `--z-prompt`)

---

## Tailwind Theme Colors

The Tailwind config (`tailwind.config.js`) maps CSS variables to Tailwind utility classes. Use these instead of arbitrary values:

| Category | Tailwind prefix | Example usage |
|----------|----------------|---------------|
| Background | `bg-bg-primary`, `bg-bg-secondary` | `<div className="bg-bg-secondary">` |
| Text | `text-text-primary`, `text-text-secondary` | `<p className="text-text-secondary">` |
| Border | `border-border`, `border-border-subtle` | `<div className="border border-border">` |
| Accent | `text-accent`, `bg-accent-subtle` | `<button className="bg-accent text-white">` |
| Status | `text-safe`, `bg-danger-subtle`, `text-warning-dark` | `<span className="text-danger">` |

---

## Message Constants

All user-facing strings live in:

```
clients/clawdefender-app/src/constants/messages.ts
```

Import what you need:

```typescript
import { EMPTY_STATES, ERROR_MESSAGES, NOTIFICATION_TEMPLATES } from "@/constants/messages";

// Onboarding
import { ONBOARDING_WELCOME, ONBOARDING_PROTECTION_LEVELS } from "@/constants/messages";

// Using a message
<p>{EMPTY_STATES.dashboard.headline}</p>
<p>{ERROR_MESSAGES.daemonNotRunning.title}</p>
```

The file includes TypeScript interfaces for all message shapes, so missing fields are caught at compile time.

### Rule: Never hardcode a user-facing string. Always use `messages.ts`.

If you need a new message, add it to the appropriate section in `messages.ts` with proper typing.

---

## Threat Level Utilities

Threat level mapping and helpers live in:

```
clients/clawdefender-app/src/utils/threatLevel.ts
```

### Available functions

```typescript
import {
  getThreatLevel,
  getThreatColor,
  getThreatIcon,
  getNotificationPriority,
  getThreatTextClass,
  getThreatBgClass,
  getThreatBorderClass,
} from "@/utils/threatLevel";

// Map a score to a level
const level = getThreatLevel(0.85); // "suspicious"

// Get CSS variable for inline styles
const color = getThreatColor(level); // "var(--color-warning)"

// Get Lucide icon name
const icon = getThreatIcon(level); // "AlertTriangle"

// Get notification priority
const priority = getNotificationPriority(level); // "prompt"

// Get Tailwind classes for badges
const bgClass = getThreatBgClass(level); // "bg-warning-subtle"
const textClass = getThreatTextOnBgClass(level); // "text-warning-dark"
```

### Types

```typescript
type ThreatLevel = "dangerous" | "suspicious" | "unusual" | "normal" | "blocked" | "info";
type NotificationPriority = "prompt_with_sound" | "prompt" | "banner" | "toast" | "in_feed" | "silent";
```

### Rule: Never hardcode a status color. Always use the threat level utility.

If you need to display a threat level color, icon, or notification priority, use the functions from `threatLevel.ts`. Do not write switch statements or if-else chains that map threat levels to colors in component code.

---

## Animation

Tailwind animation classes are available for common patterns:

| Class | Duration | Use case |
|-------|----------|----------|
| `animate-analysis-pulse` | 2s | Tray icon when analyzing |
| `animate-skeleton-shimmer` | 1.5s | Skeleton loading screens |
| `animate-spin` | 0.6s | Spinner for user-initiated actions |
| `animate-indeterminate` | 1.2s | Indeterminate progress bars |

Transition durations: `duration-fast` (100ms), `duration-normal` (150ms), `duration-moderate` (200ms), `duration-slow` (300ms).

For users with `prefers-reduced-motion`, all animations and transitions are reduced to near-instant via the `tokens.css` media query.

---

## Quick Reference

- Colors: use Tailwind classes (`text-safe`, `bg-danger-subtle`) not raw hex values
- Strings: import from `src/constants/messages.ts`
- Threat levels: use functions from `src/utils/threatLevel.ts`
- Icons: use Lucide React with `strokeWidth={1.75}` and sizes from the visual identity
- Font weights: max is `font-semibold` (600). Never use `font-bold`.
- Animation: keep it calm. Ease-out for entrances, ease-in for exits. No bouncing.
