# Settings Simplification Plan

**Version**: 1.0
**Step**: 7 -- Simplify Settings and Onboarding
**Status**: Authoritative

---

## Current State Audit

The existing `Settings.tsx` is reasonably well-structured with 6 sections:

1. Protection Level (ProtectionLevel component)
2. Start at Login (toggle)
3. AI Analysis (AIAnalysis component with model manager)
4. Theme (select dropdown)
5. Notifications (toggle + minimize to tray sub-toggle)
6. About / Help (version + links)
7. Advanced Settings (hidden behind toggle)

**What works well**:
- Clean layout with rounded cards.
- Auto-save with status indicator.
- Advanced settings are tucked away.
- Protection level has good visual design.

**Problems**:
- No protection score header -- user cannot see their score without going to Home.
- No simple/advanced mode -- the "Show advanced settings" toggle is binary but not well-delineated.
- Protection level card does not show what each level *does* -- just the name.
- AI Analysis section jumps straight to model manager which is overwhelming.
- Trust level summary is missing -- users must go to My Tools to see trust configuration.
- No clear no-model vs. has-model states for AI Analysis.
- Notification settings are minimal -- no per-type fine-tuning in advanced mode.
- Per-server settings (behavioral threshold, auto-block) are in Settings but belong in My Tools per-server detail.

---

## New Settings Architecture

### Two Modes

**Simple Mode** (default): The 80% case. Everything a normal user needs on one screen.

**Advanced Mode**: Power users toggle "Show advanced settings" to see everything.

The mode toggle persists in `appStore` (not in settings file -- it is a UI preference).

---

### Simple Mode Layout

```
+--------------------------------------------------+
|  Protection Score Header                          |
|  [Score Ring 64px] 82 -- Well protected           |
|  "Looking good. A few things could be tighter."   |
|  [View breakdown ->]                              |
+--------------------------------------------------+

+--------------------------------------------------+
|  Protection Level                                 |
|  [ProtectionLevelChooser component]               |
|  Currently: Handle it for me (balanced)           |
|  Effects: "Blocks dangerous actions, prompts for  |
|  sensitive ones, allows routine operations."      |
+--------------------------------------------------+

+--------------------------------------------------+
|  Trust Levels                                     |
|  3 servers: 1 trusted, 1 standard, 1 cautious    |
|  [Manage trust levels ->] (navigates to /tools)   |
+--------------------------------------------------+

+--------------------------------------------------+
|  AI Analysis                                      |
|  State A (no model):                              |
|    "No AI model active. I am using rules only."   |
|    [Set up AI model ->]                           |
|  State B (model active):                          |
|    "Phi-3 Mini (local) -- 342 analyses today"     |
|    [Change model ->]                              |
|  State C (cloud only):                            |
|    "Claude API (cloud) -- sends data externally"  |
|    [Change model ->]                              |
+--------------------------------------------------+

+--------------------------------------------------+
|  Notifications                   [toggle]         |
|  Get alerts when actions are blocked or need      |
|  attention.                                       |
+--------------------------------------------------+

+--------------------------------------------------+
|  Start at login                  [toggle]         |
|  Recommended -- keeps you protected automatically |
+--------------------------------------------------+

+--------------------------------------------------+
|  About Rookbot                               |
|  Version 0.5.0-beta                               |
|  [Send Feedback] [GitHub] [Documentation]         |
+--------------------------------------------------+

[Show advanced settings ->]
```

---

### Advanced Mode Layout

Everything from Simple Mode plus:

```
+--------------------------------------------------+
|  Notification Fine-Tuning                         |
|  Auto-block notifications        [toggle]         |
|  Prompt window notifications     [toggle]         |
|  Weekly digest                   [toggle]         |
|  Score change alerts             [toggle]         |
|  New tool detection alerts       [toggle]         |
+--------------------------------------------------+

+--------------------------------------------------+
|  Score Factor Weights                             |
|  Tool Coverage:       [slider 0-40] default 25    |
|  Threat Intelligence: [slider 0-40] default 20    |
|  AI Analysis:         [slider 0-40] default 15    |
|  System Visibility:   [slider 0-40] default 15    |
|  Unresolved Alerts:   [slider 0-40] default 15    |
|  Config Health:       [slider 0-40] default 10    |
|  Total: [sum] / must equal 100                    |
|  [Reset to defaults]                              |
+--------------------------------------------------+

+--------------------------------------------------+
|  Theme                                            |
|  [System] [Light] [Dark]                          |
+--------------------------------------------------+

+--------------------------------------------------+
|  Behavioral Analysis                              |
|  Auto-block threshold:  [slider 0.5-1.0]         |
|  Auto-block enabled:    [toggle]                  |
|  Analysis frequency:    [dropdown: all/high/off]  |
+--------------------------------------------------+

+--------------------------------------------------+
|  Data & Privacy                                   |
|  Event retention:  [number] days                  |
|  Log level:        [dropdown]                     |
|  Prompt timeout:   [number] seconds               |
|  Telemetry:        [toggle]                       |
+--------------------------------------------------+

+--------------------------------------------------+
|  Export / Import                                   |
|  [Export settings] [Import settings]              |
+--------------------------------------------------+
```

---

### Removed from Settings (Moved to My Tools)

These per-server settings belong in the My Tools server detail page, not in global Settings:

- Per-server trust level (already in My Tools)
- Per-server behavioral threshold override
- Per-server permission overrides

---

## Shared Components

### `ProtectionLevelChooser`

Used in both Onboarding Screen 3 and Settings Simple Mode.

**Props**:
```typescript
interface ProtectionLevelChooserProps {
  currentLevel: string;
  onLevelChanged: (level: string) => void;
  showEffects?: boolean;  // true in Settings, false in onboarding (quotes shown instead)
  compact?: boolean;      // true in Settings for inline display
}
```

**Protection level effects display** (shown in Settings):

| Level | Effects |
|-------|---------|
| Handle it for me (balanced) | Blocks dangerous actions, prompts for sensitive ones, allows routine operations. |
| Ask me about everything (strict) | Prompts for every action. Nothing passes without your approval. |
| Just watch and learn (audit-only) | Logs everything but blocks nothing. Full visibility, no interruptions. |

### `ScoreHeader`

Reusable protection score display for Settings and potentially other pages.

**Props**:
```typescript
interface ScoreHeaderProps {
  score: number;
  label: string;
  description: string;
  onViewBreakdown?: () => void;
}
```

---

## Backend Changes

### New Settings Fields

Add to `AppSettings`:
```rust
pub notification_auto_block: bool,        // default true
pub notification_prompts: bool,           // default true
pub notification_weekly_digest: bool,     // default true
pub notification_score_changes: bool,     // default true
pub notification_new_tools: bool,         // default true
pub score_weights: Option<ScoreWeights>,  // null = defaults
```

```rust
pub struct ScoreWeights {
    pub tool_coverage: u32,       // default 25
    pub threat_intelligence: u32, // default 20
    pub ai_analysis: u32,        // default 15
    pub system_visibility: u32,  // default 15
    pub unresolved_alerts: u32,  // default 15
    pub config_health: u32,      // default 10
}
```

Validation: All weights must sum to 100. If they do not, reject the update.

### New Command

```
get_trust_level_summary() -> TrustLevelSummary
```

Returns:
```typescript
interface TrustLevelSummary {
  total_servers: number;
  trusted_count: number;
  standard_count: number;
  cautious_count: number;
  restricted_count: number;
  any_customized: boolean;
}
```

---

## Migration Notes

1. The existing `ProtectionLevel` component in `components/settings/` is replaced by the shared `ProtectionLevelChooser`.
2. The existing `AdvancedSettings` component is restructured into the new advanced sections.
3. The `AIAnalysis` component is simplified for Simple Mode and retains full model manager access in Advanced Mode.
4. Theme moves from Simple to Advanced -- most users use "System" and never change it.
