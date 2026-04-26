# Onboarding Flow Specification

**Version**: 1.0
**Step**: 7 -- Simplify Settings and Onboarding
**Status**: Authoritative

---

## Current State Audit

The existing `Onboarding.tsx` has 5 steps but several problems:

1. **No personality** -- Welcome screen says "Welcome to Rookbot" with generic marketing copy. No Claw character, no typing animation, no warmth.
2. **Step 4 is AI model download** -- This is confusing for new users. AI model setup is optional and should not gate onboarding completion. Currently a full model catalog browser inside onboarding.
3. **No FDA screen** -- FDA is critical for auto-discovery but never requested during onboarding. Users only find out later when score is low.
4. **No protection score on completion** -- The "You're All Set" screen shows a checklist but no score ring to anchor the user's mental model.
5. **Step indicator is numbered dots** -- No sense of personality or progress.
6. **Security level names mismatch design system** -- Uses "Monitor Only / Balanced / Strict" instead of the design system's "Keep Watch / Stay Sharp / Lock It Down" with Claw quotes.
7. **No progressive guidance** -- After onboarding, the user is dropped on the dashboard with no first-week teaching.

---

## New 5-Screen Flow

### Screen 1: "Hi, I'm Claw"

**Layout**: Full-screen centered. Dark background, no chrome.

**Animation sequence**:
1. Claw icon fades in (300ms ease-in).
2. 400ms pause.
3. Headline types character-by-character at 30ms/char.
4. 200ms pause.
5. Body text fades in (200ms).
6. CTA button fades in (200ms).

**Copy** (use Variation B from onboarding-copy.md):
- Headline: "Hey. I am Claw -- nice to meet you."
- Body: "I watch over the AI tools on your machine and make sure they behave. Think of me as a security expert who lives in your menu bar. I will scan your system, set up protection, and stay out of your way. Ready?"
- CTA: "Let's Go"

**Behavior**:
- Single CTA button. No skip, no back.
- CTA click triggers `detect_mcp_clients` and transitions to Screen 2.

---

### Screen 2: "Here's what I found"

**Layout**: Centered card with tool list.

**Behavior**:
1. On enter, auto-run `detect_mcp_clients`. Show skeleton loading.
2. For each detected client, call `list_mcp_servers` to get servers.
3. Display tool cards with checkboxes (all checked by default).

**Tool card format**:
```
[checkbox] server-name
            Part of Client Display Name
            Can: read files, write files, run commands
```

Capabilities come from `get_server_capabilities` if available, otherwise inferred from server name.

**CTAs**:
- Primary: "Protect these" -- wraps checked servers via `wrap_server` with per-item progress indicators.
- Secondary (text link): "Skip for now" -- proceeds without wrapping.

**Empty state** (no tools found):
- Headline: "I did not find any AI tools yet."
- Body: "That is fine -- you might not have any installed, or they might not be running yet. You can add them manually later from the dashboard, or run this scan again any time."
- CTA: "Continue Without Tools"

---

### Screen 3: "How careful should I be?"

**Layout**: Three stacked cards, one pre-selected.

**Cards** (from onboarding-copy.md):

| Card | Label | Claw quote | Subtitle | Template |
|------|-------|------------|----------|----------|
| 1 | Handle it for me | "I will block anything dangerous and ask you about the rest. Most people start here -- it is the right balance of safety and flow." | Good for everyday work -- protection without constant interruptions. | `balanced` |
| 2 | Ask me about everything | "Nothing gets through without your say-so. I will prompt you for every action. It is thorough, but expect more interruptions." | Good for sensitive projects -- maximum control over every action. | `strict` |
| 3 | Just watch and learn | "I will log everything and let you know if something looks off, but I will not block anything. You stay in full control." | Good for exploring -- see what your tools are doing before setting rules. | `permissive` (audit-only) |

**Default selection**: Card 1 ("Handle it for me" / balanced).

**Card design**:
- Selected card has accent border + subtle accent background.
- Claw quote in italics inside the card.
- Radio button indicator on right.

**CTA**: "Continue" -- calls `apply_template` with selected template name.

**Shared component**: `ProtectionLevelChooser` is extracted as a reusable component used here and in Settings.

---

### Screen 4: FDA Request (Conditional)

**Condition**: Only shown if Full Disk Access is NOT granted. Skip if already granted.

Detection: Call a new command `check_fda_status() -> bool` that checks if the app can read a known protected path (e.g., `~/Library/Application Support/Claude/claude_desktop_config.json`).

**Layout**: Centered card with explanation.

**Copy** (from onboarding-copy.md):
- Headline: "One more thing -- I need your permission."
- Why: "Full Disk Access lets me read the config files for your AI tools, so I can find and protect them automatically."
- What if skip: "Without it, I can still protect servers you add manually -- I just will not be able to discover them on my own."
- Guidance: "Open System Settings, go to Privacy & Security, then Full Disk Access, and toggle Rookbot on. I will wait here."

**CTAs**:
- Primary: "Open System Settings" -- calls `tauri_plugin_shell::open("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")`.
- Secondary: "Skip for now"

**Polling**:
- After "Open System Settings" is clicked, poll `check_fda_status()` every 2 seconds.
- When FDA is granted, auto-advance to Screen 5 with a brief success animation.
- Show a subtle "Waiting for permission..." indicator while polling.

---

### Screen 5: "You're all set"

**Layout**: Centered, celebration-oriented.

**Content**:
1. **Summary line**: "[X] servers protected | [Level name] mode"
2. **Protection score ring**: Animated fill from 0 to current score (use `get_protection_score()`). Same ring component as Home page.
3. **Closing message**: "I am in your menu bar whenever you need me. Green means everything is fine. If something needs your attention, I will let you know."
4. **Restart reminder** (if servers were wrapped): "One thing -- restart any AI apps you have open so they route through me."

**CTA**: "Open Rookbot" -- calls:
1. `complete_onboarding()` to persist the flag.
2. `enable_autostart()` to set up login launch.
3. Navigate to `/` (Home).

No checkboxes for autostart/menu bar -- these are enabled by default and can be changed in Settings. Reduces decision fatigue on the final screen.

---

## Progressive Guidance System

### Overview

After onboarding, Claw teaches the user through contextual milestones. Each milestone fires exactly once. Milestones are tracked in SQLite so they persist across sessions.

### Storage

```sql
CREATE TABLE guidance_milestones (
    id TEXT PRIMARY KEY,
    triggered_at TEXT NOT NULL,
    dismissed_at TEXT
);
```

### 9 Milestones

| # | ID | Trigger | Surface | Message |
|---|-----|---------|---------|---------|
| 1 | `first_prompt` | First prompt window appears | PromptOverlay | "This is your first decision. I paused this action because it looked risky. You can allow it, block it, or tell me to always handle actions like this. Take your time." |
| 2 | `first_block` | First auto-block occurs | ClawMessage + Toast | "I just blocked something for the first time. I caught [server] trying to [action]. This is exactly what I am here for. You can review the details anytime." |
| 3 | `behavioral_complete` | First server finishes behavioral learning | ClawMessage | "I have learned how [server] normally behaves. From now on, I will notice if it does something unusual. This is one of my most powerful protections." |
| 4 | `first_day_summary` | 24 hours after onboarding completion | ClawMessage | "Your first day with me: [X] events monitored, [Y] actions I handled. Everything is running smoothly. I will keep watching." |
| 5 | `score_drop_below_70` | Protection score drops below 70 | Toast + ClawMessage | "Your protection score dropped to [X]. The main reason: [factor]. Let me help you fix it." |
| 6 | `first_week_digest` | 7 days after onboarding completion | Weekly digest with first-week framing | "Your first week: [summary]. You are getting the hang of this. I will send you a summary like this every week." |
| 7 | `feature_nudge_tools` | 3 days after onboarding, user has not visited /tools | InlineHint on Home | "Tip: Visit My Tools to see what each of your AI tools can do and customize their trust levels." |
| 8 | `ai_model_nudge` | 5 days after onboarding, SLM still in mock mode or not loaded | ClawMessage + Home pending action | "You are running without an AI model. I can still protect you with rules, but a local model helps me understand context. Set one up in Settings." |
| 9 | `restart_reminder` | 30 minutes after onboarding, no servers have reconnected through the proxy | Toast | "Your AI tools are not routing through me yet. Restart them so I can start monitoring." |

### Milestone Check Logic

Each milestone has a `check` function that returns `true` when the condition is met. The guidance engine runs these checks:
- Milestones 1--3: Checked in response to events (prompt, block, behavioral completion).
- Milestone 4: Timer started on onboarding completion, fires after 24h.
- Milestone 5: Checked whenever score changes.
- Milestone 6: Timer started on onboarding completion, fires after 7 days.
- Milestone 7: Timer fires at 3 days, checks if /tools has been visited (track page visits in appStore).
- Milestone 8: Timer fires at 5 days, checks SLM status.
- Milestone 9: Timer fires at 30 minutes, checks if any server has proxied traffic.

### Surface Types

| Surface | Component | Behavior |
|---------|-----------|----------|
| PromptOverlay | Overlay on top of PromptWindow | Appears above the first prompt, dismissed by any prompt action. |
| ClawMessage | Message in the Ask Claw conversation | Injected as a `claw` role message with `intentId: "guidance.[milestone_id]"`. |
| Toast | System notification or in-app toast | Standard toast with auto-dismiss after 8 seconds. |
| InlineHint | Small banner on Home page | Dismissible card in the pending actions area. |
| Weekly digest | Digest page/notification | Standard weekly digest with a special first-week intro paragraph. |

---

## Tauri Commands (New)

```
check_fda_status() -> bool
get_guidance_milestones() -> Vec<GuidanceMilestone>
dismiss_guidance_milestone(id: String) -> ()
trigger_guidance_check() -> Option<GuidanceMilestone>  // manual trigger for testing
```

---

## Component Architecture

### New Components

- `OnboardingScreen1Welcome` -- typing animation, Claw icon, single CTA.
- `OnboardingScreen2Detect` -- reuses detection logic from current `DetectStep` but with design system styling.
- `OnboardingScreen3Protection` -- uses shared `ProtectionLevelChooser`.
- `OnboardingScreen4FDA` -- conditional, polling-based.
- `OnboardingScreen5Complete` -- score ring, summary, single CTA.
- `ProtectionLevelChooser` -- shared between onboarding and Settings.
- `GuidanceOverlay` -- renders milestone messages on their target surfaces.

### Removed Components

- `StepIndicator` (numbered dots) -- replaced by a minimal progress bar or removed entirely. The flow is linear enough that numbered steps add visual clutter without aiding navigation.
- `AIAnalysisStep` -- model download is removed from onboarding. Users are nudged at day 5 if they have not set up a model.

---

## Transition Logic

```
Screen 1 -> Screen 2  (on CTA click)
Screen 2 -> Screen 3  (after wrap or skip)
Screen 3 -> Screen 4  (if FDA not granted)
Screen 3 -> Screen 5  (if FDA already granted)
Screen 4 -> Screen 5  (on FDA grant or skip)
Screen 5 -> Home       (on CTA click)
```
