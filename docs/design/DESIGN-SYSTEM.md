# Rookbot Design System

**Version**: 1.0
**Date**: 2026-02-24
**Status**: Approved

This is the authoritative reference for Rookbot's personality, voice, visual identity, and message library. Every developer reads this before writing any UI text or designing any screen.

---

## Quick Reference

| Topic | Document | Summary |
|-------|----------|---------|
| Who Claw is | [character-brief.md](character-brief.md) | Personality, relationship to user, how Claw handles uncertainty/bad news/success |
| How Claw speaks | [voice-guide.md](voice-guide.md) | Voice principles, tone variations by context, grammar rules |
| Threat messaging | [threat-communication.md](threat-communication.md) | Score-to-label mapping, 30 scenario templates, notification priority rules |
| Visual language | [visual-identity.md](visual-identity.md) | Colors, typography, icons, spacing, animation, component guide |
| Onboarding copy | [onboarding-copy.md](onboarding-copy.md) | Wizard screens, empty states, protection score explainers |
| Runtime messages | [runtime-messages.md](runtime-messages.md) | Prompt windows, toasts, digest, alerts, errors, conversational responses |
| Terminology | [glossary.md](glossary.md) | Every user-facing term and its definition |
| Developer guide | [developer-guide.md](developer-guide.md) | How to use the implementation files |
| Consistency review | [consistency-review.md](consistency-review.md) | QA findings and resolutions |

---

## 1. Claw's Character

Claw is defined by five adjectives: **Calm, Observant, Direct, Honest, Warm**.

- **Calm**: Never panics. Urgency is communicated through clarity, not exclamation marks.
- **Observant**: Notices what you would miss. Tells you what matters, not everything it sees.
- **Direct**: Says what it means in the fewest words necessary.
- **Honest**: Tells you when it is uncertain. Never pretends to know more than it does.
- **Warm**: On your side. Speaks like a knowledgeable friend, not a compliance report.

**Relationship to user**: Bodyguard, not drill sergeant. Advisor, not judge. Companion, not tool. Expert friend, not support bot.

Full details: [character-brief.md](character-brief.md)

---

## 2. Voice Rules (Abridged)

1. **Calm authority** — "I blocked this" not "THREAT DETECTED"
2. **Plain language** — "This tool tried to read your passwords" not "tools/call matched glob ~/.ssh/*"
3. **Honest about uncertainty** — "I'm not sure about this one" beats a fabricated score
4. **Educational without lecturing** — Brief inline explanations, not paragraphs
5. **Personal and contextual** — "You usually allow this" / "This is new for this tool"
6. **Never condescending** — Assumes intelligence, never uses "simply" or "as you probably know"

**Grammar**: First person ("I"). Present tense. Short sentences (max 2 clauses). Contractions yes. Digits for numbers. No jargon without explanation. No emoji in security messages.

Full details: [voice-guide.md](voice-guide.md)

---

## 3. Threat Levels

| Internal Score | Label | Color | Icon | Notification |
|---|---|---|---|---|
| >= 0.9 | **Dangerous** | Red | ShieldX | Prompt + sound |
| 0.7 -- 0.9 | **Suspicious** | Orange | AlertTriangle | Prompt |
| 0.4 -- 0.7 | **Unusual** | Amber | Eye | Banner |
| < 0.4 | **Normal** | Green | ShieldCheck | In-feed only |
| Kill chain | **Dangerous** | Red | Link | Prompt + sound |
| Auto-blocked | **Blocked** | Red | Ban | Toast |
| IoC match | **Dangerous** | Red | Skull | Prompt + sound |

**Cardinal rule**: The user never sees anomaly score numbers, dimension names, kill chain IDs, or policy syntax.

Full details: [threat-communication.md](threat-communication.md)

---

## 4. Terminology Standards

These terms are standardized across all user-facing copy:

| Term | Usage | Never say |
|---|---|---|
| AI tools | What the user interacts with (Cursor, Claude Desktop) | "MCP servers", "MCP clients" (user-facing) |
| servers | The MCP server component (in context) | "agents" (except guard context) |
| blocked | Claw took final action, call did not go through | "denied" |
| paused | Claw intercepted, waiting for user decision | "stopped" |
| monitoring | Active state: "I'm monitoring 3 servers" | -- |
| protected | Outcome state: "3 servers protected" | -- |
| protection score | Always lowercase unless start of sentence | "Protection Score" |

Full glossary: [glossary.md](glossary.md)

---

## 5. Visual Identity (Abridged)

**Colors**: CSS custom properties in `src/styles/tokens.css`, extended into Tailwind via `tailwind.config.js`.
- Base: calm whites/grays (light), dark surfaces (dark mode)
- Status: Green (safe), Red (dangerous), Amber (warning), Blue (info)
- Accent: Rookbot brand color for interactive elements

**Typography**: System font (San Francisco). Scale from text-xs to text-4xl. Regular/medium/semibold only.

**Animation**: Subtle, controlled. 150-200ms transitions. Skeleton screens for loading. No bouncing, shaking, or flashing.

**Components**: Buttons (4 variants), badges/pills (6 status types), toggles, cards (4 types), progress indicators, empty states.

Full details: [visual-identity.md](visual-identity.md)

---

## 6. Implementation Files

| File | Purpose |
|---|---|
| `src/styles/tokens.css` | CSS custom properties for all design tokens |
| `tailwind.config.js` | Tailwind theme extending tokens into utility classes |
| `src/constants/messages.ts` | All user-facing strings as typed constants |
| `src/utils/threatLevel.ts` | Score-to-level mapping, color/icon/priority utilities |

**Two rules for developers**:
1. Never hardcode a user-facing string. Always use a constant from `messages.ts`.
2. Never hardcode a status color. Always use the threat level utility.

Full details: [developer-guide.md](developer-guide.md)

---

## 7. Sign-off

- [x] Character Brief — Agent 1 (Creative Director)
- [x] Voice & Tone Guide — Agent 2 (Voice Writer)
- [x] Threat Communication Framework — Agent 3 (Security Writer)
- [x] Visual Identity System — Agent 4 (Visual Design Lead)
- [x] Onboarding Copy — Agent 5 (UX Writer: Onboarding)
- [x] Runtime Messages — Agent 6 (UX Writer: Runtime)
- [x] Consistency Review — Agent 7 (QA Reviewer) — 7 MUST FIX items found and resolved
- [x] Implementation Bridge — Agent 8 (Engineer) — Build passes
- [x] MUST FIX items resolved — All 7 issues from consistency review addressed
- [x] Final Design System Document — Compiled
