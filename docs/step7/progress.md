# Step 7 Progress Tracker

**Step**: 7 -- Simplify Settings and Onboarding
**Started**: 2026-02-25

---

## Agent Status

| # | Agent | Role | Status | Notes |
|---|-------|------|--------|-------|
| 1 | Settings & Onboarding Architect | Specs: score, onboarding, guidance, settings | Complete | Produced 4 spec documents |
| 2 | Protection Score Backend | Rust score service with event-driven recalc | Pending | Depends on: protection-score-spec.md |
| 3 | Onboarding Flow | Rebuild 5-screen conversational experience | Pending | Depends on: onboarding-flow.md |
| 4 | Progressive Guidance Engine | First-week contextual teaching system | Pending | Depends on: onboarding-flow.md (guidance section) |
| 5 | Home Screen Score Integration | Backend score display with trends | Pending | Depends on: Agent 2 (score backend) |
| 6 | Settings Rebuild | Simple/advanced mode with score header | Pending | Depends on: settings-plan.md, Agent 2 |
| 7 | Sidebar Score & Global Integration | Tray icon, guidance rendering, routing | Pending | Depends on: Agents 2, 4 |
| 8 | QA | Full verification of onboarding, score, settings, guidance | Pending | Depends on: all above |
| 9 | Accessibility & Polish | ARIA, keyboard nav, animations, dark mode | Pending | Depends on: all above |

---

## Deliverables

### Spec Documents (Agent 1)

- [x] `docs/step7/protection-score-spec.md` -- 6-factor scoring system, backend architecture, event-driven recalc
- [x] `docs/step7/onboarding-flow.md` -- 5-screen flow, progressive guidance (9 milestones), component architecture
- [x] `docs/step7/settings-plan.md` -- Simple/advanced mode, shared components, backend changes
- [x] `docs/step7/progress.md` -- This file

### Implementation (Agents 2--7)

- [ ] `ProtectionScoreService` in Tauri backend
- [ ] `score_history` SQLite table
- [ ] `get_protection_score`, `get_score_history`, `recalculate_score` commands
- [ ] Event-driven recalculation with 2s debounce
- [ ] `clawdefender://score-changed` event emission
- [ ] 5 new onboarding screen components
- [ ] `ProtectionLevelChooser` shared component
- [ ] `check_fda_status` command
- [ ] Typing animation for Screen 1
- [ ] FDA polling for Screen 4
- [ ] Score ring on Screen 5
- [ ] Guidance milestone table in SQLite
- [ ] 9 milestone check functions
- [ ] Guidance overlay components
- [ ] Home page score from backend (remove client-side calc)
- [ ] Score trend display
- [ ] Settings Simple Mode
- [ ] Settings Advanced Mode
- [ ] `ScoreHeader` component
- [ ] `get_trust_level_summary` command
- [ ] Sidebar mini score widget
- [ ] Tray icon color from score
- [ ] Full QA pass
- [ ] ARIA labels and keyboard navigation
- [ ] Animation polish and dark mode verification

---

## Key Decisions

1. **Score is backend-owned** -- frontend never computes the score, only displays it.
2. **AI model download removed from onboarding** -- nudged at day 5 via guidance milestone instead.
3. **FDA screen is conditional** -- only shown if not already granted.
4. **Autostart enabled by default** on completion -- no checkbox on final screen.
5. **Theme moved to Advanced** -- "System" is the right default and rarely changed.
6. **Per-server settings removed from global Settings** -- they belong in My Tools.
7. **Score weights are customizable** in Advanced Mode but must sum to 100.
