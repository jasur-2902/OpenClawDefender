# Protection Score Specification

**Version**: 1.0
**Step**: 7 -- Simplify Settings and Onboarding
**Status**: Authoritative

This document defines the single source of truth for protection score computation. The backend (Rust) owns the score. The frontend displays it but never computes it.

---

## Current State Audit

The existing score in `Home.tsx` (`calculateProtectionScore`) has these problems:

1. **Client-side only** -- computed in React, not persisted, not available to tray/daemon/CLI.
2. **7 factors totaling 100 but weights are ad hoc** -- servers (25), feed (15), SLM (15), daemon+FDA (20), events (10), behavioral (10), autostart (5). The daemon factor conflates "daemon running" with "FDA granted" and always grants full 20 if daemon is up.
3. **No history tracking** -- the score is ephemeral. Users cannot see trends.
4. **Polling-based** -- `fetchAllData` runs every 30s. Score lags behind real changes.
5. **No debounce** -- every poll recalculates even if nothing changed.
6. **Behavioral analysis weight is small** -- only 10 points, but it is a major security layer.

---

## New Scoring System

### 6 Factors, 100 Points Total

| # | Factor | Max | Computation | Rationale |
|---|--------|-----|-------------|-----------|
| 1 | Tool Coverage | 25 | `(wrapped / total) * 25`. If 0 tools detected, score is 25 (nothing to protect). | Wrapping is the foundation -- unwrapped servers are invisible. |
| 2 | Threat Intelligence | 20 | 20 if last update < 24h ago. Subtract 5 per day overdue. Floor at 0. | Stale threat data means missed known attacks. Higher weight than before. |
| 3 | AI Analysis | 15 | 15 if real local SLM loaded. 5 if cloud-only API. 0 if mock mode or none. | AI analysis is a force multiplier but not essential. |
| 4 | System Visibility | 15 | 15 if Full Disk Access granted. 5 if partial (daemon running but no FDA). 0 if daemon not running. | FDA enables auto-discovery. Daemon without FDA still gives some visibility. |
| 5 | Unresolved Alerts | 15 | 15 if 0 unresolved medium+ alerts. Subtract 3 per unresolved medium+ alert. Floor at 0. | Unresolved alerts represent known risks the user has not addressed. |
| 6 | Configuration Health | 10 | Sum of: autostart enabled (3) + protection level explicitly set (3) + at least one trust level customized (2) + behavioral profiles active (2). | A well-configured system demonstrates intentional security posture. |

**Total**: 25 + 20 + 15 + 15 + 15 + 10 = **100**

### Score Ranges and Labels

| Range | Color | Label | Claw says |
|-------|-------|-------|-----------|
| 90--100 | Green | Fully protected | "Everything is in place." |
| 70--89 | Green-light | Well protected | "Looking good. A few things could be tighter." |
| 50--69 | Amber | Could be stronger | "There are gaps worth addressing." |
| 30--49 | Orange | Needs attention | "Several protections are missing. I would fix these soon." |
| 0--29 | Red | Significant gaps | "Your protection has significant gaps. Let me help you fix them." |

### Factor Detail Messages

Each factor exposes:
- `key: string` -- unique identifier (e.g., `tool_coverage`)
- `label: string` -- human-readable name
- `points: u32` -- current points
- `max_points: u32` -- maximum points
- `status: "good" | "warn" | "bad"`
- `description: string` -- Claw-voice explanation of current state
- `fix_label: string | null` -- CTA text if improvable
- `fix_route: string | null` -- navigation target for CTA

---

## Backend Architecture

### Rust Service: `ProtectionScoreService`

Located in the Tauri app state (not in clawdefender-core, since it aggregates GUI-specific state).

```rust
pub struct ProtectionScoreService {
    current_score: Mutex<ScoreSnapshot>,
    history: Mutex<Vec<ScoreSnapshot>>,
    debounce_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

pub struct ScoreSnapshot {
    pub score: u32,
    pub factors: Vec<ScoreFactor>,
    pub computed_at: chrono::DateTime<chrono::Utc>,
}

pub struct ScoreFactor {
    pub key: String,
    pub label: String,
    pub points: u32,
    pub max_points: u32,
    pub status: FactorStatus, // Good, Warn, Bad
    pub description: String,
    pub fix_label: Option<String>,
    pub fix_route: Option<String>,
}
```

### Tauri Commands

```
get_protection_score() -> ScoreSnapshot
get_score_history(days: u32) -> Vec<ScoreSnapshot>
recalculate_score() -> ScoreSnapshot  // force recalc, mostly for testing
```

### Event-Driven Recalculation

The score recalculates in response to these events (not polling):

| Event | Source |
|-------|--------|
| Server wrapped/unwrapped | `wrap_server`, `unwrap_server` commands |
| Threat feed updated | `force_feed_update`, background feed check |
| SLM model loaded/unloaded | `activate_model`, `deactivate_model` |
| FDA status changed | System event or poll on app focus |
| Alert resolved/dismissed | `resolve_alert`, `dismiss_alert` |
| Settings changed | `update_settings`, `apply_template` |
| Daemon started/stopped | Connection monitor |
| Behavioral profile completed | Background learning event |

### Debounce

When an event triggers recalculation:
1. Cancel any pending debounce timer.
2. Start a new 2-second timer.
3. When the timer fires, compute the new score.
4. If the score changed, emit `clawdefender://score-changed` with the new `ScoreSnapshot`.
5. Append to history.

### History Storage

- Store score snapshots in SQLite (reuse the existing audit DB or a dedicated `scores` table).
- Schema: `CREATE TABLE score_history (id INTEGER PRIMARY KEY, score INTEGER NOT NULL, factors_json TEXT NOT NULL, computed_at TEXT NOT NULL)`.
- Retain 90 days of history by default (configurable via `event_retention_days`).
- `get_score_history(days)` returns one snapshot per hour (most recent per hour) to keep responses small.

---

## Frontend Integration

### Home Page

- Remove `calculateProtectionScore` from `Home.tsx`.
- Call `get_protection_score()` on mount.
- Listen to `clawdefender://score-changed` for live updates.
- Store score in `appStore` for sidebar/tray access.

### Score Breakdown Drawer

- Render `factors` from the backend `ScoreSnapshot`.
- Each factor card shows points/max, status color, description, and fix CTA.

### Sidebar Mini Score

- Read from `appStore.protectionScore`.
- Update reactively when `clawdefender://score-changed` fires.

### Tray Icon

- Green dot: score >= 70
- Amber dot: score 30--69
- Red dot: score < 30

---

## Migration Notes

- The old `calculateProtectionScore` in `Home.tsx` is deleted entirely.
- The `PROTECTION_SCORE_FACTORS` and `PROTECTION_SCORE_LEVELS` constants in `messages.ts` should be updated to match the new 6-factor system and 5-range labels.
- The `ScoreFactor` type in `components/home/ScoreBreakdown.tsx` must match the backend struct.
