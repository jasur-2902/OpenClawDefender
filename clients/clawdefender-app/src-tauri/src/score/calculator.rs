use serde::{Deserialize, Serialize};

use crate::state::AppState;
use super::factors;
use super::history;

/// The top-level protection score returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionScore {
    /// Overall score 0-100.
    pub total: u32,
    /// Human-readable label, e.g. "You're fully protected".
    pub label: String,
    /// Color key for the UI ring: "green", "green-light", "amber", "orange", "red".
    pub color: String,
    /// Individual factor breakdowns.
    pub factors: Vec<ScoreFactor>,
    /// ISO 8601 timestamp of computation.
    pub computed_at: String,
    /// Change from the previous score snapshot (+5, -10, etc.).
    pub change_from_last: Option<i32>,
}

/// One of the 6 scoring factors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreFactor {
    pub id: String,
    pub name: String,
    pub description: String,
    pub max_points: u32,
    pub current_points: u32,
    /// "full", "partial", or "empty".
    pub status: String,
    pub fix_actions: Vec<FixAction>,
    pub details: String,
}

/// An actionable fix the user can take to improve a factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixAction {
    pub label: String,
    /// "navigate", "command", or "external".
    pub action_type: String,
    /// Route path, CLI command, or URL depending on action_type.
    pub target: String,
    pub params: Option<serde_json::Value>,
}

/// A persisted score snapshot for history tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreSnapshot {
    pub id: i64,
    pub score: u32,
    pub factors_json: String,
    pub computed_at: String,
}

/// Compute the protection score from current app state.
///
/// This is the single source of truth. The frontend never computes the score.
pub fn compute_score(state: &AppState) -> ProtectionScore {
    let now = chrono::Utc::now().to_rfc3339();

    let tool_coverage = factors::compute_tool_coverage();
    let threat_intel = factors::compute_threat_intel();
    let ai_analysis = factors::compute_ai_analysis(state);
    let system_visibility = factors::compute_system_visibility(state);
    let unresolved_alerts = factors::compute_unresolved_alerts(state);
    let config_health = factors::compute_config_health();

    let all_factors = vec![
        tool_coverage,
        threat_intel,
        ai_analysis,
        system_visibility,
        unresolved_alerts,
        config_health,
    ];

    let total: u32 = all_factors.iter().map(|f| f.current_points).sum();

    let (label, color) = score_label_color(total);

    // Determine change from last snapshot
    let change_from_last = history::get_last_score().map(|last| total as i32 - last as i32);

    ProtectionScore {
        total,
        label: label.to_string(),
        color: color.to_string(),
        factors: all_factors,
        computed_at: now,
        change_from_last,
    }
}

/// Map a total score to its label and color.
pub fn score_label_color(total: u32) -> (&'static str, &'static str) {
    match total {
        90..=100 => ("Fully protected", "green"),
        70..=89 => ("Well protected", "green-light"),
        50..=69 => ("Could be stronger", "amber"),
        30..=49 => ("Needs attention", "orange"),
        _ => ("Significant gaps", "red"),
    }
}
