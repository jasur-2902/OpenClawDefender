use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::state::{AuditEvent, ServerProfileSummary};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyDigest {
    pub period_start: String,
    pub period_end: String,
    pub summary_text: String,
    pub stats: DigestStats,
    pub highlights: Vec<DigestHighlight>,
    pub recommendations: Vec<super::recommendations::Recommendation>,
    pub protection_score_trend: ScoreTrend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestStats {
    pub total_events: u64,
    pub events_by_category: HashMap<String, u64>,
    pub threats_blocked: u32,
    pub threats_by_severity: HashMap<String, u32>,
    pub most_active_tools: Vec<ToolActivity>,
    pub servers_monitored: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolActivity {
    pub server_name: String,
    pub display_name: String,
    pub event_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestHighlight {
    pub highlight_type: String,
    pub title: String,
    pub description: String,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreTrend {
    pub start_score: u32,
    pub end_score: u32,
    pub direction: String,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate a weekly digest from the given events and profiles.
pub fn generate_weekly_digest(
    events: &[AuditEvent],
    profiles: &[ServerProfileSummary],
) -> WeeklyDigest {
    let now = Utc::now();
    let week_ago = now - Duration::days(7);

    let period_start = week_ago.to_rfc3339();
    let period_end = now.to_rfc3339();

    // Filter events to the last 7 days.
    let week_events: Vec<&AuditEvent> = events
        .iter()
        .filter(|e| {
            e.timestamp
                .parse::<DateTime<Utc>>()
                .map(|ts| ts >= week_ago)
                .unwrap_or(false)
        })
        .collect();

    let stats = compute_stats(&week_events, profiles);
    let highlights = compute_highlights(&week_events);
    let protection_score_trend = compute_score_trend(&week_events, profiles);
    let recommendations =
        super::recommendations::generate_recommendations(events, profiles);

    let summary_text = build_summary_text(&stats, &highlights);

    WeeklyDigest {
        period_start,
        period_end,
        summary_text,
        stats,
        highlights,
        recommendations,
        protection_score_trend,
    }
}

// ---------------------------------------------------------------------------
// Stats computation
// ---------------------------------------------------------------------------

fn compute_stats(events: &[&AuditEvent], profiles: &[ServerProfileSummary]) -> DigestStats {
    let total_events = events.len() as u64;

    // Count by category.
    let mut events_by_category: HashMap<String, u64> = HashMap::new();
    for event in events {
        let category = categorize_event(event);
        *events_by_category.entry(category).or_insert(0) += 1;
    }

    // Count threats blocked.
    let blocked: Vec<&&AuditEvent> = events
        .iter()
        .filter(|e| e.decision == "blocked" || e.decision == "denied")
        .collect();

    let threats_blocked = blocked.len() as u32;

    let mut threats_by_severity: HashMap<String, u32> = HashMap::new();
    for event in &blocked {
        *threats_by_severity
            .entry(event.risk_level.clone())
            .or_insert(0) += 1;
    }

    // Most active tools (top 3 by event count).
    let mut tool_counts: HashMap<String, u64> = HashMap::new();
    for event in events {
        *tool_counts
            .entry(event.server_name.clone())
            .or_insert(0) += 1;
    }

    let mut tool_vec: Vec<(String, u64)> = tool_counts.into_iter().collect();
    tool_vec.sort_by_key(|x| std::cmp::Reverse(x.1));

    let most_active_tools: Vec<ToolActivity> = tool_vec
        .into_iter()
        .take(3)
        .map(|(name, count)| ToolActivity {
            display_name: name.clone(),
            server_name: name,
            event_count: count,
        })
        .collect();

    let servers_monitored = profiles.len() as u32;

    DigestStats {
        total_events,
        events_by_category,
        threats_blocked,
        threats_by_severity,
        most_active_tools,
        servers_monitored,
    }
}

fn categorize_event(event: &AuditEvent) -> String {
    match event.action.as_str() {
        "read" | "read_file" | "list_directory" | "search_files" => "file_reads".to_string(),
        "write" | "write_file" | "create_directory" | "move_file" | "delete_file" => {
            "file_writes".to_string()
        }
        "execute_command" | "run_command" => "shell_executions".to_string(),
        "connect" | "fetch" | "http_request" => "network_connections".to_string(),
        _ => "other".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Highlights
// ---------------------------------------------------------------------------

fn compute_highlights(events: &[&AuditEvent]) -> Vec<DigestHighlight> {
    let mut highlights = Vec::new();

    // Find blocked threats (most notable by risk level).
    let mut blocked_events: Vec<&&AuditEvent> = events
        .iter()
        .filter(|e| e.decision == "blocked" || e.decision == "denied")
        .collect();

    blocked_events.sort_by_key(|x| std::cmp::Reverse(risk_score(&x.risk_level)));

    for event in blocked_events.iter().take(2) {
        highlights.push(DigestHighlight {
            highlight_type: "threat_blocked".to_string(),
            title: format!("Blocked {} activity from {}", event.risk_level, event.server_name),
            description: format!(
                "I stopped {} from performing a {} action. {}",
                event.server_name, event.action, event.details
            ),
            severity: Some(event.risk_level.clone()),
        });
    }

    // AI-flagged events: events whose details contain SLM analysis with high/critical risk.
    let ai_flagged: Vec<&&AuditEvent> = events
        .iter()
        .filter(|e| {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&e.details) {
                if let Some(slm) = parsed.get("slm_analysis") {
                    let risk = slm
                        .get("risk_level")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    return risk == "high" || risk == "critical";
                }
            }
            false
        })
        .collect();

    if !ai_flagged.is_empty() {
        let count = ai_flagged.len();
        let top_server = ai_flagged
            .first()
            .map(|e| e.server_name.as_str())
            .unwrap_or("unknown");
        highlights.push(DigestHighlight {
            highlight_type: "ai_flagged".to_string(),
            title: format!("My AI flagged {} event{} as high risk", count, if count == 1 { "" } else { "s" }),
            description: if count == 1 {
                format!(
                    "My on-device AI analysis flagged an action by {} as elevated risk. Review the Alerts page for details.",
                    top_server
                )
            } else {
                format!(
                    "My on-device AI analysis flagged {} actions as elevated risk, most from {}. Review the Alerts page for details.",
                    count, top_server
                )
            },
            severity: Some("high".to_string()),
        });
    }

    // Detect new tools (servers with very few events, likely just appeared).
    let mut server_first_seen: HashMap<&str, &str> = HashMap::new();
    for event in events {
        server_first_seen
            .entry(&event.server_name)
            .or_insert(&event.timestamp);
    }

    // Check for any milestones.
    let total = events.len();
    if total >= 1000 {
        highlights.push(DigestHighlight {
            highlight_type: "milestone".to_string(),
            title: format!("{} events this week", total),
            description: format!(
                "I monitored {} events this week. Your tools are active and I'm keeping watch.",
                total
            ),
            severity: None,
        });
    }

    highlights.truncate(4);
    highlights
}

fn risk_score(level: &str) -> u32 {
    match level {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Protection score trend
// ---------------------------------------------------------------------------

fn compute_score_trend(
    events: &[&AuditEvent],
    profiles: &[ServerProfileSummary],
) -> ScoreTrend {
    // Mock score based on wrapped server count and threat ratio.
    let base_score = (profiles.len() as u32).min(10) * 10;

    let total = events.len().max(1) as f64;
    let blocked = events
        .iter()
        .filter(|e| e.decision == "blocked" || e.decision == "denied")
        .count() as f64;

    let threat_ratio = blocked / total;

    // Start score: base minus a penalty if there were many threats early in the week.
    let start_score = base_score.saturating_sub((threat_ratio * 20.0) as u32);
    // End score: base score (assumes threats were handled).
    let end_score = base_score;

    let (direction, reason) = if end_score > start_score {
        (
            "up".to_string(),
            Some("Threats were addressed during the week.".to_string()),
        )
    } else if end_score < start_score {
        (
            "down".to_string(),
            Some("New threats emerged toward the end of the week.".to_string()),
        )
    } else {
        ("stable".to_string(), None)
    };

    ScoreTrend {
        start_score,
        end_score,
        direction,
        reason,
    }
}

// ---------------------------------------------------------------------------
// Summary text generation (Claw's voice)
// ---------------------------------------------------------------------------

fn build_summary_text(stats: &DigestStats, highlights: &[DigestHighlight]) -> String {
    let mut lines = Vec::new();

    lines.push("Here's your week in review.".to_string());

    lines.push(format!(
        "{} events monitored, {} blocked.",
        stats.total_events, stats.threats_blocked
    ));

    if let Some(top_threat) = highlights.iter().find(|h| h.highlight_type == "threat_blocked") {
        lines.push(format!("Most notable: {}", top_threat.description));
    } else if stats.threats_blocked == 0 {
        lines.push("It was a quiet week -- no threats needed blocking.".to_string());
    }

    if let Some(ai_highlight) = highlights.iter().find(|h| h.highlight_type == "ai_flagged") {
        lines.push(ai_highlight.title.clone());
    }

    if !stats.most_active_tools.is_empty() {
        let tool_names: Vec<&str> = stats
            .most_active_tools
            .iter()
            .map(|t| t.display_name.as_str())
            .collect();
        lines.push(format!(
            "Your most active tools were {}.",
            join_names(&tool_names)
        ));
    }

    lines.push("I'll keep watching. You're in good hands.".to_string());

    lines.join(" ")
}

fn join_names(names: &[&str]) -> String {
    match names.len() {
        0 => String::new(),
        1 => names[0].to_string(),
        2 => format!("{} and {}", names[0], names[1]),
        _ => {
            let (last, rest) = names.split_last().unwrap();
            format!("{}, and {}", rest.join(", "), last)
        }
    }
}
