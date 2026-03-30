use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::state::AuditEvent;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub event_rate_trend: String,
    pub threat_trend: String,
    pub most_changed_tool: Option<TrendItem>,
    pub milestones: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendItem {
    pub server_name: String,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// Analyze trends over the given number of days, comparing this period to the
/// previous period of the same length.
pub fn analyze_trends(events: &[AuditEvent], days: u32) -> TrendAnalysis {
    let now = Utc::now();
    let period = Duration::days(days as i64);
    let current_start = now - period;
    let previous_start = current_start - period;

    let mut current_events: Vec<&AuditEvent> = Vec::new();
    let mut previous_events: Vec<&AuditEvent> = Vec::new();

    for event in events {
        if let Ok(ts) = event.timestamp.parse::<DateTime<Utc>>() {
            if ts >= current_start {
                current_events.push(event);
            } else if ts >= previous_start {
                previous_events.push(event);
            }
        }
    }

    let event_rate_trend = compare_counts(current_events.len(), previous_events.len());

    let current_threats = current_events
        .iter()
        .filter(|e| e.decision == "blocked" || e.decision == "denied")
        .count();
    let previous_threats = previous_events
        .iter()
        .filter(|e| e.decision == "blocked" || e.decision == "denied")
        .count();
    let threat_trend = compare_counts(current_threats, previous_threats);

    let most_changed_tool = find_most_changed_tool(&current_events, &previous_events);
    let milestones = detect_milestones(events, days);

    TrendAnalysis {
        event_rate_trend,
        threat_trend,
        most_changed_tool,
        milestones,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn compare_counts(current: usize, previous: usize) -> String {
    if previous == 0 && current == 0 {
        return "stable".to_string();
    }
    if previous == 0 {
        return "up".to_string();
    }

    let ratio = current as f64 / previous as f64;
    if ratio >= 1.2 {
        "up".to_string()
    } else if ratio <= 0.8 {
        "down".to_string()
    } else {
        "stable".to_string()
    }
}

fn find_most_changed_tool<'a>(
    current: &[&'a AuditEvent],
    previous: &[&'a AuditEvent],
) -> Option<TrendItem> {
    let mut current_counts: HashMap<&str, usize> = HashMap::new();
    let mut previous_counts: HashMap<&str, usize> = HashMap::new();

    for event in current {
        *current_counts.entry(&event.server_name).or_insert(0) += 1;
    }
    for event in previous {
        *previous_counts.entry(&event.server_name).or_insert(0) += 1;
    }

    // Collect all server names.
    let mut all_servers: Vec<&str> = current_counts.keys().copied().collect();
    for server in previous_counts.keys() {
        if !all_servers.contains(server) {
            all_servers.push(server);
        }
    }

    let mut max_delta: i64 = 0;
    let mut best: Option<TrendItem> = None;

    for server in all_servers {
        let curr = *current_counts.get(server).unwrap_or(&0) as i64;
        let prev = *previous_counts.get(server).unwrap_or(&0) as i64;
        let delta = (curr - prev).abs();

        if delta > max_delta {
            max_delta = delta;

            let description = if prev == 0 && curr > 0 {
                format!("{} is new this period with {} events.", server, curr)
            } else if curr == 0 && prev > 0 {
                format!("{} went silent after {} events last period.", server, prev)
            } else if prev > 0 {
                let pct = ((curr - prev) as f64 / prev as f64 * 100.0).round();
                if pct >= 0.0 {
                    format!(
                        "{}'s activity increased {:.0}% this period.",
                        server, pct
                    )
                } else {
                    format!(
                        "{}'s activity decreased {:.0}% this period.",
                        server, pct.abs()
                    )
                }
            } else {
                format!("{} had a change of {} events.", server, delta)
            };

            best = Some(TrendItem {
                server_name: server.to_string(),
                description,
            });
        }
    }

    // Only report if the delta is meaningful.
    if max_delta >= 3 {
        best
    } else {
        None
    }
}

fn detect_milestones(events: &[AuditEvent], _days: u32) -> Vec<String> {
    let mut milestones = Vec::new();

    // Total event count milestones.
    let total = events.len();
    let thresholds = [100, 500, 1000, 5000, 10_000];
    for threshold in &thresholds {
        if total >= *threshold {
            milestones.push(format!("{} total events monitored.", threshold));
        }
    }
    // Keep only the highest milestone.
    if milestones.len() > 1 {
        milestones = vec![milestones.pop().unwrap()];
    }

    // Check how many unique servers have been seen.
    let unique_servers: std::collections::HashSet<&str> =
        events.iter().map(|e| e.server_name.as_str()).collect();
    if unique_servers.len() >= 5 {
        milestones.push(format!(
            "{} different tools monitored.",
            unique_servers.len()
        ));
    }

    milestones.truncate(3);
    milestones
}
