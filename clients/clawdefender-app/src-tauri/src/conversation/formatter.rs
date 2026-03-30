//! Formatting utilities for Ask Claw response synthesis.
//!
//! Pure functions that turn raw data into human-readable strings
//! following Claw's voice guide: digits for numbers, plain language,
//! short sentences.

use chrono::{DateTime, Local, NaiveDateTime, Utc};

/// Format a timestamp as a human-readable relative time.
///
/// Examples: "3 minutes ago", "yesterday at 2:15 PM", "2 hours ago"
pub fn time_ago(timestamp: &str) -> String {
    let parsed = DateTime::parse_from_rfc3339(timestamp)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|| {
            NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S")
                .ok()
                .map(|ndt| ndt.and_utc())
        });

    let dt = match parsed {
        Some(dt) => dt,
        None => return timestamp.to_string(),
    };

    let now = Utc::now();
    let diff = now.signed_duration_since(dt);

    if diff.num_seconds() < 0 {
        return "just now".to_string();
    }

    if diff.num_seconds() < 60 {
        return "just now".to_string();
    }

    if diff.num_minutes() < 60 {
        let mins = diff.num_minutes();
        return count_format(mins as u64, "minute", "minutes") + " ago";
    }

    if diff.num_hours() < 24 {
        let hours = diff.num_hours();
        return count_format(hours as u64, "hour", "hours") + " ago";
    }

    let local_dt = dt.with_timezone(&Local);

    if diff.num_hours() < 48 {
        return format!("yesterday at {}", local_dt.format("%-I:%M %p"));
    }

    if diff.num_days() < 7 {
        return format!("{} days ago", diff.num_days());
    }

    format!("{}", local_dt.format("%b %-d at %-I:%M %p"))
}

/// Produce a one-line human-readable event summary from event JSON.
///
/// Expected fields: "server_name", "tool_name" or "description", "decision"
pub fn event_summary(event: &serde_json::Value) -> String {
    let server = event
        .get("server_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown server");

    let description = event
        .get("description")
        .and_then(|v| v.as_str())
        .or_else(|| event.get("tool_name").and_then(|v| v.as_str()))
        .unwrap_or("performed an action");

    let decision = event
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("logged");

    let timestamp = event
        .get("timestamp")
        .and_then(|v| v.as_str())
        .map(time_ago)
        .unwrap_or_default();

    let time_suffix = if timestamp.is_empty() {
        String::new()
    } else {
        format!(" ({})", timestamp)
    };

    format!("{} — {} — {}{}", server, description, decision, time_suffix)
}

/// Produce a one-line server summary.
///
/// Example: "Claude's filesystem-server — trusted, 2,847 actions"
pub fn server_summary(profile: &serde_json::Value) -> String {
    let name = profile
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown server");

    let status = profile
        .get("status")
        .or_else(|| profile.get("trust_level"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let events = profile
        .get("total_events")
        .or_else(|| profile.get("events_count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    format!(
        "{} — {}, {}",
        name,
        status,
        count_format(events, "action", "actions")
    )
}

/// Format a count with singular/plural noun.
///
/// Examples: "1 event", "47 events", "0 events"
pub fn count_format(n: u64, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {}", singular)
    } else {
        format!("{} {}", format_number(n), plural)
    }
}

/// Format a number with comma separators.
fn format_number(n: u64) -> String {
    if n < 1_000 {
        return n.to_string();
    }
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result
}

/// Return a label and description for a protection score.
///
/// Score ranges: 100 = Full, 80-99 = High, 50-79 = Medium, 0-49 = Low
pub fn protection_score_description(score: u32) -> (String, String) {
    match score {
        100 => (
            "Full".to_string(),
            "Fully protected. Every layer is active and up to date.".to_string(),
        ),
        80..=99 => (
            "High".to_string(),
            "Looking good. A few minor things could be tightened up.".to_string(),
        ),
        50..=79 => (
            "Medium".to_string(),
            "There are gaps in your protection. Worth addressing when you have a moment."
                .to_string(),
        ),
        _ => (
            "Low".to_string(),
            "Several protections are missing or inactive. I'd recommend fixing these soon."
                .to_string(),
        ),
    }
}

/// Format a byte count as a human-readable size.
///
/// Examples: "1.2 MB", "500 KB", "3.1 GB"
pub fn format_file_size(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = 1_024 * KB;
    const GB: u64 = 1_024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{} KB", bytes / KB)
    } else {
        count_format(bytes, "byte", "bytes")
    }
}

/// Format uptime from seconds into a readable string.
///
/// Examples: "3 hours, 12 minutes", "2 days, 5 hours"
pub fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;

    if days > 0 {
        format!(
            "{}, {}",
            count_format(days, "day", "days"),
            count_format(hours, "hour", "hours")
        )
    } else if hours > 0 {
        format!(
            "{}, {}",
            count_format(hours, "hour", "hours"),
            count_format(minutes, "minute", "minutes")
        )
    } else if minutes > 0 {
        count_format(minutes, "minute", "minutes")
    } else {
        "less than a minute".to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_format_singular() {
        assert_eq!(count_format(1, "event", "events"), "1 event");
    }

    #[test]
    fn test_count_format_plural() {
        assert_eq!(count_format(47, "event", "events"), "47 events");
    }

    #[test]
    fn test_count_format_zero() {
        assert_eq!(count_format(0, "event", "events"), "0 events");
    }

    #[test]
    fn test_count_format_large_number() {
        assert_eq!(count_format(2_847, "action", "actions"), "2,847 actions");
    }

    #[test]
    fn test_protection_score_full() {
        let (label, _desc) = protection_score_description(100);
        assert_eq!(label, "Full");
    }

    #[test]
    fn test_protection_score_high() {
        let (label, _desc) = protection_score_description(85);
        assert_eq!(label, "High");
    }

    #[test]
    fn test_protection_score_medium() {
        let (label, _desc) = protection_score_description(60);
        assert_eq!(label, "Medium");
    }

    #[test]
    fn test_protection_score_low() {
        let (label, _desc) = protection_score_description(30);
        assert_eq!(label, "Low");
    }

    #[test]
    fn test_format_file_size_bytes() {
        assert_eq!(format_file_size(500), "500 bytes");
    }

    #[test]
    fn test_format_file_size_kb() {
        assert_eq!(format_file_size(512_000), "500 KB");
    }

    #[test]
    fn test_format_file_size_mb() {
        assert_eq!(format_file_size(1_258_291), "1.2 MB");
    }

    #[test]
    fn test_format_file_size_gb() {
        assert_eq!(format_file_size(3_328_599_654), "3.1 GB");
    }

    #[test]
    fn test_format_uptime_minutes() {
        assert_eq!(format_uptime(300), "5 minutes");
    }

    #[test]
    fn test_format_uptime_hours_and_minutes() {
        assert_eq!(format_uptime(11_520), "3 hours, 12 minutes");
    }

    #[test]
    fn test_format_uptime_days() {
        assert_eq!(format_uptime(190_800), "2 days, 5 hours");
    }

    #[test]
    fn test_format_uptime_less_than_minute() {
        assert_eq!(format_uptime(30), "less than a minute");
    }

    #[test]
    fn test_time_ago_recent() {
        let now = Utc::now();
        let ts = now.to_rfc3339();
        assert_eq!(time_ago(&ts), "just now");
    }

    #[test]
    fn test_time_ago_minutes() {
        let ts = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        assert_eq!(time_ago(&ts), "5 minutes ago");
    }

    #[test]
    fn test_time_ago_hours() {
        let ts = (Utc::now() - chrono::Duration::hours(3)).to_rfc3339();
        assert_eq!(time_ago(&ts), "3 hours ago");
    }

    #[test]
    fn test_time_ago_invalid_returns_original() {
        assert_eq!(time_ago("not-a-timestamp"), "not-a-timestamp");
    }

    #[test]
    fn test_event_summary_basic() {
        let event = serde_json::json!({
            "server_name": "claude-server",
            "description": "tried to read SSH keys",
            "decision": "blocked"
        });
        let summary = event_summary(&event);
        assert!(summary.contains("claude-server"));
        assert!(summary.contains("tried to read SSH keys"));
        assert!(summary.contains("blocked"));
    }

    #[test]
    fn test_server_summary_basic() {
        let profile = serde_json::json!({
            "name": "filesystem-server",
            "status": "trusted",
            "total_events": 2847
        });
        let summary = server_summary(&profile);
        assert!(summary.contains("filesystem-server"));
        assert!(summary.contains("trusted"));
        assert!(summary.contains("2,847 actions"));
    }

    #[test]
    fn test_format_number_comma_separators() {
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1_000), "1,000");
        assert_eq!(format_number(1_000_000), "1,000,000");
    }
}
