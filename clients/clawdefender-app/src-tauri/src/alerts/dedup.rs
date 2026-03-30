use super::engine::{AlertType, IntelligentAlert};

/// Time window for anomaly dedup: 5 minutes.
const ANOMALY_DEDUP_WINDOW_SECS: i64 = 300;
/// Time window for block dedup: 1 hour.
const BLOCK_DEDUP_WINDOW_SECS: i64 = 3600;

/// Generate a deduplication key for an alert.
///
/// Rules:
/// - Anomaly: `anomaly:{server}:{action_prefix}`
/// - Block: `block:{server}:{action_prefix}`
/// - KillChain: unique per detection (never deduped)
/// - ThreatIntel (IoC): unique per detection (never deduped)
/// - Others: `{type}:{server}:{action_prefix}`
pub fn dedup_key(server: &str, action: &str, alert_type: &AlertType) -> String {
    let action_prefix = truncate_action(action);
    match alert_type {
        AlertType::Anomaly => format!("anomaly:{}:{}", server, action_prefix),
        AlertType::Block => format!("block:{}:{}", server, action_prefix),
        AlertType::KillChain => {
            // Each kill chain is unique
            let now = chrono::Utc::now().timestamp_millis();
            format!("killchain:{}:{}:{}", server, action_prefix, now)
        }
        AlertType::ThreatIntel => {
            // Each IoC match is independently important
            let now = chrono::Utc::now().timestamp_millis();
            format!("ioc:{}:{}:{}", server, action_prefix, now)
        }
        AlertType::Correlation => format!("correlation:{}:{}", server, action_prefix),
        AlertType::Timeout => format!("timeout:{}:{}", server, action_prefix),
        AlertType::Discovery => format!("discovery:{}:{}", server, action_prefix),
        AlertType::Vulnerability => format!("vulnerability:{}:{}", server, action_prefix),
        AlertType::Analysis => format!("analysis:{}:{}", server, action_prefix),
    }
}

/// Check whether a new alert should be deduplicated into an existing alert.
///
/// Returns true if the alerts share a dedup_key and are within the dedup time window.
/// Kill chain and IoC alerts are NEVER deduplicated.
pub fn should_dedup(new_alert: &IntelligentAlert, existing: &IntelligentAlert) -> bool {
    // Kill chain and IoC: never dedup
    if matches!(new_alert.alert_type, AlertType::KillChain | AlertType::ThreatIntel) {
        return false;
    }
    if matches!(existing.alert_type, AlertType::KillChain | AlertType::ThreatIntel) {
        return false;
    }

    // Keys must match
    if new_alert.dedup_key != existing.dedup_key {
        return false;
    }

    // Check time window
    let window_secs = match new_alert.alert_type {
        AlertType::Anomaly => ANOMALY_DEDUP_WINDOW_SECS,
        AlertType::Block => BLOCK_DEDUP_WINDOW_SECS,
        _ => ANOMALY_DEDUP_WINDOW_SECS, // default 5 min for others
    };

    let existing_time = chrono::DateTime::parse_from_rfc3339(&existing.updated_at);
    let new_time = chrono::DateTime::parse_from_rfc3339(&new_alert.created_at);

    match (existing_time, new_time) {
        (Ok(e), Ok(n)) => {
            let diff = n.signed_duration_since(e).num_seconds().abs();
            diff <= window_secs
        }
        _ => false,
    }
}

/// Merge a new event into an existing alert (dedup merge).
pub fn merge_into_existing(existing: &mut IntelligentAlert, new_event_id: &str) {
    existing.dedup_count += 1;
    existing.updated_at = chrono::Utc::now().to_rfc3339();
    if !existing.source_events.contains(&new_event_id.to_string()) {
        existing.source_events.push(new_event_id.to_string());
    }
}

/// Truncate an action string to a short prefix for dedup key construction.
fn truncate_action(action: &str) -> String {
    let cleaned: String = action
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == ' ')
        .take(40)
        .collect();
    cleaned.to_lowercase().replace(' ', "_")
}
