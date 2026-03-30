use super::dedup::{merge_into_existing, should_dedup};
use super::engine::{AlertStatus, AlertType, IntelligentAlert};

/// Alert statistics for the frontend dashboard.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertStats {
    pub total_active: u32,
    pub dangerous_count: u32,
    pub suspicious_count: u32,
    pub unusual_count: u32,
    pub info_count: u32,
    pub resolved_this_week: u32,
    pub blocked_this_week: u32,
    pub avg_resolution_minutes: f64,
}

// ---------------------------------------------------------------------------
// Lifecycle operations on an in-memory Vec<IntelligentAlert>
// ---------------------------------------------------------------------------

/// Add an alert to the store, applying deduplication first.
/// Returns true if a new alert was added, false if it was merged into an existing one.
pub fn add_alert(store: &mut Vec<IntelligentAlert>, alert: IntelligentAlert) -> bool {
    // Try to find an existing alert to dedup into
    for existing in store.iter_mut() {
        if existing.status == AlertStatus::Active && should_dedup(&alert, existing) {
            // Merge into existing
            let new_event_ids = alert.source_events.clone();
            for eid in &new_event_ids {
                merge_into_existing(existing, eid);
            }
            return false;
        }
    }
    // No dedup match — add as new
    store.push(alert);
    true
}

/// Mark an alert as Dismissed.
pub fn dismiss_alert(store: &mut Vec<IntelligentAlert>, alert_id: &str) -> bool {
    if let Some(alert) = store.iter_mut().find(|a| a.id == alert_id) {
        alert.status = AlertStatus::Dismissed;
        alert.updated_at = chrono::Utc::now().to_rfc3339();
        alert.resolved_at = Some(chrono::Utc::now().to_rfc3339());
        alert.resolved_by = Some("user".to_string());
        true
    } else {
        false
    }
}

/// Mark an alert as Resolved with a resolution reason.
pub fn resolve_alert(store: &mut Vec<IntelligentAlert>, alert_id: &str, resolution: &str) -> bool {
    if let Some(alert) = store.iter_mut().find(|a| a.id == alert_id) {
        alert.status = AlertStatus::Resolved;
        alert.updated_at = chrono::Utc::now().to_rfc3339();
        alert.resolved_at = Some(chrono::Utc::now().to_rfc3339());
        alert.resolved_by = Some(resolution.to_string());
        true
    } else {
        false
    }
}

/// Bulk dismiss all active alerts up to (and including) a given severity level.
/// Severity ordering: info < unusual < suspicious < dangerous.
/// Returns the number of alerts dismissed.
pub fn dismiss_all(store: &mut Vec<IntelligentAlert>, max_severity: Option<&str>) -> u32 {
    let max_level = severity_rank(max_severity.unwrap_or("dangerous"));
    let now = chrono::Utc::now().to_rfc3339();
    let mut count = 0u32;

    for alert in store.iter_mut() {
        if alert.status == AlertStatus::Active && severity_rank(&alert.severity) <= max_level {
            alert.status = AlertStatus::Dismissed;
            alert.updated_at = now.clone();
            alert.resolved_at = Some(now.clone());
            alert.resolved_by = Some("user".to_string());
            count += 1;
        }
    }
    count
}

/// Auto-expire alerts that have exceeded their lifetime.
///
/// Rules from architecture:
/// - Block alerts: auto-expire after 24 hours
/// - Correlation alerts: auto-expire after 48 hours
/// - Timeout alerts: auto-expire after 4 hours
/// - Discovery alerts: auto-expire after 7 days
/// - Others: don't auto-expire
pub fn auto_expire_alerts(store: &mut Vec<IntelligentAlert>) -> u32 {
    let now = chrono::Utc::now();
    let mut count = 0u32;

    for alert in store.iter_mut() {
        if alert.status != AlertStatus::Active {
            continue;
        }

        let max_age_hours = match alert.alert_type {
            AlertType::Block => Some(24),
            AlertType::Correlation => Some(48),
            AlertType::Timeout => Some(4),
            AlertType::Discovery => Some(168), // 7 days
            _ => None,
        };

        if let Some(max_hours) = max_age_hours {
            if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&alert.created_at) {
                let age_hours = now.signed_duration_since(created).num_hours();
                if age_hours >= max_hours {
                    alert.status = AlertStatus::AutoExpired;
                    alert.updated_at = now.to_rfc3339();
                    alert.resolved_at = Some(now.to_rfc3339());
                    alert.resolved_by = Some("auto_expiry".to_string());
                    count += 1;
                }
            }
        }
    }
    count
}

/// Get all active alerts, sorted by severity (dangerous first) then by recency.
pub fn get_active_alerts(store: &[IntelligentAlert]) -> Vec<IntelligentAlert> {
    let mut active: Vec<IntelligentAlert> = store
        .iter()
        .filter(|a| a.status == AlertStatus::Active)
        .cloned()
        .collect();

    active.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| b.created_at.cmp(&a.created_at))
    });

    active
}

/// Get alert history (resolved, dismissed, auto-expired) within the last N days.
pub fn get_alert_history(store: &[IntelligentAlert], days: u32) -> Vec<IntelligentAlert> {
    let now = chrono::Utc::now();

    let mut history: Vec<IntelligentAlert> = store
        .iter()
        .filter(|a| {
            matches!(
                a.status,
                AlertStatus::Resolved | AlertStatus::Dismissed | AlertStatus::AutoExpired
            ) && chrono::DateTime::parse_from_rfc3339(&a.created_at)
                .map(|t| now.signed_duration_since(t).num_days() <= days as i64)
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    history.sort_by(|a, b| b.resolved_at.cmp(&a.resolved_at));
    history
}

/// Compute alert statistics.
pub fn get_alert_stats(store: &[IntelligentAlert]) -> AlertStats {
    let active: Vec<&IntelligentAlert> = store
        .iter()
        .filter(|a| a.status == AlertStatus::Active)
        .collect();

    let now = chrono::Utc::now();

    let resolved_this_week = store
        .iter()
        .filter(|a| {
            a.status == AlertStatus::Resolved
                && a.resolved_at
                    .as_ref()
                    .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                    .map(|t| now.signed_duration_since(t).num_days() <= 7)
                    .unwrap_or(false)
        })
        .count() as u32;

    let blocked_this_week = store
        .iter()
        .filter(|a| {
            a.alert_type == AlertType::Block
                && chrono::DateTime::parse_from_rfc3339(&a.created_at)
                    .map(|t| now.signed_duration_since(t).num_days() <= 7)
                    .unwrap_or(false)
        })
        .count() as u32;

    // Average resolution time for resolved alerts this week
    let resolution_times: Vec<f64> = store
        .iter()
        .filter(|a| a.status == AlertStatus::Resolved)
        .filter_map(|a| {
            let created = chrono::DateTime::parse_from_rfc3339(&a.created_at).ok()?;
            let resolved = chrono::DateTime::parse_from_rfc3339(a.resolved_at.as_ref()?).ok()?;
            Some((resolved - created).num_minutes() as f64)
        })
        .collect();

    let avg_resolution_minutes = if resolution_times.is_empty() {
        0.0
    } else {
        resolution_times.iter().sum::<f64>() / resolution_times.len() as f64
    };

    AlertStats {
        total_active: active.len() as u32,
        dangerous_count: active.iter().filter(|a| a.severity == "dangerous").count() as u32,
        suspicious_count: active.iter().filter(|a| a.severity == "suspicious").count() as u32,
        unusual_count: active.iter().filter(|a| a.severity == "unusual").count() as u32,
        info_count: active.iter().filter(|a| a.severity == "info").count() as u32,
        resolved_this_week,
        blocked_this_week,
        avg_resolution_minutes,
    }
}

/// Map severity to a numeric rank for sorting.
fn severity_rank(severity: &str) -> u32 {
    match severity {
        "dangerous" => 4,
        "suspicious" => 3,
        "unusual" => 2,
        "info" => 1,
        _ => 0,
    }
}
