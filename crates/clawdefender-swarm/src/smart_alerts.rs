use anyhow::Result;
use chrono::{DateTime, Duration, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ==================== Alert Group ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertGroup {
    pub id: Uuid,
    pub primary_alert_id: String,
    pub primary_summary: String,
    pub primary_severity: String,
    pub related_alert_ids: Vec<String>,
    pub count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub group_reason: GroupReason,
    pub narrative: String,
    pub escalating: bool,
    pub status: GroupStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GroupReason {
    SameServerAction,
    KillChainRelated,
    TimeCorrelated,
    PatternMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GroupStatus {
    Active,
    Acknowledged,
    Resolved,
    Dismissed,
}

// ==================== Alert Enrichment ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEnrichment {
    pub alert_id: String,
    pub levels: Vec<EnrichmentLevel>,
    pub final_severity: String,
    pub enriched_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentLevel {
    pub level: IntelligenceLevel,
    pub summary: String,
    pub details: String,
    pub generated_at: DateTime<Utc>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceLevel {
    RuleBased,
    SlmEnriched,
    CloudEnriched,
}

// ==================== Alert Fatigue ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertFatigueManager {
    dismissal_counts: HashMap<String, DismissalRecord>,
    alert_rate: AlertRate,
    quiet_hours: Option<QuietHours>,
    digest_mode: bool,
    digest_buffer: Vec<DigestEntry>,
    suggestions: Vec<FatigueSuggestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DismissalRecord {
    pub pattern: String,
    pub count: u32,
    pub first_dismissed: DateTime<Utc>,
    pub last_dismissed: DateTime<Utc>,
    pub suggested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRate {
    pub hourly_counts: Vec<(DateTime<Utc>, u32)>,
    pub current_hour_count: u32,
    pub sustained_high: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuietHours {
    pub start: NaiveTime,
    pub end: NaiveTime,
    pub only_critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestEntry {
    pub alert_summary: String,
    pub severity: String,
    pub timestamp: DateTime<Utc>,
    pub group_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatigueSuggestion {
    pub pattern: String,
    pub dismiss_count: u32,
    pub suggestion_type: SuggestionType,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionType {
    CreateAllowRule,
    InvestigatePattern,
    MuteTemporarily,
}

// ==================== Alert Lifecycle ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertLifecycleTracker {
    lifecycles: HashMap<String, AlertLifecycle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertLifecycle {
    pub alert_id: String,
    pub current_status: LifecycleStatus,
    pub history: Vec<StatusChange>,
    pub created_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution: Option<AlertResolution>,
    pub reminder_sent: bool,
    pub recurrence_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatus {
    New,
    Acknowledged,
    Investigating,
    Resolved,
    Dismissed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusChange {
    pub from: LifecycleStatus,
    pub to: LifecycleStatus,
    pub timestamp: DateTime<Utc>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertResolution {
    PolicyChange { rule_id: String },
    FalsePositive { reason: String },
    RemediationApplied { action: String },
    Dismissed { reason: String },
}

// ==================== Supporting Types ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutedPattern {
    pub pattern: String,
    pub muted_until: DateTime<Utc>,
    pub remaining_minutes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleAlertReminder {
    pub alert_id: String,
    pub acknowledged_at: DateTime<Utc>,
    pub hours_stale: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatigueStats {
    pub current_hour_rate: u32,
    pub digest_mode_active: bool,
    pub muted_pattern_count: usize,
    pub pending_suggestions: usize,
    pub dismissal_patterns: Vec<(String, u32)>,
}

// ==================== Smart Alert Engine ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartAlertEngine {
    groups: Vec<AlertGroup>,
    enrichments: HashMap<String, AlertEnrichment>,
    fatigue: AlertFatigueManager,
    lifecycle: AlertLifecycleTracker,
    grouping_window: Duration,
    muted_patterns: HashMap<String, DateTime<Utc>>,
}

impl Default for SmartAlertEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SmartAlertEngine {
    pub fn new() -> Self {
        Self {
            groups: Vec::new(),
            enrichments: HashMap::new(),
            fatigue: AlertFatigueManager {
                dismissal_counts: HashMap::new(),
                alert_rate: AlertRate {
                    hourly_counts: Vec::new(),
                    current_hour_count: 0,
                    sustained_high: false,
                },
                quiet_hours: None,
                digest_mode: false,
                digest_buffer: Vec::new(),
                suggestions: Vec::new(),
            },
            lifecycle: AlertLifecycleTracker {
                lifecycles: HashMap::new(),
            },
            grouping_window: Duration::minutes(10),
            muted_patterns: HashMap::new(),
        }
    }

    // ==================== Alert Enrichment ====================

    pub fn enrich_rule_based(
        &mut self,
        alert_id: &str,
        event_summary: &str,
        anomaly_score: f64,
        kill_chain: Option<&str>,
    ) -> EnrichmentLevel {
        let start = std::time::Instant::now();

        let summary = format!("Rule-based detection: {}", event_summary);
        let details = format!(
            "Anomaly score: {:.2}{}",
            anomaly_score,
            kill_chain.map_or(String::new(), |kc| format!(", Kill chain: {}", kc))
        );

        let level = EnrichmentLevel {
            level: IntelligenceLevel::RuleBased,
            summary,
            details,
            generated_at: Utc::now(),
            latency_ms: start.elapsed().as_millis() as u64,
        };

        let enrichment = self
            .enrichments
            .entry(alert_id.to_string())
            .or_insert_with(|| AlertEnrichment {
                alert_id: alert_id.to_string(),
                levels: Vec::new(),
                final_severity: "MEDIUM".to_string(),
                enriched_at: Utc::now(),
            });

        enrichment.levels.push(level.clone());
        enrichment.enriched_at = Utc::now();

        debug!(
            "Rule-based enrichment for alert {} completed in {}ms",
            alert_id, level.latency_ms
        );

        level
    }

    pub fn enrich_slm(&mut self, alert_id: &str, slm_analysis: &str) -> EnrichmentLevel {
        let start = std::time::Instant::now();

        let level = EnrichmentLevel {
            level: IntelligenceLevel::SlmEnriched,
            summary: "SLM-enriched analysis".to_string(),
            details: slm_analysis.to_string(),
            generated_at: Utc::now(),
            latency_ms: start.elapsed().as_millis() as u64,
        };

        if let Some(enrichment) = self.enrichments.get_mut(alert_id) {
            enrichment.levels.push(level.clone());
            enrichment.enriched_at = Utc::now();
        }

        debug!(
            "SLM enrichment for alert {} completed in {}ms",
            alert_id, level.latency_ms
        );

        level
    }

    pub fn enrich_cloud(&mut self, alert_id: &str, cloud_analysis: &str) -> EnrichmentLevel {
        let start = std::time::Instant::now();

        let level = EnrichmentLevel {
            level: IntelligenceLevel::CloudEnriched,
            summary: "Cloud AI deep analysis".to_string(),
            details: cloud_analysis.to_string(),
            generated_at: Utc::now(),
            latency_ms: start.elapsed().as_millis() as u64,
        };

        if let Some(enrichment) = self.enrichments.get_mut(alert_id) {
            enrichment.levels.push(level.clone());
            enrichment.enriched_at = Utc::now();
            enrichment.final_severity = "HIGH".to_string();
        }

        info!(
            "Cloud enrichment for alert {} completed in {}ms",
            alert_id, level.latency_ms
        );

        level
    }

    pub fn get_enrichment(&self, alert_id: &str) -> Option<&AlertEnrichment> {
        self.enrichments.get(alert_id)
    }

    pub fn should_escalate_to_cloud(&self, severity: &str, posture_level: &str) -> bool {
        match severity {
            "CRITICAL" => true,
            "HIGH" => true,
            "MEDIUM" => matches!(posture_level, "Elevated" | "High" | "Maximum"),
            _ => false,
        }
    }

    // ==================== Alert Grouping ====================

    pub fn try_group_alert(
        &mut self,
        alert_id: &str,
        server: &str,
        tool: &str,
        target: &str,
        severity: &str,
        timestamp: DateTime<Utc>,
    ) -> Option<Uuid> {
        let now = Utc::now();

        // Check for same server action grouping
        for group in &mut self.groups {
            if group.status != GroupStatus::Active {
                continue;
            }

            let time_diff = timestamp.signed_duration_since(group.last_seen);
            if time_diff > self.grouping_window {
                continue;
            }

            // Check if this matches the group pattern
            if group.group_reason == GroupReason::SameServerAction {
                // Extract pattern from narrative
                if group.narrative.contains(server)
                    && group.narrative.contains(tool)
                    && group.narrative.contains(target)
                {
                    let prev_count = group.count;
                    group.related_alert_ids.push(alert_id.to_string());
                    group.count += 1;
                    group.last_seen = timestamp;

                    // Check if escalating
                    if group.count > prev_count && (group.count as f64 / prev_count as f64) > 1.5 {
                        group.escalating = true;
                    }

                    // Update severity if higher
                    if severity_rank(severity) > severity_rank(&group.primary_severity) {
                        group.primary_severity = severity.to_string();
                        group.escalating = true;
                    }

                    group.narrative = format!(
                        "{} on {} targeting {} (count: {}, escalating: {})",
                        tool, server, target, group.count, group.escalating
                    );

                    debug!("Grouped alert {} into group {}", alert_id, group.id);
                    return Some(group.id);
                }
            }
        }

        // Create new group
        let group_id = Uuid::new_v4();
        let group = AlertGroup {
            id: group_id,
            primary_alert_id: alert_id.to_string(),
            primary_summary: format!("{} on {}", tool, server),
            primary_severity: severity.to_string(),
            related_alert_ids: vec![alert_id.to_string()],
            count: 1,
            first_seen: timestamp,
            last_seen: timestamp,
            group_reason: GroupReason::SameServerAction,
            narrative: format!("{} on {} targeting {}", tool, server, target),
            escalating: false,
            status: GroupStatus::Active,
        };

        self.groups.push(group);
        debug!("Created new alert group {}", group_id);
        Some(group_id)
    }

    pub fn get_groups(&self) -> &[AlertGroup] {
        &self.groups
    }

    pub fn get_group(&self, group_id: Uuid) -> Option<&AlertGroup> {
        self.groups.iter().find(|g| g.id == group_id)
    }

    pub fn get_active_groups(&self) -> Vec<&AlertGroup> {
        self.groups
            .iter()
            .filter(|g| g.status == GroupStatus::Active)
            .collect()
    }

    // ==================== Alert Fatigue ====================

    pub fn record_dismissal(&mut self, pattern: &str) {
        let now = Utc::now();

        let record = self
            .fatigue
            .dismissal_counts
            .entry(pattern.to_string())
            .or_insert_with(|| DismissalRecord {
                pattern: pattern.to_string(),
                count: 0,
                first_dismissed: now,
                last_dismissed: now,
                suggested: false,
            });

        record.count += 1;
        record.last_dismissed = now;

        debug!(
            "Recorded dismissal for pattern {}: count {}",
            pattern, record.count
        );

        // Generate suggestion on 5th dismissal
        if record.count >= 5 && !record.suggested {
            let suggestion = FatigueSuggestion {
                pattern: pattern.to_string(),
                dismiss_count: record.count,
                suggestion_type: SuggestionType::CreateAllowRule,
                description: format!(
                    "You've dismissed this pattern {} times. Create an allow rule?",
                    record.count
                ),
                created_at: now,
            };

            self.fatigue.suggestions.push(suggestion);
            record.suggested = true;

            info!("Generated fatigue suggestion for pattern {}", pattern);
        }
    }

    pub fn check_fatigue_suggestions(&mut self) -> Vec<FatigueSuggestion> {
        self.fatigue.suggestions.clone()
    }

    pub fn record_alert(&mut self) {
        let now = Utc::now();
        self.fatigue.alert_rate.current_hour_count += 1;

        // Update hourly counts
        self.fatigue
            .alert_rate
            .hourly_counts
            .push((now, self.fatigue.alert_rate.current_hour_count));

        // Keep only last 3 hours
        let three_hours_ago = now - Duration::hours(3);
        self.fatigue
            .alert_rate
            .hourly_counts
            .retain(|(t, _)| *t > three_hours_ago);

        // Check for sustained high rate
        let two_hours_ago = now - Duration::hours(2);
        let recent_high_hours = self
            .fatigue
            .alert_rate
            .hourly_counts
            .iter()
            .filter(|(t, count)| *t > two_hours_ago && *count > 10)
            .count();

        let was_sustained = self.fatigue.alert_rate.sustained_high;
        self.fatigue.alert_rate.sustained_high = recent_high_hours >= 2;

        // Activate digest mode if sustained high
        if self.fatigue.alert_rate.sustained_high && !self.fatigue.digest_mode {
            self.fatigue.digest_mode = true;
            info!("Activated digest mode due to sustained high alert rate");
        } else if !self.fatigue.alert_rate.sustained_high && self.fatigue.digest_mode {
            self.fatigue.digest_mode = false;
            info!("Deactivated digest mode as alert rate normalized");
        }

        // Reset hourly count at hour boundary
        if let Some((last_time, _)) = self.fatigue.alert_rate.hourly_counts.first() {
            if now.signed_duration_since(*last_time) > Duration::hours(1) {
                self.fatigue.alert_rate.current_hour_count = 1;
            }
        }
    }

    pub fn is_digest_mode(&self) -> bool {
        self.fatigue.digest_mode
    }

    pub fn should_suppress(&self, severity: &str) -> bool {
        self.should_suppress_at(severity, Utc::now().time())
    }

    fn should_suppress_at(&self, severity: &str, current_time: NaiveTime) -> bool {
        if let Some(ref quiet_hours) = self.fatigue.quiet_hours {
            let in_quiet_hours = if quiet_hours.start < quiet_hours.end {
                current_time >= quiet_hours.start && current_time < quiet_hours.end
            } else {
                current_time >= quiet_hours.start || current_time < quiet_hours.end
            };

            if in_quiet_hours && quiet_hours.only_critical {
                return severity != "CRITICAL";
            }
        }
        false
    }

    pub fn get_digest(&mut self) -> Vec<DigestEntry> {
        let digest = self.fatigue.digest_buffer.clone();
        self.fatigue.digest_buffer.clear();
        digest
    }

    pub fn set_quiet_hours(&mut self, start: NaiveTime, end: NaiveTime) {
        self.fatigue.quiet_hours = Some(QuietHours {
            start,
            end,
            only_critical: true,
        });
        info!("Set quiet hours: {:?} to {:?}", start, end);
    }

    pub fn clear_quiet_hours(&mut self) {
        self.fatigue.quiet_hours = None;
        info!("Cleared quiet hours");
    }

    // ==================== Muting ====================

    pub fn mute_pattern(&mut self, pattern: &str, duration: Duration) {
        let mute_until = Utc::now() + duration;
        self.muted_patterns.insert(pattern.to_string(), mute_until);
        info!("Muted pattern {} until {:?}", pattern, mute_until);
    }

    pub fn is_muted(&self, pattern: &str) -> bool {
        if let Some(&mute_until) = self.muted_patterns.get(pattern) {
            Utc::now() < mute_until
        } else {
            false
        }
    }

    pub fn get_muted_patterns(&self) -> Vec<MutedPattern> {
        let now = Utc::now();
        self.muted_patterns
            .iter()
            .filter_map(|(pattern, mute_until)| {
                if now < *mute_until {
                    let remaining = mute_until.signed_duration_since(now).num_minutes();
                    Some(MutedPattern {
                        pattern: pattern.clone(),
                        muted_until: *mute_until,
                        remaining_minutes: remaining,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn unmute_pattern(&mut self, pattern: &str) {
        self.muted_patterns.remove(pattern);
        info!("Unmuted pattern {}", pattern);
    }

    // ==================== Lifecycle ====================

    pub fn acknowledge_alert(&mut self, alert_id: &str) {
        let now = Utc::now();

        let lifecycle = self
            .lifecycle
            .lifecycles
            .entry(alert_id.to_string())
            .or_insert_with(|| AlertLifecycle {
                alert_id: alert_id.to_string(),
                current_status: LifecycleStatus::New,
                history: Vec::new(),
                created_at: now,
                acknowledged_at: None,
                resolved_at: None,
                resolution: None,
                reminder_sent: false,
                recurrence_count: 0,
            });

        let old_status = lifecycle.current_status;
        lifecycle.current_status = LifecycleStatus::Acknowledged;
        lifecycle.acknowledged_at = Some(now);
        lifecycle.history.push(StatusChange {
            from: old_status,
            to: LifecycleStatus::Acknowledged,
            timestamp: now,
            reason: None,
        });

        debug!("Acknowledged alert {}", alert_id);
    }

    pub fn start_investigating(&mut self, alert_id: &str) {
        let now = Utc::now();

        if let Some(lifecycle) = self.lifecycle.lifecycles.get_mut(alert_id) {
            let old_status = lifecycle.current_status;
            lifecycle.current_status = LifecycleStatus::Investigating;
            lifecycle.history.push(StatusChange {
                from: old_status,
                to: LifecycleStatus::Investigating,
                timestamp: now,
                reason: None,
            });

            debug!("Started investigating alert {}", alert_id);
        }
    }

    pub fn resolve_alert(&mut self, alert_id: &str, resolution: AlertResolution) {
        let now = Utc::now();

        if let Some(lifecycle) = self.lifecycle.lifecycles.get_mut(alert_id) {
            let old_status = lifecycle.current_status;
            lifecycle.current_status = LifecycleStatus::Resolved;
            lifecycle.resolved_at = Some(now);
            lifecycle.resolution = Some(resolution.clone());
            lifecycle.history.push(StatusChange {
                from: old_status,
                to: LifecycleStatus::Resolved,
                timestamp: now,
                reason: Some(format!("{:?}", resolution)),
            });

            info!("Resolved alert {}: {:?}", alert_id, resolution);
        }
    }

    pub fn dismiss_alert(&mut self, alert_id: &str, reason: &str) {
        let now = Utc::now();

        let lifecycle = self
            .lifecycle
            .lifecycles
            .entry(alert_id.to_string())
            .or_insert_with(|| AlertLifecycle {
                alert_id: alert_id.to_string(),
                current_status: LifecycleStatus::New,
                history: Vec::new(),
                created_at: now,
                acknowledged_at: None,
                resolved_at: None,
                resolution: None,
                reminder_sent: false,
                recurrence_count: 0,
            });

        let old_status = lifecycle.current_status;
        lifecycle.current_status = LifecycleStatus::Dismissed;
        lifecycle.resolved_at = Some(now);
        lifecycle.resolution = Some(AlertResolution::Dismissed {
            reason: reason.to_string(),
        });
        lifecycle.history.push(StatusChange {
            from: old_status,
            to: LifecycleStatus::Dismissed,
            timestamp: now,
            reason: Some(reason.to_string()),
        });

        debug!("Dismissed alert {}: {}", alert_id, reason);
    }

    pub fn get_lifecycle(&self, alert_id: &str) -> Option<&AlertLifecycle> {
        self.lifecycle.lifecycles.get(alert_id)
    }

    pub fn check_stale_alerts(&self) -> Vec<StaleAlertReminder> {
        let now = Utc::now();
        let stale_threshold = Duration::hours(24);

        self.lifecycle
            .lifecycles
            .values()
            .filter_map(|lc| {
                if lc.current_status == LifecycleStatus::Acknowledged && !lc.reminder_sent {
                    if let Some(ack_time) = lc.acknowledged_at {
                        let age = now.signed_duration_since(ack_time);
                        if age > stale_threshold {
                            let hours = age.num_hours() as u64;
                            return Some(StaleAlertReminder {
                                alert_id: lc.alert_id.clone(),
                                acknowledged_at: ack_time,
                                hours_stale: hours,
                                message: format!(
                                    "Alert {} acknowledged {} hours ago but not resolved",
                                    lc.alert_id, hours
                                ),
                            });
                        }
                    }
                }
                None
            })
            .collect()
    }

    pub fn check_recurrence(&self, alert_id: &str, pattern: &str) -> bool {
        if let Some(lifecycle) = self.lifecycle.lifecycles.get(alert_id) {
            lifecycle.current_status == LifecycleStatus::Dismissed && lifecycle.recurrence_count > 0
        } else {
            false
        }
    }

    // ==================== Stats ====================

    pub fn get_alert_fatigue_stats(&self) -> FatigueStats {
        FatigueStats {
            current_hour_rate: self.fatigue.alert_rate.current_hour_count,
            digest_mode_active: self.fatigue.digest_mode,
            muted_pattern_count: self.muted_patterns.len(),
            pending_suggestions: self.fatigue.suggestions.len(),
            dismissal_patterns: self
                .fatigue
                .dismissal_counts
                .iter()
                .map(|(pattern, record)| (pattern.clone(), record.count))
                .collect(),
        }
    }
}

// ==================== Helper Functions ====================

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_engine() {
        let engine = SmartAlertEngine::new();
        assert_eq!(engine.groups.len(), 0);
        assert_eq!(engine.enrichments.len(), 0);
    }

    #[test]
    fn test_rule_based_enrichment() {
        let mut engine = SmartAlertEngine::new();
        let level = engine.enrich_rule_based("alert1", "Suspicious activity", 0.85, Some("recon"));

        assert_eq!(level.level, IntelligenceLevel::RuleBased);
        assert!(level.summary.contains("Rule-based"));
        assert!(level.details.contains("0.85"));
        assert!(level.details.contains("recon"));

        let enrichment = engine.get_enrichment("alert1").unwrap();
        assert_eq!(enrichment.levels.len(), 1);
    }

    #[test]
    fn test_slm_enrichment() {
        let mut engine = SmartAlertEngine::new();
        engine.enrich_rule_based("alert1", "Test", 0.5, None);
        let level = engine.enrich_slm("alert1", "This is a detailed SLM analysis");

        assert_eq!(level.level, IntelligenceLevel::SlmEnriched);
        assert_eq!(level.details, "This is a detailed SLM analysis");

        let enrichment = engine.get_enrichment("alert1").unwrap();
        assert_eq!(enrichment.levels.len(), 2);
    }

    #[test]
    fn test_cloud_enrichment() {
        let mut engine = SmartAlertEngine::new();
        engine.enrich_rule_based("alert1", "Test", 0.5, None);
        let level = engine.enrich_cloud("alert1", "Deep cloud analysis result");

        assert_eq!(level.level, IntelligenceLevel::CloudEnriched);

        let enrichment = engine.get_enrichment("alert1").unwrap();
        assert_eq!(enrichment.final_severity, "HIGH");
    }

    #[test]
    fn test_should_escalate_to_cloud_critical() {
        let engine = SmartAlertEngine::new();
        assert!(engine.should_escalate_to_cloud("CRITICAL", "Normal"));
    }

    #[test]
    fn test_should_escalate_to_cloud_high() {
        let engine = SmartAlertEngine::new();
        assert!(engine.should_escalate_to_cloud("HIGH", "Normal"));
    }

    #[test]
    fn test_should_escalate_to_cloud_medium_elevated() {
        let engine = SmartAlertEngine::new();
        assert!(engine.should_escalate_to_cloud("MEDIUM", "Elevated"));
    }

    #[test]
    fn test_should_escalate_to_cloud_medium_normal() {
        let engine = SmartAlertEngine::new();
        assert!(!engine.should_escalate_to_cloud("MEDIUM", "Normal"));
    }

    #[test]
    fn test_should_escalate_to_cloud_low() {
        let engine = SmartAlertEngine::new();
        assert!(!engine.should_escalate_to_cloud("LOW", "Elevated"));
    }

    #[test]
    fn test_group_same_server_action() {
        let mut engine = SmartAlertEngine::new();
        let now = Utc::now();

        let group_id1 = engine
            .try_group_alert("alert1", "server1", "curl", "api.com", "MEDIUM", now)
            .unwrap();
        let group_id2 = engine
            .try_group_alert(
                "alert2",
                "server1",
                "curl",
                "api.com",
                "MEDIUM",
                now + Duration::minutes(5),
            )
            .unwrap();

        assert_eq!(group_id1, group_id2);
        let group = engine.get_group(group_id1).unwrap();
        assert_eq!(group.count, 2);
        assert_eq!(group.group_reason, GroupReason::SameServerAction);
    }

    #[test]
    fn test_group_outside_window() {
        let mut engine = SmartAlertEngine::new();
        let now = Utc::now();

        let group_id1 = engine
            .try_group_alert("alert1", "server1", "curl", "api.com", "MEDIUM", now)
            .unwrap();
        let group_id2 = engine
            .try_group_alert(
                "alert2",
                "server1",
                "curl",
                "api.com",
                "MEDIUM",
                now + Duration::minutes(15),
            )
            .unwrap();

        assert_ne!(group_id1, group_id2);
    }

    #[test]
    fn test_group_escalation_by_count() {
        let mut engine = SmartAlertEngine::new();
        let now = Utc::now();

        engine.try_group_alert("alert1", "server1", "curl", "api.com", "MEDIUM", now);
        engine.try_group_alert(
            "alert2",
            "server1",
            "curl",
            "api.com",
            "MEDIUM",
            now + Duration::minutes(1),
        );

        let group = &engine.groups[0];
        assert_eq!(group.count, 2);
    }

    #[test]
    fn test_group_escalation_by_severity() {
        let mut engine = SmartAlertEngine::new();
        let now = Utc::now();

        let group_id = engine
            .try_group_alert("alert1", "server1", "curl", "api.com", "LOW", now)
            .unwrap();
        engine.try_group_alert(
            "alert2",
            "server1",
            "curl",
            "api.com",
            "HIGH",
            now + Duration::minutes(1),
        );

        let group = engine.get_group(group_id).unwrap();
        assert_eq!(group.primary_severity, "HIGH");
        assert!(group.escalating);
    }

    #[test]
    fn test_get_active_groups() {
        let mut engine = SmartAlertEngine::new();
        let now = Utc::now();

        engine.try_group_alert("alert1", "server1", "curl", "api.com", "MEDIUM", now);
        engine.groups[0].status = GroupStatus::Resolved;

        let active = engine.get_active_groups();
        assert_eq!(active.len(), 0);

        engine.try_group_alert("alert2", "server2", "wget", "evil.com", "HIGH", now);
        let active = engine.get_active_groups();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_record_dismissal() {
        let mut engine = SmartAlertEngine::new();
        let pattern = "server1:curl:download";

        engine.record_dismissal(pattern);
        assert_eq!(
            engine.fatigue.dismissal_counts.get(pattern).unwrap().count,
            1
        );

        engine.record_dismissal(pattern);
        assert_eq!(
            engine.fatigue.dismissal_counts.get(pattern).unwrap().count,
            2
        );
    }

    #[test]
    fn test_dismissal_suggestion_at_threshold() {
        let mut engine = SmartAlertEngine::new();
        let pattern = "server1:curl:download";

        for _ in 0..4 {
            engine.record_dismissal(pattern);
        }
        assert_eq!(engine.fatigue.suggestions.len(), 0);

        engine.record_dismissal(pattern);
        assert_eq!(engine.fatigue.suggestions.len(), 1);
        assert_eq!(engine.fatigue.suggestions[0].dismiss_count, 5);
    }

    #[test]
    fn test_dismissal_suggestion_only_once() {
        let mut engine = SmartAlertEngine::new();
        let pattern = "server1:curl:download";

        for _ in 0..6 {
            engine.record_dismissal(pattern);
        }

        assert_eq!(engine.fatigue.suggestions.len(), 1);
    }

    #[test]
    fn test_record_alert_rate() {
        let mut engine = SmartAlertEngine::new();

        for _ in 0..5 {
            engine.record_alert();
        }

        assert_eq!(engine.fatigue.alert_rate.current_hour_count, 5);
    }

    #[test]
    fn test_digest_mode_activation() {
        let mut engine = SmartAlertEngine::new();

        // Simulate sustained high rate
        for _ in 0..15 {
            engine.record_alert();
        }

        engine.fatigue.alert_rate.sustained_high = true;
        engine.record_alert();

        assert!(engine.is_digest_mode());
    }

    #[test]
    fn test_digest_mode_deactivation() {
        let mut engine = SmartAlertEngine::new();
        engine.fatigue.digest_mode = true;
        engine.fatigue.alert_rate.sustained_high = false;

        engine.record_alert();

        assert!(!engine.is_digest_mode());
    }

    #[test]
    fn test_quiet_hours_suppress_medium() {
        let mut engine = SmartAlertEngine::new();
        engine.set_quiet_hours(
            NaiveTime::from_hms_opt(22, 0, 0).unwrap(),
            NaiveTime::from_hms_opt(8, 0, 0).unwrap(),
        );

        // Test at 23:00 (11 PM) - should be in quiet hours
        let test_time = NaiveTime::from_hms_opt(23, 0, 0).unwrap();
        assert!(engine.should_suppress_at("MEDIUM", test_time));
    }

    #[test]
    fn test_quiet_hours_allow_critical() {
        let mut engine = SmartAlertEngine::new();
        engine.set_quiet_hours(
            NaiveTime::from_hms_opt(22, 0, 0).unwrap(),
            NaiveTime::from_hms_opt(8, 0, 0).unwrap(),
        );

        // Test at 23:00 (11 PM) - should be in quiet hours
        let test_time = NaiveTime::from_hms_opt(23, 0, 0).unwrap();
        assert!(!engine.should_suppress_at("CRITICAL", test_time));
    }

    #[test]
    fn test_clear_quiet_hours() {
        let mut engine = SmartAlertEngine::new();
        engine.set_quiet_hours(
            NaiveTime::from_hms_opt(22, 0, 0).unwrap(),
            NaiveTime::from_hms_opt(8, 0, 0).unwrap(),
        );
        engine.clear_quiet_hours();

        assert!(!engine.should_suppress("MEDIUM"));
    }

    #[test]
    fn test_mute_pattern() {
        let mut engine = SmartAlertEngine::new();
        let pattern = "server1:curl:download";

        engine.mute_pattern(pattern, Duration::hours(1));
        assert!(engine.is_muted(pattern));
    }

    #[test]
    fn test_unmute_pattern() {
        let mut engine = SmartAlertEngine::new();
        let pattern = "server1:curl:download";

        engine.mute_pattern(pattern, Duration::hours(1));
        engine.unmute_pattern(pattern);
        assert!(!engine.is_muted(pattern));
    }

    #[test]
    fn test_get_muted_patterns() {
        let mut engine = SmartAlertEngine::new();

        engine.mute_pattern("pattern1", Duration::hours(1));
        engine.mute_pattern("pattern2", Duration::minutes(30));

        let muted = engine.get_muted_patterns();
        assert_eq!(muted.len(), 2);
    }

    #[test]
    fn test_expired_mute() {
        let mut engine = SmartAlertEngine::new();
        let pattern = "server1:curl:download";

        engine.mute_pattern(pattern, Duration::seconds(-1));
        assert!(!engine.is_muted(pattern));
    }

    #[test]
    fn test_acknowledge_alert() {
        let mut engine = SmartAlertEngine::new();

        engine.acknowledge_alert("alert1");

        let lifecycle = engine.get_lifecycle("alert1").unwrap();
        assert_eq!(lifecycle.current_status, LifecycleStatus::Acknowledged);
        assert!(lifecycle.acknowledged_at.is_some());
    }

    #[test]
    fn test_start_investigating() {
        let mut engine = SmartAlertEngine::new();

        engine.acknowledge_alert("alert1");
        engine.start_investigating("alert1");

        let lifecycle = engine.get_lifecycle("alert1").unwrap();
        assert_eq!(lifecycle.current_status, LifecycleStatus::Investigating);
    }

    #[test]
    fn test_resolve_alert() {
        let mut engine = SmartAlertEngine::new();

        engine.acknowledge_alert("alert1");
        engine.resolve_alert(
            "alert1",
            AlertResolution::PolicyChange {
                rule_id: "rule123".to_string(),
            },
        );

        let lifecycle = engine.get_lifecycle("alert1").unwrap();
        assert_eq!(lifecycle.current_status, LifecycleStatus::Resolved);
        assert!(lifecycle.resolved_at.is_some());
        assert!(lifecycle.resolution.is_some());
    }

    #[test]
    fn test_dismiss_alert() {
        let mut engine = SmartAlertEngine::new();

        engine.acknowledge_alert("alert1");
        engine.dismiss_alert("alert1", "False positive");

        let lifecycle = engine.get_lifecycle("alert1").unwrap();
        assert_eq!(lifecycle.current_status, LifecycleStatus::Dismissed);
    }

    #[test]
    fn test_lifecycle_history() {
        let mut engine = SmartAlertEngine::new();

        engine.acknowledge_alert("alert1");
        engine.start_investigating("alert1");
        engine.resolve_alert(
            "alert1",
            AlertResolution::RemediationApplied {
                action: "blocked IP".to_string(),
            },
        );

        let lifecycle = engine.get_lifecycle("alert1").unwrap();
        assert_eq!(lifecycle.history.len(), 3);
    }

    #[test]
    fn test_check_stale_alerts() {
        let mut engine = SmartAlertEngine::new();

        engine.acknowledge_alert("alert1");

        // Manually set acknowledged time to 25 hours ago
        if let Some(lifecycle) = engine.lifecycle.lifecycles.get_mut("alert1") {
            lifecycle.acknowledged_at = Some(Utc::now() - Duration::hours(25));
        }

        let stale = engine.check_stale_alerts();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].alert_id, "alert1");
        assert!(stale[0].hours_stale >= 24);
    }

    #[test]
    fn test_no_stale_alerts_when_recent() {
        let mut engine = SmartAlertEngine::new();

        engine.acknowledge_alert("alert1");

        let stale = engine.check_stale_alerts();
        assert_eq!(stale.len(), 0);
    }

    #[test]
    fn test_get_alert_fatigue_stats() {
        let mut engine = SmartAlertEngine::new();

        engine.record_dismissal("pattern1");
        engine.record_dismissal("pattern2");
        engine.mute_pattern("pattern3", Duration::hours(1));

        let stats = engine.get_alert_fatigue_stats();
        assert_eq!(stats.dismissal_patterns.len(), 2);
        assert_eq!(stats.muted_pattern_count, 1);
    }

    #[test]
    fn test_get_digest() {
        let mut engine = SmartAlertEngine::new();

        engine.fatigue.digest_buffer.push(DigestEntry {
            alert_summary: "Test alert".to_string(),
            severity: "MEDIUM".to_string(),
            timestamp: Utc::now(),
            group_id: None,
        });

        let digest = engine.get_digest();
        assert_eq!(digest.len(), 1);
        assert_eq!(engine.fatigue.digest_buffer.len(), 0);
    }

    #[test]
    fn test_enrichment_retrieval_nonexistent() {
        let engine = SmartAlertEngine::new();
        assert!(engine.get_enrichment("nonexistent").is_none());
    }

    #[test]
    fn test_group_status_transitions() {
        let mut engine = SmartAlertEngine::new();
        let now = Utc::now();

        let group_id = engine
            .try_group_alert("alert1", "server1", "curl", "api.com", "MEDIUM", now)
            .unwrap();

        engine.groups[0].status = GroupStatus::Acknowledged;
        assert_eq!(
            engine.get_group(group_id).unwrap().status,
            GroupStatus::Acknowledged
        );

        engine.groups[0].status = GroupStatus::Resolved;
        assert_eq!(
            engine.get_group(group_id).unwrap().status,
            GroupStatus::Resolved
        );
    }

    #[test]
    fn test_empty_engine_operations() {
        let engine = SmartAlertEngine::new();

        assert_eq!(engine.get_groups().len(), 0);
        assert_eq!(engine.get_active_groups().len(), 0);
        assert!(engine.get_enrichment("any").is_none());
        assert!(engine.get_lifecycle("any").is_none());
        assert_eq!(engine.check_stale_alerts().len(), 0);
        assert_eq!(engine.get_muted_patterns().len(), 0);
    }

    #[test]
    fn test_alert_rate_tracking() {
        let mut engine = SmartAlertEngine::new();

        for i in 0..20 {
            engine.record_alert();
        }

        assert!(engine.fatigue.alert_rate.hourly_counts.len() > 0);
    }

    #[test]
    fn test_check_recurrence() {
        let mut engine = SmartAlertEngine::new();

        engine.dismiss_alert("alert1", "False positive");

        if let Some(lifecycle) = engine.lifecycle.lifecycles.get_mut("alert1") {
            lifecycle.recurrence_count = 1;
        }

        assert!(engine.check_recurrence("alert1", "pattern"));
    }

    #[test]
    fn test_severity_rank() {
        assert_eq!(severity_rank("CRITICAL"), 4);
        assert_eq!(severity_rank("HIGH"), 3);
        assert_eq!(severity_rank("MEDIUM"), 2);
        assert_eq!(severity_rank("LOW"), 1);
        assert_eq!(severity_rank("UNKNOWN"), 0);
    }
}
