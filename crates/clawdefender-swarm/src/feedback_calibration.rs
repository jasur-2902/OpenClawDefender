//! Feedback Loop & Calibration System
//!
//! Learns from user interactions to improve triage accuracy, alert relevance,
//! and suggestion quality over time. Provides self-assessment, calibration
//! sessions, and knowledge suggestions based on accumulated feedback.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

// ==================== Feedback Types ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageOverride {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_id: String,
    pub original_triage: String,
    pub user_triage: String,
    pub server_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDismissal {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub alert_id: String,
    pub alert_type: String,
    pub server_name: Option<String>,
    pub reason: Option<String>,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestionResponse {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub action_id: Uuid,
    pub action_type: String,
    pub server_name: Option<String>,
    pub approved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictCorrection {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub investigation_id: String,
    pub original_verdict: String,
    pub corrected_verdict: String,
    pub server_name: Option<String>,
}

// ==================== Feedback Collector ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackCollector {
    triage_overrides: Vec<TriageOverride>,
    alert_dismissals: Vec<AlertDismissal>,
    alert_investigations: Vec<Uuid>,
    suggestion_responses: Vec<SuggestionResponse>,
    countdown_cancellations: Vec<Uuid>,
    verdict_corrections: Vec<VerdictCorrection>,
    max_entries: usize,
}

impl FeedbackCollector {
    pub fn new() -> Self {
        Self {
            triage_overrides: Vec::new(),
            alert_dismissals: Vec::new(),
            alert_investigations: Vec::new(),
            suggestion_responses: Vec::new(),
            countdown_cancellations: Vec::new(),
            verdict_corrections: Vec::new(),
            max_entries: 1000,
        }
    }

    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    fn enforce_cap<T>(entries: &mut Vec<T>, max: usize) {
        while entries.len() > max {
            entries.remove(0);
        }
    }

    pub fn record_triage_override(
        &mut self,
        event_id: &str,
        original: &str,
        user_triage: &str,
        server: &str,
    ) {
        self.triage_overrides.push(TriageOverride {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_id: event_id.to_string(),
            original_triage: original.to_string(),
            user_triage: user_triage.to_string(),
            server_name: server.to_string(),
        });
        Self::enforce_cap(&mut self.triage_overrides, self.max_entries);
    }

    pub fn record_alert_dismissal(
        &mut self,
        alert_id: &str,
        alert_type: &str,
        server: Option<&str>,
        reason: Option<&str>,
        pattern: &str,
    ) {
        self.alert_dismissals.push(AlertDismissal {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            alert_id: alert_id.to_string(),
            alert_type: alert_type.to_string(),
            server_name: server.map(|s| s.to_string()),
            reason: reason.map(|r| r.to_string()),
            pattern: pattern.to_string(),
        });
        Self::enforce_cap(&mut self.alert_dismissals, self.max_entries);
    }

    pub fn record_alert_investigation(&mut self, alert_id: Uuid) {
        self.alert_investigations.push(alert_id);
        Self::enforce_cap(&mut self.alert_investigations, self.max_entries);
    }

    pub fn record_suggestion_response(
        &mut self,
        action_id: Uuid,
        action_type: &str,
        server: Option<&str>,
        approved: bool,
    ) {
        self.suggestion_responses.push(SuggestionResponse {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action_id,
            action_type: action_type.to_string(),
            server_name: server.map(|s| s.to_string()),
            approved,
        });
        Self::enforce_cap(&mut self.suggestion_responses, self.max_entries);
    }

    pub fn record_countdown_cancellation(&mut self, action_id: Uuid) {
        self.countdown_cancellations.push(action_id);
        Self::enforce_cap(&mut self.countdown_cancellations, self.max_entries);
    }

    pub fn record_verdict_correction(
        &mut self,
        investigation_id: &str,
        original: &str,
        corrected: &str,
        server: Option<&str>,
    ) {
        self.verdict_corrections.push(VerdictCorrection {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            investigation_id: investigation_id.to_string(),
            original_verdict: original.to_string(),
            corrected_verdict: corrected.to_string(),
            server_name: server.map(|s| s.to_string()),
        });
        Self::enforce_cap(&mut self.verdict_corrections, self.max_entries);
    }

    pub fn triage_overrides(&self) -> &[TriageOverride] {
        &self.triage_overrides
    }

    pub fn alert_dismissals(&self) -> &[AlertDismissal] {
        &self.alert_dismissals
    }

    pub fn alert_investigations(&self) -> &[Uuid] {
        &self.alert_investigations
    }

    pub fn suggestion_responses(&self) -> &[SuggestionResponse] {
        &self.suggestion_responses
    }

    pub fn countdown_cancellations(&self) -> &[Uuid] {
        &self.countdown_cancellations
    }

    pub fn verdict_corrections(&self) -> &[VerdictCorrection] {
        &self.verdict_corrections
    }

    fn feedback_path() -> PathBuf {
        let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("clawdefender").join("feedback.json")
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::feedback_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    pub fn load() -> Result<Self> {
        let path = Self::feedback_path();
        if !path.exists() {
            return Ok(Self::new());
        }
        let json = std::fs::read_to_string(&path)?;
        let collector: Self = serde_json::from_str(&json)?;
        Ok(collector)
    }
}

impl Default for FeedbackCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== Calibration Types ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCalibration {
    pub server_name: String,
    pub anomaly_threshold_offset: f64,
    pub triage_sensitivity: f64,
    pub noise_suppression: f64,
    pub last_adjusted: DateTime<Utc>,
    pub adjustment_reason: String,
}

impl ServerCalibration {
    pub fn new(server_name: &str) -> Self {
        Self {
            server_name: server_name.to_string(),
            anomaly_threshold_offset: 0.0,
            triage_sensitivity: 0.0,
            noise_suppression: 0.0,
            last_adjusted: Utc::now(),
            adjustment_reason: "initial".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalCalibration {
    pub countdown_duration_secs: u64,
    pub alert_sensitivity_offset: f64,
    pub auto_action_confidence_threshold: f64,
}

impl Default for GlobalCalibration {
    fn default() -> Self {
        Self {
            countdown_duration_secs: 10,
            alert_sensitivity_offset: 0.0,
            auto_action_confidence_threshold: 0.9,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub calibration_type: String,
    pub target: String,
    pub parameter: String,
    pub old_value: f64,
    pub new_value: f64,
    pub reason: String,
}

// ==================== Threshold Calibrator ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdCalibrator {
    per_server_adjustments: HashMap<String, ServerCalibration>,
    global_adjustments: GlobalCalibration,
    calibration_interval_hours: u64,
    last_calibration: Option<DateTime<Utc>>,
    calibration_history: Vec<CalibrationEvent>,
}

impl ThresholdCalibrator {
    pub fn new() -> Self {
        Self {
            per_server_adjustments: HashMap::new(),
            global_adjustments: GlobalCalibration::default(),
            calibration_interval_hours: 24,
            last_calibration: None,
            calibration_history: Vec::new(),
        }
    }

    pub fn with_interval_hours(mut self, hours: u64) -> Self {
        self.calibration_interval_hours = hours;
        self
    }

    pub fn global_adjustments(&self) -> &GlobalCalibration {
        &self.global_adjustments
    }

    pub fn per_server_adjustments(&self) -> &HashMap<String, ServerCalibration> {
        &self.per_server_adjustments
    }

    pub fn calibration_history(&self) -> &[CalibrationEvent] {
        &self.calibration_history
    }

    pub fn should_calibrate(&self) -> bool {
        match self.last_calibration {
            None => true,
            Some(last) => {
                let elapsed = Utc::now() - last;
                elapsed >= Duration::hours(self.calibration_interval_hours as i64)
            }
        }
    }

    pub fn run_calibration(&mut self, feedback: &FeedbackCollector) -> Vec<CalibrationEvent> {
        let mut events = Vec::new();
        let now = Utc::now();
        let seven_days_ago = now - Duration::days(7);

        // Rule 1: 5+ alert dismissals from a server in last 7 days → raise anomaly_threshold_offset
        let mut server_dismissal_counts: HashMap<String, u32> = HashMap::new();
        for d in &feedback.alert_dismissals {
            if d.timestamp >= seven_days_ago {
                if let Some(ref server) = d.server_name {
                    *server_dismissal_counts.entry(server.clone()).or_insert(0) += 1;
                }
            }
        }
        for (server, count) in &server_dismissal_counts {
            if *count >= 5 {
                let cal = self
                    .per_server_adjustments
                    .entry(server.clone())
                    .or_insert_with(|| ServerCalibration::new(server));
                let old = cal.anomaly_threshold_offset;
                cal.anomaly_threshold_offset += 0.05;
                cal.last_adjusted = now;
                cal.adjustment_reason = format!("{} alert dismissals in last 7 days", count);
                events.push(CalibrationEvent {
                    id: Uuid::new_v4(),
                    timestamp: now,
                    calibration_type: "server_threshold".to_string(),
                    target: server.clone(),
                    parameter: "anomaly_threshold_offset".to_string(),
                    old_value: old,
                    new_value: cal.anomaly_threshold_offset,
                    reason: cal.adjustment_reason.clone(),
                });
            }
        }

        // Rule 2: User investigates ROUTINE-triaged events → lower triage_sensitivity
        let routine_investigations: Vec<&TriageOverride> = feedback
            .triage_overrides
            .iter()
            .filter(|o| o.timestamp >= seven_days_ago && o.original_triage == "routine")
            .collect();
        let mut routine_servers: HashMap<String, u32> = HashMap::new();
        for o in &routine_investigations {
            *routine_servers.entry(o.server_name.clone()).or_insert(0) += 1;
        }
        for (server, _count) in &routine_servers {
            let cal = self
                .per_server_adjustments
                .entry(server.clone())
                .or_insert_with(|| ServerCalibration::new(server));
            let old = cal.triage_sensitivity;
            cal.triage_sensitivity -= 0.05;
            cal.last_adjusted = now;
            cal.adjustment_reason = format!("user investigated routine events on {}", server);
            events.push(CalibrationEvent {
                id: Uuid::new_v4(),
                timestamp: now,
                calibration_type: "server_threshold".to_string(),
                target: server.clone(),
                parameter: "triage_sensitivity".to_string(),
                old_value: old,
                new_value: cal.triage_sensitivity,
                reason: cal.adjustment_reason.clone(),
            });
        }

        // Rule 3: User always approves suggestions for a category → increase auto_action_confidence
        let mut category_stats: HashMap<String, (u32, u32)> = HashMap::new();
        for s in &feedback.suggestion_responses {
            if s.timestamp >= seven_days_ago {
                let entry = category_stats
                    .entry(s.action_type.clone())
                    .or_insert((0, 0));
                entry.0 += 1; // total
                if s.approved {
                    entry.1 += 1; // approved
                }
            }
        }
        for (category, (total, approved)) in &category_stats {
            if *total >= 3 && *approved == *total {
                let old = self.global_adjustments.auto_action_confidence_threshold;
                self.global_adjustments.auto_action_confidence_threshold = (old + 0.02).min(1.0);
                let reason = format!(
                    "all {} suggestions approved for category '{}'",
                    total, category
                );
                events.push(CalibrationEvent {
                    id: Uuid::new_v4(),
                    timestamp: now,
                    calibration_type: "global_sensitivity".to_string(),
                    target: "global".to_string(),
                    parameter: "auto_action_confidence_threshold".to_string(),
                    old_value: old,
                    new_value: self.global_adjustments.auto_action_confidence_threshold,
                    reason,
                });
            }
        }

        // Rule 4: 2+ countdown cancellations → increase countdown_duration_secs by 5 (max 30)
        if feedback.countdown_cancellations.len() >= 2 {
            let old = self.global_adjustments.countdown_duration_secs as f64;
            self.global_adjustments.countdown_duration_secs =
                (self.global_adjustments.countdown_duration_secs + 5).min(30);
            let new_val = self.global_adjustments.countdown_duration_secs as f64;
            if new_val != old {
                events.push(CalibrationEvent {
                    id: Uuid::new_v4(),
                    timestamp: now,
                    calibration_type: "countdown_duration".to_string(),
                    target: "global".to_string(),
                    parameter: "countdown_duration_secs".to_string(),
                    old_value: old,
                    new_value: new_val,
                    reason: format!(
                        "{} countdown cancellations recorded",
                        feedback.countdown_cancellations.len()
                    ),
                });
            }
        }

        // Rule 5: Verdict corrections for a server → lower noise_suppression
        let mut correction_servers: HashMap<String, u32> = HashMap::new();
        for vc in &feedback.verdict_corrections {
            if vc.timestamp >= seven_days_ago {
                if let Some(ref server) = vc.server_name {
                    *correction_servers.entry(server.clone()).or_insert(0) += 1;
                }
            }
        }
        for (server, _count) in &correction_servers {
            let cal = self
                .per_server_adjustments
                .entry(server.clone())
                .or_insert_with(|| ServerCalibration::new(server));
            let old = cal.noise_suppression;
            cal.noise_suppression -= 0.05;
            cal.last_adjusted = now;
            cal.adjustment_reason = format!("verdict corrections on {}", server);
            events.push(CalibrationEvent {
                id: Uuid::new_v4(),
                timestamp: now,
                calibration_type: "server_threshold".to_string(),
                target: server.clone(),
                parameter: "noise_suppression".to_string(),
                old_value: old,
                new_value: cal.noise_suppression,
                reason: cal.adjustment_reason.clone(),
            });
        }

        self.calibration_history.extend(events.clone());
        self.last_calibration = Some(now);

        events
    }

    // ==================== Self Assessment ====================

    pub fn self_assessment(&self, feedback: &FeedbackCollector) -> SelfAssessment {
        let override_count = feedback.triage_overrides.len() as f64;
        let estimated_total_triaged = if override_count > 0.0 {
            override_count * 100.0
        } else {
            1.0
        };
        let triage_accuracy = 1.0 - (override_count / estimated_total_triaged);

        let dismissal_count = feedback.alert_dismissals.len() as f64;
        let investigation_count = feedback.alert_investigations.len() as f64;
        let total_alerts = dismissal_count + investigation_count;
        let alert_relevance = if total_alerts > 0.0 {
            1.0 - (dismissal_count / total_alerts)
        } else {
            1.0
        };

        let total_suggestions = feedback.suggestion_responses.len() as f64;
        let approved_count = feedback
            .suggestion_responses
            .iter()
            .filter(|s| s.approved)
            .count() as f64;
        let suggestion_acceptance = if total_suggestions > 0.0 {
            approved_count / total_suggestions
        } else {
            1.0
        };

        let correction_count = feedback.verdict_corrections.len() as f64;
        let investigation_accuracy = if correction_count > 0.0 && investigation_count > 0.0 {
            1.0 - (correction_count / investigation_count).min(1.0)
        } else {
            1.0
        };

        let overall_accuracy =
            (triage_accuracy + alert_relevance + suggestion_acceptance + investigation_accuracy)
                / 4.0;

        let mut recommendations = Vec::new();
        if triage_accuracy < 0.95 {
            recommendations.push(
                "High triage override rate — consider lowering triage sensitivity".to_string(),
            );
        }
        if alert_relevance < 0.7 {
            recommendations
                .push("Many alerts dismissed — consider raising anomaly thresholds".to_string());
        }
        if suggestion_acceptance < 0.5 {
            recommendations
                .push("Low suggestion acceptance — review suggested action types".to_string());
        }
        if investigation_accuracy < 0.8 {
            recommendations
                .push("Verdict corrections detected — review investigation logic".to_string());
        }

        let needs_attention = overall_accuracy < 0.8 || !recommendations.is_empty();

        // Per-server accuracy from triage overrides
        let mut per_server_override_counts: HashMap<String, u32> = HashMap::new();
        for o in &feedback.triage_overrides {
            *per_server_override_counts
                .entry(o.server_name.clone())
                .or_insert(0) += 1;
        }
        let per_server_accuracy: HashMap<String, f64> = per_server_override_counts
            .iter()
            .map(|(server, count)| {
                let estimated = (*count as f64) * 100.0;
                let acc = 1.0 - (*count as f64 / estimated);
                (server.clone(), acc)
            })
            .collect();

        SelfAssessment {
            overall_accuracy,
            triage_accuracy,
            alert_relevance,
            suggestion_acceptance,
            investigation_accuracy,
            needs_attention,
            recommendations,
            per_server_accuracy,
        }
    }

    // ==================== Calibration Session ====================

    pub fn create_calibration_session(&self, feedback: &FeedbackCollector) -> CalibrationSession {
        let mut items = Vec::new();

        // Borderline decisions: triage overrides where user changed severity
        for o in feedback.triage_overrides.iter().rev().take(4) {
            items.push(CalibrationItem {
                id: Uuid::new_v4(),
                event_summary: format!("Event {} on server {}", o.event_id, o.server_name),
                agent_assessment: format!("Triaged as '{}'", o.original_triage),
                agent_action: format!("Classified event as {}", o.original_triage),
                user_agrees: None,
                item_type: "borderline".to_string(),
            });
        }

        // Auto-executed actions: approved suggestions
        for s in feedback
            .suggestion_responses
            .iter()
            .filter(|s| s.approved)
            .rev()
            .take(3)
        {
            items.push(CalibrationItem {
                id: Uuid::new_v4(),
                event_summary: format!("Action type '{}'", s.action_type),
                agent_assessment: "Auto-suggested action".to_string(),
                agent_action: format!("Suggested {} action", s.action_type),
                user_agrees: None,
                item_type: "auto_executed".to_string(),
            });
        }

        // Disagreements: verdict corrections
        for vc in feedback.verdict_corrections.iter().rev().take(3) {
            items.push(CalibrationItem {
                id: Uuid::new_v4(),
                event_summary: format!("Investigation {}", vc.investigation_id),
                agent_assessment: format!("Verdict: '{}'", vc.original_verdict),
                agent_action: format!("User corrected to '{}'", vc.corrected_verdict),
                user_agrees: None,
                item_type: "disagreement".to_string(),
            });
        }

        // Pad to 10 with alert dismissals if needed
        let remaining = 10_usize.saturating_sub(items.len());
        for d in feedback.alert_dismissals.iter().rev().take(remaining) {
            items.push(CalibrationItem {
                id: Uuid::new_v4(),
                event_summary: format!("Alert {} ({})", d.alert_id, d.alert_type),
                agent_assessment: format!("Raised alert of type '{}'", d.alert_type),
                agent_action: "Generated alert".to_string(),
                user_agrees: None,
                item_type: "borderline".to_string(),
            });
        }

        CalibrationSession {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            items,
            completed: false,
        }
    }

    pub fn apply_session_results(&mut self, session: &CalibrationSession) {
        let now = Utc::now();
        for item in &session.items {
            if let Some(agrees) = item.user_agrees {
                if !agrees {
                    match item.item_type.as_str() {
                        "borderline" => {
                            // User disagrees with a borderline triage → adjust global sensitivity
                            let old = self.global_adjustments.alert_sensitivity_offset;
                            self.global_adjustments.alert_sensitivity_offset -= 0.02;
                            self.calibration_history.push(CalibrationEvent {
                                id: Uuid::new_v4(),
                                timestamp: now,
                                calibration_type: "global_sensitivity".to_string(),
                                target: "global".to_string(),
                                parameter: "alert_sensitivity_offset".to_string(),
                                old_value: old,
                                new_value: self.global_adjustments.alert_sensitivity_offset,
                                reason: format!(
                                    "session disagreement on item '{}'",
                                    item.event_summary
                                ),
                            });
                        }
                        "auto_executed" => {
                            // User disagrees with auto-executed action → raise confidence threshold
                            let old = self.global_adjustments.auto_action_confidence_threshold;
                            self.global_adjustments.auto_action_confidence_threshold =
                                (old + 0.05).min(1.0);
                            self.calibration_history.push(CalibrationEvent {
                                id: Uuid::new_v4(),
                                timestamp: now,
                                calibration_type: "global_sensitivity".to_string(),
                                target: "global".to_string(),
                                parameter: "auto_action_confidence_threshold".to_string(),
                                old_value: old,
                                new_value: self.global_adjustments.auto_action_confidence_threshold,
                                reason: format!(
                                    "session disagreement on auto action '{}'",
                                    item.event_summary
                                ),
                            });
                        }
                        "disagreement" => {
                            // User reaffirms their correction → lower sensitivity
                            let old = self.global_adjustments.alert_sensitivity_offset;
                            self.global_adjustments.alert_sensitivity_offset -= 0.03;
                            self.calibration_history.push(CalibrationEvent {
                                id: Uuid::new_v4(),
                                timestamp: now,
                                calibration_type: "global_sensitivity".to_string(),
                                target: "global".to_string(),
                                parameter: "alert_sensitivity_offset".to_string(),
                                old_value: old,
                                new_value: self.global_adjustments.alert_sensitivity_offset,
                                reason: format!(
                                    "user reaffirmed correction for '{}'",
                                    item.event_summary
                                ),
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // ==================== Knowledge Suggestions ====================

    pub fn check_knowledge_suggestions(
        &self,
        feedback: &FeedbackCollector,
    ) -> Vec<KnowledgeSuggestion> {
        let mut suggestions = Vec::new();

        // 3+ dismissals of same pattern → suggest marking as safe
        let mut pattern_dismiss_counts: HashMap<String, u32> = HashMap::new();
        for d in &feedback.alert_dismissals {
            *pattern_dismiss_counts.entry(d.pattern.clone()).or_insert(0) += 1;
        }
        for (pattern, count) in &pattern_dismiss_counts {
            if *count >= 3 {
                suggestions.push(KnowledgeSuggestion {
                    pattern: pattern.clone(),
                    suggestion_type: "mark_safe".to_string(),
                    description: format!(
                        "Pattern '{}' has been dismissed {} times — consider marking as safe",
                        pattern, count
                    ),
                    dismiss_count: *count,
                    approval_count: 0,
                    confidence: (*count as f64 / 10.0).min(1.0),
                });
            }
        }

        // 3+ approvals of same action type → suggest confirming as known behavior
        let mut action_approval_counts: HashMap<String, u32> = HashMap::new();
        for s in &feedback.suggestion_responses {
            if s.approved {
                *action_approval_counts
                    .entry(s.action_type.clone())
                    .or_insert(0) += 1;
            }
        }
        for (action_type, count) in &action_approval_counts {
            if *count >= 3 {
                suggestions.push(KnowledgeSuggestion {
                    pattern: action_type.clone(),
                    suggestion_type: "confirm_behavior".to_string(),
                    description: format!(
                        "Action '{}' approved {} times — consider auto-approving",
                        action_type, count
                    ),
                    dismiss_count: 0,
                    approval_count: *count,
                    confidence: (*count as f64 / 10.0).min(1.0),
                });
            }
        }

        // Investigation verdict + user confirmation → high confidence threat pattern
        for vc in &feedback.verdict_corrections {
            suggestions.push(KnowledgeSuggestion {
                pattern: format!(
                    "investigation:{}:{}",
                    vc.investigation_id, vc.corrected_verdict
                ),
                suggestion_type: "threat_pattern".to_string(),
                description: format!(
                    "Investigation {} corrected from '{}' to '{}' — high confidence pattern",
                    vc.investigation_id, vc.original_verdict, vc.corrected_verdict
                ),
                dismiss_count: 0,
                approval_count: 0,
                confidence: 0.9,
            });
        }

        suggestions
    }

    // ==================== Anonymized Stats ====================

    pub fn get_anonymized_stats(&self, feedback: &FeedbackCollector) -> AnonymizedStats {
        let assessment = self.self_assessment(feedback);

        let mut fp_categories: HashMap<String, u32> = HashMap::new();
        for d in &feedback.alert_dismissals {
            *fp_categories.entry(d.alert_type.clone()).or_insert(0) += 1;
        }
        let mut common_fp: Vec<(String, u32)> = fp_categories.into_iter().collect();
        common_fp.sort_by(|a, b| b.1.cmp(&a.1));
        let common_fp_categories: Vec<String> =
            common_fp.into_iter().take(5).map(|(k, _)| k).collect();

        let mut playbook_counts: HashMap<String, u32> = HashMap::new();
        for s in &feedback.suggestion_responses {
            if s.approved {
                *playbook_counts.entry(s.action_type.clone()).or_insert(0) += 1;
            }
        }
        let mut useful: Vec<(String, u32)> = playbook_counts.into_iter().collect();
        useful.sort_by(|a, b| b.1.cmp(&a.1));
        let useful_playbook_types: Vec<String> =
            useful.into_iter().take(5).map(|(k, _)| k).collect();

        let total_alerts = feedback.alert_dismissals.len() + feedback.alert_investigations.len();
        let alert_dismiss_rate = if total_alerts > 0 {
            feedback.alert_dismissals.len() as f64 / total_alerts as f64
        } else {
            0.0
        };

        AnonymizedStats {
            triage_accuracy_percent: assessment.triage_accuracy * 100.0,
            common_fp_categories,
            useful_playbook_types,
            alert_dismiss_rate,
        }
    }

    // ==================== Stats ====================

    pub fn get_stats(&self, feedback: &FeedbackCollector) -> CalibrationStats {
        let assessment = self.self_assessment(feedback);
        CalibrationStats {
            total_calibrations: self.calibration_history.len() as u32,
            total_adjustments: self.calibration_history.len() as u32,
            servers_calibrated: self.per_server_adjustments.len() as u32,
            last_calibration: self.last_calibration,
            global_countdown_secs: self.global_adjustments.countdown_duration_secs,
            overall_accuracy: assessment.overall_accuracy,
        }
    }

    // ==================== Persistence ====================

    fn calibration_path() -> PathBuf {
        let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("clawdefender").join("calibration.json")
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::calibration_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    pub fn load() -> Result<Self> {
        let path = Self::calibration_path();
        if !path.exists() {
            return Ok(Self::new());
        }
        let json = std::fs::read_to_string(&path)?;
        let cal: Self = serde_json::from_str(&json)?;
        Ok(cal)
    }
}

impl Default for ThresholdCalibrator {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== Assessment & Session Types ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfAssessment {
    pub overall_accuracy: f64,
    pub triage_accuracy: f64,
    pub alert_relevance: f64,
    pub suggestion_acceptance: f64,
    pub investigation_accuracy: f64,
    pub needs_attention: bool,
    pub recommendations: Vec<String>,
    pub per_server_accuracy: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationSession {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub items: Vec<CalibrationItem>,
    pub completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationItem {
    pub id: Uuid,
    pub event_summary: String,
    pub agent_assessment: String,
    pub agent_action: String,
    pub user_agrees: Option<bool>,
    pub item_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeSuggestion {
    pub pattern: String,
    pub suggestion_type: String,
    pub description: String,
    pub dismiss_count: u32,
    pub approval_count: u32,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedStats {
    pub triage_accuracy_percent: f64,
    pub common_fp_categories: Vec<String>,
    pub useful_playbook_types: Vec<String>,
    pub alert_dismiss_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationStats {
    pub total_calibrations: u32,
    pub total_adjustments: u32,
    pub servers_calibrated: u32,
    pub last_calibration: Option<DateTime<Utc>>,
    pub global_countdown_secs: u64,
    pub overall_accuracy: f64,
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_collector() -> FeedbackCollector {
        FeedbackCollector::new()
    }

    fn make_calibrator() -> ThresholdCalibrator {
        ThresholdCalibrator::new()
    }

    // ---------- FeedbackCollector basics ----------

    #[test]
    fn test_new_collector_is_empty() {
        let fc = make_collector();
        assert!(fc.triage_overrides().is_empty());
        assert!(fc.alert_dismissals().is_empty());
        assert!(fc.alert_investigations().is_empty());
        assert!(fc.suggestion_responses().is_empty());
        assert!(fc.countdown_cancellations().is_empty());
        assert!(fc.verdict_corrections().is_empty());
    }

    #[test]
    fn test_record_triage_override() {
        let mut fc = make_collector();
        fc.record_triage_override("evt-1", "routine", "suspicious", "web-1");
        assert_eq!(fc.triage_overrides().len(), 1);
        assert_eq!(fc.triage_overrides()[0].event_id, "evt-1");
        assert_eq!(fc.triage_overrides()[0].original_triage, "routine");
        assert_eq!(fc.triage_overrides()[0].user_triage, "suspicious");
        assert_eq!(fc.triage_overrides()[0].server_name, "web-1");
    }

    #[test]
    fn test_record_alert_dismissal() {
        let mut fc = make_collector();
        fc.record_alert_dismissal(
            "alert-1",
            "anomaly",
            Some("db-1"),
            Some("false positive"),
            "high_cpu_spike",
        );
        assert_eq!(fc.alert_dismissals().len(), 1);
        let d = &fc.alert_dismissals()[0];
        assert_eq!(d.alert_id, "alert-1");
        assert_eq!(d.alert_type, "anomaly");
        assert_eq!(d.server_name, Some("db-1".to_string()));
        assert_eq!(d.reason, Some("false positive".to_string()));
        assert_eq!(d.pattern, "high_cpu_spike");
    }

    #[test]
    fn test_record_alert_dismissal_no_server() {
        let mut fc = make_collector();
        fc.record_alert_dismissal("alert-2", "brute_force", None, None, "ssh_pattern");
        assert_eq!(fc.alert_dismissals().len(), 1);
        assert!(fc.alert_dismissals()[0].server_name.is_none());
        assert!(fc.alert_dismissals()[0].reason.is_none());
    }

    #[test]
    fn test_record_alert_investigation() {
        let mut fc = make_collector();
        let id = Uuid::new_v4();
        fc.record_alert_investigation(id);
        assert_eq!(fc.alert_investigations().len(), 1);
        assert_eq!(fc.alert_investigations()[0], id);
    }

    #[test]
    fn test_record_suggestion_response_approved() {
        let mut fc = make_collector();
        let action_id = Uuid::new_v4();
        fc.record_suggestion_response(action_id, "block_ip", Some("firewall-1"), true);
        assert_eq!(fc.suggestion_responses().len(), 1);
        let s = &fc.suggestion_responses()[0];
        assert_eq!(s.action_id, action_id);
        assert_eq!(s.action_type, "block_ip");
        assert!(s.approved);
    }

    #[test]
    fn test_record_suggestion_response_rejected() {
        let mut fc = make_collector();
        let action_id = Uuid::new_v4();
        fc.record_suggestion_response(action_id, "restart_service", None, false);
        assert_eq!(fc.suggestion_responses().len(), 1);
        assert!(!fc.suggestion_responses()[0].approved);
    }

    #[test]
    fn test_record_countdown_cancellation() {
        let mut fc = make_collector();
        let id = Uuid::new_v4();
        fc.record_countdown_cancellation(id);
        assert_eq!(fc.countdown_cancellations().len(), 1);
        assert_eq!(fc.countdown_cancellations()[0], id);
    }

    #[test]
    fn test_record_verdict_correction() {
        let mut fc = make_collector();
        fc.record_verdict_correction("inv-1", "safe", "malicious", Some("web-2"));
        assert_eq!(fc.verdict_corrections().len(), 1);
        let vc = &fc.verdict_corrections()[0];
        assert_eq!(vc.investigation_id, "inv-1");
        assert_eq!(vc.original_verdict, "safe");
        assert_eq!(vc.corrected_verdict, "malicious");
        assert_eq!(vc.server_name, Some("web-2".to_string()));
    }

    #[test]
    fn test_verdict_correction_no_server() {
        let mut fc = make_collector();
        fc.record_verdict_correction("inv-2", "suspicious", "benign", None);
        assert!(fc.verdict_corrections()[0].server_name.is_none());
    }

    // ---------- Max entries cap ----------

    #[test]
    fn test_max_entries_cap_triage() {
        let mut fc = FeedbackCollector::new().with_max_entries(3);
        for i in 0..5 {
            fc.record_triage_override(&format!("evt-{}", i), "routine", "critical", "srv");
        }
        assert_eq!(fc.triage_overrides().len(), 3);
        // oldest removed, newest kept
        assert_eq!(fc.triage_overrides()[0].event_id, "evt-2");
        assert_eq!(fc.triage_overrides()[2].event_id, "evt-4");
    }

    #[test]
    fn test_max_entries_cap_dismissals() {
        let mut fc = FeedbackCollector::new().with_max_entries(2);
        for i in 0..4 {
            fc.record_alert_dismissal(&format!("a-{}", i), "type", None, None, "pat");
        }
        assert_eq!(fc.alert_dismissals().len(), 2);
        assert_eq!(fc.alert_dismissals()[0].alert_id, "a-2");
    }

    #[test]
    fn test_max_entries_cap_investigations() {
        let mut fc = FeedbackCollector::new().with_max_entries(2);
        let ids: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();
        for id in &ids {
            fc.record_alert_investigation(*id);
        }
        assert_eq!(fc.alert_investigations().len(), 2);
        assert_eq!(fc.alert_investigations()[0], ids[2]);
    }

    #[test]
    fn test_max_entries_cap_suggestions() {
        let mut fc = FeedbackCollector::new().with_max_entries(2);
        for _ in 0..4 {
            fc.record_suggestion_response(Uuid::new_v4(), "block", None, true);
        }
        assert_eq!(fc.suggestion_responses().len(), 2);
    }

    #[test]
    fn test_max_entries_cap_cancellations() {
        let mut fc = FeedbackCollector::new().with_max_entries(2);
        for _ in 0..4 {
            fc.record_countdown_cancellation(Uuid::new_v4());
        }
        assert_eq!(fc.countdown_cancellations().len(), 2);
    }

    #[test]
    fn test_max_entries_cap_corrections() {
        let mut fc = FeedbackCollector::new().with_max_entries(2);
        for i in 0..4 {
            fc.record_verdict_correction(&format!("inv-{}", i), "safe", "bad", None);
        }
        assert_eq!(fc.verdict_corrections().len(), 2);
        assert_eq!(fc.verdict_corrections()[0].investigation_id, "inv-2");
    }

    // ---------- ThresholdCalibrator basics ----------

    #[test]
    fn test_new_calibrator_defaults() {
        let cal = make_calibrator();
        assert_eq!(cal.global_adjustments().countdown_duration_secs, 10);
        assert_eq!(cal.global_adjustments().alert_sensitivity_offset, 0.0);
        assert!(cal.per_server_adjustments().is_empty());
        assert!(cal.calibration_history().is_empty());
    }

    #[test]
    fn test_should_calibrate_initially() {
        let cal = make_calibrator();
        assert!(cal.should_calibrate());
    }

    #[test]
    fn test_should_calibrate_after_run() {
        let mut cal = make_calibrator().with_interval_hours(24);
        let fc = make_collector();
        cal.run_calibration(&fc);
        assert!(!cal.should_calibrate());
    }

    // ---------- Calibration rules ----------

    #[test]
    fn test_calibration_rule_alert_dismissals_threshold() {
        let mut fc = make_collector();
        for i in 0..6 {
            fc.record_alert_dismissal(&format!("a-{}", i), "anomaly", Some("web-1"), None, "pat");
        }
        let mut cal = make_calibrator();
        let events = cal.run_calibration(&fc);
        assert!(!events.is_empty());
        let server_cal = cal.per_server_adjustments().get("web-1").unwrap();
        assert!((server_cal.anomaly_threshold_offset - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn test_calibration_rule_no_adjustment_below_5_dismissals() {
        let mut fc = make_collector();
        for i in 0..4 {
            fc.record_alert_dismissal(&format!("a-{}", i), "anomaly", Some("web-1"), None, "pat");
        }
        let mut cal = make_calibrator();
        let events = cal.run_calibration(&fc);
        // Should not produce anomaly_threshold_offset events for web-1
        let threshold_events: Vec<_> = events
            .iter()
            .filter(|e| e.parameter == "anomaly_threshold_offset")
            .collect();
        assert!(threshold_events.is_empty());
    }

    #[test]
    fn test_calibration_rule_routine_investigation_sensitivity() {
        let mut fc = make_collector();
        fc.record_triage_override("evt-1", "routine", "suspicious", "db-1");
        let mut cal = make_calibrator();
        let events = cal.run_calibration(&fc);
        let sens_events: Vec<_> = events
            .iter()
            .filter(|e| e.parameter == "triage_sensitivity")
            .collect();
        assert!(!sens_events.is_empty());
        let server_cal = cal.per_server_adjustments().get("db-1").unwrap();
        assert!((server_cal.triage_sensitivity - (-0.05)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_calibration_rule_auto_action_confidence() {
        let mut fc = make_collector();
        for _ in 0..3 {
            fc.record_suggestion_response(Uuid::new_v4(), "block_ip", Some("fw-1"), true);
        }
        let mut cal = make_calibrator();
        let events = cal.run_calibration(&fc);
        let conf_events: Vec<_> = events
            .iter()
            .filter(|e| e.parameter == "auto_action_confidence_threshold")
            .collect();
        assert!(!conf_events.is_empty());
        assert!(
            (cal.global_adjustments().auto_action_confidence_threshold - 0.92).abs() < f64::EPSILON
        );
    }

    #[test]
    fn test_calibration_rule_no_confidence_if_not_all_approved() {
        let mut fc = make_collector();
        for i in 0..4 {
            fc.record_suggestion_response(
                Uuid::new_v4(),
                "block_ip",
                None,
                i < 3, // 3 approved, 1 rejected
            );
        }
        let mut cal = make_calibrator();
        let events = cal.run_calibration(&fc);
        let conf_events: Vec<_> = events
            .iter()
            .filter(|e| e.parameter == "auto_action_confidence_threshold")
            .collect();
        assert!(conf_events.is_empty());
    }

    #[test]
    fn test_calibration_rule_countdown_cancellation() {
        let mut fc = make_collector();
        fc.record_countdown_cancellation(Uuid::new_v4());
        fc.record_countdown_cancellation(Uuid::new_v4());
        let mut cal = make_calibrator();
        let events = cal.run_calibration(&fc);
        let cd_events: Vec<_> = events
            .iter()
            .filter(|e| e.parameter == "countdown_duration_secs")
            .collect();
        assert!(!cd_events.is_empty());
        assert_eq!(cal.global_adjustments().countdown_duration_secs, 15);
    }

    #[test]
    fn test_calibration_rule_countdown_max_30() {
        let mut fc = make_collector();
        fc.record_countdown_cancellation(Uuid::new_v4());
        fc.record_countdown_cancellation(Uuid::new_v4());
        let mut cal = make_calibrator();
        // Run calibration multiple times
        cal.last_calibration = None;
        cal.run_calibration(&fc);
        assert_eq!(cal.global_adjustments().countdown_duration_secs, 15);
        cal.last_calibration = None;
        cal.run_calibration(&fc);
        assert_eq!(cal.global_adjustments().countdown_duration_secs, 20);
        cal.last_calibration = None;
        cal.run_calibration(&fc);
        assert_eq!(cal.global_adjustments().countdown_duration_secs, 25);
        cal.last_calibration = None;
        cal.run_calibration(&fc);
        assert_eq!(cal.global_adjustments().countdown_duration_secs, 30);
        cal.last_calibration = None;
        cal.run_calibration(&fc);
        // Should stay at 30
        assert_eq!(cal.global_adjustments().countdown_duration_secs, 30);
    }

    #[test]
    fn test_calibration_no_countdown_event_when_at_max() {
        let mut fc = make_collector();
        fc.record_countdown_cancellation(Uuid::new_v4());
        fc.record_countdown_cancellation(Uuid::new_v4());
        let mut cal = make_calibrator();
        cal.global_adjustments.countdown_duration_secs = 30;
        let events = cal.run_calibration(&fc);
        let cd_events: Vec<_> = events
            .iter()
            .filter(|e| e.parameter == "countdown_duration_secs")
            .collect();
        assert!(cd_events.is_empty());
    }

    #[test]
    fn test_calibration_rule_verdict_correction_noise() {
        let mut fc = make_collector();
        fc.record_verdict_correction("inv-1", "safe", "malicious", Some("app-1"));
        let mut cal = make_calibrator();
        let events = cal.run_calibration(&fc);
        let noise_events: Vec<_> = events
            .iter()
            .filter(|e| e.parameter == "noise_suppression")
            .collect();
        assert!(!noise_events.is_empty());
        let server_cal = cal.per_server_adjustments().get("app-1").unwrap();
        assert!((server_cal.noise_suppression - (-0.05)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_calibration_no_events_empty_feedback() {
        let fc = make_collector();
        let mut cal = make_calibrator();
        let events = cal.run_calibration(&fc);
        assert!(events.is_empty());
    }

    #[test]
    fn test_calibration_history_accumulates() {
        let mut fc = make_collector();
        for i in 0..5 {
            fc.record_alert_dismissal(&format!("a-{}", i), "anomaly", Some("web-1"), None, "pat");
        }
        fc.record_countdown_cancellation(Uuid::new_v4());
        fc.record_countdown_cancellation(Uuid::new_v4());

        let mut cal = make_calibrator();
        let events1 = cal.run_calibration(&fc);
        assert_eq!(cal.calibration_history().len(), events1.len());
    }

    // ---------- Self Assessment ----------

    #[test]
    fn test_self_assessment_perfect_scores() {
        let fc = make_collector();
        let cal = make_calibrator();
        let assessment = cal.self_assessment(&fc);
        assert!((assessment.triage_accuracy - 1.0).abs() < f64::EPSILON);
        assert!((assessment.alert_relevance - 1.0).abs() < f64::EPSILON);
        assert!((assessment.suggestion_acceptance - 1.0).abs() < f64::EPSILON);
        assert!((assessment.investigation_accuracy - 1.0).abs() < f64::EPSILON);
        assert!((assessment.overall_accuracy - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_self_assessment_with_overrides() {
        let mut fc = make_collector();
        fc.record_triage_override("evt-1", "routine", "critical", "web-1");
        let cal = make_calibrator();
        let assessment = cal.self_assessment(&fc);
        // 1 override → estimated 100 total → accuracy = 0.99
        assert!((assessment.triage_accuracy - 0.99).abs() < f64::EPSILON);
    }

    #[test]
    fn test_self_assessment_alert_relevance() {
        let mut fc = make_collector();
        fc.record_alert_dismissal("a-1", "type", None, None, "pat");
        fc.record_alert_investigation(Uuid::new_v4());
        let cal = make_calibrator();
        let assessment = cal.self_assessment(&fc);
        // 1 dismissal, 1 investigation → 2 total → relevance = 1 - 1/2 = 0.5
        assert!((assessment.alert_relevance - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_self_assessment_suggestion_acceptance() {
        let mut fc = make_collector();
        fc.record_suggestion_response(Uuid::new_v4(), "block", None, true);
        fc.record_suggestion_response(Uuid::new_v4(), "allow", None, false);
        let cal = make_calibrator();
        let assessment = cal.self_assessment(&fc);
        assert!((assessment.suggestion_acceptance - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_self_assessment_investigation_accuracy() {
        let mut fc = make_collector();
        fc.record_alert_investigation(Uuid::new_v4());
        fc.record_alert_investigation(Uuid::new_v4());
        fc.record_verdict_correction("inv-1", "safe", "bad", None);
        let cal = make_calibrator();
        let assessment = cal.self_assessment(&fc);
        // 1 correction / 2 investigations → accuracy = 1 - 0.5 = 0.5
        assert!((assessment.investigation_accuracy - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_self_assessment_needs_attention() {
        let mut fc = make_collector();
        // Create low alert_relevance: many dismissals, no investigations
        for i in 0..10 {
            fc.record_alert_dismissal(&format!("a-{}", i), "type", None, None, "pat");
        }
        let cal = make_calibrator();
        let assessment = cal.self_assessment(&fc);
        assert!(assessment.needs_attention);
        assert!(!assessment.recommendations.is_empty());
    }

    #[test]
    fn test_self_assessment_per_server_accuracy() {
        let mut fc = make_collector();
        fc.record_triage_override("evt-1", "routine", "critical", "web-1");
        fc.record_triage_override("evt-2", "routine", "critical", "web-1");
        fc.record_triage_override("evt-3", "routine", "critical", "db-1");
        let cal = make_calibrator();
        let assessment = cal.self_assessment(&fc);
        assert!(assessment.per_server_accuracy.contains_key("web-1"));
        assert!(assessment.per_server_accuracy.contains_key("db-1"));
        // web-1 has 2 overrides → estimated 200 → accuracy = 0.99
        assert!((assessment.per_server_accuracy["web-1"] - 0.99).abs() < f64::EPSILON);
    }

    // ---------- Calibration Session ----------

    #[test]
    fn test_create_calibration_session_empty() {
        let fc = make_collector();
        let cal = make_calibrator();
        let session = cal.create_calibration_session(&fc);
        assert!(session.items.is_empty());
        assert!(!session.completed);
    }

    #[test]
    fn test_create_calibration_session_with_items() {
        let mut fc = make_collector();
        fc.record_triage_override("evt-1", "routine", "critical", "web-1");
        fc.record_suggestion_response(Uuid::new_v4(), "block_ip", None, true);
        fc.record_verdict_correction("inv-1", "safe", "bad", None);
        let cal = make_calibrator();
        let session = cal.create_calibration_session(&fc);
        assert_eq!(session.items.len(), 3);
        let types: Vec<&str> = session.items.iter().map(|i| i.item_type.as_str()).collect();
        assert!(types.contains(&"borderline"));
        assert!(types.contains(&"auto_executed"));
        assert!(types.contains(&"disagreement"));
    }

    #[test]
    fn test_create_calibration_session_max_10_items() {
        let mut fc = make_collector();
        for i in 0..15 {
            fc.record_triage_override(&format!("evt-{}", i), "routine", "critical", "web-1");
        }
        for i in 0..15 {
            fc.record_alert_dismissal(&format!("a-{}", i), "anomaly", None, None, "pat");
        }
        let cal = make_calibrator();
        let session = cal.create_calibration_session(&fc);
        assert!(session.items.len() <= 10);
    }

    #[test]
    fn test_apply_session_results_borderline_disagreement() {
        let mut cal = make_calibrator();
        let fc = make_collector();
        let mut session = cal.create_calibration_session(&fc);
        session.items.push(CalibrationItem {
            id: Uuid::new_v4(),
            event_summary: "test event".to_string(),
            agent_assessment: "triaged as routine".to_string(),
            agent_action: "classified".to_string(),
            user_agrees: Some(false),
            item_type: "borderline".to_string(),
        });
        let old_offset = cal.global_adjustments().alert_sensitivity_offset;
        cal.apply_session_results(&session);
        assert!(
            (cal.global_adjustments().alert_sensitivity_offset - (old_offset - 0.02)).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn test_apply_session_results_auto_executed_disagreement() {
        let mut cal = make_calibrator();
        let session = CalibrationSession {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            items: vec![CalibrationItem {
                id: Uuid::new_v4(),
                event_summary: "block action".to_string(),
                agent_assessment: "auto".to_string(),
                agent_action: "blocked".to_string(),
                user_agrees: Some(false),
                item_type: "auto_executed".to_string(),
            }],
            completed: false,
        };
        let old_conf = cal.global_adjustments().auto_action_confidence_threshold;
        cal.apply_session_results(&session);
        assert!(
            (cal.global_adjustments().auto_action_confidence_threshold - (old_conf + 0.05)).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn test_apply_session_results_user_agrees_no_change() {
        let mut cal = make_calibrator();
        let session = CalibrationSession {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            items: vec![CalibrationItem {
                id: Uuid::new_v4(),
                event_summary: "test".to_string(),
                agent_assessment: "good".to_string(),
                agent_action: "action".to_string(),
                user_agrees: Some(true),
                item_type: "borderline".to_string(),
            }],
            completed: false,
        };
        let history_before = cal.calibration_history().len();
        cal.apply_session_results(&session);
        assert_eq!(cal.calibration_history().len(), history_before);
    }

    // ---------- Knowledge Suggestions ----------

    #[test]
    fn test_knowledge_suggestions_empty() {
        let fc = make_collector();
        let cal = make_calibrator();
        let suggestions = cal.check_knowledge_suggestions(&fc);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_knowledge_suggestion_mark_safe() {
        let mut fc = make_collector();
        for i in 0..3 {
            fc.record_alert_dismissal(&format!("a-{}", i), "anomaly", None, None, "cron_job_spike");
        }
        let cal = make_calibrator();
        let suggestions = cal.check_knowledge_suggestions(&fc);
        let safe: Vec<_> = suggestions
            .iter()
            .filter(|s| s.suggestion_type == "mark_safe")
            .collect();
        assert_eq!(safe.len(), 1);
        assert_eq!(safe[0].pattern, "cron_job_spike");
        assert_eq!(safe[0].dismiss_count, 3);
    }

    #[test]
    fn test_knowledge_suggestion_no_mark_safe_below_3() {
        let mut fc = make_collector();
        for i in 0..2 {
            fc.record_alert_dismissal(&format!("a-{}", i), "anomaly", None, None, "rare_pattern");
        }
        let cal = make_calibrator();
        let suggestions = cal.check_knowledge_suggestions(&fc);
        let safe: Vec<_> = suggestions
            .iter()
            .filter(|s| s.suggestion_type == "mark_safe")
            .collect();
        assert!(safe.is_empty());
    }

    #[test]
    fn test_knowledge_suggestion_confirm_behavior() {
        let mut fc = make_collector();
        for _ in 0..4 {
            fc.record_suggestion_response(Uuid::new_v4(), "block_ip", None, true);
        }
        let cal = make_calibrator();
        let suggestions = cal.check_knowledge_suggestions(&fc);
        let confirm: Vec<_> = suggestions
            .iter()
            .filter(|s| s.suggestion_type == "confirm_behavior")
            .collect();
        assert_eq!(confirm.len(), 1);
        assert_eq!(confirm[0].pattern, "block_ip");
        assert_eq!(confirm[0].approval_count, 4);
    }

    #[test]
    fn test_knowledge_suggestion_threat_pattern() {
        let mut fc = make_collector();
        fc.record_verdict_correction("inv-1", "safe", "malicious", None);
        let cal = make_calibrator();
        let suggestions = cal.check_knowledge_suggestions(&fc);
        let threats: Vec<_> = suggestions
            .iter()
            .filter(|s| s.suggestion_type == "threat_pattern")
            .collect();
        assert_eq!(threats.len(), 1);
        assert!((threats[0].confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_knowledge_suggestion_confidence_capped() {
        let mut fc = make_collector();
        for i in 0..20 {
            fc.record_alert_dismissal(&format!("a-{}", i), "anomaly", None, None, "same_pattern");
        }
        let cal = make_calibrator();
        let suggestions = cal.check_knowledge_suggestions(&fc);
        for s in &suggestions {
            assert!(s.confidence <= 1.0);
        }
    }

    // ---------- Anonymized Stats ----------

    #[test]
    fn test_anonymized_stats_empty() {
        let fc = make_collector();
        let cal = make_calibrator();
        let stats = cal.get_anonymized_stats(&fc);
        assert!((stats.triage_accuracy_percent - 100.0).abs() < f64::EPSILON);
        assert!(stats.common_fp_categories.is_empty());
        assert!(stats.useful_playbook_types.is_empty());
        assert!((stats.alert_dismiss_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_anonymized_stats_with_data() {
        let mut fc = make_collector();
        fc.record_alert_dismissal("a-1", "anomaly", None, None, "pat");
        fc.record_alert_dismissal("a-2", "brute_force", None, None, "pat");
        fc.record_alert_investigation(Uuid::new_v4());
        fc.record_suggestion_response(Uuid::new_v4(), "block_ip", None, true);
        let cal = make_calibrator();
        let stats = cal.get_anonymized_stats(&fc);
        // 2 dismissals / 3 total = ~0.667
        assert!((stats.alert_dismiss_rate - 2.0 / 3.0).abs() < 0.01);
        assert!(!stats.common_fp_categories.is_empty());
        assert!(stats
            .useful_playbook_types
            .contains(&"block_ip".to_string()));
    }

    // ---------- CalibrationStats ----------

    #[test]
    fn test_calibration_stats_initial() {
        let fc = make_collector();
        let cal = make_calibrator();
        let stats = cal.get_stats(&fc);
        assert_eq!(stats.total_calibrations, 0);
        assert_eq!(stats.servers_calibrated, 0);
        assert!(stats.last_calibration.is_none());
        assert_eq!(stats.global_countdown_secs, 10);
    }

    #[test]
    fn test_calibration_stats_after_calibration() {
        let mut fc = make_collector();
        for i in 0..6 {
            fc.record_alert_dismissal(&format!("a-{}", i), "anomaly", Some("web-1"), None, "pat");
        }
        let mut cal = make_calibrator();
        cal.run_calibration(&fc);
        let stats = cal.get_stats(&fc);
        assert!(stats.total_calibrations > 0);
        assert_eq!(stats.servers_calibrated, 1);
        assert!(stats.last_calibration.is_some());
    }

    // ---------- Serialization ----------

    #[test]
    fn test_feedback_collector_serialization() {
        let mut fc = make_collector();
        fc.record_triage_override("evt-1", "routine", "critical", "web-1");
        fc.record_alert_dismissal("a-1", "anomaly", Some("db-1"), None, "pat");
        let json = serde_json::to_string(&fc).unwrap();
        let deserialized: FeedbackCollector = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.triage_overrides().len(), 1);
        assert_eq!(deserialized.alert_dismissals().len(), 1);
    }

    #[test]
    fn test_calibrator_serialization() {
        let mut cal = make_calibrator();
        let mut fc = make_collector();
        fc.record_countdown_cancellation(Uuid::new_v4());
        fc.record_countdown_cancellation(Uuid::new_v4());
        cal.run_calibration(&fc);
        let json = serde_json::to_string(&cal).unwrap();
        let deserialized: ThresholdCalibrator = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.global_adjustments().countdown_duration_secs,
            cal.global_adjustments().countdown_duration_secs
        );
    }

    // ---------- ServerCalibration ----------

    #[test]
    fn test_server_calibration_new() {
        let sc = ServerCalibration::new("my-server");
        assert_eq!(sc.server_name, "my-server");
        assert_eq!(sc.anomaly_threshold_offset, 0.0);
        assert_eq!(sc.triage_sensitivity, 0.0);
        assert_eq!(sc.noise_suppression, 0.0);
    }

    // ---------- Default impls ----------

    #[test]
    fn test_feedback_collector_default() {
        let fc = FeedbackCollector::default();
        assert_eq!(fc.max_entries, 1000);
    }

    #[test]
    fn test_threshold_calibrator_default() {
        let cal = ThresholdCalibrator::default();
        assert_eq!(cal.calibration_interval_hours, 24);
    }
}
