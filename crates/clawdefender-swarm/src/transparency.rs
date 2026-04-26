//! Transparency dashboard backend — full visibility into agent activities,
//! costs, accuracy, knowledge, audit trail, and decision explanations.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

// ============================================================================
// 1. Agent Activity Tracker
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ActivityType {
    ActionProposed,
    ActionExecuted,
    ActionBlocked,
    PlaybookTriggered,
    PlaybookCompleted,
    ReportGenerated,
    CalibrationRun,
    ExportPerformed,
    ImportPerformed,
    LevelChange,
    LockdownActivated,
    LockdownDeactivated,
    FeedbackReceived,
    ThresholdAdjusted,
}

impl std::fmt::Display for ActivityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActivity {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub activity_type: ActivityType,
    pub description: String,
    pub server_name: Option<String>,
    pub autonomy_level: String,
    pub risk_level: Option<String>,
    pub outcome: Option<String>,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivitySummary {
    pub total: u64,
    pub by_type: HashMap<String, u64>,
    pub by_server: HashMap<String, u64>,
    pub last_24h: u64,
    pub last_7d: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActivityTracker {
    activities: Vec<AgentActivity>,
}

impl AgentActivityTracker {
    pub fn new() -> Self {
        Self {
            activities: Vec::new(),
        }
    }

    pub fn record_activity(&mut self, activity: AgentActivity) {
        self.activities.push(activity);
    }

    pub fn get_recent(&self, count: usize) -> &[AgentActivity] {
        let start = self.activities.len().saturating_sub(count);
        &self.activities[start..]
    }

    pub fn get_by_type(&self, activity_type: &ActivityType) -> Vec<&AgentActivity> {
        self.activities
            .iter()
            .filter(|a| &a.activity_type == activity_type)
            .collect()
    }

    pub fn get_by_server(&self, server_name: &str) -> Vec<&AgentActivity> {
        self.activities
            .iter()
            .filter(|a| a.server_name.as_deref() == Some(server_name))
            .collect()
    }

    pub fn get_by_time_range(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<&AgentActivity> {
        self.activities
            .iter()
            .filter(|a| a.timestamp >= from && a.timestamp <= to)
            .collect()
    }

    pub fn get_activity_summary(&self) -> ActivitySummary {
        let now = Utc::now();
        let day_ago = now - Duration::hours(24);
        let week_ago = now - Duration::days(7);

        let mut by_type: HashMap<String, u64> = HashMap::new();
        let mut by_server: HashMap<String, u64> = HashMap::new();
        let mut last_24h = 0u64;
        let mut last_7d = 0u64;

        for a in &self.activities {
            *by_type.entry(a.activity_type.to_string()).or_insert(0) += 1;
            if let Some(ref s) = a.server_name {
                *by_server.entry(s.clone()).or_insert(0) += 1;
            }
            if a.timestamp >= day_ago {
                last_24h += 1;
            }
            if a.timestamp >= week_ago {
                last_7d += 1;
            }
        }

        ActivitySummary {
            total: self.activities.len() as u64,
            by_type,
            by_server,
            last_24h,
            last_7d,
        }
    }

    pub fn clear_before(&mut self, timestamp: DateTime<Utc>) {
        self.activities.retain(|a| a.timestamp >= timestamp);
    }

    pub fn activity_count(&self) -> usize {
        self.activities.len()
    }
}

// ============================================================================
// 2. Cost Dashboard
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationCost {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub operation_type: String,
    pub duration_ms: u64,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeCostSummary {
    pub count: u64,
    pub total_duration_ms: u64,
    pub avg_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSummary {
    pub total_operations: u64,
    pub total_duration_ms: u64,
    pub by_type: HashMap<String, TypeCostSummary>,
    pub last_24h_operations: u64,
    pub last_7d_operations: u64,
    pub avg_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostDashboard {
    operation_costs: Vec<OperationCost>,
}

impl CostDashboard {
    pub fn new() -> Self {
        Self {
            operation_costs: Vec::new(),
        }
    }

    pub fn record_operation(&mut self, op_type: &str, duration_ms: u64, details: &str) {
        self.operation_costs.push(OperationCost {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            operation_type: op_type.to_string(),
            duration_ms,
            details: details.to_string(),
        });
    }

    pub fn get_summary(&self) -> CostSummary {
        let now = Utc::now();
        let day_ago = now - Duration::hours(24);
        let week_ago = now - Duration::days(7);

        let mut by_type: HashMap<String, TypeCostSummary> = HashMap::new();
        let mut total_duration_ms = 0u64;
        let mut last_24h_operations = 0u64;
        let mut last_7d_operations = 0u64;

        for op in &self.operation_costs {
            total_duration_ms += op.duration_ms;
            let entry = by_type
                .entry(op.operation_type.clone())
                .or_insert(TypeCostSummary {
                    count: 0,
                    total_duration_ms: 0,
                    avg_duration_ms: 0,
                });
            entry.count += 1;
            entry.total_duration_ms += op.duration_ms;
            if op.timestamp >= day_ago {
                last_24h_operations += 1;
            }
            if op.timestamp >= week_ago {
                last_7d_operations += 1;
            }
        }

        for entry in by_type.values_mut() {
            if entry.count > 0 {
                entry.avg_duration_ms = entry.total_duration_ms / entry.count;
            }
        }

        let total_operations = self.operation_costs.len() as u64;
        let avg_duration_ms = if total_operations > 0 {
            total_duration_ms / total_operations
        } else {
            0
        };

        CostSummary {
            total_operations,
            total_duration_ms,
            by_type,
            last_24h_operations,
            last_7d_operations,
            avg_duration_ms,
        }
    }

    pub fn get_recent(&self, count: usize) -> &[OperationCost] {
        let start = self.operation_costs.len().saturating_sub(count);
        &self.operation_costs[start..]
    }

    pub fn get_by_type(&self, op_type: &str) -> Vec<&OperationCost> {
        self.operation_costs
            .iter()
            .filter(|op| op.operation_type == op_type)
            .collect()
    }

    pub fn get_operations_in_range(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Vec<&OperationCost> {
        self.operation_costs
            .iter()
            .filter(|op| op.timestamp >= from && op.timestamp <= to)
            .collect()
    }

    pub fn operation_count(&self) -> usize {
        self.operation_costs.len()
    }
}

// ============================================================================
// 3. Accuracy Tracker
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccuracyTrend {
    Improving,
    Stable,
    Declining,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyRecord {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub assessment_type: String,
    pub agent_assessment: String,
    pub user_correction: Option<String>,
    pub was_correct: bool,
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeAccuracy {
    pub total: u64,
    pub correct: u64,
    pub accuracy_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyMetrics {
    pub total_assessments: u64,
    pub correct: u64,
    pub incorrect: u64,
    pub accuracy_rate: f64,
    pub by_type: HashMap<String, TypeAccuracy>,
    pub trend: AccuracyTrend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyTracker {
    assessments: Vec<AccuracyRecord>,
}

impl AccuracyTracker {
    pub fn new() -> Self {
        Self {
            assessments: Vec::new(),
        }
    }

    pub fn record_assessment(
        &mut self,
        assessment_type: &str,
        agent_assessment: &str,
        was_correct: bool,
        server_name: Option<String>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        self.assessments.push(AccuracyRecord {
            id,
            timestamp: Utc::now(),
            assessment_type: assessment_type.to_string(),
            agent_assessment: agent_assessment.to_string(),
            user_correction: None,
            was_correct,
            server_name,
        });
        id
    }

    pub fn record_correction(&mut self, id: Uuid, user_correction: &str) {
        if let Some(record) = self.assessments.iter_mut().find(|r| r.id == id) {
            record.user_correction = Some(user_correction.to_string());
            record.was_correct = false;
        }
    }

    pub fn get_metrics(&self) -> AccuracyMetrics {
        self.compute_metrics(&self.assessments)
    }

    pub fn get_metrics_for_period(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> AccuracyMetrics {
        let filtered: Vec<AccuracyRecord> = self
            .assessments
            .iter()
            .filter(|a| a.timestamp >= from && a.timestamp <= to)
            .cloned()
            .collect();
        self.compute_metrics(&filtered)
    }

    fn compute_metrics(&self, records: &[AccuracyRecord]) -> AccuracyMetrics {
        let total = records.len() as u64;
        let correct = records.iter().filter(|r| r.was_correct).count() as u64;
        let incorrect = total - correct;
        let accuracy_rate = if total > 0 {
            correct as f64 / total as f64
        } else {
            0.0
        };

        let mut by_type: HashMap<String, TypeAccuracy> = HashMap::new();
        for r in records {
            let entry = by_type
                .entry(r.assessment_type.clone())
                .or_insert(TypeAccuracy {
                    total: 0,
                    correct: 0,
                    accuracy_rate: 0.0,
                });
            entry.total += 1;
            if r.was_correct {
                entry.correct += 1;
            }
        }
        for entry in by_type.values_mut() {
            if entry.total > 0 {
                entry.accuracy_rate = entry.correct as f64 / entry.total as f64;
            }
        }

        let trend = self.compute_trend();

        AccuracyMetrics {
            total_assessments: total,
            correct,
            incorrect,
            accuracy_rate,
            by_type,
            trend,
        }
    }

    fn compute_trend(&self) -> AccuracyTrend {
        let len = self.assessments.len();
        if len < 10 {
            return AccuracyTrend::Stable;
        }
        let mid = len / 2;
        let first_half = &self.assessments[..mid];
        let second_half = &self.assessments[mid..];

        let first_rate =
            first_half.iter().filter(|r| r.was_correct).count() as f64 / first_half.len() as f64;
        let second_rate =
            second_half.iter().filter(|r| r.was_correct).count() as f64 / second_half.len() as f64;

        let diff = second_rate - first_rate;
        if diff > 0.05 {
            AccuracyTrend::Improving
        } else if diff < -0.05 {
            AccuracyTrend::Declining
        } else {
            AccuracyTrend::Stable
        }
    }

    pub fn get_by_type(&self, assessment_type: &str) -> Vec<&AccuracyRecord> {
        self.assessments
            .iter()
            .filter(|a| a.assessment_type == assessment_type)
            .collect()
    }

    pub fn get_recent(&self, count: usize) -> &[AccuracyRecord] {
        let start = self.assessments.len().saturating_sub(count);
        &self.assessments[start..]
    }

    pub fn assessment_count(&self) -> usize {
        self.assessments.len()
    }
}

// ============================================================================
// 4. Knowledge Base Viewer
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedPattern {
    pub id: Uuid,
    pub pattern: String,
    pub category: String,
    pub learned_from: String,
    pub confidence: f64,
    pub times_seen: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafePattern {
    pub pattern: String,
    pub server_name: Option<String>,
    pub dismissal_count: u32,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskPattern {
    pub pattern: String,
    pub risk_level: String,
    pub detection_count: u32,
    pub last_detected: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStats {
    pub total_learned: u64,
    pub safe_count: u64,
    pub risk_count: u64,
    pub by_category: HashMap<String, u64>,
    pub by_server: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeBaseViewer {
    learned_patterns: Vec<LearnedPattern>,
    safe_patterns: Vec<SafePattern>,
    risk_patterns: Vec<RiskPattern>,
}

impl KnowledgeBaseViewer {
    pub fn new() -> Self {
        Self {
            learned_patterns: Vec::new(),
            safe_patterns: Vec::new(),
            risk_patterns: Vec::new(),
        }
    }

    pub fn add_learned_pattern(&mut self, pattern: LearnedPattern) -> Uuid {
        let id = pattern.id;
        self.learned_patterns.push(pattern);
        id
    }

    pub fn add_safe_pattern(
        &mut self,
        pattern: &str,
        server_name: Option<String>,
        dismissal_count: u32,
    ) {
        self.safe_patterns.push(SafePattern {
            pattern: pattern.to_string(),
            server_name,
            dismissal_count,
            added_at: Utc::now(),
        });
    }

    pub fn add_risk_pattern(&mut self, pattern: &str, risk_level: &str) {
        self.risk_patterns.push(RiskPattern {
            pattern: pattern.to_string(),
            risk_level: risk_level.to_string(),
            detection_count: 1,
            last_detected: Utc::now(),
        });
    }

    pub fn get_all_patterns(&self) -> &[LearnedPattern] {
        &self.learned_patterns
    }

    pub fn get_safe_patterns(&self) -> &[SafePattern] {
        &self.safe_patterns
    }

    pub fn get_risk_patterns(&self) -> &[RiskPattern] {
        &self.risk_patterns
    }

    pub fn search_patterns(&self, query: &str) -> Vec<&LearnedPattern> {
        let query_lower = query.to_lowercase();
        self.learned_patterns
            .iter()
            .filter(|p| {
                p.pattern.to_lowercase().contains(&query_lower)
                    || p.category.to_lowercase().contains(&query_lower)
                    || p.learned_from.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    pub fn get_pattern_stats(&self) -> PatternStats {
        let mut by_category: HashMap<String, u64> = HashMap::new();
        let mut by_server: HashMap<String, u64> = HashMap::new();

        for p in &self.learned_patterns {
            *by_category.entry(p.category.clone()).or_insert(0) += 1;
            if let Some(ref s) = p.server_name {
                *by_server.entry(s.clone()).or_insert(0) += 1;
            }
        }

        PatternStats {
            total_learned: self.learned_patterns.len() as u64,
            safe_count: self.safe_patterns.len() as u64,
            risk_count: self.risk_patterns.len() as u64,
            by_category,
            by_server,
        }
    }

    pub fn remove_pattern(&mut self, id: Uuid) -> bool {
        let len_before = self.learned_patterns.len();
        self.learned_patterns.retain(|p| p.id != id);
        self.learned_patterns.len() < len_before
    }
}

// ============================================================================
// 5. Autonomy Audit Trail
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditEntryType {
    PermissionRequested,
    PermissionGranted,
    PermissionDenied,
    ActionExecuted,
    ActionBlocked,
    CountdownStarted,
    CountdownCancelled,
    LevelEscalated,
    LevelDowngraded,
    LockdownActivated,
    LockdownDeactivated,
}

impl std::fmt::Display for AuditEntryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub entry_type: AuditEntryType,
    pub autonomy_level: String,
    pub action_category: Option<String>,
    pub server_name: Option<String>,
    pub description: String,
    pub user_response: Option<String>,
    pub result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_entries: u64,
    pub permissions_requested: u64,
    pub permissions_granted: u64,
    pub permissions_denied: u64,
    pub actions_executed: u64,
    pub actions_blocked: u64,
    pub lockdowns_activated: u64,
    pub level_changes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyAuditTrail {
    entries: Vec<AuditEntry>,
}

impl AutonomyAuditTrail {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn record(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }

    pub fn get_recent(&self, count: usize) -> &[AuditEntry] {
        let start = self.entries.len().saturating_sub(count);
        &self.entries[start..]
    }

    pub fn get_by_type(&self, entry_type: &AuditEntryType) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| &e.entry_type == entry_type)
            .collect()
    }

    pub fn get_by_level(&self, level: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.autonomy_level == level)
            .collect()
    }

    pub fn get_audit_summary(&self) -> AuditSummary {
        let mut summary = AuditSummary {
            total_entries: self.entries.len() as u64,
            permissions_requested: 0,
            permissions_granted: 0,
            permissions_denied: 0,
            actions_executed: 0,
            actions_blocked: 0,
            lockdowns_activated: 0,
            level_changes: 0,
        };

        for e in &self.entries {
            match e.entry_type {
                AuditEntryType::PermissionRequested => summary.permissions_requested += 1,
                AuditEntryType::PermissionGranted => summary.permissions_granted += 1,
                AuditEntryType::PermissionDenied => summary.permissions_denied += 1,
                AuditEntryType::ActionExecuted => summary.actions_executed += 1,
                AuditEntryType::ActionBlocked => summary.actions_blocked += 1,
                AuditEntryType::LockdownActivated => summary.lockdowns_activated += 1,
                AuditEntryType::LevelEscalated | AuditEntryType::LevelDowngraded => {
                    summary.level_changes += 1
                }
                _ => {}
            }
        }

        summary
    }

    pub fn get_entries_in_range(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= from && e.timestamp <= to)
            .collect()
    }

    pub fn export_audit_log(&self) -> Vec<AuditEntry> {
        self.entries.clone()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ============================================================================
// 6. Decision Explainer
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionFactor {
    pub name: String,
    pub value: String,
    pub weight: f64,
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionExplanation {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub decision_type: String,
    pub input_summary: String,
    pub reasoning: Vec<String>,
    pub conclusion: String,
    pub confidence: f64,
    pub factors: Vec<DecisionFactor>,
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionExplainer {
    explanations: Vec<DecisionExplanation>,
}

impl DecisionExplainer {
    pub fn new() -> Self {
        Self {
            explanations: Vec::new(),
        }
    }

    pub fn record_explanation(&mut self, explanation: DecisionExplanation) {
        self.explanations.push(explanation);
    }

    pub fn get_recent(&self, count: usize) -> &[DecisionExplanation] {
        let start = self.explanations.len().saturating_sub(count);
        &self.explanations[start..]
    }

    pub fn get_by_type(&self, decision_type: &str) -> Vec<&DecisionExplanation> {
        self.explanations
            .iter()
            .filter(|e| e.decision_type == decision_type)
            .collect()
    }

    pub fn get_by_server(&self, server: &str) -> Vec<&DecisionExplanation> {
        self.explanations
            .iter()
            .filter(|e| e.server_name.as_deref() == Some(server))
            .collect()
    }

    pub fn get_explanation(&self, id: Uuid) -> Option<&DecisionExplanation> {
        self.explanations.iter().find(|e| e.id == id)
    }

    pub fn search_explanations(&self, query: &str) -> Vec<&DecisionExplanation> {
        let query_lower = query.to_lowercase();
        self.explanations
            .iter()
            .filter(|e| {
                e.input_summary.to_lowercase().contains(&query_lower)
                    || e.conclusion.to_lowercase().contains(&query_lower)
                    || e.reasoning
                        .iter()
                        .any(|r| r.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    pub fn explanation_count(&self) -> usize {
        self.explanations.len()
    }
}

// ============================================================================
// 7. Transparency Dashboard (aggregator)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub activity_summary: ActivitySummary,
    pub cost_summary: CostSummary,
    pub accuracy_metrics: AccuracyMetrics,
    pub pattern_stats: PatternStats,
    pub audit_summary: AuditSummary,
    pub recent_decisions: Vec<DecisionExplanation>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyDashboard {
    pub activity_tracker: AgentActivityTracker,
    pub cost_dashboard: CostDashboard,
    pub accuracy_tracker: AccuracyTracker,
    pub knowledge_viewer: KnowledgeBaseViewer,
    pub audit_trail: AutonomyAuditTrail,
    pub decision_explainer: DecisionExplainer,
}

impl TransparencyDashboard {
    pub fn new() -> Self {
        Self {
            activity_tracker: AgentActivityTracker::new(),
            cost_dashboard: CostDashboard::new(),
            accuracy_tracker: AccuracyTracker::new(),
            knowledge_viewer: KnowledgeBaseViewer::new(),
            audit_trail: AutonomyAuditTrail::new(),
            decision_explainer: DecisionExplainer::new(),
        }
    }

    pub fn get_dashboard_summary(&self) -> DashboardSummary {
        DashboardSummary {
            activity_summary: self.activity_tracker.get_activity_summary(),
            cost_summary: self.cost_dashboard.get_summary(),
            accuracy_metrics: self.accuracy_tracker.get_metrics(),
            pattern_stats: self.knowledge_viewer.get_pattern_stats(),
            audit_summary: self.audit_trail.get_audit_summary(),
            recent_decisions: self
                .decision_explainer
                .get_recent(10)
                .iter()
                .cloned()
                .collect(),
            generated_at: Utc::now(),
        }
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(data_dir).map_err(|e| format!("Failed to create dir: {e}"))?;
        let path = data_dir.join("transparency_dashboard.json");
        let json =
            serde_json::to_string_pretty(self).map_err(|e| format!("Serialize error: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("Write error: {e}"))?;
        Ok(())
    }

    pub fn load(data_dir: &Path) -> Result<Self, String> {
        let path = data_dir.join("transparency_dashboard.json");
        let json = std::fs::read_to_string(&path).map_err(|e| format!("Read error: {e}"))?;
        let dashboard: Self =
            serde_json::from_str(&json).map_err(|e| format!("Deserialize error: {e}"))?;
        Ok(dashboard)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // --- Helpers ---

    fn make_activity(activity_type: ActivityType, server: Option<&str>) -> AgentActivity {
        AgentActivity {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            activity_type,
            description: "test activity".to_string(),
            server_name: server.map(|s| s.to_string()),
            autonomy_level: "supervised".to_string(),
            risk_level: Some("low".to_string()),
            outcome: Some("success".to_string()),
            details: serde_json::json!({"key": "value"}),
        }
    }

    fn make_activity_at(
        activity_type: ActivityType,
        server: Option<&str>,
        ts: DateTime<Utc>,
    ) -> AgentActivity {
        let mut a = make_activity(activity_type, server);
        a.timestamp = ts;
        a
    }

    fn make_audit_entry(entry_type: AuditEntryType, level: &str) -> AuditEntry {
        AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            entry_type,
            autonomy_level: level.to_string(),
            action_category: Some("network".to_string()),
            server_name: Some("web-01".to_string()),
            description: "audit event".to_string(),
            user_response: None,
            result: None,
        }
    }

    fn make_learned_pattern(category: &str, server: Option<&str>) -> LearnedPattern {
        LearnedPattern {
            id: Uuid::new_v4(),
            pattern: format!("pattern-{}", category),
            category: category.to_string(),
            learned_from: "test_source".to_string(),
            confidence: 0.85,
            times_seen: 3,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            server_name: server.map(|s| s.to_string()),
        }
    }

    fn make_decision(decision_type: &str, server: Option<&str>) -> DecisionExplanation {
        DecisionExplanation {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            decision_type: decision_type.to_string(),
            input_summary: "some input data".to_string(),
            reasoning: vec!["reason one".to_string(), "reason two".to_string()],
            conclusion: "block the request".to_string(),
            confidence: 0.9,
            factors: vec![DecisionFactor {
                name: "severity".to_string(),
                value: "high".to_string(),
                weight: 0.8,
                direction: "negative".to_string(),
            }],
            server_name: server.map(|s| s.to_string()),
        }
    }

    // =========================================================================
    // AgentActivityTracker tests
    // =========================================================================

    #[test]
    fn test_activity_tracker_new() {
        let tracker = AgentActivityTracker::new();
        assert_eq!(tracker.activity_count(), 0);
    }

    #[test]
    fn test_activity_tracker_record_and_count() {
        let mut tracker = AgentActivityTracker::new();
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, Some("web-01")));
        tracker.record_activity(make_activity(ActivityType::ActionBlocked, None));
        assert_eq!(tracker.activity_count(), 2);
    }

    #[test]
    fn test_activity_tracker_get_recent() {
        let mut tracker = AgentActivityTracker::new();
        for _ in 0..5 {
            tracker.record_activity(make_activity(ActivityType::ActionExecuted, None));
        }
        assert_eq!(tracker.get_recent(3).len(), 3);
        assert_eq!(tracker.get_recent(10).len(), 5);
        assert_eq!(tracker.get_recent(0).len(), 0);
    }

    #[test]
    fn test_activity_tracker_get_by_type() {
        let mut tracker = AgentActivityTracker::new();
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, None));
        tracker.record_activity(make_activity(ActivityType::ActionBlocked, None));
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, None));

        let executed = tracker.get_by_type(&ActivityType::ActionExecuted);
        assert_eq!(executed.len(), 2);
        let blocked = tracker.get_by_type(&ActivityType::ActionBlocked);
        assert_eq!(blocked.len(), 1);
    }

    #[test]
    fn test_activity_tracker_get_by_server() {
        let mut tracker = AgentActivityTracker::new();
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, Some("web-01")));
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, Some("db-01")));
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, Some("web-01")));
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, None));

        assert_eq!(tracker.get_by_server("web-01").len(), 2);
        assert_eq!(tracker.get_by_server("db-01").len(), 1);
        assert_eq!(tracker.get_by_server("unknown").len(), 0);
    }

    #[test]
    fn test_activity_tracker_get_by_time_range() {
        let mut tracker = AgentActivityTracker::new();
        let now = Utc::now();
        tracker.record_activity(make_activity_at(
            ActivityType::ActionExecuted,
            None,
            now - Duration::hours(5),
        ));
        tracker.record_activity(make_activity_at(
            ActivityType::ActionExecuted,
            None,
            now - Duration::hours(2),
        ));
        tracker.record_activity(make_activity_at(
            ActivityType::ActionExecuted,
            None,
            now - Duration::minutes(30),
        ));

        let range = tracker.get_by_time_range(now - Duration::hours(3), now);
        assert_eq!(range.len(), 2);
    }

    #[test]
    fn test_activity_tracker_summary() {
        let mut tracker = AgentActivityTracker::new();
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, Some("web-01")));
        tracker.record_activity(make_activity(ActivityType::ActionBlocked, Some("db-01")));
        tracker.record_activity(make_activity(ActivityType::ReportGenerated, Some("web-01")));

        let summary = tracker.get_activity_summary();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.by_type.len(), 3);
        assert_eq!(summary.by_server.len(), 2);
        assert_eq!(summary.last_24h, 3);
        assert_eq!(summary.last_7d, 3);
    }

    #[test]
    fn test_activity_tracker_summary_empty() {
        let tracker = AgentActivityTracker::new();
        let summary = tracker.get_activity_summary();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.last_24h, 0);
        assert_eq!(summary.last_7d, 0);
    }

    #[test]
    fn test_activity_tracker_clear_before() {
        let mut tracker = AgentActivityTracker::new();
        let now = Utc::now();
        tracker.record_activity(make_activity_at(
            ActivityType::ActionExecuted,
            None,
            now - Duration::hours(48),
        ));
        tracker.record_activity(make_activity_at(
            ActivityType::ActionExecuted,
            None,
            now - Duration::hours(1),
        ));
        assert_eq!(tracker.activity_count(), 2);
        tracker.clear_before(now - Duration::hours(24));
        assert_eq!(tracker.activity_count(), 1);
    }

    #[test]
    fn test_activity_tracker_clear_all() {
        let mut tracker = AgentActivityTracker::new();
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, None));
        tracker.clear_before(Utc::now() + Duration::hours(1));
        assert_eq!(tracker.activity_count(), 0);
    }

    // =========================================================================
    // CostDashboard tests
    // =========================================================================

    #[test]
    fn test_cost_dashboard_new() {
        let cd = CostDashboard::new();
        assert_eq!(cd.operation_count(), 0);
    }

    #[test]
    fn test_cost_dashboard_record_and_count() {
        let mut cd = CostDashboard::new();
        cd.record_operation("scan", 150, "port scan");
        cd.record_operation("analysis", 300, "deep analysis");
        assert_eq!(cd.operation_count(), 2);
    }

    #[test]
    fn test_cost_dashboard_get_recent() {
        let mut cd = CostDashboard::new();
        for i in 0..5 {
            cd.record_operation("scan", i * 100, "scan op");
        }
        assert_eq!(cd.get_recent(3).len(), 3);
        assert_eq!(cd.get_recent(10).len(), 5);
    }

    #[test]
    fn test_cost_dashboard_get_by_type() {
        let mut cd = CostDashboard::new();
        cd.record_operation("scan", 100, "s1");
        cd.record_operation("analysis", 200, "a1");
        cd.record_operation("scan", 150, "s2");

        assert_eq!(cd.get_by_type("scan").len(), 2);
        assert_eq!(cd.get_by_type("analysis").len(), 1);
        assert_eq!(cd.get_by_type("unknown").len(), 0);
    }

    #[test]
    fn test_cost_dashboard_summary() {
        let mut cd = CostDashboard::new();
        cd.record_operation("scan", 100, "s1");
        cd.record_operation("scan", 200, "s2");
        cd.record_operation("analysis", 300, "a1");

        let summary = cd.get_summary();
        assert_eq!(summary.total_operations, 3);
        assert_eq!(summary.total_duration_ms, 600);
        assert_eq!(summary.avg_duration_ms, 200);
        assert_eq!(summary.by_type.len(), 2);
        assert_eq!(summary.by_type["scan"].count, 2);
        assert_eq!(summary.by_type["scan"].total_duration_ms, 300);
        assert_eq!(summary.by_type["scan"].avg_duration_ms, 150);
    }

    #[test]
    fn test_cost_dashboard_summary_empty() {
        let cd = CostDashboard::new();
        let summary = cd.get_summary();
        assert_eq!(summary.total_operations, 0);
        assert_eq!(summary.avg_duration_ms, 0);
    }

    #[test]
    fn test_cost_dashboard_operations_in_range() {
        let mut cd = CostDashboard::new();
        cd.record_operation("scan", 100, "s1");
        let now = Utc::now();
        let results =
            cd.get_operations_in_range(now - Duration::hours(1), now + Duration::hours(1));
        assert_eq!(results.len(), 1);
        let empty = cd.get_operations_in_range(now - Duration::hours(10), now - Duration::hours(5));
        assert_eq!(empty.len(), 0);
    }

    // =========================================================================
    // AccuracyTracker tests
    // =========================================================================

    #[test]
    fn test_accuracy_tracker_new() {
        let at = AccuracyTracker::new();
        assert_eq!(at.assessment_count(), 0);
    }

    #[test]
    fn test_accuracy_tracker_record() {
        let mut at = AccuracyTracker::new();
        let id = at.record_assessment("threat", "malicious", true, Some("web-01".to_string()));
        assert_eq!(at.assessment_count(), 1);
        assert!(!id.is_nil());
    }

    #[test]
    fn test_accuracy_tracker_correction() {
        let mut at = AccuracyTracker::new();
        let id = at.record_assessment("threat", "malicious", true, None);
        at.record_correction(id, "actually benign");
        let record = at.get_recent(1).first().unwrap();
        assert!(!record.was_correct);
        assert_eq!(record.user_correction.as_deref(), Some("actually benign"));
    }

    #[test]
    fn test_accuracy_tracker_correction_nonexistent() {
        let mut at = AccuracyTracker::new();
        at.record_correction(Uuid::new_v4(), "no match");
        assert_eq!(at.assessment_count(), 0);
    }

    #[test]
    fn test_accuracy_tracker_metrics() {
        let mut at = AccuracyTracker::new();
        at.record_assessment("threat", "malicious", true, None);
        at.record_assessment("threat", "benign", false, None);
        at.record_assessment("anomaly", "suspicious", true, None);

        let metrics = at.get_metrics();
        assert_eq!(metrics.total_assessments, 3);
        assert_eq!(metrics.correct, 2);
        assert_eq!(metrics.incorrect, 1);
        assert!((metrics.accuracy_rate - 2.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn test_accuracy_tracker_metrics_empty() {
        let at = AccuracyTracker::new();
        let metrics = at.get_metrics();
        assert_eq!(metrics.total_assessments, 0);
        assert_eq!(metrics.accuracy_rate, 0.0);
    }

    #[test]
    fn test_accuracy_tracker_metrics_by_type() {
        let mut at = AccuracyTracker::new();
        at.record_assessment("threat", "m", true, None);
        at.record_assessment("threat", "b", false, None);
        at.record_assessment("anomaly", "s", true, None);

        let metrics = at.get_metrics();
        assert_eq!(metrics.by_type["threat"].total, 2);
        assert_eq!(metrics.by_type["threat"].correct, 1);
        assert_eq!(metrics.by_type["anomaly"].total, 1);
        assert_eq!(metrics.by_type["anomaly"].correct, 1);
    }

    #[test]
    fn test_accuracy_tracker_trend_stable_few_records() {
        let mut at = AccuracyTracker::new();
        for _ in 0..5 {
            at.record_assessment("t", "a", true, None);
        }
        let metrics = at.get_metrics();
        assert_eq!(metrics.trend, AccuracyTrend::Stable);
    }

    #[test]
    fn test_accuracy_tracker_trend_improving() {
        let mut at = AccuracyTracker::new();
        // First half: mostly wrong
        for _ in 0..10 {
            at.record_assessment("t", "a", false, None);
        }
        // Second half: mostly right
        for _ in 0..10 {
            at.record_assessment("t", "a", true, None);
        }
        let metrics = at.get_metrics();
        assert_eq!(metrics.trend, AccuracyTrend::Improving);
    }

    #[test]
    fn test_accuracy_tracker_trend_declining() {
        let mut at = AccuracyTracker::new();
        // First half: mostly right
        for _ in 0..10 {
            at.record_assessment("t", "a", true, None);
        }
        // Second half: mostly wrong
        for _ in 0..10 {
            at.record_assessment("t", "a", false, None);
        }
        let metrics = at.get_metrics();
        assert_eq!(metrics.trend, AccuracyTrend::Declining);
    }

    #[test]
    fn test_accuracy_tracker_get_by_type() {
        let mut at = AccuracyTracker::new();
        at.record_assessment("threat", "a", true, None);
        at.record_assessment("anomaly", "b", true, None);
        at.record_assessment("threat", "c", false, None);

        assert_eq!(at.get_by_type("threat").len(), 2);
        assert_eq!(at.get_by_type("anomaly").len(), 1);
        assert_eq!(at.get_by_type("missing").len(), 0);
    }

    #[test]
    fn test_accuracy_tracker_get_recent() {
        let mut at = AccuracyTracker::new();
        for _ in 0..5 {
            at.record_assessment("t", "a", true, None);
        }
        assert_eq!(at.get_recent(3).len(), 3);
        assert_eq!(at.get_recent(10).len(), 5);
    }

    #[test]
    fn test_accuracy_tracker_metrics_for_period() {
        let mut at = AccuracyTracker::new();
        at.record_assessment("t", "a", true, None);
        at.record_assessment("t", "b", false, None);

        let now = Utc::now();
        let metrics = at.get_metrics_for_period(now - Duration::hours(1), now + Duration::hours(1));
        assert_eq!(metrics.total_assessments, 2);

        let empty_metrics =
            at.get_metrics_for_period(now - Duration::hours(10), now - Duration::hours(5));
        assert_eq!(empty_metrics.total_assessments, 0);
    }

    // =========================================================================
    // KnowledgeBaseViewer tests
    // =========================================================================

    #[test]
    fn test_knowledge_base_viewer_new() {
        let kb = KnowledgeBaseViewer::new();
        assert_eq!(kb.get_all_patterns().len(), 0);
        assert_eq!(kb.get_safe_patterns().len(), 0);
        assert_eq!(kb.get_risk_patterns().len(), 0);
    }

    #[test]
    fn test_knowledge_base_add_learned_pattern() {
        let mut kb = KnowledgeBaseViewer::new();
        let p = make_learned_pattern("intrusion", Some("web-01"));
        let id = kb.add_learned_pattern(p);
        assert!(!id.is_nil());
        assert_eq!(kb.get_all_patterns().len(), 1);
    }

    #[test]
    fn test_knowledge_base_add_safe_pattern() {
        let mut kb = KnowledgeBaseViewer::new();
        kb.add_safe_pattern("cron job", Some("web-01".to_string()), 5);
        assert_eq!(kb.get_safe_patterns().len(), 1);
        assert_eq!(kb.get_safe_patterns()[0].dismissal_count, 5);
    }

    #[test]
    fn test_knowledge_base_add_risk_pattern() {
        let mut kb = KnowledgeBaseViewer::new();
        kb.add_risk_pattern("brute force SSH", "critical");
        assert_eq!(kb.get_risk_patterns().len(), 1);
        assert_eq!(kb.get_risk_patterns()[0].risk_level, "critical");
    }

    #[test]
    fn test_knowledge_base_search_patterns() {
        let mut kb = KnowledgeBaseViewer::new();
        kb.add_learned_pattern(make_learned_pattern("intrusion", None));
        kb.add_learned_pattern(make_learned_pattern("anomaly", None));
        kb.add_learned_pattern(make_learned_pattern("intrusion_detection", None));

        let results = kb.search_patterns("intrusion");
        assert_eq!(results.len(), 2);

        let results2 = kb.search_patterns("ANOMALY");
        assert_eq!(results2.len(), 1);

        let results3 = kb.search_patterns("nonexistent");
        assert_eq!(results3.len(), 0);
    }

    #[test]
    fn test_knowledge_base_pattern_stats() {
        let mut kb = KnowledgeBaseViewer::new();
        kb.add_learned_pattern(make_learned_pattern("intrusion", Some("web-01")));
        kb.add_learned_pattern(make_learned_pattern("anomaly", Some("db-01")));
        kb.add_learned_pattern(make_learned_pattern("intrusion", Some("web-01")));
        kb.add_safe_pattern("safe1", None, 1);
        kb.add_risk_pattern("risk1", "high");

        let stats = kb.get_pattern_stats();
        assert_eq!(stats.total_learned, 3);
        assert_eq!(stats.safe_count, 1);
        assert_eq!(stats.risk_count, 1);
        assert_eq!(stats.by_category["intrusion"], 2);
        assert_eq!(stats.by_category["anomaly"], 1);
        assert_eq!(stats.by_server["web-01"], 2);
        assert_eq!(stats.by_server["db-01"], 1);
    }

    #[test]
    fn test_knowledge_base_remove_pattern() {
        let mut kb = KnowledgeBaseViewer::new();
        let p = make_learned_pattern("test", None);
        let id = p.id;
        kb.add_learned_pattern(p);
        assert!(kb.remove_pattern(id));
        assert_eq!(kb.get_all_patterns().len(), 0);
    }

    #[test]
    fn test_knowledge_base_remove_nonexistent() {
        let mut kb = KnowledgeBaseViewer::new();
        assert!(!kb.remove_pattern(Uuid::new_v4()));
    }

    // =========================================================================
    // AutonomyAuditTrail tests
    // =========================================================================

    #[test]
    fn test_audit_trail_new() {
        let trail = AutonomyAuditTrail::new();
        assert_eq!(trail.entry_count(), 0);
    }

    #[test]
    fn test_audit_trail_record_and_count() {
        let mut trail = AutonomyAuditTrail::new();
        trail.record(make_audit_entry(
            AuditEntryType::PermissionRequested,
            "supervised",
        ));
        trail.record(make_audit_entry(
            AuditEntryType::ActionExecuted,
            "autonomous",
        ));
        assert_eq!(trail.entry_count(), 2);
    }

    #[test]
    fn test_audit_trail_get_recent() {
        let mut trail = AutonomyAuditTrail::new();
        for _ in 0..5 {
            trail.record(make_audit_entry(
                AuditEntryType::ActionExecuted,
                "supervised",
            ));
        }
        assert_eq!(trail.get_recent(3).len(), 3);
        assert_eq!(trail.get_recent(10).len(), 5);
    }

    #[test]
    fn test_audit_trail_get_by_type() {
        let mut trail = AutonomyAuditTrail::new();
        trail.record(make_audit_entry(
            AuditEntryType::PermissionRequested,
            "supervised",
        ));
        trail.record(make_audit_entry(
            AuditEntryType::PermissionGranted,
            "supervised",
        ));
        trail.record(make_audit_entry(
            AuditEntryType::PermissionRequested,
            "supervised",
        ));

        assert_eq!(
            trail
                .get_by_type(&AuditEntryType::PermissionRequested)
                .len(),
            2
        );
        assert_eq!(
            trail.get_by_type(&AuditEntryType::PermissionGranted).len(),
            1
        );
    }

    #[test]
    fn test_audit_trail_get_by_level() {
        let mut trail = AutonomyAuditTrail::new();
        trail.record(make_audit_entry(
            AuditEntryType::ActionExecuted,
            "supervised",
        ));
        trail.record(make_audit_entry(
            AuditEntryType::ActionExecuted,
            "autonomous",
        ));
        trail.record(make_audit_entry(
            AuditEntryType::ActionExecuted,
            "supervised",
        ));

        assert_eq!(trail.get_by_level("supervised").len(), 2);
        assert_eq!(trail.get_by_level("autonomous").len(), 1);
        assert_eq!(trail.get_by_level("unknown").len(), 0);
    }

    #[test]
    fn test_audit_trail_summary() {
        let mut trail = AutonomyAuditTrail::new();
        trail.record(make_audit_entry(AuditEntryType::PermissionRequested, "s"));
        trail.record(make_audit_entry(AuditEntryType::PermissionGranted, "s"));
        trail.record(make_audit_entry(AuditEntryType::PermissionDenied, "s"));
        trail.record(make_audit_entry(AuditEntryType::ActionExecuted, "s"));
        trail.record(make_audit_entry(AuditEntryType::ActionBlocked, "s"));
        trail.record(make_audit_entry(AuditEntryType::LockdownActivated, "s"));
        trail.record(make_audit_entry(AuditEntryType::LevelEscalated, "s"));
        trail.record(make_audit_entry(AuditEntryType::LevelDowngraded, "s"));

        let summary = trail.get_audit_summary();
        assert_eq!(summary.total_entries, 8);
        assert_eq!(summary.permissions_requested, 1);
        assert_eq!(summary.permissions_granted, 1);
        assert_eq!(summary.permissions_denied, 1);
        assert_eq!(summary.actions_executed, 1);
        assert_eq!(summary.actions_blocked, 1);
        assert_eq!(summary.lockdowns_activated, 1);
        assert_eq!(summary.level_changes, 2);
    }

    #[test]
    fn test_audit_trail_summary_empty() {
        let trail = AutonomyAuditTrail::new();
        let summary = trail.get_audit_summary();
        assert_eq!(summary.total_entries, 0);
    }

    #[test]
    fn test_audit_trail_entries_in_range() {
        let mut trail = AutonomyAuditTrail::new();
        trail.record(make_audit_entry(AuditEntryType::ActionExecuted, "s"));
        let now = Utc::now();
        let results =
            trail.get_entries_in_range(now - Duration::hours(1), now + Duration::hours(1));
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_audit_trail_export() {
        let mut trail = AutonomyAuditTrail::new();
        trail.record(make_audit_entry(AuditEntryType::ActionExecuted, "s"));
        trail.record(make_audit_entry(AuditEntryType::ActionBlocked, "s"));
        let exported = trail.export_audit_log();
        assert_eq!(exported.len(), 2);
    }

    // =========================================================================
    // DecisionExplainer tests
    // =========================================================================

    #[test]
    fn test_decision_explainer_new() {
        let de = DecisionExplainer::new();
        assert_eq!(de.explanation_count(), 0);
    }

    #[test]
    fn test_decision_explainer_record() {
        let mut de = DecisionExplainer::new();
        de.record_explanation(make_decision("threat_analysis", Some("web-01")));
        assert_eq!(de.explanation_count(), 1);
    }

    #[test]
    fn test_decision_explainer_get_recent() {
        let mut de = DecisionExplainer::new();
        for _ in 0..5 {
            de.record_explanation(make_decision("analysis", None));
        }
        assert_eq!(de.get_recent(3).len(), 3);
        assert_eq!(de.get_recent(10).len(), 5);
    }

    #[test]
    fn test_decision_explainer_get_by_type() {
        let mut de = DecisionExplainer::new();
        de.record_explanation(make_decision("threat", None));
        de.record_explanation(make_decision("anomaly", None));
        de.record_explanation(make_decision("threat", None));

        assert_eq!(de.get_by_type("threat").len(), 2);
        assert_eq!(de.get_by_type("anomaly").len(), 1);
        assert_eq!(de.get_by_type("missing").len(), 0);
    }

    #[test]
    fn test_decision_explainer_get_by_server() {
        let mut de = DecisionExplainer::new();
        de.record_explanation(make_decision("t", Some("web-01")));
        de.record_explanation(make_decision("t", Some("db-01")));
        de.record_explanation(make_decision("t", None));

        assert_eq!(de.get_by_server("web-01").len(), 1);
        assert_eq!(de.get_by_server("db-01").len(), 1);
        assert_eq!(de.get_by_server("unknown").len(), 0);
    }

    #[test]
    fn test_decision_explainer_get_by_id() {
        let mut de = DecisionExplainer::new();
        let d = make_decision("threat", None);
        let id = d.id;
        de.record_explanation(d);
        assert!(de.get_explanation(id).is_some());
        assert!(de.get_explanation(Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_decision_explainer_search() {
        let mut de = DecisionExplainer::new();
        let mut d1 = make_decision("t", None);
        d1.conclusion = "block the malicious request".to_string();
        de.record_explanation(d1);

        let mut d2 = make_decision("t", None);
        d2.conclusion = "allow normal traffic".to_string();
        de.record_explanation(d2);

        let mut d3 = make_decision("t", None);
        d3.input_summary = "malicious payload detected".to_string();
        de.record_explanation(d3);

        assert_eq!(de.search_explanations("malicious").len(), 2);
        assert_eq!(de.search_explanations("normal").len(), 1);
        assert_eq!(de.search_explanations("xyz").len(), 0);
    }

    #[test]
    fn test_decision_explainer_search_in_reasoning() {
        let mut de = DecisionExplainer::new();
        let mut d = make_decision("t", None);
        d.reasoning = vec!["special keyword here".to_string()];
        de.record_explanation(d);
        assert_eq!(de.search_explanations("special keyword").len(), 1);
    }

    // =========================================================================
    // TransparencyDashboard tests
    // =========================================================================

    #[test]
    fn test_dashboard_new() {
        let db = TransparencyDashboard::new();
        assert_eq!(db.activity_tracker.activity_count(), 0);
        assert_eq!(db.cost_dashboard.operation_count(), 0);
        assert_eq!(db.accuracy_tracker.assessment_count(), 0);
        assert_eq!(db.audit_trail.entry_count(), 0);
        assert_eq!(db.decision_explainer.explanation_count(), 0);
    }

    #[test]
    fn test_dashboard_summary() {
        let mut db = TransparencyDashboard::new();
        db.activity_tracker
            .record_activity(make_activity(ActivityType::ActionExecuted, Some("web-01")));
        db.cost_dashboard.record_operation("scan", 100, "s1");
        db.accuracy_tracker
            .record_assessment("threat", "m", true, None);
        db.audit_trail.record(make_audit_entry(
            AuditEntryType::ActionExecuted,
            "supervised",
        ));
        db.decision_explainer
            .record_explanation(make_decision("threat", None));

        let summary = db.get_dashboard_summary();
        assert_eq!(summary.activity_summary.total, 1);
        assert_eq!(summary.cost_summary.total_operations, 1);
        assert_eq!(summary.accuracy_metrics.total_assessments, 1);
        assert_eq!(summary.audit_summary.total_entries, 1);
        assert_eq!(summary.recent_decisions.len(), 1);
    }

    #[test]
    fn test_dashboard_summary_empty() {
        let db = TransparencyDashboard::new();
        let summary = db.get_dashboard_summary();
        assert_eq!(summary.activity_summary.total, 0);
        assert_eq!(summary.cost_summary.total_operations, 0);
        assert_eq!(summary.accuracy_metrics.total_assessments, 0);
        assert_eq!(summary.audit_summary.total_entries, 0);
        assert_eq!(summary.recent_decisions.len(), 0);
    }

    #[test]
    fn test_dashboard_save_and_load() {
        let mut db = TransparencyDashboard::new();
        db.activity_tracker
            .record_activity(make_activity(ActivityType::ActionExecuted, Some("web-01")));
        db.cost_dashboard.record_operation("scan", 100, "s1");
        db.accuracy_tracker
            .record_assessment("threat", "m", true, None);
        db.knowledge_viewer
            .add_learned_pattern(make_learned_pattern("intrusion", Some("web-01")));
        db.knowledge_viewer.add_safe_pattern("cron", None, 3);
        db.knowledge_viewer.add_risk_pattern("brute_force", "high");
        db.audit_trail.record(make_audit_entry(
            AuditEntryType::ActionExecuted,
            "supervised",
        ));
        db.decision_explainer
            .record_explanation(make_decision("threat", Some("web-01")));

        let tmp = tempfile::tempdir().unwrap();
        db.save(tmp.path()).unwrap();

        let loaded = TransparencyDashboard::load(tmp.path()).unwrap();
        assert_eq!(loaded.activity_tracker.activity_count(), 1);
        assert_eq!(loaded.cost_dashboard.operation_count(), 1);
        assert_eq!(loaded.accuracy_tracker.assessment_count(), 1);
        assert_eq!(loaded.knowledge_viewer.get_all_patterns().len(), 1);
        assert_eq!(loaded.knowledge_viewer.get_safe_patterns().len(), 1);
        assert_eq!(loaded.knowledge_viewer.get_risk_patterns().len(), 1);
        assert_eq!(loaded.audit_trail.entry_count(), 1);
        assert_eq!(loaded.decision_explainer.explanation_count(), 1);
    }

    #[test]
    fn test_dashboard_load_nonexistent() {
        let result = TransparencyDashboard::load(Path::new("/tmp/nonexistent_dir_xyz"));
        assert!(result.is_err());
    }

    #[test]
    fn test_dashboard_save_creates_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a").join("b").join("c");
        let db = TransparencyDashboard::new();
        db.save(&nested).unwrap();
        assert!(nested.join("transparency_dashboard.json").exists());
    }

    #[test]
    fn test_dashboard_roundtrip_preserves_data() {
        let mut db = TransparencyDashboard::new();

        // Activity with specific details
        let mut activity = make_activity(ActivityType::PlaybookTriggered, Some("prod-db"));
        activity.description = "SSH brute force playbook".to_string();
        activity.risk_level = Some("critical".to_string());
        db.activity_tracker.record_activity(activity);

        // Multiple cost entries
        db.cost_dashboard.record_operation("scan", 500, "full scan");
        db.cost_dashboard
            .record_operation("remediate", 1200, "block IP");

        // Accuracy with correction
        let id = db.accuracy_tracker.record_assessment(
            "threat",
            "malicious",
            true,
            Some("prod-db".to_string()),
        );
        db.accuracy_tracker
            .record_correction(id, "was actually benign");

        let tmp = tempfile::tempdir().unwrap();
        db.save(tmp.path()).unwrap();
        let loaded = TransparencyDashboard::load(tmp.path()).unwrap();

        // Verify activity details
        let acts = loaded.activity_tracker.get_recent(1);
        assert_eq!(acts[0].description, "SSH brute force playbook");
        assert_eq!(acts[0].risk_level.as_deref(), Some("critical"));

        // Verify cost details
        assert_eq!(loaded.cost_dashboard.operation_count(), 2);

        // Verify correction was preserved
        let assessments = loaded.accuracy_tracker.get_recent(1);
        assert!(!assessments[0].was_correct);
        assert_eq!(
            assessments[0].user_correction.as_deref(),
            Some("was actually benign")
        );
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn test_get_recent_zero() {
        let mut tracker = AgentActivityTracker::new();
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, None));
        assert_eq!(tracker.get_recent(0).len(), 0);
    }

    #[test]
    fn test_get_recent_more_than_available() {
        let mut tracker = AgentActivityTracker::new();
        tracker.record_activity(make_activity(ActivityType::ActionExecuted, None));
        assert_eq!(tracker.get_recent(100).len(), 1);
    }

    #[test]
    fn test_empty_time_range() {
        let tracker = AgentActivityTracker::new();
        let now = Utc::now();
        assert_eq!(
            tracker
                .get_by_time_range(now - Duration::hours(1), now)
                .len(),
            0
        );
    }

    #[test]
    fn test_activity_type_display() {
        assert_eq!(ActivityType::ActionExecuted.to_string(), "ActionExecuted");
        assert_eq!(
            ActivityType::LockdownActivated.to_string(),
            "LockdownActivated"
        );
    }

    #[test]
    fn test_audit_entry_type_display() {
        assert_eq!(
            AuditEntryType::PermissionRequested.to_string(),
            "PermissionRequested"
        );
    }

    #[test]
    fn test_accuracy_all_correct() {
        let mut at = AccuracyTracker::new();
        for _ in 0..20 {
            at.record_assessment("t", "a", true, None);
        }
        let metrics = at.get_metrics();
        assert_eq!(metrics.accuracy_rate, 1.0);
        assert_eq!(metrics.incorrect, 0);
        assert_eq!(metrics.trend, AccuracyTrend::Stable);
    }

    #[test]
    fn test_accuracy_all_incorrect() {
        let mut at = AccuracyTracker::new();
        for _ in 0..20 {
            at.record_assessment("t", "a", false, None);
        }
        let metrics = at.get_metrics();
        assert_eq!(metrics.accuracy_rate, 0.0);
        assert_eq!(metrics.correct, 0);
        assert_eq!(metrics.trend, AccuracyTrend::Stable);
    }

    #[test]
    fn test_cost_summary_single_type() {
        let mut cd = CostDashboard::new();
        cd.record_operation("scan", 100, "s1");
        cd.record_operation("scan", 200, "s2");
        let summary = cd.get_summary();
        assert_eq!(summary.by_type.len(), 1);
        assert_eq!(summary.by_type["scan"].avg_duration_ms, 150);
    }

    #[test]
    fn test_pattern_stats_no_server() {
        let mut kb = KnowledgeBaseViewer::new();
        kb.add_learned_pattern(make_learned_pattern("cat", None));
        let stats = kb.get_pattern_stats();
        assert_eq!(stats.total_learned, 1);
        assert!(stats.by_server.is_empty());
    }

    #[test]
    fn test_search_patterns_case_insensitive() {
        let mut kb = KnowledgeBaseViewer::new();
        let mut p = make_learned_pattern("SQL_Injection", None);
        p.pattern = "SQL Injection Attack".to_string();
        kb.add_learned_pattern(p);
        assert_eq!(kb.search_patterns("sql injection").len(), 1);
        assert_eq!(kb.search_patterns("SQL INJECTION").len(), 1);
    }

    #[test]
    fn test_decision_factor_structure() {
        let factor = DecisionFactor {
            name: "severity".to_string(),
            value: "critical".to_string(),
            weight: 0.95,
            direction: "negative".to_string(),
        };
        assert_eq!(factor.name, "severity");
        assert_eq!(factor.weight, 0.95);
    }

    #[test]
    fn test_dashboard_subsystem_independence() {
        let mut db = TransparencyDashboard::new();
        db.activity_tracker
            .record_activity(make_activity(ActivityType::ActionExecuted, None));
        // Other subsystems should remain empty
        assert_eq!(db.cost_dashboard.operation_count(), 0);
        assert_eq!(db.accuracy_tracker.assessment_count(), 0);
        assert_eq!(db.audit_trail.entry_count(), 0);
        assert_eq!(db.decision_explainer.explanation_count(), 0);
    }

    #[test]
    fn test_dashboard_recent_decisions_capped_at_10() {
        let mut db = TransparencyDashboard::new();
        for _ in 0..15 {
            db.decision_explainer
                .record_explanation(make_decision("threat", None));
        }
        let summary = db.get_dashboard_summary();
        assert_eq!(summary.recent_decisions.len(), 10);
    }

    #[test]
    fn test_dashboard_summary_has_timestamp() {
        let db = TransparencyDashboard::new();
        let before = Utc::now();
        let summary = db.get_dashboard_summary();
        let after = Utc::now();
        assert!(summary.generated_at >= before);
        assert!(summary.generated_at <= after);
    }

    // =========================================================================
    // Serialization tests
    // =========================================================================

    #[test]
    fn test_activity_type_serde_roundtrip() {
        let val = ActivityType::LockdownActivated;
        let json = serde_json::to_string(&val).unwrap();
        let restored: ActivityType = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, val);
    }

    #[test]
    fn test_audit_entry_type_serde_roundtrip() {
        let val = AuditEntryType::LevelEscalated;
        let json = serde_json::to_string(&val).unwrap();
        let restored: AuditEntryType = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, val);
    }

    #[test]
    fn test_accuracy_trend_serde_roundtrip() {
        for trend in [
            AccuracyTrend::Improving,
            AccuracyTrend::Stable,
            AccuracyTrend::Declining,
        ] {
            let json = serde_json::to_string(&trend).unwrap();
            let restored: AccuracyTrend = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, trend);
        }
    }

    #[test]
    fn test_agent_activity_serde_roundtrip() {
        let activity = make_activity(ActivityType::PlaybookTriggered, Some("web-01"));
        let json = serde_json::to_string(&activity).unwrap();
        let restored: AgentActivity = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, activity.id);
        assert_eq!(restored.activity_type, activity.activity_type);
    }

    #[test]
    fn test_decision_explanation_serde_roundtrip() {
        let exp = make_decision("triage", Some("web-01"));
        let json = serde_json::to_string(&exp).unwrap();
        let restored: DecisionExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, exp.id);
        assert_eq!(restored.factors.len(), exp.factors.len());
    }

    #[test]
    fn test_dashboard_summary_serde_roundtrip() {
        let db = TransparencyDashboard::new();
        let summary = db.get_dashboard_summary();
        let json = serde_json::to_string(&summary).unwrap();
        let restored: DashboardSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.activity_summary.total,
            summary.activity_summary.total,
        );
    }
}
