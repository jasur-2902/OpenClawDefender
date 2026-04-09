use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::state::{ActiveModelInfo, AuditEvent, PendingPrompt};

pub const EVENT_AUDIT: &str = "clawdefender://event";
pub const EVENT_PROMPT: &str = "clawdefender://prompt";
pub const EVENT_ALERT: &str = "clawdefender://alert";
pub const EVENT_AUTO_BLOCK: &str = "clawdefender://auto-block";
pub const EVENT_STATUS_CHANGE: &str = "clawdefender://status-change";
pub const EVENT_MODEL_CHANGED: &str = "clawdefender://model-changed";

/// A suspicious event entry shown inside the AlertWindow.
#[derive(Debug, Clone, Serialize)]
pub struct SuspiciousEventPayload {
    pub timestamp: String,
    pub action: String,
}

/// Full alert payload matching the frontend `AlertData` interface.
#[derive(Debug, Clone, Serialize)]
pub struct AlertPayload {
    pub id: String,
    pub level: String,
    pub message: String,
    pub details: String,
    pub events: Vec<SuspiciousEventPayload>,
    pub kill_chain: Option<String>,
    pub pid: Option<u32>,
}

/// Payload for auto-block toast notifications, matching `AutoBlockInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct AutoBlockPayload {
    pub id: String,
    pub server_name: String,
    pub action: String,
    pub anomaly_score: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusChangePayload {
    pub daemon_running: bool,
}

pub fn emit_audit_event(app: &AppHandle, event: &AuditEvent) {
    if let Err(e) = app.emit(EVENT_AUDIT, event) {
        tracing::error!("Failed to emit audit event: {}", e);
    }
}

pub fn emit_prompt(app: &AppHandle, prompt: &PendingPrompt) {
    if let Err(e) = app.emit(EVENT_PROMPT, prompt) {
        tracing::error!("Failed to emit prompt: {}", e);
    }
}

/// Emit a full alert payload to the frontend AlertWindow.
pub fn emit_alert(app: &AppHandle, payload: &AlertPayload) {
    if let Err(e) = app.emit(EVENT_ALERT, payload) {
        tracing::error!("Failed to emit alert: {}", e);
    }
}

/// Emit an auto-block toast notification.
pub fn emit_auto_block(app: &AppHandle, payload: &AutoBlockPayload) {
    if let Err(e) = app.emit(EVENT_AUTO_BLOCK, payload) {
        tracing::error!("Failed to emit auto-block: {}", e);
    }
}

pub fn emit_status_change(app: &AppHandle, daemon_running: bool) {
    let payload = StatusChangePayload { daemon_running };
    if let Err(e) = app.emit(EVENT_STATUS_CHANGE, &payload) {
        tracing::error!("Failed to emit status change: {}", e);
    }
}

/// Emit a model-changed event so the frontend can update without polling.
pub fn emit_model_changed(app: &AppHandle, model_info: Option<&ActiveModelInfo>) {
    if let Err(e) = app.emit(EVENT_MODEL_CHANGED, &model_info) {
        tracing::error!("Failed to emit model-changed event: {}", e);
    }
}

// --- Phase 2: Cloud agent events ---

pub const EVENT_CLOUD_RESPONSE: &str = "clawdefender://cloud-response";
pub const EVENT_CLOUD_TOOL_CALL: &str = "clawdefender://cloud-tool-call";
pub const EVENT_CLOUD_ERROR: &str = "clawdefender://cloud-error";
pub const EVENT_BUDGET_WARNING: &str = "clawdefender://budget-warning";
pub const EVENT_ACTION_PENDING: &str = "clawdefender://action-pending";

/// Payload for streaming text from a cloud agent session.
#[derive(Debug, Clone, Serialize)]
pub struct CloudResponsePayload {
    pub session_id: String,
    pub text: String,
    pub is_final: bool,
}

/// Payload for a tool call happening during a cloud agent session.
#[derive(Debug, Clone, Serialize)]
pub struct CloudToolCallPayload {
    pub session_id: String,
    pub tool_name: String,
    pub input_summary: String,
    pub success: bool,
}

/// Payload for a cloud API error.
#[derive(Debug, Clone, Serialize)]
pub struct CloudErrorPayload {
    pub session_id: Option<String>,
    pub error: String,
    pub recoverable: bool,
}

/// Payload for a budget warning (80% consumed).
#[derive(Debug, Clone, Serialize)]
pub struct BudgetWarningPayload {
    pub tier: String,
    pub used_percent: f64,
    pub used_amount: f64,
    pub limit_amount: f64,
}

/// Payload for a pending action proposed by the cloud agent.
#[derive(Debug, Clone, Serialize)]
pub struct ActionPendingPayload {
    pub session_id: String,
    pub action_id: String,
    pub action_type: String,
    pub description: String,
}

pub fn emit_cloud_response(app: &AppHandle, payload: &CloudResponsePayload) {
    if let Err(e) = app.emit(EVENT_CLOUD_RESPONSE, payload) {
        tracing::error!("Failed to emit cloud response: {}", e);
    }
}

pub fn emit_cloud_tool_call(app: &AppHandle, payload: &CloudToolCallPayload) {
    if let Err(e) = app.emit(EVENT_CLOUD_TOOL_CALL, payload) {
        tracing::error!("Failed to emit cloud tool call: {}", e);
    }
}

pub fn emit_cloud_error(app: &AppHandle, payload: &CloudErrorPayload) {
    if let Err(e) = app.emit(EVENT_CLOUD_ERROR, payload) {
        tracing::error!("Failed to emit cloud error: {}", e);
    }
}

pub fn emit_budget_warning(app: &AppHandle, payload: &BudgetWarningPayload) {
    if let Err(e) = app.emit(EVENT_BUDGET_WARNING, payload) {
        tracing::error!("Failed to emit budget warning: {}", e);
    }
}

pub fn emit_action_pending(app: &AppHandle, payload: &ActionPendingPayload) {
    if let Err(e) = app.emit(EVENT_ACTION_PENDING, payload) {
        tracing::error!("Failed to emit action pending: {}", e);
    }
}

// --- Phase 3: AI scan events ---

pub const EVENT_SCAN_FINDING: &str = "clawdefender://scan-finding";
pub const EVENT_SCAN_STAGE_COMPLETE: &str = "clawdefender://scan-stage-complete";
pub const EVENT_SCAN_COMPLETE: &str = "clawdefender://scan-complete";
pub const EVENT_SCAN_USER_REQUEST: &str = "clawdefender://scan-user-request";

/// Payload for a new finding discovered during an AI scan.
#[derive(Debug, Clone, Serialize)]
pub struct ScanFindingPayload {
    pub scan_id: String,
    pub finding_id: String,
    pub severity: String,
    pub title: String,
    pub stage: String,
}

/// Payload for a stage completion in an AI scan.
#[derive(Debug, Clone, Serialize)]
pub struct ScanStageCompletePayload {
    pub scan_id: String,
    pub stage_name: String,
    pub stages_completed: usize,
    pub stages_total: usize,
}

/// Payload for scan completion.
#[derive(Debug, Clone, Serialize)]
pub struct ScanCompletePayload {
    pub scan_id: String,
    pub status: String,
    pub findings_count: usize,
    pub summary: String,
}

/// Payload for a scan requesting user input.
#[derive(Debug, Clone, Serialize)]
pub struct ScanUserRequestPayload {
    pub scan_id: String,
    pub request_id: String,
    pub question: String,
    pub context: String,
}

pub fn emit_scan_finding(app: &AppHandle, payload: &ScanFindingPayload) {
    if let Err(e) = app.emit(EVENT_SCAN_FINDING, payload) {
        tracing::error!("Failed to emit scan finding: {}", e);
    }
}

pub fn emit_scan_stage_complete(app: &AppHandle, payload: &ScanStageCompletePayload) {
    if let Err(e) = app.emit(EVENT_SCAN_STAGE_COMPLETE, payload) {
        tracing::error!("Failed to emit scan stage complete: {}", e);
    }
}

pub fn emit_scan_complete(app: &AppHandle, payload: &ScanCompletePayload) {
    if let Err(e) = app.emit(EVENT_SCAN_COMPLETE, payload) {
        tracing::error!("Failed to emit scan complete: {}", e);
    }
}

pub fn emit_scan_user_request(app: &AppHandle, payload: &ScanUserRequestPayload) {
    if let Err(e) = app.emit(EVENT_SCAN_USER_REQUEST, payload) {
        tracing::error!("Failed to emit scan user request: {}", e);
    }
}

// --- Phase 4: Investigation events ---

pub const EVENT_INVESTIGATION_STARTED: &str = "clawdefender://investigation-started";
pub const EVENT_INVESTIGATION_PROGRESS: &str = "clawdefender://investigation-progress";
pub const EVENT_INVESTIGATION_COMPLETE: &str = "clawdefender://investigation-complete";
pub const EVENT_HUNT_FINDING: &str = "clawdefender://hunt-finding";

/// Payload for an investigation that has just started.
#[derive(Debug, Clone, Serialize)]
pub struct InvestigationStartedPayload {
    pub investigation_id: String,
    pub target_summary: String,
    pub depth: String,
}

/// Payload for investigation progress updates.
#[derive(Debug, Clone, Serialize)]
pub struct InvestigationProgressPayload {
    pub investigation_id: String,
    pub status: String,
    pub questions_answered: usize,
    pub questions_total: usize,
    pub current_activity: String,
    pub elapsed_secs: u64,
}

/// Payload for a completed investigation.
#[derive(Debug, Clone, Serialize)]
pub struct InvestigationCompletePayload {
    pub investigation_id: String,
    pub verdict: String,
    pub confidence: f64,
    pub narrative_preview: String,
}

/// Payload for a finding discovered during a threat hunt.
#[derive(Debug, Clone, Serialize)]
pub struct HuntFindingPayload {
    pub hunt_id: String,
    pub finding_id: String,
    pub pattern_name: String,
    pub severity: String,
    pub description: String,
}

pub fn emit_investigation_started(app: &AppHandle, payload: &InvestigationStartedPayload) {
    if let Err(e) = app.emit(EVENT_INVESTIGATION_STARTED, payload) {
        tracing::error!("Failed to emit investigation started: {}", e);
    }
}

pub fn emit_investigation_progress(app: &AppHandle, payload: &InvestigationProgressPayload) {
    if let Err(e) = app.emit(EVENT_INVESTIGATION_PROGRESS, payload) {
        tracing::error!("Failed to emit investigation progress: {}", e);
    }
}

pub fn emit_investigation_complete(app: &AppHandle, payload: &InvestigationCompletePayload) {
    if let Err(e) = app.emit(EVENT_INVESTIGATION_COMPLETE, payload) {
        tracing::error!("Failed to emit investigation complete: {}", e);
    }
}

pub fn emit_hunt_finding(app: &AppHandle, payload: &HuntFindingPayload) {
    if let Err(e) = app.emit(EVENT_HUNT_FINDING, payload) {
        tracing::error!("Failed to emit hunt finding: {}", e);
    }
}

// --- Phase 5: Proactive Security Agent events ---

pub const EVENT_HOURLY_SWEEP: &str = "clawdefender://hourly-sweep";
pub const EVENT_DAILY_BRIEF: &str = "clawdefender://daily-brief";
pub const EVENT_WEEKLY_REPORT: &str = "clawdefender://weekly-report";
pub const EVENT_DRIFT_DETECTED: &str = "clawdefender://drift-detected";
pub const EVENT_POSTURE_CHANGE: &str = "clawdefender://posture-change";
pub const EVENT_SIMULATION_COMPLETE: &str = "clawdefender://simulation-complete";
pub const EVENT_KNOWLEDGE_UPDATED: &str = "clawdefender://knowledge-updated";

#[derive(Debug, Clone, Serialize)]
pub struct HourlySweepPayload {
    pub status: String,
    pub event_volume: String,
    pub suspicious_count: u32,
    pub concerns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DailyBriefPayload {
    pub summary: String,
    pub notable_count: u32,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftDetectedPayload {
    pub server_name: String,
    pub drift_score: f64,
    pub drift_types: Vec<String>,
    pub narrative: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostureChangePayload {
    pub old_level: String,
    pub new_level: String,
    pub reason: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationCompletePayload {
    pub defense_score: f64,
    pub scenarios_caught: u32,
    pub scenarios_total: u32,
    pub gaps_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct KnowledgeUpdatedPayload {
    pub update_type: String,
    pub description: String,
}

pub fn emit_hourly_sweep(app: &AppHandle, payload: &HourlySweepPayload) {
    if let Err(e) = app.emit(EVENT_HOURLY_SWEEP, payload) {
        tracing::error!("Failed to emit hourly sweep: {}", e);
    }
}

pub fn emit_daily_brief(app: &AppHandle, payload: &DailyBriefPayload) {
    if let Err(e) = app.emit(EVENT_DAILY_BRIEF, payload) {
        tracing::error!("Failed to emit daily brief: {}", e);
    }
}

pub fn emit_drift_detected(app: &AppHandle, payload: &DriftDetectedPayload) {
    if let Err(e) = app.emit(EVENT_DRIFT_DETECTED, payload) {
        tracing::error!("Failed to emit drift detected: {}", e);
    }
}

pub fn emit_posture_change(app: &AppHandle, payload: &PostureChangePayload) {
    if let Err(e) = app.emit(EVENT_POSTURE_CHANGE, payload) {
        tracing::error!("Failed to emit posture change: {}", e);
    }
}

pub fn emit_simulation_complete(app: &AppHandle, payload: &SimulationCompletePayload) {
    if let Err(e) = app.emit(EVENT_SIMULATION_COMPLETE, payload) {
        tracing::error!("Failed to emit simulation complete: {}", e);
    }
}

pub fn emit_knowledge_updated(app: &AppHandle, payload: &KnowledgeUpdatedPayload) {
    if let Err(e) = app.emit(EVENT_KNOWLEDGE_UPDATED, payload) {
        tracing::error!("Failed to emit knowledge updated: {}", e);
    }
}

// --- Phase 6: Agent Autonomy & Reporting events ---

pub const EVENT_AUTONOMY_CHANGED: &str = "clawdefender://autonomy-changed";
pub const EVENT_LOCKDOWN_ACTIVATED: &str = "clawdefender://lockdown-activated";
pub const EVENT_LOCKDOWN_DEACTIVATED: &str = "clawdefender://lockdown-deactivated";
pub const EVENT_PLAYBOOK_TRIGGERED: &str = "clawdefender://playbook-triggered";
pub const EVENT_PLAYBOOK_COMPLETED: &str = "clawdefender://playbook-completed";
pub const EVENT_REPORT_GENERATED: &str = "clawdefender://report-generated";
pub const EVENT_CALIBRATION_COMPLETE: &str = "clawdefender://calibration-complete";

#[derive(Debug, Clone, Serialize)]
pub struct AutonomyChangedPayload {
    pub old_level: String,
    pub new_level: String,
    pub changed_by: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LockdownPayload {
    pub reason: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlaybookTriggeredPayload {
    pub playbook_id: String,
    pub playbook_name: String,
    pub trigger_reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlaybookCompletedPayload {
    pub playbook_id: String,
    pub playbook_name: String,
    pub actions_executed: usize,
    pub actions_blocked: usize,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportGeneratedPayload {
    pub report_id: String,
    pub report_type: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CalibrationCompletePayload {
    pub adjustments_made: usize,
    pub accuracy_before: f64,
    pub accuracy_after: f64,
}

pub fn emit_autonomy_changed(app: &AppHandle, payload: &AutonomyChangedPayload) {
    if let Err(e) = app.emit(EVENT_AUTONOMY_CHANGED, payload) {
        tracing::error!("Failed to emit autonomy changed: {}", e);
    }
}

pub fn emit_lockdown_activated(app: &AppHandle, payload: &LockdownPayload) {
    if let Err(e) = app.emit(EVENT_LOCKDOWN_ACTIVATED, payload) {
        tracing::error!("Failed to emit lockdown activated: {}", e);
    }
}

pub fn emit_lockdown_deactivated(app: &AppHandle, payload: &LockdownPayload) {
    if let Err(e) = app.emit(EVENT_LOCKDOWN_DEACTIVATED, payload) {
        tracing::error!("Failed to emit lockdown deactivated: {}", e);
    }
}

pub fn emit_playbook_triggered(app: &AppHandle, payload: &PlaybookTriggeredPayload) {
    if let Err(e) = app.emit(EVENT_PLAYBOOK_TRIGGERED, payload) {
        tracing::error!("Failed to emit playbook triggered: {}", e);
    }
}

pub fn emit_playbook_completed(app: &AppHandle, payload: &PlaybookCompletedPayload) {
    if let Err(e) = app.emit(EVENT_PLAYBOOK_COMPLETED, payload) {
        tracing::error!("Failed to emit playbook completed: {}", e);
    }
}

pub fn emit_report_generated(app: &AppHandle, payload: &ReportGeneratedPayload) {
    if let Err(e) = app.emit(EVENT_REPORT_GENERATED, payload) {
        tracing::error!("Failed to emit report generated: {}", e);
    }
}

pub fn emit_calibration_complete(app: &AppHandle, payload: &CalibrationCompletePayload) {
    if let Err(e) = app.emit(EVENT_CALIBRATION_COMPLETE, payload) {
        tracing::error!("Failed to emit calibration complete: {}", e);
    }
}
