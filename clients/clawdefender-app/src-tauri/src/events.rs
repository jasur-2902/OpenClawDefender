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
