use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::state::{AuditEvent, PendingPrompt};

pub const EVENT_AUDIT: &str = "clawdefender://event";
pub const EVENT_PROMPT: &str = "clawdefender://prompt";
pub const EVENT_ALERT: &str = "clawdefender://alert";
pub const EVENT_STATUS_CHANGE: &str = "clawdefender://status-change";

#[derive(Debug, Clone, Serialize)]
pub struct AlertPayload {
    pub level: String,
    pub message: String,
    pub details: String,
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

pub fn emit_alert(app: &AppHandle, level: &str, message: &str, details: &str) {
    let payload = AlertPayload {
        level: level.to_string(),
        message: message.to_string(),
        details: details.to_string(),
    };
    if let Err(e) = app.emit(EVENT_ALERT, &payload) {
        tracing::error!("Failed to emit alert: {}", e);
    }
}

pub fn emit_status_change(app: &AppHandle, daemon_running: bool) {
    let payload = StatusChangePayload { daemon_running };
    if let Err(e) = app.emit(EVENT_STATUS_CHANGE, &payload) {
        tracing::error!("Failed to emit status change: {}", e);
    }
}
