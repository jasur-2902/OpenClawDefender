//! Correlated events linking MCP requests to their OS-level side effects.
//!
//! The correlation engine watches for an MCP tool call, then collects the
//! subsequent OS events produced by the same process tree within a time window.

use std::any::Any;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::audit::AuditRecord;
use crate::event::mcp::McpEvent;
use crate::event::os::OsEvent;
use crate::event::{Event, Severity};

/// A composite event that links an MCP request with its observed OS activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    /// Unique correlation id (UUID v4 as string).
    pub id: String,
    /// The MCP event that triggered this correlation window, if any.
    pub mcp_event: Option<McpEvent>,
    /// OS-level events observed within the correlation window.
    pub os_events: Vec<OsEvent>,
    /// Current status of the correlation.
    pub status: CorrelationStatus,
    /// When the correlation was finalized.
    pub correlated_at: Option<DateTime<Utc>>,
}

/// Status of a correlation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationStatus {
    /// OS events were successfully linked to an MCP request.
    Matched,
    /// OS events could not be linked to any MCP request.
    Uncorrelated,
    /// Correlation is still in progress (within the time window).
    Pending,
}

impl Event for CorrelatedEvent {
    fn timestamp(&self) -> DateTime<Utc> {
        self.mcp_event
            .as_ref()
            .map(|e| e.timestamp)
            .or_else(|| self.os_events.first().map(|e| e.timestamp))
            .unwrap_or_else(Utc::now)
    }

    fn source(&self) -> &str {
        "correlation"
    }

    fn severity(&self) -> Severity {
        let mcp_sev = self
            .mcp_event
            .as_ref()
            .map(|e| e.severity())
            .unwrap_or(Severity::Info);
        let os_sev = self
            .os_events
            .iter()
            .map(|e| e.severity())
            .max()
            .unwrap_or(Severity::Info);
        mcp_sev.max(os_sev)
    }

    fn to_audit_record(&self) -> AuditRecord {
        let summary = match &self.mcp_event {
            Some(mcp) => format!(
                "correlated: {} + {} os events",
                mcp.to_audit_record().event_summary,
                self.os_events.len()
            ),
            None => format!("correlated: {} uncorrelated os events", self.os_events.len()),
        };
        AuditRecord {
            timestamp: self.timestamp(),
            source: "correlation".to_string(),
            event_summary: summary,
            event_details: serde_json::to_value(self).unwrap_or_default(),
            rule_matched: None,
            action_taken: String::new(),
            response_time_ms: None,
            session_id: None,
            direction: None,
            server_name: None,
            client_name: None,
            jsonrpc_method: None,
            tool_name: None,
            arguments: None,
            classification: None,
            policy_rule: None,
            policy_action: None,
            user_decision: None,
            proxy_latency_us: None,
            slm_analysis: None,
            swarm_analysis: None,
            behavioral: None,
            injection_scan: None,
            threat_intel: None,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
