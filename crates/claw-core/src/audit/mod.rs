//! Audit logging for policy decisions and events.
//!
//! Every event that flows through ClawAI is recorded as an [`AuditRecord`] in
//! a JSON-lines file for post-hoc analysis and compliance.

pub mod logger;
pub mod query;

use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single audit log entry written to the JSON-lines audit file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Origin subsystem: `"mcp-proxy"`, `"eslogger"`, `"fsevents"`, or `"correlation"`.
    pub source: String,
    /// One-line human-readable summary of the event.
    pub event_summary: String,
    /// Full structured event data for deep inspection.
    pub event_details: serde_json::Value,
    /// Name of the policy rule that matched, if any.
    pub rule_matched: Option<String>,
    /// Action taken: `"allow"`, `"block"`, `"prompt"`, `"log"`.
    pub action_taken: String,
    /// Time from event receipt to policy decision, in milliseconds.
    pub response_time_ms: Option<u64>,

    // --- Enhanced fields for production use ---
    /// Session UUID, generated once at proxy start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Direction: "client_to_server" or "server_to_client".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// Name of the MCP server involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// Name of the MCP client involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// JSON-RPC method name (e.g. "tools/call").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jsonrpc_method: Option<String>,
    /// Tool name if this is a tool call event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Tool call arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
    /// Classification: "pass", "log", "review", "block".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    /// Policy rule that matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,
    /// Policy action: "allowed", "blocked", "prompted", "logged".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_action: Option<String>,
    /// User decision when prompted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_decision: Option<String>,
    /// Proxy latency in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_latency_us: Option<u64>,
}

/// Filter for querying the audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Only include records after this time.
    pub from: Option<DateTime<Utc>>,
    /// Only include records before this time.
    pub to: Option<DateTime<Utc>>,
    /// Only include records from this source.
    pub source: Option<String>,
    /// Only include records with this action.
    pub action: Option<String>,
    /// Maximum number of records to return.
    pub limit: usize,
}

/// Aggregate statistics from the audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total events recorded.
    pub total_events: u64,
    /// Events that were blocked.
    pub blocked: u64,
    /// Events that were allowed.
    pub allowed: u64,
    /// Events that required a user prompt.
    pub prompted: u64,
    /// Events that were logged only.
    pub logged: u64,
    /// Event counts broken down by source subsystem.
    pub by_source: HashMap<String, u64>,
    /// Unique server names seen.
    pub unique_servers: Vec<String>,
    /// Unique tool names seen.
    pub unique_tools: Vec<String>,
    /// Top 10 blocked tools by count.
    pub top_blocked_tools: Vec<(String, u64)>,
    /// Top 10 blocked paths by count.
    pub top_blocked_paths: Vec<(String, u64)>,
}

/// Trait for audit log backends.
pub trait AuditLogger: Send + Sync {
    /// Write a single audit record.
    fn log(&self, record: &AuditRecord) -> Result<()>;

    /// Query the audit log with the given filter.
    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditRecord>>;

    /// Return aggregate statistics.
    fn stats(&self) -> Result<AuditStats>;
}
