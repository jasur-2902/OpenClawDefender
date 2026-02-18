//! MCP (Model Context Protocol) event types.
//!
//! These represent JSON-RPC messages intercepted by the MCP proxy sitting
//! between the AI host and tool servers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use std::any::Any;

use crate::audit::AuditRecord;
use crate::event::{Event, Severity};

/// An event originating from the MCP JSON-RPC proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpEvent {
    /// When the message was intercepted.
    pub timestamp: DateTime<Utc>,
    /// Source identifier, typically `"mcp-proxy"`.
    pub source: String,
    /// Classified kind of MCP message.
    pub kind: McpEventKind,
    /// The raw JSON-RPC message for deep inspection.
    pub raw_message: Value,
}

/// Classification of an intercepted MCP message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum McpEventKind {
    /// A `tools/call` request.
    ToolCall(ToolCall),
    /// A `resources/read` request.
    ResourceRead(ResourceRead),
    /// A `sampling/createMessage` request.
    SamplingRequest(SamplingRequest),
    /// A `tools/list` or `resources/list` request.
    ListRequest,
    /// An MCP notification (no response expected).
    Notification(String),
    /// Any other JSON-RPC method.
    Other(String),
}

/// A parsed `tools/call` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Name of the tool being invoked.
    pub tool_name: String,
    /// Arguments passed to the tool.
    pub arguments: Value,
    /// JSON-RPC request id.
    pub request_id: Value,
}

/// A parsed `resources/read` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRead {
    /// URI of the resource being read.
    pub uri: String,
    /// JSON-RPC request id.
    pub request_id: Value,
}

/// A parsed `sampling/createMessage` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingRequest {
    /// The messages array from the sampling request.
    pub messages: Vec<Value>,
    /// Optional model preferences.
    pub model_preferences: Option<Value>,
    /// JSON-RPC request id.
    pub request_id: Value,
}

impl Event for McpEvent {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn source(&self) -> &str {
        &self.source
    }

    fn severity(&self) -> Severity {
        match &self.kind {
            McpEventKind::ToolCall(_) => Severity::Medium,
            McpEventKind::ResourceRead(_) => Severity::Low,
            McpEventKind::SamplingRequest(_) => Severity::High,
            McpEventKind::ListRequest => Severity::Info,
            McpEventKind::Notification(_) => Severity::Info,
            McpEventKind::Other(_) => Severity::Low,
        }
    }

    fn to_audit_record(&self) -> AuditRecord {
        AuditRecord {
            timestamp: self.timestamp,
            source: self.source.clone(),
            event_summary: match &self.kind {
                McpEventKind::ToolCall(tc) => format!("tool_call: {}", tc.tool_name),
                McpEventKind::ResourceRead(rr) => format!("resource_read: {}", rr.uri),
                McpEventKind::SamplingRequest(_) => "sampling_request".to_string(),
                McpEventKind::ListRequest => "list_request".to_string(),
                McpEventKind::Notification(n) => format!("notification: {n}"),
                McpEventKind::Other(m) => format!("other: {m}"),
            },
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
            network_connection: None,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
