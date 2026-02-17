//! Audit logging for policy decisions and events.
//!
//! Every event that flows through ClawDefender is recorded as an [`AuditRecord`] in
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

    /// Optional SLM risk analysis result (advisory only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slm_analysis: Option<SlmAnalysisRecord>,

    /// Optional cloud swarm analysis result (advisory only).
    /// SAFETY: Swarm verdict is advisory only. Never modifies policy decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swarm_analysis: Option<SwarmAnalysisRecord>,

    /// Optional behavioral analysis result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavioral: Option<crate::behavioral::BehavioralAuditData>,

    /// Optional injection scan result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injection_scan: Option<InjectionScanData>,

    /// Optional threat intelligence match data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_intel: Option<ThreatIntelAuditData>,
}

/// Data from threat intelligence matching, stored alongside audit records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelAuditData {
    /// IoC indicators that matched this event.
    pub ioc_matches: Vec<IoCMatchRecord>,
    /// Blocklist entry ID if the server matched a blocklist entry.
    pub blocklist_match: Option<String>,
    /// Community rule that matched this event, if any.
    pub community_rule: Option<String>,
}

/// A single IoC match record for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoCMatchRecord {
    /// Threat ID of the matched indicator.
    pub threat_id: String,
    /// Type of indicator (e.g. "ip", "domain", "hash", "tool_sequence").
    pub indicator_type: String,
    /// Severity level of the match.
    pub severity: String,
}

/// Data from an injection scan, stored alongside audit records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionScanData {
    pub score: f64,
    pub patterns_found: Vec<String>,
}

/// Record of an SLM risk analysis, stored alongside audit records.
/// SAFETY: SLM output is advisory only. It enriches the audit log
/// but does not influence the policy decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmAnalysisRecord {
    /// Risk level assessed by the SLM (e.g. "LOW", "MEDIUM", "HIGH", "CRITICAL").
    pub risk_level: String,
    /// Human-readable explanation of the risk assessment.
    pub explanation: String,
    /// Model's confidence in the assessment (0.0 to 1.0).
    pub confidence: f32,
    /// Wall-clock latency of the SLM inference in milliseconds.
    pub latency_ms: u64,
    /// Name of the SLM model used.
    pub model: String,
}

/// Record of a cloud swarm analysis, stored alongside audit records.
/// SAFETY: Swarm verdict is advisory only. Never modifies policy decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmAnalysisRecord {
    /// Risk level assessed by the swarm (e.g. "LOW", "MEDIUM", "HIGH", "CRITICAL").
    pub risk_level: String,
    /// Human-readable explanation of the risk assessment.
    pub explanation: String,
    /// Recommended action (e.g. "allow", "investigate", "block").
    pub recommended_action: String,
    /// Swarm confidence in the assessment (0.0 to 1.0).
    pub confidence: f32,
    /// Summaries from each specialist agent.
    pub specialist_summaries: Vec<String>,
    /// Total tokens consumed across all specialist calls.
    pub total_tokens: u32,
    /// Estimated cost in USD for the swarm analysis.
    pub estimated_cost_usd: f64,
    /// Wall-clock latency of the swarm analysis in milliseconds.
    pub latency_ms: u64,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_record_serializes_with_swarm_analysis() {
        let record = AuditRecord {
            timestamp: Utc::now(),
            source: "mcp-proxy".to_string(),
            event_summary: "tools/call run_command".to_string(),
            event_details: serde_json::json!({"cmd": "ls"}),
            rule_matched: Some("prompt_shell".to_string()),
            action_taken: "prompt".to_string(),
            response_time_ms: Some(5),
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
            swarm_analysis: Some(SwarmAnalysisRecord {
                risk_level: "HIGH".to_string(),
                explanation: "Shell command execution detected".to_string(),
                recommended_action: "investigate".to_string(),
                confidence: 0.92,
                specialist_summaries: vec![
                    "Hawk: suspicious command".to_string(),
                    "Forensics: no prior pattern".to_string(),
                ],
                total_tokens: 1500,
                estimated_cost_usd: 0.003,
                latency_ms: 2500,
            }),
            behavioral: None,
            injection_scan: None,
            threat_intel: None,
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("swarm_analysis"));
        assert!(json.contains("investigate"));

        // Round-trip deserialization
        let deserialized: AuditRecord = serde_json::from_str(&json).unwrap();
        let swarm = deserialized.swarm_analysis.unwrap();
        assert_eq!(swarm.risk_level, "HIGH");
        assert_eq!(swarm.recommended_action, "investigate");
        assert_eq!(swarm.specialist_summaries.len(), 2);
        assert_eq!(swarm.total_tokens, 1500);
    }

    #[test]
    fn test_audit_record_without_swarm_omits_field() {
        let record = AuditRecord {
            timestamp: Utc::now(),
            source: "mcp-proxy".to_string(),
            event_summary: "test".to_string(),
            event_details: serde_json::Value::Null,
            rule_matched: None,
            action_taken: "allow".to_string(),
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
        };

        let json = serde_json::to_string(&record).unwrap();
        // skip_serializing_if = "Option::is_none" should omit the field
        assert!(!json.contains("swarm_analysis"));
    }
}
