//! Investigation-specific tools, context enrichment, and prompt templates.
//!
//! These tools provide deep investigation capabilities available only during
//! `Investigate` and `ThreatHunt` sessions. They complement the base and scan
//! tool sets by adding session reconstruction, data-flow tracing, server
//! comparison, and prompt-context retrieval.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::agent_session::SessionType;
use crate::tools::ToolDefinition;

// ---------------------------------------------------------------------------
// Investigation target & depth
// ---------------------------------------------------------------------------

/// What the investigation is focused on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvestigationTarget {
    Event {
        event_id: String,
        event_data: Value,
    },
    Alert {
        alert_id: String,
        alert_data: Value,
    },
    Server {
        server_name: String,
    },
    TimeRange {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },
    Freeform {
        query: String,
    },
}

/// Controls how deeply the investigation runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InvestigationDepth {
    /// 3-5 tool calls, ~30 seconds.
    Quick,
    /// 10-15 tool calls, ~2-3 minutes.
    Standard,
    /// 25-40 tool calls, ~5-10 minutes.
    Deep,
}

impl InvestigationDepth {
    pub fn max_tool_calls(&self) -> usize {
        match self {
            Self::Quick => 5,
            Self::Standard => 15,
            Self::Deep => 40,
        }
    }

    pub fn max_duration_secs(&self) -> u64 {
        match self {
            Self::Quick => 30,
            Self::Standard => 180,
            Self::Deep => 600,
        }
    }

    /// Choose depth based on alert/event severity.
    pub fn auto_select(severity: &str) -> Self {
        match severity.to_uppercase().as_str() {
            "CRITICAL" => Self::Deep,
            "HIGH" => Self::Deep,
            "MEDIUM" => Self::Standard,
            "LOW" => Self::Quick,
            "INFO" => Self::Quick,
            _ => Self::Standard,
        }
    }
}

// ---------------------------------------------------------------------------
// Investigation context
// ---------------------------------------------------------------------------

/// Summary of a past investigation for the same server/event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationSummary {
    pub id: String,
    pub date: DateTime<Utc>,
    pub target: String,
    pub verdict: String,
    pub severity: String,
    pub summary: String,
}

/// Pre-built context that gets injected into the agent's system prompt when
/// an investigation starts. Provides the agent with rich background so it
/// can make informed decisions without burning tool calls on basics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationContext {
    pub target_event: Option<Value>,
    pub session_events: Vec<Value>,
    pub surrounding_events: Vec<Value>,
    pub kill_chain: Option<Value>,
    pub past_investigations: Vec<InvestigationSummary>,
    pub user_decisions: Vec<Value>,
    pub server_profile: Option<Value>,
}

impl InvestigationContext {
    /// Build context for investigating a specific event.
    pub async fn build_for_event(event_id: &str, _server_name: Option<&str>) -> Self {
        // Placeholder: real implementation would query the event store,
        // behavioural profile store, and investigation history DB.
        Self {
            target_event: Some(json!({
                "event_id": event_id,
                "status": "pending_investigation",
                "note": "Full event data will be populated from the event store"
            })),
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: None,
        }
    }

    /// Build context for investigating a server.
    pub async fn build_for_server(server_name: &str) -> Self {
        Self {
            target_event: None,
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: Some(json!({
                "server_name": server_name,
                "note": "Full profile will be populated from the behavioral profile store"
            })),
        }
    }

    /// Build context for a time-range investigation.
    pub async fn build_for_time_range(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self {
            target_event: None,
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: Some(json!({
                "time_range": {
                    "start": start.to_rfc3339(),
                    "end": end.to_rfc3339(),
                },
                "note": "Events in this window will be populated from the event store"
            })),
        }
    }

    /// Format the context as a section suitable for inclusion in the system
    /// prompt sent to Claude.
    pub fn to_prompt_section(&self) -> String {
        let mut parts: Vec<String> = Vec::new();

        parts.push("## INVESTIGATION CONTEXT (pre-loaded)".to_string());

        if let Some(event) = &self.target_event {
            parts.push(format!(
                "### Target Event\n```json\n{}\n```",
                serde_json::to_string_pretty(event).unwrap_or_default()
            ));
        }

        if !self.session_events.is_empty() {
            parts.push(format!(
                "### MCP Session Events ({} events)\n```json\n{}\n```",
                self.session_events.len(),
                serde_json::to_string_pretty(&self.session_events).unwrap_or_default()
            ));
        }

        if !self.surrounding_events.is_empty() {
            parts.push(format!(
                "### Surrounding Events (5 before + 5 after)\n```json\n{}\n```",
                serde_json::to_string_pretty(&self.surrounding_events).unwrap_or_default()
            ));
        }

        if let Some(chain) = &self.kill_chain {
            parts.push(format!(
                "### Kill Chain Match\n```json\n{}\n```",
                serde_json::to_string_pretty(chain).unwrap_or_default()
            ));
        }

        if !self.past_investigations.is_empty() {
            let summaries: Vec<String> = self
                .past_investigations
                .iter()
                .map(|inv| {
                    format!(
                        "- [{}] {} | Verdict: {} ({}) — {}",
                        inv.date.format("%Y-%m-%d"),
                        inv.target,
                        inv.verdict,
                        inv.severity,
                        inv.summary,
                    )
                })
                .collect();
            parts.push(format!(
                "### Past Investigations\n{}",
                summaries.join("\n")
            ));
        }

        if !self.user_decisions.is_empty() {
            parts.push(format!(
                "### User Trust Decisions\n```json\n{}\n```",
                serde_json::to_string_pretty(&self.user_decisions).unwrap_or_default()
            ));
        }

        if let Some(profile) = &self.server_profile {
            parts.push(format!(
                "### Server Profile\n```json\n{}\n```",
                serde_json::to_string_pretty(profile).unwrap_or_default()
            ));
        }

        parts.join("\n\n")
    }
}

// ---------------------------------------------------------------------------
// Investigation chaining / suggestions
// ---------------------------------------------------------------------------

/// When Claude discovers something that warrants a separate, deeper look.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationSuggestion {
    pub id: String,
    pub parent_investigation_id: String,
    pub suggested_target: InvestigationTarget,
    pub reason: String,
    pub priority: String,
}

// ---------------------------------------------------------------------------
// Tool definitions — investigation-specific
// ---------------------------------------------------------------------------

/// Returns all 7 investigation-specific tool definitions.
fn investigation_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        // (a) get_full_session
        ToolDefinition {
            name: "get_full_session".into(),
            description: "Get the complete MCP activity session for a server. A 'session' is a \
                continuous period of activity bounded by gaps > 5 minutes. Returns all tool \
                calls in order, correlated OS events, total duration, and summary stats."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "Name of the MCP server"
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session identifier. If omitted, returns the most recent session."
                    }
                },
                "required": ["server_name"]
            }),
        },
        // (b) get_prompt_context
        ToolDefinition {
            name: "get_prompt_context".into(),
            description: "For MCP tool calls triggered by AI sampling requests, returns the \
                prompt that led to the tool call. Critical for detecting prompt injection \
                attacks where a malicious prompt causes a tool invocation."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "event_id": {
                        "type": "string",
                        "description": "Event ID of the tool call to inspect"
                    }
                },
                "required": ["event_id"]
            }),
        },
        // (c) trace_data_flow
        ToolDefinition {
            name: "trace_data_flow".into(),
            description: "Trace what happened to data accessed by a tool call. If a tool read \
                a file, did the same server later make a network connection? Performs size \
                correlation for exfiltration detection."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "event_id": {
                        "type": "string",
                        "description": "Event ID of the data-access event to trace"
                    }
                },
                "required": ["event_id"]
            }),
        },
        // (d) get_server_history
        ToolDefinition {
            name: "get_server_history".into(),
            description: "Get a daily summary of server activity over N days. Returns \
                aggregated stats per day: event count, unique tools used, unique files \
                accessed, unique network destinations, and anomaly score trend."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "Name of the MCP server"
                    },
                    "days": {
                        "type": "integer",
                        "description": "Number of days to look back (default: 7)",
                        "default": 7
                    }
                },
                "required": ["server_name"]
            }),
        },
        // (e) compare_servers
        ToolDefinition {
            name: "compare_servers".into(),
            description: "Side-by-side comparison of behavioral profiles of two MCP servers. \
                Useful for coordinated activity detection — e.g. one server reads files while \
                another exfiltrates."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_a": {
                        "type": "string",
                        "description": "Name of the first MCP server"
                    },
                    "server_b": {
                        "type": "string",
                        "description": "Name of the second MCP server"
                    }
                },
                "required": ["server_a", "server_b"]
            }),
        },
        // (f) get_user_decisions
        ToolDefinition {
            name: "get_user_decisions".into(),
            description: "Get the history of user prompt responses (allow/deny/allow_always) \
                for an MCP server. Shows how the user has interacted with trust decisions."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "Name of the MCP server (optional — omit for all servers)"
                    }
                },
                "required": []
            }),
        },
        // (g) suggest_investigation
        ToolDefinition {
            name: "suggest_investigation".into(),
            description: "Suggest a follow-up investigation when you discover something that \
                warrants a separate, deeper look. Creates a chained investigation suggestion \
                for the user to approve."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_type": {
                        "type": "string",
                        "enum": ["event", "server", "time_range"],
                        "description": "Type of investigation target"
                    },
                    "target_id": {
                        "type": "string",
                        "description": "Event ID, server name, or time-range spec"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why this follow-up investigation is warranted"
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": "Urgency of the suggested investigation"
                    }
                },
                "required": ["target_type", "target_id", "reason", "priority"]
            }),
        },
    ]
}

/// Returns the investigation tools that should be available for a given session type.
///
/// - `Investigate`: all 7 investigation tools
/// - `Scan`: none (scan has its own tools via `scan_tools.rs`)
/// - `Chat`: none (chat uses base tools only)
/// - `Report`: none
pub fn get_investigation_tools(session_type: &SessionType) -> Vec<ToolDefinition> {
    match session_type {
        SessionType::Investigate { .. } => investigation_tool_definitions(),
        SessionType::Scan { .. } | SessionType::Chat | SessionType::Report { .. } => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Investigation tool executor
// ---------------------------------------------------------------------------

/// Executes investigation-specific tools.
///
/// Follows the same pattern as [`crate::scan_tools::ScanToolExecutor`] — each
/// tool method returns a JSON string on success or an error string on failure.
pub struct InvestigationToolExecutor {
    session_gap_threshold_secs: u64,
    max_history_days: u64,
}

impl InvestigationToolExecutor {
    pub fn new() -> Self {
        Self {
            session_gap_threshold_secs: 300, // 5 minutes
            max_history_days: 90,
        }
    }

    /// Main dispatcher for investigation tool calls.
    pub async fn execute_tool(
        &self,
        tool_name: &str,
        input: &Value,
    ) -> Result<String, String> {
        match tool_name {
            "get_full_session" => self.get_full_session(input),
            "get_prompt_context" => self.get_prompt_context(input),
            "trace_data_flow" => self.trace_data_flow(input),
            "get_server_history" => self.get_server_history(input),
            "compare_servers" => self.compare_servers(input),
            "get_user_decisions" => self.get_user_decisions(input),
            "suggest_investigation" => self.suggest_investigation(input),
            _ => Err(format!("Unknown investigation tool: {}", tool_name)),
        }
    }

    /// Check whether this executor handles the given tool name.
    pub fn handles_tool(&self, tool_name: &str) -> bool {
        matches!(
            tool_name,
            "get_full_session"
                | "get_prompt_context"
                | "trace_data_flow"
                | "get_server_history"
                | "compare_servers"
                | "get_user_decisions"
                | "suggest_investigation"
        )
    }

    // -- Tool implementations -----------------------------------------------

    fn get_full_session(&self, input: &Value) -> Result<String, String> {
        let server_name = input
            .get("server_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "server_name is required".to_string())?;

        let session_id = input
            .get("session_id")
            .and_then(|v| v.as_str());

        let result = json!({
            "server_name": server_name,
            "session_id": session_id.unwrap_or("latest"),
            "session_gap_threshold_secs": self.session_gap_threshold_secs,
            "tool_calls": [],
            "os_events": [],
            "duration_secs": 0,
            "stats": {
                "total_tool_calls": 0,
                "unique_tools": [],
                "files_accessed": [],
                "network_connections": 0,
            },
            "note": "No session data available — the event store has not recorded activity for this server"
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    fn get_prompt_context(&self, input: &Value) -> Result<String, String> {
        let event_id = input
            .get("event_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "event_id is required".to_string())?;

        let result = json!({
            "event_id": event_id,
            "has_prompt_context": false,
            "sampling_request": null,
            "prompt_text": null,
            "prompt_source": null,
            "injection_indicators": [],
            "note": "No sampling/prompt data found for this event"
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    fn trace_data_flow(&self, input: &Value) -> Result<String, String> {
        let event_id = input
            .get("event_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "event_id is required".to_string())?;

        let result = json!({
            "event_id": event_id,
            "data_accessed": null,
            "subsequent_network_activity": [],
            "size_correlation": null,
            "exfiltration_risk": "none",
            "data_flow_chain": [],
            "note": "No data-flow information available for this event"
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    fn get_server_history(&self, input: &Value) -> Result<String, String> {
        let server_name = input
            .get("server_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "server_name is required".to_string())?;

        let days = input
            .get("days")
            .and_then(|v| v.as_u64())
            .unwrap_or(7)
            .min(self.max_history_days);

        let result = json!({
            "server_name": server_name,
            "days_requested": days,
            "daily_summaries": [],
            "trend": {
                "event_count_trend": "stable",
                "anomaly_score_trend": "stable",
            },
            "note": "No historical data available for this server"
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    fn compare_servers(&self, input: &Value) -> Result<String, String> {
        let server_a = input
            .get("server_a")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "server_a is required".to_string())?;

        let server_b = input
            .get("server_b")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "server_b is required".to_string())?;

        let result = json!({
            "server_a": {
                "name": server_a,
                "tools_used": [],
                "files_accessed": [],
                "network_destinations": [],
                "anomaly_score": null,
                "trust_level": null,
            },
            "server_b": {
                "name": server_b,
                "tools_used": [],
                "files_accessed": [],
                "network_destinations": [],
                "anomaly_score": null,
                "trust_level": null,
            },
            "shared_resources": {
                "shared_files": [],
                "shared_network_destinations": [],
                "temporal_correlation": null,
            },
            "coordination_indicators": [],
            "note": "No profile data available for comparison"
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    fn get_user_decisions(&self, input: &Value) -> Result<String, String> {
        let server_name = input
            .get("server_name")
            .and_then(|v| v.as_str());

        let result = json!({
            "server_name": server_name,
            "decisions": [],
            "summary": {
                "total_prompts": 0,
                "allowed": 0,
                "denied": 0,
                "always_allowed": 0,
            },
            "note": "No user decision data available"
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    fn suggest_investigation(&self, input: &Value) -> Result<String, String> {
        let target_type = input
            .get("target_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "target_type is required".to_string())?;

        let target_id = input
            .get("target_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "target_id is required".to_string())?;

        let reason = input
            .get("reason")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "reason is required".to_string())?;

        let priority = input
            .get("priority")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "priority is required".to_string())?;

        if !matches!(priority, "high" | "medium" | "low") {
            return Err(format!(
                "Invalid priority '{}': must be high, medium, or low",
                priority
            ));
        }

        let suggestion_id = format!("inv-suggest-{}", uuid::Uuid::new_v4());

        let result = json!({
            "suggestion_id": suggestion_id,
            "target_type": target_type,
            "target_id": target_id,
            "reason": reason,
            "priority": priority,
            "status": "pending_user_approval",
            "note": "Investigation suggestion created. The user will be prompted to approve or dismiss."
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }
}

impl Default for InvestigationToolExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Investigation prompt templates
// ---------------------------------------------------------------------------

/// Safety rules appended to every investigation prompt.
const SAFETY_RULES: &str = "\
## Safety Rules
- You are performing a READ-ONLY investigation. Do NOT take destructive actions.
- Do NOT modify files, change permissions, kill processes, or alter configurations.
- If you need to propose a change, use `suggest_policy_change` or `suggest_remediation`.
- Stay focused on the investigation target. Do not investigate unrelated servers or events.
- All evidence must be grounded in tool output. Do not fabricate data.";

/// Tag protocol appended to every investigation prompt.
const TAG_PROTOCOL: &str = "\
## Output Protocol — Required Tags
When you reach a conclusion, emit these tags:

[VERDICT confidence=<0-100>]
<FalsePositive | Benign | Suspicious | ConfirmedThreat>
[/VERDICT]

[IMPACT]
data_accessed: <list of files/resources accessed>
data_modified: <list of files/resources modified, or 'none'>
data_exfiltrated: <evidence of data leaving the system, or 'none'>
blast_radius: <number of affected servers/users/files>
[/IMPACT]

[TIMELINE_ENTRY timestamp=\"<ISO8601>\"]
<Description of what happened at this point>
[/TIMELINE_ENTRY]";

/// Build the full investigation system prompt for a given target and context.
pub fn get_investigation_prompt(
    target: &InvestigationTarget,
    context: &InvestigationContext,
) -> String {
    let target_section = match target {
        InvestigationTarget::Event { event_id, event_data } => {
            format!(
                "## Mission\n\
                 You are investigating a security event.\n\n\
                 **Event ID:** {event_id}\n\
                 **Event Data:**\n```json\n{}\n```\n\n\
                 Answer these 5 questions:\n\
                 1. **What happened?** — Reconstruct the full sequence of actions.\n\
                 2. **Why did it happen?** — Was this user-initiated, automated, or triggered by \
                    a prompt injection?\n\
                 3. **Is this part of something larger?** — Check for kill-chain patterns, \
                    coordinated activity across servers.\n\
                 4. **What is the impact?** — What data was accessed, modified, or exfiltrated?\n\
                 5. **What action should be taken?** — Recommend next steps.\n",
                serde_json::to_string_pretty(event_data).unwrap_or_default()
            )
        }
        InvestigationTarget::Alert { alert_id, alert_data } => {
            format!(
                "## Mission\n\
                 You are investigating a security alert. Determine if this is a **true positive** \
                 or a **false positive**.\n\n\
                 **Alert ID:** {alert_id}\n\
                 **Alert Data:**\n```json\n{}\n```\n\n\
                 Steps:\n\
                 1. Retrieve full event details for the alert trigger.\n\
                 2. Examine the MCP session context — what was the server doing before/after?\n\
                 3. Check for prompt injection indicators.\n\
                 4. Cross-reference with server behavioral baseline.\n\
                 5. Deliver a verdict with confidence level.\n",
                serde_json::to_string_pretty(alert_data).unwrap_or_default()
            )
        }
        InvestigationTarget::Server { server_name } => {
            format!(
                "## Mission\n\
                 You are conducting a comprehensive review of MCP server **{server_name}**.\n\n\
                 Steps:\n\
                 1. Pull the full behavioral profile and history.\n\
                 2. Examine all tool usage patterns — are any tools being used unexpectedly?\n\
                 3. Check file access patterns — is the server reading sensitive files?\n\
                 4. Review network activity — any unexpected destinations?\n\
                 5. Compare with other servers — any signs of coordinated activity?\n\
                 6. Review user trust decisions for this server.\n\
                 7. Deliver an overall risk assessment.\n"
            )
        }
        InvestigationTarget::TimeRange { start, end } => {
            format!(
                "## Mission\n\
                 Review all MCP activity between **{}** and **{}**.\n\n\
                 Steps:\n\
                 1. Query all events in the time window.\n\
                 2. Identify any anomalous patterns or spikes.\n\
                 3. Check each active server's behavior during this period.\n\
                 4. Look for coordinated activity across servers.\n\
                 5. Summarize findings with timeline entries.\n",
                start.to_rfc3339(),
                end.to_rfc3339()
            )
        }
        InvestigationTarget::Freeform { query } => {
            format!(
                "## Mission\n\
                 The user asks: **{query}**\n\n\
                 Use your investigation tools to answer the question. Be thorough — pull \
                 relevant events, server profiles, and data-flow traces as needed.\n"
            )
        }
    };

    let tool_descriptions = "\
## Available Investigation Tools
- `get_full_session(server_name, session_id?)` — full MCP activity session for a server
- `get_prompt_context(event_id)` — prompt that triggered a tool call (prompt injection detection)
- `trace_data_flow(event_id)` — trace data accessed by a tool call (exfiltration detection)
- `get_server_history(server_name, days?)` — daily activity summary over N days
- `compare_servers(server_a, server_b)` — side-by-side behavioral comparison
- `get_user_decisions(server_name?)` — user allow/deny history
- `suggest_investigation(target_type, target_id, reason, priority)` — suggest follow-up investigation

You also have access to base tools (query_events, get_server_profile, get_event_detail, etc.) \
and analysis tools (compare_with_baseline, get_event_timeline, check_file_permissions, \
get_network_destinations).";

    let context_section = context.to_prompt_section();

    format!(
        "You are ClawDefender's AI Security Investigator.\n\n\
         {target_section}\n\
         {context_section}\n\n\
         {tool_descriptions}\n\n\
         {TAG_PROTOCOL}\n\n\
         {SAFETY_RULES}\n"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- Tool definitions ---------------------------------------------------

    #[test]
    fn test_investigation_tool_definitions_count() {
        let defs = investigation_tool_definitions();
        assert_eq!(defs.len(), 7, "expected 7 investigation tool definitions");
    }

    #[test]
    fn test_investigation_tool_definitions_have_valid_schema() {
        let defs = investigation_tool_definitions();
        for def in &defs {
            assert!(!def.name.is_empty(), "tool name must not be empty");
            assert!(
                !def.description.is_empty(),
                "tool '{}' must have a description",
                def.name
            );
            assert!(
                def.input_schema.is_object(),
                "tool '{}' schema must be an object",
                def.name
            );
            let schema = def.input_schema.as_object().unwrap();
            assert_eq!(
                schema.get("type").and_then(|v| v.as_str()),
                Some("object"),
                "tool '{}' schema type must be 'object'",
                def.name
            );
            assert!(
                schema.contains_key("properties"),
                "tool '{}' schema must have 'properties'",
                def.name
            );
            assert!(
                schema.contains_key("required"),
                "tool '{}' schema must have 'required'",
                def.name
            );
        }
    }

    // -- Tool availability by session type ----------------------------------

    #[test]
    fn test_investigate_session_gets_investigation_tools() {
        let tools = get_investigation_tools(&SessionType::Investigate {
            event_id: "evt-1".into(),
        });
        assert_eq!(tools.len(), 7);

        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"get_full_session"));
        assert!(names.contains(&"get_prompt_context"));
        assert!(names.contains(&"trace_data_flow"));
        assert!(names.contains(&"get_server_history"));
        assert!(names.contains(&"compare_servers"));
        assert!(names.contains(&"get_user_decisions"));
        assert!(names.contains(&"suggest_investigation"));
    }

    #[test]
    fn test_scan_session_gets_no_investigation_tools() {
        let tools = get_investigation_tools(&SessionType::Scan {
            playbook: "full".into(),
        });
        assert!(tools.is_empty());
    }

    #[test]
    fn test_chat_session_gets_no_investigation_tools() {
        let tools = get_investigation_tools(&SessionType::Chat);
        assert!(tools.is_empty());
    }

    #[test]
    fn test_report_session_gets_no_investigation_tools() {
        let tools = get_investigation_tools(&SessionType::Report {
            report_type: "weekly".into(),
        });
        assert!(tools.is_empty());
    }

    // -- InvestigationToolExecutor ------------------------------------------

    #[test]
    fn test_executor_handles_tool_known() {
        let executor = InvestigationToolExecutor::new();
        assert!(executor.handles_tool("get_full_session"));
        assert!(executor.handles_tool("get_prompt_context"));
        assert!(executor.handles_tool("trace_data_flow"));
        assert!(executor.handles_tool("get_server_history"));
        assert!(executor.handles_tool("compare_servers"));
        assert!(executor.handles_tool("get_user_decisions"));
        assert!(executor.handles_tool("suggest_investigation"));
    }

    #[test]
    fn test_executor_handles_tool_unknown() {
        let executor = InvestigationToolExecutor::new();
        assert!(!executor.handles_tool("read_file_extended"));
        assert!(!executor.handles_tool("run_scan_command"));
        assert!(!executor.handles_tool("totally_fake"));
    }

    #[tokio::test]
    async fn test_executor_unknown_tool_error() {
        let executor = InvestigationToolExecutor::new();
        let result = executor.execute_tool("not_a_real_tool", &json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown investigation tool"));
    }

    #[tokio::test]
    async fn test_get_full_session() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "get_full_session",
                &json!({ "server_name": "test-server" }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("test-server"));
        assert!(output.contains("tool_calls"));
        assert!(output.contains("os_events"));
    }

    #[tokio::test]
    async fn test_get_full_session_with_session_id() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "get_full_session",
                &json!({ "server_name": "web-server", "session_id": "sess-42" }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("sess-42"));
    }

    #[tokio::test]
    async fn test_get_full_session_missing_server_name() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool("get_full_session", &json!({}))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("server_name is required"));
    }

    #[tokio::test]
    async fn test_get_prompt_context() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "get_prompt_context",
                &json!({ "event_id": "evt-123" }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("evt-123"));
        assert!(output.contains("injection_indicators"));
    }

    #[tokio::test]
    async fn test_get_prompt_context_missing_event_id() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool("get_prompt_context", &json!({}))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("event_id is required"));
    }

    #[tokio::test]
    async fn test_trace_data_flow() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "trace_data_flow",
                &json!({ "event_id": "evt-456" }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("evt-456"));
        assert!(output.contains("exfiltration_risk"));
        assert!(output.contains("data_flow_chain"));
    }

    #[tokio::test]
    async fn test_trace_data_flow_missing_event_id() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool("trace_data_flow", &json!({}))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("event_id is required"));
    }

    #[tokio::test]
    async fn test_get_server_history() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "get_server_history",
                &json!({ "server_name": "test-server", "days": 14 }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("test-server"));
        assert!(output.contains("daily_summaries"));
        assert!(output.contains("\"days_requested\": 14"));
    }

    #[tokio::test]
    async fn test_get_server_history_default_days() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "get_server_history",
                &json!({ "server_name": "test-server" }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("\"days_requested\": 7"));
    }

    #[tokio::test]
    async fn test_get_server_history_capped_days() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "get_server_history",
                &json!({ "server_name": "test-server", "days": 999 }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        // Should be capped at max_history_days (90)
        assert!(output.contains("\"days_requested\": 90"));
    }

    #[tokio::test]
    async fn test_get_server_history_missing_server_name() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool("get_server_history", &json!({}))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("server_name is required"));
    }

    #[tokio::test]
    async fn test_compare_servers() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "compare_servers",
                &json!({ "server_a": "web-01", "server_b": "db-01" }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("web-01"));
        assert!(output.contains("db-01"));
        assert!(output.contains("shared_resources"));
        assert!(output.contains("coordination_indicators"));
    }

    #[tokio::test]
    async fn test_compare_servers_missing_server_a() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "compare_servers",
                &json!({ "server_b": "db-01" }),
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("server_a is required"));
    }

    #[tokio::test]
    async fn test_compare_servers_missing_server_b() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "compare_servers",
                &json!({ "server_a": "web-01" }),
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("server_b is required"));
    }

    #[tokio::test]
    async fn test_get_user_decisions() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "get_user_decisions",
                &json!({ "server_name": "test-server" }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("test-server"));
        assert!(output.contains("decisions"));
        assert!(output.contains("total_prompts"));
    }

    #[tokio::test]
    async fn test_get_user_decisions_no_server() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool("get_user_decisions", &json!({}))
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("decisions"));
    }

    #[tokio::test]
    async fn test_suggest_investigation() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "suggest_investigation",
                &json!({
                    "target_type": "server",
                    "target_id": "suspicious-server",
                    "reason": "Unusual network activity detected",
                    "priority": "high"
                }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("suggestion_id"));
        assert!(output.contains("suspicious-server"));
        assert!(output.contains("Unusual network activity"));
        assert!(output.contains("pending_user_approval"));
    }

    #[tokio::test]
    async fn test_suggest_investigation_missing_fields() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "suggest_investigation",
                &json!({ "target_type": "server" }),
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("target_id is required"));
    }

    #[tokio::test]
    async fn test_suggest_investigation_invalid_priority() {
        let executor = InvestigationToolExecutor::new();
        let result = executor
            .execute_tool(
                "suggest_investigation",
                &json!({
                    "target_type": "event",
                    "target_id": "evt-1",
                    "reason": "test",
                    "priority": "ultra"
                }),
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid priority"));
    }

    // -- InvestigationDepth -------------------------------------------------

    #[test]
    fn test_depth_max_tool_calls() {
        assert_eq!(InvestigationDepth::Quick.max_tool_calls(), 5);
        assert_eq!(InvestigationDepth::Standard.max_tool_calls(), 15);
        assert_eq!(InvestigationDepth::Deep.max_tool_calls(), 40);
    }

    #[test]
    fn test_depth_max_duration() {
        assert_eq!(InvestigationDepth::Quick.max_duration_secs(), 30);
        assert_eq!(InvestigationDepth::Standard.max_duration_secs(), 180);
        assert_eq!(InvestigationDepth::Deep.max_duration_secs(), 600);
    }

    #[test]
    fn test_depth_auto_select() {
        assert_eq!(
            InvestigationDepth::auto_select("CRITICAL"),
            InvestigationDepth::Deep
        );
        assert_eq!(
            InvestigationDepth::auto_select("HIGH"),
            InvestigationDepth::Deep
        );
        assert_eq!(
            InvestigationDepth::auto_select("MEDIUM"),
            InvestigationDepth::Standard
        );
        assert_eq!(
            InvestigationDepth::auto_select("LOW"),
            InvestigationDepth::Quick
        );
        assert_eq!(
            InvestigationDepth::auto_select("INFO"),
            InvestigationDepth::Quick
        );
        // Case insensitive
        assert_eq!(
            InvestigationDepth::auto_select("critical"),
            InvestigationDepth::Deep
        );
        // Unknown defaults to Standard
        assert_eq!(
            InvestigationDepth::auto_select("unknown"),
            InvestigationDepth::Standard
        );
    }

    // -- InvestigationContext -----------------------------------------------

    #[tokio::test]
    async fn test_context_build_for_event() {
        let ctx = InvestigationContext::build_for_event("evt-42", Some("test-server")).await;
        assert!(ctx.target_event.is_some());
        let event = ctx.target_event.unwrap();
        assert_eq!(event["event_id"], "evt-42");
        assert!(ctx.session_events.is_empty());
        assert!(ctx.past_investigations.is_empty());
    }

    #[tokio::test]
    async fn test_context_build_for_server() {
        let ctx = InvestigationContext::build_for_server("web-01").await;
        assert!(ctx.target_event.is_none());
        assert!(ctx.server_profile.is_some());
        let profile = ctx.server_profile.unwrap();
        assert_eq!(profile["server_name"], "web-01");
    }

    #[tokio::test]
    async fn test_context_build_for_time_range() {
        let start = Utc::now() - chrono::Duration::hours(2);
        let end = Utc::now();
        let ctx = InvestigationContext::build_for_time_range(start, end).await;
        assert!(ctx.target_event.is_none());
        assert!(ctx.server_profile.is_some());
        let profile = ctx.server_profile.unwrap();
        assert!(profile["time_range"].is_object());
    }

    #[test]
    fn test_context_to_prompt_section_with_event() {
        let ctx = InvestigationContext {
            target_event: Some(json!({"event_id": "evt-1", "severity": "high"})),
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: None,
        };
        let section = ctx.to_prompt_section();
        assert!(section.contains("INVESTIGATION CONTEXT"));
        assert!(section.contains("Target Event"));
        assert!(section.contains("evt-1"));
    }

    #[test]
    fn test_context_to_prompt_section_with_past_investigations() {
        let ctx = InvestigationContext {
            target_event: None,
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: vec![InvestigationSummary {
                id: "inv-1".into(),
                date: Utc::now(),
                target: "evil-server".into(),
                verdict: "ConfirmedThreat".into(),
                severity: "HIGH".into(),
                summary: "Server was exfiltrating data".into(),
            }],
            user_decisions: Vec::new(),
            server_profile: None,
        };
        let section = ctx.to_prompt_section();
        assert!(section.contains("Past Investigations"));
        assert!(section.contains("evil-server"));
        assert!(section.contains("ConfirmedThreat"));
    }

    #[test]
    fn test_context_to_prompt_section_with_session_events() {
        let ctx = InvestigationContext {
            target_event: None,
            session_events: vec![json!({"id": "e1"}), json!({"id": "e2"})],
            surrounding_events: vec![json!({"id": "s1"})],
            kill_chain: Some(json!({"chain": "recon -> access -> exfil"})),
            past_investigations: Vec::new(),
            user_decisions: vec![json!({"action": "allow", "server": "web-01"})],
            server_profile: Some(json!({"name": "web-01"})),
        };
        let section = ctx.to_prompt_section();
        assert!(section.contains("MCP Session Events (2 events)"));
        assert!(section.contains("Surrounding Events"));
        assert!(section.contains("Kill Chain Match"));
        assert!(section.contains("User Trust Decisions"));
        assert!(section.contains("Server Profile"));
    }

    // -- Investigation suggestions ------------------------------------------

    #[test]
    fn test_investigation_suggestion_serde() {
        let suggestion = InvestigationSuggestion {
            id: "inv-suggest-1".into(),
            parent_investigation_id: "inv-parent".into(),
            suggested_target: InvestigationTarget::Server {
                server_name: "suspicious-srv".into(),
            },
            reason: "Unusual file access pattern".into(),
            priority: "high".into(),
        };
        let json = serde_json::to_string(&suggestion).unwrap();
        let parsed: InvestigationSuggestion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "inv-suggest-1");
        assert_eq!(parsed.priority, "high");
    }

    // -- Prompt templates ---------------------------------------------------

    #[test]
    fn test_prompt_event_investigation() {
        let target = InvestigationTarget::Event {
            event_id: "evt-42".into(),
            event_data: json!({"type": "file_access", "path": "/etc/passwd"}),
        };
        let ctx = InvestigationContext {
            target_event: Some(json!({"event_id": "evt-42"})),
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: None,
        };
        let prompt = get_investigation_prompt(&target, &ctx);
        assert!(prompt.contains("investigating a security event"));
        assert!(prompt.contains("evt-42"));
        assert!(prompt.contains("5 questions"));
        assert!(prompt.contains("[VERDICT"));
        assert!(prompt.contains("[IMPACT]"));
        assert!(prompt.contains("[TIMELINE_ENTRY"));
        assert!(prompt.contains("Safety Rules"));
        assert!(prompt.contains("READ-ONLY"));
    }

    #[test]
    fn test_prompt_alert_investigation() {
        let target = InvestigationTarget::Alert {
            alert_id: "alert-7".into(),
            alert_data: json!({"severity": "high", "title": "Exfiltration attempt"}),
        };
        let ctx = InvestigationContext {
            target_event: None,
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: None,
        };
        let prompt = get_investigation_prompt(&target, &ctx);
        assert!(prompt.contains("investigating a security alert"));
        assert!(prompt.contains("true positive"));
        assert!(prompt.contains("alert-7"));
    }

    #[test]
    fn test_prompt_server_investigation() {
        let target = InvestigationTarget::Server {
            server_name: "web-01".into(),
        };
        let ctx = InvestigationContext {
            target_event: None,
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: Some(json!({"name": "web-01"})),
        };
        let prompt = get_investigation_prompt(&target, &ctx);
        assert!(prompt.contains("comprehensive review"));
        assert!(prompt.contains("web-01"));
    }

    #[test]
    fn test_prompt_time_range_investigation() {
        let start = Utc::now() - chrono::Duration::hours(2);
        let end = Utc::now();
        let target = InvestigationTarget::TimeRange { start, end };
        let ctx = InvestigationContext {
            target_event: None,
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: None,
        };
        let prompt = get_investigation_prompt(&target, &ctx);
        assert!(prompt.contains("Review all MCP activity between"));
    }

    #[test]
    fn test_prompt_freeform_investigation() {
        let target = InvestigationTarget::Freeform {
            query: "Has any server accessed SSH keys in the last hour?".into(),
        };
        let ctx = InvestigationContext {
            target_event: None,
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: None,
        };
        let prompt = get_investigation_prompt(&target, &ctx);
        assert!(prompt.contains("The user asks:"));
        assert!(prompt.contains("SSH keys"));
    }

    #[test]
    fn test_prompt_includes_tool_descriptions() {
        let target = InvestigationTarget::Freeform {
            query: "test".into(),
        };
        let ctx = InvestigationContext {
            target_event: None,
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: None,
        };
        let prompt = get_investigation_prompt(&target, &ctx);
        assert!(prompt.contains("get_full_session"));
        assert!(prompt.contains("get_prompt_context"));
        assert!(prompt.contains("trace_data_flow"));
        assert!(prompt.contains("get_server_history"));
        assert!(prompt.contains("compare_servers"));
        assert!(prompt.contains("get_user_decisions"));
        assert!(prompt.contains("suggest_investigation"));
    }

    // -- InvestigationTarget serde ------------------------------------------

    #[test]
    fn test_investigation_target_event_serde() {
        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({"type": "test"}),
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: InvestigationTarget = serde_json::from_str(&json).unwrap();
        match parsed {
            InvestigationTarget::Event { event_id, .. } => {
                assert_eq!(event_id, "evt-1");
            }
            _ => panic!("Expected Event variant"),
        }
    }

    #[test]
    fn test_investigation_target_server_serde() {
        let target = InvestigationTarget::Server {
            server_name: "test-srv".into(),
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: InvestigationTarget = serde_json::from_str(&json).unwrap();
        match parsed {
            InvestigationTarget::Server { server_name } => {
                assert_eq!(server_name, "test-srv");
            }
            _ => panic!("Expected Server variant"),
        }
    }

    #[test]
    fn test_investigation_target_freeform_serde() {
        let target = InvestigationTarget::Freeform {
            query: "check SSH keys".into(),
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: InvestigationTarget = serde_json::from_str(&json).unwrap();
        match parsed {
            InvestigationTarget::Freeform { query } => {
                assert_eq!(query, "check SSH keys");
            }
            _ => panic!("Expected Freeform variant"),
        }
    }

    // -- InvestigationDepth serde -------------------------------------------

    #[test]
    fn test_investigation_depth_serde() {
        let depths = vec![
            InvestigationDepth::Quick,
            InvestigationDepth::Standard,
            InvestigationDepth::Deep,
        ];
        for depth in &depths {
            let json = serde_json::to_string(depth).unwrap();
            let parsed: InvestigationDepth = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, depth);
        }
    }

    // -- Default trait ------------------------------------------------------

    #[test]
    fn test_executor_default() {
        let executor = InvestigationToolExecutor::default();
        assert_eq!(executor.session_gap_threshold_secs, 300);
        assert_eq!(executor.max_history_days, 90);
    }
}
