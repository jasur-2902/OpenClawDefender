//! Tool definitions for Claude-driven security investigation.
//!
//! Each tool is defined in Anthropic API format so it can be sent directly
//! as part of a `tools` array in a messages request.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A tool that Claude can call during an investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// A request from Claude to invoke a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub input: Value,
}

/// The result returned to Claude after a tool executes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_use_id: String,
    pub content: String,
    pub is_error: bool,
}

/// Audit record for a single tool execution (privacy-safe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecution {
    pub tool_name: String,
    pub input_summary: String,
    /// SHA-256 of the output — we never store the full output.
    pub output_hash: String,
    pub timestamp: String,
    pub session_id: String,
    pub success: bool,
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Tool catalogue
// ---------------------------------------------------------------------------

/// Returns every tool definition that RookBot exposes to Claude.
pub fn get_all_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        // ── Investigation tools (read-only, safe) ─────────────────────
        ToolDefinition {
            name: "query_events".into(),
            description: "Query recent security events from the audit log. \
                Use this to find what happened in a time range or for a specific server."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "time_range": {
                        "type": "string",
                        "description": "Time window to query, e.g. 'last_hour', 'last_24h', 'today'"
                    },
                    "server": {
                        "type": "string",
                        "description": "Filter by MCP server name"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Minimum severity level"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "maximum": 50,
                        "description": "Max events to return (capped at 50)"
                    }
                },
                "required": ["time_range"]
            }),
        },
        ToolDefinition {
            name: "get_server_profile".into(),
            description: "Get the behavioral profile for an MCP server — tool usage, \
                file access patterns, network activity, anomaly history, and trust level."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "Name of the MCP server to profile"
                    }
                },
                "required": ["server_name"]
            }),
        },
        ToolDefinition {
            name: "get_event_detail".into(),
            description: "Retrieve full details for a specific security event by its ID.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "event_id": {
                        "type": "string",
                        "description": "Unique event identifier"
                    }
                },
                "required": ["event_id"]
            }),
        },
        ToolDefinition {
            name: "check_reputation".into(),
            description: "Cross-reference a server or domain against blocklists \
                and indicator-of-compromise databases."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Server name, domain, or IP to check"
                    }
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "get_policy".into(),
            description: "Return the current RookBot security policy rules.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_system_posture".into(),
            description: "Get the overall system security posture — SIP status, firewall, \
                FileVault, Gatekeeper, and other macOS security settings."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "search_events".into(),
            description: "Full-text search across recent audit records. Use when you need \
                to find events matching a keyword or pattern."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search term or pattern"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "maximum": 50,
                        "description": "Max results (capped at 50)"
                    }
                },
                "required": ["query"]
            }),
        },
        // ── System inspection tools (read-only, restricted) ───────────
        ToolDefinition {
            name: "read_file".into(),
            description: "Read the contents of a file. Restricted to a small set of \
                security-relevant configuration files."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the file"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "list_directory".into(),
            description: "List the contents of a directory. Restricted to allowed paths.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the directory"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "run_command".into(),
            description: "Execute a shell command from a strictly limited allowlist of \
                security-inspection commands (e.g. csrutil status, fdesetup status)."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The exact command to execute (must be in the allowlist)"
                    }
                },
                "required": ["command"]
            }),
        },
        // ── Action tools (require user confirmation) ──────────────────
        ToolDefinition {
            name: "suggest_policy_change".into(),
            description: "Propose a change to the security policy. This does NOT execute \
                the change — it creates a pending action for the user to approve or reject."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "rule_type": {
                        "type": "string",
                        "description": "Type of policy rule to change, e.g. 'block_server', 'rate_limit'"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target of the rule (server name, path pattern, etc.)"
                    },
                    "action": {
                        "type": "string",
                        "enum": ["add", "modify", "remove"],
                        "description": "Whether to add, modify, or remove the rule"
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Why this change is recommended"
                    }
                },
                "required": ["rule_type", "target", "action", "rationale"]
            }),
        },
        ToolDefinition {
            name: "create_alert".into(),
            description: "Create a security alert to notify the user of a finding.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Alert severity"
                    },
                    "title": {
                        "type": "string",
                        "description": "Short alert title"
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed explanation of the finding"
                    },
                    "related_events": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Event IDs related to this alert"
                    }
                },
                "required": ["severity", "title", "description"]
            }),
        },
        ToolDefinition {
            name: "suggest_remediation".into(),
            description: "Propose a remediation action for a security issue. The user \
                must approve before any fix_command is executed."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "issue": {
                        "type": "string",
                        "description": "Description of the security issue"
                    },
                    "recommendation": {
                        "type": "string",
                        "description": "Recommended remediation steps"
                    },
                    "fix_command": {
                        "type": "string",
                        "description": "Optional shell command to fix the issue (requires approval)"
                    },
                    "risk_level": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "Risk level of the proposed fix"
                    }
                },
                "required": ["issue", "recommendation"]
            }),
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_definitions_have_valid_schema() {
        let defs = get_all_tool_definitions();
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

    #[test]
    fn test_tool_count() {
        let defs = get_all_tool_definitions();
        // 7 investigation + 3 system inspection + 3 action = 13
        assert_eq!(defs.len(), 13, "expected 13 tool definitions");
    }
}
