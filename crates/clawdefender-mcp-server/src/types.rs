//! Shared types for the MCP server tools.

use serde::{Deserialize, Serialize};

/// Action types that an agent can declare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    FileRead,
    FileWrite,
    FileDelete,
    ShellExecute,
    NetworkRequest,
    ResourceAccess,
    Other,
}

impl ActionType {
    /// Convert to an event type string usable by the policy engine.
    pub fn to_event_type(&self) -> &str {
        match self {
            ActionType::FileRead => "open",
            ActionType::FileWrite => "open",
            ActionType::FileDelete => "unlink",
            ActionType::ShellExecute => "exec",
            ActionType::NetworkRequest => "connect",
            ActionType::ResourceAccess => "resource_read",
            ActionType::Other => "other",
        }
    }
}

/// Risk level assessed by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Operation types for permission requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Read,
    Write,
    Execute,
    Delete,
    Connect,
}

impl Operation {
    /// Convert to an action type for policy evaluation.
    pub fn to_action_type(&self) -> ActionType {
        match self {
            Operation::Read => ActionType::FileRead,
            Operation::Write => ActionType::FileWrite,
            Operation::Execute => ActionType::ShellExecute,
            Operation::Delete => ActionType::FileDelete,
            Operation::Connect => ActionType::NetworkRequest,
        }
    }
}

/// Permission scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionScope {
    Once,
    Session,
    Permanent,
}

/// Result status for reported actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionResult {
    Success,
    Failure,
    Partial,
}

// --- checkIntent ---

/// Parameters for the `checkIntent` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckIntentParams {
    /// Human-readable description of what the agent intends to do.
    pub description: String,
    /// Type of action being planned.
    pub action_type: ActionType,
    /// Target resource (file path, URL, command, etc.).
    pub target: String,
    /// Optional justification for the action.
    pub reason: Option<String>,
}

/// Response from the `checkIntent` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckIntentResponse {
    /// Whether the action would be allowed by current policy.
    pub allowed: bool,
    /// Assessed risk level.
    pub risk_level: RiskLevel,
    /// Human-readable explanation of the decision.
    pub explanation: String,
    /// Name of the policy rule that matched.
    pub policy_rule: String,
    /// Suggestions for alternative approaches if blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestions: Option<Vec<String>>,
}

// --- requestPermission ---

/// Parameters for the `requestPermission` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPermissionParams {
    /// Resource the agent wants to access.
    pub resource: String,
    /// Type of operation.
    pub operation: Operation,
    /// Why the agent needs this access.
    pub justification: String,
    /// Timeout in seconds (default 30).
    pub timeout_seconds: Option<u32>,
}

/// Response from the `requestPermission` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPermissionResponse {
    /// Whether permission was granted.
    pub granted: bool,
    /// Scope of the grant.
    pub scope: PermissionScope,
    /// When the permission expires (if scoped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

// --- reportAction ---

/// Parameters for the `reportAction` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportActionParams {
    /// Human-readable description of what happened.
    pub description: String,
    /// Type of action that was performed.
    pub action_type: ActionType,
    /// Target resource that was acted upon.
    pub target: String,
    /// Outcome of the action.
    pub result: ActionResult,
    /// Additional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Response from the `reportAction` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportActionResponse {
    /// Whether the record was successfully written.
    pub recorded: bool,
    /// Unique ID for the audit record.
    pub event_id: String,
}

// --- getPolicy ---

/// Parameters for the `getPolicy` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPolicyParams {
    /// Filter by resource path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Filter by action type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<ActionType>,
    /// Filter by tool name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
}

/// A policy rule summary returned to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleSummary {
    pub name: String,
    pub description: String,
    pub action: String,
    pub message: String,
    pub priority: u32,
}

/// Response from the `getPolicy` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPolicyResponse {
    /// Matching policy rules.
    pub rules: Vec<PolicyRuleSummary>,
    /// Default action when no rules match.
    pub default_action: String,
}
