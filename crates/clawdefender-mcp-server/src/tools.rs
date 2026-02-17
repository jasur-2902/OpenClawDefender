//! MCP tool implementations.
//!
//! Each tool function takes parameters and the shared server state,
//! executes the appropriate logic, and returns a response.

use anyhow::Result;
use chrono::Utc;
use serde_json::{json, Value};
use tracing::{debug, warn};
use uuid::Uuid;

use clawdefender_core::audit::AuditRecord;
use clawdefender_core::event::mcp::{McpEvent, McpEventKind, ResourceRead, ToolCall};
use clawdefender_core::event::Event;
use clawdefender_core::policy::PolicyAction;

use crate::suggestions;
use crate::types::*;
use crate::McpServer;

/// Execute the `checkIntent` tool.
///
/// Constructs a synthetic MCP event from the declared intent, evaluates it
/// against the policy engine, and returns the result without performing the action.
pub async fn check_intent(
    server: &McpServer,
    params: CheckIntentParams,
) -> Result<CheckIntentResponse> {
    debug!(
        "checkIntent: {} {:?} -> {}",
        params.description, params.action_type, params.target
    );

    // Build a synthetic MCP event for the policy engine.
    let event = build_synthetic_event(&params);

    // Evaluate against the policy engine.
    let policy_engine = server.policy_engine.lock().await;
    let action = policy_engine.evaluate(&event);
    drop(policy_engine);

    let (allowed, risk_level, policy_rule) = match &action {
        PolicyAction::Allow => (true, RiskLevel::Low, "allow".to_string()),
        PolicyAction::Log => (true, RiskLevel::Low, "log".to_string()),
        PolicyAction::Block => (false, RiskLevel::High, "block".to_string()),
        PolicyAction::Prompt(msg) => (false, RiskLevel::Medium, format!("prompt: {msg}")),
    };

    let explanation = format_explanation(&params, &action);

    let suggestions = if !allowed {
        Some(suggestions::suggest(&params.action_type, &params.target))
    } else {
        None
    };

    // Log the intent check to audit.
    let mut audit_record = event.to_audit_record();
    audit_record.source = "mcp-server-intent".to_string();
    audit_record.action_taken = format!("{:?}", action);
    audit_record.classification = Some(if allowed { "pass" } else { "review" }.to_string());
    let _ = server.audit_logger.log(&audit_record);

    Ok(CheckIntentResponse {
        allowed,
        risk_level,
        explanation,
        policy_rule,
        suggestions,
    })
}

/// Execute the `requestPermission` tool.
///
/// In the current implementation, this evaluates the request against the policy
/// engine. If the policy says Allow or Log, permission is granted immediately.
/// If the policy says Prompt or Block, permission is denied (in a full
/// implementation this would forward to the UI for user decision).
pub async fn request_permission(
    server: &McpServer,
    params: RequestPermissionParams,
) -> Result<RequestPermissionResponse> {
    debug!(
        "requestPermission: {} {:?} - {}",
        params.resource, params.operation, params.justification
    );

    let action_type = params.operation.to_action_type();
    let intent = CheckIntentParams {
        description: params.justification.clone(),
        action_type,
        target: params.resource.clone(),
        reason: Some(params.justification.clone()),
    };
    let event = build_synthetic_event(&intent);

    let policy_engine = server.policy_engine.lock().await;
    let action = policy_engine.evaluate(&event);
    drop(policy_engine);

    let (granted, scope) = match &action {
        PolicyAction::Allow => (true, PermissionScope::Session),
        PolicyAction::Log => (true, PermissionScope::Once),
        PolicyAction::Block => (false, PermissionScope::Once),
        PolicyAction::Prompt(_) => {
            // In a full implementation, this would send a prompt to the UI
            // and wait for the user's decision. For now, treat as denied.
            warn!("requestPermission requires user prompt for: {}", params.resource);
            (false, PermissionScope::Once)
        }
    };

    // If granted with session scope, add a session rule so future checks pass.
    // SECURITY: The rule uses the exact resource path requested — no wildcards.
    // The resource has already been validated by validate_resource_path_exact()
    // in the protocol handler before reaching this code.
    if granted && scope == PermissionScope::Session {
        let mut policy_engine = server.policy_engine.lock().await;
        let event_type = params.operation.to_action_type().to_event_type().to_string();
        policy_engine.add_session_rule(clawdefender_core::policy::PolicyRule {
            name: format!("mcp_grant_{}_{}", params.resource.replace('/', "_"), Uuid::new_v4()),
            description: format!("MCP server grant: {} on {}", params.justification, params.resource),
            match_criteria: clawdefender_core::policy::MatchCriteria {
                // Exact path only — no glob patterns allowed
                resource_paths: Some(vec![params.resource.clone()]),
                event_types: Some(vec![event_type]),
                ..Default::default()
            },
            action: PolicyAction::Allow,
            message: format!("Granted via MCP requestPermission: {}", params.justification),
            priority: 0,
        });
    }

    // Audit the permission request.
    let mut audit_record = event.to_audit_record();
    audit_record.source = "mcp-server-permission".to_string();
    audit_record.action_taken = if granted { "granted" } else { "denied" }.to_string();
    let _ = server.audit_logger.log(&audit_record);

    Ok(RequestPermissionResponse {
        granted,
        scope,
        expires_at: None,
    })
}

/// Execute the `reportAction` tool.
///
/// Records an after-the-fact audit entry for an action an agent has already performed.
pub async fn report_action(
    server: &McpServer,
    params: ReportActionParams,
) -> Result<ReportActionResponse> {
    debug!(
        "reportAction: {} {:?} -> {} ({:?})",
        params.description, params.action_type, params.target, params.result
    );

    let event_id = Uuid::new_v4().to_string();

    let record = AuditRecord {
        timestamp: Utc::now(),
        source: "mcp-server-report".to_string(),
        event_summary: format!(
            "{:?} on {}: {}",
            params.action_type, params.target, params.description
        ),
        event_details: json!({
            "description": params.description,
            "action_type": params.action_type,
            "target": params.target,
            "result": params.result,
            "details": params.details,
        }),
        rule_matched: None,
        action_taken: format!("{:?}", params.result),
        response_time_ms: None,
        session_id: None,
        direction: None,
        server_name: None,
        client_name: Some("mcp-server-reporter".to_string()),
        jsonrpc_method: Some("reportAction".to_string()),
        tool_name: None,
        arguments: Some(json!({
            "target": params.target,
            "action_type": params.action_type,
        })),
        classification: Some(match params.result {
            ActionResult::Success => "pass".to_string(),
            ActionResult::Failure => "review".to_string(),
            ActionResult::Partial => "review".to_string(),
        }),
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

    let recorded = server.audit_logger.log(&record).is_ok();

    Ok(ReportActionResponse {
        recorded,
        event_id,
    })
}

/// Execute the `getPolicy` tool.
///
/// Queries the policy engine and returns matching rules filtered by the given parameters.
pub async fn get_policy(
    server: &McpServer,
    params: GetPolicyParams,
) -> Result<GetPolicyResponse> {
    debug!(
        "getPolicy: resource={:?}, action_type={:?}, tool_name={:?}",
        params.resource, params.action_type, params.tool_name
    );

    // Build a synthetic event to test which rules would match.
    // We evaluate with multiple synthetic events to gather matching rules.
    let policy_engine = server.policy_engine.lock().await;

    // We can't directly enumerate rules through the PolicyEngine trait,
    // so we test with a synthetic event to find the first matching rule.
    let event = build_query_event(&params);
    let action = policy_engine.evaluate(&event);
    drop(policy_engine);

    let action_str = match &action {
        PolicyAction::Allow => "allow",
        PolicyAction::Block => "block",
        PolicyAction::Prompt(_) => "prompt",
        PolicyAction::Log => "log",
    };

    // Since the PolicyEngine trait only returns the first matching rule's action,
    // we report what we can determine.
    let rules = vec![PolicyRuleSummary {
        name: format!("matched_{action_str}"),
        description: format!("Policy evaluation result for query"),
        action: action_str.to_string(),
        message: match &action {
            PolicyAction::Prompt(msg) => msg.clone(),
            _ => format!("Action: {action_str}"),
        },
        priority: 0,
    }];

    Ok(GetPolicyResponse {
        rules,
        default_action: "log".to_string(),
    })
}

// --- Helper functions ---

/// Build a synthetic MCP event from checkIntent parameters for policy evaluation.
fn build_synthetic_event(params: &CheckIntentParams) -> McpEvent {
    match params.action_type {
        ActionType::FileRead | ActionType::ResourceAccess => McpEvent {
            timestamp: Utc::now(),
            source: "mcp-server".to_string(),
            kind: McpEventKind::ResourceRead(ResourceRead {
                uri: params.target.clone(),
                request_id: json!(0),
            }),
            raw_message: json!({
                "intent": params.description,
                "reason": params.reason,
            }),
        },
        ActionType::ShellExecute => McpEvent {
            timestamp: Utc::now(),
            source: "mcp-server".to_string(),
            kind: McpEventKind::ToolCall(ToolCall {
                tool_name: "shell_execute".to_string(),
                arguments: json!({
                    "command": params.target,
                    "description": params.description,
                }),
                request_id: json!(0),
            }),
            raw_message: json!({
                "intent": params.description,
                "reason": params.reason,
            }),
        },
        _ => McpEvent {
            timestamp: Utc::now(),
            source: "mcp-server".to_string(),
            kind: McpEventKind::ToolCall(ToolCall {
                tool_name: format!("{:?}", params.action_type).to_lowercase(),
                arguments: json!({
                    "target": params.target,
                    "description": params.description,
                }),
                request_id: json!(0),
            }),
            raw_message: json!({
                "intent": params.description,
                "reason": params.reason,
            }),
        },
    }
}

/// Build a synthetic event for policy query purposes.
fn build_query_event(params: &GetPolicyParams) -> McpEvent {
    if let Some(ref resource) = params.resource {
        McpEvent {
            timestamp: Utc::now(),
            source: "mcp-server".to_string(),
            kind: McpEventKind::ResourceRead(ResourceRead {
                uri: resource.clone(),
                request_id: json!(0),
            }),
            raw_message: Value::Null,
        }
    } else if let Some(ref tool_name) = params.tool_name {
        McpEvent {
            timestamp: Utc::now(),
            source: "mcp-server".to_string(),
            kind: McpEventKind::ToolCall(ToolCall {
                tool_name: tool_name.clone(),
                arguments: Value::Null,
                request_id: json!(0),
            }),
            raw_message: Value::Null,
        }
    } else {
        McpEvent {
            timestamp: Utc::now(),
            source: "mcp-server".to_string(),
            kind: McpEventKind::Other("policy_query".to_string()),
            raw_message: Value::Null,
        }
    }
}

/// Format a human-readable explanation of a policy decision.
fn format_explanation(params: &CheckIntentParams, action: &PolicyAction) -> String {
    match action {
        PolicyAction::Allow => format!(
            "Action allowed: {:?} on '{}' is permitted by current policy.",
            params.action_type, params.target
        ),
        PolicyAction::Log => format!(
            "Action allowed (logged): {:?} on '{}' is permitted but will be audited.",
            params.action_type, params.target
        ),
        PolicyAction::Block => format!(
            "Action blocked: {:?} on '{}' is not permitted by current policy.",
            params.action_type, params.target
        ),
        PolicyAction::Prompt(msg) => format!(
            "Action requires approval: {:?} on '{}'. Reason: {}",
            params.action_type, params.target, msg
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdefender_core::audit::{AuditFilter, AuditLogger, AuditRecord, AuditStats};
    use clawdefender_core::policy::engine::DefaultPolicyEngine;
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use tempfile::NamedTempFile;

    /// A simple in-memory audit logger for tests.
    struct TestAuditLogger {
        records: StdMutex<Vec<AuditRecord>>,
    }

    impl TestAuditLogger {
        fn new() -> Self {
            Self {
                records: StdMutex::new(Vec::new()),
            }
        }
    }

    impl AuditLogger for TestAuditLogger {
        fn log(&self, record: &AuditRecord) -> anyhow::Result<()> {
            self.records.lock().unwrap().push(record.clone());
            Ok(())
        }

        fn query(&self, _filter: &AuditFilter) -> anyhow::Result<Vec<AuditRecord>> {
            Ok(self.records.lock().unwrap().clone())
        }

        fn stats(&self) -> anyhow::Result<AuditStats> {
            Ok(AuditStats::default())
        }
    }

    fn test_policy_toml() -> &'static str {
        r#"
[rules.block_ssh]
description = "Block SSH key access"
action = "block"
message = "SSH key access is not allowed"
priority = 0

[rules.block_ssh.match]
resource_path = ["/home/user/.ssh/id_*"]

[rules.allow_project]
description = "Allow project file reads"
action = "allow"
message = "Project file access allowed"
priority = 1

[rules.allow_project.match]
resource_path = ["/project/**"]

[rules.prompt_exec]
description = "Prompt on shell execution"
action = "prompt"
message = "Allow shell execution?"
priority = 2

[rules.prompt_exec.match]
tool_name = ["shell_execute"]

[rules.catch_all]
description = "Log everything else"
action = "log"
message = "Logged"
priority = 100

[rules.catch_all.match]
any = true
"#
    }

    fn make_test_server(policy_toml: &str) -> Arc<McpServer> {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(policy_toml.as_bytes()).unwrap();
        f.flush().unwrap();

        let engine = DefaultPolicyEngine::load(f.path()).unwrap();
        // Keep the tempfile alive by leaking it (test only).
        let _ = f.into_temp_path();

        let logger = Arc::new(TestAuditLogger::new());
        Arc::new(McpServer::new(Box::new(engine), logger))
    }

    #[tokio::test]
    async fn check_intent_allowed_project_read() {
        let server = make_test_server(test_policy_toml());
        let params = CheckIntentParams {
            description: "Read project source".to_string(),
            action_type: ActionType::FileRead,
            target: "/project/src/main.rs".to_string(),
            reason: None,
        };
        let resp = check_intent(&server, params).await.unwrap();
        assert!(resp.allowed);
        assert_eq!(resp.risk_level, RiskLevel::Low);
        assert!(resp.suggestions.is_none());
    }

    #[tokio::test]
    async fn check_intent_blocked_ssh_key() {
        let server = make_test_server(test_policy_toml());
        let params = CheckIntentParams {
            description: "Read SSH key".to_string(),
            action_type: ActionType::FileRead,
            target: "/home/user/.ssh/id_rsa".to_string(),
            reason: None,
        };
        let resp = check_intent(&server, params).await.unwrap();
        assert!(!resp.allowed);
        assert_eq!(resp.risk_level, RiskLevel::High);
        assert!(resp.suggestions.is_some());
        let suggestions = resp.suggestions.unwrap();
        assert!(!suggestions.is_empty());
    }

    #[tokio::test]
    async fn check_intent_shell_execute_prompted() {
        let server = make_test_server(test_policy_toml());
        let params = CheckIntentParams {
            description: "Run build command".to_string(),
            action_type: ActionType::ShellExecute,
            target: "cargo build".to_string(),
            reason: Some("Need to compile the project".to_string()),
        };
        let resp = check_intent(&server, params).await.unwrap();
        assert!(!resp.allowed);
        assert_eq!(resp.risk_level, RiskLevel::Medium);
        assert!(resp.policy_rule.starts_with("prompt"));
    }

    #[tokio::test]
    async fn report_action_records_audit() {
        let server = make_test_server(test_policy_toml());
        let params = ReportActionParams {
            description: "Wrote output file".to_string(),
            action_type: ActionType::FileWrite,
            target: "/tmp/output.txt".to_string(),
            result: ActionResult::Success,
            details: Some(json!({"bytes_written": 1024})),
        };
        let resp = report_action(&server, params).await.unwrap();
        assert!(resp.recorded);
        assert!(!resp.event_id.is_empty());
    }

    #[tokio::test]
    async fn request_permission_granted_for_allowed() {
        let server = make_test_server(test_policy_toml());
        let params = RequestPermissionParams {
            resource: "/project/data/input.csv".to_string(),
            operation: Operation::Read,
            justification: "Need to read input data for analysis".to_string(),
            timeout_seconds: None,
        };
        let resp = request_permission(&server, params).await.unwrap();
        assert!(resp.granted);
    }

    #[tokio::test]
    async fn request_permission_denied_for_blocked() {
        let server = make_test_server(test_policy_toml());
        let params = RequestPermissionParams {
            resource: "/home/user/.ssh/id_ed25519".to_string(),
            operation: Operation::Read,
            justification: "Need to read SSH key".to_string(),
            timeout_seconds: None,
        };
        let resp = request_permission(&server, params).await.unwrap();
        assert!(!resp.granted);
    }

    #[tokio::test]
    async fn request_permission_creates_session_rule() {
        let server = make_test_server(test_policy_toml());

        // First verify the project path is allowed and creates a session rule.
        let params = RequestPermissionParams {
            resource: "/project/config/settings.toml".to_string(),
            operation: Operation::Read,
            justification: "Need settings".to_string(),
            timeout_seconds: None,
        };
        let resp = request_permission(&server, params).await.unwrap();
        assert!(resp.granted);
        assert_eq!(resp.scope, PermissionScope::Session);
    }

    #[tokio::test]
    async fn get_policy_returns_result() {
        let server = make_test_server(test_policy_toml());
        let params = GetPolicyParams {
            resource: Some("/home/user/.ssh/id_rsa".to_string()),
            action_type: None,
            tool_name: None,
        };
        let resp = get_policy(&server, params).await.unwrap();
        assert!(!resp.rules.is_empty());
        assert_eq!(resp.default_action, "log");
    }

    #[tokio::test]
    async fn get_policy_tool_name_query() {
        let server = make_test_server(test_policy_toml());
        let params = GetPolicyParams {
            resource: None,
            action_type: None,
            tool_name: Some("shell_execute".to_string()),
        };
        let resp = get_policy(&server, params).await.unwrap();
        assert!(!resp.rules.is_empty());
    }

    #[tokio::test]
    async fn check_intent_with_empty_policy() {
        let server = make_test_server("");
        let params = CheckIntentParams {
            description: "Read anything".to_string(),
            action_type: ActionType::FileRead,
            target: "/any/path".to_string(),
            reason: None,
        };
        let resp = check_intent(&server, params).await.unwrap();
        // Empty policy defaults to Log, which is treated as allowed.
        assert!(resp.allowed);
    }
}
