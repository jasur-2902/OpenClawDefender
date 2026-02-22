//! SDK integration flow tests.
//!
//! Tests the MCP server from the perspective of an SDK client: checking intents
//! against various policies, verifying audit records, and querying policy rules.

use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use serde_json::{json, Value};
use tempfile::NamedTempFile;

use clawdefender_core::audit::{AuditFilter, AuditLogger, AuditRecord, AuditStats};
use clawdefender_core::policy::engine::DefaultPolicyEngine;
use clawdefender_mcp_server::protocol;
use clawdefender_mcp_server::McpServer;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

struct TestAuditLogger {
    records: StdMutex<Vec<AuditRecord>>,
}

impl TestAuditLogger {
    fn new() -> Self {
        Self {
            records: StdMutex::new(Vec::new()),
        }
    }

    fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap().clone()
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

fn make_server(policy_toml: &str) -> (Arc<McpServer>, Arc<TestAuditLogger>) {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(policy_toml.as_bytes()).unwrap();
    f.flush().unwrap();
    let engine = DefaultPolicyEngine::load(f.path()).unwrap();
    let _ = f.into_temp_path();
    let logger = Arc::new(TestAuditLogger::new());
    let server = Arc::new(McpServer::new(Box::new(engine), logger.clone()));
    (server, logger)
}

fn policy_with_block_and_allow() -> &'static str {
    r#"
[rules.allow_project]
description = "Allow project file access"
action = "allow"
message = "Project access allowed"
priority = 0

[rules.allow_project.match]
resource_path = ["/project/**"]

[rules.block_secrets]
description = "Block secrets access"
action = "block"
message = "Access to secrets is prohibited"
priority = 1

[rules.block_secrets.match]
resource_path = ["/home/user/.ssh/id_*", "/etc/shadow"]

[rules.prompt_exec]
description = "Prompt on shell exec"
action = "prompt"
message = "Allow execution?"
priority = 2

[rules.prompt_exec.match]
tool_name = ["shell_execute"]

[rules.catch_all]
description = "Log rest"
action = "log"
message = "Logged"
priority = 100

[rules.catch_all.match]
any = true
"#
}

async fn call_check_intent(server: &Arc<McpServer>, action_type: &str, target: &str) -> Value {
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "checkIntent",
            "arguments": {
                "description": format!("Test: {} on {}", action_type, target),
                "action_type": action_type,
                "target": target
            }
        }
    }))
    .unwrap();
    let resp = protocol::handle_message(server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

async fn call_report_action(
    server: &Arc<McpServer>,
    action_type: &str,
    target: &str,
    result: &str,
) -> Value {
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "reportAction",
            "arguments": {
                "description": format!("Performed {} on {}", action_type, target),
                "action_type": action_type,
                "target": target,
                "result": result
            }
        }
    }))
    .unwrap();
    let resp = protocol::handle_message(server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

async fn call_get_policy(
    server: &Arc<McpServer>,
    resource: Option<&str>,
    tool_name: Option<&str>,
) -> Value {
    let mut args = json!({});
    if let Some(r) = resource {
        args["resource"] = json!(r);
    }
    if let Some(t) = tool_name {
        args["tool_name"] = json!(t);
    }
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "getPolicy",
            "arguments": args
        }
    }))
    .unwrap();
    let resp = protocol::handle_message(server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

// ---------------------------------------------------------------------------
// checkIntent: policy allows → allowed=true
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_intent_allowed_returns_true() {
    let (server, _) = make_server(policy_with_block_and_allow());
    let result = call_check_intent(&server, "file_read", "/project/src/main.rs").await;

    assert_eq!(result["allowed"], true);
    assert_eq!(result["risk_level"], "Low");
    assert!(
        result["suggestions"].is_null()
            || result["suggestions"]
                .as_array()
                .map_or(true, |a| a.is_empty())
    );
}

#[tokio::test]
async fn check_intent_allowed_has_explanation() {
    let (server, _) = make_server(policy_with_block_and_allow());
    let result = call_check_intent(&server, "file_read", "/project/src/main.rs").await;

    let explanation = result["explanation"].as_str().unwrap();
    assert!(!explanation.is_empty());
    assert!(
        explanation.contains("allowed") || explanation.contains("permitted"),
        "Explanation should mention allowed: {}",
        explanation
    );
}

// ---------------------------------------------------------------------------
// checkIntent: policy blocks → allowed=false with suggestions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_intent_blocked_returns_false() {
    let (server, _) = make_server(policy_with_block_and_allow());
    let result = call_check_intent(&server, "file_read", "/home/user/.ssh/id_rsa").await;

    assert_eq!(result["allowed"], false);
    assert_eq!(result["risk_level"], "High");
}

#[tokio::test]
async fn check_intent_blocked_includes_suggestions() {
    let (server, _) = make_server(policy_with_block_and_allow());
    let result = call_check_intent(&server, "file_read", "/home/user/.ssh/id_rsa").await;

    assert!(result["suggestions"].is_array());
    let suggestions = result["suggestions"].as_array().unwrap();
    assert!(
        !suggestions.is_empty(),
        "Blocked intent should include suggestions"
    );
}

#[tokio::test]
async fn check_intent_blocked_explanation_mentions_blocked() {
    let (server, _) = make_server(policy_with_block_and_allow());
    let result = call_check_intent(&server, "file_read", "/home/user/.ssh/id_rsa").await;

    let explanation = result["explanation"].as_str().unwrap();
    assert!(
        explanation.contains("blocked") || explanation.contains("not permitted"),
        "Blocked explanation should say blocked: {}",
        explanation
    );
}

// ---------------------------------------------------------------------------
// checkIntent: prompted action → allowed=false, risk=Medium
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_intent_prompted_returns_false_medium_risk() {
    let (server, _) = make_server(policy_with_block_and_allow());
    let result = call_check_intent(&server, "shell_execute", "cargo build").await;

    assert_eq!(result["allowed"], false);
    assert_eq!(result["risk_level"], "Medium");
}

// ---------------------------------------------------------------------------
// reportAction: creates audit record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn report_action_creates_audit_record() {
    let (server, logger) = make_server(policy_with_block_and_allow());
    let result = call_report_action(&server, "file_write", "/tmp/output.txt", "success").await;

    assert_eq!(result["recorded"], true);
    assert!(result["event_id"].as_str().unwrap().len() > 0);

    // Verify audit record source
    let records = logger.records();
    let report_records: Vec<_> = records
        .iter()
        .filter(|r| r.source.starts_with("mcp-server"))
        .collect();
    assert!(
        !report_records.is_empty(),
        "Should have audit records with mcp-server source"
    );
}

#[tokio::test]
async fn report_action_records_correct_source() {
    let (server, logger) = make_server(policy_with_block_and_allow());
    call_report_action(&server, "file_write", "/tmp/test.txt", "success").await;

    let records = logger.records();
    let report_record = records
        .iter()
        .find(|r| r.source == "mcp-server-report")
        .expect("Should have a record with source mcp-server-report");

    assert!(report_record.event_summary.contains("file_write"));
}

#[tokio::test]
async fn report_action_failure_still_records() {
    let (server, logger) = make_server(policy_with_block_and_allow());
    let result = call_report_action(&server, "file_read", "/nonexistent", "failure").await;

    assert_eq!(result["recorded"], true);
    let records = logger.records();
    assert!(!records.is_empty());
}

// ---------------------------------------------------------------------------
// getPolicy: returns matching rules
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_policy_returns_rules_for_resource() {
    let (server, _) = make_server(policy_with_block_and_allow());
    let result = call_get_policy(&server, Some("/home/user/.ssh/id_rsa"), None).await;

    assert!(result["rules"].is_array());
    let rules = result["rules"].as_array().unwrap();
    assert!(!rules.is_empty());
    assert_eq!(result["default_action"], "log");
}

#[tokio::test]
async fn get_policy_returns_rules_for_tool_name() {
    let (server, _) = make_server(policy_with_block_and_allow());
    let result = call_get_policy(&server, None, Some("shell_execute")).await;

    assert!(result["rules"].is_array());
    let rules = result["rules"].as_array().unwrap();
    assert!(!rules.is_empty());
}

#[tokio::test]
async fn get_policy_empty_query_returns_default() {
    let (server, _) = make_server(policy_with_block_and_allow());
    let result = call_get_policy(&server, None, None).await;

    assert!(result["rules"].is_array());
    assert_eq!(result["default_action"], "log");
}

// ---------------------------------------------------------------------------
// Full flow: checkIntent → action → reportAction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_sdk_flow_allowed_action() {
    let (server, logger) = make_server(policy_with_block_and_allow());

    // Step 1: Check intent
    let intent = call_check_intent(&server, "file_read", "/project/readme.md").await;
    assert_eq!(intent["allowed"], true);

    // Step 2: Perform action (simulated)
    // Step 3: Report action
    let report = call_report_action(&server, "file_read", "/project/readme.md", "success").await;
    assert_eq!(report["recorded"], true);

    // Verify both events are in audit log
    let records = logger.records();
    assert!(records.len() >= 2, "Should have at least 2 audit records");
}

#[tokio::test]
async fn full_sdk_flow_blocked_action_no_report() {
    let (server, logger) = make_server(policy_with_block_and_allow());

    // Step 1: Check intent — blocked
    let intent = call_check_intent(&server, "file_read", "/home/user/.ssh/id_ed25519").await;
    assert_eq!(intent["allowed"], false);

    // A compliant SDK would stop here and NOT perform the action.
    // Only the intent check should be logged.
    let records = logger.records();
    let intent_records: Vec<_> = records
        .iter()
        .filter(|r| r.source == "mcp-server-intent")
        .collect();
    assert!(!intent_records.is_empty(), "Intent check should be logged");
}
