//! Security tests for the ClawDefender MCP server.
//!
//! Verifies rate limiting, scope validation, payload limits, input validation,
//! and HTTP authentication.

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
    let _ = f.into_temp_path();

    let logger = Arc::new(TestAuditLogger::new());
    Arc::new(McpServer::new(Box::new(engine), logger))
}

fn make_check_intent_msg(id: u32, target: &str) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "checkIntent",
            "arguments": {
                "description": "Read a file",
                "action_type": "file_read",
                "target": target
            }
        }
    }))
    .unwrap()
}

fn make_request_permission_msg(id: u32, resource: &str) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "requestPermission",
            "arguments": {
                "resource": resource,
                "operation": "read",
                "justification": "Need access"
            }
        }
    }))
    .unwrap()
}

fn make_report_action_msg(id: u32, description: &str, target: &str) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "reportAction",
            "arguments": {
                "description": description,
                "action_type": "file_write",
                "target": target,
                "result": "success"
            }
        }
    }))
    .unwrap()
}

// ---------------------------------------------------------------------------
// Prompt flooding: requestPermission rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_prompt_flooding_rate_limit() {
    let server = make_test_server(test_policy_toml());

    // Send 20 requestPermission calls rapidly.
    let mut blocked_count = 0;
    for i in 0..20 {
        let msg = make_request_permission_msg(i + 1, &format!("/project/file{i}.txt"));
        let resp_str = protocol::handle_message(&server, &msg).await.unwrap();
        let resp: Value = serde_json::from_str(&resp_str).unwrap();

        if resp.get("error").is_some() {
            let code = resp["error"]["code"].as_i64().unwrap();
            if code == -32000 {
                // RATE_LIMITED
                blocked_count += 1;
            }
        }
    }

    // At least some should be rate-limited (limit is 10/60s)
    assert!(
        blocked_count >= 10,
        "Expected at least 10 rate-limited responses, got {blocked_count}"
    );
}

// ---------------------------------------------------------------------------
// checkIntent rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_check_intent_rate_limit() {
    let server = make_test_server(test_policy_toml());

    // Send 110 checkIntent calls to exceed the 100/minute limit.
    let mut blocked_count = 0;
    for i in 0..110 {
        let msg = make_check_intent_msg(i + 1, "/tmp/test.txt");
        let resp_str = protocol::handle_message(&server, &msg).await.unwrap();
        let resp: Value = serde_json::from_str(&resp_str).unwrap();

        if resp.get("error").is_some() {
            let code = resp["error"]["code"].as_i64().unwrap();
            if code == -32000 {
                blocked_count += 1;
            }
        }
    }

    assert!(
        blocked_count >= 10,
        "Expected at least 10 rate-limited checkIntent responses, got {blocked_count}"
    );
}

// ---------------------------------------------------------------------------
// Scope escalation: wildcards in resource path rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_scope_escalation_wildcard_rejected() {
    let server = make_test_server(test_policy_toml());

    // Try requesting permission with a wildcard path.
    let msg = make_request_permission_msg(1, "/home/user/.ssh/*");
    let resp_str = protocol::handle_message(&server, &msg).await.unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();

    assert!(
        resp.get("error").is_some(),
        "Wildcard resource path should be rejected"
    );
    let error_msg = resp["error"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("no wildcards"),
        "Error should mention wildcards: {error_msg}"
    );
}

#[tokio::test]
async fn test_scope_escalation_exact_path_allowed() {
    let server = make_test_server(test_policy_toml());

    // Request permission for an exact path should work.
    let msg = make_request_permission_msg(1, "/project/specific-file.txt");
    let resp_str = protocol::handle_message(&server, &msg).await.unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();

    // Should succeed (no error).
    assert!(
        resp.get("error").is_none(),
        "Exact resource path should be accepted, got: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Audit pollution: oversized reportAction payload rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_oversized_report_action_rejected() {
    let server = make_test_server(test_policy_toml());

    // Create a 1 MB payload.
    let huge_details = "x".repeat(1_000_000);
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "reportAction",
            "arguments": {
                "description": "Wrote file",
                "action_type": "file_write",
                "target": "/tmp/out.txt",
                "result": "success",
                "details": {"data": huge_details}
            }
        }
    }))
    .unwrap();

    let resp_str = protocol::handle_message(&server, &msg).await.unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();

    assert!(
        resp.get("error").is_some(),
        "Oversized payload should be rejected"
    );
    let code = resp["error"]["code"].as_i64().unwrap();
    assert_eq!(code, -32001, "Error code should be PAYLOAD_TOO_LARGE");
}

// ---------------------------------------------------------------------------
// Input validation: null bytes, bidi control, oversized strings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_null_byte_in_target_rejected() {
    let server = make_test_server(test_policy_toml());

    let msg = make_check_intent_msg(1, "/tmp/safe\0../../etc/passwd");
    let resp_str = protocol::handle_message(&server, &msg).await.unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();

    assert!(
        resp.get("error").is_some(),
        "Null byte in target should be rejected"
    );
    let error_msg = resp["error"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("null byte"),
        "Error should mention null byte: {error_msg}"
    );
}

#[tokio::test]
async fn test_bidi_control_in_description_rejected() {
    let server = make_test_server(test_policy_toml());

    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "checkIntent",
            "arguments": {
                "description": format!("normal\u{202E}reversed"),
                "action_type": "file_read",
                "target": "/tmp/test.txt"
            }
        }
    }))
    .unwrap();

    let resp_str = protocol::handle_message(&server, &msg).await.unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();

    assert!(
        resp.get("error").is_some(),
        "Bidi control character should be rejected"
    );
    let error_msg = resp["error"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("bidirectional"),
        "Error should mention bidirectional: {error_msg}"
    );
}

#[tokio::test]
async fn test_oversized_string_field_rejected() {
    let server = make_test_server(test_policy_toml());

    let huge_desc = "a".repeat(5000);
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "checkIntent",
            "arguments": {
                "description": huge_desc,
                "action_type": "file_read",
                "target": "/tmp/test.txt"
            }
        }
    }))
    .unwrap();

    let resp_str = protocol::handle_message(&server, &msg).await.unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();

    assert!(
        resp.get("error").is_some(),
        "Oversized string field should be rejected"
    );
    let error_msg = resp["error"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("maximum length"),
        "Error should mention maximum length: {error_msg}"
    );
}

// ---------------------------------------------------------------------------
// HTTP auth: validate_bearer_token
// ---------------------------------------------------------------------------

#[test]
fn test_http_auth_valid_token() {
    assert!(clawdefender_mcp_server::auth::validate_bearer_token(
        "Bearer test_token_123",
        "test_token_123"
    ));
}

#[test]
fn test_http_auth_invalid_token() {
    assert!(!clawdefender_mcp_server::auth::validate_bearer_token(
        "Bearer wrong_token",
        "test_token_123"
    ));
}

#[test]
fn test_http_auth_missing_bearer() {
    assert!(!clawdefender_mcp_server::auth::validate_bearer_token(
        "test_token_123",
        "test_token_123"
    ));
}

#[test]
fn test_http_auth_empty_header() {
    assert!(!clawdefender_mcp_server::auth::validate_bearer_token(
        "",
        "test_token_123"
    ));
}

// ---------------------------------------------------------------------------
// reportAction rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_report_action_rate_limit() {
    let server = make_test_server(test_policy_toml());

    // Send 1010 reportAction calls to exceed the 1000/minute limit.
    let mut blocked_count = 0;
    for i in 0..1010 {
        let msg = make_report_action_msg(i + 1, &format!("action {i}"), "/tmp/test.txt");
        let resp_str = protocol::handle_message(&server, &msg).await.unwrap();
        let resp: Value = serde_json::from_str(&resp_str).unwrap();

        if resp.get("error").is_some() {
            let code = resp["error"]["code"].as_i64().unwrap();
            if code == -32000 {
                blocked_count += 1;
            }
        }
    }

    assert!(
        blocked_count >= 10,
        "Expected at least 10 rate-limited reportAction responses, got {blocked_count}"
    );
}

// ---------------------------------------------------------------------------
// Validation module unit tests (via integration)
// ---------------------------------------------------------------------------

#[test]
fn test_validation_valid_string() {
    assert!(clawdefender_mcp_server::validation::validate_string_field("test", "hello").is_ok());
}

#[test]
fn test_validation_null_byte() {
    assert!(clawdefender_mcp_server::validation::validate_string_field("test", "he\0llo").is_err());
}

#[test]
fn test_validation_bidi_char() {
    let val = format!("normal\u{202E}reversed");
    assert!(clawdefender_mcp_server::validation::validate_string_field("test", &val).is_err());
}

#[test]
fn test_validation_oversized() {
    let val = "a".repeat(5000);
    assert!(clawdefender_mcp_server::validation::validate_string_field("test", &val).is_err());
}

#[test]
fn test_validation_payload_size_ok() {
    assert!(clawdefender_mcp_server::validation::validate_payload_size(1024).is_ok());
}

#[test]
fn test_validation_payload_size_exceeded() {
    assert!(clawdefender_mcp_server::validation::validate_payload_size(20_000).is_err());
}

#[test]
fn test_resource_path_exact_rejects_wildcards() {
    assert!(
        clawdefender_mcp_server::validation::validate_resource_path_exact("/home/user/.ssh/*")
            .is_err()
    );
    assert!(
        clawdefender_mcp_server::validation::validate_resource_path_exact("/home/user/.ssh/config")
            .is_ok()
    );
}
