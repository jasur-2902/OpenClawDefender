//! MCP server protocol integration tests.
//!
//! Tests the full JSON-RPC protocol handling including initialize handshake,
//! tools/list, tools/call for each tool, error handling, and ping.

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

    fn record_count(&self) -> usize {
        self.records.lock().unwrap().len()
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

fn default_policy() -> &'static str {
    r#"
[rules.allow_project]
description = "Allow project reads"
action = "allow"
message = "Allowed"
priority = 0

[rules.allow_project.match]
resource_path = ["/project/**"]

[rules.block_ssh]
description = "Block SSH keys"
action = "block"
message = "SSH key access blocked"
priority = 1

[rules.block_ssh.match]
resource_path = ["/home/user/.ssh/id_*"]

[rules.catch_all]
description = "Log everything else"
action = "log"
message = "Logged"
priority = 100

[rules.catch_all.match]
any = true
"#
}

// ---------------------------------------------------------------------------
// Protocol: initialize handshake
// ---------------------------------------------------------------------------

#[tokio::test]
async fn initialize_returns_protocol_version() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert_eq!(v["result"]["protocolVersion"], "2024-11-05");
}

#[tokio::test]
async fn initialize_returns_tools_capability() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert!(v["result"]["capabilities"]["tools"].is_object());
}

#[tokio::test]
async fn initialize_returns_server_info() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert_eq!(v["result"]["serverInfo"]["name"], "clawdefender");
    assert!(v["result"]["serverInfo"]["version"].is_string());
}

// ---------------------------------------------------------------------------
// Protocol: tools/list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tools_list_returns_four_tools() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    let tools = v["result"]["tools"].as_array().unwrap();

    assert_eq!(tools.len(), 4);
}

#[tokio::test]
async fn tools_list_has_correct_tool_names() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    let tools = v["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

    assert!(names.contains(&"checkIntent"));
    assert!(names.contains(&"requestPermission"));
    assert!(names.contains(&"reportAction"));
    assert!(names.contains(&"getPolicy"));
}

#[tokio::test]
async fn tools_list_each_tool_has_input_schema() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    let tools = v["result"]["tools"].as_array().unwrap();

    for tool in tools {
        assert!(
            tool["inputSchema"].is_object(),
            "Tool {} missing inputSchema",
            tool["name"]
        );
        assert_eq!(tool["inputSchema"]["type"], "object");
    }
}

// ---------------------------------------------------------------------------
// Protocol: tools/call — checkIntent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tools_call_check_intent_valid_params() {
    let (server, _) = make_server(default_policy());
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "checkIntent",
            "arguments": {
                "description": "Read a project file",
                "action_type": "file_read",
                "target": "/project/src/main.rs"
            }
        }
    }))
    .unwrap();

    let resp = protocol::handle_message(&server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    // Should return content with a text result
    assert!(v["result"]["content"][0]["text"].is_string());
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert!(parsed["allowed"].is_boolean());
}

// ---------------------------------------------------------------------------
// Protocol: tools/call — requestPermission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tools_call_request_permission_valid_params() {
    let (server, _) = make_server(default_policy());
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "requestPermission",
            "arguments": {
                "resource": "/project/data.csv",
                "operation": "read",
                "justification": "Need to analyze data"
            }
        }
    }))
    .unwrap();

    let resp = protocol::handle_message(&server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert!(v["result"]["content"][0]["text"].is_string());
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert!(parsed["granted"].is_boolean());
}

// ---------------------------------------------------------------------------
// Protocol: tools/call — reportAction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tools_call_report_action_valid_params() {
    let (server, logger) = make_server(default_policy());
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "reportAction",
            "arguments": {
                "description": "Wrote output file",
                "action_type": "file_write",
                "target": "/tmp/output.txt",
                "result": "success"
            }
        }
    }))
    .unwrap();

    let resp = protocol::handle_message(&server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["recorded"], true);
    assert!(parsed["event_id"].is_string());

    // Verify audit record was created
    assert!(logger.record_count() > 0);
}

// ---------------------------------------------------------------------------
// Protocol: tools/call — getPolicy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tools_call_get_policy_valid_params() {
    let (server, _) = make_server(default_policy());
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "getPolicy",
            "arguments": {
                "resource": "/project/src/main.rs"
            }
        }
    }))
    .unwrap();

    let resp = protocol::handle_message(&server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert!(parsed["rules"].is_array());
    assert!(parsed["default_action"].is_string());
}

#[tokio::test]
async fn tools_call_get_policy_no_params() {
    let (server, _) = make_server(default_policy());
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "getPolicy",
            "arguments": {}
        }
    }))
    .unwrap();

    let resp = protocol::handle_message(&server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    // Should succeed even with no filter params
    assert!(v["result"]["content"][0]["text"].is_string());
}

// ---------------------------------------------------------------------------
// Protocol: tools/call — invalid params
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tools_call_missing_tool_name() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert!(v["error"].is_object());
    assert_eq!(v["error"]["code"], -32602); // INVALID_PARAMS
}

#[tokio::test]
async fn tools_call_missing_params() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert!(v["error"].is_object());
}

#[tokio::test]
async fn tools_call_check_intent_missing_required_field() {
    let (server, _) = make_server(default_policy());
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "checkIntent",
            "arguments": {
                "description": "Read a file"
                // missing action_type and target
            }
        }
    }))
    .unwrap();

    let resp = protocol::handle_message(&server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert!(v["error"].is_object());
    assert_eq!(v["error"]["code"], -32602);
}

#[tokio::test]
async fn tools_call_report_action_invalid_result_enum() {
    let (server, _) = make_server(default_policy());
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "reportAction",
            "arguments": {
                "description": "Did something",
                "action_type": "file_read",
                "target": "/tmp/file",
                "result": "invalid_result"
            }
        }
    }))
    .unwrap();

    let resp = protocol::handle_message(&server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert!(v["error"].is_object());
    assert_eq!(v["error"]["code"], -32602);
}

// ---------------------------------------------------------------------------
// Protocol: unknown method
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_method_returns_method_not_found() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","id":1,"method":"nonexistent/method"}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert_eq!(v["error"]["code"], -32601); // METHOD_NOT_FOUND
}

#[tokio::test]
async fn unknown_tool_returns_method_not_found() {
    let (server, _) = make_server(default_policy());
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "nonexistentTool",
            "arguments": {}
        }
    }))
    .unwrap();

    let resp = protocol::handle_message(&server, &msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert_eq!(v["error"]["code"], -32601);
}

// ---------------------------------------------------------------------------
// Protocol: ping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ping_returns_empty_result() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","id":42,"method":"ping"}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert_eq!(v["id"], 42);
    assert_eq!(v["result"], json!({}));
}

// ---------------------------------------------------------------------------
// Protocol: JSON-RPC error handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_json_returns_parse_error() {
    let (server, _) = make_server(default_policy());
    let resp = protocol::handle_message(&server, "not valid json").await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert_eq!(v["error"]["code"], -32700); // PARSE_ERROR
}

#[tokio::test]
async fn wrong_jsonrpc_version_returns_invalid_request() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();

    assert_eq!(v["error"]["code"], -32600); // INVALID_REQUEST
}

#[tokio::test]
async fn notification_initialized_returns_none() {
    let (server, _) = make_server(default_policy());
    let msg = r#"{"jsonrpc":"2.0","method":"initialized"}"#;
    let resp = protocol::handle_message(&server, msg).await;

    assert!(resp.is_none());
}

#[tokio::test]
async fn response_preserves_request_id() {
    let (server, _) = make_server(default_policy());

    // Integer id
    let msg = r#"{"jsonrpc":"2.0","id":99,"method":"ping"}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["id"], 99);

    // String id
    let msg = r#"{"jsonrpc":"2.0","id":"abc","method":"ping"}"#;
    let resp = protocol::handle_message(&server, msg).await.unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["id"], "abc");
}
