//! MCP protocol handler.
//!
//! Implements the JSON-RPC based MCP protocol: initialize, tools/list, tools/call, ping.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, error};

use crate::types::*;
use crate::{tools, McpServer};

/// A JSON-RPC request.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// A JSON-RPC response.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// JSON-RPC error codes.
const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const INTERNAL_ERROR: i32 = -32603;
/// Rate limit exceeded (application-specific error code).
const RATE_LIMITED: i32 = -32000;
/// Payload too large (application-specific error code).
const PAYLOAD_TOO_LARGE: i32 = -32001;

impl JsonRpcResponse {
    fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// Handle a single JSON-RPC request and return a response.
///
/// `caller_id` identifies the caller for rate limiting purposes. For stdio
/// connections this is derived from the process identity; for HTTP it comes
/// from the authenticated token or remote address.
pub async fn handle_request(
    server: &Arc<McpServer>,
    request: &JsonRpcRequest,
    caller_id: &str,
) -> Option<JsonRpcResponse> {
    debug!("handling method: {} from caller: {}", request.method, caller_id);

    // Notifications (no id) don't get responses (except for initialize).
    let id = request.id.clone();

    match request.method.as_str() {
        "initialize" => Some(handle_initialize(server, id)),
        "initialized" => None, // Notification, no response.
        "ping" => Some(handle_ping(id)),
        "tools/list" => Some(handle_tools_list(id)),
        "tools/call" => Some(handle_tools_call(server, id, &request.params, caller_id).await),
        _ => {
            // Unknown method.
            if id.is_some() {
                Some(JsonRpcResponse::error(
                    id,
                    METHOD_NOT_FOUND,
                    format!("Method not found: {}", request.method),
                ))
            } else {
                None // Don't respond to unknown notifications.
            }
        }
    }
}

/// Handle a raw JSON string, parse it, dispatch, and return the response JSON.
///
/// Uses "stdio" as the default caller ID. For HTTP callers, use
/// `handle_message_with_caller` instead.
pub async fn handle_message(server: &Arc<McpServer>, message: &str) -> Option<String> {
    handle_message_with_caller(server, message, "stdio").await
}

/// Handle a raw JSON string with an explicit caller identifier.
pub async fn handle_message_with_caller(
    server: &Arc<McpServer>,
    message: &str,
    caller_id: &str,
) -> Option<String> {
    let request: JsonRpcRequest = match serde_json::from_str(message) {
        Ok(req) => req,
        Err(e) => {
            error!("failed to parse JSON-RPC request: {}", e);
            let resp = JsonRpcResponse::error(None, PARSE_ERROR, "Parse error");
            return Some(serde_json::to_string(&resp).unwrap());
        }
    };

    if request.jsonrpc != "2.0" {
        let resp = JsonRpcResponse::error(
            request.id.clone(),
            INVALID_REQUEST,
            "Invalid JSON-RPC version, expected 2.0",
        );
        return Some(serde_json::to_string(&resp).unwrap());
    }

    let response = handle_request(server, &request, caller_id).await?;
    Some(serde_json::to_string(&response).unwrap())
}

fn handle_initialize(server: &Arc<McpServer>, id: Option<Value>) -> JsonRpcResponse {
    JsonRpcResponse::success(
        id,
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {
                    "listChanged": false
                }
            },
            "serverInfo": {
                "name": server.server_info.name,
                "version": server.server_info.version
            }
        }),
    )
}

fn handle_ping(id: Option<Value>) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!({}))
}

fn handle_tools_list(id: Option<Value>) -> JsonRpcResponse {
    JsonRpcResponse::success(
        id,
        json!({
            "tools": [
                {
                    "name": "checkIntent",
                    "description": "Check whether a planned action is allowed by ClawDefender policy. Call this BEFORE performing any sensitive operation to verify it will be permitted.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "description": {
                                "type": "string",
                                "description": "Human-readable description of what you intend to do"
                            },
                            "action_type": {
                                "type": "string",
                                "enum": ["file_read", "file_write", "file_delete", "shell_execute", "network_request", "resource_access", "other"],
                                "description": "Category of the planned action"
                            },
                            "target": {
                                "type": "string",
                                "description": "Target resource: file path, URL, command, etc."
                            },
                            "reason": {
                                "type": "string",
                                "description": "Optional justification for why this action is needed"
                            }
                        },
                        "required": ["description", "action_type", "target"]
                    }
                },
                {
                    "name": "requestPermission",
                    "description": "Request explicit permission to access a resource. Use this when checkIntent indicates the action requires approval.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "resource": {
                                "type": "string",
                                "description": "Resource you want to access (file path, URL, etc.)"
                            },
                            "operation": {
                                "type": "string",
                                "enum": ["read", "write", "execute", "delete", "connect"],
                                "description": "Type of operation to perform"
                            },
                            "justification": {
                                "type": "string",
                                "description": "Why you need this access"
                            },
                            "timeout_seconds": {
                                "type": "integer",
                                "description": "How long to wait for approval (default 30)",
                                "default": 30
                            }
                        },
                        "required": ["resource", "operation", "justification"]
                    }
                },
                {
                    "name": "reportAction",
                    "description": "Report an action that has already been performed, for audit logging. Call this AFTER performing any significant operation.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "description": {
                                "type": "string",
                                "description": "What happened"
                            },
                            "action_type": {
                                "type": "string",
                                "enum": ["file_read", "file_write", "file_delete", "shell_execute", "network_request", "resource_access", "other"],
                                "description": "Category of the action performed"
                            },
                            "target": {
                                "type": "string",
                                "description": "Target resource that was acted upon"
                            },
                            "result": {
                                "type": "string",
                                "enum": ["success", "failure", "partial"],
                                "description": "Outcome of the action"
                            },
                            "details": {
                                "type": "object",
                                "description": "Additional details about the action"
                            }
                        },
                        "required": ["description", "action_type", "target", "result"]
                    }
                },
                {
                    "name": "getPolicy",
                    "description": "Query the current security policy rules. Use this to understand what actions are allowed before planning your approach.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "resource": {
                                "type": "string",
                                "description": "Filter by resource path"
                            },
                            "action_type": {
                                "type": "string",
                                "enum": ["file_read", "file_write", "file_delete", "shell_execute", "network_request", "resource_access", "other"],
                                "description": "Filter by action type"
                            },
                            "tool_name": {
                                "type": "string",
                                "description": "Filter by tool name"
                            }
                        }
                    }
                }
            ]
        }),
    )
}

async fn handle_tools_call(
    server: &Arc<McpServer>,
    id: Option<Value>,
    params: &Option<Value>,
    caller_id: &str,
) -> JsonRpcResponse {
    let params = match params {
        Some(p) => p,
        None => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing params for tools/call");
        }
    };

    let tool_name = match params.get("name").and_then(|n| n.as_str()) {
        Some(name) => name,
        None => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing tool name in params");
        }
    };

    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    match tool_name {
        "checkIntent" => {
            // Rate limit: 100/minute per caller
            {
                let mut rl = server.intent_rate_limiter.lock().await;
                if !rl.check(caller_id) {
                    return JsonRpcResponse::error(
                        id,
                        RATE_LIMITED,
                        "checkIntent rate limit exceeded (100/minute)",
                    );
                }
            }

            match serde_json::from_value::<CheckIntentParams>(arguments) {
                Ok(tool_params) => {
                    // Validate input fields
                    if let Err(e) = crate::validation::validate_string_field("description", &tool_params.description) {
                        return JsonRpcResponse::error(id, INVALID_PARAMS, e.to_string());
                    }
                    if let Err(e) = crate::validation::validate_string_field("target", &tool_params.target) {
                        return JsonRpcResponse::error(id, INVALID_PARAMS, e.to_string());
                    }
                    if let Some(ref reason) = tool_params.reason {
                        if let Err(e) = crate::validation::validate_string_field("reason", reason) {
                            return JsonRpcResponse::error(id, INVALID_PARAMS, e.to_string());
                        }
                    }

                    match tools::check_intent(server, tool_params).await {
                        Ok(result) => JsonRpcResponse::success(
                            id,
                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&result).unwrap()
                                }]
                            }),
                        ),
                        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, e.to_string()),
                    }
                }
                Err(e) => JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    format!("Invalid checkIntent params: {e}"),
                ),
            }
        }

        "requestPermission" => {
            // Rate limit: 10/60s per server (prompt flooding prevention)
            {
                let mut rl = server.permission_rate_limiter.lock().await;
                let result = rl.check(caller_id);
                if result != clawdefender_core::rate_limit::RateLimitResult::Allowed {
                    return JsonRpcResponse::error(
                        id,
                        RATE_LIMITED,
                        "requestPermission rate limit exceeded (10/60s) — potential prompt flooding",
                    );
                }
            }

            match serde_json::from_value::<RequestPermissionParams>(arguments) {
                Ok(tool_params) => {
                    // Validate inputs
                    if let Err(e) = crate::validation::validate_string_field("resource", &tool_params.resource) {
                        return JsonRpcResponse::error(id, INVALID_PARAMS, e.to_string());
                    }
                    if let Err(e) = crate::validation::validate_string_field("justification", &tool_params.justification) {
                        return JsonRpcResponse::error(id, INVALID_PARAMS, e.to_string());
                    }
                    // Scope escalation: resource must be exact (no wildcards)
                    if let Err(e) = crate::validation::validate_resource_path_exact(&tool_params.resource) {
                        return JsonRpcResponse::error(id, INVALID_PARAMS, e.to_string());
                    }

                    match tools::request_permission(server, tool_params).await {
                        Ok(result) => JsonRpcResponse::success(
                            id,
                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&result).unwrap()
                                }]
                            }),
                        ),
                        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, e.to_string()),
                    }
                }
                Err(e) => JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    format!("Invalid requestPermission params: {e}"),
                ),
            }
        }

        "reportAction" => {
            // Payload size validation (10 KB max)
            let payload_size = serde_json::to_string(&arguments)
                .map(|s| s.len())
                .unwrap_or(0);
            if let Err(e) = crate::validation::validate_payload_size(payload_size) {
                return JsonRpcResponse::error(id, PAYLOAD_TOO_LARGE, e.to_string());
            }

            // Rate limit: 1000/minute per server
            {
                let mut rl = server.report_rate_limiter.lock().await;
                if !rl.check(caller_id) {
                    return JsonRpcResponse::error(
                        id,
                        RATE_LIMITED,
                        "reportAction rate limit exceeded (1000/minute)",
                    );
                }
            }

            match serde_json::from_value::<ReportActionParams>(arguments) {
                Ok(tool_params) => {
                    // Validate string fields
                    if let Err(e) = crate::validation::validate_string_field("description", &tool_params.description) {
                        return JsonRpcResponse::error(id, INVALID_PARAMS, e.to_string());
                    }
                    if let Err(e) = crate::validation::validate_string_field("target", &tool_params.target) {
                        return JsonRpcResponse::error(id, INVALID_PARAMS, e.to_string());
                    }

                    match tools::report_action(server, tool_params).await {
                        Ok(result) => JsonRpcResponse::success(
                            id,
                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&result).unwrap()
                                }]
                            }),
                        ),
                        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, e.to_string()),
                    }
                }
                Err(e) => JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    format!("Invalid reportAction params: {e}"),
                ),
            }
        }

        "getPolicy" => {
            match serde_json::from_value::<GetPolicyParams>(arguments) {
                Ok(tool_params) => match tools::get_policy(server, tool_params).await {
                    Ok(result) => JsonRpcResponse::success(
                        id,
                        json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&result).unwrap()
                            }]
                        }),
                    ),
                    Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, e.to_string()),
                },
                Err(e) => JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    format!("Invalid getPolicy params: {e}"),
                ),
            }
        }

        _ => JsonRpcResponse::error(
            id,
            METHOD_NOT_FOUND,
            format!("Unknown tool: {tool_name}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::McpServer;
    use clawdefender_core::audit::{AuditFilter, AuditLogger, AuditRecord, AuditStats};
    use clawdefender_core::policy::engine::DefaultPolicyEngine;
    use std::io::Write;
    use std::sync::Mutex as StdMutex;
    use tempfile::NamedTempFile;

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

    fn make_server() -> Arc<McpServer> {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(
            b"[rules.catch_all]\ndescription = \"Log all\"\naction = \"log\"\nmessage = \"ok\"\npriority = 100\n\n[rules.catch_all.match]\nany = true\n",
        )
        .unwrap();
        f.flush().unwrap();
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();
        let _ = f.into_temp_path();
        let logger = Arc::new(TestAuditLogger::new());
        Arc::new(McpServer::new(Box::new(engine), logger))
    }

    #[tokio::test]
    async fn initialize_returns_capabilities() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = handle_message(&server, msg).await.unwrap();
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        assert!(parsed["result"]["capabilities"]["tools"].is_object());
        assert_eq!(parsed["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(parsed["result"]["serverInfo"]["name"], "clawdefender");
    }

    #[tokio::test]
    async fn ping_returns_empty_object() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#;
        let resp = handle_message(&server, msg).await.unwrap();
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["result"], json!({}));
    }

    #[tokio::test]
    async fn tools_list_returns_all_four_tools() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#;
        let resp = handle_message(&server, msg).await.unwrap();
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        let tools = parsed["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 4);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"checkIntent"));
        assert!(names.contains(&"requestPermission"));
        assert!(names.contains(&"reportAction"));
        assert!(names.contains(&"getPolicy"));
    }

    #[tokio::test]
    async fn tools_call_check_intent() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"checkIntent","arguments":{"description":"Read a file","action_type":"file_read","target":"/tmp/test.txt"}}}"#;
        let resp = handle_message(&server, msg).await.unwrap();
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        assert!(parsed["result"]["content"][0]["text"].is_string());
        let text = parsed["result"]["content"][0]["text"].as_str().unwrap();
        let result: CheckIntentResponse = serde_json::from_str(text).unwrap();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn tools_call_report_action() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"reportAction","arguments":{"description":"Wrote file","action_type":"file_write","target":"/tmp/out.txt","result":"success"}}}"#;
        let resp = handle_message(&server, msg).await.unwrap();
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        let text = parsed["result"]["content"][0]["text"].as_str().unwrap();
        let result: ReportActionResponse = serde_json::from_str(text).unwrap();
        assert!(result.recorded);
    }

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":6,"method":"unknown/method"}"#;
        let resp = handle_message(&server, msg).await.unwrap();
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["error"]["code"], METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_tool_returns_error() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}"#;
        let resp = handle_message(&server, msg).await.unwrap();
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["error"]["code"], METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn invalid_json_returns_parse_error() {
        let server = make_server();
        let resp = handle_message(&server, "not json").await.unwrap();
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["error"]["code"], PARSE_ERROR);
    }

    #[tokio::test]
    async fn invalid_version_returns_error() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"1.0","id":8,"method":"ping"}"#;
        let resp = handle_message(&server, msg).await.unwrap();
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["error"]["code"], INVALID_REQUEST);
    }

    #[tokio::test]
    async fn notification_initialized_returns_none() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","method":"initialized"}"#;
        let resp = handle_message(&server, msg).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn tools_call_invalid_params() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"checkIntent","arguments":{"wrong":"params"}}}"#;
        let resp = handle_message(&server, msg).await.unwrap();
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["error"]["code"], INVALID_PARAMS);
    }
}
