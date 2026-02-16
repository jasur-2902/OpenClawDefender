//! Mock MCP server for integration testing.
//!
//! Reads JSON-RPC messages from stdin (newline-delimited) and responds on stdout.
//! Logs received messages to stderr for debugging.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

fn handle_request(req: &JsonRpcRequest) -> JsonRpcResponse {
    let id = req.id.clone().unwrap_or(Value::Null);

    match req.method.as_str() {
        "initialize" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": { "listChanged": true },
                    "resources": { "subscribe": false, "listChanged": true },
                    "sampling": {}
                },
                "serverInfo": {
                    "name": "mock-mcp-server",
                    "version": "0.1.0"
                }
            })),
            error: None,
        },

        "tools/list" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(json!({
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file from disk",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "File path to read" }
                            },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "write_file",
                        "description": "Write content to a file",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string" },
                                "content": { "type": "string" }
                            },
                            "required": ["path", "content"]
                        }
                    },
                    {
                        "name": "run_command",
                        "description": "Run a shell command",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": { "type": "string" }
                            },
                            "required": ["command"]
                        }
                    }
                ]
            })),
            error: None,
        },

        "tools/call" => {
            let params = req.params.clone().unwrap_or(json!({}));
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

            JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(json!({
                    "content": [{
                        "type": "text",
                        "text": format!("Mock result for tool '{}' with args: {}", tool_name, arguments)
                    }]
                })),
                error: None,
            }
        }

        "resources/list" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(json!({
                "resources": [
                    {
                        "uri": "file:///tmp/test.txt",
                        "name": "test.txt",
                        "mimeType": "text/plain"
                    },
                    {
                        "uri": "file:///tmp/data.json",
                        "name": "data.json",
                        "mimeType": "application/json"
                    }
                ]
            })),
            error: None,
        },

        "resources/read" => {
            let params = req.params.clone().unwrap_or(json!({}));
            let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("unknown");

            JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(json!({
                    "contents": [{
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": format!("Mock content of {}", uri)
                    }]
                })),
                error: None,
            }
        }

        "sampling/createMessage" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(json!({
                "role": "assistant",
                "content": {
                    "type": "text",
                    "text": "This is a mock LLM completion from the mock MCP server."
                },
                "model": "mock-model-v1",
                "stopReason": "endTurn"
            })),
            error: None,
        },

        _ => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", req.method),
                data: None,
            }),
        },
    }
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[mock-mcp-server] stdin read error: {e}");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        eprintln!("[mock-mcp-server] received: {trimmed}");

        // Try to parse as a JSON object first to check for notifications
        let raw: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[mock-mcp-server] parse error: {e}");
                // Send a JSON-RPC parse error
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                });
                let _ = writeln!(stdout_lock, "{}", serde_json::to_string(&err_resp).unwrap());
                let _ = stdout_lock.flush();
                continue;
            }
        };

        // Notifications have method but no id — just log and skip
        if raw.get("method").is_some() && raw.get("id").is_none() {
            eprintln!(
                "[mock-mcp-server] notification: {}",
                raw.get("method").unwrap()
            );
            continue;
        }

        // Parse as request
        let req: JsonRpcRequest = match serde_json::from_value(raw) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[mock-mcp-server] request parse error: {e}");
                continue;
            }
        };

        let resp = handle_request(&req);
        let resp_json = serde_json::to_string(&resp).unwrap();
        eprintln!("[mock-mcp-server] sending: {resp_json}");

        if writeln!(stdout_lock, "{resp_json}").is_err() {
            break;
        }
        if stdout_lock.flush().is_err() {
            break;
        }
    }

    eprintln!("[mock-mcp-server] stdin closed, exiting");
}
