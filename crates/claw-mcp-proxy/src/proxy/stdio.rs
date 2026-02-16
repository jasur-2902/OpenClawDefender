//! Stdio-based MCP proxy for wrapping agent processes.
//!
//! Intercepts JSON-RPC messages between an MCP client (connected via stdin/stdout)
//! and an MCP server spawned as a child process. Messages classified as requiring
//! review are evaluated against the policy engine before being forwarded or blocked.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use claw_core::event::mcp::{McpEvent, McpEventKind, ResourceRead, SamplingRequest, ToolCall};
use claw_core::policy::engine::DefaultPolicyEngine;
use claw_core::policy::{PolicyAction, PolicyEngine};

use crate::classifier::rules::{
    classify, extract_resource_uri, extract_tool_call, Classification,
};
use crate::jsonrpc::parser::{serialize_message, StreamParser};
use crate::jsonrpc::types::{
    JsonRpcError, JsonRpcId, JsonRpcMessage, JsonRpcResponse, POLICY_BLOCK_ERROR_CODE,
};

/// Stdio MCP proxy that wraps an MCP server child process.
pub struct StdioProxy {
    server_cmd: String,
    server_args: Vec<String>,
    policy_engine: DefaultPolicyEngine,
}

impl StdioProxy {
    /// Create a new stdio proxy.
    ///
    /// `server_cmd` — the MCP server binary to spawn.
    /// `server_args` — arguments for the MCP server.
    /// `policy_path` — path to the TOML policy file.
    pub fn new(server_cmd: String, server_args: Vec<String>, policy_path: &Path) -> Result<Self> {
        let policy_engine = if policy_path.exists() {
            DefaultPolicyEngine::load(policy_path)
                .with_context(|| format!("failed to load policy from {}", policy_path.display()))?
        } else {
            info!(
                "policy file not found at {}, using empty policy",
                policy_path.display()
            );
            DefaultPolicyEngine::empty()
        };

        Ok(Self {
            server_cmd,
            server_args,
            policy_engine,
        })
    }

    /// Create a stdio proxy with an already-built policy engine (useful for testing).
    pub fn with_engine(
        server_cmd: String,
        server_args: Vec<String>,
        policy_engine: DefaultPolicyEngine,
    ) -> Self {
        Self {
            server_cmd,
            server_args,
            policy_engine,
        }
    }

    /// Run the proxy loop. Blocks until the child process exits or the proxy
    /// receives a shutdown signal.
    pub async fn run(&mut self) -> Result<()> {
        info!(
            cmd = %self.server_cmd,
            args = ?self.server_args,
            "spawning MCP server"
        );

        let mut child = Command::new(&self.server_cmd)
            .args(&self.server_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn MCP server: {}", self.server_cmd))?;

        let child_stdin = child
            .stdin
            .take()
            .context("failed to capture child stdin")?;
        let child_stdout = child
            .stdout
            .take()
            .context("failed to capture child stdout")?;

        let mut child_writer = tokio::io::BufWriter::new(child_stdin);
        let mut child_reader = BufReader::new(child_stdout);

        let proxy_stdin = tokio::io::stdin();
        let mut proxy_reader = BufReader::new(proxy_stdin);

        let proxy_stdout = tokio::io::stdout();
        let mut proxy_writer = tokio::io::BufWriter::new(proxy_stdout);

        let mut client_parser = StreamParser::new();
        let mut server_parser = StreamParser::new();

        let mut client_buf = String::new();
        let mut server_buf = String::new();

        info!("proxy loop started");

        loop {
            tokio::select! {
                // Read a line from the MCP client (our stdin).
                result = proxy_reader.read_line(&mut client_buf) => {
                    match result {
                        Ok(0) => {
                            info!("client closed stdin, shutting down");
                            break;
                        }
                        Ok(_) => {
                            client_parser.feed(client_buf.as_bytes());
                            client_buf.clear();

                            while let Some(parse_result) = client_parser.next_message() {
                                match parse_result {
                                    Ok(msg) => {
                                        match self.handle_client_message(msg, &mut child_writer, &mut proxy_writer).await {
                                            Ok(()) => {}
                                            Err(e) => {
                                                error!("error handling client message: {e}");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("malformed client message, skipping: {e}");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("error reading from client stdin: {e}");
                            break;
                        }
                    }
                }

                // Read a line from the MCP server (child stdout).
                result = child_reader.read_line(&mut server_buf) => {
                    match result {
                        Ok(0) => {
                            info!("server closed stdout, shutting down");
                            break;
                        }
                        Ok(_) => {
                            server_parser.feed(server_buf.as_bytes());
                            server_buf.clear();

                            while let Some(parse_result) = server_parser.next_message() {
                                match parse_result {
                                    Ok(msg) => {
                                        let bytes = serialize_message(&msg);
                                        if let Err(e) = proxy_writer.write_all(&bytes).await {
                                            error!("error writing to client stdout: {e}");
                                            break;
                                        }
                                        proxy_writer.flush().await.ok();
                                    }
                                    Err(e) => {
                                        warn!("malformed server message, skipping: {e}");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("error reading from server stdout: {e}");
                            break;
                        }
                    }
                }

                // Handle child process exit.
                status = child.wait() => {
                    match status {
                        Ok(s) => info!("MCP server exited with status: {s}"),
                        Err(e) => error!("error waiting for MCP server: {e}"),
                    }
                    break;
                }
            }
        }

        // Cleanup: try to kill the child if it's still running.
        if let Err(e) = child.kill().await {
            debug!("child already exited (kill returned: {e})");
        }

        info!("proxy loop finished");
        Ok(())
    }

    /// Process a client→server message: classify, evaluate policy, forward or block.
    async fn handle_client_message<W1, W2>(
        &self,
        msg: JsonRpcMessage,
        child_writer: &mut W1,
        proxy_writer: &mut W2,
    ) -> Result<()>
    where
        W1: AsyncWriteExt + Unpin,
        W2: AsyncWriteExt + Unpin,
    {
        let classification = classify(&msg);

        match classification {
            Classification::Pass => {
                // Forward directly, no logging.
                let bytes = serialize_message(&msg);
                child_writer.write_all(&bytes).await?;
                child_writer.flush().await?;
            }
            Classification::Log => {
                // Log and forward.
                let event = build_mcp_event(&msg);
                debug!(event_summary = %event_summary(&event), "logging message");
                let bytes = serialize_message(&msg);
                child_writer.write_all(&bytes).await?;
                child_writer.flush().await?;
            }
            Classification::Review => {
                // Evaluate against policy engine.
                let event = build_mcp_event(&msg);
                let action = self.policy_engine.evaluate(&event);
                debug!(
                    event_summary = %event_summary(&event),
                    action = ?action,
                    "policy decision"
                );

                match action {
                    PolicyAction::Allow => {
                        let bytes = serialize_message(&msg);
                        child_writer.write_all(&bytes).await?;
                        child_writer.flush().await?;
                    }
                    PolicyAction::Block => {
                        // Send error response back to client instead of forwarding.
                        if let Some(id) = request_id(&msg) {
                            let block_resp =
                                make_block_response(&id, "Blocked by ClawAI policy");
                            let bytes = serialize_message(&block_resp);
                            proxy_writer.write_all(&bytes).await?;
                            proxy_writer.flush().await?;
                        }
                        info!(event_summary = %event_summary(&event), "blocked by policy");
                    }
                    PolicyAction::Prompt(_prompt_msg) => {
                        // TODO: IPC prompt integration with daemon.
                        // For now, log and allow.
                        warn!(
                            event_summary = %event_summary(&event),
                            "prompt action not yet wired to IPC, allowing"
                        );
                        let bytes = serialize_message(&msg);
                        child_writer.write_all(&bytes).await?;
                        child_writer.flush().await?;
                    }
                    PolicyAction::Log => {
                        debug!(event_summary = %event_summary(&event), "policy: log and forward");
                        let bytes = serialize_message(&msg);
                        child_writer.write_all(&bytes).await?;
                        child_writer.flush().await?;
                    }
                }
            }
            Classification::Block => {
                // Hard block from classifier (shouldn't normally happen; classifier
                // currently returns Review for sensitive ops, not Block).
                if let Some(id) = request_id(&msg) {
                    let block_resp = make_block_response(&id, "Blocked by classifier");
                    let bytes = serialize_message(&block_resp);
                    proxy_writer.write_all(&bytes).await?;
                    proxy_writer.flush().await?;
                }
                info!("message hard-blocked by classifier");
            }
        }

        Ok(())
    }
}

/// Build a block error response for a given request id.
fn make_block_response(request_id: &JsonRpcId, message: &str) -> JsonRpcMessage {
    JsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: request_id.clone(),
        result: None,
        error: Some(JsonRpcError {
            code: POLICY_BLOCK_ERROR_CODE,
            message: message.to_string(),
            data: None,
        }),
    })
}

/// Extract the request id from a JsonRpcMessage, if it has one.
fn request_id(msg: &JsonRpcMessage) -> Option<JsonRpcId> {
    match msg {
        JsonRpcMessage::Request(r) => Some(r.id.clone()),
        JsonRpcMessage::Response(r) => Some(r.id.clone()),
        JsonRpcMessage::Notification(_) => None,
    }
}

/// Build an McpEvent from a JSON-RPC message for policy evaluation and logging.
fn build_mcp_event(msg: &JsonRpcMessage) -> McpEvent {
    let raw = serde_json::to_value(msg).unwrap_or(json!({}));
    let kind = match msg {
        JsonRpcMessage::Request(r) => match r.method.as_str() {
            "tools/call" => {
                if let Some((name, args)) = extract_tool_call(msg) {
                    McpEventKind::ToolCall(ToolCall {
                        tool_name: name,
                        arguments: args,
                        request_id: serde_json::to_value(&r.id).unwrap_or_default(),
                    })
                } else {
                    McpEventKind::Other(r.method.clone())
                }
            }
            "resources/read" => {
                if let Some(uri) = extract_resource_uri(msg) {
                    McpEventKind::ResourceRead(ResourceRead {
                        uri,
                        request_id: serde_json::to_value(&r.id).unwrap_or_default(),
                    })
                } else {
                    McpEventKind::Other(r.method.clone())
                }
            }
            "sampling/createMessage" => {
                let params = r.params.clone().unwrap_or(json!({}));
                let messages = params
                    .get("messages")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let model_preferences = params.get("modelPreferences").cloned();
                McpEventKind::SamplingRequest(SamplingRequest {
                    messages,
                    model_preferences,
                    request_id: serde_json::to_value(&r.id).unwrap_or_default(),
                })
            }
            "tools/list" | "resources/list" | "prompts/list" => McpEventKind::ListRequest,
            other => McpEventKind::Other(other.to_string()),
        },
        JsonRpcMessage::Notification(n) => McpEventKind::Notification(n.method.clone()),
        JsonRpcMessage::Response(_) => McpEventKind::Other("response".to_string()),
    };

    McpEvent {
        timestamp: Utc::now(),
        source: "mcp-proxy".to_string(),
        kind,
        raw_message: raw,
    }
}

/// One-line summary of an McpEvent for log messages.
fn event_summary(event: &McpEvent) -> String {
    match &event.kind {
        McpEventKind::ToolCall(tc) => format!("tool_call: {}", tc.tool_name),
        McpEventKind::ResourceRead(rr) => format!("resource_read: {}", rr.uri),
        McpEventKind::SamplingRequest(_) => "sampling_request".to_string(),
        McpEventKind::ListRequest => "list_request".to_string(),
        McpEventKind::Notification(n) => format!("notification: {n}"),
        McpEventKind::Other(m) => format!("other: {m}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonrpc::parser::parse_message;
    use crate::jsonrpc::types::JsonRpcRequest;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn block_policy_toml() -> &'static str {
        r#"
[rules.block_exec]
description = "Block exec tool"
action = "block"
message = "exec is blocked"
priority = 0

[rules.block_exec.match]
tool_name = ["exec*"]

[rules.allow_rest]
description = "Allow everything else"
action = "allow"
message = "Allowed"
priority = 100

[rules.allow_rest.match]
any = true
"#
    }

    fn write_temp_policy(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn make_tools_call_request(tool_name: &str) -> JsonRpcMessage {
        JsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: JsonRpcId::Number(1),
            method: "tools/call".into(),
            params: Some(json!({"name": tool_name, "arguments": {"cmd": "ls"}})),
        })
    }

    fn make_initialize_request() -> JsonRpcMessage {
        JsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: JsonRpcId::Number(0),
            method: "initialize".into(),
            params: None,
        })
    }

    // -----------------------------------------------------------------------
    // Unit tests for helper functions
    // -----------------------------------------------------------------------

    #[test]
    fn test_make_block_response() {
        let resp = make_block_response(&JsonRpcId::Number(42), "blocked");
        match resp {
            JsonRpcMessage::Response(r) => {
                assert_eq!(r.id, JsonRpcId::Number(42));
                assert!(r.result.is_none());
                let err = r.error.unwrap();
                assert_eq!(err.code, POLICY_BLOCK_ERROR_CODE);
                assert_eq!(err.message, "blocked");
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn test_request_id_extraction() {
        let req = make_tools_call_request("exec");
        assert_eq!(request_id(&req), Some(JsonRpcId::Number(1)));

        let notif = JsonRpcMessage::Notification(crate::jsonrpc::types::JsonRpcNotification {
            jsonrpc: "2.0".into(),
            method: "notifications/initialized".into(),
            params: None,
        });
        assert_eq!(request_id(&notif), None);
    }

    #[test]
    fn test_build_mcp_event_tool_call() {
        let msg = make_tools_call_request("read_file");
        let event = build_mcp_event(&msg);
        match &event.kind {
            McpEventKind::ToolCall(tc) => {
                assert_eq!(tc.tool_name, "read_file");
            }
            _ => panic!("expected ToolCall event"),
        }
    }

    #[test]
    fn test_build_mcp_event_resource_read() {
        let msg = JsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: JsonRpcId::Number(2),
            method: "resources/read".into(),
            params: Some(json!({"uri": "file:///etc/passwd"})),
        });
        let event = build_mcp_event(&msg);
        match &event.kind {
            McpEventKind::ResourceRead(rr) => {
                assert_eq!(rr.uri, "file:///etc/passwd");
            }
            _ => panic!("expected ResourceRead event"),
        }
    }

    // -----------------------------------------------------------------------
    // Integration-style tests using handle_client_message with in-memory buffers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_blocked_tool_call_returns_error() {
        let f = write_temp_policy(block_policy_toml());
        let proxy = StdioProxy::new("echo".into(), vec![], f.path()).unwrap();

        let msg = make_tools_call_request("exec_command");

        let mut child_buf: Vec<u8> = Vec::new();
        let mut client_buf: Vec<u8> = Vec::new();

        proxy
            .handle_client_message(msg, &mut child_buf, &mut client_buf)
            .await
            .unwrap();

        // Nothing should be forwarded to child.
        assert!(child_buf.is_empty(), "blocked message should not reach server");

        // Client should receive a block error response.
        assert!(!client_buf.is_empty(), "client should receive error response");
        let resp = parse_message(&client_buf[..client_buf.len() - 1]).unwrap();
        match resp {
            JsonRpcMessage::Response(r) => {
                assert_eq!(r.id, JsonRpcId::Number(1));
                let err = r.error.unwrap();
                assert_eq!(err.code, POLICY_BLOCK_ERROR_CODE);
            }
            _ => panic!("expected error response"),
        }
    }

    #[tokio::test]
    async fn test_allowed_tool_call_is_forwarded() {
        let f = write_temp_policy(block_policy_toml());
        let proxy = StdioProxy::new("echo".into(), vec![], f.path()).unwrap();

        let msg = make_tools_call_request("read_file");

        let mut child_buf: Vec<u8> = Vec::new();
        let mut client_buf: Vec<u8> = Vec::new();

        proxy
            .handle_client_message(msg, &mut child_buf, &mut client_buf)
            .await
            .unwrap();

        // Message should be forwarded to child.
        assert!(!child_buf.is_empty(), "allowed message should reach server");

        // Client should not receive anything (response comes from server).
        assert!(client_buf.is_empty(), "client should not receive error");

        // Verify the forwarded message is valid.
        let fwd = parse_message(&child_buf[..child_buf.len() - 1]).unwrap();
        match fwd {
            JsonRpcMessage::Request(r) => {
                assert_eq!(r.method, "tools/call");
            }
            _ => panic!("expected request forwarded"),
        }
    }

    #[tokio::test]
    async fn test_pass_through_initialize() {
        let proxy = StdioProxy::with_engine("echo".into(), vec![], DefaultPolicyEngine::empty());

        let msg = make_initialize_request();

        let mut child_buf: Vec<u8> = Vec::new();
        let mut client_buf: Vec<u8> = Vec::new();

        proxy
            .handle_client_message(msg, &mut child_buf, &mut client_buf)
            .await
            .unwrap();

        // initialize is Classification::Pass, should go straight to server.
        assert!(!child_buf.is_empty());
        assert!(client_buf.is_empty());
    }

    #[tokio::test]
    async fn test_response_forwarded_unchanged() {
        // Simulate a server response being forwarded back to client.
        let response_json =
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}"#;
        let msg = parse_message(response_json.as_bytes()).unwrap();
        let serialized = serialize_message(&msg);

        // The serialized bytes should be valid JSON that roundtrips.
        let re_parsed = parse_message(&serialized[..serialized.len() - 1]).unwrap();
        match re_parsed {
            JsonRpcMessage::Response(r) => {
                assert_eq!(r.id, JsonRpcId::Number(1));
                assert!(r.result.is_some());
                assert!(r.error.is_none());
            }
            _ => panic!("expected response"),
        }
    }

    #[tokio::test]
    async fn test_classification_to_policy_flow() {
        // Review-classified messages go through policy.
        // With empty policy (default Log action), they should be forwarded.
        let proxy = StdioProxy::with_engine("echo".into(), vec![], DefaultPolicyEngine::empty());

        let msg = make_tools_call_request("anything");

        let mut child_buf: Vec<u8> = Vec::new();
        let mut client_buf: Vec<u8> = Vec::new();

        proxy
            .handle_client_message(msg, &mut child_buf, &mut client_buf)
            .await
            .unwrap();

        // Default policy is Log, so message should be forwarded.
        assert!(!child_buf.is_empty());
        assert!(client_buf.is_empty());
    }

    #[test]
    fn test_new_with_missing_policy_uses_empty() {
        let proxy = StdioProxy::new(
            "echo".into(),
            vec![],
            Path::new("/nonexistent/policy.toml"),
        );
        assert!(proxy.is_ok(), "should fall back to empty policy");
    }
}
