//! Test harness that manages an MCP server child process over stdio.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::timeout;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// An MCP server process managed over stdio JSON-RPC.
pub struct McpHarness {
    child: Child,
    stdin_tx: mpsc::Sender<String>,
    stdout_rx: mpsc::Receiver<String>,
    next_id: u64,
}

impl McpHarness {
    /// Start an MCP server process and wire up stdin/stdout channels.
    pub async fn start(command: &[String]) -> Result<Self> {
        if command.is_empty() {
            anyhow::bail!("Server command must not be empty");
        }

        let mut child = Command::new(&command[0])
            .args(&command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Failed to start server: {}", command.join(" ")))?;

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");

        // Channel for writing to stdin
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<String>(64);
        tokio::spawn(async move {
            let mut writer = stdin;
            while let Some(msg) = stdin_rx.recv().await {
                if writer.write_all(msg.as_bytes()).await.is_err() {
                    break;
                }
                if writer.write_all(b"\n").await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
            }
        });

        // Channel for reading from stdout
        let (stdout_tx, stdout_rx) = mpsc::channel::<String>(64);
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() && stdout_tx.send(trimmed).await.is_err() {
                    break;
                }
            }
        });

        // Small delay to let the server start
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(Self {
            child,
            stdin_tx,
            stdout_rx,
            next_id: 1,
        })
    }

    /// Send a JSON-RPC request and wait for a response.
    pub async fn send_request(&mut self, method: &str, params: Value) -> Result<Value> {
        self.send_request_with_timeout(method, params, DEFAULT_TIMEOUT)
            .await
    }

    /// Send a JSON-RPC request with a custom timeout.
    pub async fn send_request_with_timeout(
        &mut self,
        method: &str,
        params: Value,
        dur: Duration,
    ) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;

        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let request_str = serde_json::to_string(&request)?;
        self.stdin_tx
            .send(request_str)
            .await
            .context("Failed to send request to server")?;

        // Wait for response with matching id
        let response = timeout(dur, async {
            loop {
                match self.stdout_rx.recv().await {
                    Some(line) => {
                        if let Ok(val) = serde_json::from_str::<Value>(&line) {
                            // Check if this response matches our request id
                            if val.get("id").and_then(|v| v.as_u64()) == Some(id) {
                                return Ok(val);
                            }
                            // Otherwise skip (could be a notification or other response)
                        }
                    }
                    None => return Err(anyhow::anyhow!("Server stdout closed")),
                }
            }
        })
        .await
        .context("Timed out waiting for server response")??;

        Ok(response)
    }

    /// Send a JSON-RPC notification (no id, no response expected).
    pub async fn send_notification(&mut self, method: &str, params: Value) -> Result<()> {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });

        let notification_str = serde_json::to_string(&notification)?;
        self.stdin_tx
            .send(notification_str)
            .await
            .context("Failed to send notification to server")?;
        Ok(())
    }

    /// Send a raw JSON-RPC error to the server's stdin (simulating ClawDefender blocking).
    pub async fn send_raw(&mut self, raw: &str) -> Result<()> {
        self.stdin_tx
            .send(raw.to_string())
            .await
            .context("Failed to send raw message")?;
        Ok(())
    }

    /// Send initialize and return the result.
    pub async fn initialize(&mut self) -> Result<Value> {
        let resp = self
            .send_request(
                "initialize",
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "clawdefender-certify",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            )
            .await?;

        // Send initialized notification
        self.send_notification("notifications/initialized", json!({}))
            .await?;

        resp.get("result")
            .cloned()
            .ok_or_else(|| {
                let err = resp.get("error").cloned().unwrap_or(Value::Null);
                anyhow::anyhow!("Initialize failed: {err}")
            })
    }

    /// List available tools.
    pub async fn list_tools(&mut self) -> Result<Vec<Value>> {
        let resp = self.send_request("tools/list", json!({})).await?;
        let tools = resp
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(tools)
    }

    /// Call a tool by name with given arguments.
    pub async fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value> {
        self.send_request("tools/call", json!({ "name": name, "arguments": arguments }))
            .await
    }

    /// Call a tool with a custom timeout.
    pub async fn call_tool_with_timeout(
        &mut self,
        name: &str,
        arguments: Value,
        dur: Duration,
    ) -> Result<Value> {
        self.send_request_with_timeout(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
            dur,
        )
        .await
    }

    /// Check if the server process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Shutdown the server gracefully.
    pub async fn shutdown(&mut self) -> Result<()> {
        // Drop the stdin channel to signal EOF
        drop(self.stdin_tx.clone());
        // Give the server a moment to exit
        let _ = timeout(Duration::from_secs(2), self.child.wait()).await;
        // Force kill if still running
        let _ = self.child.kill().await;
        Ok(())
    }
}
