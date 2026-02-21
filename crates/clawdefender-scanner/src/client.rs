use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub uri: String,
    pub name: String,
    pub description: Option<String>,
}

pub struct ScanClient {
    child: Child,
    stdin_tx: mpsc::Sender<Vec<u8>>,
    stdout_rx: mpsc::Receiver<String>,
    next_id: u64,
    message_history: Vec<(Direction, Value)>,
    sampling_handler: Option<Box<dyn Fn(Value) -> Value + Send + Sync>>,
    request_timeout: Duration,
    pub server_stderr: Arc<Mutex<String>>,
}

impl ScanClient {
    pub async fn start(
        command: &[String],
        env_overrides: HashMap<String, String>,
    ) -> Result<Self> {
        if command.is_empty() {
            anyhow::bail!("Server command must not be empty");
        }

        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        for (key, val) in &env_overrides {
            cmd.env(key, val);
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to start server: {}", command.join(" ")))?;

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");

        // Stdin writer channel
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(64);
        tokio::spawn(async move {
            let mut writer = stdin;
            while let Some(msg) = stdin_rx.recv().await {
                if writer.write_all(&msg).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
            }
        });

        // Stdout reader channel
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

        // Stderr capture
        let server_stderr = Arc::new(Mutex::new(String::new()));
        let stderr_clone = server_stderr.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let mut buf = stderr_clone.lock().await;
                buf.push_str(&line);
                buf.push('\n');
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(Self {
            child,
            stdin_tx,
            stdout_rx,
            next_id: 1,
            message_history: Vec::new(),
            sampling_handler: None,
            request_timeout: DEFAULT_TIMEOUT,
            server_stderr,
        })
    }

    pub fn set_timeout(&mut self, dur: Duration) {
        self.request_timeout = dur;
    }

    pub fn set_sampling_handler(&mut self, handler: impl Fn(Value) -> Value + Send + Sync + 'static) {
        self.sampling_handler = Some(Box::new(handler));
    }

    pub async fn send_raw_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.stdin_tx
            .send(bytes.to_vec())
            .await
            .context("Failed to send raw bytes")?;
        Ok(())
    }

    pub async fn call_method(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;

        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        self.message_history
            .push((Direction::Sent, request.clone()));

        let request_str = serde_json::to_string(&request)?;
        let mut bytes = request_str.into_bytes();
        bytes.push(b'\n');
        self.stdin_tx
            .send(bytes)
            .await
            .context("Failed to send request")?;

        let response = timeout(self.request_timeout, async {
            loop {
                match self.stdout_rx.recv().await {
                    Some(line) => {
                        if let Ok(val) = serde_json::from_str::<Value>(&line) {
                            self.message_history
                                .push((Direction::Received, val.clone()));

                            // Handle sampling/createMessage requests from server
                            if val.get("method").and_then(|m| m.as_str())
                                == Some("sampling/createMessage")
                            {
                                if let Some(ref handler) = self.sampling_handler {
                                    let response = handler(val.clone());
                                    let resp_str = serde_json::to_string(&response)?;
                                    let mut resp_bytes = resp_str.into_bytes();
                                    resp_bytes.push(b'\n');
                                    self.stdin_tx.send(resp_bytes).await.ok();
                                    self.message_history
                                        .push((Direction::Sent, response));
                                }
                                continue;
                            }

                            if val.get("id").and_then(|v| v.as_u64()) == Some(id) {
                                return Ok(val);
                            }
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

    pub async fn initialize(&mut self) -> Result<Value> {
        let resp = self
            .call_method(
                "initialize",
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "sampling": {}
                    },
                    "clientInfo": {
                        "name": "clawdefender-scanner",
                        "version": "0.1.0"
                    }
                }),
            )
            .await?;

        // Send initialized notification
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        });
        self.message_history
            .push((Direction::Sent, notification.clone()));
        let notif_str = serde_json::to_string(&notification)?;
        let mut bytes = notif_str.into_bytes();
        bytes.push(b'\n');
        self.stdin_tx.send(bytes).await.ok();

        resp.get("result")
            .cloned()
            .ok_or_else(|| {
                let err = resp.get("error").cloned().unwrap_or(Value::Null);
                anyhow::anyhow!("Initialize failed: {err}")
            })
    }

    pub async fn call_tool_raw(&mut self, name: &str, args: Value) -> Result<Value> {
        self.call_method("tools/call", json!({ "name": name, "arguments": args }))
            .await
    }

    pub async fn list_tools(&mut self) -> Result<Vec<ToolInfo>> {
        let resp = self.call_method("tools/list", json!({})).await?;
        let tools = resp
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();

        let mut result = Vec::new();
        for tool in tools {
            result.push(ToolInfo {
                name: tool
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                description: tool
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                input_schema: tool
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or(Value::Null),
            });
        }
        Ok(result)
    }

    pub async fn list_resources(&mut self) -> Result<Vec<ResourceInfo>> {
        let resp = self.call_method("resources/list", json!({})).await?;
        let resources = resp
            .get("result")
            .and_then(|r| r.get("resources"))
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();

        let mut result = Vec::new();
        for res in resources {
            result.push(ResourceInfo {
                uri: res
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                name: res
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                description: res
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
        }
        Ok(result)
    }

    pub fn history(&self) -> &[(Direction, Value)] {
        &self.message_history
    }

    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let _ = timeout(Duration::from_secs(2), self.child.wait()).await;
        let _ = self.child.kill().await;
        Ok(())
    }
}
