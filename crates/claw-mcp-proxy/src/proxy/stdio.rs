//! Stdio-based MCP proxy for wrapping agent processes.
//!
//! Intercepts JSON-RPC messages between an MCP client (connected via stdin/stdout)
//! and an MCP server spawned as a child process. Messages classified as requiring
//! review are evaluated against the policy engine before being forwarded or blocked.

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use claw_core::audit::AuditRecord;
use claw_core::event::mcp::{McpEvent, McpEventKind, ResourceRead, SamplingRequest, ToolCall};
use claw_core::ipc::protocol::{UiRequest, UiResponse, UserDecision};
use claw_core::policy::engine::DefaultPolicyEngine;
use claw_core::policy::{MatchCriteria, PolicyAction, PolicyEngine, PolicyRule};

use crate::classifier::rules::{
    classify, extract_resource_uri, extract_tool_call, Classification,
};
use crate::jsonrpc::parser::{serialize_message, StreamParser};
use crate::jsonrpc::types::{
    JsonRpcError, JsonRpcId, JsonRpcMessage, JsonRpcResponse, POLICY_BLOCK_ERROR_CODE,
};

use super::{ProxyConfig, ProxyMetrics, UiBridge};

/// Stdio MCP proxy that wraps an MCP server child process.
pub struct StdioProxy {
    config: ProxyConfig,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
    audit_tx: mpsc::Sender<AuditRecord>,
    ui_bridge: Option<Arc<UiBridge>>,
    session_id: String,
    metrics: Arc<ProxyMetrics>,
}

impl StdioProxy {
    /// Create a new stdio proxy.
    ///
    /// `server_cmd` -- the MCP server binary to spawn.
    /// `server_args` -- arguments for the MCP server.
    /// `policy_path` -- path to the TOML policy file.
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

        let (audit_tx, _audit_rx) = mpsc::channel(1024);

        Ok(Self {
            config: ProxyConfig {
                server_command: Some(server_cmd),
                server_args,
                prompt_timeout: Duration::from_secs(30),
                max_pending_prompts: 100,
                ..Default::default()
            },
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            audit_tx,
            ui_bridge: None,
            session_id: uuid::Uuid::new_v4().to_string(),
            metrics: Arc::new(ProxyMetrics::new()),
        })
    }

    /// Create a stdio proxy with an already-built policy engine (useful for testing).
    pub fn with_engine(
        server_cmd: String,
        server_args: Vec<String>,
        policy_engine: DefaultPolicyEngine,
    ) -> Self {
        let (audit_tx, _audit_rx) = mpsc::channel(1024);

        Self {
            config: ProxyConfig {
                server_command: Some(server_cmd),
                server_args,
                ..Default::default()
            },
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            audit_tx,
            ui_bridge: None,
            session_id: uuid::Uuid::new_v4().to_string(),
            metrics: Arc::new(ProxyMetrics::new()),
        }
    }

    /// Create a stdio proxy with full configuration including UI bridge and audit channel.
    pub fn with_full_config(
        config: ProxyConfig,
        policy_engine: DefaultPolicyEngine,
        audit_tx: mpsc::Sender<AuditRecord>,
        ui_bridge: Option<Arc<UiBridge>>,
    ) -> Self {
        Self {
            config,
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            audit_tx,
            ui_bridge,
            session_id: uuid::Uuid::new_v4().to_string(),
            metrics: Arc::new(ProxyMetrics::new()),
        }
    }

    /// Get a reference to the proxy metrics.
    pub fn metrics(&self) -> &Arc<ProxyMetrics> {
        &self.metrics
    }

    /// Run the proxy loop. Blocks until the child process exits or the proxy
    /// receives a shutdown signal.
    pub async fn run(&self) -> Result<()> {
        let server_cmd = self
            .config
            .server_command
            .as_deref()
            .context("server_command is required for stdio proxy")?;

        info!(
            cmd = %server_cmd,
            args = ?self.config.server_args,
            session_id = %self.session_id,
            "spawning MCP server"
        );

        let mut child = Command::new(server_cmd)
            .args(&self.config.server_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn MCP server: {server_cmd}"))?;

        let child_stdin = child
            .stdin
            .take()
            .context("failed to capture child stdin")?;
        let child_stdout = child
            .stdout
            .take()
            .context("failed to capture child stdout")?;

        // Channel for the client->server relay to write to child stdin.
        // This allows non-blocking prompt handling: messages are sent to a writer
        // task instead of directly holding the child_writer lock.
        let (child_tx, mut child_rx) = mpsc::channel::<Vec<u8>>(512);
        // Channel for writing back to proxy stdout (client).
        let (client_tx, mut client_rx) = mpsc::channel::<Vec<u8>>(512);

        // Writer task: child stdin
        let mut child_writer = tokio::io::BufWriter::new(child_stdin);
        let child_writer_handle = tokio::spawn(async move {
            while let Some(bytes) = child_rx.recv().await {
                if let Err(e) = child_writer.write_all(&bytes).await {
                    error!("error writing to child stdin: {e}");
                    break;
                }
                if let Err(e) = child_writer.flush().await {
                    error!("error flushing child stdin: {e}");
                    break;
                }
            }
            // Close child stdin when channel drops
            drop(child_writer);
        });

        // Writer task: proxy stdout (back to client)
        let proxy_stdout = tokio::io::stdout();
        let mut proxy_writer = tokio::io::BufWriter::new(proxy_stdout);
        let client_writer_handle = tokio::spawn(async move {
            while let Some(bytes) = client_rx.recv().await {
                if let Err(e) = proxy_writer.write_all(&bytes).await {
                    error!("error writing to client stdout: {e}");
                    break;
                }
                if let Err(e) = proxy_writer.flush().await {
                    error!("error flushing client stdout: {e}");
                    break;
                }
            }
        });

        // Client -> Server relay
        let policy_engine = Arc::clone(&self.policy_engine);
        let audit_tx = self.audit_tx.clone();
        let ui_bridge = self.ui_bridge.clone();
        let metrics = Arc::clone(&self.metrics);
        let prompt_timeout = self.config.prompt_timeout;
        let max_pending = self.config.max_pending_prompts;
        let session_id = self.session_id.clone();

        let child_tx_relay = child_tx.clone();
        let client_tx_relay = client_tx.clone();

        let client_relay_handle = tokio::spawn(async move {
            let proxy_stdin = tokio::io::stdin();
            let mut proxy_reader = BufReader::new(proxy_stdin);
            let mut client_parser = StreamParser::new();
            let mut client_buf = String::new();
            let mut pending_count: usize = 0;

            loop {
                match proxy_reader.read_line(&mut client_buf).await {
                    Ok(0) => {
                        info!("client closed stdin, shutting down client relay");
                        break;
                    }
                    Ok(_) => {
                        client_parser.feed(client_buf.as_bytes());
                        client_buf.clear();

                        while let Some(parse_result) = client_parser.next_message() {
                            match parse_result {
                                Ok(msg) => {
                                    metrics.inc_total();

                                    if let Err(e) = handle_client_message(
                                        msg,
                                        &policy_engine,
                                        &audit_tx,
                                        &ui_bridge,
                                        &child_tx_relay,
                                        &client_tx_relay,
                                        &metrics,
                                        prompt_timeout,
                                        max_pending,
                                        &mut pending_count,
                                        &session_id,
                                    )
                                    .await
                                    {
                                        error!("error handling client message: {e}");
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
        });

        // Server -> Client relay
        let server_audit_tx = self.audit_tx.clone();
        let server_metrics = Arc::clone(&self.metrics);
        let client_tx_server = client_tx.clone();

        let server_relay_handle = tokio::spawn(async move {
            let mut child_reader = BufReader::new(child_stdout);
            let mut server_parser = StreamParser::new();
            let mut server_buf = String::new();

            loop {
                match child_reader.read_line(&mut server_buf).await {
                    Ok(0) => {
                        info!("server closed stdout, shutting down server relay");
                        break;
                    }
                    Ok(_) => {
                        server_parser.feed(server_buf.as_bytes());
                        server_buf.clear();

                        while let Some(parse_result) = server_parser.next_message() {
                            match parse_result {
                                Ok(msg) => {
                                    // Log server responses for audit
                                    let event = build_mcp_event(&msg);
                                    let record = build_audit_record(&event, "forward", None);
                                    let _ = server_audit_tx.try_send(record);
                                    server_metrics.inc_total();

                                    let bytes = serialize_message(&msg);
                                    if client_tx_server.send(bytes).await.is_err() {
                                        error!("client writer channel closed");
                                        break;
                                    }
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
        });

        // Wait for child exit or relay task completion
        tokio::select! {
            status = child.wait() => {
                match status {
                    Ok(s) => info!("MCP server exited with status: {s}"),
                    Err(e) => error!("error waiting for MCP server: {e}"),
                }
            }
            _ = client_relay_handle => {
                info!("client relay finished, sending EOF to child");
                // Drop the child_tx to close child stdin
                drop(child_tx);
                // Wait for child to exit with a timeout
                match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                    Ok(Ok(s)) => info!("MCP server exited after stdin EOF with status: {s}"),
                    Ok(Err(e)) => error!("error waiting for MCP server: {e}"),
                    Err(_) => {
                        warn!("child did not exit within 5s after stdin EOF, killing");
                        let _ = child.kill().await;
                    }
                }
            }
            _ = server_relay_handle => {
                info!("server relay finished");
            }
        }

        // Cleanup: try to kill the child if it's still running.
        if let Err(e) = child.kill().await {
            debug!("child already exited (kill returned: {e})");
        }

        // Drop remaining channel handles to signal writer tasks
        drop(client_tx);

        // Wait for writer tasks
        let _ = child_writer_handle.await;
        let _ = client_writer_handle.await;

        info!("proxy loop finished");
        Ok(())
    }

    /// Process a client->server message: classify, evaluate policy, forward or block.
    /// This variant operates on raw writers for backwards compatibility and testing.
    pub async fn handle_client_message<W1, W2>(
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
                self.metrics.inc_allowed();
                let bytes = serialize_message(&msg);
                child_writer.write_all(&bytes).await?;
                child_writer.flush().await?;
            }
            Classification::Log => {
                let event = build_mcp_event(&msg);
                debug!(event_summary = %event_summary(&event), "logging message");
                self.metrics.inc_logged();
                let record = build_audit_record(&event, "log", None);
                let _ = self.audit_tx.try_send(record);
                let bytes = serialize_message(&msg);
                child_writer.write_all(&bytes).await?;
                child_writer.flush().await?;
            }
            Classification::Review => {
                let event = build_mcp_event(&msg);
                let action = {
                    let engine = self.policy_engine.read().await;
                    engine.evaluate(&event)
                };
                debug!(
                    event_summary = %event_summary(&event),
                    action = ?action,
                    "policy decision"
                );

                match action {
                    PolicyAction::Allow => {
                        self.metrics.inc_allowed();
                        let record = build_audit_record(&event, "allow", None);
                        let _ = self.audit_tx.try_send(record);
                        let bytes = serialize_message(&msg);
                        child_writer.write_all(&bytes).await?;
                        child_writer.flush().await?;
                    }
                    PolicyAction::Block => {
                        self.metrics.inc_blocked();
                        if let Some(id) = request_id(&msg) {
                            let block_resp =
                                make_block_response(&id, "Blocked by ClawAI policy", None);
                            let bytes = serialize_message(&block_resp);
                            proxy_writer.write_all(&bytes).await?;
                            proxy_writer.flush().await?;
                        }
                        let record = build_audit_record(&event, "block", None);
                        let _ = self.audit_tx.try_send(record);
                        info!(event_summary = %event_summary(&event), "blocked by policy");
                    }
                    PolicyAction::Prompt(prompt_msg) => {
                        self.metrics.inc_prompted();
                        if let Some(ref bridge) = self.ui_bridge {
                            if let Some(id) = request_id(&msg) {
                                let ui_req = UiRequest::PromptUser {
                                    event_summary: event_summary(&event),
                                    rule_name: "policy".to_string(),
                                    options: vec![
                                        "Allow once".into(),
                                        "Deny".into(),
                                        "Allow for session".into(),
                                        "Add to policy".into(),
                                    ],
                                };

                                match bridge.send_prompt(ui_req).await {
                                    Ok(resp_rx) => {
                                        match tokio::time::timeout(
                                            self.config.prompt_timeout,
                                            resp_rx,
                                        )
                                        .await
                                        {
                                            Ok(Ok(UiResponse::Decision {
                                                action: UserDecision::AllowOnce,
                                                ..
                                            })) => {
                                                let bytes = serialize_message(&msg);
                                                child_writer.write_all(&bytes).await?;
                                                child_writer.flush().await?;
                                                let record =
                                                    build_audit_record(&event, "allow_once", None);
                                                let _ = self.audit_tx.try_send(record);
                                            }
                                            Ok(Ok(UiResponse::Decision {
                                                action: UserDecision::AllowSession,
                                                ..
                                            })) => {
                                                let bytes = serialize_message(&msg);
                                                child_writer.write_all(&bytes).await?;
                                                child_writer.flush().await?;
                                                // Add session rule
                                                let session_rule =
                                                    build_session_allow_rule(&event);
                                                let mut engine =
                                                    self.policy_engine.write().await;
                                                engine.add_session_rule(session_rule);
                                                let record = build_audit_record(
                                                    &event,
                                                    "allow_session",
                                                    None,
                                                );
                                                let _ = self.audit_tx.try_send(record);
                                            }
                                            Ok(Ok(UiResponse::Decision {
                                                action: UserDecision::AddPolicyRule,
                                                ..
                                            })) => {
                                                let bytes = serialize_message(&msg);
                                                child_writer.write_all(&bytes).await?;
                                                child_writer.flush().await?;
                                                let perm_rule =
                                                    build_session_allow_rule(&event);
                                                let mut engine =
                                                    self.policy_engine.write().await;
                                                let _ = engine.add_permanent_rule(perm_rule);
                                                let record = build_audit_record(
                                                    &event,
                                                    "add_to_policy",
                                                    None,
                                                );
                                                let _ = self.audit_tx.try_send(record);
                                            }
                                            _ => {
                                                // Deny or timeout
                                                let block_resp = make_block_response(
                                                    &id,
                                                    &format!("ClawAI: {prompt_msg}"),
                                                    None,
                                                );
                                                let bytes = serialize_message(&block_resp);
                                                proxy_writer.write_all(&bytes).await?;
                                                proxy_writer.flush().await?;
                                                let record =
                                                    build_audit_record(&event, "deny", None);
                                                let _ = self.audit_tx.try_send(record);
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        warn!("UI bridge unavailable, denying prompt");
                                        if let Some(id) = request_id(&msg) {
                                            let block_resp = make_block_response(
                                                &id,
                                                &format!("ClawAI: {prompt_msg}"),
                                                None,
                                            );
                                            let bytes = serialize_message(&block_resp);
                                            proxy_writer.write_all(&bytes).await?;
                                            proxy_writer.flush().await?;
                                        }
                                    }
                                }
                            }
                        } else {
                            // No UI bridge: log warning and allow (backwards compat)
                            warn!(
                                event_summary = %event_summary(&event),
                                "prompt action not yet wired to IPC, allowing"
                            );
                            let bytes = serialize_message(&msg);
                            child_writer.write_all(&bytes).await?;
                            child_writer.flush().await?;
                        }
                    }
                    PolicyAction::Log => {
                        self.metrics.inc_logged();
                        debug!(event_summary = %event_summary(&event), "policy: log and forward");
                        let record = build_audit_record(&event, "log", None);
                        let _ = self.audit_tx.try_send(record);
                        let bytes = serialize_message(&msg);
                        child_writer.write_all(&bytes).await?;
                        child_writer.flush().await?;
                    }
                }
            }
            Classification::Block => {
                self.metrics.inc_blocked();
                if let Some(id) = request_id(&msg) {
                    let block_resp = make_block_response(&id, "Blocked by classifier", None);
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

/// Handle a client message using channels (for the async relay loop).
#[allow(clippy::too_many_arguments)]
async fn handle_client_message(
    msg: JsonRpcMessage,
    policy_engine: &Arc<RwLock<DefaultPolicyEngine>>,
    audit_tx: &mpsc::Sender<AuditRecord>,
    ui_bridge: &Option<Arc<UiBridge>>,
    child_tx: &mpsc::Sender<Vec<u8>>,
    client_tx: &mpsc::Sender<Vec<u8>>,
    metrics: &Arc<ProxyMetrics>,
    prompt_timeout: Duration,
    max_pending: usize,
    pending_count: &mut usize,
    _session_id: &str,
) -> Result<()> {
    let classification = classify(&msg);

    match classification {
        Classification::Pass => {
            metrics.inc_allowed();
            let bytes = serialize_message(&msg);
            child_tx.send(bytes).await.map_err(|_| anyhow::anyhow!("child channel closed"))?;
        }
        Classification::Log => {
            let event = build_mcp_event(&msg);
            debug!(event_summary = %event_summary(&event), "logging message");
            metrics.inc_logged();
            let record = build_audit_record(&event, "log", None);
            let _ = audit_tx.try_send(record);
            let bytes = serialize_message(&msg);
            child_tx.send(bytes).await.map_err(|_| anyhow::anyhow!("child channel closed"))?;
        }
        Classification::Review => {
            let event = build_mcp_event(&msg);
            let action = {
                let engine = policy_engine.read().await;
                engine.evaluate(&event)
            };
            debug!(
                event_summary = %event_summary(&event),
                action = ?action,
                "policy decision"
            );

            match action {
                PolicyAction::Allow => {
                    metrics.inc_allowed();
                    let record = build_audit_record(&event, "allow", None);
                    let _ = audit_tx.try_send(record);
                    let bytes = serialize_message(&msg);
                    child_tx.send(bytes).await.map_err(|_| anyhow::anyhow!("child channel closed"))?;
                }
                PolicyAction::Block => {
                    metrics.inc_blocked();
                    if let Some(id) = request_id(&msg) {
                        let block_resp = make_block_response(&id, "Blocked by ClawAI policy", None);
                        let bytes = serialize_message(&block_resp);
                        client_tx.send(bytes).await.map_err(|_| anyhow::anyhow!("client channel closed"))?;
                    }
                    let record = build_audit_record(&event, "block", None);
                    let _ = audit_tx.try_send(record);
                    info!(event_summary = %event_summary(&event), "blocked by policy");
                }
                PolicyAction::Prompt(prompt_msg) => {
                    metrics.inc_prompted();

                    if let Some(ref bridge) = ui_bridge {
                        if *pending_count >= max_pending {
                            warn!("max pending prompts reached, auto-denying");
                            if let Some(id) = request_id(&msg) {
                                let block_resp = make_block_response(
                                    &id,
                                    "ClawAI: too many pending prompts",
                                    None,
                                );
                                let bytes = serialize_message(&block_resp);
                                client_tx.send(bytes).await.map_err(|_| anyhow::anyhow!("client channel closed"))?;
                            }
                            return Ok(());
                        }

                        *pending_count += 1;

                        // Spawn the prompt handling as a separate task so other messages continue flowing
                        let bridge = Arc::clone(bridge);
                        let policy_engine = Arc::clone(policy_engine);
                        let audit_tx = audit_tx.clone();
                        let child_tx = child_tx.clone();
                        let client_tx = client_tx.clone();
                        let metrics = Arc::clone(metrics);

                        tokio::spawn(async move {
                            let id = request_id(&msg);
                            let ui_req = UiRequest::PromptUser {
                                event_summary: event_summary(&event),
                                rule_name: "policy".to_string(),
                                options: vec![
                                    "Allow once".into(),
                                    "Deny".into(),
                                    "Allow for session".into(),
                                    "Add to policy".into(),
                                ],
                            };

                            let result = match bridge.send_prompt(ui_req).await {
                                Ok(resp_rx) => {
                                    match tokio::time::timeout(prompt_timeout, resp_rx).await {
                                        Ok(Ok(resp)) => Some(resp),
                                        _ => None,
                                    }
                                }
                                Err(_) => {
                                    warn!("UI bridge unavailable, denying");
                                    None
                                }
                            };

                            match result {
                                Some(UiResponse::Decision {
                                    action: UserDecision::AllowOnce,
                                    ..
                                }) => {
                                    let bytes = serialize_message(&msg);
                                    let _ = child_tx.send(bytes).await;
                                    let record = build_audit_record(&event, "allow_once", None);
                                    let _ = audit_tx.try_send(record);
                                    metrics.inc_allowed();
                                }
                                Some(UiResponse::Decision {
                                    action: UserDecision::AllowSession,
                                    ..
                                }) => {
                                    let bytes = serialize_message(&msg);
                                    let _ = child_tx.send(bytes).await;
                                    let session_rule = build_session_allow_rule(&event);
                                    let mut engine = policy_engine.write().await;
                                    engine.add_session_rule(session_rule);
                                    let record =
                                        build_audit_record(&event, "allow_session", None);
                                    let _ = audit_tx.try_send(record);
                                    metrics.inc_allowed();
                                }
                                Some(UiResponse::Decision {
                                    action: UserDecision::AddPolicyRule,
                                    ..
                                }) => {
                                    let bytes = serialize_message(&msg);
                                    let _ = child_tx.send(bytes).await;
                                    let perm_rule = build_session_allow_rule(&event);
                                    let mut engine = policy_engine.write().await;
                                    let _ = engine.add_permanent_rule(perm_rule);
                                    let record =
                                        build_audit_record(&event, "add_to_policy", None);
                                    let _ = audit_tx.try_send(record);
                                    metrics.inc_allowed();
                                }
                                _ => {
                                    // Deny or timeout
                                    if let Some(ref id) = id {
                                        let block_resp = make_block_response(
                                            id,
                                            &format!("ClawAI: {prompt_msg}"),
                                            None,
                                        );
                                        let bytes = serialize_message(&block_resp);
                                        let _ = client_tx.send(bytes).await;
                                    }
                                    let record = build_audit_record(&event, "deny", None);
                                    let _ = audit_tx.try_send(record);
                                    metrics.inc_blocked();
                                }
                            }
                        });
                    } else {
                        // No UI bridge: allow (backwards compat)
                        warn!(
                            event_summary = %event_summary(&event),
                            "prompt action not wired to IPC, allowing"
                        );
                        metrics.inc_allowed();
                        let bytes = serialize_message(&msg);
                        child_tx.send(bytes).await.map_err(|_| anyhow::anyhow!("child channel closed"))?;
                    }
                }
                PolicyAction::Log => {
                    metrics.inc_logged();
                    debug!(event_summary = %event_summary(&event), "policy: log and forward");
                    let record = build_audit_record(&event, "log", None);
                    let _ = audit_tx.try_send(record);
                    let bytes = serialize_message(&msg);
                    child_tx.send(bytes).await.map_err(|_| anyhow::anyhow!("child channel closed"))?;
                }
            }
        }
        Classification::Block => {
            metrics.inc_blocked();
            if let Some(id) = request_id(&msg) {
                let block_resp = make_block_response(&id, "Blocked by classifier", None);
                let bytes = serialize_message(&block_resp);
                client_tx.send(bytes).await.map_err(|_| anyhow::anyhow!("client channel closed"))?;
            }
            info!("message hard-blocked by classifier");
        }
    }

    Ok(())
}

/// Build a block error response for a given request id.
fn make_block_response(
    request_id: &JsonRpcId,
    message: &str,
    rule_data: Option<(&str, &str)>,
) -> JsonRpcMessage {
    let data = rule_data.map(|(rule_name, action)| {
        json!({
            "rule": rule_name,
            "action": action,
        })
    });

    JsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: request_id.clone(),
        result: None,
        error: Some(JsonRpcError {
            code: POLICY_BLOCK_ERROR_CODE,
            message: message.to_string(),
            data,
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

/// Build an audit record from an McpEvent.
fn build_audit_record(
    event: &McpEvent,
    action: &str,
    rule_name: Option<&str>,
) -> AuditRecord {
    AuditRecord {
        timestamp: event.timestamp,
        source: event.source.clone(),
        event_summary: event_summary(event),
        event_details: serde_json::to_value(event).unwrap_or_default(),
        rule_matched: rule_name.map(|s| s.to_string()),
        action_taken: action.to_string(),
        response_time_ms: None,
        session_id: None,
        direction: None,
        server_name: None,
        client_name: None,
        jsonrpc_method: None,
        tool_name: None,
        arguments: None,
        classification: None,
        policy_rule: None,
        policy_action: None,
        user_decision: None,
        proxy_latency_us: None,
    }
}

/// Build a session-scoped allow rule from an event (for AllowSession decisions).
fn build_session_allow_rule(event: &McpEvent) -> PolicyRule {
    let (name, criteria) = match &event.kind {
        McpEventKind::ToolCall(tc) => (
            format!("session_allow_{}", tc.tool_name),
            MatchCriteria {
                tool_names: Some(vec![tc.tool_name.clone()]),
                ..Default::default()
            },
        ),
        McpEventKind::ResourceRead(rr) => (
            format!("session_allow_resource_{}", rr.uri.replace('/', "_")),
            MatchCriteria {
                resource_paths: Some(vec![rr.uri.clone()]),
                ..Default::default()
            },
        ),
        _ => (
            "session_allow_generic".to_string(),
            MatchCriteria {
                any: true,
                ..Default::default()
            },
        ),
    };

    PolicyRule {
        name,
        description: "Auto-created session rule from user decision".to_string(),
        match_criteria: criteria,
        action: PolicyAction::Allow,
        message: "Allowed by session rule".to_string(),
        priority: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonrpc::parser::parse_message;
    use crate::jsonrpc::types::JsonRpcRequest;
    use std::io::Write as _;
    use std::sync::atomic::Ordering;
    use tempfile::NamedTempFile;
    use tokio::sync::oneshot;

    fn block_policy_toml() -> &'static str {
        r#"
[rules.block_exec]
description = "Block exec tool"
action = "block"
message = "exec is blocked"
priority = 0

[rules.block_exec.match]
tool_name = ["exec*"]

[rules.prompt_ssh]
description = "Prompt on SSH"
action = "prompt"
message = "Allow SSH access?"
priority = 1

[rules.prompt_ssh.match]
tool_name = ["ssh*"]

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
        let resp = make_block_response(&JsonRpcId::Number(42), "blocked", None);
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
    fn test_make_block_response_with_rule_data() {
        let resp = make_block_response(
            &JsonRpcId::Number(1),
            "ClawAI: exec blocked",
            Some(("block_exec", "blocked")),
        );
        match resp {
            JsonRpcMessage::Response(r) => {
                let err = r.error.unwrap();
                assert_eq!(err.code, POLICY_BLOCK_ERROR_CODE);
                let data = err.data.unwrap();
                assert_eq!(data["rule"], "block_exec");
                assert_eq!(data["action"], "blocked");
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

    #[test]
    fn test_build_audit_record() {
        let msg = make_tools_call_request("read_file");
        let event = build_mcp_event(&msg);
        let record = build_audit_record(&event, "allow", Some("allow_rest"));
        assert_eq!(record.action_taken, "allow");
        assert_eq!(record.rule_matched.as_deref(), Some("allow_rest"));
        assert!(record.event_summary.contains("read_file"));
    }

    #[test]
    fn test_build_session_allow_rule_tool_call() {
        let msg = make_tools_call_request("read_file");
        let event = build_mcp_event(&msg);
        let rule = build_session_allow_rule(&event);
        assert!(rule.name.contains("read_file"));
        assert_eq!(rule.action, PolicyAction::Allow);
        assert!(rule.match_criteria.tool_names.is_some());
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

        // Verify metrics
        assert_eq!(proxy.metrics().messages_blocked.load(Ordering::Relaxed), 1);
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

        assert_eq!(proxy.metrics().messages_allowed.load(Ordering::Relaxed), 1);
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
        assert_eq!(proxy.metrics().messages_logged.load(Ordering::Relaxed), 1);
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

    #[tokio::test]
    async fn test_prompt_without_ui_bridge_allows() {
        let f = write_temp_policy(block_policy_toml());
        let proxy = StdioProxy::new("echo".into(), vec![], f.path()).unwrap();

        // ssh* triggers Prompt action but no UI bridge
        let msg = make_tools_call_request("ssh_connect");

        let mut child_buf: Vec<u8> = Vec::new();
        let mut client_buf: Vec<u8> = Vec::new();

        proxy
            .handle_client_message(msg, &mut child_buf, &mut client_buf)
            .await
            .unwrap();

        // Without UI bridge, should allow (backwards compat)
        assert!(!child_buf.is_empty(), "should forward when no UI bridge");
        assert!(client_buf.is_empty());
    }

    #[tokio::test]
    async fn test_prompt_with_ui_bridge_allow_once() {
        let f = write_temp_policy(block_policy_toml());
        let (ui_tx, mut ui_rx) =
            mpsc::channel::<(UiRequest, oneshot::Sender<UiResponse>)>(16);
        let bridge = Arc::new(UiBridge::new(ui_tx));

        let (audit_tx, _audit_rx) = mpsc::channel(1024);
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();

        let proxy = StdioProxy::with_full_config(
            ProxyConfig {
                server_command: Some("echo".into()),
                ..Default::default()
            },
            engine,
            audit_tx,
            Some(bridge),
        );

        let msg = make_tools_call_request("ssh_connect");

        // Spawn handler in background
        let proxy_handle = tokio::spawn(async move {
            let mut child_buf: Vec<u8> = Vec::new();
            let mut client_buf: Vec<u8> = Vec::new();
            proxy
                .handle_client_message(msg, &mut child_buf, &mut client_buf)
                .await
                .unwrap();
            (child_buf, client_buf)
        });

        // Respond to the prompt
        let (req, resp_tx) = ui_rx.recv().await.unwrap();
        match req {
            UiRequest::PromptUser { event_summary, .. } => {
                assert!(event_summary.contains("ssh_connect"));
            }
            _ => panic!("expected PromptUser"),
        }
        resp_tx
            .send(UiResponse::Decision {
                event_id: "test".into(),
                action: UserDecision::AllowOnce,
            })
            .unwrap();

        let (child_buf, client_buf) = proxy_handle.await.unwrap();
        assert!(!child_buf.is_empty(), "should forward after AllowOnce");
        assert!(client_buf.is_empty());
    }

    #[tokio::test]
    async fn test_prompt_with_ui_bridge_deny() {
        let f = write_temp_policy(block_policy_toml());
        let (ui_tx, mut ui_rx) =
            mpsc::channel::<(UiRequest, oneshot::Sender<UiResponse>)>(16);
        let bridge = Arc::new(UiBridge::new(ui_tx));

        let (audit_tx, _audit_rx) = mpsc::channel(1024);
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();

        let proxy = StdioProxy::with_full_config(
            ProxyConfig {
                server_command: Some("echo".into()),
                ..Default::default()
            },
            engine,
            audit_tx,
            Some(bridge),
        );

        let msg = make_tools_call_request("ssh_connect");

        let proxy_handle = tokio::spawn(async move {
            let mut child_buf: Vec<u8> = Vec::new();
            let mut client_buf: Vec<u8> = Vec::new();
            proxy
                .handle_client_message(msg, &mut child_buf, &mut client_buf)
                .await
                .unwrap();
            (child_buf, client_buf)
        });

        // Respond with deny
        let (_req, resp_tx) = ui_rx.recv().await.unwrap();
        resp_tx
            .send(UiResponse::Decision {
                event_id: "test".into(),
                action: UserDecision::DenyOnce,
            })
            .unwrap();

        let (child_buf, client_buf) = proxy_handle.await.unwrap();
        assert!(child_buf.is_empty(), "should NOT forward after Deny");
        assert!(!client_buf.is_empty(), "should send error to client");

        let resp = parse_message(&client_buf[..client_buf.len() - 1]).unwrap();
        match resp {
            JsonRpcMessage::Response(r) => {
                assert_eq!(r.error.unwrap().code, POLICY_BLOCK_ERROR_CODE);
            }
            _ => panic!("expected error response"),
        }
    }

    #[tokio::test]
    async fn test_prompt_timeout_auto_denies() {
        let f = write_temp_policy(block_policy_toml());
        let (ui_tx, mut ui_rx) =
            mpsc::channel::<(UiRequest, oneshot::Sender<UiResponse>)>(16);
        let bridge = Arc::new(UiBridge::new(ui_tx));

        let (audit_tx, _audit_rx) = mpsc::channel(1024);
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();

        let proxy = StdioProxy::with_full_config(
            ProxyConfig {
                server_command: Some("echo".into()),
                prompt_timeout: Duration::from_millis(50), // Very short timeout for test
                ..Default::default()
            },
            engine,
            audit_tx,
            Some(bridge),
        );

        let msg = make_tools_call_request("ssh_connect");

        let proxy_handle = tokio::spawn(async move {
            let mut child_buf: Vec<u8> = Vec::new();
            let mut client_buf: Vec<u8> = Vec::new();
            proxy
                .handle_client_message(msg, &mut child_buf, &mut client_buf)
                .await
                .unwrap();
            (child_buf, client_buf)
        });

        // Receive the prompt but don't respond -- let it timeout
        let (_req, _resp_tx) = ui_rx.recv().await.unwrap();
        // Drop resp_tx to simulate no response

        let (child_buf, client_buf) = proxy_handle.await.unwrap();
        assert!(child_buf.is_empty(), "should NOT forward after timeout");
        assert!(!client_buf.is_empty(), "should send error after timeout");
    }

    #[tokio::test]
    async fn test_prompt_allow_session_adds_rule() {
        let f = write_temp_policy(block_policy_toml());
        let (ui_tx, mut ui_rx) =
            mpsc::channel::<(UiRequest, oneshot::Sender<UiResponse>)>(16);
        let bridge = Arc::new(UiBridge::new(ui_tx));

        let (audit_tx, _audit_rx) = mpsc::channel(1024);
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();

        let proxy = StdioProxy::with_full_config(
            ProxyConfig {
                server_command: Some("echo".into()),
                ..Default::default()
            },
            engine,
            audit_tx,
            Some(bridge),
        );

        let msg = make_tools_call_request("ssh_connect");

        let policy_engine = Arc::clone(&proxy.policy_engine);

        let proxy_handle = tokio::spawn(async move {
            let mut child_buf: Vec<u8> = Vec::new();
            let mut client_buf: Vec<u8> = Vec::new();
            proxy
                .handle_client_message(msg, &mut child_buf, &mut client_buf)
                .await
                .unwrap();
            (child_buf, client_buf)
        });

        // Respond with AllowSession
        let (_req, resp_tx) = ui_rx.recv().await.unwrap();
        resp_tx
            .send(UiResponse::Decision {
                event_id: "test".into(),
                action: UserDecision::AllowSession,
            })
            .unwrap();

        let (child_buf, _) = proxy_handle.await.unwrap();
        assert!(!child_buf.is_empty(), "should forward after AllowSession");

        // Verify that a second call now auto-allows without prompt
        let event = build_mcp_event(&make_tools_call_request("ssh_connect"));
        let engine = policy_engine.read().await;
        let action = engine.evaluate(&event);
        assert_eq!(action, PolicyAction::Allow, "session rule should auto-allow");
    }

    #[tokio::test]
    async fn test_message_ordering_preserved() {
        let proxy = StdioProxy::with_engine("echo".into(), vec![], DefaultPolicyEngine::empty());

        let mut child_buf: Vec<u8> = Vec::new();
        let mut client_buf: Vec<u8> = Vec::new();

        // Send 100 messages rapidly
        for i in 0..100 {
            let msg = JsonRpcMessage::Request(JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: JsonRpcId::Number(i),
                method: "tools/call".into(),
                params: Some(json!({"name": "read_file", "arguments": {"path": format!("/tmp/{i}")}})),
            });
            proxy
                .handle_client_message(msg, &mut child_buf, &mut client_buf)
                .await
                .unwrap();
        }

        // Parse all forwarded messages and verify ordering
        let mut parser = StreamParser::new();
        parser.feed(&child_buf);
        let mut ids = Vec::new();
        while let Some(Ok(msg)) = parser.next_message() {
            if let JsonRpcMessage::Request(r) = msg {
                if let JsonRpcId::Number(n) = r.id {
                    ids.push(n);
                }
            }
        }
        assert_eq!(ids.len(), 100);
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(*id, i as i64, "message order should be preserved");
        }
    }

    #[test]
    fn test_metrics_initial_state() {
        let metrics = ProxyMetrics::new();
        assert_eq!(metrics.messages_total.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.messages_allowed.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.messages_blocked.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_batch_messages_individually_evaluated() {
        let f = write_temp_policy(block_policy_toml());
        let proxy = StdioProxy::new("echo".into(), vec![], f.path()).unwrap();

        // exec_command should be blocked, read_file should be allowed
        let msg_blocked = make_tools_call_request("exec_command");
        let msg_allowed = make_tools_call_request("read_file");

        let mut child_buf: Vec<u8> = Vec::new();
        let mut client_buf: Vec<u8> = Vec::new();

        // Process both as individual messages (batch handling at JSON-RPC level)
        proxy
            .handle_client_message(msg_blocked, &mut child_buf, &mut client_buf)
            .await
            .unwrap();

        let blocked_child = child_buf.clone();
        let blocked_client = client_buf.clone();

        child_buf.clear();
        client_buf.clear();

        proxy
            .handle_client_message(msg_allowed, &mut child_buf, &mut client_buf)
            .await
            .unwrap();

        // First message: blocked (no child output, error to client)
        assert!(blocked_child.is_empty());
        assert!(!blocked_client.is_empty());

        // Second message: allowed (forwarded to child, no error to client)
        assert!(!child_buf.is_empty());
        assert!(client_buf.is_empty());

        assert_eq!(proxy.metrics().messages_blocked.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.metrics().messages_allowed.load(Ordering::Relaxed), 1);
    }
}
