//! Unix domain socket IPC server for daemon status and control.
//!
//! Accepts JSON-line messages from clients on a Unix socket. Supports
//! `"status"` queries (returns proxy metrics) and `"reload"` commands
//! (triggers policy hot-reload).

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use claw_core::policy::engine::DefaultPolicyEngine;
use claw_core::policy::PolicyEngine;
use claw_mcp_proxy::ProxyMetrics;

/// Run the IPC server, accepting connections on the given Unix socket path.
pub async fn run_ipc_server(
    socket_path: PathBuf,
    metrics: Arc<ProxyMetrics>,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
) -> Result<()> {
    // Remove stale socket if it exists.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).context("removing stale IPC socket")?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).context("creating IPC socket parent directory")?;
    }

    let listener = UnixListener::bind(&socket_path).context("binding IPC socket")?;

    info!(path = %socket_path.display(), "IPC server listening");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                debug!("IPC client connected");
                let metrics = Arc::clone(&metrics);
                let policy_engine = Arc::clone(&policy_engine);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, metrics, policy_engine).await {
                        debug!(error = %e, "IPC client disconnected");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "failed to accept IPC connection");
            }
        }
    }
}

async fn handle_client(
    stream: tokio::net::UnixStream,
    metrics: Arc<ProxyMetrics>,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed == "\"status\"" || trimmed == "status" {
            let response = serde_json::json!({
                "messages_total": metrics.messages_total.load(Ordering::Relaxed),
                "messages_allowed": metrics.messages_allowed.load(Ordering::Relaxed),
                "messages_blocked": metrics.messages_blocked.load(Ordering::Relaxed),
                "messages_prompted": metrics.messages_prompted.load(Ordering::Relaxed),
                "messages_logged": metrics.messages_logged.load(Ordering::Relaxed),
            });
            let response = serde_json::to_string(&response)?;
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        } else if trimmed == "\"reload\"" || trimmed == "reload" {
            let mut engine = policy_engine.write().await;
            let result = match engine.reload() {
                Ok(()) => {
                    info!("policy reloaded via IPC");
                    serde_json::json!({"ok": true})
                }
                Err(e) => {
                    warn!(error = %e, "policy reload via IPC failed");
                    serde_json::json!({"ok": false, "error": e.to_string()})
                }
            };
            let response = serde_json::to_string(&result)?;
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        } else {
            warn!(line = trimmed, "unknown IPC command");
            let response = serde_json::json!({"error": "unknown command"});
            let response = serde_json::to_string(&response)?;
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }
    }

    Ok(())
}
