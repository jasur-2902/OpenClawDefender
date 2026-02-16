//! Unix domain socket IPC server for daemon-UI communication.
//!
//! Accepts JSON-line messages from clients and dispatches them
//! as [`IpcMessage`] values to the daemon event loop.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use claw_core::ipc::protocol::UiResponse;
use claw_tui::SharedState;

use crate::IpcMessage;

/// Run the IPC server, accepting connections on the given Unix socket path.
///
/// Each connected client can send JSON-encoded [`UiResponse`] messages and
/// receives JSON-encoded [`UiRequest`] messages (currently just status updates).
pub async fn run_ipc_server(
    socket_path: PathBuf,
    tx: mpsc::Sender<IpcMessage>,
    state: SharedState,
) -> Result<()> {
    // Remove stale socket if it exists.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)
            .context("removing stale IPC socket")?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .context("creating IPC socket parent directory")?;
    }

    let listener = UnixListener::bind(&socket_path)
        .context("binding IPC socket")?;

    info!(path = %socket_path.display(), "IPC server listening");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                debug!("IPC client connected");
                let tx = tx.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, tx, state).await {
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
    _tx: mpsc::Sender<IpcMessage>,
    state: SharedState,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // Client disconnected.
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Try to parse as a simple command string first.
        if trimmed == "\"status\"" || trimmed == "status" {
            let response = if let Ok(s) = state.read() {
                serde_json::json!({
                    "total_events": s.stats.total_events,
                    "blocked": s.stats.blocked,
                    "allowed": s.stats.allowed,
                    "prompted": s.stats.prompted,
                    "uptime_secs": s.stats.uptime_secs,
                })
            } else {
                serde_json::json!(null)
            };
            let response = serde_json::to_string(&response)?;
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            continue;
        }

        // Try to parse as UiResponse.
        match serde_json::from_str::<UiResponse>(trimmed) {
            Ok(response) => {
                debug!(?response, "received IPC response from client");
                // Handle the response based on type - currently log it.
                // Future: forward prompt decisions to daemon.
            }
            Err(e) => {
                warn!(error = %e, line = trimmed, "failed to parse IPC message");
            }
        }
    }

    Ok(())
}
