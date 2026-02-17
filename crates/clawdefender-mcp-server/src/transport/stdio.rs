//! Stdio transport for the MCP server.
//!
//! Reads newline-delimited JSON-RPC messages from stdin and writes responses to stdout.

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info};

use crate::protocol;
use crate::McpServer;

/// Run the MCP server on stdio.
pub async fn run(server: Arc<McpServer>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    info!("MCP server stdio transport ready");

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        debug!("recv: {}", line);

        if let Some(response) = protocol::handle_message(&server, &line).await {
            debug!("send: {}", response);
            stdout.write_all(response.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }

    info!("stdin closed, MCP server shutting down");
    Ok(())
}
