//! HTTP transport for the MCP server using axum.
//!
//! Provides a POST endpoint at `/mcp` that accepts JSON-RPC messages.
//! When the server has an `auth_token` configured, all requests must include
//! an `Authorization: Bearer <token>` header.

use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use tracing::{info, warn};

use crate::auth;
use crate::protocol;
use crate::McpServer;

/// Run the MCP server on HTTP at the given port.
pub async fn run(server: Arc<McpServer>, port: u16) -> Result<()> {
    let app = Router::new()
        .route("/mcp", post(handle_mcp))
        .with_state(server);

    let addr = format!("127.0.0.1:{port}");
    info!("MCP HTTP server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_mcp(
    State(server): State<Arc<McpServer>>,
    headers: HeaderMap,
    body: String,
) -> Result<(StatusCode, String), StatusCode> {
    // Authenticate if token is configured.
    if let Some(ref expected_token) = server.auth_token {
        let auth_header = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !auth::validate_bearer_token(auth_header, expected_token) {
            warn!("HTTP request rejected: invalid or missing auth token");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Derive caller_id from auth token hash or "http-anonymous".
    let caller_id = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|_| "http-authenticated".to_string())
        .unwrap_or_else(|| "http-anonymous".to_string());

    match protocol::handle_message_with_caller(&server, &body, &caller_id).await {
        Some(response) => Ok((StatusCode::OK, response)),
        None => Ok((StatusCode::NO_CONTENT, String::new())),
    }
}
