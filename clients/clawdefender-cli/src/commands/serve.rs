//! `clawdefender serve` command — starts the MCP server.

use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use clawdefender_core::audit::logger::FileAuditLogger;
use clawdefender_core::config::ClawConfig;
use clawdefender_core::policy::engine::DefaultPolicyEngine;
use clawdefender_mcp_server::McpServer;

/// Run the ClawDefender MCP server.
pub async fn run(config: &ClawConfig, stdio: bool, http_port: u16) -> Result<()> {
    info!("starting ClawDefender MCP server");

    let policy_engine = DefaultPolicyEngine::load(&config.policy_path)?;
    let audit_logger = Arc::new(FileAuditLogger::new(
        config.audit_log_path.clone(),
        config.log_rotation.clone(),
    )?);

    let server = Arc::new(McpServer::new(Box::new(policy_engine), audit_logger));

    if stdio {
        server.run_stdio().await?;
    } else if http_port > 0 {
        server.run_http(http_port).await?;
    } else {
        anyhow::bail!("No transport enabled. Use --stdio or set --http-port > 0.");
    }

    Ok(())
}
