//! MCP proxy binary entry point.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("claw-mcp-proxy starting");
    // TODO: Phase 1 - launch stdio/http proxy
    Ok(())
}
