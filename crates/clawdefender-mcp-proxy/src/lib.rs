//! MCP protocol proxy with JSON-RPC interception for ClawDefender.

pub mod classifier;
pub mod jsonrpc;
pub mod proxy;

pub use proxy::http::HttpProxy;
pub use proxy::stdio::StdioProxy;
pub use proxy::{
    ProxyConfig, ProxyMetrics, SlmContext, SwarmContext, ThreatIntelContext, UiBridge,
};

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use clawdefender_core::audit::AuditRecord;
use clawdefender_core::policy::engine::DefaultPolicyEngine;
use tokio::sync::mpsc;

/// Convenience function to create and run a stdio MCP proxy.
pub async fn run_stdio_proxy(cmd: String, args: Vec<String>, policy_path: &Path) -> Result<()> {
    let proxy = StdioProxy::new(cmd, args, policy_path)?;
    proxy.run().await
}

/// Convenience function to create and run a stdio proxy with full configuration.
pub async fn run_stdio_proxy_full(
    config: ProxyConfig,
    policy_engine: DefaultPolicyEngine,
    audit_tx: mpsc::Sender<AuditRecord>,
    ui_bridge: Option<Arc<UiBridge>>,
) -> Result<()> {
    let proxy = StdioProxy::with_full_config(config, policy_engine, audit_tx, ui_bridge);
    proxy.run().await
}

/// Convenience function to create and run an HTTP MCP proxy.
pub async fn run_http_proxy(
    remote_url: String,
    policy_path: &Path,
    addr: SocketAddr,
) -> Result<()> {
    let proxy = HttpProxy::new(remote_url, policy_path)?;
    proxy.start(addr).await
}
