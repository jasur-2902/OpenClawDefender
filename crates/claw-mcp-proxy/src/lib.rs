//! MCP protocol proxy with JSON-RPC interception for ClawAI.

pub mod classifier;
pub mod jsonrpc;
pub mod proxy;

pub use proxy::stdio::StdioProxy;
pub use proxy::http::HttpProxy;

use std::path::Path;

use anyhow::Result;

/// Convenience function to create and run a stdio MCP proxy.
pub async fn run_stdio_proxy(
    cmd: String,
    args: Vec<String>,
    policy_path: &Path,
) -> Result<()> {
    let mut proxy = StdioProxy::new(cmd, args, policy_path)?;
    proxy.run().await
}
