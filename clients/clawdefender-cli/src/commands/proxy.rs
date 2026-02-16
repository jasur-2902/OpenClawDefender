//! `clawdefender proxy -- <command> <args...>` — run as a stdio MCP proxy.

use anyhow::{bail, Result};
use clawdefender_core::config::ClawConfig;

pub async fn run(server_command: Vec<String>, config: &ClawConfig) -> Result<()> {
    if server_command.is_empty() {
        bail!("No server command provided.\nUsage: clawdefender proxy -- <command> [args...]");
    }

    let (cmd, args) = server_command.split_first().unwrap();
    clawdefender_mcp_proxy::run_stdio_proxy(cmd.clone(), args.to_vec(), &config.policy_path).await
}
