//! `clawai proxy -- <command> <args...>` — run as a stdio MCP proxy.

use anyhow::{bail, Result};
use claw_core::config::ClawConfig;

pub async fn run(server_command: Vec<String>, config: &ClawConfig) -> Result<()> {
    if server_command.is_empty() {
        bail!("No server command provided.\nUsage: clawai proxy -- <command> [args...]");
    }

    let (cmd, args) = server_command.split_first().unwrap();
    claw_mcp_proxy::run_stdio_proxy(cmd.clone(), args.to_vec(), &config.policy_path).await
}
