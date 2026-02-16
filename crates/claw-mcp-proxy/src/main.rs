//! MCP proxy binary entry point.

use std::path::PathBuf;

use clap::Parser;

/// ClawAI MCP Proxy — intercepts JSON-RPC between MCP clients and servers.
#[derive(Parser, Debug)]
#[command(name = "claw-mcp-proxy", version, about)]
struct Cli {
    /// MCP server command to spawn (e.g. `node /path/to/server.js`).
    /// Use `--` to separate proxy args from server command.
    #[arg(trailing_var_arg = true, required = true)]
    server_cmd: Vec<String>,

    /// Path to the ClawAI policy TOML file.
    #[arg(long = "policy", default_value = "~/.config/clawai/policy.toml")]
    policy_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let policy_path = expand_tilde(&cli.policy_path);

    let (cmd, args) = cli
        .server_cmd
        .split_first()
        .expect("server command is required");

    tracing::info!(
        cmd = %cmd,
        args = ?args,
        policy = %policy_path.display(),
        "starting claw-mcp-proxy"
    );

    claw_mcp_proxy::run_stdio_proxy(cmd.clone(), args.to_vec(), &policy_path).await
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}
