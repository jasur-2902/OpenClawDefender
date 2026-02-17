//! MCP proxy binary entry point.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

/// ClawDefender MCP Proxy -- intercepts JSON-RPC between MCP clients and servers.
#[derive(Parser, Debug)]
#[command(name = "clawdefender-mcp-proxy", version, about)]
struct Cli {
    /// MCP server command to spawn (e.g. `node /path/to/server.js`).
    /// Use `--` to separate proxy args from server command.
    #[arg(trailing_var_arg = true)]
    server_cmd: Vec<String>,

    /// Path to the ClawDefender policy TOML file.
    #[arg(long = "policy", default_value = "~/.config/clawdefender/policy.toml")]
    policy_path: String,

    /// Run in HTTP proxy mode instead of stdio.
    #[arg(long = "http")]
    http_mode: bool,

    /// Remote MCP server URL for HTTP mode.
    #[arg(long = "remote")]
    remote_url: Option<String>,

    /// Listen address for HTTP mode.
    #[arg(long = "listen", default_value = "127.0.0.1:3100")]
    listen_addr: String,

    /// Skip TLS certificate verification (HTTP mode only).
    #[arg(long = "insecure")]
    insecure: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // CRITICAL: All logging MUST go to stderr. Any output to stdout that isn't
    // JSON-RPC will poison the MCP stream and break Claude Desktop.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let policy_path = expand_tilde(&cli.policy_path);

    if cli.http_mode {
        let remote_url = cli
            .remote_url
            .ok_or_else(|| anyhow::anyhow!("--remote is required in HTTP mode"))?;

        let addr: SocketAddr = cli
            .listen_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid listen address '{}': {e}", cli.listen_addr))?;

        tracing::info!(
            remote = %remote_url,
            listen = %addr,
            policy = %policy_path.display(),
            insecure = %cli.insecure,
            "starting clawdefender-mcp-proxy in HTTP mode"
        );

        clawdefender_mcp_proxy::run_http_proxy(remote_url, &policy_path, addr).await
    } else {
        if cli.server_cmd.is_empty() {
            anyhow::bail!("server command is required in stdio mode. Use: clawdefender-mcp-proxy [OPTIONS] -- <server-command> [args...]");
        }

        let (cmd, args) = cli
            .server_cmd
            .split_first()
            .expect("server command is required");

        tracing::info!(
            cmd = %cmd,
            args = ?args,
            policy = %policy_path.display(),
            "starting clawdefender-mcp-proxy in stdio mode"
        );

        clawdefender_mcp_proxy::run_stdio_proxy(cmd.clone(), args.to_vec(), &policy_path).await
    }
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
