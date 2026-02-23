//! ClawDefender daemon binary entry point.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use clawdefender_core::config::settings::ClawConfig;
use clawdefender_daemon::Daemon;

/// ClawDefender - firewall for AI agents.
#[derive(Parser, Debug)]
#[command(name = "clawdefender", version, about)]
struct Args {
    /// Path to configuration file.
    #[arg(short, long, default_value = "~/.config/clawdefender/config.toml")]
    config: String,

    /// Enable the terminal UI dashboard.
    #[arg(long)]
    tui: bool,

    /// Override policy file path.
    #[arg(long)]
    policy: Option<String>,

    #[command(subcommand)]
    command: Option<DaemonCommand>,
}

#[derive(Subcommand, Debug)]
enum DaemonCommand {
    /// Run the daemon in standalone mode (IPC server, sensors, audit).
    Run,
    /// Proxy an MCP server, intercepting JSON-RPC messages.
    Proxy {
        /// Command and arguments for the MCP server (after --).
        #[arg(last = true)]
        server_command: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Set up tracing: to file when TUI is enabled, to stderr otherwise.
    // Priority: CLAWDEFENDER_LOG env var > [ui] log_level in config.toml > default.
    let env_filter = EnvFilter::try_from_env("CLAWDEFENDER_LOG")
        .unwrap_or_else(|_| {
            // Try to read log_level from config.toml as fallback
            let config_log_level = read_config_log_level(&expand_tilde(&args.config));
            if let Some(level) = config_log_level {
                EnvFilter::new(level)
            } else {
                EnvFilter::from_default_env()
            }
        });

    if args.tui {
        // When TUI is active, log to a file to avoid corrupting the terminal.
        let log_dir = dirs_fallback(".local/share/clawdefender");
        std::fs::create_dir_all(&log_dir).ok();
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join("daemon.log"))
            .context("opening daemon log file")?;
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::sync::Mutex::new(log_file))
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    // Resolve config path.
    let config_path = expand_tilde(&args.config);
    tracing::info!(config = %config_path.display(), tui = args.tui, "clawdefender-daemon starting");

    // Load configuration.
    let mut config = ClawConfig::load(&config_path).context("loading configuration")?;

    // Override policy path if specified.
    if let Some(ref policy) = args.policy {
        config.policy_path = expand_tilde(policy);
    }

    match args.command {
        Some(DaemonCommand::Run) | None => {
            let daemon = Daemon::new(config, args.tui)?;
            daemon.run().await
        }
        Some(DaemonCommand::Proxy { server_command }) => {
            if server_command.is_empty() {
                anyhow::bail!("proxy command requires a server command: clawdefender proxy -- <cmd> [args...]");
            }
            let command = server_command[0].clone();
            let cmd_args = server_command[1..].to_vec();

            let daemon = Daemon::new(config, args.tui)?;
            daemon.run_proxy(command, cmd_args).await
        }
    }
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        dirs_fallback(rest)
    } else {
        PathBuf::from(path)
    }
}

/// Resolve a relative path under the user's home directory.
fn dirs_fallback(relative: &str) -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(relative)
    } else {
        PathBuf::from("/tmp").join(relative)
    }
}

/// Read log_level from config.toml [ui] section as a fallback for tracing setup.
/// Uses simple line parsing to avoid pulling in toml as a binary dependency.
fn read_config_log_level(config_path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(config_path).ok()?;
    let mut in_ui_section = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_ui_section = trimmed == "[ui]";
            continue;
        }
        if in_ui_section {
            if let Some(rest) = trimmed.strip_prefix("log_level") {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    let val = rest.trim().trim_matches('"').trim_matches('\'');
                    let valid = ["trace", "debug", "info", "warn", "error"];
                    if valid.contains(&val) {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}
