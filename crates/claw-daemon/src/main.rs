//! ClawAI daemon binary entry point.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use claw_core::config::settings::ClawConfig;
use claw_daemon::Daemon;

/// ClawAI daemon - firewall for AI agents.
#[derive(Parser, Debug)]
#[command(name = "claw-daemon", version, about)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "~/.config/clawai/config.toml")]
    config: String,

    /// Enable the terminal UI dashboard
    #[arg(long)]
    tui: bool,

    /// Run as a background daemon (placeholder for future daemonization)
    #[arg(long)]
    daemon: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Set up tracing: to file when TUI is enabled, to stderr otherwise.
    if args.tui {
        // When TUI is active, log to a file to avoid corrupting the terminal.
        let log_dir = dirs_fallback(".local/share/clawai");
        std::fs::create_dir_all(&log_dir).ok();
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join("daemon.log"))
            .context("opening daemon log file")?;
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_writer(std::sync::Mutex::new(log_file))
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    }

    // Resolve config path.
    let config_path = expand_tilde(&args.config);
    tracing::info!(config = %config_path.display(), tui = args.tui, "claw-daemon starting");

    // Load configuration.
    let config = ClawConfig::load(&config_path)
        .context("loading configuration")?;

    // Create and run daemon.
    let mut daemon = Daemon::new(config)?;
    daemon.set_tui_enabled(args.tui);
    daemon.run().await
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
