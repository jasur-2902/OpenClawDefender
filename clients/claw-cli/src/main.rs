//! CLI client for interacting with the ClawAI daemon.

mod commands;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// ClawAI — a firewall for AI agents.
#[derive(Parser, Debug)]
#[command(name = "clawai", version, about)]
struct Cli {
    /// Path to the config file.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize ClawAI configuration directory with defaults.
    Init,

    /// Wrap an MCP server so ClawAI intercepts its communication.
    Wrap {
        /// Name of the MCP server in the client config (e.g. "filesystem-server").
        server_name: String,

        /// MCP client to modify: auto, claude, cursor, vscode.
        #[arg(long, default_value = "auto")]
        client: String,
    },

    /// Unwrap an MCP server, restoring its original configuration.
    Unwrap {
        /// Name of the MCP server in the client config.
        server_name: String,

        /// MCP client to modify: auto, claude, cursor, vscode.
        #[arg(long, default_value = "auto")]
        client: String,
    },

    /// Run as a stdio proxy for an MCP server (called by wrapped configs).
    Proxy {
        /// Server command and arguments (everything after --).
        #[arg(last = true)]
        server_command: Vec<String>,
    },

    /// Check ClawAI and MCP client status.
    Status,

    /// Manage policy rules.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// View the audit log.
    Log {
        /// Show only blocked events.
        #[arg(long)]
        blocked: bool,

        /// Filter by server name.
        #[arg(long)]
        server: Option<String>,

        /// Show aggregate statistics.
        #[arg(long)]
        stats: bool,

        /// Number of log entries to show.
        #[arg(short, default_value = "50")]
        n: usize,
    },

    /// Run diagnostic checks on your ClawAI installation.
    Doctor,
}

#[derive(Subcommand, Debug)]
enum PolicyAction {
    /// List loaded policy rules.
    List,

    /// Add a new policy rule.
    Add,

    /// Test a JSON-RPC fixture against the policy.
    Test {
        /// Path to a JSON file containing a JSON-RPC message fixture.
        fixture: String,
    },

    /// Reload policy rules (signal running daemon).
    Reload,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(default_config_path);
    let config = claw_core::config::ClawConfig::load(&config_path)?;

    match cli.command {
        Commands::Init => commands::init::run(&config)?,

        Commands::Wrap { server_name, client } => {
            commands::wrap::run(&server_name, &client)?;
        }

        Commands::Unwrap { server_name, client } => {
            commands::unwrap::run(&server_name, &client)?;
        }

        Commands::Proxy { server_command } => {
            commands::proxy::run(server_command, &config).await?;
        }

        Commands::Status => {
            commands::status::run(&config)?;
        }

        Commands::Policy { action } => match action {
            PolicyAction::List => {
                commands::policy::list(&config.policy_path)?;
            }
            PolicyAction::Add => {
                commands::policy::add(&config.policy_path)?;
            }
            PolicyAction::Test { fixture } => {
                let fixture_path = expand_tilde(&fixture);
                commands::policy::test_fixture(&fixture_path, &config.policy_path)?;
            }
            PolicyAction::Reload => {
                commands::policy::reload(&config)?;
            }
        },

        Commands::Log {
            blocked,
            server,
            stats,
            n,
        } => {
            commands::log::run(&config, blocked, server, stats, n)?;
        }

        Commands::Doctor => {
            commands::doctor::run(&config)?;
        }
    }

    Ok(())
}

/// Return the default config file path.
fn default_config_path() -> PathBuf {
    expand_tilde("~/.config/clawai/config.toml")
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
