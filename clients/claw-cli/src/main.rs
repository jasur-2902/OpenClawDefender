//! CLI client for interacting with the ClawAI daemon.

mod commands;

use clap::Parser;

/// ClawAI — a firewall for AI agents.
#[derive(Parser, Debug)]
#[command(name = "clawai", version, about)]
struct Cli {
    /// Path to the config file.
    #[arg(long, default_value = "~/.config/clawai/config.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Initialize ClawAI configuration directory with defaults.
    Init,

    /// Wrap an MCP server with the ClawAI proxy.
    Wrap {
        /// MCP server command and arguments.
        #[arg(trailing_var_arg = true, required = true)]
        server_cmd: Vec<String>,

        /// Path to the policy TOML file (overrides config).
        #[arg(long)]
        policy: Option<String>,
    },

    /// Manage policy rules.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// View the audit log.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Check ClawAI daemon status.
    Status,
}

#[derive(clap::Subcommand, Debug)]
enum PolicyAction {
    /// List loaded policy rules.
    List {
        /// Path to the policy TOML file (overrides config).
        #[arg(long)]
        policy: Option<String>,
    },

    /// Test a JSON-RPC fixture against the policy.
    Test {
        /// Path to a JSON file containing a JSON-RPC message fixture.
        fixture: String,

        /// Path to the policy TOML file (overrides config).
        #[arg(long)]
        policy: Option<String>,
    },
}

#[derive(clap::Subcommand, Debug)]
enum AuditAction {
    /// Show recent audit log entries.
    Show {
        /// Maximum number of records to display.
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,

        /// Filter by source (e.g. "mcp-proxy", "eslogger").
        #[arg(long)]
        source: Option<String>,

        /// Filter by action (e.g. "allow", "block", "prompt").
        #[arg(long)]
        action: Option<String>,

        /// Path to audit log file (overrides config).
        #[arg(long)]
        log_path: Option<String>,
    },

    /// Show aggregate audit statistics.
    Stats {
        /// Path to audit log file (overrides config).
        #[arg(long)]
        log_path: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config_path = expand_tilde(&cli.config);
    let config = claw_core::config::ClawConfig::load(&config_path)?;

    match cli.command {
        Commands::Init => commands::init::run(&config)?,

        Commands::Wrap { server_cmd, policy } => {
            let policy_path = policy
                .map(|p| expand_tilde(&p))
                .unwrap_or_else(|| config.policy_path.clone());
            let (cmd, args) = server_cmd
                .split_first()
                .expect("server command is required");
            claw_mcp_proxy::run_stdio_proxy(cmd.clone(), args.to_vec(), &policy_path).await?;
        }

        Commands::Policy { action } => match action {
            PolicyAction::List { policy } => {
                let policy_path = policy
                    .map(|p| expand_tilde(&p))
                    .unwrap_or_else(|| config.policy_path.clone());
                commands::policy::list(&policy_path)?;
            }
            PolicyAction::Test { fixture, policy } => {
                let policy_path = policy
                    .map(|p| expand_tilde(&p))
                    .unwrap_or_else(|| config.policy_path.clone());
                commands::policy::test_fixture(&expand_tilde(&fixture), &policy_path)?;
            }
        },

        Commands::Audit { action } => match action {
            AuditAction::Show {
                limit,
                source,
                action,
                log_path,
            } => {
                let log = log_path
                    .map(|p| expand_tilde(&p))
                    .unwrap_or_else(|| config.audit_log_path.clone());
                commands::audit::show(&log, limit, source, action)?;
            }
            AuditAction::Stats { log_path } => {
                let log = log_path
                    .map(|p| expand_tilde(&p))
                    .unwrap_or_else(|| config.audit_log_path.clone());
                commands::audit::stats(&log)?;
            }
        },

        Commands::Status => {
            commands::status::run(&config)?;
        }
    }

    Ok(())
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(rest);
        }
    }
    std::path::PathBuf::from(path)
}
