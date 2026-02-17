//! CLI client for interacting with the ClawDefender daemon.

mod commands;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// ClawDefender — a firewall for AI agents.
#[derive(Parser, Debug)]
#[command(name = "clawdefender", version, about)]
struct Cli {
    /// Path to the config file.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize ClawDefender configuration directory with defaults.
    Init,

    /// Wrap an MCP server so ClawDefender intercepts its communication.
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

    /// Check ClawDefender and MCP client status.
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

        /// Filter by source (e.g. "agent-guard").
        #[arg(long)]
        source: Option<String>,

        /// Filter by agent name.
        #[arg(long)]
        agent: Option<String>,

        /// Show aggregate statistics.
        #[arg(long)]
        stats: bool,

        /// Number of log entries to show.
        #[arg(short, default_value = "50")]
        n: usize,
    },

    /// Run diagnostic checks on your ClawDefender installation.
    Doctor,

    /// Manage local SLM models.
    Model {
        #[command(subcommand)]
        action: ModelAction,
    },

    /// Manage API keys and cloud LLM configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// View cloud swarm token usage, costs, and budget status.
    Usage {
        /// Show the last 50 individual API calls.
        #[arg(long)]
        detail: bool,

        /// Clear all usage data (with confirmation).
        #[arg(long)]
        reset: bool,
    },

    /// Chat about a flagged event with the AI security analyst.
    Chat {
        /// Event ID to discuss, or omit with --list to see sessions.
        event_id: Option<String>,

        /// List recent chat sessions.
        #[arg(long)]
        list: bool,
    },

    /// Manage the ClawDefender daemon lifecycle.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Manage the behavioral baseline engine.
    Behavioral {
        #[command(subcommand)]
        action: BehavioralAction,
    },

    /// Manage behavioral profiles for MCP servers.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },

    /// Certify an MCP server for Claw Compliant compliance.
    Certify {
        /// Server command and arguments (everything after --).
        #[arg(last = true)]
        server_command: Vec<String>,

        /// Output JSON format.
        #[arg(long)]
        json: bool,

        /// Output file path.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Start the ClawDefender MCP server (cooperative security endpoint).
    Serve {
        /// Use stdio transport (default).
        #[arg(long, default_value = "true")]
        stdio: bool,

        /// HTTP port to listen on (0 to disable HTTP).
        #[arg(long, default_value = "3201")]
        http_port: u16,
    },

    /// Manage agent guards.
    Guard {
        #[command(subcommand)]
        action: GuardAction,
    },

    /// Run a security scan against an MCP server.
    Scan {
        /// Server command and arguments (everything after --).
        #[arg(last = true)]
        server_command: Vec<String>,

        /// Total scan timeout in seconds.
        #[arg(long, default_value = "1800")]
        timeout: Option<u64>,

        /// Comma-separated list of module names to run.
        #[arg(long)]
        modules: Option<String>,

        /// Output results as JSON.
        #[arg(long)]
        json: bool,

        /// Write an HTML report to this file.
        #[arg(long)]
        html: Option<PathBuf>,

        /// Write the report to this file.
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Minimum severity threshold for exit codes: critical, high, medium, low, info.
        #[arg(long)]
        threshold: Option<String>,

        /// Path to a baseline report JSON for delta comparison.
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// List available scan modules and exit.
        #[arg(long)]
        list_modules: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ModelAction {
    /// Download a model from the registry.
    Download {
        /// Model name to download (e.g. "tinyllama-1.1b").
        #[arg(default_value = "tinyllama-1.1b")]
        name: String,
    },
    /// List available and installed models.
    List,
    /// Set the active model by name or path.
    Set {
        /// Model filename or path to a GGUF file.
        name_or_path: String,
    },
    /// Disable the SLM subsystem.
    Off,
    /// Enable the SLM subsystem.
    On,
    /// Show SLM inference statistics.
    Stats,
}

#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Store an API key for a provider (reads from stdin if not given).
    SetApiKey {
        /// Provider name: anthropic, openai, or a custom base URL.
        #[arg(long, default_value = "auto")]
        provider: String,

        /// The API key (if omitted, reads from stdin interactively).
        #[arg(long)]
        key: Option<String>,
    },
    /// Show whether an API key is configured for a provider.
    GetApiKey {
        /// Provider name: anthropic, openai.
        provider: String,
    },
    /// Remove a stored API key.
    RemoveApiKey {
        /// Provider name: anthropic, openai.
        provider: String,
    },
    /// List all providers and their configuration status.
    ListApiKeys,
}

#[derive(Subcommand, Debug)]
enum DaemonAction {
    /// Start the daemon as a background process.
    Start,
    /// Stop the running daemon.
    Stop,
    /// Show daemon status and subsystem information.
    Status,
    /// Restart the daemon (stop then start).
    Restart,
}

#[derive(Subcommand, Debug)]
enum BehavioralAction {
    /// Show behavioral engine status and configuration.
    Status,
    /// Run calibration analysis against historical audit data.
    Calibrate,
    /// Show auto-block statistics from the audit log.
    Stats,
}

#[derive(Subcommand, Debug)]
enum ProfileAction {
    /// List all behavioral profiles.
    List,
    /// Show full details of a server profile.
    Show {
        /// Server name to show profile for.
        server: String,
    },
    /// Reset a server profile back to learning mode.
    Reset {
        /// Server name to reset.
        server: String,
    },
    /// Export a server profile as JSON.
    Export {
        /// Server name to export.
        server: String,
        /// Output file path.
        file: std::path::PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum GuardAction {
    /// List active agent guards.
    List,
    /// Show full details of a specific guard.
    Show {
        /// Guard ID to show.
        guard_id: String,
    },
    /// Forcefully remove a guard.
    Kill {
        /// Guard ID to remove.
        guard_id: String,
    },
    /// Test a permissions config file and show generated policy.
    Test {
        /// Path to a permissions config file (TOML or JSON).
        file: String,
    },
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

    /// List available policy templates.
    TemplateList,

    /// Apply a policy template (copies it to the config policy path).
    TemplateApply {
        /// Template name (e.g. "development", "strict", "audit-only", "data-science").
        name: String,
    },

    /// Suggest policy rules based on audit log patterns.
    Suggest,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // CRITICAL: All logging MUST go to stderr. When the CLI runs as
    // `clawdefender proxy -- ...`, any output to stdout that isn't JSON-RPC
    // will poison the MCP stream and break Claude Desktop.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(default_config_path);
    let config = clawdefender_core::config::ClawConfig::load(&config_path)?;

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
            PolicyAction::TemplateList => {
                commands::policy::template_list()?;
            }
            PolicyAction::TemplateApply { name } => {
                commands::policy::template_apply(&name, &config.policy_path)?;
            }
            PolicyAction::Suggest => {
                commands::policy::suggest(&config)?;
            }
        },

        Commands::Log {
            blocked,
            server,
            source,
            agent: _agent,
            stats,
            n,
        } => {
            commands::log::run(&config, blocked, server.or(source), stats, n)?;
        }

        Commands::Doctor => {
            commands::doctor::run(&config)?;
        }

        Commands::Model { action } => {
            commands::model::run(&action, &config)?;
        }

        Commands::Usage { detail, reset } => {
            commands::usage::run(detail, reset)?;
        }

        Commands::Chat { event_id, list } => {
            if list {
                commands::chat::list_sessions()?;
            } else if let Some(id) = event_id {
                commands::chat::start_chat(&id).await?;
            } else {
                anyhow::bail!("Provide an event ID or use --list to see sessions.\nUsage: clawdefender chat <event_id>");
            }
        }

        Commands::Daemon { action } => match action {
            DaemonAction::Start => commands::daemon::start(&config)?,
            DaemonAction::Stop => commands::daemon::stop(&config)?,
            DaemonAction::Status => commands::daemon::status(&config)?,
            DaemonAction::Restart => commands::daemon::restart(&config)?,
        },

        Commands::Behavioral { action } => match action {
            BehavioralAction::Status => commands::behavioral::status(&config)?,
            BehavioralAction::Calibrate => commands::behavioral::calibrate(&config)?,
            BehavioralAction::Stats => commands::behavioral::stats(&config)?,
        },

        Commands::Profile { action } => match action {
            ProfileAction::List => commands::profile_cmd::list(&config)?,
            ProfileAction::Show { server } => commands::profile_cmd::show(&server)?,
            ProfileAction::Reset { server } => commands::profile_cmd::reset(&server)?,
            ProfileAction::Export { server, file } => {
                commands::profile_cmd::export(&server, &file)?
            }
        },

        Commands::Certify {
            server_command,
            json,
            output,
        } => {
            let certify_config = clawdefender_certify::CertifyConfig {
                server_command,
                json,
                output,
                server_dir: None,
            };
            clawdefender_certify::run_certification(certify_config).await?;
        }

        Commands::Serve { stdio, http_port } => {
            commands::serve::run(&config, stdio, http_port).await?;
        }

        Commands::Guard { action } => match action {
            GuardAction::List => commands::guard::list(&config)?,
            GuardAction::Show { guard_id } => commands::guard::show(&config, &guard_id)?,
            GuardAction::Kill { guard_id } => commands::guard::kill(&config, &guard_id)?,
            GuardAction::Test { file } => commands::guard::test(&config, &file)?,
        },

        Commands::Scan {
            server_command,
            timeout,
            modules,
            json,
            html,
            output,
            threshold,
            baseline,
            list_modules,
        } => {
            commands::scan::run(
                server_command,
                timeout,
                modules,
                json,
                html,
                output,
                threshold,
                baseline,
                list_modules,
            )
            .await?;
        }

        Commands::Config { action } => {
            let keystore = clawdefender_swarm::keychain::default_keystore();
            match action {
                ConfigAction::SetApiKey { provider, key } => {
                    commands::config::set_api_key(
                        keystore.as_ref(),
                        &provider,
                        key.as_deref(),
                    )?;
                }
                ConfigAction::GetApiKey { provider } => {
                    commands::config::get_api_key(keystore.as_ref(), &provider)?;
                }
                ConfigAction::RemoveApiKey { provider } => {
                    commands::config::remove_api_key(keystore.as_ref(), &provider)?;
                }
                ConfigAction::ListApiKeys => {
                    commands::config::list_api_keys(keystore.as_ref())?;
                }
            }
        }
    }

    Ok(())
}

/// Return the default config file path.
fn default_config_path() -> PathBuf {
    expand_tilde("~/.config/clawdefender/config.toml")
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
