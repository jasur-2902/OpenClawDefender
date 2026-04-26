//! CLI client for interacting with the Rookbot daemon.

mod commands;
pub mod ipc_client;
pub mod output;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use output::Output;

/// Rookbot — a firewall for AI agents.
#[derive(Parser, Debug)]
#[command(
    name = "rookbot",
    version,
    about = "Rookbot — a firewall for AI agents"
)]
struct Cli {
    /// Path to the config file.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Output as JSON (machine-readable).
    #[arg(long, global = true)]
    json: bool,

    /// Minimal output, exit codes only.
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    /// Custom IPC socket path.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    /// Disable ANSI colors.
    #[arg(long, global = true)]
    no_color: bool,

    /// Verbose debug output.
    #[arg(long, short = 'v', global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show version and build info.
    Version,

    /// Initialize Rookbot configuration directory with defaults.
    Init,

    /// Wrap an MCP server so Rookbot intercepts its communication.
    Wrap {
        /// Name of the MCP server in the client config (e.g. "filesystem-server").
        server_name: Option<String>,

        /// MCP client to modify: auto, claude, cursor, vscode.
        #[arg(long, default_value = "auto")]
        client: String,

        /// Wrap all MCP servers across all detected clients.
        #[arg(long)]
        all: bool,
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

    /// Check Rookbot and MCP client status.
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

    /// Run diagnostic checks on your Rookbot installation.
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

    /// Manage the Rookbot daemon lifecycle.
    Daemon {
        #[command(subcommand)]
        action: commands::daemon::DaemonAction,
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

    /// Start the Rookbot MCP server (cooperative security endpoint).
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

    /// Manage threat intelligence feeds.
    Feed {
        #[command(subcommand)]
        action: FeedAction,
    },

    /// Manage community rule packs.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Manage the IoC (Indicator of Compromise) database.
    Ioc {
        #[command(subcommand)]
        action: IocAction,
    },

    /// Manage anonymous telemetry settings.
    Telemetry {
        #[command(subcommand)]
        action: TelemetryAction,
    },

    /// Manage network policy, DNS filter, and connection rules.
    Network {
        #[command(subcommand)]
        action: commands::network::NetworkAction2,
    },

    /// Check server reputation against the blocklist.
    Reputation {
        /// Server name or package name to check.
        server: String,
    },

    /// Run security scans and manage findings.
    Scan {
        #[command(subcommand)]
        action: commands::scan::ScanAction,
    },

    // ── New commands ────────────────────────────────────────────────
    /// Live event stream (like `tail -f` for security events).
    Watch(commands::watch::WatchArgs),

    /// Query and view historical security events.
    Events {
        #[command(subcommand)]
        action: commands::events::EventsAction,
    },

    /// Manage security alerts.
    Alerts {
        #[command(subcommand)]
        action: commands::alerts::AlertsAction,
    },

    /// Ask the AI security assistant a question.
    Ask(commands::ask::AskArgs),

    /// Run an AI-powered security investigation.
    Investigate {
        #[command(subcommand)]
        action: commands::investigate::InvestigateAction,
    },

    /// Proactive threat hunting.
    Hunt {
        #[command(subcommand)]
        action: commands::hunt::HuntAction,
    },

    /// Generate security reports.
    Report {
        #[command(subcommand)]
        action: commands::report::ReportAction,
    },

    /// Manage MCP servers (protect, block, trust).
    Server {
        #[command(subcommand)]
        action: commands::server::ServerAction,
    },

    /// Agent autonomy framework controls.
    Autonomy {
        #[command(subcommand)]
        action: commands::autonomy::AutonomyAction,
    },

    /// Manage automated response playbooks.
    Playbook {
        #[command(subcommand)]
        action: commands::playbook::PlaybookAction,
    },

    /// Manage the security knowledge base.
    Knowledge {
        #[command(subcommand)]
        action: commands::knowledge::KnowledgeAction,
    },

    /// File integrity monitoring.
    Fim {
        #[command(subcommand)]
        action: commands::fim::FimAction,
    },

    /// Data management: export, import, reset.
    Data {
        #[command(subcommand)]
        action: commands::data::DataAction,
    },

    /// Manage cloud API connection and budget.
    Cloud {
        #[command(subcommand)]
        action: commands::cloud::CloudAction,
    },

    /// Unified AI backend status.
    Ai {
        #[command(subcommand)]
        action: commands::ai::AiAction,
    },

    /// Threat posture management.
    Posture {
        #[command(subcommand)]
        action: commands::posture::PostureAction,
    },

    /// Compliance checking and benchmarks.
    Compliance {
        #[command(subcommand)]
        action: commands::compliance::ComplianceAction,
    },

    /// YARA rule scanning.
    Yara {
        #[command(subcommand)]
        action: commands::yara::YaraAction,
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
enum FeedAction {
    /// Show feed version, last update, next check time.
    Status,
    /// Force an immediate feed update check.
    Update,
    /// Verify feed signature and file integrity.
    Verify,
}

#[derive(Subcommand, Debug)]
enum RulesAction {
    /// List available and installed community rule packs.
    List,
    /// Install a community rule pack.
    Install {
        /// Pack ID to install.
        pack: String,
    },
    /// Uninstall a community rule pack.
    Uninstall {
        /// Pack ID to uninstall.
        pack: String,
    },
    /// Update all installed rule packs.
    Update,
}

#[derive(Subcommand, Debug)]
enum IocAction {
    /// Show IoC database statistics.
    Status,
    /// Add a local IoC indicator.
    Add {
        /// Indicator type (ip, domain, hash, url, etc.).
        ioc_type: String,
        /// Indicator value.
        value: String,
    },
    /// Test if a value matches any IoC in the database.
    Test {
        /// Value to test.
        value: String,
    },
}

#[derive(Subcommand, Debug)]
enum TelemetryAction {
    /// Show telemetry status (enabled/disabled, last report).
    Status,
    /// Preview what telemetry data would be sent.
    Preview,
    /// Opt in to anonymous telemetry.
    Enable,
    /// Opt out of anonymous telemetry.
    Disable,
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
    // `rookbot proxy -- ...`, any output to stdout that isn't JSON-RPC
    // will poison the MCP stream and break Claude Desktop.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Build the Output context from global flags.
    let out = Output::new(cli.json, cli.quiet, cli.no_color, cli.verbose);

    let config_path = cli.config.unwrap_or_else(default_config_path);
    let config = clawdefender_core::config::ClawConfig::load(&config_path)?;

    // Build the shared IPC client.
    let ipc = ipc_client::DaemonClient::from_config(&config, cli.socket.as_ref());

    match cli.command {
        Commands::Version => {
            out.data(
                &serde_json::json!({
                    "name": "rookbot",
                    "version": env!("CARGO_PKG_VERSION"),
                }),
                |_| {
                    println!("rookbot {}", env!("CARGO_PKG_VERSION"));
                    println!("  Target: {}", std::env::consts::ARCH);
                    println!("  OS: {}", std::env::consts::OS);
                },
            );
        }

        Commands::Init => commands::init::run(&config)?,

        Commands::Wrap {
            server_name,
            client,
            all,
        } => {
            if all {
                commands::wrap::run_all(&client)?;
            } else if let Some(name) = server_name {
                commands::wrap::run(&name, &client)?;
            } else {
                anyhow::bail!("Either provide a server name or use --all.\n\nUsage:\n  rookbot wrap <SERVER_NAME>\n  rookbot wrap --all");
            }
        }

        Commands::Unwrap {
            server_name,
            client,
        } => {
            commands::unwrap::run(&server_name, &client)?;
        }

        Commands::Proxy { server_command } => {
            commands::proxy::run(server_command, &config).await?;
        }

        Commands::Status => {
            commands::status::run(&config, &out, &ipc)?;
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
            commands::doctor::run(&config, &out)?;
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
                anyhow::bail!("Provide an event ID or use --list to see sessions.\nUsage: rookbot chat <event_id>");
            }
        }

        Commands::Daemon { action } => {
            commands::daemon::execute(action, &config)?;
        }

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

        Commands::Scan { action } => match action {
            commands::scan::ScanAction::Run {
                playbook,
                ai,
                signatures_only,
                quick,
                full,
                timeout,
                modules,
                json,
                html,
                output,
                threshold,
                baseline,
                server_command,
            } => {
                commands::scan::run_scan(
                    playbook,
                    ai,
                    signatures_only,
                    quick,
                    full,
                    server_command,
                    timeout,
                    modules,
                    json,
                    html,
                    output,
                    threshold,
                    baseline,
                )
                .await?;
            }
            commands::scan::ScanAction::Results {
                scan_id,
                severity,
                format,
            } => {
                commands::scan::show_results(scan_id, severity, format)?;
            }
            commands::scan::ScanAction::History { limit } => {
                commands::scan::show_history(limit)?;
            }
            commands::scan::ScanAction::Fix {
                finding_id,
                safe,
                all,
                dry_run,
            } => {
                commands::scan::apply_fix(finding_id, safe, all, dry_run)?;
            }
            commands::scan::ScanAction::Revert { remediation_id } => {
                commands::scan::revert_remediation(remediation_id)?;
            }
            commands::scan::ScanAction::Export {
                scan_id,
                format,
                output,
            } => {
                commands::scan::export_report(scan_id, format, output)?;
            }
            commands::scan::ScanAction::ListModules => {
                commands::scan::list_modules()?;
            }
        },

        Commands::Feed { action } => match action {
            FeedAction::Status => commands::threat_intel::feed_status(&config)?,
            FeedAction::Update => commands::threat_intel::feed_update(&config).await?,
            FeedAction::Verify => commands::threat_intel::feed_verify(&config)?,
        },

        Commands::Rules { action } => match action {
            RulesAction::List => commands::threat_intel::rules_list(&config)?,
            RulesAction::Install { pack } => commands::threat_intel::rules_install(&config, &pack)?,
            RulesAction::Uninstall { pack } => {
                commands::threat_intel::rules_uninstall(&config, &pack)?
            }
            RulesAction::Update => commands::threat_intel::rules_update(&config)?,
        },

        Commands::Ioc { action } => match action {
            IocAction::Status => commands::threat_intel::ioc_status(&config)?,
            IocAction::Add { ioc_type, value } => {
                commands::threat_intel::ioc_add(&config, &ioc_type, &value)?
            }
            IocAction::Test { value } => commands::threat_intel::ioc_test(&config, &value)?,
        },

        Commands::Telemetry { action } => match action {
            TelemetryAction::Status => commands::threat_intel::telemetry_status(&config)?,
            TelemetryAction::Preview => commands::threat_intel::telemetry_preview(&config)?,
            TelemetryAction::Enable => commands::threat_intel::telemetry_enable(&config)?,
            TelemetryAction::Disable => commands::threat_intel::telemetry_disable(&config)?,
        },

        Commands::Network { action } => {
            commands::network::run(&action, &config)?;
        }

        Commands::Reputation { server } => {
            commands::threat_intel::check_reputation(&config, &server)?
        }

        // ── New commands ────────────────────────────────────────────
        Commands::Watch(args) => {
            commands::watch::run(&config, &args)?;
        }

        Commands::Events { action } => {
            commands::events::run(&config, &action)?;
        }

        Commands::Alerts { action } => {
            commands::alerts::run(&config, &action)?;
        }

        Commands::Ask(args) => {
            if args.chat {
                commands::ask::run_interactive_chat().await?;
            } else if let Some(ref question) = args.question {
                commands::ask::ask_question(question).await?;
            } else {
                anyhow::bail!(
                    "Provide a question or use --chat for interactive mode.\n\
                     Usage: rookbot ask \"What alerts are active?\"\n\
                     Usage: rookbot ask --chat"
                );
            }
        }

        Commands::Investigate { action } => match action {
            commands::investigate::InvestigateAction::Run { target, depth } => {
                commands::investigate::run_investigation(&target, &depth).await?;
            }
            commands::investigate::InvestigateAction::List { limit, verdict } => {
                commands::investigate::list_investigations(limit, verdict)?;
            }
            commands::investigate::InvestigateAction::Show { investigation_id } => {
                commands::investigate::show_investigation(&investigation_id)?;
            }
            commands::investigate::InvestigateAction::Resume { investigation_id } => {
                commands::investigate::resume_investigation(&investigation_id).await?;
            }
        },

        Commands::Hunt { action } => match action {
            commands::hunt::HuntAction::Run {
                r#type,
                server,
                pattern,
                period,
            } => {
                commands::hunt::run_hunt(&r#type, server, pattern, period).await?;
            }
            commands::hunt::HuntAction::List { limit } => {
                commands::hunt::list_hunts(limit)?;
            }
            commands::hunt::HuntAction::Show { hunt_id } => {
                commands::hunt::show_hunt(&hunt_id)?;
            }
        },

        Commands::Report { action } => match action {
            commands::report::ReportAction::Daily { date, output } => {
                commands::report::generate_daily_report(date, output)?;
            }
            commands::report::ReportAction::Weekly { date, output } => {
                commands::report::generate_weekly_report(date, output)?;
            }
            commands::report::ReportAction::Incident {
                investigation_id,
                output,
            } => {
                commands::report::generate_incident_report(&investigation_id, output)?;
            }
            commands::report::ReportAction::Compliance { framework, output } => {
                commands::report::generate_compliance_report(&framework, output)?;
            }
            commands::report::ReportAction::List { r#type, limit } => {
                commands::report::list_reports(r#type, limit)?;
            }
            commands::report::ReportAction::Show { report_id } => {
                commands::report::show_report(&report_id)?;
            }
        },

        Commands::Server { action } => {
            commands::server::run(&action, &config)?;
        }

        Commands::Autonomy { action } => {
            commands::autonomy::run(&action, &config)?;
        }

        Commands::Playbook { action } => {
            commands::playbook::run(&action, &config)?;
        }

        Commands::Knowledge { action } => {
            commands::knowledge::run(&action)?;
        }

        Commands::Fim { action } => {
            commands::fim::run(&action)?;
        }

        Commands::Data { action } => {
            commands::data::run(&action)?;
        }

        Commands::Cloud { action } => {
            commands::cloud::run(&action)?;
        }

        Commands::Ai { action } => {
            commands::ai::run(&action)?;
        }

        Commands::Posture { action } => {
            commands::posture::run(&action)?;
        }

        Commands::Compliance { action } => match action {
            commands::compliance::ComplianceAction::Check { framework } => {
                commands::compliance::check(framework)?;
            }
            commands::compliance::ComplianceAction::Report { output } => {
                commands::compliance::report(output)?;
            }
            commands::compliance::ComplianceAction::Score => {
                commands::compliance::score()?;
            }
        },

        Commands::Yara { action } => match action {
            commands::yara::YaraAction::Scan { path, recursive } => {
                commands::yara::scan(path, recursive)?;
            }
            commands::yara::YaraAction::Rules { count, list } => {
                commands::yara::show_rules(count, list)?;
            }
        },

        Commands::Config { action } => {
            let keystore = clawdefender_swarm::keychain::default_keystore();
            match action {
                ConfigAction::SetApiKey { provider, key } => {
                    commands::config::set_api_key(keystore.as_ref(), &provider, key.as_deref())?;
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
