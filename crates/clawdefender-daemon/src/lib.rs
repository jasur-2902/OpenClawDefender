//! ClawDefender daemon orchestration logic.
//!
//! The [`Daemon`] struct ties together the MCP proxy, policy engine,
//! audit logger, TUI, and signal handling into a single async process.

pub mod ipc;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use clawdefender_core::audit::logger::FileAuditLogger;
use clawdefender_core::audit::{AuditLogger, AuditRecord};
use clawdefender_core::config::settings::ClawConfig;
use clawdefender_core::policy::engine::DefaultPolicyEngine;
use clawdefender_core::policy::PolicyEngine;
use clawdefender_mcp_proxy::{ProxyConfig, StdioProxy, UiBridge};
use clawdefender_slm::context::ContextTracker;
use clawdefender_slm::engine::SlmConfig as SlmEngineConfig;
use clawdefender_slm::noise_filter::NoiseFilter;
use clawdefender_slm::SlmService;
use clawdefender_swarm::chat::ChatManager;
use clawdefender_swarm::chat_server::ChatServer;
use clawdefender_swarm::commander::Commander;
use clawdefender_swarm::cost::{BudgetConfig, CostTracker, PricingTable};
use clawdefender_swarm::keychain::{self, KeyStore, Provider};
use clawdefender_swarm::llm_client::{HttpLlmClient, LlmClient};
use clawdefender_tui::{EventRecord, PendingPrompt};

/// The main daemon that orchestrates all ClawDefender subsystems.
pub struct Daemon {
    config: ClawConfig,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
    audit_logger: Arc<FileAuditLogger>,
    enable_tui: bool,
}

impl Daemon {
    /// Create a new daemon from the given configuration.
    pub fn new(config: ClawConfig, enable_tui: bool) -> Result<Self> {
        // Load policy engine -- use empty engine if policy file doesn't exist yet.
        let policy_engine = if config.policy_path.exists() {
            DefaultPolicyEngine::load(&config.policy_path).context("loading policy engine")?
        } else {
            info!(
                path = %config.policy_path.display(),
                "policy file not found, using empty policy"
            );
            DefaultPolicyEngine::empty()
        };

        // Create audit logger.
        let audit_logger = FileAuditLogger::new(
            config.audit_log_path.clone(),
            config.log_rotation.clone(),
        )
        .context("creating audit logger")?;

        Ok(Self {
            config,
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            audit_logger: Arc::new(audit_logger),
            enable_tui,
        })
    }

    /// Main entry point for `clawdefender proxy -- <command> [args...]`.
    ///
    /// Spawns the MCP proxy, audit writer, TUI (or headless), and signal
    /// handlers, then runs until the proxy finishes or a signal is received.
    pub async fn run_proxy(self, command: String, args: Vec<String>) -> Result<()> {
        // Write PID file.
        let pid_path = pid_file_path();
        write_pid_file(&pid_path)?;

        // --- Channels ---
        let (_prompt_tx, prompt_rx) = mpsc::channel::<PendingPrompt>(64);
        let (_event_tx, event_rx) = mpsc::channel::<EventRecord>(256);
        let (audit_tx, mut audit_rx) = mpsc::channel::<AuditRecord>(1024);

        // --- UiBridge (connects proxy prompts to TUI) ---
        // The UiBridge uses (UiRequest, oneshot::Sender<UiResponse>) internally.
        // We create a channel that the TUI will convert from.
        let (ui_req_tx, _ui_req_rx) =
            mpsc::channel::<(
                clawdefender_core::ipc::protocol::UiRequest,
                tokio::sync::oneshot::Sender<clawdefender_core::ipc::protocol::UiResponse>,
            )>(64);
        let ui_bridge = Arc::new(UiBridge::new(ui_req_tx));

        // --- SLM service (advisory only, graceful failure → disabled mode) ---
        let slm_engine_config = SlmEngineConfig {
            model_path: self
                .config
                .slm
                .model_path
                .clone()
                .unwrap_or_default(),
            context_size: self.config.slm.context_size,
            max_output_tokens: self.config.slm.max_output_tokens,
            temperature: self.config.slm.temperature,
            use_gpu: self.config.slm.use_gpu,
            threads: self.config.slm.threads.unwrap_or(4),
            ..SlmEngineConfig::default()
        };
        let slm_service = Arc::new(SlmService::new(
            slm_engine_config,
            self.config.slm.enabled,
        ));
        if slm_service.is_enabled() {
            info!("SLM service initialized and enabled");
        } else {
            info!("SLM service disabled (no model or disabled in config)");
        }

        let noise_filter = Arc::new(tokio::sync::Mutex::new(NoiseFilter::new()));
        let context_tracker = Arc::new(tokio::sync::Mutex::new(ContextTracker::new()));

        // --- Swarm (cloud analysis) initialization ---
        let swarm_commander: Option<Arc<Commander>> = if self.config.swarm.enabled {
            let keystore: Arc<dyn KeyStore> = Arc::from(keychain::default_keystore());
            let has_api_key = keystore.get(&Provider::Anthropic).is_ok()
                || keystore.get(&Provider::OpenAi).is_ok();

            if has_api_key {
                let llm_client: Arc<dyn LlmClient> = Arc::new(HttpLlmClient::new(keystore));

                let data_dir = if let Some(home) = std::env::var_os("HOME") {
                    PathBuf::from(home).join(".local/share/clawdefender")
                } else {
                    PathBuf::from("/tmp/clawdefender")
                };
                std::fs::create_dir_all(&data_dir).ok();
                let cost_db = data_dir.join("swarm_usage.db");

                let budget = BudgetConfig {
                    daily_limit_usd: self.config.swarm.daily_budget_usd,
                    monthly_limit_usd: self.config.swarm.monthly_budget_usd,
                };
                let cost_tracker = match CostTracker::new(&cost_db, PricingTable::default(), budget)
                {
                    Ok(t) => Some(Arc::new(std::sync::Mutex::new(t))),
                    Err(e) => {
                        warn!(error = %e, "Failed to initialize swarm cost tracker");
                        None
                    }
                };

                let commander = Commander::new(llm_client, cost_tracker);
                info!("Cloud swarm analysis enabled");
                Some(Arc::new(commander))
            } else {
                info!("Cloud analysis disabled (no API key). Run `clawdefender config set api-key` to enable.");
                None
            }
        } else {
            info!("Cloud swarm analysis disabled in config");
            None
        };

        // --- Chat server (only if swarm is active) ---
        let chat_server_handle = if let Some(ref commander) = swarm_commander {
            let data_dir = if let Some(home) = std::env::var_os("HOME") {
                PathBuf::from(home).join(".local/share/clawdefender")
            } else {
                PathBuf::from("/tmp/clawdefender")
            };
            let chat_db = data_dir.join("chat.db");
            let llm_client = commander.llm_client();
            let cost_tracker = commander.cost_tracker();

            match ChatManager::new(&chat_db, llm_client, cost_tracker) {
                Ok(chat_manager) => {
                    let chat_manager = Arc::new(chat_manager);
                    let chat_port = self.config.swarm.chat_port;
                    let server = ChatServer::new(Arc::clone(&chat_manager), chat_port);
                    let handle = tokio::spawn(async move {
                        if let Err(e) = server.start().await {
                            warn!(error = %e, "Chat server exited");
                        }
                    });
                    info!(port = chat_port, "Chat server started");
                    Some(handle)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to initialize chat manager");
                    None
                }
            }
        } else {
            None
        };

        // --- Audit writer task ---
        let audit_logger = Arc::clone(&self.audit_logger);
        let audit_writer_handle = tokio::spawn(async move {
            while let Some(record) = audit_rx.recv().await {
                if let Err(e) = audit_logger.log(&record) {
                    error!(error = %e, "failed to write audit record");
                }
            }
            info!("audit writer task finished");
        });

        // --- TUI or headless ---
        let tui_handle = if self.enable_tui && std::io::stdout().is_terminal() {
            info!("starting TUI");
            Some(tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();
                if let Err(e) = rt.block_on(clawdefender_tui::run(prompt_rx, event_rx)) {
                    error!(error = %e, "TUI exited with error");
                }
            }))
        } else {
            info!("no TTY or TUI disabled, running headless");
            Some(tokio::spawn(async move {
                if let Err(e) = clawdefender_tui::run_headless(prompt_rx).await {
                    error!(error = %e, "headless prompt handler exited with error");
                }
                // Drain events so the channel doesn't back-pressure.
                drop(event_rx);
            }))
        };

        // --- Proxy config ---
        let proxy_config = ProxyConfig {
            server_command: Some(command.clone()),
            server_args: args.clone(),
            ..Default::default()
        };

        // Get a snapshot of the policy engine for the proxy.
        let policy_snapshot = {
            // We need to pass a DefaultPolicyEngine by value. Since the proxy
            // takes ownership, we load a fresh copy.
            if self.config.policy_path.exists() {
                DefaultPolicyEngine::load(&self.config.policy_path)
                    .unwrap_or_else(|_| DefaultPolicyEngine::empty())
            } else {
                DefaultPolicyEngine::empty()
            }
        };

        // --- Create StdioProxy ---
        let slm_ctx = clawdefender_mcp_proxy::SlmContext {
            slm_service: Arc::clone(&slm_service),
            noise_filter: Arc::clone(&noise_filter),
            context_tracker: Arc::clone(&context_tracker),
        };
        let mut proxy = StdioProxy::with_full_config(
            proxy_config,
            policy_snapshot,
            audit_tx.clone(),
            Some(ui_bridge),
        )
        .with_slm_context(slm_ctx);

        if let Some(ref commander) = swarm_commander {
            proxy = proxy.with_swarm_context(clawdefender_mcp_proxy::SwarmContext {
                commander: Arc::clone(commander),
                escalation_threshold: self.config.swarm.escalation_threshold.clone(),
            });
        }

        let metrics = Arc::clone(proxy.metrics());

        // --- Policy hot-reload via notify ---
        let policy_path = self.config.policy_path.clone();
        let policy_engine_for_reload = Arc::clone(&self.policy_engine);
        let _reload_handle = if policy_path.exists() {
            Some(spawn_policy_watcher(policy_path, policy_engine_for_reload))
        } else {
            None
        };

        // --- IPC server ---
        let socket_path = self.config.daemon_socket_path.clone();
        let metrics_for_ipc = Arc::clone(&metrics);
        let policy_for_ipc = Arc::clone(&self.policy_engine);
        let ipc_handle = tokio::spawn(async move {
            if let Err(e) =
                ipc::run_ipc_server(socket_path, metrics_for_ipc, policy_for_ipc).await
            {
                warn!(error = %e, "IPC server exited");
            }
        });

        // --- Signal handlers ---
        #[cfg(unix)]
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        #[cfg(unix)]
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

        // --- Run proxy with graceful shutdown ---
        info!(cmd = %command, args = ?args, "starting MCP proxy");

        #[cfg(unix)]
        {
            tokio::select! {
                result = proxy.run() => {
                    match &result {
                        Ok(()) => info!("proxy finished normally"),
                        Err(e) => error!(error = %e, "proxy exited with error"),
                    }
                    result?;
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received, shutting down");
                }
                _ = sigint.recv() => {
                    info!("SIGINT received, shutting down");
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                result = proxy.run() => {
                    match &result {
                        Ok(()) => info!("proxy finished normally"),
                        Err(e) => error!(error = %e, "proxy exited with error"),
                    }
                    result?;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl-C received, shutting down");
                }
            }
        }

        // --- Cleanup ---
        // Drop audit sender to signal the writer to finish.
        drop(audit_tx);
        let _ = audit_writer_handle.await;

        // Shut down audit logger (flushes + session-end record).
        self.audit_logger.shutdown();

        // Abort IPC server.
        ipc_handle.abort();

        // Abort chat server.
        if let Some(handle) = chat_server_handle {
            handle.abort();
            info!("chat server stopped");
        }

        // Wait for TUI.
        if let Some(handle) = tui_handle {
            let _ = handle.await;
        }

        // Remove PID file.
        remove_pid_file(&pid_path);

        info!("daemon shut down");
        Ok(())
    }
}

/// Spawn a file watcher for policy hot-reload.
fn spawn_policy_watcher(
    policy_path: PathBuf,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use notify::{Event, EventKind, RecursiveMode, Watcher};

        let (tx, mut rx) = mpsc::channel::<()>(4);

        let watch_path = policy_path.clone();
        let mut watcher = match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_)
                ) {
                    let _ = tx.try_send(());
                }
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "failed to create file watcher for policy reload");
                return;
            }
        };

        // Watch the parent directory (file-level watching can miss renames).
        let watch_dir = watch_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            warn!(error = %e, "failed to watch policy directory");
            return;
        }

        info!(path = %policy_path.display(), "watching policy file for changes");

        while rx.recv().await.is_some() {
            // Debounce: drain any extra notifications.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            while rx.try_recv().is_ok() {}

            let mut engine = policy_engine.write().await;
            match engine.reload() {
                Ok(()) => {
                    info!("policy reloaded successfully");
                }
                Err(e) => {
                    warn!(error = %e, "failed to reload policy");
                }
            }
        }
    })
}

/// Path for the daemon PID file.
fn pid_file_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share/clawdefender/clawdefender.pid")
    } else {
        PathBuf::from("/tmp/clawdefender.pid")
    }
}

/// Write the current PID to the PID file.
fn write_pid_file(path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let pid = std::process::id();
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("writing PID file: {}", path.display()))?;
    info!(pid = pid, path = %path.display(), "wrote PID file");
    Ok(())
}

/// Remove the PID file on clean shutdown.
fn remove_pid_file(path: &PathBuf) {
    if path.exists() {
        if let Err(e) = std::fs::remove_file(path) {
            warn!(error = %e, "failed to remove PID file");
        } else {
            info!(path = %path.display(), "removed PID file");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(dir: &TempDir) -> ClawConfig {
        let mut config = ClawConfig::default();
        config.audit_log_path = dir.path().join("audit.jsonl");
        config.daemon_socket_path = dir.path().join("test.sock");
        config.eslogger.enabled = false;
        config
    }

    #[test]
    fn daemon_new_with_default_config() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let daemon = Daemon::new(config, false).unwrap();
        assert!(!daemon.enable_tui);
    }

    #[test]
    fn pid_file_creation_and_cleanup() {
        let dir = TempDir::new().unwrap();
        let pid_path = dir.path().join("test.pid");
        write_pid_file(&pid_path).unwrap();
        assert!(pid_path.exists());
        let contents = std::fs::read_to_string(&pid_path).unwrap();
        assert_eq!(contents, std::process::id().to_string());
        remove_pid_file(&pid_path);
        assert!(!pid_path.exists());
    }

    #[tokio::test]
    async fn audit_channel_writer_processes_records() {
        let dir = TempDir::new().unwrap();
        let logger = Arc::new(
            FileAuditLogger::new(
                dir.path().join("audit.jsonl"),
                clawdefender_core::config::settings::LogRotation::default(),
            )
            .unwrap(),
        );

        let (audit_tx, mut audit_rx) = mpsc::channel::<AuditRecord>(16);
        let logger_clone = Arc::clone(&logger);
        let writer = tokio::spawn(async move {
            while let Some(record) = audit_rx.recv().await {
                logger_clone.log(&record).unwrap();
            }
        });

        // Send a test record.
        let record = AuditRecord {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            event_summary: "test event".to_string(),
            event_details: serde_json::json!({}),
            rule_matched: None,
            action_taken: "allow".to_string(),
            response_time_ms: None,
            session_id: None,
            direction: None,
            server_name: None,
            client_name: None,
            jsonrpc_method: None,
            tool_name: None,
            arguments: None,
            classification: None,
            policy_rule: None,
            policy_action: None,
            user_decision: None,
            proxy_latency_us: None,
            slm_analysis: None,
            swarm_analysis: None,
        };
        audit_tx.send(record).await.unwrap();
        drop(audit_tx);
        writer.await.unwrap();

        // Verify the record was written.
        let filter = clawdefender_core::audit::AuditFilter {
            action: Some("allow".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn daemon_starts_with_swarm_disabled_no_api_key() {
        // When swarm is enabled in config but no API key is available,
        // the daemon should initialize without error (graceful degradation).
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.swarm.enabled = true;
        // No API key set — swarm commander should be None at runtime
        let daemon = Daemon::new(config, false);
        assert!(daemon.is_ok(), "daemon should start even without API key");
    }

    #[test]
    fn daemon_starts_with_swarm_explicitly_disabled() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.swarm.enabled = false;
        let daemon = Daemon::new(config, false);
        assert!(daemon.is_ok(), "daemon should start with swarm disabled");
    }

    #[test]
    fn slm_service_disabled_without_model() {
        // When no model path is configured, SLM should start in disabled mode.
        let slm_config = SlmEngineConfig::default();
        let svc = SlmService::new(slm_config, true);
        // Model path is empty by default, so it won't exist.
        assert!(!svc.is_enabled());
    }

    #[test]
    fn slm_service_disabled_when_config_says_disabled() {
        let slm_config = SlmEngineConfig::default();
        let svc = SlmService::new(slm_config, false);
        assert!(!svc.is_enabled());
    }

    #[test]
    fn config_parsing_with_slm_section() {
        let toml_str = r#"
[slm]
enabled = true
context_size = 4096
max_output_tokens = 512
temperature = 0.2
use_gpu = false
threads = 8
"#;
        let config: ClawConfig = toml::from_str(toml_str).unwrap();
        assert!(config.slm.enabled);
        assert_eq!(config.slm.context_size, 4096);
        assert_eq!(config.slm.max_output_tokens, 512);
        assert!((config.slm.temperature - 0.2).abs() < f32::EPSILON);
        assert!(!config.slm.use_gpu);
        assert_eq!(config.slm.threads, Some(8));
        assert!(config.slm.model_path.is_none());
    }

    #[test]
    fn config_parsing_slm_defaults() {
        let toml_str = "";
        let config: ClawConfig = toml::from_str(toml_str).unwrap();
        assert!(config.slm.enabled);
        assert_eq!(config.slm.context_size, 2048);
        assert_eq!(config.slm.max_output_tokens, 256);
        assert!((config.slm.temperature - 0.1).abs() < f32::EPSILON);
        assert!(config.slm.use_gpu);
        assert!(config.slm.threads.is_none());
    }

    #[tokio::test]
    async fn audit_record_includes_slm_analysis_when_present() {
        use clawdefender_core::audit::SlmAnalysisRecord;

        let dir = TempDir::new().unwrap();
        let logger = Arc::new(
            FileAuditLogger::new(
                dir.path().join("audit.jsonl"),
                clawdefender_core::config::settings::LogRotation::default(),
            )
            .unwrap(),
        );

        let record = AuditRecord {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            event_summary: "test event".to_string(),
            event_details: serde_json::json!({}),
            rule_matched: None,
            action_taken: "slm_analysis".to_string(),
            response_time_ms: None,
            session_id: None,
            direction: None,
            server_name: None,
            client_name: None,
            jsonrpc_method: None,
            tool_name: None,
            arguments: None,
            classification: None,
            policy_rule: None,
            policy_action: None,
            user_decision: None,
            proxy_latency_us: None,
            slm_analysis: Some(SlmAnalysisRecord {
                risk_level: "HIGH".to_string(),
                explanation: "Suspicious file access".to_string(),
                confidence: 0.88,
                latency_ms: 150,
                model: "mock-model-q4".to_string(),
            }),
            swarm_analysis: None,
        };

        logger.log(&record).unwrap();

        let filter = clawdefender_core::audit::AuditFilter {
            action: Some("slm_analysis".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert!(!results.is_empty());
        let first = &results[0];
        let slm = first.slm_analysis.as_ref().unwrap();
        assert_eq!(slm.risk_level, "HIGH");
        assert_eq!(slm.explanation, "Suspicious file access");
        assert!((slm.confidence - 0.88).abs() < f32::EPSILON);
        assert_eq!(slm.latency_ms, 150);
        assert_eq!(slm.model, "mock-model-q4");
    }
}
