//! ClawDefender daemon orchestration logic.
//!
//! The [`Daemon`] struct ties together the MCP proxy, policy engine,
//! audit logger, sensor subsystem (process tree, eslogger, FSEvents),
//! correlation engine, event router, TUI, and signal handling into a
//! single async process.

pub mod event_router;
pub mod ipc;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use clawdefender_core::audit::logger::FileAuditLogger;
use clawdefender_core::audit::{AuditLogger, AuditRecord};
use clawdefender_core::config::settings::{ClawConfig, SensorConfig};
use clawdefender_core::event::correlation::CorrelatedEvent;
use clawdefender_core::policy::engine::DefaultPolicyEngine;
use clawdefender_core::policy::PolicyEngine;
use clawdefender_mcp_proxy::{ProxyConfig, StdioProxy, UiBridge};
use clawdefender_sensor::correlation::engine::{
    CorrelationConfig as EngineCorrelationConfig, CorrelationEngine, CorrelationInput,
};
use clawdefender_sensor::{
    default_watch_paths, EnhancedFsWatcher, EsloggerManager, ProcessTree,
};
use clawdefender_slm::context::ContextTracker;
use clawdefender_slm::engine::SlmConfig as SlmEngineConfig;
use clawdefender_slm::noise_filter::NoiseFilter;
use clawdefender_slm::SlmService;
use clawdefender_mcp_server::McpServer;
use clawdefender_swarm::chat::ChatManager;
use clawdefender_swarm::chat_server::ChatServer;
use clawdefender_swarm::commander::Commander;
use clawdefender_swarm::cost::{BudgetConfig, CostTracker, PricingTable};
use clawdefender_swarm::keychain::{self, KeyStore, Provider};
use clawdefender_swarm::llm_client::{HttpLlmClient, LlmClient};
use clawdefender_tui::{EventRecord, PendingPrompt};

use event_router::{EventRouter, EventRouterConfig};

/// The main daemon that orchestrates all ClawDefender subsystems.
pub struct Daemon {
    config: ClawConfig,
    sensor_config: SensorConfig,
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

        // Load sensor configuration.
        let sensor_config = SensorConfig::load(&config.sensor_config_path)
            .unwrap_or_else(|e| {
                warn!(error = %e, "failed to load sensor config, using defaults");
                SensorConfig::default()
            });

        // Create audit logger.
        let audit_logger = FileAuditLogger::new(
            config.audit_log_path.clone(),
            config.log_rotation.clone(),
        )
        .context("creating audit logger")?;

        info!(
            audit_path = %config.audit_log_path.display(),
            "Audit logger: writing to path"
        );

        Ok(Self {
            config,
            sensor_config,
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            audit_logger: Arc::new(audit_logger),
            enable_tui,
        })
    }

    /// Start the sensor subsystem (process tree, eslogger, FSEvents, correlation).
    ///
    /// Each step degrades gracefully -- sensor failure does not prevent the MCP
    /// proxy from running.
    async fn start_sensor_subsystem(
        &self,
        process_tree: Arc<RwLock<ProcessTree>>,
        audit_tx: mpsc::Sender<AuditRecord>,
        ui_event_tx: mpsc::Sender<CorrelatedEvent>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        // --- Step 1: Process tree with refresh timer ---
        {
            let tree = Arc::clone(&process_tree);
            let refresh_secs = self.sensor_config.process_tree.refresh_interval_secs;
            let tree_for_init = Arc::clone(&tree);

            // Initial refresh
            {
                let mut t = tree_for_init.write().await;
                match t.refresh() {
                    Ok(()) => info!(
                        count = t.len(),
                        "Process tree: monitoring {} processes",
                        t.len()
                    ),
                    Err(e) => warn!(error = %e, "Process tree: initial refresh failed"),
                }
            }

            let handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
                loop {
                    interval.tick().await;
                    let mut t = tree.write().await;
                    if let Err(e) = t.refresh() {
                        warn!(error = %e, "process tree refresh failed");
                    }
                }
            });
            handles.push(handle);
        }

        // --- Step 2: Correlation engine ---
        let (correlation_input_tx, correlation_input_rx) = mpsc::channel::<CorrelationInput>(4096);
        let (correlated_tx, correlated_rx) = mpsc::channel::<CorrelatedEvent>(1024);

        {
            let engine_config = EngineCorrelationConfig {
                match_window: Duration::from_millis(self.sensor_config.correlation.window_ms),
                ..EngineCorrelationConfig::default()
            };
            let engine = CorrelationEngine::new(engine_config, correlated_tx);
            let tree = Arc::clone(&process_tree);
            let handle = engine.run(correlation_input_rx, tree);
            info!("Correlation engine: active");
            handles.push(handle);
        }

        // --- Step 3: Event router ---
        {
            let router = EventRouter::new(
                EventRouterConfig::default(),
                audit_tx,
                ui_event_tx,
            );
            let handle = router.run(correlated_rx);
            handles.push(handle);
        }

        // --- Step 4: eslogger (if FDA is granted) ---
        if self.sensor_config.eslogger.enabled {
            let fda_granted = EsloggerManager::check_fda();
            if fda_granted {
                let events: Vec<&str> = self
                    .sensor_config
                    .eslogger
                    .events
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                match EsloggerManager::spawn(
                    &events,
                    Some(self.sensor_config.eslogger.channel_capacity),
                    &self.sensor_config.eslogger.ignore_processes,
                    &self.sensor_config.eslogger.ignore_paths,
                ) {
                    Ok((_manager, mut eslogger_rx)) => {
                        info!("eslogger: active");
                        let corr_tx = correlation_input_tx.clone();
                        let handle = tokio::spawn(async move {
                            while let Some(os_event) = eslogger_rx.recv().await {
                                if corr_tx
                                    .send(CorrelationInput::Os(os_event))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        });
                        handles.push(handle);
                    }
                    Err(e) => {
                        warn!(error = %e, "eslogger: unavailable (failed to spawn)");
                    }
                }
            } else {
                warn!("eslogger: unavailable (Full Disk Access not granted)");
            }
        } else {
            info!("eslogger: disabled in config");
        }

        // --- Step 5: EnhancedFsWatcher ---
        if self.sensor_config.fsevents.enabled {
            let watch_paths = if self.sensor_config.fsevents.watch_paths.is_empty() {
                default_watch_paths()
            } else {
                self.sensor_config.fsevents.watch_paths.clone()
            };

            if !watch_paths.is_empty() {
                match EnhancedFsWatcher::new(None) {
                    Ok(mut watcher) => match watcher.watch(&watch_paths) {
                        Ok(mut fs_rx) => {
                            info!(
                                count = watch_paths.len(),
                                "FSEvents: watching {} directories",
                                watch_paths.len()
                            );
                            let corr_tx = correlation_input_tx.clone();
                            let handle = tokio::spawn(async move {
                                while let Some(fs_event) = fs_rx.recv().await {
                                    let os_event =
                                        clawdefender_core::event::os::OsEvent::from(fs_event);
                                    if corr_tx
                                        .send(CorrelationInput::Os(os_event))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            });
                            handles.push(handle);
                        }
                        Err(e) => {
                            warn!(error = %e, "FSEvents: failed to start watching");
                        }
                    },
                    Err(e) => {
                        warn!(error = %e, "FSEvents: failed to create watcher");
                    }
                }
            } else {
                info!("FSEvents: no paths to watch");
            }
        } else {
            info!("FSEvents: disabled in config");
        }

        // --- Step 6: Sensor config hot-reload ---
        let sensor_path = self.config.sensor_config_path.clone();
        if sensor_path.exists() {
            let handle = spawn_file_watcher(sensor_path, "sensor config");
            handles.push(handle);
        }

        // Keep the correlation input sender alive for the proxy to use.
        // We leak it into a static-ish handle via a background task.
        let _corr_tx = correlation_input_tx;

        handles
    }

    /// Main entry point for `clawdefender proxy -- <command> [args...]`.
    ///
    /// Spawns the MCP proxy, sensor subsystem, audit writer, TUI (or headless),
    /// and signal handlers, then runs until the proxy finishes or a signal is received.
    pub async fn run_proxy(self, command: String, args: Vec<String>) -> Result<()> {
        info!("ClawDefender daemon starting");

        // Write PID file.
        let pid_path = pid_file_path();
        write_pid_file(&pid_path)?;

        // --- Channels ---
        let (_prompt_tx, prompt_rx) = mpsc::channel::<PendingPrompt>(64);
        let (_event_tx, event_rx) = mpsc::channel::<EventRecord>(256);
        let (audit_tx, mut audit_rx) = mpsc::channel::<AuditRecord>(1024);

        // Channel for correlated events to be forwarded to UIs.
        let (_ui_correlated_tx, _ui_correlated_rx) = mpsc::channel::<CorrelatedEvent>(256);

        // --- UiBridge (connects proxy prompts to TUI) ---
        let (ui_req_tx, _ui_req_rx) =
            mpsc::channel::<(
                clawdefender_core::ipc::protocol::UiRequest,
                tokio::sync::oneshot::Sender<clawdefender_core::ipc::protocol::UiResponse>,
            )>(64);
        let ui_bridge = Arc::new(UiBridge::new(ui_req_tx));

        // --- Policy engine status ---
        info!("Policy engine: loaded");


        // --- SLM service (advisory only, graceful failure -> disabled mode) ---
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
            info!("SLM: enabled");
        } else {
            info!("SLM: disabled (no model or disabled in config)");
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
                info!("Swarm: enabled");
                Some(Arc::new(commander))
            } else {
                info!("Swarm: disabled (no API key)");
                None
            }
        } else {
            info!("Swarm: disabled in config");
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

        // --- MCP server (cooperative security endpoint) ---
        let mcp_server_handle = if self.config.mcp_server.enabled {
            let policy_snapshot = if self.config.policy_path.exists() {
                DefaultPolicyEngine::load(&self.config.policy_path)
                    .unwrap_or_else(|_| DefaultPolicyEngine::empty())
            } else {
                DefaultPolicyEngine::empty()
            };
            let mcp_audit = Arc::clone(&self.audit_logger);
            let mcp_server = Arc::new(McpServer::new(Box::new(policy_snapshot), mcp_audit));
            let mcp_port = self.config.mcp_server.http_port;
            let handle = tokio::spawn(async move {
                if let Err(e) = mcp_server.run_http(mcp_port).await {
                    warn!(error = %e, "MCP server exited");
                }
            });
            info!(port = mcp_port, "MCP server: listening on HTTP port {}", mcp_port);
            Some(handle)
        } else {
            info!("MCP server: disabled in config");
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

        // --- Sensor subsystem (process tree, eslogger, FSEvents, correlation) ---
        let process_tree = Arc::new(RwLock::new(ProcessTree::new()));
        let sensor_handles = self
            .start_sensor_subsystem(
                Arc::clone(&process_tree),
                audit_tx.clone(),
                _ui_correlated_tx,
            )
            .await;

        // --- TUI or headless ---
        let ui_mode = if self.enable_tui && std::io::stdout().is_terminal() {
            "TUI mode"
        } else {
            "headless"
        };
        info!(mode = ui_mode, "UI: {}", ui_mode);

        let tui_handle = if self.enable_tui && std::io::stdout().is_terminal() {
            Some(tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();
                if let Err(e) = rt.block_on(clawdefender_tui::run(prompt_rx, event_rx)) {
                    error!(error = %e, "TUI exited with error");
                }
            }))
        } else {
            Some(tokio::spawn(async move {
                if let Err(e) = clawdefender_tui::run_headless(prompt_rx).await {
                    error!(error = %e, "headless prompt handler exited with error");
                }
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
        info!(path = %socket_path.display(), "IPC: listening on {}", socket_path.display());
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
        info!(cmd = %command, args = ?args, "MCP proxy: ready");

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

        // Abort sensor tasks.
        for handle in sensor_handles {
            handle.abort();
        }

        // Abort IPC server.
        ipc_handle.abort();

        // Abort chat server.
        if let Some(handle) = chat_server_handle {
            handle.abort();
            info!("chat server stopped");
        }

        // Abort MCP server.
        if let Some(handle) = mcp_server_handle {
            handle.abort();
            info!("MCP server stopped");
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

        let watch_dir = watch_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            warn!(error = %e, "failed to watch policy directory");
            return;
        }

        info!(path = %policy_path.display(), "watching policy file for changes");

        while rx.recv().await.is_some() {
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

/// Spawn a generic file watcher that logs reload events (for sensor.toml etc.).
fn spawn_file_watcher(
    file_path: PathBuf,
    label: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use notify::{Event, EventKind, RecursiveMode, Watcher};

        let (tx, mut rx) = mpsc::channel::<()>(4);

        let watch_path = file_path.clone();
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
                warn!(error = %e, label = label, "failed to create file watcher");
                return;
            }
        };

        let watch_dir = watch_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            warn!(error = %e, label = label, "failed to watch directory");
            return;
        }

        info!(path = %file_path.display(), label = label, "watching file for changes");

        while rx.recv().await.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            while rx.try_recv().is_ok() {}
            info!(label = label, "{} changed, reload pending", label);
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
    use clawdefender_core::config::settings::SensorConfig;
    use clawdefender_core::ipc::protocol::{
        DaemonRequest, DaemonResponse, SubsystemStatus, UserDecision,
    };
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
    fn daemon_new_loads_sensor_config_defaults() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        // Point to a non-existent sensor config -> should use defaults.
        config.sensor_config_path = dir.path().join("nonexistent-sensor.toml");
        let daemon = Daemon::new(config, false).unwrap();
        assert!(daemon.sensor_config.eslogger.enabled);
        assert_eq!(daemon.sensor_config.process_tree.refresh_interval_secs, 5);
    }

    #[test]
    fn daemon_new_loads_custom_sensor_config() {
        let dir = TempDir::new().unwrap();
        let sensor_path = dir.path().join("sensor.toml");
        std::fs::write(
            &sensor_path,
            r#"
[eslogger]
enabled = false

[process_tree]
refresh_interval_secs = 10

[correlation]
window_ms = 1000
"#,
        )
        .unwrap();

        let mut config = test_config(&dir);
        config.sensor_config_path = sensor_path;
        let daemon = Daemon::new(config, false).unwrap();
        assert!(!daemon.sensor_config.eslogger.enabled);
        assert_eq!(daemon.sensor_config.process_tree.refresh_interval_secs, 10);
        assert_eq!(daemon.sensor_config.correlation.window_ms, 1000);
    }

    #[test]
    fn daemon_graceful_without_fda() {
        // Daemon should create successfully even when eslogger is enabled
        // but FDA is not granted (the actual sensor start happens at runtime).
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let daemon = Daemon::new(config, false);
        assert!(daemon.is_ok(), "daemon should start without FDA");
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
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.swarm.enabled = true;
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
        let slm_config = SlmEngineConfig::default();
        let svc = SlmService::new(slm_config, true);
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

    // --- New tests for Phase 2 ---

    #[test]
    fn sensor_config_defaults() {
        let config = SensorConfig::default();
        assert!(config.eslogger.enabled);
        assert_eq!(config.process_tree.refresh_interval_secs, 5);
        assert_eq!(config.correlation.window_ms, 500);
    }

    #[test]
    fn sensor_config_load_from_toml() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sensor.toml");
        std::fs::write(
            &path,
            r#"
[eslogger]
enabled = false
events = ["exec", "open"]
channel_capacity = 5000

[fsevents]
enabled = true

[correlation]
window_ms = 2000

[process_tree]
refresh_interval_secs = 3
"#,
        )
        .unwrap();

        let config = SensorConfig::load(&path).unwrap();
        assert!(!config.eslogger.enabled);
        assert_eq!(config.eslogger.events, vec!["exec", "open"]);
        assert_eq!(config.eslogger.channel_capacity, 5000);
        assert!(config.fsevents.enabled);
        assert_eq!(config.correlation.window_ms, 2000);
        assert_eq!(config.process_tree.refresh_interval_secs, 3);
    }

    #[test]
    fn sensor_config_load_missing_file_returns_defaults() {
        let config = SensorConfig::load(std::path::Path::new("/nonexistent/sensor.toml")).unwrap();
        assert!(config.eslogger.enabled);
    }

    #[test]
    fn daemon_request_serialization() {
        let req = DaemonRequest::ProxyRegister {
            server_name: "fs-server".to_string(),
            client_name: "claude".to_string(),
            pid: 1234,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonRequest::ProxyRegister {
                server_name,
                client_name,
                pid,
            } => {
                assert_eq!(server_name, "fs-server");
                assert_eq!(client_name, "claude");
                assert_eq!(pid, 1234);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn daemon_response_serialization() {
        let resp = DaemonResponse::StatusReport {
            subsystems: vec![
                SubsystemStatus {
                    name: "eslogger".to_string(),
                    active: true,
                    detail: "monitoring 8 event types".to_string(),
                },
                SubsystemStatus {
                    name: "fsevents".to_string(),
                    active: true,
                    detail: "watching 5 directories".to_string(),
                },
            ],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonResponse::StatusReport { subsystems } => {
                assert_eq!(subsystems.len(), 2);
                assert_eq!(subsystems[0].name, "eslogger");
                assert!(subsystems[0].active);
                assert_eq!(subsystems[1].name, "fsevents");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn daemon_request_shutdown_serialization() {
        let req = DaemonRequest::Shutdown;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, DaemonRequest::Shutdown));
    }

    #[test]
    fn daemon_request_prompt_response_serialization() {
        let req = DaemonRequest::PromptResponse {
            event_id: "evt-123".to_string(),
            decision: UserDecision::AllowOnce,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonRequest::PromptResponse {
                event_id,
                decision,
            } => {
                assert_eq!(event_id, "evt-123");
                assert_eq!(decision, UserDecision::AllowOnce);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn daemon_response_error_serialization() {
        let resp = DaemonResponse::Error {
            message: "something went wrong".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonResponse::Error { message } => {
                assert_eq!(message, "something went wrong");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn daemon_status_report_includes_all_subsystems() {
        let statuses = vec![
            SubsystemStatus {
                name: "policy_engine".to_string(),
                active: true,
                detail: "5 rules loaded".to_string(),
            },
            SubsystemStatus {
                name: "audit_logger".to_string(),
                active: true,
                detail: "/path/to/audit.jsonl".to_string(),
            },
            SubsystemStatus {
                name: "process_tree".to_string(),
                active: true,
                detail: "150 processes".to_string(),
            },
            SubsystemStatus {
                name: "eslogger".to_string(),
                active: false,
                detail: "FDA not granted".to_string(),
            },
            SubsystemStatus {
                name: "fsevents".to_string(),
                active: true,
                detail: "3 directories".to_string(),
            },
            SubsystemStatus {
                name: "correlation".to_string(),
                active: true,
                detail: "running".to_string(),
            },
            SubsystemStatus {
                name: "slm".to_string(),
                active: false,
                detail: "no model configured".to_string(),
            },
            SubsystemStatus {
                name: "swarm".to_string(),
                active: false,
                detail: "disabled".to_string(),
            },
        ];

        let resp = DaemonResponse::StatusReport {
            subsystems: statuses.clone(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonResponse::StatusReport { subsystems } => {
                assert_eq!(subsystems.len(), 8);
                let eslogger = subsystems.iter().find(|s| s.name == "eslogger").unwrap();
                assert!(!eslogger.active);
                assert_eq!(eslogger.detail, "FDA not granted");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn config_has_sensor_config_path_default() {
        let config = ClawConfig::default();
        assert!(config.sensor_config_path.to_string_lossy().contains("sensor.toml"));
    }

    #[test]
    fn config_parses_sensor_config_path() {
        let toml_str = r#"
sensor_config_path = "/custom/path/sensor.toml"
"#;
        let config: ClawConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.sensor_config_path,
            PathBuf::from("/custom/path/sensor.toml")
        );
    }

    #[tokio::test]
    async fn event_router_forwards_to_audit() {
        let (audit_tx, mut audit_rx) = mpsc::channel::<AuditRecord>(16);
        let (ui_tx, _ui_rx) = mpsc::channel::<CorrelatedEvent>(16);
        let (correlated_tx, correlated_rx) = mpsc::channel::<CorrelatedEvent>(16);

        let router = EventRouter::new(EventRouterConfig::default(), audit_tx, ui_tx);
        let _handle = router.run(correlated_rx);

        let event = CorrelatedEvent {
            id: "test-1".to_string(),
            mcp_event: None,
            os_events: vec![],
            status: clawdefender_core::event::correlation::CorrelationStatus::Uncorrelated,
            correlated_at: Some(chrono::Utc::now()),
        };
        correlated_tx.send(event).await.unwrap();
        drop(correlated_tx);

        let record = tokio::time::timeout(Duration::from_secs(1), audit_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(record.source, "correlation");
    }
}
