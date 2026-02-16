//! ClawAI daemon orchestration logic.
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

use claw_core::audit::logger::FileAuditLogger;
use claw_core::audit::{AuditLogger, AuditRecord};
use claw_core::config::settings::ClawConfig;
use claw_core::policy::engine::DefaultPolicyEngine;
use claw_core::policy::PolicyEngine;
use claw_mcp_proxy::{ProxyConfig, StdioProxy, UiBridge};
use claw_tui::{EventRecord, PendingPrompt};

/// The main daemon that orchestrates all ClawAI subsystems.
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

    /// Main entry point for `clawai proxy -- <command> [args...]`.
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
                claw_core::ipc::protocol::UiRequest,
                tokio::sync::oneshot::Sender<claw_core::ipc::protocol::UiResponse>,
            )>(64);
        let ui_bridge = Arc::new(UiBridge::new(ui_req_tx));

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
                if let Err(e) = rt.block_on(claw_tui::run(prompt_rx, event_rx)) {
                    error!(error = %e, "TUI exited with error");
                }
            }))
        } else {
            info!("no TTY or TUI disabled, running headless");
            Some(tokio::spawn(async move {
                if let Err(e) = claw_tui::run_headless(prompt_rx).await {
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
        let proxy = StdioProxy::with_full_config(
            proxy_config,
            policy_snapshot,
            audit_tx.clone(),
            Some(ui_bridge),
        );

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
        PathBuf::from(home).join(".local/share/clawai/clawai.pid")
    } else {
        PathBuf::from("/tmp/clawai.pid")
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
                claw_core::config::settings::LogRotation::default(),
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
        };
        audit_tx.send(record).await.unwrap();
        drop(audit_tx);
        writer.await.unwrap();

        // Verify the record was written.
        let filter = claw_core::audit::AuditFilter {
            action: Some("allow".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert!(!results.is_empty());
    }
}
