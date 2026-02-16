//! ClawAI daemon orchestration logic.
//!
//! The [`Daemon`] struct ties together the sensor manager, policy engine,
//! audit logger, correlation engine, and TUI into a single async event loop.

pub mod ipc;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use claw_core::audit::logger::FileAuditLogger;
use claw_core::audit::AuditLogger;
use claw_core::config::settings::ClawConfig;
use claw_core::correlation::CorrelationEngine;
use claw_core::event::os::OsEvent;
use claw_core::event::Event;
use claw_core::policy::engine::DefaultPolicyEngine;
use claw_core::policy::{PolicyAction, PolicyEngine};
use claw_sensor::SensorManager;
use claw_tui::{AppState, DashboardStats, EventRecord, SharedState};

/// The main daemon that orchestrates all ClawAI subsystems.
pub struct Daemon {
    config: ClawConfig,
    policy_engine: DefaultPolicyEngine,
    audit_logger: FileAuditLogger,
    correlation_engine: CorrelationEngine,
    tui_state: SharedState,
    enable_tui: bool,
}

impl Daemon {
    /// Create a new daemon from the given configuration.
    pub fn new(config: ClawConfig) -> Result<Self> {
        // Load policy engine -- use empty engine if policy file doesn't exist yet.
        let policy_engine = if config.policy_path.exists() {
            DefaultPolicyEngine::load(&config.policy_path)
                .context("loading policy engine")?
        } else {
            info!(path = %config.policy_path.display(), "policy file not found, using empty policy");
            DefaultPolicyEngine::empty()
        };

        // Create audit logger.
        let audit_logger = FileAuditLogger::new(
            config.audit_log_path.clone(),
            config.log_rotation.clone(),
        )
        .context("creating audit logger")?;

        // Create correlation engine with a 5-second window.
        let correlation_engine = CorrelationEngine::new(Duration::from_secs(5));

        // Create shared TUI state.
        let tui_state = Arc::new(RwLock::new(AppState::default()));

        Ok(Self {
            config,
            policy_engine,
            audit_logger,
            correlation_engine,
            tui_state,
            enable_tui: false,
        })
    }

    /// Enable or disable the TUI.
    pub fn set_tui_enabled(&mut self, enabled: bool) {
        self.enable_tui = enabled;
    }

    /// Get a reference to the shared TUI state.
    pub fn tui_state(&self) -> &SharedState {
        &self.tui_state
    }

    /// Run the daemon event loop until shutdown is requested.
    pub async fn run(&mut self) -> Result<()> {
        info!("claw-daemon starting up");
        let start_time = std::time::Instant::now();

        // Start sensor if on macOS and eslogger is enabled.
        let sensor_rx = if cfg!(target_os = "macos") && self.config.eslogger.enabled {
            match self.start_sensor() {
                Ok(rx) => Some(rx),
                Err(e) => {
                    warn!(error = %e, "failed to start sensor, continuing without it");
                    None
                }
            }
        } else {
            debug!("sensor disabled or not on macOS");
            None
        };

        // Start IPC server.
        let mut ipc_rx = self.start_ipc_server().await?;

        // Start TUI in a background task if enabled.
        let tui_handle = if self.enable_tui {
            let state = self.tui_state.clone();
            Some(tokio::task::spawn_blocking(move || {
                if let Err(e) = claw_tui::run(state) {
                    error!(error = %e, "TUI exited with error");
                }
            }))
        } else {
            None
        };

        // Main event loop.
        let mut sensor_rx = sensor_rx;
        let mut tick_interval = tokio::time::interval(Duration::from_secs(1));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!("daemon event loop started");

        loop {
            // Check if shutdown was requested.
            {
                let state = self.tui_state.read().map_err(|e| anyhow::anyhow!("{e}"))?;
                if !state.running {
                    info!("shutdown requested via TUI state");
                    break;
                }
            }

            tokio::select! {
                // Sensor events.
                Some(os_event) = async {
                    match sensor_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<OsEvent>>().await,
                    }
                } => {
                    self.handle_os_event(os_event);
                }
                // Tick for correlation engine.
                _ = tick_interval.tick() => {
                    self.handle_tick(start_time);
                }
                // IPC messages.
                Some(msg) = ipc_rx.recv() => {
                    self.handle_ipc_message(msg);
                }
                // Ctrl+C / SIGTERM.
                _ = tokio::signal::ctrl_c() => {
                    info!("received shutdown signal");
                    break;
                }
            }
        }

        // Graceful shutdown.
        self.shutdown().await;

        // Wait for TUI to finish if it was running.
        if let Some(handle) = tui_handle {
            let _ = handle.await;
        }

        info!("claw-daemon shut down");
        Ok(())
    }

    fn start_sensor(&mut self) -> Result<mpsc::Receiver<OsEvent>> {
        let mut sensor = SensorManager::new(&self.config.eslogger)
            .context("creating sensor manager")?;
        let rx = sensor.start(&[]).context("starting sensor")?;
        info!("sensor started");
        Ok(rx)
    }

    async fn start_ipc_server(&self) -> Result<mpsc::Receiver<IpcMessage>> {
        let (tx, rx) = mpsc::channel(64);
        let socket_path = self.config.daemon_socket_path.clone();
        let state = self.tui_state.clone();

        tokio::spawn(async move {
            if let Err(e) = ipc::run_ipc_server(socket_path, tx, state).await {
                error!(error = %e, "IPC server exited with error");
            }
        });

        Ok(rx)
    }

    fn handle_os_event(&mut self, event: OsEvent) {
        debug!(pid = event.pid, kind = ?event.kind, "received OS event");

        // Submit to correlation engine.
        self.correlation_engine.submit_os_event(event.clone());

        // Create audit record and log it.
        let mut record = event.to_audit_record();
        let action = self.policy_engine.evaluate(&event);
        record.action_taken = format_action(&action);

        if let Err(e) = self.audit_logger.log(&record) {
            error!(error = %e, "failed to log audit record");
        }

        // Update TUI state.
        self.push_event_to_tui(&event, &record.action_taken);
        self.update_stats(&record.action_taken);
    }

    fn handle_tick(&mut self, start_time: std::time::Instant) {
        // Process completed correlations.
        let completed = self.correlation_engine.tick();
        for corr in &completed {
            let mut record = corr.to_audit_record();
            let action = self.policy_engine.evaluate(corr);
            record.action_taken = format_action(&action);

            if let Err(e) = self.audit_logger.log(&record) {
                error!(error = %e, "failed to log correlation audit record");
            }

            // Update TUI state with correlation result.
            if let Ok(mut state) = self.tui_state.write() {
                state.push_event(EventRecord {
                    timestamp: Utc::now(),
                    source: "correlation".to_string(),
                    summary: record.event_summary.clone(),
                    action: record.action_taken.clone(),
                    severity: corr.severity(),
                    details: None,
                });
            }
        }

        // Update uptime.
        if let Ok(mut state) = self.tui_state.write() {
            state.stats.uptime_secs = start_time.elapsed().as_secs();
        }
    }

    fn handle_ipc_message(&self, msg: IpcMessage) {
        match msg {
            IpcMessage::StatusRequest { reply } => {
                let stats = self.tui_state.read().ok().map(|s| s.stats.clone());
                let _ = reply.send(stats);
            }
        }
    }

    fn push_event_to_tui(&self, event: &OsEvent, action: &str) {
        if let Ok(mut state) = self.tui_state.write() {
            state.push_event(EventRecord {
                timestamp: event.timestamp,
                source: event.source().to_string(),
                summary: event.to_audit_record().event_summary,
                action: action.to_string(),
                severity: event.severity(),
                details: None,
            });
        }
    }

    fn update_stats(&self, action: &str) {
        if let Ok(mut state) = self.tui_state.write() {
            state.stats.total_events += 1;
            match action {
                "block" => state.stats.blocked += 1,
                "allow" => state.stats.allowed += 1,
                "prompt" => state.stats.prompted += 1,
                _ => {}
            }
        }
    }

    async fn shutdown(&mut self) {
        info!("initiating graceful shutdown");

        // Signal TUI to stop.
        if let Ok(mut state) = self.tui_state.write() {
            state.running = false;
        }

        // Flush correlation engine.
        let remaining = self.correlation_engine.flush();
        for corr in &remaining {
            let mut record = corr.to_audit_record();
            record.action_taken = "log".to_string();
            if let Err(e) = self.audit_logger.log(&record) {
                error!(error = %e, "failed to log remaining correlation on shutdown");
            }
        }

        // Clean up IPC socket.
        if self.config.daemon_socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.config.daemon_socket_path) {
                warn!(error = %e, "failed to remove IPC socket");
            }
        }

        info!("shutdown complete");
    }
}

/// Internal IPC message types for the daemon event loop.
pub enum IpcMessage {
    StatusRequest {
        reply: tokio::sync::oneshot::Sender<Option<DashboardStats>>,
    },
}

fn format_action(action: &PolicyAction) -> String {
    match action {
        PolicyAction::Allow => "allow".to_string(),
        PolicyAction::Block => "block".to_string(),
        PolicyAction::Prompt(_) => "prompt".to_string(),
        PolicyAction::Log => "log".to_string(),
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
        let daemon = Daemon::new(config).unwrap();
        assert!(!daemon.enable_tui);
    }

    #[test]
    fn daemon_tui_state_is_shared() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let daemon = Daemon::new(config).unwrap();
        let state = daemon.tui_state().clone();
        let s = state.read().unwrap();
        assert!(s.running);
        assert!(s.events.is_empty());
    }

    #[test]
    fn daemon_handles_os_event() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let mut daemon = Daemon::new(config).unwrap();

        let event = OsEvent {
            timestamp: Utc::now(),
            pid: 1234,
            ppid: 1,
            process_path: "/usr/bin/cat".to_string(),
            kind: claw_core::event::os::OsEventKind::Open {
                path: "/tmp/test".to_string(),
                flags: 0,
            },
            signing_id: None,
            team_id: None,
        };

        daemon.handle_os_event(event);

        let state = daemon.tui_state.read().unwrap();
        assert_eq!(state.events.len(), 1);
        assert_eq!(state.stats.total_events, 1);
    }

    #[test]
    fn daemon_correlation_tick() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let mut daemon = Daemon::new(config).unwrap();
        // Tick with no pending correlations should not panic.
        let start = std::time::Instant::now();
        daemon.handle_tick(start);
    }

    #[tokio::test]
    async fn daemon_graceful_shutdown() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let mut daemon = Daemon::new(config).unwrap();

        // Verify running is true.
        {
            let state = daemon.tui_state.read().unwrap();
            assert!(state.running);
        }

        daemon.shutdown().await;

        // Verify running is now false.
        {
            let state = daemon.tui_state.read().unwrap();
            assert!(!state.running);
        }
    }

    #[test]
    fn format_action_strings() {
        assert_eq!(format_action(&PolicyAction::Allow), "allow");
        assert_eq!(format_action(&PolicyAction::Block), "block");
        assert_eq!(format_action(&PolicyAction::Prompt("msg".into())), "prompt");
        assert_eq!(format_action(&PolicyAction::Log), "log");
    }
}
