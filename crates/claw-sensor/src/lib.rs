//! OS-level sensors for process and filesystem monitoring.
//!
//! This crate provides macOS-specific integrations for observing process and
//! filesystem activity via Endpoint Security (eslogger) and FSEvents.

pub mod eslogger;
pub mod fsevents;
pub mod proctree;

pub use eslogger::{parse_event, EsloggerEvent, EsloggerManager, EsloggerProcess};
pub use fsevents::{FsEvent, FsEventKind, FsWatcher};
pub use proctree::{AgentInfo, Confidence, ProcessInfo, ProcessTree};

use std::path::PathBuf;

use anyhow::{Context, Result};
use claw_core::config::settings::EsloggerConfig;
use claw_core::event::os::OsEvent;
use tokio::sync::mpsc;
use tracing::info;

/// Unified sensor manager combining eslogger, process tree, and filesystem watcher.
pub struct SensorManager {
    process_tree: ProcessTree,
    fs_watcher: Option<FsWatcher>,
    config: EsloggerConfig,
}

impl SensorManager {
    /// Create a new sensor manager from the given eslogger config.
    pub fn new(config: &EsloggerConfig) -> Result<Self> {
        Ok(Self {
            process_tree: ProcessTree::new(),
            fs_watcher: None,
            config: config.clone(),
        })
    }

    /// Start the sensor subsystems and return a unified event receiver.
    ///
    /// This spawns the filesystem watcher on the given paths.
    /// On macOS, it also attempts to start eslogger (will fail gracefully
    /// if entitlements are missing).
    pub fn start(&mut self, watch_paths: &[PathBuf]) -> Result<mpsc::Receiver<OsEvent>> {
        let (tx, rx) = mpsc::channel(self.config.buffer_size);

        // Start filesystem watcher
        if !watch_paths.is_empty() {
            let mut fs_watcher = FsWatcher::new().context("failed to create FsWatcher")?;
            let mut fs_rx = fs_watcher
                .watch(watch_paths)
                .context("failed to start FsWatcher")?;

            let fs_tx = tx.clone();
            tokio::spawn(async move {
                while let Some(fs_event) = fs_rx.recv().await {
                    let os_event: OsEvent = fs_event.into();
                    if fs_tx.send(os_event).await.is_err() {
                        break;
                    }
                }
            });

            self.fs_watcher = Some(fs_watcher);
            info!(paths = ?watch_paths, "filesystem watcher started");
        }

        // Initial process tree refresh
        if let Err(e) = self.process_tree.refresh() {
            tracing::warn!(error = %e, "initial process tree refresh failed");
        }

        Ok(rx)
    }

    /// Refresh the process tree snapshot from OS data.
    pub fn refresh_process_tree(&mut self) -> Result<()> {
        self.process_tree.refresh()
    }

    /// Check whether a PID belongs to a known AI agent.
    pub fn is_agent(&self, pid: u32) -> bool {
        self.process_tree.is_agent(pid)
    }

    /// Get a reference to the underlying process tree.
    pub fn process_tree(&self) -> &ProcessTree {
        &self.process_tree
    }

    /// Get a mutable reference to the underlying process tree.
    pub fn process_tree_mut(&mut self) -> &mut ProcessTree {
        &mut self.process_tree
    }
}
