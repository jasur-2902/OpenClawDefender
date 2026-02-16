//! Eslogger child process manager.
//!
//! Manages the lifecycle of the `eslogger` subprocess that streams Endpoint
//! Security events as NDJSON.

use anyhow::Result;

/// Manages a running eslogger child process.
pub struct EsloggerManager {
    /// The event types this manager is subscribed to.
    _subscribed_events: Vec<String>,
    // TODO: Phase 2 — child: Option<tokio::process::Child>
}

impl EsloggerManager {
    /// Spawn a new eslogger process subscribing to the given event types.
    ///
    /// In production this will run: `sudo eslogger <events> --format json`
    /// and return a manager wrapping the child process handle.
    ///
    /// # Errors
    ///
    /// Currently always returns an error because eslogger is not available
    /// outside of a macOS environment with SIP/TCC entitlements.
    // TODO: Phase 2 — full implementation with restart logic, sleep/wake handling
    pub fn spawn(events: &[&str]) -> Result<Self> {
        let _subscribed = events.iter().map(|e| e.to_string()).collect::<Vec<_>>();
        anyhow::bail!("eslogger not available in this environment")
    }

    /// Check whether the eslogger child process is still alive.
    // TODO: Phase 2 — check child process status
    pub fn is_alive(&self) -> bool {
        false
    }

    /// Returns the event types this manager subscribes to.
    pub fn subscribed_events(&self) -> &[String] {
        &self._subscribed_events
    }
}
