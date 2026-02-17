//! Daemon connection types and IPC message definitions for the guard.

use serde::{Deserialize, Serialize};

use crate::types::{DaemonConnection, GuardStats, GuardStatus, PermissionSet};

/// Default socket path for the ClawDefender daemon.
pub const DEFAULT_SOCKET_PATH: &str = "~/.local/share/clawdefender/clawdefender.sock";

/// Expand tilde in socket path to the actual home directory.
pub fn expand_socket_path(path: &str) -> String {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{stripped}");
        }
    }
    path.to_string()
}

/// IPC request messages sent from the guard to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuardRequest {
    /// Register a guard with the daemon.
    GuardRegister {
        agent_name: String,
        pid: u32,
        permissions: Box<PermissionSet>,
        policy_toml: String,
    },
    /// Deregister a guard from the daemon.
    GuardDeregister {
        agent_name: String,
        pid: u32,
    },
    /// Query guard stats from the daemon.
    GuardStatsQuery {
        agent_name: String,
    },
    /// Health check request.
    GuardHealthCheck,
}

/// IPC response messages sent from the daemon to the guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuardResponse {
    /// Guard successfully registered.
    GuardRegistered {
        guard_id: String,
    },
    /// Guard successfully deregistered.
    GuardDeregistered,
    /// Guard stats response.
    GuardStatsResponse {
        stats: GuardStats,
    },
    /// Health check response.
    GuardHealthResponse {
        status: GuardStatus,
    },
    /// Error response.
    Error {
        message: String,
    },
}

/// Event sent from the daemon to the guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvent {
    /// Name of the agent this event is for.
    pub agent_name: String,
    /// The event payload.
    pub event: GuardEventKind,
}

/// Types of events the daemon can push to a guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuardEventKind {
    /// An operation was blocked by the daemon.
    OperationBlocked {
        tool: String,
        target: String,
        reason: String,
    },
    /// An anomaly was detected.
    AnomalyDetected {
        description: String,
        severity: String,
    },
    /// Policy was updated.
    PolicyUpdated,
}

impl DaemonConnection {
    /// Create a new daemon connection instance.
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            connected: false,
        }
    }

    /// Try to connect to the daemon socket.
    /// Returns Ok(true) if daemon is reachable, Ok(false) if not.
    pub fn try_connect(&mut self) -> anyhow::Result<bool> {
        let expanded = expand_socket_path(&self.socket_path);
        let path = std::path::Path::new(&expanded);

        if path.exists() {
            // Try a quick connection test.
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_stream) => {
                    self.connected = true;
                    Ok(true)
                }
                Err(_) => {
                    self.connected = false;
                    Ok(false)
                }
            }
        } else {
            self.connected = false;
            Ok(false)
        }
    }

    /// Check if currently connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Disconnect from the daemon.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }
}
