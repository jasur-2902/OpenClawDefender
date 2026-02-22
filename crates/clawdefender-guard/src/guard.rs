//! AgentGuard implementation with builder pattern and lifecycle management.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::connection::DEFAULT_SOCKET_PATH;
use crate::fallback::FallbackEngine;
use crate::policy_gen::generate_policy_toml;
use crate::selftest::run_self_test;
use crate::types::*;

/// Builder for constructing an AgentGuard.
pub struct GuardBuilder {
    name: String,
    permissions: PermissionSet,
    mode: GuardMode,
    socket_path: Option<String>,
}

impl GuardBuilder {
    /// Create a new builder for an agent guard with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            permissions: PermissionSet::default(),
            mode: GuardMode::Enforce,
            socket_path: None,
        }
    }

    /// Set the permissions for this guard.
    pub fn permissions(mut self, permissions: PermissionSet) -> Self {
        self.permissions = permissions;
        self
    }

    /// Set the guard mode (Enforce or Monitor).
    pub fn mode(mut self, mode: GuardMode) -> Self {
        self.mode = mode;
        self
    }

    /// Override the daemon socket path.
    pub fn socket_path(mut self, path: &str) -> Self {
        self.socket_path = Some(path.to_string());
        self
    }

    /// Set file read permissions.
    pub fn file_read(mut self, patterns: Vec<String>) -> Self {
        self.permissions.file_read = patterns;
        self
    }

    /// Set file write permissions.
    pub fn file_write(mut self, patterns: Vec<String>) -> Self {
        self.permissions.file_write = patterns;
        self
    }

    /// Set file delete permissions.
    pub fn file_delete(mut self, patterns: Vec<String>) -> Self {
        self.permissions.file_delete = patterns;
        self
    }

    /// Set shell execution policy.
    pub fn shell_policy(mut self, policy: ShellPolicy) -> Self {
        self.permissions.shell_execute = policy;
        self
    }

    /// Set network policy.
    pub fn network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.permissions.network = policy;
        self
    }

    /// Set allowed tools.
    pub fn tools(mut self, tools: Vec<String>) -> Self {
        self.permissions.tools = tools;
        self
    }

    /// Build the AgentGuard instance (inactive, call `activate()` to start).
    pub fn build(self) -> AgentGuard {
        AgentGuard {
            name: self.name,
            permissions: self.permissions,
            status: GuardStatus::Inactive,
            daemon_connection: None,
            policy_id: Uuid::new_v4().to_string(),
            stats: Arc::new(Mutex::new(GuardStats::default())),
            mode: self.mode,
        }
    }
}

impl AgentGuard {
    /// Create a builder for a new guard with the given name.
    pub fn builder(name: &str) -> GuardBuilder {
        GuardBuilder::new(name)
    }

    /// Activate the guard. Attempts daemon connection, falls back to embedded mode.
    pub fn activate(&mut self) -> Result<()> {
        info!(
            "Activating AgentGuard '{}' in {:?} mode",
            self.name, self.mode
        );

        // Try connecting to the daemon.
        let socket = DEFAULT_SOCKET_PATH;
        let mut conn = DaemonConnection::new(socket);
        let daemon_available = conn.try_connect().unwrap_or(false);

        if daemon_available {
            info!("Connected to ClawDefender daemon at {socket}");
            let _policy_toml = generate_policy_toml(&self.name, &self.permissions);
            // In a full implementation, we'd send GuardRegister here.
            // For now, we still use the fallback engine for action checks.
            self.daemon_connection = Some(conn);
        } else {
            info!("Daemon not available, using embedded fallback mode");
            self.daemon_connection = None;
        }

        // Run self-test to verify enforcement works.
        let engine = FallbackEngine::new(self.permissions.clone());
        let test_status = run_self_test(&engine);

        self.status = test_status.clone();
        let mut stats = self.stats.lock().unwrap();
        stats.activated_at = Some(Utc::now());
        stats.status = test_status;

        info!(
            "AgentGuard '{}' activated with status: {:?}",
            self.name, self.status
        );
        Ok(())
    }

    /// Check whether an action is allowed by the guard.
    pub fn check_action(&self, tool: &str, target: &str) -> ActionResult {
        let engine = FallbackEngine::new(self.permissions.clone());
        let result = engine.check_action(tool, target);

        match self.mode {
            GuardMode::Enforce => {
                let mut stats = self.stats.lock().unwrap();
                match &result {
                    ActionResult::Allow => {
                        stats.operations_allowed += 1;
                    }
                    ActionResult::Block(reason) => {
                        stats.operations_blocked += 1;
                        stats.blocked_details.push(BlockedOperation {
                            timestamp: Utc::now(),
                            tool: tool.to_string(),
                            target: target.to_string(),
                            reason: reason.clone(),
                        });
                    }
                    ActionResult::Monitored { .. } => {}
                }
                result
            }
            GuardMode::Monitor => {
                let would_block = matches!(result, ActionResult::Block(_));
                let reason = match &result {
                    ActionResult::Block(r) => Some(r.clone()),
                    _ => None,
                };
                let mut stats = self.stats.lock().unwrap();
                stats.operations_allowed += 1;
                stats.monitored_operations.push(MonitoredOperation {
                    timestamp: Utc::now(),
                    tool: tool.to_string(),
                    target: target.to_string(),
                    would_block,
                    reason: reason.clone(),
                });
                ActionResult::Monitored {
                    would_block,
                    reason,
                }
            }
        }
    }

    /// Deactivate the guard and clean up.
    pub fn deactivate(&mut self) -> Result<()> {
        if self.status == GuardStatus::Inactive {
            return Ok(());
        }

        info!("Deactivating AgentGuard '{}'", self.name);

        if let Some(ref mut conn) = self.daemon_connection {
            // In a full implementation, we'd send GuardDeregister here.
            conn.disconnect();
        }
        self.daemon_connection = None;
        self.status = GuardStatus::Inactive;

        let mut stats = self.stats.lock().unwrap();
        stats.status = GuardStatus::Inactive;

        info!("AgentGuard '{}' deactivated", self.name);
        Ok(())
    }

    /// Get current guard statistics.
    pub fn stats(&self) -> GuardStats {
        self.stats.lock().unwrap().clone()
    }

    /// Check if the guard is healthy.
    pub fn is_healthy(&self) -> bool {
        matches!(&self.status, GuardStatus::Active | GuardStatus::Degraded(_))
    }

    /// Get the current guard status.
    pub fn status(&self) -> &GuardStatus {
        &self.status
    }

    /// Get the guard name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the guard mode.
    pub fn mode(&self) -> GuardMode {
        self.mode
    }

    /// Analyze monitored operations and suggest minimal permissions.
    pub fn suggest_permissions(&self) -> SuggestedPermissions {
        let stats = self.stats.lock().unwrap();
        let mut suggested = SuggestedPermissions::default();

        let mut seen_reads = std::collections::HashSet::new();
        let mut seen_writes = std::collections::HashSet::new();
        let mut seen_tools = std::collections::HashSet::new();
        let mut seen_hosts = std::collections::HashSet::new();
        let mut seen_commands = std::collections::HashSet::new();

        for op in &stats.monitored_operations {
            if op.would_block {
                // Categorize by tool type.
                match op.tool.as_str() {
                    "read_file" | "file_read" | "Read" => {
                        if seen_reads.insert(op.target.clone()) {
                            suggested.file_read.push(op.target.clone());
                        }
                    }
                    "write_file" | "file_write" | "Write" | "Edit" => {
                        if seen_writes.insert(op.target.clone()) {
                            suggested.file_write.push(op.target.clone());
                        }
                    }
                    "run_command" | "execute" | "shell" | "bash" | "exec" | "terminal" | "sh" => {
                        if seen_commands.insert(op.tool.clone()) {
                            suggested.shell_commands.push(op.tool.clone());
                        }
                    }
                    "fetch" | "http_request" | "curl" | "wget" | "http" | "request" => {
                        if seen_hosts.insert(op.target.clone()) {
                            suggested.network_hosts.push(op.target.clone());
                        }
                    }
                    other => {
                        if seen_tools.insert(other.to_string()) {
                            suggested.tools.push(other.to_string());
                        }
                    }
                }
            }
        }

        suggested
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        if self.status != GuardStatus::Inactive {
            if let Err(e) = self.deactivate() {
                warn!("Error deactivating guard '{}' on drop: {e}", self.name);
            }
        }
    }
}
