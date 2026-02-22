//! Core types for the AgentGuard system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Glob pattern for matching file paths (e.g. `~/Projects/**`).
pub type PathPattern = String;
/// Domain pattern for matching hosts (e.g. `api.anthropic.com`).
pub type HostPattern = String;
/// Command pattern for matching shell commands (e.g. `git *`).
pub type CommandPattern = String;

/// The main agent guard that enforces permissions for an AI agent.
pub struct AgentGuard {
    pub(crate) name: String,
    pub(crate) permissions: PermissionSet,
    pub(crate) status: GuardStatus,
    pub(crate) daemon_connection: Option<DaemonConnection>,
    #[allow(dead_code)]
    pub(crate) policy_id: String,
    pub(crate) stats: Arc<Mutex<GuardStats>>,
    pub(crate) mode: GuardMode,
}

/// Set of permissions that define what an agent is allowed to do.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionSet {
    /// File paths allowed for reading (glob patterns).
    pub file_read: Vec<PathPattern>,
    /// File paths allowed for writing (glob patterns).
    pub file_write: Vec<PathPattern>,
    /// File paths allowed for deletion (glob patterns).
    pub file_delete: Vec<PathPattern>,
    /// Shell execution policy.
    pub shell_execute: ShellPolicy,
    /// Network access policy.
    pub network: NetworkPolicy,
    /// List of allowed tool names.
    pub tools: Vec<String>,
    /// Maximum allowed file size in bytes.
    pub max_file_size: Option<u64>,
    /// Rate limit: max files per minute.
    pub max_files_per_minute: Option<u32>,
    /// Rate limit: max network requests per minute.
    pub max_network_requests_per_minute: Option<u32>,
}

/// Policy for shell command execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShellPolicy {
    /// Deny all shell execution.
    #[default]
    Deny,
    /// Allow only commands matching these patterns.
    AllowList(Vec<CommandPattern>),
    /// Allow with user approval required.
    AllowWithApproval,
}

/// Policy for network access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Hosts that are allowed (glob patterns).
    pub allowed_hosts: Vec<HostPattern>,
    /// Ports that are allowed.
    pub allowed_ports: Vec<u16>,
    /// If true, deny all network access regardless of other settings.
    pub deny_all: bool,
}

/// Guard operational status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardStatus {
    /// Guard is not active (default).
    #[default]
    Inactive,
    /// Guard is active and enforcing.
    Active,
    /// Guard is active but operating in degraded mode.
    Degraded(String),
    /// Guard failed to activate or encountered a fatal error.
    Failed(String),
}

/// Guard enforcement mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardMode {
    /// Enforce permissions (block disallowed operations).
    #[default]
    Enforce,
    /// Monitor only (log but don't block).
    Monitor,
}

/// Connection to the ClawDefender daemon.
pub struct DaemonConnection {
    pub(crate) socket_path: String,
    pub(crate) connected: bool,
}

/// Statistics tracked by the guard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GuardStats {
    /// When the guard was activated.
    pub activated_at: Option<DateTime<Utc>>,
    /// Number of operations allowed.
    pub operations_allowed: u64,
    /// Number of operations blocked.
    pub operations_blocked: u64,
    /// Details of blocked operations.
    pub blocked_details: Vec<BlockedOperation>,
    /// Number of anomaly alerts raised.
    pub anomaly_alerts: u64,
    /// Current guard status.
    pub status: GuardStatus,
    /// Operations monitored in Monitor mode.
    pub monitored_operations: Vec<MonitoredOperation>,
}

/// Details of a blocked operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedOperation {
    /// When the operation was blocked.
    pub timestamp: DateTime<Utc>,
    /// Tool that attempted the operation.
    pub tool: String,
    /// Target of the operation (path, host, etc.).
    pub target: String,
    /// Why it was blocked.
    pub reason: String,
}

/// Details of a monitored operation (Monitor mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredOperation {
    /// When the operation was observed.
    pub timestamp: DateTime<Utc>,
    /// Tool that performed the operation.
    pub tool: String,
    /// Target of the operation.
    pub target: String,
    /// Whether this would have been blocked in Enforce mode.
    pub would_block: bool,
    /// Reason it would have been blocked (if applicable).
    pub reason: Option<String>,
}

/// Result of checking an action against guard permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionResult {
    /// Action is allowed.
    Allow,
    /// Action is blocked with the given reason.
    Block(String),
    /// Action is monitored (Monitor mode) — would have been blocked.
    Monitored {
        would_block: bool,
        reason: Option<String>,
    },
}

/// Suggested permissions based on Monitor mode observations.
#[derive(Debug, Clone, Default)]
pub struct SuggestedPermissions {
    /// Suggested file read patterns.
    pub file_read: Vec<PathPattern>,
    /// Suggested file write patterns.
    pub file_write: Vec<PathPattern>,
    /// Suggested tools.
    pub tools: Vec<String>,
    /// Suggested network hosts.
    pub network_hosts: Vec<HostPattern>,
    /// Suggested shell commands.
    pub shell_commands: Vec<CommandPattern>,
}
