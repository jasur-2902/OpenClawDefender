//! OS-level event types observed by eslogger / Endpoint Security.
//!
//! These events capture filesystem, process, and network operations performed
//! by AI-agent child processes on macOS.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use std::any::Any;

use crate::audit::AuditRecord;
use crate::event::{Event, Severity};

/// An event originating from the macOS Endpoint Security / eslogger subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsEvent {
    /// When the event was observed.
    pub timestamp: DateTime<Utc>,
    /// Process ID of the acting process.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Absolute path of the process binary.
    pub process_path: String,
    /// Classified kind of OS operation.
    pub kind: OsEventKind,
    /// Optional code-signing identity.
    pub signing_id: Option<String>,
    /// Optional Apple Team ID.
    pub team_id: Option<String>,
}

/// Classification of an OS-level operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OsEventKind {
    /// Process execution.
    Exec {
        /// Path of the binary being executed.
        target_path: String,
        /// Command-line arguments.
        args: Vec<String>,
    },
    /// File open.
    Open {
        /// Path being opened.
        path: String,
        /// Open flags (O_RDONLY, O_WRONLY, etc.).
        flags: u32,
    },
    /// File close.
    Close {
        /// Path being closed.
        path: String,
    },
    /// File rename.
    Rename {
        /// Original path.
        source: String,
        /// Destination path.
        dest: String,
    },
    /// File deletion.
    Unlink {
        /// Path being deleted.
        path: String,
    },
    /// Network connection.
    Connect {
        /// Remote address.
        address: String,
        /// Remote port.
        port: u16,
        /// Protocol (e.g. `"tcp"`, `"udp"`).
        protocol: String,
    },
    /// Process fork.
    Fork {
        /// PID of the newly created child.
        child_pid: u32,
    },
    /// Process exit.
    Exit {
        /// Exit status code.
        status: i32,
    },
    /// Pseudoterminal grant.
    PtyGrant {
        /// Path of the PTY device.
        path: String,
    },
    /// File mode change (chmod).
    SetMode {
        /// Path whose mode is being changed.
        path: String,
        /// New POSIX mode bits.
        mode: u32,
    },
    /// Kernel extension load.
    Kextload {
        /// Bundle identifier of the kext.
        identifier: String,
    },
    /// Set-UID bit change.
    Setuid {
        /// Path of the affected file.
        path: String,
    },
    /// Set-GID bit change.
    Setgid {
        /// Path of the affected file.
        path: String,
    },
    /// Hard link creation.
    Link {
        /// Path of the new hard link.
        path: String,
    },
    /// Symbolic link creation.
    Symlink {
        /// Path of the new symbolic link.
        path: String,
    },
    /// Background Task Management login item added (macOS 13+).
    BtmLaunchItemAdd {
        /// Path or URL of the launch item.
        item_url: String,
        /// Type of item: "agent", "daemon", "login_item", etc.
        item_type: String,
    },
    /// User login event.
    LoginLogin,
    /// User logout event.
    LoginLogout,
    /// Authentication event (e.g. sudo, unlock).
    Authentication {
        /// Whether the authentication succeeded.
        success: bool,
    },
    /// XProtect malware detection.
    XpMalwareDetected {
        /// Description or name of the detected malware.
        name: String,
    },
    /// User bypassed Gatekeeper warning.
    GatekeeperUserOverride {
        /// Path of the file that was allowed.
        path: String,
    },
    /// Task port acquisition (process injection vector).
    GetTask {
        /// PID of the target process.
        target_pid: u32,
    },
    /// Process tracing (debugger/injection).
    Trace {
        /// PID of the target process.
        target_pid: u32,
    },
    /// Process inspection/check.
    ProcCheck {
        /// PID of the target process.
        target_pid: u32,
    },
}

impl Event for OsEvent {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn source(&self) -> &str {
        "eslogger"
    }

    fn severity(&self) -> Severity {
        match &self.kind {
            OsEventKind::Kextload { .. } | OsEventKind::XpMalwareDetected { .. } => {
                Severity::Critical
            }
            OsEventKind::GatekeeperUserOverride { .. }
            | OsEventKind::Setuid { .. }
            | OsEventKind::Setgid { .. }
            | OsEventKind::GetTask { .. } => Severity::High,
            OsEventKind::Exec { .. }
            | OsEventKind::Connect { .. }
            | OsEventKind::Unlink { .. }
            | OsEventKind::BtmLaunchItemAdd { .. }
            | OsEventKind::Trace { .. }
            | OsEventKind::Link { .. }
            | OsEventKind::Symlink { .. } => Severity::Medium,
            OsEventKind::Rename { .. }
            | OsEventKind::SetMode { .. }
            | OsEventKind::PtyGrant { .. }
            | OsEventKind::Authentication { .. }
            | OsEventKind::LoginLogin
            | OsEventKind::LoginLogout
            | OsEventKind::ProcCheck { .. } => Severity::Low,
            OsEventKind::Open { .. }
            | OsEventKind::Close { .. }
            | OsEventKind::Fork { .. }
            | OsEventKind::Exit { .. } => Severity::Info,
        }
    }

    fn to_audit_record(&self) -> AuditRecord {
        AuditRecord {
            timestamp: self.timestamp,
            source: "eslogger".to_string(),
            event_summary: match &self.kind {
                OsEventKind::Exec { target_path, .. } => {
                    format!("exec: {target_path} (pid={})", self.pid)
                }
                OsEventKind::Open { path, .. } => format!("open: {path}"),
                OsEventKind::Close { path } => format!("close: {path}"),
                OsEventKind::Rename { source, dest } => format!("rename: {source} -> {dest}"),
                OsEventKind::Unlink { path } => format!("unlink: {path}"),
                OsEventKind::Connect {
                    address,
                    port,
                    protocol,
                } => format!("connect: {protocol}://{address}:{port}"),
                OsEventKind::Fork { child_pid } => format!("fork: child_pid={child_pid}"),
                OsEventKind::Exit { status } => format!("exit: status={status}"),
                OsEventKind::PtyGrant { path } => format!("pty_grant: {path}"),
                OsEventKind::SetMode { path, mode } => format!("setmode: {path} -> {mode:#o}"),
                OsEventKind::Kextload { identifier } => {
                    format!("kextload: {identifier}")
                }
                OsEventKind::Setuid { path } => format!("setuid: {path}"),
                OsEventKind::Setgid { path } => format!("setgid: {path}"),
                OsEventKind::Link { path } => format!("link: {path}"),
                OsEventKind::Symlink { path } => format!("symlink: {path}"),
                OsEventKind::BtmLaunchItemAdd {
                    item_url,
                    item_type,
                } => {
                    format!("btm_launch_item_add: {item_type} {item_url}")
                }
                OsEventKind::LoginLogin => "login_login".to_string(),
                OsEventKind::LoginLogout => "login_logout".to_string(),
                OsEventKind::Authentication { success } => {
                    format!("authentication: success={success}")
                }
                OsEventKind::XpMalwareDetected { name } => {
                    format!("xp_malware_detected: {name}")
                }
                OsEventKind::GatekeeperUserOverride { path } => {
                    format!("gatekeeper_user_override: {path}")
                }
                OsEventKind::GetTask { target_pid } => {
                    format!("get_task: target_pid={target_pid}")
                }
                OsEventKind::Trace { target_pid } => {
                    format!("trace: target_pid={target_pid}")
                }
                OsEventKind::ProcCheck { target_pid } => {
                    format!("proc_check: target_pid={target_pid}")
                }
            },
            event_details: serde_json::to_value(self).unwrap_or_default(),
            rule_matched: None,
            action_taken: String::new(),
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
            behavioral: None,
            injection_scan: None,
            threat_intel: None,
            network_connection: None,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
