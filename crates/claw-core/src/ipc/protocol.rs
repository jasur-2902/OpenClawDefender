//! IPC protocol definitions for daemon-UI communication.
//!
//! The daemon sends [`UiRequest`] messages to the menu-bar UI, and the UI
//! replies with [`UiResponse`] messages.

use serde::{Deserialize, Serialize};

use crate::event::Severity;

/// A request sent from the daemon to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UiRequest {
    /// Ask the user to make a policy decision.
    PromptUser {
        /// One-line summary of the event requiring a decision.
        event_summary: String,
        /// Name of the policy rule that triggered the prompt.
        rule_name: String,
        /// Available choices (e.g. `["Allow once", "Deny once", "Allow for session"]`).
        options: Vec<String>,
    },
    /// Display an alert in the UI.
    Alert {
        /// Severity of the alert.
        severity: Severity,
        /// Human-readable alert message.
        message: String,
        /// ID of the event that triggered the alert.
        event_id: String,
    },
    /// Push a status update to the UI dashboard.
    StatusUpdate {
        /// Total events blocked since daemon start.
        blocked_count: u64,
        /// Total events allowed since daemon start.
        allowed_count: u64,
        /// Total events that required a user prompt.
        prompted_count: u64,
        /// Seconds since daemon started.
        uptime_secs: u64,
    },
}

/// A response sent from the UI back to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UiResponse {
    /// The user made a policy decision.
    Decision {
        /// ID of the event the decision applies to.
        event_id: String,
        /// The user's chosen action.
        action: UserDecision,
    },
    /// The user requested a process kill.
    KillProcess {
        /// PID of the process to terminate.
        pid: u32,
    },
    /// The user dismissed an alert.
    Dismiss {
        /// ID of the dismissed event.
        event_id: String,
    },
}

/// A user's decision in response to a policy prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserDecision {
    /// Allow this one event only.
    AllowOnce,
    /// Deny this one event only.
    DenyOnce,
    /// Allow all similar events for the remainder of this session.
    AllowSession,
    /// Deny all similar events for the remainder of this session.
    DenySession,
    /// Create a permanent policy rule based on this decision.
    AddPolicyRule,
}
