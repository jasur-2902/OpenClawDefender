//! Event types for ClawDefender.
//!
//! Events are the fundamental data unit flowing through ClawDefender. They originate
//! from two sources: MCP JSON-RPC messages intercepted by the proxy, and OS-level
//! operations observed by eslogger. The correlation module links these together.

pub mod correlation;
pub mod mcp;
pub mod os;

pub use correlation::{CorrelatedEvent, CorrelationStatus};
pub use mcp::{McpEvent, McpEventKind, ResourceRead, SamplingRequest, ToolCall};
pub use os::{OsEvent, OsEventKind};

use std::any::Any;

use crate::audit::AuditRecord;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity level for an event, used by the policy engine and UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Informational, no action required.
    Info,
    /// Low severity -- logged but unlikely to need intervention.
    Low,
    /// Medium severity -- worth reviewing.
    Medium,
    /// High severity -- likely requires user attention.
    High,
    /// Critical severity -- immediate action recommended.
    Critical,
}

/// Common trait implemented by every event flowing through ClawDefender.
pub trait Event: Send + Sync {
    /// When the event occurred.
    fn timestamp(&self) -> DateTime<Utc>;

    /// Human-readable source identifier (e.g. `"mcp-proxy"`, `"eslogger"`).
    fn source(&self) -> &str;

    /// Assessed severity of this event.
    fn severity(&self) -> Severity;

    /// Convert this event into an [`AuditRecord`] for persistent logging.
    fn to_audit_record(&self) -> AuditRecord;

    /// Downcast support: return self as `&dyn Any` for concrete type inspection.
    fn as_any(&self) -> &dyn Any;
}
