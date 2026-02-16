//! Audit logging for policy decisions and events.
//!
//! Every event that flows through ClawAI is recorded as an [`AuditRecord`] in
//! a JSON-lines file for post-hoc analysis and compliance.

pub mod logger;

use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single audit log entry written to the JSON-lines audit file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Origin subsystem: `"mcp-proxy"`, `"eslogger"`, `"fsevents"`, or `"correlation"`.
    pub source: String,
    /// One-line human-readable summary of the event.
    pub event_summary: String,
    /// Full structured event data for deep inspection.
    pub event_details: serde_json::Value,
    /// Name of the policy rule that matched, if any.
    pub rule_matched: Option<String>,
    /// Action taken: `"allow"`, `"block"`, `"prompt"`, `"log"`.
    pub action_taken: String,
    /// Time from event receipt to policy decision, in milliseconds.
    pub response_time_ms: Option<u64>,
}

/// Filter for querying the audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Only include records after this time.
    pub from: Option<DateTime<Utc>>,
    /// Only include records before this time.
    pub to: Option<DateTime<Utc>>,
    /// Only include records from this source.
    pub source: Option<String>,
    /// Only include records with this action.
    pub action: Option<String>,
    /// Maximum number of records to return.
    pub limit: usize,
}

/// Aggregate statistics from the audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total events recorded.
    pub total_events: u64,
    /// Events that were blocked.
    pub blocked: u64,
    /// Events that were allowed.
    pub allowed: u64,
    /// Events that required a user prompt.
    pub prompted: u64,
    /// Event counts broken down by source subsystem.
    pub by_source: HashMap<String, u64>,
}

/// Trait for audit log backends.
pub trait AuditLogger: Send + Sync {
    /// Write a single audit record.
    fn log(&self, record: &AuditRecord) -> Result<()>;

    /// Query the audit log with the given filter.
    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditRecord>>;

    /// Return aggregate statistics.
    fn stats(&self) -> Result<AuditStats>;
}
