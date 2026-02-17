//! Telemetry data types.
//!
//! All types are designed to contain only aggregate, non-identifying data:
//! - No file paths (only categories)
//! - No server names (only blocklist entry IDs)
//! - No IP addresses, usernames, API keys, or identifiable data
//! - Installation ID is a random UUID, not derived from user data
//! - Reports contain only counts and distributions

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Configuration for the anonymous telemetry system.
///
/// Telemetry is **disabled by default** and requires explicit opt-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Whether telemetry is enabled. Default: `false` (OFF by default).
    #[serde(default)]
    pub enabled: bool,
    /// Endpoint URL for submitting telemetry reports.
    #[serde(default = "default_endpoint_url")]
    pub endpoint_url: String,
    /// How often to submit reports, in hours.
    #[serde(default = "default_report_interval_hours")]
    pub report_interval_hours: u64,
    /// Random UUID v4 generated on first opt-in. Cleared on opt-out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
}

fn default_endpoint_url() -> String {
    "https://feed.clawdefender.io/v1/telemetry".to_string()
}

fn default_report_interval_hours() -> u64 {
    24
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint_url: default_endpoint_url(),
            report_interval_hours: default_report_interval_hours(),
            installation_id: None,
        }
    }
}

/// A complete telemetry report ready for submission.
///
/// Contains only aggregate, non-identifying data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryReport {
    /// Random UUID identifying this installation (not derived from user data).
    pub installation_id: String,
    /// ISO 8601 date only (e.g. "2026-02-17"), no time component.
    pub report_date: String,
    /// Schema version for forward compatibility.
    pub report_version: u32,
    /// Blocklist match reports (entry IDs only, no server names).
    pub blocklist_matches: Vec<BlocklistMatchReport>,
    /// Aggregated anomaly detection data.
    pub anomaly_aggregate: AnomalyAggregate,
    /// Kill chain pattern trigger reports.
    pub killchain_triggers: Vec<KillchainTriggerReport>,
    /// Indicator of compromise match rate summary.
    pub ioc_match_rates: IoCMatchRates,
    /// Optional scanner finding summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner_summary: Option<ScannerSummary>,
}

/// A single blocklist match report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistMatchReport {
    /// Blocklist entry ID (e.g. "CLAW-2026-001"), NOT the server name.
    pub entry_id: String,
    /// Whether the entry was matched.
    pub matched: bool,
    /// ISO date of the match.
    pub date: String,
}

/// Aggregated anomaly detection statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnomalyAggregate {
    /// Number of events that exceeded the anomaly threshold.
    pub events_above_threshold: u64,
    /// The dimension with the highest anomaly contribution (e.g. "unknown_path").
    pub top_dimension: String,
    /// Percentage contribution of the top dimension.
    pub top_dimension_percentage: f64,
    /// Number of automatic blocks triggered by anomaly detection.
    pub auto_blocks: u64,
}

/// A kill chain pattern trigger report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillchainTriggerReport {
    /// Pattern ID (e.g. "KC-001").
    pub pattern_id: String,
    /// Number of kill chain steps matched.
    pub steps_matched: u32,
    /// User decision: "allowed", "denied", or "auto_blocked".
    pub user_decision: String,
}

/// Indicator of compromise match rate summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoCMatchRates {
    /// Total number of IoC matches.
    pub total_matches: u64,
    /// Network-based IoC matches.
    pub network_matches: u64,
    /// File-based IoC matches.
    pub file_matches: u64,
    /// Behavioral IoC matches.
    pub behavioral_matches: u64,
}

/// Summary of scanner findings (no server names or file paths).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScannerSummary {
    /// Categories of findings (e.g. "path_traversal", "injection").
    pub finding_categories: Vec<String>,
    /// Count of findings by severity level.
    pub severity_counts: HashMap<String, u64>,
}

/// Current schema version for telemetry reports.
pub const REPORT_SCHEMA_VERSION: u32 = 1;
