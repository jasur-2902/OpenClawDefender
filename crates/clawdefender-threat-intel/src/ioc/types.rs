//! IoC (Indicator of Compromise) type definitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Severity level for an indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// Indicator
// ---------------------------------------------------------------------------

/// A single indicator of compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Indicator {
    /// IP address or CIDR range (e.g. "192.168.1.0/24").
    MaliciousIP(String),
    /// Domain name; supports wildcard prefix like "*.evil.com".
    MaliciousDomain(String),
    /// URL pattern (prefix match).
    MaliciousURL(String),
    /// SHA-256 file hash (hex, lowercase).
    MaliciousFileHash(String),
    /// File path glob pattern (e.g. "/tmp/.hidden*").
    SuspiciousFilePath(String),
    /// Process name (exact match, case-insensitive).
    SuspiciousProcessName(String),
    /// Regex pattern for command-line strings.
    SuspiciousCommandLine(String),
    /// Ordered tool call sequence to detect multi-step attacks.
    SuspiciousToolSequence(Vec<String>),
    /// Tool name + argument regex pattern.
    SuspiciousArgPattern { tool: String, pattern: String },
}

// ---------------------------------------------------------------------------
// IndicatorEntry
// ---------------------------------------------------------------------------

/// A fully described indicator with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorEntry {
    /// The indicator itself.
    pub indicator: Indicator,
    /// Severity classification.
    pub severity: Severity,
    /// Reference ID (e.g. blocklist advisory, CVE, etc.).
    pub threat_id: String,
    /// Human-readable description.
    pub description: String,
    /// When this entry was last updated.
    pub last_updated: DateTime<Utc>,
    /// Confidence in the indicator (0.0 – 1.0).
    pub confidence: f64,
    /// Known false-positive rate (0.0 – 1.0).
    pub false_positive_rate: f64,
    /// If true, this indicator never expires.
    pub permanent: bool,
    /// Optional expiration time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// MatchType
// ---------------------------------------------------------------------------

/// How the indicator was matched against the event data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchType {
    Exact,
    Prefix,
    Pattern,
    CIDR,
    Wildcard,
    Glob,
    Sequence,
}

impl fmt::Display for MatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact => write!(f, "exact"),
            Self::Prefix => write!(f, "prefix"),
            Self::Pattern => write!(f, "pattern"),
            Self::CIDR => write!(f, "cidr"),
            Self::Wildcard => write!(f, "wildcard"),
            Self::Glob => write!(f, "glob"),
            Self::Sequence => write!(f, "sequence"),
        }
    }
}

// ---------------------------------------------------------------------------
// IoCMatch
// ---------------------------------------------------------------------------

/// Result of matching an event against an indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoCMatch {
    /// The indicator entry that matched.
    pub indicator: IndicatorEntry,
    /// Identifier for the event that was matched.
    pub event_id: String,
    /// How the match occurred.
    pub match_type: MatchType,
    /// Combined confidence score taking into account indicator confidence
    /// and false-positive rate.
    pub combined_confidence: f64,
    /// The actual value from the event that triggered the match.
    pub matched_value: String,
}

// ---------------------------------------------------------------------------
// EventData
// ---------------------------------------------------------------------------

/// Simplified event data used for IoC matching.
/// Captures the relevant fields from audit events, network events, etc.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventData {
    /// Unique event identifier.
    pub event_id: String,
    /// Destination IP address (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<IpAddr>,
    /// Destination domain (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_domain: Option<String>,
    /// File path involved in the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// File hash (SHA-256, lowercase hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_hash: Option<String>,
    /// Process name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// Full command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// MCP tool name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// MCP tool arguments (serialised).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_args: Option<String>,
    /// Recent tool call sequence (most recent last).
    #[serde(default)]
    pub tool_sequence: Vec<String>,
}

// ---------------------------------------------------------------------------
// DatabaseStats
// ---------------------------------------------------------------------------

/// Statistics about the current IoC database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total_entries: usize,
    pub malicious_ips: usize,
    pub malicious_domains: usize,
    pub malicious_urls: usize,
    pub malicious_hashes: usize,
    pub suspicious_file_paths: usize,
    pub suspicious_process_names: usize,
    pub suspicious_command_lines: usize,
    pub suspicious_tool_sequences: usize,
    pub suspicious_arg_patterns: usize,
    pub last_updated: Option<DateTime<Utc>>,
}
