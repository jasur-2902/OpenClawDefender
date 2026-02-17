//! Types for the blocklist / known-malicious server registry.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Blocklist top-level
// ---------------------------------------------------------------------------

/// A versioned blocklist containing entries describing malicious, vulnerable,
/// or compromised MCP servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blocklist {
    /// Monotonically increasing version number.
    pub version: u64,
    /// ISO-8601 timestamp of when this blocklist was generated.
    pub updated_at: String,
    /// The entries in this blocklist.
    pub entries: Vec<BlocklistEntry>,
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// A single entry in the blocklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// Unique identifier, e.g. "CLAW-2026-001".
    pub id: String,
    /// Classification of the entry.
    pub entry_type: BlocklistEntryType,
    /// Human-readable name / package name of the server.
    pub name: String,
    /// Specific known-bad versions (exact match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,
    /// Semver range expression describing affected versions, e.g. "<1.5.0".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions_affected: Option<String>,
    /// Versions where the vulnerability was fixed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions_fixed: Option<Vec<String>>,
    /// Severity rating.
    pub severity: Severity,
    /// Human-readable description of the threat.
    pub description: String,
    /// ISO-8601 date when the issue was first discovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_date: Option<String>,
    /// Observable indicators of compromise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indicators: Option<ThreatIndicators>,
    /// Recommended remediation steps.
    pub remediation: String,
    /// Links to advisories, write-ups, etc.
    #[serde(default)]
    pub references: Vec<String>,
    /// npm package name if the server is distributed via npm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_package: Option<String>,
    /// Associated CVE identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    /// SHA-256 hashes of known-malicious binaries / scripts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_malicious: Option<Vec<String>>,
    /// Versions known to be safe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions_safe: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Entry type
// ---------------------------------------------------------------------------

/// Classification of a blocklist entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlocklistEntryType {
    /// The server is intentionally malicious.
    MaliciousServer,
    /// The server has a known vulnerability.
    VulnerableServer,
    /// A specific version of the server has been compromised (supply-chain).
    CompromisedVersion,
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Severity rating for a blocklist entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

// ---------------------------------------------------------------------------
// Threat indicators
// ---------------------------------------------------------------------------

/// Observable indicators of compromise associated with a blocklist entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicators {
    /// Suspicious network destinations (IPs, domains, URLs).
    #[serde(default)]
    pub network: Vec<String>,
    /// Suspicious file-system access patterns.
    #[serde(default)]
    pub file_access: Vec<String>,
    /// Free-form description of suspicious runtime behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
}

// ---------------------------------------------------------------------------
// Match result
// ---------------------------------------------------------------------------

/// Describes how a server matched a blocklist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocklistMatch {
    /// The blocklist entry that matched.
    pub entry_id: String,
    /// Human-readable name from the entry.
    pub entry_name: String,
    /// How the match was determined.
    pub match_type: MatchType,
    /// Recommended action to take.
    pub action: RecommendedAction,
    /// Severity from the entry.
    pub severity: Severity,
    /// Description from the entry.
    pub description: String,
    /// Remediation advice from the entry.
    pub remediation: String,
}

/// How a blocklist match was determined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    /// Exact package-name match (all versions blocked).
    ExactName,
    /// Exact version match.
    ExactVersion,
    /// Matched via semver range expression.
    SemverRange,
    /// SHA-256 hash of the binary matched.
    Sha256Hash,
}

/// Action the caller should take in response to a match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecommendedAction {
    /// Block execution entirely.
    Block,
    /// Warn the user but allow execution.
    Warn,
    /// Surface an alert / notification.
    Alert,
}

// ---------------------------------------------------------------------------
// Override mechanism
// ---------------------------------------------------------------------------

/// A user-initiated override allowing a blocked server to run despite a
/// blocklist match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistOverride {
    /// The blocklist entry ID being overridden (e.g. "CLAW-2026-001").
    pub entry_id: String,
    /// The server name the override applies to.
    pub server_name: String,
    /// Optional specific version the override is scoped to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The user must type this exact confirmation text.
    pub confirmation: String,
    /// ISO-8601 timestamp when the override was created.
    pub created_at: String,
    /// User-supplied reason for the override.
    pub reason: String,
}

/// The required confirmation text that must be supplied verbatim to create an
/// override.
pub const OVERRIDE_CONFIRMATION_TEXT: &str = "I understand the risk";
