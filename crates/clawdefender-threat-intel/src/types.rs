//! Feed format type definitions.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// The top-level manifest describing the feed contents and file hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedManifest {
    /// Semantic version string for the feed.
    pub version: String,
    /// Timestamp of the last feed update.
    pub last_updated: DateTime<Utc>,
    /// Feed format version (for forward compatibility).
    #[serde(default = "default_feed_format_version")]
    pub feed_format_version: u32,
    /// Map of relative file paths to their metadata.
    pub files: HashMap<String, FileEntry>,
    /// Optional next public key for key rotation (hex-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_public_key: Option<String>,
}

fn default_feed_format_version() -> u32 {
    1
}

/// Metadata for a single file in the feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// SHA-256 hex digest.
    pub sha256: String,
    /// File size in bytes.
    pub size: u64,
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

/// Known malicious MCP servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blocklist {
    pub version: String,
    pub servers: Vec<BlockedServer>,
}

/// A single blocked server entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedServer {
    /// Unique identifier or URL pattern for the server.
    pub id: String,
    /// Human-readable reason for blocking.
    pub reason: String,
    /// Severity level.
    #[serde(default = "default_severity")]
    pub severity: String,
    /// When this entry was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<DateTime<Utc>>,
}

fn default_severity() -> String {
    "HIGH".to_string()
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// Index of community rule packs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesIndex {
    pub version: String,
    pub packs: Vec<RulePack>,
}

/// A community rule pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    pub id: String,
    pub name: String,
    pub description: String,
    pub file: String,
    pub rule_count: u32,
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

/// Kill chain pattern definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPatterns {
    pub version: String,
    pub patterns: Vec<KillChainPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub stages: Vec<String>,
    pub severity: String,
}

/// Injection signature definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionSignatures {
    pub version: String,
    pub signatures: Vec<InjectionSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionSignature {
    pub id: String,
    pub pattern: String,
    pub description: String,
    pub severity: String,
}

// ---------------------------------------------------------------------------
// IoCs (Indicators of Compromise)
// ---------------------------------------------------------------------------

/// Malicious host indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousHosts {
    pub version: String,
    pub hosts: Vec<HostIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIndicator {
    pub host: String,
    pub reason: String,
    pub severity: String,
}

/// Malicious hash indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousHashes {
    pub version: String,
    pub hashes: Vec<HashIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashIndicator {
    pub hash: String,
    pub algorithm: String,
    pub description: String,
    pub severity: String,
}

/// Suspicious tool indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousTools {
    pub version: String,
    pub tools: Vec<ToolIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolIndicator {
    pub name: String,
    pub description: String,
    pub severity: String,
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

/// Index of behavioral profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilesIndex {
    pub version: String,
    pub profiles: Vec<ProfileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub file: String,
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Threat intelligence feed configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    /// Whether the threat intel subsystem is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Feed base URL.
    #[serde(default = "default_feed_url")]
    pub feed_url: String,
    /// How often to check for updates, in hours.
    #[serde(default = "default_update_interval_hours")]
    pub update_interval_hours: u64,
    /// Automatically apply downloaded rule packs.
    #[serde(default = "default_true")]
    pub auto_apply_rules: bool,
    /// Automatically apply downloaded blocklist.
    #[serde(default = "default_true")]
    pub auto_apply_blocklist: bool,
    /// Automatically apply downloaded patterns.
    #[serde(default = "default_true")]
    pub auto_apply_patterns: bool,
    /// Automatically apply downloaded IoCs.
    #[serde(default = "default_true")]
    pub auto_apply_iocs: bool,
    /// Send a notification when the feed is updated.
    #[serde(default = "default_true")]
    pub notify_on_update: bool,
}

fn default_true() -> bool {
    true
}

fn default_feed_url() -> String {
    "https://feed.clawdefender.io/v1/".to_string()
}

fn default_update_interval_hours() -> u64 {
    6
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            feed_url: default_feed_url(),
            update_interval_hours: default_update_interval_hours(),
            auto_apply_rules: true,
            auto_apply_blocklist: true,
            auto_apply_patterns: true,
            auto_apply_iocs: true,
            notify_on_update: true,
        }
    }
}
