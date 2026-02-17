//! Pattern versioning and tracking types.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Pattern source
// ---------------------------------------------------------------------------

/// Where a pattern originated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternSource {
    /// Compiled into the binary.
    BuiltIn,
    /// Loaded from the threat feed.
    Feed,
}

// ---------------------------------------------------------------------------
// Dynamic kill chain pattern
// ---------------------------------------------------------------------------

/// Severity level mirroring core's `killchain::Severity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// Event type mirroring core's `killchain::StepEventType`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepEventType {
    FileRead,
    FileWrite,
    FileList,
    NetworkConnect,
    ShellExec,
    SamplingResponse,
    AnyToolCall,
}

/// A single step in a dynamic attack pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicPatternStep {
    pub event_type: StepEventType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_count: Option<usize>,
}

/// A kill chain attack pattern loaded from the threat feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicAttackPattern {
    /// Unique identifier for deduplication.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Severity level.
    pub severity: Severity,
    /// Time window in seconds for the pattern to match.
    pub window_seconds: u64,
    /// Human-readable explanation of why this pattern is dangerous.
    pub explanation: String,
    /// Ordered steps that constitute the attack pattern.
    pub steps: Vec<DynamicPatternStep>,
    /// Where this pattern came from.
    pub source: PatternSource,
    /// Pattern version string.
    pub version: String,
}

// ---------------------------------------------------------------------------
// Dynamic injection pattern
// ---------------------------------------------------------------------------

/// An injection signature loaded from the threat feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicInjectionPattern {
    /// Unique identifier for deduplication.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Regex pattern string.
    pub regex: String,
    /// Severity weight (0.0 - 1.0).
    pub severity: f64,
    /// Description of what this pattern detects.
    pub description: String,
    /// Optional language tag (e.g. "zh", "ar", "es") for multilingual patterns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// When this pattern was added to the feed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_date: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Pre-seeded behavioral profile
// ---------------------------------------------------------------------------

/// A pre-seeded behavioral profile for a known MCP server package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreSeededProfile {
    /// Package identifier (e.g. "filesystem-server", "github-mcp").
    pub server_package: String,
    /// Version of this profile definition.
    pub profile_version: String,
    /// Expected tool names this server exposes.
    #[serde(default)]
    pub expected_tools: Vec<String>,
    /// Expected file territory (directory prefixes).
    #[serde(default)]
    pub expected_file_territory: Vec<String>,
    /// Whether this server typically makes network connections.
    #[serde(default)]
    pub expected_network: bool,
    /// Whether this server typically runs shell commands.
    #[serde(default)]
    pub expected_shell: bool,
    /// Expected request rate statistics.
    #[serde(default)]
    pub expected_rate: RateStats,
    /// Human-readable notes about this server's expected behavior.
    #[serde(default)]
    pub notes: String,
}

/// Request rate statistics for a pre-seeded profile.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateStats {
    /// Mean inter-request gap in milliseconds.
    pub mean_ms: f64,
    /// Standard deviation of inter-request gap in milliseconds.
    pub stddev_ms: f64,
}

// ---------------------------------------------------------------------------
// Pattern versioning
// ---------------------------------------------------------------------------

/// Version info for a single pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternVersion {
    /// Pattern identifier.
    pub id: String,
    /// Semantic version string.
    pub version: String,
    /// Where this pattern came from.
    pub source: PatternSource,
    /// When this version was installed.
    pub updated_at: DateTime<Utc>,
}

/// Tracks installed pattern versions and detects updates.
#[derive(Debug, Clone, Default)]
pub struct VersionTracker {
    /// Currently installed pattern versions keyed by pattern ID.
    versions: HashMap<String, PatternVersion>,
    /// Pattern IDs that are pinned (won't be updated automatically).
    pinned: HashMap<String, String>,
}

impl VersionTracker {
    /// Create a new empty version tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pattern version. Returns `true` if this is a new or updated version.
    pub fn register(&mut self, pv: PatternVersion) -> bool {
        if let Some(pinned_version) = self.pinned.get(&pv.id) {
            if &pv.version != pinned_version {
                // Pinned to a different version; reject the update.
                return false;
            }
        }

        let is_update = match self.versions.get(&pv.id) {
            Some(existing) => existing.version != pv.version,
            None => true,
        };

        self.versions.insert(pv.id.clone(), pv);
        is_update
    }

    /// Pin a pattern to a specific version. Future updates to a different
    /// version will be rejected.
    pub fn pin(&mut self, pattern_id: &str, version: &str) {
        self.pinned
            .insert(pattern_id.to_string(), version.to_string());
    }

    /// Unpin a pattern, allowing it to be updated freely.
    pub fn unpin(&mut self, pattern_id: &str) {
        self.pinned.remove(pattern_id);
    }

    /// Check whether a pattern ID is pinned.
    pub fn is_pinned(&self, pattern_id: &str) -> bool {
        self.pinned.contains_key(pattern_id)
    }

    /// Get the installed version for a pattern.
    pub fn get_version(&self, pattern_id: &str) -> Option<&PatternVersion> {
        self.versions.get(pattern_id)
    }

    /// Return the number of tracked patterns.
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Return whether the tracker is empty.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// Return all tracked versions.
    pub fn all_versions(&self) -> impl Iterator<Item = &PatternVersion> {
        self.versions.values()
    }
}
