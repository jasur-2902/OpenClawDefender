//! Community rule pack type definitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Action a community rule dictates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Block,
    Prompt,
    Allow,
    Log,
}

/// A single community-contributed rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityRule {
    /// Unique name for this rule within its pack.
    pub name: String,
    /// Action to take when this rule matches.
    pub action: RuleAction,
    /// MCP methods this rule applies to (e.g. `["tools/call"]`).
    #[serde(default)]
    pub methods: Vec<String>,
    /// Resource path glob patterns this rule matches.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Human-readable message shown to the user or logged.
    pub message: String,
    /// Tags for categorisation and filtering.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Category of a community rule pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RulePackCategory {
    Security,
    Privacy,
    Development,
    ServerSpecific,
    FrameworkSpecific,
}

/// Metadata describing a community rule pack (shown in the catalog).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePackMetadata {
    /// Unique identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Semantic version.
    pub version: String,
    /// Author name or handle.
    pub author: String,
    /// Short description.
    pub description: String,
    /// Category.
    pub category: RulePackCategory,
    /// Tags for search/filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Compatible ClawDefender version range (semver).
    #[serde(default)]
    pub compatibility: Option<String>,
    /// Number of times this pack has been downloaded.
    #[serde(default)]
    pub download_count: u64,
}

/// A full community rule pack (metadata + rules).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityRulePack {
    /// Pack metadata.
    #[serde(flatten)]
    pub metadata: RulePackMetadata,
    /// The rules contained in this pack.
    pub rules: Vec<CommunityRule>,
}

/// Record of a locally installed pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPack {
    /// Metadata of the installed pack.
    #[serde(flatten)]
    pub metadata: RulePackMetadata,
    /// When the pack was installed.
    pub installed_at: DateTime<Utc>,
    /// Whether the pack should be automatically updated.
    #[serde(default = "default_true")]
    pub auto_update: bool,
}

fn default_true() -> bool {
    true
}

/// Where a policy rule originated, used for precedence ordering.
///
/// Precedence (highest to lowest): User > ThreatIntel > Community > Default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RuleSource {
    /// Rules defined by the end user (highest precedence).
    User = 3,
    /// Rules from the threat intelligence feed.
    ThreatIntel = 2,
    /// Rules from community packs.
    Community = 1,
    /// Built-in default rules (lowest precedence).
    Default = 0,
}
