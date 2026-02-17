//! Rule pack catalog — indexes available and installed community packs.

use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use crate::cache::FeedCache;
use crate::error::Result;

use super::types::{CommunityRulePack, InstalledPack, RulePackCategory, RulePackMetadata};

/// Persisted catalog of available and installed rule packs.
pub struct RuleCatalog {
    /// All packs advertised in the feed's `rules/index.json`.
    available: Vec<RulePackMetadata>,
    /// Locally installed packs.
    installed: Vec<InstalledPack>,
    /// Path to the installed-packs persistence file.
    installed_path: PathBuf,
}

/// Minimal wire format for the rules index coming from the feed.
#[derive(Debug, serde::Deserialize)]
struct FeedRulesIndex {
    #[serde(default)]
    packs: Vec<RulePackMetadata>,
}

impl RuleCatalog {
    /// Create a new catalog, loading installed-pack state from disk.
    pub fn new(data_dir: &Path) -> Result<Self> {
        let installed_path = data_dir.join("installed-packs.json");
        let installed = if installed_path.exists() {
            let data = std::fs::read_to_string(&installed_path)?;
            serde_json::from_str(&data).unwrap_or_else(|e| {
                warn!("corrupt installed-packs.json, resetting: {e}");
                Vec::new()
            })
        } else {
            Vec::new()
        };
        Ok(Self {
            available: Vec::new(),
            installed,
            installed_path,
        })
    }

    /// Create a catalog for testing (in-memory, no persistence).
    pub fn in_memory() -> Self {
        Self {
            available: Vec::new(),
            installed: Vec::new(),
            installed_path: PathBuf::from("/dev/null"),
        }
    }

    /// List all available packs from the last refresh.
    pub fn list_available(&self) -> &[RulePackMetadata] {
        &self.available
    }

    /// List all installed packs.
    pub fn list_installed(&self) -> &[InstalledPack] {
        &self.installed
    }

    /// Get a full pack by id from the feed cache.
    pub fn get_pack(&self, id: &str, feed_cache: &FeedCache) -> Result<Option<CommunityRulePack>> {
        // Packs are stored at rules/<id>.json in the feed cache.
        let relative = format!("rules/{id}.json");
        match feed_cache.read_file(&relative)? {
            Some(data) => {
                let pack: CommunityRulePack = serde_json::from_slice(&data)?;
                Ok(Some(pack))
            }
            None => Ok(None),
        }
    }

    /// Refresh the available-pack list from the local feed cache.
    pub fn refresh(&mut self, feed_cache: &FeedCache) -> Result<()> {
        match feed_cache.read_file("rules/index.json")? {
            Some(data) => {
                let index: FeedRulesIndex = serde_json::from_slice(&data)?;
                info!(count = index.packs.len(), "refreshed community rule catalog");
                self.available = index.packs;
            }
            None => {
                debug!("no rules/index.json in feed cache");
                self.available = Vec::new();
            }
        }
        Ok(())
    }

    /// Recommend packs based on detected server names.
    ///
    /// Matches server names (lowercased) against pack tags and
    /// `ServerSpecific` / `FrameworkSpecific` categories.
    pub fn recommend_for_servers(&self, server_names: &[String]) -> Vec<RulePackMetadata> {
        let lower_names: Vec<String> = server_names.iter().map(|s| s.to_lowercase()).collect();

        self.available
            .iter()
            .filter(|pack| {
                let dominated_categories = matches!(
                    pack.category,
                    RulePackCategory::ServerSpecific | RulePackCategory::FrameworkSpecific
                );
                if !dominated_categories {
                    return false;
                }
                // Check if any server name appears in the pack's tags.
                let pack_tags_lower: Vec<String> =
                    pack.tags.iter().map(|t| t.to_lowercase()).collect();
                lower_names
                    .iter()
                    .any(|name| pack_tags_lower.iter().any(|tag| tag.contains(name.as_str())))
            })
            .cloned()
            .collect()
    }

    // -- Mutation helpers used by the manager --

    /// Record a pack as installed (persists to disk).
    pub(crate) fn add_installed(&mut self, pack: InstalledPack) -> Result<()> {
        // Replace if already present.
        self.installed.retain(|p| p.metadata.id != pack.metadata.id);
        self.installed.push(pack);
        self.persist_installed()
    }

    /// Remove an installed pack record (persists to disk).
    pub(crate) fn remove_installed(&mut self, pack_id: &str) -> Result<()> {
        self.installed.retain(|p| p.metadata.id != pack_id);
        self.persist_installed()
    }

    /// Persist the installed list to disk.
    fn persist_installed(&self) -> Result<()> {
        if let Some(parent) = self.installed_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(&self.installed)?;
        std::fs::write(&self.installed_path, data)?;
        debug!("persisted installed-packs.json");
        Ok(())
    }
}
