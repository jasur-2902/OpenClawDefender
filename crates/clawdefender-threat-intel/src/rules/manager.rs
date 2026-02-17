//! Rule pack lifecycle manager — install, uninstall, update.

use chrono::Utc;
use tracing::{debug, info};

use crate::cache::FeedCache;
use crate::error::{Result, ThreatIntelError};

use super::catalog::RuleCatalog;
use super::types::{CommunityRule, InstalledPack};

/// Manages the install/uninstall/update lifecycle of community rule packs.
pub struct RulePackManager {
    /// Catalog of available and installed packs.
    catalog: RuleCatalog,
    /// Feed cache to fetch pack data from.
    feed_cache: FeedCache,
    /// Rules currently active from installed community packs, keyed by pack id.
    active_rules: std::collections::HashMap<String, Vec<CommunityRule>>,
}

impl RulePackManager {
    /// Create a new manager.
    pub fn new(catalog: RuleCatalog, feed_cache: FeedCache) -> Self {
        Self {
            catalog,
            feed_cache,
            active_rules: std::collections::HashMap::new(),
        }
    }

    /// Get a reference to the catalog.
    pub fn catalog(&self) -> &RuleCatalog {
        &self.catalog
    }

    /// Get a mutable reference to the catalog (e.g. for refresh).
    pub fn catalog_mut(&mut self) -> &mut RuleCatalog {
        &mut self.catalog
    }

    /// Install a community rule pack by its id.
    ///
    /// Fetches the pack from the feed cache, records it as installed, and
    /// stores its rules in the active set.
    pub fn install(&mut self, pack_id: &str) -> Result<()> {
        // Check if already installed.
        if self.active_rules.contains_key(pack_id) {
            debug!(pack_id, "pack already installed, skipping");
            return Ok(());
        }

        let pack = self
            .catalog
            .get_pack(pack_id, &self.feed_cache)?
            .ok_or_else(|| {
                ThreatIntelError::CacheError(format!("pack '{pack_id}' not found in feed cache"))
            })?;

        let installed = InstalledPack {
            metadata: pack.metadata.clone(),
            installed_at: Utc::now(),
            auto_update: true,
        };

        self.catalog.add_installed(installed)?;
        self.active_rules
            .insert(pack_id.to_string(), pack.rules.clone());
        info!(pack_id, rules = pack.rules.len(), "installed community rule pack");
        Ok(())
    }

    /// Uninstall a community rule pack.
    pub fn uninstall(&mut self, pack_id: &str) -> Result<()> {
        self.active_rules.remove(pack_id);
        self.catalog.remove_installed(pack_id)?;
        info!(pack_id, "uninstalled community rule pack");
        Ok(())
    }

    /// Update all installed packs that have a newer version in the catalog.
    ///
    /// Returns the list of pack ids that were updated.
    pub fn update_all(&mut self) -> Result<Vec<String>> {
        let installed: Vec<(String, String)> = self
            .catalog
            .list_installed()
            .iter()
            .filter(|p| p.auto_update)
            .map(|p| (p.metadata.id.clone(), p.metadata.version.clone()))
            .collect();

        let mut updated = Vec::new();
        for (id, current_version) in installed {
            // Check if there is a newer version available.
            let newer = self
                .catalog
                .list_available()
                .iter()
                .any(|a| a.id == id && a.version != current_version);
            if newer {
                self.update(&id)?;
                updated.push(id);
            }
        }
        Ok(updated)
    }

    /// Update a specific pack to the latest version in the feed cache.
    pub fn update(&mut self, pack_id: &str) -> Result<()> {
        let pack = self
            .catalog
            .get_pack(pack_id, &self.feed_cache)?
            .ok_or_else(|| {
                ThreatIntelError::CacheError(format!(
                    "pack '{pack_id}' not found in feed cache for update"
                ))
            })?;

        let installed = InstalledPack {
            metadata: pack.metadata.clone(),
            installed_at: Utc::now(),
            auto_update: true,
        };

        self.catalog.add_installed(installed)?;
        self.active_rules
            .insert(pack_id.to_string(), pack.rules.clone());
        info!(pack_id, version = %pack.metadata.version, "updated community rule pack");
        Ok(())
    }

    /// Get the active community rules for a specific installed pack.
    pub fn get_installed_rules(&self, pack_id: &str) -> Vec<CommunityRule> {
        self.active_rules
            .get(pack_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all active community rules across all installed packs.
    pub fn all_active_rules(&self) -> Vec<CommunityRule> {
        self.active_rules.values().flatten().cloned().collect()
    }
}
