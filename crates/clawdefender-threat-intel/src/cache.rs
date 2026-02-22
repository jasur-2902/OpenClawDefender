//! Local file cache for downloaded threat feed data.

use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use crate::error::{Result, ThreatIntelError};
use crate::types::FeedManifest;

/// Default cache directory relative to the user's data directory.
const CACHE_SUBDIR: &str = "clawdefender/threat-intel";

/// Manages the local on-disk cache of threat feed data.
#[derive(Debug, Clone)]
pub struct FeedCache {
    /// Root directory of the cache.
    cache_dir: PathBuf,
}

impl FeedCache {
    /// Create a cache using the default platform data directory.
    pub fn default_location() -> Result<Self> {
        let base = dirs::data_local_dir().unwrap_or_else(|| {
            // Fallback for systems where dirs fails.
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".local/share")
        });
        let cache_dir = base.join(CACHE_SUBDIR);
        Ok(Self { cache_dir })
    }

    /// Create a cache at a specific directory (useful for testing).
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    /// Return the root cache directory path.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Ensure the cache directory exists.
    pub fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.cache_dir).map_err(|e| {
            ThreatIntelError::CacheError(format!(
                "failed to create cache dir {}: {e}",
                self.cache_dir.display()
            ))
        })
    }

    /// Read the cached manifest, if it exists.
    pub fn read_manifest(&self) -> Result<Option<FeedManifest>> {
        let path = self.cache_dir.join("manifest.json");
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)?;
        let manifest: FeedManifest = serde_json::from_str(&data)?;
        debug!(version = %manifest.version, "loaded cached manifest");
        Ok(Some(manifest))
    }

    /// Write a manifest to the cache.
    pub fn write_manifest(&self, manifest: &FeedManifest) -> Result<()> {
        self.ensure_dir()?;
        let path = self.cache_dir.join("manifest.json");
        let data = serde_json::to_string_pretty(manifest)?;
        std::fs::write(&path, data)?;
        info!(version = %manifest.version, "cached manifest");
        Ok(())
    }

    /// Read a cached file by relative path.
    pub fn read_file(&self, relative_path: &str) -> Result<Option<Vec<u8>>> {
        let path = self.cache_dir.join(relative_path);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&path)?;
        Ok(Some(data))
    }

    /// Write a file to the cache.
    pub fn write_file(&self, relative_path: &str, data: &[u8]) -> Result<()> {
        let path = self.cache_dir.join(relative_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, data)?;
        debug!(path = relative_path, "cached file");
        Ok(())
    }

    /// Write the signature file.
    pub fn write_signature(&self, sig_bytes: &[u8]) -> Result<()> {
        self.write_file("signatures/latest.sig", sig_bytes)
    }

    /// Read the cached signature file.
    pub fn read_signature(&self) -> Result<Option<Vec<u8>>> {
        self.read_file("signatures/latest.sig")
    }

    /// Check whether a cached file exists.
    pub fn has_file(&self, relative_path: &str) -> bool {
        self.cache_dir.join(relative_path).exists()
    }

    /// Store the next public key for key rotation persistence.
    pub fn write_next_key(&self, hex_key: &str) -> Result<()> {
        self.write_file("next_public_key.txt", hex_key.as_bytes())
    }

    /// Read the stored next public key, if any.
    pub fn read_next_key(&self) -> Result<Option<String>> {
        match self.read_file("next_public_key.txt")? {
            Some(data) => {
                let key = String::from_utf8(data).map_err(|e| {
                    ThreatIntelError::CacheError(format!("invalid UTF-8 in next key file: {e}"))
                })?;
                Ok(Some(key.trim().to_string()))
            }
            None => Ok(None),
        }
    }

    /// Check if the cache has any data at all.
    pub fn is_populated(&self) -> bool {
        self.cache_dir.join("manifest.json").exists()
    }

    /// Remove all cached data.
    pub fn clear(&self) -> Result<()> {
        if self.cache_dir.exists() {
            std::fs::remove_dir_all(&self.cache_dir)?;
            warn!("cleared threat intel cache");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn test_cache() -> (FeedCache, TempDir) {
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));
        (cache, dir)
    }

    #[test]
    fn test_empty_cache() {
        let (cache, _dir) = test_cache();
        assert!(!cache.is_populated());
        assert!(cache.read_manifest().unwrap().is_none());
    }

    #[test]
    fn test_write_and_read_manifest() {
        let (cache, _dir) = test_cache();
        let manifest = FeedManifest {
            version: "1.0.0".into(),
            last_updated: Utc::now(),
            feed_format_version: 1,
            files: HashMap::new(),
            next_public_key: None,
        };
        cache.write_manifest(&manifest).unwrap();
        assert!(cache.is_populated());
        let loaded = cache.read_manifest().unwrap().unwrap();
        assert_eq!(loaded.version, "1.0.0");
    }

    #[test]
    fn test_write_and_read_file() {
        let (cache, _dir) = test_cache();
        cache.ensure_dir().unwrap();
        cache
            .write_file("blocklist.json", b"{\"servers\":[]}")
            .unwrap();
        let data = cache.read_file("blocklist.json").unwrap().unwrap();
        assert_eq!(data, b"{\"servers\":[]}");
    }

    #[test]
    fn test_clear() {
        let (cache, _dir) = test_cache();
        let manifest = FeedManifest {
            version: "1.0.0".into(),
            last_updated: Utc::now(),
            feed_format_version: 1,
            files: HashMap::new(),
            next_public_key: None,
        };
        cache.write_manifest(&manifest).unwrap();
        assert!(cache.is_populated());
        cache.clear().unwrap();
        assert!(!cache.is_populated());
    }

    #[test]
    fn test_next_key_persistence() {
        let (cache, _dir) = test_cache();
        cache.ensure_dir().unwrap();
        assert!(cache.read_next_key().unwrap().is_none());
        cache.write_next_key("abcdef0123456789").unwrap();
        let key = cache.read_next_key().unwrap().unwrap();
        assert_eq!(key, "abcdef0123456789");
    }
}
