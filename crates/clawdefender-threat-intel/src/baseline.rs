//! Bundled baseline feed for first-run / no-internet scenarios.

use crate::error::Result;
use crate::types::{Blocklist, FeedManifest};

/// Bundled manifest.json compiled into the binary.
const BASELINE_MANIFEST: &str = include_str!("../baseline/manifest.json");

/// Bundled blocklist.json compiled into the binary.
const BASELINE_BLOCKLIST: &str = include_str!("../baseline/blocklist.json");

/// Load the bundled baseline manifest.
pub fn baseline_manifest() -> Result<FeedManifest> {
    let manifest: FeedManifest = serde_json::from_str(BASELINE_MANIFEST)?;
    Ok(manifest)
}

/// Load the bundled baseline blocklist.
pub fn baseline_blocklist() -> Result<Blocklist> {
    let blocklist: Blocklist = serde_json::from_str(BASELINE_BLOCKLIST)?;
    Ok(blocklist)
}

/// Populate a cache directory with baseline data if it is empty.
pub fn populate_cache_from_baseline(cache: &crate::cache::FeedCache) -> Result<bool> {
    if cache.is_populated() {
        return Ok(false);
    }
    let manifest = baseline_manifest()?;
    cache.write_manifest(&manifest)?;
    cache.write_file("blocklist.json", BASELINE_BLOCKLIST.as_bytes())?;
    tracing::info!("populated cache from bundled baseline feed");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::FeedCache;
    use tempfile::TempDir;

    #[test]
    fn test_baseline_manifest_loads() {
        let manifest = baseline_manifest().unwrap();
        assert_eq!(manifest.version, "1.0.0");
    }

    #[test]
    fn test_baseline_blocklist_loads() {
        let blocklist = baseline_blocklist().unwrap();
        assert!(blocklist.servers.is_empty());
    }

    #[test]
    fn test_populate_cache_from_baseline() {
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));
        assert!(!cache.is_populated());

        let populated = populate_cache_from_baseline(&cache).unwrap();
        assert!(populated);
        assert!(cache.is_populated());

        // Second call should be a no-op.
        let populated2 = populate_cache_from_baseline(&cache).unwrap();
        assert!(!populated2);
    }
}
