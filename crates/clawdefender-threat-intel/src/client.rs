//! Async HTTP client for fetching threat feed updates.

use std::collections::HashMap;

use reqwest::Client;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::cache::FeedCache;
use crate::error::{Result, ThreatIntelError};
use crate::signature::{hex_encode, FeedVerifier};
use crate::types::{FeedManifest, ThreatIntelConfig};

/// Result of a feed update check.
#[derive(Debug, Clone)]
pub enum UpdateResult {
    /// Feed was updated to a new version.
    Updated {
        old_version: Option<String>,
        new_version: String,
        files_updated: Vec<String>,
    },
    /// Feed is already up to date.
    UpToDate { version: String },
    /// Update failed, using cached data.
    FallbackToCached { reason: String, version: String },
    /// No data available at all.
    NoData,
}

/// The threat intelligence feed client.
pub struct FeedClient {
    config: ThreatIntelConfig,
    http: Client,
    cache: FeedCache,
    verifier: FeedVerifier,
}

impl FeedClient {
    /// Create a new feed client.
    pub fn new(
        config: ThreatIntelConfig,
        cache: FeedCache,
        verifier: FeedVerifier,
    ) -> Result<Self> {
        let http = Client::builder()
            .user_agent("ClawDefender-ThreatIntel/1.0")
            .build()?;
        Ok(Self {
            config,
            http,
            cache,
            verifier,
        })
    }

    /// Create a feed client with a custom HTTP client (for testing with mockito).
    pub fn with_http_client(
        config: ThreatIntelConfig,
        cache: FeedCache,
        verifier: FeedVerifier,
        http: Client,
    ) -> Self {
        Self {
            config,
            http,
            cache,
            verifier,
        }
    }

    /// Check for feed updates and apply them.
    pub async fn check_update(&mut self) -> Result<UpdateResult> {
        let cached_manifest = self.cache.read_manifest()?;
        let cached_version = cached_manifest.as_ref().map(|m| m.version.clone());

        // Try to fetch remote manifest.
        let (remote_manifest, manifest_raw) = match self.fetch_manifest().await {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "failed to fetch remote manifest");
                return self.handle_fetch_failure(cached_manifest, e);
            }
        };

        // Check if we need to update.
        if let Some(ref cv) = cached_version {
            if cv == &remote_manifest.version {
                debug!(version = %cv, "feed is up to date");
                return Ok(UpdateResult::UpToDate {
                    version: cv.clone(),
                });
            }
        }

        // Fetch and verify signature.
        if let Err(e) = self.fetch_and_verify_signature(&manifest_raw).await {
            warn!(error = %e, "signature verification failed");
            return self.handle_fetch_failure(cached_manifest, e);
        }

        // Handle key rotation if announced.
        if let Some(ref next_key) = remote_manifest.next_public_key {
            debug!("manifest announces next public key for rotation");
            if let Err(e) = self.verifier.set_next_key(next_key) {
                warn!(error = %e, "failed to set next key");
            } else {
                let _ = self.cache.write_next_key(next_key);
            }
        }

        // Download changed files.
        let changed = self
            .download_changed_files(&remote_manifest, &cached_manifest)
            .await?;

        // Save manifest to cache.
        self.cache.write_manifest(&remote_manifest)?;

        info!(
            version = %remote_manifest.version,
            files_updated = changed.len(),
            "feed updated"
        );

        Ok(UpdateResult::Updated {
            old_version: cached_version,
            new_version: remote_manifest.version,
            files_updated: changed,
        })
    }

    /// Fetch the remote manifest, returning both parsed and raw bytes.
    async fn fetch_manifest(&self) -> Result<(FeedManifest, Vec<u8>)> {
        let url = format!("{}manifest.json", self.config.feed_url);
        debug!(url = %url, "fetching manifest");

        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(ThreatIntelError::FetchError(format!(
                "manifest fetch returned status {}",
                resp.status()
            )));
        }
        let raw = resp.bytes().await?.to_vec();
        let manifest: FeedManifest = serde_json::from_slice(&raw)?;
        Ok((manifest, raw))
    }

    /// Fetch the signature and verify it against the raw manifest bytes.
    async fn fetch_and_verify_signature(&self, manifest_raw: &[u8]) -> Result<()> {
        let url = format!("{}signatures/latest.sig", self.config.feed_url);
        debug!(url = %url, "fetching signature");

        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(ThreatIntelError::FetchError(format!(
                "signature fetch returned status {}",
                resp.status()
            )));
        }
        let sig_bytes = resp.bytes().await?.to_vec();

        // The signature signs the raw manifest bytes as fetched.
        self.verifier.verify(manifest_raw, &sig_bytes)?;

        // Cache the signature.
        self.cache.write_signature(&sig_bytes)?;

        Ok(())
    }

    /// Download files whose hashes differ from the cached versions.
    async fn download_changed_files(
        &self,
        remote: &FeedManifest,
        cached: &Option<FeedManifest>,
    ) -> Result<Vec<String>> {
        let cached_files: HashMap<&str, &str> = cached
            .as_ref()
            .map(|m| {
                m.files
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.sha256.as_str()))
                    .collect()
            })
            .unwrap_or_default();

        let mut updated = Vec::new();

        for (file_path, entry) in &remote.files {
            // Skip if hash matches cached version.
            if let Some(cached_hash) = cached_files.get(file_path.as_str()) {
                if *cached_hash == entry.sha256 {
                    debug!(file = %file_path, "file unchanged, skipping");
                    continue;
                }
            }

            // Download the file.
            let url = format!("{}{}", self.config.feed_url, file_path);
            debug!(url = %url, "downloading file");

            let resp = self.http.get(&url).send().await?;
            if !resp.status().is_success() {
                warn!(
                    file = %file_path,
                    status = %resp.status(),
                    "failed to download file, skipping"
                );
                continue;
            }
            let data = resp.bytes().await?.to_vec();

            // Verify hash.
            let actual_hash = sha256_hex(&data);
            if actual_hash != entry.sha256 {
                return Err(ThreatIntelError::HashMismatch {
                    file: file_path.clone(),
                    expected: entry.sha256.clone(),
                    actual: actual_hash,
                });
            }

            // Write to cache.
            self.cache.write_file(file_path, &data)?;
            updated.push(file_path.clone());
        }

        Ok(updated)
    }

    /// Handle a fetch failure by falling back to cached or bundled data.
    fn handle_fetch_failure(
        &self,
        cached: Option<FeedManifest>,
        error: ThreatIntelError,
    ) -> Result<UpdateResult> {
        if let Some(manifest) = cached {
            Ok(UpdateResult::FallbackToCached {
                reason: error.to_string(),
                version: manifest.version,
            })
        } else {
            // Try bundled baseline.
            Ok(UpdateResult::NoData)
        }
    }

    /// Get the current cached manifest.
    pub fn cached_manifest(&self) -> Result<Option<FeedManifest>> {
        self.cache.read_manifest()
    }

    /// Read a cached feed file.
    pub fn read_cached_file(&self, path: &str) -> Result<Option<Vec<u8>>> {
        self.cache.read_file(path)
    }
}

/// Compute SHA-256 hex digest.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_value() {
        // SHA-256 of empty string.
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"hello threat intel";
        let h1 = sha256_hex(data);
        let h2 = sha256_hex(data);
        assert_eq!(h1, h2);
    }
}
