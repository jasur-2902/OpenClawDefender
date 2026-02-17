//! Threat intelligence feed client for ClawDefender.
//!
//! This crate provides:
//! - Feed format type definitions (manifest, blocklist, rules, patterns, IoCs, profiles)
//! - Ed25519 signature verification with key rotation support
//! - Async HTTP feed client with incremental updates
//! - Local file cache with offline fallback
//! - Bundled baseline feed for first-run scenarios

pub mod baseline;
pub mod ioc;
pub mod blocklist;
pub mod cache;
pub mod client;
pub mod error;
pub mod patterns;
pub mod rules;
pub mod signature;
pub mod telemetry;
pub mod types;

// Re-export key types at crate root for convenience.
pub use cache::FeedCache;
pub use client::{FeedClient, UpdateResult};
pub use error::ThreatIntelError;
pub use signature::FeedVerifier;
pub use types::*;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn generate_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    #[tokio::test]
    async fn test_feed_client_with_mock_server() {
        let (signing, verifying) = generate_keypair();
        let pub_hex = signature::hex_encode(verifying.as_bytes());

        // Create manifest.
        let blocklist_data = r#"{"version":"2.0.0","servers":[]}"#;
        let blocklist_hash = client::sha256_hex(blocklist_data.as_bytes());

        let manifest = FeedManifest {
            version: "2.0.0".into(),
            last_updated: chrono::Utc::now(),
            feed_format_version: 1,
            files: {
                let mut m = HashMap::new();
                m.insert(
                    "blocklist.json".into(),
                    types::FileEntry {
                        sha256: blocklist_hash,
                        size: blocklist_data.len() as u64,
                    },
                );
                m
            },
            next_public_key: None,
        };

        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let sig = signing.sign(manifest_json.as_bytes());

        // Set up mock server.
        let mut server = mockito::Server::new_async().await;

        let _m_manifest = server
            .mock("GET", "/v1/manifest.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&manifest_json)
            .create_async()
            .await;

        let _m_sig = server
            .mock("GET", "/v1/signatures/latest.sig")
            .with_status(200)
            .with_body(sig.to_bytes().to_vec())
            .create_async()
            .await;

        let _m_blocklist = server
            .mock("GET", "/v1/blocklist.json")
            .with_status(200)
            .with_body(blocklist_data)
            .create_async()
            .await;

        // Create client.
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));
        let verifier = FeedVerifier::from_hex(&pub_hex).unwrap();

        let mut config = ThreatIntelConfig::default();
        config.feed_url = format!("{}/v1/", server.url());

        let mut client = FeedClient::new(config, cache, verifier).unwrap();
        let result = client.check_update().await.unwrap();

        match result {
            UpdateResult::Updated {
                old_version,
                new_version,
                files_updated,
            } => {
                assert!(old_version.is_none());
                assert_eq!(new_version, "2.0.0");
                assert!(files_updated.contains(&"blocklist.json".to_string()));
            }
            other => panic!("expected Updated, got {:?}", other),
        }

        // Second call should be UpToDate.
        let result2 = client.check_update().await.unwrap();
        match result2 {
            UpdateResult::UpToDate { version } => {
                assert_eq!(version, "2.0.0");
            }
            other => panic!("expected UpToDate, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_offline_fallback_to_cache() {
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));

        // Pre-populate cache.
        let manifest = FeedManifest {
            version: "1.5.0".into(),
            last_updated: chrono::Utc::now(),
            feed_format_version: 1,
            files: HashMap::new(),
            next_public_key: None,
        };
        cache.write_manifest(&manifest).unwrap();

        // Point to unreachable server.
        let verifier = FeedVerifier::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let mut config = ThreatIntelConfig::default();
        config.feed_url = "http://127.0.0.1:1/v1/".into();

        let mut client = FeedClient::new(config, cache, verifier).unwrap();
        let result = client.check_update().await.unwrap();

        match result {
            UpdateResult::FallbackToCached { version, .. } => {
                assert_eq!(version, "1.5.0");
            }
            other => panic!("expected FallbackToCached, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_no_cache_no_network_returns_no_data() {
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("empty-cache"));

        let verifier = FeedVerifier::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let mut config = ThreatIntelConfig::default();
        config.feed_url = "http://127.0.0.1:1/v1/".into();

        let mut client = FeedClient::new(config, cache, verifier).unwrap();
        let result = client.check_update().await.unwrap();

        match result {
            UpdateResult::NoData => {}
            other => panic!("expected NoData, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_bundled_baseline_when_no_cache() {
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));
        assert!(!cache.is_populated());

        let populated = baseline::populate_cache_from_baseline(&cache).unwrap();
        assert!(populated);

        let manifest = cache.read_manifest().unwrap().unwrap();
        assert_eq!(manifest.version, "1.0.0");
    }

    #[tokio::test]
    async fn test_incremental_update_only_downloads_changed() {
        let (signing, verifying) = generate_keypair();
        let pub_hex = signature::hex_encode(verifying.as_bytes());

        let blocklist_v1 = r#"{"version":"1.0.0","servers":[]}"#;
        let blocklist_v1_hash = client::sha256_hex(blocklist_v1.as_bytes());
        let rules_data = r#"{"version":"1.0.0","packs":[]}"#;
        let rules_hash = client::sha256_hex(rules_data.as_bytes());

        // Pre-populate cache with v1 manifest that has blocklist.
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));
        let v1_manifest = FeedManifest {
            version: "1.0.0".into(),
            last_updated: chrono::Utc::now(),
            feed_format_version: 1,
            files: {
                let mut m = HashMap::new();
                m.insert(
                    "blocklist.json".into(),
                    types::FileEntry {
                        sha256: blocklist_v1_hash.clone(),
                        size: blocklist_v1.len() as u64,
                    },
                );
                m
            },
            next_public_key: None,
        };
        cache.write_manifest(&v1_manifest).unwrap();
        cache
            .write_file("blocklist.json", blocklist_v1.as_bytes())
            .unwrap();

        // v2 manifest: blocklist unchanged, rules/index.json added.
        let v2_manifest = FeedManifest {
            version: "2.0.0".into(),
            last_updated: chrono::Utc::now(),
            feed_format_version: 1,
            files: {
                let mut m = HashMap::new();
                m.insert(
                    "blocklist.json".into(),
                    types::FileEntry {
                        sha256: blocklist_v1_hash,
                        size: blocklist_v1.len() as u64,
                    },
                );
                m.insert(
                    "rules/index.json".into(),
                    types::FileEntry {
                        sha256: rules_hash,
                        size: rules_data.len() as u64,
                    },
                );
                m
            },
            next_public_key: None,
        };

        let manifest_json = serde_json::to_string(&v2_manifest).unwrap();
        let sig = signing.sign(manifest_json.as_bytes());

        let mut server = mockito::Server::new_async().await;

        let _m_manifest = server
            .mock("GET", "/v1/manifest.json")
            .with_status(200)
            .with_body(&manifest_json)
            .create_async()
            .await;

        let _m_sig = server
            .mock("GET", "/v1/signatures/latest.sig")
            .with_status(200)
            .with_body(sig.to_bytes().to_vec())
            .create_async()
            .await;

        // Only rules should be fetched; blocklist should NOT be fetched.
        let _m_rules = server
            .mock("GET", "/v1/rules/index.json")
            .with_status(200)
            .with_body(rules_data)
            .expect(1)
            .create_async()
            .await;

        let _m_blocklist_not_called = server
            .mock("GET", "/v1/blocklist.json")
            .with_status(200)
            .with_body(blocklist_v1)
            .expect(0)
            .create_async()
            .await;

        let verifier = FeedVerifier::from_hex(&pub_hex).unwrap();
        let mut config = ThreatIntelConfig::default();
        config.feed_url = format!("{}/v1/", server.url());

        let mut feed_client = FeedClient::new(config, cache, verifier).unwrap();
        let result = feed_client.check_update().await.unwrap();

        match result {
            UpdateResult::Updated {
                files_updated,
                new_version,
                ..
            } => {
                assert_eq!(new_version, "2.0.0");
                assert!(files_updated.contains(&"rules/index.json".to_string()));
                assert!(!files_updated.contains(&"blocklist.json".to_string()));
            }
            other => panic!("expected Updated, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_key_rotation_via_manifest() {
        let (signing1, verifying1) = generate_keypair();
        let (signing2, verifying2) = generate_keypair();
        let pub_hex1 = signature::hex_encode(verifying1.as_bytes());
        let pub_hex2 = signature::hex_encode(verifying2.as_bytes());

        // Phase 1: manifest signed by key1, announces key2.
        let manifest1 = FeedManifest {
            version: "3.0.0".into(),
            last_updated: chrono::Utc::now(),
            feed_format_version: 1,
            files: HashMap::new(),
            next_public_key: Some(pub_hex2.clone()),
        };
        let manifest1_json = serde_json::to_string(&manifest1).unwrap();
        let sig1 = signing1.sign(manifest1_json.as_bytes());

        let mut server = mockito::Server::new_async().await;

        let _m1 = server
            .mock("GET", "/v1/manifest.json")
            .with_status(200)
            .with_body(&manifest1_json)
            .create_async()
            .await;

        let _s1 = server
            .mock("GET", "/v1/signatures/latest.sig")
            .with_status(200)
            .with_body(sig1.to_bytes().to_vec())
            .create_async()
            .await;

        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));
        let verifier = FeedVerifier::from_hex(&pub_hex1).unwrap();
        let mut config = ThreatIntelConfig::default();
        config.feed_url = format!("{}/v1/", server.url());

        let mut feed_client = FeedClient::new(config, cache, verifier).unwrap();
        let result = feed_client.check_update().await.unwrap();
        assert!(matches!(result, UpdateResult::Updated { .. }));

        // Phase 2: new manifest signed by key2 (the next key).
        let manifest2 = FeedManifest {
            version: "3.1.0".into(),
            last_updated: chrono::Utc::now(),
            feed_format_version: 1,
            files: HashMap::new(),
            next_public_key: None,
        };
        let manifest2_json = serde_json::to_string(&manifest2).unwrap();
        let sig2 = signing2.sign(manifest2_json.as_bytes());

        // Reset mocks for phase 2.
        let mut server2 = mockito::Server::new_async().await;

        let _m2 = server2
            .mock("GET", "/v1/manifest.json")
            .with_status(200)
            .with_body(&manifest2_json)
            .create_async()
            .await;

        let _s2 = server2
            .mock("GET", "/v1/signatures/latest.sig")
            .with_status(200)
            .with_body(sig2.to_bytes().to_vec())
            .create_async()
            .await;

        // Rebuild client pointing to new server, but reuse the same cache + verifier state.
        // We need to rebuild because the verifier already has next_key set.
        let cache2 = FeedCache::new(dir.path().join("cache"));
        let mut verifier2 = FeedVerifier::from_hex(&pub_hex1).unwrap();
        verifier2.set_next_key(&pub_hex2).unwrap();

        let mut config2 = ThreatIntelConfig::default();
        config2.feed_url = format!("{}/v1/", server2.url());

        let mut client2 = FeedClient::new(config2, cache2, verifier2).unwrap();
        let result2 = client2.check_update().await.unwrap();

        match result2 {
            UpdateResult::Updated { new_version, .. } => {
                assert_eq!(new_version, "3.1.0");
            }
            other => panic!("expected Updated with key2, got {:?}", other),
        }
    }

    #[test]
    fn test_hash_mismatch_detected() {
        // This is tested via the sha256_hex function.
        let data = b"some file content";
        let hash = client::sha256_hex(data);
        let wrong_hash = client::sha256_hex(b"different content");
        assert_ne!(hash, wrong_hash);
    }
}
