//! Tests for the community rules engine.

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use tempfile::TempDir;

    use crate::cache::FeedCache;
    use crate::rules::catalog::RuleCatalog;
    use crate::rules::conflict::{ConflictDetector, ConflictType, UserAction, UserPolicyRule};
    use crate::rules::manager::RulePackManager;
    use crate::rules::types::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn sample_pack_json(id: &str, version: &str) -> String {
        serde_json::json!({
            "id": id,
            "name": format!("Test Pack {id}"),
            "version": version,
            "author": "tester",
            "description": "A test community rule pack",
            "category": "Security",
            "tags": ["filesystem", "test"],
            "download_count": 42,
            "rules": [
                {
                    "name": "block_ssh_keys",
                    "action": "block",
                    "methods": ["resources/read"],
                    "paths": ["/home/**/.ssh/*"],
                    "message": "SSH key access blocked by community pack",
                    "tags": ["ssh", "security"]
                },
                {
                    "name": "log_tmp_access",
                    "action": "log",
                    "methods": [],
                    "paths": ["/tmp/**"],
                    "message": "Temporary file access logged",
                    "tags": ["tmp"]
                }
            ]
        })
        .to_string()
    }

    fn sample_index_json(packs: &[(&str, &str)]) -> String {
        let entries: Vec<serde_json::Value> = packs
            .iter()
            .map(|(id, version)| {
                serde_json::json!({
                    "id": id,
                    "name": format!("Pack {id}"),
                    "version": version,
                    "author": "tester",
                    "description": format!("Description for {id}"),
                    "category": "ServerSpecific",
                    "tags": [id],
                    "download_count": 10
                })
            })
            .collect();
        serde_json::json!({ "packs": entries }).to_string()
    }

    fn setup_cache_with_pack(dir: &TempDir, id: &str, version: &str) -> FeedCache {
        let cache = FeedCache::new(dir.path().join("cache"));
        cache.ensure_dir().unwrap();
        // Write the pack file.
        let pack_json = sample_pack_json(id, version);
        cache
            .write_file(&format!("rules/{id}.json"), pack_json.as_bytes())
            .unwrap();
        // Write the index.
        let index = sample_index_json(&[(id, version)]);
        cache
            .write_file("rules/index.json", index.as_bytes())
            .unwrap();
        cache
    }

    fn make_manager(dir: &TempDir, cache: FeedCache) -> RulePackManager {
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let mut catalog = RuleCatalog::new(&data_dir).unwrap();
        catalog.refresh(&cache).unwrap();
        RulePackManager::new(catalog, cache)
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_community_rule_pack_from_json() {
        let json = sample_pack_json("test-pack", "1.0.0");
        let pack: CommunityRulePack = serde_json::from_str(&json).unwrap();
        assert_eq!(pack.metadata.id, "test-pack");
        assert_eq!(pack.metadata.version, "1.0.0");
        assert_eq!(pack.metadata.category, RulePackCategory::Security);
        assert_eq!(pack.rules.len(), 2);
        assert_eq!(pack.rules[0].name, "block_ssh_keys");
        assert_eq!(pack.rules[0].action, RuleAction::Block);
        assert_eq!(pack.rules[1].name, "log_tmp_access");
        assert_eq!(pack.rules[1].action, RuleAction::Log);
    }

    #[test]
    fn install_and_uninstall_pack() {
        let dir = TempDir::new().unwrap();
        let cache = setup_cache_with_pack(&dir, "sec-pack", "1.0.0");
        let mut mgr = make_manager(&dir, cache);

        // Install.
        mgr.install("sec-pack").unwrap();
        let rules = mgr.get_installed_rules("sec-pack");
        assert_eq!(rules.len(), 2);
        assert_eq!(mgr.catalog().list_installed().len(), 1);

        // Uninstall.
        mgr.uninstall("sec-pack").unwrap();
        let rules = mgr.get_installed_rules("sec-pack");
        assert!(rules.is_empty());
        assert_eq!(mgr.catalog().list_installed().len(), 0);
    }

    #[test]
    fn auto_update_bumps_version() {
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));
        cache.ensure_dir().unwrap();

        // Install v1.
        let pack_v1 = sample_pack_json("updatable", "1.0.0");
        cache
            .write_file("rules/updatable.json", pack_v1.as_bytes())
            .unwrap();
        let index_v1 = sample_index_json(&[("updatable", "1.0.0")]);
        cache
            .write_file("rules/index.json", index_v1.as_bytes())
            .unwrap();

        let mut mgr = make_manager(&dir, cache.clone());
        mgr.install("updatable").unwrap();
        assert_eq!(mgr.catalog().list_installed()[0].metadata.version, "1.0.0");

        // Simulate feed update to v2.
        let pack_v2 = sample_pack_json("updatable", "2.0.0");
        cache
            .write_file("rules/updatable.json", pack_v2.as_bytes())
            .unwrap();
        let index_v2 = sample_index_json(&[("updatable", "2.0.0")]);
        cache
            .write_file("rules/index.json", index_v2.as_bytes())
            .unwrap();
        mgr.catalog_mut().refresh(&cache).unwrap();

        let updated = mgr.update_all().unwrap();
        assert_eq!(updated, vec!["updatable"]);
        assert_eq!(mgr.catalog().list_installed()[0].metadata.version, "2.0.0");
    }

    #[test]
    fn conflict_detection_block_vs_allow() {
        let pack: CommunityRulePack =
            serde_json::from_str(&sample_pack_json("cp", "1.0.0")).unwrap();

        let user_rules = vec![UserPolicyRule {
            name: "allow_ssh".to_string(),
            action: UserAction::Allow,
            methods: vec!["resources/read".to_string()],
            resource_paths: vec!["/home/**/.ssh/*".to_string()],
        }];

        let conflicts = ConflictDetector::detect_conflicts(&pack, &user_rules);
        assert!(!conflicts.is_empty());
        let ssh_conflict = conflicts
            .iter()
            .find(|c| c.community_rule == "block_ssh_keys")
            .expect("expected conflict on block_ssh_keys");
        assert_eq!(ssh_conflict.conflict_type, ConflictType::Contradicts);
    }

    #[test]
    fn rule_precedence_user_over_community() {
        // RuleSource ordering: User > ThreatIntel > Community > Default.
        assert!(RuleSource::User > RuleSource::ThreatIntel);
        assert!(RuleSource::ThreatIntel > RuleSource::Community);
        assert!(RuleSource::Community > RuleSource::Default);
    }

    #[test]
    fn catalog_refresh_and_list() {
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));
        cache.ensure_dir().unwrap();
        let index = sample_index_json(&[("pack-a", "1.0.0"), ("pack-b", "2.0.0")]);
        cache
            .write_file("rules/index.json", index.as_bytes())
            .unwrap();

        let mut catalog = RuleCatalog::in_memory();
        catalog.refresh(&cache).unwrap();
        assert_eq!(catalog.list_available().len(), 2);
    }

    #[test]
    fn recommendation_for_filesystem_server() {
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));
        cache.ensure_dir().unwrap();
        let index = sample_index_json(&[("filesystem", "1.0.0"), ("database", "1.0.0")]);
        cache
            .write_file("rules/index.json", index.as_bytes())
            .unwrap();

        let mut catalog = RuleCatalog::in_memory();
        catalog.refresh(&cache).unwrap();

        let recs = catalog.recommend_for_servers(&["filesystem".to_string()]);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].id, "filesystem");
    }

    #[test]
    fn empty_catalog_handling() {
        let catalog = RuleCatalog::in_memory();
        assert!(catalog.list_available().is_empty());
        assert!(catalog.list_installed().is_empty());
        let recs = catalog.recommend_for_servers(&["anything".to_string()]);
        assert!(recs.is_empty());
    }

    #[test]
    fn multiple_packs_installed() {
        let dir = TempDir::new().unwrap();
        let cache = FeedCache::new(dir.path().join("cache"));
        cache.ensure_dir().unwrap();

        // Write two packs.
        for id in &["alpha", "beta"] {
            let pack = sample_pack_json(id, "1.0.0");
            cache
                .write_file(&format!("rules/{id}.json"), pack.as_bytes())
                .unwrap();
        }
        let index = sample_index_json(&[("alpha", "1.0.0"), ("beta", "1.0.0")]);
        cache
            .write_file("rules/index.json", index.as_bytes())
            .unwrap();

        let mut mgr = make_manager(&dir, cache);
        mgr.install("alpha").unwrap();
        mgr.install("beta").unwrap();

        assert_eq!(mgr.catalog().list_installed().len(), 2);
        assert_eq!(mgr.get_installed_rules("alpha").len(), 2);
        assert_eq!(mgr.get_installed_rules("beta").len(), 2);
        // All active rules across both packs.
        assert_eq!(mgr.all_active_rules().len(), 4);
    }

    #[test]
    fn installed_pack_serialization_roundtrip() {
        let pack = InstalledPack {
            metadata: RulePackMetadata {
                id: "roundtrip".to_string(),
                name: "Roundtrip Pack".to_string(),
                version: "1.2.3".to_string(),
                author: "test".to_string(),
                description: "desc".to_string(),
                category: RulePackCategory::Privacy,
                tags: vec!["a".to_string()],
                compatibility: Some(">=0.3.0".to_string()),
                download_count: 99,
            },
            installed_at: Utc::now(),
            auto_update: false,
        };

        let json = serde_json::to_string(&pack).unwrap();
        let deser: InstalledPack = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.metadata.id, "roundtrip");
        assert!(!deser.auto_update);
    }
}
