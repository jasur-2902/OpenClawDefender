//! Integration tests for the patterns module.

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use regex::Regex;

    use crate::patterns::injection_loader::InjectionSignatureLoader;
    use crate::patterns::killchain_loader::KillChainLoader;
    use crate::patterns::profile_seeder::ProfileSeeder;
    use crate::patterns::types::*;
    use crate::types::{InjectionSignature, InjectionSignatures, KillChainPatterns};

    // -----------------------------------------------------------------------
    // Kill chain loading
    // -----------------------------------------------------------------------

    #[test]
    fn test_dynamic_killchain_loading_from_json() {
        let json = r#"{
            "version": "2.0.0",
            "patterns": [
                {
                    "id": "feed_recon_exfil",
                    "name": "Recon then Exfil",
                    "description": "Directory listing followed by network exfil",
                    "stages": ["file_list:/", "network_connect:!localhost"],
                    "severity": "high"
                },
                {
                    "id": "feed_persistence",
                    "name": "Persistence Install",
                    "description": "Write to startup then shell exec",
                    "stages": ["file_write:~/Library/LaunchAgents/*", "shell_exec"],
                    "severity": "critical"
                }
            ]
        }"#;

        let data: KillChainPatterns = serde_json::from_str(json).unwrap();
        let patterns = KillChainLoader::load_from_feed(&data);

        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0].id, "feed_recon_exfil");
        assert_eq!(patterns[0].severity, Severity::High);
        assert_eq!(patterns[0].steps.len(), 2);
        assert_eq!(patterns[1].severity, Severity::Critical);
    }

    #[test]
    fn test_merge_patterns_builtin_plus_dynamic_no_duplicates() {
        let builtin_names = vec![
            "credential_theft_exfiltration".to_string(),
            "recon_credential_access".to_string(),
        ];

        let dynamic = vec![
            DynamicAttackPattern {
                id: "credential_theft_exfiltration".into(), // duplicate
                name: "Dup".into(),
                severity: Severity::Critical,
                window_seconds: 60,
                explanation: "dup".into(),
                steps: vec![],
                source: PatternSource::Feed,
                version: "1.0.0".into(),
            },
            DynamicAttackPattern {
                id: "new_feed_pattern".into(),
                name: "New Feed Pattern".into(),
                severity: Severity::Medium,
                window_seconds: 30,
                explanation: "new".into(),
                steps: vec![DynamicPatternStep {
                    event_type: StepEventType::ShellExec,
                    path_pattern: None,
                    destination_pattern: None,
                    min_count: None,
                }],
                source: PatternSource::Feed,
                version: "1.0.0".into(),
            },
        ];

        let merged = KillChainLoader::merge_patterns(&builtin_names, &dynamic);
        assert_eq!(merged.len(), 1, "Duplicate should be excluded");
        assert_eq!(merged[0].id, "new_feed_pattern");
    }

    // -----------------------------------------------------------------------
    // Injection signature loading
    // -----------------------------------------------------------------------

    #[test]
    fn test_dynamic_injection_loading_from_json() {
        let json = r#"{
            "version": "2.0.0",
            "signatures": [
                {
                    "id": "inj_feed_1",
                    "pattern": "(?i)new\\s+evil\\s+pattern",
                    "description": "New evil detection",
                    "severity": "high"
                }
            ]
        }"#;

        let data: InjectionSignatures = serde_json::from_str(json).unwrap();
        let patterns = InjectionSignatureLoader::load_from_feed(&data);

        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].id, "inj_feed_1");
        let re = Regex::new(&patterns[0].regex).unwrap();
        assert!(re.is_match("new evil pattern detected"));
    }

    #[test]
    fn test_invalid_regex_rejected_gracefully() {
        let data = InjectionSignatures {
            version: "1.0.0".into(),
            signatures: vec![
                InjectionSignature {
                    id: "good".into(),
                    pattern: r"(?i)good\s+pattern".into(),
                    description: "Good".into(),
                    severity: "high".into(),
                },
                InjectionSignature {
                    id: "bad".into(),
                    pattern: r"(?P<broken".into(), // invalid
                    description: "Bad".into(),
                    severity: "high".into(),
                },
                InjectionSignature {
                    id: "also_bad".into(),
                    pattern: r"[invalid".into(), // unclosed bracket
                    description: "Also bad".into(),
                    severity: "medium".into(),
                },
            ],
        };

        let patterns = InjectionSignatureLoader::load_from_feed(&data);
        assert_eq!(patterns.len(), 1, "Only valid regex should be loaded");
        assert_eq!(patterns[0].id, "good");
    }

    #[test]
    fn test_multilingual_injection_patterns_chinese() {
        let patterns = InjectionSignatureLoader::multilingual_patterns();
        let zh = patterns.iter().find(|p| p.language.as_deref() == Some("zh")).unwrap();
        assert!(InjectionSignatureLoader::validate_regex(&zh.regex));
    }

    #[test]
    fn test_multilingual_injection_patterns_arabic() {
        let patterns = InjectionSignatureLoader::multilingual_patterns();
        let ar = patterns.iter().find(|p| p.language.as_deref() == Some("ar")).unwrap();
        assert!(InjectionSignatureLoader::validate_regex(&ar.regex));
    }

    #[test]
    fn test_multilingual_injection_patterns_all_languages() {
        let patterns = InjectionSignatureLoader::multilingual_patterns();
        let languages: Vec<&str> = vec!["zh", "es", "fr", "de", "ja", "ko", "ru", "ar"];
        for lang in &languages {
            let found = patterns.iter().any(|p| p.language.as_deref() == Some(lang));
            assert!(found, "Missing multilingual pattern for language: {}", lang);
        }
    }

    #[test]
    fn test_xml_tag_injection_detection() {
        let patterns = InjectionSignatureLoader::multilingual_patterns();
        let xml_pat = patterns.iter().find(|p| p.id == "xml_tag_injection").unwrap();
        let re = Regex::new(&xml_pat.regex).unwrap();

        assert!(re.is_match("<system>evil</system>"));
        assert!(re.is_match("<user>injected</user>"));
        assert!(re.is_match("<assistant>override</assistant>"));
        assert!(!re.is_match("<div>normal html</div>"));
        assert!(!re.is_match("<p>paragraph</p>"));
    }

    #[test]
    fn test_homoglyph_detection() {
        let patterns = InjectionSignatureLoader::multilingual_patterns();
        let homo_pat = patterns.iter().find(|p| p.id == "homoglyph_injection").unwrap();
        let re = Regex::new(&homo_pat.regex).unwrap();

        // Cyrillic 'а' (U+0430) next to Latin 'b'
        assert!(re.is_match("\u{0430}b"));
        // Pure Latin should not match
        assert!(!re.is_match("abc"));
    }

    // -----------------------------------------------------------------------
    // Pre-seeded profiles
    // -----------------------------------------------------------------------

    #[test]
    fn test_pre_seeded_profile_loading_from_json() {
        let json = r#"{
            "version": "1.0.0",
            "profiles": [
                {
                    "server_package": "filesystem-server",
                    "profile_version": "1.0.0",
                    "expected_tools": ["read_file", "write_file", "list_directory"],
                    "expected_file_territory": ["/home", "/tmp"],
                    "expected_network": false,
                    "expected_shell": false,
                    "expected_rate": {"mean_ms": 500.0, "stddev_ms": 200.0},
                    "notes": "Standard filesystem MCP server"
                }
            ]
        }"#;

        let mut seeder = ProfileSeeder::new();
        seeder.load_from_json(json).unwrap();

        let profile = seeder.get_profile("filesystem-server").unwrap();
        assert_eq!(profile.expected_tools.len(), 3);
        assert_eq!(profile.expected_file_territory.len(), 2);
        assert!(!profile.expected_network);
    }

    #[test]
    fn test_pre_seeded_profile_converts_to_server_profile() {
        let pre_seeded = PreSeededProfile {
            server_package: "test-server".into(),
            profile_version: "1.0.0".into(),
            expected_tools: vec!["tool_a".into(), "tool_b".into()],
            expected_file_territory: vec!["/var/data".into()],
            expected_network: true,
            expected_shell: false,
            expected_rate: RateStats {
                mean_ms: 1000.0,
                stddev_ms: 300.0,
            },
            notes: "Test".into(),
        };

        let profile = ProfileSeeder::to_server_profile(&pre_seeded, "my-test");
        assert_eq!(profile.server_name, "my-test");
        assert!(profile.tool_counts.contains_key("tool_a"));
        assert!(profile.tool_counts.contains_key("tool_b"));
        assert!(profile.directory_prefixes.contains("/var/data"));
        assert!(profile.has_networked);
    }

    #[test]
    fn test_pre_seeded_profile_has_learning_mode_true() {
        let pre_seeded = PreSeededProfile {
            server_package: "test".into(),
            profile_version: "1.0.0".into(),
            expected_tools: vec![],
            expected_file_territory: vec![],
            expected_network: false,
            expected_shell: false,
            expected_rate: RateStats::default(),
            notes: String::new(),
        };

        let profile = ProfileSeeder::to_server_profile(&pre_seeded, "srv");
        assert!(
            profile.learning_mode,
            "Pre-seeded profile must have learning_mode=true"
        );
    }

    // -----------------------------------------------------------------------
    // Version tracking
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_tracker_detects_update() {
        let mut tracker = VersionTracker::new();

        let v1 = PatternVersion {
            id: "pat_1".into(),
            version: "1.0.0".into(),
            source: PatternSource::Feed,
            updated_at: Utc::now(),
        };

        assert!(tracker.register(v1.clone()), "First registration should be 'new'");
        assert!(!tracker.register(v1), "Same version should not be 'update'");

        let v2 = PatternVersion {
            id: "pat_1".into(),
            version: "2.0.0".into(),
            source: PatternSource::Feed,
            updated_at: Utc::now(),
        };
        assert!(tracker.register(v2), "New version should be detected as update");
        assert_eq!(tracker.get_version("pat_1").unwrap().version, "2.0.0");
    }

    #[test]
    fn test_version_tracker_pin_respected() {
        let mut tracker = VersionTracker::new();

        let v1 = PatternVersion {
            id: "pat_1".into(),
            version: "1.0.0".into(),
            source: PatternSource::Feed,
            updated_at: Utc::now(),
        };
        tracker.register(v1);
        tracker.pin("pat_1", "1.0.0");

        assert!(tracker.is_pinned("pat_1"));

        // Attempt to update to v2 — should be rejected because pinned to 1.0.0.
        let v2 = PatternVersion {
            id: "pat_1".into(),
            version: "2.0.0".into(),
            source: PatternSource::Feed,
            updated_at: Utc::now(),
        };
        assert!(
            !tracker.register(v2),
            "Pinned pattern should reject different version"
        );
        assert_eq!(
            tracker.get_version("pat_1").unwrap().version,
            "1.0.0",
            "Version should remain pinned"
        );

        // Unpin and retry.
        tracker.unpin("pat_1");
        assert!(!tracker.is_pinned("pat_1"));

        let v2_retry = PatternVersion {
            id: "pat_1".into(),
            version: "2.0.0".into(),
            source: PatternSource::Feed,
            updated_at: Utc::now(),
        };
        assert!(tracker.register(v2_retry), "Unpinned pattern should accept update");
        assert_eq!(tracker.get_version("pat_1").unwrap().version, "2.0.0");
    }

    // -----------------------------------------------------------------------
    // Hot-reload
    // -----------------------------------------------------------------------

    #[test]
    fn test_hot_reload_replaces_old_patterns() {
        let builtin_names = vec!["builtin_1".to_string()];

        let _old_patterns = vec![DynamicAttackPattern {
            id: "feed_old".into(),
            name: "Old Pattern".into(),
            severity: Severity::Low,
            window_seconds: 30,
            explanation: "old".into(),
            steps: vec![],
            source: PatternSource::Feed,
            version: "1.0.0".into(),
        }];

        let new_patterns = vec![
            DynamicAttackPattern {
                id: "feed_new_1".into(),
                name: "New Pattern 1".into(),
                severity: Severity::High,
                window_seconds: 60,
                explanation: "new 1".into(),
                steps: vec![DynamicPatternStep {
                    event_type: StepEventType::FileRead,
                    path_pattern: Some("/secret/*".into()),
                    destination_pattern: None,
                    min_count: None,
                }],
                source: PatternSource::Feed,
                version: "2.0.0".into(),
            },
            DynamicAttackPattern {
                id: "feed_new_2".into(),
                name: "New Pattern 2".into(),
                severity: Severity::Medium,
                window_seconds: 120,
                explanation: "new 2".into(),
                steps: vec![DynamicPatternStep {
                    event_type: StepEventType::ShellExec,
                    path_pattern: None,
                    destination_pattern: None,
                    min_count: None,
                }],
                source: PatternSource::Feed,
                version: "2.0.0".into(),
            },
        ];

        // Hot reload gives us the new set.
        let payload = KillChainLoader::hot_reload_payload(&builtin_names, &new_patterns);
        assert_eq!(payload.len(), 2, "New patterns should replace old");
        assert_eq!(payload[0].id, "feed_new_1");
        assert_eq!(payload[1].id, "feed_new_2");

        // Old patterns are not in the new payload.
        assert!(
            !payload.iter().any(|p| p.id == "feed_old"),
            "Old pattern should not be in hot-reload payload"
        );
    }
}
