//! Tests for the blocklist matching engine.

#[cfg(test)]
mod tests {
    use crate::blocklist::matching::BlocklistMatcher;
    use crate::blocklist::types::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn malicious_entry() -> BlocklistEntry {
        BlocklistEntry {
            id: "CLAW-2026-001".into(),
            entry_type: BlocklistEntryType::MaliciousServer,
            name: "evil-mcp-server".into(),
            versions: None,
            versions_affected: None,
            versions_fixed: None,
            severity: Severity::Critical,
            description: "Data-exfiltrating MCP server".into(),
            discovery_date: Some("2026-01-15".into()),
            indicators: Some(ThreatIndicators {
                network: vec!["evil.example.com".into()],
                file_access: vec!["/etc/passwd".into()],
                behavior: Some("Exfiltrates environment variables".into()),
            }),
            remediation: "Remove immediately".into(),
            references: vec!["https://example.com/advisory/001".into()],
            npm_package: Some("evil-mcp-server".into()),
            cve: None,
            sha256_malicious: Some(vec![
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".into(),
            ]),
            versions_safe: None,
        }
    }

    fn vulnerable_entry() -> BlocklistEntry {
        BlocklistEntry {
            id: "CLAW-2026-002".into(),
            entry_type: BlocklistEntryType::VulnerableServer,
            name: "buggy-server".into(),
            versions: None,
            versions_affected: Some("<1.5.0".into()),
            versions_fixed: Some(vec!["1.5.0".into()]),
            severity: Severity::High,
            description: "Path traversal vulnerability".into(),
            discovery_date: Some("2026-02-01".into()),
            indicators: None,
            remediation: "Upgrade to >=1.5.0".into(),
            references: vec![],
            npm_package: None,
            cve: Some("CVE-2026-12345".into()),
            sha256_malicious: None,
            versions_safe: Some(vec!["1.5.0".into(), "1.5.1".into()]),
        }
    }

    fn compromised_entry() -> BlocklistEntry {
        BlocklistEntry {
            id: "CLAW-2026-003".into(),
            entry_type: BlocklistEntryType::CompromisedVersion,
            name: "popular-server".into(),
            versions: Some(vec!["2.1.0".into(), "2.1.1".into()]),
            versions_affected: None,
            versions_fixed: Some(vec!["2.1.2".into()]),
            severity: Severity::Critical,
            description: "Supply-chain compromise injecting backdoor".into(),
            discovery_date: None,
            indicators: None,
            remediation: "Upgrade to 2.1.2 or later".into(),
            references: vec![],
            npm_package: None,
            cve: None,
            sha256_malicious: Some(vec![
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
            ]),
            versions_safe: None,
        }
    }

    fn sample_blocklist() -> Blocklist {
        Blocklist {
            version: 1,
            updated_at: "2026-02-17T00:00:00Z".into(),
            entries: vec![malicious_entry(), vulnerable_entry(), compromised_entry()],
        }
    }

    // -----------------------------------------------------------------------
    // Exact version match
    // -----------------------------------------------------------------------

    #[test]
    fn exact_version_match_compromised() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server("popular-server", Some("2.1.0"), None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, "CLAW-2026-003");
        assert_eq!(results[0].match_type, MatchType::ExactVersion);
        assert_eq!(results[0].action, RecommendedAction::Block);
    }

    #[test]
    fn exact_version_no_match_compromised() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server("popular-server", Some("2.1.2"), None);
        assert!(results.is_empty(), "Safe version should not match");
    }

    // -----------------------------------------------------------------------
    // Semver range match
    // -----------------------------------------------------------------------

    #[test]
    fn semver_range_match_vulnerable() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server("buggy-server", Some("1.4.0"), None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, "CLAW-2026-002");
        assert_eq!(results[0].match_type, MatchType::SemverRange);
        assert_eq!(results[0].action, RecommendedAction::Warn);
    }

    #[test]
    fn semver_range_no_match_fixed_version() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        // 1.5.0 is NOT < 1.5.0, so it should not match the range.
        let results = matcher.check_server("buggy-server", Some("1.5.0"), None);
        assert!(results.is_empty(), "Fixed version should not match");
    }

    // -----------------------------------------------------------------------
    // SHA-256 hash match
    // -----------------------------------------------------------------------

    #[test]
    fn sha256_hash_match() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server(
            "some-unknown-name",
            None,
            Some("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, "CLAW-2026-001");
        assert_eq!(results[0].match_type, MatchType::Sha256Hash);
    }

    #[test]
    fn sha256_hash_case_insensitive() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server(
            "unknown",
            None,
            Some("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_type, MatchType::Sha256Hash);
    }

    // -----------------------------------------------------------------------
    // Entry types -> correct actions
    // -----------------------------------------------------------------------

    #[test]
    fn malicious_server_action_is_block() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server("evil-mcp-server", None, None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, RecommendedAction::Block);
    }

    #[test]
    fn vulnerable_server_action_is_warn() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server("buggy-server", Some("1.0.0"), None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, RecommendedAction::Warn);
    }

    #[test]
    fn compromised_version_action_is_block() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server("popular-server", Some("2.1.1"), None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, RecommendedAction::Block);
    }

    // -----------------------------------------------------------------------
    // Runtime blocklist update
    // -----------------------------------------------------------------------

    #[test]
    fn runtime_blocklist_update() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        assert_eq!(matcher.version(), 1);

        // Server is initially malicious.
        let results = matcher.check_server("evil-mcp-server", None, None);
        assert_eq!(results.len(), 1);

        // Update with an empty blocklist.
        matcher.update_blocklist(Blocklist {
            version: 2,
            updated_at: "2026-02-17T12:00:00Z".into(),
            entries: vec![],
        });
        assert_eq!(matcher.version(), 2);

        // Server should no longer match.
        let results = matcher.check_server("evil-mcp-server", None, None);
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // Override mechanism
    // -----------------------------------------------------------------------

    #[test]
    fn override_suppresses_match() {
        let matcher = BlocklistMatcher::new(sample_blocklist());

        // Confirm the match exists first.
        let results = matcher.check_server("evil-mcp-server", None, None);
        assert_eq!(results.len(), 1);

        // Add an override.
        let ovr = BlocklistOverride {
            entry_id: "CLAW-2026-001".into(),
            server_name: "evil-mcp-server".into(),
            version: None,
            confirmation: OVERRIDE_CONFIRMATION_TEXT.into(),
            created_at: "2026-02-17T10:00:00Z".into(),
            reason: "Testing in sandbox environment".into(),
        };
        matcher.add_override(ovr).expect("override should succeed");

        // Match should now be suppressed.
        let results = matcher.check_server("evil-mcp-server", None, None);
        assert!(results.is_empty(), "Override should suppress the match");

        // Overrides list should have one entry.
        assert_eq!(matcher.list_overrides().len(), 1);

        // Remove the override.
        matcher.remove_override("CLAW-2026-001", "evil-mcp-server");
        let results = matcher.check_server("evil-mcp-server", None, None);
        assert_eq!(
            results.len(),
            1,
            "Match should return after override removed"
        );
    }

    #[test]
    fn override_requires_correct_confirmation() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let ovr = BlocklistOverride {
            entry_id: "CLAW-2026-001".into(),
            server_name: "evil-mcp-server".into(),
            version: None,
            confirmation: "wrong text".into(),
            created_at: "2026-02-17T10:00:00Z".into(),
            reason: "Testing".into(),
        };
        assert!(matcher.add_override(ovr).is_err());
    }

    // -----------------------------------------------------------------------
    // Clean server (no matches, no false positives)
    // -----------------------------------------------------------------------

    #[test]
    fn clean_server_no_matches() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server("totally-safe-server", Some("1.0.0"), None);
        assert!(results.is_empty());
    }

    #[test]
    fn clean_server_safe_version_no_match() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        // popular-server 2.2.0 is NOT in the compromised versions list.
        let results = matcher.check_server("popular-server", Some("2.2.0"), None);
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // Case-insensitive name matching
    // -----------------------------------------------------------------------

    #[test]
    fn case_insensitive_name_match() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server("Evil-MCP-Server", None, None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, "CLAW-2026-001");
    }

    #[test]
    fn case_insensitive_name_match_upper() {
        let matcher = BlocklistMatcher::new(sample_blocklist());
        let results = matcher.check_server("BUGGY-SERVER", Some("1.0.0"), None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, "CLAW-2026-002");
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn blocklist_serialization_roundtrip() {
        let bl = sample_blocklist();
        let json = serde_json::to_string_pretty(&bl).expect("serialize");
        let parsed: Blocklist = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.version, bl.version);
        assert_eq!(parsed.entries.len(), bl.entries.len());
        assert_eq!(parsed.entries[0].id, "CLAW-2026-001");
    }
}
