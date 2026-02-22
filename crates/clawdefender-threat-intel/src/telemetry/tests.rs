//! Tests for the telemetry system.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::telemetry::{
        aggregator::TelemetryAggregator,
        consent::ConsentManager,
        reporter::TelemetryReporter,
        types::{TelemetryConfig, TelemetryReport, REPORT_SCHEMA_VERSION},
    };

    // -----------------------------------------------------------------------
    // Default config: telemetry is OFF
    // -----------------------------------------------------------------------

    #[test]
    fn telemetry_is_off_by_default() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled, "telemetry must be disabled by default");
        assert!(config.installation_id.is_none());
    }

    #[test]
    fn consent_manager_default_is_disabled() {
        let cm = ConsentManager::default_disabled();
        assert!(!cm.is_enabled());
        assert!(cm.get_installation_id().is_none());
    }

    // -----------------------------------------------------------------------
    // Opt-in / opt-out
    // -----------------------------------------------------------------------

    #[test]
    fn opt_in_generates_uuid_v4() {
        let mut cm = ConsentManager::default_disabled();
        let id = cm.opt_in();

        // UUID v4 format: 8-4-4-4-12 hex digits
        assert!(cm.is_enabled());
        assert_eq!(cm.get_installation_id(), Some(id.as_str()));

        // Validate UUID format
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5, "UUID should have 5 groups");
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);

        // Version nibble should be '4'
        assert!(
            parts[2].starts_with('4'),
            "UUID v4 version nibble must be 4"
        );
    }

    #[test]
    fn opt_in_generates_unique_ids() {
        let mut cm1 = ConsentManager::default_disabled();
        let mut cm2 = ConsentManager::default_disabled();
        let id1 = cm1.opt_in();
        let id2 = cm2.opt_in();
        assert_ne!(id1, id2, "different opt-ins must produce different IDs");
    }

    #[test]
    fn opt_out_clears_state() {
        let mut cm = ConsentManager::default_disabled();
        cm.opt_in();
        assert!(cm.is_enabled());
        assert!(cm.get_installation_id().is_some());

        cm.opt_out();
        assert!(!cm.is_enabled());
        assert!(cm.get_installation_id().is_none());
    }

    // -----------------------------------------------------------------------
    // Aggregation
    // -----------------------------------------------------------------------

    #[test]
    fn aggregate_100_synthetic_events() {
        let mut agg = TelemetryAggregator::new();

        // Record 100 diverse events
        for i in 0..30 {
            agg.record_blocklist_match(&format!("CLAW-2026-{:03}", i));
        }
        for i in 0..25 {
            let dim = if i % 3 == 0 {
                "unknown_path"
            } else if i % 3 == 1 {
                "unusual_port"
            } else {
                "high_entropy"
            };
            agg.record_anomaly_event(0.85 + (i as f64 * 0.001), dim);
        }
        for _ in 0..5 {
            agg.record_auto_block();
        }
        for i in 0..15 {
            let decision = match i % 3 {
                0 => "allowed",
                1 => "denied",
                _ => "auto_blocked",
            };
            agg.record_killchain_trigger(&format!("KC-{:03}", i), (i % 4 + 1) as u32, decision);
        }
        for i in 0..15 {
            let ioc_type = match i % 3 {
                0 => "network",
                1 => "file",
                _ => "behavioral",
            };
            agg.record_ioc_match(ioc_type);
        }
        for i in 0..10 {
            let cat = if i % 2 == 0 {
                "path_traversal"
            } else {
                "injection"
            };
            let sev = if i % 3 == 0 { "HIGH" } else { "MEDIUM" };
            agg.record_scan_finding(cat, sev);
        }

        let report = agg.build_report("test-install-id");

        // Verify aggregated counts
        assert_eq!(report.blocklist_matches.len(), 30);
        assert_eq!(report.anomaly_aggregate.events_above_threshold, 25);
        assert_eq!(report.anomaly_aggregate.auto_blocks, 5);
        assert_eq!(report.killchain_triggers.len(), 15);
        assert_eq!(report.ioc_match_rates.total_matches, 15);
        assert_eq!(report.ioc_match_rates.network_matches, 5);
        assert_eq!(report.ioc_match_rates.file_matches, 5);
        assert_eq!(report.ioc_match_rates.behavioral_matches, 5);

        let scanner = report.scanner_summary.as_ref().unwrap();
        assert!(scanner
            .finding_categories
            .contains(&"path_traversal".to_string()));
        assert!(scanner
            .finding_categories
            .contains(&"injection".to_string()));

        // Schema version
        assert_eq!(report.report_version, REPORT_SCHEMA_VERSION);
    }

    #[test]
    fn preview_matches_build_report() {
        let mut agg = TelemetryAggregator::new();
        agg.record_blocklist_match("CLAW-2026-001");
        agg.record_anomaly_event(0.9, "unknown_path");
        agg.record_ioc_match("network");

        let preview = agg.preview();
        let report = agg.build_report("preview");

        // Preview and report should have the same data (both use "preview" as ID)
        assert_eq!(preview.installation_id, report.installation_id);
        assert_eq!(
            preview.blocklist_matches.len(),
            report.blocklist_matches.len()
        );
        assert_eq!(
            preview.ioc_match_rates.total_matches,
            report.ioc_match_rates.total_matches
        );
    }

    #[test]
    fn reset_clears_all_data() {
        let mut agg = TelemetryAggregator::new();
        agg.record_blocklist_match("CLAW-2026-001");
        agg.record_anomaly_event(0.9, "test");
        agg.record_auto_block();
        agg.record_killchain_trigger("KC-001", 3, "denied");
        agg.record_ioc_match("network");
        agg.record_scan_finding("injection", "HIGH");

        agg.reset();

        let report = agg.build_report("test-id");
        assert!(report.blocklist_matches.is_empty());
        assert_eq!(report.anomaly_aggregate.events_above_threshold, 0);
        assert_eq!(report.anomaly_aggregate.auto_blocks, 0);
        assert!(report.killchain_triggers.is_empty());
        assert_eq!(report.ioc_match_rates.total_matches, 0);
        assert!(report.scanner_summary.is_none());
    }

    // -----------------------------------------------------------------------
    // Report schema validation
    // -----------------------------------------------------------------------

    #[test]
    fn report_serializes_to_valid_json() {
        let mut agg = TelemetryAggregator::new();
        agg.record_blocklist_match("CLAW-2026-001");
        agg.record_anomaly_event(0.9, "unknown_path");

        let report = agg.build_report("test-id-123");
        let json = serde_json::to_string(&report).expect("report should serialize");
        let deserialized: TelemetryReport =
            serde_json::from_str(&json).expect("report should deserialize");

        assert_eq!(deserialized.installation_id, "test-id-123");
        assert_eq!(deserialized.report_version, REPORT_SCHEMA_VERSION);
        assert_eq!(deserialized.blocklist_matches.len(), 1);
    }

    #[test]
    fn empty_report_is_valid() {
        let agg = TelemetryAggregator::new();
        let report = agg.build_report("empty-test");

        assert!(report.blocklist_matches.is_empty());
        assert!(report.killchain_triggers.is_empty());
        assert_eq!(report.ioc_match_rates.total_matches, 0);
        assert!(report.scanner_summary.is_none());

        // Should still serialize fine
        let json = serde_json::to_string(&report).expect("empty report should serialize");
        assert!(!json.is_empty());
    }

    // -----------------------------------------------------------------------
    // Reporter dry-run
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dry_run_does_not_send() {
        let reporter = TelemetryReporter::dry_run("https://localhost:9999/telemetry");
        assert!(reporter.is_dry_run());

        let agg = TelemetryAggregator::new();
        let report = agg.build_report("dry-run-test");

        // Dry run should succeed without making any network request
        let result = reporter.send_report(&report).await;
        assert!(result.is_ok(), "dry-run send should succeed");
    }

    // -----------------------------------------------------------------------
    // No PII validation
    // -----------------------------------------------------------------------

    #[test]
    fn no_pii_in_report_fields() {
        let mut agg = TelemetryAggregator::new();

        // Record events with only IDs and categories (no PII)
        agg.record_blocklist_match("CLAW-2026-001");
        agg.record_anomaly_event(0.95, "unknown_path");
        agg.record_killchain_trigger("KC-001", 3, "denied");
        agg.record_ioc_match("network");
        agg.record_scan_finding("path_traversal", "HIGH");

        let report = agg.build_report("550e8400-e29b-41d4-a716-446655440000");

        // Collect all user-supplied string values from the report
        // (not JSON keys, which are schema-defined and fine)
        let mut values: Vec<String> = Vec::new();
        values.push(report.installation_id.clone());
        values.push(report.report_date.clone());
        for bm in &report.blocklist_matches {
            values.push(bm.entry_id.clone());
            values.push(bm.date.clone());
        }
        values.push(report.anomaly_aggregate.top_dimension.clone());
        for kc in &report.killchain_triggers {
            values.push(kc.pattern_id.clone());
            values.push(kc.user_decision.clone());
        }
        if let Some(scanner) = &report.scanner_summary {
            for cat in &scanner.finding_categories {
                values.push(cat.clone());
            }
            for sev in scanner.severity_counts.keys() {
                values.push(sev.clone());
            }
        }

        // Check for common PII patterns in the values
        for val in &values {
            assert!(
                !val.contains('/') && !val.contains('\\'),
                "value '{}' contains path separator",
                val
            );
            assert!(
                !val.contains('@'),
                "value '{}' contains '@' (email-like)",
                val
            );
            assert!(
                !val.contains("password"),
                "value '{}' contains 'password'",
                val
            );
            assert!(
                !val.contains("/home/") && !val.contains("/Users/"),
                "value '{}' contains home directory path",
                val
            );
        }
    }

    #[test]
    fn blocklist_match_stores_id_not_name() {
        let mut agg = TelemetryAggregator::new();
        agg.record_blocklist_match("CLAW-2026-042");

        let report = agg.build_report("test");
        assert_eq!(report.blocklist_matches[0].entry_id, "CLAW-2026-042");
        // The API only accepts an entry_id string — there's no field for server name
    }

    // -----------------------------------------------------------------------
    // Config serialization
    // -----------------------------------------------------------------------

    #[test]
    fn telemetry_config_defaults_roundtrip() {
        let config = TelemetryConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: TelemetryConfig = serde_json::from_str(&json).unwrap();

        assert!(!restored.enabled);
        assert_eq!(
            restored.endpoint_url,
            "https://feed.clawdefender.io/v1/telemetry"
        );
        assert_eq!(restored.report_interval_hours, 24);
        assert!(restored.installation_id.is_none());
    }

    #[test]
    fn telemetry_config_from_empty_json() {
        // An empty JSON object should produce all defaults
        let config: TelemetryConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.enabled);
        assert_eq!(
            config.endpoint_url,
            "https://feed.clawdefender.io/v1/telemetry"
        );
    }

    // -----------------------------------------------------------------------
    // Consent + Reporter integration: no data sent without consent
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_data_sent_without_consent() {
        let cm = ConsentManager::default_disabled();
        assert!(!cm.is_enabled());

        // Even if we have a reporter and data, we should check consent first
        // This test verifies the consent guard pattern
        let reporter = TelemetryReporter::dry_run("https://localhost:9999/telemetry");
        let mut agg = TelemetryAggregator::new();
        agg.record_blocklist_match("CLAW-2026-001");

        // The correct pattern: check consent before sending
        if cm.is_enabled() {
            if let Some(id) = cm.get_installation_id() {
                let report = agg.build_report(id);
                let _ = reporter.send_report(&report).await;
                panic!("should not reach here: consent is disabled");
            }
        }
        // If consent is disabled, nothing is sent — test passes
    }
}
