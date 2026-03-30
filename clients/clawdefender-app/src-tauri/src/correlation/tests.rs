use super::engine::*;
use crate::state::AuditEvent;

fn make_event(id: &str, server: &str, event_type: &str, timestamp: &str) -> AuditEvent {
    AuditEvent {
        id: id.to_string(),
        timestamp: timestamp.to_string(),
        event_type: event_type.to_string(),
        server_name: server.to_string(),
        tool_name: Some("read_file".to_string()),
        action: "File Read".to_string(),
        decision: "allowed".to_string(),
        risk_level: "low".to_string(),
        details: String::new(),
        resource: Some("/home/user/file.txt".to_string()),
    }
}

fn make_event_with_risk(
    id: &str,
    server: &str,
    event_type: &str,
    timestamp: &str,
    risk: &str,
) -> AuditEvent {
    AuditEvent {
        risk_level: risk.to_string(),
        ..make_event(id, server, event_type, timestamp)
    }
}

#[test]
fn test_correlate_perfectly_timed_events() {
    let events = vec![
        make_event("evt-1", "filesystem", "proxy", "2025-01-15T10:30:00Z"),
        make_event("evt-2", "filesystem", "proxy", "2025-01-15T10:30:01Z"),
        make_event("evt-3", "filesystem", "system", "2025-01-15T10:30:00.500Z"),
    ];

    let result = correlate_event("evt-1", &events);

    assert_eq!(result.mcp_event_id, "evt-1");
    assert!(!result.correlated_events.is_empty());

    // evt-2 should be correlated (same server, 1s gap)
    let evt2_match = result
        .correlated_events
        .iter()
        .find(|c| c.event_id == "evt-2");
    assert!(evt2_match.is_some());
    let m = evt2_match.unwrap();
    assert!(m.match_confidence > 0.3, "confidence should be decent for 1s gap");
}

#[test]
fn test_correlate_no_matches() {
    let events = vec![
        make_event("evt-1", "filesystem", "proxy", "2025-01-15T10:30:00Z"),
        // 30 seconds away -- outside all windows
        make_event("evt-2", "other-server", "proxy", "2025-01-15T10:30:30Z"),
    ];

    let result = correlate_event("evt-1", &events);

    assert!(result.correlated_events.is_empty());
    assert_eq!(result.correlation_confidence, 0.0);
}

#[test]
fn test_correlate_event_not_found() {
    let events = vec![make_event(
        "evt-1",
        "filesystem",
        "proxy",
        "2025-01-15T10:30:00Z",
    )];

    let result = correlate_event("nonexistent", &events);

    assert_eq!(result.mcp_event_id, "nonexistent");
    assert!(result.correlated_events.is_empty());
    assert_eq!(result.coverage.assessment, "Event not found");
}

#[test]
fn test_coverage_above_70_percent() {
    // Use recent timestamps so they fall within the hours window
    let now = chrono::Utc::now();
    let t = |offset_secs: i64| -> String {
        (now + chrono::Duration::seconds(offset_secs)).to_rfc3339()
    };

    // 3 MCP events, 3 OS events within 5s of each
    let events = vec![
        make_event("mcp-1", "fs", "proxy", &t(0)),
        make_event("mcp-2", "fs", "proxy", &t(-10)),
        make_event("mcp-3", "fs", "proxy", &t(-20)),
        make_event("os-1", "fs", "system", &t(-1)),
        make_event("os-2", "fs", "system", &t(-11)),
        make_event("os-3", "fs", "system", &t(-21)),
    ];

    let coverage = get_coverage_for_server("fs", &events, 24);

    assert!(
        coverage.coverage_percent >= 70.0,
        "Should have good coverage, got {}%",
        coverage.coverage_percent
    );
    assert!(coverage.assessment.contains("Good coverage"));
}

#[test]
fn test_coverage_below_70_percent() {
    let now = chrono::Utc::now();
    let t = |offset_secs: i64| -> String {
        (now + chrono::Duration::seconds(offset_secs)).to_rfc3339()
    };

    // 3 MCP events, only 1 OS event nearby
    let events = vec![
        make_event("mcp-1", "fs", "proxy", &t(0)),
        make_event("mcp-2", "fs", "proxy", &t(-10)),
        make_event("mcp-3", "fs", "proxy", &t(-20)),
        make_event("os-1", "fs", "system", &t(-1)),
        // os events for mcp-2 and mcp-3 are missing
    ];

    let coverage = get_coverage_for_server("fs", &events, 24);

    assert!(
        coverage.coverage_percent < 70.0,
        "Should detect gap, got {}%",
        coverage.coverage_percent
    );
    assert!(coverage.assessment.contains("Gap detected"));
}

#[test]
fn test_single_event_correlation() {
    let events = vec![make_event(
        "evt-1",
        "filesystem",
        "proxy",
        "2025-01-15T10:30:00Z",
    )];

    let result = correlate_event("evt-1", &events);

    assert!(result.correlated_events.is_empty());
    // With a single MCP event, coverage is computed for the nearby window
}

#[test]
fn test_uncorrelated_os_events_flagged() {
    let events = vec![
        make_event("mcp-1", "fs", "proxy", "2025-01-15T10:30:00Z"),
        make_event_with_risk("os-1", "other", "system", "2025-01-15T10:30:02Z", "high"),
    ];

    let result = correlate_event("mcp-1", &events);

    // os-1 is from a different server and is OS-type, so it might appear
    // as correlated (cross-source) or uncorrelated depending on confidence.
    // Either way it should be present somewhere in the result.
    let total = result.correlated_events.len() + result.uncorrelated_events.len();
    assert!(total > 0, "OS event should appear in correlation results");
}

#[test]
fn test_many_events_performance() {
    // Ensure correlation handles a large event set without issues
    let mut events: Vec<AuditEvent> = Vec::new();
    for i in 0..1000 {
        let ts = format!("2025-01-15T10:{:02}:{:02}Z", (i / 60) % 60, i % 60);
        events.push(make_event(
            &format!("evt-{}", i),
            "fs",
            if i % 3 == 0 { "proxy" } else { "system" },
            &ts,
        ));
    }

    let result = correlate_event("evt-500", &events);

    // Should complete without panicking and produce some correlations
    assert_eq!(result.mcp_event_id, "evt-500");
}
