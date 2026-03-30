use super::generator::*;
use super::recommendations::*;
use super::trends::*;
use crate::state::{AuditEvent, ServerProfileSummary};
use chrono::{Duration, Utc};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_ID: AtomicU64 = AtomicU64::new(0);

fn make_event(
    server: &str,
    action: &str,
    decision: &str,
    risk_level: &str,
    resource: Option<&str>,
    timestamp: &str,
) -> AuditEvent {
    AuditEvent {
        id: format!("digest-test-{}", TEST_ID.fetch_add(1, Ordering::Relaxed)),
        timestamp: timestamp.to_string(),
        event_type: "proxy".to_string(),
        server_name: server.to_string(),
        tool_name: Some(server.to_string()),
        action: action.to_string(),
        decision: decision.to_string(),
        risk_level: risk_level.to_string(),
        details: String::new(),
        resource: resource.map(|s| s.to_string()),
    }
}

fn make_profile(
    server: &str,
    total_calls: u64,
    status: &str,
    anomaly_score: f64,
) -> ServerProfileSummary {
    ServerProfileSummary {
        server_name: server.to_string(),
        tools_count: 5,
        total_calls,
        anomaly_score,
        status: status.to_string(),
        last_activity: Utc::now().to_rfc3339(),
    }
}

fn recent_ts(hours_ago: i64) -> String {
    (Utc::now() - Duration::hours(hours_ago)).to_rfc3339()
}

// =========================================================================
// Digest generation tests
// =========================================================================

#[test]
fn test_digest_quiet_week() {
    let events = vec![
        make_event("claude-fs", "read", "allow", "low", Some("/home/user/file.rs"), &recent_ts(2)),
        make_event("claude-fs", "read", "allow", "low", Some("/home/user/lib.rs"), &recent_ts(4)),
    ];
    let profiles = vec![make_profile("claude-fs", 200, "active", 0.05)];

    let digest = generate_weekly_digest(&events, &profiles);

    assert_eq!(digest.stats.total_events, 2);
    assert_eq!(digest.stats.threats_blocked, 0);
    assert_eq!(digest.stats.servers_monitored, 1);
    assert!(digest.summary_text.contains("Here's your week in review"));
    assert!(digest.summary_text.contains("quiet week"));
    assert!(!digest.period_start.is_empty());
    assert!(!digest.period_end.is_empty());
}

#[test]
fn test_digest_active_week_with_threats() {
    let mut events = Vec::new();
    for i in 0..50 {
        events.push(make_event(
            "cursor-fs",
            "read",
            "allow",
            "low",
            Some("/project/src/file.rs"),
            &recent_ts(i),
        ));
    }
    events.push(make_event(
        "suspicious-server",
        "execute_command",
        "blocked",
        "high",
        None,
        &recent_ts(10),
    ));
    events.push(make_event(
        "suspicious-server",
        "connect",
        "denied",
        "critical",
        Some("evil.example.com"),
        &recent_ts(5),
    ));

    let profiles = vec![
        make_profile("cursor-fs", 500, "active", 0.02),
        make_profile("suspicious-server", 10, "learning", 0.8),
    ];

    let digest = generate_weekly_digest(&events, &profiles);

    assert_eq!(digest.stats.total_events, 52);
    assert_eq!(digest.stats.threats_blocked, 2);
    assert!(!digest.highlights.is_empty());
    assert!(digest
        .highlights
        .iter()
        .any(|h| h.highlight_type == "threat_blocked"));
    assert!(digest.summary_text.contains("Here's your week in review"));
}

#[test]
fn test_digest_events_by_category() {
    let events = vec![
        make_event("fs", "read", "allow", "low", None, &recent_ts(1)),
        make_event("fs", "read_file", "allow", "low", None, &recent_ts(2)),
        make_event("fs", "write", "allow", "low", None, &recent_ts(3)),
        make_event("fs", "execute_command", "allow", "medium", None, &recent_ts(4)),
        make_event("fs", "connect", "allow", "low", None, &recent_ts(5)),
    ];

    let digest = generate_weekly_digest(&events, &[]);

    assert_eq!(
        *digest.stats.events_by_category.get("file_reads").unwrap_or(&0),
        2
    );
    assert_eq!(
        *digest.stats.events_by_category.get("file_writes").unwrap_or(&0),
        1
    );
    assert_eq!(
        *digest
            .stats
            .events_by_category
            .get("shell_executions")
            .unwrap_or(&0),
        1
    );
    assert_eq!(
        *digest
            .stats
            .events_by_category
            .get("network_connections")
            .unwrap_or(&0),
        1
    );
}

#[test]
fn test_digest_most_active_tools() {
    let mut events = Vec::new();
    for _ in 0..20 {
        events.push(make_event("server-a", "read", "allow", "low", None, &recent_ts(1)));
    }
    for _ in 0..10 {
        events.push(make_event("server-b", "read", "allow", "low", None, &recent_ts(2)));
    }
    for _ in 0..5 {
        events.push(make_event("server-c", "read", "allow", "low", None, &recent_ts(3)));
    }
    for _ in 0..2 {
        events.push(make_event("server-d", "read", "allow", "low", None, &recent_ts(4)));
    }

    let digest = generate_weekly_digest(&events, &[]);

    assert!(digest.stats.most_active_tools.len() <= 3);
    assert_eq!(digest.stats.most_active_tools[0].server_name, "server-a");
    assert_eq!(digest.stats.most_active_tools[0].event_count, 20);
}

#[test]
fn test_digest_protection_score_stable() {
    let events = vec![
        make_event("fs", "read", "allow", "low", None, &recent_ts(1)),
    ];
    let profiles = vec![make_profile("fs", 200, "active", 0.05)];

    let digest = generate_weekly_digest(&events, &profiles);

    // With one profile and no threats, score should be stable.
    assert_eq!(digest.protection_score_trend.direction, "stable");
}

#[test]
fn test_digest_empty_events() {
    let digest = generate_weekly_digest(&[], &[]);

    assert_eq!(digest.stats.total_events, 0);
    assert_eq!(digest.stats.threats_blocked, 0);
    assert!(digest.highlights.is_empty());
    assert!(digest.summary_text.contains("Here's your week in review"));
}

// =========================================================================
// Recommendation tests
// =========================================================================

#[test]
fn test_recommendation_frequent_prompts() {
    let mut events = Vec::new();
    for _ in 0..8 {
        events.push(make_event("claude-fs", "read_file", "prompted", "low", None, &recent_ts(1)));
    }

    let recs = generate_recommendations(&events, &[]);

    assert!(recs.iter().any(|r| r.rec_type == "frequent_prompt"));
    let rec = recs.iter().find(|r| r.rec_type == "frequent_prompt").unwrap();
    assert!(rec.description.contains("8 times"));
    assert_eq!(rec.action_type, "add_allow_rule");
}

#[test]
fn test_recommendation_no_frequent_prompts_below_threshold() {
    let mut events = Vec::new();
    for _ in 0..3 {
        events.push(make_event("claude-fs", "read_file", "prompted", "low", None, &recent_ts(1)));
    }

    let recs = generate_recommendations(&events, &[]);

    assert!(!recs.iter().any(|r| r.rec_type == "frequent_prompt"));
}

#[test]
fn test_recommendation_permission_tightening() {
    let mut events = Vec::new();
    // 15 reads from /home/user/project, 2 from elsewhere.
    for _ in 0..15 {
        events.push(make_event(
            "fs-server",
            "read",
            "allow",
            "low",
            Some("/home/user/project/src/main.rs"),
            &recent_ts(1),
        ));
    }
    events.push(make_event(
        "fs-server",
        "read",
        "allow",
        "low",
        Some("/tmp/cache.txt"),
        &recent_ts(2),
    ));

    let recs = generate_recommendations(&events, &[]);

    assert!(recs.iter().any(|r| r.rec_type == "permission_tightening"));
}

#[test]
fn test_recommendation_trust_suggestion() {
    let profiles = vec![make_profile("stable-server", 600, "active", 0.02)];

    let recs = generate_recommendations(&[], &profiles);

    assert!(recs.iter().any(|r| r.rec_type == "trust_suggestion"));
    let rec = recs.iter().find(|r| r.rec_type == "trust_suggestion").unwrap();
    assert!(rec.description.contains("Trusted"));
    assert_eq!(rec.action_type, "change_trust_level");
}

#[test]
fn test_recommendation_learning_completion() {
    let profiles = vec![make_profile("new-server", 120, "active", 0.1)];

    let recs = generate_recommendations(&[], &profiles);

    assert!(recs.iter().any(|r| r.rec_type == "learning_completion"));
    let rec = recs.iter().find(|r| r.rec_type == "learning_completion").unwrap();
    assert!(rec.description.contains("behavioral profile is ready"));
}

#[test]
fn test_recommendation_unwrapped_servers() {
    let events = vec![
        make_event("unwatched-1", "read", "unmonitored", "low", None, &recent_ts(1)),
        make_event("unwatched-2", "read", "unmonitored", "low", None, &recent_ts(2)),
    ];

    let recs = generate_recommendations(&events, &[]);

    assert!(recs.iter().any(|r| r.rec_type == "unwrapped_servers"));
    let rec = recs.iter().find(|r| r.rec_type == "unwrapped_servers").unwrap();
    assert!(rec.description.contains("2 servers"));
}

#[test]
fn test_recommendation_sorted_by_priority() {
    // Create events that trigger both frequent_prompt and unwrapped recs.
    let mut events = Vec::new();
    for _ in 0..8 {
        events.push(make_event("fs", "read", "prompted", "low", None, &recent_ts(1)));
    }
    events.push(make_event("unwatched", "read", "unmonitored", "low", None, &recent_ts(2)));

    let recs = generate_recommendations(&events, &[]);

    // Verify sorted by priority (ascending).
    for pair in recs.windows(2) {
        assert!(pair[0].priority <= pair[1].priority);
    }
}

#[test]
fn test_execute_recommendation_add_allow_rule() {
    let rec = Recommendation {
        id: "test".to_string(),
        rec_type: "frequent_prompt".to_string(),
        description: "test".to_string(),
        action_label: "Add rule".to_string(),
        action_type: "add_allow_rule".to_string(),
        action_params: Some(serde_json::json!({
            "server_name": "claude-fs",
            "action": "read_file",
        })),
        priority: 1,
        dismissed: false,
    };

    let result = execute_recommendation(&rec);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("permanent allow rule"));
}

#[test]
fn test_execute_recommendation_restrict_territory() {
    let rec = Recommendation {
        id: "test".to_string(),
        rec_type: "permission_tightening".to_string(),
        description: "test".to_string(),
        action_label: "Restrict".to_string(),
        action_type: "restrict_territory".to_string(),
        action_params: Some(serde_json::json!({
            "server_name": "fs-server",
            "directory": "/home/user/project",
        })),
        priority: 2,
        dismissed: false,
    };

    let result = execute_recommendation(&rec);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("restricted"));
}

#[test]
fn test_execute_recommendation_change_trust() {
    let rec = Recommendation {
        id: "test".to_string(),
        rec_type: "trust_suggestion".to_string(),
        description: "test".to_string(),
        action_label: "Trust".to_string(),
        action_type: "change_trust_level".to_string(),
        action_params: Some(serde_json::json!({
            "server_name": "stable-server",
            "trust_level": "trusted",
        })),
        priority: 3,
        dismissed: false,
    };

    let result = execute_recommendation(&rec);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("trusted"));
}

#[test]
fn test_execute_recommendation_unknown_type() {
    let rec = Recommendation {
        id: "test".to_string(),
        rec_type: "unknown".to_string(),
        description: "test".to_string(),
        action_label: "Do".to_string(),
        action_type: "unknown_action".to_string(),
        action_params: None,
        priority: 5,
        dismissed: false,
    };

    let result = execute_recommendation(&rec);
    assert!(result.is_err());
}

// =========================================================================
// Trend analysis tests
// =========================================================================

#[test]
fn test_trend_stable_activity() {
    let mut events = Vec::new();
    // 10 events in current period, 10 in previous period.
    for i in 0..10 {
        events.push(make_event("fs", "read", "allow", "low", None, &recent_ts(i + 1)));
    }
    for i in 0..10 {
        events.push(make_event(
            "fs",
            "read",
            "allow",
            "low",
            None,
            &(Utc::now() - Duration::days(7) - Duration::hours(i + 1)).to_rfc3339(),
        ));
    }

    let trends = analyze_trends(&events, 7);

    assert_eq!(trends.event_rate_trend, "stable");
}

#[test]
fn test_trend_increasing_activity() {
    let mut events = Vec::new();
    // 20 events in current period, 5 in previous period.
    for i in 0..20 {
        events.push(make_event("fs", "read", "allow", "low", None, &recent_ts(i + 1)));
    }
    for i in 0..5 {
        events.push(make_event(
            "fs",
            "read",
            "allow",
            "low",
            None,
            &(Utc::now() - Duration::days(7) - Duration::hours(i + 1)).to_rfc3339(),
        ));
    }

    let trends = analyze_trends(&events, 7);

    assert_eq!(trends.event_rate_trend, "up");
}

#[test]
fn test_trend_decreasing_activity() {
    let mut events = Vec::new();
    // 3 events in current period, 20 in previous.
    for i in 0..3 {
        events.push(make_event("fs", "read", "allow", "low", None, &recent_ts(i + 1)));
    }
    for i in 0..20 {
        events.push(make_event(
            "fs",
            "read",
            "allow",
            "low",
            None,
            &(Utc::now() - Duration::days(7) - Duration::hours(i + 1)).to_rfc3339(),
        ));
    }

    let trends = analyze_trends(&events, 7);

    assert_eq!(trends.event_rate_trend, "down");
}

#[test]
fn test_trend_most_changed_tool() {
    let mut events = Vec::new();
    // server-a: 15 current, 2 previous (big increase).
    for i in 0..15 {
        events.push(make_event("server-a", "read", "allow", "low", None, &recent_ts(i + 1)));
    }
    for i in 0..2 {
        events.push(make_event(
            "server-a",
            "read",
            "allow",
            "low",
            None,
            &(Utc::now() - Duration::days(7) - Duration::hours(i + 1)).to_rfc3339(),
        ));
    }
    // server-b: stable at 5 each period.
    for i in 0..5 {
        events.push(make_event("server-b", "read", "allow", "low", None, &recent_ts(i + 1)));
    }
    for i in 0..5 {
        events.push(make_event(
            "server-b",
            "read",
            "allow",
            "low",
            None,
            &(Utc::now() - Duration::days(7) - Duration::hours(i + 1)).to_rfc3339(),
        ));
    }

    let trends = analyze_trends(&events, 7);

    assert!(trends.most_changed_tool.is_some());
    assert_eq!(
        trends.most_changed_tool.as_ref().unwrap().server_name,
        "server-a"
    );
    assert!(trends
        .most_changed_tool
        .as_ref()
        .unwrap()
        .description
        .contains("increased"));
}

#[test]
fn test_trend_threat_detection() {
    let mut events = Vec::new();
    // 3 blocked events in current period, 0 in previous.
    for i in 0..3 {
        events.push(make_event("bad", "exec", "blocked", "high", None, &recent_ts(i + 1)));
    }
    for i in 0..5 {
        events.push(make_event(
            "fs",
            "read",
            "allow",
            "low",
            None,
            &(Utc::now() - Duration::days(7) - Duration::hours(i + 1)).to_rfc3339(),
        ));
    }

    let trends = analyze_trends(&events, 7);

    assert_eq!(trends.threat_trend, "up");
}

#[test]
fn test_trend_milestones() {
    let mut events = Vec::new();
    // Create 100+ events to trigger a milestone.
    for i in 0..150 {
        events.push(make_event("fs", "read", "allow", "low", None, &recent_ts(i % 168 + 1)));
    }

    let trends = analyze_trends(&events, 7);

    assert!(!trends.milestones.is_empty());
    assert!(trends.milestones.iter().any(|m| m.contains("100")));
}

#[test]
fn test_trend_empty_events() {
    let trends = analyze_trends(&[], 7);

    assert_eq!(trends.event_rate_trend, "stable");
    assert_eq!(trends.threat_trend, "stable");
    assert!(trends.most_changed_tool.is_none());
    assert!(trends.milestones.is_empty());
}
