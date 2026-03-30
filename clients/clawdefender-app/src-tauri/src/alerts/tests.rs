use super::engine::{process_event, AlertStatus, AlertType, IntelligentAlert};
use super::dedup::{should_dedup, merge_into_existing};
use super::lifecycle::{
    add_alert, auto_expire_alerts, dismiss_alert, dismiss_all, get_active_alerts,
    get_alert_history, get_alert_stats, resolve_alert,
};
use crate::state::AuditEvent;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn make_event(id: &str, server: &str, action: &str, decision: &str, risk_level: &str) -> AuditEvent {
    AuditEvent {
        id: id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: "proxy".to_string(),
        server_name: server.to_string(),
        tool_name: None,
        action: action.to_string(),
        decision: decision.to_string(),
        risk_level: risk_level.to_string(),
        details: String::new(),
        resource: None,
    }
}

fn make_event_with_details(
    id: &str,
    server: &str,
    action: &str,
    decision: &str,
    risk_level: &str,
    details: &str,
    resource: Option<&str>,
    tool_name: Option<&str>,
    event_type: &str,
) -> AuditEvent {
    AuditEvent {
        id: id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: event_type.to_string(),
        server_name: server.to_string(),
        tool_name: tool_name.map(|s| s.to_string()),
        action: action.to_string(),
        decision: decision.to_string(),
        risk_level: risk_level.to_string(),
        details: details.to_string(),
        resource: resource.map(|s| s.to_string()),
    }
}

fn make_event_at_time(
    id: &str,
    server: &str,
    action: &str,
    decision: &str,
    risk_level: &str,
    timestamp: &str,
) -> AuditEvent {
    AuditEvent {
        id: id.to_string(),
        timestamp: timestamp.to_string(),
        event_type: "proxy".to_string(),
        server_name: server.to_string(),
        tool_name: None,
        action: action.to_string(),
        decision: decision.to_string(),
        risk_level: risk_level.to_string(),
        details: String::new(),
        resource: None,
    }
}

// ---------------------------------------------------------------------------
// Alert promotion tests
// ---------------------------------------------------------------------------

#[test]
fn test_anomaly_high_risk_produces_alert() {
    let event = make_event("evt-1", "filesystem", "File Read", "allow", "high");
    let alerts = process_event(&event, &[]);
    assert!(!alerts.is_empty());
    assert!(alerts.iter().any(|a| a.alert_type == AlertType::Anomaly));
}

#[test]
fn test_anomaly_critical_risk_produces_dangerous_alert() {
    let event = make_event("evt-1", "filesystem", "File Read", "allow", "critical");
    let alerts = process_event(&event, &[]);
    assert!(!alerts.is_empty());
    let anomaly = alerts.iter().find(|a| a.alert_type == AlertType::Anomaly).unwrap();
    assert_eq!(anomaly.severity, "dangerous");
}

#[test]
fn test_no_alert_for_low_risk() {
    let event = make_event("evt-1", "filesystem", "File Read", "allow", "low");
    let alerts = process_event(&event, &[]);
    assert!(alerts.is_empty());
}

#[test]
fn test_block_alert_on_auto_denied() {
    let event = make_event_with_details(
        "evt-1", "suspicious-server", "Shell Exec", "blocked", "high",
        "auto-blocked by policy", None, None, "proxy",
    );
    let alerts = process_event(&event, &[]);
    assert!(alerts.iter().any(|a| a.alert_type == AlertType::Block));
}

#[test]
fn test_ioc_match_produces_threat_intel_alert() {
    let event = make_event_with_details(
        "evt-1", "compromised", "Network Connect", "blocked", "high",
        "Matched ioc feed entry for malicious.com", None, None, "network",
    );
    let alerts = process_event(&event, &[]);
    assert!(alerts.iter().any(|a| a.alert_type == AlertType::ThreatIntel));
    let ti = alerts.iter().find(|a| a.alert_type == AlertType::ThreatIntel).unwrap();
    assert_eq!(ti.severity, "dangerous");
}

#[test]
fn test_uncorrelated_produces_correlation_alert() {
    let event = make_event_with_details(
        "evt-1", "unknown", "System Activity", "allow", "medium",
        "uncorrelated OS event detected", None, None, "system",
    );
    let alerts = process_event(&event, &[]);
    assert!(alerts.iter().any(|a| a.alert_type == AlertType::Correlation));
}

#[test]
fn test_timeout_produces_timeout_alert() {
    let event = make_event_with_details(
        "evt-1", "server-a", "Shell Exec", "denied", "medium",
        "Prompt timed out after 30s", None, None, "proxy",
    );
    let alerts = process_event(&event, &[]);
    assert!(alerts.iter().any(|a| a.alert_type == AlertType::Timeout));
}

#[test]
fn test_new_tool_produces_discovery_alert() {
    let event = make_event_with_details(
        "evt-1", "new-server", "new tool detected", "allow", "low",
        "", None, None, "new_tool",
    );
    let alerts = process_event(&event, &[]);
    assert!(alerts.iter().any(|a| a.alert_type == AlertType::Discovery));
}

#[test]
fn test_vulnerability_produces_alert() {
    let event = make_event_with_details(
        "evt-1", "vuln-server", "Config Read", "allow", "high",
        "CVE-2024-1234 vulnerability detected", None, None, "proxy",
    );
    let alerts = process_event(&event, &[]);
    assert!(alerts.iter().any(|a| a.alert_type == AlertType::Vulnerability));
}

#[test]
fn test_slm_high_risk_produces_analysis_alert() {
    let event = make_event_with_details(
        "evt-1", "analyzed-server", "Tool Call", "allow", "medium",
        r#"{"slm_analysis": {"risk_level": "high", "explanation": "suspicious"}}"#,
        None, None, "proxy",
    );
    let alerts = process_event(&event, &[]);
    assert!(alerts.iter().any(|a| a.alert_type == AlertType::Analysis));
}

// ---------------------------------------------------------------------------
// Deduplication tests
// ---------------------------------------------------------------------------

#[test]
fn test_dedup_10_similar_events_produces_single_alert() {
    let mut store: Vec<IntelligentAlert> = Vec::new();

    for i in 0..10 {
        let event = make_event(&format!("evt-{}", i), "server-a", "File Read", "allow", "high");
        let alerts = process_event(&event, &[]);
        for alert in alerts {
            add_alert(&mut store, alert);
        }
    }

    let active = get_active_alerts(&store);
    // Should be deduplicated into 1 alert with count >= 10
    assert_eq!(active.len(), 1);
    assert!(active[0].dedup_count >= 10);
}

#[test]
fn test_ioc_alerts_never_deduplicated() {
    let mut store: Vec<IntelligentAlert> = Vec::new();

    for i in 0..3 {
        let event = make_event_with_details(
            &format!("evt-{}", i), "server-a", "Network", "blocked", "high",
            "ioc match detected", None, None, "proxy",
        );
        let alerts = process_event(&event, &[]);
        for alert in alerts {
            if alert.alert_type == AlertType::ThreatIntel {
                add_alert(&mut store, alert);
            }
        }
    }

    let ioc_alerts: Vec<&IntelligentAlert> = store.iter().filter(|a| a.alert_type == AlertType::ThreatIntel).collect();
    // Each IoC should be a separate alert
    assert_eq!(ioc_alerts.len(), 3);
}

#[test]
fn test_should_dedup_same_key_within_window() {
    let now = chrono::Utc::now().to_rfc3339();
    let a1 = IntelligentAlert {
        id: "alert-1".to_string(),
        alert_type: AlertType::Anomaly,
        severity: "suspicious".to_string(),
        status: AlertStatus::Active,
        title: "Test".to_string(),
        description: "Test".to_string(),
        recommendation: "Test".to_string(),
        source_events: vec!["evt-1".to_string()],
        server_name: Some("server-a".to_string()),
        created_at: now.clone(),
        updated_at: now.clone(),
        resolved_at: None,
        resolved_by: None,
        dedup_key: "anomaly:server-a:test".to_string(),
        dedup_count: 1,
        actions: vec![],
        kill_chain: None,
        ai_summary: None,
        ai_risk_level: None,
        ai_confidence: None,
        ai_recommendation: None,
    };
    let a2 = IntelligentAlert {
        id: "alert-2".to_string(),
        dedup_key: "anomaly:server-a:test".to_string(),
        ..a1.clone()
    };
    assert!(should_dedup(&a2, &a1));
}

#[test]
fn test_merge_into_existing_increments_count() {
    let now = chrono::Utc::now().to_rfc3339();
    let mut existing = IntelligentAlert {
        id: "alert-1".to_string(),
        alert_type: AlertType::Anomaly,
        severity: "suspicious".to_string(),
        status: AlertStatus::Active,
        title: "Test".to_string(),
        description: "Test".to_string(),
        recommendation: "Test".to_string(),
        source_events: vec!["evt-1".to_string()],
        server_name: Some("server-a".to_string()),
        created_at: now.clone(),
        updated_at: now,
        resolved_at: None,
        resolved_by: None,
        dedup_key: "anomaly:server-a:test".to_string(),
        dedup_count: 1,
        actions: vec![],
        kill_chain: None,
        ai_summary: None,
        ai_risk_level: None,
        ai_confidence: None,
        ai_recommendation: None,
    };

    merge_into_existing(&mut existing, "evt-2");
    assert_eq!(existing.dedup_count, 2);
    assert!(existing.source_events.contains(&"evt-2".to_string()));
}

// ---------------------------------------------------------------------------
// Kill chain tests
// ---------------------------------------------------------------------------

#[test]
fn test_kill_chain_credential_exfiltration() {
    let now = chrono::Utc::now();
    let t1 = (now - chrono::Duration::seconds(30)).to_rfc3339();
    let t2 = now.to_rfc3339();

    let read_event = AuditEvent {
        id: "evt-1".to_string(),
        timestamp: t1,
        event_type: "proxy".to_string(),
        server_name: "evil-server".to_string(),
        tool_name: Some("read_file".to_string()),
        action: "File Read".to_string(),
        decision: "allow".to_string(),
        risk_level: "high".to_string(),
        details: String::new(),
        resource: Some("/home/user/.ssh/id_rsa".to_string()),
    };

    let network_event = AuditEvent {
        id: "evt-2".to_string(),
        timestamp: t2,
        event_type: "network".to_string(),
        server_name: "evil-server".to_string(),
        tool_name: None,
        action: "Network Connect".to_string(),
        decision: "blocked".to_string(),
        risk_level: "high".to_string(),
        details: String::new(),
        resource: Some("malicious.example.com:443".to_string()),
    };

    let alerts = process_event(&network_event, &[read_event]);
    let kc = alerts.iter().find(|a| a.alert_type == AlertType::KillChain);
    assert!(kc.is_some(), "Should detect credential exfiltration kill chain");
    let kc = kc.unwrap();
    assert_eq!(kc.severity, "dangerous");
    assert!(kc.kill_chain.is_some());
    assert_eq!(kc.kill_chain.as_ref().unwrap().pattern_name, "credential_exfiltration");
}

#[test]
fn test_kill_chain_supersedes_individual_alerts() {
    let now = chrono::Utc::now();
    let t1 = (now - chrono::Duration::seconds(20)).to_rfc3339();
    let t2 = now.to_rfc3339();

    let read_event = AuditEvent {
        id: "evt-1".to_string(),
        timestamp: t1,
        event_type: "proxy".to_string(),
        server_name: "evil-server".to_string(),
        tool_name: Some("read_file".to_string()),
        action: "File Read".to_string(),
        decision: "allow".to_string(),
        risk_level: "high".to_string(),
        details: String::new(),
        resource: Some("/home/user/.aws/credentials".to_string()),
    };

    let network_event = AuditEvent {
        id: "evt-2".to_string(),
        timestamp: t2,
        event_type: "network".to_string(),
        server_name: "evil-server".to_string(),
        tool_name: None,
        action: "Outbound Connection".to_string(),
        decision: "blocked".to_string(),
        risk_level: "high".to_string(),
        details: String::new(),
        resource: None,
    };

    let alerts = process_event(&network_event, &[read_event]);
    // Kill chain should be the ONLY alert (supersedes anomaly)
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].alert_type, AlertType::KillChain);
}

// ---------------------------------------------------------------------------
// Lifecycle tests
// ---------------------------------------------------------------------------

#[test]
fn test_dismiss_alert_changes_status() {
    let event = make_event("evt-1", "server-a", "Action", "allow", "high");
    let alerts = process_event(&event, &[]);
    let mut store = alerts;

    assert!(!store.is_empty());
    let id = store[0].id.clone();
    dismiss_alert(&mut store, &id);
    assert_eq!(store[0].status, AlertStatus::Dismissed);
    assert!(store[0].resolved_at.is_some());
}

#[test]
fn test_resolve_alert_changes_status() {
    let event = make_event("evt-1", "server-a", "Action", "allow", "high");
    let alerts = process_event(&event, &[]);
    let mut store = alerts;

    let id = store[0].id.clone();
    resolve_alert(&mut store, &id, "user");
    assert_eq!(store[0].status, AlertStatus::Resolved);
    assert_eq!(store[0].resolved_by, Some("user".to_string()));
}

#[test]
fn test_auto_expire_block_alert() {
    let mut store: Vec<IntelligentAlert> = Vec::new();
    let event = make_event_with_details(
        "evt-1", "server-a", "Shell Exec", "blocked", "high",
        "auto-blocked by policy", None, None, "proxy",
    );
    let alerts = process_event(&event, &[]);
    for alert in alerts {
        add_alert(&mut store, alert);
    }

    // Manually set created_at to 25 hours ago to simulate expiry
    let old_time = (chrono::Utc::now() - chrono::Duration::hours(25)).to_rfc3339();
    for alert in store.iter_mut() {
        if alert.alert_type == AlertType::Block {
            alert.created_at = old_time.clone();
        }
    }

    let expired = auto_expire_alerts(&mut store);
    assert!(expired > 0);
    let block_alerts: Vec<&IntelligentAlert> = store.iter().filter(|a| a.alert_type == AlertType::Block).collect();
    assert!(block_alerts.iter().all(|a| a.status == AlertStatus::AutoExpired));
}

#[test]
fn test_dismiss_all_with_severity_filter() {
    let mut store: Vec<IntelligentAlert> = Vec::new();

    // Add one "info" and one "dangerous" alert
    let info_event = make_event_with_details(
        "evt-1", "server-a", "new tool detected", "allow", "low",
        "", None, None, "new_tool",
    );
    let danger_event = make_event_with_details(
        "evt-2", "server-b", "Action", "blocked", "high",
        "ioc match", None, None, "proxy",
    );

    for alert in process_event(&info_event, &[]) {
        add_alert(&mut store, alert);
    }
    for alert in process_event(&danger_event, &[]) {
        add_alert(&mut store, alert);
    }

    // Dismiss only "info" severity and below
    let count = dismiss_all(&mut store, Some("info"));
    // Only info alerts should be dismissed
    let still_active = get_active_alerts(&store);
    assert!(count > 0);
    assert!(!still_active.is_empty()); // dangerous alerts should remain
    for a in &still_active {
        assert_ne!(a.severity, "info");
    }
}

#[test]
fn test_alert_stats_computation() {
    let mut store: Vec<IntelligentAlert> = Vec::new();

    // Add some alerts
    for i in 0..5 {
        let event = make_event(&format!("evt-{}", i), "server-a", "Action", "allow", "high");
        let mut alerts = process_event(&event, &[]);
        // Make first one unique
        if let Some(a) = alerts.first_mut() {
            a.dedup_key = format!("unique-{}", i);
        }
        for alert in alerts {
            add_alert(&mut store, alert);
        }
    }

    // Resolve one
    if let Some(id) = store.first().map(|a| a.id.clone()) {
        resolve_alert(&mut store, &id, "user");
    }

    let stats = get_alert_stats(&store);
    assert_eq!(stats.total_active, 4);
    assert_eq!(stats.resolved_this_week, 1);
}

#[test]
fn test_get_alert_history() {
    let mut store: Vec<IntelligentAlert> = Vec::new();
    let event = make_event("evt-1", "server-a", "Action", "allow", "high");
    let alerts = process_event(&event, &[]);
    for alert in alerts {
        add_alert(&mut store, alert);
    }

    let id = store[0].id.clone();
    resolve_alert(&mut store, &id, "user");

    let history = get_alert_history(&store, 7);
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].status, AlertStatus::Resolved);
}
