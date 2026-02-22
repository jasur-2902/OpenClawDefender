//! Integration tests for the network subsystem (Phase 12).
//!
//! Tests the complete conceptual flow across policy engine, DNS filter,
//! rate limiter, mock extension, network logging, and kill chain context.

use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;

use clawdefender_core::behavioral::killchain::Severity;
use clawdefender_core::dns::filter::{DnsAction, DnsFilter, DnsQuery, DnsQueryType};
use clawdefender_core::network_log::{
    ConnectionDecision, ConnectionInfo, DecisionSignals, NetworkConnectionLog, NetworkSummary,
    NetworkTrafficStats,
};
use clawdefender_core::network_policy::engine::{
    ExternalSignals, NetworkConnectionRequest, NetworkPolicyEngine,
};
use clawdefender_core::network_policy::rate_limiter::{
    ConnectionRateLimiter, RateLimitAlertType, RateLimitConfig,
};
use clawdefender_core::network_policy::rules::NetworkAction;
use clawdefender_daemon::mock_network_extension::{
    MockConnectEvent, MockNetworkDecision, MockNetworkExtension, MockNetworkExtensionConfig,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn agent_request(domain: &str, port: u16) -> NetworkConnectionRequest {
    NetworkConnectionRequest {
        pid: 1000,
        process_name: "test-agent".to_string(),
        server_name: Some("test-server".to_string()),
        is_agent: true,
        destination_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        destination_domain: Some(domain.to_string()),
        destination_port: port,
        protocol: "tcp".to_string(),
    }
}

fn non_agent_request(domain: &str) -> NetworkConnectionRequest {
    NetworkConnectionRequest {
        pid: 2000,
        process_name: "user-browser".to_string(),
        server_name: None,
        is_agent: false,
        destination_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        destination_domain: Some(domain.to_string()),
        destination_port: 443,
        protocol: "tcp".to_string(),
    }
}

fn dns_query(domain: &str) -> DnsQuery {
    DnsQuery {
        domain: domain.to_string(),
        query_type: DnsQueryType::A,
        source_pid: 1000,
        server_name: Some("test-server".to_string()),
        timestamp: Utc::now(),
    }
}

fn mock_event(pid: u32, host: &str, port: u16) -> MockConnectEvent {
    MockConnectEvent {
        pid,
        process_name: "test-process".to_string(),
        destination_host: host.to_string(),
        destination_port: port,
        protocol: "tcp".to_string(),
        timestamp: Utc::now(),
    }
}

fn make_log(
    action: &str,
    dest_ip: &str,
    dest_domain: Option<&str>,
    server: Option<&str>,
    bytes_sent: u64,
    bytes_received: u64,
) -> NetworkConnectionLog {
    NetworkConnectionLog {
        event_type: "network_connection".to_string(),
        timestamp: Utc::now(),
        pid: 1234,
        process_name: "test-process".to_string(),
        server_name: server.map(|s| s.to_string()),
        client_name: None,
        connection: ConnectionInfo {
            protocol: "tcp".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            source_port: Some(54321),
            destination_ip: dest_ip.to_string(),
            destination_port: 443,
            destination_domain: dest_domain.map(|d| d.to_string()),
            tls: true,
        },
        decision: ConnectionDecision {
            action: action.to_string(),
            reason: "policy decision".to_string(),
            rule: None,
            signals: DecisionSignals {
                ioc_match: false,
                anomaly_score: None,
                behavioral: None,
                kill_chain: None,
            },
        },
        bytes_sent,
        bytes_received,
        duration_ms: 100,
    }
}

// ===========================================================================
// Test 1: Complete conceptual flow — policy engine decides, audit record
// ===========================================================================

#[test]
fn flow_agent_connection_evaluated_and_logged() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request("api.example.com", 443);
    let signals = ExternalSignals::default();

    let decision = engine.evaluate(&request, &signals);

    // Default rules: localhost is allowed, everything else prompts for agents.
    // api.example.com matches the catch-all prompt rule.
    assert!(
        decision.action == NetworkAction::Prompt || decision.action == NetworkAction::Allow,
        "Agent connection to external domain should prompt or allow: {:?}",
        decision.action
    );

    // Create an audit log entry from the decision.
    let action_str = match decision.action {
        NetworkAction::Allow => "allowed",
        NetworkAction::Block => "blocked",
        NetworkAction::Prompt => "prompted",
        NetworkAction::Log => "allowed",
    };
    let log = make_log(
        action_str,
        "93.184.216.34",
        Some("api.example.com"),
        Some("test-server"),
        512,
        1024,
    );

    assert_eq!(log.event_type, "network_connection");
    assert_eq!(
        log.connection.destination_domain.as_deref(),
        Some("api.example.com")
    );
    assert!(!log.decision.action.is_empty());
}

// ===========================================================================
// Test 2: DNS filter blocks malicious domain, logged as block
// ===========================================================================

#[test]
fn flow_dns_filter_blocks_malicious_domain() {
    let mut filter = DnsFilter::new();
    filter.add_block("malware-c2.evil.com");

    let query = dns_query("malware-c2.evil.com");
    let result = filter.check_domain(&query);

    assert_eq!(result.action, DnsAction::Block);
    assert!(result.reason.contains("blocklist"));

    // Log the blocked DNS query as a blocked connection.
    let log = make_log(
        "blocked",
        "0.0.0.0",
        Some("malware-c2.evil.com"),
        Some("test-server"),
        0,
        0,
    );
    assert_eq!(log.decision.action, "blocked");
}

#[test]
fn flow_dns_filter_allows_safe_domain() {
    let filter = DnsFilter::new();

    let query = dns_query("api.github.com");
    let result = filter.check_domain(&query);

    assert_eq!(result.action, DnsAction::Allow);
}

#[test]
fn flow_dns_ioc_feed_blocks_domain() {
    let mut filter = DnsFilter::new();
    filter.refresh_ioc_domains(&["known-bad-domain.net".to_string()]);

    let query = dns_query("known-bad-domain.net");
    let result = filter.check_domain(&query);

    assert_eq!(result.action, DnsAction::Block);
    assert!(result.reason.contains("IoC"));
    assert!(result.threat_id.is_some());
}

// ===========================================================================
// Test 3: Rate limiter fires on burst
// ===========================================================================

#[test]
fn flow_rate_limiter_fires_on_burst() {
    let config = RateLimitConfig {
        max_connections_per_minute: 5,
        max_unique_destinations_per_10s: 3,
        alert_on_exceed: true,
    };
    let mut limiter = ConnectionRateLimiter::new(config);
    let now = Utc::now();

    // Send 6 connections from same PID to unique destinations.
    for i in 0..6 {
        let alerts = limiter.record_connection(1000, &format!("dest-{}.example.com", i), now);

        if i >= 5 {
            // Should have connection rate alert after exceeding 5/min.
            assert!(
                !alerts.is_empty(),
                "Expected rate limit alert at connection {}",
                i
            );
            assert!(alerts
                .iter()
                .any(|a| a.alert_type == RateLimitAlertType::ConnectionsPerMinute));
        }
        if i >= 3 {
            // Should have unique destination alert after exceeding 3/10s.
            let has_dest_alert = alerts
                .iter()
                .any(|a| a.alert_type == RateLimitAlertType::UniqueDestinationsPer10s);
            if i >= 4 {
                assert!(
                    has_dest_alert,
                    "Expected unique destination alert at connection {}",
                    i
                );
            }
        }
    }
}

// ===========================================================================
// Test 4: Kill chain context — credential read followed by network connection
// ===========================================================================

#[test]
fn flow_kill_chain_escalates_severity() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request("suspicious-server.com", 443);

    // Simulate kill chain context: credential read events preceded this connection.
    let signals = ExternalSignals {
        kill_chain_context: Some("Credential access followed by external connection".to_string()),
        ioc_match: None,
        anomaly_score: Some(0.8),
        server_has_never_networked: false,
        destination_unknown_to_profile: true,
        guard_network_allowlist: None,
    };

    let decision = engine.evaluate(&request, &signals);

    // Kill chain context should escalate severity to Critical.
    assert_eq!(
        decision.severity,
        Severity::Critical,
        "Kill chain context should escalate to Critical severity"
    );
    assert!(decision.signals.kill_chain.is_some());
    assert!(decision
        .signals
        .kill_chain
        .as_ref()
        .unwrap()
        .contains("Credential"));
}

#[test]
fn flow_ioc_match_overrides_allow_rules() {
    let mut engine = NetworkPolicyEngine::with_defaults();

    // Even a known-good-looking domain should be blocked if IoC matches.
    let request = agent_request("api.trusted-service.com", 443);
    let signals = ExternalSignals {
        ioc_match: Some("THREAT-2026-001".to_string()),
        ..ExternalSignals::default()
    };

    let decision = engine.evaluate(&request, &signals);
    assert_eq!(decision.action, NetworkAction::Block);
    assert_eq!(decision.severity, Severity::Critical);
    assert!(decision.reason.contains("threat indicator"));
}

// ===========================================================================
// Test 5: Non-agent traffic always passes through untouched
// ===========================================================================

#[test]
fn flow_non_agent_always_allowed_policy_engine() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = non_agent_request("any-domain.com");

    // Even with hostile signals, non-agent traffic should always pass.
    let signals = ExternalSignals {
        ioc_match: Some("THREAT-XYZ".to_string()),
        kill_chain_context: Some("Active kill chain".to_string()),
        anomaly_score: Some(1.0),
        server_has_never_networked: true,
        destination_unknown_to_profile: true,
        guard_network_allowlist: Some(vec!["only-this.com".to_string()]),
    };

    let decision = engine.evaluate(&request, &signals);
    assert_eq!(
        decision.action,
        NetworkAction::Allow,
        "Non-agent traffic must always be allowed regardless of signals"
    );
    assert_eq!(decision.severity, Severity::Low);
}

#[test]
fn flow_non_agent_always_allowed_mock_extension() {
    let mut ext = MockNetworkExtension::new(MockNetworkExtensionConfig::default());
    ext.update_blocked_hosts(vec!["evil.com".to_string()]);

    let event = mock_event(5000, "evil.com", 443);
    let (decision, _) = ext.evaluate_connect(&event, false, None);

    assert_eq!(
        decision,
        MockNetworkDecision::Allow,
        "Mock extension must allow non-agent traffic even to blocked hosts"
    );
}

// ===========================================================================
// Test 6: Backward compatibility — disable network policy, Phase 0-11 unchanged
// ===========================================================================

#[test]
fn backward_compat_default_engine_does_not_block_localhost() {
    let mut engine = NetworkPolicyEngine::with_defaults();

    let request = NetworkConnectionRequest {
        pid: 1000,
        process_name: "agent".to_string(),
        server_name: Some("server".to_string()),
        is_agent: true,
        destination_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        destination_domain: Some("localhost".to_string()),
        destination_port: 8080,
        protocol: "tcp".to_string(),
    };

    let decision = engine.evaluate(&request, &ExternalSignals::default());
    assert_eq!(
        decision.action,
        NetworkAction::Allow,
        "Localhost connections should always be allowed"
    );
}

#[test]
fn backward_compat_no_signals_means_default_behavior() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request("api.example.com", 443);

    // No external signals at all — should fall through to default rules.
    let decision = engine.evaluate(&request, &ExternalSignals::default());

    // The default catch-all rule for agents is "prompt".
    assert_eq!(
        decision.action,
        NetworkAction::Prompt,
        "With no signals, agent traffic should get the default prompt action"
    );
}

// ===========================================================================
// Test 7: Mock extension end-to-end
// ===========================================================================

#[test]
fn flow_mock_extension_full_lifecycle() {
    let mut ext = MockNetworkExtension::new(MockNetworkExtensionConfig::default());
    ext.update_blocked_hosts(vec!["c2-server.bad.com".to_string()]);

    // Non-agent traffic → always allowed.
    let (d1, _) = ext.evaluate_connect(&mock_event(100, "c2-server.bad.com", 443), false, None);
    assert_eq!(d1, MockNetworkDecision::Allow);

    // Agent + localhost → allowed.
    let (d2, _) = ext.evaluate_connect(
        &mock_event(200, "127.0.0.1", 8080),
        true,
        Some("test-server"),
    );
    assert_eq!(d2, MockNetworkDecision::Allow);

    // Agent + IoC blocked host → blocked.
    let (d3, _) = ext.evaluate_connect(
        &mock_event(200, "c2-server.bad.com", 443),
        true,
        Some("test-server"),
    );
    assert_eq!(d3, MockNetworkDecision::Block);

    // Agent + unknown host → allowed (mock default).
    let (d4, _) = ext.evaluate_connect(
        &mock_event(200, "safe.example.com", 443),
        true,
        Some("test-server"),
    );
    assert_eq!(d4, MockNetworkDecision::Allow);

    // Stats should reflect all 4 flows.
    let stats = ext.stats();
    assert_eq!(stats.flows_total, 4);
    assert_eq!(stats.flows_allowed_not_agent, 1);
    assert_eq!(stats.flows_blocked, 1);
}

// ===========================================================================
// Test 8: Network log aggregation
// ===========================================================================

#[test]
fn flow_log_aggregation_summary() {
    let logs = vec![
        make_log(
            "allowed",
            "1.1.1.1",
            Some("api.github.com"),
            Some("github"),
            500,
            1000,
        ),
        make_log(
            "allowed",
            "1.1.1.2",
            Some("cdn.github.com"),
            Some("github"),
            200,
            3000,
        ),
        make_log(
            "blocked",
            "10.0.0.1",
            Some("c2.evil.com"),
            Some("github"),
            0,
            0,
        ),
        make_log(
            "prompted",
            "172.16.0.1",
            Some("internal.corp"),
            Some("other"),
            50,
            100,
        ),
    ];

    let summary = NetworkSummary::from_logs(&logs, "last_24h");
    assert_eq!(summary.total_allowed, 2);
    assert_eq!(summary.total_blocked, 1);
    assert_eq!(summary.total_prompted, 1);
    assert!(summary.top_destinations.len() <= 10);
}

#[test]
fn flow_log_aggregation_per_server() {
    let logs = vec![
        make_log(
            "allowed",
            "1.1.1.1",
            Some("api.github.com"),
            Some("github"),
            500,
            1000,
        ),
        make_log(
            "blocked",
            "10.0.0.1",
            Some("evil.com"),
            Some("github"),
            0,
            0,
        ),
        make_log(
            "allowed",
            "93.184.216.34",
            Some("example.com"),
            Some("filesystem"),
            100,
            200,
        ),
    ];

    let stats = NetworkTrafficStats::from_logs(&logs, "github", "last_24h");
    assert_eq!(stats.total_connections, 2);
    assert_eq!(stats.connections_allowed, 1);
    assert_eq!(stats.connections_blocked, 1);
    assert_eq!(stats.bytes_sent, 500);
    assert_eq!(stats.bytes_received, 1000);
    assert_eq!(stats.unique_destinations, 2);
}

// ===========================================================================
// Test 9: DNS filter + policy engine combined flow
// ===========================================================================

#[test]
fn flow_dns_then_policy_combined() {
    // Step 1: DNS filter checks the domain.
    let mut dns_filter = DnsFilter::new();
    dns_filter.add_block("known-c2.evil.com");

    let query = dns_query("known-c2.evil.com");
    let dns_result = dns_filter.check_domain(&query);
    assert_eq!(dns_result.action, DnsAction::Block);

    // Step 2: If DNS blocked, the connection never reaches the policy engine.
    // But if a connection somehow bypasses DNS (IP-based), policy engine
    // should still catch it via IoC signals.
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request("known-c2.evil.com", 443);
    let signals = ExternalSignals {
        ioc_match: Some("IOC-DNS-BYPASS".to_string()),
        ..ExternalSignals::default()
    };

    let decision = engine.evaluate(&request, &signals);
    assert_eq!(decision.action, NetworkAction::Block);
    assert_eq!(decision.severity, Severity::Critical);
}

// ===========================================================================
// Test 10: Guard allowlist integration
// ===========================================================================

#[test]
fn flow_guard_allowlist_blocks_unauthorized_destinations() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request("unauthorized.com", 443);

    let signals = ExternalSignals {
        guard_network_allowlist: Some(vec!["api.anthropic.com".to_string()]),
        ..ExternalSignals::default()
    };

    let decision = engine.evaluate(&request, &signals);
    assert_eq!(decision.action, NetworkAction::Block);
    assert!(decision.reason.contains("guard"));
}

#[test]
fn flow_guard_allowlist_permits_authorized_destinations() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request("api.anthropic.com", 443);

    let signals = ExternalSignals {
        guard_network_allowlist: Some(vec!["api.anthropic.com".to_string()]),
        ..ExternalSignals::default()
    };

    let decision = engine.evaluate(&request, &signals);
    // Should NOT be blocked by guard since it's in the allowlist.
    assert_ne!(decision.action, NetworkAction::Block);
}

// ===========================================================================
// Test 11: Behavioral escalation — server never networked
// ===========================================================================

#[test]
fn flow_behavioral_escalation_never_networked() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request("api.example.com", 443);

    let signals = ExternalSignals {
        server_has_never_networked: true,
        ..ExternalSignals::default()
    };

    let decision = engine.evaluate(&request, &signals);
    // When a server has never networked and the default rule would allow,
    // it should escalate to Prompt.
    assert!(
        decision.action == NetworkAction::Prompt,
        "Server that has never networked should have connection escalated to prompt"
    );
}

// ===========================================================================
// Test 12: DNS wildcard blocking
// ===========================================================================

#[test]
fn flow_dns_wildcard_blocks_subdomains() {
    let mut filter = DnsFilter::new();
    filter.add_block("*.evil-corp.com");

    // Subdomain should be blocked.
    let result = filter.check_domain(&dns_query("api.evil-corp.com"));
    assert_eq!(result.action, DnsAction::Block);

    // Deeper subdomain should also be blocked.
    let result = filter.check_domain(&dns_query("deep.sub.evil-corp.com"));
    assert_eq!(result.action, DnsAction::Block);

    // The root domain itself should NOT be blocked by wildcard.
    let result = filter.check_domain(&dns_query("evil-corp.com"));
    assert_ne!(result.action, DnsAction::Block);
}

// ===========================================================================
// Test 13: DNS allowlist overrides blocklist
// ===========================================================================

#[test]
fn flow_dns_allowlist_overrides_blocklist() {
    let mut filter = DnsFilter::new();
    filter.add_block("example.com");
    filter.add_allow("example.com");

    let result = filter.check_domain(&dns_query("example.com"));
    assert_eq!(
        result.action,
        DnsAction::Allow,
        "Allowlist should override blocklist"
    );
}
