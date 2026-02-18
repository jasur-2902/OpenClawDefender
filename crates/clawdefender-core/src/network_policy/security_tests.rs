//! Security-focused tests for the network policy engine.
//!
//! These tests verify critical security invariants:
//! - Process isolation: non-agent traffic is never filtered
//! - Fail-open: daemon unavailable means all connections succeed
//! - Localhost always allowed
//! - Edge cases: invalid PID, large ports, IPv6
//! - IoC matches override allow rules (security-critical)
//! - Guard restrictions are enforced

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::engine::*;
use super::rate_limiter::*;
use super::rules::*;
use crate::behavioral::killchain::Severity;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn agent_request(
    pid: u32,
    ip: Option<IpAddr>,
    domain: Option<&str>,
    port: u16,
) -> NetworkConnectionRequest {
    NetworkConnectionRequest {
        pid,
        process_name: "node".to_string(),
        server_name: Some("test-server".to_string()),
        is_agent: true,
        destination_ip: ip,
        destination_domain: domain.map(|s| s.to_string()),
        destination_port: port,
        protocol: "tcp".to_string(),
    }
}

fn non_agent_request(
    pid: u32,
    ip: Option<IpAddr>,
    domain: Option<&str>,
    port: u16,
) -> NetworkConnectionRequest {
    NetworkConnectionRequest {
        pid,
        process_name: "curl".to_string(),
        server_name: None,
        is_agent: false,
        destination_ip: ip,
        destination_domain: domain.map(|s| s.to_string()),
        destination_port: port,
        protocol: "tcp".to_string(),
    }
}

fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn ip6_loopback() -> IpAddr {
    IpAddr::V6(Ipv6Addr::LOCALHOST)
}

fn no_signals() -> ExternalSignals {
    ExternalSignals::default()
}

// ===========================================================================
// 1. Process isolation: non-agent traffic NEVER filtered
// ===========================================================================

#[test]
fn security_non_agent_always_allowed_regardless_of_destination() {
    let mut engine = NetworkPolicyEngine::with_defaults();

    // Even a known-malicious IP should be allowed for non-agent processes.
    let request = non_agent_request(2000, Some(ip4(185, 234, 216, 47)), None, 443);
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Allow);
    assert!(decision.reason.contains("Non-agent"));
}

#[test]
fn security_non_agent_allowed_even_with_ioc_match() {
    let mut engine = NetworkPolicyEngine::with_defaults();

    let request = non_agent_request(2000, Some(ip4(10, 0, 0, 1)), Some("evil.com"), 443);
    let signals = ExternalSignals {
        ioc_match: Some("THREAT-999".to_string()),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    // Non-agent bypasses ALL checks, including IoC.
    assert_eq!(decision.action, NetworkAction::Allow);
    assert!(decision.reason.contains("Non-agent"));
}

#[test]
fn security_non_agent_allowed_even_with_guard_restriction() {
    let mut engine = NetworkPolicyEngine::with_defaults();

    let request = non_agent_request(2000, Some(ip4(8, 8, 8, 8)), Some("dns.google"), 53);
    let signals = ExternalSignals {
        guard_network_allowlist: Some(vec!["only-this.com".to_string()]),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    assert_eq!(decision.action, NetworkAction::Allow);
}

#[test]
fn security_non_agent_allowed_with_kill_chain_context() {
    let mut engine = NetworkPolicyEngine::with_defaults();

    let request = non_agent_request(2000, Some(ip4(1, 2, 3, 4)), None, 80);
    let signals = ExternalSignals {
        kill_chain_context: Some("data_exfiltration".to_string()),
        anomaly_score: Some(1.0),
        server_has_never_networked: true,
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    assert_eq!(decision.action, NetworkAction::Allow);
}

#[test]
fn security_non_agent_never_produces_block_or_prompt() {
    let mut engine = NetworkPolicyEngine::new(
        vec![NetworkRule {
            name: "block_all".to_string(),
            action: NetworkAction::Block,
            destinations: vec![DestinationPattern::All],
            not_destinations: vec![],
            source: RuleSource::User,
            only_agents: false, // Applies to ALL processes.
            description: "Block everything".to_string(),
            priority: 0,
        }],
        NetworkAction::Block,
        RateLimitConfig::default(),
    );

    let request = non_agent_request(2000, Some(ip4(1, 2, 3, 4)), None, 80);
    let decision = engine.evaluate(&request, &no_signals());
    // Even with a block-all rule that targets all processes, non-agent
    // traffic is unconditionally allowed by the engine's first check.
    assert_eq!(decision.action, NetworkAction::Allow);
}

// ===========================================================================
// 2. Fail-open behavior
// ===========================================================================

#[test]
fn security_dns_filter_allows_when_no_blocklist_loaded() {
    use crate::dns::filter::{DnsAction, DnsFilter, DnsQuery, DnsQueryType};

    let filter = DnsFilter::new();
    let query = DnsQuery {
        domain: "anything.example.com".to_string(),
        query_type: DnsQueryType::A,
        source_pid: 1000,
        server_name: Some("test".to_string()),
        timestamp: chrono::Utc::now(),
    };
    let result = filter.check_domain(&query);
    assert_eq!(result.action, DnsAction::Allow);
}

#[test]
fn security_engine_returns_allow_for_non_agents_even_with_block_default() {
    let mut engine = NetworkPolicyEngine::new(
        Vec::new(),
        NetworkAction::Block, // Default action is Block.
        RateLimitConfig::default(),
    );

    let request = non_agent_request(2000, Some(ip4(8, 8, 8, 8)), None, 53);
    let decision = engine.evaluate(&request, &no_signals());
    // Non-agent processes are always allowed regardless of default action.
    assert_eq!(decision.action, NetworkAction::Allow);
}

// ===========================================================================
// 3. Localhost always allowed
// ===========================================================================

#[test]
fn security_localhost_127_0_0_1_always_allowed_for_agents() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(1000, Some(ip4(127, 0, 0, 1)), None, 8080);
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Allow);
}

#[test]
fn security_localhost_domain_always_allowed_for_agents() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(1000, None, Some("localhost"), 3000);
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Allow);
}

#[test]
fn security_ipv6_loopback_always_allowed_for_agents() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(1000, Some(ip6_loopback()), None, 8080);
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Allow);
}

#[test]
fn security_localhost_allowed_even_with_kill_chain() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(1000, Some(ip4(127, 0, 0, 1)), Some("localhost"), 8080);
    let signals = ExternalSignals {
        kill_chain_context: Some("c2_communication".to_string()),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    // Localhost rule has priority 0, should match before behavioral checks.
    assert_eq!(decision.action, NetworkAction::Allow);
}

// ===========================================================================
// 4. Edge cases
// ===========================================================================

#[test]
fn security_pid_zero_handled_gracefully() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(0, Some(ip4(93, 184, 216, 34)), Some("example.com"), 443);
    let decision = engine.evaluate(&request, &no_signals());
    // Should not panic — PID 0 is unusual but engine should handle it.
    assert!(
        decision.action == NetworkAction::Prompt || decision.action == NetworkAction::Allow
    );
}

#[test]
fn security_pid_zero_non_agent() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = non_agent_request(0, Some(ip4(1, 2, 3, 4)), None, 80);
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Allow);
}

#[test]
fn security_max_port_number() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(1000, Some(ip4(93, 184, 216, 34)), None, 65535);
    let decision = engine.evaluate(&request, &no_signals());
    // Should not panic — port 65535 is valid.
    assert!(matches!(
        decision.action,
        NetworkAction::Allow | NetworkAction::Prompt | NetworkAction::Block
    ));
}

#[test]
fn security_port_zero() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(1000, Some(ip4(93, 184, 216, 34)), None, 0);
    let decision = engine.evaluate(&request, &no_signals());
    // Port 0 is unusual but should not panic.
    assert!(matches!(
        decision.action,
        NetworkAction::Allow | NetworkAction::Prompt | NetworkAction::Block
    ));
}

#[test]
fn security_ipv6_addresses_evaluated_correctly() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let ipv6 = IpAddr::V6("2001:db8::1".parse().unwrap());
    let request = agent_request(1000, Some(ipv6), None, 443);
    let decision = engine.evaluate(&request, &no_signals());
    // Non-localhost IPv6 for an agent should prompt (default rule).
    assert_eq!(decision.action, NetworkAction::Prompt);
}

#[test]
fn security_no_ip_no_domain_handled() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(1000, None, None, 443);
    let decision = engine.evaluate(&request, &no_signals());
    // No destination info — engine should still produce a valid decision.
    assert!(matches!(
        decision.action,
        NetworkAction::Allow | NetworkAction::Prompt | NetworkAction::Block
    ));
}

// ===========================================================================
// 5. Rate limiter does not block legitimate bursts
// ===========================================================================

#[test]
fn security_rate_limiter_no_alert_below_threshold() {
    let config = RateLimitConfig {
        max_connections_per_minute: 10,
        max_unique_destinations_per_10s: 5,
        alert_on_exceed: true,
    };
    let mut limiter = ConnectionRateLimiter::new(config);
    let now = chrono::Utc::now();

    // Send exactly the threshold number — should not alert.
    for i in 0..10 {
        let alerts = limiter.record_connection(
            100,
            "example.com",
            now + chrono::Duration::milliseconds(i * 100),
        );
        assert!(
            alerts.is_empty(),
            "No alert expected at connection {} (at threshold)",
            i
        );
    }
}

#[test]
fn security_rate_limiter_alerts_above_threshold() {
    let config = RateLimitConfig {
        max_connections_per_minute: 5,
        max_unique_destinations_per_10s: 100,
        alert_on_exceed: true,
    };
    let mut limiter = ConnectionRateLimiter::new(config);
    let now = chrono::Utc::now();

    let mut got_alert = false;
    for i in 0..10 {
        let alerts = limiter.record_connection(
            100,
            "example.com",
            now + chrono::Duration::milliseconds(i * 100),
        );
        if !alerts.is_empty() {
            got_alert = true;
        }
    }
    assert!(got_alert, "Expected rate limit alert above threshold");
}

// ===========================================================================
// 6. IoC matches override allow rules (security-critical)
// ===========================================================================

#[test]
fn security_ioc_overrides_user_allow_rule() {
    let allow_rule = NetworkRule {
        name: "allow_evil".to_string(),
        action: NetworkAction::Allow,
        destinations: vec![DestinationPattern::Exact("evil.com".to_string())],
        not_destinations: vec![],
        source: RuleSource::User,
        only_agents: true,
        description: "User explicitly allowed evil.com".to_string(),
        priority: 1,
    };
    let mut engine = NetworkPolicyEngine::new(
        vec![allow_rule],
        NetworkAction::Allow,
        RateLimitConfig::default(),
    );

    let request = agent_request(1000, None, Some("evil.com"), 443);
    let signals = ExternalSignals {
        ioc_match: Some("THREAT-001".to_string()),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    // IoC MUST override even explicit user allow rules.
    assert_eq!(decision.action, NetworkAction::Block);
    assert_eq!(decision.severity, Severity::Critical);
    assert!(decision.signals.ioc_match.is_some());
}

#[test]
fn security_ioc_overrides_guard_allowlist() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(1000, None, Some("evil.com"), 443);
    let signals = ExternalSignals {
        ioc_match: Some("THREAT-002".to_string()),
        guard_network_allowlist: Some(vec!["evil.com".to_string()]),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    // IoC takes priority over guard allowlist.
    assert_eq!(decision.action, NetworkAction::Block);
}

// ===========================================================================
// 7. Guard restrictions enforced
// ===========================================================================

#[test]
fn security_guard_blocks_non_allowlisted_domain() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(
        1000,
        Some(ip4(93, 184, 216, 34)),
        Some("unauthorized.com"),
        443,
    );
    let signals = ExternalSignals {
        guard_network_allowlist: Some(vec!["api.anthropic.com".to_string()]),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    assert_eq!(decision.action, NetworkAction::Block);
    assert!(decision.signals.guard_restriction.is_some());
}

#[test]
fn security_guard_allows_wildcard_match() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(1000, None, Some("sub.example.com"), 443);
    let signals = ExternalSignals {
        guard_network_allowlist: Some(vec!["*.example.com".to_string()]),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    // Should NOT be blocked by guard restriction.
    assert_ne!(decision.action, NetworkAction::Block);
}

#[test]
fn security_guard_empty_allowlist_blocks_everything() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = agent_request(1000, None, Some("any.com"), 443);
    let signals = ExternalSignals {
        guard_network_allowlist: Some(vec![]),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    assert_eq!(decision.action, NetworkAction::Block);
}

// ===========================================================================
// 8. Mock network extension fail-open behavior
// ===========================================================================
// NOTE: MockNetworkExtension tests live in crates/clawdefender-daemon/src/mock_network_extension.rs
// because the mock is part of the daemon crate, not the core crate.
// The daemon crate's existing tests already verify:
// - non_agent_traffic_always_allowed
// - localhost_always_allowed_for_agents
// - blocked_host_returns_block
// - default_policy_allows_unknown_hosts (fail-open)
