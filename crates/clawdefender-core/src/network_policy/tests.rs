//! Comprehensive tests for the network policy engine.

use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;

use super::engine::*;
use super::rate_limiter::*;
use super::rules::*;
use crate::behavioral::killchain::Severity;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_agent_request(
    ip: Option<IpAddr>,
    domain: Option<&str>,
    port: u16,
    server_name: Option<&str>,
) -> NetworkConnectionRequest {
    NetworkConnectionRequest {
        pid: 1000,
        process_name: "node".to_string(),
        server_name: server_name.map(|s| s.to_string()),
        is_agent: true,
        destination_ip: ip,
        destination_domain: domain.map(|s| s.to_string()),
        destination_port: port,
        protocol: "tcp".to_string(),
    }
}

fn make_non_agent_request(ip: IpAddr, port: u16) -> NetworkConnectionRequest {
    NetworkConnectionRequest {
        pid: 2000,
        process_name: "curl".to_string(),
        server_name: None,
        is_agent: false,
        destination_ip: Some(ip),
        destination_domain: None,
        destination_port: port,
        protocol: "tcp".to_string(),
    }
}

fn no_signals() -> ExternalSignals {
    ExternalSignals::default()
}

fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_non_agent_always_allowed() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_non_agent_request(ip4(185, 234, 216, 47), 443);
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Allow);
    assert!(decision.reason.contains("Non-agent"));
}

#[test]
fn test_ioc_match_overrides_static_allow() {
    // Add a rule that explicitly allows a destination.
    let allow_rule = NetworkRule {
        name: "allow_evil".to_string(),
        action: NetworkAction::Allow,
        destinations: vec![DestinationPattern::Exact("evil.com".to_string())],
        not_destinations: vec![],
        source: RuleSource::User,
        only_agents: true,
        description: "User allowed evil.com".to_string(),
        priority: 1,
    };
    let mut engine = NetworkPolicyEngine::new(
        vec![allow_rule],
        NetworkAction::Prompt,
        RateLimitConfig::default(),
    );

    let request = make_agent_request(None, Some("evil.com"), 443, Some("fetch-server"));
    let signals = ExternalSignals {
        ioc_match: Some("THREAT-001".to_string()),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    // IoC should override the static allow.
    assert_eq!(decision.action, NetworkAction::Block);
    assert!(decision.signals.ioc_match.is_some());
    assert_eq!(decision.severity, Severity::Critical);
}

#[test]
fn test_guard_restriction_blocks_non_allowlisted() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_agent_request(
        Some(ip4(93, 184, 216, 34)),
        Some("example.com"),
        443,
        Some("fetch-server"),
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
fn test_guard_allows_allowlisted_destination() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_agent_request(None, Some("api.anthropic.com"), 443, Some("fetch-server"));
    let signals = ExternalSignals {
        guard_network_allowlist: Some(vec!["api.anthropic.com".to_string()]),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    // Should NOT be blocked by guard — falls through to static rules.
    assert_ne!(decision.action, NetworkAction::Block);
}

#[test]
fn test_static_rule_exact_ip_match() {
    let block_rule = NetworkRule {
        name: "block_bad_ip".to_string(),
        action: NetworkAction::Block,
        destinations: vec![DestinationPattern::Exact("185.234.216.47".to_string())],
        not_destinations: vec![],
        source: RuleSource::ThreatIntel,
        only_agents: true,
        description: "Known C2 IP".to_string(),
        priority: 5,
    };
    let mut engine = NetworkPolicyEngine::new(
        vec![block_rule],
        NetworkAction::Prompt,
        RateLimitConfig::default(),
    );

    let request = make_agent_request(
        Some(ip4(185, 234, 216, 47)),
        None,
        443,
        Some("fetch-server"),
    );
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Block);
    assert_eq!(decision.rule_name.as_deref(), Some("block_bad_ip"));
}

#[test]
fn test_static_rule_cidr_match() {
    let block_rule = NetworkRule {
        name: "block_private_10".to_string(),
        action: NetworkAction::Block,
        destinations: vec![DestinationPattern::CIDR("10.0.0.0/8".to_string())],
        not_destinations: vec![],
        source: RuleSource::User,
        only_agents: true,
        description: "Block 10.x.x.x".to_string(),
        priority: 5,
    };
    let mut engine = NetworkPolicyEngine::new(
        vec![block_rule],
        NetworkAction::Prompt,
        RateLimitConfig::default(),
    );

    let request = make_agent_request(Some(ip4(10, 1, 2, 3)), None, 80, Some("srv"));
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Block);

    // IP outside the range should not match.
    let request2 = make_agent_request(Some(ip4(192, 168, 1, 1)), None, 80, Some("srv"));
    let decision2 = engine.evaluate(&request2, &no_signals());
    assert_ne!(decision2.action, NetworkAction::Block);
}

#[test]
fn test_static_rule_domain_match() {
    let allow_rule = NetworkRule {
        name: "allow_api".to_string(),
        action: NetworkAction::Allow,
        destinations: vec![DestinationPattern::Exact("api.anthropic.com".to_string())],
        not_destinations: vec![],
        source: RuleSource::User,
        only_agents: true,
        description: "Allow Anthropic API".to_string(),
        priority: 5,
    };
    let mut engine = NetworkPolicyEngine::new(
        vec![allow_rule],
        NetworkAction::Prompt,
        RateLimitConfig::default(),
    );

    let request = make_agent_request(None, Some("api.anthropic.com"), 443, Some("fetch-server"));
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Allow);
}

#[test]
fn test_static_rule_wildcard_match() {
    let allow_rule = NetworkRule {
        name: "allow_google".to_string(),
        action: NetworkAction::Allow,
        destinations: vec![DestinationPattern::Wildcard("*.googleapis.com".to_string())],
        not_destinations: vec![],
        source: RuleSource::User,
        only_agents: true,
        description: "Allow Google APIs".to_string(),
        priority: 5,
    };
    let mut engine = NetworkPolicyEngine::new(
        vec![allow_rule],
        NetworkAction::Prompt,
        RateLimitConfig::default(),
    );

    let request = make_agent_request(
        None,
        Some("storage.googleapis.com"),
        443,
        Some("fetch-server"),
    );
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Allow);

    // Should NOT match the bare domain.
    let request2 = make_agent_request(None, Some("googleapis.com"), 443, Some("fetch-server"));
    let decision2 = engine.evaluate(&request2, &no_signals());
    assert_ne!(decision2.rule_name.as_deref(), Some("allow_google"));
}

#[test]
fn test_rule_priority_ordering() {
    let block_rule = NetworkRule {
        name: "block_all".to_string(),
        action: NetworkAction::Block,
        destinations: vec![DestinationPattern::All],
        not_destinations: vec![],
        source: RuleSource::User,
        only_agents: true,
        description: "Block everything".to_string(),
        priority: 10,
    };
    let allow_rule = NetworkRule {
        name: "allow_api".to_string(),
        action: NetworkAction::Allow,
        destinations: vec![DestinationPattern::Exact("api.anthropic.com".to_string())],
        not_destinations: vec![],
        source: RuleSource::User,
        only_agents: true,
        description: "Allow Anthropic".to_string(),
        priority: 5, // Lower number = higher priority.
    };
    let mut engine = NetworkPolicyEngine::new(
        vec![block_rule, allow_rule],
        NetworkAction::Prompt,
        RateLimitConfig::default(),
    );

    let request = make_agent_request(None, Some("api.anthropic.com"), 443, Some("srv"));
    let decision = engine.evaluate(&request, &no_signals());
    // allow_api has lower priority number, so it wins.
    assert_eq!(decision.action, NetworkAction::Allow);
    assert_eq!(decision.rule_name.as_deref(), Some("allow_api"));
}

#[test]
fn test_behavioral_first_network_access_adds_warning() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_agent_request(
        Some(ip4(93, 184, 216, 34)),
        Some("example.com"),
        443,
        Some("filesystem-server"),
    );
    let signals = ExternalSignals {
        server_has_never_networked: true,
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    // The default allow_localhost won't match, so it should hit the
    // prompt_unknown_external rule, and behavioral context should be set.
    assert!(decision.signals.behavioral_context.is_some());
    assert!(decision
        .signals
        .behavioral_context
        .as_ref()
        .unwrap()
        .contains("NEVER"));
}

#[test]
fn test_kill_chain_context_escalates_severity() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_agent_request(
        Some(ip4(93, 184, 216, 34)),
        Some("example.com"),
        443,
        Some("fetch-server"),
    );
    let signals = ExternalSignals {
        kill_chain_context: Some("credential_theft_exfiltration".to_string()),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    assert_eq!(decision.severity, Severity::Critical);
    assert!(decision.signals.kill_chain.is_some());
}

#[test]
fn test_rate_limiter_fires_on_burst() {
    let config = RateLimitConfig {
        max_connections_per_minute: 5,
        max_unique_destinations_per_10s: 3,
        alert_on_exceed: true,
    };
    let mut limiter = ConnectionRateLimiter::new(config);
    let now = Utc::now();

    // Fire 6 connections to the same dest — should exceed connections/minute.
    for i in 0..6 {
        let alerts = limiter.record_connection(
            100,
            "example.com",
            now + chrono::Duration::milliseconds(i * 100),
        );
        if i >= 5 {
            assert!(
                alerts
                    .iter()
                    .any(|a| a.alert_type == RateLimitAlertType::ConnectionsPerMinute),
                "Expected rate limit alert on connection {}",
                i
            );
        }
    }
}

#[test]
fn test_rate_limiter_no_alert_on_normal_rate() {
    let config = RateLimitConfig {
        max_connections_per_minute: 100,
        max_unique_destinations_per_10s: 10,
        alert_on_exceed: true,
    };
    let mut limiter = ConnectionRateLimiter::new(config);
    let now = Utc::now();

    for i in 0..5 {
        let alerts =
            limiter.record_connection(100, "example.com", now + chrono::Duration::seconds(i * 15));
        assert!(alerts.is_empty(), "No alerts expected for normal rate");
    }
}

#[test]
fn test_rate_limiter_unique_destinations() {
    let config = RateLimitConfig {
        max_connections_per_minute: 100,
        max_unique_destinations_per_10s: 3,
        alert_on_exceed: true,
    };
    let mut limiter = ConnectionRateLimiter::new(config);
    let now = Utc::now();

    // 4 unique destinations within 10 seconds.
    let dests = ["a.com", "b.com", "c.com", "d.com"];
    let mut got_alert = false;
    for (i, dest) in dests.iter().enumerate() {
        let alerts =
            limiter.record_connection(100, dest, now + chrono::Duration::seconds(i as i64));
        if alerts
            .iter()
            .any(|a| a.alert_type == RateLimitAlertType::UniqueDestinationsPer10s)
        {
            got_alert = true;
        }
    }
    assert!(got_alert, "Expected unique destination alert");
}

#[test]
fn test_default_prompt_for_unknown_agent_destinations() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_agent_request(
        Some(ip4(93, 184, 216, 34)),
        Some("random-site.example"),
        443,
        Some("fetch-server"),
    );
    let decision = engine.evaluate(&request, &no_signals());
    // The prompt_unknown_external default rule should match.
    assert_eq!(decision.action, NetworkAction::Prompt);
}

#[test]
fn test_localhost_always_allowed() {
    let mut engine = NetworkPolicyEngine::with_defaults();

    // 127.0.0.1
    let request1 = make_agent_request(Some(ip4(127, 0, 0, 1)), None, 3000, Some("srv"));
    assert_eq!(
        engine.evaluate(&request1, &no_signals()).action,
        NetworkAction::Allow
    );

    // localhost domain
    let request2 = make_agent_request(None, Some("localhost"), 3000, Some("srv"));
    assert_eq!(
        engine.evaluate(&request2, &no_signals()).action,
        NetworkAction::Allow
    );
}

#[test]
fn test_combined_signals_produce_correct_decision() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_agent_request(
        Some(ip4(93, 184, 216, 34)),
        Some("suspicious.example"),
        443,
        Some("filesystem-server"),
    );
    let signals = ExternalSignals {
        anomaly_score: Some(0.85),
        server_has_never_networked: true,
        destination_unknown_to_profile: true,
        kill_chain_context: Some("credential_theft_exfiltration".to_string()),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    // Should have behavioral context, kill chain, and high severity.
    assert!(decision.signals.behavioral_context.is_some());
    assert!(decision.signals.kill_chain.is_some());
    assert_eq!(decision.severity, Severity::Critical);
}

#[test]
fn test_network_prompt_info_generation() {
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_agent_request(
        Some(ip4(93, 184, 216, 34)),
        Some("suspicious.example"),
        443,
        Some("filesystem-server"),
    );
    let signals = ExternalSignals {
        anomaly_score: Some(0.85),
        server_has_never_networked: true,
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    let prompt = engine.build_prompt_info(&request, &decision);

    assert_eq!(prompt.server_name, "filesystem-server");
    assert!(prompt.destination.contains("443"));
    assert_eq!(prompt.domain.as_deref(), Some("suspicious.example"));
    assert!(prompt.behavioral_context.contains("NEVER"));
    assert_eq!(prompt.timeout_action, NetworkAction::Block);
}

#[test]
fn test_config_parsing() {
    let config = NetworkPolicyConfig::default();
    assert!(config.enabled);
    assert_eq!(config.default_agent_action, "prompt");
    assert_eq!(config.prompt_timeout_seconds, 15);
    assert_eq!(config.timeout_action, "block");
    assert_eq!(config.rate_limit_connections_per_min, 100);
    assert_eq!(config.rate_limit_unique_dest_per_10s, 10);
    assert!(!config.block_private_ranges);
    assert!(config.log_all_dns);
}

#[test]
fn test_per_server_profile_integration() {
    // A server that normally networks should not get behavioral escalation.
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_agent_request(
        Some(ip4(93, 184, 216, 34)),
        Some("api.example.com"),
        443,
        Some("fetch-server"),
    );
    let signals = ExternalSignals {
        server_has_never_networked: false,
        destination_unknown_to_profile: false,
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    // No behavioral context should be set.
    assert!(decision.signals.behavioral_context.is_none());
}

#[test]
fn test_destination_pattern_exact() {
    let pat = DestinationPattern::Exact("10.0.0.1".to_string());
    assert!(pat.matches(Some(ip4(10, 0, 0, 1)), None));
    assert!(!pat.matches(Some(ip4(10, 0, 0, 2)), None));
}

#[test]
fn test_destination_pattern_cidr() {
    let pat = DestinationPattern::CIDR("192.168.0.0/16".to_string());
    assert!(pat.matches(Some(ip4(192, 168, 1, 100)), None));
    assert!(!pat.matches(Some(ip4(10, 0, 0, 1)), None));
}

#[test]
fn test_destination_pattern_wildcard() {
    let pat = DestinationPattern::Wildcard("*.example.com".to_string());
    assert!(pat.matches(None, Some("sub.example.com")));
    assert!(!pat.matches(None, Some("example.com")));
    assert!(pat.matches(None, Some("deep.sub.example.com")));
}

#[test]
fn test_destination_pattern_all() {
    let pat = DestinationPattern::All;
    assert!(pat.matches(Some(ip4(1, 2, 3, 4)), Some("anything.com")));
}

#[test]
fn test_not_destinations_exclusion() {
    let rule = NetworkRule {
        name: "block_except_localhost".to_string(),
        action: NetworkAction::Block,
        destinations: vec![DestinationPattern::All],
        not_destinations: vec![DestinationPattern::Exact("127.0.0.1".to_string())],
        source: RuleSource::User,
        only_agents: true,
        description: "Block all except localhost".to_string(),
        priority: 5,
    };
    // 127.0.0.1 should be excluded.
    assert!(!rule.matches_destination(Some(ip4(127, 0, 0, 1)), None));
    // Other IPs should match.
    assert!(rule.matches_destination(Some(ip4(10, 0, 0, 1)), None));
}

// Use the config struct for the config parsing test.
use crate::config::settings::NetworkPolicyConfig;

// ---------------------------------------------------------------------------
// Security verification: process-scoped filtering
// ---------------------------------------------------------------------------

#[test]
fn test_security_non_agent_with_malicious_domain_always_allowed() {
    // Verify that non-agent processes are ALWAYS allowed, even when
    // connecting to destinations that would be blocked for agents.
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = NetworkConnectionRequest {
        pid: 5000,
        process_name: "firefox".to_string(),
        server_name: None,
        is_agent: false,
        destination_ip: Some(ip4(185, 234, 216, 47)),
        destination_domain: Some("c2-server.evil.com".to_string()),
        destination_port: 443,
        protocol: "tcp".to_string(),
    };
    let signals = ExternalSignals {
        ioc_match: Some("THREAT-CRITICAL".to_string()),
        kill_chain_context: Some("data_exfiltration".to_string()),
        anomaly_score: Some(1.0),
        ..Default::default()
    };
    let decision = engine.evaluate(&request, &signals);
    assert_eq!(decision.action, NetworkAction::Allow);
    assert!(decision.reason.contains("Non-agent"));
}

#[test]
fn test_security_agent_with_suspicious_destination_gets_prompt_or_block() {
    // Verify that agent processes connecting to unknown destinations
    // are NOT silently allowed.
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_agent_request(
        Some(ip4(93, 184, 216, 34)),
        Some("suspicious.example"),
        443,
        Some("filesystem-server"),
    );
    let decision = engine.evaluate(&request, &no_signals());
    assert!(
        decision.action == NetworkAction::Prompt || decision.action == NetworkAction::Block,
        "Agent traffic to unknown destinations must not be silently allowed"
    );
}

#[test]
fn test_security_engine_never_inspects_non_agent_traffic() {
    // Verify that when is_agent=false, the engine returns immediately
    // without consulting any signals, rules, or behavioral context.
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_non_agent_request(ip4(1, 2, 3, 4), 80);
    let signals = ExternalSignals {
        ioc_match: Some("THREAT-001".to_string()),
        anomaly_score: Some(0.99),
        server_has_never_networked: true,
        destination_unknown_to_profile: true,
        kill_chain_context: Some("credential_theft".to_string()),
        guard_network_allowlist: Some(vec![]),
    };
    let decision = engine.evaluate(&request, &signals);
    assert_eq!(decision.action, NetworkAction::Allow);
    // Signals should NOT be populated for non-agent traffic.
    assert!(decision.signals.ioc_match.is_none());
    assert!(decision.signals.guard_restriction.is_none());
    assert!(decision.signals.kill_chain.is_none());
    assert!(decision.signals.behavioral_context.is_none());
}

// ---------------------------------------------------------------------------
// Security verification: fail-open behavior
// ---------------------------------------------------------------------------

#[test]
fn test_security_dns_filter_allows_all_when_empty() {
    // DnsFilter with no blocklist entries should allow all queries.
    use crate::dns::filter::{DnsAction, DnsFilter, DnsQuery, DnsQueryType};

    let filter = DnsFilter::new();
    for domain in &["example.com", "evil.com", "c2.malware.net", "localhost"] {
        let query = DnsQuery {
            domain: domain.to_string(),
            query_type: DnsQueryType::A,
            source_pid: 1000,
            server_name: Some("test".to_string()),
            timestamp: chrono::Utc::now(),
        };
        let result = filter.check_domain(&query);
        // With no blocklist, the filter should allow (or at worst log for
        // suspicious-looking domains via domain intel heuristics, but never block).
        assert_ne!(
            result.action,
            DnsAction::Block,
            "Empty DnsFilter should not block '{}'",
            domain
        );
    }
}

#[test]
fn test_security_engine_allows_non_agents_when_default_is_block() {
    // Even when the engine's default action is Block, non-agent traffic
    // must still be allowed — fail-open for non-agent processes.
    let mut engine =
        NetworkPolicyEngine::new(Vec::new(), NetworkAction::Block, RateLimitConfig::default());
    let request = make_non_agent_request(ip4(8, 8, 8, 8), 53);
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Allow);
}

// ---------------------------------------------------------------------------
// Security verification: localhost always allowed
// ---------------------------------------------------------------------------

#[test]
fn test_security_ipv6_loopback_allowed() {
    use std::net::Ipv6Addr;
    let mut engine = NetworkPolicyEngine::with_defaults();
    let request = make_agent_request(
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        None,
        8080,
        Some("srv"),
    );
    let decision = engine.evaluate(&request, &no_signals());
    assert_eq!(decision.action, NetworkAction::Allow);
}
