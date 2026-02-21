//! Mock network extension for development/testing.
//!
//! Simulates the macOS Network Extension's behavior by intercepting eslogger
//! `connect` events from agent processes and evaluating network policy. Since
//! this is a mock, it cannot actually block connections — it logs what *would*
//! have happened with a real system extension installed.
//!
//! Enable via the `--mock-network-extension` CLI flag.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Configuration for the mock network extension.
#[derive(Debug, Clone)]
pub struct MockNetworkExtensionConfig {
    /// Whether the mock extension is enabled.
    pub enabled: bool,
    /// Cache TTL for PID agent-status lookups.
    pub pid_cache_ttl_secs: u64,
    /// Cache TTL for policy decisions.
    pub policy_cache_ttl_secs: u64,
    /// Hosts that are always allowed (localhost variants).
    pub always_allow_hosts: Vec<String>,
}

impl Default for MockNetworkExtensionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pid_cache_ttl_secs: 1,
            policy_cache_ttl_secs: 30,
            always_allow_hosts: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "0.0.0.0".to_string(),
            ],
        }
    }
}

/// Network decision from mock evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockNetworkDecision {
    Allow,
    Block,
    Prompt,
}

impl std::fmt::Display for MockNetworkDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Block => write!(f, "BLOCK"),
            Self::Prompt => write!(f, "PROMPT"),
        }
    }
}

/// Cached entry for whether a PID is an agent process.
#[allow(dead_code)]
struct PidCacheEntry {
    is_agent: bool,
    server_name: Option<String>,
    expires_at: Instant,
}

/// Cached policy decision.
struct PolicyCacheEntry {
    decision: MockNetworkDecision,
    reason: String,
    expires_at: Instant,
}

/// A connect event from eslogger that we evaluate as a mock network flow.
///
/// SECURITY: Contains metadata only — PID, process name, destination host/port.
/// No connection payload, request body, or response content is captured.
#[derive(Debug, Clone)]
pub struct MockConnectEvent {
    pub pid: u32,
    pub process_name: String,
    pub destination_host: String,
    pub destination_port: u16,
    pub protocol: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// The mock network extension. Evaluates connect events from eslogger against
/// network policy, logging decisions as if a real extension were installed.
///
/// SECURITY: Fail-open design — when the daemon is unavailable (which is the
/// default state for the mock), all connections default to Allow. This ensures
/// network connectivity is never broken by ClawDefender failures.
///
/// SECURITY: Non-agent traffic is always allowed immediately (step 1 of
/// evaluate_connect). The mock never filters, blocks, or logs user traffic.
///
/// Threat model: the mock extension cannot actually block connections — it only
/// logs what a real extension would do. It is used for development and testing.
pub struct MockNetworkExtension {
    config: MockNetworkExtensionConfig,
    /// PID -> agent status cache.
    pid_cache: HashMap<u32, PidCacheEntry>,
    /// (host, port) -> policy decision cache.
    policy_cache: HashMap<String, PolicyCacheEntry>,
    /// IoC blocklist (domains/IPs that should be blocked).
    blocked_hosts: Vec<String>,
    /// Statistics.
    stats: MockExtensionStats,
}

/// Statistics for the mock extension.
#[derive(Debug, Default, Clone)]
pub struct MockExtensionStats {
    pub flows_total: u64,
    pub flows_allowed_not_agent: u64,
    pub flows_allowed_policy: u64,
    pub flows_blocked: u64,
    pub flows_prompted: u64,
}

impl MockNetworkExtension {
    /// Create a new mock network extension.
    pub fn new(config: MockNetworkExtensionConfig) -> Self {
        Self {
            config,
            pid_cache: HashMap::new(),
            policy_cache: HashMap::new(),
            blocked_hosts: Vec::new(),
            stats: MockExtensionStats::default(),
        }
    }

    /// Update the IoC blocklist.
    pub fn update_blocked_hosts(&mut self, hosts: Vec<String>) {
        info!(
            count = hosts.len(),
            "MockNetExt: updated blocklist with {} hosts",
            hosts.len()
        );
        self.blocked_hosts = hosts.into_iter().map(|h| h.to_lowercase()).collect();
    }

    /// Get current statistics.
    pub fn stats(&self) -> &MockExtensionStats {
        &self.stats
    }

    /// Evaluate a connect event as if we were a real network extension.
    ///
    /// Returns the decision and reason string. Since this is a mock, the
    /// connection is NOT actually blocked — we just log what would happen.
    ///
    /// SECURITY: Evaluation order is security-critical:
    /// 1. Non-agent -> ALLOW (process isolation guarantee)
    /// 2. Localhost -> ALLOW (system services always reachable)
    /// 3. IoC blocklist -> BLOCK (threat intel override)
    /// 4. Policy cache -> cached decision
    /// 5. Default -> ALLOW (fail-open)
    ///
    /// On failure at any step, the default is Allow (fail-open).
    pub fn evaluate_connect(
        &mut self,
        event: &MockConnectEvent,
        is_agent: bool,
        server_name: Option<&str>,
    ) -> (MockNetworkDecision, String) {
        self.stats.flows_total += 1;

        // Step 1: Not an agent process -> ALLOW immediately.
        if !is_agent {
            self.stats.flows_allowed_not_agent += 1;
            debug!(
                pid = event.pid,
                process = %event.process_name,
                dest = %event.destination_host,
                "MockNetExt: ALLOW (not agent)"
            );
            return (MockNetworkDecision::Allow, "not an agent process".to_string());
        }

        let host = event.destination_host.to_lowercase();

        // Step 2: Always-allow localhost.
        if self.config.always_allow_hosts.contains(&host) {
            self.stats.flows_allowed_policy += 1;
            debug!(
                pid = event.pid,
                dest = %host,
                "MockNetExt: ALLOW (localhost)"
            );
            return (MockNetworkDecision::Allow, "localhost always allowed".to_string());
        }

        // Step 3: Check IoC blocklist.
        let is_blocked = self.blocked_hosts.iter().any(|blocked| {
            host == *blocked || host.ends_with(&format!(".{}", blocked))
        });
        if is_blocked {
            self.stats.flows_blocked += 1;
            let reason = format!("host {} on IoC blocklist", host);
            warn!(
                pid = event.pid,
                process = %event.process_name,
                server = server_name.unwrap_or("unknown"),
                dest = %host,
                port = event.destination_port,
                "MOCK: would have blocked connection to {}:{} (IoC blocklist)",
                host,
                event.destination_port
            );
            return (MockNetworkDecision::Block, reason);
        }

        // Step 4: Check policy cache.
        let cache_key = format!("{}:{}", host, event.destination_port);
        let now = Instant::now();
        if let Some(entry) = self.policy_cache.get(&cache_key) {
            if entry.expires_at > now {
                match entry.decision {
                    MockNetworkDecision::Allow => self.stats.flows_allowed_policy += 1,
                    MockNetworkDecision::Block => self.stats.flows_blocked += 1,
                    MockNetworkDecision::Prompt => self.stats.flows_prompted += 1,
                }
                return (entry.decision, entry.reason.clone());
            }
        }

        // Step 5: Default policy — for the mock, allow with a log.
        // In a real extension, this would query the daemon.
        self.stats.flows_allowed_policy += 1;
        let reason = format!(
            "mock default allow for agent {} -> {}:{}",
            server_name.unwrap_or("unknown"),
            host,
            event.destination_port
        );
        info!(
            pid = event.pid,
            process = %event.process_name,
            server = server_name.unwrap_or("unknown"),
            dest = format!("{}:{}", host, event.destination_port),
            "MockNetExt: ALLOW (default policy) — real extension would query daemon"
        );

        // Cache the decision.
        self.policy_cache.insert(
            cache_key,
            PolicyCacheEntry {
                decision: MockNetworkDecision::Allow,
                reason: reason.clone(),
                expires_at: now + Duration::from_secs(self.config.policy_cache_ttl_secs),
            },
        );

        (MockNetworkDecision::Allow, reason)
    }

    /// Prune expired cache entries.
    pub fn prune_caches(&mut self) {
        let now = Instant::now();
        self.pid_cache.retain(|_, v| v.expires_at > now);
        self.policy_cache.retain(|_, v| v.expires_at > now);
    }
}

/// Shared, async-safe wrapper around MockNetworkExtension.
pub type SharedMockNetworkExtension = Arc<RwLock<MockNetworkExtension>>;

/// Create a new shared mock network extension.
pub fn new_shared(config: MockNetworkExtensionConfig) -> SharedMockNetworkExtension {
    Arc::new(RwLock::new(MockNetworkExtension::new(config)))
}

/// Spawn a background task that periodically prunes the mock extension's caches.
pub fn spawn_cache_pruner(
    ext: SharedMockNetworkExtension,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            ext.write().await.prune_caches();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_event(pid: u32, host: &str, port: u16) -> MockConnectEvent {
        MockConnectEvent {
            pid,
            process_name: "test-process".to_string(),
            destination_host: host.to_string(),
            destination_port: port,
            protocol: "tcp".to_string(),
            timestamp: chrono::Utc::now(),
        }
    }

    #[test]
    fn non_agent_traffic_always_allowed() {
        let mut ext = MockNetworkExtension::new(MockNetworkExtensionConfig::default());
        let event = test_event(1234, "evil.example.com", 443);
        let (decision, _) = ext.evaluate_connect(&event, false, None);
        assert_eq!(decision, MockNetworkDecision::Allow);
        assert_eq!(ext.stats().flows_allowed_not_agent, 1);
    }

    #[test]
    fn localhost_always_allowed_for_agents() {
        let mut ext = MockNetworkExtension::new(MockNetworkExtensionConfig::default());
        let event = test_event(1234, "127.0.0.1", 8080);
        let (decision, reason) = ext.evaluate_connect(&event, true, Some("test-server"));
        assert_eq!(decision, MockNetworkDecision::Allow);
        assert!(reason.contains("localhost"));
    }

    #[test]
    fn blocked_host_returns_block() {
        let mut ext = MockNetworkExtension::new(MockNetworkExtensionConfig::default());
        ext.update_blocked_hosts(vec!["evil.example.com".to_string()]);

        let event = test_event(1234, "evil.example.com", 443);
        let (decision, reason) = ext.evaluate_connect(&event, true, Some("test-server"));
        assert_eq!(decision, MockNetworkDecision::Block);
        assert!(reason.contains("IoC blocklist"));
        assert_eq!(ext.stats().flows_blocked, 1);
    }

    #[test]
    fn subdomain_of_blocked_host_also_blocked() {
        let mut ext = MockNetworkExtension::new(MockNetworkExtensionConfig::default());
        ext.update_blocked_hosts(vec!["evil.com".to_string()]);

        let event = test_event(1234, "api.evil.com", 443);
        let (decision, _) = ext.evaluate_connect(&event, true, Some("test-server"));
        assert_eq!(decision, MockNetworkDecision::Block);
    }

    #[test]
    fn default_policy_allows_unknown_hosts() {
        let mut ext = MockNetworkExtension::new(MockNetworkExtensionConfig::default());
        let event = test_event(1234, "api.openai.com", 443);
        let (decision, _) = ext.evaluate_connect(&event, true, Some("test-server"));
        assert_eq!(decision, MockNetworkDecision::Allow);
        assert_eq!(ext.stats().flows_allowed_policy, 1);
    }

    #[test]
    fn policy_cache_is_used() {
        let mut ext = MockNetworkExtension::new(MockNetworkExtensionConfig::default());
        let event = test_event(1234, "api.example.com", 443);

        // First call populates cache.
        ext.evaluate_connect(&event, true, Some("s1"));
        // Second call should use cache.
        let (decision, _) = ext.evaluate_connect(&event, true, Some("s1"));
        assert_eq!(decision, MockNetworkDecision::Allow);
        assert_eq!(ext.stats().flows_total, 2);
    }

    #[test]
    fn cache_pruning() {
        let mut config = MockNetworkExtensionConfig::default();
        config.policy_cache_ttl_secs = 0; // Expire immediately.
        let mut ext = MockNetworkExtension::new(config);

        let event = test_event(1234, "api.example.com", 443);
        ext.evaluate_connect(&event, true, Some("s1"));

        // Cache should be populated.
        assert_eq!(ext.policy_cache.len(), 1);

        // After pruning with 0 TTL, cache should be empty.
        std::thread::sleep(Duration::from_millis(10));
        ext.prune_caches();
        assert_eq!(ext.policy_cache.len(), 0);
    }

    #[test]
    fn stats_accumulate() {
        let mut ext = MockNetworkExtension::new(MockNetworkExtensionConfig::default());
        ext.update_blocked_hosts(vec!["bad.com".to_string()]);

        ext.evaluate_connect(&test_event(1, "x.com", 80), false, None);
        ext.evaluate_connect(&test_event(2, "127.0.0.1", 80), true, Some("s"));
        ext.evaluate_connect(&test_event(3, "bad.com", 80), true, Some("s"));
        ext.evaluate_connect(&test_event(4, "ok.com", 80), true, Some("s"));

        let stats = ext.stats();
        assert_eq!(stats.flows_total, 4);
        assert_eq!(stats.flows_allowed_not_agent, 1);
        assert_eq!(stats.flows_blocked, 1);
        // localhost + ok.com = 2
        assert_eq!(stats.flows_allowed_policy, 2);
    }
}
