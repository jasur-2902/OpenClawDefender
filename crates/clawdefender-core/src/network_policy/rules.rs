//! Network rule types and matching logic.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// A single network policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    /// Unique name for this rule.
    pub name: String,
    /// Action to take when matched.
    pub action: NetworkAction,
    /// Destinations that this rule applies to.
    pub destinations: Vec<DestinationPattern>,
    /// Destinations explicitly excluded from this rule.
    #[serde(default)]
    pub not_destinations: Vec<DestinationPattern>,
    /// Where this rule came from.
    pub source: RuleSource,
    /// If true, only apply this rule to agent processes.
    #[serde(default)]
    pub only_agents: bool,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Priority — lower numbers are evaluated first.
    #[serde(default)]
    pub priority: u32,
}

/// Action the network policy engine can take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAction {
    Allow,
    Block,
    Prompt,
    Log,
}

/// Pattern for matching destinations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum DestinationPattern {
    /// Exact match: "127.0.0.1", "api.anthropic.com"
    Exact(String),
    /// CIDR range: "10.0.0.0/8"
    CIDR(String),
    /// Wildcard: "*.googleapis.com"
    Wildcard(String),
    /// Match everything.
    All,
}

/// Where a rule originated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    User,
    ThreatIntel,
    Community,
    Default,
    Guard,
}

impl NetworkRule {
    /// Check whether a destination (IP or domain) matches this rule.
    pub fn matches_destination(&self, ip: Option<IpAddr>, domain: Option<&str>) -> bool {
        // Check exclusions first.
        for pat in &self.not_destinations {
            if pat.matches(ip, domain) {
                return false;
            }
        }
        // Check inclusions.
        for pat in &self.destinations {
            if pat.matches(ip, domain) {
                return true;
            }
        }
        false
    }
}

impl DestinationPattern {
    /// Test if this pattern matches the given IP address or domain.
    pub fn matches(&self, ip: Option<IpAddr>, domain: Option<&str>) -> bool {
        match self {
            DestinationPattern::All => true,
            DestinationPattern::Exact(value) => {
                // Match against domain.
                if let Some(d) = domain {
                    if d.eq_ignore_ascii_case(value) {
                        return true;
                    }
                }
                // Match against IP string.
                if let Some(ip_addr) = ip {
                    if ip_addr.to_string() == *value {
                        return true;
                    }
                }
                false
            }
            DestinationPattern::CIDR(cidr_str) => {
                if let Some(ip_addr) = ip {
                    cidr_contains(cidr_str, ip_addr)
                } else {
                    false
                }
            }
            DestinationPattern::Wildcard(pattern) => {
                if let Some(d) = domain {
                    wildcard_match(pattern, d)
                } else {
                    false
                }
            }
        }
    }
}

/// Check if an IP address falls within a CIDR range.
fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((addr_str, prefix_str)) = cidr.split_once('/') else {
        // Not a CIDR, try exact match.
        return addr_str_matches(cidr, ip);
    };
    let Ok(prefix_len) = prefix_str.parse::<u8>() else {
        return false;
    };
    let Ok(network) = addr_str.parse::<IpAddr>() else {
        return false;
    };

    match (network, ip) {
        (IpAddr::V4(net), IpAddr::V4(addr)) => {
            if prefix_len == 0 {
                return true;
            }
            if prefix_len >= 32 {
                return net == addr;
            }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from(net) & mask) == (u32::from(addr) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) => {
            if prefix_len == 0 {
                return true;
            }
            if prefix_len >= 128 {
                return net == addr;
            }
            let net_bits = u128::from(net);
            let addr_bits = u128::from(addr);
            let mask = u128::MAX << (128 - prefix_len);
            (net_bits & mask) == (addr_bits & mask)
        }
        _ => false,
    }
}

fn addr_str_matches(addr_str: &str, ip: IpAddr) -> bool {
    if let Ok(parsed) = addr_str.parse::<IpAddr>() {
        parsed == ip
    } else {
        false
    }
}

/// Simple wildcard matching for domain patterns like "*.googleapis.com".
fn wildcard_match(pattern: &str, domain: &str) -> bool {
    let lower_domain = domain.to_lowercase();
    let lower_pattern = pattern.to_lowercase();

    if lower_pattern == "*" {
        return true;
    }
    if let Some(suffix) = lower_pattern.strip_prefix("*.") {
        // "*.googleapis.com" matches "storage.googleapis.com" and
        // "sub.storage.googleapis.com", but NOT "googleapis.com" itself.
        lower_domain.ends_with(&format!(".{}", suffix))
    } else {
        lower_domain == lower_pattern
    }
}

/// Build the default rules that always apply.
pub fn default_rules() -> Vec<NetworkRule> {
    vec![
        NetworkRule {
            name: "allow_localhost".to_string(),
            action: NetworkAction::Allow,
            destinations: vec![
                DestinationPattern::Exact("127.0.0.1".to_string()),
                DestinationPattern::Exact("::1".to_string()),
                DestinationPattern::Exact("localhost".to_string()),
            ],
            not_destinations: vec![],
            source: RuleSource::Default,
            only_agents: false,
            description: "Always allow localhost connections".to_string(),
            priority: 0,
        },
        NetworkRule {
            name: "prompt_unknown_external".to_string(),
            action: NetworkAction::Prompt,
            destinations: vec![DestinationPattern::All],
            not_destinations: vec![],
            source: RuleSource::Default,
            only_agents: true,
            description: "Prompt for unknown external destinations from agents".to_string(),
            priority: 1000,
        },
    ]
}
