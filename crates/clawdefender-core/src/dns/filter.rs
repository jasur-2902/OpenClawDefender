//! DNS filtering engine.
//!
//! Evaluates DNS queries against blocklists, allowlists, wildcard patterns,
//! IoC feeds, and domain intelligence to produce allow/block/log decisions.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::domain_intel::{DomainCategory, DomainIntelligence};

/// A DNS query to evaluate.
///
/// SECURITY: Contains metadata only — domain name, query type, source PID.
/// No DNS response payload or resolved IP addresses are stored in this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub domain: String,
    pub query_type: DnsQueryType,
    pub source_pid: u32,
    pub server_name: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// DNS record type being queried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsQueryType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    SRV,
    Other(String),
}

/// Result of evaluating a DNS query against the filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFilterResult {
    pub action: DnsAction,
    pub reason: String,
    pub domain_category: DomainCategory,
    pub threat_id: Option<String>,
}

/// Action to take on a DNS query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsAction {
    /// Forward to resolver.
    Allow,
    /// Return NXDOMAIN.
    Block,
    /// Allow but log with extra detail.
    Log,
}

/// Audit event for a DNS query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryEvent {
    pub event_type: String,
    pub source: String,
    pub pid: u32,
    pub server_name: Option<String>,
    pub domain: String,
    pub query_type: String,
    pub result: String,
    pub reason: Option<String>,
    pub category: DomainCategory,
    pub timestamp: DateTime<Utc>,
}

/// DNS filtering engine that checks domains against multiple lists.
///
/// SECURITY: This filter operates on domain names only — metadata, not content.
/// It never inspects DNS response payloads, TLS certificates, or application data.
///
/// SECURITY: Fail-open design — when no blocklist is loaded, all queries are
/// allowed. The filter never blocks a domain unless it explicitly matches a
/// blocklist entry, IoC feed, or domain intelligence heuristic.
///
/// Threat model: prevents DNS-based C2 communication, blocks known malicious
/// domains, and detects suspicious domain patterns (DGA, high entropy). Does
/// NOT prevent IP-based C2 that bypasses DNS.
pub struct DnsFilter {
    blocklist: HashSet<String>,
    wildcard_blocks: Vec<String>,
    allowlist: HashSet<String>,
    ioc_domains: Vec<String>,
    domain_intel: DomainIntelligence,
}

impl DnsFilter {
    /// Create a new DNS filter with default domain intelligence.
    pub fn new() -> Self {
        Self {
            blocklist: HashSet::new(),
            wildcard_blocks: Vec::new(),
            allowlist: HashSet::new(),
            ioc_domains: Vec::new(),
            domain_intel: DomainIntelligence::new(),
        }
    }

    /// Evaluate a DNS query and return the filter decision.
    ///
    /// Check order: allowlist -> blocklist -> wildcard blocks -> IoC domains -> domain intel -> allow
    ///
    /// SECURITY: The check order is security-critical. Allowlist is checked first
    /// so that user overrides are respected, but IoC feeds can still block domains
    /// that are on the blocklist. If no list matches, the default is Allow (fail-open).
    pub fn check_domain(&self, query: &DnsQuery) -> DnsFilterResult {
        let domain = query.domain.to_lowercase();

        // 1. Allowlist check — explicitly allowed domains pass immediately.
        if self.allowlist.contains(&domain) {
            return DnsFilterResult {
                action: DnsAction::Allow,
                reason: "domain in allowlist".to_string(),
                domain_category: DomainCategory::KnownSafe,
                threat_id: None,
            };
        }

        // 2. Exact blocklist check.
        if self.blocklist.contains(&domain) {
            return DnsFilterResult {
                action: DnsAction::Block,
                reason: "domain in blocklist".to_string(),
                domain_category: DomainCategory::KnownMalicious,
                threat_id: None,
            };
        }

        // 3. Wildcard blocklist check.
        for pattern in &self.wildcard_blocks {
            // pattern is stored as ".evil.com" (the suffix after the wildcard)
            if domain.ends_with(pattern) && domain.len() > pattern.len() {
                return DnsFilterResult {
                    action: DnsAction::Block,
                    reason: format!("domain matches wildcard block *{}", pattern),
                    domain_category: DomainCategory::KnownMalicious,
                    threat_id: None,
                };
            }
        }

        // 4. IoC domain check.
        for ioc in &self.ioc_domains {
            let ioc_lower = ioc.to_lowercase();
            if domain == ioc_lower {
                return DnsFilterResult {
                    action: DnsAction::Block,
                    reason: "domain matches IoC feed".to_string(),
                    domain_category: DomainCategory::KnownMalicious,
                    threat_id: Some(format!("ioc-domain-{}", ioc_lower)),
                };
            }
        }

        // 5. Domain intelligence categorization.
        let category = self.domain_intel.categorize(&domain);
        match category {
            DomainCategory::KnownMalicious => DnsFilterResult {
                action: DnsAction::Block,
                reason: "domain intelligence: known malicious".to_string(),
                domain_category: category,
                threat_id: None,
            },
            DomainCategory::Suspicious => {
                let (_is_suspicious, reasons) = self.domain_intel.is_suspicious(&domain);
                DnsFilterResult {
                    action: DnsAction::Log,
                    reason: format!("suspicious domain: {}", reasons.join(", ")),
                    domain_category: category,
                    threat_id: None,
                }
            }
            _ => DnsFilterResult {
                action: DnsAction::Allow,
                reason: "no threat detected".to_string(),
                domain_category: category,
                threat_id: None,
            },
        }
    }

    /// Add a domain to the blocklist.
    pub fn add_block(&mut self, domain: &str) {
        let lower = domain.to_lowercase();
        if lower.starts_with("*.") {
            // Store as suffix: "*.evil.com" -> ".evil.com"
            self.wildcard_blocks.push(lower[1..].to_string());
        } else {
            self.blocklist.insert(lower);
        }
    }

    /// Add a domain to the allowlist.
    pub fn add_allow(&mut self, domain: &str) {
        self.allowlist.insert(domain.to_lowercase());
    }

    /// Replace the IoC domain list (called when the IoC feed updates).
    pub fn refresh_ioc_domains(&mut self, domains: &[String]) {
        self.ioc_domains = domains.to_vec();
    }
}

impl Default for DnsFilter {
    fn default() -> Self {
        Self::new()
    }
}
