//! Domain categorization and intelligence.
//!
//! Classifies domains as known-safe, known-malicious, suspicious, or unknown
//! using pre-populated lists, wildcard patterns, and heuristic analysis.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Classification of a domain's threat level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainCategory {
    /// Major cloud, code hosting, package registries, AI APIs.
    KnownSafe,
    /// From IoC feed or blocklist.
    KnownMalicious,
    /// High entropy, new TLD, dynamic DNS, free hosting.
    Suspicious,
    /// Everything else.
    Unknown,
}

/// Domain intelligence engine with pre-populated safe domains and heuristics.
pub struct DomainIntelligence {
    known_safe: HashSet<String>,
    known_safe_wildcards: Vec<String>,
    dynamic_dns_providers: Vec<String>,
    suspicious_tlds: Vec<String>,
}

impl DomainIntelligence {
    /// Create a new instance with pre-populated known-safe domains.
    pub fn new() -> Self {
        let mut known_safe = HashSet::new();
        for domain in &[
            // Cloud
            "amazonaws.com",
            "googleapis.com",
            "azure.com",
            "cloudflare.com",
            // Code hosting
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            // Package registries
            "npmjs.org",
            "pypi.org",
            "crates.io",
            "rubygems.org",
            // AI APIs
            "api.anthropic.com",
            "api.openai.com",
            "api.cohere.com",
            // CDN
            "cdn.jsdelivr.net",
            "unpkg.com",
            "cdnjs.cloudflare.com",
        ] {
            known_safe.insert(domain.to_string());
        }

        let known_safe_wildcards = vec![
            ".amazonaws.com".to_string(),
            ".googleapis.com".to_string(),
            ".azure.com".to_string(),
            ".cloudflare.com".to_string(),
            ".github.com".to_string(),
            ".gitlab.com".to_string(),
        ];

        let dynamic_dns_providers = vec![
            "duckdns.org".to_string(),
            "no-ip.com".to_string(),
            "ddns.net".to_string(),
            "dynu.com".to_string(),
            "freedns.afraid.org".to_string(),
        ];

        let suspicious_tlds = vec![
            ".tk".to_string(),
            ".ml".to_string(),
            ".ga".to_string(),
            ".cf".to_string(),
            ".gq".to_string(),
        ];

        Self {
            known_safe,
            known_safe_wildcards,
            dynamic_dns_providers,
            suspicious_tlds,
        }
    }

    /// Categorize a domain based on intelligence data and heuristics.
    pub fn categorize(&self, domain: &str) -> DomainCategory {
        let lower = domain.to_lowercase();

        // Check exact known safe
        if self.known_safe.contains(&lower) {
            return DomainCategory::KnownSafe;
        }

        // Check wildcard known safe
        for suffix in &self.known_safe_wildcards {
            if lower.ends_with(suffix) {
                return DomainCategory::KnownSafe;
            }
        }

        // Check suspicious heuristics
        let (suspicious, _reasons) = self.is_suspicious(&lower);
        if suspicious {
            return DomainCategory::Suspicious;
        }

        DomainCategory::Unknown
    }

    /// Calculate Shannon entropy of a label (domain component).
    pub fn entropy(label: &str) -> f64 {
        if label.is_empty() {
            return 0.0;
        }

        let len = label.len() as f64;
        let mut freq = [0u32; 256];
        for &b in label.as_bytes() {
            freq[b as usize] += 1;
        }

        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Check if a domain is suspicious and return reasons.
    pub fn is_suspicious(&self, domain: &str) -> (bool, Vec<String>) {
        let lower = domain.to_lowercase();
        let mut reasons = Vec::new();

        // Extract labels (parts separated by dots)
        let labels: Vec<&str> = lower.split('.').collect();

        // Check entropy of each label (especially subdomains)
        for label in &labels {
            let e = Self::entropy(label);
            if e > 3.5 && label.len() > 6 {
                reasons.push(format!("high entropy label '{}' ({:.2})", label, e));
            }
        }

        // Check for very long subdomain (total subdomain length > 50)
        if labels.len() > 2 {
            let subdomain_part: String = labels[..labels.len() - 2].join(".");
            if subdomain_part.len() > 50 {
                reasons.push(format!(
                    "very long subdomain ({} chars)",
                    subdomain_part.len()
                ));
            }
        }

        // Check dynamic DNS providers
        for provider in &self.dynamic_dns_providers {
            if lower == *provider || lower.ends_with(&format!(".{}", provider)) {
                reasons.push(format!("dynamic DNS provider: {}", provider));
            }
        }

        // Check suspicious TLDs
        for tld in &self.suspicious_tlds {
            if lower.ends_with(tld) {
                reasons.push(format!("suspicious TLD: {}", tld));
            }
        }

        let suspicious = !reasons.is_empty();
        (suspicious, reasons)
    }
}

impl Default for DomainIntelligence {
    fn default() -> Self {
        Self::new()
    }
}
