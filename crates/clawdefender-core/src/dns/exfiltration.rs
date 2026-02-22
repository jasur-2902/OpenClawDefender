//! DNS exfiltration detection.
//!
//! Detects attempts to tunnel data out via DNS queries by monitoring
//! subdomain length, encoding patterns, query rates, and unique subdomain counts.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::domain_intel::DomainIntelligence;

/// Severity level for exfiltration alerts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Configuration for DNS exfiltration detection thresholds.
#[derive(Debug, Clone)]
pub struct ExfiltrationConfig {
    pub max_subdomain_length: usize,
    pub max_queries_per_minute: u32,
    pub max_unique_subdomains: u32,
    pub entropy_threshold: f64,
}

impl Default for ExfiltrationConfig {
    fn default() -> Self {
        Self {
            max_subdomain_length: 50,
            max_queries_per_minute: 10,
            max_unique_subdomains: 20,
            entropy_threshold: 3.5,
        }
    }
}

/// An alert generated when DNS exfiltration is suspected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsExfiltrationAlert {
    pub parent_domain: String,
    pub suspicious_subdomains: Vec<String>,
    pub severity: Severity,
    pub detection_reason: String,
}

/// Per-parent-domain query history for rate and pattern analysis.
struct DomainQueryHistory {
    query_times: Vec<Instant>,
    unique_subdomains: Vec<String>,
    window_start: Instant,
}

impl DomainQueryHistory {
    fn new() -> Self {
        Self {
            query_times: Vec::new(),
            unique_subdomains: Vec::new(),
            window_start: Instant::now(),
        }
    }

    /// Prune entries older than 5 minutes and reset window if needed.
    fn prune(&mut self) {
        let five_min = std::time::Duration::from_secs(300);
        let now = Instant::now();
        if now.duration_since(self.window_start) > five_min {
            self.query_times.clear();
            self.unique_subdomains.clear();
            self.window_start = now;
        }
    }
}

/// DNS exfiltration detector that tracks query patterns per parent domain.
pub struct DnsExfiltrationDetector {
    query_history: HashMap<String, DomainQueryHistory>,
    config: ExfiltrationConfig,
}

impl DnsExfiltrationDetector {
    /// Create a new detector with the given configuration.
    pub fn new(config: ExfiltrationConfig) -> Self {
        Self {
            query_history: HashMap::new(),
            config,
        }
    }

    /// Extract the parent domain (last two labels) from a full domain.
    fn parent_domain(domain: &str) -> Option<(&str, &str)> {
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 2 {
            return None;
        }
        // parent = last two labels, subdomain = everything before
        let parent_start =
            domain.len() - labels[labels.len() - 2].len() - 1 - labels[labels.len() - 1].len();
        let parent = &domain[parent_start..];
        let subdomain = if parent_start > 0 {
            &domain[..parent_start - 1]
        } else {
            ""
        };
        Some((parent, subdomain))
    }

    /// Check whether a query looks like potential data exfiltration.
    pub fn check_query(&self, domain: &str, _pid: u32) -> Option<DnsExfiltrationAlert> {
        let lower = domain.to_lowercase();
        let (parent, subdomain) = Self::parent_domain(&lower)?;

        if subdomain.is_empty() {
            return None;
        }

        let mut reasons = Vec::new();
        let mut suspicious_subs = Vec::new();

        // Check subdomain length
        if subdomain.len() > self.config.max_subdomain_length {
            reasons.push(format!(
                "subdomain length {} exceeds threshold {}",
                subdomain.len(),
                self.config.max_subdomain_length
            ));
            suspicious_subs.push(subdomain.to_string());
        }

        // Check for base64-like or hex-like encoding
        if Self::looks_encoded(subdomain) {
            reasons.push("subdomain appears base64 or hex encoded".to_string());
            suspicious_subs.push(subdomain.to_string());
        }

        // Check entropy
        let e = DomainIntelligence::entropy(subdomain);
        if e > self.config.entropy_threshold && subdomain.len() > 10 {
            reasons.push(format!("high entropy subdomain ({:.2})", e));
            if !suspicious_subs.contains(&subdomain.to_string()) {
                suspicious_subs.push(subdomain.to_string());
            }
        }

        // Check query rate and unique subdomain count from history
        if let Some(history) = self.query_history.get(parent) {
            let one_min_ago = Instant::now() - std::time::Duration::from_secs(60);
            let recent_count = history
                .query_times
                .iter()
                .filter(|t| **t > one_min_ago)
                .count() as u32;
            if recent_count >= self.config.max_queries_per_minute {
                reasons.push(format!(
                    "high query rate: {} queries/min to {}",
                    recent_count, parent
                ));
            }

            if history.unique_subdomains.len() as u32 >= self.config.max_unique_subdomains {
                reasons.push(format!(
                    "many unique subdomains: {} for {}",
                    history.unique_subdomains.len(),
                    parent
                ));
            }
        }

        if reasons.is_empty() {
            return None;
        }

        let severity = if reasons.len() >= 3 {
            Severity::Critical
        } else if reasons.len() >= 2 {
            Severity::High
        } else {
            Severity::Medium
        };

        Some(DnsExfiltrationAlert {
            parent_domain: parent.to_string(),
            suspicious_subdomains: suspicious_subs,
            severity,
            detection_reason: reasons.join("; "),
        })
    }

    /// Record a query for rate and pattern tracking.
    pub fn record_query(&mut self, domain: &str, _pid: u32) {
        let lower = domain.to_lowercase();
        if let Some((parent, subdomain)) = Self::parent_domain(&lower) {
            let parent_owned = parent.to_string();
            let history = self
                .query_history
                .entry(parent_owned)
                .or_insert_with(DomainQueryHistory::new);
            history.prune();
            history.query_times.push(Instant::now());
            let sub = subdomain.to_string();
            if !sub.is_empty() && !history.unique_subdomains.contains(&sub) {
                history.unique_subdomains.push(sub);
            }
        }
    }

    /// Check if a string looks like base64 or hex encoded data.
    fn looks_encoded(s: &str) -> bool {
        if s.len() < 12 {
            return false;
        }

        // Remove dots for subdomain analysis
        let clean: String = s.chars().filter(|c| *c != '.').collect();

        // Hex check: all chars are hex digits
        let hex_chars = clean.chars().filter(|c| c.is_ascii_hexdigit()).count();
        if hex_chars == clean.len() && clean.len() >= 16 {
            return true;
        }

        // Base64 check: mostly alphanumeric with some +/= padding
        let b64_chars = clean
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .count();
        if b64_chars == clean.len() && clean.len() >= 16 {
            // Also check that it has mixed case (typical of base64)
            let has_upper = clean.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = clean.chars().any(|c| c.is_ascii_lowercase());
            let has_digit = clean.chars().any(|c| c.is_ascii_digit());
            if (has_upper && has_lower) || (has_digit && (has_upper || has_lower)) {
                return true;
            }
        }

        false
    }
}

impl Default for DnsExfiltrationDetector {
    fn default() -> Self {
        Self::new(ExfiltrationConfig::default())
    }
}
