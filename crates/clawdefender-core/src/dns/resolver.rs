//! Reverse DNS enrichment.
//!
//! Maintains a cache of IP-to-domain mappings built from observed forward DNS
//! resolutions, and provides enrichment for IP addresses in logs and alerts.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A cached reverse DNS entry with expiration.
struct RdnsEntry {
    domain: Option<String>,
    cached_at: Instant,
}

/// Reverse DNS resolver that caches IP-to-domain mappings.
pub struct ReverseDnsResolver {
    cache: HashMap<IpAddr, RdnsEntry>,
    max_cache_size: usize,
    ttl: Duration,
}

impl ReverseDnsResolver {
    /// Create a new resolver with the given cache size and TTL.
    pub fn new(max_cache_size: usize, ttl: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            max_cache_size,
            ttl,
        }
    }

    /// Look up a cached reverse DNS entry for an IP address.
    pub fn resolve(&self, ip: IpAddr) -> Option<String> {
        if let Some(entry) = self.cache.get(&ip) {
            if entry.cached_at.elapsed() <= self.ttl {
                return entry.domain.clone();
            }
        }
        None
    }

    /// Record a forward DNS resolution (domain -> IP) for reverse lookups.
    pub fn record_forward(&mut self, domain: &str, ip: IpAddr) {
        if self.cache.len() >= self.max_cache_size && !self.cache.contains_key(&ip) {
            // Evict expired entries
            self.cache
                .retain(|_, entry| entry.cached_at.elapsed() <= self.ttl);

            // If still full, remove the oldest
            if self.cache.len() >= self.max_cache_size {
                let oldest = self
                    .cache
                    .iter()
                    .min_by_key(|(_, e)| e.cached_at)
                    .map(|(k, _)| *k);
                if let Some(key) = oldest {
                    self.cache.remove(&key);
                }
            }
        }

        self.cache.insert(
            ip,
            RdnsEntry {
                domain: Some(domain.to_string()),
                cached_at: Instant::now(),
            },
        );
    }

    /// Enrich an IP address string with its reverse DNS name if known.
    ///
    /// Returns "example.com (93.184.216.34)" if a mapping exists,
    /// or just the IP string if not.
    pub fn enrich_event(&self, ip_str: &str) -> String {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if let Some(domain) = self.resolve(ip) {
                return format!("{} ({})", domain, ip_str);
            }
        }
        ip_str.to_string()
    }
}

impl Default for ReverseDnsResolver {
    fn default() -> Self {
        Self::new(10_000, Duration::from_secs(3600))
    }
}
