//! DNS cache with TTL-based expiration and size limits.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::domain_intel::DomainCategory;

/// Statistics about the DNS cache.
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub size: usize,
    pub max_size: usize,
    pub hits: u64,
    pub misses: u64,
}

impl CacheStats {
    /// Hit rate as a fraction (0.0 to 1.0).
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }
}

/// A single cached DNS entry.
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub domain: String,
    pub ips: Vec<IpAddr>,
    pub ttl: Duration,
    pub cached_at: Instant,
    pub category: DomainCategory,
}

impl DnsCacheEntry {
    /// Whether this entry has expired based on its TTL.
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// TTL-based DNS cache with bounded size.
pub struct DnsCache {
    entries: HashMap<String, DnsCacheEntry>,
    max_size: usize,
    hits: u64,
    misses: u64,
}

impl DnsCache {
    /// Create a new cache with the given maximum number of entries.
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a domain in the cache. Returns `None` if not present or expired.
    pub fn lookup(&mut self, domain: &str) -> Option<&DnsCacheEntry> {
        let lower = domain.to_lowercase();

        // Check if expired first
        if let Some(entry) = self.entries.get(&lower) {
            if entry.is_expired() {
                self.entries.remove(&lower);
                self.misses += 1;
                return None;
            }
        }

        if self.entries.contains_key(&lower) {
            self.hits += 1;
            self.entries.get(&lower)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert a DNS entry into the cache.
    pub fn insert(
        &mut self,
        domain: &str,
        ips: Vec<IpAddr>,
        ttl: Duration,
        category: DomainCategory,
    ) {
        // Evict expired entries if we're at capacity.
        if self.entries.len() >= self.max_size {
            self.evict_expired();
        }

        // If still at capacity after eviction, remove the oldest entry.
        if self.entries.len() >= self.max_size {
            let oldest_key = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at)
                .map(|(key, _)| key.clone());
            if let Some(key) = oldest_key {
                self.entries.remove(&key);
            }
        }

        let lower = domain.to_lowercase();
        self.entries.insert(
            lower.clone(),
            DnsCacheEntry {
                domain: lower,
                ips,
                ttl,
                cached_at: Instant::now(),
                category,
            },
        );
    }

    /// Remove all entries that have exceeded their TTL.
    pub fn evict_expired(&mut self) {
        self.entries.retain(|_, entry| !entry.is_expired());
    }

    /// Clear all entries (e.g., on blocklist update).
    pub fn invalidate_all(&mut self) {
        self.entries.clear();
    }

    /// Return cache statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            size: self.entries.len(),
            max_size: self.max_size,
            hits: self.hits,
            misses: self.misses,
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(10_000)
    }
}
