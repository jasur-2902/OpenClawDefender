//! Comprehensive tests for the DNS module.

use std::net::IpAddr;
use std::time::Duration;

use chrono::Utc;

use super::cache::DnsCache;
use super::domain_intel::{DomainCategory, DomainIntelligence};
use super::exfiltration::{DnsExfiltrationDetector, ExfiltrationConfig};
use super::filter::{DnsAction, DnsFilter, DnsQuery, DnsQueryType};
use super::resolver::ReverseDnsResolver;

fn make_query(domain: &str) -> DnsQuery {
    DnsQuery {
        domain: domain.to_string(),
        query_type: DnsQueryType::A,
        source_pid: 1234,
        server_name: None,
        timestamp: Utc::now(),
    }
}

// -----------------------------------------------------------------------
// DNS Filter tests
// -----------------------------------------------------------------------

#[test]
fn test_blocked_domain_returns_block() {
    let mut filter = DnsFilter::new();
    filter.add_block("malware.example.com");
    let result = filter.check_domain(&make_query("malware.example.com"));
    assert_eq!(result.action, DnsAction::Block);
    assert!(result.reason.contains("blocklist"));
}

#[test]
fn test_allowed_domain_returns_allow() {
    let mut filter = DnsFilter::new();
    filter.add_block("example.com");
    filter.add_allow("example.com");
    // Allowlist takes priority over blocklist
    let result = filter.check_domain(&make_query("example.com"));
    assert_eq!(result.action, DnsAction::Allow);
    assert!(result.reason.contains("allowlist"));
}

#[test]
fn test_wildcard_block() {
    let mut filter = DnsFilter::new();
    filter.add_block("*.evil.com");
    let result = filter.check_domain(&make_query("sub.evil.com"));
    assert_eq!(result.action, DnsAction::Block);
    assert!(result.reason.contains("wildcard"));

    // The parent itself should not be blocked by the wildcard
    let result2 = filter.check_domain(&make_query("evil.com"));
    assert_ne!(result2.action, DnsAction::Block);
}

#[test]
fn test_ioc_domain_blocking() {
    let mut filter = DnsFilter::new();
    filter.refresh_ioc_domains(&["c2.badguys.net".to_string()]);
    let result = filter.check_domain(&make_query("c2.badguys.net"));
    assert_eq!(result.action, DnsAction::Block);
    assert!(result.reason.contains("IoC"));
    assert!(result.threat_id.is_some());
}

// -----------------------------------------------------------------------
// Domain Intelligence tests
// -----------------------------------------------------------------------

#[test]
fn test_categorize_known_safe() {
    let intel = DomainIntelligence::new();
    assert_eq!(intel.categorize("github.com"), DomainCategory::KnownSafe);
    assert_eq!(
        intel.categorize("s3.amazonaws.com"),
        DomainCategory::KnownSafe
    );
    assert_eq!(
        intel.categorize("api.anthropic.com"),
        DomainCategory::KnownSafe
    );
}

#[test]
fn test_categorize_suspicious() {
    let intel = DomainIntelligence::new();
    // .tk TLD is suspicious
    let cat = intel.categorize("something.tk");
    assert_eq!(cat, DomainCategory::Suspicious);
}

#[test]
fn test_categorize_unknown() {
    let intel = DomainIntelligence::new();
    assert_eq!(
        intel.categorize("normal-company.com"),
        DomainCategory::Unknown
    );
}

#[test]
fn test_entropy_calculation() {
    // All same character: entropy should be 0
    let e = DomainIntelligence::entropy("aaaa");
    assert!((e - 0.0).abs() < 0.01);

    // Two equally distributed chars: entropy should be 1.0
    let e = DomainIntelligence::entropy("abab");
    assert!((e - 1.0).abs() < 0.01);

    // High entropy random-looking string
    let e = DomainIntelligence::entropy("x8k3m9p2q7w4");
    assert!(e > 3.0);
}

#[test]
fn test_suspicious_high_entropy() {
    let intel = DomainIntelligence::new();
    let (suspicious, reasons) = intel.is_suspicious("x8k3m9p2q7w4z1.example.com");
    assert!(suspicious);
    assert!(reasons.iter().any(|r| r.contains("entropy")));
}

#[test]
fn test_suspicious_long_subdomain() {
    let intel = DomainIntelligence::new();
    let long_sub = "a".repeat(60);
    let domain = format!("{}.example.com", long_sub);
    let (suspicious, reasons) = intel.is_suspicious(&domain);
    assert!(suspicious);
    assert!(reasons.iter().any(|r| r.contains("long subdomain")));
}

#[test]
fn test_suspicious_dynamic_dns() {
    let intel = DomainIntelligence::new();
    let (suspicious, reasons) = intel.is_suspicious("myhost.duckdns.org");
    assert!(suspicious);
    assert!(reasons.iter().any(|r| r.contains("dynamic DNS")));
}

// -----------------------------------------------------------------------
// DNS Cache tests
// -----------------------------------------------------------------------

#[test]
fn test_cache_insert_and_lookup() {
    let mut cache = DnsCache::new(100);
    let ip: IpAddr = "93.184.216.34".parse().unwrap();
    cache.insert(
        "example.com",
        vec![ip],
        Duration::from_secs(300),
        DomainCategory::Unknown,
    );
    let entry = cache.lookup("example.com");
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().ips[0], ip);
}

#[test]
fn test_cache_ttl_expiration() {
    let mut cache = DnsCache::new(100);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    // Insert with zero TTL so it expires immediately
    cache.insert(
        "expired.com",
        vec![ip],
        Duration::from_secs(0),
        DomainCategory::Unknown,
    );
    // Should be expired
    let entry = cache.lookup("expired.com");
    assert!(entry.is_none());
}

#[test]
fn test_cache_max_size_eviction() {
    let mut cache = DnsCache::new(2);
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    cache.insert(
        "first.com",
        vec![ip],
        Duration::from_secs(300),
        DomainCategory::Unknown,
    );
    cache.insert(
        "second.com",
        vec![ip],
        Duration::from_secs(300),
        DomainCategory::Unknown,
    );
    cache.insert(
        "third.com",
        vec![ip],
        Duration::from_secs(300),
        DomainCategory::Unknown,
    );
    // One entry should have been evicted to make room
    let stats = cache.stats();
    assert!(stats.size <= 2);
}

#[test]
fn test_cache_invalidate_all() {
    let mut cache = DnsCache::new(100);
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    cache.insert(
        "a.com",
        vec![ip],
        Duration::from_secs(300),
        DomainCategory::Unknown,
    );
    cache.insert(
        "b.com",
        vec![ip],
        Duration::from_secs(300),
        DomainCategory::Unknown,
    );
    cache.invalidate_all();
    assert_eq!(cache.stats().size, 0);
}

// -----------------------------------------------------------------------
// DNS Exfiltration Detection tests
// -----------------------------------------------------------------------

#[test]
fn test_exfiltration_long_subdomain() {
    let detector = DnsExfiltrationDetector::new(ExfiltrationConfig {
        max_subdomain_length: 50,
        ..Default::default()
    });
    let long_sub = "a".repeat(60);
    let domain = format!("{}.evil.com", long_sub);
    let alert = detector.check_query(&domain, 1);
    assert!(alert.is_some());
    let alert = alert.unwrap();
    assert!(alert.detection_reason.contains("subdomain length"));
}

#[test]
fn test_exfiltration_high_query_rate() {
    let config = ExfiltrationConfig {
        max_queries_per_minute: 5,
        ..Default::default()
    };
    let mut detector = DnsExfiltrationDetector::new(config);

    // Record many queries to same parent
    for i in 0..10 {
        let domain = format!("sub{}.evil.com", i);
        detector.record_query(&domain, 1);
    }

    // Now check a new query — history should show high rate
    let alert = detector.check_query("another.evil.com", 1);
    assert!(alert.is_some());
    let alert = alert.unwrap();
    assert!(
        alert.detection_reason.contains("query rate")
            || alert.detection_reason.contains("unique subdomains")
    );
}

#[test]
fn test_exfiltration_many_unique_subdomains() {
    let config = ExfiltrationConfig {
        max_unique_subdomains: 5,
        ..Default::default()
    };
    let mut detector = DnsExfiltrationDetector::new(config);

    for i in 0..10 {
        let domain = format!("unique{}.evil.com", i);
        detector.record_query(&domain, 1);
    }

    let alert = detector.check_query("newunique.evil.com", 1);
    assert!(alert.is_some());
    let alert = alert.unwrap();
    assert!(alert.detection_reason.contains("unique subdomains"));
}

#[test]
fn test_exfiltration_base64_subdomain() {
    let detector = DnsExfiltrationDetector::default();
    // Base64-like subdomain
    let domain = "SGVsbG8gV29ybGQhIFRoaXM.evil.com";
    let alert = detector.check_query(domain, 1);
    assert!(alert.is_some());
    let alert = alert.unwrap();
    assert!(
        alert.detection_reason.contains("encoded")
            || alert.detection_reason.contains("entropy")
    );
}

// -----------------------------------------------------------------------
// Reverse DNS tests
// -----------------------------------------------------------------------

#[test]
fn test_reverse_dns_enrichment() {
    let mut resolver = ReverseDnsResolver::default();
    let ip: IpAddr = "93.184.216.34".parse().unwrap();
    resolver.record_forward("example.com", ip);

    let enriched = resolver.enrich_event("93.184.216.34");
    assert_eq!(enriched, "example.com (93.184.216.34)");

    // Unknown IP returns just the IP
    let unknown = resolver.enrich_event("1.2.3.4");
    assert_eq!(unknown, "1.2.3.4");
}

// -----------------------------------------------------------------------
// Performance test
// -----------------------------------------------------------------------

#[test]
fn test_performance_1000_lookups() {
    let mut filter = DnsFilter::new();
    // Add some domains to the filter
    for i in 0..100 {
        filter.add_block(&format!("blocked{}.example.com", i));
    }
    filter.add_allow("safe.example.com");

    let start = std::time::Instant::now();
    for i in 0..1_000 {
        let domain = format!("test{}.example.com", i % 200);
        filter.check_domain(&make_query(&domain));
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "1,000 lookups took {:?}, expected < 1s",
        elapsed
    );
}
