//! High-performance IoC matching engine.
//!
//! Uses optimised data structures for sub-millisecond matching:
//! - `HashSet` for exact IP / hash lookups
//! - Aho-Corasick automaton for domain and string pattern multi-matching
//! - Compiled `Regex` for command-line patterns
//! - Linear scan with parsed CIDR networks for IP range checks
//! - `glob::Pattern` for file path matching

use std::collections::HashMap;
use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use regex::Regex;

use super::types::*;

// ---------------------------------------------------------------------------
// Parsed CIDR helper
// ---------------------------------------------------------------------------

/// A parsed CIDR range for efficient containment checks.
#[derive(Debug, Clone)]
struct CidrEntry {
    network: IpAddr,
    prefix_len: u8,
    entry_index: usize,
}

impl CidrEntry {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                if self.prefix_len >= 32 {
                    return net == addr;
                }
                let mask = u32::MAX << (32 - self.prefix_len);
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                if self.prefix_len >= 128 {
                    return net == addr;
                }
                let net_bits = u128::from(net);
                let addr_bits = u128::from(addr);
                let mask = u128::MAX << (128 - self.prefix_len);
                (net_bits & mask) == (addr_bits & mask)
            }
            _ => false, // v4 vs v6 mismatch
        }
    }
}

// ---------------------------------------------------------------------------
// IoCEngine
// ---------------------------------------------------------------------------

/// The compiled IoC matching engine.
///
/// Build this from a set of `IndicatorEntry` items via [`IoCEngine::build`].
/// The engine is immutable once built; to update indicators, build a new one
/// and swap it in via `Arc`.
#[derive(Debug)]
pub struct IoCEngine {
    /// All indicator entries (the engine references them by index).
    entries: Vec<IndicatorEntry>,

    // -- Exact-match structures --
    /// IP string -> entry indices (for single-IP indicators).
    exact_ips: HashMap<IpAddr, Vec<usize>>,
    /// Lowercase SHA-256 hash -> entry indices.
    exact_hashes: HashMap<String, Vec<usize>>,
    /// Lowercase process name -> entry indices.
    exact_process_names: HashMap<String, Vec<usize>>,

    // -- CIDR --
    cidrs: Vec<CidrEntry>,

    // -- Domain matching (Aho-Corasick) --
    /// Exact domain strings used as Aho-Corasick patterns.
    domain_patterns: Vec<String>,
    domain_entry_indices: Vec<usize>,
    domain_ac: Option<AhoCorasick>,
    /// Wildcard domain suffixes (e.g. ".evil.com" for "*.evil.com").
    wildcard_domains: Vec<(String, usize)>,

    // -- URL prefix matching --
    url_prefixes: Vec<(String, usize)>,

    // -- File path globs --
    file_globs: Vec<(glob::Pattern, usize)>,

    // -- Command-line regex --
    cmd_regexes: Vec<(Regex, usize)>,

    // -- Tool sequence patterns --
    tool_sequences: Vec<(Vec<String>, usize)>,

    // -- Arg patterns (tool + regex) --
    arg_patterns: Vec<(String, Regex, usize)>,
}

impl IoCEngine {
    /// Build a new engine from a set of indicator entries.
    pub fn build(entries: Vec<IndicatorEntry>) -> Self {
        let mut exact_ips: HashMap<IpAddr, Vec<usize>> = HashMap::new();
        let mut exact_hashes: HashMap<String, Vec<usize>> = HashMap::new();
        let mut exact_process_names: HashMap<String, Vec<usize>> = HashMap::new();
        let mut cidrs = Vec::new();
        let mut domain_patterns = Vec::new();
        let mut domain_entry_indices = Vec::new();
        let mut wildcard_domains = Vec::new();
        let mut url_prefixes = Vec::new();
        let mut file_globs = Vec::new();
        let mut cmd_regexes = Vec::new();
        let mut tool_sequences = Vec::new();
        let mut arg_patterns = Vec::new();

        for (idx, entry) in entries.iter().enumerate() {
            match &entry.indicator {
                Indicator::MaliciousIP(ip_str) => {
                    if let Some((addr, prefix)) = parse_cidr(ip_str) {
                        let is_single = match addr {
                            IpAddr::V4(_) => prefix == 32,
                            IpAddr::V6(_) => prefix == 128,
                        };
                        if is_single {
                            exact_ips.entry(addr).or_default().push(idx);
                        } else {
                            cidrs.push(CidrEntry {
                                network: addr,
                                prefix_len: prefix,
                                entry_index: idx,
                            });
                        }
                    }
                }
                Indicator::MaliciousDomain(domain) => {
                    let lower = domain.to_lowercase();
                    if lower.starts_with("*.") {
                        // Wildcard: *.evil.com -> suffix ".evil.com"
                        let suffix = lower[1..].to_string(); // ".evil.com"
                        wildcard_domains.push((suffix, idx));
                    } else {
                        domain_patterns.push(lower);
                        domain_entry_indices.push(idx);
                    }
                }
                Indicator::MaliciousURL(url) => {
                    url_prefixes.push((url.to_lowercase(), idx));
                }
                Indicator::MaliciousFileHash(hash) => {
                    exact_hashes
                        .entry(hash.to_lowercase())
                        .or_default()
                        .push(idx);
                }
                Indicator::SuspiciousFilePath(pattern) => {
                    if let Ok(p) = glob::Pattern::new(pattern) {
                        file_globs.push((p, idx));
                    }
                }
                Indicator::SuspiciousProcessName(name) => {
                    exact_process_names
                        .entry(name.to_lowercase())
                        .or_default()
                        .push(idx);
                }
                Indicator::SuspiciousCommandLine(pattern) => {
                    if let Ok(re) = Regex::new(pattern) {
                        cmd_regexes.push((re, idx));
                    }
                }
                Indicator::SuspiciousToolSequence(seq) => {
                    tool_sequences.push((seq.clone(), idx));
                }
                Indicator::SuspiciousArgPattern { tool, pattern } => {
                    if let Ok(re) = Regex::new(pattern) {
                        arg_patterns.push((tool.clone(), re, idx));
                    }
                }
            }
        }

        // Build Aho-Corasick for domain exact matching.
        let domain_ac = if domain_patterns.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&domain_patterns)
                .ok()
        };

        Self {
            entries,
            exact_ips,
            exact_hashes,
            exact_process_names,
            cidrs,
            domain_patterns,
            domain_entry_indices,
            domain_ac,
            wildcard_domains,
            url_prefixes,
            file_globs,
            cmd_regexes,
            tool_sequences,
            arg_patterns,
        }
    }

    /// Check an event against all loaded indicators. Returns all matches.
    pub fn check_event(&self, event: &EventData) -> Vec<IoCMatch> {
        let mut matches = Vec::new();

        // -- IP matching --
        if let Some(ip) = event.destination_ip {
            // Exact IP
            if let Some(indices) = self.exact_ips.get(&ip) {
                for &idx in indices {
                    matches.push(self.make_match(
                        idx,
                        &event.event_id,
                        MatchType::Exact,
                        ip.to_string(),
                    ));
                }
            }
            // CIDR ranges
            for cidr in &self.cidrs {
                if cidr.contains(ip) {
                    matches.push(self.make_match(
                        cidr.entry_index,
                        &event.event_id,
                        MatchType::CIDR,
                        ip.to_string(),
                    ));
                }
            }
        }

        // -- Domain matching --
        if let Some(ref domain) = event.destination_domain {
            let lower = domain.to_lowercase();

            // Aho-Corasick exact domain check
            if let Some(ref ac) = self.domain_ac {
                // We need exact match, not substring, so verify length
                for mat in ac.find_overlapping_iter(&lower) {
                    let pattern_idx = mat.pattern().as_usize();
                    if self.domain_patterns[pattern_idx] == lower {
                        let entry_idx = self.domain_entry_indices[pattern_idx];
                        matches.push(self.make_match(
                            entry_idx,
                            &event.event_id,
                            MatchType::Exact,
                            domain.clone(),
                        ));
                    }
                }
            }

            // Wildcard domain check
            for (suffix, idx) in &self.wildcard_domains {
                if lower.ends_with(suffix) && lower.len() > suffix.len() {
                    matches.push(self.make_match(
                        *idx,
                        &event.event_id,
                        MatchType::Wildcard,
                        domain.clone(),
                    ));
                }
            }
        }

        // -- URL prefix matching --
        if let Some(ref domain) = event.destination_domain {
            let lower = domain.to_lowercase();
            for (prefix, idx) in &self.url_prefixes {
                if lower.starts_with(prefix.as_str()) {
                    matches.push(self.make_match(
                        *idx,
                        &event.event_id,
                        MatchType::Prefix,
                        domain.clone(),
                    ));
                }
            }
        }

        // -- Hash matching --
        if let Some(ref hash) = event.file_hash {
            let lower = hash.to_lowercase();
            if let Some(indices) = self.exact_hashes.get(&lower) {
                for &idx in indices {
                    matches.push(self.make_match(
                        idx,
                        &event.event_id,
                        MatchType::Exact,
                        hash.clone(),
                    ));
                }
            }
        }

        // -- File path glob matching --
        if let Some(ref path) = event.file_path {
            for (pattern, idx) in &self.file_globs {
                if pattern.matches(path) {
                    matches.push(self.make_match(
                        *idx,
                        &event.event_id,
                        MatchType::Glob,
                        path.clone(),
                    ));
                }
            }
        }

        // -- Process name matching --
        if let Some(ref name) = event.process_name {
            let lower = name.to_lowercase();
            if let Some(indices) = self.exact_process_names.get(&lower) {
                for &idx in indices {
                    matches.push(self.make_match(
                        idx,
                        &event.event_id,
                        MatchType::Exact,
                        name.clone(),
                    ));
                }
            }
        }

        // -- Command-line regex matching --
        if let Some(ref cmd) = event.command_line {
            for (re, idx) in &self.cmd_regexes {
                if re.is_match(cmd) {
                    matches.push(self.make_match(
                        *idx,
                        &event.event_id,
                        MatchType::Pattern,
                        cmd.clone(),
                    ));
                }
            }
        }

        // -- Tool sequence matching --
        if !event.tool_sequence.is_empty() {
            for (seq, idx) in &self.tool_sequences {
                if contains_subsequence(&event.tool_sequence, seq) {
                    matches.push(self.make_match(
                        *idx,
                        &event.event_id,
                        MatchType::Sequence,
                        format!("{:?}", event.tool_sequence),
                    ));
                }
            }
        }

        // -- Arg pattern matching --
        if let Some(ref tool) = event.tool_name {
            if let Some(ref args) = event.tool_args {
                for (t, re, idx) in &self.arg_patterns {
                    if t == tool && re.is_match(args) {
                        matches.push(self.make_match(
                            *idx,
                            &event.event_id,
                            MatchType::Pattern,
                            format!("{}:{}", tool, args),
                        ));
                    }
                }
            }
        }

        matches
    }

    /// Number of loaded indicator entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns a reference to all indicator entries.
    pub fn entries(&self) -> &[IndicatorEntry] {
        &self.entries
    }

    // -- helpers --

    fn make_match(
        &self,
        entry_index: usize,
        event_id: &str,
        match_type: MatchType,
        matched_value: String,
    ) -> IoCMatch {
        let entry = &self.entries[entry_index];
        let combined_confidence = entry.confidence * (1.0 - entry.false_positive_rate);
        IoCMatch {
            indicator: entry.clone(),
            event_id: event_id.to_string(),
            match_type,
            combined_confidence,
            matched_value,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a CIDR string like "192.168.1.0/24" or a plain IP like "10.0.0.1".
fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    if let Some((addr_str, prefix_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str.parse().ok()?;
        let prefix: u8 = prefix_str.parse().ok()?;
        Some((addr, prefix))
    } else {
        let addr: IpAddr = s.parse().ok()?;
        let prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Some((addr, prefix))
    }
}

/// Check if `haystack` contains `needle` as a contiguous subsequence.
fn contains_subsequence(haystack: &[String], needle: &[String]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
