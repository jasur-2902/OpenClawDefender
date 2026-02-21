//! Blocklist matching engine.
//!
//! Provides [`BlocklistMatcher`] which holds a parsed blocklist and can check
//! whether a given MCP server (by name, version, or binary hash) appears in
//! the blocklist.

use std::sync::Arc;
use std::sync::RwLock;

use super::types::*;

// ---------------------------------------------------------------------------
// Semver helpers (lightweight, no external crate)
// ---------------------------------------------------------------------------

/// A parsed semantic version (major.minor.patch). Pre-release / build metadata
/// are intentionally ignored for blocklist matching purposes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SemVer {
    major: u64,
    minor: u64,
    patch: u64,
}

impl SemVer {
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches('v');
        let mut parts = s.splitn(3, '.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        let patch = parts
            .next()
            .and_then(|p| {
                // strip pre-release / build metadata
                let clean = p.split(['-', '+']).next().unwrap_or(p);
                clean.parse().ok()
            })
            .unwrap_or(0);
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

/// Evaluate a simple semver range expression against a concrete version.
///
/// Supported forms:
///   `<1.5.0`  `<=1.5.0`  `>2.0.0`  `>=2.0.0`  `=1.0.0`  `1.0.0`
///   `>=1.0.0, <2.0.0`  (comma-separated conjunction)
fn matches_semver_range(version_str: &str, range_expr: &str) -> bool {
    let range_expr = range_expr.trim();
    // Handle comma-separated conjunction
    if range_expr.contains(',') {
        return range_expr
            .split(',')
            .all(|part| matches_single_range(version_str, part.trim()));
    }
    matches_single_range(version_str, range_expr)
}

fn matches_single_range(version_str: &str, range: &str) -> bool {
    let range = range.trim();
    if range.is_empty() {
        return false;
    }

    let ver = match SemVer::parse(version_str) {
        Some(v) => v,
        None => return false,
    };

    if let Some(rest) = range.strip_prefix("<=") {
        SemVer::parse(rest).is_some_and(|bound| ver <= bound)
    } else if let Some(rest) = range.strip_prefix(">=") {
        SemVer::parse(rest).is_some_and(|bound| ver >= bound)
    } else if let Some(rest) = range.strip_prefix('<') {
        SemVer::parse(rest).is_some_and(|bound| ver < bound)
    } else if let Some(rest) = range.strip_prefix('>') {
        SemVer::parse(rest).is_some_and(|bound| ver > bound)
    } else if let Some(rest) = range.strip_prefix('=') {
        SemVer::parse(rest).is_some_and(|bound| ver == bound)
    } else {
        // bare version = exact match
        SemVer::parse(range).is_some_and(|bound| ver == bound)
    }
}

// ---------------------------------------------------------------------------
// BlocklistMatcher
// ---------------------------------------------------------------------------

/// Holds a parsed blocklist and performs server lookups.
///
/// The inner blocklist is behind an `Arc<RwLock<..>>` so that it can be
/// atomically replaced at runtime when a feed update arrives.
#[derive(Debug, Clone)]
pub struct BlocklistMatcher {
    blocklist: Arc<RwLock<Blocklist>>,
    overrides: Arc<RwLock<Vec<BlocklistOverride>>>,
}

impl BlocklistMatcher {
    /// Create a new matcher from the given blocklist.
    pub fn new(blocklist: Blocklist) -> Self {
        Self {
            blocklist: Arc::new(RwLock::new(blocklist)),
            overrides: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create an empty matcher with no entries.
    pub fn empty() -> Self {
        Self::new(Blocklist {
            version: 0,
            updated_at: String::new(),
            entries: Vec::new(),
        })
    }

    /// Atomically replace the entire blocklist (e.g. after a feed update).
    pub fn update_blocklist(&self, new_blocklist: Blocklist) {
        let mut bl = self.blocklist.write().expect("blocklist lock poisoned");
        *bl = new_blocklist;
    }

    /// Return the current blocklist version number.
    pub fn version(&self) -> u64 {
        self.blocklist
            .read()
            .expect("blocklist lock poisoned")
            .version
    }

    /// Check a server against the blocklist.
    ///
    /// - `name`: the package / server name (matched case-insensitively).
    /// - `version`: optional version string.
    /// - `sha256`: optional hex-encoded SHA-256 hash of the server binary.
    ///
    /// Returns all matching entries (there may be more than one).
    pub fn check_server(
        &self,
        name: &str,
        version: Option<&str>,
        sha256: Option<&str>,
    ) -> Vec<BlocklistMatch> {
        let bl = self.blocklist.read().expect("blocklist lock poisoned");
        let overrides = self.overrides.read().expect("overrides lock poisoned");

        let name_lower = name.to_ascii_lowercase();

        let mut matches: Vec<BlocklistMatch> = Vec::new();

        for entry in &bl.entries {
            let entry_name_lower = entry.name.to_ascii_lowercase();

            // --- SHA-256 match (independent of name) ---
            if let (Some(hash), Some(ref hashes)) = (sha256, &entry.sha256_malicious) {
                let hash_lower = hash.to_ascii_lowercase();
                if hashes.iter().any(|h| h.to_ascii_lowercase() == hash_lower) {
                    matches.push(build_match(entry, MatchType::Sha256Hash));
                    continue; // already matched this entry
                }
            }

            // Name must match for the remaining checks.
            if entry_name_lower != name_lower {
                // Also check npm_package name
                let npm_match = entry
                    .npm_package
                    .as_ref()
                    .is_some_and(|npm| npm.to_ascii_lowercase() == name_lower);
                if !npm_match {
                    continue;
                }
            }

            match entry.entry_type {
                BlocklistEntryType::MaliciousServer => {
                    // All versions are malicious — name match is enough.
                    // But if specific versions listed, check those first.
                    if let Some(ref versions) = entry.versions {
                        if let Some(ver) = version {
                            if versions.iter().any(|v| v == ver) {
                                matches.push(build_match(entry, MatchType::ExactVersion));
                            } else {
                                // Name matched, but version not in list —
                                // for MaliciousServer we still block by name.
                                matches.push(build_match(entry, MatchType::ExactName));
                            }
                        } else {
                            matches.push(build_match(entry, MatchType::ExactName));
                        }
                    } else {
                        matches.push(build_match(entry, MatchType::ExactName));
                    }
                }

                BlocklistEntryType::VulnerableServer => {
                    // Need version information to determine if affected.
                    if let Some(ver) = version {
                        // Check semver range first.
                        if let Some(ref range) = entry.versions_affected {
                            if matches_semver_range(ver, range) {
                                // Check if this version is in the safe list.
                                let is_safe = entry
                                    .versions_safe
                                    .as_ref()
                                    .is_some_and(|safe| safe.iter().any(|s| s == ver));
                                if !is_safe {
                                    matches.push(build_match(entry, MatchType::SemverRange));
                                }
                                continue;
                            }
                        }
                        // Check exact version list.
                        if let Some(ref versions) = entry.versions {
                            if versions.iter().any(|v| v == ver) {
                                matches.push(build_match(entry, MatchType::ExactVersion));
                            }
                        }
                    }
                    // Without a version we cannot tell — no match.
                }

                BlocklistEntryType::CompromisedVersion => {
                    // Only specific versions are compromised.
                    if let Some(ver) = version {
                        if let Some(ref versions) = entry.versions {
                            if versions.iter().any(|v| v == ver) {
                                matches.push(build_match(entry, MatchType::ExactVersion));
                            }
                        }
                    }
                }
            }
        }

        // Filter out overridden matches.
        matches.retain(|m| {
            !overrides.iter().any(|o| {
                o.entry_id == m.entry_id && o.server_name.to_ascii_lowercase() == name_lower
            })
        });

        matches
    }

    // -----------------------------------------------------------------------
    // Overrides
    // -----------------------------------------------------------------------

    /// Add an override allowing a blocked server to run.
    ///
    /// The caller must supply the exact confirmation text
    /// [`OVERRIDE_CONFIRMATION_TEXT`] or the override will be rejected.
    pub fn add_override(&self, ovr: BlocklistOverride) -> Result<(), String> {
        if ovr.confirmation != OVERRIDE_CONFIRMATION_TEXT {
            return Err(format!(
                "Invalid confirmation text. Expected exactly: \"{}\"",
                OVERRIDE_CONFIRMATION_TEXT
            ));
        }
        let mut overrides = self.overrides.write().expect("overrides lock poisoned");
        overrides.push(ovr);
        Ok(())
    }

    /// Remove all overrides for a given entry ID and server name.
    pub fn remove_override(&self, entry_id: &str, server_name: &str) {
        let mut overrides = self.overrides.write().expect("overrides lock poisoned");
        let name_lower = server_name.to_ascii_lowercase();
        overrides.retain(|o| {
            !(o.entry_id == entry_id && o.server_name.to_ascii_lowercase() == name_lower)
        });
    }

    /// List current overrides.
    pub fn list_overrides(&self) -> Vec<BlocklistOverride> {
        self.overrides
            .read()
            .expect("overrides lock poisoned")
            .clone()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn action_for(entry_type: &BlocklistEntryType) -> RecommendedAction {
    match entry_type {
        BlocklistEntryType::MaliciousServer => RecommendedAction::Block,
        BlocklistEntryType::VulnerableServer => RecommendedAction::Warn,
        BlocklistEntryType::CompromisedVersion => RecommendedAction::Block,
    }
}

fn build_match(entry: &BlocklistEntry, match_type: MatchType) -> BlocklistMatch {
    BlocklistMatch {
        entry_id: entry.id.clone(),
        entry_name: entry.name.clone(),
        match_type,
        action: action_for(&entry.entry_type),
        severity: entry.severity.clone(),
        description: entry.description.clone(),
        remediation: entry.remediation.clone(),
    }
}

#[cfg(test)]
mod semver_tests {
    use super::*;

    #[test]
    fn parse_basic() {
        assert_eq!(
            SemVer::parse("1.5.3"),
            Some(SemVer {
                major: 1,
                minor: 5,
                patch: 3
            })
        );
    }

    #[test]
    fn parse_with_v_prefix() {
        assert_eq!(
            SemVer::parse("v2.0.0"),
            Some(SemVer {
                major: 2,
                minor: 0,
                patch: 0
            })
        );
    }

    #[test]
    fn range_less_than() {
        assert!(matches_semver_range("1.4.9", "<1.5.0"));
        assert!(!matches_semver_range("1.5.0", "<1.5.0"));
        assert!(!matches_semver_range("1.5.1", "<1.5.0"));
    }

    #[test]
    fn range_greater_equal() {
        assert!(matches_semver_range("2.0.0", ">=2.0.0"));
        assert!(matches_semver_range("3.0.0", ">=2.0.0"));
        assert!(!matches_semver_range("1.9.9", ">=2.0.0"));
    }

    #[test]
    fn range_conjunction() {
        assert!(matches_semver_range("1.5.0", ">=1.0.0, <2.0.0"));
        assert!(!matches_semver_range("2.0.0", ">=1.0.0, <2.0.0"));
        assert!(!matches_semver_range("0.9.0", ">=1.0.0, <2.0.0"));
    }
}
