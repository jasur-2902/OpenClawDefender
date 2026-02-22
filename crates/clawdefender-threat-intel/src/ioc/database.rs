//! IoC database manager.
//!
//! Manages the full set of indicators, supports loading from JSON files,
//! incremental updates, expiration, and rebuilding the matching engine.

use std::path::Path;
use std::sync::Arc;

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::engine::IoCEngine;
use super::types::*;

// ---------------------------------------------------------------------------
// Serialization wrapper for JSON files
// ---------------------------------------------------------------------------

/// JSON file format for IoC indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoCFile {
    pub version: String,
    pub indicators: Vec<IndicatorEntry>,
}

// ---------------------------------------------------------------------------
// IoCDatabase
// ---------------------------------------------------------------------------

/// Manages the complete set of IoC indicators and rebuilds the matching engine.
pub struct IoCDatabase {
    /// All current indicators, keyed by threat_id for deduplication.
    indicators: Vec<IndicatorEntry>,
    /// The compiled matching engine, wrapped in Arc for thread-safe sharing.
    engine: Arc<IoCEngine>,
    /// Default expiration age in days for non-permanent indicators.
    expiration_days: i64,
}

impl IoCDatabase {
    /// Create a new empty database.
    pub fn new() -> Self {
        let engine = Arc::new(IoCEngine::build(Vec::new()));
        Self {
            indicators: Vec::new(),
            engine,
            expiration_days: 90,
        }
    }

    /// Create a new database with a custom expiration period.
    pub fn with_expiration_days(days: i64) -> Self {
        let mut db = Self::new();
        db.expiration_days = days;
        db
    }

    /// Load indicators from a JSON file and add them to the database.
    pub fn load_from_file(&mut self, path: &Path) -> Result<usize, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        let ioc_file: IoCFile = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

        let count = ioc_file.indicators.len();
        info!(
            path = %path.display(),
            count,
            version = %ioc_file.version,
            "Loaded IoC indicators from file"
        );

        for entry in ioc_file.indicators {
            self.add_indicator(entry);
        }

        self.rebuild_engine();
        Ok(count)
    }

    /// Load all JSON files from a directory.
    pub fn load_from_directory(&mut self, dir: &Path) -> Result<usize, String> {
        let mut total = 0;
        let entries = std::fs::read_dir(dir)
            .map_err(|e| format!("Failed to read directory {}: {}", dir.display(), e))?;

        let mut files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
            })
            .collect();
        files.sort_by_key(|e| e.path());

        for entry in files {
            let path = entry.path();
            let content = std::fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
            let ioc_file: IoCFile = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

            debug!(
                path = %path.display(),
                count = ioc_file.indicators.len(),
                "Loading IoC file"
            );

            for ind in ioc_file.indicators {
                self.add_indicator(ind);
                total += 1;
            }
        }

        if total > 0 {
            self.rebuild_engine();
        }
        info!(total, "Loaded IoC indicators from directory");
        Ok(total)
    }

    /// Add a single indicator. Duplicates (same threat_id + same indicator)
    /// are replaced with the newer entry.
    pub fn add_indicator(&mut self, entry: IndicatorEntry) {
        // Remove any existing entry with the same threat_id and indicator variant
        self.indicators.retain(|existing| {
            !(existing.threat_id == entry.threat_id
                && indicator_variant_eq(&existing.indicator, &entry.indicator))
        });
        self.indicators.push(entry);
    }

    /// Add a single indicator and immediately rebuild the engine.
    pub fn add_indicator_and_rebuild(&mut self, entry: IndicatorEntry) {
        self.add_indicator(entry);
        self.rebuild_engine();
    }

    /// Remove expired indicators and rebuild the engine.
    pub fn expire_indicators(&mut self) -> usize {
        let now = Utc::now();
        let default_cutoff = now - Duration::days(self.expiration_days);
        let before = self.indicators.len();

        self.indicators.retain(|entry| {
            if entry.permanent {
                return true;
            }
            if let Some(expires_at) = entry.expires_at {
                if expires_at <= now {
                    debug!(threat_id = %entry.threat_id, "Expiring indicator (explicit expiry)");
                    return false;
                }
            }
            if entry.last_updated < default_cutoff {
                debug!(threat_id = %entry.threat_id, "Expiring indicator (age)");
                return false;
            }
            true
        });

        let removed = before - self.indicators.len();
        if removed > 0 {
            info!(
                removed,
                remaining = self.indicators.len(),
                "Expired IoC indicators"
            );
            self.rebuild_engine();
        }
        removed
    }

    /// Rebuild the matching engine from the current indicators.
    pub fn rebuild_engine(&mut self) {
        let engine = IoCEngine::build(self.indicators.clone());
        self.engine = Arc::new(engine);
        debug!(count = self.indicators.len(), "Rebuilt IoC matching engine");
    }

    /// Get a thread-safe reference to the current matching engine.
    pub fn engine(&self) -> Arc<IoCEngine> {
        Arc::clone(&self.engine)
    }

    /// Get statistics about the current database.
    pub fn stats(&self) -> DatabaseStats {
        let mut stats = DatabaseStats {
            total_entries: self.indicators.len(),
            ..Default::default()
        };

        let mut latest: Option<chrono::DateTime<chrono::Utc>> = None;

        for entry in &self.indicators {
            match &entry.indicator {
                Indicator::MaliciousIP(_) => stats.malicious_ips += 1,
                Indicator::MaliciousDomain(_) => stats.malicious_domains += 1,
                Indicator::MaliciousURL(_) => stats.malicious_urls += 1,
                Indicator::MaliciousFileHash(_) => stats.malicious_hashes += 1,
                Indicator::SuspiciousFilePath(_) => stats.suspicious_file_paths += 1,
                Indicator::SuspiciousProcessName(_) => stats.suspicious_process_names += 1,
                Indicator::SuspiciousCommandLine(_) => stats.suspicious_command_lines += 1,
                Indicator::SuspiciousToolSequence(_) => stats.suspicious_tool_sequences += 1,
                Indicator::SuspiciousArgPattern { .. } => stats.suspicious_arg_patterns += 1,
            }

            match latest {
                None => latest = Some(entry.last_updated),
                Some(l) if entry.last_updated > l => latest = Some(entry.last_updated),
                _ => {}
            }
        }

        stats.last_updated = latest;
        stats
    }

    /// Total number of indicators.
    pub fn len(&self) -> usize {
        self.indicators.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.indicators.is_empty()
    }

    /// Get all indicators (read-only).
    pub fn indicators(&self) -> &[IndicatorEntry] {
        &self.indicators
    }

    /// Remove all indicators matching a given threat_id.
    pub fn remove_by_threat_id(&mut self, threat_id: &str) -> usize {
        let before = self.indicators.len();
        self.indicators.retain(|e| e.threat_id != threat_id);
        let removed = before - self.indicators.len();
        if removed > 0 {
            self.rebuild_engine();
        }
        removed
    }
}

impl Default for IoCDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if two indicators are of the same variant with the same value.
fn indicator_variant_eq(a: &Indicator, b: &Indicator) -> bool {
    match (a, b) {
        (Indicator::MaliciousIP(x), Indicator::MaliciousIP(y)) => x == y,
        (Indicator::MaliciousDomain(x), Indicator::MaliciousDomain(y)) => x == y,
        (Indicator::MaliciousURL(x), Indicator::MaliciousURL(y)) => x == y,
        (Indicator::MaliciousFileHash(x), Indicator::MaliciousFileHash(y)) => x == y,
        (Indicator::SuspiciousFilePath(x), Indicator::SuspiciousFilePath(y)) => x == y,
        (Indicator::SuspiciousProcessName(x), Indicator::SuspiciousProcessName(y)) => x == y,
        (Indicator::SuspiciousCommandLine(x), Indicator::SuspiciousCommandLine(y)) => x == y,
        (Indicator::SuspiciousToolSequence(x), Indicator::SuspiciousToolSequence(y)) => x == y,
        (
            Indicator::SuspiciousArgPattern {
                tool: t1,
                pattern: p1,
            },
            Indicator::SuspiciousArgPattern {
                tool: t2,
                pattern: p2,
            },
        ) => t1 == t2 && p1 == p2,
        _ => false,
    }
}
