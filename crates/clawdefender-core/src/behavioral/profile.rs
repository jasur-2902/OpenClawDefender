//! Behavioral profile data structures.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Behavioral profile for a single MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerProfile {
    /// Name of the MCP server.
    pub server_name: String,
    /// Name of the client connected to this server.
    pub client_name: String,
    /// When this server was first observed.
    pub first_seen: DateTime<Utc>,
    /// When the profile was last updated.
    pub last_updated: DateTime<Utc>,
    /// Whether the profile is still in learning mode.
    pub learning_mode: bool,
    /// Total number of events observed.
    pub observation_count: u64,
    /// Tool usage profile.
    pub tool_profile: ToolProfile,
    /// File access profile.
    pub file_profile: FileProfile,
    /// Network access profile.
    pub network_profile: NetworkProfile,
    /// Temporal behavior profile.
    pub temporal_profile: TemporalProfile,
}

/// Tool usage behavioral profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolProfile {
    /// Frequency map of tool names to call counts.
    pub tool_counts: HashMap<String, u64>,
    /// Typical argument patterns per tool (tool_name -> set of observed arg keys).
    pub argument_patterns: HashMap<String, HashSet<String>>,
    /// Call rate in calls per minute (exponential moving average).
    pub call_rate: f64,
    /// Tool sequence bigrams: (tool_a, tool_b) -> count.
    pub sequence_bigrams: HashMap<(String, String), u64>,
    /// Last tool called (for building bigrams).
    #[serde(default)]
    pub last_tool: Option<String>,
}

/// File access behavioral profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProfile {
    /// Directory prefixes covering most file operations ("territory").
    pub directory_prefixes: HashSet<String>,
    /// File extension frequency map.
    pub extension_counts: HashMap<String, u64>,
    /// Number of read operations.
    pub read_count: u64,
    /// Number of write operations.
    pub write_count: u64,
    /// Peak file operations per minute (exponential moving average).
    pub peak_ops_rate: f64,
}

/// Network access behavioral profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProfile {
    /// Set of observed hostnames/IPs.
    pub observed_hosts: HashSet<String>,
    /// Set of typical ports.
    pub observed_ports: HashSet<u16>,
    /// Request frequency (requests per minute, EMA).
    pub request_rate: f64,
    /// Whether this server has ever made a network connection.
    pub has_networked: bool,
}

/// Temporal behavior profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalProfile {
    /// Typical session duration in seconds.
    pub typical_session_duration_secs: f64,
    /// Mean inter-request gap in milliseconds.
    pub inter_request_gap_mean_ms: f64,
    /// Standard deviation of inter-request gap.
    pub inter_request_gap_stddev_ms: f64,
    /// Typical burst size (consecutive rapid events).
    pub burst_size_mean: f64,
    /// Standard deviation of burst size.
    pub burst_size_stddev: f64,
    /// Timestamp of the last event (for computing gaps).
    #[serde(default)]
    pub last_event_time: Option<DateTime<Utc>>,
    /// Running count of gap observations for online stddev calculation.
    #[serde(default)]
    pub gap_count: u64,
    /// Running sum of gaps for mean calculation.
    #[serde(default)]
    pub gap_sum_ms: f64,
    /// Running sum of squared gaps for stddev calculation.
    #[serde(default)]
    pub gap_sum_sq_ms: f64,
}

impl ServerProfile {
    /// Create a new profile in learning mode.
    pub fn new(server_name: String, client_name: String) -> Self {
        let now = Utc::now();
        Self {
            server_name,
            client_name,
            first_seen: now,
            last_updated: now,
            learning_mode: true,
            observation_count: 0,
            tool_profile: ToolProfile::default(),
            file_profile: FileProfile::default(),
            network_profile: NetworkProfile::default(),
            temporal_profile: TemporalProfile::default(),
        }
    }
}

impl Default for ToolProfile {
    fn default() -> Self {
        Self {
            tool_counts: HashMap::new(),
            argument_patterns: HashMap::new(),
            call_rate: 0.0,
            sequence_bigrams: HashMap::new(),
            last_tool: None,
        }
    }
}

impl Default for FileProfile {
    fn default() -> Self {
        Self {
            directory_prefixes: HashSet::new(),
            extension_counts: HashMap::new(),
            read_count: 0,
            write_count: 0,
            peak_ops_rate: 0.0,
        }
    }
}

impl Default for NetworkProfile {
    fn default() -> Self {
        Self {
            observed_hosts: HashSet::new(),
            observed_ports: HashSet::new(),
            request_rate: 0.0,
            has_networked: false,
        }
    }
}

impl Default for TemporalProfile {
    fn default() -> Self {
        Self {
            typical_session_duration_secs: 0.0,
            inter_request_gap_mean_ms: 0.0,
            inter_request_gap_stddev_ms: 0.0,
            burst_size_mean: 0.0,
            burst_size_stddev: 0.0,
            last_event_time: None,
            gap_count: 0,
            gap_sum_ms: 0.0,
            gap_sum_sq_ms: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Memory caps — prevent unbounded growth of profile collections
// ---------------------------------------------------------------------------

/// Maximum directory prefixes (file paths) to keep per profile.
/// Keeps the most frequently accessed by retaining those whose extensions
/// appear most often. 100 is enough to capture the working set of any
/// reasonably-scoped MCP server.
const MAX_DIRECTORY_PREFIXES: usize = 100;
/// Maximum network hosts to keep per profile.
const MAX_NETWORK_HOSTS: usize = 50;
/// Maximum tools to keep per profile.
const MAX_TOOL_COUNTS: usize = 50;

impl ServerProfile {
    /// Enforce memory caps on unbounded collections within this profile.
    ///
    /// When a collection exceeds its cap, only the most frequently accessed
    /// entries are retained. Call this periodically (e.g., every N events)
    /// to bound memory usage per profile.
    pub fn enforce_memory_caps(&mut self) {
        // Cap tool_counts: keep top MAX_TOOL_COUNTS by call count.
        if self.tool_profile.tool_counts.len() > MAX_TOOL_COUNTS {
            let mut entries: Vec<(String, u64)> =
                self.tool_profile.tool_counts.drain().collect();
            entries.sort_by(|a, b| b.1.cmp(&a.1));
            entries.truncate(MAX_TOOL_COUNTS);
            self.tool_profile.tool_counts = entries.into_iter().collect();
        }

        // Cap directory_prefixes: keep top MAX_DIRECTORY_PREFIXES.
        // Since directory_prefixes is a HashSet without counts, we keep the
        // ones whose extensions appear in extension_counts (proxy for frequency).
        // If we still exceed the cap, drop the longest paths (least specific).
        if self.file_profile.directory_prefixes.len() > MAX_DIRECTORY_PREFIXES {
            let mut prefixes: Vec<String> =
                self.file_profile.directory_prefixes.drain().collect();
            // Prefer shorter paths (more general, higher-value for anomaly detection)
            prefixes.sort_by_key(|p| p.len());
            prefixes.truncate(MAX_DIRECTORY_PREFIXES);
            self.file_profile.directory_prefixes = prefixes.into_iter().collect();
        }

        // Cap observed_hosts: keep top MAX_NETWORK_HOSTS.
        // Since it's a HashSet without counts, keep shorter hostnames
        // (more likely to be significant domain names vs long CDN URLs).
        if self.network_profile.observed_hosts.len() > MAX_NETWORK_HOSTS {
            let mut hosts: Vec<String> =
                self.network_profile.observed_hosts.drain().collect();
            hosts.sort_by_key(|h| h.len());
            hosts.truncate(MAX_NETWORK_HOSTS);
            self.network_profile.observed_hosts = hosts.into_iter().collect();
        }

        // Cap argument_patterns: keep only for tools that remain after tool_counts cap.
        self.tool_profile
            .argument_patterns
            .retain(|tool, _| self.tool_profile.tool_counts.contains_key(tool));

        // Cap sequence_bigrams: keep only bigrams involving retained tools.
        self.tool_profile
            .sequence_bigrams
            .retain(|(a, b), _| {
                self.tool_profile.tool_counts.contains_key(a)
                    && self.tool_profile.tool_counts.contains_key(b)
            });
    }
}
