use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Main drift detection system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftDetector {
    pub baselines: HashMap<String, DriftBaseline>,
    pub policy_baseline: PolicyBaseline,
    pub config_baseline: ConfigBaseline,
    pub detection_interval: Duration,
    pub drift_reports: Vec<DriftReport>,
    pub baselines_path: PathBuf,
}

/// Behavioral baseline for a server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftBaseline {
    pub server_name: String,
    pub established_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,

    // Behavioral baseline
    pub avg_daily_events: f64,
    pub typical_tools: HashSet<String>,
    pub typical_file_paths: HashSet<String>,
    pub typical_network_hosts: HashSet<String>,
    pub typical_active_hours: (u8, u8),

    // Current state (rolling 7-day window)
    pub current_daily_events: f64,
    pub current_tools: HashSet<String>,
    pub current_file_paths: HashSet<String>,
    pub current_network_hosts: HashSet<String>,
    pub current_active_hours: (u8, u8),

    // Drift tracking
    pub consecutive_drift_days: u32,
}

/// Types of behavioral drift
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DriftType {
    ScopeCreep,
    ActivityVolume,
    ToolUsage,
    NetworkDrift,
    TemporalDrift,
}

/// A single dimension of drift
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftDimension {
    pub drift_type: DriftType,
    pub score: f64,
    pub description: String,
    pub details: DriftDetails,
}

/// Detailed drift information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftDetails {
    ScopeCreep {
        new_paths: Vec<String>,
        growth_percent: f64,
    },
    ActivityVolume {
        baseline_avg: f64,
        current_avg: f64,
        change_percent: f64,
    },
    ToolUsage {
        new_tools: Vec<String>,
    },
    NetworkDrift {
        new_hosts: Vec<String>,
    },
    TemporalDrift {
        unusual_hours: Vec<u8>,
        normal_range: (u8, u8),
    },
}

/// Policy baseline snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBaseline {
    pub established_at: DateTime<Utc>,
    pub rule_count: usize,
    pub enabled_rules: usize,
    pub default_action: String,
    pub rule_hashes: HashMap<String, String>,
}

impl Default for PolicyBaseline {
    fn default() -> Self {
        Self {
            established_at: Utc::now(),
            rule_count: 0,
            enabled_rules: 0,
            default_action: "allow".to_string(),
            rule_hashes: HashMap::new(),
        }
    }
}

/// Policy drift detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDrift {
    pub rules_added: Vec<String>,
    pub rules_removed: Vec<String>,
    pub rules_disabled: Vec<String>,
    pub default_action_changed: bool,
    pub coverage_before: f64,
    pub coverage_after: f64,
}

/// Configuration baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBaseline {
    pub established_at: DateTime<Utc>,
    pub known_servers: HashMap<String, ServerConfigSnapshot>,
}

impl Default for ConfigBaseline {
    fn default() -> Self {
        Self {
            established_at: Utc::now(),
            known_servers: HashMap::new(),
        }
    }
}

/// Server configuration snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigSnapshot {
    pub command: Vec<String>,
    pub args_hash: String,
    pub transport: String,
}

/// Configuration drift detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigDrift {
    pub new_servers: Vec<String>,
    pub removed_servers: Vec<String>,
    pub changed_servers: Vec<ConfigChange>,
}

/// A single configuration change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    pub server_name: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

/// Threat landscape drift (retroactive matches)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLandscapeDrift {
    pub retroactive_matches: Vec<RetroactiveMatch>,
}

/// A retroactive threat match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetroactiveMatch {
    pub indicator: String,
    pub indicator_type: String,
    pub matched_event_id: String,
    pub event_timestamp: DateTime<Utc>,
    pub added_to_feed_at: DateTime<Utc>,
    pub description: String,
}

/// Complete drift report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub id: Uuid,
    pub server_name: String,
    pub period: TimeRange,
    pub timestamp: DateTime<Utc>,
    pub overall_drift_score: f64,
    pub dimensions: Vec<DriftDimension>,
    pub narrative: String,
    pub recommended_action: DriftAction,
}

/// Time range for drift analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Recommended action based on drift score
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DriftAction {
    NoAction,
    Monitor,
    Investigate { reason: String },
    RestrictAccess { suggestion: String },
    Alert { severity: String },
}

/// Policy snapshot for comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub rules: Vec<PolicyRuleInfo>,
    pub default_action: String,
}

/// Policy rule information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleInfo {
    pub id: String,
    pub enabled: bool,
    pub hash: String,
}

/// Config snapshot for comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub servers: HashMap<String, ServerConfigSnapshot>,
}

/// Threat indicator for retroactive matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub value: String,
    pub indicator_type: String,
    pub added_at: DateTime<Utc>,
}

/// Historical event for retroactive matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub server_name: String,
    pub targets: Vec<String>,
}

/// State update for baseline tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateUpdate {
    pub events_today: u64,
    pub tools_used: HashSet<String>,
    pub file_paths_accessed: HashSet<String>,
    pub network_hosts: HashSet<String>,
    pub active_hours: Vec<u8>,
}

/// Baseline summary for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub server_name: String,
    pub established_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub tool_count: usize,
    pub path_count: usize,
    pub host_count: usize,
    pub current_drift_score: Option<f64>,
}

impl DriftDetector {
    /// Create a new drift detector
    pub fn new() -> Self {
        let baselines_path = dirs::home_dir()
            .expect("Failed to get home directory")
            .join(".local/share/rookbot/drift_baselines.json");

        Self {
            baselines: HashMap::new(),
            policy_baseline: PolicyBaseline::default(),
            config_baseline: ConfigBaseline::default(),
            detection_interval: Duration::try_hours(24).unwrap(),
            drift_reports: Vec::new(),
            baselines_path,
        }
    }

    // Baseline management

    /// Establish a new baseline for a server
    pub fn establish_baseline(&mut self, server_name: &str, baseline: DriftBaseline) {
        info!("Establishing baseline for server: {}", server_name);
        self.baselines.insert(server_name.to_string(), baseline);
    }

    /// Get baseline for a server
    pub fn get_baseline(&self, server_name: &str) -> Option<&DriftBaseline> {
        self.baselines.get(server_name)
    }

    /// Reset baseline for a server
    pub fn reset_baseline(&mut self, server_name: &str) {
        info!("Resetting baseline for server: {}", server_name);
        self.baselines.remove(server_name);
    }

    /// List all baselines
    pub fn list_baselines(&self) -> Vec<BaselineSummary> {
        self.baselines
            .iter()
            .map(|(name, baseline)| {
                let drift_score = self.check_server_drift(name).map(|r| r.overall_drift_score);
                BaselineSummary {
                    server_name: name.clone(),
                    established_at: baseline.established_at,
                    last_updated: baseline.last_updated,
                    tool_count: baseline.typical_tools.len(),
                    path_count: baseline.typical_file_paths.len(),
                    host_count: baseline.typical_network_hosts.len(),
                    current_drift_score: drift_score,
                }
            })
            .collect()
    }

    // Behavioral drift detection

    /// Check for scope creep (file path expansion)
    pub fn check_scope_creep(&self, server_name: &str) -> Option<DriftDimension> {
        let baseline = self.baselines.get(server_name)?;

        let new_paths: Vec<String> = baseline
            .current_file_paths
            .difference(&baseline.typical_file_paths)
            .cloned()
            .collect();

        if new_paths.is_empty() {
            return None;
        }

        let baseline_count = baseline.typical_file_paths.len().max(1) as f64;
        let growth_percent = (new_paths.len() as f64 / baseline_count) * 100.0;

        if growth_percent < 20.0 {
            return None;
        }

        let score = (new_paths.len() as f64 / baseline_count).min(1.0);

        Some(DriftDimension {
            drift_type: DriftType::ScopeCreep,
            score,
            description: format!(
                "File path set grew by {:.1}% ({} new paths)",
                growth_percent,
                new_paths.len()
            ),
            details: DriftDetails::ScopeCreep {
                new_paths,
                growth_percent,
            },
        })
    }

    /// Check for activity volume drift
    pub fn check_activity_volume(&self, server_name: &str) -> Option<DriftDimension> {
        let baseline = self.baselines.get(server_name)?;

        if baseline.avg_daily_events == 0.0 {
            return None;
        }

        let change = baseline.current_daily_events - baseline.avg_daily_events;
        if change <= 0.0 {
            return None;
        }

        let change_percent = (change / baseline.avg_daily_events) * 100.0;

        if change_percent < 50.0 {
            return None;
        }

        let score = (change / baseline.avg_daily_events).min(1.0);

        Some(DriftDimension {
            drift_type: DriftType::ActivityVolume,
            score,
            description: format!(
                "Daily events increased by {:.1}% (from {:.0} to {:.0})",
                change_percent, baseline.avg_daily_events, baseline.current_daily_events
            ),
            details: DriftDetails::ActivityVolume {
                baseline_avg: baseline.avg_daily_events,
                current_avg: baseline.current_daily_events,
                change_percent,
            },
        })
    }

    /// Check for new tool usage
    pub fn check_tool_usage(&self, server_name: &str) -> Option<DriftDimension> {
        let baseline = self.baselines.get(server_name)?;

        // If baseline is empty, no drift can be detected
        if baseline.typical_tools.is_empty() {
            return None;
        }

        let new_tools: Vec<String> = baseline
            .current_tools
            .difference(&baseline.typical_tools)
            .cloned()
            .collect();

        if new_tools.is_empty() {
            return None;
        }

        let score = (new_tools.len() as f64 * 0.3).min(1.0);

        Some(DriftDimension {
            drift_type: DriftType::ToolUsage,
            score,
            description: format!("{} new tools detected", new_tools.len()),
            details: DriftDetails::ToolUsage { new_tools },
        })
    }

    /// Check for network drift
    pub fn check_network_drift(&self, server_name: &str) -> Option<DriftDimension> {
        let baseline = self.baselines.get(server_name)?;

        let new_hosts: Vec<String> = baseline
            .current_network_hosts
            .difference(&baseline.typical_network_hosts)
            .cloned()
            .collect();

        if new_hosts.is_empty() {
            return None;
        }

        let score = (new_hosts.len() as f64 * 0.25).min(1.0);

        Some(DriftDimension {
            drift_type: DriftType::NetworkDrift,
            score,
            description: format!("{} new network destinations", new_hosts.len()),
            details: DriftDetails::NetworkDrift { new_hosts },
        })
    }

    /// Check for temporal drift (unusual hours)
    pub fn check_temporal_drift(&self, server_name: &str) -> Option<DriftDimension> {
        let baseline = self.baselines.get(server_name)?;

        let (normal_start, normal_end) = baseline.typical_active_hours;
        let (current_start, current_end) = baseline.current_active_hours;

        let mut unusual_hours = Vec::new();

        // Check if current activity is outside normal hours
        if current_start < normal_start {
            for h in current_start..normal_start {
                unusual_hours.push(h);
            }
        }
        if current_end > normal_end {
            for h in normal_end..current_end {
                unusual_hours.push(h);
            }
        }

        if unusual_hours.is_empty() {
            return None;
        }

        let score = (unusual_hours.len() as f64 * 0.2).min(1.0);

        Some(DriftDimension {
            drift_type: DriftType::TemporalDrift,
            score,
            description: format!(
                "Activity outside normal hours ({}-{}, now {}-{})",
                normal_start, normal_end, current_start, current_end
            ),
            details: DriftDetails::TemporalDrift {
                unusual_hours,
                normal_range: baseline.typical_active_hours,
            },
        })
    }

    /// Check all drift dimensions for a server
    pub fn check_server_drift(&self, server_name: &str) -> Option<DriftReport> {
        let baseline = self.baselines.get(server_name)?;

        let mut dimensions = Vec::new();

        if let Some(dim) = self.check_scope_creep(server_name) {
            dimensions.push(dim);
        }
        if let Some(dim) = self.check_activity_volume(server_name) {
            dimensions.push(dim);
        }
        if let Some(dim) = self.check_tool_usage(server_name) {
            dimensions.push(dim);
        }
        if let Some(dim) = self.check_network_drift(server_name) {
            dimensions.push(dim);
        }
        if let Some(dim) = self.check_temporal_drift(server_name) {
            dimensions.push(dim);
        }

        if dimensions.is_empty() {
            return None;
        }

        let overall_drift_score = Self::calculate_drift_score(&dimensions);
        let recommended_action = Self::determine_action(overall_drift_score, &dimensions);

        let narrative = Self::generate_narrative(server_name, &dimensions, overall_drift_score);

        Some(DriftReport {
            id: Uuid::new_v4(),
            server_name: server_name.to_string(),
            period: TimeRange {
                start: baseline.last_updated,
                end: Utc::now(),
            },
            timestamp: Utc::now(),
            overall_drift_score,
            dimensions,
            narrative,
            recommended_action,
        })
    }

    /// Check drift for all servers
    pub fn check_all_servers(&self) -> Vec<DriftReport> {
        self.baselines
            .keys()
            .filter_map(|name| self.check_server_drift(name))
            .collect()
    }

    // Policy drift

    /// Check for policy drift
    pub fn check_policy_drift(&self, current: &PolicySnapshot) -> Option<PolicyDrift> {
        let baseline = &self.policy_baseline;

        let baseline_rule_ids: HashSet<_> = baseline.rule_hashes.keys().cloned().collect();
        let current_rule_ids: HashSet<_> = current.rules.iter().map(|r| r.id.clone()).collect();

        let rules_added: Vec<String> = current_rule_ids
            .difference(&baseline_rule_ids)
            .cloned()
            .collect();

        let rules_removed: Vec<String> = baseline_rule_ids
            .difference(&current_rule_ids)
            .cloned()
            .collect();

        let mut rules_disabled = Vec::new();
        for rule in &current.rules {
            if baseline.rule_hashes.contains_key(&rule.id) && !rule.enabled {
                // Check if it was enabled before
                let baseline_rule = current.rules.iter().find(|r| r.id == rule.id);
                if let Some(br) = baseline_rule {
                    if br.enabled {
                        rules_disabled.push(rule.id.clone());
                    }
                }
            }
        }

        let default_action_changed = baseline.default_action != current.default_action;

        let coverage_before = if baseline.rule_count > 0 {
            baseline.enabled_rules as f64 / baseline.rule_count as f64
        } else {
            0.0
        };

        let enabled_count = current.rules.iter().filter(|r| r.enabled).count();
        let coverage_after = if !current.rules.is_empty() {
            enabled_count as f64 / current.rules.len() as f64
        } else {
            0.0
        };

        if rules_added.is_empty()
            && rules_removed.is_empty()
            && rules_disabled.is_empty()
            && !default_action_changed
        {
            return None;
        }

        Some(PolicyDrift {
            rules_added,
            rules_removed,
            rules_disabled,
            default_action_changed,
            coverage_before,
            coverage_after,
        })
    }

    /// Set policy baseline
    pub fn set_policy_baseline(&mut self, snapshot: PolicySnapshot) {
        let enabled_rules = snapshot.rules.iter().filter(|r| r.enabled).count();
        let rule_hashes = snapshot
            .rules
            .iter()
            .map(|r| (r.id.clone(), r.hash.clone()))
            .collect();

        self.policy_baseline = PolicyBaseline {
            established_at: Utc::now(),
            rule_count: snapshot.rules.len(),
            enabled_rules,
            default_action: snapshot.default_action,
            rule_hashes,
        };

        info!(
            "Policy baseline established with {} rules",
            snapshot.rules.len()
        );
    }

    // Config drift

    /// Check for config drift
    pub fn check_config_drift(&self, current: &ConfigSnapshot) -> Option<ConfigDrift> {
        let baseline = &self.config_baseline;

        let baseline_servers: HashSet<_> = baseline.known_servers.keys().cloned().collect();
        let current_servers: HashSet<_> = current.servers.keys().cloned().collect();

        let new_servers: Vec<String> = current_servers
            .difference(&baseline_servers)
            .cloned()
            .collect();

        let removed_servers: Vec<String> = baseline_servers
            .difference(&current_servers)
            .cloned()
            .collect();

        let mut changed_servers = Vec::new();

        for (name, current_config) in &current.servers {
            if let Some(baseline_config) = baseline.known_servers.get(name) {
                if current_config.args_hash != baseline_config.args_hash {
                    changed_servers.push(ConfigChange {
                        server_name: name.clone(),
                        field: "args_hash".to_string(),
                        old_value: baseline_config.args_hash.clone(),
                        new_value: current_config.args_hash.clone(),
                    });
                }
                if current_config.transport != baseline_config.transport {
                    changed_servers.push(ConfigChange {
                        server_name: name.clone(),
                        field: "transport".to_string(),
                        old_value: baseline_config.transport.clone(),
                        new_value: current_config.transport.clone(),
                    });
                }
            }
        }

        if new_servers.is_empty() && removed_servers.is_empty() && changed_servers.is_empty() {
            return None;
        }

        Some(ConfigDrift {
            new_servers,
            removed_servers,
            changed_servers,
        })
    }

    /// Set config baseline
    pub fn set_config_baseline(&mut self, snapshot: ConfigSnapshot) {
        self.config_baseline = ConfigBaseline {
            established_at: Utc::now(),
            known_servers: snapshot.servers,
        };

        info!(
            "Config baseline established with {} servers",
            self.config_baseline.known_servers.len()
        );
    }

    // Threat landscape

    /// Check for retroactive threat matches
    pub fn check_retroactive_threats(
        &self,
        new_indicators: &[ThreatIndicator],
        historical_events: &[HistoricalEvent],
    ) -> Vec<RetroactiveMatch> {
        let mut matches = Vec::new();

        for indicator in new_indicators {
            for event in historical_events {
                // Check if any event target matches the indicator
                for target in &event.targets {
                    if target == &indicator.value {
                        matches.push(RetroactiveMatch {
                            indicator: indicator.value.clone(),
                            indicator_type: indicator.indicator_type.clone(),
                            matched_event_id: event.id.clone(),
                            event_timestamp: event.timestamp,
                            added_to_feed_at: indicator.added_at,
                            description: format!(
                                "Historical event {} on {} matched newly added {} indicator {}",
                                event.id,
                                event.server_name,
                                indicator.indicator_type,
                                indicator.value
                            ),
                        });
                    }
                }
            }
        }

        if !matches.is_empty() {
            warn!("Found {} retroactive threat matches", matches.len());
        }

        matches
    }

    // Scoring

    /// Calculate overall drift score from dimensions
    fn calculate_drift_score(dimensions: &[DriftDimension]) -> f64 {
        if dimensions.is_empty() {
            return 0.0;
        }

        if dimensions.len() == 1 {
            return dimensions[0].score;
        }

        // Check if ALL dimensions are drifting (compound effect)
        let all_drift_types = [
            DriftType::ScopeCreep,
            DriftType::ActivityVolume,
            DriftType::ToolUsage,
            DriftType::NetworkDrift,
            DriftType::TemporalDrift,
        ];

        let detected_types: HashSet<_> = dimensions.iter().map(|d| &d.drift_type).collect();
        let all_drifting = all_drift_types.iter().all(|t| detected_types.contains(t));

        if all_drifting {
            // Compound effect: max * 1.3 capped at 1.0
            let max_score = dimensions.iter().map(|d| d.score).fold(0.0, f64::max);
            (max_score * 1.3).min(1.0)
        } else {
            // Average score
            let sum: f64 = dimensions.iter().map(|d| d.score).sum();
            sum / dimensions.len() as f64
        }
    }

    /// Determine recommended action based on drift score
    fn determine_action(score: f64, dimensions: &[DriftDimension]) -> DriftAction {
        if score < 0.2 {
            DriftAction::NoAction
        } else if score < 0.4 {
            DriftAction::Monitor
        } else if score < 0.6 {
            let reason = dimensions
                .iter()
                .map(|d| d.description.clone())
                .collect::<Vec<_>>()
                .join("; ");
            DriftAction::Investigate { reason }
        } else if score < 0.8 {
            let suggestion = format!(
                "Consider restricting access due to: {}",
                dimensions
                    .iter()
                    .map(|d| d.description.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            DriftAction::RestrictAccess { suggestion }
        } else {
            let severity = if score > 0.9 {
                "Critical".to_string()
            } else {
                "High".to_string()
            };
            DriftAction::Alert { severity }
        }
    }

    /// Generate narrative for drift report
    fn generate_narrative(server_name: &str, dimensions: &[DriftDimension], score: f64) -> String {
        let mut narrative = format!(
            "Server '{}' exhibits drift score of {:.2}. ",
            server_name, score
        );

        for dim in dimensions {
            narrative.push_str(&format!("{}. ", dim.description));
        }

        narrative
    }

    // State updates

    /// Update current state for a server
    pub fn update_current_state(&mut self, server_name: &str, update: StateUpdate) {
        if let Some(baseline) = self.baselines.get_mut(server_name) {
            baseline.current_daily_events = update.events_today as f64;
            baseline.current_tools = update.tools_used;
            baseline.current_file_paths = update.file_paths_accessed;
            baseline.current_network_hosts = update.network_hosts;

            if !update.active_hours.is_empty() {
                let min_hour = *update.active_hours.iter().min().unwrap_or(&0);
                let max_hour = *update.active_hours.iter().max().unwrap_or(&23);
                baseline.current_active_hours = (min_hour, max_hour);
            }

            baseline.last_updated = Utc::now();

            debug!("Updated state for server: {}", server_name);
        }
    }

    // Auto-sliding baselines

    /// Slide baselines that have been stable for 30+ days
    pub fn slide_baselines(&mut self) {
        let mut to_slide = Vec::new();

        for (name, baseline) in &self.baselines {
            if baseline.consecutive_drift_days > 30 {
                // Check if drift score is low enough to accept
                if let Some(report) = self.check_server_drift(name) {
                    if report.overall_drift_score < 0.4 {
                        to_slide.push(name.clone());
                    }
                }
            }
        }

        for name in to_slide {
            if let Some(baseline) = self.baselines.get_mut(&name) {
                // Accept new behavior as normal
                baseline.typical_tools = baseline.current_tools.clone();
                baseline.typical_file_paths = baseline.current_file_paths.clone();
                baseline.typical_network_hosts = baseline.current_network_hosts.clone();
                baseline.typical_active_hours = baseline.current_active_hours;
                baseline.avg_daily_events = baseline.current_daily_events;
                baseline.consecutive_drift_days = 0;
                baseline.last_updated = Utc::now();

                info!(
                    "Baseline auto-updated for server {} after 30 days of stable drift",
                    name
                );
            }
        }
    }

    // Persistence

    /// Save baselines to disk
    pub fn save_baselines(&self) -> Result<()> {
        if let Some(parent) = self.baselines_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(&self)?;
        std::fs::write(&self.baselines_path, json)?;

        info!("Saved baselines to {:?}", self.baselines_path);
        Ok(())
    }

    /// Load baselines from disk
    pub fn load_baselines(&mut self) -> Result<()> {
        if !self.baselines_path.exists() {
            debug!("No baseline file found at {:?}", self.baselines_path);
            return Ok(());
        }

        let json = std::fs::read_to_string(&self.baselines_path)?;
        let loaded: DriftDetector = serde_json::from_str(&json)?;

        self.baselines = loaded.baselines;
        self.policy_baseline = loaded.policy_baseline;
        self.config_baseline = loaded.config_baseline;
        self.drift_reports = loaded.drift_reports;

        info!("Loaded {} baselines from disk", self.baselines.len());
        Ok(())
    }

    // Reports

    /// Get recent drift reports
    pub fn get_recent_reports(&self, count: usize) -> Vec<&DriftReport> {
        let mut reports: Vec<_> = self.drift_reports.iter().collect();
        reports.sort_by_key(|x| Reverse(x.timestamp));
        reports.into_iter().take(count).collect()
    }

    /// Get drift history for a specific server
    pub fn get_server_drift_history(&self, server_name: &str) -> Vec<&DriftReport> {
        let mut reports: Vec<_> = self
            .drift_reports
            .iter()
            .filter(|r| r.server_name == server_name)
            .collect();
        reports.sort_by_key(|x| Reverse(x.timestamp));
        reports
    }
}

impl Default for DriftDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_baseline(server_name: &str) -> DriftBaseline {
        let mut typical_tools = HashSet::new();
        typical_tools.insert("bash".to_string());
        typical_tools.insert("git".to_string());

        let mut typical_paths = HashSet::new();
        typical_paths.insert("/home/user/project".to_string());
        typical_paths.insert("/tmp".to_string());

        let mut typical_hosts = HashSet::new();
        typical_hosts.insert("api.example.com".to_string());

        DriftBaseline {
            server_name: server_name.to_string(),
            established_at: Utc::now(),
            last_updated: Utc::now(),
            avg_daily_events: 100.0,
            typical_tools: typical_tools.clone(),
            typical_file_paths: typical_paths.clone(),
            typical_network_hosts: typical_hosts.clone(),
            typical_active_hours: (9, 17),
            current_daily_events: 100.0,
            current_tools: typical_tools,
            current_file_paths: typical_paths,
            current_network_hosts: typical_hosts,
            current_active_hours: (9, 17),
            consecutive_drift_days: 0,
        }
    }

    #[test]
    fn test_new_drift_detector() {
        let detector = DriftDetector::new();
        assert!(detector.baselines.is_empty());
        assert_eq!(detector.drift_reports.len(), 0);
    }

    #[test]
    fn test_establish_baseline() {
        let mut detector = DriftDetector::new();
        let baseline = create_test_baseline("test-server");

        detector.establish_baseline("test-server", baseline);
        assert!(detector.baselines.contains_key("test-server"));
    }

    #[test]
    fn test_get_baseline() {
        let mut detector = DriftDetector::new();
        let baseline = create_test_baseline("test-server");

        detector.establish_baseline("test-server", baseline);
        let retrieved = detector.get_baseline("test-server");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().server_name, "test-server");
    }

    #[test]
    fn test_reset_baseline() {
        let mut detector = DriftDetector::new();
        let baseline = create_test_baseline("test-server");

        detector.establish_baseline("test-server", baseline);
        detector.reset_baseline("test-server");
        assert!(!detector.baselines.contains_key("test-server"));
    }

    #[test]
    fn test_list_baselines() {
        let mut detector = DriftDetector::new();
        detector.establish_baseline("server1", create_test_baseline("server1"));
        detector.establish_baseline("server2", create_test_baseline("server2"));

        let summaries = detector.list_baselines();
        assert_eq!(summaries.len(), 2);
    }

    #[test]
    fn test_scope_creep_detection() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        // Add 25% more paths to trigger scope creep
        baseline
            .current_file_paths
            .insert("/new/path/1".to_string());

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_scope_creep("test-server");

        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.drift_type, DriftType::ScopeCreep);
        assert!(drift.score > 0.0);
    }

    #[test]
    fn test_scope_creep_no_detection_below_threshold() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        // Add only 10% more paths (below 20% threshold)
        baseline.typical_file_paths.clear();
        for i in 0..10 {
            baseline.typical_file_paths.insert(format!("/path/{}", i));
        }
        baseline.current_file_paths = baseline.typical_file_paths.clone();
        baseline.current_file_paths.insert("/new/path".to_string());

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_scope_creep("test-server");

        assert!(drift.is_none());
    }

    #[test]
    fn test_activity_volume_detection() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        // Increase activity by 60%
        baseline.current_daily_events = 160.0;

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_activity_volume("test-server");

        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.drift_type, DriftType::ActivityVolume);
        assert!(drift.score > 0.0);
    }

    #[test]
    fn test_activity_volume_no_detection_below_threshold() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        // Increase by only 30% (below 50% threshold)
        baseline.current_daily_events = 130.0;

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_activity_volume("test-server");

        assert!(drift.is_none());
    }

    #[test]
    fn test_tool_usage_detection() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        baseline.current_tools.insert("python".to_string());
        baseline.current_tools.insert("node".to_string());

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_tool_usage("test-server");

        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.drift_type, DriftType::ToolUsage);
    }

    #[test]
    fn test_tool_usage_no_new_tools() {
        let mut detector = DriftDetector::new();
        let baseline = create_test_baseline("test-server");

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_tool_usage("test-server");

        assert!(drift.is_none());
    }

    #[test]
    fn test_network_drift_detection() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        baseline
            .current_network_hosts
            .insert("malicious.com".to_string());

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_network_drift("test-server");

        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.drift_type, DriftType::NetworkDrift);
    }

    #[test]
    fn test_temporal_drift_detection() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        // Activity now extends into unusual hours
        baseline.current_active_hours = (6, 20);

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_temporal_drift("test-server");

        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.drift_type, DriftType::TemporalDrift);
    }

    #[test]
    fn test_temporal_drift_no_detection() {
        let mut detector = DriftDetector::new();
        let baseline = create_test_baseline("test-server");

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_temporal_drift("test-server");

        assert!(drift.is_none());
    }

    #[test]
    fn test_calculate_drift_score_single_dimension() {
        let dimensions = vec![DriftDimension {
            drift_type: DriftType::ScopeCreep,
            score: 0.5,
            description: "Test".to_string(),
            details: DriftDetails::ScopeCreep {
                new_paths: vec![],
                growth_percent: 50.0,
            },
        }];

        let score = DriftDetector::calculate_drift_score(&dimensions);
        assert_eq!(score, 0.5);
    }

    #[test]
    fn test_calculate_drift_score_average() {
        let dimensions = vec![
            DriftDimension {
                drift_type: DriftType::ScopeCreep,
                score: 0.5,
                description: "Test".to_string(),
                details: DriftDetails::ScopeCreep {
                    new_paths: vec![],
                    growth_percent: 50.0,
                },
            },
            DriftDimension {
                drift_type: DriftType::ToolUsage,
                score: 0.3,
                description: "Test".to_string(),
                details: DriftDetails::ToolUsage { new_tools: vec![] },
            },
        ];

        let score = DriftDetector::calculate_drift_score(&dimensions);
        assert_eq!(score, 0.4);
    }

    #[test]
    fn test_calculate_drift_score_compound_effect() {
        let dimensions = vec![
            DriftDimension {
                drift_type: DriftType::ScopeCreep,
                score: 0.6,
                description: "Test".to_string(),
                details: DriftDetails::ScopeCreep {
                    new_paths: vec![],
                    growth_percent: 60.0,
                },
            },
            DriftDimension {
                drift_type: DriftType::ActivityVolume,
                score: 0.5,
                description: "Test".to_string(),
                details: DriftDetails::ActivityVolume {
                    baseline_avg: 100.0,
                    current_avg: 150.0,
                    change_percent: 50.0,
                },
            },
            DriftDimension {
                drift_type: DriftType::ToolUsage,
                score: 0.4,
                description: "Test".to_string(),
                details: DriftDetails::ToolUsage { new_tools: vec![] },
            },
            DriftDimension {
                drift_type: DriftType::NetworkDrift,
                score: 0.3,
                description: "Test".to_string(),
                details: DriftDetails::NetworkDrift { new_hosts: vec![] },
            },
            DriftDimension {
                drift_type: DriftType::TemporalDrift,
                score: 0.2,
                description: "Test".to_string(),
                details: DriftDetails::TemporalDrift {
                    unusual_hours: vec![],
                    normal_range: (9, 17),
                },
            },
        ];

        let score = DriftDetector::calculate_drift_score(&dimensions);
        // Max score 0.6 * 1.3 = 0.78
        assert!(score > 0.7 && score < 0.8);
    }

    #[test]
    fn test_determine_action_no_action() {
        let dims = vec![];
        let action = DriftDetector::determine_action(0.1, &dims);
        assert_eq!(action, DriftAction::NoAction);
    }

    #[test]
    fn test_determine_action_monitor() {
        let dims = vec![];
        let action = DriftDetector::determine_action(0.3, &dims);
        assert_eq!(action, DriftAction::Monitor);
    }

    #[test]
    fn test_determine_action_investigate() {
        let dims = vec![DriftDimension {
            drift_type: DriftType::ScopeCreep,
            score: 0.5,
            description: "Test drift".to_string(),
            details: DriftDetails::ScopeCreep {
                new_paths: vec![],
                growth_percent: 50.0,
            },
        }];
        let action = DriftDetector::determine_action(0.5, &dims);
        match action {
            DriftAction::Investigate { .. } => {}
            _ => panic!("Expected Investigate action"),
        }
    }

    #[test]
    fn test_determine_action_restrict_access() {
        let dims = vec![DriftDimension {
            drift_type: DriftType::ScopeCreep,
            score: 0.7,
            description: "High drift".to_string(),
            details: DriftDetails::ScopeCreep {
                new_paths: vec![],
                growth_percent: 70.0,
            },
        }];
        let action = DriftDetector::determine_action(0.7, &dims);
        match action {
            DriftAction::RestrictAccess { .. } => {}
            _ => panic!("Expected RestrictAccess action"),
        }
    }

    #[test]
    fn test_determine_action_alert_high() {
        let dims = vec![];
        let action = DriftDetector::determine_action(0.85, &dims);
        match action {
            DriftAction::Alert { severity } => assert_eq!(severity, "High"),
            _ => panic!("Expected Alert action"),
        }
    }

    #[test]
    fn test_determine_action_alert_critical() {
        let dims = vec![];
        let action = DriftDetector::determine_action(0.95, &dims);
        match action {
            DriftAction::Alert { severity } => assert_eq!(severity, "Critical"),
            _ => panic!("Expected Alert action"),
        }
    }

    #[test]
    fn test_check_server_drift_no_drift() {
        let mut detector = DriftDetector::new();
        let baseline = create_test_baseline("test-server");

        detector.establish_baseline("test-server", baseline);
        let report = detector.check_server_drift("test-server");

        assert!(report.is_none());
    }

    #[test]
    fn test_check_server_drift_with_drift() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        baseline.current_daily_events = 160.0;
        baseline.current_tools.insert("python".to_string());

        detector.establish_baseline("test-server", baseline);
        let report = detector.check_server_drift("test-server");

        assert!(report.is_some());
        let report = report.unwrap();
        assert!(report.overall_drift_score > 0.0);
        assert!(!report.dimensions.is_empty());
    }

    #[test]
    fn test_check_all_servers() {
        let mut detector = DriftDetector::new();
        let mut baseline1 = create_test_baseline("server1");
        baseline1.current_daily_events = 160.0;

        let mut baseline2 = create_test_baseline("server2");
        baseline2.current_tools.insert("python".to_string());

        detector.establish_baseline("server1", baseline1);
        detector.establish_baseline("server2", baseline2);

        let reports = detector.check_all_servers();
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_policy_drift_detection() {
        let mut detector = DriftDetector::new();

        let baseline = PolicySnapshot {
            rules: vec![
                PolicyRuleInfo {
                    id: "rule1".to_string(),
                    enabled: true,
                    hash: "hash1".to_string(),
                },
                PolicyRuleInfo {
                    id: "rule2".to_string(),
                    enabled: true,
                    hash: "hash2".to_string(),
                },
            ],
            default_action: "allow".to_string(),
        };

        detector.set_policy_baseline(baseline);

        let current = PolicySnapshot {
            rules: vec![
                PolicyRuleInfo {
                    id: "rule1".to_string(),
                    enabled: true,
                    hash: "hash1".to_string(),
                },
                PolicyRuleInfo {
                    id: "rule3".to_string(),
                    enabled: true,
                    hash: "hash3".to_string(),
                },
            ],
            default_action: "deny".to_string(),
        };

        let drift = detector.check_policy_drift(&current);
        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.rules_added.len(), 1);
        assert_eq!(drift.rules_removed.len(), 1);
        assert!(drift.default_action_changed);
    }

    #[test]
    fn test_policy_drift_no_changes() {
        let mut detector = DriftDetector::new();

        let baseline = PolicySnapshot {
            rules: vec![PolicyRuleInfo {
                id: "rule1".to_string(),
                enabled: true,
                hash: "hash1".to_string(),
            }],
            default_action: "allow".to_string(),
        };

        detector.set_policy_baseline(baseline.clone());
        let drift = detector.check_policy_drift(&baseline);
        assert!(drift.is_none());
    }

    #[test]
    fn test_config_drift_detection() {
        let mut detector = DriftDetector::new();

        let mut baseline_servers = HashMap::new();
        baseline_servers.insert(
            "server1".to_string(),
            ServerConfigSnapshot {
                command: vec!["bash".to_string()],
                args_hash: "hash1".to_string(),
                transport: "stdio".to_string(),
            },
        );

        detector.set_config_baseline(ConfigSnapshot {
            servers: baseline_servers,
        });

        let mut current_servers = HashMap::new();
        current_servers.insert(
            "server1".to_string(),
            ServerConfigSnapshot {
                command: vec!["bash".to_string()],
                args_hash: "hash2".to_string(),
                transport: "stdio".to_string(),
            },
        );
        current_servers.insert(
            "server2".to_string(),
            ServerConfigSnapshot {
                command: vec!["python".to_string()],
                args_hash: "hash3".to_string(),
                transport: "http".to_string(),
            },
        );

        let drift = detector.check_config_drift(&ConfigSnapshot {
            servers: current_servers,
        });

        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.new_servers.len(), 1);
        assert_eq!(drift.changed_servers.len(), 1);
    }

    #[test]
    fn test_config_drift_no_changes() {
        let mut detector = DriftDetector::new();

        let mut servers = HashMap::new();
        servers.insert(
            "server1".to_string(),
            ServerConfigSnapshot {
                command: vec!["bash".to_string()],
                args_hash: "hash1".to_string(),
                transport: "stdio".to_string(),
            },
        );

        let snapshot = ConfigSnapshot {
            servers: servers.clone(),
        };

        detector.set_config_baseline(snapshot.clone());
        let drift = detector.check_config_drift(&snapshot);
        assert!(drift.is_none());
    }

    #[test]
    fn test_retroactive_threat_matching() {
        let detector = DriftDetector::new();

        let indicators = vec![ThreatIndicator {
            value: "malicious.com".to_string(),
            indicator_type: "domain".to_string(),
            added_at: Utc::now(),
        }];

        let events = vec![HistoricalEvent {
            id: "event1".to_string(),
            timestamp: Utc::now() - Duration::try_days(7).unwrap(),
            server_name: "test-server".to_string(),
            targets: vec!["malicious.com".to_string()],
        }];

        let matches = detector.check_retroactive_threats(&indicators, &events);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].indicator, "malicious.com");
    }

    #[test]
    fn test_retroactive_threat_no_match() {
        let detector = DriftDetector::new();

        let indicators = vec![ThreatIndicator {
            value: "malicious.com".to_string(),
            indicator_type: "domain".to_string(),
            added_at: Utc::now(),
        }];

        let events = vec![HistoricalEvent {
            id: "event1".to_string(),
            timestamp: Utc::now() - Duration::try_days(7).unwrap(),
            server_name: "test-server".to_string(),
            targets: vec!["legitimate.com".to_string()],
        }];

        let matches = detector.check_retroactive_threats(&indicators, &events);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_update_current_state() {
        let mut detector = DriftDetector::new();
        let baseline = create_test_baseline("test-server");

        detector.establish_baseline("test-server", baseline);

        let mut new_tools = HashSet::new();
        new_tools.insert("python".to_string());

        let update = StateUpdate {
            events_today: 150,
            tools_used: new_tools.clone(),
            file_paths_accessed: HashSet::new(),
            network_hosts: HashSet::new(),
            active_hours: vec![9, 10, 11, 12],
        };

        detector.update_current_state("test-server", update);

        let baseline = detector.get_baseline("test-server").unwrap();
        assert_eq!(baseline.current_daily_events, 150.0);
        assert!(baseline.current_tools.contains("python"));
    }

    #[test]
    fn test_slide_baselines() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        baseline.consecutive_drift_days = 35;
        baseline.current_tools.insert("python".to_string());

        detector.establish_baseline("test-server", baseline);
        detector.slide_baselines();

        let baseline = detector.get_baseline("test-server").unwrap();
        assert_eq!(baseline.consecutive_drift_days, 0);
        assert!(baseline.typical_tools.contains("python"));
    }

    #[test]
    fn test_slide_baselines_high_drift_no_slide() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        baseline.consecutive_drift_days = 35;
        baseline.current_daily_events = 500.0; // High drift

        detector.establish_baseline("test-server", baseline);
        detector.slide_baselines();

        let baseline = detector.get_baseline("test-server").unwrap();
        assert_eq!(baseline.consecutive_drift_days, 35); // Not reset
    }

    #[test]
    fn test_get_recent_reports() {
        let mut detector = DriftDetector::new();

        for i in 0..5 {
            detector.drift_reports.push(DriftReport {
                id: Uuid::new_v4(),
                server_name: format!("server{}", i),
                period: TimeRange {
                    start: Utc::now(),
                    end: Utc::now(),
                },
                timestamp: Utc::now(),
                overall_drift_score: 0.5,
                dimensions: vec![],
                narrative: "Test".to_string(),
                recommended_action: DriftAction::Monitor,
            });
        }

        let recent = detector.get_recent_reports(3);
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn test_get_server_drift_history() {
        let mut detector = DriftDetector::new();

        for i in 0..5 {
            detector.drift_reports.push(DriftReport {
                id: Uuid::new_v4(),
                server_name: if i % 2 == 0 {
                    "server1".to_string()
                } else {
                    "server2".to_string()
                },
                period: TimeRange {
                    start: Utc::now(),
                    end: Utc::now(),
                },
                timestamp: Utc::now(),
                overall_drift_score: 0.5,
                dimensions: vec![],
                narrative: "Test".to_string(),
                recommended_action: DriftAction::Monitor,
            });
        }

        let history = detector.get_server_drift_history("server1");
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn test_empty_baseline_no_drift() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        baseline.typical_tools.clear();
        baseline.typical_file_paths.clear();
        baseline.typical_network_hosts.clear();

        detector.establish_baseline("test-server", baseline);

        let drift = detector.check_tool_usage("test-server");
        assert!(drift.is_none());
    }

    #[test]
    fn test_scope_creep_calculation() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        // Clear and set known baseline
        baseline.typical_file_paths.clear();
        baseline.typical_file_paths.insert("/path1".to_string());
        baseline.typical_file_paths.insert("/path2".to_string());

        baseline.current_file_paths = baseline.typical_file_paths.clone();
        baseline.current_file_paths.insert("/path3".to_string()); // 50% growth

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_scope_creep("test-server");

        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.score, 0.5);
    }

    #[test]
    fn test_activity_volume_calculation() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        baseline.avg_daily_events = 100.0;
        baseline.current_daily_events = 200.0; // 100% increase

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_activity_volume("test-server");

        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.score, 1.0); // Capped at 1.0
    }

    #[test]
    fn test_tool_usage_score_calculation() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        // Add 4 new tools: 4 * 0.3 = 1.2, capped at 1.0
        baseline.current_tools.insert("python".to_string());
        baseline.current_tools.insert("node".to_string());
        baseline.current_tools.insert("ruby".to_string());
        baseline.current_tools.insert("go".to_string());

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_tool_usage("test-server");

        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.score, 1.0); // Capped at 1.0
    }

    #[test]
    fn test_network_drift_score_calculation() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        // Add 3 new hosts: 3 * 0.25 = 0.75
        baseline
            .current_network_hosts
            .insert("host1.com".to_string());
        baseline
            .current_network_hosts
            .insert("host2.com".to_string());
        baseline
            .current_network_hosts
            .insert("host3.com".to_string());

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_network_drift("test-server");

        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert_eq!(drift.score, 0.75);
    }

    #[test]
    fn test_temporal_drift_score_calculation() {
        let mut detector = DriftDetector::new();
        let mut baseline = create_test_baseline("test-server");

        baseline.typical_active_hours = (9, 17);
        baseline.current_active_hours = (6, 20); // 3 hours early + 3 hours late = 6 unusual hours

        detector.establish_baseline("test-server", baseline);
        let drift = detector.check_temporal_drift("test-server");

        assert!(drift.is_some());
        let drift = drift.unwrap();
        // 6 unusual hours * 0.2 = 1.2, capped at 1.0
        assert_eq!(drift.score, 1.0);
    }
}
