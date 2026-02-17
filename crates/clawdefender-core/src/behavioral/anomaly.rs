//! Anomaly detection engine for ClawDefender.
//!
//! Scores behavioral events against established server profiles to detect
//! anomalous activity. Each event is scored across multiple dimensions
//! (unknown tools, paths, network, rate, sequence, arguments, sensitivity,
//! first network access, privilege escalation) and combined into a single
//! normalized anomaly score with human-readable explanations.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::profile::ServerProfile;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Composite anomaly score for a single behavioral event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    /// Overall anomaly score in \[0.0, 1.0\].
    pub total: f64,
    /// Per-dimension breakdown.
    pub components: Vec<AnomalyComponent>,
    /// Human-readable explanation.
    pub explanation: String,
}

/// A single dimension's contribution to the anomaly score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyComponent {
    pub dimension: AnomalyDimension,
    pub score: f64,
    pub weight: f64,
    pub explanation: String,
}

/// The dimensions along which anomalies are measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyDimension {
    UnknownTool,
    UnknownPath,
    UnknownNetwork,
    AbnormalRate,
    AbnormalSequence,
    AbnormalArguments,
    SensitiveTarget,
    FirstNetworkAccess,
    PrivilegeEscalation,
}

/// A simplified behavioral event for scoring purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEvent {
    pub event_type: BehavioralEventType,
    pub server_name: String,
    pub timestamp: DateTime<Utc>,
}

/// The kind of behavioral event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehavioralEventType {
    ToolCall {
        tool_name: String,
        arguments: HashMap<String, String>,
    },
    FileAccess {
        path: String,
        is_write: bool,
    },
    NetworkConnect {
        host: String,
        port: u16,
    },
}

// ---------------------------------------------------------------------------
// Scorer
// ---------------------------------------------------------------------------

/// Default sensitive paths that warrant elevated scores.
const DEFAULT_SENSITIVE_PATHS: &[&str] = &[
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/.kube/",
    "/.config/gcloud/",
    "/.azure/",
    "/Library/Keychains/",
    "/.password-store/",
    "/Cookies/",
    "/Login Data",
    "/Keychain-",
    "/.docker/config.json",
    "/credentials",
    "/.netrc",
    "/id_rsa",
    "/id_ed25519",
];

/// Scores behavioral events against a server profile.
pub struct AnomalyScorer {
    sensitive_paths: Vec<String>,
}

impl Default for AnomalyScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyScorer {
    pub fn new() -> Self {
        Self {
            sensitive_paths: DEFAULT_SENSITIVE_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    pub fn with_sensitive_paths(mut self, paths: Vec<String>) -> Self {
        self.sensitive_paths = paths;
        self
    }

    /// Score an event against the profile. Returns `None` if the profile is
    /// still in learning mode.
    pub fn score(
        &self,
        event: &BehavioralEvent,
        profile: &ServerProfile,
    ) -> Option<AnomalyScore> {
        if profile.learning_mode {
            return None;
        }

        let mut components = Vec::new();

        match &event.event_type {
            BehavioralEventType::ToolCall {
                tool_name,
                arguments,
            } => {
                components.push(self.score_unknown_tool(tool_name, profile));
                components.push(self.score_abnormal_sequence(tool_name, profile));
                components.push(self.score_abnormal_arguments(tool_name, arguments, profile));
            }
            BehavioralEventType::FileAccess { path, .. } => {
                components.push(self.score_unknown_path(path, profile));
                if self.is_sensitive_path(path) {
                    components.push(self.score_sensitive_target(path, profile));
                }
            }
            BehavioralEventType::NetworkConnect { host, port } => {
                components.push(self.score_unknown_network(host, *port, profile));
                if !profile.network_profile.has_networked {
                    components.push(self.score_first_network_access(profile));
                }
            }
        }

        // Rate scoring applies to all event types.
        components.push(self.score_abnormal_rate(event, profile));

        let total = Self::compute_total(&components);
        let explanation = Self::build_explanation(&components, total, event, profile);

        Some(AnomalyScore {
            total,
            components,
            explanation,
        })
    }

    // -----------------------------------------------------------------------
    // Dimension scorers
    // -----------------------------------------------------------------------

    fn score_unknown_tool(&self, tool_name: &str, profile: &ServerProfile) -> AnomalyComponent {
        let count = profile
            .tool_profile
            .tool_counts
            .get(tool_name)
            .copied()
            .unwrap_or(0);

        let score = if count == 0 {
            1.0
        } else if count < 5 {
            0.5
        } else {
            0.0
        };

        AnomalyComponent {
            dimension: AnomalyDimension::UnknownTool,
            score,
            weight: 0.3,
            explanation: if count == 0 {
                format!("Tool '{}' has never been seen before", tool_name)
            } else if count < 5 {
                format!(
                    "Tool '{}' rarely used (seen {} time{})",
                    tool_name,
                    count,
                    if count == 1 { "" } else { "s" }
                )
            } else {
                format!("Tool '{}' is well-established ({} calls)", tool_name, count)
            },
        }
    }

    fn score_unknown_path(&self, path: &str, profile: &ServerProfile) -> AnomalyComponent {
        let prefixes = &profile.file_profile.directory_prefixes;

        if prefixes.is_empty() {
            // No file territory established yet — moderate score.
            return AnomalyComponent {
                dimension: AnomalyDimension::UnknownPath,
                score: 0.3,
                weight: 0.4,
                explanation: format!(
                    "No file territory established; path '{}' cannot be evaluated",
                    path
                ),
            };
        }

        // Check if path is within known territory.
        let within_territory = prefixes.iter().any(|p| path.starts_with(p.as_str()));
        if within_territory {
            return AnomalyComponent {
                dimension: AnomalyDimension::UnknownPath,
                score: 0.0,
                weight: 0.4,
                explanation: format!("Path '{}' is within known territory", path),
            };
        }

        // Check if it is a sibling of territory (shares a grandparent directory).
        // E.g. profile knows /home/user/Projects/, path is /home/user/Downloads/file.txt
        // → prefix parent is /home/user, path dir parent is /home/user → sibling.
        let path_dir = parent_dir(path); // directory containing the file
        let path_grandparent = parent_dir(path_dir); // parent of that directory
        let is_sibling = prefixes.iter().any(|p| {
            let p_parent = parent_dir(p);
            !p_parent.is_empty() && !path_grandparent.is_empty() && p_parent == path_grandparent
        });

        let is_sensitive = self.is_sensitive_path(path);

        let score = if is_sensitive {
            1.0
        } else if is_sibling {
            0.3
        } else {
            0.7
        };

        let territory_list: Vec<&String> = prefixes.iter().take(3).collect();
        AnomalyComponent {
            dimension: AnomalyDimension::UnknownPath,
            score,
            weight: 0.4,
            explanation: format!(
                "Path '{}' is outside known territory ({:?}){}",
                path,
                territory_list,
                if is_sensitive {
                    " — CRITICAL: sensitive path"
                } else if is_sibling {
                    " — sibling of known territory"
                } else {
                    " — completely unrelated"
                }
            ),
        }
    }

    fn score_unknown_network(
        &self,
        host: &str,
        port: u16,
        profile: &ServerProfile,
    ) -> AnomalyComponent {
        let np = &profile.network_profile;

        if !np.has_networked {
            return AnomalyComponent {
                dimension: AnomalyDimension::UnknownNetwork,
                score: 1.0,
                weight: 0.5,
                explanation: format!(
                    "Server has never made network connections; now connecting to {}:{}",
                    host, port
                ),
            };
        }

        let known_host = np.observed_hosts.contains(host);
        let known_port = np.observed_ports.contains(&port);

        let score = if known_host && known_port {
            0.0
        } else if known_host || known_port {
            0.3
        } else {
            0.5
        };

        AnomalyComponent {
            dimension: AnomalyDimension::UnknownNetwork,
            score,
            weight: 0.5,
            explanation: if score == 0.0 {
                format!("{}:{} is a known destination", host, port)
            } else {
                format!(
                    "New network destination {}:{} (known hosts: {}, known ports: {})",
                    host,
                    port,
                    np.observed_hosts.len(),
                    np.observed_ports.len()
                )
            },
        }
    }

    fn score_abnormal_rate(
        &self,
        event: &BehavioralEvent,
        profile: &ServerProfile,
    ) -> AnomalyComponent {
        let tp = &profile.temporal_profile;

        // If we don't have enough data for meaningful stats, skip.
        if tp.gap_count < 5 || tp.inter_request_gap_stddev_ms <= 0.0 {
            return AnomalyComponent {
                dimension: AnomalyDimension::AbnormalRate,
                score: 0.0,
                weight: 0.2,
                explanation: "Insufficient temporal data for rate analysis".to_string(),
            };
        }

        // Compute gap from last event.
        let gap_ms = match tp.last_event_time {
            Some(last) => {
                let diff = event.timestamp.signed_duration_since(last);
                diff.num_milliseconds() as f64
            }
            None => return AnomalyComponent {
                dimension: AnomalyDimension::AbnormalRate,
                score: 0.0,
                weight: 0.2,
                explanation: "No previous event for rate comparison".to_string(),
            },
        };

        // A very small gap means very rapid requests — high rate.
        // Z-score: how many stddevs below the mean gap (lower gap = higher rate).
        let z = if tp.inter_request_gap_stddev_ms > 0.0 {
            (tp.inter_request_gap_mean_ms - gap_ms) / tp.inter_request_gap_stddev_ms
        } else {
            0.0
        };

        let score = if z > 3.0 {
            0.8
        } else if z > 2.0 {
            0.4
        } else {
            0.0
        };

        AnomalyComponent {
            dimension: AnomalyDimension::AbnormalRate,
            score,
            weight: 0.2,
            explanation: if score > 0.0 {
                format!(
                    "Request rate anomaly: gap {:.0}ms vs mean {:.0}ms (z={:.1}σ)",
                    gap_ms, tp.inter_request_gap_mean_ms, z
                )
            } else {
                format!(
                    "Request rate normal: gap {:.0}ms vs mean {:.0}ms",
                    gap_ms, tp.inter_request_gap_mean_ms
                )
            },
        }
    }

    fn score_abnormal_sequence(
        &self,
        tool_name: &str,
        profile: &ServerProfile,
    ) -> AnomalyComponent {
        let tp = &profile.tool_profile;

        let score = match &tp.last_tool {
            Some(last) => {
                let bigram = (last.clone(), tool_name.to_string());
                let count = tp.sequence_bigrams.get(&bigram).copied().unwrap_or(0);
                if count == 0 {
                    0.5
                } else {
                    0.0
                }
            }
            None => 0.0, // No previous tool — can't evaluate sequence.
        };

        AnomalyComponent {
            dimension: AnomalyDimension::AbnormalSequence,
            score,
            weight: 0.15,
            explanation: if score > 0.0 {
                format!(
                    "Tool sequence '{} -> {}' has never been observed",
                    profile
                        .tool_profile
                        .last_tool
                        .as_deref()
                        .unwrap_or("?"),
                    tool_name
                )
            } else {
                format!("Tool sequence is normal for '{}'", tool_name)
            },
        }
    }

    fn score_abnormal_arguments(
        &self,
        tool_name: &str,
        arguments: &HashMap<String, String>,
        profile: &ServerProfile,
    ) -> AnomalyComponent {
        let tp = &profile.tool_profile;

        let known_patterns = tp.argument_patterns.get(tool_name);
        let score = match known_patterns {
            Some(known_keys) => {
                if known_keys.is_empty() {
                    0.0
                } else {
                    let arg_keys: std::collections::HashSet<&str> =
                        arguments.keys().map(|k| k.as_str()).collect();
                    let novel_count = arg_keys
                        .iter()
                        .filter(|k| !known_keys.contains(**k))
                        .count();
                    if novel_count > 0 {
                        0.6
                    } else {
                        0.0
                    }
                }
            }
            None => 0.0, // Tool itself is unknown; scored by UnknownTool.
        };

        AnomalyComponent {
            dimension: AnomalyDimension::AbnormalArguments,
            score,
            weight: 0.15,
            explanation: if score > 0.0 {
                format!(
                    "Tool '{}' called with unusual argument keys: {:?}",
                    tool_name,
                    arguments.keys().collect::<Vec<_>>()
                )
            } else {
                format!("Arguments for '{}' match known patterns", tool_name)
            },
        }
    }

    fn score_sensitive_target(&self, path: &str, profile: &ServerProfile) -> AnomalyComponent {
        let within_territory = profile
            .file_profile
            .directory_prefixes
            .iter()
            .any(|p| path.starts_with(p.as_str()));

        AnomalyComponent {
            dimension: AnomalyDimension::SensitiveTarget,
            score: 1.0,
            weight: 0.3,
            explanation: format!(
                "Accessing sensitive path '{}'{} in {} previous events",
                path,
                if within_territory {
                    " (within territory but sensitive)"
                } else {
                    " (OUTSIDE territory)"
                },
                profile.observation_count
            ),
        }
    }

    fn score_first_network_access(&self, profile: &ServerProfile) -> AnomalyComponent {
        AnomalyComponent {
            dimension: AnomalyDimension::FirstNetworkAccess,
            score: 1.0,
            weight: 0.5,
            explanation: format!(
                "Server '{}' has NEVER made network connections in {} observed events",
                profile.server_name, profile.observation_count
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn is_sensitive_path(&self, path: &str) -> bool {
        self.sensitive_paths.iter().any(|sp| path.contains(sp.as_str()))
    }

    fn compute_total(components: &[AnomalyComponent]) -> f64 {
        if components.is_empty() {
            return 0.0;
        }

        let weight_sum: f64 = components.iter().map(|c| c.weight).sum();
        if weight_sum <= 0.0 {
            return 0.0;
        }

        let weighted_sum: f64 = components.iter().map(|c| c.score * c.weight).sum();
        let mut total = weighted_sum / weight_sum;

        // Floor rule: any dimension at 1.0 → total at least 0.7.
        let any_max = components.iter().any(|c| (c.score - 1.0).abs() < f64::EPSILON);
        if any_max && total < 0.7 {
            total = 0.7;
        }

        total.clamp(0.0, 1.0)
    }

    fn build_explanation(
        components: &[AnomalyComponent],
        total: f64,
        event: &BehavioralEvent,
        profile: &ServerProfile,
    ) -> String {
        let mut top: Vec<&AnomalyComponent> = components
            .iter()
            .filter(|c| c.score > 0.0)
            .collect();
        top.sort_by(|a, b| {
            (b.score * b.weight)
                .partial_cmp(&(a.score * a.weight))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        if top.is_empty() {
            return format!(
                "Anomaly score {:.2}: {} event from '{}' appears normal.",
                total,
                event_type_label(&event.event_type),
                profile.server_name,
            );
        }

        let details: Vec<String> = top.iter().take(3).map(|c| c.explanation.clone()).collect();
        format!(
            "Anomaly score {:.2}: {}. This server has {} previous observations.",
            total,
            details.join("; "),
            profile.observation_count,
        )
    }
}

/// Extract the parent directory from a path string.
fn parent_dir(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(idx) => &trimmed[..idx],
        None => "",
    }
}

fn event_type_label(et: &BehavioralEventType) -> &'static str {
    match et {
        BehavioralEventType::ToolCall { .. } => "tool-call",
        BehavioralEventType::FileAccess { .. } => "file-access",
        BehavioralEventType::NetworkConnect { .. } => "network-connect",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn established_profile() -> ServerProfile {
        let mut tool_counts = HashMap::new();
        tool_counts.insert("read_file".to_string(), 100);
        tool_counts.insert("write_file".to_string(), 80);
        tool_counts.insert("list_dir".to_string(), 60);

        let mut argument_patterns = HashMap::new();
        argument_patterns.insert(
            "read_file".to_string(),
            ["path".to_string()].into_iter().collect(),
        );
        argument_patterns.insert(
            "write_file".to_string(),
            ["path".to_string(), "content".to_string()]
                .into_iter()
                .collect(),
        );

        let mut bigrams = HashMap::new();
        bigrams.insert(("read_file".to_string(), "write_file".to_string()), 50u64);
        bigrams.insert(("list_dir".to_string(), "read_file".to_string()), 40);

        let mut dir_prefixes = HashSet::new();
        dir_prefixes.insert("/home/user/Projects/".to_string());
        dir_prefixes.insert("/home/user/Documents/".to_string());

        let mut ext_counts = HashMap::new();
        ext_counts.insert("rs".to_string(), 200);
        ext_counts.insert("toml".to_string(), 50);

        let mut observed_hosts = HashSet::new();
        observed_hosts.insert("api.example.com".to_string());

        let mut observed_ports = HashSet::new();
        observed_ports.insert(443);

        ServerProfile {
            server_name: "filesystem-server".to_string(),
            client_name: "test-client".to_string(),
            first_seen: Utc::now(),
            last_updated: Utc::now(),
            learning_mode: false,
            observation_count: 2847,
            tool_profile: super::super::profile::ToolProfile {
                tool_counts,
                argument_patterns,
                call_rate: 5.0,
                sequence_bigrams: bigrams,
                last_tool: Some("read_file".to_string()),
            },
            file_profile: super::super::profile::FileProfile {
                directory_prefixes: dir_prefixes,
                extension_counts: ext_counts,
                read_count: 1500,
                write_count: 800,
                peak_ops_rate: 10.0,
            },
            network_profile: super::super::profile::NetworkProfile {
                observed_hosts,
                observed_ports,
                request_rate: 2.0,
                has_networked: true,
            },
            temporal_profile: super::super::profile::TemporalProfile {
                typical_session_duration_secs: 3600.0,
                inter_request_gap_mean_ms: 500.0,
                inter_request_gap_stddev_ms: 100.0,
                burst_size_mean: 3.0,
                burst_size_stddev: 1.0,
                last_event_time: Some(Utc::now() - chrono::Duration::milliseconds(500)),
                gap_count: 100,
                gap_sum_ms: 50000.0,
                gap_sum_sq_ms: 30000000.0,
            },
        }
    }

    fn non_networked_profile() -> ServerProfile {
        let mut p = established_profile();
        p.network_profile.has_networked = false;
        p.network_profile.observed_hosts.clear();
        p.network_profile.observed_ports.clear();
        p
    }

    fn learning_profile() -> ServerProfile {
        let mut p = established_profile();
        p.learning_mode = true;
        p
    }

    fn make_tool_event(tool_name: &str, args: Vec<(&str, &str)>) -> BehavioralEvent {
        BehavioralEvent {
            event_type: BehavioralEventType::ToolCall {
                tool_name: tool_name.to_string(),
                arguments: args.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            },
            server_name: "filesystem-server".to_string(),
            timestamp: Utc::now(),
        }
    }

    fn make_file_event(path: &str, is_write: bool) -> BehavioralEvent {
        BehavioralEvent {
            event_type: BehavioralEventType::FileAccess {
                path: path.to_string(),
                is_write,
            },
            server_name: "filesystem-server".to_string(),
            timestamp: Utc::now(),
        }
    }

    fn make_network_event(host: &str, port: u16) -> BehavioralEvent {
        BehavioralEvent {
            event_type: BehavioralEventType::NetworkConnect {
                host: host.to_string(),
                port,
            },
            server_name: "filesystem-server".to_string(),
            timestamp: Utc::now(),
        }
    }

    // -- UnknownTool tests --

    #[test]
    fn test_unknown_tool_never_seen() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_tool_event("evil_exploit", vec![]);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::UnknownTool).unwrap();
        assert!((comp.score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_unknown_tool_rarely_seen() {
        let scorer = AnomalyScorer::new();
        let mut profile = established_profile();
        profile.tool_profile.tool_counts.insert("rare_tool".to_string(), 3);
        let event = make_tool_event("rare_tool", vec![]);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::UnknownTool).unwrap();
        assert!((comp.score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_unknown_tool_established() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_tool_event("read_file", vec![("path", "/home/user/Projects/foo.rs")]);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::UnknownTool).unwrap();
        assert!(comp.score.abs() < f64::EPSILON);
    }

    // -- UnknownPath tests --

    #[test]
    fn test_path_within_territory() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_file_event("/home/user/Projects/src/main.rs", false);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::UnknownPath).unwrap();
        assert!(comp.score.abs() < f64::EPSILON);
    }

    #[test]
    fn test_path_sibling_of_territory() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        // /home/user/Downloads is a sibling of /home/user/Projects/
        let event = make_file_event("/home/user/Downloads/file.txt", false);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::UnknownPath).unwrap();
        assert!((comp.score - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_path_completely_unrelated() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_file_event("/etc/passwd", false);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::UnknownPath).unwrap();
        assert!((comp.score - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_path_sensitive_outside_territory() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_file_event("/home/user/.ssh/id_rsa", false);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::UnknownPath).unwrap();
        assert!((comp.score - 1.0).abs() < f64::EPSILON);
    }

    // -- UnknownNetwork tests --

    #[test]
    fn test_known_network_destination() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_network_event("api.example.com", 443);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::UnknownNetwork).unwrap();
        assert!(comp.score.abs() < f64::EPSILON);
    }

    #[test]
    fn test_new_network_destination() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_network_event("evil.example.com", 8080);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::UnknownNetwork).unwrap();
        assert!((comp.score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_non_networked_server_connects() {
        let scorer = AnomalyScorer::new();
        let profile = non_networked_profile();
        let event = make_network_event("evil.example.com", 8080);
        let result = scorer.score(&event, &profile).unwrap();

        // Both UnknownNetwork and FirstNetworkAccess should fire.
        let unknown = result.components.iter().find(|c| c.dimension == AnomalyDimension::UnknownNetwork).unwrap();
        assert!((unknown.score - 1.0).abs() < f64::EPSILON);

        let first = result.components.iter().find(|c| c.dimension == AnomalyDimension::FirstNetworkAccess).unwrap();
        assert!((first.score - 1.0).abs() < f64::EPSILON);
    }

    // -- AbnormalRate tests --

    #[test]
    fn test_normal_rate() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        // Gap of ~500ms matches the mean.
        let event = make_tool_event("read_file", vec![("path", "/home/user/Projects/f.rs")]);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::AbnormalRate).unwrap();
        assert!(comp.score.abs() < f64::EPSILON);
    }

    #[test]
    fn test_abnormal_rate_high_z() {
        let scorer = AnomalyScorer::new();
        let mut profile = established_profile();
        // Set last_event_time to 50ms ago (gap=50ms, mean=500ms, stddev=100ms → z=4.5).
        profile.temporal_profile.last_event_time =
            Some(Utc::now() - chrono::Duration::milliseconds(50));
        let event = make_tool_event("read_file", vec![("path", "/home/user/Projects/f.rs")]);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::AbnormalRate).unwrap();
        assert!((comp.score - 0.8).abs() < f64::EPSILON);
    }

    // -- AbnormalSequence tests --

    #[test]
    fn test_known_sequence() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        // last_tool is read_file, calling write_file → known bigram.
        let event = make_tool_event("write_file", vec![("path", "/home/user/Projects/f.rs"), ("content", "hello")]);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::AbnormalSequence).unwrap();
        assert!(comp.score.abs() < f64::EPSILON);
    }

    #[test]
    fn test_unknown_sequence() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        // last_tool is read_file, calling list_dir → not in bigrams.
        let event = make_tool_event("list_dir", vec![]);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::AbnormalSequence).unwrap();
        assert!((comp.score - 0.5).abs() < f64::EPSILON);
    }

    // -- AbnormalArguments tests --

    #[test]
    fn test_normal_arguments() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_tool_event("read_file", vec![("path", "/home/user/Projects/f.rs")]);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::AbnormalArguments).unwrap();
        assert!(comp.score.abs() < f64::EPSILON);
    }

    #[test]
    fn test_abnormal_arguments() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_tool_event("read_file", vec![("path", "/etc/passwd"), ("encoding", "binary")]);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::AbnormalArguments).unwrap();
        assert!((comp.score - 0.6).abs() < f64::EPSILON);
    }

    // -- SensitiveTarget tests --

    #[test]
    fn test_sensitive_path_ssh() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_file_event("/home/user/.ssh/id_rsa", false);
        let result = scorer.score(&event, &profile).unwrap();
        let comp = result.components.iter().find(|c| c.dimension == AnomalyDimension::SensitiveTarget).unwrap();
        assert!((comp.score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sensitive_path_aws() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_file_event("/home/user/.aws/credentials", false);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(result.components.iter().any(|c| c.dimension == AnomalyDimension::SensitiveTarget));
    }

    #[test]
    fn test_sensitive_path_gnupg() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_file_event("/home/user/.gnupg/secring.gpg", false);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(result.components.iter().any(|c| c.dimension == AnomalyDimension::SensitiveTarget));
    }

    #[test]
    fn test_sensitive_path_kube() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_file_event("/home/user/.kube/config", false);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(result.components.iter().any(|c| c.dimension == AnomalyDimension::SensitiveTarget));
    }

    // -- Floor rule tests --

    #[test]
    fn test_floor_rule_single_max_dimension() {
        let scorer = AnomalyScorer::new();
        let profile = non_networked_profile();
        let event = make_network_event("evil.com", 4444);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(
            result.total >= 0.7,
            "Floor rule violated: total {} should be >= 0.7",
            result.total
        );
    }

    #[test]
    fn test_floor_rule_with_unknown_tool() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_tool_event("never_seen_tool", vec![]);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(
            result.total >= 0.7,
            "Floor rule violated: total {} should be >= 0.7 (unknown tool scored 1.0)",
            result.total
        );
    }

    // -- Learning mode test --

    #[test]
    fn test_learning_mode_returns_none() {
        let scorer = AnomalyScorer::new();
        let profile = learning_profile();
        let event = make_tool_event("evil_tool", vec![]);
        assert!(scorer.score(&event, &profile).is_none());
    }

    // -- Well-established behavior test --

    #[test]
    fn test_well_established_behavior_low_score() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        // Normal tool, normal path arg, known sequence.
        let event = make_tool_event("write_file", vec![
            ("path", "/home/user/Projects/src/main.rs"),
            ("content", "fn main() {}"),
        ]);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(
            result.total < 0.3,
            "Established behavior should score low, got {}",
            result.total
        );
    }

    // -- Explanation tests --

    #[test]
    fn test_explanation_non_empty() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_file_event("/home/user/.aws/credentials", false);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(!result.explanation.is_empty());
        assert!(result.explanation.contains("Anomaly score"));
    }

    #[test]
    fn test_explanation_contains_score() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        let event = make_file_event("/home/user/Projects/main.rs", false);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(result.explanation.contains("Anomaly score"));
    }

    // -- Combined scenario: real-world --

    #[test]
    fn test_real_world_credential_theft_scenario() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        // A filesystem server suddenly accessing SSH keys.
        let event = make_file_event("/home/user/.ssh/id_rsa", false);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(
            result.total >= 0.7,
            "Credential theft scenario should score high, got {}",
            result.total
        );
        // Should have both UnknownPath and SensitiveTarget components.
        assert!(result.components.iter().any(|c| c.dimension == AnomalyDimension::UnknownPath));
        assert!(result.components.iter().any(|c| c.dimension == AnomalyDimension::SensitiveTarget));
    }

    #[test]
    fn test_real_world_lateral_movement_scenario() {
        let scorer = AnomalyScorer::new();
        let profile = non_networked_profile();
        // A previously non-networked server suddenly making outbound connections.
        let event = make_network_event("c2.attacker.com", 4444);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(
            result.total >= 0.7,
            "Lateral movement scenario should score high, got {}",
            result.total
        );
    }

    #[test]
    fn test_total_score_normalized() {
        let scorer = AnomalyScorer::new();
        let profile = established_profile();
        // Even with many anomalous dimensions, total stays in [0, 1].
        let event = make_tool_event("evil_tool", vec![("evil_arg", "evil_val")]);
        let result = scorer.score(&event, &profile).unwrap();
        assert!(result.total >= 0.0 && result.total <= 1.0);
    }

    #[test]
    fn test_parent_dir_helper() {
        // Trailing slash is stripped first, then last component is removed.
        assert_eq!(parent_dir("/home/user/Projects/"), "/home/user");
        assert_eq!(parent_dir("/home/user/Projects"), "/home/user");
        assert_eq!(parent_dir("/home"), "");
        assert_eq!(parent_dir(""), "");
    }
}
