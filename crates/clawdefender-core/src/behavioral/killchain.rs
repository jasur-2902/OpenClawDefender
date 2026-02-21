//! Kill chain detection engine.
//!
//! Detects multi-step attack patterns by matching sequences of events within
//! configurable time windows. Ships with 6 built-in patterns and supports
//! custom patterns loaded from TOML configuration.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Severity level for an attack pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// Type of event that can be matched in a pattern step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepEventType {
    FileRead,
    FileWrite,
    FileList,
    NetworkConnect,
    ShellExec,
    SamplingResponse,
    AnyToolCall,
}

/// A single step in an attack pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStep {
    pub event_type: StepEventType,
    #[serde(default)]
    pub path_pattern: Option<String>,
    #[serde(default)]
    pub destination_pattern: Option<String>,
    #[serde(default)]
    pub min_count: Option<usize>,
}

/// An attack pattern consisting of ordered steps within a time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub name: String,
    pub severity: Severity,
    pub window_seconds: u64,
    pub explanation: String,
    pub steps: Vec<PatternStep>,
}

/// A timestamped event in the sliding window.
#[derive(Debug, Clone)]
pub struct TimestampedEvent {
    pub timestamp: DateTime<Utc>,
    pub event: KillChainEvent,
}

/// An event suitable for kill-chain analysis.
#[derive(Debug, Clone)]
pub struct KillChainEvent {
    pub event_type: StepEventType,
    pub path: Option<String>,
    pub destination: Option<String>,
    pub server_name: String,
}

/// A successful match of a kill-chain pattern.
#[derive(Debug, Clone)]
pub struct KillChainMatch {
    pub pattern: AttackPattern,
    pub matched_events: Vec<TimestampedEvent>,
    pub explanation: String,
    pub severity: Severity,
}

impl KillChainMatch {
    /// Score boost to add to the anomaly score when a kill chain matches.
    pub fn anomaly_boost(&self) -> f64 {
        0.3
    }
}

// ---------------------------------------------------------------------------
// TOML configuration wrapper
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PatternsFile {
    #[serde(default)]
    pattern: Vec<AttackPattern>,
}

// ---------------------------------------------------------------------------
// Built-in patterns
// ---------------------------------------------------------------------------

fn builtin_patterns() -> Vec<AttackPattern> {
    vec![
        // Pattern 1 — Credential Theft + Exfiltration
        AttackPattern {
            name: "credential_theft_exfiltration".into(),
            severity: Severity::Critical,
            window_seconds: 60,
            explanation: "Credential file was read followed by an external network connection — \
                          possible credential exfiltration."
                .into(),
            steps: vec![
                PatternStep {
                    event_type: StepEventType::FileRead,
                    path_pattern: Some("~/.ssh/*,~/.aws/*,~/.gnupg/*,~/.config/gcloud/*,~/.kube/*,~/.config/clawdefender/honeypot/ssh/*,~/.config/clawdefender/honeypot/aws/*".into()),
                    destination_pattern: None,
                    min_count: None,
                },
                PatternStep {
                    event_type: StepEventType::NetworkConnect,
                    path_pattern: None,
                    destination_pattern: Some("!localhost,!127.0.0.1,!::1".into()),
                    min_count: None,
                },
            ],
        },
        // Pattern 2 — Reconnaissance + Credential Access
        AttackPattern {
            name: "recon_credential_access".into(),
            severity: Severity::High,
            window_seconds: 120,
            explanation: "Broad directory listing followed by credential file access — \
                          possible reconnaissance leading to credential theft."
                .into(),
            steps: vec![
                PatternStep {
                    event_type: StepEventType::FileList,
                    path_pattern: Some("~/,/Users/,/".into()),
                    destination_pattern: None,
                    min_count: None,
                },
                PatternStep {
                    event_type: StepEventType::FileRead,
                    path_pattern: Some("~/.ssh/*,~/.aws/*,~/.gnupg/*,~/.config/gcloud/*,~/.kube/*,~/.config/clawdefender/honeypot/ssh/*,~/.config/clawdefender/honeypot/aws/*".into()),
                    destination_pattern: None,
                    min_count: None,
                },
            ],
        },
        // Pattern 3 — Persistence Installation
        AttackPattern {
            name: "persistence_installation".into(),
            severity: Severity::Critical,
            window_seconds: 30,
            explanation: "File written to a startup/persistence location followed by shell \
                          execution — possible persistence mechanism being installed."
                .into(),
            steps: vec![
                PatternStep {
                    event_type: StepEventType::FileWrite,
                    path_pattern: Some(
                        "~/Library/LaunchAgents/*,~/.bashrc,~/.zshrc,~/Library/Application Scripts/*"
                            .into(),
                    ),
                    destination_pattern: None,
                    min_count: None,
                },
                PatternStep {
                    event_type: StepEventType::ShellExec,
                    path_pattern: None,
                    destination_pattern: None,
                    min_count: None,
                },
            ],
        },
        // Pattern 4 — Data Staging + Exfiltration
        AttackPattern {
            name: "data_staging_exfiltration".into(),
            severity: Severity::Critical,
            window_seconds: 120,
            explanation: "Multiple sensitive file reads followed by a write to /tmp and network \
                          or shell activity — possible data staging and exfiltration."
                .into(),
            steps: vec![
                PatternStep {
                    event_type: StepEventType::FileRead,
                    path_pattern: Some("~/.ssh/*,~/.aws/*,~/.gnupg/*,~/.config/gcloud/*,~/.kube/*,~/.config/clawdefender/honeypot/ssh/*,~/.config/clawdefender/honeypot/aws/*".into()),
                    destination_pattern: None,
                    min_count: Some(3),
                },
                PatternStep {
                    event_type: StepEventType::FileWrite,
                    path_pattern: Some("/tmp/*".into()),
                    destination_pattern: None,
                    min_count: None,
                },
                PatternStep {
                    event_type: StepEventType::NetworkConnect,
                    path_pattern: None,
                    destination_pattern: None,
                    min_count: None,
                },
            ],
        },
        // Pattern 5 — Shell Escape
        AttackPattern {
            name: "shell_escape".into(),
            severity: Severity::High,
            window_seconds: 10,
            explanation: "An MCP tool call was immediately followed by an uncorrelated shell \
                          execution — possible container/sandbox escape."
                .into(),
            steps: vec![
                PatternStep {
                    event_type: StepEventType::AnyToolCall,
                    path_pattern: None,
                    destination_pattern: None,
                    min_count: None,
                },
                PatternStep {
                    event_type: StepEventType::ShellExec,
                    path_pattern: None,
                    destination_pattern: None,
                    min_count: None,
                },
            ],
        },
        // Pattern 6 — Prompt Injection Followthrough
        AttackPattern {
            name: "prompt_injection_followthrough".into(),
            severity: Severity::High,
            window_seconds: 30,
            explanation: "A sampling/createMessage response was followed by an anomalous action — \
                          possible prompt injection follow-through."
                .into(),
            steps: vec![
                PatternStep {
                    event_type: StepEventType::SamplingResponse,
                    path_pattern: None,
                    destination_pattern: None,
                    min_count: None,
                },
                PatternStep {
                    event_type: StepEventType::ShellExec,
                    path_pattern: None,
                    destination_pattern: None,
                    min_count: None,
                },
            ],
        },
    ]
}

// ---------------------------------------------------------------------------
// Pattern matching helpers
// ---------------------------------------------------------------------------

/// Expand a leading `~` to the home directory path.
fn expand_tilde(pattern: &str) -> String {
    if let Some(rest) = pattern.strip_prefix('~') {
        if let Some(home) = dirs_home() {
            return format!("{}{}", home, rest);
        }
    }
    pattern.to_string()
}

/// Best-effort home directory lookup without extra deps.
fn dirs_home() -> Option<String> {
    std::env::var("HOME").ok()
}

/// Check if `value` matches any of the comma-separated patterns in `pattern_str`.
/// Supports simple glob with `*`, and negation prefixes `!`.
fn matches_pattern(value: &str, pattern_str: &str) -> bool {
    let patterns: Vec<&str> = pattern_str.split(',').collect();

    // If all patterns are negations, the semantic is "match everything except …".
    let all_negated = patterns.iter().all(|p| p.starts_with('!'));

    for pat in &patterns {
        if let Some(neg) = pat.strip_prefix('!') {
            let expanded = expand_tilde(neg);
            if simple_glob_match(&expanded, value) {
                return false; // explicitly excluded
            }
        } else {
            let expanded = expand_tilde(pat);
            if simple_glob_match(&expanded, value) {
                return true;
            }
        }
    }

    // If every pattern was a negation and none matched, the value is allowed.
    all_negated
}

/// Minimal glob: `*` matches any substring (non-greedy within a segment is not needed here).
fn simple_glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        // Exact match or prefix match (for paths like ~/.bashrc matching ~/.bashrc)
        return value == pattern || value.starts_with(pattern);
    }
    // Split on `*` and check that all segments appear in order.
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // First segment must be a prefix.
            if !value[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
        } else if let Some(found) = value[pos..].find(part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }
    true
}

/// Check if a step matches a single event.
fn step_matches_event(step: &PatternStep, event: &KillChainEvent) -> bool {
    // Event type must match (AnyToolCall matches everything).
    if step.event_type != StepEventType::AnyToolCall && step.event_type != event.event_type {
        return false;
    }

    // Path pattern check.
    if let Some(ref pat) = step.path_pattern {
        match &event.path {
            Some(path) => {
                if !matches_pattern(path, pat) {
                    return false;
                }
            }
            None => return false,
        }
    }

    // Destination pattern check.
    if let Some(ref pat) = step.destination_pattern {
        match &event.destination {
            Some(dest) => {
                if !matches_pattern(dest, pat) {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

// ---------------------------------------------------------------------------
// KillChainDetector
// ---------------------------------------------------------------------------

/// Maximum events to keep per server in the sliding window.
const MAX_WINDOW_SIZE: usize = 1000;
/// Default window duration.
const WINDOW_DURATION_SECS: i64 = 300; // 5 minutes

/// The kill chain detector maintains per-server event windows and checks
/// incoming events against all registered attack patterns.
pub struct KillChainDetector {
    patterns: Vec<AttackPattern>,
    event_windows: HashMap<String, VecDeque<TimestampedEvent>>,
    custom_patterns_path: Option<PathBuf>,
    last_config_modified: Option<std::time::SystemTime>,
}

impl KillChainDetector {
    /// Create a new detector with built-in patterns only.
    pub fn new() -> Self {
        Self {
            patterns: builtin_patterns(),
            event_windows: HashMap::new(),
            custom_patterns_path: None,
            last_config_modified: None,
        }
    }

    /// Create a new detector and attempt to load custom patterns from the
    /// given path. Built-in patterns are always included.
    pub fn with_custom_patterns(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut detector = Self::new();
        detector.custom_patterns_path = Some(path.clone());
        detector.try_load_custom_patterns(&path);
        detector
    }

    /// Return the number of registered patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Return a reference to all registered patterns.
    pub fn patterns(&self) -> &[AttackPattern] {
        &self.patterns
    }

    /// Try to hot-reload custom patterns if the config file changed.
    pub fn try_hot_reload(&mut self) {
        let path = match &self.custom_patterns_path {
            Some(p) => p.clone(),
            None => return,
        };

        let modified = fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());

        if modified != self.last_config_modified {
            // Rebuild patterns: start with built-in, then append custom.
            self.patterns = builtin_patterns();
            self.try_load_custom_patterns(&path);
        }
    }

    fn try_load_custom_patterns(&mut self, path: &Path) {
        if let Ok(contents) = fs::read_to_string(path) {
            if let Ok(file) = toml::from_str::<PatternsFile>(&contents) {
                self.patterns.extend(file.pattern);
            }
        }
        self.last_config_modified = fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok());
    }

    /// Ingest a new event and return any kill-chain matches.
    pub fn ingest(&mut self, event: KillChainEvent, timestamp: DateTime<Utc>) -> Vec<KillChainMatch> {
        let server = event.server_name.clone();

        // Mutate the window in a block so the mutable borrow is released.
        {
            let window = self.event_windows.entry(server.clone()).or_default();

            window.push_back(TimestampedEvent {
                timestamp,
                event,
            });

            // Trim: remove events older than 5 minutes.
            let cutoff = timestamp - Duration::seconds(WINDOW_DURATION_SECS);
            while let Some(front) = window.front() {
                if front.timestamp < cutoff {
                    window.pop_front();
                } else {
                    break;
                }
            }

            // Trim: cap at MAX_WINDOW_SIZE.
            while window.len() > MAX_WINDOW_SIZE {
                window.pop_front();
            }
        }

        // Now borrow self immutably for pattern checking.
        let window = self.event_windows.get(&server).unwrap();
        self.check_patterns(window)
    }

    fn check_patterns(&self, window: &VecDeque<TimestampedEvent>) -> Vec<KillChainMatch> {
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            if pattern.steps.is_empty() {
                continue;
            }

            if let Some(m) = self.match_pattern(pattern, window) {
                matches.push(m);
            }
        }

        matches
    }

    fn match_pattern(
        &self,
        pattern: &AttackPattern,
        window: &VecDeque<TimestampedEvent>,
    ) -> Option<KillChainMatch> {
        let events: Vec<_> = window.iter().collect();
        if events.is_empty() {
            return None;
        }

        // We walk through the pattern steps in order, finding matching events
        // in chronological order. The first and last matched event must be
        // within `window_seconds`.
        let mut matched_events: Vec<TimestampedEvent> = Vec::new();
        let mut step_idx = 0;
        let mut search_start = 0usize;

        while step_idx < pattern.steps.len() && search_start < events.len() {
            let step = &pattern.steps[step_idx];
            let required_count = step.min_count.unwrap_or(1);
            let mut found_in_step: Vec<TimestampedEvent> = Vec::new();

            for (i, ev) in events.iter().enumerate().skip(search_start) {
                if step_matches_event(step, &ev.event) {
                    found_in_step.push((*ev).clone());
                    if found_in_step.len() >= required_count {
                        search_start = i + 1;
                        break;
                    }
                }
            }

            if found_in_step.len() >= required_count {
                matched_events.extend(found_in_step);
                step_idx += 1;
            } else {
                return None;
            }
        }

        if step_idx < pattern.steps.len() {
            return None;
        }

        // Check time window: first to last matched event.
        if matched_events.len() >= 2 {
            let first_ts = matched_events.first().unwrap().timestamp;
            let last_ts = matched_events.last().unwrap().timestamp;
            let elapsed = (last_ts - first_ts).num_seconds().unsigned_abs();
            if elapsed > pattern.window_seconds {
                return None;
            }
        }

        Some(KillChainMatch {
            severity: pattern.severity.clone(),
            explanation: pattern.explanation.clone(),
            pattern: pattern.clone(),
            matched_events,
        })
    }

    /// Clear the event window for a specific server.
    pub fn clear_server(&mut self, server_name: &str) {
        self.event_windows.remove(server_name);
    }

    /// Clear all event windows.
    pub fn clear_all(&mut self) {
        self.event_windows.clear();
    }
}

impl Default for KillChainDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn ts(base: DateTime<Utc>, offset_secs: i64) -> DateTime<Utc> {
        base + Duration::seconds(offset_secs)
    }

    fn make_event(
        event_type: StepEventType,
        path: Option<&str>,
        destination: Option<&str>,
        server: &str,
    ) -> KillChainEvent {
        KillChainEvent {
            event_type,
            path: path.map(|s| s.to_string()),
            destination: destination.map(|s| s.to_string()),
            server_name: server.to_string(),
        }
    }

    // -- Pattern 1: Credential Theft + Exfiltration --

    #[test]
    fn test_credential_theft_exfiltration_ssh() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        // Step 1: read credential file
        let path = format!("{}/.ssh/id_rsa", home);
        let r = det.ingest(
            make_event(StepEventType::FileRead, Some(&path), None, "srv"),
            now,
        );
        assert!(r.is_empty());

        // Step 2: network connect to external host
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("evil.com"), "srv"),
            ts(now, 10),
        );
        assert!(!r.is_empty());
        assert_eq!(r[0].pattern.name, "credential_theft_exfiltration");
        assert_eq!(r[0].severity, Severity::Critical);
    }

    #[test]
    fn test_credential_theft_aws() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        let path = format!("{}/.aws/credentials", home);
        det.ingest(make_event(StepEventType::FileRead, Some(&path), None, "srv"), now);
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("10.0.0.1"), "srv"),
            ts(now, 5),
        );
        assert!(!r.is_empty());
        assert_eq!(r[0].pattern.name, "credential_theft_exfiltration");
    }

    #[test]
    fn test_credential_theft_gcloud() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        let path = format!("{}/.config/gcloud/application_default_credentials.json", home);
        det.ingest(make_event(StepEventType::FileRead, Some(&path), None, "srv"), now);
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("attacker.io"), "srv"),
            ts(now, 30),
        );
        assert!(!r.is_empty());
    }

    #[test]
    fn test_credential_theft_kube() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        let path = format!("{}/.kube/config", home);
        det.ingest(make_event(StepEventType::FileRead, Some(&path), None, "srv"), now);
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("8.8.8.8"), "srv"),
            ts(now, 55),
        );
        assert!(!r.is_empty());
    }

    #[test]
    fn test_credential_theft_blocked_by_localhost() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        let path = format!("{}/.ssh/id_rsa", home);
        det.ingest(make_event(StepEventType::FileRead, Some(&path), None, "srv"), now);

        // localhost should be excluded by the negation pattern
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("localhost"), "srv"),
            ts(now, 5),
        );
        // Should NOT match credential_theft_exfiltration specifically
        let cred_match = r.iter().find(|m| m.pattern.name == "credential_theft_exfiltration");
        assert!(cred_match.is_none());
    }

    #[test]
    fn test_credential_theft_outside_window() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        let path = format!("{}/.ssh/id_rsa", home);
        det.ingest(make_event(StepEventType::FileRead, Some(&path), None, "srv"), now);

        // 61 seconds later — outside the 60s window
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("evil.com"), "srv"),
            ts(now, 61),
        );
        let cred_match = r.iter().find(|m| m.pattern.name == "credential_theft_exfiltration");
        assert!(cred_match.is_none());
    }

    #[test]
    fn test_credential_theft_missing_network_step() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        let path = format!("{}/.ssh/id_rsa", home);
        det.ingest(make_event(StepEventType::FileRead, Some(&path), None, "srv"), now);

        // Only a file write, no network
        let r = det.ingest(
            make_event(StepEventType::FileWrite, Some("/tmp/out"), None, "srv"),
            ts(now, 5),
        );
        let cred_match = r.iter().find(|m| m.pattern.name == "credential_theft_exfiltration");
        assert!(cred_match.is_none());
    }

    // -- Pattern 2: Reconnaissance + Credential Access --

    #[test]
    fn test_recon_credential_access() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        // Step 1: broad directory listing
        det.ingest(
            make_event(StepEventType::FileList, Some(&format!("{}/", home)), None, "srv"),
            now,
        );

        // Step 2: read credential file
        let r = det.ingest(
            make_event(StepEventType::FileRead, Some(&format!("{}/.ssh/id_rsa", home)), None, "srv"),
            ts(now, 30),
        );
        assert!(!r.is_empty());
        let m = r.iter().find(|m| m.pattern.name == "recon_credential_access");
        assert!(m.is_some());
    }

    #[test]
    fn test_recon_outside_window() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        det.ingest(
            make_event(StepEventType::FileList, Some(&format!("{}/", home)), None, "srv"),
            now,
        );

        // 121 seconds — outside 120s window
        let r = det.ingest(
            make_event(StepEventType::FileRead, Some(&format!("{}/.ssh/id_rsa", home)), None, "srv"),
            ts(now, 121),
        );
        let m = r.iter().find(|m| m.pattern.name == "recon_credential_access");
        assert!(m.is_none());
    }

    // -- Pattern 3: Persistence Installation --

    #[test]
    fn test_persistence_launch_agents() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        det.ingest(
            make_event(
                StepEventType::FileWrite,
                Some(&format!("{}/Library/LaunchAgents/evil.plist", home)),
                None,
                "srv",
            ),
            now,
        );

        let r = det.ingest(
            make_event(StepEventType::ShellExec, None, None, "srv"),
            ts(now, 5),
        );
        let m = r.iter().find(|m| m.pattern.name == "persistence_installation");
        assert!(m.is_some());
        assert_eq!(m.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_persistence_bashrc() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        det.ingest(
            make_event(StepEventType::FileWrite, Some(&format!("{}/.bashrc", home)), None, "srv"),
            now,
        );

        let r = det.ingest(
            make_event(StepEventType::ShellExec, None, None, "srv"),
            ts(now, 10),
        );
        let m = r.iter().find(|m| m.pattern.name == "persistence_installation");
        assert!(m.is_some());
    }

    #[test]
    fn test_persistence_zshrc() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        det.ingest(
            make_event(StepEventType::FileWrite, Some(&format!("{}/.zshrc", home)), None, "srv"),
            now,
        );

        let r = det.ingest(
            make_event(StepEventType::ShellExec, None, None, "srv"),
            ts(now, 5),
        );
        let m = r.iter().find(|m| m.pattern.name == "persistence_installation");
        assert!(m.is_some());
    }

    #[test]
    fn test_persistence_outside_window() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        det.ingest(
            make_event(
                StepEventType::FileWrite,
                Some(&format!("{}/Library/LaunchAgents/evil.plist", home)),
                None,
                "srv",
            ),
            now,
        );

        let r = det.ingest(
            make_event(StepEventType::ShellExec, None, None, "srv"),
            ts(now, 31),
        );
        let m = r.iter().find(|m| m.pattern.name == "persistence_installation");
        assert!(m.is_none());
    }

    // -- Pattern 4: Data Staging + Exfiltration --

    #[test]
    fn test_data_staging_exfiltration() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        // 3 credential file reads
        det.ingest(
            make_event(StepEventType::FileRead, Some(&format!("{}/.ssh/id_rsa", home)), None, "srv"),
            now,
        );
        det.ingest(
            make_event(StepEventType::FileRead, Some(&format!("{}/.aws/credentials", home)), None, "srv"),
            ts(now, 2),
        );
        det.ingest(
            make_event(StepEventType::FileRead, Some(&format!("{}/.gnupg/pubring.kbx", home)), None, "srv"),
            ts(now, 4),
        );

        // Write to /tmp
        det.ingest(
            make_event(StepEventType::FileWrite, Some("/tmp/exfil.tar.gz"), None, "srv"),
            ts(now, 10),
        );

        // Network connect
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("evil.com"), "srv"),
            ts(now, 15),
        );
        let m = r.iter().find(|m| m.pattern.name == "data_staging_exfiltration");
        assert!(m.is_some());
        assert_eq!(m.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_data_staging_insufficient_reads() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        // Only 2 reads (need 3)
        det.ingest(
            make_event(StepEventType::FileRead, Some(&format!("{}/.ssh/id_rsa", home)), None, "srv"),
            now,
        );
        det.ingest(
            make_event(StepEventType::FileRead, Some(&format!("{}/.aws/credentials", home)), None, "srv"),
            ts(now, 2),
        );

        det.ingest(
            make_event(StepEventType::FileWrite, Some("/tmp/out"), None, "srv"),
            ts(now, 10),
        );

        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("evil.com"), "srv"),
            ts(now, 15),
        );
        let m = r.iter().find(|m| m.pattern.name == "data_staging_exfiltration");
        assert!(m.is_none());
    }

    // -- Pattern 5: Shell Escape --

    #[test]
    fn test_shell_escape() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();

        det.ingest(
            make_event(StepEventType::AnyToolCall, None, None, "srv"),
            now,
        );

        let r = det.ingest(
            make_event(StepEventType::ShellExec, None, None, "srv"),
            ts(now, 3),
        );
        let m = r.iter().find(|m| m.pattern.name == "shell_escape");
        assert!(m.is_some());
        assert_eq!(m.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_shell_escape_outside_window() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();

        det.ingest(
            make_event(StepEventType::AnyToolCall, None, None, "srv"),
            now,
        );

        // 11 seconds — outside the 10s window
        let r = det.ingest(
            make_event(StepEventType::ShellExec, None, None, "srv"),
            ts(now, 11),
        );
        let m = r.iter().find(|m| m.pattern.name == "shell_escape");
        assert!(m.is_none());
    }

    // -- Pattern 6: Prompt Injection Followthrough --

    #[test]
    fn test_prompt_injection_followthrough() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();

        det.ingest(
            make_event(StepEventType::SamplingResponse, None, None, "srv"),
            now,
        );

        let r = det.ingest(
            make_event(StepEventType::ShellExec, None, None, "srv"),
            ts(now, 10),
        );
        let m = r.iter().find(|m| m.pattern.name == "prompt_injection_followthrough");
        assert!(m.is_some());
        assert_eq!(m.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_prompt_injection_outside_window() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();

        det.ingest(
            make_event(StepEventType::SamplingResponse, None, None, "srv"),
            now,
        );

        let r = det.ingest(
            make_event(StepEventType::ShellExec, None, None, "srv"),
            ts(now, 31),
        );
        let m = r.iter().find(|m| m.pattern.name == "prompt_injection_followthrough");
        assert!(m.is_none());
    }

    // -- Cross-server isolation --

    #[test]
    fn test_no_cross_server_contamination() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        // Server A: reads credentials
        det.ingest(
            make_event(StepEventType::FileRead, Some(&format!("{}/.ssh/id_rsa", home)), None, "server_a"),
            now,
        );

        // Server B: makes network connection
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("evil.com"), "server_b"),
            ts(now, 5),
        );
        let cred_match = r.iter().find(|m| m.pattern.name == "credential_theft_exfiltration");
        assert!(cred_match.is_none());
    }

    // -- Sliding window management --

    #[test]
    fn test_window_trims_old_events() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();

        // Add an event 6 minutes ago
        det.ingest(
            make_event(StepEventType::FileRead, Some("/tmp/old"), None, "srv"),
            ts(now, -360),
        );

        // Add a current event — the old one should be trimmed
        det.ingest(
            make_event(StepEventType::FileRead, Some("/tmp/new"), None, "srv"),
            now,
        );

        let window = det.event_windows.get("srv").unwrap();
        assert_eq!(window.len(), 1);
        assert_eq!(window[0].event.path.as_deref(), Some("/tmp/new"));
    }

    #[test]
    fn test_window_max_size() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();

        // Insert more than MAX_WINDOW_SIZE events
        for i in 0..1010 {
            det.ingest(
                make_event(StepEventType::FileRead, Some("/tmp/f"), None, "srv"),
                ts(now, i),
            );
        }

        let window = det.event_windows.get("srv").unwrap();
        assert!(window.len() <= MAX_WINDOW_SIZE);
    }

    // -- Custom pattern loading --

    #[test]
    fn test_custom_pattern_loading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("patterns.toml");
        std::fs::write(
            &path,
            r#"
[[pattern]]
name = "custom_exfil"
severity = "critical"
window_seconds = 60
explanation = "Custom exfiltration detected"

[[pattern.steps]]
event_type = "file_read"
path_pattern = "/secret/*"

[[pattern.steps]]
event_type = "network_connect"
"#,
        )
        .unwrap();

        let mut det = KillChainDetector::with_custom_patterns(&path);
        // 6 built-in + 1 custom
        assert_eq!(det.pattern_count(), 7);

        let now = Utc::now();
        det.ingest(
            make_event(StepEventType::FileRead, Some("/secret/key"), None, "srv"),
            now,
        );
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("x.com"), "srv"),
            ts(now, 5),
        );
        let m = r.iter().find(|m| m.pattern.name == "custom_exfil");
        assert!(m.is_some());
    }

    #[test]
    fn test_hot_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("patterns.toml");
        std::fs::write(&path, "").unwrap();

        let mut det = KillChainDetector::with_custom_patterns(&path);
        assert_eq!(det.pattern_count(), 6);

        // Write a new pattern
        std::fs::write(
            &path,
            r#"
[[pattern]]
name = "hot_loaded"
severity = "low"
window_seconds = 10
explanation = "Hot loaded"

[[pattern.steps]]
event_type = "shell_exec"
"#,
        )
        .unwrap();

        // Force modified time change (filesystem granularity)
        std::thread::sleep(std::time::Duration::from_millis(50));
        det.try_hot_reload();
        assert_eq!(det.pattern_count(), 7);
    }

    // -- Anomaly boost --

    #[test]
    fn test_anomaly_boost() {
        let m = KillChainMatch {
            pattern: AttackPattern {
                name: "test".into(),
                severity: Severity::High,
                window_seconds: 10,
                explanation: "test".into(),
                steps: vec![],
            },
            matched_events: vec![],
            explanation: "test".into(),
            severity: Severity::High,
        };
        assert!((m.anomaly_boost() - 0.3).abs() < f64::EPSILON);
    }

    // -- Time window boundary tests --

    #[test]
    fn test_credential_theft_just_inside_window() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        det.ingest(
            make_event(StepEventType::FileRead, Some(&format!("{}/.ssh/id_rsa", home)), None, "srv"),
            now,
        );
        // Exactly at 60 seconds
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("evil.com"), "srv"),
            ts(now, 60),
        );
        let m = r.iter().find(|m| m.pattern.name == "credential_theft_exfiltration");
        assert!(m.is_some()); // 60 <= 60, should match
    }

    #[test]
    fn test_shell_escape_just_at_boundary() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();

        det.ingest(
            make_event(StepEventType::AnyToolCall, None, None, "srv"),
            now,
        );

        // Exactly at 10 seconds
        let r = det.ingest(
            make_event(StepEventType::ShellExec, None, None, "srv"),
            ts(now, 10),
        );
        let m = r.iter().find(|m| m.pattern.name == "shell_escape");
        assert!(m.is_some()); // 10 <= 10, should match
    }

    // -- Builtin pattern count --

    #[test]
    fn test_builtin_pattern_count() {
        let det = KillChainDetector::new();
        assert_eq!(det.pattern_count(), 6);
    }

    // -- Clear methods --

    #[test]
    fn test_clear_server() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();

        det.ingest(make_event(StepEventType::ShellExec, None, None, "srv"), now);
        assert!(det.event_windows.contains_key("srv"));

        det.clear_server("srv");
        assert!(!det.event_windows.contains_key("srv"));
    }

    #[test]
    fn test_clear_all() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();

        det.ingest(make_event(StepEventType::ShellExec, None, None, "a"), now);
        det.ingest(make_event(StepEventType::ShellExec, None, None, "b"), now);
        assert_eq!(det.event_windows.len(), 2);

        det.clear_all();
        assert!(det.event_windows.is_empty());
    }

    // -- Helper function tests --

    #[test]
    fn test_simple_glob_match() {
        assert!(simple_glob_match("/tmp/*", "/tmp/foo.txt"));
        assert!(simple_glob_match("/tmp/*", "/tmp/bar/baz"));
        assert!(!simple_glob_match("/tmp/*", "/var/tmp/foo"));
        assert!(simple_glob_match("*", "anything"));
        assert!(simple_glob_match("/home/*/.ssh/*", "/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn test_matches_pattern_negation() {
        assert!(!matches_pattern("localhost", "!localhost,!127.0.0.1,!::1"));
        assert!(!matches_pattern("127.0.0.1", "!localhost,!127.0.0.1,!::1"));
        assert!(!matches_pattern("::1", "!localhost,!127.0.0.1,!::1"));
        assert!(matches_pattern("evil.com", "!localhost,!127.0.0.1,!::1"));
    }

    #[test]
    fn test_gnupg_credential_path() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        let path = format!("{}/.gnupg/secring.gpg", home);
        det.ingest(make_event(StepEventType::FileRead, Some(&path), None, "srv"), now);
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("evil.com"), "srv"),
            ts(now, 5),
        );
        assert!(!r.is_empty());
    }

    // -- Honeypot tests --

    #[test]
    fn test_honeypot_ssh_triggers_credential_theft() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        // Step 1: read honeypot SSH key
        let path = format!("{}/.config/clawdefender/honeypot/ssh/id_rsa", home);
        det.ingest(
            make_event(StepEventType::FileRead, Some(&path), None, "srv"),
            now,
        );

        // Step 2: network connect to external host
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("evil.com"), "srv"),
            ts(now, 10),
        );
        assert!(!r.is_empty());
        assert_eq!(r[0].pattern.name, "credential_theft_exfiltration");
    }

    #[test]
    fn test_honeypot_aws_triggers_credential_theft() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        let path = format!("{}/.config/clawdefender/honeypot/aws/credentials", home);
        det.ingest(make_event(StepEventType::FileRead, Some(&path), None, "srv"), now);
        let r = det.ingest(
            make_event(StepEventType::NetworkConnect, None, Some("evil.com"), "srv"),
            ts(now, 10),
        );
        assert!(!r.is_empty());
        assert_eq!(r[0].pattern.name, "credential_theft_exfiltration");
    }

    #[test]
    fn test_honeypot_ssh_triggers_recon_credential_access() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        // Step 1: broad directory listing
        det.ingest(
            make_event(StepEventType::FileList, Some(&format!("{}/", home)), None, "srv"),
            now,
        );

        // Step 2: read honeypot SSH key
        let path = format!("{}/.config/clawdefender/honeypot/ssh/id_rsa", home);
        let r = det.ingest(
            make_event(StepEventType::FileRead, Some(&path), None, "srv"),
            ts(now, 30),
        );
        let m = r.iter().find(|m| m.pattern.name == "recon_credential_access");
        assert!(m.is_some());
    }

    #[test]
    fn test_application_scripts_persistence() {
        let mut det = KillChainDetector::new();
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());

        det.ingest(
            make_event(
                StepEventType::FileWrite,
                Some(&format!("{}/Library/Application Scripts/com.evil.app/script.sh", home)),
                None,
                "srv",
            ),
            now,
        );
        let r = det.ingest(
            make_event(StepEventType::ShellExec, None, None, "srv"),
            ts(now, 5),
        );
        let m = r.iter().find(|m| m.pattern.name == "persistence_installation");
        assert!(m.is_some());
    }
}
