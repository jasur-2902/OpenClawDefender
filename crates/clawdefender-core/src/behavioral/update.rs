//! Incremental profile updates after learning phase.
//!
//! After learning completes, profiles continue to update but with exponential
//! moving averages and conservative set expansion to maintain stability.

use std::collections::{HashMap, HashSet};

use crate::event::mcp::{McpEvent, McpEventKind};
use crate::event::os::{OsEvent, OsEventKind};

use super::profile::ServerProfile;

/// Default EMA alpha (new data gets 10% influence).
const DEFAULT_EMA_ALPHA: f64 = 0.1;

/// Default observation threshold before a new entry is added to a set.
const DEFAULT_SET_EXPANSION_THRESHOLD: u64 = 5;

/// Handles incremental profile updates after learning is complete.
pub struct ProfileUpdater {
    /// EMA alpha for rate metrics.
    ema_alpha: f64,
    /// Number of observations required before adding a new set entry.
    set_expansion_threshold: u64,
    /// Pending observations for new set entries: (server_name, category, key) -> count.
    pending_observations: HashMap<(String, String, String), u64>,
}

impl ProfileUpdater {
    /// Create a new updater with default parameters.
    pub fn new() -> Self {
        Self {
            ema_alpha: DEFAULT_EMA_ALPHA,
            set_expansion_threshold: DEFAULT_SET_EXPANSION_THRESHOLD,
            pending_observations: HashMap::new(),
        }
    }

    /// Create with custom parameters.
    pub fn with_params(ema_alpha: f64, set_expansion_threshold: u64) -> Self {
        Self {
            ema_alpha,
            set_expansion_threshold,
            pending_observations: HashMap::new(),
        }
    }

    /// Update a post-learning profile with an MCP event.
    pub fn update_with_mcp_event(
        &mut self,
        profile: &mut ServerProfile,
        event: &McpEvent,
    ) {
        if profile.learning_mode {
            return; // Should use LearningEngine instead
        }

        profile.observation_count += 1;
        profile.last_updated = event.timestamp;

        match &event.kind {
            McpEventKind::ToolCall(tc) => {
                // Update existing tool counts directly
                if profile.tool_profile.tool_counts.contains_key(&tc.tool_name) {
                    *profile
                        .tool_profile
                        .tool_counts
                        .get_mut(&tc.tool_name)
                        .unwrap() += 1;
                } else {
                    // New tool: require multiple observations before adding
                    self.observe_pending(
                        &profile.server_name,
                        "tool",
                        &tc.tool_name,
                        &mut profile.tool_profile.tool_counts,
                    );
                }

                // Update bigrams (only for known tools)
                if let Some(ref last) = profile.tool_profile.last_tool {
                    if profile.tool_profile.tool_counts.contains_key(&tc.tool_name)
                        && profile.tool_profile.tool_counts.contains_key(last)
                    {
                        *profile
                            .tool_profile
                            .sequence_bigrams
                            .entry((last.clone(), tc.tool_name.clone()))
                            .or_insert(0) += 1;
                    }
                }
                profile.tool_profile.last_tool = Some(tc.tool_name.clone());

                // Update call rate with EMA
                // Simple approximation: use a counter-based approach
                self.update_rate_ema(&mut profile.tool_profile.call_rate);
            }
            McpEventKind::ResourceRead(rr) => {
                let path = rr.uri.strip_prefix("file://").unwrap_or(&rr.uri);
                self.update_file_profile_incremental(profile, path, true);
            }
            _ => {}
        }
    }

    /// Update a post-learning profile with an OS event.
    pub fn update_with_os_event(
        &mut self,
        profile: &mut ServerProfile,
        event: &OsEvent,
    ) {
        if profile.learning_mode {
            return;
        }

        profile.observation_count += 1;
        profile.last_updated = event.timestamp;

        match &event.kind {
            OsEventKind::Open { path, flags } => {
                let is_read = *flags & 0x3 == 0;
                self.update_file_profile_incremental(profile, path, is_read);
            }
            OsEventKind::Close { path } | OsEventKind::Unlink { path } => {
                self.update_file_profile_incremental(profile, path, false);
            }
            OsEventKind::Rename { source, dest } => {
                self.update_file_profile_incremental(profile, source, false);
                self.update_file_profile_incremental(profile, dest, false);
            }
            OsEventKind::Connect {
                address, port, ..
            } => {
                // Update network profile conservatively
                if profile.network_profile.observed_hosts.contains(address) {
                    // Known host, update rate
                    self.update_rate_ema(&mut profile.network_profile.request_rate);
                } else {
                    // New host: require multiple observations
                    self.observe_pending_host(
                        &profile.server_name,
                        address,
                        &mut profile.network_profile.observed_hosts,
                    );
                }
                if !profile.network_profile.observed_ports.contains(port) {
                    self.observe_pending_port(
                        &profile.server_name,
                        *port,
                        &mut profile.network_profile.observed_ports,
                    );
                }
            }
            _ => {}
        }
    }

    /// Update file profile incrementally.
    fn update_file_profile_incremental(
        &mut self,
        profile: &mut ServerProfile,
        path: &str,
        is_read: bool,
    ) {
        if let Some(parent) = std::path::Path::new(path).parent() {
            let dir = parent.to_string_lossy().to_string();
            if !profile.file_profile.directory_prefixes.contains(&dir) {
                // New directory: require multiple observations
                self.observe_pending_dir(
                    &profile.server_name,
                    &dir,
                    &mut profile.file_profile.directory_prefixes,
                );
            }
        }

        if let Some(ext) = std::path::Path::new(path).extension() {
            let ext_str = ext.to_string_lossy().to_string();
            if profile.file_profile.extension_counts.contains_key(&ext_str) {
                *profile
                    .file_profile
                    .extension_counts
                    .get_mut(&ext_str)
                    .unwrap() += 1;
            }
            // Don't add new extensions post-learning (conservative)
        }

        if is_read {
            profile.file_profile.read_count += 1;
        } else {
            profile.file_profile.write_count += 1;
        }

        self.update_rate_ema(&mut profile.file_profile.peak_ops_rate);
    }

    /// Track a pending observation for a new tool, adding it only after threshold.
    fn observe_pending(
        &mut self,
        server_name: &str,
        category: &str,
        key: &str,
        target: &mut HashMap<String, u64>,
    ) {
        let pending_key = (
            server_name.to_string(),
            category.to_string(),
            key.to_string(),
        );
        let count = self.pending_observations.entry(pending_key).or_insert(0);
        *count += 1;
        if *count >= self.set_expansion_threshold {
            target.insert(key.to_string(), *count);
            // Clean up pending entry
            self.pending_observations.remove(&(
                server_name.to_string(),
                category.to_string(),
                key.to_string(),
            ));
        }
    }

    /// Track a pending host observation.
    fn observe_pending_host(
        &mut self,
        server_name: &str,
        host: &str,
        target: &mut HashSet<String>,
    ) {
        let pending_key = (
            server_name.to_string(),
            "host".to_string(),
            host.to_string(),
        );
        let count = self.pending_observations.entry(pending_key).or_insert(0);
        *count += 1;
        if *count >= self.set_expansion_threshold {
            target.insert(host.to_string());
            self.pending_observations.remove(&(
                server_name.to_string(),
                "host".to_string(),
                host.to_string(),
            ));
        }
    }

    /// Track a pending port observation.
    fn observe_pending_port(
        &mut self,
        server_name: &str,
        port: u16,
        target: &mut HashSet<u16>,
    ) {
        let pending_key = (
            server_name.to_string(),
            "port".to_string(),
            port.to_string(),
        );
        let count = self.pending_observations.entry(pending_key).or_insert(0);
        *count += 1;
        if *count >= self.set_expansion_threshold {
            target.insert(port);
            self.pending_observations.remove(&(
                server_name.to_string(),
                "port".to_string(),
                port.to_string(),
            ));
        }
    }

    /// Track a pending directory observation.
    fn observe_pending_dir(
        &mut self,
        server_name: &str,
        dir: &str,
        target: &mut HashSet<String>,
    ) {
        let pending_key = (
            server_name.to_string(),
            "dir".to_string(),
            dir.to_string(),
        );
        let count = self.pending_observations.entry(pending_key).or_insert(0);
        *count += 1;
        if *count >= self.set_expansion_threshold {
            target.insert(dir.to_string());
            self.pending_observations.remove(&(
                server_name.to_string(),
                "dir".to_string(),
                dir.to_string(),
            ));
        }
    }

    /// Update a rate metric using EMA.
    fn update_rate_ema(&self, current: &mut f64) {
        // Simple EMA: new_value = alpha * 1.0 + (1 - alpha) * old_value
        // Here 1.0 represents "an event just happened"
        *current = self.ema_alpha * 1.0 + (1.0 - self.ema_alpha) * *current;
    }

    /// Get the current pending observation count for a key.
    pub fn pending_count(
        &self,
        server_name: &str,
        category: &str,
        key: &str,
    ) -> u64 {
        self.pending_observations
            .get(&(
                server_name.to_string(),
                category.to_string(),
                key.to_string(),
            ))
            .copied()
            .unwrap_or(0)
    }
}

impl Default for ProfileUpdater {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavioral::profile::ServerProfile;
    use crate::event::mcp::{McpEvent, McpEventKind, ToolCall};
    use crate::event::os::{OsEvent, OsEventKind};
    use chrono::Utc;
    use serde_json::json;

    fn make_learned_profile() -> ServerProfile {
        let mut profile =
            ServerProfile::new("test-server".to_string(), "test-client".to_string());
        profile.learning_mode = false;
        profile.observation_count = 100;
        profile
            .tool_profile
            .tool_counts
            .insert("read_file".to_string(), 50);
        profile
            .tool_profile
            .tool_counts
            .insert("write_file".to_string(), 30);
        profile
            .file_profile
            .directory_prefixes
            .insert("/home/user/Projects".to_string());
        profile
            .file_profile
            .extension_counts
            .insert("rs".to_string(), 80);
        profile
            .network_profile
            .observed_hosts
            .insert("api.example.com".to_string());
        profile.network_profile.observed_ports.insert(443);
        profile
    }

    fn make_tool_event(tool_name: &str) -> McpEvent {
        McpEvent {
            timestamp: Utc::now(),
            source: "mcp-proxy".to_string(),
            kind: McpEventKind::ToolCall(ToolCall {
                tool_name: tool_name.to_string(),
                arguments: json!({}),
                request_id: json!(1),
            }),
            raw_message: json!({}),
        }
    }

    fn make_os_open(path: &str) -> OsEvent {
        OsEvent {
            timestamp: Utc::now(),
            pid: 1234,
            ppid: 1,
            process_path: "/usr/bin/test".to_string(),
            kind: OsEventKind::Open {
                path: path.to_string(),
                flags: 0,
            },
            signing_id: None,
            team_id: None,
        }
    }

    #[test]
    fn test_new_tool_not_immediately_added() {
        let mut profile = make_learned_profile();
        let mut updater = ProfileUpdater::new();

        // Observe a new tool once
        updater.update_with_mcp_event(&mut profile, &make_tool_event("dangerous_tool"));

        // Should NOT be in the profile yet
        assert!(!profile.tool_profile.tool_counts.contains_key("dangerous_tool"));
    }

    #[test]
    fn test_new_tool_added_after_threshold() {
        let mut profile = make_learned_profile();
        let mut updater = ProfileUpdater::new();

        // Observe a new tool 5 times (default threshold)
        for _ in 0..5 {
            updater.update_with_mcp_event(&mut profile, &make_tool_event("new_tool"));
        }

        // Now it should be in the profile
        assert!(profile.tool_profile.tool_counts.contains_key("new_tool"));
    }

    #[test]
    fn test_existing_tool_updated_immediately() {
        let mut profile = make_learned_profile();
        let mut updater = ProfileUpdater::new();

        let initial = profile.tool_profile.tool_counts["read_file"];
        updater.update_with_mcp_event(&mut profile, &make_tool_event("read_file"));

        assert_eq!(profile.tool_profile.tool_counts["read_file"], initial + 1);
    }

    #[test]
    fn test_ssh_directory_not_added_with_few_observations() {
        let mut profile = make_learned_profile();
        let mut updater = ProfileUpdater::new();

        // Access ~/.ssh/ only twice (below threshold of 5)
        updater.update_with_os_event(
            &mut profile,
            &make_os_open("/home/user/.ssh/id_rsa"),
        );
        updater.update_with_os_event(
            &mut profile,
            &make_os_open("/home/user/.ssh/known_hosts"),
        );

        // ~/.ssh should NOT be in the baseline
        assert!(
            !profile
                .file_profile
                .directory_prefixes
                .contains("/home/user/.ssh"),
            "~/.ssh should NOT be added to baseline with only 2 observations"
        );
    }

    #[test]
    fn test_ssh_directory_added_after_threshold() {
        let mut profile = make_learned_profile();
        let mut updater = ProfileUpdater::new();

        // Access ~/.ssh/ 5 times (meets threshold)
        for i in 0..5 {
            updater.update_with_os_event(
                &mut profile,
                &make_os_open(&format!("/home/user/.ssh/file{i}")),
            );
        }

        // Now it should be in the baseline
        assert!(
            profile
                .file_profile
                .directory_prefixes
                .contains("/home/user/.ssh"),
        );
    }

    #[test]
    fn test_known_directory_remains_accessible() {
        let mut profile = make_learned_profile();
        let mut updater = ProfileUpdater::new();

        let initial_reads = profile.file_profile.read_count;
        updater.update_with_os_event(
            &mut profile,
            &make_os_open("/home/user/Projects/src/main.rs"),
        );

        assert_eq!(profile.file_profile.read_count, initial_reads + 1);
    }

    #[test]
    fn test_new_host_not_immediately_added() {
        let mut profile = make_learned_profile();
        let mut updater = ProfileUpdater::new();

        let event = OsEvent {
            timestamp: Utc::now(),
            pid: 1234,
            ppid: 1,
            process_path: "/usr/bin/test".to_string(),
            kind: OsEventKind::Connect {
                address: "evil.example.com".to_string(),
                port: 8080,
                protocol: "tcp".to_string(),
            },
            signing_id: None,
            team_id: None,
        };
        updater.update_with_os_event(&mut profile, &event);

        assert!(!profile.network_profile.observed_hosts.contains("evil.example.com"));
    }

    #[test]
    fn test_ema_alpha_affects_rate() {
        let mut profile = make_learned_profile();
        let mut updater = ProfileUpdater::new();

        let initial_rate = profile.tool_profile.call_rate;
        updater.update_with_mcp_event(&mut profile, &make_tool_event("read_file"));

        // Rate should have increased via EMA
        assert!(profile.tool_profile.call_rate > initial_rate);
    }

    #[test]
    fn test_learning_mode_events_ignored() {
        let mut profile = make_learned_profile();
        profile.learning_mode = true;
        let mut updater = ProfileUpdater::new();

        let initial_count = profile.observation_count;
        updater.update_with_mcp_event(&mut profile, &make_tool_event("read_file"));

        // Should not have been updated
        assert_eq!(profile.observation_count, initial_count);
    }
}
