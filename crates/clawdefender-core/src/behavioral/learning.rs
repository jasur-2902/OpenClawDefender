//! Learning phase logic for behavioral baselines.
//!
//! When a server is first seen, it enters learning mode. During learning:
//! - Every event updates the profile directly
//! - No anomaly scores are generated
//! - Learning ends when both thresholds are met

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use tracing::info;

use crate::config::settings::BehavioralConfig;
use crate::event::mcp::{McpEvent, McpEventKind};
use crate::event::os::{OsEvent, OsEventKind};

use super::profile::ServerProfile;

/// Manages the learning phase for behavioral baselines.
pub struct LearningEngine {
    /// Active profiles keyed by server_name.
    profiles: HashMap<String, ServerProfile>,
    /// Configuration thresholds.
    config: BehavioralConfig,
}

impl LearningEngine {
    /// Create a new learning engine with the given config.
    pub fn new(config: BehavioralConfig) -> Self {
        Self {
            profiles: HashMap::new(),
            config,
        }
    }

    /// Load existing profiles (e.g., from persistence).
    pub fn load_profiles(&mut self, profiles: Vec<ServerProfile>) {
        for p in profiles {
            self.profiles.insert(p.server_name.clone(), p);
        }
    }

    /// Get or create a profile for the given server.
    pub fn get_or_create_profile(
        &mut self,
        server_name: &str,
        client_name: &str,
    ) -> &mut ServerProfile {
        self.profiles
            .entry(server_name.to_string())
            .or_insert_with(|| ServerProfile::new(server_name.to_string(), client_name.to_string()))
    }

    /// Get a reference to a profile by server name.
    pub fn get_profile(&self, server_name: &str) -> Option<&ServerProfile> {
        self.profiles.get(server_name)
    }

    /// Get a mutable reference to a profile by server name.
    pub fn get_profile_mut(&mut self, server_name: &str) -> Option<&mut ServerProfile> {
        self.profiles.get_mut(server_name)
    }

    /// Get all profiles.
    pub fn all_profiles(&self) -> impl Iterator<Item = &ServerProfile> {
        self.profiles.values()
    }

    /// Process an MCP event, updating the relevant profile.
    /// Returns true if the profile just completed learning.
    pub fn observe_mcp_event(
        &mut self,
        server_name: &str,
        client_name: &str,
        event: &McpEvent,
    ) -> bool {
        let is_new = !self.profiles.contains_key(server_name);
        let profile = self.get_or_create_profile(server_name, client_name);
        if is_new {
            // Set first_seen from the first event's timestamp
            profile.first_seen = event.timestamp;
        }
        let was_learning = profile.learning_mode;

        profile.observation_count += 1;
        profile.last_updated = event.timestamp;

        // Update temporal profile
        update_temporal(profile, event.timestamp);

        // Update tool profile from MCP events
        match &event.kind {
            McpEventKind::ToolCall(tc) => {
                *profile
                    .tool_profile
                    .tool_counts
                    .entry(tc.tool_name.clone())
                    .or_insert(0) += 1;

                // Extract argument keys for pattern tracking
                if let Some(obj) = tc.arguments.as_object() {
                    let keys: std::collections::HashSet<String> =
                        obj.keys().cloned().collect();
                    profile
                        .tool_profile
                        .argument_patterns
                        .entry(tc.tool_name.clone())
                        .or_default()
                        .extend(keys);
                }

                // Update bigrams
                if let Some(ref last) = profile.tool_profile.last_tool {
                    *profile
                        .tool_profile
                        .sequence_bigrams
                        .entry((last.clone(), tc.tool_name.clone()))
                        .or_insert(0) += 1;
                }
                profile.tool_profile.last_tool = Some(tc.tool_name.clone());
            }
            McpEventKind::ResourceRead(rr) => {
                // Track resource reads as file-like operations
                update_file_profile_from_uri(profile, &rr.uri, true);
            }
            _ => {}
        }

        // Check if learning should complete
        if was_learning {
            return self.check_learning_complete(server_name);
        }
        false
    }

    /// Process an OS event, updating the relevant profile.
    /// Returns true if the profile just completed learning.
    pub fn observe_os_event(
        &mut self,
        server_name: &str,
        client_name: &str,
        event: &OsEvent,
    ) -> bool {
        let is_new = !self.profiles.contains_key(server_name);
        let profile = self.get_or_create_profile(server_name, client_name);
        if is_new {
            profile.first_seen = event.timestamp;
        }
        let was_learning = profile.learning_mode;

        profile.observation_count += 1;
        profile.last_updated = event.timestamp;

        // Update temporal profile
        update_temporal(profile, event.timestamp);

        match &event.kind {
            OsEventKind::Open { path, flags } => {
                let is_read = *flags & 0x3 == 0; // O_RDONLY
                update_file_profile(profile, path, is_read);
            }
            OsEventKind::Close { path } | OsEventKind::Unlink { path } => {
                update_file_profile(profile, path, false);
            }
            OsEventKind::Rename { source, dest } => {
                update_file_profile(profile, source, false);
                update_file_profile(profile, dest, false);
            }
            OsEventKind::Connect {
                address, port, ..
            } => {
                profile.network_profile.observed_hosts.insert(address.clone());
                profile.network_profile.observed_ports.insert(*port);
                profile.network_profile.has_networked = true;
            }
            _ => {}
        }

        if was_learning {
            return self.check_learning_complete(server_name);
        }
        false
    }

    /// Check if learning should complete for the given server.
    fn check_learning_complete(&mut self, server_name: &str) -> bool {
        let profile = match self.profiles.get_mut(server_name) {
            Some(p) => p,
            None => return false,
        };

        if !profile.learning_mode {
            return false;
        }

        let events_met =
            profile.observation_count >= self.config.learning_event_threshold;
        let elapsed = profile.last_updated - profile.first_seen;
        let minutes_met =
            elapsed.num_minutes() >= self.config.learning_time_minutes as i64;

        if events_met && minutes_met {
            profile.learning_mode = false;
            info!(
                server_name = %profile.server_name,
                observation_count = profile.observation_count,
                elapsed_minutes = elapsed.num_minutes(),
                "Behavioral learning phase completed"
            );
            return true;
        }
        false
    }

    /// Reset a profile back to learning mode.
    pub fn reset_profile(&mut self, server_name: &str) {
        if let Some(profile) = self.profiles.get_mut(server_name) {
            let now = Utc::now();
            profile.learning_mode = true;
            profile.observation_count = 0;
            profile.first_seen = now;
            profile.last_updated = now;
            profile.tool_profile = Default::default();
            profile.file_profile = Default::default();
            profile.network_profile = Default::default();
            profile.temporal_profile = Default::default();
        }
    }

    /// Delete a profile entirely.
    pub fn delete_profile(&mut self, server_name: &str) {
        self.profiles.remove(server_name);
    }

    /// Get a reference to the config.
    pub fn config(&self) -> &BehavioralConfig {
        &self.config
    }
}

/// Update file profile from a file path.
fn update_file_profile(profile: &mut ServerProfile, path: &str, is_read: bool) {
    // Extract directory prefix
    if let Some(parent) = Path::new(path).parent() {
        profile
            .file_profile
            .directory_prefixes
            .insert(parent.to_string_lossy().to_string());
    }

    // Extract extension
    if let Some(ext) = Path::new(path).extension() {
        *profile
            .file_profile
            .extension_counts
            .entry(ext.to_string_lossy().to_string())
            .or_insert(0) += 1;
    }

    if is_read {
        profile.file_profile.read_count += 1;
    } else {
        profile.file_profile.write_count += 1;
    }
}

/// Update file profile from a resource URI.
fn update_file_profile_from_uri(profile: &mut ServerProfile, uri: &str, is_read: bool) {
    // Strip file:// prefix if present
    let path = if let Some(stripped) = uri.strip_prefix("file://") {
        stripped
    } else {
        uri
    };
    update_file_profile(profile, path, is_read);
}

/// Update temporal profile with a new event timestamp.
fn update_temporal(profile: &mut ServerProfile, timestamp: DateTime<Utc>) {
    if let Some(last) = profile.temporal_profile.last_event_time {
        let gap_ms = (timestamp - last).num_milliseconds() as f64;
        if gap_ms >= 0.0 {
            profile.temporal_profile.gap_count += 1;
            profile.temporal_profile.gap_sum_ms += gap_ms;
            profile.temporal_profile.gap_sum_sq_ms += gap_ms * gap_ms;

            // Update running mean and stddev
            let n = profile.temporal_profile.gap_count as f64;
            profile.temporal_profile.inter_request_gap_mean_ms =
                profile.temporal_profile.gap_sum_ms / n;
            if n > 1.0 {
                let variance = (profile.temporal_profile.gap_sum_sq_ms
                    - (profile.temporal_profile.gap_sum_ms.powi(2) / n))
                    / (n - 1.0);
                profile.temporal_profile.inter_request_gap_stddev_ms =
                    if variance > 0.0 { variance.sqrt() } else { 0.0 };
            }
        }
    }
    profile.temporal_profile.last_event_time = Some(timestamp);

    // Update session duration
    let duration = (timestamp - profile.first_seen).num_seconds() as f64;
    profile.temporal_profile.typical_session_duration_secs = duration;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::BehavioralConfig;
    use crate::event::mcp::{McpEvent, McpEventKind, ToolCall};
    use crate::event::os::{OsEvent, OsEventKind};
    use chrono::{Duration, Utc};
    use serde_json::json;

    fn test_config() -> BehavioralConfig {
        BehavioralConfig {
            enabled: true,
            learning_event_threshold: 100,
            learning_time_minutes: 30,
            anomaly_threshold: 0.7,
            auto_block_threshold: 0.9,
            auto_block_enabled: false,
        }
    }

    fn make_tool_call_event(tool_name: &str, timestamp: DateTime<Utc>) -> McpEvent {
        McpEvent {
            timestamp,
            source: "mcp-proxy".to_string(),
            kind: McpEventKind::ToolCall(ToolCall {
                tool_name: tool_name.to_string(),
                arguments: json!({"path": "/tmp/test.rs"}),
                request_id: json!(1),
            }),
            raw_message: json!({}),
        }
    }

    fn make_os_open_event(path: &str, flags: u32, timestamp: DateTime<Utc>) -> OsEvent {
        OsEvent {
            timestamp,
            pid: 1234,
            ppid: 1,
            process_path: "/usr/bin/test".to_string(),
            kind: OsEventKind::Open {
                path: path.to_string(),
                flags,
            },
            signing_id: None,
            team_id: None,
        }
    }

    fn make_os_connect_event(
        address: &str,
        port: u16,
        timestamp: DateTime<Utc>,
    ) -> OsEvent {
        OsEvent {
            timestamp,
            pid: 1234,
            ppid: 1,
            process_path: "/usr/bin/test".to_string(),
            kind: OsEventKind::Connect {
                address: address.to_string(),
                port,
                protocol: "tcp".to_string(),
            },
            signing_id: None,
            team_id: None,
        }
    }

    #[test]
    fn test_learning_phase_completes_after_thresholds() {
        let mut engine = LearningEngine::new(test_config());
        let base_time = Utc::now() - Duration::minutes(31);

        // Feed 100 events spanning 31 minutes
        for i in 0..100u64 {
            let ts = base_time + Duration::seconds((i * 19) as i64); // ~19s apart
            let event = make_tool_call_event("read_file", ts);
            let completed = engine.observe_mcp_event("test-server", "test-client", &event);
            if i < 99 {
                assert!(!completed, "Should not complete at event {i}");
            } else {
                assert!(completed, "Should complete at event 99 (100th event)");
            }
        }

        let profile = engine.get_profile("test-server").unwrap();
        assert!(!profile.learning_mode);
        assert_eq!(profile.observation_count, 100);
    }

    #[test]
    fn test_learning_requires_both_thresholds() {
        let mut engine = LearningEngine::new(test_config());
        let base_time = Utc::now();

        // Feed 100 events but all within 1 minute (time threshold not met)
        for i in 0..100u64 {
            let ts = base_time + Duration::milliseconds(i as i64 * 100);
            let event = make_tool_call_event("read_file", ts);
            let completed = engine.observe_mcp_event("test-server", "test-client", &event);
            assert!(!completed, "Should not complete - time threshold not met");
        }

        let profile = engine.get_profile("test-server").unwrap();
        assert!(profile.learning_mode);
    }

    #[test]
    fn test_profile_records_tool_usage() {
        let mut engine = LearningEngine::new(test_config());
        let ts = Utc::now();

        let event1 = make_tool_call_event("read_file", ts);
        let event2 = make_tool_call_event("read_file", ts + Duration::seconds(1));
        let event3 = make_tool_call_event("write_file", ts + Duration::seconds(2));

        engine.observe_mcp_event("srv", "cli", &event1);
        engine.observe_mcp_event("srv", "cli", &event2);
        engine.observe_mcp_event("srv", "cli", &event3);

        let profile = engine.get_profile("srv").unwrap();
        assert_eq!(profile.tool_profile.tool_counts["read_file"], 2);
        assert_eq!(profile.tool_profile.tool_counts["write_file"], 1);
        assert!(profile
            .tool_profile
            .argument_patterns
            .get("read_file")
            .unwrap()
            .contains("path"));
    }

    #[test]
    fn test_profile_records_bigrams() {
        let mut engine = LearningEngine::new(test_config());
        let ts = Utc::now();

        engine.observe_mcp_event(
            "srv",
            "cli",
            &make_tool_call_event("read_file", ts),
        );
        engine.observe_mcp_event(
            "srv",
            "cli",
            &make_tool_call_event("write_file", ts + Duration::seconds(1)),
        );

        let profile = engine.get_profile("srv").unwrap();
        let bigram_key = ("read_file".to_string(), "write_file".to_string());
        assert_eq!(profile.tool_profile.sequence_bigrams[&bigram_key], 1);
    }

    #[test]
    fn test_profile_records_file_operations() {
        let mut engine = LearningEngine::new(test_config());
        let ts = Utc::now();

        // O_RDONLY = 0
        engine.observe_os_event(
            "srv",
            "cli",
            &make_os_open_event("/home/user/project/src/main.rs", 0, ts),
        );
        // O_WRONLY = 1
        engine.observe_os_event(
            "srv",
            "cli",
            &make_os_open_event("/home/user/project/src/lib.rs", 1, ts + Duration::seconds(1)),
        );

        let profile = engine.get_profile("srv").unwrap();
        assert!(profile
            .file_profile
            .directory_prefixes
            .contains("/home/user/project/src"));
        assert_eq!(profile.file_profile.extension_counts["rs"], 2);
        assert_eq!(profile.file_profile.read_count, 1);
        assert_eq!(profile.file_profile.write_count, 1);
    }

    #[test]
    fn test_profile_records_network_activity() {
        let mut engine = LearningEngine::new(test_config());
        let ts = Utc::now();

        engine.observe_os_event(
            "srv",
            "cli",
            &make_os_connect_event("api.example.com", 443, ts),
        );

        let profile = engine.get_profile("srv").unwrap();
        assert!(profile.network_profile.has_networked);
        assert!(profile.network_profile.observed_hosts.contains("api.example.com"));
        assert!(profile.network_profile.observed_ports.contains(&443));
    }

    #[test]
    fn test_temporal_profile_tracks_gaps() {
        let mut engine = LearningEngine::new(test_config());
        let ts = Utc::now();

        engine.observe_mcp_event(
            "srv",
            "cli",
            &make_tool_call_event("a", ts),
        );
        engine.observe_mcp_event(
            "srv",
            "cli",
            &make_tool_call_event("b", ts + Duration::seconds(2)),
        );
        engine.observe_mcp_event(
            "srv",
            "cli",
            &make_tool_call_event("c", ts + Duration::seconds(4)),
        );

        let profile = engine.get_profile("srv").unwrap();
        assert_eq!(profile.temporal_profile.gap_count, 2);
        assert!((profile.temporal_profile.inter_request_gap_mean_ms - 2000.0).abs() < 1.0);
    }

    #[test]
    fn test_reset_profile() {
        let mut engine = LearningEngine::new(test_config());
        let ts = Utc::now();

        engine.observe_mcp_event(
            "srv",
            "cli",
            &make_tool_call_event("read_file", ts),
        );

        let profile = engine.get_profile("srv").unwrap();
        assert_eq!(profile.observation_count, 1);

        engine.reset_profile("srv");

        let profile = engine.get_profile("srv").unwrap();
        assert_eq!(profile.observation_count, 0);
        assert!(profile.learning_mode);
        assert!(profile.tool_profile.tool_counts.is_empty());
    }
}
