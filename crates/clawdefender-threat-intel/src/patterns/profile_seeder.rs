//! Pre-seeded behavioral profile loading.
//!
//! When a known MCP server starts for the first time, initialize its behavioral
//! profile with pre-seeded data from the threat feed so anomaly detection works
//! immediately without waiting for the learning phase to complete. Learning
//! still continues to refine the profile.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::types::PreSeededProfile;

// ---------------------------------------------------------------------------
// Feed format for profile bundles
// ---------------------------------------------------------------------------

/// A collection of pre-seeded profiles as delivered by the threat feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileBundle {
    pub version: String,
    pub profiles: Vec<PreSeededProfile>,
}

// ---------------------------------------------------------------------------
// ProfileSeeder
// ---------------------------------------------------------------------------

/// Loads and serves pre-seeded behavioral profiles for known server packages.
#[derive(Debug, Clone, Default)]
pub struct ProfileSeeder {
    profiles: HashMap<String, PreSeededProfile>,
}

impl ProfileSeeder {
    /// Create a new empty seeder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load profiles from a feed bundle.
    pub fn load_from_bundle(&mut self, bundle: &ProfileBundle) {
        for profile in &bundle.profiles {
            self.profiles
                .insert(profile.server_package.clone(), profile.clone());
        }
    }

    /// Load profiles from JSON data.
    pub fn load_from_json(&mut self, json: &str) -> Result<(), serde_json::Error> {
        let bundle: ProfileBundle = serde_json::from_str(json)?;
        self.load_from_bundle(&bundle);
        Ok(())
    }

    /// Get a pre-seeded profile for a server package.
    pub fn get_profile(&self, server_package: &str) -> Option<&PreSeededProfile> {
        self.profiles.get(server_package)
    }

    /// Return the number of loaded profiles.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Return whether there are no loaded profiles.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Convert a pre-seeded profile into a `SeededServerProfile` suitable for
    /// initializing the core `ServerProfile`.
    ///
    /// The resulting profile has `learning_mode = true` so the learning engine
    /// continues to refine the baseline, but the pre-seeded data provides
    /// immediate anomaly detection capability.
    pub fn to_server_profile(
        pre_seeded: &PreSeededProfile,
        server_name: &str,
    ) -> SeededServerProfile {
        let now = chrono::Utc::now();

        // Build tool profile from expected tools.
        let mut tool_counts = HashMap::new();
        for tool in &pre_seeded.expected_tools {
            // Start with a baseline count so the tool is recognized.
            tool_counts.insert(tool.clone(), 10);
        }

        // Build file territory.
        let directory_prefixes: HashSet<String> =
            pre_seeded.expected_file_territory.iter().cloned().collect();

        SeededServerProfile {
            server_name: server_name.to_string(),
            client_name: String::new(),
            first_seen: now,
            last_updated: now,
            learning_mode: true,
            observation_count: 0,
            tool_counts,
            directory_prefixes,
            has_networked: pre_seeded.expected_network,
            inter_request_gap_mean_ms: pre_seeded.expected_rate.mean_ms,
            inter_request_gap_stddev_ms: pre_seeded.expected_rate.stddev_ms,
        }
    }
}

/// A server profile produced by the seeder, carrying pre-populated baseline
/// data. The integration layer (Agent 7) converts this to the core
/// `ServerProfile` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeededServerProfile {
    pub server_name: String,
    pub client_name: String,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub learning_mode: bool,
    pub observation_count: u64,
    pub tool_counts: HashMap<String, u64>,
    pub directory_prefixes: HashSet<String>,
    pub has_networked: bool,
    pub inter_request_gap_mean_ms: f64,
    pub inter_request_gap_stddev_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::types::RateStats;

    fn sample_bundle() -> ProfileBundle {
        ProfileBundle {
            version: "1.0.0".into(),
            profiles: vec![
                PreSeededProfile {
                    server_package: "filesystem-server".into(),
                    profile_version: "1.0.0".into(),
                    expected_tools: vec![
                        "read_file".into(),
                        "write_file".into(),
                        "list_directory".into(),
                    ],
                    expected_file_territory: vec!["/home".into(), "/tmp".into()],
                    expected_network: false,
                    expected_shell: false,
                    expected_rate: RateStats {
                        mean_ms: 500.0,
                        stddev_ms: 200.0,
                    },
                    notes: "Standard filesystem server".into(),
                },
                PreSeededProfile {
                    server_package: "github-mcp".into(),
                    profile_version: "1.0.0".into(),
                    expected_tools: vec!["create_issue".into(), "search_repos".into()],
                    expected_file_territory: vec![],
                    expected_network: true,
                    expected_shell: false,
                    expected_rate: RateStats {
                        mean_ms: 2000.0,
                        stddev_ms: 1000.0,
                    },
                    notes: "GitHub API server".into(),
                },
            ],
        }
    }

    #[test]
    fn test_load_from_bundle() {
        let mut seeder = ProfileSeeder::new();
        seeder.load_from_bundle(&sample_bundle());
        assert_eq!(seeder.len(), 2);
    }

    #[test]
    fn test_get_profile() {
        let mut seeder = ProfileSeeder::new();
        seeder.load_from_bundle(&sample_bundle());

        let fs = seeder.get_profile("filesystem-server").unwrap();
        assert_eq!(fs.expected_tools.len(), 3);
        assert!(!fs.expected_network);

        let gh = seeder.get_profile("github-mcp").unwrap();
        assert!(gh.expected_network);

        assert!(seeder.get_profile("unknown-server").is_none());
    }

    #[test]
    fn test_to_server_profile_learning_mode() {
        let mut seeder = ProfileSeeder::new();
        seeder.load_from_bundle(&sample_bundle());
        let pre_seeded = seeder.get_profile("filesystem-server").unwrap();
        let profile = ProfileSeeder::to_server_profile(pre_seeded, "my-fs-server");

        assert!(profile.learning_mode, "Seeded profile should have learning_mode=true");
        assert_eq!(profile.server_name, "my-fs-server");
        assert!(profile.tool_counts.contains_key("read_file"));
        assert!(profile.directory_prefixes.contains("/home"));
        assert!(!profile.has_networked);
    }

    #[test]
    fn test_to_server_profile_network_server() {
        let mut seeder = ProfileSeeder::new();
        seeder.load_from_bundle(&sample_bundle());
        let pre_seeded = seeder.get_profile("github-mcp").unwrap();
        let profile = ProfileSeeder::to_server_profile(pre_seeded, "gh-server");

        assert!(profile.has_networked);
        assert!(profile.learning_mode);
        assert!((profile.inter_request_gap_mean_ms - 2000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_load_from_json() {
        let json = serde_json::to_string(&sample_bundle()).unwrap();
        let mut seeder = ProfileSeeder::new();
        seeder.load_from_json(&json).unwrap();
        assert_eq!(seeder.len(), 2);
    }
}
