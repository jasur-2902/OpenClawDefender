//! Behavioral Engine Test Harness
//!
//! Simulates a realistic filesystem-server session with a learning phase,
//! normal operation, and a compromise scenario. Measures detection latency,
//! false positive rate, true positive rate, and kill chain pattern detection.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use clawdefender_core::behavioral::*;
use clawdefender_core::config::settings::BehavioralConfig;
use clawdefender_core::event::mcp::{McpEvent, McpEventKind, ToolCall};
use clawdefender_core::event::os::{OsEvent, OsEventKind};
use serde_json::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn make_tool_call(tool_name: &str, path: &str, ts: DateTime<Utc>) -> McpEvent {
    McpEvent {
        timestamp: ts,
        source: "mcp-proxy".to_string(),
        kind: McpEventKind::ToolCall(ToolCall {
            tool_name: tool_name.to_string(),
            arguments: json!({"path": path}),
            request_id: json!(1),
        }),
        raw_message: json!({}),
    }
}

fn make_os_open(path: &str, flags: u32, ts: DateTime<Utc>) -> OsEvent {
    OsEvent {
        timestamp: ts,
        pid: 1234,
        ppid: 1,
        process_path: "/usr/bin/node".to_string(),
        kind: OsEventKind::Open {
            path: path.to_string(),
            flags,
        },
        signing_id: None,
        team_id: None,
    }
}

fn make_os_connect(address: &str, port: u16, ts: DateTime<Utc>) -> OsEvent {
    OsEvent {
        timestamp: ts,
        pid: 1234,
        ppid: 1,
        process_path: "/usr/bin/node".to_string(),
        kind: OsEventKind::Connect {
            address: address.to_string(),
            port,
            protocol: "tcp".to_string(),
        },
        signing_id: None,
        team_id: None,
    }
}

/// Normal file paths used during the learning and stable phases.
const NORMAL_TOOLS: &[&str] = &["read_file", "list_directory", "write_file"];
const NORMAL_DIRS: &[&str] = &[
    "/home/user/Projects/webapp/src",
    "/home/user/Projects/webapp/tests",
    "/home/user/Projects/api/src",
];
const NORMAL_EXTENSIONS: &[&str] = &[".ts", ".json", ".rs"];

fn normal_file_path(i: u64) -> String {
    let dir = NORMAL_DIRS[(i as usize) % NORMAL_DIRS.len()];
    let ext = NORMAL_EXTENSIONS[(i as usize) % NORMAL_EXTENSIONS.len()];
    format!("{}/file_{}{}", dir, i % 20, ext)
}

fn normal_tool(i: u64) -> &'static str {
    NORMAL_TOOLS[(i as usize) % NORMAL_TOOLS.len()]
}

// ---------------------------------------------------------------------------
// Test: Full simulation — learning + normal + compromise
// ---------------------------------------------------------------------------

#[test]
fn test_harness_full_simulation() {
    let config = test_config();
    let mut engine = LearningEngine::new(config);
    let scorer = AnomalyScorer::new();
    let mut kc_detector = KillChainDetector::new();

    let base_time = Utc::now() - Duration::hours(2);
    let server = "filesystem-server";
    let client = "test-client";

    // -----------------------------------------------------------------------
    // Phase 1: Learning — first 200 events (spanning 31+ minutes)
    // -----------------------------------------------------------------------
    for i in 0..200u64 {
        let ts = base_time + Duration::seconds((i * 10) as i64); // 10s apart
        let tool = normal_tool(i);
        let path = normal_file_path(i);
        let event = make_tool_call(tool, &path, ts);
        engine.observe_mcp_event(server, client, &event);

        // Also feed corresponding OS events for file access
        let os_event = make_os_open(&path, 0, ts);
        engine.observe_os_event(server, client, &os_event);
    }

    let profile = engine.get_profile(server).unwrap();
    assert!(
        !profile.learning_mode,
        "Learning should be complete after 200 events spanning {}s",
        200 * 10
    );

    // -----------------------------------------------------------------------
    // Phase 2: Normal operation — events 201..500
    // -----------------------------------------------------------------------
    let mut false_positives = 0u64;
    let normal_start_idx = 200u64;
    let normal_end_idx = 500u64;

    for i in normal_start_idx..normal_end_idx {
        let ts = base_time + Duration::seconds((i * 10) as i64);
        let tool = normal_tool(i);
        let path = normal_file_path(i);

        // Feed into learning engine for profile updates
        let mcp_event = make_tool_call(tool, &path, ts);
        engine.observe_mcp_event(server, client, &mcp_event);

        // Score the event
        let profile = engine.get_profile(server).unwrap();
        let behavioral_event = BehavioralEvent {
            event_type: BehavioralEventType::FileAccess {
                path: path.clone(),
                is_write: tool == "write_file",
            },
            server_name: server.to_string(),
            timestamp: ts,
        };

        if let Some(score) = scorer.score(&behavioral_event, profile) {
            if score.total >= 0.7 {
                false_positives += 1;
            }
        }
    }

    let total_normal = normal_end_idx - normal_start_idx;
    let fp_rate = false_positives as f64 / total_normal as f64;
    assert!(
        fp_rate == 0.0,
        "False positive rate during normal events: {:.2}% ({}/{}) — should be 0%",
        fp_rate * 100.0,
        false_positives,
        total_normal
    );

    // -----------------------------------------------------------------------
    // Phase 3: Compromise — events 500+
    // The server reads sensitive files then makes network connections.
    // -----------------------------------------------------------------------
    let compromise_start_idx = 500u64;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());

    // Sensitive file access sequence
    let sensitive_paths = vec![
        format!("{}/.ssh/id_rsa", home),
        format!("{}/.aws/credentials", home),
        format!("{}/.gnupg/secring.gpg", home),
        format!("{}/.kube/config", home),
    ];

    let mut first_detection_offset: Option<u64> = None;
    let mut true_positives = 0u64;
    let mut total_compromised = 0u64;

    // Feed sensitive file reads
    for (j, path) in sensitive_paths.iter().enumerate() {
        let i = compromise_start_idx + j as u64;
        let ts = base_time + Duration::seconds((i * 10) as i64);

        // Feed OS event for file read
        let os_event = make_os_open(path, 0, ts);
        engine.observe_os_event(server, client, &os_event);

        // Score as file access
        let profile = engine.get_profile(server).unwrap();
        let behavioral_event = BehavioralEvent {
            event_type: BehavioralEventType::FileAccess {
                path: path.clone(),
                is_write: false,
            },
            server_name: server.to_string(),
            timestamp: ts,
        };

        total_compromised += 1;
        if let Some(score) = scorer.score(&behavioral_event, profile) {
            if score.total >= 0.7 {
                true_positives += 1;
                if first_detection_offset.is_none() {
                    first_detection_offset = Some(j as u64);
                }
            }
        }

        // Feed into kill chain detector
        let kc_event = KillChainEvent {
            event_type: killchain::StepEventType::FileRead,
            path: Some(path.clone()),
            destination: None,
            server_name: server.to_string(),
        };
        kc_detector.ingest(kc_event, ts);
    }

    // Network connections after credential reads
    let network_targets = vec![
        ("c2.attacker.com", 4444u16),
        ("evil.example.org", 8080u16),
    ];

    for (j, (host, port)) in network_targets.iter().enumerate() {
        let i = compromise_start_idx + sensitive_paths.len() as u64 + j as u64;
        let ts = base_time + Duration::seconds((i * 10) as i64);

        let os_event = make_os_connect(host, *port, ts);
        engine.observe_os_event(server, client, &os_event);

        let profile = engine.get_profile(server).unwrap();
        let behavioral_event = BehavioralEvent {
            event_type: BehavioralEventType::NetworkConnect {
                host: host.to_string(),
                port: *port,
            },
            server_name: server.to_string(),
            timestamp: ts,
        };

        total_compromised += 1;
        if let Some(score) = scorer.score(&behavioral_event, profile) {
            if score.total >= 0.7 {
                true_positives += 1;
                if first_detection_offset.is_none() {
                    first_detection_offset = Some(sensitive_paths.len() as u64 + j as u64);
                }
            }
        }

        // Feed into kill chain detector
        let kc_event = KillChainEvent {
            event_type: killchain::StepEventType::NetworkConnect,
            path: None,
            destination: Some(host.to_string()),
            server_name: server.to_string(),
        };
        let kc_matches = kc_detector.ingest(kc_event, ts);

        // After credential read + network connect, kill chain should fire
        if j == 0 {
            let cred_theft = kc_matches
                .iter()
                .find(|m| m.pattern.name == "credential_theft_exfiltration");
            assert!(
                cred_theft.is_some(),
                "Kill chain should detect credential_theft_exfiltration after \
                 sensitive file read + network connect"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Assertions
    // -----------------------------------------------------------------------

    // Detection latency: should detect within 5 events of behavioral change
    assert!(
        first_detection_offset.is_some(),
        "Behavioral engine should detect the compromise"
    );
    let latency = first_detection_offset.unwrap();
    assert!(
        latency <= 5,
        "Detection latency: {} events — should be <= 5",
        latency
    );

    // True positive rate
    let tp_rate = true_positives as f64 / total_compromised as f64;
    assert!(
        tp_rate >= 0.5,
        "True positive rate: {:.2}% ({}/{}) — should be >= 50%",
        tp_rate * 100.0,
        true_positives,
        total_compromised
    );
}

// ---------------------------------------------------------------------------
// Test: Detection latency for sensitive file access
// ---------------------------------------------------------------------------

#[test]
fn test_detection_latency_sensitive_file() {
    let scorer = AnomalyScorer::new();

    // Build an established profile with known territory
    let profile = build_established_profile();

    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
    let ssh_path = format!("{}/.ssh/id_rsa", home);

    let event = BehavioralEvent {
        event_type: BehavioralEventType::FileAccess {
            path: ssh_path,
            is_write: false,
        },
        server_name: "filesystem-server".to_string(),
        timestamp: Utc::now(),
    };

    let score = scorer.score(&event, &profile).unwrap();
    assert!(
        score.total >= 0.7,
        "Sensitive file access should immediately trigger anomaly >= 0.7, got {:.2}",
        score.total
    );
}

// ---------------------------------------------------------------------------
// Test: Detection latency for first network access
// ---------------------------------------------------------------------------

#[test]
fn test_detection_latency_first_network() {
    let scorer = AnomalyScorer::new();
    let mut profile = build_established_profile();
    profile.network_profile.has_networked = false;
    profile.network_profile.observed_hosts.clear();
    profile.network_profile.observed_ports.clear();

    let event = BehavioralEvent {
        event_type: BehavioralEventType::NetworkConnect {
            host: "evil.com".to_string(),
            port: 4444,
        },
        server_name: "filesystem-server".to_string(),
        timestamp: Utc::now(),
    };

    let score = scorer.score(&event, &profile).unwrap();
    assert!(
        score.total >= 0.7,
        "First network access should trigger anomaly >= 0.7, got {:.2}",
        score.total
    );
}

// ---------------------------------------------------------------------------
// Test: Zero false positives during well-established normal operation
// ---------------------------------------------------------------------------

#[test]
fn test_zero_false_positives_normal_territory() {
    let scorer = AnomalyScorer::new();
    let profile = build_established_profile();

    // Test 100 normal file access events within known territory
    for i in 0..100 {
        let path = normal_file_path(i);
        let event = BehavioralEvent {
            event_type: BehavioralEventType::FileAccess {
                path,
                is_write: i % 3 == 0,
            },
            server_name: "filesystem-server".to_string(),
            timestamp: Utc::now(),
        };

        if let Some(score) = scorer.score(&event, &profile) {
            assert!(
                score.total < 0.7,
                "Normal event {} should score < 0.7, got {:.2}: {}",
                i,
                score.total,
                score.explanation
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test: Kill chain detection with full credential theft scenario
// ---------------------------------------------------------------------------

#[test]
fn test_kill_chain_credential_theft_full_scenario() {
    let mut detector = KillChainDetector::new();
    let now = Utc::now();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());

    // Step 1: Read SSH key
    detector.ingest(
        KillChainEvent {
            event_type: killchain::StepEventType::FileRead,
            path: Some(format!("{}/.ssh/id_rsa", home)),
            destination: None,
            server_name: "fs-server".to_string(),
        },
        now,
    );

    // Step 2: Read AWS credentials
    detector.ingest(
        KillChainEvent {
            event_type: killchain::StepEventType::FileRead,
            path: Some(format!("{}/.aws/credentials", home)),
            destination: None,
            server_name: "fs-server".to_string(),
        },
        now + Duration::seconds(5),
    );

    // Step 3: Network connect to external host
    let matches = detector.ingest(
        KillChainEvent {
            event_type: killchain::StepEventType::NetworkConnect,
            path: None,
            destination: Some("c2.attacker.com".to_string()),
            server_name: "fs-server".to_string(),
        },
        now + Duration::seconds(15),
    );

    // Should detect credential_theft_exfiltration pattern
    let cred_theft = matches
        .iter()
        .find(|m| m.pattern.name == "credential_theft_exfiltration");
    assert!(
        cred_theft.is_some(),
        "Should detect credential theft exfiltration pattern"
    );
    assert_eq!(
        cred_theft.unwrap().severity,
        killchain::Severity::Critical
    );
}

// ---------------------------------------------------------------------------
// Test: Data staging + exfiltration kill chain
// ---------------------------------------------------------------------------

#[test]
fn test_kill_chain_data_staging_exfiltration() {
    let mut detector = KillChainDetector::new();
    let now = Utc::now();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());

    // 3 credential reads
    for (i, name) in ["id_rsa", "credentials", "config"].iter().enumerate() {
        let path = if *name == "id_rsa" {
            format!("{}/.ssh/{}", home, name)
        } else if *name == "credentials" {
            format!("{}/.aws/{}", home, name)
        } else {
            format!("{}/.kube/{}", home, name)
        };

        detector.ingest(
            KillChainEvent {
                event_type: killchain::StepEventType::FileRead,
                path: Some(path),
                destination: None,
                server_name: "srv".to_string(),
            },
            now + Duration::seconds(i as i64 * 3),
        );
    }

    // Write to /tmp
    detector.ingest(
        KillChainEvent {
            event_type: killchain::StepEventType::FileWrite,
            path: Some("/tmp/exfil.tar.gz".to_string()),
            destination: None,
            server_name: "srv".to_string(),
        },
        now + Duration::seconds(20),
    );

    // Network connect
    let matches = detector.ingest(
        KillChainEvent {
            event_type: killchain::StepEventType::NetworkConnect,
            path: None,
            destination: Some("exfil.evil.com".to_string()),
            server_name: "srv".to_string(),
        },
        now + Duration::seconds(30),
    );

    let staging = matches
        .iter()
        .find(|m| m.pattern.name == "data_staging_exfiltration");
    assert!(
        staging.is_some(),
        "Should detect data staging exfiltration pattern"
    );
}

// ---------------------------------------------------------------------------
// Test: Profile evolution through learning and post-learning
// ---------------------------------------------------------------------------

#[test]
fn test_profile_evolution_through_phases() {
    let config = test_config();
    let mut engine = LearningEngine::new(config);
    let scorer = AnomalyScorer::new();

    let base_time = Utc::now() - Duration::minutes(35);
    let server = "evolution-server";

    // Phase 1: Learning (should return None for anomaly scores)
    for i in 0..50u64 {
        let ts = base_time + Duration::seconds((i * 10) as i64);
        let event = make_tool_call("read_file", "/home/user/Projects/src/main.rs", ts);
        engine.observe_mcp_event(server, "client", &event);
    }

    let profile = engine.get_profile(server).unwrap();
    assert!(profile.learning_mode, "Should still be in learning mode at 50 events");

    let test_event = BehavioralEvent {
        event_type: BehavioralEventType::FileAccess {
            path: "/home/user/.ssh/id_rsa".to_string(),
            is_write: false,
        },
        server_name: server.to_string(),
        timestamp: Utc::now(),
    };
    assert!(
        scorer.score(&test_event, profile).is_none(),
        "Should return None during learning mode"
    );

    // Complete learning
    for i in 50..105u64 {
        let ts = base_time + Duration::seconds((i * 25) as i64);
        let event = make_tool_call("read_file", "/home/user/Projects/src/main.rs", ts);
        engine.observe_mcp_event(server, "client", &event);
    }

    let profile = engine.get_profile(server).unwrap();
    assert!(
        !profile.learning_mode,
        "Learning should be complete after 105 events spanning 43+ minutes"
    );

    // Phase 2: Post-learning — anomaly scores should now be produced
    let score = scorer.score(&test_event, profile);
    assert!(
        score.is_some(),
        "Should produce anomaly scores after learning"
    );
    assert!(
        score.unwrap().total >= 0.7,
        "Sensitive file access should score high after learning"
    );
}

// ---------------------------------------------------------------------------
// Test: Multiple anomaly dimensions fire simultaneously
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_anomaly_dimensions() {
    let scorer = AnomalyScorer::new();
    let mut profile = build_established_profile();
    profile.network_profile.has_networked = false;
    profile.network_profile.observed_hosts.clear();
    profile.network_profile.observed_ports.clear();

    // Network event on a non-networked server
    let event = BehavioralEvent {
        event_type: BehavioralEventType::NetworkConnect {
            host: "c2.evil.com".to_string(),
            port: 4444,
        },
        server_name: "filesystem-server".to_string(),
        timestamp: Utc::now(),
    };

    let score = scorer.score(&event, &profile).unwrap();

    // Both UnknownNetwork and FirstNetworkAccess should fire
    let dimensions: Vec<_> = score
        .components
        .iter()
        .filter(|c| c.score > 0.0)
        .map(|c| c.dimension)
        .collect();

    assert!(
        dimensions.contains(&AnomalyDimension::UnknownNetwork),
        "UnknownNetwork dimension should fire"
    );
    assert!(
        dimensions.contains(&AnomalyDimension::FirstNetworkAccess),
        "FirstNetworkAccess dimension should fire"
    );
    assert!(
        score.total >= 0.7,
        "Combined score should be >= 0.7, got {:.2}",
        score.total
    );
}

// ---------------------------------------------------------------------------
// Test: Unknown tool detection
// ---------------------------------------------------------------------------

#[test]
fn test_unknown_tool_triggers_high_score() {
    let scorer = AnomalyScorer::new();
    let profile = build_established_profile();

    let event = BehavioralEvent {
        event_type: BehavioralEventType::ToolCall {
            tool_name: "execute_shell_command".to_string(),
            arguments: HashMap::new(),
        },
        server_name: "filesystem-server".to_string(),
        timestamp: Utc::now(),
    };

    let score = scorer.score(&event, &profile).unwrap();
    assert!(
        score.total >= 0.7,
        "Unknown tool should trigger anomaly >= 0.7, got {:.2}",
        score.total
    );
}

// ---------------------------------------------------------------------------
// Test: Anomaly scorer explanation quality
// ---------------------------------------------------------------------------

#[test]
fn test_anomaly_explanation_contains_useful_info() {
    let scorer = AnomalyScorer::new();
    let profile = build_established_profile();

    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
    let event = BehavioralEvent {
        event_type: BehavioralEventType::FileAccess {
            path: format!("{}/.ssh/id_rsa", home),
            is_write: false,
        },
        server_name: "filesystem-server".to_string(),
        timestamp: Utc::now(),
    };

    let score = scorer.score(&event, &profile).unwrap();
    assert!(
        !score.explanation.is_empty(),
        "Explanation should not be empty"
    );
    assert!(
        score.explanation.contains("Anomaly score"),
        "Explanation should mention anomaly score"
    );
}

// ---------------------------------------------------------------------------
// Shared helper: build an established profile
// ---------------------------------------------------------------------------

fn build_established_profile() -> ServerProfile {
    let mut tool_counts = HashMap::new();
    tool_counts.insert("read_file".to_string(), 200);
    tool_counts.insert("write_file".to_string(), 150);
    tool_counts.insert("list_directory".to_string(), 100);

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
    bigrams.insert(("read_file".to_string(), "write_file".to_string()), 80u64);
    bigrams.insert(("list_directory".to_string(), "read_file".to_string()), 60);

    let mut dir_prefixes = HashSet::new();
    dir_prefixes.insert("/home/user/Projects/webapp/src".to_string());
    dir_prefixes.insert("/home/user/Projects/webapp/tests".to_string());
    dir_prefixes.insert("/home/user/Projects/api/src".to_string());

    let mut ext_counts = HashMap::new();
    ext_counts.insert("ts".to_string(), 300);
    ext_counts.insert("json".to_string(), 100);
    ext_counts.insert("rs".to_string(), 200);

    ServerProfile {
        server_name: "filesystem-server".to_string(),
        client_name: "test-client".to_string(),
        first_seen: Utc::now() - Duration::hours(4),
        last_updated: Utc::now(),
        learning_mode: false,
        observation_count: 5000,
        tool_profile: ToolProfile {
            tool_counts,
            argument_patterns,
            call_rate: 5.0,
            sequence_bigrams: bigrams,
            last_tool: Some("read_file".to_string()),
        },
        file_profile: FileProfile {
            directory_prefixes: dir_prefixes,
            extension_counts: ext_counts,
            read_count: 3000,
            write_count: 1500,
            peak_ops_rate: 12.0,
        },
        network_profile: NetworkProfile {
            observed_hosts: HashSet::new(),
            observed_ports: HashSet::new(),
            request_rate: 0.0,
            has_networked: false,
        },
        temporal_profile: TemporalProfile {
            typical_session_duration_secs: 7200.0,
            inter_request_gap_mean_ms: 500.0,
            inter_request_gap_stddev_ms: 100.0,
            burst_size_mean: 3.0,
            burst_size_stddev: 1.0,
            last_event_time: Some(Utc::now() - Duration::milliseconds(500)),
            gap_count: 200,
            gap_sum_ms: 100000.0,
            gap_sum_sq_ms: 60000000.0,
        },
    }
}
