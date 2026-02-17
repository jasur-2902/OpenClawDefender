//! Integration tests for the sensor correlation pipeline.
//!
//! These tests exercise the full correlation flow without requiring
//! sudo, FDA, or a running eslogger process.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::json;
use tokio::sync::{mpsc, RwLock};

use clawdefender_core::event::correlation::{CorrelatedEvent, CorrelationStatus};
use clawdefender_core::event::mcp::{McpEvent, McpEventKind, ResourceRead, ToolCall};
use clawdefender_core::event::os::{OsEvent, OsEventKind};
use clawdefender_sensor::correlation::engine::{
    CorrelationConfig, CorrelationEngine, CorrelationInput,
};
use clawdefender_sensor::proctree::{ProcessInfo, ProcessTree};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_process_tree(server_pid: u32, child_pid: u32) -> ProcessTree {
    let mut tree = ProcessTree::new();
    tree.insert(ProcessInfo {
        pid: server_pid,
        ppid: 1,
        name: "node".into(),
        path: "/usr/bin/node".into(),
        args: vec![],
        start_time: None,
    });
    tree.insert(ProcessInfo {
        pid: child_pid,
        ppid: server_pid,
        name: "bash".into(),
        path: "/bin/bash".into(),
        args: vec![],
        start_time: None,
    });
    tree
}

fn make_tool_call(tool_name: &str, arguments: serde_json::Value) -> McpEvent {
    McpEvent {
        timestamp: Utc::now(),
        source: "mcp-proxy".into(),
        kind: McpEventKind::ToolCall(ToolCall {
            tool_name: tool_name.into(),
            arguments,
            request_id: json!(1),
        }),
        raw_message: json!({}),
    }
}

fn make_resource_read(uri: &str) -> McpEvent {
    McpEvent {
        timestamp: Utc::now(),
        source: "mcp-proxy".into(),
        kind: McpEventKind::ResourceRead(ResourceRead {
            uri: uri.into(),
            request_id: json!(1),
        }),
        raw_message: json!({}),
    }
}

fn make_os_exec(pid: u32, ppid: u32, target: &str, args: Vec<&str>) -> OsEvent {
    OsEvent {
        timestamp: Utc::now(),
        pid,
        ppid,
        process_path: "/bin/bash".into(),
        kind: OsEventKind::Exec {
            target_path: target.into(),
            args: args.into_iter().map(String::from).collect(),
        },
        signing_id: None,
        team_id: None,
    }
}

#[allow(dead_code)]
fn make_os_connect(pid: u32, ppid: u32, address: &str, port: u16) -> OsEvent {
    OsEvent {
        timestamp: Utc::now(),
        pid,
        ppid,
        process_path: "/usr/bin/curl".into(),
        kind: OsEventKind::Connect {
            address: address.into(),
            port,
            protocol: "tcp".into(),
        },
        signing_id: None,
        team_id: None,
    }
}

fn make_os_open(pid: u32, ppid: u32, path: &str) -> OsEvent {
    OsEvent {
        timestamp: Utc::now(),
        pid,
        ppid,
        process_path: "/usr/bin/cat".into(),
        kind: OsEventKind::Open {
            path: path.into(),
            flags: 0,
        },
        signing_id: None,
        team_id: None,
    }
}

fn test_config(server_pid: u32) -> CorrelationConfig {
    CorrelationConfig {
        match_window: Duration::from_secs(5),
        max_mcp_window: 100,
        max_os_window: 1000,
        window_duration: Duration::from_secs(10),
        server_pid,
        project_dir: Some("/Users/dev/project".into()),
        dedup_window: Duration::from_secs(1),
    }
}

// ---------------------------------------------------------------------------
// Test: End-to-end correlation flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn correlation_end_to_end_tool_call_to_exec_and_connect() {
    let server_pid = 100;
    let child_pid = 200;

    let (tx, mut rx) = mpsc::channel::<CorrelatedEvent>(100);
    let config = CorrelationConfig {
        match_window: Duration::from_millis(50),
        server_pid,
        ..test_config(server_pid)
    };
    let mut engine = CorrelationEngine::new(config, tx);
    let tree = make_process_tree(server_pid, child_pid);

    // MCP ToolCall for run_command("curl http://example.com")
    let mcp = make_tool_call(
        "run_command",
        json!({"command": "curl http://example.com"}),
    );
    engine.process_mcp_event(mcp, &tree);

    // Matching eslogger exec event for /usr/bin/curl from agent child
    let os_exec = make_os_exec(
        child_pid,
        server_pid,
        "/usr/bin/curl",
        vec!["curl", "http://example.com"],
    );
    engine.process_os_event(os_exec, &tree);

    // Wait for correlation window to expire and tick
    tokio::time::sleep(Duration::from_millis(100)).await;
    engine.tick();

    // Verify correlated event with status Matched
    let event = rx.try_recv().expect("should have correlated event");
    assert_eq!(event.status, CorrelationStatus::Matched);
    assert!(event.mcp_event.is_some());
    assert!(!event.os_events.is_empty());
}

// ---------------------------------------------------------------------------
// Test: Uncorrelated activity detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn uncorrelated_os_event_from_agent_pid() {
    let server_pid = 100;
    let child_pid = 200;

    let (tx, mut rx) = mpsc::channel::<CorrelatedEvent>(100);
    let config = CorrelationConfig {
        match_window: Duration::from_millis(50),
        server_pid,
        project_dir: Some("/Users/dev/project".into()),
        ..test_config(server_pid)
    };
    let mut engine = CorrelationEngine::new(config, tx);
    let tree = make_process_tree(server_pid, child_pid);

    // OS connect event from agent PID with NO preceding MCP event
    let os = OsEvent {
        timestamp: Utc::now() - chrono::Duration::milliseconds(100),
        pid: child_pid,
        ppid: server_pid,
        process_path: "/usr/bin/curl".into(),
        kind: OsEventKind::Connect {
            address: "evil.example.com".into(),
            port: 443,
            protocol: "tcp".into(),
        },
        signing_id: None,
        team_id: None,
    };
    engine.process_os_event(os, &tree);
    assert_eq!(engine.pending_os_count(), 1);

    // Wait for correlation window to expire
    tokio::time::sleep(Duration::from_millis(100)).await;
    engine.tick();

    // Verify Uncorrelated event
    let event = rx.try_recv().expect("should have uncorrelated event");
    assert_eq!(event.status, CorrelationStatus::Uncorrelated);
    assert!(event.mcp_event.is_none());
    assert_eq!(event.os_events.len(), 1);
}

// ---------------------------------------------------------------------------
// Test: Multi-server correlation (no cross-contamination)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multi_server_correlation_no_cross_contamination() {
    let server1_pid = 100;
    let server1_child = 200;
    let server2_pid = 300;
    let server2_child = 400;

    // Engine for server 1
    let (tx1, mut rx1) = mpsc::channel::<CorrelatedEvent>(100);
    let config1 = CorrelationConfig {
        match_window: Duration::from_millis(100),
        server_pid: server1_pid,
        ..test_config(server1_pid)
    };
    let mut engine1 = CorrelationEngine::new(config1, tx1);
    let mut tree1 = ProcessTree::new();
    tree1.insert(ProcessInfo {
        pid: server1_pid,
        ppid: 1,
        name: "node".into(),
        path: "/usr/bin/node".into(),
        args: vec![],
        start_time: None,
    });
    tree1.insert(ProcessInfo {
        pid: server1_child,
        ppid: server1_pid,
        name: "bash".into(),
        path: "/bin/bash".into(),
        args: vec![],
        start_time: None,
    });

    // Engine for server 2
    let (tx2, mut rx2) = mpsc::channel::<CorrelatedEvent>(100);
    let config2 = CorrelationConfig {
        match_window: Duration::from_millis(100),
        server_pid: server2_pid,
        ..test_config(server2_pid)
    };
    let mut engine2 = CorrelationEngine::new(config2, tx2);
    let mut tree2 = ProcessTree::new();
    tree2.insert(ProcessInfo {
        pid: server2_pid,
        ppid: 1,
        name: "python".into(),
        path: "/usr/bin/python3".into(),
        args: vec![],
        start_time: None,
    });
    tree2.insert(ProcessInfo {
        pid: server2_child,
        ppid: server2_pid,
        name: "sh".into(),
        path: "/bin/sh".into(),
        args: vec![],
        start_time: None,
    });

    // Server 1: MCP ToolCall + matching OS exec
    let mcp1 = make_tool_call("run_command", json!({"command": "ls"}));
    engine1.process_mcp_event(mcp1, &tree1);
    let os1 = make_os_exec(server1_child, server1_pid, "/bin/ls", vec!["ls"]);
    engine1.process_os_event(os1, &tree1);

    // Server 2: MCP ResourceRead + matching OS open
    let mcp2 = make_resource_read("file:///tmp/data.txt");
    engine2.process_mcp_event(mcp2, &tree2);
    let os2 = make_os_open(server2_child, server2_pid, "/tmp/data.txt");
    engine2.process_os_event(os2, &tree2);

    // Cross-contamination check: server2 child event sent to server1 engine
    let os_wrong = make_os_exec(server2_child, server2_pid, "/bin/ls", vec!["ls"]);
    engine1.process_os_event(os_wrong, &tree1);
    // server2_child (400) is NOT a descendant of server1 (100) in tree1
    assert_eq!(
        engine1.pending_os_count(),
        1,
        "server2 OS event should not match server1 engine"
    );

    // Tick to expire
    tokio::time::sleep(Duration::from_millis(150)).await;
    engine1.tick();
    engine2.tick();

    // Server 1: should have matched event
    let ev1 = rx1.try_recv().expect("server1 should have correlated event");
    assert_eq!(ev1.status, CorrelationStatus::Matched);
    assert!(ev1.mcp_event.is_some());

    // Server 2: should have matched event
    let ev2 = rx2.try_recv().expect("server2 should have correlated event");
    assert_eq!(ev2.status, CorrelationStatus::Matched);
    assert!(ev2.mcp_event.is_some());
}

// ---------------------------------------------------------------------------
// Test: Sensor degradation (eslogger disabled)
// ---------------------------------------------------------------------------

#[test]
fn sensor_degradation_eslogger_disabled() {
    use clawdefender_core::config::settings::SensorConfig;

    let toml_str = r#"
[eslogger]
enabled = false

[fsevents]
enabled = false

[correlation]
window_ms = 500

[process_tree]
refresh_interval_secs = 5
"#;
    let config: SensorConfig = toml::from_str(toml_str).unwrap();
    assert!(!config.eslogger.enabled, "eslogger should be disabled");
    assert!(!config.fsevents.enabled, "fsevents should be disabled");
    assert_eq!(config.correlation.window_ms, 500);
}

#[test]
fn daemon_creates_with_eslogger_disabled() {
    use clawdefender_core::config::settings::ClawConfig;

    let dir = tempfile::TempDir::new().unwrap();
    let mut config = ClawConfig::default();
    config.audit_log_path = dir.path().join("audit.jsonl");
    config.daemon_socket_path = dir.path().join("test.sock");
    config.eslogger.enabled = false;

    let daemon = clawdefender_daemon::Daemon::new(config, false);
    assert!(daemon.is_ok(), "daemon should start with eslogger disabled");
}

// ---------------------------------------------------------------------------
// Test: Mock eslogger JSON format compatibility
// ---------------------------------------------------------------------------

#[test]
fn mock_eslogger_exec_format_parses() {
    let exec_json = r#"{
        "event_type": "exec",
        "process": {
            "pid": 200,
            "ppid": 100,
            "executable": "/bin/bash",
            "signing_id": "com.apple.bash",
            "team_id": null,
            "audit_token": null
        },
        "event": {
            "target_path": "/usr/bin/curl",
            "args": ["curl", "http://example.com"]
        },
        "timestamp": "2026-01-15T10:30:00Z"
    }"#;

    let parsed = clawdefender_sensor::parse_event(exec_json)
        .expect("mock eslogger JSON should parse correctly");
    assert_eq!(parsed.event_type, "exec");
    assert_eq!(parsed.process.pid, 200);
    assert_eq!(parsed.process.ppid, 100);

    let os_event: OsEvent = parsed.into();
    assert_eq!(os_event.pid, 200);
    match &os_event.kind {
        OsEventKind::Exec { target_path, args } => {
            assert_eq!(target_path, "/usr/bin/curl");
            assert_eq!(args, &["curl", "http://example.com"]);
        }
        other => panic!("expected Exec, got {other:?}"),
    }
}

#[test]
fn mock_eslogger_connect_format_parses() {
    let connect_json = r#"{
        "event_type": "connect",
        "process": {
            "pid": 200,
            "ppid": 100,
            "executable": "/usr/bin/curl",
            "signing_id": null,
            "team_id": null
        },
        "event": {
            "address": "93.184.216.34",
            "port": 80,
            "socket_type": "tcp"
        },
        "timestamp": "2026-01-15T10:31:00Z"
    }"#;

    let parsed = clawdefender_sensor::parse_event(connect_json)
        .expect("mock connect JSON should parse correctly");
    assert_eq!(parsed.event_type, "connect");

    let os_event: OsEvent = parsed.into();
    match &os_event.kind {
        OsEventKind::Connect {
            address,
            port,
            protocol,
        } => {
            assert_eq!(address, "93.184.216.34");
            assert_eq!(*port, 80);
            assert_eq!(protocol, "tcp");
        }
        other => panic!("expected Connect, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test: Process tree agent ancestry in correlation
// ---------------------------------------------------------------------------

#[test]
fn agent_grandchild_events_correlate() {
    let server_pid = 100;
    let child_pid = 200;
    let grandchild_pid = 300;

    let mut tree = ProcessTree::new();
    tree.insert(ProcessInfo {
        pid: server_pid,
        ppid: 1,
        name: "node".into(),
        path: "/usr/bin/node".into(),
        args: vec![],
        start_time: None,
    });
    tree.insert(ProcessInfo {
        pid: child_pid,
        ppid: server_pid,
        name: "bash".into(),
        path: "/bin/bash".into(),
        args: vec![],
        start_time: None,
    });
    tree.insert(ProcessInfo {
        pid: grandchild_pid,
        ppid: child_pid,
        name: "curl".into(),
        path: "/usr/bin/curl".into(),
        args: vec![],
        start_time: None,
    });

    let (tx, _rx) = mpsc::channel::<CorrelatedEvent>(100);
    let mut engine = CorrelationEngine::new(test_config(server_pid), tx);

    let mcp = make_tool_call(
        "run_command",
        json!({"command": "curl http://example.com"}),
    );
    engine.process_mcp_event(mcp, &tree);

    let os = make_os_exec(
        grandchild_pid,
        child_pid,
        "/usr/bin/curl",
        vec!["curl", "http://example.com"],
    );
    engine.process_os_event(os, &tree);

    assert_eq!(
        engine.pending_os_count(),
        0,
        "grandchild OS event should match via process tree ancestry"
    );
}

// ---------------------------------------------------------------------------
// Test: Non-agent events do not correlate
// ---------------------------------------------------------------------------

#[test]
fn non_agent_events_do_not_correlate() {
    let server_pid = 100;
    let unrelated_pid = 999;
    let tree = make_process_tree(server_pid, 200);

    let (tx, _rx) = mpsc::channel::<CorrelatedEvent>(100);
    let mut engine = CorrelationEngine::new(test_config(server_pid), tx);

    let mcp = make_tool_call("run_command", json!({"command": "ls"}));
    engine.process_mcp_event(mcp, &tree);

    let os = make_os_exec(unrelated_pid, 1, "/bin/ls", vec!["ls"]);
    engine.process_os_event(os, &tree);

    assert_eq!(
        engine.pending_os_count(),
        1,
        "unrelated PID should not match"
    );
}

// ---------------------------------------------------------------------------
// Test: Correlation engine async run loop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn correlation_engine_run_loop_matches_and_shuts_down() {
    let server_pid = 100;
    let child_pid = 200;

    let (output_tx, mut output_rx) = mpsc::channel::<CorrelatedEvent>(100);
    let (input_tx, input_rx) = mpsc::channel::<CorrelationInput>(100);

    let config = CorrelationConfig {
        match_window: Duration::from_millis(100),
        server_pid,
        ..test_config(server_pid)
    };
    let engine = CorrelationEngine::new(config, output_tx);
    let tree = Arc::new(RwLock::new(make_process_tree(server_pid, child_pid)));

    let handle = engine.run(input_rx, tree);

    // Send MCP event
    let mcp = make_tool_call("run_command", json!({"command": "ls"}));
    input_tx.send(CorrelationInput::Mcp(mcp)).await.unwrap();

    // Send matching OS event
    let os = make_os_exec(child_pid, server_pid, "/bin/ls", vec!["ls"]);
    input_tx.send(CorrelationInput::Os(os)).await.unwrap();

    // Wait for tick to flush
    tokio::time::sleep(Duration::from_millis(200)).await;
    input_tx.send(CorrelationInput::Tick).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Shutdown
    input_tx
        .send(CorrelationInput::Shutdown)
        .await
        .unwrap();
    handle.await.unwrap();

    // Should have received at least one correlated event
    let event = output_rx
        .try_recv()
        .expect("should have at least one correlated event");
    assert_eq!(event.status, CorrelationStatus::Matched);
}

// ---------------------------------------------------------------------------
// Test: Resource read to file open correlation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resource_read_correlates_to_file_open() {
    let server_pid = 100;
    let child_pid = 200;

    let (tx, mut rx) = mpsc::channel::<CorrelatedEvent>(100);
    let config = CorrelationConfig {
        match_window: Duration::from_millis(50),
        server_pid,
        ..test_config(server_pid)
    };
    let mut engine = CorrelationEngine::new(config, tx);
    let tree = make_process_tree(server_pid, child_pid);

    // MCP: resources/read file:///tmp/data.csv
    let mcp = make_resource_read("file:///tmp/data.csv");
    engine.process_mcp_event(mcp, &tree);

    // OS: open /tmp/data.csv
    let os = make_os_open(child_pid, server_pid, "/tmp/data.csv");
    engine.process_os_event(os, &tree);

    // Tick to expire
    tokio::time::sleep(Duration::from_millis(100)).await;
    engine.tick();

    let event = rx.try_recv().expect("should have correlated event");
    assert_eq!(event.status, CorrelationStatus::Matched);
    assert!(event.mcp_event.is_some());
}

// ---------------------------------------------------------------------------
// Test: File tool to file operation correlation
// ---------------------------------------------------------------------------

#[test]
fn file_tool_correlates_to_file_open() {
    std::env::set_var("HOME", "/Users/dev");
    let server_pid = 100;
    let child_pid = 200;

    let (tx, _rx) = mpsc::channel::<CorrelatedEvent>(100);
    let mut engine = CorrelationEngine::new(test_config(server_pid), tx);
    let tree = make_process_tree(server_pid, child_pid);

    let mcp = make_tool_call("write_file", json!({"path": "~/output.txt"}));
    engine.process_mcp_event(mcp, &tree);

    let os = make_os_open(child_pid, server_pid, "/Users/dev/output.txt");
    engine.process_os_event(os, &tree);

    assert_eq!(
        engine.pending_os_count(),
        0,
        "file tool should match file open with tilde expansion"
    );
}
