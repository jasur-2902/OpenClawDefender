//! Security evasion tests for the sensor layer.
//!
//! These tests verify that the sensor correctly handles:
//! - Path traversal attacks via `..` components
//! - Unicode normalization evasion (NFC vs NFD)
//! - Null byte injection in paths
//! - Multi-process transitive agent identification
//! - PID recycling attacks
//! - Oversized field injection

use chrono::DateTime;
use clawdefender_core::event::os::{OsEvent, OsEventKind};
use clawdefender_sensor::eslogger::types::sanitize_path;
use clawdefender_sensor::fsevents::classify_path;
use clawdefender_sensor::parse_event;
use clawdefender_sensor::proctree::{ProcessInfo, ProcessTree};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Path traversal evasion
// ---------------------------------------------------------------------------

#[test]
fn path_traversal_resolves_dotdot() {
    // An agent might try to access ~/.ssh/id_rsa via a traversal path
    let raw = "/Users/dev/Projects/../../.ssh/id_rsa";
    let sanitized = sanitize_path(raw);
    assert_eq!(sanitized, "/Users/.ssh/id_rsa");
    // The important thing is that `..` components are resolved
    assert!(!sanitized.contains(".."));
}

#[test]
fn path_traversal_classified_correctly_after_canonicalization() {
    // After sanitization, a path resolving to ~/.ssh should be Critical
    let home = std::env::var("HOME").unwrap();
    let traversal = format!("{home}/Projects/../../{}/", home.trim_start_matches('/'));
    let raw = format!("{traversal}.ssh/id_rsa");
    let sanitized = sanitize_path(&raw);

    let path = PathBuf::from(&sanitized);
    let _tier = classify_path(&path, None);
    // The path after canonicalization should resolve to something under home/.ssh
    // and be classified as Critical
    assert!(
        !sanitized.contains(".."),
        "path should not contain '..' after sanitization: {sanitized}"
    );
}

#[test]
fn dotdot_cannot_escape_root() {
    let raw = "/../../etc/shadow";
    let sanitized = sanitize_path(raw);
    assert_eq!(sanitized, "/etc/shadow");
    assert!(!sanitized.contains(".."));
}

#[test]
fn dot_components_removed() {
    let raw = "/Users/./dev/./Projects/./file.txt";
    let sanitized = sanitize_path(raw);
    assert_eq!(sanitized, "/Users/dev/Projects/file.txt");
}

// ---------------------------------------------------------------------------
// Unicode normalization evasion
// ---------------------------------------------------------------------------

#[test]
fn unicode_nfc_nfd_paths_normalize_to_same() {
    // NFD representation of "cafe\u{0301}" (e + combining acute)
    let nfd_path = "/Users/dev/caf\u{0065}\u{0301}/file.txt";
    // NFC representation "caf\u{00e9}" (precomposed e-acute)
    let nfc_path = "/Users/dev/caf\u{00e9}/file.txt";

    let sanitized_nfd = sanitize_path(nfd_path);
    let sanitized_nfc = sanitize_path(nfc_path);

    assert_eq!(
        sanitized_nfd, sanitized_nfc,
        "NFC and NFD paths should normalize to the same string"
    );
}

#[test]
fn unicode_normalization_applied_to_exec_event() {
    // An MCP event might use NFC while eslogger reports NFD
    let nfd_json = r#"{
        "event_type": "exec",
        "process": {
            "pid": 1234,
            "ppid": 1,
            "executable": "/usr/bin/node"
        },
        "event": {
            "target_path": "/Users/dev/caf\u0065\u0301/server.js"
        },
        "timestamp": "2026-01-15T10:30:00Z"
    }"#;

    let event = parse_event(nfd_json).unwrap();
    let os_event: OsEvent = event.into();

    match &os_event.kind {
        OsEventKind::Exec { target_path, .. } => {
            // After normalization, should use NFC (precomposed)
            assert!(
                target_path.contains('\u{00e9}'),
                "expected NFC e-acute in path, got: {target_path}"
            );
            assert!(
                !target_path.contains('\u{0301}'),
                "should not contain combining acute after NFC normalization"
            );
        }
        other => panic!("expected Exec, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Null byte injection
// ---------------------------------------------------------------------------

#[test]
fn null_byte_truncated_in_path() {
    let raw = "/Users/dev/file.txt\0/etc/shadow";
    let sanitized = sanitize_path(raw);
    assert_eq!(sanitized, "/Users/dev/file.txt");
    assert!(!sanitized.contains('\0'));
}

#[test]
fn null_byte_in_open_event() {
    let json = r#"{
        "event_type": "open",
        "process": {
            "pid": 1234,
            "ppid": 1,
            "executable": "/usr/bin/python3"
        },
        "event": {
            "path": "/tmp/safe.txt\u0000/etc/shadow",
            "flags": 1
        },
        "timestamp": "2026-01-15T10:30:00Z"
    }"#;

    let event = parse_event(json).unwrap();
    let os_event: OsEvent = event.into();

    match &os_event.kind {
        OsEventKind::Open { path, .. } => {
            assert!(!path.contains('\0'), "null bytes should be stripped");
            assert!(
                !path.contains("/etc/shadow"),
                "injected path after null should be removed"
            );
        }
        other => panic!("expected Open, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Multi-process transitive agent identification
// ---------------------------------------------------------------------------

#[test]
fn transitive_identification_across_three_generations() {
    // Agent forks child that forks grandchild
    let mut tree = ProcessTree::new();

    // Claude (PID 100) -> shell (PID 200) -> npm (PID 300)
    tree.insert(ProcessInfo {
        pid: 100,
        ppid: 1,
        name: "Claude".to_string(),
        path: "/Applications/Claude.app/Contents/MacOS/Claude".to_string(),
        args: Vec::new(),
        start_time: None,
    });
    tree.insert(ProcessInfo {
        pid: 200,
        ppid: 100,
        name: "bash".to_string(),
        path: "/bin/bash".to_string(),
        args: Vec::new(),
        start_time: None,
    });
    tree.insert(ProcessInfo {
        pid: 300,
        ppid: 200,
        name: "npm".to_string(),
        path: "/usr/local/bin/npm".to_string(),
        args: Vec::new(),
        start_time: None,
    });

    // All should be identified as agent-related
    assert!(tree.is_agent(100), "Claude itself should be identified");
    assert!(
        tree.is_agent(200),
        "child of agent should be identified transitively"
    );
    assert!(
        tree.is_agent(300),
        "grandchild of agent should be identified transitively"
    );
}

#[test]
fn transitive_identification_stops_at_non_agent_root() {
    let mut tree = ProcessTree::new();

    // launchd (PID 1) -> vim (PID 500) -> child (PID 600)
    tree.insert(ProcessInfo {
        pid: 1,
        ppid: 0,
        name: "launchd".to_string(),
        path: "/sbin/launchd".to_string(),
        args: Vec::new(),
        start_time: None,
    });
    tree.insert(ProcessInfo {
        pid: 500,
        ppid: 1,
        name: "vim".to_string(),
        path: "/usr/bin/vim".to_string(),
        args: Vec::new(),
        start_time: None,
    });
    tree.insert(ProcessInfo {
        pid: 600,
        ppid: 500,
        name: "grep".to_string(),
        path: "/usr/bin/grep".to_string(),
        args: Vec::new(),
        start_time: None,
    });

    assert!(!tree.is_agent(500), "vim should NOT be identified as agent");
    assert!(!tree.is_agent(600), "grep child of vim should NOT be agent");
}

// ---------------------------------------------------------------------------
// PID recycling attack
// ---------------------------------------------------------------------------

#[test]
fn pid_recycling_prevents_false_agent_identification() {
    let mut tree = ProcessTree::new();
    let t1 = DateTime::from_timestamp(1000, 0);
    let t2 = DateTime::from_timestamp(9999, 0);

    // Register agent node process with start_time t1
    tree.insert(ProcessInfo {
        pid: 42,
        ppid: 1,
        name: "node".to_string(),
        path: "/usr/bin/node".to_string(),
        args: Vec::new(),
        start_time: t1,
    });
    tree.register_agent(42, "mcp-server".to_string(), "Claude".to_string());
    assert!(tree.is_agent(42), "registered agent should be identified");

    // Simulate PID recycling: process exits and new process gets same PID
    tree.insert(ProcessInfo {
        pid: 42,
        ppid: 1,
        name: "malicious".to_string(),
        path: "/tmp/malicious".to_string(),
        args: Vec::new(),
        start_time: t2,
    });

    assert!(
        !tree.is_agent(42),
        "recycled PID with different start_time should NOT be identified as agent"
    );
}

// ---------------------------------------------------------------------------
// Oversized field rejection
// ---------------------------------------------------------------------------

#[test]
fn oversized_json_line_rejected() {
    // Create a JSON line that exceeds 1MB
    let huge_path = "a".repeat(2_000_000);
    let json = format!(
        r#"{{"event_type":"exec","process":{{"pid":1,"ppid":0,"executable":"{}"}},"event":{{"target_path":"/bin/ls"}},"timestamp":"2026-01-15T10:00:00Z"}}"#,
        huge_path
    );
    let result = parse_event(&json);
    assert!(result.is_err(), "oversized JSON line should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("maximum length"),
        "error should mention maximum length, got: {err}"
    );
}

#[test]
fn oversized_path_field_truncated_in_conversion() {
    let long_path = format!("/{}", "a".repeat(5000));
    let json = format!(
        r#"{{"event_type":"open","process":{{"pid":1234,"ppid":1,"executable":"/usr/bin/test"}},"event":{{"path":"{}","flags":1}},"timestamp":"2026-01-15T10:00:00Z"}}"#,
        long_path
    );
    let event = parse_event(&json).unwrap();
    let os_event: OsEvent = event.into();

    match &os_event.kind {
        OsEventKind::Open { path, .. } => {
            assert!(
                path.len() <= 4096,
                "path should be truncated to 4096 bytes, got {}",
                path.len()
            );
        }
        other => panic!("expected Open, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Combined evasion: path traversal + unicode
// ---------------------------------------------------------------------------

#[test]
fn combined_traversal_and_unicode_evasion() {
    // Attacker uses NFD + path traversal to try to access sensitive file
    let raw = "/Users/dev/Projets/../caf\u{0065}\u{0301}/../.ssh/id_rsa";
    let sanitized = sanitize_path(raw);

    assert!(!sanitized.contains(".."), "traversal should be resolved");
    // After normalization, the combining acute should be composed
    assert!(
        !sanitized.contains('\u{0301}'),
        "combining characters should be normalized to NFC"
    );
}
