//! Mock eslogger binary for integration testing.
//!
//! Outputs JSON lines matching the real eslogger format to stdout.
//! Supports configurable event sequences, rates, simulated crashes, and hangs.

use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use clap::Parser;
use serde::Serialize;
use serde_json::json;

/// Mock eslogger for testing ClawDefender sensor integration.
#[derive(Parser, Debug)]
#[command(name = "mock-eslogger")]
struct Args {
    /// Scenario to run: "basic", "crash", "hang", "burst", "mixed"
    #[arg(short, long, default_value = "basic")]
    scenario: String,

    /// Delay between events in milliseconds
    #[arg(short, long, default_value = "100")]
    delay_ms: u64,

    /// Number of events to emit (0 = unlimited for basic)
    #[arg(short, long, default_value = "10")]
    count: u64,

    /// PID to use for generated events
    #[arg(long, default_value = "200")]
    pid: u32,

    /// PPID to use for generated events
    #[arg(long, default_value = "100")]
    ppid: u32,
}

/// Eslogger JSON event structure matching the real format.
#[derive(Debug, Serialize)]
struct MockEvent {
    event_type: String,
    process: MockProcess,
    event: serde_json::Value,
    timestamp: String,
}

#[derive(Debug, Serialize)]
struct MockProcess {
    pid: u32,
    ppid: u32,
    executable: String,
    signing_id: Option<String>,
    team_id: Option<String>,
    audit_token: Option<serde_json::Value>,
}

fn make_exec_event(pid: u32, ppid: u32, target: &str, args: &[&str]) -> MockEvent {
    MockEvent {
        event_type: "exec".into(),
        process: MockProcess {
            pid,
            ppid,
            executable: "/bin/bash".into(),
            signing_id: Some("com.apple.bash".into()),
            team_id: None,
            audit_token: None,
        },
        event: json!({
            "target_path": target,
            "args": args,
        }),
        timestamp: Utc::now().to_rfc3339(),
    }
}

fn make_open_event(pid: u32, ppid: u32, path: &str) -> MockEvent {
    MockEvent {
        event_type: "open".into(),
        process: MockProcess {
            pid,
            ppid,
            executable: "/usr/bin/cat".into(),
            signing_id: None,
            team_id: None,
            audit_token: None,
        },
        event: json!({
            "path": path,
            "flags": 0,
        }),
        timestamp: Utc::now().to_rfc3339(),
    }
}

fn make_connect_event(pid: u32, ppid: u32, address: &str, port: u16) -> MockEvent {
    MockEvent {
        event_type: "connect".into(),
        process: MockProcess {
            pid,
            ppid,
            executable: "/usr/bin/curl".into(),
            signing_id: None,
            team_id: None,
            audit_token: None,
        },
        event: json!({
            "address": address,
            "port": port,
            "socket_type": "tcp",
        }),
        timestamp: Utc::now().to_rfc3339(),
    }
}

fn make_fork_event(pid: u32, ppid: u32, child_pid: u32) -> MockEvent {
    MockEvent {
        event_type: "fork".into(),
        process: MockProcess {
            pid,
            ppid,
            executable: "/bin/bash".into(),
            signing_id: None,
            team_id: None,
            audit_token: None,
        },
        event: json!({
            "child_pid": child_pid,
        }),
        timestamp: Utc::now().to_rfc3339(),
    }
}

fn make_exit_event(pid: u32, ppid: u32, status: i32) -> MockEvent {
    MockEvent {
        event_type: "exit".into(),
        process: MockProcess {
            pid,
            ppid,
            executable: "/bin/bash".into(),
            signing_id: None,
            team_id: None,
            audit_token: None,
        },
        event: json!({
            "status": status,
        }),
        timestamp: Utc::now().to_rfc3339(),
    }
}

fn emit(event: &MockEvent) {
    let json = serde_json::to_string(event).expect("serialize mock event");
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "{json}").ok();
    handle.flush().ok();
}

fn run_basic(args: &Args) {
    let events = vec![
        make_exec_event(args.pid, args.ppid, "/usr/bin/curl", &["curl", "http://example.com"]),
        make_connect_event(args.pid, args.ppid, "93.184.216.34", 80),
        make_open_event(args.pid, args.ppid, "/tmp/output.txt"),
        make_exec_event(args.pid, args.ppid, "/bin/ls", &["ls", "-la"]),
        make_open_event(args.pid, args.ppid, "/etc/hosts"),
        make_fork_event(args.pid, args.ppid, args.pid + 1),
        make_exec_event(args.pid + 1, args.pid, "/usr/bin/grep", &["grep", "pattern"]),
        make_connect_event(args.pid, args.ppid, "127.0.0.1", 8080),
        make_open_event(args.pid, args.ppid, "/Users/dev/.ssh/id_rsa"),
        make_exit_event(args.pid + 1, args.pid, 0),
    ];

    let count = if args.count == 0 { events.len() as u64 } else { args.count.min(events.len() as u64) };
    for event in events.iter().take(count as usize) {
        emit(event);
        thread::sleep(Duration::from_millis(args.delay_ms));
    }
}

fn run_crash(args: &Args) {
    // Emit a few events, then exit with non-zero code to simulate crash.
    let events = [
        make_exec_event(args.pid, args.ppid, "/bin/ls", &["ls"]),
        make_open_event(args.pid, args.ppid, "/tmp/foo.txt"),
        make_connect_event(args.pid, args.ppid, "10.0.0.1", 443),
    ];

    let crash_after = args.count.min(events.len() as u64);
    for event in events.iter().take(crash_after as usize) {
        emit(event);
        thread::sleep(Duration::from_millis(args.delay_ms));
    }

    // Simulate crash
    std::process::exit(1);
}

fn run_hang(args: &Args) {
    // Emit a few events, then stop producing output (hang).
    let events = [
        make_exec_event(args.pid, args.ppid, "/bin/echo", &["echo", "hello"]),
        make_open_event(args.pid, args.ppid, "/tmp/test.txt"),
    ];

    let emit_count = args.count.min(events.len() as u64);
    for event in events.iter().take(emit_count as usize) {
        emit(event);
        thread::sleep(Duration::from_millis(args.delay_ms));
    }

    // Hang indefinitely (simulate eslogger becoming unresponsive)
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn run_burst(args: &Args) {
    // Emit many events rapidly to test rate limiting/backpressure.
    for i in 0..args.count {
        let event = make_exec_event(args.pid, args.ppid, "/bin/ls", &["ls", &format!("file_{i}")]);
        emit(&event);
        // Minimal delay for burst mode
        if args.delay_ms > 0 {
            thread::sleep(Duration::from_millis(args.delay_ms));
        }
    }
}

fn run_mixed(args: &Args) {
    // Emit a realistic mixed sequence from two different server PIDs.
    let server1_pid = args.pid;
    let server1_child = args.pid + 1;
    let server2_pid = args.pid + 100;
    let server2_child = args.pid + 101;

    let events = vec![
        // Server 1: curl to example.com
        make_fork_event(server1_pid, args.ppid, server1_child),
        make_exec_event(server1_child, server1_pid, "/usr/bin/curl", &["curl", "http://example.com"]),
        make_connect_event(server1_child, server1_pid, "93.184.216.34", 80),
        // Server 2: read a file
        make_fork_event(server2_pid, args.ppid, server2_child),
        make_exec_event(server2_child, server2_pid, "/usr/bin/cat", &["cat", "/tmp/data.txt"]),
        make_open_event(server2_child, server2_pid, "/tmp/data.txt"),
        // Server 1: write file
        make_open_event(server1_child, server1_pid, "/tmp/output.html"),
        // Cleanup
        make_exit_event(server1_child, server1_pid, 0),
        make_exit_event(server2_child, server2_pid, 0),
    ];

    let count = if args.count == 0 { events.len() as u64 } else { args.count.min(events.len() as u64) };
    for event in events.iter().take(count as usize) {
        emit(event);
        thread::sleep(Duration::from_millis(args.delay_ms));
    }
}

fn main() {
    let args = Args::parse();

    match args.scenario.as_str() {
        "basic" => run_basic(&args),
        "crash" => run_crash(&args),
        "hang" => run_hang(&args),
        "burst" => run_burst(&args),
        "mixed" => run_mixed(&args),
        other => {
            eprintln!("Unknown scenario: {other}");
            eprintln!("Available: basic, crash, hang, burst, mixed");
            std::process::exit(2);
        }
    }
}
