//! Performance tests for the clawdefender-guard crate.
//!
//! These are basic timing tests to verify that guard operations
//! meet performance targets:
//! - Guard activation: < 100ms without daemon
//! - Per-operation check: < 0.5ms
//! - Registry lookup: reasonable for multiple guards

use std::time::Instant;

use clawdefender_guard::fallback::FallbackEngine;
use clawdefender_guard::guard::GuardBuilder;
use clawdefender_guard::types::*;

// ---------------------------------------------------------------------------
// Guard activation time
// ---------------------------------------------------------------------------

#[test]
fn perf_guard_activation_under_100ms() {
    let start = Instant::now();

    let mut guard = GuardBuilder::new("perf-agent")
        .file_read(vec!["/workspace/**".to_string()])
        .file_write(vec!["/workspace/output/**".to_string()])
        .shell_policy(ShellPolicy::Deny)
        .network_policy(NetworkPolicy {
            allowed_hosts: vec!["api.anthropic.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        })
        .tools(vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "search".to_string(),
        ])
        .build();

    guard.activate().unwrap();
    let elapsed = start.elapsed();

    guard.deactivate().unwrap();

    assert!(
        elapsed.as_millis() < 100,
        "Guard activation took {}ms, target is < 100ms",
        elapsed.as_millis()
    );
}

// ---------------------------------------------------------------------------
// Per-operation check time
// ---------------------------------------------------------------------------

#[test]
fn perf_check_action_under_half_ms() {
    let mut guard = GuardBuilder::new("perf-agent")
        .file_read(vec!["/workspace/**".to_string()])
        .file_write(vec!["/workspace/output/**".to_string()])
        .shell_policy(ShellPolicy::Deny)
        .network_policy(NetworkPolicy {
            allowed_hosts: vec!["api.anthropic.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        })
        .tools(vec!["read_file".to_string()])
        .build();

    guard.activate().unwrap();

    // Warm up.
    for _ in 0..100 {
        guard.check_action("read_file", "/workspace/file.txt");
    }

    // Benchmark 1000 operations.
    let iterations = 1000;
    let start = Instant::now();
    for i in 0..iterations {
        let path = format!("/workspace/file_{i}.txt");
        guard.check_action("read_file", &path);
    }
    let elapsed = start.elapsed();
    let per_op_us = elapsed.as_micros() as f64 / iterations as f64;

    guard.deactivate().unwrap();

    assert!(
        per_op_us < 500.0,
        "Per-operation check took {per_op_us:.1}us, target is < 500us (0.5ms)"
    );
}

// ---------------------------------------------------------------------------
// Fallback engine check time
// ---------------------------------------------------------------------------

#[test]
fn perf_fallback_engine_check() {
    let engine = FallbackEngine::new(PermissionSet {
        file_read: vec!["/workspace/**".to_string()],
        file_write: vec!["/workspace/output/**".to_string()],
        shell_execute: ShellPolicy::Deny,
        network: NetworkPolicy {
            allowed_hosts: vec!["api.anthropic.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        },
        tools: vec!["read_file".to_string()],
        ..Default::default()
    });

    // Warm up.
    for _ in 0..100 {
        engine.check_action("read_file", "/workspace/file.txt");
    }

    // Benchmark.
    let iterations = 1000;
    let start = Instant::now();
    for i in 0..iterations {
        let path = format!("/workspace/file_{i}.txt");
        engine.check_action("read_file", &path);
    }
    let elapsed = start.elapsed();
    let per_op_us = elapsed.as_micros() as f64 / iterations as f64;

    assert!(
        per_op_us < 500.0,
        "Fallback engine check took {per_op_us:.1}us, target is < 500us"
    );
}

// ---------------------------------------------------------------------------
// Registry lookup with multiple guards
// ---------------------------------------------------------------------------

#[tokio::test]
async fn perf_registry_lookup_with_many_guards() {
    use clawdefender_guard::registry::{GuardMode, GuardRegistry, PermissionSet};

    let registry = GuardRegistry::new();
    let mut guard_ids = Vec::new();

    // Register 50 guards.
    for i in 0..50 {
        let perms = PermissionSet {
            file_read: vec![format!("/project-{i}/**")],
            file_write: vec![],
            file_delete: vec![],
            shell_policy: "deny".to_string(),
            network_allowlist: vec!["api.anthropic.com".to_string()],
            tools: vec!["read_file".to_string()],
            max_file_size: None,
            max_files_per_minute: None,
            max_network_requests_per_minute: None,
        };
        let (id, _) = registry
            .register(
                format!("agent-{i}"),
                i as u32 + 1000,
                perms,
                GuardMode::Enforce,
            )
            .await;
        guard_ids.push(id);
    }

    // Benchmark lookups.
    let iterations = 100;
    let start = Instant::now();
    for _ in 0..iterations {
        for id in &guard_ids {
            let _ = registry.get(id).await;
        }
    }
    let elapsed = start.elapsed();
    let total_lookups = iterations * guard_ids.len();
    let per_lookup_us = elapsed.as_micros() as f64 / total_lookups as f64;

    assert!(
        per_lookup_us < 1000.0,
        "Registry lookup took {per_lookup_us:.1}us per lookup with 50 guards"
    );

    // Benchmark check_action.
    let home = std::env::var("HOME").unwrap_or_default();
    let start = Instant::now();
    for id in &guard_ids {
        registry
            .check_action(id, "file_read", &format!("{home}/project-0/file.txt"))
            .await;
    }
    let elapsed = start.elapsed();
    let per_check_us = elapsed.as_micros() as f64 / guard_ids.len() as f64;

    assert!(
        per_check_us < 1000.0,
        "Registry check_action took {per_check_us:.1}us per check with 50 guards"
    );

    // Cleanup.
    for id in &guard_ids {
        registry.deregister(id).await;
    }
}
