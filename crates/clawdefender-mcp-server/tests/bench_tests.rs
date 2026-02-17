//! Performance benchmark tests for the ClawDefender MCP server.
//!
//! Uses std::time::Instant for simple, dependency-free benchmarking.
//! Targets:
//!   - checkIntent latency: < 5ms for in-process
//!   - 100 concurrent checkIntent calls: all within 1 second
//!   - reportAction throughput: > 1000/second

use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tempfile::NamedTempFile;

use clawdefender_core::audit::{AuditFilter, AuditLogger, AuditRecord, AuditStats};
use clawdefender_core::policy::engine::DefaultPolicyEngine;
use clawdefender_mcp_server::protocol;
use clawdefender_mcp_server::McpServer;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

struct BenchAuditLogger {
    count: StdMutex<u64>,
}

impl BenchAuditLogger {
    fn new() -> Self {
        Self {
            count: StdMutex::new(0),
        }
    }
}

impl AuditLogger for BenchAuditLogger {
    fn log(&self, _record: &AuditRecord) -> anyhow::Result<()> {
        *self.count.lock().unwrap() += 1;
        Ok(())
    }

    fn query(&self, _filter: &AuditFilter) -> anyhow::Result<Vec<AuditRecord>> {
        Ok(Vec::new())
    }

    fn stats(&self) -> anyhow::Result<AuditStats> {
        Ok(AuditStats::default())
    }
}

fn make_bench_server() -> Arc<McpServer> {
    let policy = r#"
[rules.allow_all]
description = "Allow everything"
action = "allow"
message = "Allowed"
priority = 0

[rules.allow_all.match]
any = true
"#;
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(policy.as_bytes()).unwrap();
    f.flush().unwrap();
    let engine = DefaultPolicyEngine::load(f.path()).unwrap();
    let _ = f.into_temp_path();
    let logger = Arc::new(BenchAuditLogger::new());
    Arc::new(McpServer::new(Box::new(engine), logger))
}

fn check_intent_msg(id: u32) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "checkIntent",
            "arguments": {
                "description": format!("Bench read file {}", id),
                "action_type": "file_read",
                "target": format!("/project/file_{}.rs", id)
            }
        }
    }))
    .unwrap()
}

fn report_action_msg(id: u32) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "reportAction",
            "arguments": {
                "description": format!("Wrote file {}", id),
                "action_type": "file_write",
                "target": format!("/tmp/bench_{}.txt", id),
                "result": "success"
            }
        }
    }))
    .unwrap()
}

// ---------------------------------------------------------------------------
// Benchmark: checkIntent latency < 5ms
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bench_check_intent_latency_under_5ms() {
    let server = make_bench_server();

    // Warm up
    for i in 0..10 {
        let msg = check_intent_msg(i);
        protocol::handle_message(&server, &msg).await;
    }

    // Measure 50 calls
    let mut total = Duration::ZERO;
    let iterations = 50u32;

    for i in 0..iterations {
        let msg = check_intent_msg(100 + i);
        let start = Instant::now();
        let resp = protocol::handle_message(&server, &msg).await.unwrap();
        let elapsed = start.elapsed();
        total += elapsed;

        // Verify the response is valid
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v["result"]["content"][0]["text"].is_string());
    }

    let avg = total / iterations;
    eprintln!(
        "checkIntent avg latency: {:?} (total {:?} over {} calls)",
        avg, total, iterations
    );

    assert!(
        avg < Duration::from_millis(5),
        "checkIntent average latency {:?} exceeds 5ms target",
        avg
    );
}

// ---------------------------------------------------------------------------
// Benchmark: 100 concurrent checkIntent calls within 1 second
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bench_100_concurrent_check_intent_under_1s() {
    let server = make_bench_server();
    let count = 100;

    let start = Instant::now();

    let mut handles = Vec::new();
    for i in 0..count {
        let server = server.clone();
        let msg = check_intent_msg(200 + i);
        handles.push(tokio::spawn(async move {
            let resp = protocol::handle_message_with_caller(&server, &msg, &format!("bench-{}", i))
                .await
                .unwrap();
            let v: Value = serde_json::from_str(&resp).unwrap();
            assert!(v["result"]["content"][0]["text"].is_string());
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    eprintln!(
        "100 concurrent checkIntent calls completed in {:?}",
        elapsed
    );

    assert!(
        elapsed < Duration::from_secs(1),
        "100 concurrent checkIntent calls took {:?}, exceeds 1 second target",
        elapsed
    );
}

// ---------------------------------------------------------------------------
// Benchmark: reportAction throughput > 1000/second
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bench_report_action_throughput_over_1000_per_sec() {
    let server = make_bench_server();
    let count = 500u32;

    let start = Instant::now();

    for i in 0..count {
        let msg = report_action_msg(i);
        let resp = protocol::handle_message(&server, &msg).await.unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v["result"]["content"][0]["text"].is_string());
    }

    let elapsed = start.elapsed();
    let throughput = count as f64 / elapsed.as_secs_f64();
    eprintln!(
        "reportAction throughput: {:.0}/second ({} calls in {:?})",
        throughput, count, elapsed
    );

    assert!(
        throughput > 1000.0,
        "reportAction throughput {:.0}/s is below 1000/s target",
        throughput
    );
}

// ---------------------------------------------------------------------------
// Benchmark: getPolicy latency
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bench_get_policy_latency() {
    let server = make_bench_server();
    let iterations = 50u32;

    let mut total = Duration::ZERO;

    for i in 0..iterations {
        let msg = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": i,
            "method": "tools/call",
            "params": {
                "name": "getPolicy",
                "arguments": {
                    "resource": format!("/project/file_{}.rs", i)
                }
            }
        }))
        .unwrap();

        let start = Instant::now();
        protocol::handle_message(&server, &msg).await;
        total += start.elapsed();
    }

    let avg = total / iterations;
    eprintln!("getPolicy avg latency: {:?}", avg);

    assert!(
        avg < Duration::from_millis(5),
        "getPolicy average latency {:?} exceeds 5ms",
        avg
    );
}

// ---------------------------------------------------------------------------
// Benchmark: mixed workload (realistic scenario)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bench_mixed_workload() {
    let server = make_bench_server();
    let iterations = 100u32;

    let start = Instant::now();

    for i in 0..iterations {
        // checkIntent
        let msg = check_intent_msg(300 + i);
        protocol::handle_message(&server, &msg).await;

        // reportAction
        let msg = report_action_msg(300 + i);
        protocol::handle_message(&server, &msg).await;
    }

    let elapsed = start.elapsed();
    let ops_per_sec = (iterations * 2) as f64 / elapsed.as_secs_f64();
    eprintln!(
        "Mixed workload: {:.0} ops/second ({} check+report pairs in {:?})",
        ops_per_sec, iterations, elapsed
    );

    assert!(
        ops_per_sec > 500.0,
        "Mixed workload {:.0} ops/s is below 500/s",
        ops_per_sec
    );
}
