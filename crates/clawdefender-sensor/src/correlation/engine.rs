//! The main correlation engine that matches MCP events to OS events.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, trace};
use uuid::Uuid;

use clawdefender_core::event::correlation::{CorrelatedEvent, CorrelationStatus};
use clawdefender_core::event::mcp::McpEvent;
use clawdefender_core::event::os::OsEvent;

use crate::proctree::ProcessTree;

use super::rules::{self, MatchResult};
use super::severity::rate_uncorrelated;

/// Configuration for the correlation engine.
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Maximum time window for matching (default: 5 seconds).
    pub match_window: Duration,
    /// Maximum MCP events in the sliding window (default: 500).
    pub max_mcp_window: usize,
    /// Maximum OS events in the sliding window (default: 5000).
    pub max_os_window: usize,
    /// How long to keep events in the sliding window (default: 10 seconds).
    pub window_duration: Duration,
    /// PID of the MCP server process.
    pub server_pid: u32,
    /// Optional project directory for severity classification.
    pub project_dir: Option<String>,
    /// Deduplication window (default: 1 second).
    pub dedup_window: Duration,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            match_window: Duration::from_secs(5),
            max_mcp_window: 500,
            max_os_window: 5000,
            window_duration: Duration::from_secs(10),
            server_pid: 0,
            project_dir: None,
            dedup_window: Duration::from_secs(1),
        }
    }
}

/// An MCP event with its arrival timestamp.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TimestampedMcpEvent {
    event: McpEvent,
    arrived_at: DateTime<Utc>,
}

/// An OS event with its arrival timestamp.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TimestampedOsEvent {
    event: OsEvent,
    arrived_at: DateTime<Utc>,
}

/// A pending MCP event awaiting OS event matches.
#[derive(Debug)]
struct PendingMcp {
    event: McpEvent,
    created_at: DateTime<Utc>,
    matched_os: Vec<(OsEvent, MatchResult)>,
}

/// A pending OS event awaiting an MCP event match.
#[derive(Debug)]
struct PendingOs {
    event: OsEvent,
    created_at: DateTime<Utc>,
}

/// Input events to the correlation engine.
pub enum CorrelationInput {
    Mcp(McpEvent),
    Os(OsEvent),
    Tick,
    Shutdown,
}

/// The correlation engine that connects MCP-level events to OS-level events.
pub struct CorrelationEngine {
    mcp_window: VecDeque<TimestampedMcpEvent>,
    os_window: VecDeque<TimestampedOsEvent>,
    pending_mcp: HashMap<String, PendingMcp>,
    pending_os: HashMap<String, PendingOs>,
    config: CorrelationConfig,
    output_tx: mpsc::Sender<CorrelatedEvent>,
    /// Counter for generating unique pending-OS keys.
    os_counter: u64,
}

impl CorrelationEngine {
    /// Create a new correlation engine.
    pub fn new(config: CorrelationConfig, output_tx: mpsc::Sender<CorrelatedEvent>) -> Self {
        Self {
            mcp_window: VecDeque::new(),
            os_window: VecDeque::new(),
            pending_mcp: HashMap::new(),
            pending_os: HashMap::new(),
            config,
            output_tx,
            os_counter: 0,
        }
    }

    /// Process an incoming MCP event: add to window and try to match pending OS events.
    pub fn process_mcp_event(&mut self, event: McpEvent, process_tree: &ProcessTree) {
        let now = Utc::now();
        let mcp_id = Uuid::new_v4().to_string();

        // Add to sliding window
        self.mcp_window.push_back(TimestampedMcpEvent {
            event: event.clone(),
            arrived_at: now,
        });
        self.trim_mcp_window();

        // Try to match against pending OS events
        let mut matched_os_keys = Vec::new();
        let mut matched_os_events = Vec::new();

        for (key, pending) in &self.pending_os {
            let delta = pending.event.timestamp - event.timestamp;
            let abs_delta = if delta < chrono::Duration::zero() {
                -delta
            } else {
                delta
            };
            if abs_delta
                > chrono::Duration::from_std(self.config.match_window)
                    .unwrap_or(chrono::Duration::seconds(5))
            {
                continue;
            }

            if let Some(match_result) =
                rules::try_match(&event, &pending.event, process_tree, self.config.server_pid)
            {
                matched_os_keys.push(key.clone());
                matched_os_events.push((pending.event.clone(), match_result));
            }
        }

        // Remove matched OS events from pending
        for key in &matched_os_keys {
            self.pending_os.remove(key);
        }

        if matched_os_events.is_empty() {
            // No OS matches yet; register as pending MCP
            self.pending_mcp.insert(
                mcp_id,
                PendingMcp {
                    event,
                    created_at: now,
                    matched_os: Vec::new(),
                },
            );
        } else {
            // Emit correlated event with deduplication
            self.emit_correlated(Some(event), matched_os_events);
        }
    }

    /// Process an incoming OS event: add to window and try to match pending MCP events.
    pub fn process_os_event(&mut self, event: OsEvent, process_tree: &ProcessTree) {
        let now = Utc::now();

        // Add to sliding window
        self.os_window.push_back(TimestampedOsEvent {
            event: event.clone(),
            arrived_at: now,
        });
        self.trim_os_window();

        // Try to match against pending MCP events
        let mut best_mcp_key: Option<String> = None;
        let mut best_match: Option<MatchResult> = None;

        for (key, pending) in &self.pending_mcp {
            let delta = event.timestamp - pending.event.timestamp;
            if delta < chrono::Duration::zero()
                || delta
                    > chrono::Duration::from_std(self.config.match_window)
                        .unwrap_or(chrono::Duration::seconds(5))
            {
                continue;
            }

            if let Some(match_result) =
                rules::try_match(&pending.event, &event, process_tree, self.config.server_pid)
            {
                let dominated = match &best_match {
                    Some(existing) => match_result.confidence > existing.confidence,
                    None => true,
                };
                if dominated {
                    best_mcp_key = Some(key.clone());
                    best_match = Some(match_result);
                }
            }
        }

        if let (Some(mcp_key), Some(_match_result)) = (best_mcp_key, best_match) {
            // Add OS event to the pending MCP's matched list
            if let Some(pending) = self.pending_mcp.get_mut(&mcp_key) {
                pending
                    .matched_os
                    .push((event, _match_result));
            }
        } else {
            // No MCP match; register as pending OS
            self.os_counter += 1;
            let key = format!("os-{}", self.os_counter);
            self.pending_os.insert(
                key,
                PendingOs {
                    event,
                    created_at: now,
                },
            );
        }
    }

    /// Called periodically to expire pending events and emit results.
    pub fn tick(&mut self) {
        let now = Utc::now();
        let window = chrono::Duration::from_std(self.config.match_window)
            .unwrap_or(chrono::Duration::seconds(5));

        // Expire pending MCP events
        let expired_mcp: Vec<String> = self
            .pending_mcp
            .iter()
            .filter(|(_, p)| now - p.created_at > window)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_mcp {
            if let Some(pending) = self.pending_mcp.remove(&key) {
                if pending.matched_os.is_empty() {
                    // MCP event with no OS matches -> still emit as Matched with just MCP
                    // (the tool call happened, no side effects observed)
                    let correlated = CorrelatedEvent {
                        id: Uuid::new_v4().to_string(),
                        mcp_event: Some(pending.event),
                        os_events: Vec::new(),
                        status: CorrelationStatus::Matched,
                        correlated_at: Some(now),
                    };
                    let _ = self.output_tx.try_send(correlated);
                } else {
                    // Emit with collected OS events (dedup)
                    self.emit_correlated(Some(pending.event), pending.matched_os);
                }
            }
        }

        // Expire pending OS events -> Uncorrelated
        let expired_os: Vec<String> = self
            .pending_os
            .iter()
            .filter(|(_, p)| now - p.created_at > window)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_os {
            if let Some(pending) = self.pending_os.remove(&key) {
                let severity = rate_uncorrelated(
                    &pending.event,
                    self.config.project_dir.as_deref(),
                );
                debug!(
                    pid = pending.event.pid,
                    ?severity,
                    "uncorrelated OS event expired"
                );
                let correlated = CorrelatedEvent {
                    id: Uuid::new_v4().to_string(),
                    mcp_event: None,
                    os_events: vec![pending.event],
                    status: CorrelationStatus::Uncorrelated,
                    correlated_at: Some(now),
                };
                let _ = self.output_tx.try_send(correlated);
            }
        }

        // Trim sliding windows by age
        self.trim_mcp_window();
        self.trim_os_window();
    }

    /// Spawn the async service loop.
    pub fn run(
        mut self,
        mut input_rx: mpsc::Receiver<CorrelationInput>,
        process_tree: Arc<RwLock<ProcessTree>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let tick_interval = Duration::from_secs(1);
            let mut tick_timer = tokio::time::interval(tick_interval);

            loop {
                tokio::select! {
                    Some(input) = input_rx.recv() => {
                        match input {
                            CorrelationInput::Mcp(event) => {
                                let tree = process_tree.read().await;
                                self.process_mcp_event(event, &tree);
                            }
                            CorrelationInput::Os(event) => {
                                let tree = process_tree.read().await;
                                self.process_os_event(event, &tree);
                            }
                            CorrelationInput::Tick => {
                                self.tick();
                            }
                            CorrelationInput::Shutdown => {
                                // Flush remaining pending events
                                self.tick();
                                break;
                            }
                        }
                    }
                    _ = tick_timer.tick() => {
                        self.tick();
                    }
                    else => break,
                }
            }

            trace!("correlation engine shut down");
        })
    }

    /// Emit a correlated event, deduplicating OS events within the dedup window.
    fn emit_correlated(
        &self,
        mcp_event: Option<McpEvent>,
        mut os_matches: Vec<(OsEvent, MatchResult)>,
    ) {
        if os_matches.is_empty() {
            let correlated = CorrelatedEvent {
                id: Uuid::new_v4().to_string(),
                mcp_event,
                os_events: Vec::new(),
                status: CorrelationStatus::Matched,
                correlated_at: Some(Utc::now()),
            };
            let _ = self.output_tx.try_send(correlated);
            return;
        }

        // Sort by confidence descending, then dedup by keeping best per event kind
        os_matches.sort_by(|a, b| b.1.confidence.partial_cmp(&a.1.confidence).unwrap());

        // Dedup: within the dedup window, group OS events and keep the most specific
        let dedup_window = chrono::Duration::from_std(self.config.dedup_window)
            .unwrap_or(chrono::Duration::seconds(1));

        let mut deduped: Vec<OsEvent> = Vec::new();
        let mut seen_kinds: Vec<(String, DateTime<Utc>)> = Vec::new();

        for (os_event, _match) in &os_matches {
            let kind_key = format!("{:?}", std::mem::discriminant(&os_event.kind));
            let dominated = seen_kinds.iter().any(|(k, ts)| {
                k == &kind_key && (os_event.timestamp - *ts).abs() < dedup_window
            });
            if !dominated {
                seen_kinds.push((kind_key, os_event.timestamp));
                deduped.push(os_event.clone());
            }
        }

        let correlated = CorrelatedEvent {
            id: Uuid::new_v4().to_string(),
            mcp_event,
            os_events: deduped,
            status: CorrelationStatus::Matched,
            correlated_at: Some(Utc::now()),
        };
        let _ = self.output_tx.try_send(correlated);
    }

    fn trim_mcp_window(&mut self) {
        let now = Utc::now();
        let max_age = chrono::Duration::from_std(self.config.window_duration)
            .unwrap_or(chrono::Duration::seconds(10));

        while self.mcp_window.len() > self.config.max_mcp_window {
            self.mcp_window.pop_front();
        }
        while let Some(front) = self.mcp_window.front() {
            if now - front.arrived_at > max_age {
                self.mcp_window.pop_front();
            } else {
                break;
            }
        }
    }

    fn trim_os_window(&mut self) {
        let now = Utc::now();
        let max_age = chrono::Duration::from_std(self.config.window_duration)
            .unwrap_or(chrono::Duration::seconds(10));

        while self.os_window.len() > self.config.max_os_window {
            self.os_window.pop_front();
        }
        while let Some(front) = self.os_window.front() {
            if now - front.arrived_at > max_age {
                self.os_window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get the number of pending MCP events (for testing/metrics).
    pub fn pending_mcp_count(&self) -> usize {
        self.pending_mcp.len()
    }

    /// Get the number of pending OS events (for testing/metrics).
    pub fn pending_os_count(&self) -> usize {
        self.pending_os.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdefender_core::event::mcp::{McpEventKind, ToolCall, ResourceRead};
    use clawdefender_core::event::os::OsEventKind;
    use serde_json::json;
    use std::time::Duration;

    fn make_process_tree(server_pid: u32, child_pid: u32) -> ProcessTree {
        let mut tree = ProcessTree::new();
        tree.insert(crate::proctree::ProcessInfo {
            pid: server_pid,
            ppid: 1,
            name: "node".into(),
            path: "/usr/bin/node".into(),
            args: vec![],
            start_time: None,
        });
        tree.insert(crate::proctree::ProcessInfo {
            pid: child_pid,
            ppid: server_pid,
            name: "bash".into(),
            path: "/bin/bash".into(),
            args: vec![],
            start_time: None,
        });
        tree
    }

    fn make_mcp_tool_call(tool_name: &str, arguments: serde_json::Value) -> McpEvent {
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

    fn make_mcp_resource_read(uri: &str) -> McpEvent {
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

    fn make_os_open(pid: u32, ppid: u32, path: &str) -> OsEvent {
        OsEvent {
            timestamp: Utc::now(),
            pid,
            ppid,
            process_path: "/bin/cat".into(),
            kind: OsEventKind::Open {
                path: path.into(),
                flags: 0,
            },
            signing_id: None,
            team_id: None,
        }
    }

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

    #[test]
    fn test_rule1_tool_call_to_exec() {
        let (tx, _rx) = mpsc::channel(100);
        let config = CorrelationConfig {
            server_pid: 100,
            match_window: Duration::from_secs(5),
            ..Default::default()
        };
        let mut engine = CorrelationEngine::new(config, tx);
        let tree = make_process_tree(100, 200);

        // MCP: tools/call run_command("ls")
        let mcp = make_mcp_tool_call("run_command", json!({"command": "ls"}));
        engine.process_mcp_event(mcp, &tree);

        // OS: exec /bin/ls from child pid
        let os = make_os_exec(200, 100, "/bin/ls", vec!["ls"]);
        engine.process_os_event(os, &tree);

        // Tick to flush
        engine.tick();

        // The MCP event should have matched the OS event
        assert!(engine.pending_os_count() == 0, "OS event should have been matched");
    }

    #[test]
    fn test_rule2_resource_read_to_open() {
        let (tx, _rx) = mpsc::channel(100);
        let config = CorrelationConfig {
            server_pid: 100,
            match_window: Duration::from_secs(5),
            ..Default::default()
        };
        let mut engine = CorrelationEngine::new(config, tx);
        let tree = make_process_tree(100, 200);

        // MCP: resources/read file:///tmp/foo.txt
        let mcp = make_mcp_resource_read("file:///tmp/foo.txt");
        engine.process_mcp_event(mcp, &tree);

        // OS: open /tmp/foo.txt
        let os = make_os_open(200, 100, "/tmp/foo.txt");
        engine.process_os_event(os, &tree);

        assert_eq!(engine.pending_os_count(), 0, "OS event should have matched");
    }

    #[test]
    fn test_rule3_file_tool_to_file_op() {
        std::env::set_var("HOME", "/Users/dev");
        let (tx, _rx) = mpsc::channel(100);
        let config = CorrelationConfig {
            server_pid: 100,
            match_window: Duration::from_secs(5),
            ..Default::default()
        };
        let mut engine = CorrelationEngine::new(config, tx);
        let tree = make_process_tree(100, 200);

        // MCP: tools/call write_file {path: "~/test.txt"}
        let mcp = make_mcp_tool_call("write_file", json!({"path": "~/test.txt"}));
        engine.process_mcp_event(mcp, &tree);

        // OS: open /Users/dev/test.txt
        let os = make_os_open(200, 100, "/Users/dev/test.txt");
        engine.process_os_event(os, &tree);

        assert_eq!(engine.pending_os_count(), 0, "OS event should have matched file tool");
    }

    #[test]
    fn test_rule4_network_tool_to_connect() {
        let (tx, _rx) = mpsc::channel(100);
        let config = CorrelationConfig {
            server_pid: 100,
            match_window: Duration::from_secs(5),
            ..Default::default()
        };
        let mut engine = CorrelationEngine::new(config, tx);
        let tree = make_process_tree(100, 200);

        // MCP: tools/call fetch {url: "http://example.com"}
        let mcp = make_mcp_tool_call("fetch", json!({"url": "http://example.com"}));
        engine.process_mcp_event(mcp, &tree);

        // OS: connect 93.184.216.34
        let os = make_os_connect(200, 100, "93.184.216.34", 80);
        engine.process_os_event(os, &tree);

        // The network tool won't match by IP directly since the IP isn't in args.
        // But the "example.com" substring match should trigger.
        // This tests the fuzzy matching logic.
        assert_eq!(engine.pending_os_count(), 0, "OS connect should have matched network tool via hostname");
    }

    #[tokio::test]
    async fn test_uncorrelated_os_event() {
        let (tx, mut rx) = mpsc::channel(100);
        let config = CorrelationConfig {
            server_pid: 100,
            match_window: Duration::from_millis(100), // Short window for test
            project_dir: Some("/Users/dev/project".into()),
            ..Default::default()
        };
        let mut engine = CorrelationEngine::new(config, tx);
        let tree = make_process_tree(100, 200);

        // OS: exec from agent PID, no MCP event
        let os = OsEvent {
            timestamp: Utc::now() - chrono::Duration::milliseconds(200),
            pid: 200,
            ppid: 100,
            process_path: "/bin/bash".into(),
            kind: OsEventKind::Exec {
                target_path: "/bin/rm".into(),
                args: vec!["rm".into(), "-rf".into(), "/".into()],
            },
            signing_id: None,
            team_id: None,
        };
        engine.process_os_event(os, &tree);
        assert_eq!(engine.pending_os_count(), 1);

        // Wait and tick to expire
        tokio::time::sleep(Duration::from_millis(150)).await;
        engine.tick();

        // Should have emitted an uncorrelated event
        let event = rx.try_recv().expect("should have uncorrelated event");
        assert_eq!(event.status, CorrelationStatus::Uncorrelated);
        assert!(event.mcp_event.is_none());
        assert_eq!(event.os_events.len(), 1);
    }

    #[test]
    fn test_time_window_no_match() {
        let (tx, _rx) = mpsc::channel(100);
        let config = CorrelationConfig {
            server_pid: 100,
            match_window: Duration::from_secs(5),
            ..Default::default()
        };
        let mut engine = CorrelationEngine::new(config, tx);
        let tree = make_process_tree(100, 200);

        // MCP event
        let mcp = make_mcp_tool_call("run_command", json!({"command": "ls"}));
        engine.process_mcp_event(mcp, &tree);

        // OS event 6 seconds later — outside the window
        let os = OsEvent {
            timestamp: Utc::now() + chrono::Duration::seconds(6),
            pid: 200,
            ppid: 100,
            process_path: "/bin/bash".into(),
            kind: OsEventKind::Exec {
                target_path: "/bin/ls".into(),
                args: vec!["ls".into()],
            },
            signing_id: None,
            team_id: None,
        };
        engine.process_os_event(os, &tree);

        // OS event should remain pending (no match due to time window)
        assert_eq!(engine.pending_os_count(), 1);
    }

    #[test]
    fn test_dedup_multiple_os_events() {
        let (tx, mut rx) = mpsc::channel(100);
        let config = CorrelationConfig {
            server_pid: 100,
            match_window: Duration::from_secs(5),
            dedup_window: Duration::from_secs(1),
            ..Default::default()
        };
        let mut engine = CorrelationEngine::new(config, tx);
        let tree = make_process_tree(100, 200);

        // First, put OS events as pending
        let os1 = make_os_open(200, 100, "/tmp/foo.txt");
        let os2 = make_os_open(200, 100, "/tmp/foo.txt");
        let os3 = make_os_open(200, 100, "/tmp/foo.txt");
        engine.process_os_event(os1, &tree);
        engine.process_os_event(os2, &tree);
        engine.process_os_event(os3, &tree);

        assert_eq!(engine.pending_os_count(), 3);

        // Now MCP event arrives that matches
        let mcp = make_mcp_resource_read("file:///tmp/foo.txt");
        engine.process_mcp_event(mcp, &tree);

        // All 3 OS events should be consumed from pending
        assert_eq!(engine.pending_os_count(), 0);

        // But after dedup, we should get a single correlated output
        // The MCP event matched all 3, so they're emitted as one correlated event
        // (dedup collapses same-kind events within 1s window)
        // The event is emitted immediately since OS events were already pending
        let event = rx.try_recv().expect("should have correlated event");
        assert_eq!(event.status, CorrelationStatus::Matched);
        assert!(event.mcp_event.is_some());
        // After dedup, same-kind events within 1s collapse to 1
        assert_eq!(event.os_events.len(), 1, "dedup should collapse 3 identical opens to 1");
    }

    #[test]
    fn test_fuzzy_path_tilde() {
        std::env::set_var("HOME", "/Users/dev");
        let (tx, _rx) = mpsc::channel(100);
        let config = CorrelationConfig {
            server_pid: 100,
            match_window: Duration::from_secs(5),
            ..Default::default()
        };
        let mut engine = CorrelationEngine::new(config, tx);
        let tree = make_process_tree(100, 200);

        // MCP uses ~/file.txt
        let mcp = make_mcp_tool_call("write_file", json!({"path": "~/file.txt"}));
        engine.process_mcp_event(mcp, &tree);

        // OS uses /Users/dev/file.txt
        let os = make_os_open(200, 100, "/Users/dev/file.txt");
        engine.process_os_event(os, &tree);

        assert_eq!(engine.pending_os_count(), 0, "tilde path should match expanded path");
    }

    #[tokio::test]
    async fn test_pending_to_uncorrelated_transition() {
        let (tx, mut rx) = mpsc::channel(100);
        let config = CorrelationConfig {
            server_pid: 100,
            match_window: Duration::from_millis(50),
            ..Default::default()
        };
        let mut engine = CorrelationEngine::new(config, tx);
        let tree = make_process_tree(100, 200);

        // OS event with old timestamp so it expires quickly
        let os = OsEvent {
            timestamp: Utc::now() - chrono::Duration::milliseconds(100),
            pid: 200,
            ppid: 100,
            process_path: "/bin/bash".into(),
            kind: OsEventKind::Open {
                path: "/tmp/suspicious.txt".into(),
                flags: 0,
            },
            signing_id: None,
            team_id: None,
        };
        engine.process_os_event(os, &tree);
        assert_eq!(engine.pending_os_count(), 1);

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(100)).await;
        engine.tick();

        assert_eq!(engine.pending_os_count(), 0, "pending should have been expired");
        let event = rx.try_recv().expect("should have uncorrelated event");
        assert_eq!(event.status, CorrelationStatus::Uncorrelated);
    }
}
