//! Event clustering engine: groups related security events to reduce SLM inference calls.
//!
//! Instead of triggering a separate SLM call for every event, the clustering buffer
//! groups events by server within a configurable time window. When the window expires
//! or the cluster reaches a maximum size, the finalized cluster is sent for triage.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, trace};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Why events were grouped into a cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterReason {
    /// Events from the same server within the time window.
    TimeWindow,
    /// Events linked by the correlation engine.
    Correlation,
    /// Events matching a kill-chain pattern.
    KillChain,
}

/// A lightweight representation of a single event inside a cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterEvent {
    pub timestamp: DateTime<Utc>,
    /// E.g. "tool_call", "file_read", "file_write", "network_connect".
    pub event_type: String,
    pub tool_name: Option<String>,
    /// File path or network host.
    pub target: Option<String>,
    pub anomaly_score: f64,
    pub server_name: String,
}

/// A finalized group of related events ready for SLM triage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCluster {
    pub id: String,
    pub server_name: String,
    pub events: Vec<ClusterEvent>,
    pub cluster_reason: ClusterReason,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    /// Maximum anomaly score across all events in the cluster.
    pub aggregate_anomaly: f64,
    pub has_kill_chain: bool,
    /// Unique tool names observed.
    pub tool_names: Vec<String>,
    /// Unique file paths / network hosts observed.
    pub targets: Vec<String>,
    /// Human-readable action sequence, e.g. "read_file(~/.ssh/id_rsa) -> network_connect(43.128.x.x)".
    pub action_sequence: String,
}

/// Internal state for a cluster that is still accumulating events.
struct PendingCluster {
    cluster: EventCluster,
    created_at: Instant,
    window_duration: Duration,
}

impl PendingCluster {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.window_duration
    }
}

// ---------------------------------------------------------------------------
// ClusteringBuffer
// ---------------------------------------------------------------------------

/// Buffers incoming events and groups them into clusters per server.
///
/// Clusters are finalized (sent to the output channel) when:
/// - The time window expires, or
/// - The cluster reaches `max_events_per_cluster`.
pub struct ClusteringBuffer {
    pending: Mutex<HashMap<String, PendingCluster>>,
    output: mpsc::Sender<EventCluster>,
    window_duration: Duration,
    max_events_per_cluster: usize,
    id_counter: AtomicU64,
}

impl ClusteringBuffer {
    /// Create a new clustering buffer.
    ///
    /// * `output` - channel to send finalized clusters to.
    /// * `window_duration` - how long to wait before flushing a cluster.
    /// * `max_events` - maximum events per cluster before forced flush.
    pub fn new(
        output: mpsc::Sender<EventCluster>,
        window_duration: Duration,
        max_events: usize,
    ) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            output,
            window_duration,
            max_events_per_cluster: max_events,
            id_counter: AtomicU64::new(1),
        }
    }

    /// Generate a simple unique cluster ID.
    fn next_id(&self) -> String {
        let n = self.id_counter.fetch_add(1, Ordering::Relaxed);
        format!("cluster-{n}")
    }

    /// Add an event to the clustering buffer.
    ///
    /// If the server already has a pending cluster whose window has expired or that
    /// has reached the max event count, the existing cluster is finalized first.
    pub async fn add_event(&self, event: ClusterEvent) {
        let server = event.server_name.clone();
        let mut pending = self.pending.lock().await;

        // Check if we need to flush the existing cluster first.
        if let Some(pc) = pending.get(&server) {
            if pc.is_expired() || pc.cluster.events.len() >= self.max_events_per_cluster {
                let pc = pending.remove(&server).unwrap();
                self.send_cluster(pc.cluster).await;
            }
        }

        if let Some(pc) = pending.get_mut(&server) {
            // Append to existing cluster.
            Self::append_event(&mut pc.cluster, &event);
        } else {
            // Start a new cluster.
            let mut cluster = EventCluster {
                id: self.next_id(),
                server_name: server.clone(),
                events: Vec::new(),
                cluster_reason: ClusterReason::TimeWindow,
                window_start: event.timestamp,
                window_end: event.timestamp,
                aggregate_anomaly: 0.0,
                has_kill_chain: false,
                tool_names: Vec::new(),
                targets: Vec::new(),
                action_sequence: String::new(),
            };
            Self::append_event(&mut cluster, &event);
            pending.insert(
                server,
                PendingCluster {
                    cluster,
                    created_at: Instant::now(),
                    window_duration: self.window_duration,
                },
            );
        }
    }

    /// Flush all clusters whose time window has expired.
    pub async fn flush_expired(&self) {
        let mut pending = self.pending.lock().await;
        let expired_keys: Vec<String> = pending
            .iter()
            .filter(|(_, pc)| pc.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            if let Some(pc) = pending.remove(&key) {
                self.send_cluster(pc.cluster).await;
            }
        }
    }

    /// Flush ALL pending clusters (e.g. on shutdown).
    pub async fn flush_all(&self) {
        let mut pending = self.pending.lock().await;
        let keys: Vec<String> = pending.keys().cloned().collect();
        for key in keys {
            if let Some(pc) = pending.remove(&key) {
                self.send_cluster(pc.cluster).await;
            }
        }
    }

    /// Number of servers with pending (unflushed) clusters.
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }

    /// Spawn a background task that flushes expired clusters every `interval`.
    pub fn spawn_flush_loop(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let buffer = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                buffer.flush_expired().await;
            }
        })
    }

    // -- internal helpers --

    /// Append an event to a cluster, updating aggregates.
    fn append_event(cluster: &mut EventCluster, event: &ClusterEvent) {
        // Update window bounds.
        if event.timestamp < cluster.window_start {
            cluster.window_start = event.timestamp;
        }
        if event.timestamp > cluster.window_end {
            cluster.window_end = event.timestamp;
        }

        // Update aggregate anomaly (max).
        if event.anomaly_score > cluster.aggregate_anomaly {
            cluster.aggregate_anomaly = event.anomaly_score;
        }

        // Track unique tool names.
        if let Some(ref tool) = event.tool_name {
            if !cluster.tool_names.contains(tool) {
                cluster.tool_names.push(tool.clone());
            }
        }

        // Track unique targets.
        if let Some(ref target) = event.target {
            if !cluster.targets.contains(target) {
                cluster.targets.push(target.clone());
            }
        }

        // Detect kill-chain patterns.
        cluster.has_kill_chain = detect_kill_chain(&cluster.events, event);

        cluster.events.push(event.clone());

        // Rebuild action sequence.
        cluster.action_sequence = build_action_sequence(&cluster.events);
    }

    async fn send_cluster(&self, cluster: EventCluster) {
        debug!(
            id = %cluster.id,
            server = %cluster.server_name,
            events = cluster.events.len(),
            anomaly = cluster.aggregate_anomaly,
            "Flushing event cluster"
        );
        if let Err(e) = self.output.send(cluster).await {
            trace!("Cluster output channel closed: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a human-readable action sequence from a list of events.
///
/// Example output: `"read_file(~/.ssh/id_rsa) -> network_connect(43.128.x.x)"`
fn build_action_sequence(events: &[ClusterEvent]) -> String {
    events
        .iter()
        .map(|e| {
            let target = e.target.as_deref().unwrap_or("?");
            format!("{}({})", e.event_type, target)
        })
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// Simple kill-chain heuristic: credential access followed by network activity.
fn detect_kill_chain(existing: &[ClusterEvent], new_event: &ClusterEvent) -> bool {
    let is_network = matches!(
        new_event.event_type.as_str(),
        "network_connect" | "http_post" | "http_get"
    );
    let has_credential_access = existing.iter().any(|e| {
        if let Some(ref target) = e.target {
            let t = target.to_lowercase();
            t.contains(".ssh")
                || t.contains("id_rsa")
                || t.contains("credentials")
                || t.contains("passwd")
                || t.contains("shadow")
                || t.contains("token")
        } else {
            false
        }
    });

    if is_network && has_credential_access {
        return true;
    }

    // Also check the reverse: existing network event, new credential access.
    let new_is_credential = new_event.target.as_ref().map_or(false, |t| {
        let t = t.to_lowercase();
        t.contains(".ssh")
            || t.contains("id_rsa")
            || t.contains("credentials")
            || t.contains("passwd")
            || t.contains("shadow")
            || t.contains("token")
    });
    let has_network = existing.iter().any(|e| {
        matches!(
            e.event_type.as_str(),
            "network_connect" | "http_post" | "http_get"
        )
    });

    new_is_credential && has_network
}

// ---------------------------------------------------------------------------
// Prompt formatters
// ---------------------------------------------------------------------------

impl EventCluster {
    /// Format this cluster as a compact triage prompt line.
    ///
    /// Example:
    /// ```text
    /// CLUSTER server=FileManager events=5 window=30s anomaly_max=0.72 killchain=true
    /// SEQUENCE: read_file(~/.ssh/id_rsa) -> network_connect(43.128.x.x)
    /// ```
    pub fn to_triage_prompt(&self) -> String {
        let window_secs = (self.window_end - self.window_start).num_seconds();
        format!(
            "CLUSTER server={} events={} window={}s anomaly_max={:.2} killchain={}\nSEQUENCE: {}",
            self.server_name,
            self.events.len(),
            window_secs,
            self.aggregate_anomaly,
            self.has_kill_chain,
            self.action_sequence,
        )
    }

    /// Format this cluster for detailed SLM analysis.
    pub fn to_deep_analysis_prompt(&self) -> String {
        let window_secs = (self.window_end - self.window_start).num_seconds();
        let mut prompt = format!(
            "DEEP ANALYSIS REQUEST\n\
             Server: {}\n\
             Events: {}\n\
             Time window: {}s\n\
             Max anomaly score: {:.2}\n\
             Kill chain detected: {}\n\
             Tools used: {}\n\
             Targets: {}\n\n\
             Action sequence:\n  {}\n\n\
             Individual events:\n",
            self.server_name,
            self.events.len(),
            window_secs,
            self.aggregate_anomaly,
            self.has_kill_chain,
            if self.tool_names.is_empty() {
                "none".to_string()
            } else {
                self.tool_names.join(", ")
            },
            if self.targets.is_empty() {
                "none".to_string()
            } else {
                self.targets.join(", ")
            },
            self.action_sequence,
        );

        for (i, event) in self.events.iter().enumerate() {
            prompt.push_str(&format!(
                "  {}. [{}] {} target={} anomaly={:.2}\n",
                i + 1,
                event.timestamp.format("%H:%M:%S"),
                event.event_type,
                event.target.as_deref().unwrap_or("?"),
                event.anomaly_score,
            ));
        }

        prompt
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_event(
        server: &str,
        event_type: &str,
        target: Option<&str>,
        anomaly: f64,
    ) -> ClusterEvent {
        ClusterEvent {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            tool_name: Some(event_type.to_string()),
            target: target.map(|t| t.to_string()),
            anomaly_score: anomaly,
            server_name: server.to_string(),
        }
    }

    fn make_event_at(
        server: &str,
        event_type: &str,
        target: Option<&str>,
        anomaly: f64,
        ts: DateTime<Utc>,
    ) -> ClusterEvent {
        ClusterEvent {
            timestamp: ts,
            event_type: event_type.to_string(),
            tool_name: Some(event_type.to_string()),
            target: target.map(|t| t.to_string()),
            anomaly_score: anomaly,
            server_name: server.to_string(),
        }
    }

    #[tokio::test]
    async fn single_event_creates_cluster() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_millis(50), 20);

        buffer
            .add_event(make_event("server-a", "tool_call", Some("/tmp/file"), 0.5))
            .await;

        assert_eq!(buffer.pending_count().await, 1);

        // Flush to get the cluster.
        buffer.flush_all().await;
        let cluster = rx.recv().await.unwrap();
        assert_eq!(cluster.events.len(), 1);
        assert_eq!(cluster.server_name, "server-a");
    }

    #[tokio::test]
    async fn multiple_events_same_server_grouped() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(30), 20);

        buffer
            .add_event(make_event("server-a", "file_read", Some("/etc/hosts"), 0.3))
            .await;
        buffer
            .add_event(make_event(
                "server-a",
                "file_read",
                Some("/etc/hostname"),
                0.2,
            ))
            .await;
        buffer
            .add_event(make_event(
                "server-a",
                "network_connect",
                Some("10.0.0.1"),
                0.7,
            ))
            .await;

        assert_eq!(buffer.pending_count().await, 1);

        buffer.flush_all().await;
        let cluster = rx.recv().await.unwrap();
        assert_eq!(cluster.events.len(), 3);
        assert_eq!(cluster.server_name, "server-a");
    }

    #[tokio::test]
    async fn different_servers_separate_clusters() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(30), 20);

        buffer
            .add_event(make_event("server-a", "file_read", Some("/tmp/a"), 0.1))
            .await;
        buffer
            .add_event(make_event("server-b", "file_read", Some("/tmp/b"), 0.2))
            .await;

        assert_eq!(buffer.pending_count().await, 2);

        buffer.flush_all().await;
        let c1 = rx.recv().await.unwrap();
        let c2 = rx.recv().await.unwrap();
        assert_ne!(c1.server_name, c2.server_name);
    }

    #[tokio::test]
    async fn window_expiry_flushes_cluster() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_millis(30), 20);

        buffer
            .add_event(make_event("server-a", "file_read", Some("/tmp/a"), 0.1))
            .await;

        // Wait for the window to expire.
        tokio::time::sleep(Duration::from_millis(50)).await;

        buffer.flush_expired().await;
        assert_eq!(buffer.pending_count().await, 0);

        let cluster = rx.recv().await.unwrap();
        assert_eq!(cluster.events.len(), 1);
        assert_eq!(cluster.server_name, "server-a");
    }

    #[tokio::test]
    async fn max_events_per_cluster_caps_at_limit() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(300), 5);

        // Add 5 events -- they fit in one cluster.
        for i in 0..5 {
            buffer
                .add_event(make_event(
                    "server-a",
                    "tool_call",
                    Some(&format!("/tmp/{i}")),
                    0.1,
                ))
                .await;
        }
        assert_eq!(buffer.pending_count().await, 1);

        // The 6th event should flush the first cluster (5 events) and start a new one.
        buffer
            .add_event(make_event("server-a", "tool_call", Some("/tmp/5"), 0.1))
            .await;
        assert_eq!(buffer.pending_count().await, 1);

        let cluster = rx.recv().await.unwrap();
        assert_eq!(cluster.events.len(), 5);
    }

    #[tokio::test]
    async fn burst_of_50_events_creates_correct_clusters() {
        let (tx, mut rx) = mpsc::channel(64);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(300), 20);

        for i in 0..50 {
            buffer
                .add_event(make_event(
                    "server-a",
                    "tool_call",
                    Some(&format!("/tmp/{i}")),
                    0.1,
                ))
                .await;
        }

        // Should have flushed 2 clusters of 20 already, with 10 pending.
        buffer.flush_all().await;

        let mut total_events = 0;
        let mut cluster_count = 0;
        while let Ok(cluster) = rx.try_recv() {
            total_events += cluster.events.len();
            cluster_count += 1;
        }
        assert_eq!(total_events, 50);
        assert_eq!(cluster_count, 3);
    }

    #[tokio::test]
    async fn to_triage_prompt_format() {
        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 30).unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(300), 20);

        buffer
            .add_event(make_event_at(
                "FileManager",
                "read_file",
                Some("~/.ssh/id_rsa"),
                0.72,
                ts1,
            ))
            .await;
        buffer
            .add_event(make_event_at(
                "FileManager",
                "network_connect",
                Some("43.128.0.1"),
                0.65,
                ts2,
            ))
            .await;

        buffer.flush_all().await;
        let cluster = rx.recv().await.unwrap();

        let prompt = cluster.to_triage_prompt();
        assert!(prompt.contains("server=FileManager"));
        assert!(prompt.contains("events=2"));
        assert!(prompt.contains("window=30s"));
        assert!(prompt.contains("anomaly_max=0.72"));
        assert!(prompt.contains("killchain=true"));
        assert!(prompt.contains("SEQUENCE:"));
    }

    #[tokio::test]
    async fn aggregate_anomaly_is_max() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(300), 20);

        buffer
            .add_event(make_event("server-a", "file_read", Some("/tmp/a"), 0.3))
            .await;
        buffer
            .add_event(make_event("server-a", "file_read", Some("/tmp/b"), 0.9))
            .await;
        buffer
            .add_event(make_event("server-a", "file_read", Some("/tmp/c"), 0.5))
            .await;

        buffer.flush_all().await;
        let cluster = rx.recv().await.unwrap();
        assert!((cluster.aggregate_anomaly - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn action_sequence_builder() {
        let events = vec![
            make_event("s", "read_file", Some("~/.ssh/id_rsa"), 0.5),
            make_event("s", "http_post", Some("43.128.x.x"), 0.6),
            make_event("s", "network_connect", Some("43.128.x.x:443"), 0.7),
        ];
        let seq = build_action_sequence(&events);
        assert_eq!(
            seq,
            "read_file(~/.ssh/id_rsa) -> http_post(43.128.x.x) -> network_connect(43.128.x.x:443)"
        );
    }

    #[test]
    fn action_sequence_missing_target() {
        let events = vec![make_event("s", "unknown_op", None, 0.1)];
        let seq = build_action_sequence(&events);
        assert_eq!(seq, "unknown_op(?)");
    }

    #[tokio::test]
    async fn flush_all_produces_all_pending() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(300), 20);

        buffer
            .add_event(make_event("server-a", "file_read", Some("/a"), 0.1))
            .await;
        buffer
            .add_event(make_event("server-b", "file_read", Some("/b"), 0.2))
            .await;
        buffer
            .add_event(make_event("server-c", "file_read", Some("/c"), 0.3))
            .await;

        assert_eq!(buffer.pending_count().await, 3);
        buffer.flush_all().await;
        assert_eq!(buffer.pending_count().await, 0);

        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn has_kill_chain_set_correctly() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(300), 20);

        // Credential access followed by network activity -> kill chain.
        buffer
            .add_event(make_event(
                "server-a",
                "file_read",
                Some("~/.ssh/id_rsa"),
                0.8,
            ))
            .await;
        buffer
            .add_event(make_event(
                "server-a",
                "network_connect",
                Some("evil.com"),
                0.9,
            ))
            .await;

        buffer.flush_all().await;
        let cluster = rx.recv().await.unwrap();
        assert!(cluster.has_kill_chain);
    }

    #[tokio::test]
    async fn no_kill_chain_for_normal_events() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(300), 20);

        buffer
            .add_event(make_event(
                "server-a",
                "file_read",
                Some("/tmp/readme"),
                0.1,
            ))
            .await;
        buffer
            .add_event(make_event(
                "server-a",
                "file_write",
                Some("/tmp/output"),
                0.2,
            ))
            .await;

        buffer.flush_all().await;
        let cluster = rx.recv().await.unwrap();
        assert!(!cluster.has_kill_chain);
    }

    #[tokio::test]
    async fn unique_tool_names_tracked() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(300), 20);

        buffer
            .add_event(make_event("s", "file_read", Some("/a"), 0.1))
            .await;
        buffer
            .add_event(make_event("s", "file_read", Some("/b"), 0.1))
            .await;
        buffer
            .add_event(make_event("s", "file_write", Some("/c"), 0.1))
            .await;

        buffer.flush_all().await;
        let cluster = rx.recv().await.unwrap();
        assert_eq!(cluster.tool_names.len(), 2);
        assert!(cluster.tool_names.contains(&"file_read".to_string()));
        assert!(cluster.tool_names.contains(&"file_write".to_string()));
    }

    #[tokio::test]
    async fn unique_targets_tracked() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(300), 20);

        buffer
            .add_event(make_event("s", "file_read", Some("/shared"), 0.1))
            .await;
        buffer
            .add_event(make_event("s", "file_read", Some("/shared"), 0.1))
            .await;
        buffer
            .add_event(make_event("s", "file_write", Some("/other"), 0.1))
            .await;

        buffer.flush_all().await;
        let cluster = rx.recv().await.unwrap();
        assert_eq!(cluster.targets.len(), 2);
    }

    #[tokio::test]
    async fn deep_analysis_prompt_contains_details() {
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_secs(300), 20);

        buffer
            .add_event(make_event(
                "MyServer",
                "read_file",
                Some("/etc/passwd"),
                0.85,
            ))
            .await;

        buffer.flush_all().await;
        let cluster = rx.recv().await.unwrap();

        let prompt = cluster.to_deep_analysis_prompt();
        assert!(prompt.contains("DEEP ANALYSIS REQUEST"));
        assert!(prompt.contains("Server: MyServer"));
        assert!(prompt.contains("Events: 1"));
        assert!(prompt.contains("Max anomaly score: 0.85"));
        assert!(prompt.contains("/etc/passwd"));
    }

    #[tokio::test]
    async fn window_expiry_on_add_event() {
        // When adding an event and the existing cluster is expired, it should flush first.
        let (tx, mut rx) = mpsc::channel(16);
        let buffer = ClusteringBuffer::new(tx, Duration::from_millis(20), 20);

        buffer
            .add_event(make_event("server-a", "file_read", Some("/a"), 0.1))
            .await;

        tokio::time::sleep(Duration::from_millis(40)).await;

        // This add should flush the expired cluster first, then start a new one.
        buffer
            .add_event(make_event("server-a", "file_read", Some("/b"), 0.2))
            .await;

        let flushed = rx.recv().await.unwrap();
        assert_eq!(flushed.events.len(), 1);
        assert_eq!(flushed.events[0].target.as_deref(), Some("/a"));

        // The new event should be in a new pending cluster.
        assert_eq!(buffer.pending_count().await, 1);
    }
}
