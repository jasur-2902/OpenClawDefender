//! SLM inference throttle and demand-driven scheduler.
//!
//! Ensures the SLM doesn't burn CPU/GPU constantly by:
//! - Batching clusters and processing them on a demand-driven schedule
//! - Adapting batch intervals based on system CPU load
//! - Enforcing cooldown periods between inference batches
//! - Skipping inference for known patterns via a knowledge base fast-path
//! - Pausing SLM work when on battery and the system is under load
//! - Tracking inference statistics for observability

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::clustering::EventCluster;
use crate::triage::TriageLevel;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the SLM scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmSchedulerConfig {
    /// Cooldown duration between inference batches (seconds).
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
    /// Maximum number of pending batches before dropping oldest.
    #[serde(default = "default_max_pending")]
    pub max_pending_batches: usize,
    /// CPU usage threshold (0-100) above which we back off.
    #[serde(default = "default_cpu_backoff_threshold")]
    pub cpu_backoff_threshold: f32,
    /// CPU usage threshold (0-100) above which we consider the system heavy.
    #[serde(default = "default_cpu_heavy_threshold")]
    pub cpu_heavy_threshold: f32,
    /// CPU usage threshold (0-100) below which the system is idle.
    #[serde(default = "default_cpu_idle_threshold")]
    pub cpu_idle_threshold: f32,
    /// Battery CPU threshold: pause SLM if on battery and CPU > this.
    #[serde(default = "default_battery_cpu_pause_threshold")]
    pub battery_cpu_pause_threshold: f32,
    /// Batch interval on battery (seconds) when CPU is low enough to process.
    #[serde(default = "default_battery_batch_interval_secs")]
    pub battery_batch_interval_secs: u64,
    /// Number of approved events before a server is considered "high trust".
    #[serde(default = "default_high_trust_event_count")]
    pub high_trust_event_count: u64,
}

fn default_cooldown_secs() -> u64 {
    2
}
fn default_max_pending() -> usize {
    32
}
fn default_cpu_backoff_threshold() -> f32 {
    50.0
}
fn default_cpu_heavy_threshold() -> f32 {
    80.0
}
fn default_cpu_idle_threshold() -> f32 {
    20.0
}
fn default_battery_cpu_pause_threshold() -> f32 {
    30.0
}
fn default_battery_batch_interval_secs() -> u64 {
    30
}
fn default_high_trust_event_count() -> u64 {
    20
}

impl Default for SlmSchedulerConfig {
    fn default() -> Self {
        Self {
            cooldown_secs: default_cooldown_secs(),
            max_pending_batches: default_max_pending(),
            cpu_backoff_threshold: default_cpu_backoff_threshold(),
            cpu_heavy_threshold: default_cpu_heavy_threshold(),
            cpu_idle_threshold: default_cpu_idle_threshold(),
            battery_cpu_pause_threshold: default_battery_cpu_pause_threshold(),
            battery_batch_interval_secs: default_battery_batch_interval_secs(),
            high_trust_event_count: default_high_trust_event_count(),
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Current state of the SLM scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlmState {
    /// No pending work, model warm but not inferring.
    Idle,
    /// Actively running inference.
    Processing,
    /// System under load, holding work.
    Paused,
    /// Just finished, waiting before next batch.
    Cooldown,
}

impl std::fmt::Display for SlmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlmState::Idle => write!(f, "IDLE"),
            SlmState::Processing => write!(f, "PROCESSING"),
            SlmState::Paused => write!(f, "PAUSED"),
            SlmState::Cooldown => write!(f, "COOLDOWN"),
        }
    }
}

/// System load classification derived from CPU usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemLoad {
    /// CPU < 20%: user likely idle.
    Idle,
    /// CPU 20-50%: light work.
    Light,
    /// CPU 50-80%: moderate work (editor, builds starting).
    Moderate,
    /// CPU 80-95%: heavy build or compute.
    Heavy,
    /// CPU > 95%: system saturated.
    Critical,
}

impl SystemLoad {
    /// Classify CPU usage percentage into a load tier.
    pub fn from_cpu_percent(cpu: f32) -> Self {
        if cpu < 20.0 {
            SystemLoad::Idle
        } else if cpu < 50.0 {
            SystemLoad::Light
        } else if cpu < 80.0 {
            SystemLoad::Moderate
        } else if cpu < 95.0 {
            SystemLoad::Heavy
        } else {
            SystemLoad::Critical
        }
    }

    /// Recommended batch delay for this load level.
    pub fn batch_delay(&self) -> Duration {
        match self {
            SystemLoad::Idle => Duration::from_secs(3),
            SystemLoad::Light => Duration::from_secs(5),
            SystemLoad::Moderate => Duration::from_secs(10),
            SystemLoad::Heavy => Duration::from_secs(30),
            SystemLoad::Critical => Duration::from_secs(60),
        }
    }
}

impl std::fmt::Display for SystemLoad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemLoad::Idle => write!(f, "IDLE"),
            SystemLoad::Light => write!(f, "LIGHT"),
            SystemLoad::Moderate => write!(f, "MODERATE"),
            SystemLoad::Heavy => write!(f, "HEAVY"),
            SystemLoad::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Result of the knowledge base fast-path check.
#[derive(Debug, Clone)]
pub enum FastPathResult {
    /// Known false positive pattern -- classify as ROUTINE without inference.
    KnownRoutine(String),
    /// Known attack pattern -- classify as SUSPICIOUS without inference.
    KnownSuspicious(String),
    /// No match -- requires SLM inference.
    NoMatch,
}

/// Power state re-exported for SLM scheduler use.
/// Uses the same enum from the daemon scheduler module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    PluggedIn,
    Battery(u8),
    LowBattery(u8),
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Statistics tracked by the SLM scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmSchedulerStats {
    /// Total inference calls executed.
    pub inference_calls: u64,
    /// Events skipped via knowledge base fast-path.
    pub events_skipped_knowledge_base: u64,
    /// Events skipped because system load was too high.
    pub events_skipped_load: u64,
    /// Events skipped because of battery + load pause.
    pub events_skipped_battery: u64,
    /// Total wall-clock latency across all inferences (ms).
    pub total_inference_latency_ms: u64,
    /// Number of batches processed.
    pub batches_processed: u64,
    /// Number of batches dropped (queue overflow).
    pub batches_dropped: u64,
    /// Current scheduler state.
    pub current_state: String,
    /// Current system load classification.
    pub current_load: String,
}

/// Atomic counters for lock-free stats tracking.
pub struct SlmSchedulerCounters {
    pub inference_calls: AtomicU64,
    pub events_skipped_knowledge_base: AtomicU64,
    pub events_skipped_load: AtomicU64,
    pub events_skipped_battery: AtomicU64,
    pub total_inference_latency_ms: AtomicU64,
    pub batches_processed: AtomicU64,
    pub batches_dropped: AtomicU64,
}

impl SlmSchedulerCounters {
    pub fn new() -> Self {
        Self {
            inference_calls: AtomicU64::new(0),
            events_skipped_knowledge_base: AtomicU64::new(0),
            events_skipped_load: AtomicU64::new(0),
            events_skipped_battery: AtomicU64::new(0),
            total_inference_latency_ms: AtomicU64::new(0),
            batches_processed: AtomicU64::new(0),
            batches_dropped: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> SlmSchedulerStats {
        SlmSchedulerStats {
            inference_calls: self.inference_calls.load(Ordering::Relaxed),
            events_skipped_knowledge_base: self
                .events_skipped_knowledge_base
                .load(Ordering::Relaxed),
            events_skipped_load: self.events_skipped_load.load(Ordering::Relaxed),
            events_skipped_battery: self.events_skipped_battery.load(Ordering::Relaxed),
            total_inference_latency_ms: self.total_inference_latency_ms.load(Ordering::Relaxed),
            batches_processed: self.batches_processed.load(Ordering::Relaxed),
            batches_dropped: self.batches_dropped.load(Ordering::Relaxed),
            current_state: String::new(), // filled in by scheduler
            current_load: String::new(),  // filled in by scheduler
        }
    }
}

impl Default for SlmSchedulerCounters {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Knowledge base fast-path
// ---------------------------------------------------------------------------

/// Known patterns that can be resolved without SLM inference.
pub struct KnowledgeBase {
    /// Action sequences known to be false positives.
    false_positive_patterns: Vec<KnownPattern>,
    /// Action sequences known to be suspicious.
    suspicious_patterns: Vec<KnownPattern>,
}

struct KnownPattern {
    /// Description of the pattern (for logging).
    description: String,
    /// Matcher: returns true if the cluster matches this pattern.
    matcher: Box<dyn Fn(&EventCluster) -> bool + Send + Sync>,
}

impl KnowledgeBase {
    /// Create a knowledge base pre-populated with default patterns.
    pub fn with_defaults() -> Self {
        let mut kb = Self {
            false_positive_patterns: Vec::new(),
            suspicious_patterns: Vec::new(),
        };

        // --- Known false positives ---

        // IDE/editor file watches: single file_read events in common project dirs
        kb.false_positive_patterns.push(KnownPattern {
            description: "IDE file watch: single read in project directory".to_string(),
            matcher: Box::new(|cluster| {
                if cluster.events.len() != 1 {
                    return false;
                }
                let evt = &cluster.events[0];
                if evt.event_type != "file_read" && evt.event_type != "file_open" {
                    return false;
                }
                if let Some(ref target) = evt.target {
                    let t = target.to_lowercase();
                    // Common project directories
                    t.contains("/src/")
                        || t.contains("/lib/")
                        || t.contains("/test")
                        || t.contains("/node_modules/")
                        || t.contains("/target/")
                        || t.contains("/.git/")
                        || t.ends_with(".ts")
                        || t.ends_with(".js")
                        || t.ends_with(".rs")
                        || t.ends_with(".py")
                        || t.ends_with(".go")
                        || t.ends_with(".json")
                        || t.ends_with(".toml")
                        || t.ends_with(".yaml")
                        || t.ends_with(".yml")
                        || t.ends_with(".md")
                } else {
                    false
                }
            }),
        });

        // Temp file operations
        kb.false_positive_patterns.push(KnownPattern {
            description: "Temp file operations in /tmp or /var/folders".to_string(),
            matcher: Box::new(|cluster| {
                cluster.events.iter().all(|e| {
                    e.target.as_ref().is_some_and(|t| {
                        t.starts_with("/tmp/")
                            || t.starts_with("/var/folders/")
                            || t.starts_with("/private/tmp/")
                    })
                })
            }),
        });

        // --- Known suspicious patterns ---

        // Any cluster with kill chain already detected
        kb.suspicious_patterns.push(KnownPattern {
            description: "Kill chain pattern detected in cluster".to_string(),
            matcher: Box::new(|cluster| cluster.has_kill_chain),
        });

        // High anomaly score clusters (>= 0.9)
        kb.suspicious_patterns.push(KnownPattern {
            description: "Very high anomaly score (>= 0.9)".to_string(),
            matcher: Box::new(|cluster| cluster.aggregate_anomaly >= 0.9),
        });

        // Credential file access
        kb.suspicious_patterns.push(KnownPattern {
            description: "Credential or key file access".to_string(),
            matcher: Box::new(|cluster| {
                cluster.targets.iter().any(|t| {
                    let lower = t.to_lowercase();
                    lower.contains(".ssh/")
                        || lower.contains("id_rsa")
                        || lower.contains("id_ed25519")
                        || lower.contains("/etc/shadow")
                        || lower.contains(".env")
                        || lower.contains("credentials")
                        || lower.contains("secrets")
                        || lower.contains(".aws/")
                        || lower.contains(".kube/config")
                })
            }),
        });

        kb
    }

    /// Check if a cluster matches any known pattern.
    pub fn check(&self, cluster: &EventCluster) -> FastPathResult {
        // Check suspicious patterns first (fail-closed: if both match, suspicious wins).
        for pattern in &self.suspicious_patterns {
            if (pattern.matcher)(cluster) {
                return FastPathResult::KnownSuspicious(pattern.description.clone());
            }
        }

        for pattern in &self.false_positive_patterns {
            if (pattern.matcher)(cluster) {
                return FastPathResult::KnownRoutine(pattern.description.clone());
            }
        }

        FastPathResult::NoMatch
    }
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// The SLM inference scheduler.
///
/// Manages a queue of pending event clusters and decides when to process them
/// based on system load, power state, and cooldown timers.
pub struct SlmScheduler {
    config: SlmSchedulerConfig,
    pending: Mutex<VecDeque<EventCluster>>,
    state: Mutex<SlmState>,
    system_load: Mutex<SystemLoad>,
    power_state: Mutex<PowerState>,
    last_inference: Mutex<Instant>,
    knowledge_base: KnowledgeBase,
    counters: Arc<SlmSchedulerCounters>,
}

impl SlmScheduler {
    /// Create a new scheduler with default knowledge base.
    pub fn new(config: SlmSchedulerConfig) -> Self {
        Self {
            config,
            pending: Mutex::new(VecDeque::new()),
            state: Mutex::new(SlmState::Idle),
            system_load: Mutex::new(SystemLoad::Idle),
            power_state: Mutex::new(PowerState::PluggedIn),
            last_inference: Mutex::new(Instant::now()),
            knowledge_base: KnowledgeBase::with_defaults(),
            counters: Arc::new(SlmSchedulerCounters::new()),
        }
    }

    /// Get a reference to the stats counters.
    pub fn counters(&self) -> &Arc<SlmSchedulerCounters> {
        &self.counters
    }

    /// Get current scheduler stats.
    pub async fn stats(&self) -> SlmSchedulerStats {
        let mut stats = self.counters.snapshot();
        stats.current_state = self.state.lock().await.to_string();
        stats.current_load = self.system_load.lock().await.to_string();
        stats
    }

    /// Submit a cluster for scheduled processing.
    ///
    /// The cluster is first checked against the knowledge base. If it matches
    /// a known pattern, it's resolved immediately without queuing. Otherwise
    /// it's added to the pending queue.
    ///
    /// Returns the fast-path result if the cluster was resolved without queuing.
    pub async fn submit(&self, cluster: EventCluster) -> Option<(TriageLevel, FastPathResult)> {
        // Knowledge base fast-path check.
        let fast_result = self.knowledge_base.check(&cluster);
        match &fast_result {
            FastPathResult::KnownRoutine(reason) => {
                debug!(
                    cluster_id = %cluster.id,
                    reason = %reason,
                    "Knowledge base fast-path: ROUTINE (skipping SLM)"
                );
                self.counters
                    .events_skipped_knowledge_base
                    .fetch_add(1, Ordering::Relaxed);
                return Some((TriageLevel::Routine, fast_result));
            }
            FastPathResult::KnownSuspicious(reason) => {
                debug!(
                    cluster_id = %cluster.id,
                    reason = %reason,
                    "Knowledge base fast-path: SUSPICIOUS (skipping SLM)"
                );
                self.counters
                    .events_skipped_knowledge_base
                    .fetch_add(1, Ordering::Relaxed);
                return Some((TriageLevel::Suspicious, fast_result));
            }
            FastPathResult::NoMatch => {}
        }

        // Add to pending queue.
        let mut pending = self.pending.lock().await;
        if pending.len() >= self.config.max_pending_batches {
            // Drop oldest batch to make room.
            let dropped = pending.pop_front();
            if let Some(dropped_cluster) = dropped {
                warn!(
                    dropped_id = %dropped_cluster.id,
                    queue_size = pending.len(),
                    "SLM scheduler queue full, dropped oldest batch"
                );
                self.counters.batches_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        pending.push_back(cluster);
        None
    }

    /// Update system CPU load. Call this periodically (e.g., every 5 seconds).
    pub async fn update_cpu_load(&self, cpu_percent: f32) {
        let load = SystemLoad::from_cpu_percent(cpu_percent);
        let mut current = self.system_load.lock().await;
        if *current != load {
            debug!(
                old = %*current,
                new = %load,
                cpu = cpu_percent,
                "SLM scheduler: system load changed"
            );
            *current = load;
        }
    }

    /// Update power state. Call this when power state changes.
    pub async fn update_power_state(&self, state: PowerState) {
        let mut current = self.power_state.lock().await;
        if *current != state {
            info!(
                old = ?*current,
                new = ?state,
                "SLM scheduler: power state changed"
            );
            *current = state;
        }
    }

    /// Check if the scheduler should process the next batch now.
    ///
    /// Returns `true` if:
    /// - There are pending batches
    /// - Cooldown has elapsed
    /// - System load and power state allow processing
    /// - Adaptive batch delay has elapsed
    pub async fn should_process(&self) -> bool {
        let pending = self.pending.lock().await;
        if pending.is_empty() {
            return false;
        }
        drop(pending);

        let power = *self.power_state.lock().await;
        let load = *self.system_load.lock().await;
        let last = *self.last_inference.lock().await;

        // Battery-aware pausing.
        match power {
            PowerState::Battery(_) | PowerState::LowBattery(_) => {
                if matches!(load, SystemLoad::Moderate | SystemLoad::Heavy | SystemLoad::Critical) {
                    // On battery with CPU > threshold: pause entirely.
                    return false;
                }
                // On battery with low CPU: use longer interval.
                let battery_interval =
                    Duration::from_secs(self.config.battery_batch_interval_secs);
                if last.elapsed() < battery_interval {
                    return false;
                }
            }
            PowerState::PluggedIn => {
                // Check cooldown.
                let cooldown = Duration::from_secs(self.config.cooldown_secs);
                if last.elapsed() < cooldown {
                    return false;
                }

                // Check adaptive batch delay based on system load.
                let batch_delay = load.batch_delay();
                if last.elapsed() < batch_delay {
                    return false;
                }
            }
        }

        // Low battery: only process if system is truly idle.
        if matches!(power, PowerState::LowBattery(_)) && !matches!(load, SystemLoad::Idle) {
            return false;
        }

        true
    }

    /// Take the next batch from the pending queue for processing.
    ///
    /// Call this only after `should_process()` returns `true`.
    /// Transitions state to `Processing`.
    pub async fn take_next_batch(&self) -> Option<EventCluster> {
        let mut pending = self.pending.lock().await;
        let cluster = pending.pop_front();
        if cluster.is_some() {
            *self.state.lock().await = SlmState::Processing;
        }
        cluster
    }

    /// Mark the current batch as complete. Transitions to `Cooldown`.
    ///
    /// `latency_ms` is the wall-clock time the inference took.
    pub async fn mark_batch_complete(&self, latency_ms: u64) {
        *self.last_inference.lock().await = Instant::now();
        *self.state.lock().await = SlmState::Cooldown;
        self.counters.inference_calls.fetch_add(1, Ordering::Relaxed);
        self.counters
            .batches_processed
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .total_inference_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
    }

    /// Record that events were skipped due to system load.
    pub fn record_load_skip(&self, count: u64) {
        self.counters
            .events_skipped_load
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Record that events were skipped due to battery state.
    pub fn record_battery_skip(&self, count: u64) {
        self.counters
            .events_skipped_battery
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Get the current number of pending batches.
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }

    /// Get the current scheduler state.
    pub async fn state(&self) -> SlmState {
        *self.state.lock().await
    }

    /// Get the current system load.
    pub async fn system_load(&self) -> SystemLoad {
        *self.system_load.lock().await
    }

    /// Update the scheduler state (called by the processing loop).
    pub async fn set_state(&self, state: SlmState) {
        *self.state.lock().await = state;
    }

    /// Get the adaptive delay before the next batch based on current conditions.
    pub async fn next_batch_delay(&self) -> Duration {
        let power = *self.power_state.lock().await;
        let load = *self.system_load.lock().await;

        match power {
            PowerState::LowBattery(_) => Duration::from_secs(60),
            PowerState::Battery(_) => {
                Duration::from_secs(self.config.battery_batch_interval_secs)
            }
            PowerState::PluggedIn => load.batch_delay(),
        }
    }
}

// ---------------------------------------------------------------------------
// CPU load sampling (macOS)
// ---------------------------------------------------------------------------

/// Sample the current system-wide CPU usage percentage.
///
/// On macOS, uses `host_processor_info` via sysctl. Falls back to 0.0 on error.
#[cfg(target_os = "macos")]
pub fn sample_cpu_usage() -> f32 {
    use std::process::Command;

    // Use `sysctl` to get load average as a rough CPU proxy.
    // For more accurate per-core CPU, we'd use host_processor_info(),
    // but load average is sufficient for our throttling purposes.
    let output = match Command::new("sysctl").args(["-n", "vm.loadavg"]).output() {
        Ok(o) => o,
        Err(_) => return 0.0,
    };

    if !output.status.success() {
        return 0.0;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: "{ 1.50 2.00 1.75 }" — parse the 1-minute load average.
    let load_1min = stdout
        .trim()
        .trim_start_matches('{')
        .trim()
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f32>().ok())
        .unwrap_or(0.0);

    // Convert load average to approximate CPU percentage.
    // load_avg / num_cpus * 100 gives a rough percentage.
    let num_cpus = num_cpus::get() as f32;
    ((load_1min / num_cpus) * 100.0).min(100.0)
}

/// Fallback for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn sample_cpu_usage() -> f32 {
    0.0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clustering::{ClusterEvent, ClusterReason, EventCluster};
    use chrono::Utc;

    /// Create a cluster that does NOT match any knowledge base pattern
    /// (not a project file, not a temp file, not a credential file, not kill chain).
    fn make_cluster(id: &str, server: &str) -> EventCluster {
        EventCluster {
            id: id.to_string(),
            server_name: server.to_string(),
            events: vec![ClusterEvent {
                timestamp: Utc::now(),
                event_type: "tool_call".to_string(),
                tool_name: Some("custom_tool".to_string()),
                target: Some("/usr/local/bin/analyze".to_string()),
                anomaly_score: 0.3,
                server_name: server.to_string(),
            }],
            cluster_reason: ClusterReason::TimeWindow,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.3,
            has_kill_chain: false,
            tool_names: vec!["custom_tool".to_string()],
            targets: vec!["/usr/local/bin/analyze".to_string()],
            action_sequence: "tool_call(/usr/local/bin/analyze)".to_string(),
        }
    }

    fn make_project_file_cluster(id: &str) -> EventCluster {
        EventCluster {
            id: id.to_string(),
            server_name: "dev-server".to_string(),
            events: vec![ClusterEvent {
                timestamp: Utc::now(),
                event_type: "file_read".to_string(),
                tool_name: Some("read_file".to_string()),
                target: Some("/home/user/project/src/main.rs".to_string()),
                anomaly_score: 0.1,
                server_name: "dev-server".to_string(),
            }],
            cluster_reason: ClusterReason::TimeWindow,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.1,
            has_kill_chain: false,
            tool_names: vec!["read_file".to_string()],
            targets: vec!["/home/user/project/src/main.rs".to_string()],
            action_sequence: "file_read(/home/user/project/src/main.rs)".to_string(),
        }
    }

    fn make_ssh_cluster(id: &str) -> EventCluster {
        EventCluster {
            id: id.to_string(),
            server_name: "evil-server".to_string(),
            events: vec![ClusterEvent {
                timestamp: Utc::now(),
                event_type: "file_read".to_string(),
                tool_name: Some("read_file".to_string()),
                target: Some("~/.ssh/id_rsa".to_string()),
                anomaly_score: 0.85,
                server_name: "evil-server".to_string(),
            }],
            cluster_reason: ClusterReason::TimeWindow,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.85,
            has_kill_chain: false,
            tool_names: vec!["read_file".to_string()],
            targets: vec!["~/.ssh/id_rsa".to_string()],
            action_sequence: "file_read(~/.ssh/id_rsa)".to_string(),
        }
    }

    fn make_kill_chain_cluster(id: &str) -> EventCluster {
        EventCluster {
            id: id.to_string(),
            server_name: "malicious".to_string(),
            events: vec![
                ClusterEvent {
                    timestamp: Utc::now(),
                    event_type: "file_read".to_string(),
                    tool_name: Some("read_file".to_string()),
                    target: Some("~/.ssh/id_rsa".to_string()),
                    anomaly_score: 0.9,
                    server_name: "malicious".to_string(),
                },
                ClusterEvent {
                    timestamp: Utc::now(),
                    event_type: "network_connect".to_string(),
                    tool_name: None,
                    target: Some("evil.com".to_string()),
                    anomaly_score: 0.95,
                    server_name: "malicious".to_string(),
                },
            ],
            cluster_reason: ClusterReason::KillChain,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.95,
            has_kill_chain: true,
            tool_names: vec!["read_file".to_string()],
            targets: vec!["~/.ssh/id_rsa".to_string(), "evil.com".to_string()],
            action_sequence: "file_read(~/.ssh/id_rsa) -> network_connect(evil.com)".to_string(),
        }
    }

    // -- SystemLoad tests --

    #[test]
    fn system_load_from_cpu_percent() {
        assert_eq!(SystemLoad::from_cpu_percent(5.0), SystemLoad::Idle);
        assert_eq!(SystemLoad::from_cpu_percent(19.9), SystemLoad::Idle);
        assert_eq!(SystemLoad::from_cpu_percent(20.0), SystemLoad::Light);
        assert_eq!(SystemLoad::from_cpu_percent(49.9), SystemLoad::Light);
        assert_eq!(SystemLoad::from_cpu_percent(50.0), SystemLoad::Moderate);
        assert_eq!(SystemLoad::from_cpu_percent(79.9), SystemLoad::Moderate);
        assert_eq!(SystemLoad::from_cpu_percent(80.0), SystemLoad::Heavy);
        assert_eq!(SystemLoad::from_cpu_percent(94.9), SystemLoad::Heavy);
        assert_eq!(SystemLoad::from_cpu_percent(95.0), SystemLoad::Critical);
        assert_eq!(SystemLoad::from_cpu_percent(100.0), SystemLoad::Critical);
    }

    #[test]
    fn system_load_batch_delays() {
        assert_eq!(SystemLoad::Idle.batch_delay(), Duration::from_secs(3));
        assert_eq!(SystemLoad::Light.batch_delay(), Duration::from_secs(5));
        assert_eq!(SystemLoad::Moderate.batch_delay(), Duration::from_secs(10));
        assert_eq!(SystemLoad::Heavy.batch_delay(), Duration::from_secs(30));
        assert_eq!(SystemLoad::Critical.batch_delay(), Duration::from_secs(60));
    }

    // -- Knowledge base tests --

    #[test]
    fn knowledge_base_project_file_is_routine() {
        let kb = KnowledgeBase::with_defaults();
        let cluster = make_project_file_cluster("c-1");
        match kb.check(&cluster) {
            FastPathResult::KnownRoutine(reason) => {
                assert!(reason.contains("IDE"));
            }
            other => panic!("Expected KnownRoutine, got {:?}", other),
        }
    }

    #[test]
    fn knowledge_base_ssh_key_is_suspicious() {
        let kb = KnowledgeBase::with_defaults();
        let cluster = make_ssh_cluster("c-2");
        match kb.check(&cluster) {
            FastPathResult::KnownSuspicious(reason) => {
                assert!(reason.contains("Credential") || reason.contains("key file"));
            }
            other => panic!("Expected KnownSuspicious, got {:?}", other),
        }
    }

    #[test]
    fn knowledge_base_kill_chain_is_suspicious() {
        let kb = KnowledgeBase::with_defaults();
        let cluster = make_kill_chain_cluster("c-3");
        match kb.check(&cluster) {
            FastPathResult::KnownSuspicious(_) => {}
            other => panic!("Expected KnownSuspicious, got {:?}", other),
        }
    }

    #[test]
    fn knowledge_base_normal_cluster_no_match() {
        let kb = KnowledgeBase::with_defaults();
        // A cluster with a non-project, non-sensitive target
        let cluster = EventCluster {
            id: "c-4".to_string(),
            server_name: "some-server".to_string(),
            events: vec![ClusterEvent {
                timestamp: Utc::now(),
                event_type: "tool_call".to_string(),
                tool_name: Some("custom_tool".to_string()),
                target: Some("/usr/local/bin/something".to_string()),
                anomaly_score: 0.4,
                server_name: "some-server".to_string(),
            }],
            cluster_reason: ClusterReason::TimeWindow,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.4,
            has_kill_chain: false,
            tool_names: vec!["custom_tool".to_string()],
            targets: vec!["/usr/local/bin/something".to_string()],
            action_sequence: "tool_call(/usr/local/bin/something)".to_string(),
        };
        assert!(matches!(kb.check(&cluster), FastPathResult::NoMatch));
    }

    #[test]
    fn knowledge_base_suspicious_wins_over_routine() {
        let kb = KnowledgeBase::with_defaults();
        // A cluster that matches both: has_kill_chain (suspicious) AND
        // single event in project dir (routine). Suspicious should win.
        let cluster = EventCluster {
            id: "c-5".to_string(),
            server_name: "test".to_string(),
            events: vec![ClusterEvent {
                timestamp: Utc::now(),
                event_type: "file_read".to_string(),
                tool_name: Some("read_file".to_string()),
                target: Some("/home/user/project/src/main.rs".to_string()),
                anomaly_score: 0.95,
                server_name: "test".to_string(),
            }],
            cluster_reason: ClusterReason::KillChain,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.95,
            has_kill_chain: true,
            tool_names: vec!["read_file".to_string()],
            targets: vec!["/home/user/project/src/main.rs".to_string()],
            action_sequence: "file_read(/home/user/project/src/main.rs)".to_string(),
        };
        assert!(matches!(
            kb.check(&cluster),
            FastPathResult::KnownSuspicious(_)
        ));
    }

    #[test]
    fn knowledge_base_temp_files_are_routine() {
        let kb = KnowledgeBase::with_defaults();
        let cluster = EventCluster {
            id: "c-tmp".to_string(),
            server_name: "build-server".to_string(),
            events: vec![
                ClusterEvent {
                    timestamp: Utc::now(),
                    event_type: "file_write".to_string(),
                    tool_name: Some("write_file".to_string()),
                    target: Some("/tmp/build-output-123".to_string()),
                    anomaly_score: 0.1,
                    server_name: "build-server".to_string(),
                },
                ClusterEvent {
                    timestamp: Utc::now(),
                    event_type: "file_read".to_string(),
                    tool_name: Some("read_file".to_string()),
                    target: Some("/var/folders/xx/yyy/T/tmpfile".to_string()),
                    anomaly_score: 0.05,
                    server_name: "build-server".to_string(),
                },
            ],
            cluster_reason: ClusterReason::TimeWindow,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.1,
            has_kill_chain: false,
            tool_names: vec!["write_file".to_string(), "read_file".to_string()],
            targets: vec![
                "/tmp/build-output-123".to_string(),
                "/var/folders/xx/yyy/T/tmpfile".to_string(),
            ],
            action_sequence: "file_write(/tmp/build-output-123) -> file_read(/var/folders/xx/yyy/T/tmpfile)".to_string(),
        };
        assert!(matches!(
            kb.check(&cluster),
            FastPathResult::KnownRoutine(_)
        ));
    }

    // -- Scheduler tests --

    #[tokio::test]
    async fn scheduler_submit_queues_normal_cluster() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());
        let cluster = make_cluster("c-1", "server-a");
        let result = scheduler.submit(cluster).await;
        assert!(result.is_none()); // Not fast-pathed
        assert_eq!(scheduler.pending_count().await, 1);
    }

    #[tokio::test]
    async fn scheduler_submit_fast_paths_project_file() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());
        let cluster = make_project_file_cluster("c-1");
        let result = scheduler.submit(cluster).await;
        assert!(result.is_some());
        let (level, _) = result.unwrap();
        assert_eq!(level, TriageLevel::Routine);
        assert_eq!(scheduler.pending_count().await, 0); // Not queued
    }

    #[tokio::test]
    async fn scheduler_submit_fast_paths_ssh_key() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());
        let cluster = make_ssh_cluster("c-1");
        let result = scheduler.submit(cluster).await;
        assert!(result.is_some());
        let (level, _) = result.unwrap();
        assert_eq!(level, TriageLevel::Suspicious);
        assert_eq!(scheduler.pending_count().await, 0);
    }

    #[tokio::test]
    async fn scheduler_queue_overflow_drops_oldest() {
        let config = SlmSchedulerConfig {
            max_pending_batches: 3,
            ..Default::default()
        };
        let scheduler = SlmScheduler::new(config);

        for i in 0..5 {
            let cluster = make_cluster(&format!("c-{i}"), "server");
            scheduler.submit(cluster).await;
        }

        assert_eq!(scheduler.pending_count().await, 3);
        let stats = scheduler.counters.snapshot();
        assert_eq!(stats.batches_dropped, 2);
    }

    #[tokio::test]
    async fn scheduler_should_process_empty_queue() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());
        assert!(!scheduler.should_process().await);
    }

    #[tokio::test]
    async fn scheduler_take_next_batch() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());
        let cluster = make_cluster("c-1", "server");
        scheduler.submit(cluster).await;

        let taken = scheduler.take_next_batch().await;
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().id, "c-1");
        assert_eq!(scheduler.state().await, SlmState::Processing);
        assert_eq!(scheduler.pending_count().await, 0);
    }

    #[tokio::test]
    async fn scheduler_mark_batch_complete() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());
        scheduler.set_state(SlmState::Processing).await;
        scheduler.mark_batch_complete(150).await;

        assert_eq!(scheduler.state().await, SlmState::Cooldown);
        let stats = scheduler.counters.snapshot();
        assert_eq!(stats.inference_calls, 1);
        assert_eq!(stats.batches_processed, 1);
        assert_eq!(stats.total_inference_latency_ms, 150);
    }

    #[tokio::test]
    async fn scheduler_cpu_load_update() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());
        scheduler.update_cpu_load(75.0).await;
        assert_eq!(scheduler.system_load().await, SystemLoad::Moderate);

        scheduler.update_cpu_load(95.0).await;
        assert_eq!(scheduler.system_load().await, SystemLoad::Critical);
    }

    #[tokio::test]
    async fn scheduler_power_state_update() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());
        scheduler
            .update_power_state(PowerState::Battery(65))
            .await;
        assert_eq!(*scheduler.power_state.lock().await, PowerState::Battery(65));
    }

    #[tokio::test]
    async fn scheduler_battery_pauses_under_load() {
        let config = SlmSchedulerConfig {
            cooldown_secs: 0,
            battery_batch_interval_secs: 0,
            ..Default::default()
        };
        let scheduler = SlmScheduler::new(config);
        scheduler.submit(make_cluster("c-1", "server")).await;

        // On battery with moderate load: should NOT process.
        scheduler
            .update_power_state(PowerState::Battery(50))
            .await;
        scheduler.update_cpu_load(60.0).await; // Moderate

        // Force last_inference far enough back.
        *scheduler.last_inference.lock().await =
            Instant::now() - Duration::from_secs(120);

        assert!(!scheduler.should_process().await);
    }

    #[tokio::test]
    async fn scheduler_battery_allows_when_idle() {
        let config = SlmSchedulerConfig {
            cooldown_secs: 0,
            battery_batch_interval_secs: 0,
            ..Default::default()
        };
        let scheduler = SlmScheduler::new(config);
        scheduler.submit(make_cluster("c-1", "server")).await;

        // On battery with idle CPU: should process after interval.
        scheduler
            .update_power_state(PowerState::Battery(50))
            .await;
        scheduler.update_cpu_load(10.0).await; // Idle

        // Force last_inference far enough back.
        *scheduler.last_inference.lock().await =
            Instant::now() - Duration::from_secs(120);

        assert!(scheduler.should_process().await);
    }

    #[tokio::test]
    async fn scheduler_stats_tracking() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());

        // Submit some fast-path clusters.
        scheduler.submit(make_project_file_cluster("c-1")).await;
        scheduler.submit(make_ssh_cluster("c-2")).await;

        // Submit a normal cluster and process it.
        scheduler.submit(make_cluster("c-3", "server")).await;
        scheduler.mark_batch_complete(200).await;

        scheduler.record_load_skip(5);
        scheduler.record_battery_skip(3);

        let stats = scheduler.stats().await;
        assert_eq!(stats.events_skipped_knowledge_base, 2);
        assert_eq!(stats.inference_calls, 1);
        assert_eq!(stats.total_inference_latency_ms, 200);
        assert_eq!(stats.events_skipped_load, 5);
        assert_eq!(stats.events_skipped_battery, 3);
        assert_eq!(stats.batches_processed, 1);
    }

    #[tokio::test]
    async fn scheduler_next_batch_delay_varies_by_load() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());

        scheduler.update_cpu_load(5.0).await;
        assert_eq!(scheduler.next_batch_delay().await, Duration::from_secs(3));

        scheduler.update_cpu_load(90.0).await;
        assert_eq!(scheduler.next_batch_delay().await, Duration::from_secs(30));

        scheduler.update_cpu_load(99.0).await;
        assert_eq!(scheduler.next_batch_delay().await, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn scheduler_next_batch_delay_battery_override() {
        let scheduler = SlmScheduler::new(SlmSchedulerConfig::default());

        scheduler
            .update_power_state(PowerState::Battery(50))
            .await;
        // On battery: fixed 30s interval regardless of CPU.
        assert_eq!(scheduler.next_batch_delay().await, Duration::from_secs(30));

        scheduler
            .update_power_state(PowerState::LowBattery(10))
            .await;
        // Low battery: 60s.
        assert_eq!(scheduler.next_batch_delay().await, Duration::from_secs(60));
    }

    #[test]
    fn config_defaults() {
        let config = SlmSchedulerConfig::default();
        assert_eq!(config.cooldown_secs, 2);
        assert_eq!(config.max_pending_batches, 32);
        assert!((config.cpu_backoff_threshold - 50.0).abs() < f32::EPSILON);
        assert!((config.cpu_heavy_threshold - 80.0).abs() < f32::EPSILON);
        assert!((config.cpu_idle_threshold - 20.0).abs() < f32::EPSILON);
        assert!((config.battery_cpu_pause_threshold - 30.0).abs() < f32::EPSILON);
        assert_eq!(config.battery_batch_interval_secs, 30);
        assert_eq!(config.high_trust_event_count, 20);
    }

    #[test]
    fn slm_state_display() {
        assert_eq!(format!("{}", SlmState::Idle), "IDLE");
        assert_eq!(format!("{}", SlmState::Processing), "PROCESSING");
        assert_eq!(format!("{}", SlmState::Paused), "PAUSED");
        assert_eq!(format!("{}", SlmState::Cooldown), "COOLDOWN");
    }

    #[test]
    fn system_load_display() {
        assert_eq!(format!("{}", SystemLoad::Idle), "IDLE");
        assert_eq!(format!("{}", SystemLoad::Light), "LIGHT");
        assert_eq!(format!("{}", SystemLoad::Moderate), "MODERATE");
        assert_eq!(format!("{}", SystemLoad::Heavy), "HEAVY");
        assert_eq!(format!("{}", SystemLoad::Critical), "CRITICAL");
    }

    #[test]
    fn high_anomaly_score_is_suspicious() {
        let kb = KnowledgeBase::with_defaults();
        let cluster = EventCluster {
            id: "c-high".to_string(),
            server_name: "test".to_string(),
            events: vec![ClusterEvent {
                timestamp: Utc::now(),
                event_type: "tool_call".to_string(),
                tool_name: Some("mystery_tool".to_string()),
                target: Some("/usr/local/bin/something".to_string()),
                anomaly_score: 0.95,
                server_name: "test".to_string(),
            }],
            cluster_reason: ClusterReason::TimeWindow,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.95,
            has_kill_chain: false,
            tool_names: vec!["mystery_tool".to_string()],
            targets: vec!["/usr/local/bin/something".to_string()],
            action_sequence: "tool_call(/usr/local/bin/something)".to_string(),
        };
        assert!(matches!(
            kb.check(&cluster),
            FastPathResult::KnownSuspicious(_)
        ));
    }
}
