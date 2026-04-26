//! Rolling security context window for the SLM engine.
//!
//! The context window is the SLM's "short-term memory" — a compact representation
//! of recent system state that is attached to inference prompts so the model can
//! make decisions informed by recent activity patterns.
//!
//! Two serialization modes are provided:
//! - **triage_context_line**: ~50 tokens, appended to every fast-path triage prompt.
//! - **deep_analysis_context**: ~300-500 tokens, used for deep analysis prompts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::triage::TriageLevel;

// ---------------------------------------------------------------------------
// Data structs
// ---------------------------------------------------------------------------

/// A snapshot of the current security context, serializable for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// Human-readable event summary, e.g. "47 events in last hour: 38 routine, 7 notable, 2 suspicious"
    pub event_summary: String,
    /// Per-server status snapshots.
    pub active_servers: Vec<ServerSnapshot>,
    /// Last 5 suspicious events (brief summaries).
    pub recent_suspicious: Vec<SuspiciousEventBrief>,
    /// Active kill chain patterns being tracked.
    pub active_kill_chains: Vec<KillChainSnapshot>,
    /// System posture info.
    pub system_posture: PostureSnapshot,
    /// Threat intelligence feed status.
    pub threat_intel_status: ThreatIntelStatus,
    /// Start of the rolling window.
    pub window_start: chrono::DateTime<Utc>,
    /// End of the rolling window.
    pub window_end: chrono::DateTime<Utc>,
    /// Total events observed in the window.
    pub total_events_in_window: u64,
    /// When this snapshot was last refreshed.
    pub last_updated: chrono::DateTime<Utc>,
    /// Whether this context was loaded from disk and may be stale.
    pub is_stale: bool,
}

impl Default for SecurityContext {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            event_summary: "0 events: 0 routine, 0 notable, 0 suspicious".to_string(),
            active_servers: Vec::new(),
            recent_suspicious: Vec::new(),
            active_kill_chains: Vec::new(),
            system_posture: PostureSnapshot::default(),
            threat_intel_status: ThreatIntelStatus::default(),
            window_start: now,
            window_end: now,
            total_events_in_window: 0,
            last_updated: now,
            is_stale: false,
        }
    }
}

/// Per-server snapshot for the context window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSnapshot {
    pub name: String,
    /// Trust level: "trusted", "verified", "new", "unknown".
    pub trust_level: String,
    /// Anomaly score (0.0 = normal, 1.0 = highly anomalous).
    pub anomaly_score: f64,
    /// Number of events from this server in the window.
    pub event_count: u64,
}

/// Brief summary of a suspicious event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousEventBrief {
    pub timestamp: String,
    pub server_name: String,
    pub description: String,
}

/// Snapshot of an active kill chain pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainSnapshot {
    pub server_name: String,
    pub pattern_name: String,
    pub stages_matched: u32,
    pub total_stages: u32,
}

/// System posture snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureSnapshot {
    pub daemon_status: String,
    pub model_status: String,
    pub wrapped_server_count: u32,
    pub total_server_count: u32,
}

impl Default for PostureSnapshot {
    fn default() -> Self {
        Self {
            daemon_status: "unknown".to_string(),
            model_status: "unknown".to_string(),
            wrapped_server_count: 0,
            total_server_count: 0,
        }
    }
}

/// Threat intelligence feed status.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatIntelStatus {
    /// Whether offline intelligence has been generated.
    pub offline_intel_ready: bool,
    /// Number of server assessments available.
    pub server_assessments: u32,
    /// Number of security tips generated.
    pub security_tips: u32,
    /// Last time intelligence was refreshed.
    pub last_refreshed: Option<String>,
}

/// Event counts accumulated for the current window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventCounts {
    pub routine: u64,
    pub notable: u64,
    pub suspicious: u64,
}

impl EventCounts {
    fn total(&self) -> u64 {
        self.routine + self.notable + self.suspicious
    }
}

// ---------------------------------------------------------------------------
// Context window manager
// ---------------------------------------------------------------------------

/// Maximum number of suspicious event briefs retained.
const MAX_SUSPICIOUS: usize = 5;

/// How often the context window refreshes (aggregates pending data).
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// How often the context window persists to disk.
const PERSIST_INTERVAL: Duration = Duration::from_secs(300);

/// The rolling context window manager.
///
/// Thread-safe: all internal state is behind locks so that event recording
/// can happen concurrently with context reads.
pub struct ContextWindow {
    /// The current aggregated security context.
    current: RwLock<SecurityContext>,
    /// Event counts accumulated since last refresh.
    pending_counts: Mutex<EventCounts>,
    /// Suspicious events accumulated since last refresh.
    pending_suspicious: Mutex<Vec<SuspiciousEventBrief>>,
    /// Server anomaly scores (updated by behavioral engine).
    server_scores: Mutex<HashMap<String, f64>>,
    /// Server event counts (accumulated since last refresh).
    server_event_counts: Mutex<HashMap<String, u64>>,
    /// Persistence path for the context snapshot.
    persist_path: PathBuf,
    /// Last time the context was persisted to disk.
    last_persisted: Mutex<Instant>,
    /// Shutdown signal for the run loop.
    shutdown: AtomicBool,
}

/// Return the default persistence path: `~/.local/share/rookbot/context_window.json`.
pub fn default_persist_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local")
        .join("share")
        .join("clawdefender")
        .join("context_window.json")
}

impl ContextWindow {
    /// Create a new context window with default (empty) state.
    pub fn new(persist_path: PathBuf) -> Self {
        Self {
            current: RwLock::new(SecurityContext::default()),
            pending_counts: Mutex::new(EventCounts::default()),
            pending_suspicious: Mutex::new(Vec::new()),
            server_scores: Mutex::new(HashMap::new()),
            server_event_counts: Mutex::new(HashMap::new()),
            persist_path,
            last_persisted: Mutex::new(Instant::now()),
            shutdown: AtomicBool::new(false),
        }
    }

    /// Create a context window, loading stale context from disk if available.
    ///
    /// On daemon restart this recovers the previous context (marked stale),
    /// which will be refreshed on the next cycle.
    pub fn load_or_default(persist_path: PathBuf) -> Self {
        let initial = if persist_path.exists() {
            match Self::load_from_disk(&persist_path) {
                Ok(ctx) => {
                    info!(
                        path = %persist_path.display(),
                        events = ctx.total_events_in_window,
                        "Recovered stale context from disk"
                    );
                    ctx
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %persist_path.display(),
                        "Failed to load context from disk, starting fresh"
                    );
                    SecurityContext::default()
                }
            }
        } else {
            SecurityContext::default()
        };

        Self {
            current: RwLock::new(initial),
            pending_counts: Mutex::new(EventCounts::default()),
            pending_suspicious: Mutex::new(Vec::new()),
            server_scores: Mutex::new(HashMap::new()),
            server_event_counts: Mutex::new(HashMap::new()),
            persist_path,
            last_persisted: Mutex::new(Instant::now()),
            shutdown: AtomicBool::new(false),
        }
    }

    /// Record a triage result for the context window.
    pub fn record_event(&self, server: &str, level: TriageLevel) {
        {
            let mut counts = self.pending_counts.lock().expect("pending_counts poisoned");
            match level {
                TriageLevel::Routine => counts.routine += 1,
                TriageLevel::Notable => counts.notable += 1,
                TriageLevel::Suspicious => counts.suspicious += 1,
            }
        }
        {
            let mut server_counts = self
                .server_event_counts
                .lock()
                .expect("server_event_counts poisoned");
            *server_counts.entry(server.to_string()).or_insert(0) += 1;
        }
    }

    /// Record a suspicious event for the context.
    pub fn record_suspicious(&self, brief: SuspiciousEventBrief) {
        let mut pending = self
            .pending_suspicious
            .lock()
            .expect("pending_suspicious poisoned");
        pending.push(brief);
        // Keep only the last MAX_SUSPICIOUS entries.
        while pending.len() > MAX_SUSPICIOUS {
            pending.remove(0);
        }
    }

    /// Update server anomaly score.
    pub fn update_server_score(&self, server: &str, score: f64) {
        let mut scores = self.server_scores.lock().expect("server_scores poisoned");
        scores.insert(server.to_string(), score);
    }

    /// Update kill chain data on the current context.
    pub fn update_kill_chains(&self, chains: Vec<KillChainSnapshot>) {
        // Directly update the current context (blocking write).
        let mut ctx = self.current.blocking_write();
        ctx.active_kill_chains = chains;
    }

    /// Update system posture on the current context.
    pub fn update_posture(&self, posture: PostureSnapshot) {
        let mut ctx = self.current.blocking_write();
        ctx.system_posture = posture;
    }

    /// Update threat intelligence status on the current context.
    pub fn update_threat_intel(&self, status: ThreatIntelStatus) {
        let mut ctx = self.current.blocking_write();
        ctx.threat_intel_status = status;
    }

    /// Signal the run loop to stop.
    pub fn signal_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Check whether enough time has elapsed since the last persist.
    fn should_persist(&self) -> bool {
        match self.last_persisted.lock() {
            Ok(last) => last.elapsed() >= PERSIST_INTERVAL,
            Err(_) => true,
        }
    }

    /// Run the context update loop: refresh every 60s, persist every 5min.
    ///
    /// This is intended to be spawned as a background task and will run until
    /// `signal_shutdown()` is called.
    pub async fn run_loop(&self) {
        info!("Context window update loop started");
        loop {
            tokio::time::sleep(REFRESH_INTERVAL).await;

            if self.shutdown.load(Ordering::Relaxed) {
                // Final persist before exiting.
                if let Err(e) = self.persist().await {
                    warn!(error = %e, "Failed to persist context on shutdown");
                }
                info!("Context window update loop stopped");
                return;
            }

            self.refresh().await;
            debug!("Context window refreshed");

            if self.should_persist() {
                if let Err(e) = self.persist().await {
                    warn!(error = %e, "Failed to persist context window to disk");
                } else {
                    debug!(path = %self.persist_path.display(), "Context window persisted to disk");
                }
            }
        }
    }

    /// Refresh the context by aggregating pending data into the current snapshot.
    ///
    /// This should be called periodically (e.g. every 60 seconds).
    pub async fn refresh(&self) {
        let now = Utc::now();

        // Drain pending counts.
        let counts = {
            let mut pending = self.pending_counts.lock().expect("pending_counts poisoned");
            let c = pending.clone();
            *pending = EventCounts::default();
            c
        };

        // Drain pending suspicious events.
        let suspicious = {
            let mut pending = self
                .pending_suspicious
                .lock()
                .expect("pending_suspicious poisoned");

            std::mem::take(&mut *pending)
        };

        // Snapshot server scores.
        let scores = {
            let scores = self.server_scores.lock().expect("server_scores poisoned");
            scores.clone()
        };

        // Snapshot server event counts.
        let event_counts = {
            let mut ec = self
                .server_event_counts
                .lock()
                .expect("server_event_counts poisoned");
            let snapshot = ec.clone();
            ec.clear();
            snapshot
        };

        // Update the current context.
        let mut ctx = self.current.write().await;

        // Merge event counts.
        ctx.total_events_in_window += counts.total();
        ctx.event_summary = format!(
            "{} events: {} routine, {} notable, {} suspicious",
            ctx.total_events_in_window, counts.routine, counts.notable, counts.suspicious
        );

        // Merge suspicious events (keep last MAX_SUSPICIOUS across old + new).
        for s in suspicious {
            ctx.recent_suspicious.push(s);
        }
        while ctx.recent_suspicious.len() > MAX_SUSPICIOUS {
            ctx.recent_suspicious.remove(0);
        }

        // Rebuild server snapshots from scores and event counts.
        let mut servers: HashMap<String, ServerSnapshot> = HashMap::new();
        for existing in ctx.active_servers.drain(..) {
            servers.insert(existing.name.clone(), existing);
        }
        for (name, count) in &event_counts {
            let entry = servers
                .entry(name.clone())
                .or_insert_with(|| ServerSnapshot {
                    name: name.clone(),
                    trust_level: "unknown".to_string(),
                    anomaly_score: 0.0,
                    event_count: 0,
                });
            entry.event_count += count;
        }
        for (name, score) in &scores {
            let entry = servers
                .entry(name.clone())
                .or_insert_with(|| ServerSnapshot {
                    name: name.clone(),
                    trust_level: "unknown".to_string(),
                    anomaly_score: 0.0,
                    event_count: 0,
                });
            entry.anomaly_score = *score;
        }
        ctx.active_servers = servers.into_values().collect();
        ctx.active_servers.sort_by(|a, b| a.name.cmp(&b.name));

        ctx.window_end = now;
        ctx.last_updated = now;
        ctx.is_stale = false;
    }

    /// Get a compact context line for triage prompts (~50 tokens).
    pub fn triage_context_line(&self) -> String {
        let ctx = self.current.blocking_read();
        let suspicious_count = ctx.recent_suspicious.len();
        let server_count = ctx.active_servers.len();
        let kc_count = ctx.active_kill_chains.len();

        format!(
            "[CONTEXT events={} servers={} suspicious={} killchains={} posture={}]",
            ctx.total_events_in_window,
            server_count,
            suspicious_count,
            kc_count,
            ctx.system_posture.daemon_status,
        )
    }

    /// Get the full context for deep analysis prompts (~300-500 tokens).
    pub fn deep_analysis_context(&self) -> String {
        let ctx = self.current.blocking_read();
        let mut out = String::with_capacity(800);

        // Header.
        let window_mins = (ctx.window_end - ctx.window_start).num_minutes().max(1);
        out.push_str(&format!(
            "[CONTEXT window=last_{}min events={}]\n",
            window_mins, ctx.total_events_in_window,
        ));

        // Servers.
        if !ctx.active_servers.is_empty() {
            out.push_str("SERVERS:");
            for s in &ctx.active_servers {
                let anomaly_label = if s.anomaly_score < 0.3 {
                    "low"
                } else if s.anomaly_score < 0.7 {
                    "med"
                } else {
                    "high"
                };
                out.push_str(&format!(
                    " {}({},{},{})",
                    s.name, s.trust_level, anomaly_label, s.event_count
                ));
            }
            out.push('\n');
        }

        // Suspicious events.
        if !ctx.recent_suspicious.is_empty() {
            out.push_str("SUSPICIOUS:");
            for s in &ctx.recent_suspicious {
                out.push_str(&format!(
                    " {} {} {}",
                    s.timestamp, s.server_name, s.description
                ));
                out.push_str(" |");
            }
            // Remove trailing " |"
            if out.ends_with(" |") {
                out.truncate(out.len() - 2);
            }
            out.push('\n');
        }

        // Kill chains.
        if !ctx.active_kill_chains.is_empty() {
            out.push_str("KILLCHAIN:");
            for kc in &ctx.active_kill_chains {
                out.push_str(&format!(
                    " {} stage={} ({}/{})",
                    kc.server_name, kc.pattern_name, kc.stages_matched, kc.total_stages
                ));
            }
            out.push('\n');
        }

        // Posture.
        out.push_str(&format!(
            "POSTURE: daemon={} model={} wrapped={}/{}\n",
            ctx.system_posture.daemon_status,
            ctx.system_posture.model_status,
            ctx.system_posture.wrapped_server_count,
            ctx.system_posture.total_server_count,
        ));

        // Threat intel.
        if ctx.threat_intel_status.offline_intel_ready {
            out.push_str(&format!(
                "INTEL: ready assessments={} tips={}\n",
                ctx.threat_intel_status.server_assessments, ctx.threat_intel_status.security_tips,
            ));
        }

        out.push_str("[/CONTEXT]");
        out
    }

    /// Async version of [`deep_analysis_context()`] for use within a tokio runtime.
    ///
    /// Uses `.read().await` instead of `.blocking_read()` to avoid panicking
    /// when called from an async context.
    pub async fn deep_analysis_context_async(&self) -> String {
        let ctx = self.current.read().await;
        let mut out = String::with_capacity(800);

        let window_mins = (ctx.window_end - ctx.window_start).num_minutes().max(1);
        out.push_str(&format!(
            "[CONTEXT window=last_{}min events={}]\n",
            window_mins, ctx.total_events_in_window,
        ));

        if !ctx.active_servers.is_empty() {
            out.push_str("SERVERS:");
            for s in &ctx.active_servers {
                let anomaly_label = if s.anomaly_score < 0.3 {
                    "low"
                } else if s.anomaly_score < 0.7 {
                    "med"
                } else {
                    "high"
                };
                out.push_str(&format!(
                    " {}({},{},{})",
                    s.name, s.trust_level, anomaly_label, s.event_count
                ));
            }
            out.push('\n');
        }

        if !ctx.recent_suspicious.is_empty() {
            out.push_str("SUSPICIOUS:");
            for s in &ctx.recent_suspicious {
                out.push_str(&format!(
                    " {} {} {}",
                    s.timestamp, s.server_name, s.description
                ));
                out.push_str(" |");
            }
            if out.ends_with(" |") {
                out.truncate(out.len() - 2);
            }
            out.push('\n');
        }

        if !ctx.active_kill_chains.is_empty() {
            out.push_str("KILLCHAIN:");
            for kc in &ctx.active_kill_chains {
                out.push_str(&format!(
                    " {} stage={} ({}/{})",
                    kc.server_name, kc.pattern_name, kc.stages_matched, kc.total_stages
                ));
            }
            out.push('\n');
        }

        out.push_str(&format!(
            "POSTURE: daemon={} model={} wrapped={}/{}\n",
            ctx.system_posture.daemon_status,
            ctx.system_posture.model_status,
            ctx.system_posture.wrapped_server_count,
            ctx.system_posture.total_server_count,
        ));

        if ctx.threat_intel_status.offline_intel_ready {
            out.push_str(&format!(
                "INTEL: ready assessments={} tips={}\n",
                ctx.threat_intel_status.server_assessments, ctx.threat_intel_status.security_tips,
            ));
        }

        out.push_str("[/CONTEXT]");
        out
    }

    /// Persist the current context to disk as JSON.
    pub async fn persist(&self) -> Result<()> {
        let ctx = self.current.read().await;
        let json = serde_json::to_string_pretty(&*ctx)?;
        tokio::fs::create_dir_all(self.persist_path.parent().unwrap_or(Path::new("."))).await?;
        tokio::fs::write(&self.persist_path, json.as_bytes()).await?;
        if let Ok(mut last) = self.last_persisted.lock() {
            *last = Instant::now();
        }
        Ok(())
    }

    /// Load a security context from disk. The loaded context is marked as stale.
    pub fn load_from_disk(persist_path: &Path) -> Result<SecurityContext> {
        let data = std::fs::read_to_string(persist_path)?;
        let mut ctx: SecurityContext = serde_json::from_str(&data)?;
        ctx.is_stale = true;
        Ok(ctx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_window() -> ContextWindow {
        ContextWindow::new(PathBuf::from("/tmp/clawdefender-test-context.json"))
    }

    #[test]
    fn context_creation_defaults() {
        let w = test_window();
        let ctx = w.current.blocking_read();
        assert_eq!(ctx.total_events_in_window, 0);
        assert!(ctx.active_servers.is_empty());
        assert!(ctx.recent_suspicious.is_empty());
        assert!(ctx.active_kill_chains.is_empty());
        assert!(!ctx.is_stale);
        assert!(ctx.event_summary.contains("0 events"));
    }

    #[test]
    fn record_event_updates_counts() {
        let w = test_window();
        w.record_event("server-a", TriageLevel::Routine);
        w.record_event("server-a", TriageLevel::Routine);
        w.record_event("server-a", TriageLevel::Notable);
        w.record_event("server-b", TriageLevel::Suspicious);

        let counts = w.pending_counts.lock().unwrap();
        assert_eq!(counts.routine, 2);
        assert_eq!(counts.notable, 1);
        assert_eq!(counts.suspicious, 1);
        assert_eq!(counts.total(), 4);

        let server_counts = w.server_event_counts.lock().unwrap();
        assert_eq!(*server_counts.get("server-a").unwrap(), 3);
        assert_eq!(*server_counts.get("server-b").unwrap(), 1);
    }

    #[test]
    fn record_suspicious_maintains_last_5() {
        let w = test_window();
        for i in 0..8 {
            w.record_suspicious(SuspiciousEventBrief {
                timestamp: format!("14:{:02}", i),
                server_name: "srv".to_string(),
                description: format!("event_{}", i),
            });
        }
        let pending = w.pending_suspicious.lock().unwrap();
        assert_eq!(pending.len(), MAX_SUSPICIOUS);
        // Should have kept events 3..8 (the last 5).
        assert_eq!(pending[0].description, "event_3");
        assert_eq!(pending[4].description, "event_7");
    }

    #[tokio::test]
    async fn refresh_aggregates_pending_data() {
        let w = test_window();

        w.record_event("server-a", TriageLevel::Routine);
        w.record_event("server-a", TriageLevel::Routine);
        w.record_event("server-b", TriageLevel::Suspicious);
        w.record_suspicious(SuspiciousEventBrief {
            timestamp: "14:23".to_string(),
            server_name: "server-b".to_string(),
            description: "read ~/.env".to_string(),
        });
        w.update_server_score("server-a", 0.1);
        w.update_server_score("server-b", 0.8);

        w.refresh().await;

        let ctx = w.current.read().await;
        assert_eq!(ctx.total_events_in_window, 3);
        assert!(ctx.event_summary.contains("3 events"));
        assert!(ctx.event_summary.contains("2 routine"));
        assert!(ctx.event_summary.contains("1 suspicious"));
        assert_eq!(ctx.recent_suspicious.len(), 1);
        assert_eq!(ctx.recent_suspicious[0].description, "read ~/.env");
        assert_eq!(ctx.active_servers.len(), 2);

        // Verify server scores were applied.
        let srv_a = ctx
            .active_servers
            .iter()
            .find(|s| s.name == "server-a")
            .unwrap();
        assert!((srv_a.anomaly_score - 0.1).abs() < f64::EPSILON);
        let srv_b = ctx
            .active_servers
            .iter()
            .find(|s| s.name == "server-b")
            .unwrap();
        assert!((srv_b.anomaly_score - 0.8).abs() < f64::EPSILON);

        // Pending should be drained.
        let counts = w.pending_counts.lock().unwrap();
        assert_eq!(counts.total(), 0);
    }

    #[test]
    fn triage_context_line_is_compact() {
        let w = test_window();
        let line = w.triage_context_line();
        // Should be under ~100 "tokens" (rough: < 400 chars).
        assert!(
            line.len() < 400,
            "triage line too long: {} chars",
            line.len()
        );
        assert!(line.starts_with("[CONTEXT"));
        assert!(line.contains("events="));
    }

    #[test]
    fn deep_analysis_context_is_bounded() {
        let w = test_window();
        w.record_event("server-a", TriageLevel::Routine);
        w.update_server_score("server-a", 0.5);
        w.update_posture(PostureSnapshot {
            daemon_status: "ok".to_string(),
            model_status: "qwen3-1.7b".to_string(),
            wrapped_server_count: 3,
            total_server_count: 5,
        });
        w.update_kill_chains(vec![KillChainSnapshot {
            server_name: "FileManager".to_string(),
            pattern_name: "credential_access".to_string(),
            stages_matched: 2,
            total_stages: 6,
        }]);

        // Need to refresh to get pending data into the context.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(w.refresh());

        let ctx_text = w.deep_analysis_context();
        assert!(
            ctx_text.len() < 1000,
            "deep analysis context too long: {} chars",
            ctx_text.len()
        );
        assert!(ctx_text.contains("[CONTEXT"));
        assert!(ctx_text.contains("[/CONTEXT]"));
        assert!(ctx_text.contains("POSTURE:"));
        assert!(ctx_text.contains("KILLCHAIN:"));
    }

    #[tokio::test]
    async fn persist_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("clawdefender-ctx-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("context.json");

        let w = ContextWindow::new(path.clone());
        w.record_event("srv", TriageLevel::Notable);
        w.record_suspicious(SuspiciousEventBrief {
            timestamp: "15:00".to_string(),
            server_name: "srv".to_string(),
            description: "test persist".to_string(),
        });
        w.refresh().await;
        w.persist().await.expect("persist should succeed");

        // Load back.
        let loaded = ContextWindow::load_from_disk(&path).expect("load should succeed");
        assert!(loaded.is_stale, "loaded context should be marked stale");
        assert_eq!(loaded.total_events_in_window, 1);
        assert_eq!(loaded.recent_suspicious.len(), 1);
        assert_eq!(loaded.recent_suspicious[0].description, "test persist");

        // Clean up.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_from_disk_marks_stale() {
        let dir = std::env::temp_dir().join("clawdefender-ctx-stale-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("stale_context.json");

        // Write a valid context to disk.
        let ctx = SecurityContext::default();
        let json = serde_json::to_string_pretty(&ctx).unwrap();
        std::fs::write(&path, json).unwrap();

        let loaded = ContextWindow::load_from_disk(&path).unwrap();
        assert!(loaded.is_stale);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn cold_start_empty_context_is_valid() {
        let w = test_window();
        // Even with no events, triage and deep analysis should produce valid output.
        let triage = w.triage_context_line();
        assert!(!triage.is_empty());
        assert!(triage.contains("events=0"));

        let deep = w.deep_analysis_context();
        assert!(!deep.is_empty());
        assert!(deep.contains("[CONTEXT"));
        assert!(deep.contains("[/CONTEXT]"));
    }

    #[test]
    fn update_server_score_stores_value() {
        let w = test_window();
        w.update_server_score("srv-a", 0.42);
        let scores = w.server_scores.lock().unwrap();
        assert!((scores["srv-a"] - 0.42).abs() < f64::EPSILON);
    }

    #[test]
    fn update_kill_chains_replaces() {
        let w = test_window();
        w.update_kill_chains(vec![KillChainSnapshot {
            server_name: "srv".to_string(),
            pattern_name: "recon".to_string(),
            stages_matched: 1,
            total_stages: 4,
        }]);
        let ctx = w.current.blocking_read();
        assert_eq!(ctx.active_kill_chains.len(), 1);
        assert_eq!(ctx.active_kill_chains[0].pattern_name, "recon");
    }

    #[test]
    fn update_posture_replaces() {
        let w = test_window();
        w.update_posture(PostureSnapshot {
            daemon_status: "ok".to_string(),
            model_status: "loaded".to_string(),
            wrapped_server_count: 2,
            total_server_count: 4,
        });
        let ctx = w.current.blocking_read();
        assert_eq!(ctx.system_posture.daemon_status, "ok");
        assert_eq!(ctx.system_posture.wrapped_server_count, 2);
    }

    #[test]
    fn update_threat_intel_stores_status() {
        let w = test_window();
        w.update_threat_intel(ThreatIntelStatus {
            offline_intel_ready: true,
            server_assessments: 3,
            security_tips: 5,
            last_refreshed: Some("2026-04-08T12:00:00Z".to_string()),
        });
        let ctx = w.current.blocking_read();
        assert!(ctx.threat_intel_status.offline_intel_ready);
        assert_eq!(ctx.threat_intel_status.server_assessments, 3);
        assert_eq!(ctx.threat_intel_status.security_tips, 5);
    }

    #[test]
    fn deep_analysis_includes_threat_intel_when_ready() {
        let w = test_window();
        w.update_threat_intel(ThreatIntelStatus {
            offline_intel_ready: true,
            server_assessments: 2,
            security_tips: 4,
            last_refreshed: None,
        });
        let deep = w.deep_analysis_context();
        assert!(deep.contains("INTEL: ready"));
        assert!(deep.contains("assessments=2"));
        assert!(deep.contains("tips=4"));
    }

    #[test]
    fn deep_analysis_omits_threat_intel_when_not_ready() {
        let w = test_window();
        // Default threat_intel_status has offline_intel_ready = false
        let deep = w.deep_analysis_context();
        assert!(!deep.contains("INTEL:"));
    }

    #[tokio::test]
    async fn load_or_default_recovers_from_disk() {
        let dir = std::env::temp_dir().join("clawdefender-ctx-recovery-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("recovery_context.json");

        // Create and persist a context with data.
        let w = ContextWindow::new(path.clone());
        w.record_event("srv-x", TriageLevel::Suspicious);
        w.record_suspicious(SuspiciousEventBrief {
            timestamp: "16:00".to_string(),
            server_name: "srv-x".to_string(),
            description: "recovery test event".to_string(),
        });
        w.refresh().await;
        w.persist().await.expect("persist should succeed");

        // Simulate daemon restart: load_or_default should recover.
        let w2 = ContextWindow::load_or_default(path.clone());
        let ctx = w2.current.read().await;
        assert!(ctx.is_stale, "recovered context should be marked stale");
        assert_eq!(ctx.total_events_in_window, 1);
        assert_eq!(ctx.recent_suspicious.len(), 1);
        assert_eq!(ctx.recent_suspicious[0].description, "recovery test event");

        // Clean up.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_or_default_fresh_start_when_no_file() {
        let path = PathBuf::from("/tmp/clawdefender-nonexistent-path/ctx.json");
        let w = ContextWindow::load_or_default(path);
        let ctx = w.current.blocking_read();
        assert!(!ctx.is_stale);
        assert_eq!(ctx.total_events_in_window, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn run_loop_shutdown_persists_and_exits() {
        let dir = std::env::temp_dir().join("clawdefender-ctx-loop-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("loop_context.json");

        let w = std::sync::Arc::new(ContextWindow::new(path.clone()));
        w.record_event("srv", TriageLevel::Routine);

        // Signal shutdown immediately so the loop exits after one sleep.
        w.signal_shutdown();

        // Run the loop -- with start_paused=true, tokio auto-advances time
        // so the 60s sleep completes instantly.
        let w2 = w.clone();
        let handle = tokio::spawn(async move {
            w2.run_loop().await;
        });

        // Wait for the loop to finish.
        let result = tokio::time::timeout(Duration::from_secs(300), handle).await;
        assert!(result.is_ok(), "run_loop should have exited");

        // Context should have been persisted on shutdown.
        assert!(
            path.exists(),
            "context file should exist after shutdown persist"
        );

        // Clean up.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn default_persist_path_contains_clawdefender() {
        let path = default_persist_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("clawdefender"),
            "path should contain 'clawdefender': {}",
            path_str
        );
        assert!(path_str.ends_with("context_window.json"));
    }

    #[test]
    fn threat_intel_status_default() {
        let status = ThreatIntelStatus::default();
        assert!(!status.offline_intel_ready);
        assert_eq!(status.server_assessments, 0);
        assert_eq!(status.security_tips, 0);
        assert!(status.last_refreshed.is_none());
    }

    #[test]
    fn security_context_default_has_threat_intel() {
        let ctx = SecurityContext::default();
        assert!(!ctx.threat_intel_status.offline_intel_ready);
    }

    #[test]
    fn persist_and_load_preserves_threat_intel() {
        let dir = std::env::temp_dir().join("clawdefender-ctx-intel-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("intel_context.json");

        let w = ContextWindow::new(path.clone());
        w.update_threat_intel(ThreatIntelStatus {
            offline_intel_ready: true,
            server_assessments: 7,
            security_tips: 3,
            last_refreshed: Some("2026-04-08".to_string()),
        });
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(w.persist()).expect("persist should succeed");

        let loaded = ContextWindow::load_from_disk(&path).expect("load should succeed");
        assert!(loaded.threat_intel_status.offline_intel_ready);
        assert_eq!(loaded.threat_intel_status.server_assessments, 7);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
