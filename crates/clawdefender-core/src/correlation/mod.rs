//! Event correlation engine.
//!
//! Links MCP tool-call events to the OS-level side effects they produce by
//! tracking process IDs within a configurable time window.

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::event::correlation::{CorrelatedEvent, CorrelationStatus};
use crate::event::mcp::McpEvent;
use crate::event::os::OsEvent;

/// Statistics about the correlation engine's lifetime activity.
#[derive(Debug, Clone)]
pub struct CorrelationStats {
    /// Total number of correlations that completed with status [`CorrelationStatus::Matched`].
    pub total_correlated: u64,
    /// Total number of correlations that completed with status [`CorrelationStatus::Uncorrelated`].
    pub total_uncorrelated: u64,
    /// Number of correlations currently in the pending window.
    pub currently_pending: usize,
    /// Average number of OS events per completed correlation.
    pub avg_os_events_per_correlation: f64,
}

/// Internal state for an in-flight correlation window.
struct PendingCorrelation {
    id: String,
    mcp_event: McpEvent,
    os_events: Vec<OsEvent>,
    created_at: DateTime<Utc>,
    /// PIDs associated with this MCP event's originating process.
    associated_pids: Vec<u32>,
}

/// Maximum number of pending correlations before the oldest are force-completed.
const MAX_PENDING_CORRELATIONS: usize = 10_000;

/// The correlation engine links MCP events to the OS events they produce.
///
/// Usage:
/// 1. Call [`submit_mcp_event`](Self::submit_mcp_event) when an MCP tool-call arrives.
/// 2. Call [`submit_os_event`](Self::submit_os_event) for every OS event observed.
/// 3. Call [`tick`](Self::tick) periodically to collect completed correlations.
pub struct CorrelationEngine {
    /// Active MCP events waiting for OS event correlation.
    pending: Vec<PendingCorrelation>,
    /// Time window for correlation.
    window: Duration,
    /// Counter for generating correlation IDs.
    next_id: u64,
    // Lifetime stats
    total_correlated: u64,
    total_uncorrelated: u64,
    total_os_events: u64,
    total_completed: u64,
}

impl CorrelationEngine {
    /// Create a new engine with the given correlation time window.
    pub fn new(window: Duration) -> Self {
        Self {
            pending: Vec::new(),
            window,
            next_id: 0,
            total_correlated: 0,
            total_uncorrelated: 0,
            total_os_events: 0,
            total_completed: 0,
        }
    }

    /// Submit an MCP event and begin a correlation window for it.
    ///
    /// Returns the correlation ID assigned to this event.
    /// If the pending queue exceeds [`MAX_PENDING_CORRELATIONS`], the oldest
    /// entries are force-completed to prevent unbounded memory growth.
    pub fn submit_mcp_event(&mut self, event: McpEvent, originator_pid: Option<u32>) -> String {
        // Evict oldest pending correlations if at capacity.
        while self.pending.len() >= MAX_PENDING_CORRELATIONS {
            if let Some(p) = self.pending.first() {
                let status = if p.os_events.is_empty() {
                    self.total_uncorrelated += 1;
                    CorrelationStatus::Uncorrelated
                } else {
                    self.total_correlated += 1;
                    CorrelationStatus::Matched
                };
                self.total_os_events += p.os_events.len() as u64;
                self.total_completed += 1;
                let _ = status; // evicted silently
            }
            self.pending.remove(0);
        }

        let id = format!("corr-{}", self.next_id);
        self.next_id += 1;

        let mut associated_pids = Vec::new();
        if let Some(pid) = originator_pid {
            associated_pids.push(pid);
        }

        self.pending.push(PendingCorrelation {
            id: id.clone(),
            mcp_event: event,
            os_events: Vec::new(),
            created_at: Utc::now(),
            associated_pids,
        });

        id
    }

    /// Submit an OS event for potential correlation with pending MCP events.
    ///
    /// The event is matched by checking whether its `pid` or `ppid` belongs to
    /// any pending correlation's associated process set.
    pub fn submit_os_event(&mut self, event: OsEvent) {
        for pending in &mut self.pending {
            if pending.associated_pids.is_empty() {
                continue;
            }
            let direct_match = pending.associated_pids.contains(&event.pid);
            let child_match = pending.associated_pids.contains(&event.ppid);
            if direct_match || child_match {
                pending.os_events.push(event);
                return;
            }
        }
        // Uncorrelated OS event -- currently dropped.
    }

    /// Finalize any pending correlations whose time window has elapsed.
    ///
    /// Call this periodically (e.g. every second).
    pub fn tick(&mut self) -> Vec<CorrelatedEvent> {
        let now = Utc::now();
        let window_chrono = chrono::Duration::from_std(self.window)
            .unwrap_or_else(|_| chrono::Duration::seconds(5));

        let mut completed = Vec::new();
        let mut remaining = Vec::new();

        for p in self.pending.drain(..) {
            if now.signed_duration_since(p.created_at) >= window_chrono {
                let status = if p.os_events.is_empty() {
                    self.total_uncorrelated += 1;
                    CorrelationStatus::Uncorrelated
                } else {
                    self.total_correlated += 1;
                    CorrelationStatus::Matched
                };
                self.total_os_events += p.os_events.len() as u64;
                self.total_completed += 1;

                completed.push(CorrelatedEvent {
                    id: p.id,
                    mcp_event: Some(p.mcp_event),
                    os_events: p.os_events,
                    status,
                    correlated_at: Some(now),
                });
            } else {
                remaining.push(p);
            }
        }
        self.pending = remaining;

        completed
    }

    /// Force-complete all pending correlations (e.g. on shutdown).
    pub fn flush(&mut self) -> Vec<CorrelatedEvent> {
        let now = Utc::now();
        let mut completed = Vec::new();

        for p in self.pending.drain(..) {
            let status = if p.os_events.is_empty() {
                self.total_uncorrelated += 1;
                CorrelationStatus::Uncorrelated
            } else {
                self.total_correlated += 1;
                CorrelationStatus::Matched
            };
            self.total_os_events += p.os_events.len() as u64;
            self.total_completed += 1;

            completed.push(CorrelatedEvent {
                id: p.id,
                mcp_event: Some(p.mcp_event),
                os_events: p.os_events,
                status,
                correlated_at: Some(now),
            });
        }

        completed
    }

    /// Number of currently pending correlations.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Lifetime statistics for this engine instance.
    pub fn stats(&self) -> CorrelationStats {
        let avg = if self.total_completed > 0 {
            self.total_os_events as f64 / self.total_completed as f64
        } else {
            0.0
        };
        CorrelationStats {
            total_correlated: self.total_correlated,
            total_uncorrelated: self.total_uncorrelated,
            currently_pending: self.pending.len(),
            avg_os_events_per_correlation: avg,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::mcp::{McpEvent, McpEventKind, ToolCall};
    use crate::event::os::{OsEvent, OsEventKind};
    use serde_json::json;
    use std::time::Duration;

    fn make_mcp_event() -> McpEvent {
        McpEvent {
            timestamp: Utc::now(),
            source: "mcp-proxy".to_string(),
            kind: McpEventKind::ToolCall(ToolCall {
                tool_name: "read_file".to_string(),
                arguments: json!({"path": "/tmp/test"}),
                request_id: json!(1),
            }),
            raw_message: json!({}),
        }
    }

    fn make_os_event(pid: u32, ppid: u32) -> OsEvent {
        OsEvent {
            timestamp: Utc::now(),
            pid,
            ppid,
            process_path: "/usr/bin/cat".to_string(),
            kind: OsEventKind::Open {
                path: "/tmp/test".to_string(),
                flags: 0,
            },
            signing_id: None,
            team_id: None,
        }
    }

    #[test]
    fn matched_correlation() {
        let mut engine = CorrelationEngine::new(Duration::from_millis(0));
        let mcp = make_mcp_event();
        let _id = engine.submit_mcp_event(mcp, Some(100));
        engine.submit_os_event(make_os_event(100, 1));

        let results = engine.tick();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CorrelationStatus::Matched);
        assert_eq!(results[0].os_events.len(), 1);
    }

    #[test]
    fn uncorrelated_when_no_os_events() {
        let mut engine = CorrelationEngine::new(Duration::from_millis(0));
        let mcp = make_mcp_event();
        let _id = engine.submit_mcp_event(mcp, Some(100));

        let results = engine.tick();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CorrelationStatus::Uncorrelated);
        assert!(results[0].os_events.is_empty());
    }

    #[test]
    fn multiple_os_events_in_one_correlation() {
        let mut engine = CorrelationEngine::new(Duration::from_millis(0));
        let mcp = make_mcp_event();
        let _id = engine.submit_mcp_event(mcp, Some(100));
        engine.submit_os_event(make_os_event(100, 1));
        engine.submit_os_event(make_os_event(100, 1));
        engine.submit_os_event(make_os_event(100, 1));

        let results = engine.tick();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].os_events.len(), 3);
        assert_eq!(results[0].status, CorrelationStatus::Matched);
    }

    #[test]
    fn direct_pid_match() {
        let mut engine = CorrelationEngine::new(Duration::from_millis(0));
        engine.submit_mcp_event(make_mcp_event(), Some(200));
        engine.submit_os_event(make_os_event(200, 1));

        let results = engine.tick();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CorrelationStatus::Matched);
    }

    #[test]
    fn child_pid_match() {
        let mut engine = CorrelationEngine::new(Duration::from_millis(0));
        engine.submit_mcp_event(make_mcp_event(), Some(200));
        // OS event with ppid matching the associated pid
        engine.submit_os_event(make_os_event(300, 200));

        let results = engine.tick();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CorrelationStatus::Matched);
    }

    #[test]
    fn unrelated_pid_does_not_match() {
        let mut engine = CorrelationEngine::new(Duration::from_millis(0));
        engine.submit_mcp_event(make_mcp_event(), Some(200));
        // OS event with unrelated pid and ppid
        engine.submit_os_event(make_os_event(999, 888));

        let results = engine.tick();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CorrelationStatus::Uncorrelated);
    }

    #[test]
    fn multiple_concurrent_mcp_events() {
        let mut engine = CorrelationEngine::new(Duration::from_millis(0));
        engine.submit_mcp_event(make_mcp_event(), Some(100));
        engine.submit_mcp_event(make_mcp_event(), Some(200));

        engine.submit_os_event(make_os_event(100, 1));
        engine.submit_os_event(make_os_event(200, 1));

        let results = engine.tick();
        assert_eq!(results.len(), 2);
        // Each correlation should have exactly 1 OS event
        for r in &results {
            assert_eq!(r.status, CorrelationStatus::Matched);
            assert_eq!(r.os_events.len(), 1);
        }
    }

    #[test]
    fn flush_completes_all_pending() {
        let mut engine = CorrelationEngine::new(Duration::from_secs(60));
        engine.submit_mcp_event(make_mcp_event(), Some(100));
        engine.submit_mcp_event(make_mcp_event(), Some(200));
        engine.submit_os_event(make_os_event(100, 1));

        assert_eq!(engine.pending_count(), 2);

        let results = engine.flush();
        assert_eq!(results.len(), 2);
        assert_eq!(engine.pending_count(), 0);

        // One matched, one uncorrelated
        let matched = results
            .iter()
            .filter(|r| r.status == CorrelationStatus::Matched)
            .count();
        let uncorrelated = results
            .iter()
            .filter(|r| r.status == CorrelationStatus::Uncorrelated)
            .count();
        assert_eq!(matched, 1);
        assert_eq!(uncorrelated, 1);
    }

    #[test]
    fn time_window_respected() {
        // Large window -- tick should NOT finalize events yet
        let mut engine = CorrelationEngine::new(Duration::from_secs(60));
        engine.submit_mcp_event(make_mcp_event(), Some(100));
        engine.submit_os_event(make_os_event(100, 1));

        let results = engine.tick();
        assert!(results.is_empty());
        assert_eq!(engine.pending_count(), 1);
    }

    #[test]
    fn stats_returns_correct_counts() {
        let mut engine = CorrelationEngine::new(Duration::from_millis(0));

        engine.submit_mcp_event(make_mcp_event(), Some(100));
        engine.submit_os_event(make_os_event(100, 1));
        engine.submit_os_event(make_os_event(100, 1));
        engine.tick();

        engine.submit_mcp_event(make_mcp_event(), Some(200));
        engine.tick();

        // One more pending
        engine.submit_mcp_event(make_mcp_event(), Some(300));

        let stats = engine.stats();
        assert_eq!(stats.total_correlated, 1);
        assert_eq!(stats.total_uncorrelated, 1);
        assert_eq!(stats.currently_pending, 1);
        // 2 os events across 2 completed correlations = 1.0 avg
        assert!((stats.avg_os_events_per_correlation - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn correlation_ids_are_unique() {
        let mut engine = CorrelationEngine::new(Duration::from_secs(5));
        let id1 = engine.submit_mcp_event(make_mcp_event(), None);
        let id2 = engine.submit_mcp_event(make_mcp_event(), None);
        let id3 = engine.submit_mcp_event(make_mcp_event(), None);
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
    }

    #[test]
    fn no_pid_means_no_os_match() {
        let mut engine = CorrelationEngine::new(Duration::from_millis(0));
        engine.submit_mcp_event(make_mcp_event(), None);
        engine.submit_os_event(make_os_event(100, 1));

        let results = engine.tick();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CorrelationStatus::Uncorrelated);
    }
}
