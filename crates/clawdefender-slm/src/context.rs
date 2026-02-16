//! Context tracking for MCP servers.
//!
//! Maintains a ring buffer of recent events and reputation counters
//! per server, used to provide context for SLM risk analysis.

use std::collections::{HashMap, VecDeque};

use crate::analyzer::{AnalysisContext, EventSummary, ServerReputation};

/// Maximum number of recent events to retain per server.
const MAX_RECENT_EVENTS: usize = 20;

/// Per-server context: recent events and reputation counters.
#[derive(Debug, Clone)]
pub struct ServerContext {
    recent_events: VecDeque<EventSummary>,
    total_allowed: u64,
    total_blocked: u64,
    total_prompted: u64,
}

impl ServerContext {
    fn new() -> Self {
        Self {
            recent_events: VecDeque::with_capacity(MAX_RECENT_EVENTS),
            total_allowed: 0,
            total_blocked: 0,
            total_prompted: 0,
        }
    }
}

/// Tracks context across all known MCP servers.
#[derive(Debug, Clone, Default)]
pub struct ContextTracker {
    servers: HashMap<String, ServerContext>,
}

/// The outcome of a policy decision, used to update reputation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionOutcome {
    Allowed,
    Blocked,
    Prompted,
}

impl ContextTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an event summary for a server (ring buffer, max 20).
    pub fn record_event(&mut self, server: &str, summary: EventSummary) {
        let ctx = self
            .servers
            .entry(server.to_string())
            .or_insert_with(ServerContext::new);
        if ctx.recent_events.len() >= MAX_RECENT_EVENTS {
            ctx.recent_events.pop_front();
        }
        ctx.recent_events.push_back(summary);
    }

    /// Record a policy decision outcome for reputation tracking.
    pub fn record_decision(&mut self, server: &str, outcome: DecisionOutcome) {
        let ctx = self
            .servers
            .entry(server.to_string())
            .or_insert_with(ServerContext::new);
        match outcome {
            DecisionOutcome::Allowed => ctx.total_allowed += 1,
            DecisionOutcome::Blocked => ctx.total_blocked += 1,
            DecisionOutcome::Prompted => ctx.total_prompted += 1,
        }
    }

    /// Get analysis context for a server, including the last `n` events.
    pub fn get_context(&self, server: &str, n: usize) -> AnalysisContext {
        match self.servers.get(server) {
            Some(ctx) => {
                let len = ctx.recent_events.len();
                let start = len.saturating_sub(n);
                let recent_events: Vec<EventSummary> =
                    ctx.recent_events.iter().skip(start).cloned().collect();
                AnalysisContext {
                    recent_events,
                    server_reputation: ServerReputation {
                        total_allowed: ctx.total_allowed,
                        total_blocked: ctx.total_blocked,
                        total_prompted: ctx.total_prompted,
                    },
                }
            }
            None => AnalysisContext {
                recent_events: vec![],
                server_reputation: ServerReputation::default(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_summary(n: usize) -> EventSummary {
        EventSummary {
            timestamp: format!("2025-01-01T00:{:02}:00Z", n % 60),
            summary: format!("event_{n}"),
        }
    }

    #[test]
    fn record_and_retrieve_events() {
        let mut tracker = ContextTracker::new();
        tracker.record_event("server-a", make_summary(1));
        tracker.record_event("server-a", make_summary(2));
        tracker.record_event("server-a", make_summary(3));

        let ctx = tracker.get_context("server-a", 10);
        assert_eq!(ctx.recent_events.len(), 3);
        assert_eq!(ctx.recent_events[0].summary, "event_1");
        assert_eq!(ctx.recent_events[2].summary, "event_3");
    }

    #[test]
    fn ring_buffer_evicts_oldest() {
        let mut tracker = ContextTracker::new();
        for i in 0..25 {
            tracker.record_event("server-a", make_summary(i));
        }

        let ctx = tracker.get_context("server-a", 100);
        assert_eq!(ctx.recent_events.len(), MAX_RECENT_EVENTS);
        // Oldest should be event_5 (0-4 evicted).
        assert_eq!(ctx.recent_events[0].summary, "event_5");
        assert_eq!(ctx.recent_events[19].summary, "event_24");
    }

    #[test]
    fn get_context_limits_to_n_events() {
        let mut tracker = ContextTracker::new();
        for i in 0..10 {
            tracker.record_event("server-a", make_summary(i));
        }

        let ctx = tracker.get_context("server-a", 3);
        assert_eq!(ctx.recent_events.len(), 3);
        // Should be the last 3 events.
        assert_eq!(ctx.recent_events[0].summary, "event_7");
        assert_eq!(ctx.recent_events[2].summary, "event_9");
    }

    #[test]
    fn unknown_server_returns_empty_context() {
        let tracker = ContextTracker::new();
        let ctx = tracker.get_context("nonexistent", 10);
        assert!(ctx.recent_events.is_empty());
        assert_eq!(ctx.server_reputation.total_allowed, 0);
        assert_eq!(ctx.server_reputation.total_blocked, 0);
        assert_eq!(ctx.server_reputation.total_prompted, 0);
    }

    #[test]
    fn reputation_counts() {
        let mut tracker = ContextTracker::new();
        tracker.record_decision("server-a", DecisionOutcome::Allowed);
        tracker.record_decision("server-a", DecisionOutcome::Allowed);
        tracker.record_decision("server-a", DecisionOutcome::Blocked);
        tracker.record_decision("server-a", DecisionOutcome::Prompted);
        tracker.record_decision("server-a", DecisionOutcome::Prompted);
        tracker.record_decision("server-a", DecisionOutcome::Prompted);

        let ctx = tracker.get_context("server-a", 0);
        assert_eq!(ctx.server_reputation.total_allowed, 2);
        assert_eq!(ctx.server_reputation.total_blocked, 1);
        assert_eq!(ctx.server_reputation.total_prompted, 3);
    }

    #[test]
    fn separate_server_contexts() {
        let mut tracker = ContextTracker::new();
        tracker.record_event("server-a", make_summary(1));
        tracker.record_event("server-b", make_summary(2));
        tracker.record_decision("server-a", DecisionOutcome::Blocked);
        tracker.record_decision("server-b", DecisionOutcome::Allowed);

        let ctx_a = tracker.get_context("server-a", 10);
        assert_eq!(ctx_a.recent_events.len(), 1);
        assert_eq!(ctx_a.recent_events[0].summary, "event_1");
        assert_eq!(ctx_a.server_reputation.total_blocked, 1);
        assert_eq!(ctx_a.server_reputation.total_allowed, 0);

        let ctx_b = tracker.get_context("server-b", 10);
        assert_eq!(ctx_b.recent_events.len(), 1);
        assert_eq!(ctx_b.recent_events[0].summary, "event_2");
        assert_eq!(ctx_b.server_reputation.total_allowed, 1);
        assert_eq!(ctx_b.server_reputation.total_blocked, 0);
    }

    #[test]
    fn ring_buffer_at_exact_capacity() {
        let mut tracker = ContextTracker::new();
        for i in 0..MAX_RECENT_EVENTS {
            tracker.record_event("server-a", make_summary(i));
        }

        let ctx = tracker.get_context("server-a", 100);
        assert_eq!(ctx.recent_events.len(), MAX_RECENT_EVENTS);
        assert_eq!(ctx.recent_events[0].summary, "event_0");

        // One more should evict the first.
        tracker.record_event("server-a", make_summary(100));
        let ctx = tracker.get_context("server-a", 100);
        assert_eq!(ctx.recent_events.len(), MAX_RECENT_EVENTS);
        assert_eq!(ctx.recent_events[0].summary, "event_1");
    }
}
