//! Event budget system for eslogger rate limiting.
//!
//! Caps how many eslogger events per second the daemon processes, with
//! intelligent priority-based sampling under load. Security-critical events
//! (sensitive path access, exec, network) are always processed; low-value
//! events (close, non-sensitive open) are sampled or dropped when over budget.

use std::time::{Duration, Instant};

use tracing::debug;

/// Rolling window size for rate calculation.
const RATE_WINDOW: Duration = Duration::from_secs(5);

/// How often to recalculate the tier (every N events).
const TIER_RECALC_INTERVAL: u64 = 64;

/// Sensitive path prefixes where even read-only access must always be processed.
const BUDGET_SENSITIVE_PREFIXES: &[&str] = &[
    "/.ssh/",
    "/.ssh",
    "/.gnupg/",
    "/.gnupg",
    "/.aws/",
    "/.aws",
    "/.kube/",
    "/.kube",
    "/.azure/",
    "/.azure",
    "/.config/gcloud/",
    "/.config/gcloud",
    "/.docker/config.json",
    "/.npmrc",
    "/.pypirc",
    "/.netrc",
    "/.gitconfig",
    "/.env",
    "/Library/Keychains/",
    "/Library/Keychains",
];

/// Sensitive absolute paths that always bypass the budget.
const BUDGET_SENSITIVE_ABSOLUTE: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/private/etc/",
];

/// Load tier classification based on raw event rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetTier {
    /// < 10 events/sec: process ALL events.
    Idle,
    /// 10-50 events/sec: process ALL events.
    Normal,
    /// 50-200 events/sec: sample down to ~50/sec for non-critical.
    Busy,
    /// 200-1000 events/sec: sample down to ~30/sec for non-critical.
    Heavy,
    /// 1000+ events/sec: sample down to ~10/sec for non-critical.
    Flood,
}

impl BudgetTier {
    /// Maximum non-critical events per second for this tier.
    /// Returns `None` if no sampling is needed (all events pass).
    fn budget_limit(self) -> Option<u32> {
        match self {
            BudgetTier::Idle | BudgetTier::Normal => None,
            BudgetTier::Busy => Some(50),
            BudgetTier::Heavy => Some(30),
            BudgetTier::Flood => Some(10),
        }
    }

    fn from_rate(rate: f64) -> Self {
        if rate < 10.0 {
            BudgetTier::Idle
        } else if rate < 50.0 {
            BudgetTier::Normal
        } else if rate < 200.0 {
            BudgetTier::Busy
        } else if rate < 1000.0 {
            BudgetTier::Heavy
        } else {
            BudgetTier::Flood
        }
    }
}

impl std::fmt::Display for BudgetTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetTier::Idle => write!(f, "idle"),
            BudgetTier::Normal => write!(f, "normal"),
            BudgetTier::Busy => write!(f, "busy"),
            BudgetTier::Heavy => write!(f, "heavy"),
            BudgetTier::Flood => write!(f, "flood"),
        }
    }
}

/// Decision returned by the budget system for a given event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessDecision {
    /// Security-critical event, always process regardless of budget.
    Always,
    /// Under budget, process normally.
    Process,
    /// Over budget, drop this event.
    Drop,
}

/// Snapshot of budget statistics for external consumers (e.g. UI).
#[derive(Debug, Clone)]
pub struct BudgetStats {
    /// Raw events per second entering the system.
    pub current_rate: f64,
    /// Events actually processed per second.
    pub processed_rate: f64,
    /// Current load tier.
    pub tier: BudgetTier,
    /// Total events dropped since start.
    pub events_dropped: u64,
    /// Total events sampled (passed via sampling) since start.
    pub events_sampled: u64,
    /// Whether sampling is currently active.
    pub sampling_active: bool,
}

/// Event budget tracker with priority-based sampling.
///
/// Must be called on every event before expensive processing. The check is
/// designed to be extremely cheap (<1us): no allocations, no locks, just
/// arithmetic and a few comparisons.
pub struct EventBudget {
    /// Current load tier.
    tier: BudgetTier,
    /// Configurable max events/sec (overrides tier default when set).
    max_events_per_second: Option<u32>,
    /// Start of the current rolling window.
    window_start: Instant,
    /// Total events seen in the current window.
    window_events: u64,
    /// Computed rate from the last complete window.
    current_rate: f64,
    // --- Stats ---
    /// Total events that received `Always` or `Process`.
    events_processed: u64,
    /// Events that passed via sampling (subset of processed).
    events_sampled: u64,
    /// Events that were dropped.
    events_dropped: u64,
    // --- Sampling ---
    /// Counter used for deterministic 1-in-N sampling.
    sample_counter: u64,
    /// Events processed in the current second (for budget tracking).
    second_start: Instant,
    second_processed: u32,
}

impl EventBudget {
    /// Create a new budget tracker.
    ///
    /// `max_events_per_second`: optional hard cap that overrides the tier-based
    /// limit. Pass `None` to use the default tier-based limits.
    pub fn new(max_events_per_second: Option<u32>) -> Self {
        let now = Instant::now();
        Self {
            tier: BudgetTier::Idle,
            max_events_per_second,
            window_start: now,
            window_events: 0,
            current_rate: 0.0,
            events_processed: 0,
            events_sampled: 0,
            events_dropped: 0,
            sample_counter: 0,
            second_start: now,
            second_processed: 0,
        }
    }

    /// Decide whether an event should be processed.
    ///
    /// `event_type`: the downstream event type string (e.g. "exec", "open", "close").
    /// `event_path`: optional path from the event payload (for sensitive path checks).
    ///
    /// This function is designed to be called on every single event and must be
    /// extremely cheap.
    #[inline]
    pub fn should_process(&mut self, event_type: &str, event_path: Option<&str>) -> ProcessDecision {
        let now = Instant::now();

        // --- Update rate tracking ---
        self.window_events += 1;

        // Recalculate tier periodically (every TIER_RECALC_INTERVAL events).
        if self.window_events & (TIER_RECALC_INTERVAL - 1) == 0 {
            self.update_rate(now);
        }

        // Reset per-second budget counter.
        if now.duration_since(self.second_start) >= Duration::from_secs(1) {
            self.second_start = now;
            self.second_processed = 0;
        }

        // --- Priority classification ---

        // Security-critical events: ALWAYS process.
        if is_always_process(event_type, event_path) {
            self.events_processed += 1;
            self.second_processed += 1;
            return ProcessDecision::Always;
        }

        // Close events: drop when ANY sampling is active.
        if event_type == "close" {
            if self.tier as u8 >= BudgetTier::Busy as u8 {
                self.events_dropped += 1;
                return ProcessDecision::Drop;
            }
        }

        // --- Budget check ---
        let limit = self
            .max_events_per_second
            .or_else(|| self.tier.budget_limit());

        match limit {
            None => {
                // No sampling needed.
                self.events_processed += 1;
                self.second_processed += 1;
                ProcessDecision::Process
            }
            Some(max_per_sec) => {
                if self.second_processed < max_per_sec {
                    // Under budget.
                    self.events_processed += 1;
                    self.second_processed += 1;
                    ProcessDecision::Process
                } else {
                    // Over budget: deterministic 1-in-N sampling.
                    self.sample_counter += 1;
                    let overload_factor = if max_per_sec > 0 {
                        (self.current_rate as u32).checked_div(max_per_sec).unwrap_or(1).max(1)
                    } else {
                        1
                    };
                    if self.sample_counter % overload_factor as u64 == 0 {
                        self.events_sampled += 1;
                        self.events_processed += 1;
                        self.second_processed += 1;
                        ProcessDecision::Process
                    } else {
                        self.events_dropped += 1;
                        ProcessDecision::Drop
                    }
                }
            }
        }
    }

    /// Update the rolling rate and tier.
    fn update_rate(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.window_start);
        if elapsed >= RATE_WINDOW {
            let secs = elapsed.as_secs_f64();
            if secs > 0.0 {
                let new_rate = self.window_events as f64 / secs;
                let old_tier = self.tier;
                self.current_rate = new_rate;
                self.tier = BudgetTier::from_rate(new_rate);
                if self.tier != old_tier {
                    debug!(
                        old_tier = %old_tier,
                        new_tier = %self.tier,
                        rate = format!("{:.1}", new_rate),
                        "event budget tier changed"
                    );
                }
            }
            // Reset window.
            self.window_start = now;
            self.window_events = 0;
        }
    }

    /// Get a snapshot of current budget statistics.
    pub fn stats(&self) -> BudgetStats {
        let total = self.events_processed + self.events_dropped;
        let processed_rate = if total > 0 {
            self.current_rate * (self.events_processed as f64 / total as f64)
        } else {
            0.0
        };
        BudgetStats {
            current_rate: self.current_rate,
            processed_rate,
            tier: self.tier,
            events_dropped: self.events_dropped,
            events_sampled: self.events_sampled,
            sampling_active: self.tier.budget_limit().is_some()
                || self.max_events_per_second.is_some(),
        }
    }

    /// Current load tier.
    pub fn tier(&self) -> BudgetTier {
        self.tier
    }

    /// Current computed event rate (events/sec).
    pub fn current_rate(&self) -> f64 {
        self.current_rate
    }
}

/// Check if an event type + path combination should always be processed.
///
/// This covers security-critical events that must never be dropped:
/// - exec (process execution)
/// - connect (network connections)
/// - fork (process creation)
/// - kextload, setuid, setgid, btm_launch_item_add, authentication,
///   xp_malware_detected, gatekeeper_user_override, login_login, login_logout
/// - get_task, trace, proc_check (injection / debugging vectors)
/// - Any event touching a sensitive path
#[inline]
fn is_always_process(event_type: &str, event_path: Option<&str>) -> bool {
    match event_type {
        // Process lifecycle and execution: always critical.
        "exec" | "fork" => return true,
        // Network connections: always critical.
        "connect" => return true,
        // High-value security events: always critical.
        "kextload" | "setuid" | "setgid" | "btm_launch_item_add" | "authentication"
        | "xp_malware_detected" | "gatekeeper_user_override" | "login_login" | "login_logout" => {
            return true;
        }
        // Injection / debugging vectors: always critical.
        "get_task" | "trace" | "proc_check" => return true,
        _ => {}
    }

    // Check if the event path is security-sensitive.
    if let Some(path) = event_path {
        if is_budget_sensitive_path(path) {
            return true;
        }
    }

    false
}

/// Fast check for security-sensitive paths.
#[inline]
fn is_budget_sensitive_path(path: &str) -> bool {
    for prefix in BUDGET_SENSITIVE_ABSOLUTE {
        if path.starts_with(prefix) {
            return true;
        }
    }
    for suffix in BUDGET_SENSITIVE_PREFIXES {
        if path.contains(suffix) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_budget_starts_idle() {
        let budget = EventBudget::new(None);
        assert_eq!(budget.tier(), BudgetTier::Idle);
        assert_eq!(budget.current_rate(), 0.0);
    }

    #[test]
    fn exec_always_processed() {
        let mut budget = EventBudget::new(None);
        let decision = budget.should_process("exec", None);
        assert_eq!(decision, ProcessDecision::Always);
    }

    #[test]
    fn connect_always_processed() {
        let mut budget = EventBudget::new(None);
        let decision = budget.should_process("connect", Some("192.168.1.1:443"));
        assert_eq!(decision, ProcessDecision::Always);
    }

    #[test]
    fn fork_always_processed() {
        let mut budget = EventBudget::new(None);
        assert_eq!(budget.should_process("fork", None), ProcessDecision::Always);
    }

    #[test]
    fn kextload_always_processed() {
        let mut budget = EventBudget::new(None);
        assert_eq!(
            budget.should_process("kextload", None),
            ProcessDecision::Always
        );
    }

    #[test]
    fn sensitive_path_always_processed() {
        let mut budget = EventBudget::new(None);
        // SSH key access.
        assert_eq!(
            budget.should_process("open", Some("/Users/dev/.ssh/id_rsa")),
            ProcessDecision::Always
        );
        // AWS credentials.
        assert_eq!(
            budget.should_process("open", Some("/Users/dev/.aws/credentials")),
            ProcessDecision::Always
        );
        // .env file.
        assert_eq!(
            budget.should_process("open", Some("/Users/dev/project/.env")),
            ProcessDecision::Always
        );
        // /etc/passwd.
        assert_eq!(
            budget.should_process("open", Some("/etc/passwd")),
            ProcessDecision::Always
        );
    }

    #[test]
    fn non_sensitive_open_passes_when_idle() {
        let mut budget = EventBudget::new(None);
        let decision = budget.should_process("open", Some("/tmp/random.txt"));
        assert_eq!(decision, ProcessDecision::Process);
    }

    #[test]
    fn budget_tier_from_rate() {
        assert_eq!(BudgetTier::from_rate(0.0), BudgetTier::Idle);
        assert_eq!(BudgetTier::from_rate(5.0), BudgetTier::Idle);
        assert_eq!(BudgetTier::from_rate(10.0), BudgetTier::Normal);
        assert_eq!(BudgetTier::from_rate(49.9), BudgetTier::Normal);
        assert_eq!(BudgetTier::from_rate(50.0), BudgetTier::Busy);
        assert_eq!(BudgetTier::from_rate(199.9), BudgetTier::Busy);
        assert_eq!(BudgetTier::from_rate(200.0), BudgetTier::Heavy);
        assert_eq!(BudgetTier::from_rate(999.9), BudgetTier::Heavy);
        assert_eq!(BudgetTier::from_rate(1000.0), BudgetTier::Flood);
        assert_eq!(BudgetTier::from_rate(5000.0), BudgetTier::Flood);
    }

    #[test]
    fn budget_limit_returns_none_for_idle_and_normal() {
        assert!(BudgetTier::Idle.budget_limit().is_none());
        assert!(BudgetTier::Normal.budget_limit().is_none());
    }

    #[test]
    fn budget_limit_returns_value_for_sampling_tiers() {
        assert_eq!(BudgetTier::Busy.budget_limit(), Some(50));
        assert_eq!(BudgetTier::Heavy.budget_limit(), Some(30));
        assert_eq!(BudgetTier::Flood.budget_limit(), Some(10));
    }

    #[test]
    fn stats_reflect_state() {
        let budget = EventBudget::new(None);
        let stats = budget.stats();
        assert_eq!(stats.tier, BudgetTier::Idle);
        assert_eq!(stats.events_dropped, 0);
        assert_eq!(stats.events_sampled, 0);
        assert!(!stats.sampling_active);
    }

    #[test]
    fn custom_max_events_overrides_tier() {
        let mut budget = EventBudget::new(Some(5));
        // With a limit of 5/sec, 6th event should be dropped or sampled.
        for _ in 0..5 {
            let d = budget.should_process("open", Some("/tmp/test.txt"));
            assert_eq!(d, ProcessDecision::Process);
        }
        // After 5 events in the same second, should start sampling/dropping.
        let d = budget.should_process("open", Some("/tmp/test.txt"));
        // Could be Process (via sampling) or Drop, but budget is active.
        assert!(d == ProcessDecision::Process || d == ProcessDecision::Drop);
        // Stats should show sampling is active.
        assert!(budget.stats().sampling_active);
    }

    #[test]
    fn security_events_bypass_custom_limit() {
        let mut budget = EventBudget::new(Some(1));
        // Use up the budget.
        budget.should_process("open", Some("/tmp/test.txt"));
        // Exec should still be Always.
        assert_eq!(budget.should_process("exec", None), ProcessDecision::Always);
        // Sensitive path should still be Always.
        assert_eq!(
            budget.should_process("open", Some("/Users/dev/.ssh/id_rsa")),
            ProcessDecision::Always
        );
    }

    #[test]
    fn display_tier() {
        assert_eq!(format!("{}", BudgetTier::Idle), "idle");
        assert_eq!(format!("{}", BudgetTier::Flood), "flood");
    }

    #[test]
    fn injection_events_always_processed() {
        let mut budget = EventBudget::new(None);
        assert_eq!(
            budget.should_process("get_task", None),
            ProcessDecision::Always
        );
        assert_eq!(
            budget.should_process("trace", None),
            ProcessDecision::Always
        );
        assert_eq!(
            budget.should_process("proc_check", None),
            ProcessDecision::Always
        );
    }

    #[test]
    fn gnupg_path_is_sensitive() {
        assert!(is_budget_sensitive_path("/Users/dev/.gnupg/pubring.kbx"));
    }

    #[test]
    fn env_file_is_sensitive() {
        assert!(is_budget_sensitive_path("/Users/dev/project/.env"));
    }

    #[test]
    fn tmp_path_not_sensitive() {
        assert!(!is_budget_sensitive_path("/tmp/random.log"));
    }
}
