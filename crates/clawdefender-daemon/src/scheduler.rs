//! Unified power-aware task scheduler.
//!
//! Consolidates multiple independent polling loops and timers into a single
//! 500ms tick loop. On each tick the scheduler checks which tasks are due and
//! runs them in one batch (coalesced wakeups), reducing CPU wake-ups and
//! adapting intervals based on the current power state.

use std::time::{Duration, Instant};

use tracing::{debug, info};

/// Power state of the machine, used to scale task intervals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// Connected to AC power.
    PluggedIn,
    /// Running on battery with the given charge percentage.
    Battery(u8),
    /// Battery is below 20%.
    LowBattery(u8),
}

impl std::fmt::Display for PowerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PowerState::PluggedIn => write!(f, "AC Power"),
            PowerState::Battery(pct) => write!(f, "Battery ({}%)", pct),
            PowerState::LowBattery(pct) => write!(f, "Low Battery ({}%)", pct),
        }
    }
}

/// A single scheduled task with power-aware intervals.
pub struct ScheduledTask {
    /// Human-readable name for logging.
    pub name: &'static str,
    /// Interval when plugged in to AC power.
    pub interval_plugged: Duration,
    /// Interval when on battery power (>= 20%).
    pub interval_battery: Duration,
    /// Interval when on low battery (< 20%). Duration::ZERO means disabled.
    pub interval_low_battery: Duration,
    /// When the task last ran.
    pub last_run: Instant,
    /// Whether the task is enabled.
    pub enabled: bool,
}

impl ScheduledTask {
    /// Create a new scheduled task. Starts with `last_run` set to now so
    /// it won't fire immediately on the first tick (caller can override).
    pub fn new(
        name: &'static str,
        interval_plugged: Duration,
        interval_battery: Duration,
        interval_low_battery: Duration,
    ) -> Self {
        Self {
            name,
            interval_plugged,
            interval_battery,
            interval_low_battery,
            last_run: Instant::now(),
            enabled: true,
        }
    }

    /// Create a task that fires immediately on the first tick.
    pub fn new_immediate(
        name: &'static str,
        interval_plugged: Duration,
        interval_battery: Duration,
        interval_low_battery: Duration,
    ) -> Self {
        Self {
            name,
            interval_plugged,
            interval_battery,
            interval_low_battery,
            // Set last_run far enough in the past to trigger immediately
            last_run: Instant::now() - interval_plugged - Duration::from_secs(1),
            enabled: true,
        }
    }

    /// Get the effective interval for the current power state.
    fn effective_interval(&self, power_state: PowerState) -> Duration {
        match power_state {
            PowerState::PluggedIn => self.interval_plugged,
            PowerState::Battery(_) => self.interval_battery,
            PowerState::LowBattery(_) => self.interval_low_battery,
        }
    }

    /// Check if this task is due to run. Returns true if enough time has
    /// elapsed since the last run. Tasks with Duration::ZERO interval are
    /// disabled for that power state.
    fn is_due(&self, power_state: PowerState) -> bool {
        if !self.enabled {
            return false;
        }
        let interval = self.effective_interval(power_state);
        if interval == Duration::ZERO {
            return false; // disabled in this power state
        }
        self.last_run.elapsed() >= interval
    }

    /// Mark the task as having just run.
    fn mark_run(&mut self) {
        self.last_run = Instant::now();
    }
}

/// Well-known task identifiers used to index into the scheduler's task list.
/// These must match the order tasks are registered in `Scheduler::with_daemon_tasks`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskId {
    ProcessTreeRefresh = 0,
    GuardPidCleanup = 1,
    PowerStateCheck = 2,
}

/// The unified scheduler that replaces independent timer spawns.
///
/// Ticks every 500ms, checks which tasks are due, and returns their indices
/// so the caller can run them. This design avoids allocations per tick — the
/// due-list is a fixed-capacity `Vec` reused across ticks.
pub struct Scheduler {
    tasks: Vec<ScheduledTask>,
    power_state: PowerState,
    tick_interval: Duration,
}

impl Scheduler {
    /// Create a new scheduler with the given tick interval.
    pub fn new(tick_interval: Duration) -> Self {
        Self {
            tasks: Vec::new(),
            power_state: PowerState::PluggedIn,
            tick_interval,
        }
    }

    /// Get the tick interval.
    pub fn tick_interval(&self) -> Duration {
        self.tick_interval
    }

    /// Get the current power state.
    pub fn power_state(&self) -> PowerState {
        self.power_state
    }

    /// Update the power state. Returns true if the state changed.
    pub fn set_power_state(&mut self, state: PowerState) -> bool {
        if self.power_state != state {
            info!(
                old = %self.power_state,
                new = %state,
                "Power state changed: {} -> {}",
                self.power_state,
                state,
            );
            self.power_state = state;
            true
        } else {
            false
        }
    }

    /// Add a task to the scheduler. Returns the task index.
    pub fn add_task(&mut self, task: ScheduledTask) -> usize {
        let idx = self.tasks.len();
        debug!(name = task.name, idx, "Scheduler: registered task '{}' at index {}", task.name, idx);
        self.tasks.push(task);
        idx
    }

    /// Check which tasks are due and return their indices. Marks due tasks
    /// as having run. This is the hot path — no allocations beyond the
    /// returned Vec (which callers should reuse if performance-critical).
    pub fn tick(&mut self) -> Vec<usize> {
        let mut due = Vec::new();
        let state = self.power_state;
        for (idx, task) in self.tasks.iter_mut().enumerate() {
            if task.is_due(state) {
                task.mark_run();
                due.push(idx);
            }
        }
        due
    }

    /// Get the number of registered tasks.
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Enable or disable a task by index.
    pub fn set_task_enabled(&mut self, idx: usize, enabled: bool) {
        if let Some(task) = self.tasks.get_mut(idx) {
            task.enabled = enabled;
        }
    }

    /// Create a scheduler pre-populated with the standard daemon tasks.
    ///
    /// Task indices correspond to `TaskId` variants:
    /// - 0: ProcessTreeRefresh
    /// - 1: GuardPidCleanup
    /// - 2: PowerStateCheck
    pub fn with_daemon_tasks(process_tree_refresh_secs: u64) -> Self {
        let mut scheduler = Self::new(Duration::from_millis(500));

        // Task 0: Process tree refresh
        scheduler.add_task(ScheduledTask::new_immediate(
            "process_tree_refresh",
            Duration::from_secs(process_tree_refresh_secs),
            Duration::from_secs(15),
            Duration::from_secs(30),
        ));

        // Task 1: Guard PID cleanup
        scheduler.add_task(ScheduledTask::new(
            "guard_pid_cleanup",
            Duration::from_secs(5),
            Duration::from_secs(15),
            Duration::from_secs(30),
        ));

        // Task 2: Power state check (always runs at 30s regardless of state)
        scheduler.add_task(ScheduledTask::new(
            "power_state_check",
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
        ));

        scheduler
    }
}

/// Detect the current power state on macOS by parsing `pmset -g batt` output.
///
/// Returns `PowerState::PluggedIn` as the default if detection fails, since
/// that's the safest assumption (no interval scaling).
#[cfg(target_os = "macos")]
pub fn detect_power_state() -> PowerState {
    use std::process::Command;

    let output = match Command::new("pmset").args(["-g", "batt"]).output() {
        Ok(o) => o,
        Err(e) => {
            debug!(error = %e, "pmset command failed, assuming AC power");
            return PowerState::PluggedIn;
        }
    };

    if !output.status.success() {
        debug!("pmset returned non-zero exit code, assuming AC power");
        return PowerState::PluggedIn;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_pmset_output(&stdout)
}

/// Fallback for non-macOS platforms: always report AC power.
#[cfg(not(target_os = "macos"))]
pub fn detect_power_state() -> PowerState {
    PowerState::PluggedIn
}

/// Parse the output of `pmset -g batt` to determine power state.
///
/// Example output:
/// ```text
/// Now drawing from 'AC Power'
///  -InternalBattery-0 (id=...)	100%; charged; 0:00 remaining
/// ```
/// or:
/// ```text
/// Now drawing from 'Battery Power'
///  -InternalBattery-0 (id=...)	45%; discharging; 3:20 remaining
/// ```
fn parse_pmset_output(output: &str) -> PowerState {
    // Check if on AC power
    let on_ac = output.contains("AC Power");

    if on_ac {
        return PowerState::PluggedIn;
    }

    // Try to extract battery percentage
    // Look for pattern like "45%;" or "100%;"
    let percentage = output
        .lines()
        .find(|line| line.contains('%'))
        .and_then(|line| {
            // Find the percentage number before the % sign
            let pct_pos = line.find('%')?;
            // Walk backwards from % to find the start of the number
            let num_start = line[..pct_pos]
                .rfind(|c: char| !c.is_ascii_digit())
                .map(|i| i + 1)
                .unwrap_or(0);
            line[num_start..pct_pos].parse::<u8>().ok()
        })
        .unwrap_or(50); // Default to 50% if we can't parse

    if percentage < 20 {
        PowerState::LowBattery(percentage)
    } else {
        PowerState::Battery(percentage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pmset_ac_power() {
        let output = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=...)	100%; charged; 0:00 remaining\n";
        assert_eq!(parse_pmset_output(output), PowerState::PluggedIn);
    }

    #[test]
    fn test_parse_pmset_battery_normal() {
        let output = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=...)	45%; discharging; 3:20 remaining\n";
        assert_eq!(parse_pmset_output(output), PowerState::Battery(45));
    }

    #[test]
    fn test_parse_pmset_battery_low() {
        let output = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=...)	12%; discharging; 0:45 remaining\n";
        assert_eq!(parse_pmset_output(output), PowerState::LowBattery(12));
    }

    #[test]
    fn test_parse_pmset_empty_defaults_to_plugged_in() {
        // No "AC Power" and no percentage => Battery(50) default
        let output = "Now drawing from 'Battery Power'\n";
        assert_eq!(parse_pmset_output(output), PowerState::Battery(50));
    }

    #[test]
    fn test_task_due_when_interval_elapsed() {
        let mut task = ScheduledTask::new(
            "test",
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(300),
        );
        // Just created, not due yet
        assert!(!task.is_due(PowerState::PluggedIn));

        // Force last_run into the past
        task.last_run = Instant::now() - Duration::from_millis(150);
        assert!(task.is_due(PowerState::PluggedIn));
    }

    #[test]
    fn test_task_disabled_in_low_battery() {
        let task = ScheduledTask::new_immediate(
            "test",
            Duration::from_secs(60),
            Duration::from_secs(120),
            Duration::ZERO, // disabled on low battery
        );
        assert!(!task.is_due(PowerState::LowBattery(10)));
    }

    #[test]
    fn test_task_uses_battery_interval() {
        let mut task = ScheduledTask::new(
            "test",
            Duration::from_millis(100),
            Duration::from_millis(500),
            Duration::from_millis(1000),
        );
        // 200ms ago — due on AC (100ms interval) but not on battery (500ms interval)
        task.last_run = Instant::now() - Duration::from_millis(200);
        assert!(task.is_due(PowerState::PluggedIn));
        assert!(!task.is_due(PowerState::Battery(50)));
    }

    #[test]
    fn test_scheduler_tick_returns_due_tasks() {
        let mut scheduler = Scheduler::new(Duration::from_millis(500));
        let idx0 = scheduler.add_task(ScheduledTask::new_immediate(
            "fast",
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::from_millis(10),
        ));
        let idx1 = scheduler.add_task(ScheduledTask::new(
            "slow",
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        ));
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);

        // Small sleep to ensure the fast task is due
        std::thread::sleep(Duration::from_millis(15));

        let due = scheduler.tick();
        assert!(due.contains(&0), "fast task should be due");
        assert!(!due.contains(&1), "slow task should not be due");
    }

    #[test]
    fn test_scheduler_power_state_change() {
        let mut scheduler = Scheduler::new(Duration::from_millis(500));
        assert_eq!(scheduler.power_state(), PowerState::PluggedIn);

        let changed = scheduler.set_power_state(PowerState::Battery(75));
        assert!(changed);
        assert_eq!(scheduler.power_state(), PowerState::Battery(75));

        let changed = scheduler.set_power_state(PowerState::Battery(75));
        assert!(!changed);
    }

    #[test]
    fn test_set_task_enabled() {
        let mut scheduler = Scheduler::new(Duration::from_millis(500));
        scheduler.add_task(ScheduledTask::new_immediate(
            "test",
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        ));
        std::thread::sleep(Duration::from_millis(5));

        // Should be due
        assert!(!scheduler.tick().is_empty());

        // Disable it
        scheduler.set_task_enabled(0, false);
        std::thread::sleep(Duration::from_millis(5));
        assert!(scheduler.tick().is_empty());

        // Re-enable
        scheduler.set_task_enabled(0, true);
        std::thread::sleep(Duration::from_millis(5));
        assert!(!scheduler.tick().is_empty());
    }
}
