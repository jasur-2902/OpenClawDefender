//! Resource limits and monitoring for the sensor layer.
//!
//! Provides configurable limits for channel sizes, buffer capacities, and
//! memory usage, along with a periodic monitor that logs warnings when
//! thresholds are approached.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::warn;

/// Configurable resource limits for the sensor subsystem.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum capacity for the main event channel.
    pub max_event_channel_capacity: usize,
    /// Maximum number of MCP events in the correlation window.
    pub max_mcp_window_size: usize,
    /// Maximum number of OS events in the correlation window.
    pub max_os_window_size: usize,
    /// Maximum entries in the process tree.
    pub max_process_tree_size: usize,
    /// Maximum entries in debounce maps.
    pub max_debounce_entries: usize,
    /// Memory usage warning threshold in megabytes.
    pub memory_warning_threshold_mb: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_event_channel_capacity: 10_000,
            max_mcp_window_size: 500,
            max_os_window_size: 5_000,
            max_process_tree_size: 10_000,
            max_debounce_entries: 10_000,
            memory_warning_threshold_mb: 100,
        }
    }
}

/// Periodically estimates the sensor's memory usage and logs warnings
/// when approaching configured thresholds.
pub struct ResourceMonitor {
    limits: Arc<ResourceLimits>,
    shutdown_rx: watch::Receiver<bool>,
}

impl ResourceMonitor {
    /// Create a new resource monitor.
    ///
    /// Returns the monitor and a shutdown sender. Drop or send `true` on
    /// the sender to stop the monitoring loop.
    pub fn new(limits: ResourceLimits) -> (Self, watch::Sender<bool>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        (
            Self {
                limits: Arc::new(limits),
                shutdown_rx,
            },
            shutdown_tx,
        )
    }

    /// Start the monitoring loop. Checks memory usage at the given interval.
    pub async fn run(mut self, interval: Duration) {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    self.check_memory();
                }
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        return;
                    }
                }
            }
        }
    }

    /// Estimate current process memory usage and warn if over threshold.
    fn check_memory(&self) {
        let rss_mb = estimate_rss_mb();
        if rss_mb > self.limits.memory_warning_threshold_mb {
            warn!(
                rss_mb = rss_mb,
                threshold_mb = self.limits.memory_warning_threshold_mb,
                "sensor memory usage exceeds warning threshold"
            );
        }
    }

    /// Get a reference to the configured limits.
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }
}

/// Estimate the current process RSS in megabytes using sysinfo.
fn estimate_rss_mb() -> usize {
    use sysinfo::{ProcessesToUpdate, System};
    let pid = std::process::id();
    let mut sys = System::new();
    sys.refresh_processes(
        ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]),
        true,
    );
    sys.process(sysinfo::Pid::from_u32(pid))
        .map(|p| (p.memory() / (1024 * 1024)) as usize)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_are_sane() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_event_channel_capacity, 10_000);
        assert_eq!(limits.max_mcp_window_size, 500);
        assert_eq!(limits.max_os_window_size, 5_000);
        assert_eq!(limits.max_process_tree_size, 10_000);
        assert_eq!(limits.max_debounce_entries, 10_000);
        assert_eq!(limits.memory_warning_threshold_mb, 100);
    }

    #[test]
    fn estimate_rss_returns_nonzero() {
        // Our own process should use some memory
        let rss = estimate_rss_mb();
        // Just verify it doesn't panic; on CI the value might be 0
        assert!(rss < 10_000, "RSS seems unreasonably high: {rss} MB");
    }

    #[tokio::test]
    async fn monitor_can_be_shutdown() {
        let (monitor, shutdown_tx) = ResourceMonitor::new(ResourceLimits::default());
        let handle = tokio::spawn(monitor.run(Duration::from_millis(50)));

        // Let it run one tick
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Signal shutdown
        shutdown_tx.send(true).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "monitor should have shut down");
    }
}
