//! Connection rate limiting for network policy enforcement.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Configuration for connection rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum connections per minute per PID.
    #[serde(default = "default_max_connections_per_minute")]
    pub max_connections_per_minute: u32,
    /// Maximum unique destinations in a 10-second window per PID.
    #[serde(default = "default_max_unique_dest_per_10s")]
    pub max_unique_destinations_per_10s: u32,
    /// Whether to generate alerts when limits are exceeded.
    #[serde(default = "default_true")]
    pub alert_on_exceed: bool,
}

fn default_max_connections_per_minute() -> u32 {
    100
}

fn default_max_unique_dest_per_10s() -> u32 {
    10
}

fn default_true() -> bool {
    true
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_connections_per_minute: default_max_connections_per_minute(),
            max_unique_destinations_per_10s: default_max_unique_dest_per_10s(),
            alert_on_exceed: true,
        }
    }
}

/// Per-PID rate tracking window.
#[derive(Debug, Clone)]
struct RateWindow {
    /// Timestamps of connections in the last minute.
    connection_times: Vec<DateTime<Utc>>,
    /// (destination, timestamp) pairs for unique destination tracking.
    destination_times: Vec<(String, DateTime<Utc>)>,
}

impl Default for RateWindow {
    fn default() -> Self {
        Self {
            connection_times: Vec::new(),
            destination_times: Vec::new(),
        }
    }
}

/// An alert generated when rate limits are exceeded.
#[derive(Debug, Clone)]
pub struct RateLimitAlert {
    pub pid: u32,
    pub alert_type: RateLimitAlertType,
    pub current_value: u32,
    pub threshold: u32,
    pub timestamp: DateTime<Utc>,
}

/// Type of rate limit violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitAlertType {
    ConnectionsPerMinute,
    UniqueDestinationsPer10s,
}

/// Tracks per-PID connection rates and generates alerts on violations.
pub struct ConnectionRateLimiter {
    windows: HashMap<u32, RateWindow>,
    config: RateLimitConfig,
}

impl ConnectionRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            windows: HashMap::new(),
            config,
        }
    }

    /// Record a connection and return any rate limit alerts.
    pub fn record_connection(
        &mut self,
        pid: u32,
        destination: &str,
        now: DateTime<Utc>,
    ) -> Vec<RateLimitAlert> {
        let window = self.windows.entry(pid).or_default();

        // Add current connection.
        window.connection_times.push(now);
        window
            .destination_times
            .push((destination.to_string(), now));

        // Prune entries older than 60 seconds.
        let one_minute_ago = now - chrono::Duration::seconds(60);
        window
            .connection_times
            .retain(|t| *t >= one_minute_ago);

        // Prune destination entries older than 10 seconds.
        let ten_seconds_ago = now - chrono::Duration::seconds(10);
        window
            .destination_times
            .retain(|(_, t)| *t >= ten_seconds_ago);

        let mut alerts = Vec::new();

        if !self.config.alert_on_exceed {
            return alerts;
        }

        // Check connections per minute.
        let conn_count = window.connection_times.len() as u32;
        if conn_count > self.config.max_connections_per_minute {
            alerts.push(RateLimitAlert {
                pid,
                alert_type: RateLimitAlertType::ConnectionsPerMinute,
                current_value: conn_count,
                threshold: self.config.max_connections_per_minute,
                timestamp: now,
            });
        }

        // Check unique destinations in 10-second window.
        let mut unique_dests = std::collections::HashSet::new();
        for (dest, _) in &window.destination_times {
            unique_dests.insert(dest.as_str());
        }
        let unique_count = unique_dests.len() as u32;
        if unique_count > self.config.max_unique_destinations_per_10s {
            alerts.push(RateLimitAlert {
                pid,
                alert_type: RateLimitAlertType::UniqueDestinationsPer10s,
                current_value: unique_count,
                threshold: self.config.max_unique_destinations_per_10s,
                timestamp: now,
            });
        }

        alerts
    }

    /// Clear tracking data for a specific PID.
    pub fn clear_pid(&mut self, pid: u32) {
        self.windows.remove(&pid);
    }
}
