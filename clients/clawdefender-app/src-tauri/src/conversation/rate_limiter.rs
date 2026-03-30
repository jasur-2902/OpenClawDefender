//! Rate limiting for Ask Claw conversation actions.
//!
//! Prevents abuse by enforcing per-minute limits on messages, control actions,
//! and file analyses. Uses a sliding window approach with VecDeque of timestamps.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Rate limiter for conversation operations.
///
/// Enforces separate limits for:
/// - General messages (60/min)
/// - Control actions like block/allow/pause (10/min)
/// - File/URL analysis requests (20/min)
pub struct RateLimiter {
    message_timestamps: VecDeque<Instant>,
    control_timestamps: VecDeque<Instant>,
    analysis_timestamps: VecDeque<Instant>,
    max_messages_per_minute: usize,
    max_controls_per_minute: usize,
    max_analyses_per_minute: usize,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            message_timestamps: VecDeque::new(),
            control_timestamps: VecDeque::new(),
            analysis_timestamps: VecDeque::new(),
            max_messages_per_minute: 60,
            max_controls_per_minute: 10,
            max_analyses_per_minute: 20,
        }
    }

    /// Check and record a general message. Returns Err if rate limit exceeded.
    pub fn check_message(&mut self) -> Result<(), String> {
        Self::check_and_record(
            &mut self.message_timestamps,
            self.max_messages_per_minute,
            "messages",
        )
    }

    /// Check and record a control action. Returns Err if rate limit exceeded.
    pub fn check_control_action(&mut self) -> Result<(), String> {
        Self::check_and_record(
            &mut self.control_timestamps,
            self.max_controls_per_minute,
            "control actions",
        )
    }

    /// Check and record a file/URL analysis. Returns Err if rate limit exceeded.
    pub fn check_file_analysis(&mut self) -> Result<(), String> {
        Self::check_and_record(
            &mut self.analysis_timestamps,
            self.max_analyses_per_minute,
            "file analyses",
        )
    }

    /// Prune expired entries, check limit, and record a new timestamp.
    fn check_and_record(
        timestamps: &mut VecDeque<Instant>,
        max_per_minute: usize,
        label: &str,
    ) -> Result<(), String> {
        let window = Duration::from_secs(60);
        let now = Instant::now();

        // Remove timestamps older than 1 minute
        while let Some(&front) = timestamps.front() {
            if now.duration_since(front) > window {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        if timestamps.len() >= max_per_minute {
            let oldest = timestamps.front().unwrap();
            let wait = window
                .checked_sub(now.duration_since(*oldest))
                .unwrap_or(Duration::ZERO);
            return Err(format!(
                "Rate limit exceeded: {} {} per minute. Try again in {} seconds.",
                max_per_minute,
                label,
                wait.as_secs() + 1,
            ));
        }

        timestamps.push_back(now);
        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_under_limit() {
        let mut rl = RateLimiter::new();
        for _ in 0..60 {
            assert!(rl.check_message().is_ok());
        }
    }

    #[test]
    fn test_message_over_limit() {
        let mut rl = RateLimiter::new();
        for _ in 0..60 {
            rl.check_message().unwrap();
        }
        let result = rl.check_message();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Rate limit exceeded"));
    }

    #[test]
    fn test_control_limit() {
        let mut rl = RateLimiter::new();
        for _ in 0..10 {
            assert!(rl.check_control_action().is_ok());
        }
        assert!(rl.check_control_action().is_err());
    }

    #[test]
    fn test_analysis_limit() {
        let mut rl = RateLimiter::new();
        for _ in 0..20 {
            assert!(rl.check_file_analysis().is_ok());
        }
        assert!(rl.check_file_analysis().is_err());
    }

    #[test]
    fn test_independent_limits() {
        let mut rl = RateLimiter::new();
        // Exhaust control limit
        for _ in 0..10 {
            rl.check_control_action().unwrap();
        }
        assert!(rl.check_control_action().is_err());
        // Message limit should still be available
        assert!(rl.check_message().is_ok());
        assert!(rl.check_file_analysis().is_ok());
    }

    #[test]
    fn test_default_trait() {
        let rl = RateLimiter::default();
        assert_eq!(rl.max_messages_per_minute, 60);
        assert_eq!(rl.max_controls_per_minute, 10);
        assert_eq!(rl.max_analyses_per_minute, 20);
    }

    #[test]
    fn test_error_message_format() {
        let mut rl = RateLimiter::new();
        for _ in 0..10 {
            rl.check_control_action().unwrap();
        }
        let err = rl.check_control_action().unwrap_err();
        assert!(err.contains("10"));
        assert!(err.contains("control actions"));
        assert!(err.contains("Try again in"));
    }
}
