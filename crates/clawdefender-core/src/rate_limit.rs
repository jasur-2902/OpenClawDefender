//! Prompt rate limiting to prevent prompt fatigue attacks.
//!
//! If an MCP server floods the user with prompt-triggering calls, the rate
//! limiter auto-blocks further prompts from that server for the rest of the
//! session.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Result of a rate-limit check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitResult {
    /// The prompt is allowed.
    Allowed,
    /// This prompt caused the server to exceed the limit; it is now blocked.
    NewlyBlocked,
    /// The server was already blocked from a previous excess.
    AutoBlocked,
}

/// Rate limiter for prompt-triggering events per MCP server.
pub struct PromptRateLimiter {
    /// server_name -> (count, window_start)
    counters: HashMap<String, (u32, Instant)>,
    /// Maximum prompts allowed per window before auto-blocking.
    max_prompts: u32,
    /// Time window for counting prompts.
    window: Duration,
    /// Servers that have been blocked this session.
    blocked_servers: HashSet<String>,
}

impl PromptRateLimiter {
    /// Create a new rate limiter with the given limits.
    pub fn new(max_prompts: u32, window: Duration) -> Self {
        Self {
            counters: HashMap::new(),
            max_prompts,
            window,
            blocked_servers: HashSet::new(),
        }
    }

    /// Check whether a prompt from the given server is allowed.
    ///
    /// Increments the counter and returns the result.
    pub fn check(&mut self, server_name: &str) -> RateLimitResult {
        // If already blocked this session, reject immediately
        if self.blocked_servers.contains(server_name) {
            return RateLimitResult::AutoBlocked;
        }

        let now = Instant::now();
        let entry = self
            .counters
            .entry(server_name.to_string())
            .or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1) >= self.window {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += 1;

        if entry.0 > self.max_prompts {
            self.blocked_servers.insert(server_name.to_string());
            RateLimitResult::NewlyBlocked
        } else {
            RateLimitResult::Allowed
        }
    }

    /// Returns true if the given server is currently blocked.
    pub fn is_blocked(&self, server_name: &str) -> bool {
        self.blocked_servers.contains(server_name)
    }

    /// Unblock a server (e.g., if the user explicitly allows it).
    pub fn unblock(&mut self, server_name: &str) {
        self.blocked_servers.remove(server_name);
        self.counters.remove(server_name);
    }
}

impl Default for PromptRateLimiter {
    fn default() -> Self {
        Self::new(10, Duration::from_secs(60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_limit() {
        let mut rl = PromptRateLimiter::new(3, Duration::from_secs(60));
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
    }

    #[test]
    fn blocks_on_exceed() {
        let mut rl = PromptRateLimiter::new(2, Duration::from_secs(60));
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
        // Third call exceeds limit
        assert_eq!(rl.check("server-a"), RateLimitResult::NewlyBlocked);
    }

    #[test]
    fn auto_blocks_after_newly_blocked() {
        let mut rl = PromptRateLimiter::new(1, Duration::from_secs(60));
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
        assert_eq!(rl.check("server-a"), RateLimitResult::NewlyBlocked);
        // Subsequent calls are AutoBlocked
        assert_eq!(rl.check("server-a"), RateLimitResult::AutoBlocked);
        assert_eq!(rl.check("server-a"), RateLimitResult::AutoBlocked);
    }

    #[test]
    fn independent_servers() {
        let mut rl = PromptRateLimiter::new(1, Duration::from_secs(60));
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
        assert_eq!(rl.check("server-b"), RateLimitResult::Allowed);
        // server-a blocked, server-b still ok
        assert_eq!(rl.check("server-a"), RateLimitResult::NewlyBlocked);
        assert_eq!(rl.check("server-b"), RateLimitResult::NewlyBlocked);
    }

    #[test]
    fn window_reset() {
        let mut rl = PromptRateLimiter::new(2, Duration::from_millis(50));
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(60));
        // Counter resets, but once blocked stays blocked
        // Actually let's test a fresh server with window reset
        assert_eq!(rl.check("server-b"), RateLimitResult::Allowed);
        assert_eq!(rl.check("server-b"), RateLimitResult::Allowed);
        std::thread::sleep(Duration::from_millis(60));
        // Window expired, counter reset
        assert_eq!(rl.check("server-b"), RateLimitResult::Allowed);
    }

    #[test]
    fn unblock_works() {
        let mut rl = PromptRateLimiter::new(1, Duration::from_secs(60));
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
        assert_eq!(rl.check("server-a"), RateLimitResult::NewlyBlocked);
        assert!(rl.is_blocked("server-a"));

        rl.unblock("server-a");
        assert!(!rl.is_blocked("server-a"));
        assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
    }

    #[test]
    fn default_limits() {
        let rl = PromptRateLimiter::default();
        assert_eq!(rl.max_prompts, 10);
        assert_eq!(rl.window, Duration::from_secs(60));
    }

    #[test]
    fn rate_limit_eleven_prompts_in_60s() {
        let mut rl = PromptRateLimiter::new(10, Duration::from_secs(60));
        for _ in 0..10 {
            assert_eq!(rl.check("flood-server"), RateLimitResult::Allowed);
        }
        // 11th prompt should trigger block
        assert_eq!(rl.check("flood-server"), RateLimitResult::NewlyBlocked);
        // 12th should be auto-blocked
        assert_eq!(rl.check("flood-server"), RateLimitResult::AutoBlocked);
    }
}
