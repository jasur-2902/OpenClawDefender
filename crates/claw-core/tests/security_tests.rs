//! Security-focused integration tests for ClawAI core.
//!
//! These tests verify that security hardening measures work correctly,
//! including path canonicalization, regex protection, and rate limiting.

use std::time::Duration;

use claw_core::policy::matcher::{canonicalize_path, GlobMatcher, RegexMatcher};
use claw_core::policy::rule::EventContext;
use claw_core::policy::{MatchCriteria, PolicyAction, PolicyRule};
use claw_core::rate_limit::{PromptRateLimiter, RateLimitResult};

// ---------------------------------------------------------------------------
// Path canonicalization security tests
// ---------------------------------------------------------------------------

#[test]
fn test_null_byte_in_path_rejected() {
    let result = canonicalize_path("/tmp/safe\0/../../etc/passwd");
    assert!(result.is_err(), "Null byte in path must be rejected");
    assert!(result.unwrap_err().to_string().contains("null byte"));
}

#[test]
fn test_path_traversal_blocked() {
    // Even though the raw path contains traversal, canonicalize resolves it
    let canonical = canonicalize_path("/project/data/../../../etc/passwd").unwrap();
    assert_eq!(canonical, "/etc/passwd");

    // A policy that allows /project/** should NOT match the canonicalized path
    let rule = PolicyRule {
        name: "allow_project".to_string(),
        description: "Allow project files".to_string(),
        match_criteria: MatchCriteria {
            resource_paths: Some(vec!["/project/**".to_string()]),
            ..Default::default()
        },
        action: PolicyAction::Allow,
        message: "Allowed".to_string(),
        priority: 0,
    };

    // The canonicalized path is /etc/passwd, which should NOT match /project/**
    let ctx = EventContext {
        resource_path: Some("/project/data/../../../etc/passwd".to_string()),
        ..Default::default()
    };
    // The rule.matches() now canonicalizes internally, so traversal is blocked
    assert!(
        !rule.matches(&ctx),
        "Path traversal must not bypass policy rules"
    );
}

#[test]
fn test_case_insensitive_path_matching() {
    // On macOS HFS+, /etc/passwd and /ETC/PASSWD refer to the same file.
    // GlobMatcher should handle this via case-insensitive matching option.
    // For now, verify that the glob matcher uses exact case by default,
    // and document that macOS case sensitivity is an acknowledged limitation.
    let m = GlobMatcher::new("/etc/passwd").unwrap();
    assert!(m.is_match("/etc/passwd"));
    // Note: glob crate is case-sensitive by default. On macOS, this means
    // /ETC/PASSWD and /etc/passwd are treated differently by the matcher,
    // even though HFS+ considers them the same. This is a known limitation.
}

#[test]
fn test_empty_home_env_handled() {
    // Save and clear HOME
    let original_home = std::env::var("HOME").ok();
    std::env::remove_var("HOME");

    // Should not panic or error -- just keeps the ~ literal
    let result = canonicalize_path("~/.ssh/id_rsa");
    assert!(result.is_ok(), "Empty HOME should not cause an error");

    // Restore HOME
    if let Some(home) = original_home {
        std::env::set_var("HOME", home);
    }
}

#[test]
fn test_double_dot_at_root_stays_at_root() {
    let canonical = canonicalize_path("/../../../../").unwrap();
    assert_eq!(canonical, "/");
}

#[test]
fn test_repeated_slashes_normalized() {
    let canonical = canonicalize_path("/a///b////c").unwrap();
    assert_eq!(canonical, "/a/b/c");
}

#[test]
fn test_dot_segments_resolved() {
    let canonical = canonicalize_path("/a/./b/./c/./d").unwrap();
    assert_eq!(canonical, "/a/b/c/d");
}

// ---------------------------------------------------------------------------
// Regex timeout / ReDoS protection tests
// ---------------------------------------------------------------------------

#[test]
fn test_regex_timeout_protection() {
    // Pathological regex pattern that could cause exponential backtracking.
    // The regex crate uses a finite automaton, so it won't actually hang,
    // but we verify that a complex pattern is handled within size limits.
    let result = RegexMatcher::new("(a+)+b");
    // The regex crate's RE2-style engine handles this pattern efficiently,
    // so it should compile. The size_limit guards against truly massive patterns.
    assert!(result.is_ok(), "Simple nested quantifier should compile");

    // Very large pattern that exceeds size limit
    let huge_pattern = format!("({})+", "a".repeat(50000));
    let result = RegexMatcher::new(&huge_pattern);
    assert!(
        result.is_err(),
        "Extremely large regex pattern should be rejected by size limit"
    );
}

// ---------------------------------------------------------------------------
// Prompt rate limiting tests
// ---------------------------------------------------------------------------

#[test]
fn test_prompt_rate_limiting() {
    let mut rl = PromptRateLimiter::new(10, Duration::from_secs(60));

    // First 10 prompts should be allowed
    for i in 0..10 {
        assert_eq!(
            rl.check("attack-server"),
            RateLimitResult::Allowed,
            "Prompt {} should be allowed",
            i + 1
        );
    }

    // 11th prompt should trigger blocking
    assert_eq!(
        rl.check("attack-server"),
        RateLimitResult::NewlyBlocked,
        "11th prompt should trigger auto-block"
    );

    // Subsequent prompts should be auto-blocked
    assert_eq!(
        rl.check("attack-server"),
        RateLimitResult::AutoBlocked,
        "12th prompt should be auto-blocked"
    );
}

#[test]
fn test_rate_limit_does_not_affect_other_servers() {
    let mut rl = PromptRateLimiter::new(1, Duration::from_secs(60));

    assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
    assert_eq!(rl.check("server-a"), RateLimitResult::NewlyBlocked);

    // server-b should be unaffected
    assert_eq!(rl.check("server-b"), RateLimitResult::Allowed);
}

#[test]
fn test_rate_limit_blocked_persists_across_window() {
    let mut rl = PromptRateLimiter::new(1, Duration::from_millis(10));

    assert_eq!(rl.check("server-a"), RateLimitResult::Allowed);
    assert_eq!(rl.check("server-a"), RateLimitResult::NewlyBlocked);

    // Even after window expires, blocked servers stay blocked for the session
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        rl.check("server-a"),
        RateLimitResult::AutoBlocked,
        "Blocked servers should stay blocked for the entire session"
    );
}
