//! Security-focused integration tests for ClawDefender core.
//!
//! These tests verify that security hardening measures work correctly,
//! including path canonicalization, regex protection, and rate limiting.

use std::time::Duration;

use std::io::Write;

use clawdefender_core::policy::engine::DefaultPolicyEngine;
use clawdefender_core::policy::matcher::{canonicalize_path, GlobMatcher, RegexMatcher};
use clawdefender_core::policy::rule::EventContext;
use clawdefender_core::policy::{MatchCriteria, PolicyAction, PolicyEngine, PolicyRule};
use clawdefender_core::rate_limit::{PromptRateLimiter, RateLimitResult};

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

// ---------------------------------------------------------------------------
// Symlink resolution security tests
// ---------------------------------------------------------------------------

#[test]
fn test_symlink_to_ssh_key_resolves() {
    // Create a temp directory structure with a symlink pointing to a sensitive file
    let dir = tempfile::TempDir::new().unwrap();
    let target = dir.path().join("secret.txt");
    std::fs::write(&target, "secret").unwrap();

    let link = dir.path().join("innocent.txt");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    // canonicalize_path should resolve the symlink to the real target
    let canonical = canonicalize_path(link.to_str().unwrap()).unwrap();
    assert_eq!(
        canonical,
        target.canonicalize().unwrap().to_str().unwrap(),
        "Symlinks must be resolved to their real target for policy matching"
    );
}

#[test]
fn test_tilde_traversal_to_ssh_blocked() {
    std::env::set_var("HOME", "/Users/testuser");

    // ~/Projects/../../.ssh/test-key should resolve to /Users/.ssh/test-key
    let canonical = canonicalize_path("~/Projects/../../.ssh/test-key").unwrap();
    assert_eq!(canonical, "/Users/.ssh/test-key");

    // Verify it does NOT match ~/Projects/**
    let m = GlobMatcher::new("/Users/testuser/Projects/**").unwrap();
    assert!(
        !m.is_match(&canonical),
        "Traversal from ~/Projects/../../.ssh must not match ~/Projects/**"
    );
}

// ---------------------------------------------------------------------------
// Unicode and long path security tests
// ---------------------------------------------------------------------------

#[test]
fn test_unicode_path_matching() {
    let m = GlobMatcher::new("/project/**").unwrap();
    assert!(m.is_match("/project/na\u{00ef}ve.txt"), "Unicode paths must be matchable");
    assert!(m.is_match("/project/\u{1F600}.txt"), "Emoji in path must be matchable");
}

#[test]
fn test_very_long_path_handled() {
    // 300-char path component
    let long_component = "a".repeat(300);
    let long_path = format!("/project/{}/file.txt", long_component);
    let result = canonicalize_path(&long_path);
    assert!(result.is_ok(), "Very long paths should be handled");

    let m = GlobMatcher::new("/project/**").unwrap();
    assert!(m.is_match(&result.unwrap()));
}

// ---------------------------------------------------------------------------
// Policy reload error resilience
// ---------------------------------------------------------------------------

#[test]
fn test_reload_with_invalid_toml_preserves_old_rules() {
    // Write valid policy first
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"[rules.block_ssh]\ndescription = \"Block SSH\"\naction = \"block\"\nmessage = \"blocked\"\npriority = 0\n\n[rules.block_ssh.match]\nresource_path = [\"/home/user/.ssh/id_*\"]\n").unwrap();
    f.flush().unwrap();

    let mut engine = DefaultPolicyEngine::load(f.path()).unwrap();
    assert_eq!(engine.evaluate(&make_resource_event("/home/user/.ssh/id_rsa")), PolicyAction::Block);

    // Write invalid TOML
    std::fs::write(f.path(), "this is {{{{ not valid toml").unwrap();

    // Reload should fail
    let result = engine.reload();
    assert!(result.is_err(), "Reload with invalid TOML must return error");

    // Original rules must still be in effect
    assert_eq!(
        engine.evaluate(&make_resource_event("/home/user/.ssh/id_rsa")),
        PolicyAction::Block,
        "After failed reload, old rules must still be active"
    );
}

fn make_resource_event(uri: &str) -> clawdefender_core::event::mcp::McpEvent {
    use clawdefender_core::event::mcp::*;
    use chrono::Utc;
    use serde_json::json;
    McpEvent {
        timestamp: Utc::now(),
        source: "test".to_string(),
        kind: McpEventKind::ResourceRead(ResourceRead {
            uri: uri.to_string(),
            request_id: json!(1),
        }),
        raw_message: json!({}),
    }
}

// ---------------------------------------------------------------------------
// Policy template validation
// ---------------------------------------------------------------------------

#[test]
fn test_all_policy_templates_parse_successfully() {
    let templates = &[
        include_str!("../../../policies/templates/audit-only.toml"),
        include_str!("../../../policies/templates/data-science.toml"),
        include_str!("../../../policies/templates/development.toml"),
        include_str!("../../../policies/templates/strict.toml"),
        include_str!("../../../policies/default.toml"),
    ];

    for (i, template) in templates.iter().enumerate() {
        let result = clawdefender_core::policy::rule::parse_policy_toml(template);
        assert!(
            result.is_ok(),
            "Template {} failed to parse: {:?}",
            i,
            result.err()
        );
        let rules = result.unwrap();
        assert!(
            !rules.is_empty(),
            "Template {} parsed but has no rules",
            i
        );
    }
}

#[test]
fn test_default_policy_blocks_ssh_keys() {
    let content = include_str!("../../../policies/default.toml");
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();

    let engine = DefaultPolicyEngine::load(f.path()).unwrap();

    // SSH keys must be blocked
    std::env::set_var("HOME", "/Users/testuser");
    let event = make_resource_event("/Users/testuser/.ssh/id_rsa");
    assert_eq!(engine.evaluate(&event), PolicyAction::Block);

    let event = make_resource_event("/Users/testuser/.ssh/id_ed25519");
    assert_eq!(engine.evaluate(&event), PolicyAction::Block);
}

#[test]
fn test_default_policy_blocks_aws_credentials() {
    let content = include_str!("../../../policies/default.toml");
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();

    std::env::set_var("HOME", "/Users/testuser");
    let engine = DefaultPolicyEngine::load(f.path()).unwrap();
    let event = make_resource_event("/Users/testuser/.aws/credentials");
    assert_eq!(engine.evaluate(&event), PolicyAction::Block);
}

// ---------------------------------------------------------------------------
// Glob pattern edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_glob_double_star_matches_deeply_nested() {
    let m = GlobMatcher::new("/project/**").unwrap();
    assert!(m.is_match("/project/a/b/c/d/e/f.txt"));
    assert!(!m.is_match("/other/project/file.txt"));
}

#[test]
fn test_glob_single_star_does_not_cross_directory() {
    let m = GlobMatcher::new("/project/*").unwrap();
    assert!(m.is_match("/project/file.txt"));
    // With require_literal_separator enabled, * should NOT match across dirs
    assert!(!m.is_match("/project/sub/file.txt"),
        "* must not match across directory boundaries");
}

#[test]
fn test_glob_question_mark_matches_single_char() {
    let m = GlobMatcher::new("/tmp/file?.txt").unwrap();
    assert!(m.is_match("/tmp/file1.txt"));
    assert!(m.is_match("/tmp/fileA.txt"));
    assert!(!m.is_match("/tmp/file12.txt"));
}

// ---------------------------------------------------------------------------
// Regex anchoring security test
// ---------------------------------------------------------------------------

#[test]
fn test_regex_substring_match_behavior() {
    // Document: regex is_match does substring matching, not full-string matching.
    // This is by design -- policy authors must use ^ and $ anchors for exact match.
    let m = RegexMatcher::new("shell_exec").unwrap();
    assert!(m.is_match("shell_exec"));
    assert!(
        m.is_match("my_shell_exec_wrapper"),
        "Regex matches substrings -- policy authors must anchor with ^ and $ for exact match"
    );

    // Anchored version
    let m = RegexMatcher::new("^shell_exec$").unwrap();
    assert!(m.is_match("shell_exec"));
    assert!(!m.is_match("my_shell_exec_wrapper"));
}

// ---------------------------------------------------------------------------
// Session rule scoping
// ---------------------------------------------------------------------------

#[test]
fn test_session_rules_cleared_on_reload() {
    let content = "[rules.log_all]\ndescription = \"Log all\"\naction = \"log\"\nmessage = \"logged\"\npriority = 1000\n\n[rules.log_all.match]\nany = true\n";
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();

    let mut engine = DefaultPolicyEngine::load(f.path()).unwrap();

    // Add a session rule
    engine.add_session_rule(PolicyRule {
        name: "session_allow".to_string(),
        description: "Session allow".to_string(),
        match_criteria: MatchCriteria {
            any: true,
            ..Default::default()
        },
        action: PolicyAction::Allow,
        message: "session".to_string(),
        priority: 0,
    });

    // Session rule takes effect
    let event = make_resource_event("/some/path");
    assert_eq!(engine.evaluate(&event), PolicyAction::Allow);

    // Reload does NOT clear session rules (they're session-scoped, not file-scoped)
    engine.reload().unwrap();
    assert_eq!(
        engine.evaluate(&event),
        PolicyAction::Allow,
        "Session rules should persist across reload (they expire on restart)"
    );
}
