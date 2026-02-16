//! Pattern matching for policy rules against events.
//!
//! Provides concrete [`Matcher`](super::Matcher) implementations using glob
//! patterns, regular expressions, and exact string comparison.

use super::Matcher;
use crate::event::Event;
use anyhow::{Context, Result};

/// Matches event fields using glob patterns (e.g. `"fs_*"`, `"/tmp/**"`).
pub struct GlobMatcher {
    /// The glob pattern string (for display).
    pub pattern: String,
    /// Compiled glob pattern.
    compiled: glob::Pattern,
}

impl GlobMatcher {
    /// Create a new glob matcher. Supports `~` expansion to the user's home directory.
    pub fn new(pattern: &str) -> Result<Self> {
        let expanded = expand_tilde(pattern);
        let compiled = glob::Pattern::new(&expanded)
            .with_context(|| format!("invalid glob pattern: {pattern}"))?;
        Ok(Self {
            pattern: pattern.to_string(),
            compiled,
        })
    }

    /// Returns true if the given value matches this glob pattern.
    pub fn is_match(&self, value: &str) -> bool {
        let expanded_value = expand_tilde(value);
        self.compiled.matches(&expanded_value)
    }
}

impl Matcher for GlobMatcher {
    fn matches(&self, _event: &dyn Event) -> bool {
        // GlobMatcher is used internally via is_match on extracted fields,
        // not directly on events. This returns false by default.
        false
    }

    fn description(&self) -> &str {
        &self.pattern
    }
}

/// Matches event fields using regular expressions.
pub struct RegexMatcher {
    /// The regex pattern string (for display).
    pub pattern: String,
    /// Compiled regex.
    compiled: regex::Regex,
}

impl RegexMatcher {
    /// Create a new case-insensitive regex matcher.
    pub fn new(pattern: &str) -> Result<Self> {
        let compiled = regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .with_context(|| format!("invalid regex pattern: {pattern}"))?;
        Ok(Self {
            pattern: pattern.to_string(),
            compiled,
        })
    }

    /// Returns true if the given value matches this regex.
    pub fn is_match(&self, value: &str) -> bool {
        self.compiled.is_match(value)
    }
}

impl Matcher for RegexMatcher {
    fn matches(&self, _event: &dyn Event) -> bool {
        false
    }

    fn description(&self) -> &str {
        &self.pattern
    }
}

/// Matches event fields using exact string comparison.
pub struct ExactMatcher {
    /// The exact value to match against.
    pub value: String,
}

impl ExactMatcher {
    /// Create a new exact matcher.
    pub fn new(value: &str) -> Self {
        Self {
            value: value.to_string(),
        }
    }

    /// Returns true if the given value equals this matcher's value exactly.
    pub fn is_match(&self, value: &str) -> bool {
        self.value == value
    }
}

impl Matcher for ExactMatcher {
    fn matches(&self, _event: &dyn Event) -> bool {
        false
    }

    fn description(&self) -> &str {
        &self.value
    }
}

/// Expand `~` at the start of a path to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") || path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen('~', &home, 1);
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_simple() {
        let m = GlobMatcher::new("*.txt").unwrap();
        assert!(m.is_match("readme.txt"));
        assert!(!m.is_match("readme.md"));
    }

    #[test]
    fn glob_matches_path_wildcard() {
        let m = GlobMatcher::new("/tmp/**").unwrap();
        assert!(m.is_match("/tmp/foo/bar"));
        assert!(!m.is_match("/var/tmp/foo"));
    }

    #[test]
    fn glob_matches_tilde_expansion() {
        std::env::set_var("HOME", "/Users/testuser");
        let m = GlobMatcher::new("~/.ssh/id_*").unwrap();
        assert!(m.is_match("/Users/testuser/.ssh/id_rsa"));
        assert!(m.is_match("~/.ssh/id_ed25519"));
        assert!(!m.is_match("/Users/testuser/.ssh/config"));
    }

    #[test]
    fn glob_invalid_pattern() {
        let result = GlobMatcher::new("[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn regex_case_insensitive() {
        let m = RegexMatcher::new("^shell_exec$").unwrap();
        assert!(m.is_match("shell_exec"));
        assert!(m.is_match("SHELL_EXEC"));
        assert!(m.is_match("Shell_Exec"));
    }

    #[test]
    fn regex_special_chars() {
        let m = RegexMatcher::new(r"fs_\w+").unwrap();
        assert!(m.is_match("fs_read"));
        assert!(m.is_match("fs_write"));
        assert!(!m.is_match("network_read"));
    }

    #[test]
    fn regex_invalid_pattern() {
        let result = RegexMatcher::new("[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn exact_matches() {
        let m = ExactMatcher::new("tools/call");
        assert!(m.is_match("tools/call"));
        assert!(!m.is_match("tools/list"));
        assert!(!m.is_match("Tools/Call"));
    }
}
