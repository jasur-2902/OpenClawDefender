//! Pattern matching for policy rules against events.
//!
//! Provides concrete [`Matcher`](super::Matcher) implementations using glob
//! patterns, regular expressions, and exact string comparison.

use super::Matcher;
use crate::event::Event;
use anyhow::{anyhow, Context, Result};

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
    ///
    /// Uses `require_literal_separator` so that `*` only matches within a
    /// single directory, while `**` matches across directory boundaries.
    /// This prevents policy rules from being accidentally too broad.
    pub fn is_match(&self, value: &str) -> bool {
        let expanded_value = expand_tilde(value);
        let opts = glob::MatchOptions {
            require_literal_separator: true,
            ..Default::default()
        };
        self.compiled.matches_with(&expanded_value, opts)
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
    /// Maximum compiled regex size (256 KB) to prevent ReDoS via pathological patterns.
    const MAX_REGEX_SIZE: usize = 256 * 1024;

    /// Create a new case-insensitive regex matcher with size limits to prevent ReDoS.
    pub fn new(pattern: &str) -> Result<Self> {
        let compiled = regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .size_limit(Self::MAX_REGEX_SIZE)
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

/// Canonicalize a path for safe policy matching.
///
/// This function:
/// 1. Rejects paths containing null bytes
/// 2. Expands `~` to `$HOME`
/// 3. Attempts symlink resolution via `std::fs::canonicalize` (if the path exists)
/// 4. Resolves `.` and `..` segments (without requiring the file to exist)
/// 5. Normalizes path separators (collapses repeated `/`)
/// 6. Strips trailing slashes (except for root `/`)
pub fn canonicalize_path(path: &str) -> Result<String> {
    // 1. Reject null bytes
    if path.contains('\0') {
        return Err(anyhow!("Path contains null byte"));
    }

    // 2. Expand ~ to $HOME
    let expanded = expand_tilde(path);

    // 3. Try real filesystem canonicalization first (resolves symlinks).
    // If the path exists on disk, std::fs::canonicalize will resolve symlinks,
    // `.`, `..`, and produce an absolute path. This is critical for security:
    // a symlink at ~/Projects/innocent -> ~/.ssh/id_rsa must resolve to the
    // real target so policy rules can match it correctly.
    if let Ok(real_path) = std::fs::canonicalize(&expanded) {
        if let Some(s) = real_path.to_str() {
            return Ok(s.to_string());
        }
    }

    // 4. Fallback: resolve . and .. segments using a stack-based algorithm
    // (when the file does not exist, e.g. during policy pattern validation)
    let mut segments: Vec<&str> = Vec::new();
    let is_absolute = expanded.starts_with('/');

    for segment in expanded.split('/') {
        match segment {
            "" | "." => {
                // Skip empty segments (from repeated /) and current-dir markers
            }
            ".." => {
                if is_absolute {
                    // For absolute paths, never go above root
                    segments.pop();
                } else if segments.last().is_none_or(|s| *s == "..") {
                    segments.push("..");
                } else {
                    segments.pop();
                }
            }
            other => {
                segments.push(other);
            }
        }
    }

    // 5. Reconstruct the normalized path
    let normalized = if is_absolute {
        format!("/{}", segments.join("/"))
    } else if segments.is_empty() {
        ".".to_string()
    } else {
        segments.join("/")
    };

    // 6. Trailing slash is already stripped by the reconstruction above
    // (root "/" is preserved by the format! above)
    Ok(normalized)
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

    // --- canonicalize_path tests ---

    #[test]
    fn canonicalize_rejects_null_byte() {
        let result = canonicalize_path("/tmp/foo\0bar");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("null byte"));
    }

    #[test]
    fn canonicalize_resolves_dot_segments() {
        assert_eq!(canonicalize_path("/a/b/../c").unwrap(), "/a/c");
        assert_eq!(canonicalize_path("/a/./b/./c").unwrap(), "/a/b/c");
        assert_eq!(canonicalize_path("/a/b/../../c").unwrap(), "/c");
    }

    #[test]
    fn canonicalize_traversal_cannot_escape_root() {
        // On macOS, /etc is a symlink to /private/etc, so canonicalize_path
        // resolves to /private/etc/passwd when the path exists on disk.
        // When the path doesn't exist, the fallback logic resolves to /etc/passwd.
        let result = canonicalize_path("/a/../../../../etc/passwd").unwrap();
        assert!(
            result == "/etc/passwd" || result == "/private/etc/passwd",
            "expected /etc/passwd or /private/etc/passwd, got {result}"
        );

        let result = canonicalize_path("/../../../etc/passwd").unwrap();
        assert!(
            result == "/etc/passwd" || result == "/private/etc/passwd",
            "expected /etc/passwd or /private/etc/passwd, got {result}"
        );
    }

    #[test]
    fn canonicalize_collapses_repeated_slashes() {
        assert_eq!(canonicalize_path("/a///b//c").unwrap(), "/a/b/c");
    }

    #[test]
    fn canonicalize_strips_trailing_slash() {
        assert_eq!(canonicalize_path("/a/b/c/").unwrap(), "/a/b/c");
    }

    #[test]
    fn canonicalize_preserves_root() {
        assert_eq!(canonicalize_path("/").unwrap(), "/");
    }

    #[test]
    fn canonicalize_expands_tilde() {
        std::env::set_var("HOME", "/Users/testuser");
        assert_eq!(
            canonicalize_path("~/.ssh/id_rsa").unwrap(),
            "/Users/testuser/.ssh/id_rsa"
        );
    }

    #[test]
    fn canonicalize_relative_path() {
        assert_eq!(canonicalize_path("a/b/../c").unwrap(), "a/c");
    }

    #[test]
    fn canonicalize_empty_home_env() {
        // If HOME is unset, tilde stays as-is
        let old = std::env::var("HOME").ok();
        std::env::remove_var("HOME");
        let result = canonicalize_path("~/test");
        // Restore
        if let Some(h) = old {
            std::env::set_var("HOME", h);
        }
        // Should not error, just keep ~ literal
        assert!(result.is_ok());
    }
}
