//! Data minimization for event data before cloud submission.
//!
//! Redacts sensitive information (home paths, private IPs, API keys,
//! environment secrets) so that only analysis-relevant metadata reaches
//! the cloud provider.

use regex::Regex;
use std::sync::LazyLock;

/// Maximum length for individual command arguments.
const MAX_ARG_LEN: usize = 200;

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

/// Matches home directory paths like /Users/username/ or /home/username/
static HOME_DIR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/(Users|home)/[A-Za-z0-9._-]+/").expect("home dir regex")
});

/// Matches RFC-1918 private IPv4 addresses.
static PRIVATE_IP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    )
    .expect("private IP regex")
});

/// Matches strings that look like API keys, tokens, or passwords.
/// Covers common prefixes (sk-, ghp_, xoxb-, Bearer ...) and generic
/// high-entropy hex/base64 strings of 20+ characters.
static SECRET_LIKE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:sk-[a-z0-9_-]{10,}|sk-ant-[a-z0-9_-]{10,}|ghp_[a-zA-Z0-9]{20,}|gho_[a-zA-Z0-9]{20,}|xox[bprs]-[a-zA-Z0-9-]{20,}|AKIA[A-Z0-9]{16}|Bearer\s+[A-Za-z0-9._~+/=-]{20,}|(?:api[_-]?key|token|password|secret|auth)\s*[=:]\s*\S{8,})",
    )
    .expect("secret regex")
});

/// Matches environment variable assignments that may contain secrets.
static ENV_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:API_KEY|TOKEN|SECRET|PASSWORD|AUTH|CREDENTIAL|PRIVATE_KEY)\s*=\s*\S+",
    )
    .expect("env secret regex")
});

/// Input event data to be minimized.
#[derive(Debug, Clone)]
pub struct SwarmEventData {
    pub tool_name: String,
    pub arguments: String,
    pub working_directory: String,
    pub description: String,
}

/// Minimized event data safe for cloud submission.
#[derive(Debug, Clone)]
pub struct MinimizedEventData {
    pub tool_name: String,
    pub arguments: String,
    pub working_directory: String,
    pub description: String,
}

pub struct DataMinimizer;

impl DataMinimizer {
    /// Redact sensitive data from event before cloud submission.
    pub fn minimize(event: &SwarmEventData) -> MinimizedEventData {
        MinimizedEventData {
            tool_name: event.tool_name.clone(),
            arguments: Self::redact_field(&Self::truncate(&event.arguments, MAX_ARG_LEN)),
            working_directory: Self::redact_field(&event.working_directory),
            description: Self::redact_field(&event.description),
        }
    }

    /// Apply all redaction rules to a string field.
    fn redact_field(input: &str) -> String {
        let s = HOME_DIR_RE.replace_all(input, "~/").to_string();
        let s = PRIVATE_IP_RE.replace_all(&s, "[PRIVATE_IP]").to_string();
        let s = SECRET_LIKE_RE.replace_all(&s, "[REDACTED]").to_string();
        ENV_SECRET_RE.replace_all(&s, "[REDACTED_ENV]").to_string()
    }

    /// Truncate a string to `max` bytes on a char boundary.
    fn truncate(s: &str, max: usize) -> String {
        if s.len() <= max {
            return s.to_string();
        }
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        let mut out = s[..end].to_string();
        out.push_str("...");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(args: &str) -> SwarmEventData {
        SwarmEventData {
            tool_name: "test".into(),
            arguments: args.into(),
            working_directory: "/Users/alice/project".into(),
            description: "test event".into(),
        }
    }

    #[test]
    fn test_home_path_redacted() {
        let e = make_event("read /Users/alice/secrets.txt");
        let m = DataMinimizer::minimize(&e);
        assert!(!m.arguments.contains("alice"));
        assert!(m.arguments.contains("~/"));
        assert!(!m.working_directory.contains("alice"));
    }

    #[test]
    fn test_private_ip_redacted() {
        let e = make_event("curl 192.168.1.100:8080");
        let m = DataMinimizer::minimize(&e);
        assert!(!m.arguments.contains("192.168.1.100"));
        assert!(m.arguments.contains("[PRIVATE_IP]"));
    }

    #[test]
    fn test_api_key_redacted() {
        let e = make_event("call --key sk-ant-api03-AAABBBCCCDDD1234567890abcdef");
        let m = DataMinimizer::minimize(&e);
        assert!(!m.arguments.contains("sk-ant-api03"));
        assert!(m.arguments.contains("[REDACTED]"));
    }

    #[test]
    fn test_env_secret_redacted() {
        let e = make_event("API_KEY=mysupersecretkey123");
        let m = DataMinimizer::minimize(&e);
        assert!(!m.arguments.contains("mysupersecretkey123"));
    }

    #[test]
    fn test_truncate_long_args() {
        let long_args = "x".repeat(500);
        let e = make_event(&long_args);
        let m = DataMinimizer::minimize(&e);
        assert!(m.arguments.len() <= MAX_ARG_LEN + 3); // +3 for "..."
    }

    #[test]
    fn test_tool_name_preserved() {
        let e = SwarmEventData {
            tool_name: "write_file".into(),
            arguments: "safe content".into(),
            working_directory: "/tmp".into(),
            description: "no secrets here".into(),
        };
        let m = DataMinimizer::minimize(&e);
        assert_eq!(m.tool_name, "write_file");
    }
}
