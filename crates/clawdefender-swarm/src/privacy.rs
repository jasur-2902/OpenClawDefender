//! Privacy filter for redacting, sanitizing, and auditing all data before
//! it leaves the device to any cloud API.
//!
//! This module provides comprehensive data protection beyond what `data_minimizer`
//! does — it adds per-rule tracking, an outbound audit trail, anonymization mode,
//! and inbound response scanning.

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionRule {
    pub name: String,
    pub pattern: String,
    pub replacement: String,
    pub data_type: DataType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DataType {
    ApiKey,
    HomePath,
    InternalIp,
    Email,
    Hostname,
    EnvironmentVariable,
    Password,
    PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterResult {
    pub filtered_text: String,
    pub redaction_count: u32,
    pub redactions: Vec<RedactionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionEntry {
    pub rule_name: String,
    pub data_type: DataType,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionLog {
    pub timestamp: String,
    pub rule_name: String,
    pub redaction_count: u32,
    pub data_type: DataType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundAuditEntry {
    pub timestamp: String,
    pub session_id: String,
    pub provider: String,
    pub token_count_estimate: u32,
    pub payload_hash: String,
    pub redaction_summary: Vec<RedactionEntry>,
}

// ---------------------------------------------------------------------------
// Compiled rule (internal)
// ---------------------------------------------------------------------------

struct CompiledRule {
    name: String,
    regex: Regex,
    replacement: String,
    data_type: DataType,
}

// ---------------------------------------------------------------------------
// PrivacyFilter
// ---------------------------------------------------------------------------

pub struct PrivacyFilter {
    rules: Vec<CompiledRule>,
    anonymize_mode: bool,
    anonymize_map: Mutex<HashMap<String, String>>,
    anonymize_counter: Mutex<u32>,
    audit_trail: Mutex<Vec<OutboundAuditEntry>>,
}

impl PrivacyFilter {
    /// Create a new `PrivacyFilter` with default redaction rules and anonymize mode off.
    pub fn new() -> Self {
        Self::build(false)
    }

    /// Create a new `PrivacyFilter` with the given anonymize mode setting.
    pub fn with_anonymize(anonymize: bool) -> Self {
        Self::build(anonymize)
    }

    fn build(anonymize: bool) -> Self {
        let rules = Self::default_rules();
        let compiled: Vec<CompiledRule> = rules
            .into_iter()
            .map(|r| CompiledRule {
                name: r.name,
                regex: Regex::new(&r.pattern).expect("invalid default redaction regex"),
                replacement: r.replacement,
                data_type: r.data_type,
            })
            .collect();

        Self {
            rules: compiled,
            anonymize_mode: anonymize,
            anonymize_map: Mutex::new(HashMap::new()),
            anonymize_counter: Mutex::new(0),
            audit_trail: Mutex::new(Vec::new()),
        }
    }

    /// Built-in redaction rules.
    fn default_rules() -> Vec<RedactionRule> {
        let mut rules = vec![
            // --- API Keys / Tokens ---
            RedactionRule {
                name: "openai_api_key".into(),
                pattern: r"sk-[a-zA-Z0-9]{20,}".into(),
                replacement: "[REDACTED_API_KEY]".into(),
                data_type: DataType::ApiKey,
            },
            RedactionRule {
                name: "github_token".into(),
                pattern: r"ghp_[a-zA-Z0-9]{36,}".into(),
                replacement: "[REDACTED_GITHUB_TOKEN]".into(),
                data_type: DataType::ApiKey,
            },
            RedactionRule {
                name: "aws_key".into(),
                pattern: r"AKIA[A-Z0-9]{16}".into(),
                replacement: "[REDACTED_AWS_KEY]".into(),
                data_type: DataType::ApiKey,
            },
            RedactionRule {
                name: "bearer_token".into(),
                pattern: r"Bearer\s+[a-zA-Z0-9._\-]{20,}".into(),
                replacement: "Bearer [REDACTED_TOKEN]".into(),
                data_type: DataType::ApiKey,
            },
            RedactionRule {
                name: "generic_secret".into(),
                pattern:
                    r#"(?i)(key|token|password|secret|api_key|apikey|auth)\s*[=:]\s*["']?[^\s"'\[]{8,}"#
                        .into(),
                replacement: "$1=[REDACTED]".into(),
                data_type: DataType::Password,
            },
            // --- Private Key Material ---
            RedactionRule {
                name: "pem_private_key".into(),
                pattern: r"-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE KEY-----".into(),
                replacement: "[REDACTED_PRIVATE_KEY]".into(),
                data_type: DataType::PrivateKey,
            },
            RedactionRule {
                name: "openssh_private_key".into(),
                pattern: r"-----BEGIN\s+OPENSSH\s+PRIVATE KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE KEY-----".into(),
                replacement: "[REDACTED_PRIVATE_KEY]".into(),
                data_type: DataType::PrivateKey,
            },
            // --- Home Directory Paths ---
            RedactionRule {
                name: "macos_home_path".into(),
                pattern: r"/Users/[a-zA-Z0-9._-]+/".into(),
                replacement: "~/".into(),
                data_type: DataType::HomePath,
            },
            RedactionRule {
                name: "linux_home_path".into(),
                pattern: r"/home/[a-zA-Z0-9._-]+/".into(),
                replacement: "~/".into(),
                data_type: DataType::HomePath,
            },
            // --- Internal IPs ---
            RedactionRule {
                name: "internal_ip_192".into(),
                pattern: r"\b192\.168\.\d{1,3}\.\d{1,3}\b".into(),
                replacement: "[INTERNAL_IP]".into(),
                data_type: DataType::InternalIp,
            },
            RedactionRule {
                name: "internal_ip_10".into(),
                pattern: r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b".into(),
                replacement: "[INTERNAL_IP]".into(),
                data_type: DataType::InternalIp,
            },
            RedactionRule {
                name: "internal_ip_172".into(),
                pattern: r"\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b".into(),
                replacement: "[INTERNAL_IP]".into(),
                data_type: DataType::InternalIp,
            },
            // --- Email Addresses ---
            RedactionRule {
                name: "email_address".into(),
                pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".into(),
                replacement: "[EMAIL]".into(),
                data_type: DataType::Email,
            },
        ];

        // --- Machine Hostname ---
        // Detect system hostname at startup and add a rule for it.
        if let Ok(hostname) = hostname::get() {
            if let Some(hostname_str) = hostname.to_str() {
                if !hostname_str.is_empty() {
                    rules.push(RedactionRule {
                        name: "machine_hostname".into(),
                        pattern: regex::escape(hostname_str),
                        replacement: "[LOCAL_HOST]".into(),
                        data_type: DataType::Hostname,
                    });
                }
            }
        }

        rules
    }

    /// Apply all redaction rules to arbitrary text.
    pub fn filter_text(&self, text: &str) -> FilterResult {
        self.apply_rules(text)
    }

    /// Filter the system prompt / briefing before sending to the cloud.
    pub fn filter_briefing(&self, briefing: &str) -> FilterResult {
        self.apply_rules(briefing)
    }

    /// Filter tool execution output before sending to the cloud.
    pub fn filter_tool_result(&self, result: &str) -> FilterResult {
        self.apply_rules(result)
    }

    /// Filter an inbound response from the cloud (scan for echoed secrets).
    pub fn filter_response(&self, response: &str) -> FilterResult {
        self.apply_rules(response)
    }

    /// Core filtering engine — apply all compiled rules sequentially.
    fn apply_rules(&self, text: &str) -> FilterResult {
        let mut current = text.to_string();
        let mut redactions: Vec<RedactionEntry> = Vec::new();

        for rule in &self.rules {
            let matches: Vec<_> = rule.regex.find_iter(&current).collect();
            let count = matches.len() as u32;
            if count > 0 {
                current = rule
                    .regex
                    .replace_all(&current, rule.replacement.as_str())
                    .to_string();
                redactions.push(RedactionEntry {
                    rule_name: rule.name.clone(),
                    data_type: rule.data_type.clone(),
                    count,
                });
            }
        }

        let redaction_count = redactions.iter().map(|r| r.count).sum();

        FilterResult {
            filtered_text: current,
            redaction_count,
            redactions,
        }
    }

    /// Consistently map a name to an anonymized form within a session.
    ///
    /// The same input always produces the same output. The mapping is
    /// `prefix` + "_" + letter (A, B, C, ...).
    pub fn anonymize_name(&self, name: &str, prefix: &str) -> String {
        if !self.anonymize_mode {
            return name.to_string();
        }

        let key = format!("{}:{}", prefix, name);
        let mut map = self.anonymize_map.lock().unwrap();

        if let Some(existing) = map.get(&key) {
            return existing.clone();
        }

        let mut counter = self.anonymize_counter.lock().unwrap();
        let letter = (*counter as u8 + b'A') as char;
        *counter += 1;

        let anon = format!("{}_{}", prefix, letter);
        map.insert(key, anon.clone());
        anon
    }

    /// Record an outbound API call in the audit trail.
    pub fn log_outbound(
        &self,
        session_id: &str,
        provider: &str,
        payload: &str,
        token_estimate: u32,
    ) {
        let filter_result = self.filter_text(payload);

        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let entry = OutboundAuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
            provider: provider.to_string(),
            token_count_estimate: token_estimate,
            payload_hash: hash,
            redaction_summary: filter_result.redactions,
        };

        self.audit_trail.lock().unwrap().push(entry);
    }

    /// Return the full audit trail.
    pub fn get_audit_trail(&self) -> Vec<OutboundAuditEntry> {
        self.audit_trail.lock().unwrap().clone()
    }

    /// Aggregate redaction statistics by data type.
    pub fn get_redaction_stats(&self) -> HashMap<DataType, u32> {
        let trail = self.audit_trail.lock().unwrap();
        let mut stats: HashMap<DataType, u32> = HashMap::new();
        for entry in trail.iter() {
            for redaction in &entry.redaction_summary {
                *stats.entry(redaction.data_type.clone()).or_insert(0) += redaction.count;
            }
        }
        stats
    }
}

impl Default for PrivacyFilter {
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

    fn filter() -> PrivacyFilter {
        PrivacyFilter::new()
    }

    fn filter_anon() -> PrivacyFilter {
        PrivacyFilter::with_anonymize(true)
    }

    #[test]
    fn test_api_key_redaction() {
        let f = filter();
        let result = f.filter_text("My key is sk-abc12345678901234567890123");
        assert!(result.filtered_text.contains("[REDACTED_API_KEY]"));
        assert!(!result.filtered_text.contains("sk-abc"));
        assert!(result.redaction_count > 0);
    }

    #[test]
    fn test_github_token_redaction() {
        let f = filter();
        let token = format!("ghp_{}", "a".repeat(40));
        let result = f.filter_text(&format!("token: {}", token));
        assert!(result.filtered_text.contains("[REDACTED_GITHUB_TOKEN]"));
        assert!(!result.filtered_text.contains("ghp_"));
    }

    #[test]
    fn test_aws_key_redaction() {
        let f = filter();
        let result = f.filter_text("AKIAIOSFODNN7EXAMPLE1");
        assert!(result.filtered_text.contains("[REDACTED_AWS_KEY]"));
        assert!(!result.filtered_text.contains("AKIA"));
    }

    #[test]
    fn test_bearer_token_redaction() {
        let f = filter();
        let result = f.filter_text(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
        );
        assert!(result.filtered_text.contains("Bearer [REDACTED_TOKEN]"));
        assert!(!result.filtered_text.contains("eyJhbGci"));
    }

    #[test]
    fn test_home_path_redaction() {
        let f = filter();
        let result = f.filter_text("/Users/jasur/Documents/project/file.txt");
        assert!(result
            .filtered_text
            .contains("~/Documents/project/file.txt"));
        assert!(!result.filtered_text.contains("jasur"));
    }

    #[test]
    fn test_linux_home_path_redaction() {
        let f = filter();
        let result = f.filter_text("/home/deploy/app/config.yml");
        assert!(result.filtered_text.contains("~/app/config.yml"));
        assert!(!result.filtered_text.contains("deploy"));
    }

    #[test]
    fn test_internal_ip_redaction() {
        let f = filter();
        let result = f.filter_text("Connect to 192.168.1.100 on port 8080");
        assert!(result.filtered_text.contains("[INTERNAL_IP]"));
        assert!(!result.filtered_text.contains("192.168.1.100"));
    }

    #[test]
    fn test_internal_ip_10_redaction() {
        let f = filter();
        let result = f.filter_text("Server at 10.0.0.1");
        assert!(result.filtered_text.contains("[INTERNAL_IP]"));
        assert!(!result.filtered_text.contains("10.0.0.1"));
    }

    #[test]
    fn test_internal_ip_172_redaction() {
        let f = filter();
        let result = f.filter_text("Gateway: 172.16.0.1");
        assert!(result.filtered_text.contains("[INTERNAL_IP]"));
        assert!(!result.filtered_text.contains("172.16.0.1"));
    }

    #[test]
    fn test_external_ip_preserved() {
        let f = filter();
        let result = f.filter_text("External: 43.128.55.12");
        assert!(
            result.filtered_text.contains("43.128.55.12"),
            "External IP should NOT be redacted: {}",
            result.filtered_text
        );
    }

    #[test]
    fn test_email_redaction() {
        let f = filter();
        let result = f.filter_text("Contact user@example.com for details");
        assert!(result.filtered_text.contains("[EMAIL]"));
        assert!(!result.filtered_text.contains("user@example.com"));
    }

    #[test]
    fn test_private_key_redaction() {
        let f = filter();
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANB...\n-----END PRIVATE KEY-----";
        let result = f.filter_text(pem);
        assert!(result.filtered_text.contains("[REDACTED_PRIVATE_KEY]"));
        assert!(!result.filtered_text.contains("MIIEvQ"));
    }

    #[test]
    fn test_rsa_private_key_redaction() {
        let f = filter();
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBog...\n-----END RSA PRIVATE KEY-----";
        let result = f.filter_text(pem);
        assert!(result.filtered_text.contains("[REDACTED_PRIVATE_KEY]"));
    }

    #[test]
    fn test_openssh_private_key_redaction() {
        let f = filter();
        let pem =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz...\n-----END OPENSSH PRIVATE KEY-----";
        let result = f.filter_text(pem);
        assert!(result.filtered_text.contains("[REDACTED_PRIVATE_KEY]"));
    }

    #[test]
    fn test_password_in_config() {
        let f = filter();
        let result = f.filter_text("password=mysecret123 next");
        assert!(result.filtered_text.contains("[REDACTED]"));
        assert!(!result.filtered_text.contains("mysecret123"));
    }

    #[test]
    fn test_generic_secret_with_colon() {
        let f = filter();
        let result = f.filter_text("api_key: \"sk_live_abcdefgh12345678\"");
        assert!(result.filtered_text.contains("[REDACTED]"));
    }

    #[test]
    fn test_anonymize_mode_servers() {
        let f = filter_anon();
        let a1 = f.anonymize_name("FileManager", "Server");
        let a2 = f.anonymize_name("FileManager", "Server");
        let a3 = f.anonymize_name("NetworkGuard", "Server");

        assert_eq!(a1, a2, "Same input must map to same output");
        assert_ne!(a1, a3, "Different inputs must map to different outputs");
        assert!(a1.starts_with("Server_"));
        assert!(a3.starts_with("Server_"));
    }

    #[test]
    fn test_anonymize_mode_off() {
        let f = filter();
        let name = f.anonymize_name("FileManager", "Server");
        assert_eq!(name, "FileManager", "Anonymize off should preserve names");
    }

    #[test]
    fn test_anonymize_tools() {
        let f = filter_anon();
        let t1 = f.anonymize_name("query_events", "Tool");
        let t2 = f.anonymize_name("query_events", "Tool");
        assert_eq!(t1, t2);
        assert!(t1.starts_with("Tool_"));
    }

    #[test]
    fn test_filter_result_counts() {
        let f = filter();
        let text = "IPs: 192.168.1.1 and 10.0.0.1, email: a@b.com";
        let result = f.filter_text(text);
        // At least 3 redactions: 2 IPs + 1 email
        assert!(
            result.redaction_count >= 3,
            "Expected >= 3 redactions, got {}",
            result.redaction_count
        );
        assert!(!result.redactions.is_empty());
    }

    #[test]
    fn test_inbound_response_filtering() {
        let f = filter();
        let response = "Here is your key: sk-abc12345678901234567890123";
        let result = f.filter_response(response);
        assert!(result.filtered_text.contains("[REDACTED_API_KEY]"));
        assert!(!result.filtered_text.contains("sk-abc"));
    }

    #[test]
    fn test_no_false_positives_on_normal_text() {
        let f = filter();
        let text = "The system detected 5 suspicious file writes to the Documents folder. \
                    Process nginx (PID 1234) attempted to modify configuration files. \
                    Risk level is moderate.";
        let result = f.filter_text(text);
        assert_eq!(
            result.redaction_count, 0,
            "Normal text should have 0 redactions"
        );
        assert_eq!(result.filtered_text, text);
    }

    #[test]
    fn test_audit_trail_logging() {
        let f = filter();
        f.log_outbound("session-1", "anthropic", "Hello world", 10);
        f.log_outbound("session-1", "anthropic", "secret: password=hunter2!", 20);

        let trail = f.get_audit_trail();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail[0].session_id, "session-1");
        assert_eq!(trail[0].provider, "anthropic");
        assert_eq!(trail[0].token_count_estimate, 10);
        assert!(!trail[0].payload_hash.is_empty());
        // Second entry should have redactions
        assert!(!trail[1].redaction_summary.is_empty());
    }

    #[test]
    fn test_audit_trail_hash_is_sha256() {
        let f = filter();
        f.log_outbound("s1", "openai", "test payload", 5);
        let trail = f.get_audit_trail();
        // SHA-256 hex is 64 characters
        assert_eq!(trail[0].payload_hash.len(), 64);
    }

    #[test]
    fn test_redaction_stats() {
        let f = filter();
        f.log_outbound("s1", "anthropic", "192.168.1.1 and user@test.com", 10);
        let stats = f.get_redaction_stats();
        assert!(stats.contains_key(&DataType::InternalIp));
        assert!(stats.contains_key(&DataType::Email));
    }

    #[test]
    fn test_filter_briefing() {
        let f = filter();
        let briefing = "Analyze events from /Users/admin/logs/ on server 10.0.0.5";
        let result = f.filter_briefing(briefing);
        assert!(result.filtered_text.contains("~/logs/"));
        assert!(result.filtered_text.contains("[INTERNAL_IP]"));
    }

    #[test]
    fn test_filter_tool_result() {
        let f = filter();
        let tool_output = "Found config at /home/user/.ssh/id_rsa with password=abc12345678";
        let result = f.filter_tool_result(tool_output);
        assert!(result.filtered_text.contains("~/"));
        assert!(result.filtered_text.contains("[REDACTED]"));
    }

    #[test]
    fn test_multiple_redactions_same_type() {
        let f = filter();
        let text = "IPs: 192.168.1.1 192.168.1.2 192.168.1.3";
        let result = f.filter_text(text);
        let ip_entry = result
            .redactions
            .iter()
            .find(|r| r.data_type == DataType::InternalIp)
            .expect("should have IP redaction");
        assert_eq!(ip_entry.count, 3);
    }

    #[test]
    fn test_default_trait() {
        let f = PrivacyFilter::default();
        let result = f.filter_text("192.168.0.1");
        assert!(result.filtered_text.contains("[INTERNAL_IP]"));
    }
}
