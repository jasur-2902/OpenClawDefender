//! Audit trail for cloud API calls.
//!
//! Every cloud API call is logged with a SHA-256 hash of the prompt
//! (never the prompt itself) along with response metadata. This supports
//! post-incident forensics without leaking sensitive event data.

use sha2::{Digest, Sha256};

/// Audit record for a single cloud API call.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiCallAudit {
    /// Provider name (e.g. "Anthropic", "OpenAI").
    pub provider: String,
    /// Model identifier (e.g. "claude-sonnet-4-5-20250929").
    pub model: String,
    /// SHA-256 hex digest of the full prompt. Never the prompt itself.
    pub prompt_hash: String,
    /// Length of the response body in bytes.
    pub response_length: usize,
    /// Number of input tokens consumed.
    pub input_tokens: u32,
    /// Number of output tokens generated.
    pub output_tokens: u32,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u64,
    /// Validation flags triggered by output sanitization.
    pub validation_flags: Vec<String>,
}

/// Builder for constructing audit records.
pub struct AuditBuilder {
    provider: String,
    model: String,
    prompt: String,
    response_length: usize,
    input_tokens: u32,
    output_tokens: u32,
    latency_ms: u64,
    validation_flags: Vec<String>,
}

impl AuditBuilder {
    pub fn new(provider: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            prompt: String::new(),
            response_length: 0,
            input_tokens: 0,
            output_tokens: 0,
            latency_ms: 0,
            validation_flags: Vec::new(),
        }
    }

    /// Set the prompt to hash. The prompt content is hashed immediately
    /// and never stored in the audit record.
    pub fn prompt(mut self, prompt: &str) -> Self {
        self.prompt = prompt.to_string();
        self
    }

    pub fn response_length(mut self, len: usize) -> Self {
        self.response_length = len;
        self
    }

    pub fn tokens(mut self, input: u32, output: u32) -> Self {
        self.input_tokens = input;
        self.output_tokens = output;
        self
    }

    pub fn latency_ms(mut self, ms: u64) -> Self {
        self.latency_ms = ms;
        self
    }

    pub fn validation_flags(mut self, flags: Vec<String>) -> Self {
        self.validation_flags = flags;
        self
    }

    /// Build the audit record. The prompt is SHA-256-hashed here.
    pub fn build(self) -> ApiCallAudit {
        ApiCallAudit {
            provider: self.provider,
            model: self.model,
            prompt_hash: hash_prompt(&self.prompt),
            response_length: self.response_length,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            latency_ms: self.latency_ms,
            validation_flags: self.validation_flags,
        }
    }
}

/// Compute SHA-256 hex digest of a prompt string.
pub fn hash_prompt(prompt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prompt.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_is_sha256_hex() {
        let hash = hash_prompt("test prompt");
        // SHA-256 produces 32 bytes = 64 hex chars
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = hash_prompt("same input");
        let h2 = hash_prompt("same input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let h1 = hash_prompt("input A");
        let h2 = hash_prompt("input B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_audit_builder() {
        let prompt = "Analyze this MCP event for security risks";
        let audit = AuditBuilder::new("Anthropic", "claude-sonnet-4-5-20250929")
            .prompt(prompt)
            .response_length(350)
            .tokens(100, 80)
            .latency_ms(1200)
            .validation_flags(vec!["url_detected".into()])
            .build();

        assert_eq!(audit.provider, "Anthropic");
        assert_eq!(audit.model, "claude-sonnet-4-5-20250929");
        assert_eq!(audit.prompt_hash, hash_prompt(prompt));
        assert_eq!(audit.response_length, 350);
        assert_eq!(audit.input_tokens, 100);
        assert_eq!(audit.output_tokens, 80);
        assert_eq!(audit.latency_ms, 1200);
        assert_eq!(audit.validation_flags, vec!["url_detected"]);

        // Crucially: the prompt text itself is NOT in the audit record
        let json = serde_json::to_string(&audit).unwrap();
        assert!(!json.contains("Analyze this MCP event"));
    }
}
