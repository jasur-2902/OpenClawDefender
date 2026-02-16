//! Security test suite for the cloud swarm hardening layer.
//!
//! These tests verify that data minimization, output sanitization, and
//! audit hashing work correctly to prevent data leakage, prompt injection,
//! and abuse in the cloud swarm pipeline.

use clawdefender_swarm::audit_hasher::{hash_prompt, AuditBuilder};
use clawdefender_swarm::data_minimizer::{DataMinimizer, SwarmEventData};
use clawdefender_swarm::output_sanitizer::{OutputSanitizer, SanitizedOutput};

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

fn event(args: &str) -> SwarmEventData {
    SwarmEventData {
        tool_name: "test_tool".into(),
        arguments: args.into(),
        working_directory: "/Users/testuser/projects/myapp".into(),
        description: "test event".into(),
    }
}

// =========================================================================
// 1. Data minimization: home path redacted
// =========================================================================

#[test]
fn data_min_home_path_redacted() {
    let e = event("read /Users/alice/Documents/secrets.txt");
    let m = DataMinimizer::minimize(&e);

    assert!(
        !m.arguments.contains("/Users/alice/"),
        "Home path must be redacted from arguments"
    );
    assert!(
        m.arguments.contains("~/"),
        "Home path should be replaced with ~/"
    );
    assert!(
        !m.working_directory.contains("/Users/testuser/"),
        "Home path must be redacted from working_directory"
    );
}

#[test]
fn data_min_linux_home_path_redacted() {
    let e = SwarmEventData {
        tool_name: "read".into(),
        arguments: "cat /home/bob/.ssh/id_rsa".into(),
        working_directory: "/home/bob/code".into(),
        description: "reading ssh key".into(),
    };
    let m = DataMinimizer::minimize(&e);

    assert!(!m.arguments.contains("/home/bob/"));
    assert!(!m.working_directory.contains("/home/bob/"));
}

// =========================================================================
// 2. Data minimization: API key-like strings stripped
// =========================================================================

#[test]
fn data_min_api_key_stripped() {
    let keys = [
        "sk-ant-api03-AAABBBCCCDDD1234567890abcdef",
        "sk-proj-AAABBBCCCDDD1234567890",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXyz",
        "AKIAIOSFODNN7EXAMPLE",
    ];

    for key in &keys {
        let e = event(&format!("call --key {}", key));
        let m = DataMinimizer::minimize(&e);
        assert!(
            !m.arguments.contains(key),
            "API key '{}' must be stripped from output, got: {}",
            key,
            m.arguments
        );
    }
}

#[test]
fn data_min_bearer_token_stripped() {
    let e = event("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature");
    let m = DataMinimizer::minimize(&e);
    assert!(
        !m.arguments.contains("eyJhbGciOiJ"),
        "Bearer token must be stripped"
    );
}

// =========================================================================
// 3. Data minimization: command args truncated to 200 chars
// =========================================================================

#[test]
fn data_min_args_truncated_to_200() {
    let long_arg = "a".repeat(500);
    let e = event(&long_arg);
    let m = DataMinimizer::minimize(&e);

    // 200 chars + "..." = 203 max
    assert!(
        m.arguments.len() <= 203,
        "Arguments must be truncated to ~200 chars, got {}",
        m.arguments.len()
    );
}

// =========================================================================
// 4. Output sanitizer: nonce echo detected and flagged
// =========================================================================

#[test]
fn output_san_nonce_echo_detected() {
    let nonce = "a1b2c3d4e5f6";
    let response = format!("The event looks safe. Token: {}", nonce);

    match OutputSanitizer::sanitize(&response, nonce) {
        SanitizedOutput::Flagged { reasons, .. } => {
            assert!(
                reasons.iter().any(|r| r.contains("nonce")),
                "Should flag nonce echo, got: {:?}",
                reasons
            );
        }
        SanitizedOutput::Clean(_) => panic!("Nonce echo must be flagged, not clean"),
    }
}

// =========================================================================
// 5. Output sanitizer: URL in response flagged
// =========================================================================

#[test]
fn output_san_url_flagged() {
    let response = "Check https://malicious-site.com/payload for details.";

    match OutputSanitizer::sanitize(response, "nonce123") {
        SanitizedOutput::Flagged { reasons, .. } => {
            assert!(
                reasons.iter().any(|r| r.contains("URL")),
                "Should flag URL, got: {:?}",
                reasons
            );
        }
        SanitizedOutput::Clean(_) => panic!("URL in response must be flagged"),
    }
}

#[test]
fn output_san_http_url_flagged() {
    let response = "See http://example.com/docs for more info.";
    match OutputSanitizer::sanitize(response, "x") {
        SanitizedOutput::Flagged { reasons, .. } => {
            assert!(reasons.iter().any(|r| r.contains("URL")));
        }
        SanitizedOutput::Clean(_) => panic!("HTTP URL must be flagged"),
    }
}

// =========================================================================
// 6. Output sanitizer: code block in response flagged
// =========================================================================

#[test]
fn output_san_code_block_flagged() {
    let response = "Try this fix:\n```bash\nrm -rf /\n```\nThat should work.";

    match OutputSanitizer::sanitize(response, "nonce") {
        SanitizedOutput::Flagged { reasons, .. } => {
            assert!(
                reasons.iter().any(|r| r.contains("code block")),
                "Should flag code block, got: {:?}",
                reasons
            );
        }
        SanitizedOutput::Clean(_) => panic!("Code block must be flagged"),
    }
}

// =========================================================================
// 7. Output sanitizer: response over 500 chars truncated
// =========================================================================

#[test]
fn output_san_long_response_truncated() {
    let response = "x".repeat(800);

    match OutputSanitizer::sanitize(&response, "nonce") {
        SanitizedOutput::Flagged { report, reasons } => {
            assert!(
                report.content.len() <= 500,
                "Response must be truncated to 500 chars, got {}",
                report.content.len()
            );
            assert!(
                reasons.iter().any(|r| r.contains("truncated")),
                "Should flag truncation, got: {:?}",
                reasons
            );
        }
        SanitizedOutput::Clean(_) => panic!("Over-length response must be flagged"),
    }
}

// =========================================================================
// 8. Audit hasher: prompt hash is SHA-256, not plaintext
// =========================================================================

#[test]
fn audit_hash_is_sha256_not_plaintext() {
    let prompt = "Analyze this MCP tool call for security risks: write_file /etc/passwd";
    let hash = hash_prompt(prompt);

    // SHA-256 = 64 hex chars
    assert_eq!(hash.len(), 64, "Hash must be 64 hex chars (SHA-256)");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "Hash must be valid hex"
    );
    // Must not contain the original prompt
    assert!(
        !hash.contains("Analyze"),
        "Hash must not contain plaintext prompt"
    );
    assert!(
        !hash.contains("write_file"),
        "Hash must not contain plaintext prompt"
    );
}

#[test]
fn audit_hash_is_deterministic() {
    let prompt = "same prompt content";
    assert_eq!(hash_prompt(prompt), hash_prompt(prompt));
}

// =========================================================================
// 9. API keys never appear in audit records
// =========================================================================

#[test]
fn audit_record_never_contains_api_key() {
    let prompt = "api_key=sk-ant-api03-SECRET123 Analyze event: tool call write_file";
    let audit = AuditBuilder::new("Anthropic", "claude-sonnet-4-5-20250929")
        .prompt(prompt)
        .response_length(200)
        .tokens(50, 40)
        .latency_ms(800)
        .build();

    let json = serde_json::to_string(&audit).unwrap();
    assert!(
        !json.contains("sk-ant-"),
        "Audit JSON must not contain API key prefix"
    );
    assert!(
        !json.contains("SECRET123"),
        "Audit JSON must not contain API key content"
    );
    assert!(
        !json.contains("write_file"),
        "Audit JSON must not contain prompt content"
    );
    // But it should contain the hash
    assert!(
        json.contains(&audit.prompt_hash),
        "Audit JSON must contain the prompt hash"
    );
}

// =========================================================================
// 10. Private IP addresses redacted
// =========================================================================

#[test]
fn data_min_private_ips_redacted() {
    let cases = [
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.100",
    ];

    for ip in &cases {
        let e = event(&format!("curl {}:8080/api", ip));
        let m = DataMinimizer::minimize(&e);
        assert!(
            !m.arguments.contains(ip),
            "Private IP {} must be redacted, got: {}",
            ip,
            m.arguments
        );
        assert!(m.arguments.contains("[PRIVATE_IP]"));
    }
}

// =========================================================================
// 11. Clean output passes through without flags
// =========================================================================

#[test]
fn output_san_clean_response_passes() {
    let response = "This tool call writes a config file. Risk is moderate due to path.";

    match OutputSanitizer::sanitize(response, "nonce123") {
        SanitizedOutput::Clean(report) => {
            assert_eq!(report.content, response);
        }
        SanitizedOutput::Flagged { reasons, .. } => {
            panic!("Clean response should not be flagged: {:?}", reasons);
        }
    }
}

// =========================================================================
// 12. Multiple flags can be triggered simultaneously
// =========================================================================

#[test]
fn output_san_multiple_flags_combined() {
    // This response has a URL AND is over 500 chars
    let response = format!(
        "Visit https://evil.com for details. {}",
        "x".repeat(500)
    );

    match OutputSanitizer::sanitize(&response, "nonce") {
        SanitizedOutput::Flagged { reasons, .. } => {
            assert!(
                reasons.len() >= 2,
                "Should have at least 2 flags (URL + length), got: {:?}",
                reasons
            );
        }
        SanitizedOutput::Clean(_) => panic!("Should be flagged"),
    }
}
