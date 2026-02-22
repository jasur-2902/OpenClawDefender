//! Integration tests for the certification harness.

use clawdefender_certify::manifest::Manifest;
use clawdefender_certify::report::{CertificationReport, LevelReport, LevelResult, TestResult};

// ──────────────────────────────────────────────────────────────────────
// Manifest parser tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn parse_full_manifest() {
    let toml = r#"
[server]
name = "example-server"
version = "2.0.0"
description = "A fully-specified server"

[permissions]
required = [
    { action = "file_read", scope = "~/Projects/**", justification = "Read project files" },
    { action = "file_write", scope = "~/Projects/**", justification = "Write build artifacts" },
]
optional = [
    { action = "shell_execute", justification = "Run git commands" },
]

[risk_profile]
max_risk = "high"
declares_all_actions = true
supports_clawdefender = true
sdk_version = "0.5.0"
"#;
    let manifest = Manifest::parse(toml).unwrap();
    assert_eq!(manifest.server.name, "example-server");
    assert_eq!(manifest.server.version, "2.0.0");
    assert_eq!(manifest.permissions.required.len(), 2);
    assert_eq!(manifest.permissions.optional.len(), 1);
    assert_eq!(manifest.risk_profile.max_risk, "high");
    assert!(manifest.risk_profile.declares_all_actions);
    assert!(manifest.has_permissions());
}

#[test]
fn parse_minimal_manifest() {
    let toml = r#"
[server]
name = "bare-minimum"
version = "0.1.0"
"#;
    let manifest = Manifest::parse(toml).unwrap();
    assert_eq!(manifest.server.name, "bare-minimum");
    assert!(!manifest.has_permissions());
    // Default risk profile
    assert_eq!(manifest.risk_profile.max_risk, "medium");
    assert!(!manifest.risk_profile.supports_clawdefender);
}

#[test]
fn reject_empty_server_name() {
    let toml = r#"
[server]
name = ""
version = "1.0.0"
"#;
    assert!(Manifest::parse(toml).is_err());
}

#[test]
fn reject_empty_server_version() {
    let toml = r#"
[server]
name = "test"
version = ""
"#;
    assert!(Manifest::parse(toml).is_err());
}

#[test]
fn reject_invalid_risk_level() {
    let toml = r#"
[server]
name = "test"
version = "1.0.0"

[risk_profile]
max_risk = "critical"
"#;
    assert!(Manifest::parse(toml).is_err());
}

#[test]
fn reject_permission_without_justification() {
    let toml = r#"
[server]
name = "test"
version = "1.0.0"

[permissions]
required = [
    { action = "file_read", justification = "" },
]
"#;
    assert!(Manifest::parse(toml).is_err());
}

#[test]
fn reject_missing_server_section() {
    let toml = r#"
[permissions]
required = []
"#;
    assert!(Manifest::parse(toml).is_err());
}

#[test]
fn accept_all_risk_levels() {
    for level in &["low", "medium", "high"] {
        let toml = format!(
            r#"
[server]
name = "test"
version = "1.0.0"

[risk_profile]
max_risk = "{level}"
"#
        );
        assert!(
            Manifest::parse(&toml).is_ok(),
            "risk level '{level}' should be accepted"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────
// Report format tests
// ──────────────────────────────────────────────────────────────────────

fn make_test_report(l1_pass: bool, l2_pass: bool, l3_pass: bool) -> CertificationReport {
    let make_level = |name: &str, pass: bool| {
        LevelReport::from_tests(
            name,
            vec![
                TestResult {
                    name: "Test A".to_string(),
                    passed: pass,
                    message: if pass {
                        String::new()
                    } else {
                        "Failed".to_string()
                    },
                },
                TestResult {
                    name: "Test B".to_string(),
                    passed: true,
                    message: String::new(),
                },
            ],
        )
    };

    let level1 = make_level("Transparent", l1_pass);
    let level2 = make_level("Cooperative", l2_pass);
    let level3 = make_level("Proactive", l3_pass);

    let overall_level = if l3_pass {
        3
    } else if l2_pass {
        2
    } else if l1_pass {
        1
    } else {
        0
    };

    CertificationReport {
        server_name: "test-server".to_string(),
        timestamp: chrono::Utc::now(),
        tool_version: "0.1.0".to_string(),
        level1,
        level2,
        level3,
        overall_level,
    }
}

#[test]
fn report_text_contains_server_name() {
    let report = make_test_report(true, true, false);
    let text = report.to_text();
    assert!(text.contains("test-server"));
    assert!(text.contains("Level 2 Compliant"));
}

#[test]
fn report_text_level3_compliant() {
    let report = make_test_report(true, true, true);
    let text = report.to_text();
    assert!(text.contains("Level 3 Compliant"));
}

#[test]
fn report_text_not_compliant() {
    let report = make_test_report(false, false, false);
    let text = report.to_text();
    assert!(text.contains("Not Compliant"));
}

#[test]
fn report_json_roundtrip() {
    let report = make_test_report(true, false, false);
    let json_str = report.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["server_name"], "test-server");
    assert_eq!(parsed["overall_level"], 1);
    assert_eq!(parsed["level1"]["result"], "PASS");
}

#[test]
fn report_text_shows_pass_fail_markers() {
    let report = make_test_report(false, false, false);
    let text = report.to_text();
    assert!(text.contains("[PASS]"));
    assert!(text.contains("[FAIL]"));
}

// ──────────────────────────────────────────────────────────────────────
// LevelReport computation tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn level_result_all_pass() {
    let report = LevelReport::from_tests(
        "Test",
        vec![
            TestResult {
                name: "A".into(),
                passed: true,
                message: String::new(),
            },
            TestResult {
                name: "B".into(),
                passed: true,
                message: String::new(),
            },
        ],
    );
    assert_eq!(report.result, LevelResult::Pass);
}

#[test]
fn level_result_all_fail() {
    let report = LevelReport::from_tests(
        "Test",
        vec![
            TestResult {
                name: "A".into(),
                passed: false,
                message: "fail".into(),
            },
            TestResult {
                name: "B".into(),
                passed: false,
                message: "fail".into(),
            },
        ],
    );
    assert_eq!(report.result, LevelResult::Fail);
}

#[test]
fn level_result_partial() {
    let report = LevelReport::from_tests(
        "Test",
        vec![
            TestResult {
                name: "A".into(),
                passed: true,
                message: String::new(),
            },
            TestResult {
                name: "B".into(),
                passed: false,
                message: "fail".into(),
            },
            TestResult {
                name: "C".into(),
                passed: true,
                message: String::new(),
            },
        ],
    );
    assert_eq!(report.result, LevelResult::Partial);
}

#[test]
fn level_result_empty_is_pass() {
    // Edge case: no tests means all (0) passed
    let report = LevelReport::from_tests("Test", vec![]);
    assert_eq!(report.result, LevelResult::Pass);
}

// ──────────────────────────────────────────────────────────────────────
// Mock server certification tests (requires building mock-mcp-server)
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod mock_server_tests {
    use super::*;
    use clawdefender_certify::CertifyConfig;

    /// Helper to get mock server binary path (must be built first).
    fn mock_server_command() -> Option<Vec<String>> {
        // Try to find the built mock-mcp-server binary
        let possible_paths = [
            "../../target/debug/mock-mcp-server",
            "target/debug/mock-mcp-server",
        ];
        for path in &possible_paths {
            let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
            if full.exists() {
                return Some(vec![full.to_string_lossy().to_string()]);
            }
        }
        None
    }

    #[tokio::test]
    async fn mock_server_passes_level1() {
        let cmd = match mock_server_command() {
            Some(c) => c,
            None => {
                eprintln!("Skipping: mock-mcp-server not built. Run `cargo build -p mock-mcp-server` first.");
                return;
            }
        };

        let config = CertifyConfig {
            server_command: cmd,
            json: false,
            output: None,
            server_dir: None,
        };

        let report = clawdefender_certify::level1::run(&config).await.unwrap();
        assert_eq!(
            report.result,
            LevelResult::Pass,
            "Mock server should pass Level 1. Failures: {:?}",
            report
                .tests
                .iter()
                .filter(|t| !t.passed)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn mock_server_fails_level2() {
        let cmd = match mock_server_command() {
            Some(c) => c,
            None => {
                eprintln!("Skipping: mock-mcp-server not built.");
                return;
            }
        };

        let config = CertifyConfig {
            server_command: cmd,
            json: false,
            output: None,
            server_dir: None,
        };

        // The basic mock server has no SDK integration, so Level 2 should fail
        let report = clawdefender_certify::level2::run(&config).await.unwrap();
        assert_ne!(
            report.result,
            LevelResult::Pass,
            "Basic mock server should NOT pass Level 2 (no SDK)"
        );
    }

    #[tokio::test]
    async fn mock_server_fails_level3() {
        let cmd = match mock_server_command() {
            Some(c) => c,
            None => {
                eprintln!("Skipping: mock-mcp-server not built.");
                return;
            }
        };

        let config = CertifyConfig {
            server_command: cmd,
            json: false,
            output: None,
            server_dir: None,
        };

        // No manifest, so Level 3 should fail
        let report = clawdefender_certify::level3::run(&config).await.unwrap();
        assert_ne!(
            report.result,
            LevelResult::Pass,
            "Basic mock server should NOT pass Level 3 (no manifest)"
        );
    }
}
