use clawdefender_scanner::client::Direction;
use clawdefender_scanner::evidence::EvidenceCollector;
use clawdefender_scanner::finding::{Evidence, Finding, ModuleCategory, Reproduction, Severity};
use clawdefender_scanner::modules::capability_escalation::CapabilityEscalationModule;
use clawdefender_scanner::modules::dependency_audit::DependencyAuditModule;
use clawdefender_scanner::modules::exfiltration::ExfiltrationModule;
use clawdefender_scanner::modules::fuzzing::FuzzingModule;
use clawdefender_scanner::modules::path_traversal::PathTraversalModule;
use clawdefender_scanner::modules::prompt_injection::PromptInjectionModule;
use clawdefender_scanner::modules::ScanModule;
use clawdefender_scanner::progress::{ModuleStatus, ScanProgress};
use clawdefender_scanner::report;
use clawdefender_scanner::sandbox::{Sandbox, SandboxConfig};
use clawdefender_scanner::scanner::{ScanReport, ScanSummary};
use serde_json::json;

fn make_test_finding(severity: Severity, category: ModuleCategory) -> Finding {
    Finding {
        id: format!("{}-001", severity.finding_id_prefix()),
        title: format!("Test {} finding", severity),
        severity,
        cvss: match severity {
            Severity::Critical => 9.8,
            Severity::High => 7.5,
            Severity::Medium => 5.0,
            Severity::Low => 3.0,
            Severity::Info => 0.0,
        },
        category,
        description: "Test finding description".to_string(),
        reproduction: Some(Reproduction {
            method: "MCP tool call".to_string(),
            tool: Some("read_file".to_string()),
            arguments: Some(json!({"path": "../../etc/passwd"})),
        }),
        evidence: Evidence {
            messages: vec![0, 1],
            audit_record: None,
            canary_detected: severity == Severity::Critical,
            os_events: vec!["file_open /etc/passwd".to_string()],
            files_modified: vec![],
            network_connections: vec![],
            stderr_output: None,
        },
        remediation: "Fix the vulnerability".to_string(),
    }
}

fn make_test_report() -> ScanReport {
    let findings = vec![
        make_test_finding(Severity::Critical, ModuleCategory::PathTraversal),
        make_test_finding(Severity::High, ModuleCategory::PromptInjection),
        make_test_finding(Severity::Medium, ModuleCategory::DataExfiltration),
        make_test_finding(Severity::Low, ModuleCategory::Configuration),
        make_test_finding(Severity::Info, ModuleCategory::DependencyAudit),
    ];
    let summary = ScanSummary::from_findings(&findings);
    ScanReport {
        target: "test-server".to_string(),
        scan_date: chrono::Utc::now(),
        duration_secs: 42.5,
        findings,
        summary,
    }
}

// --- Sandbox tests ---

#[test]
fn test_sandbox_creation() {
    let sandbox = Sandbox::new(&SandboxConfig::default()).unwrap();
    let home = sandbox.home();
    assert!(home.join(".ssh/id_rsa").exists());
    assert!(home.join(".aws/credentials").exists());
    assert!(home.join(".gnupg/secring.gpg").exists());
    assert!(home.join(".bash_history").exists());
    assert!(home.join(".env").exists());
    assert!(home.join("Projects/test-project/package.json").exists());
    assert!(home.join("Projects/test-project/src/index.ts").exists());
    assert!(home.join("Projects/test-project/README.md").exists());
}

#[test]
fn test_sandbox_env_vars() {
    let sandbox = Sandbox::new(&SandboxConfig::default()).unwrap();
    let vars = sandbox.env_vars();
    assert!(vars.contains_key("HOME"));
    assert!(vars.contains_key("XDG_CONFIG_HOME"));
    assert!(vars.contains_key("XDG_DATA_HOME"));
    assert!(vars["HOME"].contains("home"));
}

#[test]
fn test_sandbox_canary_strings() {
    let sandbox = Sandbox::new(&SandboxConfig::default()).unwrap();
    let canaries = sandbox.canary_strings();
    assert!(canaries.len() >= 5);
    assert!(canaries.contains(&"CANARY_SSH_KEY_CONTENT_DO_NOT_EXFILTRATE"));
    assert!(canaries.contains(&"CANARY_AWS_ACCESS_KEY"));
    assert!(canaries.contains(&"CANARY_SECRET_TOKEN_VALUE"));
}

#[test]
fn test_sandbox_canary_detection_positive() {
    let sandbox = Sandbox::new(&SandboxConfig::default()).unwrap();
    let text = "The server returned CANARY_AWS_ACCESS_KEY in its response";
    let found = sandbox.check_canary(text);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0], "CANARY_AWS_ACCESS_KEY");
}

#[test]
fn test_sandbox_canary_detection_negative() {
    let sandbox = Sandbox::new(&SandboxConfig::default()).unwrap();
    let text = "This is a normal response with no sensitive data";
    let found = sandbox.check_canary(text);
    assert!(found.is_empty());
}

#[test]
fn test_sandbox_canary_detection_multiple() {
    let sandbox = Sandbox::new(&SandboxConfig::default()).unwrap();
    let text = "Found CANARY_AWS_ACCESS_KEY and CANARY_GPG_KEY_DO_NOT_EXFILTRATE";
    let found = sandbox.check_canary(text);
    assert_eq!(found.len(), 2);
}

#[test]
fn test_sandbox_file_contents() {
    let sandbox = Sandbox::new(&SandboxConfig::default()).unwrap();
    let ssh_key = std::fs::read_to_string(sandbox.home().join(".ssh/id_rsa")).unwrap();
    assert!(ssh_key.contains("BEGIN OPENSSH PRIVATE KEY"));
    assert!(ssh_key.contains("CANARY_SSH_KEY_CONTENT_DO_NOT_EXFILTRATE"));

    let env = std::fs::read_to_string(sandbox.home().join(".env")).unwrap();
    assert!(env.contains("CANARY_SECRET_TOKEN_VALUE"));
}

// --- Finding / Severity tests ---

#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn test_severity_display() {
    assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
    assert_eq!(format!("{}", Severity::High), "HIGH");
    assert_eq!(format!("{}", Severity::Medium), "MEDIUM");
    assert_eq!(format!("{}", Severity::Low), "LOW");
    assert_eq!(format!("{}", Severity::Info), "INFO");
}

#[test]
fn test_severity_id_prefix() {
    assert_eq!(Severity::Critical.finding_id_prefix(), "CRIT");
    assert_eq!(Severity::High.finding_id_prefix(), "HIGH");
    assert_eq!(Severity::Medium.finding_id_prefix(), "MED");
    assert_eq!(Severity::Low.finding_id_prefix(), "LOW");
    assert_eq!(Severity::Info.finding_id_prefix(), "INFO");
}

#[test]
fn test_severity_sort() {
    let mut severities = vec![
        Severity::Low,
        Severity::Critical,
        Severity::Info,
        Severity::High,
        Severity::Medium,
    ];
    severities.sort();
    assert_eq!(
        severities,
        vec![
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ]
    );
}

// --- Evidence tests ---

#[test]
fn test_evidence_collector_basic() {
    let mut collector = EvidenceCollector::new();
    collector.record_os_event("file_open /etc/passwd".to_string());
    collector.record_file_change("/tmp/test.txt".to_string());
    collector.record_network("tcp:443:evil.com".to_string());
    collector.record_stderr("warning: something".to_string());

    let evidence = collector.build_evidence(vec![0, 1, 2]);
    assert_eq!(evidence.messages, vec![0, 1, 2]);
    assert_eq!(evidence.os_events.len(), 1);
    assert_eq!(evidence.files_modified.len(), 1);
    assert_eq!(evidence.network_connections.len(), 1);
    assert!(evidence.stderr_output.is_some());
    assert!(!evidence.canary_detected);
}

#[test]
fn test_evidence_collector_canary() {
    let mut collector = EvidenceCollector::new();
    collector.record_canary_detection("CANARY_AWS_ACCESS_KEY".to_string());
    let evidence = collector.build_evidence(vec![]);
    assert!(evidence.canary_detected);
}

#[test]
fn test_evidence_check_canary_in_message() {
    let collector = EvidenceCollector::new();
    let msg = json!({
        "content": [{"type": "text", "text": "Here is CANARY_AWS_ACCESS_KEY for you"}]
    });
    let canaries = &["CANARY_AWS_ACCESS_KEY", "CANARY_SECRET_TOKEN_VALUE"];
    let found = collector.check_canary_in_message(&msg, canaries);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0], "CANARY_AWS_ACCESS_KEY");
}

#[test]
fn test_evidence_record_message() {
    let mut collector = EvidenceCollector::new();
    collector.record_message(Direction::Sent, json!({"method": "tools/call"}), 0);
    collector.record_message(Direction::Received, json!({"result": {}}), 1);
    let evidence = collector.build_evidence(vec![0, 1]);
    assert_eq!(evidence.messages, vec![0, 1]);
}

// --- Report tests ---

#[test]
fn test_render_terminal() {
    let report = make_test_report();
    let output = report::render_terminal(&report);
    assert!(output.contains("ClawDefender Security Scan Report"));
    assert!(output.contains("test-server"));
    assert!(output.contains("CRITICAL"));
    assert!(output.contains("CRIT-001"));
}

#[test]
fn test_render_json() {
    let report = make_test_report();
    let json_str = report::render_json(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["target"], "test-server");
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 5);
    assert_eq!(parsed["summary"]["critical"], 1);
}

#[test]
fn test_render_html() {
    let report = make_test_report();
    let html = report::render_html(&report);
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("ClawDefender Scan Report"));
    assert!(html.contains("CRIT-001"));
    assert!(html.contains("Canary data detected"));
}

// --- Progress tests ---

#[test]
fn test_progress_render() {
    let mut progress = ScanProgress::new(vec![
        "path-traversal".to_string(),
        "prompt-injection".to_string(),
        "exfiltration".to_string(),
    ]);
    let output = progress.render();
    assert!(output.contains("0/3"));
    assert!(output.contains("pending"));

    progress.update_module("path-traversal", ModuleStatus::Running);
    let output = progress.render();
    assert!(output.contains("running"));

    progress.update_module(
        "path-traversal",
        ModuleStatus::Complete {
            findings: vec![make_test_finding(
                Severity::High,
                ModuleCategory::PathTraversal,
            )],
        },
    );
    let output = progress.render();
    assert!(output.contains("1/3"));
    assert!(output.contains("1 finding"));
}

// --- Module stub tests ---

#[test]
fn test_path_traversal_module_metadata() {
    let m = PathTraversalModule::new();
    assert_eq!(m.name(), "path-traversal");
    assert_eq!(m.category(), ModuleCategory::PathTraversal);
    assert!(!m.description().is_empty());
}

#[test]
fn test_prompt_injection_module_metadata() {
    let m = PromptInjectionModule::new();
    assert_eq!(m.name(), "prompt-injection");
    assert_eq!(m.category(), ModuleCategory::PromptInjection);
}

#[test]
fn test_exfiltration_module_metadata() {
    let m = ExfiltrationModule::new();
    assert_eq!(m.name(), "exfiltration");
    assert_eq!(m.category(), ModuleCategory::DataExfiltration);
}

#[test]
fn test_capability_escalation_module_metadata() {
    let m = CapabilityEscalationModule::new();
    assert_eq!(m.name(), "capability-escalation");
    assert_eq!(m.category(), ModuleCategory::CapabilityEscalation);
}

#[test]
fn test_dependency_audit_module_metadata() {
    let m = DependencyAuditModule::new();
    assert_eq!(m.name(), "dependency-audit");
    assert_eq!(m.category(), ModuleCategory::DependencyAudit);
}

#[test]
fn test_fuzzing_module_metadata() {
    let m = FuzzingModule::new();
    assert_eq!(m.name(), "fuzzing");
    assert_eq!(m.category(), ModuleCategory::Fuzzing);
}

// --- ScanSummary tests ---

#[test]
fn test_scan_summary_from_findings() {
    let findings = vec![
        make_test_finding(Severity::Critical, ModuleCategory::PathTraversal),
        make_test_finding(Severity::Critical, ModuleCategory::DataExfiltration),
        make_test_finding(Severity::High, ModuleCategory::PromptInjection),
        make_test_finding(Severity::Low, ModuleCategory::Configuration),
    ];
    let summary = ScanSummary::from_findings(&findings);
    assert_eq!(summary.total, 4);
    assert_eq!(summary.critical, 2);
    assert_eq!(summary.high, 1);
    assert_eq!(summary.medium, 0);
    assert_eq!(summary.low, 1);
    assert_eq!(summary.info, 0);
}

#[test]
fn test_finding_serialization() {
    let finding = make_test_finding(Severity::High, ModuleCategory::PromptInjection);
    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.id, finding.id);
    assert_eq!(deserialized.severity, finding.severity);
    assert_eq!(deserialized.category, finding.category);
}
