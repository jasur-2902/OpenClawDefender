use clawdefender_scanner::finding::{
    calculate_cvss, cvss_to_string, fix_suggestion, AttackComplexity, AttackVector, CvssVector,
    Evidence, Finding, Impact, ModuleCategory, PrivilegesRequired, Reproduction, Scope, Severity,
    UserInteraction,
};
use clawdefender_scanner::progress::{ModuleStatus, ScanProgress};
use clawdefender_scanner::report;
use clawdefender_scanner::scanner::{
    compute_delta, correlate_findings, deduplicate_findings, exit_code_for_findings, ScanReport,
    ScanSummary, Scanner,
};

fn make_finding(
    id: &str,
    title: &str,
    severity: Severity,
    category: ModuleCategory,
    tool: Option<&str>,
) -> Finding {
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        severity,
        cvss: match severity {
            Severity::Critical => 9.8,
            Severity::High => 7.5,
            Severity::Medium => 5.0,
            Severity::Low => 3.0,
            Severity::Info => 0.0,
        },
        category,
        description: format!("Description for {title}"),
        reproduction: tool.map(|t| Reproduction {
            method: "MCP tool call".to_string(),
            tool: Some(t.to_string()),
            arguments: None,
        }),
        evidence: Evidence {
            messages: vec![0],
            audit_record: None,
            canary_detected: false,
            os_events: vec![],
            files_modified: vec![],
            network_connections: vec![],
            stderr_output: None,
        },
        remediation: "Fix it".to_string(),
    }
}

fn make_report(findings: Vec<Finding>) -> ScanReport {
    let summary = ScanSummary::from_findings(&findings);
    ScanReport {
        target: "test-server".to_string(),
        scan_date: chrono::Utc::now(),
        duration_secs: 10.0,
        findings,
        summary,
    }
}

// --- CVSS Calculation Tests ---

#[test]
fn test_cvss_path_traversal_credentials() {
    let vector = CvssVector::path_traversal_credentials();
    let score = calculate_cvss(&vector);
    assert!((score - 7.5).abs() < 0.1, "Expected ~7.5, got {score}");
}

#[test]
fn test_cvss_shell_injection() {
    let vector = CvssVector::shell_injection();
    let score = calculate_cvss(&vector);
    assert!((score - 9.8).abs() < 0.1, "Expected ~9.8, got {score}");
}

#[test]
fn test_cvss_prompt_injection_exfil() {
    let vector = CvssVector::prompt_injection_exfil();
    let score = calculate_cvss(&vector);
    assert!(score >= 9.0, "Expected >=9.0, got {score}");
}

#[test]
fn test_cvss_zero_impact() {
    let vector = CvssVector {
        attack_vector: AttackVector::Network,
        attack_complexity: AttackComplexity::Low,
        privileges_required: PrivilegesRequired::None,
        user_interaction: UserInteraction::None,
        scope: Scope::Unchanged,
        confidentiality: Impact::None,
        integrity: Impact::None,
        availability: Impact::None,
    };
    let score = calculate_cvss(&vector);
    assert_eq!(score, 0.0, "Zero impact should yield 0.0");
}

#[test]
fn test_cvss_to_string_format() {
    let vector = CvssVector::shell_injection();
    let s = cvss_to_string(&vector);
    assert_eq!(s, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
}

#[test]
fn test_cvss_to_string_path_traversal() {
    let vector = CvssVector::path_traversal_credentials();
    let s = cvss_to_string(&vector);
    assert_eq!(s, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
}

// --- Deduplication Tests ---

#[test]
fn test_deduplicate_keeps_highest_severity() {
    let findings = vec![
        make_finding(
            "F1",
            "Path issue",
            Severity::Medium,
            ModuleCategory::PathTraversal,
            Some("read_file"),
        ),
        make_finding(
            "F2",
            "Path issue critical",
            Severity::Critical,
            ModuleCategory::PathTraversal,
            Some("read_file"),
        ),
    ];
    let deduped = deduplicate_findings(findings);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].severity, Severity::Critical);
}

#[test]
fn test_deduplicate_different_tools_kept_separate() {
    let findings = vec![
        make_finding(
            "F1",
            "Issue A",
            Severity::High,
            ModuleCategory::PathTraversal,
            Some("read_file"),
        ),
        make_finding(
            "F2",
            "Issue B",
            Severity::High,
            ModuleCategory::PathTraversal,
            Some("write_file"),
        ),
    ];
    let deduped = deduplicate_findings(findings);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn test_deduplicate_merges_evidence() {
    let mut f1 = make_finding(
        "F1",
        "Issue",
        Severity::High,
        ModuleCategory::DataExfiltration,
        Some("fetch"),
    );
    f1.evidence.network_connections = vec!["tcp:443:evil.com".to_string()];

    let mut f2 = make_finding(
        "F2",
        "Issue variant",
        Severity::Medium,
        ModuleCategory::DataExfiltration,
        Some("fetch"),
    );
    f2.evidence.network_connections = vec!["tcp:80:bad.com".to_string()];

    let deduped = deduplicate_findings(vec![f1, f2]);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].evidence.network_connections.len(), 2);
}

// --- Correlation Tests ---

#[test]
fn test_correlate_adds_cross_references() {
    let mut f1 = make_finding(
        "F1",
        "Path traversal to creds",
        Severity::High,
        ModuleCategory::PathTraversal,
        Some("read_file"),
    );
    f1.evidence.files_modified = vec!["/etc/passwd".to_string()];

    let mut f2 = make_finding(
        "F2",
        "Exfil of creds",
        Severity::High,
        ModuleCategory::DataExfiltration,
        Some("fetch"),
    );
    f2.evidence.files_modified = vec!["/etc/passwd".to_string()];

    let mut findings = vec![f1, f2];
    correlate_findings(&mut findings);
    assert!(findings[0].description.contains("Cross-ref"));
    assert!(findings[1].description.contains("Cross-ref"));
}

// --- Baseline Delta Tests ---

#[test]
fn test_compute_delta_new_findings_only() {
    let baseline = make_report(vec![make_finding(
        "F1",
        "Known issue",
        Severity::High,
        ModuleCategory::PathTraversal,
        Some("read_file"),
    )]);

    let current = make_report(vec![
        make_finding(
            "F1",
            "Known issue",
            Severity::High,
            ModuleCategory::PathTraversal,
            Some("read_file"),
        ),
        make_finding(
            "F2",
            "New issue",
            Severity::Critical,
            ModuleCategory::PromptInjection,
            Some("prompt"),
        ),
    ]);

    let delta = compute_delta(&current, &baseline);
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].title, "New issue");
}

#[test]
fn test_compute_delta_empty_baseline() {
    let baseline = make_report(vec![]);
    let current = make_report(vec![
        make_finding(
            "F1",
            "Issue A",
            Severity::High,
            ModuleCategory::PathTraversal,
            Some("read_file"),
        ),
    ]);
    let delta = compute_delta(&current, &baseline);
    assert_eq!(delta.len(), 1);
}

// --- Exit Code Tests ---

#[test]
fn test_exit_code_no_findings() {
    let code = exit_code_for_findings(&[], None);
    assert_eq!(code, 0);
}

#[test]
fn test_exit_code_critical() {
    let findings = vec![make_finding(
        "F1",
        "Critical",
        Severity::Critical,
        ModuleCategory::PathTraversal,
        None,
    )];
    let code = exit_code_for_findings(&findings, None);
    assert_eq!(code, 1);
}

#[test]
fn test_exit_code_high_no_critical() {
    let findings = vec![make_finding(
        "F1",
        "High",
        Severity::High,
        ModuleCategory::PathTraversal,
        None,
    )];
    let code = exit_code_for_findings(&findings, None);
    assert_eq!(code, 2);
}

#[test]
fn test_exit_code_medium_with_threshold() {
    let findings = vec![make_finding(
        "F1",
        "Medium",
        Severity::Medium,
        ModuleCategory::PathTraversal,
        None,
    )];
    // Default threshold (High) => medium alone should be 0
    let code = exit_code_for_findings(&findings, None);
    assert_eq!(code, 0);
    // With medium threshold => should be non-zero
    let code = exit_code_for_findings(&findings, Some(&Severity::Medium));
    assert_eq!(code, 2);
}

// --- Module Listing ---

#[test]
fn test_default_modules_list() {
    let modules = Scanner::default_modules();
    assert_eq!(modules.len(), 6);
    let names: Vec<&str> = modules.iter().map(|m| m.name()).collect();
    assert!(names.contains(&"path-traversal"));
    assert!(names.contains(&"prompt-injection"));
    assert!(names.contains(&"exfiltration"));
    assert!(names.contains(&"capability-escalation"));
    assert!(names.contains(&"dependency-audit"));
    assert!(names.contains(&"fuzzing"));
}

// --- JSON Report Round-Trip ---

#[test]
fn test_json_report_roundtrip() {
    let report = make_report(vec![
        make_finding(
            "F1",
            "Path issue",
            Severity::High,
            ModuleCategory::PathTraversal,
            Some("read_file"),
        ),
        make_finding(
            "F2",
            "Injection",
            Severity::Critical,
            ModuleCategory::PromptInjection,
            Some("prompt"),
        ),
    ]);

    let json_str = report::render_json(&report).unwrap();
    let deserialized: ScanReport = serde_json::from_str(&json_str).unwrap();

    assert_eq!(deserialized.target, report.target);
    assert_eq!(deserialized.findings.len(), 2);
    assert_eq!(deserialized.summary.critical, 1);
    assert_eq!(deserialized.summary.high, 1);
}

// --- HTML Report ---

#[test]
fn test_html_report_contains_elements() {
    let report = make_report(vec![make_finding(
        "F1",
        "Test Finding",
        Severity::High,
        ModuleCategory::PathTraversal,
        Some("read_file"),
    )]);

    let html = report::render_html(&report);
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("ClawDefender Scan Report"));
    assert!(html.contains("Test Finding"));
    assert!(html.contains("summary-card"));
    assert!(html.contains("HIGH"));
}

// --- Fix Suggestions ---

#[test]
fn test_fix_suggestions_exist_for_all_categories() {
    let categories = [
        ModuleCategory::PathTraversal,
        ModuleCategory::PromptInjection,
        ModuleCategory::DataExfiltration,
        ModuleCategory::CapabilityEscalation,
        ModuleCategory::DependencyAudit,
        ModuleCategory::Fuzzing,
        ModuleCategory::Configuration,
    ];

    for cat in &categories {
        let suggestion = fix_suggestion(*cat, "test");
        assert!(
            suggestion.is_some(),
            "Missing fix suggestion for {:?}",
            cat
        );
        let text = suggestion.unwrap();
        assert!(!text.is_empty(), "Empty fix suggestion for {:?}", cat);
    }
}

#[test]
fn test_fix_suggestions_contain_code_examples() {
    let suggestion = fix_suggestion(ModuleCategory::PathTraversal, "traversal").unwrap();
    // Should contain both TypeScript and Python examples
    assert!(suggestion.contains("TypeScript") || suggestion.contains("typescript"));
    assert!(suggestion.contains("Python") || suggestion.contains("python"));
}

// --- Progress Display ---

#[test]
fn test_progress_render_with_timing() {
    let mut progress = ScanProgress::new(vec![
        "path-traversal".to_string(),
        "prompt-injection".to_string(),
    ]);

    let output = progress.render();
    assert!(output.contains("ClawDefender Security Scan"));
    assert!(output.contains("0%"));
    assert!(output.contains("pending"));

    progress.update_module("path-traversal", ModuleStatus::Running);
    let output = progress.render();
    assert!(output.contains("running"));

    progress.update_module(
        "path-traversal",
        ModuleStatus::Complete {
            findings: vec![make_finding(
                "F1",
                "Issue",
                Severity::High,
                ModuleCategory::PathTraversal,
                None,
            )],
        },
    );
    let output = progress.render();
    assert!(output.contains("50%"));
    assert!(output.contains("1 finding"));
}

// --- CVSS for_category ---

#[test]
fn test_cvss_for_category() {
    let v = CvssVector::for_category(ModuleCategory::PathTraversal, Severity::High);
    let score = calculate_cvss(&v);
    assert!(score > 5.0, "Path traversal should be > 5.0");

    let v2 = CvssVector::for_category(ModuleCategory::Configuration, Severity::Low);
    let score2 = calculate_cvss(&v2);
    assert!(score2 < 5.0, "Low config issue should be < 5.0");
}
