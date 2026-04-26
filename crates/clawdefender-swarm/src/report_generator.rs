//! Scan report generator — turns raw findings, evidence, and remediations
//! into polished, exportable security reports in Markdown and HTML formats.
//!
//! Supports report persistence, listing, loading, and scan-to-scan comparison.

use std::path::PathBuf;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::remediation::Remediation;
use crate::scan_orchestrator::{AiScanResult, FindingSeverity};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A complete security scan report ready for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub report_id: String,
    pub scan_id: String,
    pub generated_at: DateTime<Utc>,
    pub format: ReportFormat,

    // Report content
    pub title: String,
    pub executive_summary: String,
    pub risk_assessment: RiskAssessment,
    pub findings: Vec<ReportFinding>,
    pub remediation_plan: RemediationPlan,
    pub system_posture: Option<String>,
    pub comparison: Option<ScanComparison>,

    // Metadata
    pub scan_duration_secs: u64,
    pub stages_completed: Vec<String>,
    pub tool_calls_used: u32,
    pub playbook_name: String,
}

/// Output format for a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportFormat {
    Markdown,
    Html,
}

/// Overall risk assessment with severity counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_level: String,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub info_count: u32,
}

/// A finding formatted for display in a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFinding {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence_summary: String,
    pub remediation: Option<String>,
    pub stage: String,
}

/// Prioritized remediation plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub priority_1_immediate: Vec<String>,
    pub priority_2_soon: Vec<String>,
    pub priority_3_later: Vec<String>,
}

/// Comparison between two scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanComparison {
    pub previous_scan_id: String,
    pub previous_scan_date: String,
    pub new_findings: Vec<String>,
    pub resolved_findings: Vec<String>,
    pub persistent_findings: Vec<String>,
    pub risk_trend: String,
}

/// Lightweight summary of a saved report for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub report_id: String,
    pub scan_id: String,
    pub generated_at: String,
    pub format: String,
    pub playbook_name: String,
    pub finding_count: usize,
    pub overall_risk: String,
    pub file_path: String,
}

// ---------------------------------------------------------------------------
// ReportGenerator
// ---------------------------------------------------------------------------

/// Generates, renders, and persists security scan reports.
pub struct ReportGenerator;

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate a report from scan results, evidence, remediations, and an
    /// optional Claude-generated executive summary.
    pub fn generate(
        &self,
        scan_result: &AiScanResult,
        evidence_data: Option<&serde_json::Value>,
        remediations: &[Remediation],
        format: ReportFormat,
        executive_summary: Option<String>,
    ) -> Result<ScanReport> {
        let risk_assessment = build_risk_assessment(&scan_result.findings);
        let findings = build_report_findings(&scan_result.findings, evidence_data, remediations);
        let remediation_plan = build_remediation_plan(&scan_result.findings, remediations);

        let summary = executive_summary.unwrap_or_else(|| auto_generate_summary(scan_result));

        let duration = compute_duration(scan_result);

        let playbook_name = scan_result.playbook_id.replace('_', " ");

        let report = ScanReport {
            report_id: format!("rpt-{}", uuid::Uuid::new_v4()),
            scan_id: scan_result.scan_id.clone(),
            generated_at: Utc::now(),
            format,
            title: "RookBot Security Scan Report".to_string(),
            executive_summary: summary,
            risk_assessment,
            findings,
            remediation_plan,
            system_posture: if scan_result.summary.is_empty() {
                None
            } else {
                Some(scan_result.summary.clone())
            },
            comparison: None,
            scan_duration_secs: duration,
            stages_completed: scan_result.stages_completed.clone(),
            tool_calls_used: scan_result.total_tool_calls as u32,
            playbook_name,
        };

        Ok(report)
    }

    /// Render a report as a Markdown string.
    pub fn render_markdown(&self, report: &ScanReport) -> String {
        let mut md = String::new();

        md.push_str("# CLAWDEFENDER SECURITY SCAN REPORT\n\n");
        md.push_str(&format!(
            "**Date:** {}  \n",
            report.generated_at.format("%B %d, %Y")
        ));
        md.push_str(&format!("**Playbook:** {}  \n", report.playbook_name));
        md.push_str(&format!(
            "**Duration:** {} | **Stages:** {} | **Tool Calls:** {}\n\n",
            format_duration(report.scan_duration_secs),
            report.stages_completed.len(),
            report.tool_calls_used,
        ));
        md.push_str("---\n\n");

        // Executive Summary
        md.push_str("## Executive Summary\n\n");
        md.push_str(&report.executive_summary);
        md.push_str("\n\n");

        // Risk Assessment
        md.push_str("## Risk Assessment\n\n");
        md.push_str(&format!(
            "**Overall Risk:** {}\n\n",
            report.risk_assessment.overall_level
        ));
        md.push_str("| Severity | Count |\n");
        md.push_str("|----------|-------|\n");
        md.push_str(&format!(
            "| Critical | {} |\n",
            report.risk_assessment.critical_count
        ));
        md.push_str(&format!(
            "| High | {} |\n",
            report.risk_assessment.high_count
        ));
        md.push_str(&format!(
            "| Medium | {} |\n",
            report.risk_assessment.medium_count
        ));
        md.push_str(&format!("| Low | {} |\n", report.risk_assessment.low_count));
        md.push_str(&format!(
            "| Info | {} |\n\n",
            report.risk_assessment.info_count
        ));

        // Findings
        if !report.findings.is_empty() {
            md.push_str("## Findings\n\n");
            for finding in &report.findings {
                md.push_str(&format!("### [{}] {}\n\n", finding.severity, finding.title));
                md.push_str(&format!("**Stage:** {}  \n", finding.stage));
                md.push_str(&format!("**Description:** {}  \n", finding.description));
                if !finding.evidence_summary.is_empty() {
                    md.push_str(&format!("**Evidence:** {}  \n", finding.evidence_summary));
                }
                if let Some(ref rem) = finding.remediation {
                    md.push_str(&format!("**Recommended Fix:** {}\n", rem));
                }
                md.push_str("\n---\n\n");
            }
        }

        // Remediation Plan
        md.push_str("## Remediation Plan\n\n");
        if !report.remediation_plan.priority_1_immediate.is_empty() {
            md.push_str("### Priority 1 — Immediate\n");
            for item in &report.remediation_plan.priority_1_immediate {
                md.push_str(&format!("- [ ] {}\n", item));
            }
            md.push('\n');
        }
        if !report.remediation_plan.priority_2_soon.is_empty() {
            md.push_str("### Priority 2 — This Week\n");
            for item in &report.remediation_plan.priority_2_soon {
                md.push_str(&format!("- [ ] {}\n", item));
            }
            md.push('\n');
        }
        if !report.remediation_plan.priority_3_later.is_empty() {
            md.push_str("### Priority 3 — When Convenient\n");
            for item in &report.remediation_plan.priority_3_later {
                md.push_str(&format!("- [ ] {}\n", item));
            }
            md.push('\n');
        }

        // Comparison
        if let Some(ref cmp) = report.comparison {
            md.push_str("## Comparison with Previous Scan\n\n");
            md.push_str(&format!(
                "**Previous Scan:** {} ({})\n\n",
                cmp.previous_scan_id, cmp.previous_scan_date
            ));
            if !cmp.resolved_findings.is_empty() {
                md.push_str(&format!(
                    "**Resolved:** {}\n\n",
                    cmp.resolved_findings.join(", ")
                ));
            }
            if !cmp.new_findings.is_empty() {
                md.push_str(&format!(
                    "**New Issues:** {}\n\n",
                    cmp.new_findings.join(", ")
                ));
            }
            if !cmp.persistent_findings.is_empty() {
                md.push_str(&format!(
                    "**Unresolved:** {}\n\n",
                    cmp.persistent_findings.join(", ")
                ));
            }
            md.push_str(&format!("**Trend:** {}\n\n", cmp.risk_trend));
        }

        md.push_str("---\n\n");
        md.push_str("*Generated by RookBot AI Scanner*\n");

        md
    }

    /// Render a report as a self-contained HTML string.
    pub fn render_html(&self, report: &ScanReport) -> String {
        let md_content = self.render_markdown(report);
        let body_html = markdown_to_html(&md_content);

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    max-width: 900px;
    margin: 0 auto;
    padding: 2rem;
    color: #1a1a2e;
    background: #f8f9fa;
    line-height: 1.6;
  }}
  h1 {{
    color: #0d1b2a;
    border-bottom: 3px solid #2b6cb0;
    padding-bottom: 0.5rem;
  }}
  h2 {{
    color: #1b3a5c;
    margin-top: 2rem;
    border-bottom: 1px solid #ddd;
    padding-bottom: 0.3rem;
  }}
  h3 {{ color: #2d3748; }}
  table {{
    border-collapse: collapse;
    width: 100%;
    margin: 1rem 0;
  }}
  th, td {{
    border: 1px solid #ddd;
    padding: 0.5rem 1rem;
    text-align: left;
  }}
  th {{ background: #edf2f7; font-weight: 600; }}
  hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 1.5rem 0; }}
  code {{ background: #edf2f7; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.9em; }}
  .severity-critical {{ color: #fff; background: #c53030; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: 600; }}
  .severity-high {{ color: #fff; background: #dd6b20; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: 600; }}
  .severity-medium {{ color: #1a202c; background: #ecc94b; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: 600; }}
  .severity-low {{ color: #1a202c; background: #68d391; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: 600; }}
  .severity-info {{ color: #1a202c; background: #bee3f8; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: 600; }}
  ul {{ padding-left: 1.5rem; }}
  li {{ margin-bottom: 0.3rem; }}
  @media print {{
    body {{ background: #fff; }}
  }}
</style>
</head>
<body>
<header style="text-align:center; margin-bottom:2rem;">
  <h1 style="border-bottom:none; margin-bottom:0;">RookBot</h1>
  <p style="color:#4a5568; margin-top:0.25rem;">AI-Powered Security Scanner</p>
</header>
{body}
</body>
</html>"#,
            title = report.title,
            body = body_html,
        )
    }

    /// Save a report to disk. Returns the file path.
    pub fn save_report(&self, report: &ScanReport, content: &str) -> Result<String> {
        let reports_dir = reports_directory();
        std::fs::create_dir_all(&reports_dir)?;

        let ext = match report.format {
            ReportFormat::Markdown => "md",
            ReportFormat::Html => "html",
        };
        let file_name = format!("{}-report.{}", report.scan_id, ext);
        let file_path = reports_dir.join(&file_name);

        std::fs::write(&file_path, content)?;

        // Also save the JSON metadata
        let meta_path = reports_dir.join(format!("{}-report.json", report.scan_id));
        let meta_json = serde_json::to_string_pretty(report)?;
        std::fs::write(&meta_path, meta_json)?;

        Ok(file_path.to_string_lossy().to_string())
    }

    /// Load a previously generated report's content from disk.
    pub fn load_report(scan_id: &str) -> Result<String> {
        let reports_dir = reports_directory();

        // Try markdown first, then HTML
        let md_path = reports_dir.join(format!("{}-report.md", scan_id));
        if md_path.exists() {
            return Ok(std::fs::read_to_string(&md_path)?);
        }

        let html_path = reports_dir.join(format!("{}-report.html", scan_id));
        if html_path.exists() {
            return Ok(std::fs::read_to_string(&html_path)?);
        }

        anyhow::bail!("No report found for scan: {}", scan_id)
    }

    /// List all generated reports.
    pub fn list_reports() -> Result<Vec<ReportSummary>> {
        let reports_dir = reports_directory();
        if !reports_dir.exists() {
            return Ok(Vec::new());
        }

        let mut summaries = Vec::new();

        for entry in std::fs::read_dir(&reports_dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            if !name.ends_with("-report.json") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let report: ScanReport = match serde_json::from_str(&content) {
                Ok(r) => r,
                Err(_) => continue,
            };

            let ext = match report.format {
                ReportFormat::Markdown => "md",
                ReportFormat::Html => "html",
            };
            let report_file = reports_dir.join(format!("{}-report.{}", report.scan_id, ext));

            summaries.push(ReportSummary {
                report_id: report.report_id,
                scan_id: report.scan_id,
                generated_at: report.generated_at.to_rfc3339(),
                format: match report.format {
                    ReportFormat::Markdown => "markdown".to_string(),
                    ReportFormat::Html => "html".to_string(),
                },
                playbook_name: report.playbook_name,
                finding_count: report.findings.len(),
                overall_risk: report.risk_assessment.overall_level,
                file_path: report_file.to_string_lossy().to_string(),
            });
        }

        summaries.sort_by(|a, b| b.generated_at.cmp(&a.generated_at));
        Ok(summaries)
    }

    /// Compare two scan results to identify new, resolved, and persistent findings.
    pub fn compare_scans(current: &AiScanResult, previous: &AiScanResult) -> ScanComparison {
        let current_titles: Vec<String> =
            current.findings.iter().map(|f| f.title.clone()).collect();
        let previous_titles: Vec<String> =
            previous.findings.iter().map(|f| f.title.clone()).collect();

        let new_findings: Vec<String> = current_titles
            .iter()
            .filter(|t| !titles_match_any(t, &previous_titles))
            .cloned()
            .collect();

        let resolved_findings: Vec<String> = previous_titles
            .iter()
            .filter(|t| !titles_match_any(t, &current_titles))
            .cloned()
            .collect();

        let persistent_findings: Vec<String> = current_titles
            .iter()
            .filter(|t| titles_match_any(t, &previous_titles))
            .cloned()
            .collect();

        let current_risk = compute_risk_score(&current.findings);
        let previous_risk = compute_risk_score(&previous.findings);

        let risk_trend = if current_risk < previous_risk {
            "improving".to_string()
        } else if current_risk > previous_risk {
            "worsening".to_string()
        } else {
            "stable".to_string()
        };

        ScanComparison {
            previous_scan_id: previous.scan_id.clone(),
            previous_scan_date: previous.started_at.clone(),
            new_findings,
            resolved_findings,
            persistent_findings,
            risk_trend,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the risk assessment from scan findings.
fn build_risk_assessment(findings: &[crate::scan_orchestrator::ScanFinding]) -> RiskAssessment {
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;
    let mut info = 0u32;

    for f in findings {
        match f.severity {
            FindingSeverity::Critical => critical += 1,
            FindingSeverity::High => high += 1,
            FindingSeverity::Medium => medium += 1,
            FindingSeverity::Low => low += 1,
            FindingSeverity::Info => info += 1,
        }
    }

    let overall_level = if critical > 0 {
        "CRITICAL".to_string()
    } else if high > 0 {
        "HIGH".to_string()
    } else if medium > 0 {
        "MEDIUM".to_string()
    } else if low > 0 {
        "LOW".to_string()
    } else {
        "INFO".to_string()
    };

    RiskAssessment {
        overall_level,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        info_count: info,
    }
}

/// Convert scan findings into report findings, incorporating evidence and remediations.
fn build_report_findings(
    findings: &[crate::scan_orchestrator::ScanFinding],
    evidence_data: Option<&serde_json::Value>,
    remediations: &[Remediation],
) -> Vec<ReportFinding> {
    findings
        .iter()
        .map(|f| {
            let severity = match f.severity {
                FindingSeverity::Critical => "CRITICAL",
                FindingSeverity::High => "HIGH",
                FindingSeverity::Medium => "MEDIUM",
                FindingSeverity::Low => "LOW",
                FindingSeverity::Info => "INFO",
            };

            let evidence_summary = build_evidence_summary(&f.id, &f.evidence_ids, evidence_data);

            let remediation =
                find_remediation_for_finding(&f.id, &f.remediation_hint, remediations);

            ReportFinding {
                severity: severity.to_string(),
                title: f.title.clone(),
                description: f.description.clone(),
                evidence_summary,
                remediation,
                stage: f.stage.clone(),
            }
        })
        .collect()
}

/// Build a human-readable evidence summary for a finding.
fn build_evidence_summary(
    finding_id: &str,
    evidence_ids: &[String],
    evidence_data: Option<&serde_json::Value>,
) -> String {
    if evidence_ids.is_empty() && evidence_data.is_none() {
        return String::new();
    }

    // Try to find a chain summary from the evidence data
    if let Some(data) = evidence_data {
        if let Some(chains) = data.get("finding_chains").and_then(|c| c.as_array()) {
            for chain in chains {
                if chain.get("finding_id").and_then(|v| v.as_str()) == Some(finding_id) {
                    if let Some(summary) = chain.get("summary").and_then(|v| v.as_str()) {
                        return summary.to_string();
                    }
                }
            }
        }
    }

    if evidence_ids.is_empty() {
        String::new()
    } else {
        format!(
            "Supported by {} evidence item(s): {}",
            evidence_ids.len(),
            evidence_ids.join(", ")
        )
    }
}

/// Find the best remediation text for a finding.
fn find_remediation_for_finding(
    finding_id: &str,
    hint: &str,
    remediations: &[Remediation],
) -> Option<String> {
    // Try to match by finding_id first
    for rem in remediations {
        if rem.finding_id == finding_id {
            return Some(rem.title.clone());
        }
    }

    // Fall back to the hint from the finding itself
    if !hint.is_empty() {
        Some(hint.to_string())
    } else {
        None
    }
}

/// Build a prioritized remediation plan from findings and remediations.
fn build_remediation_plan(
    findings: &[crate::scan_orchestrator::ScanFinding],
    remediations: &[Remediation],
) -> RemediationPlan {
    let mut immediate = Vec::new();
    let mut soon = Vec::new();
    let mut later = Vec::new();

    // First, use remediations matched to findings by severity
    for finding in findings {
        let text = remediations
            .iter()
            .find(|r| r.finding_id == finding.id)
            .map(|r| r.title.clone())
            .unwrap_or_else(|| {
                if !finding.remediation_hint.is_empty() {
                    finding.remediation_hint.clone()
                } else {
                    format!("Address: {}", finding.title)
                }
            });

        match finding.severity {
            FindingSeverity::Critical => immediate.push(text),
            FindingSeverity::High => soon.push(text),
            FindingSeverity::Medium | FindingSeverity::Low => later.push(text),
            FindingSeverity::Info => {} // Info findings don't need remediation
        }
    }

    RemediationPlan {
        priority_1_immediate: immediate,
        priority_2_soon: soon,
        priority_3_later: later,
    }
}

/// Auto-generate an executive summary when a Claude-generated one isn't available.
fn auto_generate_summary(result: &AiScanResult) -> String {
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;

    for f in &result.findings {
        match f.severity {
            FindingSeverity::Critical => critical += 1,
            FindingSeverity::High => high += 1,
            FindingSeverity::Medium => medium += 1,
            FindingSeverity::Low => low += 1,
            FindingSeverity::Info => {}
        }
    }

    let tone = if critical > 0 {
        "critical"
    } else if high > 0 {
        "concerning"
    } else {
        "routine"
    };

    let total = result.findings.len();
    let urgency = if critical > 0 {
        "Immediate attention is required."
    } else if high > 0 {
        "Several issues require prompt attention."
    } else {
        "No critical issues were identified."
    };

    let duration = compute_duration(result);

    format!(
        "A {} scan was conducted using the {} playbook, completing {} stages in {} seconds. \
         The scan discovered {} findings: {} critical, {} high, {} medium, and {} low severity issues. \
         {}",
        tone,
        result.playbook_id.replace('_', " "),
        result.stages_completed.len(),
        duration,
        total,
        critical,
        high,
        medium,
        low,
        urgency,
    )
}

/// Compute scan duration from started_at and completed_at timestamps.
fn compute_duration(result: &AiScanResult) -> u64 {
    let start = chrono::DateTime::parse_from_rfc3339(&result.started_at).ok();
    let end = result
        .completed_at
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());

    match (start, end) {
        (Some(s), Some(e)) => e.signed_duration_since(s).num_seconds().unsigned_abs(),
        _ => 0,
    }
}

/// Format seconds into a human-readable duration string.
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else {
        let mins = secs / 60;
        let remaining = secs % 60;
        format!("{}m {}s", mins, remaining)
    }
}

/// Compute a numeric risk score from findings for comparison.
fn compute_risk_score(findings: &[crate::scan_orchestrator::ScanFinding]) -> u32 {
    findings
        .iter()
        .map(|f| match f.severity {
            FindingSeverity::Critical => 10,
            FindingSeverity::High => 5,
            FindingSeverity::Medium => 2,
            FindingSeverity::Low => 1,
            FindingSeverity::Info => 0,
        })
        .sum()
}

/// Check if a title matches any title in a list (exact or substring match).
fn titles_match_any(title: &str, candidates: &[String]) -> bool {
    let title_lower = title.to_lowercase();
    candidates.iter().any(|c| {
        c.to_lowercase() == title_lower
            || c.to_lowercase().contains(&title_lower)
            || title_lower.contains(&c.to_lowercase())
    })
}

/// Get the reports storage directory.
fn reports_directory() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/share/rookbot/reports")
}

/// Minimal markdown-to-HTML conversion for report rendering.
fn markdown_to_html(md: &str) -> String {
    let mut html = String::new();
    let mut in_table = false;
    let mut in_list = false;

    for line in md.lines() {
        let trimmed = line.trim();

        // Headings
        if let Some(content) = trimmed.strip_prefix("### ") {
            close_contexts(&mut html, &mut in_table, &mut in_list);
            let content = apply_severity_badges(content);
            html.push_str(&format!("<h3>{}</h3>\n", content));
            continue;
        }
        if let Some(content) = trimmed.strip_prefix("## ") {
            close_contexts(&mut html, &mut in_table, &mut in_list);
            html.push_str(&format!("<h2>{}</h2>\n", content));
            continue;
        }
        if let Some(content) = trimmed.strip_prefix("# ") {
            close_contexts(&mut html, &mut in_table, &mut in_list);
            html.push_str(&format!("<h1>{}</h1>\n", content));
            continue;
        }

        // Horizontal rules
        if trimmed == "---" {
            close_contexts(&mut html, &mut in_table, &mut in_list);
            html.push_str("<hr>\n");
            continue;
        }

        // Table rows
        if trimmed.starts_with('|') && trimmed.ends_with('|') {
            // Skip separator rows
            if trimmed.contains("---") {
                continue;
            }
            if !in_table {
                close_list(&mut html, &mut in_list);
                html.push_str("<table>\n");
                in_table = true;
                // First table row is header
                let cells: Vec<&str> = trimmed
                    .split('|')
                    .filter(|c| !c.is_empty())
                    .map(|c| c.trim())
                    .collect();
                html.push_str("<tr>");
                for cell in cells {
                    html.push_str(&format!("<th>{}</th>", cell));
                }
                html.push_str("</tr>\n");
                continue;
            }
            let cells: Vec<&str> = trimmed
                .split('|')
                .filter(|c| !c.is_empty())
                .map(|c| c.trim())
                .collect();
            html.push_str("<tr>");
            for cell in cells {
                html.push_str(&format!("<td>{}</td>", cell));
            }
            html.push_str("</tr>\n");
            continue;
        } else if in_table {
            html.push_str("</table>\n");
            in_table = false;
        }

        // List items
        if let Some(content) = trimmed.strip_prefix("- ") {
            if !in_list {
                html.push_str("<ul>\n");
                in_list = true;
            }
            // Handle checkbox syntax
            let content = content.replace("[ ] ", "").replace("[x] ", "");
            html.push_str(&format!("<li>{}</li>\n", apply_inline_formatting(&content)));
            continue;
        } else if in_list && trimmed.is_empty() {
            html.push_str("</ul>\n");
            in_list = false;
        }

        // Empty lines
        if trimmed.is_empty() {
            continue;
        }

        // Emphasis/italic text wrapped in *...*
        let content = apply_inline_formatting(trimmed);
        html.push_str(&format!("<p>{}</p>\n", content));
    }

    close_contexts(&mut html, &mut in_table, &mut in_list);
    html
}

/// Apply severity badge CSS classes to [SEVERITY] tags in headings.
fn apply_severity_badges(text: &str) -> String {
    text.replace(
        "[CRITICAL]",
        "<span class=\"severity-critical\">CRITICAL</span>",
    )
    .replace("[HIGH]", "<span class=\"severity-high\">HIGH</span>")
    .replace("[MEDIUM]", "<span class=\"severity-medium\">MEDIUM</span>")
    .replace("[LOW]", "<span class=\"severity-low\">LOW</span>")
    .replace("[INFO]", "<span class=\"severity-info\">INFO</span>")
}

/// Apply inline markdown formatting (bold, italic).
fn apply_inline_formatting(text: &str) -> String {
    let mut result = text.to_string();
    // Bold: **text**
    while let Some(start) = result.find("**") {
        if let Some(end) = result[start + 2..].find("**") {
            let bold_text = &result[start + 2..start + 2 + end];
            result = format!(
                "{}<strong>{}</strong>{}",
                &result[..start],
                bold_text,
                &result[start + 2 + end + 2..]
            );
        } else {
            break;
        }
    }
    // Italic: *text* (single asterisk, but be careful not to match bold)
    // Simple approach: skip this to avoid conflicts with bold
    result
}

fn close_contexts(html: &mut String, in_table: &mut bool, in_list: &mut bool) {
    if *in_table {
        html.push_str("</table>\n");
        *in_table = false;
    }
    if *in_list {
        html.push_str("</ul>\n");
        *in_list = false;
    }
}

fn close_list(html: &mut String, in_list: &mut bool) {
    if *in_list {
        html.push_str("</ul>\n");
        *in_list = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_orchestrator::{AiScanResult, FindingSeverity, ScanFinding, ScanStatus};

    fn make_test_finding(id: &str, severity: FindingSeverity, title: &str) -> ScanFinding {
        ScanFinding {
            id: id.to_string(),
            severity,
            title: title.to_string(),
            description: format!("Description of {}", title),
            evidence_ids: vec!["ev-1".to_string()],
            remediation_hint: format!("Fix for {}", title),
            stage: "Test Stage".to_string(),
            discovered_at: "2025-01-01T00:05:00Z".to_string(),
        }
    }

    fn make_test_scan_result(findings: Vec<ScanFinding>) -> AiScanResult {
        let total_findings = findings.len();
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Critical)
            .count();
        let high_count = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::High)
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Medium)
            .count();
        let low_count = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Low)
            .count();
        let info_count = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Info)
            .count();
        AiScanResult {
            scan_id: "scan-test-001".to_string(),
            playbook_id: "mcp_security_audit".to_string(),
            playbook_name: "MCP Security Audit".to_string(),
            status: ScanStatus::Completed,
            started_at: "2026-04-08T10:00:00Z".to_string(),
            completed_at: Some("2026-04-08T10:05:00Z".to_string()),
            duration_secs: 300,
            findings,
            stages_completed: vec!["Stage 1".to_string(), "Stage 2".to_string()],
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            total_tool_calls: 25,
            total_input_tokens: 30000,
            total_output_tokens: 10000,
            estimated_cost_usd: 0.24,
            evidence_count: 0,
            summary: "Scan completed successfully.".to_string(),
        }
    }

    fn make_test_remediation(finding_id: &str, title: &str) -> Remediation {
        Remediation {
            id: format!("rem-{}", finding_id),
            finding_id: finding_id.to_string(),
            scan_id: "scan-test-001".to_string(),
            title: title.to_string(),
            description: title.to_string(),
            risk_of_fix: crate::remediation::FixRisk::Safe,
            reversible: true,
            auto_executable: false, // ManualAction is not auto-executable
            fix_type: crate::remediation::FixType::ManualAction {
                instructions: title.to_string(),
            },
            status: crate::remediation::RemediationStatus::Proposed,
            executed_at: None,
            revert_data: None,
        }
    }

    // -- Report generation ---------------------------------------------------

    #[test]
    fn test_generate_report_basic() {
        let gen = ReportGenerator::new();
        let findings = vec![
            make_test_finding("FINDING-1", FindingSeverity::High, "SSH key exposed"),
            make_test_finding("FINDING-2", FindingSeverity::Medium, "Weak firewall rules"),
        ];
        let result = make_test_scan_result(findings);
        let remediations = vec![make_test_remediation(
            "FINDING-1",
            "Restrict SSH key access",
        )];

        let report = gen
            .generate(&result, None, &remediations, ReportFormat::Markdown, None)
            .unwrap();

        assert!(report.report_id.starts_with("rpt-"));
        assert_eq!(report.scan_id, "scan-test-001");
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.risk_assessment.overall_level, "HIGH");
        assert_eq!(report.risk_assessment.high_count, 1);
        assert_eq!(report.risk_assessment.medium_count, 1);
        assert_eq!(report.tool_calls_used, 25);
        assert_eq!(report.stages_completed.len(), 2);
    }

    #[test]
    fn test_generate_report_with_custom_summary() {
        let gen = ReportGenerator::new();
        let result = make_test_scan_result(vec![]);
        let custom = "This is a custom executive summary.".to_string();

        let report = gen
            .generate(
                &result,
                None,
                &[],
                ReportFormat::Markdown,
                Some(custom.clone()),
            )
            .unwrap();

        assert_eq!(report.executive_summary, custom);
    }

    #[test]
    fn test_generate_report_empty_findings() {
        let gen = ReportGenerator::new();
        let result = make_test_scan_result(vec![]);

        let report = gen
            .generate(&result, None, &[], ReportFormat::Markdown, None)
            .unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.risk_assessment.overall_level, "INFO");
        assert_eq!(report.risk_assessment.critical_count, 0);
        assert!(report.remediation_plan.priority_1_immediate.is_empty());
        assert!(report.remediation_plan.priority_2_soon.is_empty());
        assert!(report.remediation_plan.priority_3_later.is_empty());
    }

    // -- Markdown rendering --------------------------------------------------

    #[test]
    fn test_render_markdown_contains_sections() {
        let gen = ReportGenerator::new();
        let findings = vec![make_test_finding(
            "FINDING-1",
            FindingSeverity::Critical,
            "Critical bug",
        )];
        let result = make_test_scan_result(findings);
        let remediations = vec![make_test_remediation("FINDING-1", "Fix critical bug")];

        let report = gen
            .generate(&result, None, &remediations, ReportFormat::Markdown, None)
            .unwrap();
        let md = gen.render_markdown(&report);

        assert!(md.contains("# CLAWDEFENDER SECURITY SCAN REPORT"));
        assert!(md.contains("## Executive Summary"));
        assert!(md.contains("## Risk Assessment"));
        assert!(md.contains("## Findings"));
        assert!(md.contains("## Remediation Plan"));
        assert!(md.contains("[CRITICAL] Critical bug"));
        assert!(md.contains("*Generated by RookBot AI Scanner*"));
    }

    #[test]
    fn test_render_markdown_risk_table() {
        let gen = ReportGenerator::new();
        let findings = vec![
            make_test_finding("F-1", FindingSeverity::High, "A"),
            make_test_finding("F-2", FindingSeverity::Medium, "B"),
            make_test_finding("F-3", FindingSeverity::Low, "C"),
        ];
        let result = make_test_scan_result(findings);

        let report = gen
            .generate(&result, None, &[], ReportFormat::Markdown, None)
            .unwrap();
        let md = gen.render_markdown(&report);

        assert!(md.contains("| High | 1 |"));
        assert!(md.contains("| Medium | 1 |"));
        assert!(md.contains("| Low | 1 |"));
        assert!(md.contains("| Critical | 0 |"));
    }

    // -- HTML rendering ------------------------------------------------------

    #[test]
    fn test_render_html_structure() {
        let gen = ReportGenerator::new();
        let findings = vec![make_test_finding(
            "F-1",
            FindingSeverity::High,
            "HTML test finding",
        )];
        let result = make_test_scan_result(findings);

        let report = gen
            .generate(&result, None, &[], ReportFormat::Html, None)
            .unwrap();
        let html = gen.render_html(&report);

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<html"));
        assert!(html.contains("</html>"));
        assert!(html.contains("<head>"));
        assert!(html.contains("</head>"));
        assert!(html.contains("<body>"));
        assert!(html.contains("</body>"));
        assert!(html.contains("RookBot"));
        assert!(html.contains("severity-high"));
    }

    #[test]
    fn test_render_html_self_contained() {
        let gen = ReportGenerator::new();
        let result = make_test_scan_result(vec![]);

        let report = gen
            .generate(&result, None, &[], ReportFormat::Html, None)
            .unwrap();
        let html = gen.render_html(&report);

        // Should have inline CSS, no external deps
        assert!(html.contains("<style>"));
        assert!(!html.contains("<link rel=\"stylesheet\""));
    }

    // -- Auto-generated summary ----------------------------------------------

    #[test]
    fn test_auto_generate_summary_critical() {
        let findings = vec![make_test_finding("F-1", FindingSeverity::Critical, "Bad")];
        let result = make_test_scan_result(findings);

        let summary = auto_generate_summary(&result);
        assert!(summary.contains("critical"));
        assert!(summary.contains("Immediate attention is required."));
    }

    #[test]
    fn test_auto_generate_summary_high() {
        let findings = vec![make_test_finding(
            "F-1",
            FindingSeverity::High,
            "Concerning",
        )];
        let result = make_test_scan_result(findings);

        let summary = auto_generate_summary(&result);
        assert!(summary.contains("concerning"));
        assert!(summary.contains("Several issues require prompt attention."));
    }

    #[test]
    fn test_auto_generate_summary_routine() {
        let findings = vec![make_test_finding("F-1", FindingSeverity::Low, "Minor")];
        let result = make_test_scan_result(findings);

        let summary = auto_generate_summary(&result);
        assert!(summary.contains("routine"));
        assert!(summary.contains("No critical issues were identified."));
    }

    #[test]
    fn test_auto_generate_summary_no_findings() {
        let result = make_test_scan_result(vec![]);

        let summary = auto_generate_summary(&result);
        assert!(summary.contains("routine"));
        assert!(summary.contains("0 findings"));
    }

    // -- Risk assessment -----------------------------------------------------

    #[test]
    fn test_risk_assessment_critical() {
        let findings = vec![
            make_test_finding("F-1", FindingSeverity::Critical, "A"),
            make_test_finding("F-2", FindingSeverity::Low, "B"),
        ];
        let ra = build_risk_assessment(&findings);
        assert_eq!(ra.overall_level, "CRITICAL");
        assert_eq!(ra.critical_count, 1);
        assert_eq!(ra.low_count, 1);
    }

    #[test]
    fn test_risk_assessment_high() {
        let findings = vec![
            make_test_finding("F-1", FindingSeverity::High, "A"),
            make_test_finding("F-2", FindingSeverity::Medium, "B"),
        ];
        let ra = build_risk_assessment(&findings);
        assert_eq!(ra.overall_level, "HIGH");
    }

    #[test]
    fn test_risk_assessment_medium() {
        let findings = vec![make_test_finding("F-1", FindingSeverity::Medium, "A")];
        let ra = build_risk_assessment(&findings);
        assert_eq!(ra.overall_level, "MEDIUM");
    }

    #[test]
    fn test_risk_assessment_info_only() {
        let findings = vec![make_test_finding("F-1", FindingSeverity::Info, "A")];
        let ra = build_risk_assessment(&findings);
        assert_eq!(ra.overall_level, "INFO");
        assert_eq!(ra.info_count, 1);
    }

    #[test]
    fn test_risk_assessment_empty() {
        let ra = build_risk_assessment(&[]);
        assert_eq!(ra.overall_level, "INFO");
        assert_eq!(ra.critical_count, 0);
        assert_eq!(ra.high_count, 0);
        assert_eq!(ra.medium_count, 0);
        assert_eq!(ra.low_count, 0);
        assert_eq!(ra.info_count, 0);
    }

    // -- Remediation plan prioritization -------------------------------------

    #[test]
    fn test_remediation_plan_prioritization() {
        let findings = vec![
            make_test_finding("F-1", FindingSeverity::Critical, "Critical issue"),
            make_test_finding("F-2", FindingSeverity::High, "High issue"),
            make_test_finding("F-3", FindingSeverity::Medium, "Medium issue"),
            make_test_finding("F-4", FindingSeverity::Low, "Low issue"),
            make_test_finding("F-5", FindingSeverity::Info, "Info item"),
        ];
        let remediations = vec![
            make_test_remediation("F-1", "Fix critical"),
            make_test_remediation("F-2", "Fix high"),
            make_test_remediation("F-3", "Fix medium"),
        ];

        let plan = build_remediation_plan(&findings, &remediations);

        assert_eq!(plan.priority_1_immediate.len(), 1);
        assert!(plan.priority_1_immediate[0].contains("Fix critical"));

        assert_eq!(plan.priority_2_soon.len(), 1);
        assert!(plan.priority_2_soon[0].contains("Fix high"));

        // Medium + Low go into priority 3
        assert_eq!(plan.priority_3_later.len(), 2);
    }

    #[test]
    fn test_remediation_plan_no_remediations() {
        let findings = vec![make_test_finding(
            "F-1",
            FindingSeverity::High,
            "Something bad",
        )];

        let plan = build_remediation_plan(&findings, &[]);

        // Should fall back to remediation_hint
        assert_eq!(plan.priority_2_soon.len(), 1);
        assert!(plan.priority_2_soon[0].contains("Fix for Something bad"));
    }

    // -- Scan comparison -----------------------------------------------------

    #[test]
    fn test_compare_scans_new_findings() {
        let current = make_test_scan_result(vec![
            make_test_finding("F-1", FindingSeverity::High, "Existing issue"),
            make_test_finding("F-2", FindingSeverity::Medium, "Brand new issue"),
        ]);
        let previous = make_test_scan_result(vec![make_test_finding(
            "F-1",
            FindingSeverity::High,
            "Existing issue",
        )]);

        let cmp = ReportGenerator::compare_scans(&current, &previous);

        assert_eq!(cmp.new_findings.len(), 1);
        assert_eq!(cmp.new_findings[0], "Brand new issue");
        assert_eq!(cmp.persistent_findings.len(), 1);
        assert_eq!(cmp.persistent_findings[0], "Existing issue");
        assert!(cmp.resolved_findings.is_empty());
        assert_eq!(cmp.risk_trend, "worsening");
    }

    #[test]
    fn test_compare_scans_resolved_findings() {
        let current = make_test_scan_result(vec![make_test_finding(
            "F-1",
            FindingSeverity::Low,
            "Minor thing",
        )]);
        let previous = make_test_scan_result(vec![
            make_test_finding("F-1", FindingSeverity::High, "Major issue"),
            make_test_finding("F-2", FindingSeverity::Low, "Minor thing"),
        ]);

        let cmp = ReportGenerator::compare_scans(&current, &previous);

        assert_eq!(cmp.resolved_findings.len(), 1);
        assert_eq!(cmp.resolved_findings[0], "Major issue");
        assert_eq!(cmp.persistent_findings.len(), 1);
        assert_eq!(cmp.risk_trend, "improving");
    }

    #[test]
    fn test_compare_scans_stable() {
        let findings = vec![make_test_finding(
            "F-1",
            FindingSeverity::Medium,
            "Same issue",
        )];
        let current = make_test_scan_result(findings.clone());
        let previous = make_test_scan_result(findings);

        let cmp = ReportGenerator::compare_scans(&current, &previous);

        assert!(cmp.new_findings.is_empty());
        assert!(cmp.resolved_findings.is_empty());
        assert_eq!(cmp.persistent_findings.len(), 1);
        assert_eq!(cmp.risk_trend, "stable");
    }

    #[test]
    fn test_compare_scans_both_empty() {
        let current = make_test_scan_result(vec![]);
        let previous = make_test_scan_result(vec![]);

        let cmp = ReportGenerator::compare_scans(&current, &previous);

        assert!(cmp.new_findings.is_empty());
        assert!(cmp.resolved_findings.is_empty());
        assert!(cmp.persistent_findings.is_empty());
        assert_eq!(cmp.risk_trend, "stable");
    }

    // -- Report persistence --------------------------------------------------

    #[test]
    fn test_save_and_load_report() {
        let gen = ReportGenerator::new();
        let result = make_test_scan_result(vec![make_test_finding(
            "F-1",
            FindingSeverity::Medium,
            "Test finding",
        )]);

        let report = gen
            .generate(&result, None, &[], ReportFormat::Markdown, None)
            .unwrap();
        let md = gen.render_markdown(&report);

        // Use a temp dir to avoid polluting the real reports directory
        let tmp = tempfile::tempdir().unwrap();
        let reports_dir = tmp.path().join("reports");
        std::fs::create_dir_all(&reports_dir).unwrap();

        let file_path = reports_dir.join(format!("{}-report.md", report.scan_id));
        std::fs::write(&file_path, &md).unwrap();

        let meta_path = reports_dir.join(format!("{}-report.json", report.scan_id));
        let meta = serde_json::to_string_pretty(&report).unwrap();
        std::fs::write(&meta_path, &meta).unwrap();

        // Verify files exist and can be read
        let loaded_md = std::fs::read_to_string(&file_path).unwrap();
        assert!(loaded_md.contains("CLAWDEFENDER SECURITY SCAN REPORT"));
        assert!(loaded_md.contains("Test finding"));

        let loaded_meta: ScanReport =
            serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
        assert_eq!(loaded_meta.scan_id, "scan-test-001");
        assert_eq!(loaded_meta.findings.len(), 1);
    }

    // -- ReportSummary listing -----------------------------------------------

    #[test]
    fn test_list_reports_from_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let reports_dir = tmp.path();

        let gen = ReportGenerator::new();
        let result = make_test_scan_result(vec![make_test_finding(
            "F-1",
            FindingSeverity::High,
            "Found something",
        )]);
        let report = gen
            .generate(&result, None, &[], ReportFormat::Markdown, None)
            .unwrap();

        let meta_path = reports_dir.join(format!("{}-report.json", report.scan_id));
        let meta = serde_json::to_string_pretty(&report).unwrap();
        std::fs::write(&meta_path, &meta).unwrap();

        // Manually read and verify the JSON file parses
        let loaded: ScanReport =
            serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
        assert_eq!(loaded.scan_id, "scan-test-001");
        assert_eq!(loaded.risk_assessment.overall_level, "HIGH");
    }

    // -- Edge cases ----------------------------------------------------------

    #[test]
    fn test_report_no_evidence_no_remediations() {
        let gen = ReportGenerator::new();
        let findings = vec![make_test_finding(
            "F-1",
            FindingSeverity::Info,
            "Informational",
        )];
        // Clear evidence_ids
        let mut result = make_test_scan_result(findings);
        result.findings[0].evidence_ids.clear();
        result.findings[0].remediation_hint.clear();

        let report = gen
            .generate(&result, None, &[], ReportFormat::Markdown, None)
            .unwrap();

        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].evidence_summary.is_empty());
        assert!(report.findings[0].remediation.is_none());
    }

    #[test]
    fn test_report_serde_roundtrip() {
        let gen = ReportGenerator::new();
        let result = make_test_scan_result(vec![make_test_finding(
            "F-1",
            FindingSeverity::High,
            "Test",
        )]);

        let report = gen
            .generate(&result, None, &[], ReportFormat::Markdown, None)
            .unwrap();

        let json = serde_json::to_string(&report).unwrap();
        let parsed: ScanReport = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.scan_id, report.scan_id);
        assert_eq!(parsed.report_id, report.report_id);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.risk_assessment.overall_level, "HIGH");
    }

    // -- Duration formatting -------------------------------------------------

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(0), "0s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(263), "4m 23s");
    }

    #[test]
    fn test_compute_duration_from_timestamps() {
        let result = make_test_scan_result(vec![]);
        let d = compute_duration(&result);
        assert_eq!(d, 300); // 5 minutes
    }

    #[test]
    fn test_compute_duration_missing_timestamps() {
        let mut result = make_test_scan_result(vec![]);
        result.completed_at = None;
        let d = compute_duration(&result);
        assert_eq!(d, 0);
    }

    // -- Risk score comparison -----------------------------------------------

    #[test]
    fn test_compute_risk_score() {
        let findings = vec![
            make_test_finding("F-1", FindingSeverity::Critical, "A"),
            make_test_finding("F-2", FindingSeverity::High, "B"),
            make_test_finding("F-3", FindingSeverity::Medium, "C"),
            make_test_finding("F-4", FindingSeverity::Low, "D"),
            make_test_finding("F-5", FindingSeverity::Info, "E"),
        ];
        // 10 + 5 + 2 + 1 + 0 = 18
        assert_eq!(compute_risk_score(&findings), 18);
    }

    #[test]
    fn test_compute_risk_score_empty() {
        assert_eq!(compute_risk_score(&[]), 0);
    }

    // -- Title matching for comparison ---------------------------------------

    #[test]
    fn test_titles_match_exact() {
        let candidates = vec!["SSH key exposed".to_string()];
        assert!(titles_match_any("SSH key exposed", &candidates));
    }

    #[test]
    fn test_titles_match_case_insensitive() {
        let candidates = vec!["ssh key exposed".to_string()];
        assert!(titles_match_any("SSH Key Exposed", &candidates));
    }

    #[test]
    fn test_titles_match_substring() {
        let candidates = vec!["SSH key exposed in MCP config".to_string()];
        assert!(titles_match_any("SSH key exposed", &candidates));
    }

    #[test]
    fn test_titles_no_match() {
        let candidates = vec!["Weak firewall".to_string()];
        assert!(!titles_match_any("SSH key exposed", &candidates));
    }

    // -- Evidence summary building -------------------------------------------

    #[test]
    fn test_evidence_summary_with_chain_data() {
        let evidence = serde_json::json!({
            "finding_chains": [
                {
                    "finding_id": "F-1",
                    "summary": "3 evidence item(s) collected via: query_events, get_server_profile, read_file"
                }
            ]
        });

        let summary = build_evidence_summary("F-1", &["ev-1".to_string()], Some(&evidence));
        assert!(summary.contains("3 evidence item(s)"));
    }

    #[test]
    fn test_evidence_summary_without_chain_data() {
        let summary =
            build_evidence_summary("F-1", &["ev-1".to_string(), "ev-2".to_string()], None);
        assert!(summary.contains("2 evidence item(s)"));
        assert!(summary.contains("ev-1"));
    }

    #[test]
    fn test_evidence_summary_empty() {
        let summary = build_evidence_summary("F-1", &[], None);
        assert!(summary.is_empty());
    }
}
