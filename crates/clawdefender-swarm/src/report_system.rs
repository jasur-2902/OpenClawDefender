//! Professional security report generation system for RookBot.
//!
//! Generates Daily Briefs, Weekly Reports, Incident Reports, Compliance Reports,
//! and Executive Summaries in Markdown and HTML formats. Supports report
//! persistence, listing, deletion, export, and history management.

use std::path::PathBuf;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Report types and formats
// ---------------------------------------------------------------------------

/// The kind of report to generate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportType {
    DailyBrief,
    WeeklyReport,
    IncidentReport,
    ComplianceReport,
    ExecutiveSummary,
}

impl ReportType {
    /// Short filesystem-safe label.
    fn label(&self) -> &str {
        match self {
            Self::DailyBrief => "daily_brief",
            Self::WeeklyReport => "weekly_report",
            Self::IncidentReport => "incident_report",
            Self::ComplianceReport => "compliance_report",
            Self::ExecutiveSummary => "executive_summary",
        }
    }

    /// Human-readable title for report headers.
    fn title(&self) -> &str {
        match self {
            Self::DailyBrief => "DAILY BRIEF",
            Self::WeeklyReport => "WEEKLY SECURITY REPORT",
            Self::IncidentReport => "INCIDENT REPORT",
            Self::ComplianceReport => "COMPLIANCE REPORT",
            Self::ExecutiveSummary => "EXECUTIVE SUMMARY",
        }
    }
}

/// Output format for a generated report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportFormat {
    Markdown,
    Html,
}

// ---------------------------------------------------------------------------
// Generated report metadata
// ---------------------------------------------------------------------------

/// Metadata for a generated report persisted on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedReport {
    pub id: Uuid,
    pub report_type: ReportType,
    pub generated_at: DateTime<Utc>,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    pub format: ReportFormat,
    pub file_path: String,
    pub summary: String,
    pub size_bytes: u64,
}

// ---------------------------------------------------------------------------
// Report data input structs
// ---------------------------------------------------------------------------

/// Data for a Daily Brief report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyBriefData {
    pub date: NaiveDate,
    pub events_total: u64,
    pub events_suspicious: u32,
    pub alerts_total: u32,
    pub blocked_count: u32,
    pub posture_changes: Vec<PostureChangeEntry>,
    pub defense_score: u32,
    pub highlights: Vec<String>,
    pub action_items: Vec<ActionItem>,
    pub agent_actions_taken: u32,
    pub agent_actions_suggested: u32,
}

/// A posture change entry recording a transition at a given time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureChangeEntry {
    pub time: String,
    pub from: String,
    pub to: String,
}

/// An action item with a priority level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionItem {
    pub description: String,
    pub priority: String,
}

/// Data for a Weekly Report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyReportData {
    pub week_start: NaiveDate,
    pub week_end: NaiveDate,
    pub total_events: u64,
    pub events_change_percent: f64,
    pub suspicious_count: u32,
    pub suspicious_change: i32,
    pub alerts_generated: u32,
    pub alerts_resolved: u32,
    pub alerts_investigating: u32,
    pub alerts_dismissed: u32,
    pub scans_completed: u32,
    pub scan_findings: String,
    pub investigations_count: u32,
    pub investigations_false_positive: u32,
    pub investigations_confirmed: u32,
    pub agent_actions: u32,
    pub daily_event_volumes: Vec<u64>,
    pub top_events: Vec<TopEvent>,
    pub server_health: Vec<ServerHealthEntry>,
    pub defense_score: u32,
    pub defense_score_change: i32,
    pub improvements: Vec<String>,
    pub gaps: Vec<String>,
    pub recommendations: Vec<String>,
    pub executive_summary: String,
    pub trend_narrative: String,
}

/// A notable event for the weekly top-events section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopEvent {
    pub description: String,
    pub severity: String,
    pub resolution: String,
}

/// Server health status entry for weekly reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHealthEntry {
    pub server_name: String,
    pub trust_level: String,
    pub anomaly_trend: String,
    pub drift_status: String,
    pub event_count: u64,
}

/// Data for an Incident Report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentReportData {
    pub incident_id: String,
    pub date: NaiveDate,
    pub severity: String,
    pub status: String,
    pub executive_summary: String,
    pub timeline: Vec<TimelineEntry>,
    pub root_cause: String,
    pub data_accessed: Vec<String>,
    pub data_modified: Vec<String>,
    pub data_exfiltrated: bool,
    pub affected_systems: Vec<String>,
    pub evidence_items: Vec<String>,
    pub response_actions: Vec<ResponseAction>,
    pub recommendations: Vec<String>,
    pub lessons_learned: String,
}

/// A timeline entry for incident reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub description: String,
    pub severity: String,
}

/// A response action taken during an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub timestamp: String,
    pub description: String,
}

/// Data for a Compliance Report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReportData {
    pub generated_at: DateTime<Utc>,
    pub control_areas: Vec<ControlArea>,
    pub overall_score: f64,
    pub summary: String,
}

/// A compliance control area with scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlArea {
    pub name: String,
    pub status: String,
    pub evidence: Vec<String>,
    pub gaps: Vec<String>,
    pub score: f64,
}

// ---------------------------------------------------------------------------
// ReportGenerator
// ---------------------------------------------------------------------------

/// Generates, manages, and persists professional security reports.
pub struct ReportGenerator {
    report_history: Vec<GeneratedReport>,
    reports_dir: PathBuf,
    max_reports: usize,
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator {
    /// Create a new `ReportGenerator` using the default reports directory.
    pub fn new() -> Self {
        Self {
            report_history: Vec::new(),
            reports_dir: default_reports_dir(),
            max_reports: 100,
        }
    }

    /// Create a `ReportGenerator` with a custom directory (useful for testing).
    pub fn with_dir(reports_dir: PathBuf) -> Self {
        Self {
            report_history: Vec::new(),
            reports_dir,
            max_reports: 100,
        }
    }

    // -- Generation methods --------------------------------------------------

    /// Generate a Daily Brief report.
    pub fn generate_daily_brief(
        &mut self,
        data: &DailyBriefData,
    ) -> Result<GeneratedReport, String> {
        let content = render_daily_brief(data);
        let summary = format!(
            "Daily brief for {}: {} events, {} alerts, score {}/100",
            data.date, data.events_total, data.alerts_total, data.defense_score,
        );
        self.persist_report(
            ReportType::DailyBrief,
            &content,
            &summary,
            Some(date_to_utc(data.date)),
            Some(date_to_utc(data.date)),
        )
    }

    /// Generate a Weekly Report.
    pub fn generate_weekly_report(
        &mut self,
        data: &WeeklyReportData,
    ) -> Result<GeneratedReport, String> {
        let content = render_weekly_report(data);
        let summary = format!(
            "Weekly report {} to {}: {} events, score {}/100",
            data.week_start, data.week_end, data.total_events, data.defense_score,
        );
        self.persist_report(
            ReportType::WeeklyReport,
            &content,
            &summary,
            Some(date_to_utc(data.week_start)),
            Some(date_to_utc(data.week_end)),
        )
    }

    /// Generate an Incident Report.
    pub fn generate_incident_report(
        &mut self,
        data: &IncidentReportData,
    ) -> Result<GeneratedReport, String> {
        let content = render_incident_report(data);
        let summary = format!(
            "Incident {} — {} ({})",
            data.incident_id, data.severity, data.status,
        );
        self.persist_report(
            ReportType::IncidentReport,
            &content,
            &summary,
            Some(date_to_utc(data.date)),
            Some(date_to_utc(data.date)),
        )
    }

    /// Generate a Compliance Report.
    pub fn generate_compliance_report(
        &mut self,
        data: &ComplianceReportData,
    ) -> Result<GeneratedReport, String> {
        let content = render_compliance_report(data);
        let summary = format!(
            "Compliance report — overall score {:.0}%",
            data.overall_score * 100.0,
        );
        self.persist_report(
            ReportType::ComplianceReport,
            &content,
            &summary,
            Some(data.generated_at),
            Some(data.generated_at),
        )
    }

    /// Generate an Executive Summary (condensed weekly report).
    pub fn generate_executive_summary(
        &mut self,
        data: &WeeklyReportData,
    ) -> Result<GeneratedReport, String> {
        let content = render_executive_summary(data);
        let summary = format!(
            "Executive summary {} to {}: score {}/100",
            data.week_start, data.week_end, data.defense_score,
        );
        self.persist_report(
            ReportType::ExecutiveSummary,
            &content,
            &summary,
            Some(date_to_utc(data.week_start)),
            Some(date_to_utc(data.week_end)),
        )
    }

    // -- Report management ---------------------------------------------------

    /// List reports, optionally filtered by type, returning up to `count`.
    pub fn list_reports(
        &self,
        report_type: Option<&ReportType>,
        count: usize,
    ) -> Vec<&GeneratedReport> {
        let mut filtered: Vec<&GeneratedReport> = self
            .report_history
            .iter()
            .filter(|r| report_type.is_none_or(|rt| r.report_type == *rt))
            .collect();
        filtered.sort_by(|a, b| b.generated_at.cmp(&a.generated_at));
        filtered.truncate(count);
        filtered
    }

    /// Get a report by ID.
    pub fn get_report(&self, id: Uuid) -> Option<&GeneratedReport> {
        self.report_history.iter().find(|r| r.id == id)
    }

    /// Read the file content of a report.
    pub fn get_report_content(&self, id: Uuid) -> Result<String, String> {
        let report = self
            .get_report(id)
            .ok_or_else(|| format!("Report not found: {}", id))?;
        std::fs::read_to_string(&report.file_path)
            .map_err(|e| format!("Failed to read report file: {}", e))
    }

    /// Delete a report (both the file and the history entry).
    pub fn delete_report(&mut self, id: Uuid) -> Result<(), String> {
        let idx = self
            .report_history
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| format!("Report not found: {}", id))?;
        let report = self.report_history.remove(idx);
        let path = std::path::Path::new(&report.file_path);
        if path.exists() {
            std::fs::remove_file(path)
                .map_err(|e| format!("Failed to delete report file: {}", e))?;
        }
        Ok(())
    }

    /// Export a report to a different format. Returns the new file path.
    pub fn export_report(&self, id: Uuid, format: ReportFormat) -> Result<String, String> {
        let report = self
            .get_report(id)
            .ok_or_else(|| format!("Report not found: {}", id))?;

        if report.format == format {
            return Ok(report.file_path.clone());
        }

        let content = std::fs::read_to_string(&report.file_path)
            .map_err(|e| format!("Failed to read report: {}", e))?;

        match format {
            ReportFormat::Html => {
                let html = to_html(&content, report.report_type.title());
                let html_path = report.file_path.replace(".md", ".html");
                std::fs::write(&html_path, &html)
                    .map_err(|e| format!("Failed to write HTML: {}", e))?;
                Ok(html_path)
            }
            ReportFormat::Markdown => {
                // Already markdown — just return the original path
                Ok(report.file_path.clone())
            }
        }
    }

    // -- History persistence -------------------------------------------------

    /// Save report history to `history.json`.
    pub fn save_history(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.reports_dir)
            .map_err(|e| format!("Failed to create reports dir: {}", e))?;
        let path = self.reports_dir.join("history.json");
        let json = serde_json::to_string_pretty(&self.report_history)
            .map_err(|e| format!("Failed to serialize history: {}", e))?;
        std::fs::write(&path, json).map_err(|e| format!("Failed to write history: {}", e))
    }

    /// Load report history from `history.json`.
    pub fn load_history(&mut self) -> Result<(), String> {
        let path = self.reports_dir.join("history.json");
        if !path.exists() {
            return Ok(());
        }
        let json =
            std::fs::read_to_string(&path).map_err(|e| format!("Failed to read history: {}", e))?;
        self.report_history =
            serde_json::from_str(&json).map_err(|e| format!("Failed to parse history: {}", e))?;
        Ok(())
    }

    /// Get the number of reports in history.
    pub fn report_count(&self) -> usize {
        self.report_history.len()
    }

    // -- Internal helpers ----------------------------------------------------

    /// Write report content to disk and record it in history.
    fn persist_report(
        &mut self,
        report_type: ReportType,
        content: &str,
        summary: &str,
        period_start: Option<DateTime<Utc>>,
        period_end: Option<DateTime<Utc>>,
    ) -> Result<GeneratedReport, String> {
        std::fs::create_dir_all(&self.reports_dir)
            .map_err(|e| format!("Failed to create reports dir: {}", e))?;

        let id = Uuid::new_v4();
        let now = Utc::now();
        let date_str = now.format("%Y%m%d").to_string();
        let short_id = &id.to_string()[..8];
        let file_name = format!("{}_{}_{}_.md", report_type.label(), date_str, short_id);
        let file_path = self.reports_dir.join(&file_name);

        std::fs::write(&file_path, content)
            .map_err(|e| format!("Failed to write report: {}", e))?;

        let size_bytes = content.len() as u64;

        let report = GeneratedReport {
            id,
            report_type,
            generated_at: now,
            period_start,
            period_end,
            format: ReportFormat::Markdown,
            file_path: file_path.to_string_lossy().to_string(),
            summary: summary.to_string(),
            size_bytes,
        };

        self.report_history.push(report.clone());
        self.enforce_max_reports();

        Ok(report)
    }

    /// Enforce the max_reports cap, deleting the oldest reports when exceeded.
    fn enforce_max_reports(&mut self) {
        while self.report_history.len() > self.max_reports {
            // Remove the oldest report
            let oldest = self.report_history.remove(0);
            let path = std::path::Path::new(&oldest.file_path);
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTML conversion
// ---------------------------------------------------------------------------

/// Convert a Markdown report to self-contained HTML with inline CSS.
pub fn to_html(markdown: &str, title: &str) -> String {
    let body = markdown_to_html_body(markdown);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RookBot — {title}</title>
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
  .status-met {{ color: #276749; font-weight: 600; }}
  .status-partial {{ color: #c05621; font-weight: 600; }}
  .status-not-met {{ color: #c53030; font-weight: 600; }}
  .severity-critical {{ color: #fff; background: #c53030; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: 600; }}
  .severity-high {{ color: #fff; background: #dd6b20; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: 600; }}
  .severity-medium {{ color: #1a202c; background: #ecc94b; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: 600; }}
  .severity-low {{ color: #1a202c; background: #68d391; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: 600; }}
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
  <p style="color:#4a5568; margin-top:0.25rem;">AI-Powered Security Platform</p>
</header>
{body}
</body>
</html>"#,
        title = title,
        body = body,
    )
}

// ---------------------------------------------------------------------------
// Markdown templates
// ---------------------------------------------------------------------------

fn render_daily_brief(data: &DailyBriefData) -> String {
    let status = if data.events_suspicious == 0 && data.alerts_total == 0 {
        ("GREEN", "All Clear")
    } else if data.events_suspicious > 5 || data.alerts_total > 3 {
        ("RED", "Elevated Threat Activity")
    } else {
        ("YELLOW", "Monitoring")
    };

    let mut md = String::new();
    md.push_str(&format!("# CLAWDEFENDER DAILY BRIEF — {}\n\n", data.date));
    md.push_str(&format!("**STATUS:** [{}] {}\n\n", status.0, status.1));

    // Today in Numbers
    md.push_str("## Today in Numbers\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!("| Events | {} |\n", data.events_total));
    md.push_str(&format!("| Suspicious | {} |\n", data.events_suspicious));
    md.push_str(&format!("| Alerts | {} |\n", data.alerts_total));
    md.push_str(&format!("| Blocked | {} |\n", data.blocked_count));
    md.push('\n');

    // Posture
    if data.posture_changes.is_empty() {
        md.push_str("**Posture:** No changes\n\n");
    } else {
        md.push_str("**Posture Changes:**\n\n");
        for pc in &data.posture_changes {
            md.push_str(&format!("- {} — {} -> {}\n", pc.time, pc.from, pc.to));
        }
        md.push('\n');
    }

    md.push_str(&format!(
        "**Defense Score:** {}/100\n\n",
        data.defense_score
    ));

    // Highlights
    md.push_str("## Highlights\n\n");
    if data.highlights.is_empty() {
        md.push_str("- No notable highlights today.\n\n");
    } else {
        for h in &data.highlights {
            md.push_str(&format!("- {}\n", h));
        }
        md.push('\n');
    }

    // Action Items
    md.push_str("## Action Items\n\n");
    if data.action_items.is_empty() {
        md.push_str("- No action items.\n\n");
    } else {
        for item in &data.action_items {
            md.push_str(&format!("- **[{}]** {}\n", item.priority, item.description));
        }
        md.push('\n');
    }

    // Agent Activity
    md.push_str("## Agent Activity\n\n");
    md.push_str(&format!("- Actions taken: {}\n", data.agent_actions_taken));
    md.push_str(&format!(
        "- Actions suggested: {}\n",
        data.agent_actions_suggested
    ));
    md.push('\n');
    md.push_str("---\n\n");
    md.push_str("*Generated by RookBot Report System*\n");

    md
}

fn render_weekly_report(data: &WeeklyReportData) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "# CLAWDEFENDER WEEKLY SECURITY REPORT\n\n**Period:** {} to {}\n\n",
        data.week_start, data.week_end,
    ));
    md.push_str("---\n\n");

    // Executive Summary
    md.push_str("## Executive Summary\n\n");
    md.push_str(&data.executive_summary);
    md.push_str("\n\n");

    // Key Metrics
    md.push_str("## Key Metrics\n\n");
    md.push_str("| Metric | Value | Change |\n");
    md.push_str("|--------|-------|--------|\n");
    md.push_str(&format!(
        "| Total Events | {} | {:.1}% |\n",
        data.total_events, data.events_change_percent,
    ));
    md.push_str(&format!(
        "| Suspicious Events | {} | {:+} |\n",
        data.suspicious_count, data.suspicious_change,
    ));
    md.push_str(&format!(
        "| Alerts Generated | {} | — |\n",
        data.alerts_generated,
    ));
    md.push_str(&format!(
        "| Alerts Resolved | {} | — |\n",
        data.alerts_resolved,
    ));
    md.push_str(&format!(
        "| Alerts Investigating | {} | — |\n",
        data.alerts_investigating,
    ));
    md.push_str(&format!(
        "| Alerts Dismissed | {} | — |\n",
        data.alerts_dismissed,
    ));
    md.push_str(&format!(
        "| Scans Completed | {} | — |\n",
        data.scans_completed,
    ));
    md.push_str(&format!("| Scan Findings | {} | — |\n", data.scan_findings,));
    md.push_str(&format!(
        "| Investigations | {} | — |\n",
        data.investigations_count,
    ));
    md.push_str(&format!("| Agent Actions | {} | — |\n", data.agent_actions,));
    md.push('\n');

    // Investigation Breakdown
    md.push_str("## Investigation Breakdown\n\n");
    md.push_str(&format!(
        "- Confirmed threats: {}\n",
        data.investigations_confirmed,
    ));
    md.push_str(&format!(
        "- False positives: {}\n",
        data.investigations_false_positive,
    ));
    md.push('\n');

    // Daily Event Volumes
    md.push_str("## Daily Event Volumes\n\n");
    let days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    md.push_str("| Day | Events |\n");
    md.push_str("|-----|--------|\n");
    for (i, vol) in data.daily_event_volumes.iter().enumerate() {
        let day_label = days.get(i).unwrap_or(&"—");
        md.push_str(&format!("| {} | {} |\n", day_label, vol));
    }
    md.push('\n');

    // Trend Analysis
    md.push_str("## Trend Analysis\n\n");
    md.push_str(&data.trend_narrative);
    md.push_str("\n\n");

    // Top Events
    if !data.top_events.is_empty() {
        md.push_str("## Top Events\n\n");
        md.push_str("| Event | Severity | Resolution |\n");
        md.push_str("|-------|----------|------------|\n");
        for ev in &data.top_events {
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                ev.description, ev.severity, ev.resolution,
            ));
        }
        md.push('\n');
    }

    // Server Health
    if !data.server_health.is_empty() {
        md.push_str("## Server Health\n\n");
        md.push_str("| Server | Trust | Anomaly Trend | Drift | Events |\n");
        md.push_str("|--------|-------|---------------|-------|--------|\n");
        for s in &data.server_health {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                s.server_name, s.trust_level, s.anomaly_trend, s.drift_status, s.event_count,
            ));
        }
        md.push('\n');
    }

    // Defense Posture
    md.push_str("## Defense Posture\n\n");
    md.push_str(&format!(
        "**Score:** {}/100 ({:+})\n\n",
        data.defense_score, data.defense_score_change,
    ));

    if !data.improvements.is_empty() {
        md.push_str("### Improvements\n\n");
        for item in &data.improvements {
            md.push_str(&format!("- {}\n", item));
        }
        md.push('\n');
    }

    if !data.gaps.is_empty() {
        md.push_str("### Gaps\n\n");
        for item in &data.gaps {
            md.push_str(&format!("- {}\n", item));
        }
        md.push('\n');
    }

    // Recommendations
    if !data.recommendations.is_empty() {
        md.push_str("## Recommendations\n\n");
        for (i, rec) in data.recommendations.iter().enumerate() {
            md.push_str(&format!("{}. {}\n", i + 1, rec));
        }
        md.push('\n');
    }

    md.push_str("---\n\n");
    md.push_str("*Generated by RookBot Report System*\n");

    md
}

fn render_incident_report(data: &IncidentReportData) -> String {
    let mut md = String::new();
    md.push_str("# CLAWDEFENDER INCIDENT REPORT\n\n");
    md.push_str(&format!("**Incident ID:** {}  \n", data.incident_id));
    md.push_str(&format!("**Date:** {}  \n", data.date));
    md.push_str(&format!("**Severity:** {}  \n", data.severity));
    md.push_str(&format!("**Status:** {}\n\n", data.status));
    md.push_str("---\n\n");

    // Executive Summary
    md.push_str("## Executive Summary\n\n");
    md.push_str(&data.executive_summary);
    md.push_str("\n\n");

    // Timeline
    md.push_str("## Timeline\n\n");
    if data.timeline.is_empty() {
        md.push_str("No timeline entries recorded.\n\n");
    } else {
        md.push_str("| Time | Event | Severity |\n");
        md.push_str("|------|-------|----------|\n");
        for entry in &data.timeline {
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                entry.timestamp, entry.description, entry.severity,
            ));
        }
        md.push('\n');
    }

    // Root Cause Analysis
    md.push_str("## Root Cause Analysis\n\n");
    md.push_str(&data.root_cause);
    md.push_str("\n\n");

    // Impact Assessment
    md.push_str("## Impact Assessment\n\n");
    md.push_str("### Data Impact\n\n");
    if !data.data_accessed.is_empty() {
        md.push_str("**Data Accessed:**\n\n");
        for item in &data.data_accessed {
            md.push_str(&format!("- {}\n", item));
        }
        md.push('\n');
    }
    if !data.data_modified.is_empty() {
        md.push_str("**Data Modified:**\n\n");
        for item in &data.data_modified {
            md.push_str(&format!("- {}\n", item));
        }
        md.push('\n');
    }
    md.push_str(&format!(
        "**Data Exfiltration:** {}\n\n",
        if data.data_exfiltrated { "Yes" } else { "No" },
    ));

    // Affected Systems
    if !data.affected_systems.is_empty() {
        md.push_str("### Affected Systems\n\n");
        for sys in &data.affected_systems {
            md.push_str(&format!("- {}\n", sys));
        }
        md.push('\n');
    }

    // Evidence Chain
    if !data.evidence_items.is_empty() {
        md.push_str("## Evidence Chain\n\n");
        for (i, ev) in data.evidence_items.iter().enumerate() {
            md.push_str(&format!("{}. {}\n", i + 1, ev));
        }
        md.push('\n');
    }

    // Response Actions
    if !data.response_actions.is_empty() {
        md.push_str("## Response Actions\n\n");
        md.push_str("| Time | Action |\n");
        md.push_str("|------|--------|\n");
        for action in &data.response_actions {
            md.push_str(&format!(
                "| {} | {} |\n",
                action.timestamp, action.description,
            ));
        }
        md.push('\n');
    }

    // Recommendations
    if !data.recommendations.is_empty() {
        md.push_str("## Recommendations\n\n");
        for (i, rec) in data.recommendations.iter().enumerate() {
            md.push_str(&format!("{}. {}\n", i + 1, rec));
        }
        md.push('\n');
    }

    // Lessons Learned
    md.push_str("## Lessons Learned\n\n");
    md.push_str(&data.lessons_learned);
    md.push_str("\n\n");

    md.push_str("---\n\n");
    md.push_str("*Generated by RookBot Report System*\n");

    md
}

fn render_compliance_report(data: &ComplianceReportData) -> String {
    let mut md = String::new();
    md.push_str("# CLAWDEFENDER COMPLIANCE REPORT\n\n");
    md.push_str(&format!(
        "**Generated:** {}\n\n",
        data.generated_at.format("%B %d, %Y %H:%M UTC"),
    ));
    md.push_str("---\n\n");

    // Summary
    md.push_str("## Summary\n\n");
    md.push_str(&data.summary);
    md.push_str("\n\n");
    md.push_str(&format!(
        "**Overall Compliance Score:** {:.0}%\n\n",
        data.overall_score * 100.0,
    ));

    // Control Areas Overview
    md.push_str("## Control Areas Overview\n\n");
    md.push_str("| Control Area | Status | Score |\n");
    md.push_str("|-------------|--------|-------|\n");
    for area in &data.control_areas {
        md.push_str(&format!(
            "| {} | {} | {:.0}% |\n",
            area.name,
            area.status,
            area.score * 100.0,
        ));
    }
    md.push('\n');

    // Detailed Control Areas
    for area in &data.control_areas {
        md.push_str(&format!("## {} — {}\n\n", area.name, area.status));
        md.push_str(&format!("**Score:** {:.0}%\n\n", area.score * 100.0));

        if !area.evidence.is_empty() {
            md.push_str("**Evidence:**\n\n");
            for ev in &area.evidence {
                md.push_str(&format!("- {}\n", ev));
            }
            md.push('\n');
        }

        if !area.gaps.is_empty() {
            md.push_str("**Gaps:**\n\n");
            for gap in &area.gaps {
                md.push_str(&format!("- {}\n", gap));
            }
            md.push('\n');
        }
    }

    md.push_str("---\n\n");
    md.push_str("*Generated by RookBot Report System*\n");

    md
}

fn render_executive_summary(data: &WeeklyReportData) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "# CLAWDEFENDER EXECUTIVE SUMMARY\n\n**Period:** {} to {}\n\n",
        data.week_start, data.week_end,
    ));
    md.push_str("---\n\n");

    // Overview
    md.push_str("## Overview\n\n");
    md.push_str(&data.executive_summary);
    md.push_str("\n\n");

    // Key Numbers
    md.push_str("## Key Numbers\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!("| Total Events | {} |\n", data.total_events));
    md.push_str(&format!(
        "| Suspicious Events | {} |\n",
        data.suspicious_count
    ));
    md.push_str(&format!("| Alerts | {} |\n", data.alerts_generated));
    md.push_str(&format!("| Scans | {} |\n", data.scans_completed));
    md.push_str(&format!("| Defense Score | {}/100 |\n", data.defense_score));
    md.push('\n');

    // Trend
    md.push_str("## Trend\n\n");
    md.push_str(&data.trend_narrative);
    md.push_str("\n\n");

    // Recommendations
    if !data.recommendations.is_empty() {
        md.push_str("## Recommendations\n\n");
        for (i, rec) in data.recommendations.iter().enumerate() {
            md.push_str(&format!("{}. {}\n", i + 1, rec));
        }
        md.push('\n');
    }

    md.push_str("---\n\n");
    md.push_str("*Generated by RookBot Report System*\n");

    md
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Default reports directory.
fn default_reports_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/share/rookbot/reports")
}

/// Convert a NaiveDate to a DateTime<Utc> at midnight.
fn date_to_utc(date: NaiveDate) -> DateTime<Utc> {
    date.and_hms_opt(0, 0, 0).unwrap().and_utc()
}

/// Minimal Markdown-to-HTML conversion for report rendering.
fn markdown_to_html_body(md: &str) -> String {
    let mut html = String::new();
    let mut in_table = false;
    let mut in_list = false;

    for line in md.lines() {
        let trimmed = line.trim();

        // Headings
        if let Some(content) = trimmed.strip_prefix("### ") {
            close_contexts(&mut html, &mut in_table, &mut in_list);
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
            if trimmed.contains("---") {
                continue;
            }
            if !in_table {
                close_list(&mut html, &mut in_list);
                html.push_str("<table>\n");
                in_table = true;
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
            html.push_str(&format!("<li>{}</li>\n", apply_bold(content)));
            continue;
        }
        // Numbered list items
        if trimmed.len() > 2 && trimmed.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            if let Some(rest) = trimmed.split_once(". ").map(|x| x.1) {
                if !in_list {
                    html.push_str("<ul>\n");
                    in_list = true;
                }
                html.push_str(&format!("<li>{}</li>\n", apply_bold(rest)));
                continue;
            }
        }

        if in_list && trimmed.is_empty() {
            html.push_str("</ul>\n");
            in_list = false;
        }

        if trimmed.is_empty() {
            continue;
        }

        html.push_str(&format!("<p>{}</p>\n", apply_bold(trimmed)));
    }

    close_contexts(&mut html, &mut in_table, &mut in_list);
    html
}

/// Apply **bold** inline formatting.
fn apply_bold(text: &str) -> String {
    let mut result = text.to_string();
    while let Some(start) = result.find("**") {
        if let Some(end) = result[start + 2..].find("**") {
            let bold_text = &result[start + 2..start + 2 + end].to_string();
            result = format!(
                "{}<strong>{}</strong>{}",
                &result[..start],
                bold_text,
                &result[start + 2 + end + 2..],
            );
        } else {
            break;
        }
    }
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
    use tempfile::TempDir;

    // -- Test data builders --------------------------------------------------

    fn sample_daily_brief() -> DailyBriefData {
        DailyBriefData {
            date: NaiveDate::from_ymd_opt(2026, 4, 8).unwrap(),
            events_total: 1250,
            events_suspicious: 3,
            alerts_total: 2,
            blocked_count: 1,
            posture_changes: vec![PostureChangeEntry {
                time: "14:30".to_string(),
                from: "Normal".to_string(),
                to: "Elevated".to_string(),
            }],
            defense_score: 82,
            highlights: vec![
                "Blocked brute-force attempt from 10.0.0.50".to_string(),
                "Completed weekly vulnerability scan".to_string(),
            ],
            action_items: vec![
                ActionItem {
                    description: "Review SSH access logs".to_string(),
                    priority: "High".to_string(),
                },
                ActionItem {
                    description: "Update firewall rules".to_string(),
                    priority: "Medium".to_string(),
                },
            ],
            agent_actions_taken: 5,
            agent_actions_suggested: 3,
        }
    }

    fn sample_weekly_report() -> WeeklyReportData {
        WeeklyReportData {
            week_start: NaiveDate::from_ymd_opt(2026, 3, 30).unwrap(),
            week_end: NaiveDate::from_ymd_opt(2026, 4, 5).unwrap(),
            total_events: 8742,
            events_change_percent: -12.5,
            suspicious_count: 18,
            suspicious_change: -3,
            alerts_generated: 7,
            alerts_resolved: 5,
            alerts_investigating: 1,
            alerts_dismissed: 1,
            scans_completed: 3,
            scan_findings: "2H, 4M, 3L".to_string(),
            investigations_count: 4,
            investigations_false_positive: 2,
            investigations_confirmed: 2,
            agent_actions: 23,
            daily_event_volumes: vec![1200, 1350, 1100, 1400, 1300, 800, 592],
            top_events: vec![
                TopEvent {
                    description: "SSH brute-force detected".to_string(),
                    severity: "High".to_string(),
                    resolution: "Blocked source IP".to_string(),
                },
                TopEvent {
                    description: "Config drift on web-server-01".to_string(),
                    severity: "Medium".to_string(),
                    resolution: "Auto-remediated".to_string(),
                },
            ],
            server_health: vec![
                ServerHealthEntry {
                    server_name: "web-server-01".to_string(),
                    trust_level: "High".to_string(),
                    anomaly_trend: "stable".to_string(),
                    drift_status: "Clean".to_string(),
                    event_count: 3200,
                },
                ServerHealthEntry {
                    server_name: "db-server-01".to_string(),
                    trust_level: "Medium".to_string(),
                    anomaly_trend: "rising".to_string(),
                    drift_status: "Drift detected".to_string(),
                    event_count: 1800,
                },
            ],
            defense_score: 78,
            defense_score_change: 3,
            improvements: vec!["Reduced false positive rate by 15%".to_string()],
            gaps: vec!["Log coverage gap on staging servers".to_string()],
            recommendations: vec![
                "Enable audit logging on staging".to_string(),
                "Rotate SSH keys older than 90 days".to_string(),
            ],
            executive_summary: "Security posture improved this week with fewer suspicious events and successful remediation of detected threats.".to_string(),
            trend_narrative: "Event volume decreased 12.5% week-over-week, indicating improved baseline stability. Suspicious activity declined with 3 fewer flagged events.".to_string(),
        }
    }

    fn sample_incident_report() -> IncidentReportData {
        IncidentReportData {
            incident_id: "INC-2026-0042".to_string(),
            date: NaiveDate::from_ymd_opt(2026, 4, 7).unwrap(),
            severity: "High".to_string(),
            status: "Resolved".to_string(),
            executive_summary: "Unauthorized access attempt detected and blocked on production database server.".to_string(),
            timeline: vec![
                TimelineEntry {
                    timestamp: "2026-04-07 14:22:00".to_string(),
                    description: "Anomalous login attempt detected".to_string(),
                    severity: "Medium".to_string(),
                },
                TimelineEntry {
                    timestamp: "2026-04-07 14:23:15".to_string(),
                    description: "Multiple failed auth attempts from same source".to_string(),
                    severity: "High".to_string(),
                },
                TimelineEntry {
                    timestamp: "2026-04-07 14:24:00".to_string(),
                    description: "Source IP blocked by automated response".to_string(),
                    severity: "Info".to_string(),
                },
            ],
            root_cause: "Compromised service account credentials exposed in a public repository.".to_string(),
            data_accessed: vec!["User table metadata".to_string()],
            data_modified: vec![],
            data_exfiltrated: false,
            affected_systems: vec![
                "db-server-01".to_string(),
                "auth-service".to_string(),
            ],
            evidence_items: vec![
                "Auth logs showing 47 failed attempts from 203.0.113.42".to_string(),
                "Git commit exposing credentials in config file".to_string(),
                "Network capture of connection attempts".to_string(),
            ],
            response_actions: vec![
                ResponseAction {
                    timestamp: "14:24:00".to_string(),
                    description: "Blocked source IP at firewall".to_string(),
                },
                ResponseAction {
                    timestamp: "14:30:00".to_string(),
                    description: "Rotated compromised credentials".to_string(),
                },
                ResponseAction {
                    timestamp: "15:00:00".to_string(),
                    description: "Initiated full access audit".to_string(),
                },
            ],
            recommendations: vec![
                "Implement pre-commit hooks to prevent credential exposure".to_string(),
                "Enable MFA on all service accounts".to_string(),
            ],
            lessons_learned: "Credential scanning in CI/CD pipeline would have prevented the initial exposure. Need to implement automated secret detection.".to_string(),
        }
    }

    fn sample_compliance_report() -> ComplianceReportData {
        ComplianceReportData {
            generated_at: Utc::now(),
            control_areas: vec![
                ControlArea {
                    name: "Access Control".to_string(),
                    status: "Met".to_string(),
                    evidence: vec![
                        "MFA enabled for all admin accounts".to_string(),
                        "RBAC policies reviewed quarterly".to_string(),
                    ],
                    gaps: vec![],
                    score: 0.95,
                },
                ControlArea {
                    name: "Monitoring".to_string(),
                    status: "Partially Met".to_string(),
                    evidence: vec!["Central log aggregation in place".to_string()],
                    gaps: vec!["Staging environment not covered".to_string()],
                    score: 0.70,
                },
                ControlArea {
                    name: "Incident Response".to_string(),
                    status: "Met".to_string(),
                    evidence: vec!["IR runbook documented and tested".to_string()],
                    gaps: vec![],
                    score: 0.90,
                },
                ControlArea {
                    name: "Data Protection".to_string(),
                    status: "Partially Met".to_string(),
                    evidence: vec!["Encryption at rest enabled".to_string()],
                    gaps: vec!["Backup encryption not verified".to_string()],
                    score: 0.75,
                },
                ControlArea {
                    name: "System Hardening".to_string(),
                    status: "Not Met".to_string(),
                    evidence: vec![],
                    gaps: vec![
                        "Default passwords on 3 services".to_string(),
                        "Unnecessary ports open".to_string(),
                    ],
                    score: 0.40,
                },
            ],
            overall_score: 0.74,
            summary: "The organization demonstrates strong access control and incident response capabilities but has gaps in monitoring coverage and system hardening.".to_string(),
        }
    }

    fn make_generator() -> (ReportGenerator, TempDir) {
        let tmp = TempDir::new().unwrap();
        let gen = ReportGenerator::with_dir(tmp.path().to_path_buf());
        (gen, tmp)
    }

    // -- Daily Brief tests ---------------------------------------------------

    #[test]
    fn test_daily_brief_generation() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_daily_brief();
        let report = gen.generate_daily_brief(&data).unwrap();

        assert_eq!(report.report_type, ReportType::DailyBrief);
        assert_eq!(report.format, ReportFormat::Markdown);
        assert!(report.size_bytes > 0);
        assert!(report.summary.contains("Daily brief"));
        assert!(report.period_start.is_some());
    }

    #[test]
    fn test_daily_brief_content_header() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_daily_brief();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("# CLAWDEFENDER DAILY BRIEF"));
        assert!(content.contains("2026-04-08"));
    }

    #[test]
    fn test_daily_brief_metrics_table() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_daily_brief();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("| Events | 1250 |"));
        assert!(content.contains("| Suspicious | 3 |"));
        assert!(content.contains("| Alerts | 2 |"));
        assert!(content.contains("| Blocked | 1 |"));
    }

    #[test]
    fn test_daily_brief_posture_changes() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_daily_brief();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("14:30"));
        assert!(content.contains("Normal -> Elevated"));
    }

    #[test]
    fn test_daily_brief_no_posture_changes() {
        let (mut gen, _tmp) = make_generator();
        let mut data = sample_daily_brief();
        data.posture_changes.clear();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("No changes"));
    }

    #[test]
    fn test_daily_brief_highlights() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_daily_brief();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("Blocked brute-force"));
        assert!(content.contains("vulnerability scan"));
    }

    #[test]
    fn test_daily_brief_action_items() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_daily_brief();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("[High]"));
        assert!(content.contains("Review SSH access logs"));
        assert!(content.contains("[Medium]"));
    }

    #[test]
    fn test_daily_brief_agent_activity() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_daily_brief();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("Actions taken: 5"));
        assert!(content.contains("Actions suggested: 3"));
    }

    #[test]
    fn test_daily_brief_status_green() {
        let (mut gen, _tmp) = make_generator();
        let mut data = sample_daily_brief();
        data.events_suspicious = 0;
        data.alerts_total = 0;
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("[GREEN] All Clear"));
    }

    #[test]
    fn test_daily_brief_status_red() {
        let (mut gen, _tmp) = make_generator();
        let mut data = sample_daily_brief();
        data.events_suspicious = 10;
        data.alerts_total = 5;
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("[RED]"));
    }

    #[test]
    fn test_daily_brief_defense_score() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_daily_brief();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("82/100"));
    }

    // -- Weekly Report tests -------------------------------------------------

    #[test]
    fn test_weekly_report_generation() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_weekly_report();
        let report = gen.generate_weekly_report(&data).unwrap();

        assert_eq!(report.report_type, ReportType::WeeklyReport);
        assert!(report.summary.contains("Weekly report"));
        assert!(report.size_bytes > 100);
    }

    #[test]
    fn test_weekly_report_metrics() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_weekly_report();
        let report = gen.generate_weekly_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("| Total Events | 8742 |"));
        assert!(content.contains("-12.5%"));
        assert!(content.contains("| Suspicious Events | 18 |"));
    }

    #[test]
    fn test_weekly_report_top_events() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_weekly_report();
        let report = gen.generate_weekly_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("SSH brute-force detected"));
        assert!(content.contains("Config drift on web-server-01"));
    }

    #[test]
    fn test_weekly_report_server_health() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_weekly_report();
        let report = gen.generate_weekly_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("web-server-01"));
        assert!(content.contains("db-server-01"));
        assert!(content.contains("Drift detected"));
    }

    #[test]
    fn test_weekly_report_defense_posture() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_weekly_report();
        let report = gen.generate_weekly_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("78/100"));
        assert!(content.contains("+3"));
    }

    #[test]
    fn test_weekly_report_recommendations() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_weekly_report();
        let report = gen.generate_weekly_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("Enable audit logging"));
        assert!(content.contains("Rotate SSH keys"));
    }

    #[test]
    fn test_weekly_report_daily_volumes() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_weekly_report();
        let report = gen.generate_weekly_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("| Mon | 1200 |"));
        assert!(content.contains("| Sun | 592 |"));
    }

    // -- Incident Report tests -----------------------------------------------

    #[test]
    fn test_incident_report_generation() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_incident_report();
        let report = gen.generate_incident_report(&data).unwrap();

        assert_eq!(report.report_type, ReportType::IncidentReport);
        assert!(report.summary.contains("INC-2026-0042"));
    }

    #[test]
    fn test_incident_report_header() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_incident_report();
        let report = gen.generate_incident_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("# CLAWDEFENDER INCIDENT REPORT"));
        assert!(content.contains("INC-2026-0042"));
        assert!(content.contains("High"));
        assert!(content.contains("Resolved"));
    }

    #[test]
    fn test_incident_report_timeline() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_incident_report();
        let report = gen.generate_incident_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("Anomalous login attempt"));
        assert!(content.contains("Multiple failed auth attempts"));
        assert!(content.contains("Source IP blocked"));
    }

    #[test]
    fn test_incident_report_root_cause() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_incident_report();
        let report = gen.generate_incident_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("Compromised service account credentials"));
    }

    #[test]
    fn test_incident_report_impact_assessment() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_incident_report();
        let report = gen.generate_incident_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("User table metadata"));
        assert!(content.contains("Data Exfiltration:** No"));
    }

    #[test]
    fn test_incident_report_evidence_chain() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_incident_report();
        let report = gen.generate_incident_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("47 failed attempts"));
        assert!(content.contains("Git commit exposing credentials"));
    }

    #[test]
    fn test_incident_report_response_actions() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_incident_report();
        let report = gen.generate_incident_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("Blocked source IP at firewall"));
        assert!(content.contains("Rotated compromised credentials"));
    }

    #[test]
    fn test_incident_report_lessons_learned() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_incident_report();
        let report = gen.generate_incident_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("Credential scanning in CI/CD"));
    }

    // -- Compliance Report tests ---------------------------------------------

    #[test]
    fn test_compliance_report_generation() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_compliance_report();
        let report = gen.generate_compliance_report(&data).unwrap();

        assert_eq!(report.report_type, ReportType::ComplianceReport);
        assert!(report.summary.contains("74%"));
    }

    #[test]
    fn test_compliance_report_control_areas() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_compliance_report();
        let report = gen.generate_compliance_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("Access Control"));
        assert!(content.contains("Monitoring"));
        assert!(content.contains("System Hardening"));
        assert!(content.contains("Met"));
        assert!(content.contains("Partially Met"));
        assert!(content.contains("Not Met"));
    }

    #[test]
    fn test_compliance_report_scores() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_compliance_report();
        let report = gen.generate_compliance_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("74%"));
        assert!(content.contains("95%"));
        assert!(content.contains("40%"));
    }

    #[test]
    fn test_compliance_report_gaps() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_compliance_report();
        let report = gen.generate_compliance_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("Staging environment not covered"));
        assert!(content.contains("Default passwords"));
    }

    // -- Executive Summary tests ---------------------------------------------

    #[test]
    fn test_executive_summary_generation() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_weekly_report();
        let report = gen.generate_executive_summary(&data).unwrap();

        assert_eq!(report.report_type, ReportType::ExecutiveSummary);
        assert!(report.summary.contains("Executive summary"));
    }

    #[test]
    fn test_executive_summary_condensed() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_weekly_report();
        let weekly = gen.generate_weekly_report(&data).unwrap();
        let weekly_content = gen.get_report_content(weekly.id).unwrap();

        let exec = gen.generate_executive_summary(&data).unwrap();
        let exec_content = gen.get_report_content(exec.id).unwrap();

        // Executive summary should be shorter than the full weekly report
        assert!(exec_content.len() < weekly_content.len());
    }

    #[test]
    fn test_executive_summary_key_numbers() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_weekly_report();
        let report = gen.generate_executive_summary(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("8742"));
        assert!(content.contains("78/100"));
    }

    // -- HTML conversion tests -----------------------------------------------

    #[test]
    fn test_to_html_structure() {
        let md = "# Test Report\n\nSome content.\n";
        let html = to_html(md, "Test");

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<html"));
        assert!(html.contains("</html>"));
        assert!(html.contains("RookBot"));
        assert!(html.contains("<h1>Test Report</h1>"));
    }

    #[test]
    fn test_to_html_table() {
        let md = "| Col A | Col B |\n|-------|-------|\n| val1 | val2 |\n";
        let html = to_html(md, "Test");

        assert!(html.contains("<table>"));
        assert!(html.contains("<th>Col A</th>"));
        assert!(html.contains("<td>val1</td>"));
        assert!(html.contains("</table>"));
    }

    #[test]
    fn test_to_html_list() {
        let md = "- Item one\n- Item two\n";
        let html = to_html(md, "Test");

        assert!(html.contains("<ul>"));
        assert!(html.contains("<li>Item one</li>"));
        assert!(html.contains("<li>Item two</li>"));
        assert!(html.contains("</ul>"));
    }

    #[test]
    fn test_to_html_bold() {
        let md = "This is **bold** text.\n";
        let html = to_html(md, "Test");

        assert!(html.contains("<strong>bold</strong>"));
    }

    #[test]
    fn test_to_html_has_inline_css() {
        let html = to_html("# Test\n", "Test");

        assert!(html.contains("<style>"));
        assert!(html.contains("font-family"));
        assert!(html.contains("@media print"));
    }

    #[test]
    fn test_to_html_full_report() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_daily_brief();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();
        let html = to_html(&content, "Daily Brief");

        assert!(html.contains("CLAWDEFENDER DAILY BRIEF"));
        assert!(html.contains("<table>"));
        assert!(html.contains("RookBot"));
    }

    // -- Report management tests ---------------------------------------------

    #[test]
    fn test_list_reports_empty() {
        let (gen, _tmp) = make_generator();
        let reports = gen.list_reports(None, 10);
        assert!(reports.is_empty());
    }

    #[test]
    fn test_list_reports_all() {
        let (mut gen, _tmp) = make_generator();
        gen.generate_daily_brief(&sample_daily_brief()).unwrap();
        gen.generate_weekly_report(&sample_weekly_report()).unwrap();

        let reports = gen.list_reports(None, 10);
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_list_reports_filtered() {
        let (mut gen, _tmp) = make_generator();
        gen.generate_daily_brief(&sample_daily_brief()).unwrap();
        gen.generate_weekly_report(&sample_weekly_report()).unwrap();
        gen.generate_daily_brief(&sample_daily_brief()).unwrap();

        let daily = gen.list_reports(Some(&ReportType::DailyBrief), 10);
        assert_eq!(daily.len(), 2);

        let weekly = gen.list_reports(Some(&ReportType::WeeklyReport), 10);
        assert_eq!(weekly.len(), 1);
    }

    #[test]
    fn test_list_reports_limited() {
        let (mut gen, _tmp) = make_generator();
        for _ in 0..5 {
            gen.generate_daily_brief(&sample_daily_brief()).unwrap();
        }

        let reports = gen.list_reports(None, 3);
        assert_eq!(reports.len(), 3);
    }

    #[test]
    fn test_get_report_found() {
        let (mut gen, _tmp) = make_generator();
        let report = gen.generate_daily_brief(&sample_daily_brief()).unwrap();

        let found = gen.get_report(report.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, report.id);
    }

    #[test]
    fn test_get_report_not_found() {
        let (gen, _tmp) = make_generator();
        let result = gen.get_report(Uuid::new_v4());
        assert!(result.is_none());
    }

    #[test]
    fn test_get_report_content() {
        let (mut gen, _tmp) = make_generator();
        let report = gen.generate_daily_brief(&sample_daily_brief()).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("CLAWDEFENDER DAILY BRIEF"));
    }

    #[test]
    fn test_get_report_content_not_found() {
        let (gen, _tmp) = make_generator();
        let result = gen.get_report_content(Uuid::new_v4());
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_report() {
        let (mut gen, _tmp) = make_generator();
        let report = gen.generate_daily_brief(&sample_daily_brief()).unwrap();
        let file_path = report.file_path.clone();

        assert!(std::path::Path::new(&file_path).exists());
        gen.delete_report(report.id).unwrap();

        assert!(!std::path::Path::new(&file_path).exists());
        assert!(gen.get_report(report.id).is_none());
        assert_eq!(gen.report_count(), 0);
    }

    #[test]
    fn test_delete_report_not_found() {
        let (mut gen, _tmp) = make_generator();
        let result = gen.delete_report(Uuid::new_v4());
        assert!(result.is_err());
    }

    #[test]
    fn test_export_report_to_html() {
        let (mut gen, _tmp) = make_generator();
        let report = gen.generate_daily_brief(&sample_daily_brief()).unwrap();

        let html_path = gen.export_report(report.id, ReportFormat::Html).unwrap();
        assert!(html_path.ends_with(".html"));

        let html_content = std::fs::read_to_string(&html_path).unwrap();
        assert!(html_content.contains("<!DOCTYPE html>"));
        assert!(html_content.contains("RookBot"));
    }

    #[test]
    fn test_export_report_same_format() {
        let (mut gen, _tmp) = make_generator();
        let report = gen.generate_daily_brief(&sample_daily_brief()).unwrap();

        let path = gen
            .export_report(report.id, ReportFormat::Markdown)
            .unwrap();
        assert_eq!(path, report.file_path);
    }

    #[test]
    fn test_export_report_not_found() {
        let (gen, _tmp) = make_generator();
        let result = gen.export_report(Uuid::new_v4(), ReportFormat::Html);
        assert!(result.is_err());
    }

    // -- History persistence tests -------------------------------------------

    #[test]
    fn test_save_and_load_history() {
        let tmp = TempDir::new().unwrap();
        let reports_dir = tmp.path().to_path_buf();

        let report_id;
        {
            let mut gen = ReportGenerator::with_dir(reports_dir.clone());
            let report = gen.generate_daily_brief(&sample_daily_brief()).unwrap();
            report_id = report.id;
            gen.save_history().unwrap();
        }

        {
            let mut gen = ReportGenerator::with_dir(reports_dir);
            gen.load_history().unwrap();
            assert_eq!(gen.report_count(), 1);
            let found = gen.get_report(report_id);
            assert!(found.is_some());
        }
    }

    #[test]
    fn test_load_history_no_file() {
        let tmp = TempDir::new().unwrap();
        let mut gen = ReportGenerator::with_dir(tmp.path().to_path_buf());
        // Should succeed even if no history file exists
        gen.load_history().unwrap();
        assert_eq!(gen.report_count(), 0);
    }

    #[test]
    fn test_save_history_creates_dir() {
        let tmp = TempDir::new().unwrap();
        let reports_dir = tmp.path().join("nested").join("reports");
        let mut gen = ReportGenerator::with_dir(reports_dir.clone());
        gen.generate_daily_brief(&sample_daily_brief()).unwrap();
        gen.save_history().unwrap();

        assert!(reports_dir.join("history.json").exists());
    }

    // -- Max reports enforcement tests ---------------------------------------

    #[test]
    fn test_max_reports_enforcement() {
        let tmp = TempDir::new().unwrap();
        let mut gen = ReportGenerator::with_dir(tmp.path().to_path_buf());
        gen.max_reports = 3;

        for _ in 0..5 {
            gen.generate_daily_brief(&sample_daily_brief()).unwrap();
        }

        assert_eq!(gen.report_count(), 3);
    }

    #[test]
    fn test_max_reports_deletes_oldest_files() {
        let tmp = TempDir::new().unwrap();
        let mut gen = ReportGenerator::with_dir(tmp.path().to_path_buf());
        gen.max_reports = 2;

        let r1 = gen.generate_daily_brief(&sample_daily_brief()).unwrap();
        let r1_path = r1.file_path.clone();
        let _r2 = gen.generate_daily_brief(&sample_daily_brief()).unwrap();
        let _r3 = gen.generate_daily_brief(&sample_daily_brief()).unwrap();

        // r1 should have been deleted
        assert!(!std::path::Path::new(&r1_path).exists());
        assert_eq!(gen.report_count(), 2);
    }

    // -- Template formatting edge cases --------------------------------------

    #[test]
    fn test_daily_brief_empty_highlights() {
        let (mut gen, _tmp) = make_generator();
        let mut data = sample_daily_brief();
        data.highlights.clear();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("No notable highlights"));
    }

    #[test]
    fn test_daily_brief_empty_action_items() {
        let (mut gen, _tmp) = make_generator();
        let mut data = sample_daily_brief();
        data.action_items.clear();
        let report = gen.generate_daily_brief(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("No action items"));
    }

    #[test]
    fn test_incident_report_no_data_modified() {
        let (mut gen, _tmp) = make_generator();
        let data = sample_incident_report();
        let report = gen.generate_incident_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        // data_modified is empty in sample, so "Data Modified" header should not appear
        assert!(!content.contains("Data Modified"));
    }

    #[test]
    fn test_incident_report_exfiltration_yes() {
        let (mut gen, _tmp) = make_generator();
        let mut data = sample_incident_report();
        data.data_exfiltrated = true;
        let report = gen.generate_incident_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(content.contains("Data Exfiltration:** Yes"));
    }

    #[test]
    fn test_weekly_report_empty_top_events() {
        let (mut gen, _tmp) = make_generator();
        let mut data = sample_weekly_report();
        data.top_events.clear();
        let report = gen.generate_weekly_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        // Should not have "Top Events" header when empty
        assert!(!content.contains("## Top Events"));
    }

    #[test]
    fn test_weekly_report_empty_server_health() {
        let (mut gen, _tmp) = make_generator();
        let mut data = sample_weekly_report();
        data.server_health.clear();
        let report = gen.generate_weekly_report(&data).unwrap();
        let content = gen.get_report_content(report.id).unwrap();

        assert!(!content.contains("## Server Health"));
    }

    #[test]
    fn test_report_file_path_format() {
        let (mut gen, _tmp) = make_generator();
        let report = gen.generate_daily_brief(&sample_daily_brief()).unwrap();

        assert!(report.file_path.contains("daily_brief_"));
        assert!(report.file_path.ends_with(".md"));
    }

    // -- Serde roundtrip tests -----------------------------------------------

    #[test]
    fn test_generated_report_serde() {
        let (mut gen, _tmp) = make_generator();
        let report = gen.generate_daily_brief(&sample_daily_brief()).unwrap();

        let json = serde_json::to_string(&report).unwrap();
        let parsed: GeneratedReport = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, report.id);
        assert_eq!(parsed.report_type, report.report_type);
        assert_eq!(parsed.summary, report.summary);
    }

    #[test]
    fn test_report_type_serde() {
        let rt = ReportType::IncidentReport;
        let json = serde_json::to_string(&rt).unwrap();
        let parsed: ReportType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, rt);
    }

    #[test]
    fn test_report_format_serde() {
        let fmt = ReportFormat::Html;
        let json = serde_json::to_string(&fmt).unwrap();
        let parsed: ReportFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, fmt);
    }

    // -- date_to_utc helper --------------------------------------------------

    #[test]
    fn test_date_to_utc() {
        let date = NaiveDate::from_ymd_opt(2026, 4, 8).unwrap();
        let dt = date_to_utc(date);
        assert_eq!(dt.date_naive(), date);
    }

    // -- Report footer -------------------------------------------------------

    #[test]
    fn test_all_reports_have_footer() {
        let (mut gen, _tmp) = make_generator();

        let r1 = gen.generate_daily_brief(&sample_daily_brief()).unwrap();
        let c1 = gen.get_report_content(r1.id).unwrap();
        assert!(c1.contains("Generated by RookBot Report System"));

        let r2 = gen.generate_weekly_report(&sample_weekly_report()).unwrap();
        let c2 = gen.get_report_content(r2.id).unwrap();
        assert!(c2.contains("Generated by RookBot Report System"));

        let r3 = gen
            .generate_incident_report(&sample_incident_report())
            .unwrap();
        let c3 = gen.get_report_content(r3.id).unwrap();
        assert!(c3.contains("Generated by RookBot Report System"));

        let r4 = gen
            .generate_compliance_report(&sample_compliance_report())
            .unwrap();
        let c4 = gen.get_report_content(r4.id).unwrap();
        assert!(c4.contains("Generated by RookBot Report System"));

        let r5 = gen
            .generate_executive_summary(&sample_weekly_report())
            .unwrap();
        let c5 = gen.get_report_content(r5.id).unwrap();
        assert!(c5.contains("Generated by RookBot Report System"));
    }
}
