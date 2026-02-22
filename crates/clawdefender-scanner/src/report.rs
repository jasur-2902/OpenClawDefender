use crate::finding::Severity;
use crate::scanner::ScanReport;

pub fn severity_color(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "\x1b[1;31m", // bold red
        Severity::High => "\x1b[33m",       // yellow
        Severity::Medium => "\x1b[35m",     // magenta
        Severity::Low => "\x1b[36m",        // cyan
        Severity::Info => "\x1b[37m",       // white
    }
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

pub fn render_terminal(report: &ScanReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "\n{}ClawDefender Security Scan Report{}\n",
        BOLD, RESET
    ));
    out.push_str(&format!("Target: {}\n", report.target));
    out.push_str(&format!(
        "Date:   {}\n",
        report.scan_date.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    out.push_str(&format!("Duration: {:.1}s\n", report.duration_secs));
    out.push_str(&"=".repeat(60));
    out.push('\n');

    // Summary
    out.push_str(&format!("\n{}Summary{}\n", BOLD, RESET));
    out.push_str(&format!(
        "  {}CRITICAL: {}{}\n",
        severity_color(&Severity::Critical),
        report.summary.critical,
        RESET
    ));
    out.push_str(&format!(
        "  {}HIGH:     {}{}\n",
        severity_color(&Severity::High),
        report.summary.high,
        RESET
    ));
    out.push_str(&format!(
        "  {}MEDIUM:   {}{}\n",
        severity_color(&Severity::Medium),
        report.summary.medium,
        RESET
    ));
    out.push_str(&format!(
        "  {}LOW:      {}{}\n",
        severity_color(&Severity::Low),
        report.summary.low,
        RESET
    ));
    out.push_str(&format!(
        "  {}INFO:     {}{}\n",
        severity_color(&Severity::Info),
        report.summary.info,
        RESET
    ));
    out.push_str(&format!("  Total:    {}\n", report.summary.total));

    // Findings
    if !report.findings.is_empty() {
        out.push_str(&format!("\n{}Findings{}\n", BOLD, RESET));
        out.push_str(&"-".repeat(60));
        out.push('\n');

        for finding in &report.findings {
            let color = severity_color(&finding.severity);
            out.push_str(&format!(
                "\n{}{} [{}]{} {}\n",
                color, finding.id, finding.severity, RESET, finding.title
            ));
            out.push_str(&format!("  Category: {}\n", finding.category));
            out.push_str(&format!("  CVSS:     {:.1}\n", finding.cvss));
            out.push_str(&format!("  {}\n", finding.description));
            out.push_str(&format!("  Remediation: {}\n", finding.remediation));

            if finding.evidence.canary_detected {
                out.push_str(&format!(
                    "  {}!! Canary data detected in output !!{}\n",
                    severity_color(&Severity::Critical),
                    RESET
                ));
            }
        }
    } else {
        out.push_str("\nNo findings.\n");
    }

    out.push('\n');
    out
}

pub fn render_json(report: &ScanReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

pub fn render_html(report: &ScanReport) -> String {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n");
    html.push_str("<title>ClawDefender Scan Report</title>\n");
    html.push_str("<style>\n");
    html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2em; background: #1a1a2e; color: #e0e0e0; }\n");
    html.push_str("h1 { color: #00d4ff; }\n");
    html.push_str(".summary { display: flex; gap: 1em; margin: 1em 0; }\n");
    html.push_str(".summary-card { padding: 1em; border-radius: 8px; min-width: 100px; text-align: center; }\n");
    html.push_str(".critical { background: #dc3545; color: white; }\n");
    html.push_str(".high { background: #fd7e14; color: white; }\n");
    html.push_str(".medium { background: #ffc107; color: black; }\n");
    html.push_str(".low { background: #17a2b8; color: white; }\n");
    html.push_str(".info { background: #6c757d; color: white; }\n");
    html.push_str(
        ".finding { border: 1px solid #333; border-radius: 8px; padding: 1em; margin: 1em 0; }\n",
    );
    html.push_str(".finding-header { cursor: pointer; }\n");
    html.push_str(".evidence { display: none; margin-top: 1em; padding: 1em; background: #0d0d1a; border-radius: 4px; }\n");
    html.push_str("details[open] .evidence { display: block; }\n");
    html.push_str("</style></head><body>\n");

    html.push_str("<h1>ClawDefender Security Scan Report</h1>\n");
    html.push_str(&format!(
        "<p>Target: <code>{}</code></p>\n",
        html_escape(&report.target)
    ));
    html.push_str(&format!(
        "<p>Date: {} | Duration: {:.1}s</p>\n",
        report.scan_date.format("%Y-%m-%d %H:%M:%S UTC"),
        report.duration_secs
    ));

    // Summary dashboard
    html.push_str("<div class=\"summary\">\n");
    html.push_str(&format!(
        "<div class=\"summary-card critical\"><div style=\"font-size:2em\">{}</div><div>Critical</div></div>\n",
        report.summary.critical
    ));
    html.push_str(&format!(
        "<div class=\"summary-card high\"><div style=\"font-size:2em\">{}</div><div>High</div></div>\n",
        report.summary.high
    ));
    html.push_str(&format!(
        "<div class=\"summary-card medium\"><div style=\"font-size:2em\">{}</div><div>Medium</div></div>\n",
        report.summary.medium
    ));
    html.push_str(&format!(
        "<div class=\"summary-card low\"><div style=\"font-size:2em\">{}</div><div>Low</div></div>\n",
        report.summary.low
    ));
    html.push_str(&format!(
        "<div class=\"summary-card info\"><div style=\"font-size:2em\">{}</div><div>Info</div></div>\n",
        report.summary.info
    ));
    html.push_str("</div>\n");

    // Findings
    html.push_str("<h2>Findings</h2>\n");
    if report.findings.is_empty() {
        html.push_str("<p>No findings.</p>\n");
    } else {
        for finding in &report.findings {
            let sev_class = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            html.push_str(&format!(
                "<details class=\"finding\"><summary class=\"finding-header\">\
                 <span class=\"summary-card {}\" style=\"display:inline-block;padding:0.2em 0.6em;font-size:0.9em\">{}</span> \
                 <strong>{}</strong> - {}</summary>\n",
                sev_class,
                finding.severity,
                html_escape(&finding.id),
                html_escape(&finding.title)
            ));
            html.push_str(&format!(
                "<p>Category: {} | CVSS: {:.1}</p>\n",
                finding.category, finding.cvss
            ));
            html.push_str(&format!("<p>{}</p>\n", html_escape(&finding.description)));
            html.push_str(&format!(
                "<p><strong>Remediation:</strong> {}</p>\n",
                html_escape(&finding.remediation)
            ));

            html.push_str("<div class=\"evidence\">\n");
            html.push_str("<h4>Evidence</h4>\n");
            if finding.evidence.canary_detected {
                html.push_str(
                    "<p style=\"color:#dc3545\"><strong>Canary data detected!</strong></p>\n",
                );
            }
            if !finding.evidence.files_modified.is_empty() {
                html.push_str("<p>Files modified:</p><ul>\n");
                for f in &finding.evidence.files_modified {
                    html.push_str(&format!("<li><code>{}</code></li>\n", html_escape(f)));
                }
                html.push_str("</ul>\n");
            }
            if !finding.evidence.network_connections.is_empty() {
                html.push_str("<p>Network connections:</p><ul>\n");
                for n in &finding.evidence.network_connections {
                    html.push_str(&format!("<li><code>{}</code></li>\n", html_escape(n)));
                }
                html.push_str("</ul>\n");
            }
            html.push_str("</div>\n");
            html.push_str("</details>\n");
        }
    }

    html.push_str("</body></html>\n");
    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
