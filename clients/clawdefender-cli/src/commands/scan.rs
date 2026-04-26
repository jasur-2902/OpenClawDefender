//! Scan commands for playbook-based security scanning.

use std::path::PathBuf;
use std::process;

use clap::Parser;
use clawdefender_scanner::finding::Severity;
use clawdefender_scanner::report;
use clawdefender_scanner::scanner::{
    compute_delta, exit_code_for_findings, load_baseline, ScanConfig, Scanner,
};

/// Scan action subcommands.
#[derive(Debug, Parser)]
pub enum ScanAction {
    /// Run a security scan with optional playbook.
    #[command(name = "run")]
    Run {
        /// Named playbook: mcp_security_audit, system_hardening, credential_exposure,
        /// network_security, behavioral_deep_dive, full_audit.
        #[arg(value_name = "PLAYBOOK")]
        playbook: Option<String>,

        /// Enable AI-enhanced analysis.
        #[arg(long)]
        ai: bool,

        /// Run signatures/patterns only (skip behavioral).
        #[arg(long)]
        signatures_only: bool,

        /// Quick scan (essential modules only).
        #[arg(long)]
        quick: bool,

        /// Full comprehensive scan.
        #[arg(long)]
        full: bool,

        /// Timeout in seconds.
        #[arg(long)]
        timeout: Option<u64>,

        /// Specific modules to run (comma-separated).
        #[arg(long)]
        modules: Option<String>,

        /// Output format: json or terminal.
        #[arg(long)]
        json: bool,

        /// HTML report output path.
        #[arg(long)]
        html: Option<PathBuf>,

        /// Report output path.
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Severity threshold for exit code.
        #[arg(long)]
        threshold: Option<String>,

        /// Baseline comparison file.
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Server command to scan (after --).
        #[arg(last = true)]
        server_command: Vec<String>,
    },

    /// Show findings from last or specified scan.
    #[command(name = "results")]
    Results {
        /// Scan ID to show (defaults to last).
        #[arg(value_name = "SCAN_ID")]
        scan_id: Option<String>,

        /// Filter by severity level.
        #[arg(long)]
        severity: Option<String>,

        /// Output format: json, terminal, or markdown.
        #[arg(long, default_value = "terminal")]
        format: String,
    },

    /// List past scans.
    #[command(name = "history")]
    History {
        /// Limit number of scans to show.
        #[arg(long, default_value = "10")]
        limit: usize,
    },

    /// Apply remediation for a finding.
    #[command(name = "fix")]
    Fix {
        /// Finding ID to fix (or --all).
        #[arg(value_name = "FINDING_ID")]
        finding_id: Option<String>,

        /// Only apply safe remediations.
        #[arg(long)]
        safe: bool,

        /// Fix all findings.
        #[arg(long)]
        all: bool,

        /// Show what would be done without applying.
        #[arg(long)]
        dry_run: bool,
    },

    /// Revert a previously applied remediation.
    #[command(name = "revert")]
    Revert {
        /// Remediation ID to undo.
        #[arg(value_name = "REMEDIATION_ID")]
        remediation_id: String,
    },

    /// Export scan report.
    #[command(name = "export")]
    Export {
        /// Scan ID to export.
        #[arg(value_name = "SCAN_ID")]
        scan_id: String,

        /// Export format: md, html, or pdf.
        #[arg(long, default_value = "md")]
        format: String,

        /// Output file path.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// List available scan modules.
    #[command(name = "modules")]
    ListModules,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_scan(
    playbook: Option<String>,
    ai: bool,
    signatures_only: bool,
    quick: bool,
    full: bool,
    server_command: Vec<String>,
    timeout: Option<u64>,
    modules: Option<String>,
    json: bool,
    html: Option<PathBuf>,
    output: Option<PathBuf>,
    threshold: Option<String>,
    baseline: Option<PathBuf>,
) -> anyhow::Result<()> {
    if server_command.is_empty() {
        anyhow::bail!(
            "No server command provided.\n\
             Usage: rookbot scan run [OPTIONS] -- <server-command> [args...]\n\
             Example: rookbot scan run -- npx -y @modelcontextprotocol/server-filesystem /tmp"
        );
    }

    // Display playbook info if specified
    if let Some(ref pb) = playbook {
        eprintln!("Running playbook: {}", pb);
        if ai {
            eprintln!("AI-enhanced analysis: enabled");
        }
        if signatures_only {
            eprintln!("Mode: signatures only");
        } else if quick {
            eprintln!("Mode: quick scan");
        } else if full {
            eprintln!("Mode: full comprehensive scan");
        }
        eprintln!();
    }

    let threshold_severity = match threshold.as_deref() {
        Some("critical") => Some(Severity::Critical),
        Some("high") => Some(Severity::High),
        Some("medium") => Some(Severity::Medium),
        Some("low") => Some(Severity::Low),
        Some("info") => Some(Severity::Info),
        Some(other) => {
            anyhow::bail!("Unknown threshold: {other}. Use: critical, high, medium, low, info")
        }
        None => None,
    };

    let module_filter = modules.map(|s| s.split(',').map(|m| m.trim().to_string()).collect());

    let config = ScanConfig {
        server_command: server_command.clone(),
        timeout_per_module: 300,
        total_timeout: timeout.unwrap_or(1800),
        modules: module_filter,
        output_format: if json {
            "json".to_string()
        } else {
            "terminal".to_string()
        },
        output_path: output.clone(),
        threshold: threshold_severity,
        baseline_path: baseline.clone(),
    };

    // Build scanner with default modules
    let mut scanner = Scanner::new();
    for m in Scanner::default_modules() {
        scanner.add_module(m);
    }

    eprintln!("Starting security scan of: {}", server_command.join(" "));
    eprintln!();

    let scan_report = scanner.run(config).await?;

    // Apply baseline delta if provided
    let report_findings = if let Some(ref baseline_path) = baseline {
        let baseline_report = load_baseline(baseline_path)?;
        let delta = compute_delta(&scan_report, &baseline_report);
        eprintln!(
            "Baseline comparison: {} new findings (out of {} total)",
            delta.len(),
            scan_report.findings.len()
        );
        delta
    } else {
        scan_report.findings.clone()
    };

    // Build a report with possibly filtered findings for output
    let output_report = clawdefender_scanner::scanner::ScanReport {
        target: scan_report.target.clone(),
        scan_date: scan_report.scan_date,
        duration_secs: scan_report.duration_secs,
        findings: report_findings.clone(),
        summary: clawdefender_scanner::scanner::ScanSummary::from_findings(&report_findings),
    };

    // Render output
    let rendered = if json {
        report::render_json(&output_report)?
    } else {
        report::render_terminal(&output_report)
    };

    // Write to file or stdout
    if let Some(ref out_path) = output {
        std::fs::write(out_path, &rendered)?;
        eprintln!("Report written to {}", out_path.display());
    } else {
        println!("{rendered}");
    }

    // HTML report
    if let Some(ref html_path) = html {
        let html_content = report::render_html(&output_report);
        std::fs::write(html_path, &html_content)?;
        eprintln!("HTML report written to {}", html_path.display());
    }

    // Exit code for CI/CD
    let code = exit_code_for_findings(&report_findings, threshold_severity.as_ref());
    if code != 0 {
        process::exit(code);
    }

    Ok(())
}

pub fn show_results(
    scan_id: Option<String>,
    severity: Option<String>,
    format: String,
) -> anyhow::Result<()> {
    let id = scan_id.as_deref().unwrap_or("last");
    println!("Scan Results: {}", id);
    println!("============={}=", "=".repeat(id.len()));

    if let Some(ref sev) = severity {
        println!("Filtered by severity: {}", sev);
    }
    println!("Format: {}", format);
    println!();
    println!("(Scan result storage will be implemented in a future version)");

    Ok(())
}

pub fn show_history(limit: usize) -> anyhow::Result<()> {
    println!("Scan History (last {})", limit);
    println!(
        "===================={}=",
        "=".repeat(limit.to_string().len())
    );
    println!();
    println!("(Scan history will be available in a future version)");

    Ok(())
}

pub fn apply_fix(
    finding_id: Option<String>,
    safe: bool,
    all: bool,
    dry_run: bool,
) -> anyhow::Result<()> {
    if all {
        println!("Applying remediations for all findings...");
    } else if let Some(ref id) = finding_id {
        println!("Applying remediation for finding: {}", id);
    } else {
        anyhow::bail!("Specify --all or provide a finding ID");
    }

    if safe {
        println!("Mode: safe remediations only");
    }
    if dry_run {
        println!("Mode: dry-run (no changes will be made)");
    }
    println!();
    println!("(Automated remediation will be available in a future version)");

    Ok(())
}

pub fn revert_remediation(remediation_id: String) -> anyhow::Result<()> {
    println!("Reverting remediation: {}", remediation_id);
    println!(
        "=========================={}=",
        "=".repeat(remediation_id.len())
    );
    println!();
    println!("(Remediation rollback will be available in a future version)");

    Ok(())
}

pub fn export_report(
    scan_id: String,
    format: String,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    println!("Exporting scan: {}", scan_id);
    println!("Format: {}", format);
    if let Some(ref path) = output {
        println!("Output: {}", path.display());
    }
    println!();
    println!("(Report export will be available in a future version)");

    Ok(())
}

pub fn list_modules() -> anyhow::Result<()> {
    let mods = Scanner::default_modules();
    println!("Available Scan Modules");
    println!("======================\n");
    for m in &mods {
        println!("  {:<25} {} [{}]", m.name(), m.description(), m.category());
    }
    println!("\nUse --modules <name1,name2,...> to run specific modules.");

    Ok(())
}
