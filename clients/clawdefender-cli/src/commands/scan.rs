use std::path::PathBuf;
use std::process;

use clawdefender_scanner::finding::Severity;
use clawdefender_scanner::report;
use clawdefender_scanner::scanner::{
    compute_delta, exit_code_for_findings, load_baseline, ScanConfig, Scanner,
};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    server_command: Vec<String>,
    timeout: Option<u64>,
    modules: Option<String>,
    json: bool,
    html: Option<PathBuf>,
    output: Option<PathBuf>,
    threshold: Option<String>,
    baseline: Option<PathBuf>,
    list_modules: bool,
) -> anyhow::Result<()> {
    // --list-modules: print available modules and exit
    if list_modules {
        let mods = Scanner::default_modules();
        println!("Available scan modules:\n");
        for m in &mods {
            println!(
                "  {:<25} {} [{}]",
                m.name(),
                m.description(),
                m.category()
            );
        }
        println!("\nUse --modules <name1,name2,...> to run specific modules.");
        return Ok(());
    }

    if server_command.is_empty() {
        anyhow::bail!(
            "No server command provided.\n\
             Usage: clawdefender scan [OPTIONS] -- <server-command> [args...]\n\
             Example: clawdefender scan -- npx -y @modelcontextprotocol/server-filesystem /tmp"
        );
    }

    let threshold_severity = match threshold.as_deref() {
        Some("critical") => Some(Severity::Critical),
        Some("high") => Some(Severity::High),
        Some("medium") => Some(Severity::Medium),
        Some("low") => Some(Severity::Low),
        Some("info") => Some(Severity::Info),
        Some(other) => anyhow::bail!("Unknown threshold: {other}. Use: critical, high, medium, low, info"),
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
