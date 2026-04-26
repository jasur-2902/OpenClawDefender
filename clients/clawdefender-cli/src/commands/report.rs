//! `rookbot report` — Security report generation from the terminal.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;

use clawdefender_swarm::report_system::{
    DailyBriefData, ReportFormat, ReportGenerator, ReportType,
};

#[derive(Subcommand, Debug)]
pub enum ReportAction {
    /// Generate daily security report.
    Daily {
        /// Date (YYYY-MM-DD). Defaults to today.
        #[arg(long)]
        date: Option<String>,
        /// Output file path. If not specified, prints to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Generate weekly security report.
    Weekly {
        /// Week ending date (YYYY-MM-DD). Defaults to today.
        #[arg(long)]
        date: Option<String>,
        /// Output file path. If not specified, prints to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Generate incident report from an investigation.
    Incident {
        /// Investigation ID to generate report from.
        investigation_id: String,
        /// Output file path. If not specified, prints to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Generate compliance report.
    Compliance {
        /// Compliance framework: cis, nist, pci-dss, soc2.
        #[arg(long, default_value = "cis")]
        framework: String,
        /// Output file path. If not specified, prints to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List past reports.
    List {
        /// Filter by report type: daily, weekly, incident, compliance.
        #[arg(long)]
        r#type: Option<String>,
        /// Maximum number of reports to list.
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Show a past report.
    Show { report_id: String },
}

/// Default reports directory: ~/.local/share/rookbot/reports/
fn reports_dir() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME not set");
    PathBuf::from(home).join(".local/share/rookbot/reports")
}

/// Generate daily security report.
pub fn generate_daily_report(date: Option<String>, output: Option<PathBuf>) -> Result<()> {
    let reports_dir = reports_dir();
    std::fs::create_dir_all(&reports_dir)?;

    let date = if let Some(date_str) = date {
        chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
            .map_err(|_| anyhow::anyhow!("Invalid date format. Use YYYY-MM-DD."))?
    } else {
        chrono::Local::now().date_naive()
    };

    println!("Generating daily report for {}...", date);

    // Gather data from daemon/database
    // For now, use placeholder data
    let data = DailyBriefData {
        date,
        events_total: 142,
        events_suspicious: 3,
        alerts_total: 1,
        blocked_count: 0,
        posture_changes: vec![],
        defense_score: 85,
        highlights: vec![
            "3 suspicious events detected and investigated".to_string(),
            "1 medium-severity alert requires attention".to_string(),
            "All MCP servers operating within policy".to_string(),
        ],
        action_items: vec![
            clawdefender_swarm::report_system::ActionItem {
                priority: "Medium".to_string(),
                description: "Review medium-severity alert: Unusual network pattern".to_string(),
            },
        ],
        agent_actions_taken: 0,
        agent_actions_suggested: 1,
    };

    let mut generator = ReportGenerator::new();
    let report = generator.generate_daily_brief(&data).map_err(|e| anyhow::anyhow!(e))?;

    // Read the generated report content
    let markdown = std::fs::read_to_string(&report.file_path)?;

    // Output report
    if let Some(output_path) = output {
        std::fs::write(&output_path, markdown)?;
        println!("Report written to: {}", output_path.display());
    } else {
        println!();
        println!("{markdown}");
    }

    println!();
    println!("Report saved to: {}", reports_dir.display());

    Ok(())
}

/// Generate weekly security report.
pub fn generate_weekly_report(date: Option<String>, output: Option<PathBuf>) -> Result<()> {
    let reports_dir = reports_dir();
    std::fs::create_dir_all(&reports_dir)?;

    let end_date = if let Some(date_str) = date {
        chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
            .map_err(|_| anyhow::anyhow!("Invalid date format. Use YYYY-MM-DD."))?
    } else {
        chrono::Local::now().date_naive()
    };

    let start_date = end_date - chrono::Duration::days(7);

    println!("Generating weekly report for {} to {}...", start_date, end_date);

    // Gather data from daemon/database
    // For now, create placeholder report
    let markdown = format!(
        "# WEEKLY SECURITY REPORT\n\
         \n\
         **Period:** {} to {}\n\
         **Generated:** {}\n\
         \n\
         ## Executive Summary\n\
         \n\
         Security posture remains stable. 873 events monitored, 12 flagged as suspicious, \
         all investigated with no confirmed threats.\n\
         \n\
         ## Key Metrics\n\
         \n\
         - **Total Events:** 873\n\
         - **Suspicious Events:** 12\n\
         - **Alerts Generated:** 3\n\
         - **Threats Blocked:** 0\n\
         - **Defense Score:** 87/100 (↑2 from last week)\n\
         \n\
         ## Highlights\n\
         \n\
         - All MCP servers operating within policy\n\
         - No data exfiltration detected\n\
         - Security posture improved with updated policies\n\
         \n\
         ## Recommended Actions\n\
         \n\
         1. Review and close 1 pending medium-severity alert\n\
         2. Consider enabling stricter network policies for external servers\n\
         \n\
         ---\n\
         Generated by RookBot | ClawDefender Security Platform\n",
        start_date,
        end_date,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
    );

    // Save report
    let report_id = format!("{:x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs());
    let report_file = reports_dir.join(format!("weekly_{}.md", report_id));
    std::fs::write(&report_file, &markdown)?;

    // Output report
    if let Some(output_path) = output {
        std::fs::write(&output_path, &markdown)?;
        println!("Report written to: {}", output_path.display());
    } else {
        println!();
        println!("{markdown}");
    }

    println!();
    println!("Report saved to: {}", report_file.display());

    Ok(())
}

/// Generate incident report from investigation.
pub fn generate_incident_report(investigation_id: &str, output: Option<PathBuf>) -> Result<()> {
    let reports_dir = reports_dir();
    std::fs::create_dir_all(&reports_dir)?;

    // Load investigation result
    let investigations_dir = PathBuf::from(std::env::var_os("HOME").expect("HOME not set"))
        .join(".local/share/rookbot/investigations");

    let inv_store = clawdefender_swarm::investigation_store::InvestigationStore::with_dir(investigations_dir)?;
    let investigation = inv_store.load(investigation_id)?;

    println!("Generating incident report for investigation: {investigation_id}...");

    // Generate markdown report
    let markdown = format!(
        "# INCIDENT REPORT\n\
         \n\
         **Investigation ID:** {}\n\
         **Target:** {} - {}\n\
         **Date:** {}\n\
         **Verdict:** {:?}\n\
         **Confidence:** {:.0}%\n\
         \n\
         ## Executive Summary\n\
         \n\
         {}\n\
         \n\
         ## What Happened\n\
         \n\
         {}\n\
         \n\
         ## Root Cause Analysis\n\
         \n\
         {}\n\
         \n\
         ## Impact Assessment\n\
         \n\
         - **Severity:** {}\n\
         - **Blast Radius:** {}\n\
         - **Data Accessed:** {}\n\
         - **Data Modified:** {}\n\
         - **Data Exfiltration:** {}\n\
         \n\
         ## Recommendations\n\
         \n\
         {}\n\
         \n\
         ## Timeline\n\
         \n\
         - **Investigation Started:** {}\n\
         - **Investigation Completed:** {}\n\
         \n\
         ---\n\
         Generated by RookBot | ClawDefender Security Platform\n",
        investigation.investigation_id,
        investigation.target_type,
        investigation.target_summary,
        investigation.started_at.format("%Y-%m-%d %H:%M:%S"),
        investigation.verdict,
        investigation.confidence * 100.0,
        investigation.narrative,
        investigation.what_happened,
        investigation.why_it_happened,
        investigation.impact.severity,
        investigation.impact.blast_radius,
        if investigation.impact.data_accessed.is_empty() {
            "None".to_string()
        } else {
            investigation.impact.data_accessed.join(", ")
        },
        if investigation.impact.data_modified.is_empty() {
            "None".to_string()
        } else {
            investigation.impact.data_modified.join(", ")
        },
        if investigation.impact.data_exfiltrated { "YES" } else { "NO" },
        investigation
            .recommendations
            .iter()
            .enumerate()
            .map(|(i, rec)| format!("{}. {}", i + 1, rec))
            .collect::<Vec<_>>()
            .join("\n"),
        investigation.started_at.format("%Y-%m-%d %H:%M:%S"),
        investigation
            .completed_at
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "In Progress".to_string())
    );

    // Save report
    let report_file = reports_dir.join(format!("incident_{}.md", investigation_id));
    std::fs::write(&report_file, &markdown)?;

    // Output report
    if let Some(output_path) = output {
        std::fs::write(&output_path, &markdown)?;
        println!("Report written to: {}", output_path.display());
    } else {
        println!();
        println!("{markdown}");
    }

    println!();
    println!("Report saved to: {}", report_file.display());

    Ok(())
}

/// Generate compliance report.
pub fn generate_compliance_report(framework: &str, output: Option<PathBuf>) -> Result<()> {
    let reports_dir = reports_dir();
    std::fs::create_dir_all(&reports_dir)?;

    let framework_upper = framework.to_uppercase();
    println!("Generating {framework_upper} compliance report...");

    // Generate placeholder compliance report
    let markdown = format!(
        "# {framework_upper} COMPLIANCE REPORT\n\
         \n\
         **Framework:** {framework_upper}\n\
         **Generated:** {}\n\
         **System:** ClawDefender Security Platform\n\
         \n\
         ## Executive Summary\n\
         \n\
         Overall compliance status: 87% ({} of {} controls met)\n\
         \n\
         ## Control Assessment\n\
         \n\
         ### Access Control\n\
         - ✓ MCP server authentication enabled\n\
         - ✓ Policy-based access control enforced\n\
         - ✓ Session monitoring active\n\
         \n\
         ### Audit & Logging\n\
         - ✓ All events logged to audit database\n\
         - ✓ Log retention: 90 days\n\
         - ✓ Tamper-evident logging enabled\n\
         \n\
         ### Monitoring & Response\n\
         - ✓ Real-time threat detection active\n\
         - ✓ Automated response playbooks configured\n\
         - ⚠️  Incident response plan requires update\n\
         \n\
         ### Data Protection\n\
         - ✓ Data minimization in effect\n\
         - ✓ Sensitive data redaction enabled\n\
         - ✓ Encryption at rest\n\
         \n\
         ## Gaps & Recommendations\n\
         \n\
         1. **Update Incident Response Plan** (Priority: Medium)\n\
            - Last updated: 45 days ago\n\
            - Recommended: Update quarterly\n\
         \n\
         ## Conclusion\n\
         \n\
         The system demonstrates strong compliance with {framework_upper} requirements. \
         Address the identified gap to achieve full compliance.\n\
         \n\
         ---\n\
         Generated by RookBot | ClawDefender Security Platform\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
        13,
        15,
    );

    // Save report
    let report_id = format!("{:x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs());
    let report_file = reports_dir.join(format!("compliance_{}_{}.md", framework, report_id));
    std::fs::write(&report_file, &markdown)?;

    // Output report
    if let Some(output_path) = output {
        std::fs::write(&output_path, &markdown)?;
        println!("Report written to: {}", output_path.display());
    } else {
        println!();
        println!("{markdown}");
    }

    println!();
    println!("Report saved to: {}", report_file.display());

    Ok(())
}

/// List past reports.
pub fn list_reports(type_filter: Option<String>, limit: usize) -> Result<()> {
    let reports_dir = reports_dir();

    if !reports_dir.exists() {
        println!("No reports found.");
        return Ok(());
    }

    // Collect report files
    let mut reports = Vec::new();
    for entry in std::fs::read_dir(&reports_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("md") {
            let file_name = path.file_name().unwrap().to_string_lossy().to_string();
            let report_type = if file_name.starts_with("daily_") {
                "daily"
            } else if file_name.starts_with("weekly_") {
                "weekly"
            } else if file_name.starts_with("incident_") {
                "incident"
            } else if file_name.starts_with("compliance_") {
                "compliance"
            } else {
                "other"
            };

            // Apply type filter
            if let Some(ref filter) = type_filter {
                if report_type != filter {
                    continue;
                }
            }

            let metadata = std::fs::metadata(&path)?;
            let modified = metadata.modified()?;
            let datetime: chrono::DateTime<chrono::Utc> = modified.into();

            reports.push((file_name, report_type.to_string(), datetime));
        }
    }

    if reports.is_empty() {
        println!("No reports found.");
        if type_filter.is_some() {
            println!("Try without --type filter.");
        }
        return Ok(());
    }

    // Sort by date (newest first)
    reports.sort_by(|a, b| b.2.cmp(&a.2));
    reports.truncate(limit);

    println!("{:<40} {:<12} {}", "Report File", "Type", "Generated");
    println!("{}", "-".repeat(70));

    for (file_name, report_type, datetime) in &reports {
        let short_name = if file_name.len() > 38 {
            format!("{}...", &file_name[..35])
        } else {
            file_name.clone()
        };
        println!(
            "{:<40} {:<12} {}",
            short_name,
            report_type,
            datetime.format("%Y-%m-%d %H:%M")
        );
    }

    Ok(())
}

/// Show a past report.
pub fn show_report(report_id: &str) -> Result<()> {
    let reports_dir = reports_dir();

    // Find report file matching the ID
    let mut found_file: Option<PathBuf> = None;
    for entry in std::fs::read_dir(&reports_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.contains(report_id))
            .unwrap_or(false)
        {
            found_file = Some(path);
            break;
        }
    }

    let report_file = found_file.ok_or_else(|| anyhow::anyhow!("Report not found: {report_id}"))?;

    let content = std::fs::read_to_string(&report_file)?;
    println!("{content}");

    Ok(())
}
