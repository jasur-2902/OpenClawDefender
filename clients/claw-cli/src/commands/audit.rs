//! `clawai audit show` and `clawai audit stats` commands.

use std::path::Path;

use anyhow::{Context, Result};
use claw_core::audit::logger::FileAuditLogger;
use claw_core::audit::{AuditFilter, AuditLogger};
use claw_core::config::settings::LogRotation;

/// Show recent audit log entries.
pub fn show(
    log_path: &Path,
    limit: usize,
    source: Option<String>,
    action: Option<String>,
) -> Result<()> {
    if !log_path.exists() {
        println!("No audit log found at {}", log_path.display());
        println!("The audit log is created when the ClawAI proxy processes events.");
        return Ok(());
    }

    let logger = FileAuditLogger::new(
        log_path.to_path_buf(),
        LogRotation {
            max_size_mb: 0, // read-only, no rotation
            max_files: 0,
        },
    )
    .with_context(|| format!("opening audit log: {}", log_path.display()))?;

    let filter = AuditFilter {
        from: None,
        to: None,
        source,
        action,
        limit,
    };

    let records = logger.query(&filter)?;

    if records.is_empty() {
        println!("No audit records found.");
        return Ok(());
    }

    println!(
        "  {:<24} {:<14} {:<8} SUMMARY",
        "TIMESTAMP", "SOURCE", "ACTION"
    );
    println!("  {}", "-".repeat(76));

    for record in &records {
        let ts = record.timestamp.format("%Y-%m-%d %H:%M:%S");
        let action = if record.action_taken.is_empty() {
            "-"
        } else {
            &record.action_taken
        };
        // Truncate summary to fit nicely.
        let summary = if record.event_summary.len() > 40 {
            format!("{}...", &record.event_summary[..37])
        } else {
            record.event_summary.clone()
        };
        println!("  {:<24} {:<14} {:<8} {}", ts, record.source, action, summary);
    }

    println!();
    println!("  Showing {} of the most recent records", records.len());

    Ok(())
}

/// Show aggregate audit statistics.
pub fn stats(log_path: &Path) -> Result<()> {
    if !log_path.exists() {
        println!("No audit log found at {}", log_path.display());
        return Ok(());
    }

    let logger = FileAuditLogger::new(
        log_path.to_path_buf(),
        LogRotation {
            max_size_mb: 0,
            max_files: 0,
        },
    )
    .with_context(|| format!("opening audit log: {}", log_path.display()))?;

    let stats = logger.stats()?;

    println!("Audit Log Statistics");
    println!("  Total events:  {}", stats.total_events);
    println!("  Allowed:       {}", stats.allowed);
    println!("  Blocked:       {}", stats.blocked);
    println!("  Prompted:      {}", stats.prompted);

    if !stats.by_source.is_empty() {
        println!();
        println!("  By source:");
        let mut sources: Vec<_> = stats.by_source.iter().collect();
        sources.sort_by(|a, b| b.1.cmp(a.1));
        for (source, count) in sources {
            println!("    {:<20} {}", source, count);
        }
    }

    Ok(())
}
