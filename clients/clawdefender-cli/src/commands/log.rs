//! `clawdefender log` — view audit log entries.

use anyhow::{Context, Result};
use clawdefender_core::audit::logger::FileAuditLogger;
use clawdefender_core::audit::{AuditFilter, AuditLogger};
use clawdefender_core::config::settings::LogRotation;
use clawdefender_core::config::ClawConfig;

pub fn run(
    config: &ClawConfig,
    blocked: bool,
    server: Option<String>,
    stats: bool,
    n: usize,
) -> Result<()> {
    let log_path = &config.audit_log_path;

    if !log_path.exists() {
        println!("No audit log found at {}", log_path.display());
        println!("The audit log is created when the ClawDefender proxy processes events.");
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

    if stats {
        let s = logger.stats()?;
        println!("Audit Log Statistics");
        println!("  Total events:  {}", s.total_events);
        println!("  Allowed:       {}", s.allowed);
        println!("  Blocked:       {}", s.blocked);
        println!("  Prompted:      {}", s.prompted);
        println!("  Logged:        {}", s.logged);

        if !s.by_source.is_empty() {
            println!();
            println!("  By source:");
            let mut sources: Vec<_> = s.by_source.iter().collect();
            sources.sort_by(|a, b| b.1.cmp(a.1));
            for (source, count) in sources {
                println!("    {:<20} {}", source, count);
            }
        }

        if !s.unique_servers.is_empty() {
            println!();
            println!("  Servers: {}", s.unique_servers.join(", "));
        }

        return Ok(());
    }

    let action_filter = if blocked {
        Some("block".to_string())
    } else {
        None
    };

    let filter = AuditFilter {
        from: None,
        to: None,
        source: server,
        action: action_filter,
        limit: n,
    };

    let records = logger.query(&filter)?;

    if records.is_empty() {
        println!("No audit records found.");
        return Ok(());
    }

    println!(
        "  {:<20} {:<8} {:<16} {:<12} SUMMARY",
        "TIMESTAMP", "ACTION", "SERVER", "METHOD"
    );
    println!("  {}", "-".repeat(80));

    for record in &records {
        let ts = record.timestamp.format("%Y-%m-%d %H:%M:%S");
        let action = if record.action_taken.is_empty() {
            "-"
        } else {
            &record.action_taken
        };
        let server_name = record
            .server_name
            .as_deref()
            .unwrap_or("-");
        let method = record
            .jsonrpc_method
            .as_deref()
            .unwrap_or("-");

        let summary = if record.event_summary.len() > 30 {
            format!("{}...", &record.event_summary[..27])
        } else {
            record.event_summary.clone()
        };

        println!(
            "  {:<20} {:<8} {:<16} {:<12} {}",
            ts, action, server_name, method, summary,
        );
    }

    println!();
    println!("  Showing {} record(s)", records.len());

    Ok(())
}
