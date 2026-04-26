//! `rookbot watch` — live event stream monitoring.
//!
//! Displays security events in real-time as they occur, similar to `tail -f`.

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Args;
use clawdefender_core::audit::logger::FileAuditLogger;
use clawdefender_core::audit::{AuditFilter, AuditLogger};
use clawdefender_core::config::settings::LogRotation;
use clawdefender_core::config::ClawConfig;
use std::thread;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct WatchArgs {
    /// Filter expression (e.g. "path contains .ssh").
    #[arg(long)]
    filter: Option<String>,
    /// Show events from a specific MCP server only.
    #[arg(long)]
    server: Option<String>,
    /// Filter by risk level: routine, notable, suspicious.
    #[arg(long)]
    risk: Option<String>,
    /// Hide routine events (show notable + suspicious only).
    #[arg(long)]
    no_routine: bool,
}

/// Main entry point for the `watch` command.
pub fn run(config: &ClawConfig, args: &WatchArgs) -> Result<()> {
    let log_path = &config.audit_log_path;

    if !log_path.exists() {
        println!("No audit log found at {}", log_path.display());
        println!("The audit log is created when the ClawDefender proxy processes events.");
        println!("Waiting for events...");
    }

    let logger = FileAuditLogger::new(
        log_path.to_path_buf(),
        LogRotation {
            max_size_mb: 0,
            max_files: 0,
        },
    )
    .with_context(|| format!("opening audit log: {}", log_path.display()))?;

    println!("Watching for security events... (Press Ctrl+C to exit)");
    println!();
    println!(
        "  {:<8} {:<16} {:<20} {:<12} {:<12} SUMMARY",
        "TIME", "RISK", "SERVER", "METHOD", "ACTION"
    );
    println!("  {}", "-".repeat(90));

    let mut last_offset = 0;

    loop {
        // Poll the audit log for new records.
        let filter = AuditFilter {
            from: None,
            to: None,
            source: args.server.clone(),
            action: None,
            limit: 1000, // Read recent records.
        };

        let records = logger.query(&filter)?;

        // Show only new records since last poll.
        let new_records = if records.len() > last_offset {
            &records[last_offset..]
        } else {
            &[]
        };

        for record in new_records {
            // Apply filtering.
            if args.no_routine && !is_notable_or_suspicious(&record.event_summary) {
                continue;
            }
            if let Some(ref risk_level) = args.risk {
                if !matches_risk_level(&record.event_summary, risk_level) {
                    continue;
                }
            }
            if let Some(ref filter_expr) = args.filter {
                if !record.event_summary.contains(filter_expr) {
                    continue;
                }
            }

            // Display the event in compact format.
            let time = record.timestamp.format("%H:%M:%S");
            let risk = infer_risk_level(&record.event_summary, &record.action_taken);
            let server_name = record.server_name.as_deref().unwrap_or("-");
            let method = record.jsonrpc_method.as_deref().unwrap_or("-");
            let action = if record.action_taken.is_empty() {
                "-"
            } else {
                &record.action_taken
            };

            let summary = if record.event_summary.len() > 30 {
                format!("{}...", &record.event_summary[..27])
            } else {
                record.event_summary.clone()
            };

            println!(
                "  {:<8} {:<16} {:<20} {:<12} {:<12} {}",
                time, risk, server_name, method, action, summary
            );
        }

        last_offset = records.len();

        // Poll every 500ms.
        // Note: Ctrl+C will interrupt the sleep and exit naturally
        thread::sleep(Duration::from_millis(500));
    }
}

/// Infer risk level from event summary and action.
fn infer_risk_level(summary: &str, action: &str) -> &'static str {
    let summary_lower = summary.to_lowercase();
    if action == "block" || summary_lower.contains("blocked") || summary_lower.contains("denied") {
        return "SUSPICIOUS";
    }
    if summary_lower.contains("prompt")
        || summary_lower.contains("review")
        || summary_lower.contains("warning")
    {
        return "NOTABLE";
    }
    "ROUTINE"
}

/// Check if a record is notable or suspicious.
fn is_notable_or_suspicious(summary: &str) -> bool {
    let summary_lower = summary.to_lowercase();
    summary_lower.contains("block")
        || summary_lower.contains("deny")
        || summary_lower.contains("prompt")
        || summary_lower.contains("review")
        || summary_lower.contains("warning")
        || summary_lower.contains("suspicious")
}

/// Check if a record matches the given risk level.
fn matches_risk_level(summary: &str, risk: &str) -> bool {
    let inferred = infer_risk_level(summary, "");
    inferred.to_lowercase() == risk.to_lowercase()
}
