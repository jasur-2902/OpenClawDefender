//! `rookbot watch` — live event stream monitoring.
//!
//! Displays security events in real-time as they occur, similar to `tail -f`.

use anyhow::{Context, Result};
use clap::Args;
use clawdefender_core::audit::logger::FileAuditLogger;
use clawdefender_core::audit::{AuditFilter, AuditLogger, AuditRecord};
use clawdefender_core::config::settings::LogRotation;
use clawdefender_core::config::ClawConfig;
use std::thread;
use std::time::Duration;

use crate::output::{ansi_bold, ansi_dim, ansi_green, ansi_red, ansi_yellow, supports_color};

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
    let color = supports_color();

    if !log_path.exists() {
        if color {
            println!("\n  {}  {}", "\u{1f4cb}", ansi_bold("No events recorded yet."));
        } else {
            println!("\n  No events recorded yet.");
        }
        println!();
        println!("   The audit log is created when Rookbot processes events.");
        println!("   To get started:");
        println!("     1. Start the daemon:  {}", if color { ansi_dim("rookbot daemon start") } else { "rookbot daemon start".to_string() });
        println!("     2. Wrap a server:     {}", if color { ansi_dim("rookbot wrap <server-name>") } else { "rookbot wrap <server-name>".to_string() });
        println!("     3. Or try demo mode:  {}", if color { ansi_dim("rookbot demo start") } else { "rookbot demo start".to_string() });
        println!();
        println!("   Waiting for events...");
        println!();
    }

    let logger = FileAuditLogger::new(
        log_path.to_path_buf(),
        LogRotation {
            max_size_mb: 0,
            max_files: 0,
        },
    )
    .with_context(|| format!("opening audit log: {}", log_path.display()))?;

    if color {
        println!(
            "{} (Ctrl+C to exit)",
            ansi_bold("Watching for security events...")
        );
    } else {
        println!("Watching for security events... (Ctrl+C to exit)");
    }
    println!();

    // Column header
    println!(
        "  {:<10} {:<14} {:<22} {:<10} {}",
        "TIME", "RISK", "SOURCE", "ACTION", "WHAT HAPPENED"
    );
    let sep = "\u{2500}";
    println!(
        "  {}  {}  {}  {}  {}",
        sep.repeat(8),
        sep.repeat(12),
        sep.repeat(20),
        sep.repeat(8),
        sep.repeat(35)
    );

    // Track the most recent timestamp we've shown, so we only display NEW events.
    // Start with "now" so we skip all historical events.
    let mut last_shown_ts = chrono::Utc::now();
    // Also track event summaries in last batch to deduplicate.
    let mut shown_set: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        // Poll the audit log for events newer than our last shown timestamp.
        let filter = AuditFilter {
            from: Some(last_shown_ts - chrono::Duration::seconds(1)),
            to: None,
            source: args.server.clone(),
            action: None,
            limit: 200,
        };

        let records = logger.query(&filter)?;

        // Filter to only truly new events (newer than last_shown_ts).
        // The query returns most-recent-first, so reverse for chronological display.
        let mut new_records: Vec<&AuditRecord> = records
            .iter()
            .filter(|r| r.timestamp > last_shown_ts)
            .collect();
        new_records.sort_by_key(|r| r.timestamp);

        for record in &new_records {
            // Apply filtering.
            let risk = infer_risk_level(record);
            if args.no_routine && risk == "ROUTINE" {
                continue;
            }
            if let Some(ref risk_level) = args.risk {
                if risk.to_lowercase() != risk_level.to_lowercase() {
                    continue;
                }
            }
            if let Some(ref filter_expr) = args.filter {
                if !record.event_summary.contains(filter_expr) {
                    continue;
                }
            }

            // Deduplicate: skip if we already showed this exact event in this batch.
            let dedup_key = format!("{}:{}", record.timestamp, record.event_summary);
            if shown_set.contains(&dedup_key) {
                continue;
            }
            shown_set.insert(dedup_key);

            print_event(record, risk, color);

            if record.timestamp > last_shown_ts {
                last_shown_ts = record.timestamp;
            }
        }

        // Keep shown_set from growing unbounded.
        if shown_set.len() > 500 {
            shown_set.clear();
        }

        // Poll every 500ms.
        thread::sleep(Duration::from_millis(500));
    }
}

/// Print a single event row with color coding.
fn print_event(record: &AuditRecord, risk: &str, color: bool) {
    let time = record.timestamp.format("%H:%M:%S").to_string();
    let server_name = record.server_name.as_deref().unwrap_or("-");
    let action = if record.action_taken.is_empty() {
        "-"
    } else {
        &record.action_taken
    };

    // Build the summary: prefer tool_name + key arg over event_summary
    let summary = build_summary(record);

    if color {
        // Risk badge with color
        let risk_badge = match risk {
            "SUSPICIOUS" => ansi_red(&format!("\u{25cf} {:<10}", risk)),
            "NOTABLE" => ansi_yellow(&format!("\u{25b2} {:<10}", risk)),
            _ => ansi_green(&format!("\u{25a0} {:<10}", risk)),
        };

        // Action indicator with color
        let action_display = match action {
            "allow" => ansi_green(&format!("\u{2713} {}", action)),
            "block" => ansi_red(&format!("\u{2717} {}", action)),
            "prompt" => ansi_yellow(&format!("? {}", action)),
            "log" => ansi_dim(&format!("  {}", action)),
            other => format!("  {}", other),
        };

        println!(
            "  {:<10} {}  {:<20} {:<10} {}",
            ansi_dim(&time),
            risk_badge,
            server_name,
            action_display,
            summary,
        );
    } else {
        // No-color fallback
        let risk_badge = match risk {
            "SUSPICIOUS" => format!("! {:<10}", risk),
            "NOTABLE" => format!("^ {:<10}", risk),
            _ => format!("  {:<10}", risk),
        };

        let action_display = match action {
            "allow" => format!("+ {}", action),
            "block" => format!("x {}", action),
            "prompt" => format!("? {}", action),
            other => format!("  {}", other),
        };

        println!(
            "  {:<10} {}  {:<20} {:<10} {}",
            time, risk_badge, server_name, action_display, summary,
        );
    }
}

/// Build a human-friendly summary from the audit record.
fn build_summary(record: &AuditRecord) -> String {
    // If we have a tool_name, use it as the primary label
    if let Some(ref tool) = record.tool_name {
        // Try to extract a key argument for context
        if let Some(ref args) = record.arguments {
            if let Some(path) = args.get("path").and_then(|v| v.as_str()) {
                return format!("{} {}", tool, shorten_path(path));
            }
            if let Some(query) = args.get("query").and_then(|v| v.as_str()) {
                let short = if query.len() > 40 {
                    format!("\"{}...\"", &query[..37])
                } else {
                    format!("\"{}\"", query)
                };
                return format!("{} {}", tool, short);
            }
            if let Some(cmd) = args.get("command").and_then(|v| v.as_str()) {
                let short = if cmd.len() > 40 {
                    format!("{}...", &cmd[..37])
                } else {
                    cmd.to_string()
                };
                return format!("{} {}", tool, short);
            }
            if let Some(url) = args.get("url").and_then(|v| v.as_str()) {
                let short = if url.len() > 50 {
                    format!("{}...", &url[..47])
                } else {
                    url.to_string()
                };
                return format!("{} {}", tool, short);
            }
        }
        return tool.clone();
    }

    // Fall back to event_summary, but don't truncate aggressively
    if record.event_summary.len() > 60 {
        format!("{}...", &record.event_summary[..57])
    } else {
        record.event_summary.clone()
    }
}

/// Shorten a file path by replacing HOME with ~.
fn shorten_path(path: &str) -> String {
    if let Some(home) = std::env::var("HOME").ok() {
        if path.starts_with(&home) {
            return format!("~{}", &path[home.len()..]);
        }
    }
    path.to_string()
}

/// Infer risk level from an audit record, checking SLM analysis and classification first.
fn infer_risk_level(record: &AuditRecord) -> &'static str {
    // Check SLM analysis first (most accurate)
    if let Some(ref slm) = record.slm_analysis {
        return match slm.risk_level.to_uppercase().as_str() {
            "HIGH" | "CRITICAL" => "SUSPICIOUS",
            "MEDIUM" => "NOTABLE",
            _ => "ROUTINE",
        };
    }
    // Check classification field
    if let Some(ref class) = record.classification {
        return match class.as_str() {
            "block" => "SUSPICIOUS",
            "review" => "NOTABLE",
            _ => "ROUTINE",
        };
    }
    // Fall back to keyword matching on summary + action
    let summary_lower = record.event_summary.to_lowercase();
    if record.action_taken == "block"
        || summary_lower.contains("blocked")
        || summary_lower.contains("denied")
    {
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
