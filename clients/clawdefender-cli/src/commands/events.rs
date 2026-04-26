//! `rookbot events` — query and view historical security events.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use clap::Subcommand;
use clawdefender_core::audit::logger::FileAuditLogger;
use clawdefender_core::audit::{AuditFilter, AuditLogger};
use clawdefender_core::config::settings::LogRotation;
use clawdefender_core::config::ClawConfig;

#[derive(Subcommand, Debug)]
pub enum EventsAction {
    /// Query historical events (default: last 50).
    List {
        #[arg(long, default_value = "50")]
        last: usize,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        risk: Option<String>,
        #[arg(long)]
        search: Option<String>,
    },
    /// Show full detail for a specific event.
    Detail { event_id: String },
    /// Show event statistics.
    Stats {
        #[arg(long)]
        period: Option<String>,
    },
}

/// Main entry point for the `events` command.
pub fn run(config: &ClawConfig, action: &EventsAction) -> Result<()> {
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

    match action {
        EventsAction::List {
            last,
            since,
            server,
            risk,
            search,
        } => {
            let from = if let Some(ref since_str) = since {
                Some(parse_time_offset(since_str)?)
            } else {
                None
            };

            let filter = AuditFilter {
                from,
                to: None,
                source: server.clone(),
                action: None,
                limit: *last,
            };

            let records = logger.query(&filter)?;

            if records.is_empty() {
                println!("No events found.");
                return Ok(());
            }

            // Apply additional filters.
            let filtered: Vec<_> = records
                .iter()
                .filter(|r| {
                    if let Some(ref risk_level) = risk {
                        let inferred = infer_risk_level(&r.event_summary, &r.action_taken);
                        if inferred.to_lowercase() != risk_level.to_lowercase() {
                            return false;
                        }
                    }
                    if let Some(ref search_term) = search {
                        if !r.event_summary.contains(search_term) {
                            return false;
                        }
                    }
                    true
                })
                .collect();

            if filtered.is_empty() {
                println!("No events matched the filters.");
                return Ok(());
            }

            println!(
                "  {:<20} {:<16} {:<16} {:<12} SUMMARY",
                "TIMESTAMP", "RISK", "SERVER", "METHOD"
            );
            println!("  {}", "-".repeat(80));

            for record in &filtered {
                let ts = record.timestamp.format("%Y-%m-%d %H:%M:%S");
                let risk = infer_risk_level(&record.event_summary, &record.action_taken);
                let server_name = record.server_name.as_deref().unwrap_or("-");
                let method = record.jsonrpc_method.as_deref().unwrap_or("-");

                let summary = if record.event_summary.len() > 30 {
                    format!("{}...", &record.event_summary[..27])
                } else {
                    record.event_summary.clone()
                };

                println!(
                    "  {:<20} {:<16} {:<16} {:<12} {}",
                    ts, risk, server_name, method, summary
                );
            }

            println!();
            println!("  Showing {} event(s)", filtered.len());
        }

        EventsAction::Detail { event_id } => {
            let filter = AuditFilter {
                from: None,
                to: None,
                source: None,
                action: None,
                limit: 10000,
            };

            let records = logger.query(&filter)?;
            let record = records
                .iter()
                .find(|r| {
                    r.session_id
                        .as_ref()
                        .map(|id| id.contains(event_id))
                        .unwrap_or(false)
                })
                .context("Event ID not found")?;

            println!("Event Detail");
            println!("  Timestamp:     {}", record.timestamp.to_rfc3339());
            println!("  Source:        {}", record.source);
            println!(
                "  Server:        {}",
                record.server_name.as_deref().unwrap_or("-")
            );
            println!(
                "  Method:        {}",
                record.jsonrpc_method.as_deref().unwrap_or("-")
            );
            println!("  Action:        {}", record.action_taken);
            println!("  Summary:       {}", record.event_summary);
            if let Some(ref rule) = record.rule_matched {
                println!("  Rule Matched:  {}", rule);
            }
            if let Some(ref decision) = record.user_decision {
                println!("  User Decision: {}", decision);
            }
            println!();
            println!("Event Details:");
            println!("{}", serde_json::to_string_pretty(&record.event_details)?);
        }

        EventsAction::Stats { period } => {
            let stats = logger.stats()?;

            let period_label = period.as_deref().unwrap_or("all time");
            println!("Event Statistics ({})", period_label);
            println!();
            println!("  Total events:  {}", stats.total_events);
            println!("  Allowed:       {}", stats.allowed);
            println!("  Blocked:       {}", stats.blocked);
            println!("  Prompted:      {}", stats.prompted);
            println!("  Logged:        {}", stats.logged);

            if !stats.by_source.is_empty() {
                println!();
                println!("  By source:");
                let mut sources: Vec<_> = stats.by_source.iter().collect();
                sources.sort_by(|a, b| b.1.cmp(a.1));
                for (source, count) in sources {
                    println!("    {:<20} {}", source, count);
                }
            }

            if !stats.unique_servers.is_empty() {
                println!();
                println!("  Active servers: {}", stats.unique_servers.join(", "));
            }

            if !stats.unique_tools.is_empty() {
                println!();
                println!("  Unique tools:   {}", stats.unique_tools.len());
            }

            if !stats.top_blocked_tools.is_empty() {
                println!();
                println!("  Top blocked tools:");
                for (tool, count) in &stats.top_blocked_tools {
                    println!("    {:<30} {}", tool, count);
                }
            }

            if !stats.top_blocked_paths.is_empty() {
                println!();
                println!("  Top blocked paths:");
                for (path, count) in &stats.top_blocked_paths {
                    println!("    {:<40} {}", path, count);
                }
            }
        }
    }

    Ok(())
}

/// Parse a time offset string like "1h", "30m", "2d" into a DateTime.
fn parse_time_offset(offset: &str) -> Result<DateTime<Utc>> {
    let offset = offset.trim();
    let (num_str, unit) = if let Some(stripped) = offset.strip_suffix('h') {
        (stripped, "hours")
    } else if let Some(stripped) = offset.strip_suffix('m') {
        (stripped, "minutes")
    } else if let Some(stripped) = offset.strip_suffix('d') {
        (stripped, "days")
    } else {
        anyhow::bail!(
            "Invalid time offset: {}. Use format like '1h', '30m', or '2d'",
            offset
        );
    };

    let num: i64 = num_str.parse()?;
    let duration = match unit {
        "hours" => Duration::hours(num),
        "minutes" => Duration::minutes(num),
        "days" => Duration::days(num),
        _ => unreachable!(),
    };

    Ok(Utc::now() - duration)
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
