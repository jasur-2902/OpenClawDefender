//! `rookbot investigate` — AI-powered investigation from the terminal.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Result};
use clap::Subcommand;

use clawdefender_swarm::investigation_store::InvestigationStore;
use clawdefender_swarm::investigation_tools::{InvestigationDepth, InvestigationTarget};
use clawdefender_swarm::keychain;

#[derive(Subcommand, Debug)]
pub enum InvestigateAction {
    /// Launch an investigation on an event, alert, or server.
    Run {
        /// Event ID, alert ID, or server name to investigate.
        target: String,
        /// Investigation depth: quick, standard, deep.
        #[arg(long, default_value = "standard")]
        depth: String,
    },
    /// List past investigations.
    List {
        #[arg(long, default_value = "20")]
        limit: usize,
        #[arg(long)]
        verdict: Option<String>,
    },
    /// Show a past investigation.
    Show { investigation_id: String },
    /// Resume a paused investigation.
    Resume { investigation_id: String },
}

/// Default investigation store directory: ~/.local/share/rookbot/investigations/
fn investigations_dir() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME not set");
    PathBuf::from(home)
        .join(".local/share/rookbot/investigations")
}

/// Parse investigation depth from string.
fn parse_depth(depth: &str) -> Result<InvestigationDepth> {
    match depth.to_lowercase().as_str() {
        "quick" => Ok(InvestigationDepth::Quick),
        "standard" => Ok(InvestigationDepth::Standard),
        "deep" => Ok(InvestigationDepth::Deep),
        _ => bail!("Invalid depth: {depth}. Use quick, standard, or deep."),
    }
}

/// Run an investigation.
pub async fn run_investigation(target: &str, depth: &str) -> Result<()> {
    let depth = parse_depth(depth)?;

    // Check for API key if not using quick mode with local SLM
    let keystore = keychain::default_keystore();
    let has_api_key = keystore.get(&keychain::Provider::Anthropic).is_ok();

    if !has_api_key && depth != InvestigationDepth::Quick {
        bail!(
            "Cloud API key required for {:?} investigations.\n\
             Configure with: rookbot cloud setup\n\
             Or use --depth quick for local-only analysis.",
            depth
        );
    }

    println!("Starting investigation on: {target}");
    println!("Depth: {:?}", depth);
    println!();

    // Parse target type
    let investigation_target = if target.starts_with("event-") {
        InvestigationTarget::Event {
            event_id: target.to_string(),
            event_data: serde_json::json!({"id": target}),
        }
    } else if target.starts_with("alert-") {
        InvestigationTarget::Alert {
            alert_id: target.to_string(),
            alert_data: serde_json::json!({"id": target}),
        }
    } else {
        InvestigationTarget::Server {
            server_name: target.to_string(),
        }
    };

    // Placeholder implementation - InvestigationEngine not yet fully available
    println!("⚠️  Investigation engine is not yet fully implemented.");
    println!("Investigation functionality coming soon.");
    println!();
    println!("Target: {target}");
    println!("Depth: {:?}", depth);
    println!();
    println!("This would launch an AI-powered investigation to:");
    println!("  1. Gather related events and context");
    println!("  2. Analyze behavioral patterns");
    println!("  3. Determine what happened and why");
    println!("  4. Assess impact and blast radius");
    println!("  5. Provide actionable recommendations");

    return Ok(());

}

/// List past investigations.
pub fn list_investigations(limit: usize, verdict_filter: Option<String>) -> Result<()> {
    let mut store = InvestigationStore::with_dir(investigations_dir())?;

    let mut query = clawdefender_swarm::investigation_store::InvestigationSearchQuery::default();
    query.limit = Some(limit);
    if let Some(ref verdict) = verdict_filter {
        query.verdict = Some(verdict.clone());
    }

    let mut investigations = store.list(Some(&query));


    if investigations.is_empty() {
        println!("No investigations found.");
        if verdict_filter.is_some() {
            println!("Try without --verdict filter.");
        }
        return Ok(());
    }

    println!("{:<24} {:<16} {:<20} {:<12} {:<8}", "ID", "Target", "Summary", "Verdict", "Confidence");
    println!("{}", "-".repeat(90));

    for inv in &investigations {
        let short_id = if inv.id.len() > 22 {
            format!("{}...", &inv.id[..19])
        } else {
            inv.id.clone()
        };
        let short_summary = if inv.narrative_preview.len() > 18 {
            format!("{}...", &inv.narrative_preview[..15])
        } else {
            inv.narrative_preview.clone()
        };
        println!(
            "{:<24} {:<16} {:<20} {:<12} {:<7.0}%",
            short_id,
            inv.target_id,
            short_summary,
            format!("{:?}", inv.verdict),
            inv.confidence * 100.0
        );
    }

    Ok(())
}

/// Show a past investigation.
pub fn show_investigation(investigation_id: &str) -> Result<()> {
    let store = InvestigationStore::with_dir(investigations_dir())?;

    let result = store.load(investigation_id)?;

    println!("Investigation: {}", result.investigation_id);
    println!("Target: {} - {}", result.target_type, result.target_summary);
    println!("Depth: {}", result.depth);
    println!("Started: {}", result.started_at.format("%Y-%m-%d %H:%M:%S"));
    if let Some(completed_at) = result.completed_at {
        println!("Completed: {}", completed_at.format("%Y-%m-%d %H:%M:%S"));
    }
    println!();
    println!("Verdict: {:?}", result.verdict);
    println!("Confidence: {:.0}%", result.confidence * 100.0);
    println!();
    println!("═══ Narrative ═══");
    println!("{}", result.narrative);
    println!();
    println!("═══ What Happened ═══");
    println!("{}", result.what_happened);
    println!();
    println!("═══ Why It Happened ═══");
    println!("{}", result.why_it_happened);
    println!();
    if let Some(part_of_larger) = &result.part_of_larger {
        println!("═══ Part of Larger Pattern ═══");
        println!("{part_of_larger}");
        println!();
    }
    println!("═══ Impact ═══");
    println!("Severity: {}", result.impact.severity);
    println!("Blast Radius: {}", result.impact.blast_radius);
    if !result.impact.data_accessed.is_empty() {
        println!("Data Accessed:");
        for item in &result.impact.data_accessed {
            println!("  - {item}");
        }
    }
    if !result.impact.data_modified.is_empty() {
        println!("Data Modified:");
        for item in &result.impact.data_modified {
            println!("  - {item}");
        }
    }
    if result.impact.data_exfiltrated {
        println!("⚠️  Data Exfiltration: YES");
    }
    println!();
    println!("═══ Recommendations ═══");
    for (i, rec) in result.recommendations.iter().enumerate() {
        println!("{}. {rec}", i + 1);
    }
    println!();
    println!("Tool Calls: {}", result.total_tool_calls);
    println!("Tokens: {} in, {} out", result.total_input_tokens, result.total_output_tokens);
    println!("Cost: ${:.4}", result.estimated_cost_usd);

    Ok(())
}

/// Resume a paused investigation.
pub async fn resume_investigation(investigation_id: &str) -> Result<()> {
    println!("Resuming investigation: {investigation_id}");
    println!("⚠️  Resume functionality coming soon.");
    println!("For now, start a new investigation on the same target.");
    Ok(())
}

/// Get a human-readable summary of an investigation target.
fn target_summary(target: &InvestigationTarget) -> String {
    match target {
        InvestigationTarget::Event { event_id, .. } => format!("Event: {event_id}"),
        InvestigationTarget::Alert { alert_id, .. } => format!("Alert: {alert_id}"),
        InvestigationTarget::Server { server_name } => format!("Server: {server_name}"),
        InvestigationTarget::TimeRange { start, end } => {
            format!("Time Range: {} to {}", start.format("%Y-%m-%d"), end.format("%Y-%m-%d"))
        }
        InvestigationTarget::Freeform { query } => format!("Query: {query}"),
    }
}
