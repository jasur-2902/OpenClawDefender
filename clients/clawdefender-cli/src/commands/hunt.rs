//! `rookbot hunt` — Proactive threat hunting from the terminal.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;

use clawdefender_swarm::keychain;
use clawdefender_swarm::threat_hunting::{HuntType, TimeRange};

#[derive(Subcommand, Debug)]
pub enum HuntAction {
    /// Run a threat hunt.
    Run {
        /// Hunt type: general, server, pattern, historical.
        #[arg(long, default_value = "general")]
        r#type: String,
        /// Server name (for server-focused hunts).
        #[arg(long)]
        server: Option<String>,
        /// Pattern to search (for pattern hunts).
        #[arg(long)]
        pattern: Option<String>,
        /// Time period: last-24h, last-7d, last-30d (for historical hunts).
        #[arg(long)]
        period: Option<String>,
    },
    /// List past hunts.
    List {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Show hunt results.
    Show { hunt_id: String },
}

/// Default hunt results directory: ~/.local/share/rookbot/hunts/
fn hunts_dir() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME not set");
    PathBuf::from(home).join(".local/share/rookbot/hunts")
}

/// Parse hunt type from arguments.
fn parse_hunt_type(
    type_str: &str,
    server: Option<String>,
    pattern: Option<String>,
    period: Option<String>,
) -> Result<HuntType> {
    match type_str.to_lowercase().as_str() {
        "general" => Ok(HuntType::GeneralSweep),
        "server" => {
            let server = server.ok_or_else(|| {
                anyhow::anyhow!("Server-focused hunt requires --server argument")
            })?;
            Ok(HuntType::ServerFocused { server })
        }
        "pattern" => {
            let pattern = pattern.ok_or_else(|| {
                anyhow::anyhow!("Pattern hunt requires --pattern argument")
            })?;
            Ok(HuntType::PatternSearch { pattern })
        }
        "historical" => {
            let period = period.unwrap_or_else(|| "last-7d".to_string());
            Ok(HuntType::HistoricalReview { period })
        }
        _ => bail!(
            "Invalid hunt type: {type_str}. Use general, server, pattern, or historical."
        ),
    }
}

/// Calculate time range from period string.
fn parse_time_range(period: &str) -> Result<TimeRange> {
    let now = chrono::Utc::now();
    let duration = match period {
        "last-24h" => chrono::Duration::hours(24),
        "last-7d" => chrono::Duration::days(7),
        "last-30d" => chrono::Duration::days(30),
        "last-90d" => chrono::Duration::days(90),
        _ => bail!("Invalid period: {period}. Use last-24h, last-7d, last-30d, or last-90d."),
    };

    Ok(TimeRange {
        start: now - duration,
        end: now,
    })
}

/// Run a threat hunt.
pub async fn run_hunt(
    type_str: &str,
    server: Option<String>,
    pattern: Option<String>,
    period: Option<String>,
) -> Result<()> {
    let hunts_dir = hunts_dir();
    std::fs::create_dir_all(&hunts_dir)?;

    // Check for API key
    let keystore = keychain::default_keystore();
    let has_api_key = keystore.get(&keychain::Provider::Anthropic).is_ok();

    if !has_api_key {
        bail!(
            "Cloud API key required for threat hunting.\n\
             Configure with: rookbot cloud setup"
        );
    }

    let hunt_type = parse_hunt_type(type_str, server, pattern, period.clone())?;

    println!("Starting threat hunt...");
    println!("Type: {}", type_str);
    match &hunt_type {
        HuntType::GeneralSweep => {},
        HuntType::ServerFocused { server } => println!("Server: {server}"),
        HuntType::PatternSearch { pattern } => println!("Pattern: {pattern}"),
        HuntType::HistoricalReview { period } => println!("Period: {period}"),
    }
    println!();

    // Placeholder implementation - HuntEngine not yet available
    println!("⚠️  Threat hunting engine is not yet implemented.");
    println!("Hunt functionality coming soon.");
    println!();
    println!("For now, use 'rookbot investigate' for deep dives on specific targets.");

    return Ok(());

}

/// List past hunts.
pub fn list_hunts(limit: usize) -> Result<()> {
    let hunts_dir = hunts_dir();

    if !hunts_dir.exists() {
        println!("No hunts found.");
        return Ok(());
    }

    // Read hunt result files
    let mut hunts = Vec::new();
    for entry in std::fs::read_dir(&hunts_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(result) =
                    serde_json::from_str::<clawdefender_swarm::threat_hunting::HuntResult>(&content)
                {
                    hunts.push(result);
                }
            }
        }
    }

    if hunts.is_empty() {
        println!("No hunts found.");
        return Ok(());
    }

    // Sort by time (newest first)
    hunts.sort_by(|a, b| b.time_range.end.cmp(&a.time_range.end));
    hunts.truncate(limit);

    println!("{:<24} {:<20} {:<12} {:<10} {:<8}", "Hunt ID", "Type", "Findings", "Patterns", "Date");
    println!("{}", "-".repeat(80));

    for hunt in &hunts {
        let short_id = if hunt.hunt_id.len() > 22 {
            format!("{}...", &hunt.hunt_id[..19])
        } else {
            hunt.hunt_id.clone()
        };
        let type_str = match &hunt.hunt_type {
            HuntType::GeneralSweep => "General".to_string(),
            HuntType::ServerFocused { server } => format!("Server: {server}"),
            HuntType::PatternSearch { pattern } => format!("Pattern: {pattern}"),
            HuntType::HistoricalReview { period } => format!("Historical: {period}"),
        };
        let type_display = if type_str.len() > 18 {
            format!("{}...", &type_str[..15])
        } else {
            type_str
        };
        println!(
            "{:<24} {:<20} {:<12} {:<10} {}",
            short_id,
            type_display,
            hunt.findings.len(),
            hunt.patterns_checked.len(),
            hunt.time_range.end.format("%Y-%m-%d")
        );
    }

    Ok(())
}

/// Show hunt results.
pub fn show_hunt(hunt_id: &str) -> Result<()> {
    let hunts_dir = hunts_dir();
    let hunt_file = hunts_dir.join(format!("{hunt_id}.json"));

    if !hunt_file.exists() {
        bail!("Hunt not found: {hunt_id}");
    }

    let content = std::fs::read_to_string(&hunt_file)?;
    let result: clawdefender_swarm::threat_hunting::HuntResult = serde_json::from_str(&content)?;

    println!("Hunt ID: {}", result.hunt_id);
    print!("Type: ");
    match &result.hunt_type {
        HuntType::GeneralSweep => println!("General Sweep"),
        HuntType::ServerFocused { server } => println!("Server-Focused ({})", server),
        HuntType::PatternSearch { pattern } => println!("Pattern Search ({})", pattern),
        HuntType::HistoricalReview { period } => println!("Historical Review ({})", period),
    }
    println!("Time Range: {} to {}",
        result.time_range.start.format("%Y-%m-%d %H:%M:%S"),
        result.time_range.end.format("%Y-%m-%d %H:%M:%S")
    );
    println!("Patterns Checked: {}", result.patterns_checked.len());
    println!();

    if result.findings.is_empty() {
        println!("✓ No threats found.");
    } else {
        println!("═══ {} Findings ═══", result.findings.len());
        for (i, finding) in result.findings.iter().enumerate() {
            println!();
            println!("{}. {} [{}]", i + 1, finding.pattern_name, finding.severity);
            println!("   ID: {}", finding.id);
            println!("   {}", finding.description);
            println!("   Confidence: {:.0}%", finding.confidence * 100.0);
            if !finding.involved_servers.is_empty() {
                println!("   Servers Involved:");
                for server in &finding.involved_servers {
                    println!("     - {server}");
                }
            }
            if !finding.involved_events.is_empty() {
                println!("   Events: {}", finding.involved_events.len());
            }
            println!("   Time Range: {} to {}",
                finding.time_range.start.format("%Y-%m-%d %H:%M"),
                finding.time_range.end.format("%Y-%m-%d %H:%M")
            );
            println!();
            println!("   Recommended Investigation:");
            println!("   {}", finding.recommended_investigation);
        }
    }

    Ok(())
}

