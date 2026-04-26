//! `rookbot ai` -- unified AI backend status.

use anyhow::Result;
use clap::Subcommand;
use clawdefender_swarm::keychain::default_keystore;

#[derive(Subcommand, Debug)]
pub enum AiAction {
    /// Show both local SLM and cloud backend status.
    Status,
}

pub fn run(action: &AiAction) -> Result<()> {
    match action {
        AiAction::Status => cmd_status()?,
    }
    Ok(())
}

fn cmd_status() -> Result<()> {
    println!("RookBot AI Backend Status");
    println!("{}", "=".repeat(60));
    println!();

    // Local SLM Status
    println!("Local SLM:");
    println!("  Status:           Not loaded");
    println!("  Active Model:     None");
    println!("  Memory Usage:     N/A");
    println!("  Inference Count:  N/A");
    println!("  Avg Latency:      N/A");
    println!();

    // Cloud Backend Status
    println!("Cloud Backend:");
    let keystore = default_keystore();
    let entries = keystore.list();

    if entries.is_empty() {
        println!("  Status:           Not configured");
        println!("  Provider:         None");
        println!();
        println!("  Run `rookbot cloud setup` to configure a cloud provider.");
    } else {
        let configured_count = entries.iter().filter(|(_, c)| *c).count();
        if configured_count > 0 {
            println!("  Status:           Configured");
            for (name, configured) in &entries {
                if *configured {
                    println!("  Provider:         {}", name);
                }
            }
            println!("  API Calls Today:  0");
            println!("  Cost Today:       $0.00");
        } else {
            println!("  Status:           Not configured");
            println!("  Provider:         None");
        }
    }

    println!();
    println!("Task Routing:");
    println!("  Strategy:         Auto (prefer local for triage, cloud for complex)");
    println!("  Local Available:  No");
    println!(
        "  Cloud Available:  {}",
        if entries.is_empty() { "No" } else { "Yes" }
    );
    println!();
    println!("Note: Live metrics require a running daemon.");
    println!("      Start daemon: rookbot daemon start");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_status_runs() {
        // Should not panic.
        cmd_status().unwrap();
    }
}
