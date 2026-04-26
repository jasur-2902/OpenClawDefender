//! `rookbot autonomy` — Agent autonomy framework commands.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

use clawdefender_core::config::ClawConfig;

#[derive(Subcommand, Debug)]
pub enum AutonomyAction {
    /// Show current autonomy levels.
    Status,
    /// Set autonomy level (L0-L3).
    Set {
        level: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Emergency lockdown — drop to L0.
    Lockdown {
        #[arg(long)]
        release: bool,
    },
    /// Show agent action log.
    Log {
        #[arg(long, default_value = "50")]
        limit: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AutonomyState {
    #[serde(default = "default_global_level")]
    global_level: String,
    #[serde(default)]
    server_levels: HashMap<String, String>,
    #[serde(default)]
    lockdown: bool,
}

fn default_global_level() -> String {
    "L1".to_string()
}

impl Default for AutonomyState {
    fn default() -> Self {
        Self {
            global_level: default_global_level(),
            server_levels: HashMap::new(),
            lockdown: false,
        }
    }
}

/// Run the autonomy subcommand.
pub fn run(action: &AutonomyAction, config: &ClawConfig) -> Result<()> {
    match action {
        AutonomyAction::Status => status(),
        AutonomyAction::Set { level, server } => set_level(level, server.as_deref()),
        AutonomyAction::Lockdown { release } => lockdown(*release),
        AutonomyAction::Log { limit } => log(*limit, config),
    }
}

/// Show current autonomy levels.
fn status() -> Result<()> {
    let state = load_autonomy_state()?;

    println!("Autonomy Levels");
    println!("===============");
    println!();

    if state.lockdown {
        println!("  STATUS: LOCKDOWN (all servers forced to L0)");
        println!();
        println!("  Release lockdown: rookbot autonomy lockdown --release");
        return Ok(());
    }

    println!("  Global level:     {}", state.global_level);
    println!();

    if !state.server_levels.is_empty() {
        println!("  Server-specific levels:");
        for (server, level) in &state.server_levels {
            println!("    {:<30} {}", server, level);
        }
        println!();
    }

    println!("  Autonomy Levels:");
    println!("    L0 - Observe only (no actions)");
    println!("    L1 - Suggest actions (requires approval)");
    println!("    L2 - Confirm & act (show prompt, then proceed)");
    println!("    L3 - Full auto (take actions without prompts)");

    Ok(())
}

/// Set autonomy level.
fn set_level(level: &str, server: Option<&str>) -> Result<()> {
    let valid_levels = ["L0", "L1", "L2", "L3"];
    let level_upper = level.to_uppercase();
    if !valid_levels.contains(&level_upper.as_str()) {
        bail!(
            "Invalid autonomy level: {}\nValid levels: L0, L1, L2, L3",
            level
        );
    }

    let mut state = load_autonomy_state()?;

    if let Some(srv) = server {
        state
            .server_levels
            .insert(srv.to_string(), level_upper.clone());
        println!("Set autonomy level for \"{}\": {}", srv, level_upper);
    } else {
        state.global_level = level_upper.clone();
        println!("Set global autonomy level: {}", level_upper);
    }

    save_autonomy_state(&state)?;
    Ok(())
}

/// Emergency lockdown.
fn lockdown(release: bool) -> Result<()> {
    let mut state = load_autonomy_state()?;

    if release {
        state.lockdown = false;
        save_autonomy_state(&state)?;
        println!("Lockdown released.");
        println!();
        println!("Autonomy levels restored to previous settings.");
    } else {
        state.lockdown = true;
        save_autonomy_state(&state)?;
        println!("LOCKDOWN ACTIVATED");
        println!();
        println!("All servers forced to L0 (observe only).");
        println!("No autonomous actions will be taken.");
        println!();
        println!("Release: rookbot autonomy lockdown --release");
    }

    Ok(())
}

/// Show agent action log.
fn log(limit: usize, config: &ClawConfig) -> Result<()> {
    println!("Agent Action Log (last {} entries)", limit);
    println!("===================");
    println!();

    use clawdefender_core::audit::logger::FileAuditLogger;
    use clawdefender_core::audit::{AuditFilter, AuditLogger};

    let logger = FileAuditLogger::new(config.audit_log_path.clone(), config.log_rotation.clone())?;
    let filter = AuditFilter {
        limit,
        ..Default::default()
    };
    let records = logger.query(&filter)?;

    if records.is_empty() {
        println!("  No agent actions recorded.");
        return Ok(());
    }

    println!(
        "  {:<20} {:<20} {:<10} EVENT",
        "TIMESTAMP", "SOURCE", "ACTION"
    );
    println!("  {}", "-".repeat(80));

    for record in records.iter().rev() {
        let ts = record.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        let source = if record.source.len() > 20 {
            format!("{}...", &record.source[..17])
        } else {
            record.source.clone()
        };
        let action = &record.action_taken;
        let event = if record.event_summary.len() > 30 {
            format!("{}...", &record.event_summary[..27])
        } else {
            record.event_summary.clone()
        };

        println!("  {:<20} {:<20} {:<10} {}", ts, source, action, event);
    }

    println!();
    println!("  {} action(s) shown", records.len());

    Ok(())
}

/// Load autonomy state from ~/.local/share/rookbot/autonomy.json.
fn load_autonomy_state() -> Result<AutonomyState> {
    let path = autonomy_state_path()?;
    if !path.exists() {
        return Ok(AutonomyState::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let state: AutonomyState = serde_json::from_str(&content)?;
    Ok(state)
}

/// Save autonomy state to ~/.local/share/rookbot/autonomy.json.
fn save_autonomy_state(state: &AutonomyState) -> Result<()> {
    let path = autonomy_state_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, content)?;
    Ok(())
}

/// Return the path to autonomy.json.
fn autonomy_state_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")?;
    Ok(PathBuf::from(home).join(".local/share/rookbot/autonomy.json"))
}
