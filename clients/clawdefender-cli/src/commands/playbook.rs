//! `rookbot playbook` — Response playbook management.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

use clawdefender_core::config::ClawConfig;

#[derive(Subcommand, Debug)]
pub enum PlaybookAction {
    /// List available playbooks.
    List,
    /// Enable a playbook.
    Enable { id: String },
    /// Disable a playbook.
    Disable { id: String },
    /// Test a playbook (dry run).
    Test {
        id: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Show playbook execution history.
    History { id: String },
    /// Create a new custom playbook.
    Create {
        #[arg(long)]
        trigger: String,
        #[arg(long)]
        actions: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Playbook {
    id: String,
    name: String,
    description: String,
    enabled: bool,
    trigger: String,
    actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlaybookRegistry {
    playbooks: Vec<Playbook>,
}

impl Default for PlaybookRegistry {
    fn default() -> Self {
        Self {
            playbooks: vec![
                Playbook {
                    id: "block-shell".to_string(),
                    name: "Block Shell Commands".to_string(),
                    description: "Block all shell execution attempts".to_string(),
                    enabled: false,
                    trigger: "tool:execute_command".to_string(),
                    actions: vec!["block".to_string(), "alert:high".to_string()],
                },
                Playbook {
                    id: "quarantine-malware".to_string(),
                    name: "Quarantine Malware".to_string(),
                    description: "Isolate and report malware detections".to_string(),
                    enabled: false,
                    trigger: "scanner:malware".to_string(),
                    actions: vec![
                        "quarantine".to_string(),
                        "alert:critical".to_string(),
                        "report".to_string(),
                    ],
                },
                Playbook {
                    id: "rate-limit-api".to_string(),
                    name: "Rate Limit API Calls".to_string(),
                    description: "Throttle excessive API requests".to_string(),
                    enabled: false,
                    trigger: "rate:api:>100/min".to_string(),
                    actions: vec!["throttle".to_string(), "alert:medium".to_string()],
                },
            ],
        }
    }
}

/// Run the playbook subcommand.
pub fn run(action: &PlaybookAction, config: &ClawConfig) -> Result<()> {
    match action {
        PlaybookAction::List => list(),
        PlaybookAction::Enable { id } => enable(id),
        PlaybookAction::Disable { id } => disable(id),
        PlaybookAction::Test { id, dry_run } => test(id, *dry_run),
        PlaybookAction::History { id } => history(id, config),
        PlaybookAction::Create { trigger, actions } => create(trigger, actions),
    }
}

/// List available playbooks.
fn list() -> Result<()> {
    let registry = load_playbook_registry()?;

    println!("Available Playbooks");
    println!("===================");
    println!();

    if registry.playbooks.is_empty() {
        println!("  No playbooks configured.");
        return Ok(());
    }

    println!("  {:<20} {:<8} DESCRIPTION", "ID", "STATUS");
    println!("  {}", "-".repeat(70));

    for pb in &registry.playbooks {
        let status = if pb.enabled { "enabled" } else { "disabled" };
        println!("  {:<20} {:<8} {}", pb.id, status, pb.description);
    }

    println!();
    println!("  {} playbook(s) configured", registry.playbooks.len());

    Ok(())
}

/// Enable a playbook.
fn enable(id: &str) -> Result<()> {
    let mut registry = load_playbook_registry()?;
    let playbook = registry
        .playbooks
        .iter_mut()
        .find(|pb| pb.id == id)
        .ok_or_else(|| anyhow::anyhow!("Playbook not found: {}", id))?;

    playbook.enabled = true;
    let trigger = playbook.trigger.clone();
    let actions = playbook.actions.clone();

    save_playbook_registry(&registry)?;

    println!("Enabled playbook: {}", id);
    println!();
    println!("Trigger: {}", trigger);
    println!("Actions: {}", actions.join(", "));

    Ok(())
}

/// Disable a playbook.
fn disable(id: &str) -> Result<()> {
    let mut registry = load_playbook_registry()?;
    let playbook = registry
        .playbooks
        .iter_mut()
        .find(|pb| pb.id == id)
        .ok_or_else(|| anyhow::anyhow!("Playbook not found: {}", id))?;

    playbook.enabled = false;
    save_playbook_registry(&registry)?;

    println!("Disabled playbook: {}", id);
    Ok(())
}

/// Test a playbook (dry run).
fn test(id: &str, dry_run: bool) -> Result<()> {
    let registry = load_playbook_registry()?;
    let playbook = registry
        .playbooks
        .iter()
        .find(|pb| pb.id == id)
        .ok_or_else(|| anyhow::anyhow!("Playbook not found: {}", id))?;

    println!("Testing Playbook: {}", playbook.name);
    println!("=================");
    println!();
    println!("  ID:          {}", playbook.id);
    println!("  Description: {}", playbook.description);
    println!("  Trigger:     {}", playbook.trigger);
    println!("  Actions:     {}", playbook.actions.join(", "));
    println!();

    if dry_run {
        println!("  DRY RUN: No actions will be executed.");
    } else {
        println!("  Simulating playbook execution...");
        println!();
        for (i, action) in playbook.actions.iter().enumerate() {
            println!("  [{}] {}", i + 1, action);
        }
        println!();
        println!("  Playbook test complete.");
    }

    Ok(())
}

/// Show playbook execution history.
fn history(id: &str, config: &ClawConfig) -> Result<()> {
    println!("Playbook Execution History: {}", id);
    println!("===========================");
    println!();

    use clawdefender_core::audit::logger::FileAuditLogger;
    use clawdefender_core::audit::{AuditFilter, AuditLogger};

    let logger = FileAuditLogger::new(config.audit_log_path.clone(), config.log_rotation.clone())?;
    let filter = AuditFilter {
        limit: 100,
        ..Default::default()
    };
    let records = logger.query(&filter)?;

    // Filter records that mention this playbook ID.
    let playbook_records: Vec<_> = records
        .iter()
        .filter(|r| r.event_summary.contains(id))
        .collect();

    if playbook_records.is_empty() {
        println!("  No execution history for this playbook.");
        return Ok(());
    }

    println!("  {:<20} ACTION", "TIMESTAMP");
    println!("  {}", "-".repeat(50));

    for record in playbook_records.iter().take(20) {
        let ts = record.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        println!("  {:<20} {}", ts, record.action_taken);
    }

    println!();
    println!("  {} execution(s) recorded", playbook_records.len());

    Ok(())
}

/// Create a new custom playbook.
fn create(trigger: &str, actions: &str) -> Result<()> {
    let mut registry = load_playbook_registry()?;

    let action_list: Vec<String> = actions.split(',').map(|s| s.trim().to_string()).collect();

    // Generate a simple ID from the trigger.
    let id = trigger
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_lowercase();

    if registry.playbooks.iter().any(|pb| pb.id == id) {
        bail!("Playbook with ID '{}' already exists.", id);
    }

    let playbook = Playbook {
        id: id.clone(),
        name: format!("Custom: {}", trigger),
        description: format!("Trigger: {}", trigger),
        enabled: false,
        trigger: trigger.to_string(),
        actions: action_list,
    };

    registry.playbooks.push(playbook);
    save_playbook_registry(&registry)?;

    println!("Created playbook: {}", id);
    println!();
    println!("Enable it: rookbot playbook enable {}", id);

    Ok(())
}

/// Load playbook registry from ~/.config/rookbot/playbooks.json.
fn load_playbook_registry() -> Result<PlaybookRegistry> {
    let path = playbook_registry_path()?;
    if !path.exists() {
        return Ok(PlaybookRegistry::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let registry: PlaybookRegistry = serde_json::from_str(&content)?;
    Ok(registry)
}

/// Save playbook registry to ~/.config/rookbot/playbooks.json.
fn save_playbook_registry(registry: &PlaybookRegistry) -> Result<()> {
    let path = playbook_registry_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(registry)?;
    std::fs::write(&path, content)?;
    Ok(())
}

/// Return the path to playbooks.json.
fn playbook_registry_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")?;
    Ok(PathBuf::from(home).join(".config/rookbot/playbooks.json"))
}
