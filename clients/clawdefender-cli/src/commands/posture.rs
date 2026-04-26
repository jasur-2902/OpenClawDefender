//! `rookbot posture` — threat posture management.
//!
//! Manages the system's threat posture level, which influences policy enforcement
//! and monitoring sensitivity. Posture state is stored in ~/.local/share/rookbot/posture.json.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum PostureAction {
    /// Show current threat posture.
    Show,
    /// Set threat posture level.
    Set { level: String },
    /// Toggle automatic posture adjustment.
    Auto {
        #[arg(long)]
        enable: bool,
        #[arg(long)]
        disable: bool,
    },
    /// Show posture change history.
    History {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
}

/// Threat posture level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PostureLevel {
    Low,
    Normal,
    Elevated,
    High,
    Critical,
}

impl PostureLevel {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "normal" => Ok(Self::Normal),
            "elevated" => Ok(Self::Elevated),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => anyhow::bail!(
                "Invalid posture level: {}. Valid levels: low, normal, elevated, high, critical",
                s
            ),
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::Low => "Minimal monitoring, permissive policy",
            Self::Normal => "Standard monitoring and policy enforcement",
            Self::Elevated => "Increased monitoring, stricter policy",
            Self::High => "High monitoring, most operations require review",
            Self::Critical => "Maximum monitoring, all operations require approval",
        }
    }
}

/// Posture change history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PostureChange {
    timestamp: DateTime<Utc>,
    from_level: PostureLevel,
    to_level: PostureLevel,
    reason: String,
    automatic: bool,
}

/// Posture state store.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PostureStore {
    current_level: PostureLevel,
    auto_adjust: bool,
    last_changed: DateTime<Utc>,
    history: Vec<PostureChange>,
}

impl Default for PostureStore {
    fn default() -> Self {
        Self {
            current_level: PostureLevel::Normal,
            auto_adjust: true,
            last_changed: Utc::now(),
            history: Vec::new(),
        }
    }
}

impl PostureStore {
    fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        let store: PostureStore = serde_json::from_str(&content)?;
        Ok(store)
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(&self)?;
        fs::write(path, content)?;
        Ok(())
    }

    fn set_level(&mut self, new_level: PostureLevel, reason: String, automatic: bool) {
        let change = PostureChange {
            timestamp: Utc::now(),
            from_level: self.current_level.clone(),
            to_level: new_level.clone(),
            reason,
            automatic,
        };
        self.history.push(change);
        self.current_level = new_level;
        self.last_changed = Utc::now();
    }
}

/// Main entry point for the `posture` command.
pub fn run(action: &PostureAction) -> Result<()> {
    let posture_path = get_posture_path()?;
    let mut store = PostureStore::load(&posture_path)?;

    match action {
        PostureAction::Show => {
            println!("Threat Posture Status");
            println!();
            println!("  Current Level:    {:?}", store.current_level);
            println!("  Description:      {}", store.current_level.description());
            println!("  Auto-Adjust:      {}", if store.auto_adjust { "enabled" } else { "disabled" });
            println!("  Last Changed:     {}", store.last_changed.to_rfc3339());
            println!();

            if !store.history.is_empty() {
                let recent = store.history.iter().rev().take(3);
                println!("Recent changes:");
                for change in recent {
                    let auto_label = if change.automatic { "[AUTO]" } else { "[MANUAL]" };
                    println!(
                        "  {} {} {:?} → {:?}: {}",
                        change.timestamp.format("%Y-%m-%d %H:%M"),
                        auto_label,
                        change.from_level,
                        change.to_level,
                        change.reason
                    );
                }
            }
        }

        PostureAction::Set { level } => {
            let new_level = PostureLevel::from_str(level)?;

            if new_level == store.current_level {
                println!("Posture level is already {:?}.", new_level);
                return Ok(());
            }

            store.set_level(new_level.clone(), format!("Manual change via CLI"), false);
            store.save(&posture_path)?;

            println!("Threat posture set to {:?}.", new_level);
            println!("  {}", new_level.description());
        }

        PostureAction::Auto { enable, disable } => {
            if *enable && *disable {
                anyhow::bail!("Cannot specify both --enable and --disable");
            }

            if *enable {
                store.auto_adjust = true;
                store.save(&posture_path)?;
                println!("Automatic posture adjustment enabled.");
                println!("The system will adjust posture based on threat activity.");
            } else if *disable {
                store.auto_adjust = false;
                store.save(&posture_path)?;
                println!("Automatic posture adjustment disabled.");
                println!("Posture level will remain fixed until manually changed.");
            } else {
                println!(
                    "Automatic posture adjustment is currently {}.",
                    if store.auto_adjust { "enabled" } else { "disabled" }
                );
            }
        }

        PostureAction::History { limit } => {
            if store.history.is_empty() {
                println!("No posture change history.");
                return Ok(());
            }

            println!("Posture Change History");
            println!();
            println!(
                "  {:<20} {:<8} {:<12} {:<12} REASON",
                "TIMESTAMP", "TYPE", "FROM", "TO"
            );
            println!("  {}", "-".repeat(80));

            for change in store.history.iter().rev().take(*limit) {
                let ts = change.timestamp.format("%Y-%m-%d %H:%M:%S");
                let type_str = if change.automatic { "AUTO" } else { "MANUAL" };
                let from_str = format!("{:?}", change.from_level);
                let to_str = format!("{:?}", change.to_level);

                let reason = if change.reason.len() > 30 {
                    format!("{}...", &change.reason[..27])
                } else {
                    change.reason.clone()
                };

                println!(
                    "  {:<20} {:<8} {:<12} {:<12} {}",
                    ts, type_str, from_str, to_str, reason
                );
            }

            println!();
            println!("  Showing {} of {} change(s)",
                store.history.len().min(*limit),
                store.history.len()
            );
        }
    }

    Ok(())
}

/// Get the path to the posture JSON file.
fn get_posture_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".local/share/rookbot/posture.json"))
}
