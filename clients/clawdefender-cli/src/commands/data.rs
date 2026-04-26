//! `rookbot data` — Data management (export/import/reset).

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Debug)]
pub enum DataAction {
    /// Export Rookbot data.
    Export {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        include: Option<String>,
    },
    /// Import Rookbot data.
    Import {
        path: PathBuf,
        #[arg(long, default_value = "merge")]
        mode: String,
        #[arg(long)]
        preview: bool,
    },
    /// Reset Rookbot data.
    Reset {
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        keep_config: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RookbotData {
    version: String,
    exported_at: String,
    #[serde(default)]
    server_state: Option<serde_json::Value>,
    #[serde(default)]
    autonomy_state: Option<serde_json::Value>,
    #[serde(default)]
    playbooks: Option<serde_json::Value>,
    #[serde(default)]
    knowledge: Option<serde_json::Value>,
    #[serde(default)]
    fim_baseline: Option<serde_json::Value>,
}

/// Run the data subcommand.
pub fn run(action: &DataAction) -> Result<()> {
    match action {
        DataAction::Export { output, include } => export(output.as_deref(), include.as_deref()),
        DataAction::Import {
            path,
            mode,
            preview,
        } => import(path, mode, *preview),
        DataAction::Reset {
            confirm,
            keep_config,
        } => reset(*confirm, *keep_config),
    }
}

/// Export Rookbot data.
fn export(output: Option<&std::path::Path>, include: Option<&str>) -> Result<()> {
    println!("Exporting Rookbot data...");
    println!();

    let mut data = RookbotData {
        version: env!("CARGO_PKG_VERSION").to_string(),
        exported_at: chrono::Utc::now().to_rfc3339(),
        server_state: None,
        autonomy_state: None,
        playbooks: None,
        knowledge: None,
        fim_baseline: None,
    };

    let components: Vec<&str> = if let Some(inc) = include {
        inc.split(',').map(|s| s.trim()).collect()
    } else {
        vec!["all"]
    };

    let export_all = components.contains(&"all");

    // Export server state.
    if export_all || components.contains(&"server") {
        if let Ok(content) = read_data_file("server_state.json") {
            data.server_state = Some(serde_json::from_str(&content)?);
            println!("  Exported: server state");
        }
    }

    // Export autonomy state.
    if export_all || components.contains(&"autonomy") {
        if let Ok(content) = read_data_file("autonomy.json") {
            data.autonomy_state = Some(serde_json::from_str(&content)?);
            println!("  Exported: autonomy state");
        }
    }

    // Export playbooks.
    if export_all || components.contains(&"playbooks") {
        if let Ok(content) = read_config_file("playbooks.json") {
            data.playbooks = Some(serde_json::from_str(&content)?);
            println!("  Exported: playbooks");
        }
    }

    // Export knowledge.
    if export_all || components.contains(&"knowledge") {
        if let Ok(content) = read_data_file("knowledge.json") {
            data.knowledge = Some(serde_json::from_str(&content)?);
            println!("  Exported: knowledge base");
        }
    }

    // Export FIM baseline.
    if export_all || components.contains(&"fim") {
        if let Ok(content) = read_data_file("fim/baseline.json") {
            data.fim_baseline = Some(serde_json::from_str(&content)?);
            println!("  Exported: FIM baseline");
        }
    }

    let json = serde_json::to_string_pretty(&data)?;

    if let Some(path) = output {
        std::fs::write(path, &json)?;
        println!();
        println!("Exported to: {}", path.display());
    } else {
        println!();
        println!("{}", json);
    }

    Ok(())
}

/// Import Rookbot data.
fn import(path: &PathBuf, mode: &str, preview: bool) -> Result<()> {
    let valid_modes = ["merge", "replace"];
    if !valid_modes.contains(&mode) {
        bail!("Invalid import mode: {}\nValid modes: merge, replace", mode);
    }

    let content = std::fs::read_to_string(path)?;
    let data: RookbotData = serde_json::from_str(&content)?;

    println!("Importing Rookbot data...");
    println!();
    println!("  Source:       {}", path.display());
    println!("  Version:      {}", data.version);
    println!("  Exported:     {}", data.exported_at);
    println!("  Import mode:  {}", mode);
    println!();

    if preview {
        println!("PREVIEW MODE: No changes will be made.");
        println!();
    }

    // Import server state.
    if let Some(ref server_state) = data.server_state {
        println!("  Importing: server state");
        if !preview {
            write_data_file(
                "server_state.json",
                &serde_json::to_string_pretty(server_state)?,
            )?;
        }
    }

    // Import autonomy state.
    if let Some(ref autonomy_state) = data.autonomy_state {
        println!("  Importing: autonomy state");
        if !preview {
            write_data_file(
                "autonomy.json",
                &serde_json::to_string_pretty(autonomy_state)?,
            )?;
        }
    }

    // Import playbooks.
    if let Some(ref playbooks) = data.playbooks {
        println!("  Importing: playbooks");
        if !preview {
            write_config_file("playbooks.json", &serde_json::to_string_pretty(playbooks)?)?;
        }
    }

    // Import knowledge.
    if let Some(ref knowledge) = data.knowledge {
        println!("  Importing: knowledge base");
        if !preview {
            write_data_file("knowledge.json", &serde_json::to_string_pretty(knowledge)?)?;
        }
    }

    // Import FIM baseline.
    if let Some(ref fim_baseline) = data.fim_baseline {
        println!("  Importing: FIM baseline");
        if !preview {
            write_data_file(
                "fim/baseline.json",
                &serde_json::to_string_pretty(fim_baseline)?,
            )?;
        }
    }

    println!();
    if preview {
        println!("Preview complete. Run without --preview to apply changes.");
    } else {
        println!("Import complete.");
    }

    Ok(())
}

/// Reset Rookbot data.
fn reset(confirm: bool, keep_config: bool) -> Result<()> {
    if !confirm {
        println!("WARNING: This will delete all Rookbot data.");
        println!();
        println!("To confirm, run: rookbot data reset --confirm");
        return Ok(());
    }

    println!("Resetting Rookbot data...");
    println!();

    let data_dir = data_dir_path()?;
    let config_dir = config_dir_path()?;

    // Remove data directory.
    if data_dir.exists() {
        std::fs::remove_dir_all(&data_dir)?;
        println!("  Removed: {}", data_dir.display());
    }

    // Remove config directory (unless --keep-config is set).
    if !keep_config && config_dir.exists() {
        std::fs::remove_dir_all(&config_dir)?;
        println!("  Removed: {}", config_dir.display());
    } else if keep_config {
        println!("  Kept:    {} (--keep-config)", config_dir.display());
    }

    println!();
    println!("Reset complete.");

    Ok(())
}

/// Read a data file from ~/.local/share/rookbot/.
fn read_data_file(relative_path: &str) -> Result<String> {
    let path = data_dir_path()?.join(relative_path);
    Ok(std::fs::read_to_string(path)?)
}

/// Write a data file to ~/.local/share/rookbot/.
fn write_data_file(relative_path: &str, content: &str) -> Result<()> {
    let path = data_dir_path()?.join(relative_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    Ok(())
}

/// Read a config file from ~/.config/rookbot/.
fn read_config_file(relative_path: &str) -> Result<String> {
    let path = config_dir_path()?.join(relative_path);
    Ok(std::fs::read_to_string(path)?)
}

/// Write a config file to ~/.config/rookbot/.
fn write_config_file(relative_path: &str, content: &str) -> Result<()> {
    let path = config_dir_path()?.join(relative_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    Ok(())
}

/// Return the data directory path: ~/.local/share/rookbot.
fn data_dir_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")?;
    Ok(PathBuf::from(home).join(".local/share/rookbot"))
}

/// Return the config directory path: ~/.config/rookbot.
fn config_dir_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")?;
    Ok(PathBuf::from(home).join(".config/rookbot"))
}
