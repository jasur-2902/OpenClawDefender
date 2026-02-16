//! `clawdefender model` -- manage local SLM models.

use std::path::PathBuf;

use anyhow::Result;
use clawdefender_core::config::ClawConfig;
use clawdefender_slm::model_manager::{ModelManager, recommended_models};

use crate::ModelAction;

pub fn run(action: &ModelAction, config: &ClawConfig) -> Result<()> {
    let mgr = ModelManager::default_dir()?;

    match action {
        ModelAction::Download { name } => cmd_download(&mgr, name)?,
        ModelAction::List => cmd_list(&mgr, config)?,
        ModelAction::Set { name_or_path } => cmd_set(name_or_path, config)?,
        ModelAction::Off => cmd_toggle(false, config)?,
        ModelAction::On => cmd_toggle(true, config)?,
        ModelAction::Stats => cmd_stats(config)?,
    }

    Ok(())
}

fn cmd_download(mgr: &ModelManager, name: &str) -> Result<()> {
    let registry = recommended_models();
    let model = registry
        .iter()
        .find(|m| m.name.to_lowercase().contains(&name.to_lowercase()) || m.filename.to_lowercase().contains(&name.to_lowercase()));

    match model {
        Some(m) => {
            if mgr.is_installed(&m.filename) {
                println!("Model already installed: {}", m.filename);
                println!("  Path: {}", mgr.model_path(&m.filename).display());
                return Ok(());
            }

            println!("Model: {}", m.name);
            println!("  File: {}", m.filename);
            println!("  Size: {:.1} MB", m.size_bytes as f64 / 1_000_000.0);
            println!("  Quantization: {}", m.quantization);
            println!();
            println!(
                "To download, run with the `download` feature enabled."
            );
            println!(
                "Or manually download from:\n  {}\n\nAnd place in:\n  {}",
                m.url,
                mgr.models_dir().display()
            );
            mgr.ensure_dir()?;
        }
        None => {
            println!("Model \"{name}\" not found in registry.");
            println!();
            println!("Available models:");
            for m in &registry {
                println!(
                    "  - {} ({}, {:.1} MB)",
                    m.name,
                    m.quantization,
                    m.size_bytes as f64 / 1_000_000.0
                );
            }
        }
    }

    Ok(())
}

fn cmd_list(mgr: &ModelManager, config: &ClawConfig) -> Result<()> {
    let registry = recommended_models();
    let installed = mgr.list_installed()?;
    let active_path = config.slm.model_path.as_deref();

    println!("Available Models:");
    println!();

    for m in &registry {
        let is_installed = mgr.is_installed(&m.filename);
        let is_active = active_path
            .map(|p| p.ends_with(&m.filename))
            .unwrap_or(false);

        let status = if is_active {
            "* active"
        } else if is_installed {
            "  installed"
        } else {
            "  not installed"
        };

        let check = if is_installed { "[x]" } else { "[ ]" };
        println!(
            "  {check} {:<35} {:<10} {:>8.1} MB  {status}",
            m.name,
            m.quantization,
            m.size_bytes as f64 / 1_000_000.0,
        );
    }

    // Show any extra installed models not in the registry.
    let registry_filenames: Vec<&str> = registry.iter().map(|m| m.filename.as_str()).collect();
    let extra: Vec<_> = installed
        .iter()
        .filter(|i| !registry_filenames.contains(&i.filename.as_str()))
        .collect();

    if !extra.is_empty() {
        println!();
        println!("Custom Models:");
        for m in extra {
            let is_active = active_path
                .map(|p| p.ends_with(&m.filename))
                .unwrap_or(false);
            let marker = if is_active { "* active" } else { "" };
            println!(
                "  [x] {:<35} {:>8.1} MB  {marker}",
                m.filename,
                m.size_bytes as f64 / 1_000_000.0,
            );
        }
    }

    println!();
    println!("Models directory: {}", mgr.models_dir().display());
    println!(
        "SLM enabled: {}",
        if config.slm.enabled { "yes" } else { "no" }
    );

    Ok(())
}

fn cmd_set(name_or_path: &str, _config: &ClawConfig) -> Result<()> {
    let path = PathBuf::from(name_or_path);

    if path.is_absolute() && path.exists() {
        println!("Set active model to: {}", path.display());
        println!();
        println!("Update your config.toml:");
        println!("  [slm]");
        println!("  model_path = \"{}\"", path.display());
        return Ok(());
    }

    // Try to find in default models dir.
    let mgr = ModelManager::default_dir()?;

    // Check if it matches a registry model name.
    let registry = recommended_models();
    if let Some(m) = registry.iter().find(|m| {
        m.name.to_lowercase().contains(&name_or_path.to_lowercase())
            || m.filename.to_lowercase().contains(&name_or_path.to_lowercase())
    }) {
        let model_path = mgr.model_path(&m.filename);
        if !model_path.exists() {
            println!("Model not installed: {}", m.name);
            println!("Run: clawdefender model download {}", name_or_path);
            return Ok(());
        }
        println!("Set active model to: {} ({})", m.name, m.filename);
        println!();
        println!("Update your config.toml:");
        println!("  [slm]");
        println!("  model_path = \"{}\"", model_path.display());
        return Ok(());
    }

    // Try as a filename in the models directory.
    let model_path = mgr.model_path(name_or_path);
    if model_path.exists() {
        println!("Set active model to: {}", name_or_path);
        println!();
        println!("Update your config.toml:");
        println!("  [slm]");
        println!("  model_path = \"{}\"", model_path.display());
    } else {
        println!(
            "Model not found: {name_or_path}\nRun `clawdefender model list` to see available models."
        );
    }

    Ok(())
}

fn cmd_toggle(enable: bool, _config: &ClawConfig) -> Result<()> {
    let state = if enable { "enabled" } else { "disabled" };
    println!("SLM {state}.");
    println!();
    println!("Update your config.toml:");
    println!("  [slm]");
    println!("  enabled = {enable}");
    Ok(())
}

fn cmd_stats(_config: &ClawConfig) -> Result<()> {
    // In a running daemon, we'd query via IPC. For now, show the config state.
    println!("SLM Statistics");
    println!();
    println!("  Note: Connect to a running ClawDefender daemon for live stats.");
    println!("  The daemon tracks inference count, avg latency, and noise filter stats.");
    println!();
    println!("  To see live stats, start the daemon with `clawdefender proxy` and");
    println!("  the TUI will show SLM status in the header bar.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_list_runs() {
        let mgr = ModelManager::new(std::path::PathBuf::from("/tmp/clawdefender-test-models-nonexistent"));
        let config = ClawConfig::default();
        // Should not panic.
        cmd_list(&mgr, &config).unwrap();
    }

    #[test]
    fn test_model_download_unknown() {
        let mgr = ModelManager::new(std::path::PathBuf::from("/tmp/clawdefender-test-models-nonexistent"));
        // Should print "not found" but not error.
        cmd_download(&mgr, "nonexistent-model-xyz").unwrap();
    }

    #[test]
    fn test_toggle_on_off() {
        let config = ClawConfig::default();
        cmd_toggle(true, &config).unwrap();
        cmd_toggle(false, &config).unwrap();
    }

    #[test]
    fn test_stats_runs() {
        let config = ClawConfig::default();
        cmd_stats(&config).unwrap();
    }

    #[test]
    fn test_set_nonexistent_model() {
        let config = ClawConfig::default();
        cmd_set("nonexistent-model", &config).unwrap();
    }
}
