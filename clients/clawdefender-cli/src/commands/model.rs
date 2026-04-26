//! `rookbot model` -- manage local SLM models.

use std::path::PathBuf;

use anyhow::Result;
use clawdefender_core::config::ClawConfig;
use clawdefender_slm::model_manager::{recommended_models, ModelManager};

use crate::ModelAction;

pub fn run(action: &ModelAction, config: &ClawConfig) -> Result<()> {
    let mgr = ModelManager::default_dir()?;

    match action {
        ModelAction::Download { name } => cmd_download(&mgr, name, false)?,
        ModelAction::List => cmd_list(&mgr, config)?,
        ModelAction::Set { name_or_path } => cmd_set(name_or_path, config)?,
        ModelAction::Off => cmd_toggle(false, config)?,
        ModelAction::On => cmd_toggle(true, config)?,
        ModelAction::Stats => cmd_stats(config)?,
    }

    Ok(())
}

fn cmd_download(mgr: &ModelManager, name: &str, progress: bool) -> Result<()> {
    let registry = recommended_models();
    let model = registry.iter().find(|m| {
        m.name.to_lowercase().contains(&name.to_lowercase())
            || m.filename.to_lowercase().contains(&name.to_lowercase())
    });

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

            if progress {
                println!("Download with progress tracking is not yet implemented.");
                println!("Progress bar support coming in a future release.");
                println!();
            }

            println!("To download, run with the `download` feature enabled.");
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

        // Estimate RAM needs (rough estimate based on model size)
        let ram_gb = (m.size_bytes as f64 / 1_073_741_824.0 * 1.2).ceil();

        // Show recommended badge for first model
        let recommended = if m.name.contains("TinyLlama") {
            " [RECOMMENDED]"
        } else {
            ""
        };

        println!(
            "  {check} {:<35} {:<10} {:>8.1} MB  ~{}GB RAM  {status}{recommended}",
            m.name,
            m.quantization,
            m.size_bytes as f64 / 1_000_000.0,
            ram_gb,
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
            || m.filename
                .to_lowercase()
                .contains(&name_or_path.to_lowercase())
    }) {
        let model_path = mgr.model_path(&m.filename);
        if !model_path.exists() {
            println!("Model not installed: {}", m.name);
            println!("Run: rookbot model download {}", name_or_path);
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
            "Model not found: {name_or_path}\nRun `rookbot model list` to see available models."
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
    println!("  Note: Connect to a running RookBot daemon for live stats.");
    println!("  The daemon tracks inference count, avg latency, and noise filter stats.");
    println!();
    println!("  To see live stats, start the daemon with `rookbot daemon start` and");
    println!("  use `rookbot model status` to view real-time metrics.");
    Ok(())
}

// New commands for enhanced model management (will be integrated by team lead)

#[allow(dead_code)]
fn cmd_activate(name: &str, _config: &ClawConfig) -> Result<()> {
    let mgr = ModelManager::default_dir()?;
    let registry = recommended_models();

    let model = registry.iter().find(|m| {
        m.name.to_lowercase().contains(&name.to_lowercase())
            || m.filename.to_lowercase().contains(&name.to_lowercase())
    });

    match model {
        Some(m) => {
            if !mgr.is_installed(&m.filename) {
                println!("Model not installed: {}", m.name);
                println!("Run: rookbot model download {}", name);
                return Ok(());
            }

            println!("Loading model into daemon's local backend: {}", m.name);
            println!();
            println!("Note: This requires a running daemon.");
            println!("  The daemon will load the model into memory and make it available");
            println!("  for local inference. This may take a few seconds.");
            println!();
            println!("  Model: {}", m.filename);
            println!("  Path: {}", mgr.model_path(&m.filename).display());
        }
        None => {
            println!("Model \"{name}\" not found in registry.");
            println!("Run `rookbot model list` to see available models.");
        }
    }

    Ok(())
}

#[allow(dead_code)]
fn cmd_deactivate(_config: &ClawConfig) -> Result<()> {
    println!("Unloading model from daemon's local backend.");
    println!();
    println!("Note: This requires a running daemon.");
    println!("  The daemon will unload the current model from memory, freeing");
    println!("  resources. Cloud backend (if configured) will remain available.");
    Ok(())
}

#[allow(dead_code)]
fn cmd_delete(mgr: &ModelManager, name: &str) -> Result<()> {
    let registry = recommended_models();
    let model = registry.iter().find(|m| {
        m.name.to_lowercase().contains(&name.to_lowercase())
            || m.filename.to_lowercase().contains(&name.to_lowercase())
    });

    let filename = match model {
        Some(m) => &m.filename,
        None => name,
    };

    let model_path = mgr.model_path(filename);
    if !model_path.exists() {
        println!("Model not installed: {}", filename);
        return Ok(());
    }

    std::fs::remove_file(&model_path)?;
    println!("Deleted model: {}", filename);
    println!("  Path: {}", model_path.display());

    Ok(())
}

#[allow(dead_code)]
fn cmd_status(_config: &ClawConfig) -> Result<()> {
    println!("Local Model Status");
    println!("{}", "=".repeat(60));
    println!();
    println!("Note: This requires a running daemon for live metrics.");
    println!();
    println!("  Active Model:     None (daemon not connected)");
    println!("  Status:           Not loaded");
    println!("  Inference Count:  N/A");
    println!("  Avg Latency:      N/A");
    println!("  Memory Usage:     N/A");
    println!("  GPU Status:       N/A");
    println!();
    println!("Connect to the daemon with `rookbot daemon start` to see live stats.");

    Ok(())
}

#[allow(dead_code)]
fn cmd_benchmark(name: Option<&str>, _config: &ClawConfig) -> Result<()> {
    println!("Model Benchmark");
    println!("{}", "=".repeat(60));
    println!();

    if let Some(n) = name {
        println!("Benchmarking model: {}", n);
    } else {
        println!("Benchmarking active model...");
    }

    println!();
    println!("Note: This requires a running daemon with a loaded model.");
    println!();
    println!("  Test: Running inference with standard prompt");
    println!("  Prompt tokens:  ~50");
    println!("  Output tokens:  ~100");
    println!();
    println!("  Results:");
    println!("    Tokens/sec:   N/A (daemon not connected)");
    println!("    Latency:      N/A");
    println!("    Memory:       N/A");
    println!();
    println!("Connect to the daemon with `rookbot daemon start` to run benchmarks.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_list_runs() {
        let mgr = ModelManager::new(std::path::PathBuf::from(
            "/tmp/rookbot-test-models-nonexistent",
        ));
        let config = ClawConfig::default();
        // Should not panic.
        cmd_list(&mgr, &config).unwrap();
    }

    #[test]
    fn test_model_download_unknown() {
        let mgr = ModelManager::new(std::path::PathBuf::from(
            "/tmp/rookbot-test-models-nonexistent",
        ));
        // Should print "not found" but not error.
        cmd_download(&mgr, "nonexistent-model-xyz", false).unwrap();
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
