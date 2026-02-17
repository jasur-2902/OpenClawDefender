//! Uninstaller — reverses the auto-install process.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// The marker comment added to shell config files.
pub const PATH_MARKER: &str = "# Added by ClawDefender";

/// Options for uninstallation.
#[derive(Debug, Clone)]
pub struct UninstallOptions {
    /// Remove configuration directories as well.
    pub remove_config: bool,
    /// Path to the ClawDefender binary.
    pub binary_path: PathBuf,
    /// Path to the shell config file to clean up.
    pub shell_config_path: PathBuf,
    /// ClawDefender base directory (e.g., `~/.clawdefender`).
    pub base_dir: PathBuf,
}

impl UninstallOptions {
    /// Create default uninstall options based on standard paths.
    pub fn default_for_home(home: &Path, shell_config: &Path) -> Self {
        Self {
            remove_config: false,
            binary_path: home.join(".clawdefender/bin/clawdefender"),
            shell_config_path: shell_config.to_path_buf(),
            base_dir: home.join(".clawdefender"),
        }
    }
}

/// Result of uninstallation.
#[derive(Debug)]
pub struct UninstallResult {
    pub binary_removed: bool,
    pub path_cleaned: bool,
    pub config_removed: bool,
    pub daemon_stopped: bool,
}

/// Run the full uninstallation.
pub fn uninstall(options: &UninstallOptions) -> Result<UninstallResult> {
    let mut result = UninstallResult {
        binary_removed: false,
        path_cleaned: false,
        config_removed: false,
        daemon_stopped: false,
    };

    // 1. Stop daemon
    result.daemon_stopped = stop_daemon();

    // 2. Remove binary
    if options.binary_path.exists() {
        std::fs::remove_file(&options.binary_path)
            .with_context(|| format!("Failed to remove binary at {:?}", options.binary_path))?;
        result.binary_removed = true;
        info!("Removed binary: {:?}", options.binary_path);
    }

    // 3. Clean PATH from shell config
    result.path_cleaned = remove_path_from_shell_config(&options.shell_config_path)?;

    // 4. Optionally remove config dirs
    if options.remove_config {
        result.config_removed = remove_config_dirs(&options.base_dir)?;
    }

    Ok(result)
}

/// Attempt to stop the ClawDefender daemon.
fn stop_daemon() -> bool {
    match std::process::Command::new("clawdefender")
        .args(["daemon", "stop"])
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                info!("Stopped ClawDefender daemon");
                true
            } else {
                warn!("Daemon stop returned non-zero (may not be running)");
                true // Not running is fine
            }
        }
        Err(_) => {
            warn!("Could not run clawdefender daemon stop");
            false
        }
    }
}

/// Remove the PATH export line from a shell configuration file.
pub fn remove_path_from_shell_config(config_path: &Path) -> Result<bool> {
    if !config_path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(config_path)?;
    let lines: Vec<&str> = content.lines().collect();
    let filtered: Vec<&str> = lines
        .into_iter()
        .filter(|line| !line.contains(PATH_MARKER))
        .collect();

    let new_content = filtered.join("\n");
    // Preserve trailing newline if original had one
    let new_content = if content.ends_with('\n') && !new_content.ends_with('\n') {
        format!("{new_content}\n")
    } else {
        new_content
    };

    if new_content != content {
        std::fs::write(config_path, &new_content)?;
        info!("Removed PATH entry from {:?}", config_path);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Remove ClawDefender configuration directories.
fn remove_config_dirs(base_dir: &Path) -> Result<bool> {
    let mut removed = false;

    // Remove ~/.clawdefender/
    if base_dir.exists() {
        std::fs::remove_dir_all(base_dir)?;
        info!("Removed {:?}", base_dir);
        removed = true;
    }

    // Also remove XDG config and data dirs
    if let Some(config_dir) = dirs::config_dir() {
        let cd_config = config_dir.join("clawdefender");
        if cd_config.exists() {
            std::fs::remove_dir_all(&cd_config)?;
            info!("Removed {:?}", cd_config);
            removed = true;
        }
    }

    if let Some(data_dir) = dirs::data_local_dir() {
        let cd_data = data_dir.join("clawdefender");
        if cd_data.exists() {
            std::fs::remove_dir_all(&cd_data)?;
            info!("Removed {:?}", cd_data);
            removed = true;
        }
    }

    Ok(removed)
}
