//! Auto-Installation & Bootstrap system for ClawDefender.
//!
//! This module provides automatic installation of ClawDefender on machines
//! where it isn't already present. It handles platform detection, downloading,
//! checksum verification, installation, PATH setup, and rollback on failure.

pub mod detect;
pub mod download;
pub mod platform;
pub mod uninstall;
pub mod version;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use detect::InstallationStatus;
use download::{build_checksum_url, build_download_url, verify_checksum, Downloader};
use platform::PlatformInfo;
use uninstall::PATH_MARKER;
use version::InstallMetadata;

/// How consent for installation is determined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentMode {
    /// TTY available, ask user interactively.
    Interactive,
    /// Developer passed consent=True programmatically.
    PreAuthorized,
    /// CLAWDEFENDER_AUTO_INSTALL=1 environment variable is set.
    HeadlessEnvVar,
    /// Don't install, use embedded/fallback mode.
    FallbackOnly,
}

impl ConsentMode {
    /// Detect consent mode from the environment.
    pub fn detect() -> Self {
        if std::env::var("CLAWDEFENDER_AUTO_INSTALL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            return ConsentMode::HeadlessEnvVar;
        }
        if atty_is_interactive() {
            ConsentMode::Interactive
        } else {
            ConsentMode::FallbackOnly
        }
    }

    /// Returns true if installation is authorized without user prompt.
    pub fn is_authorized(&self) -> bool {
        matches!(self, ConsentMode::PreAuthorized | ConsentMode::HeadlessEnvVar)
    }
}

/// Check if stdin is a TTY (simplified check).
fn atty_is_interactive() -> bool {
    // Use a simple heuristic: check if TERM is set
    std::env::var("TERM").is_ok()
}

/// Result of the installation process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallResult {
    /// ClawDefender was already installed and up to date.
    AlreadyInstalled { path: PathBuf, version: String },
    /// ClawDefender was freshly installed.
    Installed { path: PathBuf, version: String },
    /// ClawDefender was upgraded from an older version.
    Upgraded {
        path: PathBuf,
        old_version: String,
        new_version: String,
    },
    /// Running in fallback/embedded mode without full installation.
    FallbackMode,
    /// User declined installation when prompted.
    Declined,
}

/// The main installer orchestrator.
pub struct AutoInstaller {
    platform: PlatformInfo,
    downloader: Box<dyn Downloader>,
    consent_mode: ConsentMode,
    /// Override the installation base directory (for testing).
    base_dir_override: Option<PathBuf>,
    /// Override the shell config path (for testing).
    shell_config_override: Option<PathBuf>,
}

impl AutoInstaller {
    /// Create a new AutoInstaller with the given downloader and consent mode.
    pub fn new(downloader: Box<dyn Downloader>, consent_mode: ConsentMode) -> Self {
        Self {
            platform: PlatformInfo::detect(),
            downloader,
            consent_mode,
            base_dir_override: None,
            shell_config_override: None,
        }
    }

    /// Override the base directory (for testing).
    pub fn with_base_dir(mut self, base_dir: PathBuf) -> Self {
        self.base_dir_override = Some(base_dir);
        self
    }

    /// Override the shell config path (for testing).
    pub fn with_shell_config(mut self, path: PathBuf) -> Self {
        self.shell_config_override = Some(path);
        self
    }

    /// Get the base directory for ClawDefender installation.
    fn base_dir(&self) -> PathBuf {
        self.base_dir_override.clone().unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".clawdefender")
        })
    }

    /// Get the binary installation path.
    fn bin_path(&self) -> PathBuf {
        self.base_dir().join("bin").join("clawdefender")
    }

    /// Get the shell config path.
    fn shell_config(&self) -> PathBuf {
        self.shell_config_override
            .clone()
            .unwrap_or_else(|| self.platform.shell_config_path.clone())
    }

    /// Get the metadata file path.
    fn metadata_path(&self) -> PathBuf {
        self.base_dir().join("install.json")
    }

    /// Run the full installation process.
    pub async fn install(&self) -> Result<InstallResult> {
        info!("Starting ClawDefender auto-installer");
        info!("Platform: {}", self.platform.platform_string());

        // Step 1: Check existing installation
        let latest_version = self
            .downloader
            .get_latest_version()
            .await
            .unwrap_or_else(|_| "0.0.0".to_string());

        let status = self.check_existing(&latest_version);

        match status {
            InstallationStatus::Installed { path, version } => {
                info!("ClawDefender already installed at {:?} (v{})", path, version);
                return Ok(InstallResult::AlreadyInstalled { path, version });
            }
            InstallationStatus::Outdated {
                path,
                current,
                latest,
            } => {
                info!("ClawDefender outdated at {:?} (v{} -> v{})", path, current, latest);
                // Continue to upgrade flow
                return self.upgrade(&path, &current, &latest).await;
            }
            InstallationStatus::NotInstalled => {
                info!("ClawDefender not found, proceeding with installation");
            }
        }

        // Step 2: Check consent
        if self.consent_mode == ConsentMode::FallbackOnly {
            info!("FallbackOnly mode — skipping installation");
            return Ok(InstallResult::FallbackMode);
        }

        if self.consent_mode == ConsentMode::Interactive {
            // In a real implementation, we'd prompt the user here.
            // For now, treat Interactive as authorized if we get this far.
            info!("Interactive mode — would prompt user for consent");
        }

        if !self.consent_mode.is_authorized() && self.consent_mode != ConsentMode::Interactive {
            return Ok(InstallResult::Declined);
        }

        // Step 3: Download and install
        self.perform_install(&latest_version).await
    }

    /// Check for existing installation.
    fn check_existing(&self, latest_version: &str) -> InstallationStatus {
        // Check the target bin path first
        let bin_path = self.bin_path();
        if bin_path.exists() {
            // Try to read version from metadata
            if let Ok(meta) = InstallMetadata::read_from(&self.metadata_path()) {
                if detect::version_less_than(&meta.version, latest_version) {
                    return InstallationStatus::Outdated {
                        path: bin_path,
                        current: meta.version,
                        latest: latest_version.to_string(),
                    };
                }
                return InstallationStatus::Installed {
                    path: bin_path,
                    version: meta.version,
                };
            }
        }

        // Fall back to system-wide detection
        detect::detect_installation(Some(latest_version))
    }

    /// Perform the actual installation.
    async fn perform_install(&self, version: &str) -> Result<InstallResult> {
        let bin_path = self.bin_path();

        // Track what we've done for rollback
        let mut created_dirs = false;
        let mut wrote_binary = false;
        let mut modified_shell = false;

        let result = self
            .do_install_steps(
                version,
                &bin_path,
                &mut created_dirs,
                &mut wrote_binary,
                &mut modified_shell,
            )
            .await;

        match result {
            Ok(()) => Ok(InstallResult::Installed {
                path: bin_path,
                version: version.to_string(),
            }),
            Err(e) => {
                warn!("Installation failed, rolling back: {e}");
                self.rollback(created_dirs, wrote_binary, modified_shell);
                Err(e)
            }
        }
    }

    async fn do_install_steps(
        &self,
        version: &str,
        bin_path: &Path,
        created_dirs: &mut bool,
        wrote_binary: &mut bool,
        modified_shell: &mut bool,
    ) -> Result<()> {
        let platform_str = self.platform.platform_string();

        // Create directories
        let bin_dir = bin_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid bin path"))?;
        std::fs::create_dir_all(bin_dir)
            .context("Failed to create installation directory")?;
        *created_dirs = true;

        // Download binary
        let download_url = build_download_url(&platform_str);
        info!("Downloading from {download_url}");
        let binary_data = self
            .downloader
            .download(&download_url)
            .await
            .context("Failed to download binary")?;

        // Download and verify checksum
        let checksum_url = build_checksum_url(&platform_str);
        let checksum_data = self
            .downloader
            .download(&checksum_url)
            .await
            .context("Failed to download checksum")?;
        let checksum_str = String::from_utf8(checksum_data)
            .context("Invalid checksum file encoding")?;
        verify_checksum(&binary_data, &checksum_str)
            .context("Checksum verification failed")?;

        // Write binary
        std::fs::write(bin_path, &binary_data).context("Failed to write binary")?;
        *wrote_binary = true;

        // Make binary executable (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(bin_path, perms)
                .context("Failed to set binary permissions")?;
        }

        // Add to PATH
        self.add_to_path()?;
        *modified_shell = true;

        // Save metadata
        let metadata = InstallMetadata::new(version, bin_path, &platform_str);
        metadata
            .write_to(&self.metadata_path())
            .context("Failed to write installation metadata")?;

        info!("ClawDefender v{version} installed to {:?}", bin_path);
        Ok(())
    }

    /// Add ClawDefender bin directory to PATH via shell config.
    fn add_to_path(&self) -> Result<()> {
        let shell_config = self.shell_config();
        let path_line = format!(
            "export PATH=\"$HOME/.clawdefender/bin:$PATH\" {PATH_MARKER}"
        );

        // Check if already present
        if shell_config.exists() {
            let content = std::fs::read_to_string(&shell_config)?;
            if content.contains(PATH_MARKER) {
                info!("PATH already configured in {:?}", shell_config);
                return Ok(());
            }
        }

        // Append to shell config
        let mut content = if shell_config.exists() {
            std::fs::read_to_string(&shell_config)?
        } else {
            String::new()
        };

        if !content.ends_with('\n') && !content.is_empty() {
            content.push('\n');
        }
        content.push_str(&path_line);
        content.push('\n');

        std::fs::write(&shell_config, &content)?;
        info!("Added PATH entry to {:?}", shell_config);
        Ok(())
    }

    /// Rollback installation on failure.
    fn rollback(&self, created_dirs: bool, wrote_binary: bool, modified_shell: bool) {
        if modified_shell {
            let _ = uninstall::remove_path_from_shell_config(&self.shell_config());
        }
        if wrote_binary {
            let _ = std::fs::remove_file(self.bin_path());
        }
        if created_dirs {
            // Only remove the bin dir if we created it and it's empty
            if let Some(bin_dir) = self.bin_path().parent() {
                let _ = std::fs::remove_dir(bin_dir);
            }
        }
        warn!("Rollback completed");
    }

    /// Upgrade an existing installation.
    async fn upgrade(
        &self,
        _existing_path: &Path,
        old_version: &str,
        new_version: &str,
    ) -> Result<InstallResult> {
        // For upgrade, we download new binary and replace
        let bin_path = self.bin_path();
        let platform_str = self.platform.platform_string();

        let download_url = build_download_url(&platform_str);
        let binary_data = self.downloader.download(&download_url).await?;

        let checksum_url = build_checksum_url(&platform_str);
        let checksum_data = self.downloader.download(&checksum_url).await?;
        let checksum_str = String::from_utf8(checksum_data)?;
        verify_checksum(&binary_data, &checksum_str)?;

        // Backup old binary
        let backup_path = bin_path.with_extension("bak");
        if bin_path.exists() {
            std::fs::rename(&bin_path, &backup_path)?;
        }

        // Write new binary
        if let Some(parent) = bin_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&bin_path, &binary_data)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&bin_path, perms)?;
        }

        // Update metadata
        let metadata = InstallMetadata::new(new_version, &bin_path, &platform_str);
        metadata.write_to(&self.metadata_path())?;

        // Remove backup
        let _ = std::fs::remove_file(&backup_path);

        Ok(InstallResult::Upgraded {
            path: bin_path,
            old_version: old_version.to_string(),
            new_version: new_version.to_string(),
        })
    }
}
