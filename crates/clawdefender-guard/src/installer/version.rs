//! Version management and installation metadata.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Installation metadata stored at `~/.clawdefender/install.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallMetadata {
    pub version: String,
    pub installed_at: DateTime<Utc>,
    pub install_method: String,
    pub install_path: String,
    pub platform: String,
}

impl InstallMetadata {
    /// Create new installation metadata.
    pub fn new(version: &str, install_path: &Path, platform: &str) -> Self {
        Self {
            version: version.to_string(),
            installed_at: Utc::now(),
            install_method: "auto".to_string(),
            install_path: install_path.display().to_string(),
            platform: platform.to_string(),
        }
    }

    /// Read installation metadata from a file.
    pub fn read_from(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let metadata: Self = serde_json::from_str(&content)?;
        Ok(metadata)
    }

    /// Write installation metadata to a file.
    pub fn write_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// Default path for installation metadata.
pub fn default_metadata_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".clawdefender")
        .join("install.json")
}

/// Check if an update is available by comparing installed vs latest version.
pub fn check_for_update(installed: &str, latest: &str) -> Option<String> {
    if super::detect::version_less_than(installed, latest) {
        Some(format!(
            "Update available: {installed} -> {latest}"
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_serialize_roundtrip() {
        let meta = InstallMetadata::new(
            "0.1.0",
            Path::new("/home/user/.clawdefender/bin/clawdefender"),
            "linux-x86_64",
        );
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let parsed: InstallMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "0.1.0");
        assert_eq!(parsed.platform, "linux-x86_64");
        assert_eq!(parsed.install_method, "auto");
    }

    #[test]
    fn test_check_for_update() {
        assert!(check_for_update("0.1.0", "0.2.0").is_some());
        assert!(check_for_update("0.2.0", "0.2.0").is_none());
        assert!(check_for_update("0.3.0", "0.2.0").is_none());
    }
}
