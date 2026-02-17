//! Parser for `clawdefender.toml` server manifests.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A parsed `clawdefender.toml` manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub server: ServerInfo,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub risk_profile: RiskProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Permissions {
    #[serde(default)]
    pub required: Vec<PermissionEntry>,
    #[serde(default)]
    pub optional: Vec<PermissionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEntry {
    pub action: String,
    #[serde(default)]
    pub scope: Option<String>,
    pub justification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskProfile {
    #[serde(default = "default_max_risk")]
    pub max_risk: String,
    #[serde(default)]
    pub declares_all_actions: bool,
    #[serde(default)]
    pub supports_clawdefender: bool,
    #[serde(default)]
    pub sdk_version: Option<String>,
}

impl Default for RiskProfile {
    fn default() -> Self {
        Self {
            max_risk: "medium".to_string(),
            declares_all_actions: false,
            supports_clawdefender: false,
            sdk_version: None,
        }
    }
}

fn default_max_risk() -> String {
    "medium".to_string()
}

impl Manifest {
    /// Load a manifest from a file path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest: {}", path.display()))?;
        Self::parse(&content)
    }

    /// Parse manifest from TOML string.
    pub fn parse(content: &str) -> Result<Self> {
        let manifest: Manifest =
            toml::from_str(content).context("Failed to parse clawdefender.toml")?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate manifest contents.
    fn validate(&self) -> Result<()> {
        if self.server.name.is_empty() {
            anyhow::bail!("Manifest server.name must not be empty");
        }
        if self.server.version.is_empty() {
            anyhow::bail!("Manifest server.version must not be empty");
        }
        // Check that required permissions have justifications
        for perm in &self.permissions.required {
            if perm.justification.is_empty() {
                anyhow::bail!(
                    "Required permission '{}' must have a justification",
                    perm.action
                );
            }
        }
        // Validate risk level
        match self.risk_profile.max_risk.as_str() {
            "low" | "medium" | "high" => {}
            other => anyhow::bail!("Invalid max_risk: '{other}'. Must be low, medium, or high"),
        }
        Ok(())
    }

    /// Check if the manifest declares permissions.
    pub fn has_permissions(&self) -> bool {
        !self.permissions.required.is_empty() || !self.permissions.optional.is_empty()
    }
}

/// Search for a `clawdefender.toml` manifest in a directory and its parents.
pub fn find_manifest(start_dir: &Path) -> Option<std::path::PathBuf> {
    let mut dir = start_dir.to_path_buf();
    loop {
        let candidate = dir.join("clawdefender.toml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_manifest() {
        let toml = r#"
[server]
name = "test-server"
version = "1.0.0"
description = "A test server"

[permissions]
required = [
    { action = "file_read", scope = "~/Projects/**", justification = "Core functionality" },
]
optional = [
    { action = "shell_execute", justification = "Git operations" },
]

[risk_profile]
max_risk = "medium"
declares_all_actions = true
supports_clawdefender = true
sdk_version = "0.5.0"
"#;
        let manifest = Manifest::parse(toml).unwrap();
        assert_eq!(manifest.server.name, "test-server");
        assert_eq!(manifest.permissions.required.len(), 1);
        assert_eq!(manifest.permissions.optional.len(), 1);
        assert!(manifest.risk_profile.supports_clawdefender);
    }

    #[test]
    fn reject_empty_name() {
        let toml = r#"
[server]
name = ""
version = "1.0.0"
"#;
        assert!(Manifest::parse(toml).is_err());
    }

    #[test]
    fn reject_invalid_risk() {
        let toml = r#"
[server]
name = "test"
version = "1.0.0"

[risk_profile]
max_risk = "extreme"
"#;
        assert!(Manifest::parse(toml).is_err());
    }

    #[test]
    fn reject_missing_justification() {
        let toml = r#"
[server]
name = "test"
version = "1.0.0"

[permissions]
required = [
    { action = "file_read", justification = "" },
]
"#;
        assert!(Manifest::parse(toml).is_err());
    }

    #[test]
    fn minimal_manifest() {
        let toml = r#"
[server]
name = "minimal"
version = "0.1.0"
"#;
        let manifest = Manifest::parse(toml).unwrap();
        assert_eq!(manifest.server.name, "minimal");
        assert!(!manifest.has_permissions());
    }
}
