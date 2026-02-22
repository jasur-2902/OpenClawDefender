//! Installation detection — checks if ClawDefender is already installed.

use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;

/// Status of an existing ClawDefender installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationStatus {
    /// ClawDefender is not installed.
    NotInstalled,
    /// ClawDefender is installed at the given path with the given version.
    Installed { path: PathBuf, version: String },
    /// ClawDefender is installed but outdated.
    Outdated {
        path: PathBuf,
        current: String,
        latest: String,
    },
}

/// Standard locations to check for the ClawDefender binary.
const STANDARD_LOCATIONS: &[&str] = &[
    "/usr/local/bin/clawdefender",
    ".local/bin/clawdefender",
    ".clawdefender/bin/clawdefender",
];

/// Detect whether ClawDefender is already installed.
pub fn detect_installation(latest_version: Option<&str>) -> InstallationStatus {
    // First check standard locations relative to home
    if let Some(home) = dirs::home_dir() {
        for loc in STANDARD_LOCATIONS {
            let path = if loc.starts_with('/') {
                PathBuf::from(loc)
            } else {
                home.join(loc)
            };
            if path.exists() {
                if let Some(version) = get_binary_version(&path) {
                    return check_version(path, version, latest_version);
                }
            }
        }
    }

    // Check PATH
    if let Ok(output) = Command::new("which").arg("clawdefender").output() {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let path = PathBuf::from(&path_str);
            if path.exists() {
                if let Some(version) = get_binary_version(&path) {
                    return check_version(path, version, latest_version);
                }
            }
        }
    }

    InstallationStatus::NotInstalled
}

/// Detect installation from custom search paths (for testing).
pub fn detect_installation_in_paths(
    paths: &[PathBuf],
    latest_version: Option<&str>,
) -> InstallationStatus {
    for path in paths {
        if path.exists() {
            if let Some(version) = get_binary_version(path) {
                return check_version(path.clone(), version, latest_version);
            }
        }
    }
    InstallationStatus::NotInstalled
}

fn get_binary_version(path: &PathBuf) -> Option<String> {
    Command::new(path)
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                // Parse "clawdefender x.y.z" or just "x.y.z"
                parse_version_string(&stdout)
            } else {
                None
            }
        })
}

fn parse_version_string(output: &str) -> Option<String> {
    let trimmed = output.trim();
    // Try "clawdefender x.y.z" format
    if let Some(ver) = trimmed.strip_prefix("clawdefender ") {
        return Some(ver.trim().to_string());
    }
    // Try just version number
    if trimmed
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        return Some(trimmed.to_string());
    }
    None
}

fn check_version(
    path: PathBuf,
    current: String,
    latest_version: Option<&str>,
) -> InstallationStatus {
    if let Some(latest) = latest_version {
        if version_less_than(&current, latest) {
            return InstallationStatus::Outdated {
                path,
                current,
                latest: latest.to_string(),
            };
        }
    }
    InstallationStatus::Installed {
        path,
        version: current,
    }
}

/// Simple version comparison using semver.
pub fn version_less_than(current: &str, latest: &str) -> bool {
    match (
        semver::Version::parse(current),
        semver::Version::parse(latest),
    ) {
        (Ok(c), Ok(l)) => c < l,
        _ => current < latest, // fallback string comparison
    }
}

/// Parse the version string from `clawdefender --version` output.
pub fn parse_version_output(output: &str) -> Result<String> {
    parse_version_string(output)
        .ok_or_else(|| anyhow::anyhow!("Could not parse version from: {}", output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_string() {
        assert_eq!(
            parse_version_string("clawdefender 0.1.0"),
            Some("0.1.0".to_string())
        );
        assert_eq!(parse_version_string("0.2.0\n"), Some("0.2.0".to_string()));
        assert_eq!(parse_version_string("garbage"), None);
    }

    #[test]
    fn test_version_less_than() {
        assert!(version_less_than("0.1.0", "0.2.0"));
        assert!(!version_less_than("0.2.0", "0.1.0"));
        assert!(!version_less_than("0.1.0", "0.1.0"));
        assert!(version_less_than("1.0.0", "2.0.0"));
    }
}
