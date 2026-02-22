//! Downloader for ClawDefender binaries from GitHub releases.

use anyhow::{bail, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

/// Base URL for GitHub releases.
const RELEASE_BASE_URL: &str =
    "https://github.com/clawdefender/clawdefender/releases/latest/download";

/// Trait for downloading ClawDefender binaries. Mockable for testing.
#[async_trait]
pub trait Downloader: Send + Sync {
    /// Download content from the given URL.
    async fn download(&self, url: &str) -> Result<Vec<u8>>;
    /// Get the latest available version string.
    async fn get_latest_version(&self) -> Result<String>;
}

/// Real downloader that fetches from GitHub releases.
pub struct GithubDownloader;

#[async_trait]
impl Downloader for GithubDownloader {
    async fn download(&self, url: &str) -> Result<Vec<u8>> {
        // In a real implementation, this would use reqwest or hyper.
        // For now, use a simple subprocess call to curl as a fallback.
        let output = tokio::process::Command::new("curl")
            .args(["-fsSL", "--max-time", "120", url])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Download failed from {url}: {stderr}");
        }

        Ok(output.stdout)
    }

    async fn get_latest_version(&self) -> Result<String> {
        // Query GitHub API for latest release tag
        let output = tokio::process::Command::new("curl")
            .args([
                "-fsSL",
                "--max-time",
                "30",
                "-H",
                "Accept: application/json",
                "https://api.github.com/repos/clawdefender/clawdefender/releases/latest",
            ])
            .output()
            .await?;

        if !output.status.success() {
            bail!("Failed to query latest version from GitHub");
        }

        let body: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let tag = body["tag_name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No tag_name in release response"))?;

        // Strip leading 'v' if present
        Ok(tag.strip_prefix('v').unwrap_or(tag).to_string())
    }
}

/// Mock downloader for testing.
pub struct MockDownloader {
    pub binary_data: Vec<u8>,
    pub checksum: String,
    pub version: String,
    /// If set, download() will return this error.
    pub should_fail: bool,
}

impl MockDownloader {
    /// Create a new mock downloader with the given binary data and version.
    pub fn new(binary_data: Vec<u8>, version: &str) -> Self {
        let checksum = compute_sha256(&binary_data);
        Self {
            binary_data,
            checksum,
            version: version.to_string(),
            should_fail: false,
        }
    }

    /// Create a mock downloader that will fail on download.
    pub fn failing() -> Self {
        Self {
            binary_data: vec![],
            checksum: String::new(),
            version: String::new(),
            should_fail: true,
        }
    }
}

#[async_trait]
impl Downloader for MockDownloader {
    async fn download(&self, url: &str) -> Result<Vec<u8>> {
        if self.should_fail {
            bail!("Mock download failure");
        }
        if url.ends_with(".sha256") {
            // Return checksum file content: "<hash>  filename\n"
            Ok(format!("{}  clawdefender\n", self.checksum).into_bytes())
        } else {
            Ok(self.binary_data.clone())
        }
    }

    async fn get_latest_version(&self) -> Result<String> {
        if self.should_fail {
            bail!("Mock version check failure");
        }
        Ok(self.version.clone())
    }
}

/// Compute the SHA-256 hash of data and return it as a hex string.
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Verify a binary's SHA-256 checksum against the expected checksum file content.
///
/// The checksum file format is: `<hex_hash>  <filename>\n`
pub fn verify_checksum(data: &[u8], checksum_content: &str) -> Result<()> {
    let expected = checksum_content
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid checksum file format"))?
        .to_lowercase();

    let actual = compute_sha256(data);

    if actual != expected {
        bail!("Checksum mismatch: expected {expected}, got {actual}");
    }

    Ok(())
}

/// Build the download URL for a given platform.
pub fn build_download_url(platform_string: &str) -> String {
    format!("{RELEASE_BASE_URL}/clawdefender-{platform_string}")
}

/// Build the checksum URL for a given platform.
pub fn build_checksum_url(platform_string: &str) -> String {
    format!("{RELEASE_BASE_URL}/clawdefender-{platform_string}.sha256")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256() {
        let data = b"hello world";
        let hash = compute_sha256(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_verify_checksum_valid() {
        let data = b"test data";
        let hash = compute_sha256(data);
        let checksum_content = format!("{hash}  clawdefender\n");
        assert!(verify_checksum(data, &checksum_content).is_ok());
    }

    #[test]
    fn test_verify_checksum_invalid() {
        let data = b"test data";
        let checksum_content =
            "0000000000000000000000000000000000000000000000000000000000000000  clawdefender\n";
        assert!(verify_checksum(data, &checksum_content).is_err());
    }

    #[test]
    fn test_build_urls() {
        assert_eq!(
            build_download_url("macos-arm64"),
            "https://github.com/clawdefender/clawdefender/releases/latest/download/clawdefender-macos-arm64"
        );
        assert_eq!(
            build_checksum_url("linux-x86_64"),
            "https://github.com/clawdefender/clawdefender/releases/latest/download/clawdefender-linux-x86_64.sha256"
        );
    }
}
