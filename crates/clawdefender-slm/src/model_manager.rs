//! Model manager: download, verify, list, and activate GGUF models.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Information about a model available in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Human-friendly name (e.g. "TinyLlama 1.1B Q4_K_M").
    pub name: String,
    /// Filename of the GGUF file on disk.
    pub filename: String,
    /// Size of the model file in bytes.
    pub size_bytes: u64,
    /// Quantization level (e.g. "Q4_K_M").
    pub quantization: String,
    /// Download URL.
    pub url: String,
    /// Expected SHA-256 hex digest.
    pub sha256: String,
}

/// Manages model storage on disk.
pub struct ModelManager {
    models_dir: PathBuf,
}

impl ModelManager {
    /// Create a new model manager pointing at the given directory.
    pub fn new(models_dir: PathBuf) -> Self {
        Self { models_dir }
    }

    /// Create a model manager using the default platform directory.
    ///
    /// On macOS/Linux: `~/.local/share/clawdefender/models/`
    pub fn default_dir() -> Result<Self> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| anyhow::anyhow!("cannot determine home directory"))?;
        let dir = PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("clawdefender")
            .join("models");
        Ok(Self { models_dir: dir })
    }

    /// Return the models directory path.
    pub fn models_dir(&self) -> &Path {
        &self.models_dir
    }

    /// List models that are currently installed (present on disk).
    pub fn list_installed(&self) -> Result<Vec<InstalledModel>> {
        let mut installed = Vec::new();
        if !self.models_dir.exists() {
            return Ok(installed);
        }
        let entries = std::fs::read_dir(&self.models_dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("gguf") {
                let metadata = entry.metadata()?;
                installed.push(InstalledModel {
                    filename: entry
                        .file_name()
                        .to_string_lossy()
                        .to_string(),
                    path,
                    size_bytes: metadata.len(),
                });
            }
        }
        installed.sort_by(|a, b| a.filename.cmp(&b.filename));
        Ok(installed)
    }

    /// Return the full path where a model file would be stored.
    pub fn model_path(&self, filename: &str) -> PathBuf {
        self.models_dir.join(filename)
    }

    /// Check if a specific model file exists on disk.
    pub fn is_installed(&self, filename: &str) -> bool {
        self.model_path(filename).exists()
    }

    /// Ensure the models directory exists, creating it if needed.
    pub fn ensure_dir(&self) -> Result<()> {
        if !self.models_dir.exists() {
            std::fs::create_dir_all(&self.models_dir)?;
            info!(dir = %self.models_dir.display(), "created models directory");
        }
        Ok(())
    }

    /// Download a model with progress callback and SHA-256 verification.
    ///
    /// Only available when the `download` feature is enabled.
    #[cfg(feature = "download")]
    pub async fn download<F>(
        &self,
        model: &ModelInfo,
        progress: F,
    ) -> Result<PathBuf>
    where
        F: Fn(u64, u64) + Send + 'static,
    {
        use sha2::{Digest, Sha256};

        self.ensure_dir()?;
        let dest = self.model_path(&model.filename);
        if dest.exists() {
            info!(path = %dest.display(), "model already exists, skipping download");
            return Ok(dest);
        }

        let tmp = dest.with_extension("gguf.tmp");
        info!(url = %model.url, dest = %dest.display(), "downloading model");

        let client = reqwest::Client::new();
        let resp = client.get(&model.url).send().await?;
        if !resp.status().is_success() {
            bail!("download failed: HTTP {}", resp.status());
        }
        let total = resp.content_length().unwrap_or(model.size_bytes);

        let mut file = tokio::fs::File::create(&tmp).await?;
        let mut hasher = Sha256::new();
        let mut downloaded: u64 = 0;

        use tokio::io::AsyncWriteExt;
        let mut stream = resp.bytes_stream();
        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            progress(downloaded, total);
        }
        file.flush().await?;
        drop(file);

        // Verify checksum.
        let digest = format!("{:x}", hasher.finalize());
        if digest != model.sha256 {
            tokio::fs::remove_file(&tmp).await.ok();
            bail!(
                "SHA-256 mismatch: expected {}, got {}",
                model.sha256,
                digest
            );
        }

        tokio::fs::rename(&tmp, &dest).await?;
        info!(path = %dest.display(), "model downloaded and verified");
        Ok(dest)
    }

    /// Delete an installed model file.
    pub fn delete(&self, filename: &str) -> Result<()> {
        let path = self.model_path(filename);
        if path.exists() {
            std::fs::remove_file(&path)?;
            info!(path = %path.display(), "deleted model file");
        }
        Ok(())
    }
}

/// An installed model file on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledModel {
    pub filename: String,
    pub path: PathBuf,
    pub size_bytes: u64,
}

// ---------------------------------------------------------------------------
// Built-in model registry
// ---------------------------------------------------------------------------

/// Return the built-in registry of recommended models.
pub fn recommended_models() -> Vec<ModelInfo> {
    vec![
        ModelInfo {
            name: "TinyLlama 1.1B Chat Q4_K_M".to_string(),
            filename: "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf".to_string(),
            size_bytes: 669_000_000,
            quantization: "Q4_K_M".to_string(),
            url: "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf".to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        },
        ModelInfo {
            name: "Phi-2 Q4_K_M".to_string(),
            filename: "phi-2.Q4_K_M.gguf".to_string(),
            size_bytes: 1_790_000_000,
            quantization: "Q4_K_M".to_string(),
            url: "https://huggingface.co/TheBloke/phi-2-GGUF/resolve/main/phi-2.Q4_K_M.gguf".to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        },
        ModelInfo {
            name: "Qwen2-0.5B Instruct Q8_0".to_string(),
            filename: "qwen2-0_5b-instruct-q8_0.gguf".to_string(),
            size_bytes: 530_000_000,
            quantization: "Q8_0".to_string(),
            url: "https://huggingface.co/Qwen/Qwen2-0.5B-Instruct-GGUF/resolve/main/qwen2-0_5b-instruct-q8_0.gguf".to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dir_is_under_home() {
        // Requires HOME to be set, which it is in test environments.
        if std::env::var("HOME").is_ok() {
            let mgr = ModelManager::default_dir().unwrap();
            let dir = mgr.models_dir().to_string_lossy();
            assert!(dir.contains("clawdefender"));
            assert!(dir.ends_with("models"));
        }
    }

    #[test]
    fn model_path_construction() {
        let mgr = ModelManager::new(PathBuf::from("/tmp/models"));
        assert_eq!(
            mgr.model_path("test.gguf"),
            PathBuf::from("/tmp/models/test.gguf")
        );
    }

    #[test]
    fn is_installed_false_for_nonexistent() {
        let mgr = ModelManager::new(PathBuf::from("/tmp/clawdefender-test-nonexistent"));
        assert!(!mgr.is_installed("nope.gguf"));
    }

    #[test]
    fn list_installed_empty_when_dir_missing() {
        let mgr = ModelManager::new(PathBuf::from("/tmp/clawdefender-test-nonexistent"));
        let list = mgr.list_installed().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn recommended_models_not_empty() {
        let models = recommended_models();
        assert!(models.len() >= 2);
        for m in &models {
            assert!(!m.name.is_empty());
            assert!(m.filename.ends_with(".gguf"));
            assert!(m.size_bytes > 0);
        }
    }

    #[test]
    fn ensure_dir_creates_directory() {
        let dir = std::env::temp_dir().join("clawdefender-test-ensure-dir");
        let _ = std::fs::remove_dir_all(&dir);
        let mgr = ModelManager::new(dir.clone());
        mgr.ensure_dir().unwrap();
        assert!(dir.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn delete_nonexistent_is_ok() {
        let mgr = ModelManager::new(std::env::temp_dir());
        // Should not error when deleting a file that doesn't exist.
        mgr.delete("nonexistent-model.gguf").unwrap();
    }
}
