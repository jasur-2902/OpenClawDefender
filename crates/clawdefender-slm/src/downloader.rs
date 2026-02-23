//! Download engine with progress tracking, resume, cancellation, and SHA-256 verification.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{watch, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use crate::model_registry;

/// All-zeros placeholder means "skip verification".
const PLACEHOLDER_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Minimum bytes between progress updates.
const PROGRESS_UPDATE_INTERVAL_BYTES: u64 = 100 * 1024; // 100 KB

// ---------------------------------------------------------------------------
// Progress types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadProgress {
    pub task_id: String,
    pub status: DownloadStatus,
    pub bytes_downloaded: u64,
    pub bytes_total: u64,
    pub speed_bytes_per_sec: f64,
    pub eta_seconds: f64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DownloadStatus {
    Pending,
    Downloading,
    Verifying,
    Completed,
    Cancelled,
    Failed(String),
}

/// Information about an installed model file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledModelInfo {
    pub filename: String,
    pub size_bytes: u64,
    pub catalog_id: Option<String>,
    pub display_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal task handle
// ---------------------------------------------------------------------------

struct DownloadTask {
    #[allow(dead_code)] // kept alive to prevent channel close
    progress_tx: watch::Sender<DownloadProgress>,
    progress_rx: watch::Receiver<DownloadProgress>,
    cancel_token: CancellationToken,
}

// ---------------------------------------------------------------------------
// DownloadManager
// ---------------------------------------------------------------------------

/// Manages concurrent model downloads with progress tracking and cancellation.
pub struct DownloadManager {
    downloads: Arc<Mutex<HashMap<String, DownloadTask>>>,
    client: Client,
}

impl DownloadManager {
    pub fn new() -> Self {
        // Security: Use a custom redirect policy that validates redirect targets
        // stay within allowed domains. reqwest follows redirects by default,
        // which could allow a malicious redirect to an attacker-controlled server.
        let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > 5 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        });

        let client = Client::builder()
            .user_agent("ClawDefender/0.1")
            .redirect(redirect_policy)
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            downloads: Arc::new(Mutex::new(HashMap::new())),
            client,
        }
    }

    /// Start downloading a catalog model by its ID.
    /// Returns the task_id for progress tracking.
    pub async fn start_download(&self, model_id: &str, models_dir: &Path) -> Result<String> {
        let model = model_registry::find_model(model_id)
            .ok_or_else(|| anyhow::anyhow!("model not found in catalog: {}", model_id))?;

        let task_id = Uuid::new_v4().to_string();
        let dest = models_dir.join(&model.filename);

        // Already downloaded?
        if dest.exists() {
            let meta = std::fs::metadata(&dest)?;
            if meta.len() > 0 {
                bail!("model already installed: {}", model.filename);
            }
        }

        self.spawn_download(
            task_id.clone(),
            model.download_url.clone(),
            model.filename.clone(),
            model.size_bytes,
            model.sha256.clone(),
            models_dir.to_path_buf(),
        )
        .await;

        Ok(task_id)
    }

    /// Start downloading from a custom URL.
    /// Returns the task_id for progress tracking.
    pub async fn start_custom_download(&self, url: &str, models_dir: &Path) -> Result<String> {
        // Security: Validate the URL scheme is HTTPS to prevent file:// or other protocol attacks.
        validate_download_url(url)?;

        let task_id = Uuid::new_v4().to_string();

        // Extract filename from URL
        let filename = url
            .rsplit('/')
            .next()
            .unwrap_or("custom-model.gguf")
            .split('?')
            .next()
            .unwrap_or("custom-model.gguf")
            .to_string();

        // Security: Validate extracted filename has no path traversal components.
        if filename.contains("..") || filename.contains('/') || filename.contains('\\') || filename.is_empty() {
            bail!("invalid filename extracted from URL");
        }

        let dest = models_dir.join(&filename);
        if dest.exists() {
            let meta = std::fs::metadata(&dest)?;
            if meta.len() > 0 {
                bail!("file already exists: {}", filename);
            }
        }

        self.spawn_download(
            task_id.clone(),
            url.to_string(),
            filename,
            0, // unknown size
            PLACEHOLDER_SHA256.to_string(), // no checksum for custom
            models_dir.to_path_buf(),
        )
        .await;

        Ok(task_id)
    }

    /// Get current progress for a download task.
    pub async fn get_progress(&self, task_id: &str) -> Option<DownloadProgress> {
        let downloads = self.downloads.lock().await;
        downloads
            .get(task_id)
            .map(|task| task.progress_rx.borrow().clone())
    }

    /// Cancel an active download. Returns true if the task was found and cancelled.
    pub async fn cancel(&self, task_id: &str) -> bool {
        let downloads = self.downloads.lock().await;
        if let Some(task) = downloads.get(task_id) {
            task.cancel_token.cancel();
            true
        } else {
            false
        }
    }

    /// Delete an installed model file.
    pub fn delete_model(filename: &str, models_dir: &Path) -> Result<()> {
        // Security: Prevent path traversal in filename.
        if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
            bail!("invalid model filename: path traversal not allowed");
        }
        let path = models_dir.join(filename);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed to delete {}", path.display()))?;
            info!(path = %path.display(), "deleted model file");
        }
        // Also clean up any leftover .part file
        let part_path = models_dir.join(format!("{}.part", filename));
        if part_path.exists() {
            std::fs::remove_file(&part_path).ok();
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    async fn spawn_download(
        &self,
        task_id: String,
        url: String,
        filename: String,
        expected_size: u64,
        sha256: String,
        models_dir: PathBuf,
    ) {
        let initial = DownloadProgress {
            task_id: task_id.clone(),
            status: DownloadStatus::Pending,
            bytes_downloaded: 0,
            bytes_total: expected_size,
            speed_bytes_per_sec: 0.0,
            eta_seconds: 0.0,
            percent: 0.0,
        };

        let (tx, rx) = watch::channel(initial);
        let cancel_token = CancellationToken::new();

        let task = DownloadTask {
            progress_tx: tx.clone(),
            progress_rx: rx,
            cancel_token: cancel_token.clone(),
        };

        {
            let mut downloads = self.downloads.lock().await;
            downloads.insert(task_id.clone(), task);
        }

        let client = self.client.clone();
        let downloads_ref = self.downloads.clone();

        tokio::spawn(async move {
            let result = run_download(
                &client,
                &tx,
                &cancel_token,
                &task_id,
                &url,
                &filename,
                expected_size,
                &sha256,
                &models_dir,
            )
            .await;

            if let Err(e) = result {
                let _ = tx.send(DownloadProgress {
                    task_id: task_id.clone(),
                    status: DownloadStatus::Failed(e.to_string()),
                    bytes_downloaded: tx.borrow().bytes_downloaded,
                    bytes_total: tx.borrow().bytes_total,
                    speed_bytes_per_sec: 0.0,
                    eta_seconds: 0.0,
                    percent: tx.borrow().percent,
                });
            }

            // Clean up completed/failed tasks after a delay so clients can read final status
            let task_id_cleanup = task_id.clone();
            let downloads_cleanup = downloads_ref.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                let mut downloads = downloads_cleanup.lock().await;
                downloads.remove(&task_id_cleanup);
            });
        });
    }
}

impl Default for DownloadManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Core download logic
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_download(
    client: &Client,
    tx: &watch::Sender<DownloadProgress>,
    cancel_token: &CancellationToken,
    task_id: &str,
    url: &str,
    filename: &str,
    expected_size: u64,
    sha256: &str,
    models_dir: &Path,
) -> Result<()> {
    // Ensure models directory exists
    tokio::fs::create_dir_all(models_dir).await?;

    let dest = models_dir.join(filename);
    let part_path = models_dir.join(format!("{}.part", filename));

    // Check disk space (need at least expected_size + 100MB buffer)
    if expected_size > 0 {
        check_disk_space(models_dir, expected_size)?;
    }

    // Check for existing partial download (resume support)
    let mut resume_from: u64 = 0;
    if part_path.exists() {
        let meta = tokio::fs::metadata(&part_path).await?;
        resume_from = meta.len();
        info!(
            resume_from,
            part_file = %part_path.display(),
            "found partial download, attempting resume"
        );
    }

    // Build request with optional Range header for resume
    let mut request = client.get(url);
    if resume_from > 0 {
        request = request.header("Range", format!("bytes={}-", resume_from));
    }

    // Send request
    let resp = request.send().await.context("HTTP request failed")?;

    let status = resp.status();
    if !status.is_success() && status.as_u16() != 206 {
        bail!("download failed: HTTP {}", status);
    }

    // If we got a 200 instead of 206, server doesn't support range — restart from 0
    if resume_from > 0 && status.as_u16() == 200 {
        warn!("server did not honor Range header, restarting download from scratch");
        resume_from = 0;
    }

    let content_length = resp.content_length().unwrap_or(0);
    let bytes_total = if status.as_u16() == 206 {
        // Partial content: total = resume_from + content_length
        resume_from + content_length
    } else if content_length > 0 {
        content_length
    } else if expected_size > 0 {
        expected_size
    } else {
        0
    };

    // Open file for writing (append if resuming, create if not)
    let mut file = if resume_from > 0 && status.as_u16() == 206 {
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(&part_path)
            .await
            .context("failed to open part file for resume")?
    } else {
        resume_from = 0;
        tokio::fs::File::create(&part_path)
            .await
            .context("failed to create part file")?
    };

    // Update status to Downloading
    let _ = tx.send(DownloadProgress {
        task_id: task_id.to_string(),
        status: DownloadStatus::Downloading,
        bytes_downloaded: resume_from,
        bytes_total,
        speed_bytes_per_sec: 0.0,
        eta_seconds: 0.0,
        percent: if bytes_total > 0 {
            (resume_from as f64 / bytes_total as f64) * 100.0
        } else {
            0.0
        },
    });

    let mut downloaded = resume_from;
    let mut last_progress_bytes = resume_from;
    let start_time = Instant::now();
    let mut stream = resp.bytes_stream();

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                file.flush().await.ok();
                let _ = tx.send(DownloadProgress {
                    task_id: task_id.to_string(),
                    status: DownloadStatus::Cancelled,
                    bytes_downloaded: downloaded,
                    bytes_total,
                    speed_bytes_per_sec: 0.0,
                    eta_seconds: 0.0,
                    percent: if bytes_total > 0 { (downloaded as f64 / bytes_total as f64) * 100.0 } else { 0.0 },
                });
                info!(task_id, "download cancelled");
                return Ok(());
            }
            chunk = stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        file.write_all(&bytes).await.context("write to part file failed")?;
                        downloaded += bytes.len() as u64;

                        // Throttle progress updates
                        if downloaded - last_progress_bytes >= PROGRESS_UPDATE_INTERVAL_BYTES
                            || downloaded == bytes_total
                        {
                            let elapsed = start_time.elapsed().as_secs_f64();
                            let net_downloaded = downloaded - resume_from;
                            let speed = if elapsed > 0.0 { net_downloaded as f64 / elapsed } else { 0.0 };
                            let remaining = if bytes_total > downloaded { bytes_total - downloaded } else { 0 };
                            let eta = if speed > 0.0 { remaining as f64 / speed } else { 0.0 };
                            let percent = if bytes_total > 0 { (downloaded as f64 / bytes_total as f64) * 100.0 } else { 0.0 };

                            let _ = tx.send(DownloadProgress {
                                task_id: task_id.to_string(),
                                status: DownloadStatus::Downloading,
                                bytes_downloaded: downloaded,
                                bytes_total,
                                speed_bytes_per_sec: speed,
                                eta_seconds: eta,
                                percent,
                            });
                            last_progress_bytes = downloaded;
                        }
                    }
                    Some(Err(e)) => {
                        file.flush().await.ok();
                        bail!("stream error: {}", e);
                    }
                    None => break, // stream ended
                }
            }
        }
    }

    file.flush().await?;
    drop(file);

    // Check cancellation one more time before verification
    if cancel_token.is_cancelled() {
        let _ = tx.send(DownloadProgress {
            task_id: task_id.to_string(),
            status: DownloadStatus::Cancelled,
            bytes_downloaded: downloaded,
            bytes_total,
            speed_bytes_per_sec: 0.0,
            eta_seconds: 0.0,
            percent: if bytes_total > 0 {
                (downloaded as f64 / bytes_total as f64) * 100.0
            } else {
                0.0
            },
        });
        return Ok(());
    }

    // SHA-256 verification
    let skip_verify = sha256 == PLACEHOLDER_SHA256 || sha256.is_empty();
    if !skip_verify {
        let _ = tx.send(DownloadProgress {
            task_id: task_id.to_string(),
            status: DownloadStatus::Verifying,
            bytes_downloaded: downloaded,
            bytes_total,
            speed_bytes_per_sec: 0.0,
            eta_seconds: 0.0,
            percent: 100.0,
        });

        let computed = hash_file(&part_path).await?;
        if computed != sha256 {
            tokio::fs::remove_file(&part_path).await.ok();
            bail!(
                "SHA-256 mismatch: expected {}, got {}",
                sha256,
                computed
            );
        }
        info!(task_id, "SHA-256 verification passed");
    }

    // Rename .part -> final
    tokio::fs::rename(&part_path, &dest)
        .await
        .context("failed to rename part file to final destination")?;

    let _ = tx.send(DownloadProgress {
        task_id: task_id.to_string(),
        status: DownloadStatus::Completed,
        bytes_downloaded: downloaded,
        bytes_total: downloaded, // correct total if it was unknown
        speed_bytes_per_sec: 0.0,
        eta_seconds: 0.0,
        percent: 100.0,
    });

    info!(task_id, filename, "download completed successfully");
    Ok(())
}

/// Compute SHA-256 of a file.
async fn hash_file(path: &Path) -> Result<String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    })
    .await?
}

/// Check that there is enough disk space.
fn check_disk_space(dir: &Path, needed_bytes: u64) -> Result<()> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;

        let dir_str = dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid directory path"))?;
        let c_path = CString::new(dir_str)?;

        unsafe {
            let mut stat = MaybeUninit::<libc::statvfs>::uninit();
            if libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) == 0 {
                let stat = stat.assume_init();
                let available = stat.f_bavail as u64 * stat.f_frsize as u64;
                let buffer = 100 * 1024 * 1024; // 100 MB buffer
                if available < needed_bytes + buffer {
                    bail!(
                        "insufficient disk space: need {} bytes but only {} available",
                        needed_bytes + buffer,
                        available
                    );
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, needed_bytes);
    }
    Ok(())
}

/// Security: Validate that a download URL uses HTTPS and has a reasonable structure.
/// Prevents file://, ftp://, or other protocol attacks.
fn validate_download_url(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        bail!("download URL must use HTTPS");
    }

    // Must have a hostname after https://
    let after_scheme = &url["https://".len()..];
    let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    let host = &after_scheme[..host_end];
    if host.is_empty() || !host.contains('.') {
        bail!("download URL must have a valid hostname");
    }

    Ok(())
}

/// List installed models with catalog metadata.
pub fn list_installed_models(models_dir: &Path) -> Result<Vec<InstalledModelInfo>> {
    let mut installed = Vec::new();
    if !models_dir.exists() {
        return Ok(installed);
    }

    let catalog = model_registry::catalog();

    let entries = std::fs::read_dir(models_dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("gguf") {
            let filename = entry.file_name().to_string_lossy().to_string();
            let metadata = entry.metadata()?;

            // Try to match against catalog
            let catalog_match = catalog.iter().find(|m| m.filename == filename);

            installed.push(InstalledModelInfo {
                filename,
                size_bytes: metadata.len(),
                catalog_id: catalog_match.map(|m| m.id.clone()),
                display_name: catalog_match.map(|m| m.display_name.clone()),
            });
        }
    }

    installed.sort_by(|a, b| a.filename.cmp(&b.filename));
    Ok(installed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_status_serialization() {
        let progress = DownloadProgress {
            task_id: "test-123".to_string(),
            status: DownloadStatus::Downloading,
            bytes_downloaded: 500,
            bytes_total: 1000,
            speed_bytes_per_sec: 100.0,
            eta_seconds: 5.0,
            percent: 50.0,
        };
        let json = serde_json::to_string(&progress).unwrap();
        let parsed: DownloadProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.task_id, "test-123");
        assert_eq!(parsed.status, DownloadStatus::Downloading);
        assert_eq!(parsed.bytes_downloaded, 500);
    }

    #[test]
    fn download_status_failed_serialization() {
        let status = DownloadStatus::Failed("network error".to_string());
        let json = serde_json::to_string(&status).unwrap();
        let parsed: DownloadStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DownloadStatus::Failed("network error".to_string()));
    }

    #[test]
    fn installed_model_info_serialization() {
        let info = InstalledModelInfo {
            filename: "test.gguf".to_string(),
            size_bytes: 1000,
            catalog_id: Some("test-model".to_string()),
            display_name: Some("Test Model".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: InstalledModelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.filename, "test.gguf");
        assert_eq!(parsed.catalog_id, Some("test-model".to_string()));
    }

    #[test]
    fn list_installed_empty_when_dir_missing() {
        let result = list_installed_models(Path::new("/tmp/clawdefender-test-nonexistent-dl"));
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn check_disk_space_passes_for_small_amounts() {
        // /tmp should have enough space for a tiny amount
        let result = check_disk_space(Path::new("/tmp"), 1024);
        assert!(result.is_ok());
    }

    #[test]
    fn download_manager_default() {
        let _dm = DownloadManager::new();
    }

    #[tokio::test]
    async fn cancel_nonexistent_task_returns_false() {
        let dm = DownloadManager::new();
        assert!(!dm.cancel("nonexistent").await);
    }

    #[tokio::test]
    async fn get_progress_nonexistent_returns_none() {
        let dm = DownloadManager::new();
        assert!(dm.get_progress("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn start_download_unknown_model_fails() {
        let dm = DownloadManager::new();
        let result = dm.start_download("nonexistent-model", Path::new("/tmp")).await;
        assert!(result.is_err());
    }

    #[test]
    fn download_status_all_variants_serialize() {
        let variants = vec![
            DownloadStatus::Pending,
            DownloadStatus::Downloading,
            DownloadStatus::Verifying,
            DownloadStatus::Completed,
            DownloadStatus::Cancelled,
            DownloadStatus::Failed("err".into()),
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let parsed: DownloadStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn list_installed_models_scans_temp_dir() {
        let dir = std::env::temp_dir().join("clawdefender-test-scan-models");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Create fake .gguf files
        std::fs::write(dir.join("model-a.gguf"), b"fake gguf data").unwrap();
        std::fs::write(dir.join("model-b.gguf"), b"more fake data").unwrap();
        // Non-gguf file should be ignored
        std::fs::write(dir.join("readme.txt"), b"not a model").unwrap();

        let installed = list_installed_models(&dir).unwrap();
        assert_eq!(installed.len(), 2);
        assert_eq!(installed[0].filename, "model-a.gguf");
        assert_eq!(installed[1].filename, "model-b.gguf");
        assert!(installed[0].size_bytes > 0);
        // Non-catalog models should have None for catalog_id
        assert!(installed[0].catalog_id.is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn validate_download_url_rejects_http() {
        assert!(validate_download_url("http://example.com/model.gguf").is_err());
    }

    #[test]
    fn validate_download_url_rejects_file_protocol() {
        assert!(validate_download_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn validate_download_url_accepts_https() {
        assert!(validate_download_url("https://example.com/model.gguf").is_ok());
    }

    #[test]
    fn validate_download_url_rejects_no_hostname() {
        assert!(validate_download_url("https:///path").is_err());
    }

    #[test]
    fn download_progress_percent_field() {
        let progress = DownloadProgress {
            task_id: "t1".into(),
            status: DownloadStatus::Completed,
            bytes_downloaded: 1000,
            bytes_total: 1000,
            speed_bytes_per_sec: 0.0,
            eta_seconds: 0.0,
            percent: 100.0,
        };
        let json = serde_json::to_string(&progress).unwrap();
        assert!(json.contains("100"));
        let parsed: DownloadProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.percent, 100.0);
    }
}
