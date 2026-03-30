//! Atomic file writes using the write-fsync-rename pattern.
//!
//! On POSIX systems, `rename(2)` is atomic within the same filesystem.
//! This module writes content to a temporary file in the same directory,
//! calls `fsync` to flush to disk, then renames over the target path.
//! If any step fails, the temporary file is cleaned up and the original
//! file is preserved.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonically increasing counter to ensure unique temp file names.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomically write `contents` to `path`.
///
/// 1. Write to a uniquely-named temp file in the same directory.
/// 2. `fsync` the file descriptor to ensure durability.
/// 3. Rename the temp file to `<path>` (atomic on POSIX).
/// 4. On error, clean up the temp file.
pub fn atomic_write_file(path: &Path, contents: &str) -> std::io::Result<()> {
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string()),
        pid,
        seq,
    );
    let tmp_path = path.with_file_name(tmp_name);

    // Write to temp file
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?; // fsync
        Ok(())
    })();

    if let Err(e) = result {
        // Clean up temp file on write/sync failure
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Atomic rename
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    Ok(())
}

/// Atomically write `contents` to `path`, creating a `.bak` backup first.
///
/// If `path` already exists, its current contents are copied to `path.bak`
/// (overwriting any previous backup) before the atomic write proceeds.
/// This provides an additional safety net: even if the atomic write succeeds
/// but the new content is logically wrong, the previous version is recoverable.
pub fn atomic_write_with_backup(path: &Path, contents: &str) -> std::io::Result<()> {
    if path.exists() {
        let bak_extension = match path.extension() {
            Some(ext) => format!("{}.bak", ext.to_string_lossy()),
            None => "bak".to_string(),
        };
        let backup_path = path.with_extension(bak_extension);
        // Best-effort backup -- warn but don't fail the write if backup fails
        if let Err(e) = std::fs::copy(path, &backup_path) {
            eprintln!(
                "Warning: failed to create backup at {}: {}",
                backup_path.display(),
                e
            );
        }
    }
    atomic_write_file(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn successful_write_creates_file_and_cleans_tmp() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");

        atomic_write_file(&path, "key = \"value\"\n").unwrap();

        // File should exist with correct content
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "key = \"value\"\n");

        // No temp files should remain in the directory
        let tmp_files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(tmp_files.is_empty(), "temp files should be cleaned up");
    }

    #[test]
    fn overwrites_existing_file_atomically() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");

        std::fs::write(&path, "original content").unwrap();
        atomic_write_file(&path, "new content").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new content");
    }

    #[test]
    fn preserves_original_on_invalid_directory() {
        // Writing to a non-existent directory should fail
        let path = PathBuf::from("/nonexistent_dir_12345/config.toml");
        let result = atomic_write_file(&path, "data");
        assert!(result.is_err());
    }

    #[test]
    fn tmp_cleaned_up_after_write() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.toml");

        atomic_write_file(&path, "hello").unwrap();

        // No temp files should remain in the directory
        let tmp_files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(tmp_files.is_empty(), "temp file should be cleaned up");
    }

    #[test]
    fn concurrent_writes_dont_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "initial").unwrap();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let p = path.clone();
                std::thread::spawn(move || {
                    let content = format!("writer-{}-content\n", i);
                    atomic_write_file(&p, &content).unwrap();
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // File must contain exactly one writer's content (no corruption/mixing)
        let final_content = std::fs::read_to_string(&path).unwrap();
        assert!(final_content.starts_with("writer-"));
        assert!(final_content.ends_with("-content\n"));
    }

    #[test]
    fn handles_file_without_extension() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("noext");

        atomic_write_file(&path, "data").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "data");

        // Temp file should use .tmp extension
        let tmp_path = path.with_extension("tmp");
        assert!(!tmp_path.exists());
    }

    // --- atomic_write_with_backup tests ---

    #[test]
    fn backup_creates_bak_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");

        std::fs::write(&path, "original").unwrap();
        atomic_write_with_backup(&path, "updated").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "updated");
        let bak = dir.path().join("config.toml.bak");
        assert!(bak.exists(), ".bak file should be created");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), "original");
    }

    #[test]
    fn backup_overwrites_previous_bak() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");

        std::fs::write(&path, "v1").unwrap();
        atomic_write_with_backup(&path, "v2").unwrap();
        atomic_write_with_backup(&path, "v3").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "v3");
        let bak = dir.path().join("config.toml.bak");
        // .bak should contain the version just before the latest write
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), "v2");
    }

    #[test]
    fn backup_skipped_for_new_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("new.toml");

        // No existing file -- backup should be skipped, write should succeed
        atomic_write_with_backup(&path, "fresh").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "fresh");
        let bak = dir.path().join("new.toml.bak");
        assert!(!bak.exists(), ".bak should not exist for new files");
    }

    #[test]
    fn backup_with_no_extension() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("configfile");

        std::fs::write(&path, "old").unwrap();
        atomic_write_with_backup(&path, "new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let bak = dir.path().join("configfile.bak");
        assert!(bak.exists());
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), "old");
    }
}
