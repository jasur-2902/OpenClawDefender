//! Crash report collection and management.
//!
//! Collects privacy-safe crash reports and stores them as JSON files
//! in ~/.local/share/clawdefender/crashes/. Reports include only
//! non-sensitive system information and never contain audit log contents,
//! file paths from events, policy rules, API keys, or behavioral data.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Directory where crash reports are stored.
fn crashes_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/share/clawdefender/crashes")
}

/// A crash report with privacy-safe system information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    pub id: String,
    pub timestamp: String,
    pub crash_type: String,
    pub details: String,
    pub app_version: String,
    pub os_version: String,
    pub arch: String,
}

/// Save a crash report to disk.
///
/// PRIVACY: Only captures app version, OS version, crash type, and details.
/// NEVER includes: audit log contents, file paths from events, policy rules,
/// API keys, or behavioral data.
pub fn save_crash_report(crash_type: &str, details: &str) -> Result<String, String> {
    let dir = crashes_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create crashes directory: {}", e))?;

    let now = chrono::Utc::now();
    let id = format!("crash-{}", now.format("%Y%m%d-%H%M%S"));
    let filename = format!("{}.json", id);

    // Get OS version (macOS)
    let os_version = get_os_version();

    let report = CrashReport {
        id: id.clone(),
        timestamp: now.to_rfc3339(),
        crash_type: crash_type.to_string(),
        details: details.to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        os_version,
        arch: std::env::consts::ARCH.to_string(),
    };

    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Failed to serialize crash report: {}", e))?;

    let path = dir.join(&filename);
    std::fs::write(&path, json)
        .map_err(|e| format!("Failed to write crash report: {}", e))?;

    tracing::info!(id = %id, crash_type = %crash_type, "Saved crash report");
    Ok(id)
}

/// List all pending crash reports.
pub fn list_crash_reports() -> Vec<CrashReport> {
    let dir = crashes_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return vec![],
    };

    let mut reports = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        match serde_json::from_str::<CrashReport>(&content) {
            Ok(report) => reports.push(report),
            Err(_) => continue,
        }
    }

    reports.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    reports
}

/// Get a specific crash report by ID.
pub fn get_crash_report(id: &str) -> Option<CrashReport> {
    let path = crashes_dir().join(format!("{}.json", id));
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Delete (dismiss) a crash report by ID.
pub fn dismiss_crash_report(id: &str) -> Result<(), String> {
    let path = crashes_dir().join(format!("{}.json", id));
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to delete crash report: {}", e))?;
        tracing::info!(id = %id, "Dismissed crash report");
    }
    Ok(())
}

/// Get macOS version string using sw_vers.
fn get_os_version() -> String {
    std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| format!("macOS {}", s.trim()))
        .unwrap_or_else(|| format!("{} {}", std::env::consts::OS, std::env::consts::ARCH))
}
