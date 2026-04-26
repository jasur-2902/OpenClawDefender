use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::finding::{calculate_cvss, CvssVector, Evidence, Finding, ModuleCategory, Severity};
use crate::modules::{ScanContext, ScanModule};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBaseline {
    pub sha256: String,
    pub size: u64,
    pub permissions: u32,
    pub mtime_epoch: i64,
    pub last_verified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimBaseline {
    pub version: u32,
    pub created_at: String,
    pub files: HashMap<String, FileBaseline>,
}

#[derive(Debug, Clone)]
pub enum IntegrityViolation {
    HashChanged {
        path: String,
        old: String,
        new: String,
    },
    PermissionChanged {
        path: String,
        old: u32,
        new: u32,
    },
    FileDeleted {
        path: String,
    },
    NewFile {
        path: String,
    },
    SizeChanged {
        path: String,
        old: u64,
        new: u64,
    },
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct FileIntegrityModule;

impl FileIntegrityModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanModule for FileIntegrityModule {
    fn name(&self) -> &str {
        "file-integrity"
    }

    fn description(&self) -> &str {
        "File integrity monitoring via SHA-256 checksums"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Configuration
    }

    async fn run(&self, _ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        self.run_standalone().await
    }

    async fn run_standalone(&self) -> Result<Vec<Finding>> {
        let watch_paths = default_watch_paths();
        let existing_baseline = load_baseline()?;

        match existing_baseline {
            None => {
                let baseline = create_baseline(&watch_paths)?;
                let file_count = baseline.files.len();
                save_baseline(&baseline)?;

                let cvss_vec = CvssVector::configuration_info();
                let cvss = calculate_cvss(&cvss_vec);

                Ok(vec![Finding {
                    id: "FIM-INFO-001".to_string(),
                    title: format!("File integrity baseline created for {} files", file_count),
                    severity: Severity::Info,
                    cvss,
                    category: ModuleCategory::Configuration,
                    description: format!(
                        "Initial file integrity baseline established. {} files are now \
                         being monitored for unauthorized modifications. Run the integrity \
                         check again to detect changes.",
                        file_count
                    ),
                    reproduction: None,
                    evidence: Evidence::empty(),
                    remediation: "No action needed. The baseline has been saved and future \
                                  scans will compare against it."
                        .to_string(),
                }])
            }
            Some(old) => {
                let (new_baseline, violations) = compare_against_baseline(&old, &watch_paths)?;
                save_baseline(&new_baseline)?;
                Ok(violations_to_findings(violations))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Watch list
// ---------------------------------------------------------------------------

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn default_watch_paths() -> Vec<PathBuf> {
    let home = dirs_home();
    let mut paths = vec![
        // System files
        PathBuf::from("/etc/sudoers"),
        PathBuf::from("/etc/hosts"),
        PathBuf::from("/etc/ssh/sshd_config"),
        // User credentials (NOT private keys — never read ~/.ssh/id_*)
        home.join(".ssh/config"),
        home.join(".ssh/authorized_keys"),
        home.join(".ssh/known_hosts"),
        // Shell init
        home.join(".zshrc"),
        home.join(".zprofile"),
        home.join(".zshenv"),
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".profile"),
        // RookBot configs
        home.join(".config/rookbot/policy.toml"),
        home.join(".config/rookbot/config.toml"),
    ];

    // Directories to watch (enumerate all files within)
    let watch_dirs = vec![
        home.join("Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchDaemons"),
        PathBuf::from("/etc/sudoers.d"),
        PathBuf::from("/etc/pam.d"),
    ];

    for dir in watch_dirs {
        if dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    if entry.path().is_file() {
                        paths.push(entry.path());
                    }
                }
            }
        }
    }

    paths
}

// ---------------------------------------------------------------------------
// Checksum computation
// ---------------------------------------------------------------------------

fn compute_file_baseline(path: &Path) -> Result<FileBaseline> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = format!("{:x}", hasher.finalize());

    let meta = std::fs::metadata(path)?;
    let permissions = meta.permissions().mode();
    let mtime = meta
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(FileBaseline {
        sha256: hash,
        size: meta.len(),
        permissions,
        mtime_epoch: mtime,
        last_verified: chrono::Utc::now().to_rfc3339(),
    })
}

// ---------------------------------------------------------------------------
// Baseline lifecycle
// ---------------------------------------------------------------------------

const BASELINE_PATH: &str = ".local/share/rookbot/fim_baseline.json";

fn load_baseline() -> Result<Option<FimBaseline>> {
    let home = dirs_home();
    let path = home.join(BASELINE_PATH);
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)?;
    Ok(Some(serde_json::from_str(&data)?))
}

fn save_baseline(baseline: &FimBaseline) -> Result<()> {
    let home = dirs_home();
    let path = home.join(BASELINE_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(baseline)?;
    std::fs::write(&path, data)?;
    Ok(())
}

fn create_baseline(watch_paths: &[PathBuf]) -> Result<FimBaseline> {
    let mut files = HashMap::new();

    for path in watch_paths {
        if path.is_file() {
            match compute_file_baseline(path) {
                Ok(bl) => {
                    files.insert(path.to_string_lossy().to_string(), bl);
                }
                Err(e) => {
                    tracing::debug!(
                        path = %path.display(),
                        error = %e,
                        "Skipping file for baseline (not accessible)"
                    );
                }
            }
        }
    }

    Ok(FimBaseline {
        version: 1,
        created_at: chrono::Utc::now().to_rfc3339(),
        files,
    })
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

fn compare_against_baseline(
    old: &FimBaseline,
    watch_paths: &[PathBuf],
) -> Result<(FimBaseline, Vec<IntegrityViolation>)> {
    let mut violations = Vec::new();
    let new_baseline = create_baseline(watch_paths)?;

    // Check existing baseline entries
    for (path_str, old_entry) in &old.files {
        match new_baseline.files.get(path_str) {
            None => {
                // File was deleted or became inaccessible
                violations.push(IntegrityViolation::FileDeleted {
                    path: path_str.clone(),
                });
            }
            Some(new_entry) => {
                // Check hash
                if old_entry.sha256 != new_entry.sha256 {
                    violations.push(IntegrityViolation::HashChanged {
                        path: path_str.clone(),
                        old: old_entry.sha256.clone(),
                        new: new_entry.sha256.clone(),
                    });
                }
                // Check permissions
                if old_entry.permissions != new_entry.permissions {
                    violations.push(IntegrityViolation::PermissionChanged {
                        path: path_str.clone(),
                        old: old_entry.permissions,
                        new: new_entry.permissions,
                    });
                }
                // Check size (if hash also changed, this is additional info)
                if old_entry.size != new_entry.size && old_entry.sha256 == new_entry.sha256 {
                    // Size changed but hash didn't — shouldn't normally happen,
                    // but flag it if it does (could indicate metadata corruption)
                    violations.push(IntegrityViolation::SizeChanged {
                        path: path_str.clone(),
                        old: old_entry.size,
                        new: new_entry.size,
                    });
                }
            }
        }
    }

    // Check for new files not in the old baseline
    for path_str in new_baseline.files.keys() {
        if !old.files.contains_key(path_str) {
            violations.push(IntegrityViolation::NewFile {
                path: path_str.clone(),
            });
        }
    }

    Ok((new_baseline, violations))
}

// ---------------------------------------------------------------------------
// Violation -> Finding conversion
// ---------------------------------------------------------------------------

fn violations_to_findings(violations: Vec<IntegrityViolation>) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (id_counter, violation) in (1_u32..).zip(violations.into_iter()) {
        let (severity, title, description, file_path) = match &violation {
            IntegrityViolation::HashChanged { path, old, new } => {
                let old_short = if old.len() >= 12 { &old[..12] } else { old };
                let new_short = if new.len() >= 12 { &new[..12] } else { new };
                (
                    Severity::High,
                    format!("File content modified: {}", path),
                    format!(
                        "SHA-256 checksum changed for monitored file.\n\
                         Path: {}\n\
                         Previous hash: {}...\n\
                         Current hash:  {}...\n\n\
                         This may indicate unauthorized modification of a critical \
                         system or configuration file.",
                        path, old_short, new_short
                    ),
                    path.clone(),
                )
            }
            IntegrityViolation::PermissionChanged { path, old, new } => (
                Severity::Medium,
                format!("File permissions changed: {}", path),
                format!(
                    "File permissions were modified on a monitored file.\n\
                     Path: {}\n\
                     Previous permissions: {:o}\n\
                     Current permissions:  {:o}\n\n\
                     Permission changes on critical files may indicate privilege \
                     escalation attempts.",
                    path, old, new
                ),
                path.clone(),
            ),
            IntegrityViolation::FileDeleted { path } => (
                Severity::Medium,
                format!("Watched file deleted: {}", path),
                format!(
                    "A monitored file has been deleted or is no longer accessible.\n\
                     Path: {}\n\n\
                     Deletion of critical system files may indicate tampering or \
                     an attack attempting to remove security controls.",
                    path
                ),
                path.clone(),
            ),
            IntegrityViolation::NewFile { path } => (
                Severity::Medium,
                format!("New file in monitored directory: {}", path),
                format!(
                    "A new file was detected in a monitored directory.\n\
                     Path: {}\n\n\
                     Unexpected files in system directories (LaunchAgents, \
                     sudoers.d, pam.d) may indicate persistence mechanisms \
                     or unauthorized configuration changes.",
                    path
                ),
                path.clone(),
            ),
            IntegrityViolation::SizeChanged { path, old, new } => (
                Severity::Medium,
                format!("File size anomaly: {}", path),
                format!(
                    "File size changed without a corresponding hash change.\n\
                     Path: {}\n\
                     Previous size: {} bytes\n\
                     Current size:  {} bytes\n\n\
                     This is unusual and may indicate filesystem-level corruption.",
                    path, old, new
                ),
                path.clone(),
            ),
        };

        let prefix = severity.finding_id_prefix();
        let id = format!("FIM-{prefix}-{:03}", id_counter);
        id_counter += 1;

        let cvss_vec = match severity {
            Severity::High => CvssVector {
                attack_vector: crate::finding::AttackVector::Local,
                attack_complexity: crate::finding::AttackComplexity::Low,
                privileges_required: crate::finding::PrivilegesRequired::Low,
                user_interaction: crate::finding::UserInteraction::None,
                scope: crate::finding::Scope::Unchanged,
                confidentiality: crate::finding::Impact::High,
                integrity: crate::finding::Impact::High,
                availability: crate::finding::Impact::None,
            },
            _ => CvssVector::configuration_info(),
        };
        let cvss = calculate_cvss(&cvss_vec);

        let remediation = match &violation {
            IntegrityViolation::HashChanged { path, .. } => format!(
                "Investigate who or what modified {}. Check file contents for \
                 unauthorized changes. If the change was intentional, reset the \
                 baseline. If unauthorized, restore from backup and investigate \
                 the attack vector.",
                path
            ),
            IntegrityViolation::PermissionChanged { path, .. } => format!(
                "Verify the permission change on {} was intentional. Restore \
                 original permissions if unauthorized. Check system logs for the \
                 user/process that made the change.",
                path
            ),
            IntegrityViolation::FileDeleted { path } => format!(
                "Determine why {} was deleted. If unauthorized, restore from \
                 backup immediately and investigate the cause.",
                path
            ),
            IntegrityViolation::NewFile { path } => format!(
                "Review the new file at {} to determine if it is legitimate. \
                 Check its contents, ownership, and how it was created. Remove \
                 if unauthorized.",
                path
            ),
            IntegrityViolation::SizeChanged { path, .. } => format!(
                "Investigate the size anomaly for {}. Check filesystem integrity \
                 and verify file contents.",
                path
            ),
        };

        findings.push(Finding {
            id,
            title,
            severity,
            cvss,
            category: ModuleCategory::Configuration,
            description,
            reproduction: None,
            evidence: Evidence {
                messages: Vec::new(),
                audit_record: None,
                canary_detected: false,
                os_events: Vec::new(),
                files_modified: vec![file_path],
                network_connections: Vec::new(),
                stderr_output: None,
            },
            remediation,
        });
    }

    findings
}

// ---------------------------------------------------------------------------
// Public helpers for Tauri commands
// ---------------------------------------------------------------------------

/// Run a file integrity check and return findings as JSON.
pub fn run_integrity_check_sync() -> Result<Vec<Finding>> {
    let watch_paths = default_watch_paths();
    let existing_baseline = load_baseline()?;

    match existing_baseline {
        None => {
            let baseline = create_baseline(&watch_paths)?;
            let file_count = baseline.files.len();
            save_baseline(&baseline)?;

            let cvss_vec = CvssVector::configuration_info();
            let cvss = calculate_cvss(&cvss_vec);

            Ok(vec![Finding {
                id: "FIM-INFO-001".to_string(),
                title: format!("File integrity baseline created for {} files", file_count),
                severity: Severity::Info,
                cvss,
                category: ModuleCategory::Configuration,
                description: format!(
                    "Initial file integrity baseline established. {} files are now \
                     being monitored for unauthorized modifications.",
                    file_count
                ),
                reproduction: None,
                evidence: Evidence::empty(),
                remediation: "No action needed. The baseline has been saved.".to_string(),
            }])
        }
        Some(old) => {
            let (new_baseline, violations) = compare_against_baseline(&old, &watch_paths)?;
            save_baseline(&new_baseline)?;
            Ok(violations_to_findings(violations))
        }
    }
}

/// Reset the file integrity baseline. Deletes the existing baseline file.
pub fn reset_baseline_sync() -> Result<u64> {
    let home = dirs_home();
    let path = home.join(BASELINE_PATH);
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    // Create a fresh baseline and return the file count
    let watch_paths = default_watch_paths();
    let baseline = create_baseline(&watch_paths)?;
    let count = baseline.files.len() as u64;
    save_baseline(&baseline)?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_file_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let bl = compute_file_baseline(&file_path).unwrap();

        // SHA-256 of "hello world"
        assert_eq!(
            bl.sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(bl.size, 11);
        assert!(bl.permissions > 0);
        assert!(!bl.last_verified.is_empty());
    }

    #[test]
    fn test_baseline_create_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.txt");
        let file2 = dir.path().join("b.txt");
        std::fs::write(&file1, b"content a").unwrap();
        std::fs::write(&file2, b"content b").unwrap();

        let paths = vec![file1.clone(), file2.clone()];
        let baseline = create_baseline(&paths).unwrap();

        assert_eq!(baseline.files.len(), 2);
        assert!(baseline
            .files
            .contains_key(&file1.to_string_lossy().to_string()));
        assert!(baseline
            .files
            .contains_key(&file2.to_string_lossy().to_string()));

        // Test serialization round-trip
        let json = serde_json::to_string(&baseline).unwrap();
        let loaded: FimBaseline = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.files.len(), 2);
        assert_eq!(loaded.version, 1);
    }

    #[test]
    fn test_violation_hash_changed() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, b"original").unwrap();

        let paths = vec![file_path.clone()];
        let baseline = create_baseline(&paths).unwrap();

        // Modify the file
        std::fs::write(&file_path, b"modified").unwrap();

        let (_, violations) = compare_against_baseline(&baseline, &paths).unwrap();

        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            IntegrityViolation::HashChanged { path, .. }
            if path == &file_path.to_string_lossy().to_string()
        ));
    }

    #[test]
    fn test_violation_permission_changed() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, b"content").unwrap();

        let paths = vec![file_path.clone()];
        let baseline = create_baseline(&paths).unwrap();

        // Change permissions
        let mut perms = std::fs::metadata(&file_path).unwrap().permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(&file_path, perms).unwrap();

        let (_, violations) = compare_against_baseline(&baseline, &paths).unwrap();

        let has_perm_change = violations.iter().any(|v| {
            matches!(v, IntegrityViolation::PermissionChanged { path, .. }
                if path == &file_path.to_string_lossy().to_string())
        });
        assert!(has_perm_change, "Expected permission change violation");
    }

    #[test]
    fn test_violation_file_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, b"content").unwrap();

        let paths = vec![file_path.clone()];
        let baseline = create_baseline(&paths).unwrap();

        // Delete the file
        std::fs::remove_file(&file_path).unwrap();

        let (_, violations) = compare_against_baseline(&baseline, &paths).unwrap();

        let has_deletion = violations.iter().any(|v| {
            matches!(v, IntegrityViolation::FileDeleted { path }
                if path == &file_path.to_string_lossy().to_string())
        });
        assert!(has_deletion, "Expected file deleted violation");
    }

    #[test]
    fn test_violation_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.txt");
        std::fs::write(&file1, b"content").unwrap();

        let paths_v1 = vec![file1.clone()];
        let baseline = create_baseline(&paths_v1).unwrap();

        // Add a new file
        let file2 = dir.path().join("b.txt");
        std::fs::write(&file2, b"new content").unwrap();

        let paths_v2 = vec![file1, file2.clone()];
        let (_, violations) = compare_against_baseline(&baseline, &paths_v2).unwrap();

        let has_new = violations.iter().any(|v| {
            matches!(v, IntegrityViolation::NewFile { path }
                if path == &file2.to_string_lossy().to_string())
        });
        assert!(has_new, "Expected new file violation");
    }

    #[test]
    fn test_violations_to_findings() {
        let violations = vec![
            IntegrityViolation::HashChanged {
                path: "/etc/hosts".to_string(),
                old: "aabbccdd11223344".to_string(),
                new: "1122334455667788".to_string(),
            },
            IntegrityViolation::PermissionChanged {
                path: "/etc/sudoers".to_string(),
                old: 0o644,
                new: 0o777,
            },
            IntegrityViolation::FileDeleted {
                path: "/etc/ssh/sshd_config".to_string(),
            },
            IntegrityViolation::NewFile {
                path: "/Library/LaunchAgents/com.evil.plist".to_string(),
            },
        ];

        let findings = violations_to_findings(violations);
        assert_eq!(findings.len(), 4);

        // Hash change should be High
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("File content modified"));
        assert!(findings[0]
            .evidence
            .files_modified
            .contains(&"/etc/hosts".to_string()));

        // Permission change should be Medium
        assert_eq!(findings[1].severity, Severity::Medium);
        assert!(findings[1].title.contains("File permissions changed"));

        // Deletion should be Medium
        assert_eq!(findings[2].severity, Severity::Medium);
        assert!(findings[2].title.contains("Watched file deleted"));

        // New file should be Medium
        assert_eq!(findings[3].severity, Severity::Medium);
        assert!(findings[3]
            .title
            .contains("New file in monitored directory"));
    }

    #[test]
    fn test_no_violations_when_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, b"stable content").unwrap();

        let paths = vec![file_path.clone()];
        let baseline = create_baseline(&paths).unwrap();

        // Compare without changes
        let (_, violations) = compare_against_baseline(&baseline, &paths).unwrap();
        assert!(violations.is_empty(), "Expected no violations");
    }

    #[test]
    fn test_baseline_serialization() {
        let mut files = HashMap::new();
        files.insert(
            "/etc/hosts".to_string(),
            FileBaseline {
                sha256: "abc123".to_string(),
                size: 42,
                permissions: 0o644,
                mtime_epoch: 1700000000,
                last_verified: "2024-01-01T00:00:00Z".to_string(),
            },
        );

        let baseline = FimBaseline {
            version: 1,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            files,
        };

        let json = serde_json::to_string_pretty(&baseline).unwrap();
        let loaded: FimBaseline = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.files.len(), 1);
        let entry = loaded.files.get("/etc/hosts").unwrap();
        assert_eq!(entry.sha256, "abc123");
        assert_eq!(entry.size, 42);
        assert_eq!(entry.permissions, 0o644);
    }

    #[test]
    fn test_finding_ids_unique() {
        let violations = vec![
            IntegrityViolation::HashChanged {
                path: "/a".to_string(),
                old: "old".to_string(),
                new: "new".to_string(),
            },
            IntegrityViolation::HashChanged {
                path: "/b".to_string(),
                old: "old2".to_string(),
                new: "new2".to_string(),
            },
        ];

        let findings = violations_to_findings(violations);
        assert_ne!(findings[0].id, findings[1].id);
    }

    #[tokio::test]
    async fn test_module_trait() {
        let module = FileIntegrityModule::new();
        assert_eq!(module.name(), "file-integrity");
        assert_eq!(module.category(), ModuleCategory::Configuration);
        assert!(!module.description().is_empty());
    }
}
