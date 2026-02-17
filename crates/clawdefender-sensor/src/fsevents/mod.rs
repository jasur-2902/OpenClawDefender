//! Filesystem event monitoring.
//!
//! Wraps the `notify` crate to provide a stream of filesystem change events
//! that can be correlated with eslogger process events. Includes sensitivity
//! classification, debouncing, rate limiting, and optional PID correlation.

pub mod debouncer;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use notify::{Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

use clawdefender_core::event::os::{OsEvent, OsEventKind};

use debouncer::run_debounce_pipeline;

// ---------------------------------------------------------------------------
// Sensitivity classification
// ---------------------------------------------------------------------------

/// Sensitivity tier for a filesystem path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SensitivityTier {
    Low,
    Medium,
    High,
    Critical,
}

/// Critical path prefixes (relative to home directory).
const CRITICAL_PREFIXES: &[&str] = &[
    ".ssh/",
    ".ssh",
    ".gnupg/",
    ".gnupg",
    ".aws/",
    ".aws",
    ".config/gcloud/",
    ".config/gcloud",
    ".azure/",
    ".azure",
    ".kube/",
    ".kube",
    "Library/Keychains/",
    "Library/Keychains",
];

/// High-sensitivity path prefixes and exact files (relative to home directory).
const HIGH_PREFIXES: &[&str] = &[
    ".config/",
    ".config",
    "Library/LaunchAgents/",
    "Library/LaunchAgents",
];

const HIGH_EXACT: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
];

/// Classify a path into a sensitivity tier.
pub fn classify_path(path: &Path, project_root: Option<&Path>) -> SensitivityTier {
    let home = dirs_path();
    if let Some(home) = &home {
        if let Ok(rel) = path.strip_prefix(home) {
            let rel_str = rel.to_string_lossy();

            // Check critical first (more specific)
            for prefix in CRITICAL_PREFIXES {
                if rel_str.starts_with(prefix) {
                    return SensitivityTier::Critical;
                }
            }

            // Check high exact matches
            for exact in HIGH_EXACT {
                if rel_str == *exact {
                    return SensitivityTier::High;
                }
            }

            // Check high prefixes
            for prefix in HIGH_PREFIXES {
                if rel_str.starts_with(prefix) {
                    return SensitivityTier::High;
                }
            }
        }
    }

    // Check project root
    if let Some(root) = project_root {
        if path.starts_with(root) {
            return SensitivityTier::Low;
        }
    }

    SensitivityTier::Medium
}

fn dirs_path() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Returns the default set of paths that should be monitored.
pub fn default_watch_paths() -> Vec<PathBuf> {
    let Some(home) = dirs_path() else {
        return Vec::new();
    };

    let paths = [
        ".ssh",
        ".gnupg",
        ".aws",
        ".config/gcloud",
        ".kube",
        "Library/Keychains",
        "Library/LaunchAgents",
        ".config/clawdefender",
    ];

    paths
        .iter()
        .map(|p| home.join(p))
        .filter(|p| p.exists())
        .collect()
}

// ---------------------------------------------------------------------------
// Eslogger PID correlation
// ---------------------------------------------------------------------------

/// Maintains a sliding window of recent eslogger file events for PID lookup.
pub struct EsloggerCorrelator {
    /// path -> (pid, timestamp)
    window: HashMap<PathBuf, (u32, Instant)>,
    /// How long entries remain valid.
    ttl: Duration,
}

impl EsloggerCorrelator {
    pub fn new(ttl: Duration) -> Self {
        Self {
            window: HashMap::new(),
            ttl,
        }
    }

    /// Record a file event from eslogger with its associated PID.
    pub fn record(&mut self, path: PathBuf, pid: u32) {
        self.window.insert(path, (pid, Instant::now()));
    }

    /// Look up the PID for a given path, if a recent eslogger event matches.
    pub fn lookup_pid(&mut self, path: &Path) -> Option<u32> {
        self.evict_expired();
        self.window.get(path).map(|(pid, _)| *pid)
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.window
            .retain(|_, (_, ts)| now.duration_since(*ts) < self.ttl);
    }
}

// ---------------------------------------------------------------------------
// FsEvent types
// ---------------------------------------------------------------------------

/// A filesystem change event.
#[derive(Debug, Clone)]
pub struct FsEvent {
    pub path: PathBuf,
    pub kind: FsEventKind,
    pub timestamp: DateTime<Utc>,
    pub sensitivity: SensitivityTier,
    pub source_pid: Option<u32>,
}

/// The kind of filesystem change observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsEventKind {
    Created,
    Modified,
    Removed,
    Renamed,
}

impl From<FsEvent> for OsEvent {
    fn from(ev: FsEvent) -> Self {
        let kind = match ev.kind {
            FsEventKind::Created | FsEventKind::Modified => OsEventKind::Open {
                path: ev.path.to_string_lossy().into_owned(),
                // Use O_WRONLY (1) for Created/Modified so the pre-filter doesn't
                // discard these as read-only opens.
                flags: 1,
            },
            FsEventKind::Removed => OsEventKind::Unlink {
                path: ev.path.to_string_lossy().into_owned(),
            },
            FsEventKind::Renamed => OsEventKind::Rename {
                source: ev.path.to_string_lossy().into_owned(),
                dest: String::new(),
            },
        };

        OsEvent {
            timestamp: ev.timestamp,
            pid: ev.source_pid.unwrap_or(0),
            ppid: 0,
            process_path: String::new(),
            kind,
            signing_id: None,
            team_id: None,
        }
    }
}

/// Convert a notify EventKind to our FsEventKind, returning None for
/// events we don't care about (e.g. Access).
fn convert_event_kind(kind: &EventKind) -> Option<FsEventKind> {
    match kind {
        EventKind::Create(_) => Some(FsEventKind::Created),
        EventKind::Modify(notify::event::ModifyKind::Name(_)) => Some(FsEventKind::Renamed),
        EventKind::Modify(_) => Some(FsEventKind::Modified),
        EventKind::Remove(_) => Some(FsEventKind::Removed),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// FsWatcher (original, preserved for compatibility)
// ---------------------------------------------------------------------------

/// Filesystem watcher that monitors directories for changes.
pub struct FsWatcher {
    watcher: Option<RecommendedWatcher>,
    watched_paths: Vec<PathBuf>,
}

impl FsWatcher {
    /// Create a new filesystem watcher (not yet watching anything).
    pub fn new() -> Result<Self> {
        Ok(Self {
            watcher: None,
            watched_paths: Vec::new(),
        })
    }

    /// Start watching the given paths and return a channel receiver for events.
    pub fn watch(&mut self, paths: &[PathBuf]) -> Result<mpsc::Receiver<FsEvent>> {
        let (tx, rx) = mpsc::channel(256);

        let watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
            match res {
                Ok(event) => {
                    if let Some(fs_kind) = convert_event_kind(&event.kind) {
                        for path in &event.paths {
                            let fs_event = FsEvent {
                                path: path.clone(),
                                kind: fs_kind.clone(),
                                timestamp: Utc::now(),
                                sensitivity: SensitivityTier::Low,
                                source_pid: None,
                            };
                            let _ = tx.try_send(fs_event);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "filesystem watcher error");
                }
            }
        })
        .context("failed to create filesystem watcher")?;

        self.watcher = Some(watcher);

        for path in paths {
            self.watcher
                .as_mut()
                .unwrap()
                .watch(path, RecursiveMode::Recursive)
                .with_context(|| format!("failed to watch path: {}", path.display()))?;
            self.watched_paths.push(path.clone());
        }

        Ok(rx)
    }
}

// ---------------------------------------------------------------------------
// EnhancedFsWatcher
// ---------------------------------------------------------------------------

/// Enhanced filesystem watcher with debouncing, rate limiting,
/// sensitivity classification, and optional eslogger PID correlation.
pub struct EnhancedFsWatcher {
    watcher: Option<RecommendedWatcher>,
    watched_paths: Vec<PathBuf>,
    project_root: Option<PathBuf>,
    debounce_window: Duration,
    rate_threshold: u64,
    sample_ratio: u64,
}

impl EnhancedFsWatcher {
    pub fn new(project_root: Option<PathBuf>) -> Result<Self> {
        Ok(Self {
            watcher: None,
            watched_paths: Vec::new(),
            project_root,
            debounce_window: Duration::from_millis(200),
            rate_threshold: 500,
            sample_ratio: 10,
        })
    }

    /// Override the debounce window (default 200ms).
    pub fn with_debounce_window(mut self, window: Duration) -> Self {
        self.debounce_window = window;
        self
    }

    /// Override the rate limiter threshold (default 500 events/sec).
    pub fn with_rate_threshold(mut self, threshold: u64) -> Self {
        self.rate_threshold = threshold;
        self
    }

    /// Start watching paths. Returns a receiver of debounced, rate-limited,
    /// sensitivity-classified events.
    pub fn watch(&mut self, paths: &[PathBuf]) -> Result<mpsc::Receiver<FsEvent>> {
        let (raw_tx, raw_rx) = mpsc::channel(1024);
        let (out_tx, out_rx) = mpsc::channel(256);

        let project_root = self.project_root.clone();

        let watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
            match res {
                Ok(event) => {
                    if let Some(fs_kind) = convert_event_kind(&event.kind) {
                        for path in &event.paths {
                            let sensitivity =
                                classify_path(path, project_root.as_deref());
                            let fs_event = FsEvent {
                                path: path.clone(),
                                kind: fs_kind.clone(),
                                timestamp: Utc::now(),
                                sensitivity,
                                source_pid: None,
                            };
                            let _ = raw_tx.try_send(fs_event);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "filesystem watcher error");
                }
            }
        })
        .context("failed to create enhanced filesystem watcher")?;

        self.watcher = Some(watcher);

        for path in paths {
            self.watcher
                .as_mut()
                .unwrap()
                .watch(path, RecursiveMode::Recursive)
                .with_context(|| format!("failed to watch path: {}", path.display()))?;
            self.watched_paths.push(path.clone());
        }

        // Spawn debounce + rate-limit pipeline
        let debounce_window = self.debounce_window;
        let rate_threshold = self.rate_threshold;
        let sample_ratio = self.sample_ratio;
        tokio::spawn(async move {
            run_debounce_pipeline(raw_rx, out_tx, debounce_window, rate_threshold, sample_ratio)
                .await;
        });

        Ok(out_rx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn watch_detects_file_creation() {
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let tmp_path = tmp_dir.path().to_path_buf();

        let mut watcher = FsWatcher::new().expect("failed to create FsWatcher");
        let mut rx = watcher.watch(&[tmp_path.clone()]).expect("failed to watch");

        // Small delay to let the watcher initialize
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create a file
        let file_path = tmp_path.join("test.txt");
        fs::write(&file_path, "hello").expect("failed to write file");

        // We should receive at least one event
        let event = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for fs event")
            .expect("channel closed");

        assert!(
            event.kind == FsEventKind::Created || event.kind == FsEventKind::Modified,
            "expected Created or Modified, got {:?}",
            event.kind
        );
    }

    #[test]
    fn classify_ssh_as_critical() {
        let home = dirs_path().unwrap();
        let path = home.join(".ssh/id_rsa");
        assert_eq!(classify_path(&path, None), SensitivityTier::Critical);
    }

    #[test]
    fn classify_gnupg_as_critical() {
        let home = dirs_path().unwrap();
        let path = home.join(".gnupg/pubring.kbx");
        assert_eq!(classify_path(&path, None), SensitivityTier::Critical);
    }

    #[test]
    fn classify_aws_as_critical() {
        let home = dirs_path().unwrap();
        let path = home.join(".aws/credentials");
        assert_eq!(classify_path(&path, None), SensitivityTier::Critical);
    }

    #[test]
    fn classify_config_as_high() {
        let home = dirs_path().unwrap();
        let path = home.join(".config/foo/bar.toml");
        assert_eq!(classify_path(&path, None), SensitivityTier::High);
    }

    #[test]
    fn classify_zshrc_as_high() {
        let home = dirs_path().unwrap();
        let path = home.join(".zshrc");
        assert_eq!(classify_path(&path, None), SensitivityTier::High);
    }

    #[test]
    fn classify_launch_agents_as_high() {
        let home = dirs_path().unwrap();
        let path = home.join("Library/LaunchAgents/com.example.plist");
        assert_eq!(classify_path(&path, None), SensitivityTier::High);
    }

    #[test]
    fn classify_project_path_as_low() {
        let project_root = PathBuf::from("/tmp/project");
        let path = PathBuf::from("/tmp/project/src/main.rs");
        assert_eq!(
            classify_path(&path, Some(&project_root)),
            SensitivityTier::Low
        );
    }

    #[test]
    fn classify_outside_project_as_medium() {
        let project_root = PathBuf::from("/tmp/project");
        let path = PathBuf::from("/var/log/system.log");
        assert_eq!(
            classify_path(&path, Some(&project_root)),
            SensitivityTier::Medium
        );
    }

    #[test]
    fn default_watch_paths_expansion() {
        // Should not panic and should return a vec (may be empty if dirs don't exist)
        let paths = default_watch_paths();
        for path in &paths {
            assert!(
                path.is_absolute(),
                "expected absolute path, got: {}",
                path.display()
            );
        }
    }

    #[test]
    fn eslogger_correlator_lookup() {
        let mut correlator = EsloggerCorrelator::new(Duration::from_secs(2));
        let path = PathBuf::from("/tmp/test.txt");
        correlator.record(path.clone(), 1234);
        assert_eq!(correlator.lookup_pid(&path), Some(1234));
    }

    #[test]
    fn eslogger_correlator_no_match() {
        let mut correlator = EsloggerCorrelator::new(Duration::from_secs(2));
        let path = PathBuf::from("/tmp/unknown.txt");
        assert_eq!(correlator.lookup_pid(&path), None);
    }

    #[test]
    fn from_fsevent_uses_source_pid() {
        let ev = FsEvent {
            path: PathBuf::from("/tmp/test.txt"),
            kind: FsEventKind::Modified,
            timestamp: Utc::now(),
            sensitivity: SensitivityTier::Low,
            source_pid: Some(42),
        };
        let os_event: OsEvent = ev.into();
        assert_eq!(os_event.pid, 42);
    }

    #[test]
    fn from_fsevent_no_pid_defaults_to_zero() {
        let ev = FsEvent {
            path: PathBuf::from("/tmp/test.txt"),
            kind: FsEventKind::Created,
            timestamp: Utc::now(),
            sensitivity: SensitivityTier::Low,
            source_pid: None,
        };
        let os_event: OsEvent = ev.into();
        assert_eq!(os_event.pid, 0);
        // Created/Modified events should have flags=1 so they aren't filtered as read-only
        match &os_event.kind {
            OsEventKind::Open { flags, .. } => assert_eq!(*flags, 1),
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn sensitivity_tier_ordering() {
        assert!(SensitivityTier::Low < SensitivityTier::Medium);
        assert!(SensitivityTier::Medium < SensitivityTier::High);
        assert!(SensitivityTier::High < SensitivityTier::Critical);
    }
}
