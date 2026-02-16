//! Filesystem event monitoring.
//!
//! Wraps the `notify` crate to provide a stream of filesystem change events
//! that can be correlated with eslogger process events.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use notify::{Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use clawdefender_core::event::os::{OsEvent, OsEventKind};

/// A filesystem change event.
#[derive(Debug, Clone)]
pub struct FsEvent {
    pub path: PathBuf,
    pub kind: FsEventKind,
    pub timestamp: DateTime<Utc>,
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
                flags: 0,
            },
            FsEventKind::Removed => OsEventKind::Unlink {
                path: ev.path.to_string_lossy().into_owned(),
            },
            FsEventKind::Renamed => OsEventKind::Rename {
                source: ev.path.to_string_lossy().into_owned(),
                dest: String::new(), // FSEvents doesn't provide the destination
            },
        };

        OsEvent {
            timestamp: ev.timestamp,
            pid: 0,  // FSEvents does not provide PID
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
                            };
                            // Best-effort send; if the receiver is dropped, we just skip.
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
}
