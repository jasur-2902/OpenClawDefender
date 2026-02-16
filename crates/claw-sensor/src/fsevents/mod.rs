//! Filesystem event monitoring.
//!
//! Wraps the `notify` crate to provide a stream of filesystem change events
//! that can be correlated with eslogger process events.

use std::path::PathBuf;

use chrono::{DateTime, Utc};

use claw_core::event::os::{OsEvent, OsEventKind};

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

/// Filesystem watcher that monitors directories for changes.
// TODO: Phase 2 — implement watch() returning async stream via notify crate
pub struct FsWatcher {
    _watched_paths: Vec<PathBuf>,
}

impl FsWatcher {
    /// Create a new watcher for the given paths.
    // TODO: Phase 2 — initialize notify::RecommendedWatcher
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            _watched_paths: paths,
        }
    }
}
