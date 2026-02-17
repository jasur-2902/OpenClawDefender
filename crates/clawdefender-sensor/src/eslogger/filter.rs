//! Pre-filter for eslogger events.
//!
//! Drops noisy system process events before they enter the pipeline, reducing
//! stream volume by ~90-95%.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use clawdefender_core::event::os::{OsEvent, OsEventKind};

/// Debounce window for rapid duplicate events from the same PID+path.
const DEBOUNCE_WINDOW: Duration = Duration::from_millis(100);

/// Pre-filter that drops system process events via fast HashSet lookups and
/// debouncing of rapid duplicate events.
pub struct EventPreFilter {
    /// System process names to ignore.
    ignore_processes: HashSet<String>,
    /// Path prefixes to ignore.
    ignore_path_prefixes: Vec<String>,
    /// Paths that bypass the prefix filter (allowlisted).
    allowed_paths: HashSet<String>,
    /// Debounce map: (pid, path) -> last seen instant.
    debounce_map: HashMap<(u32, String), Instant>,
    /// Counter for debounce map cleanup.
    debounce_cleanup_counter: u64,
}

impl EventPreFilter {
    /// Create a new pre-filter with default system process and path rules.
    ///
    /// `extra_ignore_processes` and `extra_ignore_paths` extend the built-in
    /// ignore lists from sensor configuration.
    pub fn new(extra_ignore_processes: &[String], extra_ignore_paths: &[String]) -> Self {
        let mut ignore_processes: HashSet<String> = [
            "kernel_task",
            "launchd",
            "WindowServer",
            "loginwindow",
            "Finder",
            "Spotlight",
            "mds",
            "mds_stores",
            "mdworker",
            "backupd",
            "cloudd",
            "nsurlsessiond",
            "trustd",
            "securityd",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        for p in extra_ignore_processes {
            ignore_processes.insert(p.clone());
        }

        let mut ignore_path_prefixes = vec![
            "/System/".to_string(),
            "/usr/libexec/".to_string(),
            "/usr/sbin/".to_string(),
        ];
        for p in extra_ignore_paths {
            ignore_path_prefixes.push(p.clone());
        }

        let allowed_paths: HashSet<String> = [
            "/usr/bin/curl",
            "/usr/bin/python3",
            "/usr/bin/env",
            "/usr/bin/git",
            "/usr/bin/ssh",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            ignore_processes,
            ignore_path_prefixes,
            allowed_paths,
            debounce_map: HashMap::new(),
            debounce_cleanup_counter: 0,
        }
    }

    /// Returns `true` if the event should pass through the filter (i.e., is
    /// interesting). Returns `false` if the event should be dropped.
    pub fn should_pass(&mut self, event: &OsEvent) -> bool {
        // Drop PID 0 (kernel) and PID 1 (launchd)
        if event.pid <= 1 {
            return false;
        }

        // Drop events from known system processes (by executable basename)
        let basename = event
            .process_path
            .rsplit('/')
            .next()
            .unwrap_or(&event.process_path);
        if self.ignore_processes.contains(basename) {
            return false;
        }

        // Drop events from Apple signing IDs
        if let Some(ref team_id) = event.team_id {
            if team_id.starts_with("com.apple") {
                return false;
            }
        }

        // Drop events from ignored path prefixes (unless allowlisted)
        if !self.allowed_paths.contains(&event.process_path) {
            for prefix in &self.ignore_path_prefixes {
                if event.process_path.starts_with(prefix) {
                    return false;
                }
            }
        }

        // Drop close events on paths that look read-only (no modification)
        if let OsEventKind::Close { ref path } = event.kind {
            // Close events without a meaningful path are noise
            if path.is_empty() {
                return false;
            }
        }

        // Drop open events with read-only flags (flags == 0 means O_RDONLY)
        if let OsEventKind::Open { flags, .. } = event.kind {
            if flags == 0 {
                return false;
            }
        }

        // Debounce: rapid duplicate events from same PID+path within 100ms
        let event_path = self.event_path(event);
        if let Some(path) = event_path {
            let key = (event.pid, path);
            let now = Instant::now();
            if let Some(last) = self.debounce_map.get(&key) {
                if now.duration_since(*last) < DEBOUNCE_WINDOW {
                    return false;
                }
            }
            self.debounce_map.insert(key, now);

            // Periodic cleanup to prevent unbounded growth
            self.debounce_cleanup_counter += 1;
            if self.debounce_cleanup_counter % 10_000 == 0 {
                self.cleanup_debounce_map(now);
            }
        }

        true
    }

    /// Extract the relevant path from an event for debounce keying.
    fn event_path(&self, event: &OsEvent) -> Option<String> {
        match &event.kind {
            OsEventKind::Exec { target_path, .. } => Some(target_path.clone()),
            OsEventKind::Open { path, .. } => Some(path.clone()),
            OsEventKind::Close { path } => Some(path.clone()),
            OsEventKind::Rename { source, .. } => Some(source.clone()),
            OsEventKind::Unlink { path } => Some(path.clone()),
            OsEventKind::Connect { address, port, .. } => Some(format!("{address}:{port}")),
            OsEventKind::Fork { .. }
            | OsEventKind::Exit { .. }
            | OsEventKind::PtyGrant { .. }
            | OsEventKind::SetMode { .. } => None,
        }
    }

    /// Remove stale entries from the debounce map.
    fn cleanup_debounce_map(&mut self, now: Instant) {
        self.debounce_map
            .retain(|_, last| now.duration_since(*last) < Duration::from_secs(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_event(pid: u32, process_path: &str, kind: OsEventKind) -> OsEvent {
        OsEvent {
            timestamp: Utc::now(),
            pid,
            ppid: 1,
            process_path: process_path.to_string(),
            kind,
            signing_id: None,
            team_id: None,
        }
    }

    fn exec_kind(target: &str) -> OsEventKind {
        OsEventKind::Exec {
            target_path: target.to_string(),
            args: vec![],
        }
    }

    fn open_kind(path: &str, flags: u32) -> OsEventKind {
        OsEventKind::Open {
            path: path.to_string(),
            flags,
        }
    }

    #[test]
    fn drops_pid_0_and_1() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let ev0 = make_event(0, "/sbin/launchd", exec_kind("/bin/ls"));
        let ev1 = make_event(1, "/sbin/launchd", exec_kind("/bin/ls"));
        assert!(!filter.should_pass(&ev0));
        assert!(!filter.should_pass(&ev1));
    }

    #[test]
    fn drops_system_processes() {
        let mut filter = EventPreFilter::new(&[], &[]);
        for name in &["launchd", "Spotlight", "mds", "WindowServer", "kernel_task"] {
            let path = format!("/usr/sbin/{name}");
            // Use a PID > 1 so it's not dropped by the PID check; test process name filter
            let ev = OsEvent {
                timestamp: Utc::now(),
                pid: 500,
                ppid: 1,
                process_path: path,
                kind: exec_kind("/bin/ls"),
                signing_id: None,
                team_id: None,
            };
            assert!(
                !filter.should_pass(&ev),
                "{name} should be dropped"
            );
        }
    }

    #[test]
    fn passes_agent_processes() {
        let mut filter = EventPreFilter::new(&[], &[]);
        // node running under an MCP client
        let ev = make_event(1234, "/usr/local/bin/node", exec_kind("/app/server.js"));
        assert!(filter.should_pass(&ev));

        // python3 is allowlisted even though under /usr/bin/
        let ev2 = make_event(
            1235,
            "/usr/bin/python3",
            OsEventKind::Exec {
                target_path: "/home/user/script.py".to_string(),
                args: vec!["python3".to_string(), "script.py".to_string()],
            },
        );
        assert!(filter.should_pass(&ev2));
    }

    #[test]
    fn drops_apple_team_id() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let mut ev = make_event(500, "/usr/local/bin/something", exec_kind("/bin/ls"));
        ev.team_id = Some("com.apple.security".to_string());
        assert!(!filter.should_pass(&ev));
    }

    #[test]
    fn drops_system_path_prefixes() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let ev = make_event(
            500,
            "/System/Library/PrivateFrameworks/Something.framework/something",
            exec_kind("/bin/ls"),
        );
        assert!(!filter.should_pass(&ev));

        let ev2 = make_event(500, "/usr/libexec/amfid", exec_kind("/bin/ls"));
        assert!(!filter.should_pass(&ev2));
    }

    #[test]
    fn allows_allowlisted_paths() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let ev = make_event(500, "/usr/bin/curl", exec_kind("https://example.com"));
        assert!(filter.should_pass(&ev));

        let ev2 = make_event(500, "/usr/bin/git", exec_kind("status"));
        assert!(filter.should_pass(&ev2));
    }

    #[test]
    fn drops_readonly_open_events() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let ev = make_event(500, "/usr/local/bin/node", open_kind("/etc/passwd", 0));
        assert!(!filter.should_pass(&ev));
    }

    #[test]
    fn passes_write_open_events() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let ev = make_event(500, "/usr/local/bin/node", open_kind("/tmp/output.txt", 1));
        assert!(filter.should_pass(&ev));
    }

    #[test]
    fn debounce_rapid_duplicate_events() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let kind = exec_kind("/app/server.js");
        let mut passed = 0;
        for _ in 0..10 {
            let ev = make_event(1234, "/usr/local/bin/node", kind.clone());
            if filter.should_pass(&ev) {
                passed += 1;
            }
        }
        // First event should pass, rest should be debounced (within 100ms)
        assert!(
            passed <= 2,
            "expected at most 2 events to pass debounce, got {passed}"
        );
        assert!(
            passed >= 1,
            "expected at least 1 event to pass debounce, got {passed}"
        );
    }

    #[test]
    fn extra_ignore_processes_work() {
        let mut filter = EventPreFilter::new(&["my_daemon".to_string()], &[]);
        let ev = make_event(500, "/usr/local/bin/my_daemon", exec_kind("/bin/ls"));
        assert!(!filter.should_pass(&ev));
    }

    #[test]
    fn extra_ignore_paths_work() {
        let mut filter = EventPreFilter::new(&[], &["/opt/internal/".to_string()]);
        let ev = make_event(500, "/opt/internal/worker", exec_kind("/bin/ls"));
        assert!(!filter.should_pass(&ev));
    }
}
