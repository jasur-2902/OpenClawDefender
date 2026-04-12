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
            "mdworker_shared",
            "distnoted",
            "backupd",
            "cloudd",
            "nsurlsessiond",
            "trustd",
            "securityd",
            "coreduetd",
            "bird",
            "secinitd",
            "cfprefsd",
            "containermanagerd",
            "lsd",
            "symptomsd",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        for p in extra_ignore_processes {
            ignore_processes.insert(p.clone());
        }

        let mut ignore_path_prefixes = vec![
            "/System/".to_string(),
            "/usr/lib/".to_string(),
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
            "/usr/bin/ruby",
            "/usr/bin/perl",
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

        // --- New high-value events: always pass (they are rare and always significant) ---
        match &event.kind {
            OsEventKind::Kextload { .. }
            | OsEventKind::BtmLaunchItemAdd { .. }
            | OsEventKind::XpMalwareDetected { .. }
            | OsEventKind::GatekeeperUserOverride { .. } => {
                return true; // Never filter these
            }
            _ => {}
        }

        // Authentication / login events: apply debounce (same user within 5s)
        match &event.kind {
            OsEventKind::Authentication { .. }
            | OsEventKind::LoginLogin
            | OsEventKind::LoginLogout => {
                return self.dedupe_authentication(event);
            }
            _ => {}
        }

        // Privilege events (setuid/setgid): only from user processes
        match &event.kind {
            OsEventKind::Setuid { .. } | OsEventKind::Setgid { .. } => {
                // Skip system processes (PID < 100) or Apple-signed
                if event.pid < 100 {
                    return false;
                }
                if is_apple_signed(event) {
                    return false;
                }
                return true;
            }
            _ => {}
        }

        // Task/trace/proc_check: only non-system, non-debugger
        match &event.kind {
            OsEventKind::GetTask { .. }
            | OsEventKind::Trace { .. }
            | OsEventKind::ProcCheck { .. } => {
                let name = event
                    .process_path
                    .rsplit('/')
                    .next()
                    .unwrap_or(&event.process_path);
                // Allow known debuggers/profilers — they're expected to use these
                if name.contains("lldb")
                    || name.contains("dtrace")
                    || name.contains("sample")
                    || name.contains("instruments")
                {
                    return false;
                }
                if event.pid < 100 {
                    return false;
                }
                return true;
            }
            _ => {}
        }

        // Link/symlink: only in sensitive directories
        match &event.kind {
            OsEventKind::Link { ref path } | OsEventKind::Symlink { ref path } => {
                return is_sensitive_area(path);
            }
            _ => {}
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

        // Drop events from Apple-signed processes
        if is_apple_signed(event) {
            return false;
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

        // Drop read-only open events ONLY for non-sensitive paths.
        // We must still track read-only opens on sensitive paths (e.g. ~/.ssh/id_rsa)
        // since unauthorized credential reads are a key threat vector.
        if let OsEventKind::Open { ref path, flags } = event.kind {
            if flags == 0 && !is_sensitive_path(path) {
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
            if self.debounce_cleanup_counter.is_multiple_of(10_000) {
                self.cleanup_debounce_map(now);
            }
        }

        true
    }

    /// Deduplicate authentication/login events: allow at most one per 5 seconds
    /// from the same PID.
    fn dedupe_authentication(&mut self, event: &OsEvent) -> bool {
        let key = (event.pid, "auth_dedup".to_string());
        let now = Instant::now();
        if let Some(last) = self.debounce_map.get(&key) {
            if now.duration_since(*last) < Duration::from_secs(5) {
                return false;
            }
        }
        self.debounce_map.insert(key, now);
        true
    }

    /// Extract the relevant path from an event for debounce keying.
    fn event_path(&self, event: &OsEvent) -> Option<String> {
        match &event.kind {
            OsEventKind::Exec { target_path, .. } => Some(target_path.clone()),
            OsEventKind::Open { path, .. }
            | OsEventKind::Close { path }
            | OsEventKind::Unlink { path }
            | OsEventKind::Setuid { path }
            | OsEventKind::Setgid { path }
            | OsEventKind::Link { path }
            | OsEventKind::Symlink { path }
            | OsEventKind::GatekeeperUserOverride { path } => Some(path.clone()),
            OsEventKind::Rename { source, .. } => Some(source.clone()),
            OsEventKind::Connect { address, port, .. } => Some(format!("{address}:{port}")),
            OsEventKind::Kextload { identifier } => Some(identifier.clone()),
            OsEventKind::BtmLaunchItemAdd { item_url, .. } => Some(item_url.clone()),
            OsEventKind::XpMalwareDetected { name } => Some(name.clone()),
            OsEventKind::GetTask { target_pid }
            | OsEventKind::Trace { target_pid }
            | OsEventKind::ProcCheck { target_pid } => Some(format!("pid:{target_pid}")),
            OsEventKind::Fork { .. }
            | OsEventKind::Exit { .. }
            | OsEventKind::PtyGrant { .. }
            | OsEventKind::SetMode { .. }
            | OsEventKind::Authentication { .. }
            | OsEventKind::LoginLogin
            | OsEventKind::LoginLogout => None,
        }
    }

    /// Remove stale entries from the debounce map.
    fn cleanup_debounce_map(&mut self, now: Instant) {
        self.debounce_map
            .retain(|_, last| now.duration_since(*last) < Duration::from_secs(5));
    }
}

/// Check if an event originated from an Apple-signed process.
fn is_apple_signed(event: &OsEvent) -> bool {
    if let Some(ref signing_id) = event.signing_id {
        signing_id.starts_with("com.apple.")
    } else {
        false
    }
}

/// Sensitive areas where link/symlink creation should be monitored.
const SENSITIVE_AREA_PREFIXES: &[&str] = &[
    "/etc/",
    "/private/etc/",
    "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
];

/// Check if a path is in a sensitive area (for link/symlink filtering).
fn is_sensitive_area(path: &str) -> bool {
    for prefix in SENSITIVE_AREA_PREFIXES {
        if path.starts_with(prefix) {
            return true;
        }
    }
    // Also check home-directory sensitive areas
    if path.contains("/.ssh/")
        || path.contains("/LaunchAgents/")
        || path.contains("/LaunchDaemons/")
        || path.contains("/.gnupg/")
        || path.contains("/.aws/")
        || path.contains("/Library/Keychains/")
    {
        return true;
    }
    false
}

/// Sensitive path prefixes where even read-only access should be monitored.
const SENSITIVE_PATH_PREFIXES: &[&str] = &[
    "/.ssh/",
    "/.ssh",
    "/.gnupg/",
    "/.gnupg",
    "/.aws/",
    "/.aws",
    "/.kube/",
    "/.kube",
    "/.azure/",
    "/.azure",
    "/.config/gcloud/",
    "/.config/gcloud",
    "/.docker/config.json",
    "/.npmrc",
    "/.pypirc",
    "/.netrc",
    "/.gitconfig",
    "/Library/Keychains/",
    "/Library/Keychains",
];

/// Sensitive absolute paths.
const SENSITIVE_ABSOLUTE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/private/etc/",
];

/// Check if a path is sensitive enough that even read-only opens should be monitored.
fn is_sensitive_path(path: &str) -> bool {
    // Check absolute sensitive paths
    for prefix in SENSITIVE_ABSOLUTE_PATHS {
        if path.starts_with(prefix) {
            return true;
        }
    }
    // Check home-relative sensitive paths (match anywhere with the suffix pattern)
    for suffix in SENSITIVE_PATH_PREFIXES {
        if path.contains(suffix) {
            return true;
        }
    }
    false
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
            assert!(!filter.should_pass(&ev), "{name} should be dropped");
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
    fn drops_apple_signing_id() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let mut ev = make_event(500, "/usr/local/bin/something", exec_kind("/bin/ls"));
        ev.signing_id = Some("com.apple.security".to_string());
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
    fn drops_readonly_open_on_nonsensitive_path() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let ev = make_event(500, "/usr/local/bin/node", open_kind("/tmp/readme.txt", 0));
        assert!(!filter.should_pass(&ev));
    }

    #[test]
    fn passes_readonly_open_on_sensitive_path() {
        let mut filter = EventPreFilter::new(&[], &[]);
        // Read-only open on /etc/passwd must NOT be dropped
        let ev = make_event(500, "/usr/local/bin/node", open_kind("/etc/passwd", 0));
        assert!(filter.should_pass(&ev));

        // Read-only open on ~/.ssh/id_rsa must NOT be dropped
        let ev2 = make_event(
            500,
            "/usr/local/bin/node",
            open_kind("/Users/dev/.ssh/id_rsa", 0),
        );
        assert!(filter.should_pass(&ev2));

        // Read-only open on ~/.aws/credentials must NOT be dropped
        let ev3 = make_event(
            500,
            "/usr/local/bin/node",
            open_kind("/Users/dev/.aws/credentials", 0),
        );
        assert!(filter.should_pass(&ev3));
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

    // --- Tests for new event types ---

    #[test]
    fn kextload_always_passes() {
        let mut filter = EventPreFilter::new(&[], &[]);
        // kextload should pass even from system paths
        let ev = make_event(
            50,
            "/System/Library/Extensions/kextd",
            OsEventKind::Kextload {
                identifier: "com.malware.rootkit".to_string(),
            },
        );
        assert!(filter.should_pass(&ev), "kextload must always pass");
    }

    #[test]
    fn xp_malware_always_passes() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let ev = make_event(
            50,
            "/usr/libexec/XProtectService",
            OsEventKind::XpMalwareDetected {
                name: "OSX.Trojan".to_string(),
            },
        );
        assert!(filter.should_pass(&ev), "xp_malware_detected must always pass");
    }

    #[test]
    fn btm_launch_item_always_passes() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let ev = make_event(
            50,
            "/usr/sbin/installer",
            OsEventKind::BtmLaunchItemAdd {
                item_url: "/Library/LaunchDaemons/evil.plist".to_string(),
                item_type: "daemon".to_string(),
            },
        );
        assert!(filter.should_pass(&ev), "btm_launch_item_add must always pass");
    }

    #[test]
    fn gatekeeper_override_always_passes() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let ev = make_event(
            50,
            "/usr/sbin/syspolicyd",
            OsEventKind::GatekeeperUserOverride {
                path: "/Downloads/sketchy.app".to_string(),
            },
        );
        assert!(
            filter.should_pass(&ev),
            "gatekeeper_user_override must always pass"
        );
    }

    #[test]
    fn setuid_filtered_for_system_processes() {
        let mut filter = EventPreFilter::new(&[], &[]);
        // PID < 100 should be filtered
        let ev = make_event(
            50,
            "/usr/sbin/sysctl",
            OsEventKind::Setuid {
                path: "/usr/sbin/something".to_string(),
            },
        );
        assert!(!filter.should_pass(&ev), "setuid from PID < 100 should be dropped");

        // Apple-signed should be filtered
        let mut ev2 = make_event(
            500,
            "/usr/local/bin/something",
            OsEventKind::Setuid {
                path: "/tmp/test".to_string(),
            },
        );
        ev2.signing_id = Some("com.apple.security".to_string());
        assert!(
            !filter.should_pass(&ev2),
            "setuid from Apple-signed should be dropped"
        );

        // Normal user process should pass
        let ev3 = make_event(
            500,
            "/usr/local/bin/malware",
            OsEventKind::Setuid {
                path: "/tmp/escalate".to_string(),
            },
        );
        assert!(filter.should_pass(&ev3), "setuid from user process should pass");
    }

    #[test]
    fn get_task_filtered_for_debuggers() {
        let mut filter = EventPreFilter::new(&[], &[]);
        // lldb should be filtered (known debugger)
        let ev = make_event(
            500,
            "/usr/bin/lldb",
            OsEventKind::GetTask { target_pid: 1234 },
        );
        assert!(
            !filter.should_pass(&ev),
            "get_task from lldb should be dropped"
        );

        // Unknown process should pass
        let ev2 = make_event(
            500,
            "/tmp/injector",
            OsEventKind::GetTask { target_pid: 1234 },
        );
        assert!(filter.should_pass(&ev2), "get_task from unknown process should pass");

        // System process (PID < 100) should be filtered
        let ev3 = make_event(
            50,
            "/usr/sbin/something",
            OsEventKind::GetTask { target_pid: 1234 },
        );
        assert!(
            !filter.should_pass(&ev3),
            "get_task from PID < 100 should be dropped"
        );
    }

    #[test]
    fn link_filtered_outside_sensitive_areas() {
        let mut filter = EventPreFilter::new(&[], &[]);
        // Link in non-sensitive area should be filtered
        let ev = make_event(
            500,
            "/usr/local/bin/node",
            OsEventKind::Link {
                path: "/tmp/some_link".to_string(),
            },
        );
        assert!(
            !filter.should_pass(&ev),
            "link in /tmp should be dropped"
        );

        // Link in sensitive area should pass
        let ev2 = make_event(
            500,
            "/usr/local/bin/node",
            OsEventKind::Link {
                path: "/etc/sudoers_link".to_string(),
            },
        );
        assert!(filter.should_pass(&ev2), "link in /etc should pass");

        // Symlink in LaunchAgents should pass
        let ev3 = make_event(
            500,
            "/usr/local/bin/node",
            OsEventKind::Symlink {
                path: "/Users/dev/Library/LaunchAgents/evil.plist".to_string(),
            },
        );
        assert!(
            filter.should_pass(&ev3),
            "symlink in LaunchAgents should pass"
        );
    }

    #[test]
    fn authentication_deduplication() {
        let mut filter = EventPreFilter::new(&[], &[]);
        let ev = make_event(
            500,
            "/usr/bin/sudo",
            OsEventKind::Authentication { success: true },
        );
        // First should pass
        assert!(filter.should_pass(&ev), "first auth event should pass");
        // Rapid duplicate should be filtered (within 5s)
        assert!(
            !filter.should_pass(&ev),
            "rapid duplicate auth should be filtered"
        );
    }
}
