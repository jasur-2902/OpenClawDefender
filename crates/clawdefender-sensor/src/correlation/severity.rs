//! Severity rating for uncorrelated OS events.
//!
//! When an OS event from an agent process cannot be matched to any MCP request,
//! we assign a severity based on how suspicious the activity is.

use clawdefender_core::event::os::{OsEvent, OsEventKind};
use clawdefender_core::event::Severity;

/// Sensitivity classification for file paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PathSensitivity {
    Normal,
    OutsideProject,
    Critical,
}

/// Critical paths that should never be accessed without an MCP match.
const CRITICAL_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/private/etc/",
    "/var/db/dslocal/",
    "/Library/Keychains/",
    "/Users/*/Library/Keychains/",
    "/Users/*/.ssh/",
    "/Users/*/.gnupg/",
    "/Users/*/.aws/",
    "/Users/*/.config/gcloud/",
    "/Users/*/.azure/",
    "/Users/*/.kube/config",
    "/Users/*/.npmrc",
    "/Users/*/.pypirc",
    "/Users/*/.docker/config.json",
    "/Users/*/.gitconfig",
    "/Users/*/.netrc",
    "/System/",
];

/// Rate the severity of an uncorrelated OS event.
pub fn rate_uncorrelated(event: &OsEvent, project_dir: Option<&str>) -> Severity {
    match &event.kind {
        // Critical: outbound network to external IP without MCP match
        OsEventKind::Connect { address, .. } => {
            if is_external_address(address) {
                Severity::Critical
            } else {
                Severity::Low
            }
        }
        // High: exec without MCP shell tool match
        OsEventKind::Exec { .. } => Severity::High,
        // File operations: depends on path sensitivity
        OsEventKind::Open { path, .. } => rate_file_access(path, project_dir),
        OsEventKind::Unlink { path } => rate_file_access(path, project_dir),
        OsEventKind::Rename { source, dest } => {
            rate_file_access(source, project_dir).max(rate_file_access(dest, project_dir))
        }
        OsEventKind::SetMode { path, .. } => rate_file_access(path, project_dir),
        // Low: other events
        OsEventKind::Close { .. } => Severity::Info,
        OsEventKind::Fork { .. } => Severity::Info,
        OsEventKind::Exit { .. } => Severity::Info,
        OsEventKind::PtyGrant { .. } => Severity::Low,
    }
}

fn rate_file_access(path: &str, project_dir: Option<&str>) -> Severity {
    let sensitivity = classify_path_sensitivity(path, project_dir);
    match sensitivity {
        PathSensitivity::Critical => Severity::High,
        PathSensitivity::OutsideProject => Severity::Medium,
        PathSensitivity::Normal => Severity::Low,
    }
}

fn classify_path_sensitivity(path: &str, project_dir: Option<&str>) -> PathSensitivity {
    // Check critical paths
    for pattern in CRITICAL_PATHS {
        if path_matches_pattern(path, pattern) {
            return PathSensitivity::Critical;
        }
    }

    // Check if inside project directory
    if let Some(proj) = project_dir {
        if path.starts_with(proj) {
            return PathSensitivity::Normal;
        }
        return PathSensitivity::OutsideProject;
    }

    PathSensitivity::Normal
}

fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        // Simple glob: split on * and check parts
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let (prefix, suffix) = (parts[0], parts[1]);
            if path.starts_with(prefix) {
                // Find the end of the wildcard segment
                if let Some(rest) = path.strip_prefix(prefix) {
                    // The * matches up to the next /
                    if let Some(after_slash) = rest.find('/') {
                        let remaining = &rest[after_slash..];
                        return remaining.starts_with(suffix);
                    }
                }
            }
            return false;
        }
    }
    path.starts_with(pattern)
}

/// Check if an address is external (not loopback).
fn is_external_address(address: &str) -> bool {
    !(address.starts_with("127.")
        || address == "::1"
        || address == "0.0.0.0"
        || address == "localhost"
        || address.starts_with("0:0:0:0:0:0:0:1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_os_event(kind: OsEventKind) -> OsEvent {
        OsEvent {
            timestamp: Utc::now(),
            pid: 100,
            ppid: 50,
            process_path: "/usr/bin/test".to_string(),
            kind,
            signing_id: None,
            team_id: None,
        }
    }

    #[test]
    fn external_connect_is_critical() {
        let event = make_os_event(OsEventKind::Connect {
            address: "93.184.216.34".into(),
            port: 443,
            protocol: "tcp".into(),
        });
        assert_eq!(rate_uncorrelated(&event, None), Severity::Critical);
    }

    #[test]
    fn loopback_connect_is_low() {
        let event = make_os_event(OsEventKind::Connect {
            address: "127.0.0.1".into(),
            port: 8080,
            protocol: "tcp".into(),
        });
        assert_eq!(rate_uncorrelated(&event, None), Severity::Low);
    }

    #[test]
    fn exec_without_match_is_high() {
        let event = make_os_event(OsEventKind::Exec {
            target_path: "/bin/ls".into(),
            args: vec!["ls".into()],
        });
        assert_eq!(rate_uncorrelated(&event, None), Severity::High);
    }

    #[test]
    fn file_outside_project_is_medium() {
        let event = make_os_event(OsEventKind::Open {
            path: "/etc/hosts".into(),
            flags: 0,
        });
        assert_eq!(
            rate_uncorrelated(&event, Some("/Users/dev/project")),
            Severity::Medium
        );
    }

    #[test]
    fn file_inside_project_is_low() {
        let event = make_os_event(OsEventKind::Open {
            path: "/Users/dev/project/src/main.rs".into(),
            flags: 0,
        });
        assert_eq!(
            rate_uncorrelated(&event, Some("/Users/dev/project")),
            Severity::Low
        );
    }

    #[test]
    fn critical_path_is_high() {
        let event = make_os_event(OsEventKind::Open {
            path: "/Users/dev/.ssh/id_rsa".into(),
            flags: 0,
        });
        assert_eq!(
            rate_uncorrelated(&event, Some("/Users/dev/project")),
            Severity::High
        );
    }
}
