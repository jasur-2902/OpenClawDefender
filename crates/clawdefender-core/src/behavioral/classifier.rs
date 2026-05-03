//! Tier 1 cheap event classification.
//!
//! Classifies correlated events into priority tiers using O(1) lookups and
//! simple string matching. This runs on every event and must be extremely
//! cheap (<10us per event). Events classified as `Routine` skip the expensive
//! behavioral analysis pipeline (anomaly scoring, kill chain detection,
//! decision engine) while still being logged and sent to the UI.

use std::sync::LazyLock;

use crate::event::correlation::CorrelatedEvent;
use crate::event::os::OsEventKind;

/// Priority tier for a correlated event.
///
/// Determines how deeply the event is processed through the behavioral
/// analysis pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventPriority {
    /// Sensitive path access, network connections, process exec, privilege ops.
    /// Goes through the FULL pipeline: behavioral -> anomaly -> kill chain -> decision -> SLM.
    High,
    /// From an MCP-tracked process (has an MCP event component).
    /// Goes through the FULL pipeline.
    Mcp,
    /// Normal file ops in project/build/cache directories.
    /// ONLY logged (audit) and sent to UI — skips behavioral analysis entirely.
    Routine,
}

/// Sensitive path fragments for O(1)-style matching.
///
/// We use `contains()` checks on these fragments rather than regex.
/// The list covers credentials, secrets, persistence mechanisms, and
/// configuration files that are common targets for MCP-based attacks.
static SENSITIVE_PATH_FRAGMENTS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        // SSH keys and config
        "/.ssh/",
        "/.ssh",
        // AWS credentials
        "/.aws/",
        "/.aws",
        // GPG keys
        "/.gnupg/",
        "/.gnupg",
        // Environment files
        "/.env",
        // macOS persistence
        "/Library/LaunchAgents/",
        "/Library/LaunchDaemons/",
        "/Library/Keychains/",
        "/Library/Application Scripts/",
        // System files
        "/etc/sudoers",
        "/etc/hosts",
        "/etc/ssh/",
        "/private/etc/",
        // Shell profiles (persistence targets)
        "/.zshrc",
        "/.bashrc",
        "/.zprofile",
        "/.bash_profile",
        // App-specific config (clawdefender / rookbot)
        "/.config/clawdefender/",
        "/.config/rookbot/",
        // MCP client configs
        "/claude_desktop_config.json",
        "/.cursor/mcp.json",
        // Container/cloud credentials
        "/.kube/config",
        "/.kube/",
        "/.docker/config.json",
        "/.config/gcloud/",
        "/.azure/",
        // Other credentials
        "/.password-store/",
        "/.netrc",
        "/.npmrc",
        "/.pypirc",
        "/id_rsa",
        "/id_ed25519",
        "/Cookies/",
        "/Login Data",
        "/Keychain-",
        "/credentials",
        // Honeypot files
        "/rookbot/honeypot/",
    ]
});

/// Classify a correlated event into a priority tier.
///
/// This is the Tier 1 classifier — it must be extremely cheap (<10us).
/// Uses simple string matching and field checks, no regex or allocations.
pub fn tier1_classify(event: &CorrelatedEvent) -> EventPriority {
    // Any event with an MCP component goes through full analysis.
    if event.mcp_event.is_some() {
        return EventPriority::Mcp;
    }

    // Check OS events for high-priority indicators.
    for os_event in &event.os_events {
        match &os_event.kind {
            // Network connections are always high priority.
            OsEventKind::Connect { .. } => return EventPriority::High,

            // Process execution is always high priority.
            OsEventKind::Exec { .. } => return EventPriority::High,

            // Privilege escalation events are always high priority.
            OsEventKind::Setuid { .. } | OsEventKind::Setgid { .. } => {
                return EventPriority::High
            }

            // Kernel extension loads are always high priority.
            OsEventKind::Kextload { .. } => return EventPriority::High,

            // Background task management items (persistence).
            OsEventKind::BtmLaunchItemAdd { .. } => return EventPriority::High,

            // XProtect malware detection.
            OsEventKind::XpMalwareDetected { .. } => return EventPriority::High,

            // Gatekeeper override.
            OsEventKind::GatekeeperUserOverride { .. } => return EventPriority::High,

            // Process inspection (potential injection).
            OsEventKind::GetTask { .. }
            | OsEventKind::Trace { .. }
            | OsEventKind::ProcCheck { .. } => return EventPriority::High,

            // Authentication events.
            OsEventKind::Authentication { .. }
            | OsEventKind::LoginLogin
            | OsEventKind::LoginLogout => return EventPriority::High,

            // Link/symlink creation (potential persistence).
            OsEventKind::Link { path } | OsEventKind::Symlink { path } => {
                if is_sensitive_path(path) {
                    return EventPriority::High;
                }
            }

            // File operations — check if path is sensitive.
            OsEventKind::Open { path, .. } => {
                if is_sensitive_path(path) {
                    return EventPriority::High;
                }
            }
            OsEventKind::Close { path } | OsEventKind::Unlink { path } => {
                if is_sensitive_path(path) {
                    return EventPriority::High;
                }
            }
            OsEventKind::Rename { source, dest } => {
                if is_sensitive_path(source) || is_sensitive_path(dest) {
                    return EventPriority::High;
                }
            }

            // PTY grant (terminal allocation — could be interactive shell).
            OsEventKind::PtyGrant { .. } => return EventPriority::High,

            // SetMode on sensitive files.
            OsEventKind::SetMode { .. } => return EventPriority::High,

            // Fork/Exit are low-value on their own.
            OsEventKind::Fork { .. } | OsEventKind::Exit { .. } => {}
        }
    }

    EventPriority::Routine
}

/// Check if a path touches a sensitive location.
///
/// Uses `contains()` checks against pre-compiled path fragments.
/// This is O(n) over the fragment list but n is small (~40 entries)
/// and each check is a simple substring scan.
fn is_sensitive_path(path: &str) -> bool {
    for fragment in SENSITIVE_PATH_FRAGMENTS.iter() {
        if path.contains(fragment) {
            return true;
        }
    }
    false
}

/// Check if a path is within a common build, project, or cache directory.
///
/// These paths generate high event volume but rarely represent security
/// concerns when accessed without an MCP component.
pub fn is_project_or_build_path(path: &str) -> bool {
    path.contains("/target/")          // Rust build
        || path.contains("/node_modules/")  // Node
        || path.contains("/.git/objects/")  // Git internals
        || path.contains("/build/")         // Generic build
        || path.contains("/dist/")          // Build output
        || path.contains("/__pycache__/")   // Python cache
        || path.contains("/Library/Caches/") // macOS caches
        || path.contains("/DerivedData/")   // Xcode
        || path.contains("/.cache/")        // Generic cache
        || path.contains("/Caches/")        // macOS app caches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::correlation::{CorrelatedEvent, CorrelationStatus};
    use crate::event::mcp::{McpEvent, McpEventKind, ToolCall};
    use crate::event::os::{OsEvent, OsEventKind};
    use chrono::Utc;
    use serde_json::json;

    fn make_os_event(kind: OsEventKind) -> OsEvent {
        OsEvent {
            timestamp: Utc::now(),
            pid: 1234,
            ppid: 100,
            process_path: "/usr/local/bin/node".to_string(),
            kind,
            signing_id: None,
            team_id: None,
        }
    }

    fn make_correlated(mcp: Option<McpEvent>, os_events: Vec<OsEvent>) -> CorrelatedEvent {
        CorrelatedEvent {
            id: "test-id".to_string(),
            mcp_event: mcp,
            os_events,
            status: CorrelationStatus::Matched,
            correlated_at: Some(Utc::now()),
        }
    }

    fn make_mcp_tool_call() -> McpEvent {
        McpEvent {
            timestamp: Utc::now(),
            source: "mcp-proxy".to_string(),
            kind: McpEventKind::ToolCall(ToolCall {
                tool_name: "read_file".to_string(),
                arguments: json!({"path": "/tmp/test.rs"}),
                request_id: json!(1),
            }),
            raw_message: json!({}),
        }
    }

    // -- MCP events always get Mcp priority --

    #[test]
    fn test_mcp_event_is_mcp_priority() {
        let event = make_correlated(Some(make_mcp_tool_call()), vec![]);
        assert_eq!(tier1_classify(&event), EventPriority::Mcp);
    }

    #[test]
    fn test_mcp_with_os_events_is_mcp_priority() {
        let os = make_os_event(OsEventKind::Open {
            path: "/tmp/foo.txt".to_string(),
            flags: 0,
        });
        let event = make_correlated(Some(make_mcp_tool_call()), vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::Mcp);
    }

    // -- Network connections are High --

    #[test]
    fn test_network_connect_is_high() {
        let os = make_os_event(OsEventKind::Connect {
            address: "evil.com".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    // -- Exec is High --

    #[test]
    fn test_exec_is_high() {
        let os = make_os_event(OsEventKind::Exec {
            target_path: "/bin/bash".to_string(),
            args: vec![],
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    // -- Sensitive path access is High --

    #[test]
    fn test_ssh_key_access_is_high() {
        let os = make_os_event(OsEventKind::Open {
            path: "/Users/dev/.ssh/id_rsa".to_string(),
            flags: 0,
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    #[test]
    fn test_aws_credentials_is_high() {
        let os = make_os_event(OsEventKind::Open {
            path: "/Users/dev/.aws/credentials".to_string(),
            flags: 0,
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    #[test]
    fn test_env_file_is_high() {
        let os = make_os_event(OsEventKind::Open {
            path: "/Users/dev/project/.env".to_string(),
            flags: 0,
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    #[test]
    fn test_kube_config_is_high() {
        let os = make_os_event(OsEventKind::Open {
            path: "/Users/dev/.kube/config".to_string(),
            flags: 0,
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    #[test]
    fn test_launch_agents_is_high() {
        let os = make_os_event(OsEventKind::Open {
            path: "/Users/dev/Library/LaunchAgents/evil.plist".to_string(),
            flags: 1,
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    #[test]
    fn test_bashrc_is_high() {
        let os = make_os_event(OsEventKind::Open {
            path: "/Users/dev/.bashrc".to_string(),
            flags: 1,
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    #[test]
    fn test_honeypot_is_high() {
        let os = make_os_event(OsEventKind::Open {
            path: "/Users/dev/.config/rookbot/honeypot/ssh/id_rsa".to_string(),
            flags: 0,
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    // -- Routine file access in build dirs --

    #[test]
    fn test_normal_file_open_is_routine() {
        let os = make_os_event(OsEventKind::Open {
            path: "/Users/dev/project/target/debug/build/foo.rs".to_string(),
            flags: 1,
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::Routine);
    }

    #[test]
    fn test_node_modules_is_routine() {
        let os = make_os_event(OsEventKind::Open {
            path: "/Users/dev/project/node_modules/foo/index.js".to_string(),
            flags: 0,
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::Routine);
    }

    // -- Empty event is Routine --

    #[test]
    fn test_empty_os_events_is_routine() {
        let event = make_correlated(None, vec![]);
        assert_eq!(tier1_classify(&event), EventPriority::Routine);
    }

    // -- Mixed events: High takes precedence --

    #[test]
    fn test_mixed_events_high_takes_precedence() {
        let routine_os = make_os_event(OsEventKind::Open {
            path: "/tmp/build/foo.o".to_string(),
            flags: 1,
        });
        let sensitive_os = make_os_event(OsEventKind::Connect {
            address: "evil.com".to_string(),
            port: 8080,
            protocol: "tcp".to_string(),
        });
        let event = make_correlated(None, vec![routine_os, sensitive_os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    // -- Privilege events --

    #[test]
    fn test_setuid_is_high() {
        let os = make_os_event(OsEventKind::Setuid {
            path: "/tmp/escalate".to_string(),
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    #[test]
    fn test_kextload_is_high() {
        let os = make_os_event(OsEventKind::Kextload {
            identifier: "com.evil.rootkit".to_string(),
        });
        let event = make_correlated(None, vec![os]);
        assert_eq!(tier1_classify(&event), EventPriority::High);
    }

    // -- Helper function tests --

    #[test]
    fn test_is_sensitive_path() {
        assert!(is_sensitive_path("/Users/dev/.ssh/id_rsa"));
        assert!(is_sensitive_path("/Users/dev/.aws/credentials"));
        assert!(is_sensitive_path("/Users/dev/.gnupg/secring.gpg"));
        assert!(is_sensitive_path("/Users/dev/.env"));
        assert!(is_sensitive_path("/Users/dev/project/.env"));
        assert!(is_sensitive_path("/etc/sudoers"));
        assert!(is_sensitive_path("/etc/hosts"));
        assert!(is_sensitive_path("/Users/dev/.kube/config"));
        assert!(is_sensitive_path("/Users/dev/.docker/config.json"));
        assert!(is_sensitive_path(
            "/Users/dev/.config/rookbot/honeypot/ssh/id_rsa"
        ));
        // Non-sensitive paths
        assert!(!is_sensitive_path("/tmp/build/foo.o"));
        assert!(!is_sensitive_path("/Users/dev/project/src/main.rs"));
        assert!(!is_sensitive_path("/Users/dev/node_modules/foo/index.js"));
    }

    #[test]
    fn test_is_project_or_build_path() {
        assert!(is_project_or_build_path(
            "/Users/dev/project/target/debug/build/foo.rs"
        ));
        assert!(is_project_or_build_path(
            "/Users/dev/project/node_modules/foo/index.js"
        ));
        assert!(is_project_or_build_path(
            "/Users/dev/project/.git/objects/ab/cdef1234"
        ));
        assert!(is_project_or_build_path(
            "/Users/dev/project/build/output.o"
        ));
        assert!(is_project_or_build_path("/Users/dev/project/dist/app.js"));
        assert!(is_project_or_build_path(
            "/Users/dev/project/__pycache__/mod.pyc"
        ));
        assert!(is_project_or_build_path(
            "/Users/dev/Library/Caches/com.apple.something"
        ));
        assert!(is_project_or_build_path(
            "/Users/dev/Library/Developer/Xcode/DerivedData/foo"
        ));
        // Non-build paths
        assert!(!is_project_or_build_path("/Users/dev/project/src/main.rs"));
        assert!(!is_project_or_build_path("/tmp/foo.txt"));
    }
}
