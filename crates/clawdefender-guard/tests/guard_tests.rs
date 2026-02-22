//! Comprehensive tests for the clawdefender-guard crate.

use clawdefender_guard::connection::{
    expand_socket_path, GuardEvent, GuardEventKind, GuardRequest, GuardResponse,
};
use clawdefender_guard::fallback::FallbackEngine;
use clawdefender_guard::guard::GuardBuilder;
use clawdefender_guard::policy_gen::{generate_policy_toml, validate_policy_toml};
use clawdefender_guard::selftest::run_self_test;
use clawdefender_guard::types::*;

// ---------------------------------------------------------------------------
// Builder pattern tests
// ---------------------------------------------------------------------------

#[test]
fn builder_creates_inactive_guard() {
    let guard = GuardBuilder::new("test-agent").build();
    assert_eq!(guard.name(), "test-agent");
    assert_eq!(guard.status(), &GuardStatus::Inactive);
    assert_eq!(guard.mode(), GuardMode::Enforce);
}

#[test]
fn builder_with_permissions() {
    let perms = PermissionSet {
        file_read: vec!["/project/**".to_string()],
        file_write: vec!["/project/src/**".to_string()],
        tools: vec!["read_file".to_string()],
        ..Default::default()
    };
    let guard = GuardBuilder::new("test-agent").permissions(perms).build();
    assert_eq!(guard.name(), "test-agent");
}

#[test]
fn builder_with_mode() {
    let guard = GuardBuilder::new("monitor-agent")
        .mode(GuardMode::Monitor)
        .build();
    assert_eq!(guard.mode(), GuardMode::Monitor);
}

#[test]
fn builder_with_fluent_api() {
    let guard = AgentGuard::builder("fluent-agent")
        .file_read(vec!["/project/**".to_string()])
        .file_write(vec!["/project/src/**".to_string()])
        .file_delete(vec!["/tmp/**".to_string()])
        .shell_policy(ShellPolicy::Deny)
        .network_policy(NetworkPolicy {
            allowed_hosts: vec!["api.example.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        })
        .tools(vec!["custom_tool".to_string()])
        .mode(GuardMode::Enforce)
        .build();
    assert_eq!(guard.name(), "fluent-agent");
    assert_eq!(guard.mode(), GuardMode::Enforce);
}

#[test]
fn builder_socket_path() {
    let guard = GuardBuilder::new("test-agent")
        .socket_path("/custom/socket.sock")
        .build();
    assert_eq!(guard.name(), "test-agent");
}

// ---------------------------------------------------------------------------
// Policy generation tests
// ---------------------------------------------------------------------------

#[test]
fn policy_gen_basic_permissions() {
    let perms = PermissionSet {
        file_read: vec!["/project/**".to_string()],
        file_write: vec!["/project/src/**".to_string()],
        ..Default::default()
    };
    let toml = generate_policy_toml("test-agent", &perms);
    assert!(toml.contains("guard_block_sensitive_paths"));
    assert!(toml.contains("guard_allow_project_read"));
    assert!(toml.contains("guard_allow_project_write"));
    assert!(toml.contains("guard_block_everything_else"));
    validate_policy_toml(&toml).unwrap();
}

#[test]
fn policy_gen_shell_deny() {
    let perms = PermissionSet {
        shell_execute: ShellPolicy::Deny,
        ..Default::default()
    };
    let toml = generate_policy_toml("test-agent", &perms);
    assert!(toml.contains("guard_block_all_shell"));
    validate_policy_toml(&toml).unwrap();
}

#[test]
fn policy_gen_shell_allowlist() {
    let perms = PermissionSet {
        shell_execute: ShellPolicy::AllowList(vec!["git *".to_string()]),
        ..Default::default()
    };
    let toml = generate_policy_toml("test-agent", &perms);
    assert!(toml.contains("guard_allow_shell"));
    validate_policy_toml(&toml).unwrap();
}

#[test]
fn policy_gen_shell_with_approval() {
    let perms = PermissionSet {
        shell_execute: ShellPolicy::AllowWithApproval,
        ..Default::default()
    };
    let toml = generate_policy_toml("test-agent", &perms);
    assert!(toml.contains("guard_prompt_shell"));
    validate_policy_toml(&toml).unwrap();
}

#[test]
fn policy_gen_network_deny_all() {
    let perms = PermissionSet {
        network: NetworkPolicy {
            deny_all: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let toml = generate_policy_toml("test-agent", &perms);
    assert!(toml.contains("guard_block_all_network"));
    validate_policy_toml(&toml).unwrap();
}

#[test]
fn policy_gen_network_allowed_hosts() {
    let perms = PermissionSet {
        network: NetworkPolicy {
            allowed_hosts: vec!["api.anthropic.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        },
        ..Default::default()
    };
    let toml = generate_policy_toml("test-agent", &perms);
    assert!(toml.contains("guard_allow_network"));
    assert!(toml.contains("guard_block_undeclared_network"));
    validate_policy_toml(&toml).unwrap();
}

#[test]
fn policy_gen_with_tools() {
    let perms = PermissionSet {
        tools: vec!["custom_tool".to_string(), "another_tool".to_string()],
        ..Default::default()
    };
    let toml = generate_policy_toml("test-agent", &perms);
    assert!(toml.contains("guard_allow_declared_tools"));
    assert!(toml.contains("custom_tool"));
    validate_policy_toml(&toml).unwrap();
}

#[test]
fn policy_gen_sensitive_paths_always_present() {
    let perms = PermissionSet::default();
    let toml = generate_policy_toml("test-agent", &perms);
    assert!(toml.contains("~/.ssh/**"));
    assert!(toml.contains("~/.aws/**"));
    assert!(toml.contains("~/.gnupg/**"));
    assert!(toml.contains("~/.config/gcloud/**"));
    validate_policy_toml(&toml).unwrap();
}

#[test]
fn policy_gen_empty_permissions() {
    let perms = PermissionSet::default();
    let toml = generate_policy_toml("minimal-agent", &perms);
    assert!(toml.contains("guard_block_sensitive_paths"));
    assert!(toml.contains("guard_block_everything_else"));
    assert!(!toml.contains("guard_allow_project_read"));
    validate_policy_toml(&toml).unwrap();
}

#[test]
fn policy_gen_with_delete_paths() {
    let perms = PermissionSet {
        file_delete: vec!["/tmp/agent-*".to_string()],
        ..Default::default()
    };
    let toml = generate_policy_toml("test-agent", &perms);
    assert!(toml.contains("guard_allow_project_delete"));
    validate_policy_toml(&toml).unwrap();
}

// ---------------------------------------------------------------------------
// Enforce mode tests
// ---------------------------------------------------------------------------

#[test]
fn enforce_allow_declared_read() {
    let mut guard = AgentGuard::builder("test-agent")
        .file_read(vec!["/project/**".to_string()])
        .build();
    guard.activate().unwrap();
    let result = guard.check_action("read_file", "/project/src/main.rs");
    assert_eq!(result, ActionResult::Allow);
}

#[test]
fn enforce_block_undeclared_read() {
    let mut guard = AgentGuard::builder("test-agent")
        .file_read(vec!["/project/**".to_string()])
        .build();
    guard.activate().unwrap();
    let result = guard.check_action("read_file", "/etc/passwd");
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn enforce_block_sensitive_path() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let mut guard = AgentGuard::builder("test-agent")
        .file_read(vec![format!("{home}/**")])
        .build();
    guard.activate().unwrap();
    let ssh_path = format!("{home}/.ssh/id_rsa");
    let result = guard.check_action("read_file", &ssh_path);
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn enforce_block_shell_when_deny() {
    let mut guard = AgentGuard::builder("test-agent")
        .shell_policy(ShellPolicy::Deny)
        .build();
    guard.activate().unwrap();
    let result = guard.check_action("bash", "ls -la");
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn enforce_block_network_when_deny_all() {
    let mut guard = AgentGuard::builder("test-agent")
        .network_policy(NetworkPolicy {
            deny_all: true,
            ..Default::default()
        })
        .build();
    guard.activate().unwrap();
    let result = guard.check_action("fetch", "https://example.com");
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn enforce_allow_declared_tool() {
    let mut guard = AgentGuard::builder("test-agent")
        .tools(vec!["custom_tool".to_string()])
        .build();
    guard.activate().unwrap();
    let result = guard.check_action("custom_tool", "anything");
    assert_eq!(result, ActionResult::Allow);
}

#[test]
fn enforce_block_undeclared_tool() {
    let mut guard = AgentGuard::builder("test-agent")
        .tools(vec!["custom_tool".to_string()])
        .build();
    guard.activate().unwrap();
    let result = guard.check_action("dangerous_tool", "anything");
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn enforce_allow_declared_write() {
    let mut guard = AgentGuard::builder("test-agent")
        .file_write(vec!["/project/src/**".to_string()])
        .build();
    guard.activate().unwrap();
    let result = guard.check_action("write_file", "/project/src/lib.rs");
    assert_eq!(result, ActionResult::Allow);
}

#[test]
fn enforce_block_undeclared_write() {
    let mut guard = AgentGuard::builder("test-agent")
        .file_write(vec!["/project/src/**".to_string()])
        .build();
    guard.activate().unwrap();
    let result = guard.check_action("write_file", "/etc/shadow");
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn enforce_allow_network_declared_host() {
    let mut guard = AgentGuard::builder("test-agent")
        .network_policy(NetworkPolicy {
            allowed_hosts: vec!["api.example.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        })
        .build();
    guard.activate().unwrap();
    let result = guard.check_action("fetch", "api.example.com");
    assert_eq!(result, ActionResult::Allow);
}

#[test]
fn enforce_block_network_undeclared_host() {
    let mut guard = AgentGuard::builder("test-agent")
        .network_policy(NetworkPolicy {
            allowed_hosts: vec!["api.example.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        })
        .build();
    guard.activate().unwrap();
    let result = guard.check_action("fetch", "evil.example.com");
    assert!(matches!(result, ActionResult::Block(_)));
}

// ---------------------------------------------------------------------------
// Monitor mode tests
// ---------------------------------------------------------------------------

#[test]
fn monitor_mode_does_not_block() {
    let mut guard = AgentGuard::builder("monitor-agent")
        .mode(GuardMode::Monitor)
        .build();
    guard.activate().unwrap();

    let result = guard.check_action("dangerous_tool", "/etc/passwd");
    assert!(matches!(
        result,
        ActionResult::Monitored {
            would_block: true,
            ..
        }
    ));
}

#[test]
fn monitor_mode_records_operations() {
    let mut guard = AgentGuard::builder("monitor-agent")
        .mode(GuardMode::Monitor)
        .file_read(vec!["/project/**".to_string()])
        .build();
    guard.activate().unwrap();

    guard.check_action("read_file", "/project/src/main.rs");
    guard.check_action("read_file", "/etc/passwd");

    let stats = guard.stats();
    assert_eq!(stats.monitored_operations.len(), 2);
    assert!(!stats.monitored_operations[0].would_block);
    assert!(stats.monitored_operations[1].would_block);
}

#[test]
fn monitor_mode_all_counted_as_allowed() {
    let mut guard = AgentGuard::builder("monitor-agent")
        .mode(GuardMode::Monitor)
        .build();
    guard.activate().unwrap();

    guard.check_action("dangerous_tool", "target1");
    guard.check_action("dangerous_tool", "target2");

    let stats = guard.stats();
    assert_eq!(stats.operations_allowed, 2);
    assert_eq!(stats.operations_blocked, 0);
}

// ---------------------------------------------------------------------------
// suggest_permissions tests
// ---------------------------------------------------------------------------

#[test]
fn suggest_permissions_from_monitored_ops() {
    let mut guard = AgentGuard::builder("monitor-agent")
        .mode(GuardMode::Monitor)
        .build();
    guard.activate().unwrap();

    guard.check_action("read_file", "/project/src/main.rs");
    guard.check_action("write_file", "/project/src/lib.rs");
    guard.check_action("bash", "git status");
    guard.check_action("fetch", "api.example.com");
    guard.check_action("custom_tool", "anything");

    let suggested = guard.suggest_permissions();
    assert!(suggested
        .file_read
        .contains(&"/project/src/main.rs".to_string()));
    assert!(suggested
        .file_write
        .contains(&"/project/src/lib.rs".to_string()));
    assert!(suggested.shell_commands.contains(&"bash".to_string()));
    assert!(suggested
        .network_hosts
        .contains(&"api.example.com".to_string()));
    assert!(suggested.tools.contains(&"custom_tool".to_string()));
}

#[test]
fn suggest_permissions_empty_when_no_blocks() {
    let mut guard = AgentGuard::builder("monitor-agent")
        .mode(GuardMode::Monitor)
        .file_read(vec!["/project/**".to_string()])
        .tools(vec!["custom_tool".to_string()])
        .build();
    guard.activate().unwrap();

    guard.check_action("read_file", "/project/src/main.rs");
    guard.check_action("custom_tool", "anything");

    let suggested = guard.suggest_permissions();
    assert!(suggested.file_read.is_empty());
    assert!(suggested.tools.is_empty());
}

#[test]
fn suggest_permissions_deduplicates() {
    let mut guard = AgentGuard::builder("monitor-agent")
        .mode(GuardMode::Monitor)
        .build();
    guard.activate().unwrap();

    guard.check_action("read_file", "/etc/passwd");
    guard.check_action("read_file", "/etc/passwd");
    guard.check_action("read_file", "/etc/passwd");

    let suggested = guard.suggest_permissions();
    assert_eq!(suggested.file_read.len(), 1);
}

// ---------------------------------------------------------------------------
// Self-test tests
// ---------------------------------------------------------------------------

#[test]
fn selftest_passes_with_default_perms() {
    let engine = FallbackEngine::new(PermissionSet::default());
    let status = run_self_test(&engine);
    assert_eq!(status, GuardStatus::Active);
}

#[test]
fn selftest_with_safe_permissions() {
    let engine = FallbackEngine::new(PermissionSet {
        file_read: vec!["/safe/**".to_string()],
        ..Default::default()
    });
    let status = run_self_test(&engine);
    assert_eq!(status, GuardStatus::Active);
}

// ---------------------------------------------------------------------------
// Stats tracking tests
// ---------------------------------------------------------------------------

#[test]
fn stats_track_allowed_operations() {
    let mut guard = AgentGuard::builder("test-agent")
        .file_read(vec!["/project/**".to_string()])
        .build();
    guard.activate().unwrap();

    guard.check_action("read_file", "/project/a.txt");
    guard.check_action("read_file", "/project/b.txt");

    let stats = guard.stats();
    assert_eq!(stats.operations_allowed, 2);
    assert_eq!(stats.operations_blocked, 0);
}

#[test]
fn stats_track_blocked_operations() {
    let mut guard = AgentGuard::builder("test-agent")
        .file_read(vec!["/project/**".to_string()])
        .build();
    guard.activate().unwrap();

    guard.check_action("read_file", "/etc/passwd");
    guard.check_action("read_file", "/etc/shadow");

    let stats = guard.stats();
    assert_eq!(stats.operations_blocked, 2);
    assert_eq!(stats.blocked_details.len(), 2);
}

#[test]
fn stats_have_activation_timestamp() {
    let mut guard = AgentGuard::builder("test-agent").build();
    let stats = guard.stats();
    assert!(stats.activated_at.is_none());

    guard.activate().unwrap();
    let stats = guard.stats();
    assert!(stats.activated_at.is_some());
}

#[test]
fn stats_blocked_details_have_correct_fields() {
    let mut guard = AgentGuard::builder("test-agent")
        .file_read(vec!["/project/**".to_string()])
        .build();
    guard.activate().unwrap();

    guard.check_action("read_file", "/etc/passwd");

    let stats = guard.stats();
    assert_eq!(stats.blocked_details.len(), 1);
    assert_eq!(stats.blocked_details[0].tool, "read_file");
    assert_eq!(stats.blocked_details[0].target, "/etc/passwd");
    assert!(!stats.blocked_details[0].reason.is_empty());
}

// ---------------------------------------------------------------------------
// Lifecycle tests
// ---------------------------------------------------------------------------

#[test]
fn guard_activation_deactivation() {
    let mut guard = AgentGuard::builder("lifecycle-agent")
        .file_read(vec!["/project/**".to_string()])
        .build();

    assert_eq!(guard.status(), &GuardStatus::Inactive);
    assert!(!guard.is_healthy());

    guard.activate().unwrap();
    assert!(guard.is_healthy());

    guard.deactivate().unwrap();
    assert_eq!(guard.status(), &GuardStatus::Inactive);
    assert!(!guard.is_healthy());
}

#[test]
fn guard_double_deactivate_is_ok() {
    let mut guard = AgentGuard::builder("test-agent").build();
    guard.activate().unwrap();
    guard.deactivate().unwrap();
    guard.deactivate().unwrap();
    assert_eq!(guard.status(), &GuardStatus::Inactive);
}

#[test]
fn guard_drop_deactivates() {
    let mut guard = AgentGuard::builder("drop-agent")
        .file_read(vec!["/project/**".to_string()])
        .build();
    guard.activate().unwrap();
    assert!(guard.is_healthy());
    drop(guard);
}

// ---------------------------------------------------------------------------
// Fallback engine tests
// ---------------------------------------------------------------------------

#[test]
fn fallback_blocks_sensitive_ssh() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let engine = FallbackEngine::new(PermissionSet {
        file_read: vec![format!("{home}/**")],
        ..Default::default()
    });
    let result = engine.check_action("read_file", &format!("{home}/.ssh/id_rsa"));
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn fallback_blocks_sensitive_aws() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let engine = FallbackEngine::new(PermissionSet::default());
    let result = engine.check_action("read_file", &format!("{home}/.aws/credentials"));
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn fallback_blocks_sensitive_gnupg() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let engine = FallbackEngine::new(PermissionSet::default());
    let result = engine.check_action("read_file", &format!("{home}/.gnupg/private-keys-v1.d/key"));
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn fallback_allows_declared_read() {
    let engine = FallbackEngine::new(PermissionSet {
        file_read: vec!["/project/**".to_string()],
        ..Default::default()
    });
    let result = engine.check_action("read_file", "/project/src/main.rs");
    assert_eq!(result, ActionResult::Allow);
}

#[test]
fn fallback_blocks_shell_deny() {
    let engine = FallbackEngine::new(PermissionSet {
        shell_execute: ShellPolicy::Deny,
        ..Default::default()
    });
    let result = engine.check_action("bash", "ls -la");
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn fallback_blocks_network_deny_all() {
    let engine = FallbackEngine::new(PermissionSet {
        network: NetworkPolicy {
            deny_all: true,
            ..Default::default()
        },
        ..Default::default()
    });
    let result = engine.check_action("fetch", "https://example.com");
    assert!(matches!(result, ActionResult::Block(_)));
}

#[test]
fn fallback_allows_declared_tool() {
    let engine = FallbackEngine::new(PermissionSet {
        tools: vec!["custom_tool".to_string()],
        ..Default::default()
    });
    let result = engine.check_action("custom_tool", "anything");
    assert_eq!(result, ActionResult::Allow);
}

#[test]
fn fallback_catchall_blocks() {
    let engine = FallbackEngine::new(PermissionSet::default());
    let result = engine.check_action("unknown_tool", "/random/path");
    assert!(matches!(result, ActionResult::Block(_)));
}

// ---------------------------------------------------------------------------
// Connection tests
// ---------------------------------------------------------------------------

#[test]
fn expand_socket_path_with_tilde() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let expanded = expand_socket_path("~/.local/share/clawdefender/clawdefender.sock");
    assert_eq!(
        expanded,
        format!("{home}/.local/share/clawdefender/clawdefender.sock")
    );
}

#[test]
fn expand_socket_path_without_tilde() {
    let path = "/var/run/clawdefender.sock";
    assert_eq!(expand_socket_path(path), path);
}

// ---------------------------------------------------------------------------
// IPC message serialization tests
// ---------------------------------------------------------------------------

#[test]
fn guard_request_register_serialization() {
    let req = GuardRequest::GuardRegister {
        agent_name: "test-agent".to_string(),
        pid: 12345,
        permissions: Box::new(PermissionSet::default()),
        policy_toml: "# test".to_string(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let _: GuardRequest = serde_json::from_str(&json).unwrap();
}

#[test]
fn guard_response_registered_serialization() {
    let resp = GuardResponse::GuardRegistered {
        guard_id: "guard-123".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let _: GuardResponse = serde_json::from_str(&json).unwrap();
}

#[test]
fn guard_event_blocked_serialization() {
    let event = GuardEvent {
        agent_name: "test-agent".to_string(),
        event: GuardEventKind::OperationBlocked {
            tool: "bash".to_string(),
            target: "rm -rf /".to_string(),
            reason: "shell denied".to_string(),
        },
    };
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: GuardEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.agent_name, "test-agent");
}

#[test]
fn guard_deregister_request_serialization() {
    let req = GuardRequest::GuardDeregister {
        agent_name: "test-agent".to_string(),
        pid: 12345,
    };
    let json = serde_json::to_string(&req).unwrap();
    let _: GuardRequest = serde_json::from_str(&json).unwrap();
}

#[test]
fn guard_health_check_serialization() {
    let req = GuardRequest::GuardHealthCheck;
    let json = serde_json::to_string(&req).unwrap();
    let _: GuardRequest = serde_json::from_str(&json).unwrap();

    let resp = GuardResponse::GuardHealthResponse {
        status: GuardStatus::Active,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let _: GuardResponse = serde_json::from_str(&json).unwrap();
}

#[test]
fn guard_anomaly_event_serialization() {
    let event = GuardEvent {
        agent_name: "test-agent".to_string(),
        event: GuardEventKind::AnomalyDetected {
            description: "unusual pattern".to_string(),
            severity: "HIGH".to_string(),
        },
    };
    let json = serde_json::to_string(&event).unwrap();
    let _: GuardEvent = serde_json::from_str(&json).unwrap();
}

#[test]
fn guard_stats_query_serialization() {
    let req = GuardRequest::GuardStatsQuery {
        agent_name: "test-agent".to_string(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let _: GuardRequest = serde_json::from_str(&json).unwrap();
}

#[test]
fn guard_error_response_serialization() {
    let resp = GuardResponse::Error {
        message: "something went wrong".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: GuardResponse = serde_json::from_str(&json).unwrap();
    match deserialized {
        GuardResponse::Error { message } => assert_eq!(message, "something went wrong"),
        _ => panic!("expected Error response"),
    }
}

#[test]
fn guard_policy_updated_event_serialization() {
    let event = GuardEvent {
        agent_name: "test-agent".to_string(),
        event: GuardEventKind::PolicyUpdated,
    };
    let json = serde_json::to_string(&event).unwrap();
    let _: GuardEvent = serde_json::from_str(&json).unwrap();
}
