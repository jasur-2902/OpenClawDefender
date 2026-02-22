//! Integration tests for guard-daemon interaction.

use clawdefender_guard::connection::{GuardRequest, GuardResponse};
use clawdefender_guard::registry::{GuardMode, GuardRegistry, PermissionSet};
use clawdefender_guard::types;

// ---- Guard registry tests ----

#[tokio::test]
async fn guard_register_via_registry() {
    let registry = GuardRegistry::new();
    let perms = test_permissions();
    let (id, rules) = registry
        .register("test-agent".into(), 9999, perms, GuardMode::Enforce)
        .await;
    assert!(!id.is_empty());
    assert!(rules > 0);
    let info = registry.get(&id).await.unwrap();
    assert_eq!(info["agent_name"], "test-agent");
    assert_eq!(info["pid"], 9999);
}

#[tokio::test]
async fn guard_deregister_via_registry() {
    let registry = GuardRegistry::new();
    let (id, _) = registry
        .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
        .await;
    assert!(registry.deregister(&id).await);
    assert!(registry.get(&id).await.is_none());
}

#[tokio::test]
async fn guard_list_multiple() {
    let registry = GuardRegistry::new();
    registry
        .register(
            "agent-a".into(),
            100,
            test_permissions(),
            GuardMode::Enforce,
        )
        .await;
    registry
        .register(
            "agent-b".into(),
            200,
            test_permissions(),
            GuardMode::Monitor,
        )
        .await;
    let list = registry.list().await;
    assert_eq!(list.len(), 2);
}

#[tokio::test]
async fn guard_stats_query() {
    let registry = GuardRegistry::new();
    let (id, _) = registry
        .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
        .await;

    // Perform some checks to generate stats.
    registry.check_action(&id, "shell", "ls").await;
    registry.check_action(&id, "tool_use", "read_file").await;

    let stats = registry.get_stats(&id).await.unwrap();
    assert_eq!(stats["checks_total"], 2);
    assert!(stats["checks_blocked"].as_u64().unwrap() >= 1); // shell should be blocked
}

#[tokio::test]
async fn guard_cleanup_removes_dead_pids() {
    let registry = GuardRegistry::new();
    // Register with a PID that is very unlikely to exist.
    let (id, _) = registry
        .register(
            "dead-agent".into(),
            999999,
            test_permissions(),
            GuardMode::Enforce,
        )
        .await;
    assert!(registry.get(&id).await.is_some());

    // Run cleanup.
    registry.cleanup_dead_pids().await;

    // Guard should be removed because PID 999999 doesn't exist.
    assert!(registry.get(&id).await.is_none());
}

#[tokio::test]
async fn guard_cleanup_keeps_alive_pids() {
    let registry = GuardRegistry::new();
    // Register with our own PID (which is alive).
    let own_pid = std::process::id();
    let (id, _) = registry
        .register(
            "alive-agent".into(),
            own_pid,
            test_permissions(),
            GuardMode::Enforce,
        )
        .await;

    registry.cleanup_dead_pids().await;

    // Our PID is alive, so guard should remain.
    assert!(registry.get(&id).await.is_some());
}

// ---- GuardRequest/GuardResponse serialization tests ----

#[test]
fn guard_register_request_serialization() {
    let req = GuardRequest::GuardRegister {
        agent_name: "my-bot".to_string(),
        pid: 12345,
        permissions: Box::new(types::PermissionSet {
            file_read: vec!["~/workspace/**".to_string()],
            file_write: vec!["~/workspace/**".to_string()],
            file_delete: vec![],
            shell_execute: types::ShellPolicy::Deny,
            network: types::NetworkPolicy {
                allowed_hosts: vec!["api.example.com".to_string()],
                allowed_ports: vec![443],
                deny_all: false,
            },
            tools: vec!["read_file".to_string()],
            max_file_size: None,
            max_files_per_minute: None,
            max_network_requests_per_minute: None,
        }),
        policy_toml: String::new(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let parsed: GuardRequest = serde_json::from_str(&json).unwrap();
    match parsed {
        GuardRequest::GuardRegister {
            agent_name, pid, ..
        } => {
            assert_eq!(agent_name, "my-bot");
            assert_eq!(pid, 12345);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn guard_deregister_request_serialization() {
    let req = GuardRequest::GuardDeregister {
        agent_name: "my-bot".to_string(),
        pid: 12345,
    };
    let json = serde_json::to_string(&req).unwrap();
    let parsed: GuardRequest = serde_json::from_str(&json).unwrap();
    match parsed {
        GuardRequest::GuardDeregister { agent_name, pid } => {
            assert_eq!(agent_name, "my-bot");
            assert_eq!(pid, 12345);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn guard_health_check_serialization() {
    let req = GuardRequest::GuardHealthCheck;
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("GuardHealthCheck"));
    let parsed: GuardRequest = serde_json::from_str(&json).unwrap();
    assert!(matches!(parsed, GuardRequest::GuardHealthCheck));
}

#[test]
fn guard_stats_query_serialization() {
    let req = GuardRequest::GuardStatsQuery {
        agent_name: "my-bot".to_string(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let parsed: GuardRequest = serde_json::from_str(&json).unwrap();
    match parsed {
        GuardRequest::GuardStatsQuery { agent_name } => {
            assert_eq!(agent_name, "my-bot");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn guard_registered_response_serialization() {
    let resp = GuardResponse::GuardRegistered {
        guard_id: "guard_abc123".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: GuardResponse = serde_json::from_str(&json).unwrap();
    match parsed {
        GuardResponse::GuardRegistered { guard_id } => {
            assert_eq!(guard_id, "guard_abc123");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn guard_deregistered_response_serialization() {
    let resp = GuardResponse::GuardDeregistered;
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: GuardResponse = serde_json::from_str(&json).unwrap();
    assert!(matches!(parsed, GuardResponse::GuardDeregistered));
}

#[test]
fn guard_error_response_serialization() {
    let resp = GuardResponse::Error {
        message: "not found".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: GuardResponse = serde_json::from_str(&json).unwrap();
    match parsed {
        GuardResponse::Error { message } => {
            assert_eq!(message, "not found");
        }
        _ => panic!("wrong variant"),
    }
}

// ---- Policy scoping tests ----

#[tokio::test]
async fn guard_policy_only_applies_to_registered_guard() {
    let registry = GuardRegistry::new();
    let (id, _) = registry
        .register(
            "scoped-agent".into(),
            100,
            test_permissions(),
            GuardMode::Enforce,
        )
        .await;

    // Guard's PID (100) should be checked against guard policy.
    let result = registry.check_action(&id, "shell", "rm -rf /").await;
    assert!(result.is_some());
    assert!(!result.unwrap().allowed);

    // Non-existent guard should return None.
    let result = registry
        .check_action("nonexistent", "shell", "rm -rf /")
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn guard_policy_allows_permitted_operations() {
    let registry = GuardRegistry::new();
    let home = std::env::var("HOME").unwrap_or_default();
    let (id, _) = registry
        .register(
            "permissive-agent".into(),
            1,
            test_permissions(),
            GuardMode::Enforce,
        )
        .await;

    let result = registry
        .check_action(
            &id,
            "file_read",
            &format!("{}/Projects/workspace/src/main.rs", home),
        )
        .await
        .unwrap();
    assert!(result.allowed);
}

#[tokio::test]
async fn guard_policy_blocks_sensitive_paths() {
    let registry = GuardRegistry::new();
    let (id, _) = registry
        .register(
            "sensitive-agent".into(),
            1,
            test_permissions(),
            GuardMode::Enforce,
        )
        .await;

    let result = registry
        .check_action(&id, "file_read", "/home/user/.ssh/id_rsa")
        .await
        .unwrap();
    assert!(!result.allowed);
    assert_eq!(result.rule, "guard_block_sensitive_paths");
}

// ---- Config tests ----

#[test]
fn guard_api_config_defaults() {
    let config = clawdefender_core::config::ClawConfig::default();
    assert!(config.guard_api.enabled);
    assert_eq!(config.guard_api.port, 3202);
}

#[test]
fn guard_api_config_from_toml() {
    let toml_str = r#"
[guard_api]
enabled = false
port = 4000
"#;
    let config: clawdefender_core::config::ClawConfig = toml::from_str(toml_str).unwrap();
    assert!(!config.guard_api.enabled);
    assert_eq!(config.guard_api.port, 4000);
}

#[test]
fn guard_api_config_empty_toml_uses_defaults() {
    let config: clawdefender_core::config::ClawConfig = toml::from_str("").unwrap();
    assert!(config.guard_api.enabled);
    assert_eq!(config.guard_api.port, 3202);
}

// ---- Helpers ----

fn test_permissions() -> PermissionSet {
    PermissionSet {
        file_read: vec!["~/Projects/workspace/**".to_string()],
        file_write: vec!["~/Projects/workspace/**".to_string()],
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec!["api.anthropic.com".to_string()],
        tools: vec!["read_file".to_string(), "write_file".to_string()],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    }
}
