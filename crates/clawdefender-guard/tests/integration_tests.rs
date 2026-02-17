//! End-to-end integration tests for the clawdefender-guard crate.
//!
//! These tests exercise the full lifecycle: guard creation, policy generation,
//! action checking, stats verification, monitor mode, and multi-guard scenarios.

use clawdefender_guard::fallback::FallbackEngine;
use clawdefender_guard::guard::GuardBuilder;
use clawdefender_guard::policy_gen::{generate_policy_toml, validate_policy_toml};
use clawdefender_guard::registry::GuardRegistry;
use clawdefender_guard::selftest::run_self_test;
use clawdefender_guard::types::*;

// ---------------------------------------------------------------------------
// 1. Full lifecycle: create → activate → check → stats → deactivate
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_enforce_mode() {
    let mut guard = AgentGuard::builder("lifecycle-bot")
        .file_read(vec!["/workspace/**".to_string()])
        .file_write(vec!["/workspace/output/**".to_string()])
        .network_policy(NetworkPolicy {
            allowed_hosts: vec!["api.anthropic.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        })
        .shell_policy(ShellPolicy::Deny)
        .tools(vec!["read_file".to_string(), "write_file".to_string()])
        .mode(GuardMode::Enforce)
        .build();

    // Initially inactive.
    assert_eq!(guard.status(), &GuardStatus::Inactive);
    assert!(!guard.is_healthy());

    // Activate.
    guard.activate().unwrap();
    assert!(guard.is_healthy());

    // Allowed operations.
    assert_eq!(
        guard.check_action("read_file", "/workspace/data.txt"),
        ActionResult::Allow
    );
    assert_eq!(
        guard.check_action("write_file", "/workspace/output/result.txt"),
        ActionResult::Allow
    );
    assert_eq!(
        guard.check_action("fetch", "api.anthropic.com"),
        ActionResult::Allow
    );

    // Blocked operations.
    assert!(matches!(
        guard.check_action("read_file", "/etc/passwd"),
        ActionResult::Block(_)
    ));
    assert!(matches!(
        guard.check_action("bash", "rm -rf /"),
        ActionResult::Block(_)
    ));
    assert!(matches!(
        guard.check_action("fetch", "evil.example.com"),
        ActionResult::Block(_)
    ));

    // Verify stats.
    let stats = guard.stats();
    assert_eq!(stats.operations_allowed, 3);
    assert_eq!(stats.operations_blocked, 3);
    assert_eq!(stats.blocked_details.len(), 3);
    assert!(stats.activated_at.is_some());

    // Deactivate.
    guard.deactivate().unwrap();
    assert_eq!(guard.status(), &GuardStatus::Inactive);
    assert!(!guard.is_healthy());
}

// ---------------------------------------------------------------------------
// 2. Monitor mode: operations recorded but not blocked
// ---------------------------------------------------------------------------

#[test]
fn monitor_mode_records_without_blocking() {
    let mut guard = AgentGuard::builder("monitor-bot")
        .file_read(vec!["/workspace/**".to_string()])
        .mode(GuardMode::Monitor)
        .build();

    guard.activate().unwrap();

    // All operations return Monitored, not Block.
    let result = guard.check_action("read_file", "/etc/shadow");
    assert!(matches!(
        result,
        ActionResult::Monitored {
            would_block: true,
            ..
        }
    ));

    let result = guard.check_action("read_file", "/workspace/ok.txt");
    assert!(matches!(
        result,
        ActionResult::Monitored {
            would_block: false,
            ..
        }
    ));

    // All counted as allowed (monitor does not block).
    let stats = guard.stats();
    assert_eq!(stats.operations_allowed, 2);
    assert_eq!(stats.operations_blocked, 0);
    assert_eq!(stats.monitored_operations.len(), 2);

    guard.deactivate().unwrap();
}

// ---------------------------------------------------------------------------
// 3. suggest_permissions works after monitor observations
// ---------------------------------------------------------------------------

#[test]
fn suggest_permissions_after_monitor() {
    let mut guard = AgentGuard::builder("suggest-bot")
        .mode(GuardMode::Monitor)
        .build();

    guard.activate().unwrap();

    guard.check_action("read_file", "/project/src/main.rs");
    guard.check_action("write_file", "/project/src/lib.rs");
    guard.check_action("bash", "git status");
    guard.check_action("fetch", "api.example.com");
    guard.check_action("custom_tool", "payload");

    let suggested = guard.suggest_permissions();
    assert!(!suggested.file_read.is_empty());
    assert!(!suggested.file_write.is_empty());
    assert!(!suggested.shell_commands.is_empty());
    assert!(!suggested.network_hosts.is_empty());
    assert!(!suggested.tools.is_empty());

    guard.deactivate().unwrap();
}

// ---------------------------------------------------------------------------
// 4. Multiple guards with different permissions don't interfere
// ---------------------------------------------------------------------------

#[test]
fn multiple_guards_independent() {
    let mut guard_a = AgentGuard::builder("agent-a")
        .file_read(vec!["/project-a/**".to_string()])
        .build();
    let mut guard_b = AgentGuard::builder("agent-b")
        .file_read(vec!["/project-b/**".to_string()])
        .build();

    guard_a.activate().unwrap();
    guard_b.activate().unwrap();

    // Guard A can read project-a but not project-b.
    assert_eq!(
        guard_a.check_action("read_file", "/project-a/file.rs"),
        ActionResult::Allow
    );
    assert!(matches!(
        guard_a.check_action("read_file", "/project-b/file.rs"),
        ActionResult::Block(_)
    ));

    // Guard B can read project-b but not project-a.
    assert_eq!(
        guard_b.check_action("read_file", "/project-b/file.rs"),
        ActionResult::Allow
    );
    assert!(matches!(
        guard_b.check_action("read_file", "/project-a/file.rs"),
        ActionResult::Block(_)
    ));

    // Stats are independent.
    assert_eq!(guard_a.stats().operations_allowed, 1);
    assert_eq!(guard_a.stats().operations_blocked, 1);
    assert_eq!(guard_b.stats().operations_allowed, 1);
    assert_eq!(guard_b.stats().operations_blocked, 1);

    guard_a.deactivate().unwrap();
    guard_b.deactivate().unwrap();
}

// ---------------------------------------------------------------------------
// 5. Guard deactivation unblocks (guard no longer enforces)
// ---------------------------------------------------------------------------

#[test]
fn deactivation_resets_status() {
    let mut guard = AgentGuard::builder("deactivate-bot")
        .file_read(vec!["/safe/**".to_string()])
        .build();

    guard.activate().unwrap();
    assert!(guard.is_healthy());

    // Can check actions while active.
    assert_eq!(
        guard.check_action("read_file", "/safe/file.txt"),
        ActionResult::Allow
    );

    guard.deactivate().unwrap();
    assert!(!guard.is_healthy());
    assert_eq!(guard.status(), &GuardStatus::Inactive);
}

// ---------------------------------------------------------------------------
// 6. Builder pattern with various configurations
// ---------------------------------------------------------------------------

#[test]
fn builder_minimal_config() {
    let guard = GuardBuilder::new("minimal").build();
    assert_eq!(guard.name(), "minimal");
    assert_eq!(guard.mode(), GuardMode::Enforce);
    assert_eq!(guard.status(), &GuardStatus::Inactive);
}

#[test]
fn builder_full_config() {
    let guard = AgentGuard::builder("full-config")
        .file_read(vec!["/a/**".to_string(), "/b/**".to_string()])
        .file_write(vec!["/a/output/**".to_string()])
        .file_delete(vec!["/tmp/scratch/**".to_string()])
        .shell_policy(ShellPolicy::AllowList(vec!["git *".to_string()]))
        .network_policy(NetworkPolicy {
            allowed_hosts: vec!["*.example.com".to_string()],
            allowed_ports: vec![80, 443],
            deny_all: false,
        })
        .tools(vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "search".to_string(),
        ])
        .mode(GuardMode::Monitor)
        .socket_path("/tmp/test.sock")
        .build();

    assert_eq!(guard.name(), "full-config");
    assert_eq!(guard.mode(), GuardMode::Monitor);
}

// ---------------------------------------------------------------------------
// 7. TOML policy generation validity
// ---------------------------------------------------------------------------

#[test]
fn generated_toml_is_valid_minimal() {
    let perms = PermissionSet::default();
    let toml = generate_policy_toml("test", &perms);
    validate_policy_toml(&toml).unwrap();
}

#[test]
fn generated_toml_is_valid_full() {
    let perms = PermissionSet {
        file_read: vec!["/project/**".to_string()],
        file_write: vec!["/project/src/**".to_string()],
        file_delete: vec!["/tmp/**".to_string()],
        shell_execute: ShellPolicy::AllowList(vec!["git *".to_string()]),
        network: NetworkPolicy {
            allowed_hosts: vec!["api.anthropic.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        },
        tools: vec!["read_file".to_string(), "write_file".to_string()],
        max_file_size: Some(10_000_000),
        max_files_per_minute: Some(100),
        max_network_requests_per_minute: Some(60),
    };
    let toml = generate_policy_toml("full-agent", &perms);
    validate_policy_toml(&toml).unwrap();

    // Verify key sections present.
    assert!(toml.contains("guard_block_sensitive_paths"));
    assert!(toml.contains("guard_allow_project_read"));
    assert!(toml.contains("guard_allow_project_write"));
    assert!(toml.contains("guard_allow_project_delete"));
    assert!(toml.contains("guard_allow_shell"));
    assert!(toml.contains("guard_allow_network"));
    assert!(toml.contains("guard_allow_declared_tools"));
    assert!(toml.contains("guard_block_everything_else"));
}

#[test]
fn generated_toml_contains_sensitive_paths() {
    let toml = generate_policy_toml("test", &PermissionSet::default());
    assert!(toml.contains("~/.ssh/**"));
    assert!(toml.contains("~/.aws/**"));
    assert!(toml.contains("~/.gnupg/**"));
    assert!(toml.contains("~/.config/gcloud/**"));
}

// ---------------------------------------------------------------------------
// 8. Cross-language consistency: same config produces same enforcement
// ---------------------------------------------------------------------------

#[test]
fn fallback_engine_matches_guard_enforcement() {
    let perms = PermissionSet {
        file_read: vec!["/workspace/**".to_string()],
        file_write: vec!["/workspace/output/**".to_string()],
        shell_execute: ShellPolicy::Deny,
        network: NetworkPolicy {
            allowed_hosts: vec!["api.anthropic.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        },
        tools: vec!["read_file".to_string()],
        ..Default::default()
    };

    // Build a guard with the same permissions.
    let mut guard = AgentGuard::builder("consistency-test")
        .permissions(perms.clone())
        .build();
    guard.activate().unwrap();

    // Build a standalone fallback engine.
    let engine = FallbackEngine::new(perms);

    // Test cases: guard and engine should agree.
    let cases = vec![
        ("read_file", "/workspace/data.txt"),
        ("read_file", "/etc/passwd"),
        ("write_file", "/workspace/output/result.txt"),
        ("write_file", "/etc/shadow"),
        ("bash", "ls -la"),
        ("fetch", "api.anthropic.com"),
        ("fetch", "evil.example.com"),
        ("read_file", "anything"),
    ];

    for (tool, target) in cases {
        let guard_result = guard.check_action(tool, target);
        let engine_result = engine.check_action(tool, target);

        let guard_allowed = matches!(guard_result, ActionResult::Allow);
        let engine_allowed = matches!(engine_result, ActionResult::Allow);

        assert_eq!(
            guard_allowed, engine_allowed,
            "Mismatch for ({tool}, {target}): guard={guard_result:?}, engine={engine_result:?}"
        );
    }

    guard.deactivate().unwrap();
}

// ---------------------------------------------------------------------------
// 9. Fallback mode enforcement matches for basic checks
// ---------------------------------------------------------------------------

#[test]
fn fallback_sensitive_paths_always_blocked() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let perms = PermissionSet {
        file_read: vec![format!("{home}/**")],
        ..Default::default()
    };
    let engine = FallbackEngine::new(perms);

    // Even though we allowed reading all of $HOME, sensitive paths are blocked.
    assert!(matches!(
        engine.check_action("read_file", &format!("{home}/.ssh/id_rsa")),
        ActionResult::Block(_)
    ));
    assert!(matches!(
        engine.check_action("read_file", &format!("{home}/.aws/credentials")),
        ActionResult::Block(_)
    ));
    assert!(matches!(
        engine.check_action("read_file", &format!("{home}/.gnupg/key")),
        ActionResult::Block(_)
    ));
    assert!(matches!(
        engine.check_action("read_file", &format!("{home}/.config/gcloud/token")),
        ActionResult::Block(_)
    ));
}

// ---------------------------------------------------------------------------
// 10. Guard stats accurate after mixed allow/block operations
// ---------------------------------------------------------------------------

#[test]
fn stats_accurate_after_mixed_operations() {
    let mut guard = AgentGuard::builder("stats-bot")
        .file_read(vec!["/workspace/**".to_string()])
        .file_write(vec!["/workspace/**".to_string()])
        .tools(vec!["custom_tool".to_string()])
        .build();

    guard.activate().unwrap();

    // 3 allowed.
    guard.check_action("read_file", "/workspace/a.txt");
    guard.check_action("write_file", "/workspace/b.txt");
    guard.check_action("custom_tool", "payload");

    // 4 blocked.
    guard.check_action("read_file", "/etc/passwd");
    guard.check_action("write_file", "/etc/shadow");
    guard.check_action("bash", "rm -rf /");
    guard.check_action("dangerous_tool", "exploit");

    let stats = guard.stats();
    assert_eq!(stats.operations_allowed, 3);
    assert_eq!(stats.operations_blocked, 4);
    assert_eq!(stats.blocked_details.len(), 4);

    // Verify blocked details content.
    let tools: Vec<&str> = stats.blocked_details.iter().map(|b| b.tool.as_str()).collect();
    assert!(tools.contains(&"read_file"));
    assert!(tools.contains(&"write_file"));
    assert!(tools.contains(&"bash"));
    assert!(tools.contains(&"dangerous_tool"));

    guard.deactivate().unwrap();
}

// ---------------------------------------------------------------------------
// 11. Blocked operation details are captured correctly
// ---------------------------------------------------------------------------

#[test]
fn blocked_details_have_correct_fields() {
    let mut guard = AgentGuard::builder("detail-bot")
        .file_read(vec!["/safe/**".to_string()])
        .build();
    guard.activate().unwrap();

    guard.check_action("read_file", "/forbidden/secret.key");

    let stats = guard.stats();
    assert_eq!(stats.blocked_details.len(), 1);
    let detail = &stats.blocked_details[0];
    assert_eq!(detail.tool, "read_file");
    assert_eq!(detail.target, "/forbidden/secret.key");
    assert!(!detail.reason.is_empty());
    // Timestamp should be recent (within last minute).
    let age = chrono::Utc::now() - detail.timestamp;
    assert!(age.num_seconds() < 60);

    guard.deactivate().unwrap();
}

// ---------------------------------------------------------------------------
// 12. Self-test passes for various permission sets
// ---------------------------------------------------------------------------

#[test]
fn selftest_passes_default() {
    let engine = FallbackEngine::new(PermissionSet::default());
    assert_eq!(run_self_test(&engine), GuardStatus::Active);
}

#[test]
fn selftest_passes_with_broad_read() {
    let engine = FallbackEngine::new(PermissionSet {
        file_read: vec!["/workspace/**".to_string()],
        ..Default::default()
    });
    assert_eq!(run_self_test(&engine), GuardStatus::Active);
}

// ---------------------------------------------------------------------------
// 13. Guard with file delete permissions
// ---------------------------------------------------------------------------

#[test]
fn file_delete_permissions() {
    let mut guard = AgentGuard::builder("delete-bot")
        .file_delete(vec!["/tmp/scratch/**".to_string()])
        .build();
    guard.activate().unwrap();

    assert_eq!(
        guard.check_action("delete_file", "/tmp/scratch/temp.txt"),
        ActionResult::Allow
    );
    assert!(matches!(
        guard.check_action("delete_file", "/important/data.db"),
        ActionResult::Block(_)
    ));

    guard.deactivate().unwrap();
}

// ---------------------------------------------------------------------------
// 14. Shell allowlist enforcement
// ---------------------------------------------------------------------------

#[test]
fn shell_allowlist_specific_command() {
    let engine = FallbackEngine::new(PermissionSet {
        shell_execute: ShellPolicy::AllowList(vec!["*".to_string()]),
        ..Default::default()
    });
    assert_eq!(engine.check_action("bash", "git status"), ActionResult::Allow);
}

#[test]
fn shell_allowlist_blocks_unlisted() {
    let engine = FallbackEngine::new(PermissionSet {
        shell_execute: ShellPolicy::AllowList(vec!["git".to_string()]),
        ..Default::default()
    });
    let result = engine.check_action("bash", "rm -rf /");
    assert!(matches!(result, ActionResult::Block(_)));
}

// ---------------------------------------------------------------------------
// 15. Shell with approval mode in fallback
// ---------------------------------------------------------------------------

#[test]
fn shell_approval_mode_blocks_in_fallback() {
    let engine = FallbackEngine::new(PermissionSet {
        shell_execute: ShellPolicy::AllowWithApproval,
        ..Default::default()
    });
    let result = engine.check_action("bash", "anything");
    assert!(matches!(result, ActionResult::Block(_)));
}

// ---------------------------------------------------------------------------
// 16. Network with empty hosts blocks all
// ---------------------------------------------------------------------------

#[test]
fn empty_network_hosts_blocks_all() {
    let engine = FallbackEngine::new(PermissionSet {
        network: NetworkPolicy {
            allowed_hosts: vec![],
            allowed_ports: vec![],
            deny_all: false,
        },
        ..Default::default()
    });
    let result = engine.check_action("fetch", "any-host.com");
    assert!(matches!(result, ActionResult::Block(_)));
}

// ---------------------------------------------------------------------------
// 17. Registry register/check/deregister flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registry_full_flow() {
    let registry = GuardRegistry::new();

    let perms = clawdefender_guard::registry::PermissionSet {
        file_read: vec!["~/workspace/**".to_string()],
        file_write: vec![],
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec!["api.anthropic.com".to_string()],
        tools: vec!["read_file".to_string()],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };

    // Register.
    let (guard_id, rule_count) = registry
        .register(
            "registry-test-agent".to_string(),
            std::process::id(),
            perms,
            clawdefender_guard::registry::GuardMode::Enforce,
        )
        .await;
    assert!(!guard_id.is_empty());
    assert!(rule_count > 0);

    // Check allowed action.
    let home = std::env::var("HOME").unwrap_or_default();
    let check = registry
        .check_action(&guard_id, "file_read", &format!("{home}/workspace/file.txt"))
        .await
        .unwrap();
    assert!(check.allowed);

    // Check blocked action.
    let check = registry
        .check_action(&guard_id, "file_read", "~/.ssh/id_rsa")
        .await
        .unwrap();
    assert!(!check.allowed);

    // Verify stats.
    let stats = registry.get_stats(&guard_id).await.unwrap();
    assert_eq!(stats["checks_total"], 2);

    // Deregister.
    assert!(registry.deregister(&guard_id).await);
    assert!(registry.get(&guard_id).await.is_none());
}

// ---------------------------------------------------------------------------
// 18. Registry multiple guards
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registry_multiple_guards() {
    let registry = GuardRegistry::new();

    let perms = clawdefender_guard::registry::PermissionSet {
        file_read: vec![],
        file_write: vec![],
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec![],
        tools: vec![],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };

    let (id1, _) = registry
        .register(
            "agent-1".to_string(),
            1,
            perms.clone(),
            clawdefender_guard::registry::GuardMode::Enforce,
        )
        .await;
    let (id2, _) = registry
        .register(
            "agent-2".to_string(),
            2,
            perms,
            clawdefender_guard::registry::GuardMode::Monitor,
        )
        .await;

    let list = registry.list().await;
    assert_eq!(list.len(), 2);

    // IDs are unique.
    assert_ne!(id1, id2);

    // Each guard has its own identity.
    let info1 = registry.get(&id1).await.unwrap();
    let info2 = registry.get(&id2).await.unwrap();
    assert_eq!(info1["agent_name"], "agent-1");
    assert_eq!(info2["agent_name"], "agent-2");

    registry.deregister(&id1).await;
    registry.deregister(&id2).await;
}

// ---------------------------------------------------------------------------
// 19. Monitor mode suggest_permissions deduplication
// ---------------------------------------------------------------------------

#[test]
fn monitor_suggest_deduplicates() {
    let mut guard = AgentGuard::builder("dedup-bot")
        .mode(GuardMode::Monitor)
        .build();
    guard.activate().unwrap();

    // Same operation repeated many times.
    for _ in 0..10 {
        guard.check_action("read_file", "/etc/passwd");
    }

    let suggested = guard.suggest_permissions();
    assert_eq!(suggested.file_read.len(), 1);
    assert_eq!(suggested.file_read[0], "/etc/passwd");

    guard.deactivate().unwrap();
}

// ---------------------------------------------------------------------------
// 20. Guard with all tool types covered
// ---------------------------------------------------------------------------

#[test]
fn all_tool_types_enforce_correctly() {
    let mut guard = AgentGuard::builder("all-tools-bot")
        .file_read(vec!["/workspace/**".to_string()])
        .file_write(vec!["/workspace/**".to_string()])
        .file_delete(vec!["/workspace/tmp/**".to_string()])
        .shell_policy(ShellPolicy::Deny)
        .network_policy(NetworkPolicy {
            allowed_hosts: vec!["api.anthropic.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        })
        .tools(vec!["search".to_string()])
        .build();
    guard.activate().unwrap();

    // File read: allowed and blocked.
    assert_eq!(
        guard.check_action("read_file", "/workspace/code.rs"),
        ActionResult::Allow
    );
    assert!(matches!(
        guard.check_action("Read", "/outside/file.txt"),
        ActionResult::Block(_)
    ));

    // File write: allowed and blocked.
    assert_eq!(
        guard.check_action("write_file", "/workspace/output.txt"),
        ActionResult::Allow
    );
    assert!(matches!(
        guard.check_action("Edit", "/outside/file.txt"),
        ActionResult::Block(_)
    ));

    // File delete: allowed and blocked.
    assert_eq!(
        guard.check_action("delete_file", "/workspace/tmp/scratch.txt"),
        ActionResult::Allow
    );
    assert!(matches!(
        guard.check_action("remove", "/important/data.db"),
        ActionResult::Block(_)
    ));

    // Shell: all blocked.
    assert!(matches!(guard.check_action("bash", "ls"), ActionResult::Block(_)));
    assert!(matches!(guard.check_action("sh", "ls"), ActionResult::Block(_)));
    assert!(matches!(
        guard.check_action("run_command", "ls"),
        ActionResult::Block(_)
    ));

    // Network: allowed host and blocked host.
    assert_eq!(
        guard.check_action("fetch", "api.anthropic.com"),
        ActionResult::Allow
    );
    assert!(matches!(
        guard.check_action("curl", "evil.example.com"),
        ActionResult::Block(_)
    ));

    // Custom tool: allowed and blocked.
    assert_eq!(
        guard.check_action("search", "query"),
        ActionResult::Allow
    );
    assert!(matches!(
        guard.check_action("undeclared", "target"),
        ActionResult::Block(_)
    ));

    guard.deactivate().unwrap();
}

// ---------------------------------------------------------------------------
// 21. TOML generation for all shell policy variants
// ---------------------------------------------------------------------------

#[test]
fn toml_gen_all_shell_variants() {
    // Deny
    let perms = PermissionSet {
        shell_execute: ShellPolicy::Deny,
        ..Default::default()
    };
    let toml = generate_policy_toml("test", &perms);
    validate_policy_toml(&toml).unwrap();
    assert!(toml.contains("guard_block_all_shell"));

    // AllowList
    let perms = PermissionSet {
        shell_execute: ShellPolicy::AllowList(vec!["git *".to_string(), "npm *".to_string()]),
        ..Default::default()
    };
    let toml = generate_policy_toml("test", &perms);
    validate_policy_toml(&toml).unwrap();
    assert!(toml.contains("guard_allow_shell"));

    // AllowWithApproval
    let perms = PermissionSet {
        shell_execute: ShellPolicy::AllowWithApproval,
        ..Default::default()
    };
    let toml = generate_policy_toml("test", &perms);
    validate_policy_toml(&toml).unwrap();
    assert!(toml.contains("guard_prompt_shell"));
}

// ---------------------------------------------------------------------------
// 22. Double-deactivate is safe
// ---------------------------------------------------------------------------

#[test]
fn double_deactivate_safe() {
    let mut guard = AgentGuard::builder("double-deactivate")
        .file_read(vec!["/tmp/**".to_string()])
        .build();

    guard.activate().unwrap();
    guard.deactivate().unwrap();
    guard.deactivate().unwrap(); // Should not panic or error.
    assert_eq!(guard.status(), &GuardStatus::Inactive);
}

// ---------------------------------------------------------------------------
// 23. Guard drop triggers deactivation
// ---------------------------------------------------------------------------

#[test]
fn drop_deactivates_guard() {
    let mut guard = AgentGuard::builder("drop-test")
        .file_read(vec!["/workspace/**".to_string()])
        .build();
    guard.activate().unwrap();
    assert!(guard.is_healthy());
    // Drop should deactivate without panicking.
    drop(guard);
}
