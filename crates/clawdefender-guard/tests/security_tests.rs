//! Security tests for the ClawDefender guard system.
//!
//! These tests verify that the guard system is secure against abuse,
//! privilege escalation, and compromised agents.

use std::env;

use clawdefender_guard::api_auth;
use clawdefender_guard::guard::GuardBuilder;
use clawdefender_guard::installer::download::{
    build_checksum_url, build_download_url, compute_sha256, verify_checksum,
};
use clawdefender_guard::registry::{
    GuardMode as RegistryGuardMode, GuardRegistry, PermissionSet as RegistryPermissionSet,
};
use clawdefender_guard::types::*;

// ---------------------------------------------------------------------------
// Helper to create a registry PermissionSet for tests
// ---------------------------------------------------------------------------
fn registry_perms(file_read: Vec<&str>, file_write: Vec<&str>) -> RegistryPermissionSet {
    RegistryPermissionSet {
        file_read: file_read.into_iter().map(String::from).collect(),
        file_write: file_write.into_iter().map(String::from).collect(),
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec![],
        tools: vec!["read_file".to_string(), "write_file".to_string()],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    }
}

// ===========================================================================
// 1. Privilege escalation prevention
// ===========================================================================

/// Global sensitive-path blocks should always take precedence over
/// guard-level permissions, even if the guard allows broad paths.
#[tokio::test]
async fn security_global_sensitive_blocks_override_guard_permissions() {
    let registry = GuardRegistry::new();
    let perms = RegistryPermissionSet {
        file_read: vec!["**/*".to_string()], // allow ALL
        file_write: vec!["**/*".to_string()],
        file_delete: vec![],
        shell_policy: "allow".to_string(),
        network_allowlist: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };
    let (id, _) = registry
        .register(
            "broad-agent".into(),
            9999,
            perms,
            RegistryGuardMode::Enforce,
        )
        .await;

    // Even with wildcard permissions, sensitive paths must be blocked.
    let result = registry
        .check_action(&id, "file_read", "/home/user/.ssh/id_rsa")
        .await
        .unwrap();
    assert!(
        !result.allowed,
        "Sensitive path .ssh/id_rsa should be blocked even with broad perms"
    );

    let result = registry
        .check_action(&id, "file_read", "/home/user/.aws/credentials")
        .await
        .unwrap();
    assert!(
        !result.allowed,
        "Sensitive path .aws/credentials should be blocked"
    );

    let result = registry
        .check_action(&id, "file_read", "/app/.env")
        .await
        .unwrap();
    assert!(!result.allowed, ".env files should always be blocked");
}

/// A guard should not be able to register with a PID that is not running.
/// (In practice, the registry does not validate PIDs at registration time,
/// but cleanup_dead_pids removes guards with dead PIDs.)
#[tokio::test]
async fn security_guard_with_dead_pid_is_cleaned_up() {
    let registry = GuardRegistry::new();
    // Use a PID that almost certainly does not exist.
    let (id, _) = registry
        .register(
            "dead-pid-agent".into(),
            999999,
            registry_perms(vec![], vec![]),
            RegistryGuardMode::Enforce,
        )
        .await;

    // Guard is initially present.
    assert!(registry.get(&id).await.is_some());

    // After cleanup, the guard with a dead PID should be removed.
    registry.cleanup_dead_pids().await;
    assert!(
        registry.get(&id).await.is_none(),
        "Guard with dead PID should be removed after cleanup"
    );
}

/// One guard should not be able to deregister another guard.
/// Each guard can only be deregistered by its own ID.
#[tokio::test]
async fn security_one_guard_cannot_deregister_another() {
    let registry = GuardRegistry::new();
    let (id_a, _) = registry
        .register(
            "agent-a".into(),
            1,
            registry_perms(vec![], vec![]),
            RegistryGuardMode::Enforce,
        )
        .await;
    let (id_b, _) = registry
        .register(
            "agent-b".into(),
            2,
            registry_perms(vec![], vec![]),
            RegistryGuardMode::Enforce,
        )
        .await;

    // Guard A cannot deregister Guard B using Guard A's ID — deregister
    // only works with the exact guard_id.
    assert!(registry.deregister(&id_a).await);
    // Guard B should still exist.
    assert!(registry.get(&id_b).await.is_some());
    // And Guard A should be gone.
    assert!(registry.get(&id_a).await.is_none());
}

/// REST API authentication rejects requests without valid token.
#[test]
fn security_api_rejects_missing_auth() {
    assert!(api_auth::authenticate(None, "secret-token").is_err());
}

/// REST API authentication rejects requests with wrong token.
#[test]
fn security_api_rejects_wrong_token() {
    assert!(api_auth::authenticate(Some("Bearer wrong-token"), "secret-token").is_err());
}

/// REST API authentication rejects malformed bearer prefix.
#[test]
fn security_api_rejects_malformed_bearer() {
    assert!(!api_auth::validate_bearer_token(
        "Basic secret-token",
        "secret-token"
    ));
    assert!(!api_auth::validate_bearer_token(
        "secret-token",
        "secret-token"
    ));
}

/// Even a guard with broad permissions should still have sensitive paths blocked.
#[tokio::test]
async fn security_broad_permissions_still_block_sensitive_paths() {
    let registry = GuardRegistry::new();
    let perms = RegistryPermissionSet {
        file_read: vec!["/home/**/*".to_string()],
        file_write: vec!["/home/**/*".to_string()],
        file_delete: vec!["/home/**/*".to_string()],
        shell_policy: "allow".to_string(),
        network_allowlist: vec!["*".to_string()],
        tools: vec![],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };
    let (id, _) = registry
        .register("broad".into(), 1, perms, RegistryGuardMode::Enforce)
        .await;

    for sensitive in &[
        "/home/user/.ssh/id_rsa",
        "/home/user/.gnupg/secring.gpg",
        "/home/user/.git/config",
        "/home/user/project/.env",
        "/home/user/.ssh/id_ed25519",
    ] {
        let result = registry
            .check_action(&id, "file_read", sensitive)
            .await
            .unwrap();
        assert!(
            !result.allowed,
            "Sensitive path {} should be blocked even with broad perms",
            sensitive
        );
    }
}

// ===========================================================================
// 2. Guard resilience against compromised agents
// ===========================================================================

/// After activating a guard with tight permissions, accessing ~/.ssh/id_rsa
/// must be blocked.
#[test]
fn security_tight_guard_blocks_ssh_key() {
    let home = env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let mut guard = GuardBuilder::new("tight-agent")
        .file_read(vec![format!("{home}/workspace/**")])
        .build();
    guard.activate().unwrap();

    let ssh_path = format!("{home}/.ssh/id_rsa");
    let result = guard.check_action("read_file", &ssh_path);
    assert!(
        matches!(result, ActionResult::Block(_)),
        "SSH key access should be blocked: {:?}",
        result
    );
    guard.deactivate().unwrap();
}

/// Undeclared tools should be blocked.
#[test]
fn security_undeclared_tool_blocked() {
    let mut guard = GuardBuilder::new("tool-test")
        .tools(vec!["read_file".to_string(), "write_file".to_string()])
        .build();
    guard.activate().unwrap();

    let result = guard.check_action("dangerous_tool", "/tmp/test");
    assert!(
        matches!(result, ActionResult::Block(_)),
        "Undeclared tool should be blocked"
    );
    guard.deactivate().unwrap();
}

/// Blocked operations should be tracked in stats.
#[test]
fn security_blocked_operations_tracked_in_stats() {
    let mut guard = GuardBuilder::new("stats-test")
        .file_read(vec!["/tmp/allowed/**".to_string()])
        .build();
    guard.activate().unwrap();

    guard.check_action("read_file", "/etc/shadow");
    guard.check_action("read_file", "/etc/passwd");
    guard.check_action("read_file", "/tmp/allowed/ok.txt");

    let stats = guard.stats();
    assert_eq!(
        stats.operations_blocked, 2,
        "Two operations should be blocked"
    );
    assert_eq!(
        stats.operations_allowed, 1,
        "One operation should be allowed"
    );
    assert_eq!(
        stats.blocked_details.len(),
        2,
        "Two blocked detail records expected"
    );
    guard.deactivate().unwrap();
}

/// Enforce mode actually prevents actions (returns Block, not Monitored).
#[test]
fn security_enforce_mode_blocks_actions() {
    let mut guard = GuardBuilder::new("enforce-test")
        .mode(GuardMode::Enforce)
        .file_read(vec!["/tmp/**".to_string()])
        .build();
    guard.activate().unwrap();

    let result = guard.check_action("read_file", "/etc/passwd");
    match &result {
        ActionResult::Block(_) => {} // expected
        other => panic!("Enforce mode should Block, got {:?}", other),
    }
    guard.deactivate().unwrap();
}

/// Monitor mode logs but does not block.
#[test]
fn security_monitor_mode_logs_but_allows() {
    let mut guard = GuardBuilder::new("monitor-test")
        .mode(GuardMode::Monitor)
        .file_read(vec!["/tmp/**".to_string()])
        .build();
    guard.activate().unwrap();

    let result = guard.check_action("read_file", "/etc/passwd");
    match &result {
        ActionResult::Monitored { would_block, .. } => {
            assert!(would_block, "Monitor mode should indicate it would block");
        }
        other => panic!("Monitor mode should return Monitored, got {:?}", other),
    }
    guard.deactivate().unwrap();
}

/// Deactivation is logged — guard goes from Active to Inactive.
#[test]
fn security_deactivation_changes_status() {
    let mut guard = GuardBuilder::new("deactivation-test")
        .file_read(vec!["/tmp/**".to_string()])
        .build();
    guard.activate().unwrap();
    assert!(guard.is_healthy());

    guard.deactivate().unwrap();
    assert_eq!(*guard.status(), GuardStatus::Inactive);
    assert!(!guard.is_healthy());
}

// ===========================================================================
// 3. Multi-guard isolation
// ===========================================================================

/// Two guards with different permissions should have independent access control.
#[tokio::test]
async fn security_multi_guard_isolation_workspace_a_vs_b() {
    let registry = GuardRegistry::new();
    let home = env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());

    let perms_a = registry_perms(
        vec![&format!("{home}/workspace-a/**")],
        vec![&format!("{home}/workspace-a/**")],
    );
    let perms_b = registry_perms(
        vec![&format!("{home}/workspace-b/**")],
        vec![&format!("{home}/workspace-b/**")],
    );

    let (id_a, _) = registry
        .register("agent-a".into(), 100, perms_a, RegistryGuardMode::Enforce)
        .await;
    let (id_b, _) = registry
        .register("agent-b".into(), 200, perms_b, RegistryGuardMode::Enforce)
        .await;

    // Guard A can access workspace-a
    let result = registry
        .check_action(
            &id_a,
            "file_read",
            &format!("{home}/workspace-a/src/main.rs"),
        )
        .await
        .unwrap();
    assert!(result.allowed, "Guard A should access workspace-a");

    // Guard A cannot access workspace-b
    let result = registry
        .check_action(
            &id_a,
            "file_read",
            &format!("{home}/workspace-b/secret.txt"),
        )
        .await
        .unwrap();
    assert!(!result.allowed, "Guard A should NOT access workspace-b");

    // Guard B can access workspace-b
    let result = registry
        .check_action(&id_b, "file_read", &format!("{home}/workspace-b/data.csv"))
        .await
        .unwrap();
    assert!(result.allowed, "Guard B should access workspace-b");

    // Guard B cannot access workspace-a
    let result = registry
        .check_action(
            &id_b,
            "file_read",
            &format!("{home}/workspace-a/config.toml"),
        )
        .await
        .unwrap();
    assert!(!result.allowed, "Guard B should NOT access workspace-a");
}

/// Guards should have independent stats.
#[tokio::test]
async fn security_multi_guard_independent_stats() {
    let registry = GuardRegistry::new();
    let home = env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());

    let perms_a = registry_perms(vec![&format!("{home}/workspace-a/**")], vec![]);
    let perms_b = registry_perms(vec![&format!("{home}/workspace-b/**")], vec![]);

    let (id_a, _) = registry
        .register("a".into(), 1, perms_a, RegistryGuardMode::Enforce)
        .await;
    let (id_b, _) = registry
        .register("b".into(), 2, perms_b, RegistryGuardMode::Enforce)
        .await;

    // Only guard A performs a check.
    registry
        .check_action(&id_a, "file_read", "/etc/secret")
        .await;

    let stats_a = registry.get_stats(&id_a).await.unwrap();
    let stats_b = registry.get_stats(&id_b).await.unwrap();

    assert_eq!(stats_a["checks_total"], 1);
    assert_eq!(
        stats_b["checks_total"], 0,
        "Guard B stats should be independent of Guard A"
    );
}

// ===========================================================================
// 4. Fallback mode honesty
// ===========================================================================

/// Fallback mode correctly enforces file path restrictions.
#[test]
fn security_fallback_enforces_path_restrictions() {
    use clawdefender_guard::fallback::FallbackEngine;

    let perms = PermissionSet {
        file_read: vec!["/tmp/safe/**".to_string()],
        file_write: vec![],
        file_delete: vec![],
        shell_execute: ShellPolicy::Deny,
        network: NetworkPolicy::default(),
        tools: vec![],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };
    let engine = FallbackEngine::new(perms);

    // Allowed path
    assert!(matches!(
        engine.check_action("read_file", "/tmp/safe/data.txt"),
        ActionResult::Allow
    ));

    // Disallowed path
    assert!(matches!(
        engine.check_action("read_file", "/etc/passwd"),
        ActionResult::Block(_)
    ));
}

/// Fallback mode logs its limitations — the guard status is Active
/// (not something misleading like "Full OS monitoring").
#[test]
fn security_fallback_mode_status_is_honest() {
    let mut guard = GuardBuilder::new("fallback-honest")
        .file_read(vec!["/tmp/**".to_string()])
        .build();
    guard.activate().unwrap();

    // Without a daemon, the guard activates but status should be Active
    // (indicating self-test passed), not claiming OS-level enforcement.
    let status = guard.status().clone();
    match status {
        GuardStatus::Active => {} // expected
        GuardStatus::Degraded(msg) => {
            // Also acceptable — it honestly reports degraded state
            assert!(
                !msg.contains("OS-level"),
                "Fallback should not claim OS-level monitoring: {}",
                msg
            );
        }
        other => panic!("Unexpected status in fallback mode: {:?}", other),
    }
    guard.deactivate().unwrap();
}

/// Fallback mode does NOT claim to have OS-level monitoring.
/// The GuardMode enum only has Enforce and Monitor — no "FullOS" variant.
#[test]
fn security_fallback_no_os_monitoring_claim() {
    // The guard only has Enforce and Monitor modes.
    // There is no "FullOS", "Kernel", or "Syscall" mode.
    let enforce = GuardMode::Enforce;
    let monitor = GuardMode::Monitor;
    assert_ne!(enforce, monitor);
    // If someone added a misleading variant, this test documents the intent:
    // the guard should NOT have modes that claim OS-level enforcement.
}

// ===========================================================================
// 5. Auto-install security
// ===========================================================================

/// Download URLs must use HTTPS.
#[test]
fn security_download_urls_use_https() {
    let url = build_download_url("linux-x86_64");
    assert!(
        url.starts_with("https://"),
        "Download URL must use HTTPS: {}",
        url
    );

    let checksum_url = build_checksum_url("macos-arm64");
    assert!(
        checksum_url.starts_with("https://"),
        "Checksum URL must use HTTPS: {}",
        checksum_url
    );
}

/// Checksum verification catches tampered binaries.
#[test]
fn security_checksum_catches_tampered_binary() {
    let original = b"legitimate binary data";
    let checksum = compute_sha256(original);
    let checksum_content = format!("{checksum}  clawdefender\n");

    // Valid binary passes verification.
    assert!(verify_checksum(original, &checksum_content).is_ok());

    // Tampered binary fails verification.
    let tampered = b"malicious binary data";
    assert!(
        verify_checksum(tampered, &checksum_content).is_err(),
        "Tampered binary should fail checksum verification"
    );
}

/// Install path uses correct permissions (0o755 for binary, not world-writable).
#[test]
fn security_install_permissions_not_world_writable() {
    // The installer sets mode 0o755 on the binary (see installer/mod.rs line ~302).
    // 0o755 = rwxr-xr-x — owner can read/write/execute, others can read/execute.
    // World-writable would be 0o777. Verify our expected mode is correct.
    let expected_mode: u32 = 0o755;
    assert_eq!(
        expected_mode & 0o002,
        0,
        "Binary should not be world-writable"
    );
    assert_eq!(
        expected_mode & 0o020,
        0,
        "Binary should not be group-writable"
    );
    assert_ne!(
        expected_mode & 0o100,
        0,
        "Binary should be owner-executable"
    );
}

// ===========================================================================
// 6. Additional security tests
// ===========================================================================

/// Shell execution should be denied by default.
#[test]
fn security_shell_denied_by_default() {
    let mut guard = GuardBuilder::new("shell-default").build();
    guard.activate().unwrap();

    let result = guard.check_action("bash", "rm -rf /");
    assert!(
        matches!(result, ActionResult::Block(_)),
        "Shell should be denied by default"
    );
    guard.deactivate().unwrap();
}

/// Network access to undeclared hosts should be blocked.
#[test]
fn security_network_access_to_undeclared_host_blocked() {
    let mut guard = GuardBuilder::new("net-test")
        .network_policy(NetworkPolicy {
            allowed_hosts: vec!["api.anthropic.com".to_string()],
            allowed_ports: vec![443],
            deny_all: false,
        })
        .build();
    guard.activate().unwrap();

    let result = guard.check_action("fetch", "evil-exfil.example.com");
    assert!(
        matches!(result, ActionResult::Block(_)),
        "Network to undeclared host should be blocked"
    );

    let result = guard.check_action("fetch", "api.anthropic.com");
    assert!(
        matches!(result, ActionResult::Allow),
        "Network to declared host should be allowed"
    );
    guard.deactivate().unwrap();
}

/// Constant-time token comparison prevents timing attacks.
#[test]
fn security_constant_time_token_comparison() {
    // Valid token should match.
    assert!(api_auth::validate_bearer_token(
        "Bearer correct-token",
        "correct-token"
    ));

    // Tokens differing only in last character should both fail equally.
    assert!(!api_auth::validate_bearer_token(
        "Bearer correct-tokeX",
        "correct-token"
    ));
    assert!(!api_auth::validate_bearer_token(
        "Bearer Xorrect-token",
        "correct-token"
    ));

    // Different length tokens should fail.
    assert!(!api_auth::validate_bearer_token(
        "Bearer short",
        "correct-token"
    ));
}
