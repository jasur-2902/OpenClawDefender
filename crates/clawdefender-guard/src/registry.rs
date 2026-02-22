//! Thread-safe in-memory registry of active guards.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

/// Permission set defining what an agent is allowed to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionSet {
    #[serde(default)]
    pub file_read: Vec<String>,
    #[serde(default)]
    pub file_write: Vec<String>,
    #[serde(default)]
    pub file_delete: Vec<String>,
    #[serde(default = "default_shell_policy")]
    pub shell_policy: String,
    #[serde(default)]
    pub network_allowlist: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    pub max_file_size: Option<u64>,
    pub max_files_per_minute: Option<u32>,
    pub max_network_requests_per_minute: Option<u32>,
}

fn default_shell_policy() -> String {
    "deny".to_string()
}

/// Guard operating mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GuardMode {
    Enforce,
    Monitor,
    Permissive,
}

/// Statistics for a guard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GuardStats {
    pub checks_total: u64,
    pub checks_allowed: u64,
    pub checks_blocked: u64,
    pub blocked_operations: Vec<BlockedOperation>,
}

/// Record of a blocked operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedOperation {
    pub action: String,
    pub target: String,
    pub reason: String,
    pub rule: String,
    pub timestamp: DateTime<Utc>,
}

/// Webhook registration for a guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRegistration {
    pub url: String,
    pub events: Vec<String>,
}

/// A registered guard instance.
pub struct RegisteredGuard {
    pub guard_id: String,
    pub agent_name: String,
    pub pid: u32,
    pub permissions: PermissionSet,
    pub mode: GuardMode,
    pub stats: Arc<Mutex<GuardStats>>,
    pub policy_rules: Vec<String>,
    pub webhooks: Vec<WebhookRegistration>,
    pub created_at: DateTime<Utc>,
}

/// Thread-safe registry of active guards.
#[derive(Clone)]
pub struct GuardRegistry {
    guards: Arc<RwLock<HashMap<String, RegisteredGuard>>>,
}

/// Result of checking an action against a guard.
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResult {
    pub allowed: bool,
    pub reason: String,
    pub rule: String,
}

/// Suggestion for permission adjustment.
#[derive(Debug, Serialize, Deserialize)]
pub struct PermissionSuggestion {
    pub action: String,
    pub suggested_pattern: String,
    pub reason: String,
}

impl Default for GuardRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardRegistry {
    pub fn new() -> Self {
        Self {
            guards: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new guard and return its ID and generated rule count.
    pub async fn register(
        &self,
        agent_name: String,
        pid: u32,
        permissions: PermissionSet,
        mode: GuardMode,
    ) -> (String, usize) {
        let guard_id = format!("guard_{}", Uuid::new_v4().simple());
        let policy_rules = generate_policy_rules(&permissions);
        let rule_count = policy_rules.len();

        let guard = RegisteredGuard {
            guard_id: guard_id.clone(),
            agent_name,
            pid,
            permissions,
            mode,
            stats: Arc::new(Mutex::new(GuardStats::default())),
            policy_rules,
            webhooks: Vec::new(),
            created_at: Utc::now(),
        };

        let mut guards = self.guards.write().await;
        guards.insert(guard_id.clone(), guard);

        (guard_id, rule_count)
    }

    /// Remove a guard from the registry.
    pub async fn deregister(&self, guard_id: &str) -> bool {
        let mut guards = self.guards.write().await;
        guards.remove(guard_id).is_some()
    }

    /// Get a guard's basic info as JSON value.
    pub async fn get(&self, guard_id: &str) -> Option<serde_json::Value> {
        let guards = self.guards.read().await;
        let guard = guards.get(guard_id)?;
        let stats = guard.stats.lock().await;
        Some(serde_json::json!({
            "guard_id": guard.guard_id,
            "agent_name": guard.agent_name,
            "pid": guard.pid,
            "mode": guard.mode,
            "status": "active",
            "created_at": guard.created_at.to_rfc3339(),
            "checks_total": stats.checks_total,
            "checks_allowed": stats.checks_allowed,
            "checks_blocked": stats.checks_blocked,
        }))
    }

    /// Get detailed stats for a guard.
    pub async fn get_stats(&self, guard_id: &str) -> Option<serde_json::Value> {
        let guards = self.guards.read().await;
        let guard = guards.get(guard_id)?;
        let stats = guard.stats.lock().await;
        Some(serde_json::json!({
            "guard_id": guard.guard_id,
            "checks_total": stats.checks_total,
            "checks_allowed": stats.checks_allowed,
            "checks_blocked": stats.checks_blocked,
            "blocked_operations": stats.blocked_operations,
            "policy_rules": guard.policy_rules,
        }))
    }

    /// List all active guards.
    pub async fn list(&self) -> Vec<serde_json::Value> {
        let guards = self.guards.read().await;
        let mut result = Vec::new();
        for guard in guards.values() {
            let stats = guard.stats.lock().await;
            result.push(serde_json::json!({
                "guard_id": guard.guard_id,
                "agent_name": guard.agent_name,
                "pid": guard.pid,
                "mode": guard.mode,
                "status": "active",
                "created_at": guard.created_at.to_rfc3339(),
                "checks_total": stats.checks_total,
            }));
        }
        result
    }

    /// Check if an action is allowed by a guard's permissions.
    pub async fn check_action(
        &self,
        guard_id: &str,
        action: &str,
        target: &str,
    ) -> Option<CheckResult> {
        let guards = self.guards.read().await;
        let guard = guards.get(guard_id)?;

        let result = evaluate_action(&guard.permissions, guard.mode, action, target);

        // Update stats
        let mut stats = guard.stats.lock().await;
        stats.checks_total += 1;
        if result.allowed {
            stats.checks_allowed += 1;
        } else {
            stats.checks_blocked += 1;
            stats.blocked_operations.push(BlockedOperation {
                action: action.to_string(),
                target: target.to_string(),
                reason: result.reason.clone(),
                rule: result.rule.clone(),
                timestamp: Utc::now(),
            });
        }

        Some(result)
    }

    /// Get permission suggestions for a guard in monitor mode.
    pub async fn suggest(&self, guard_id: &str) -> Option<Vec<PermissionSuggestion>> {
        let guards = self.guards.read().await;
        let guard = guards.get(guard_id)?;
        let stats = guard.stats.lock().await;

        let mut suggestions = Vec::new();
        for op in &stats.blocked_operations {
            suggestions.push(PermissionSuggestion {
                action: op.action.clone(),
                suggested_pattern: op.target.clone(),
                reason: format!(
                    "Operation '{}' on '{}' was blocked by rule '{}'",
                    op.action, op.target, op.rule
                ),
            });
        }
        Some(suggestions)
    }

    /// Register a webhook for a guard.
    pub async fn register_webhook(
        &self,
        guard_id: &str,
        registration: WebhookRegistration,
    ) -> bool {
        let mut guards = self.guards.write().await;
        if let Some(guard) = guards.get_mut(guard_id) {
            guard.webhooks.push(registration);
            true
        } else {
            false
        }
    }

    /// Get webhooks for a guard.
    pub async fn get_webhooks(&self, guard_id: &str) -> Option<Vec<WebhookRegistration>> {
        let guards = self.guards.read().await;
        guards.get(guard_id).map(|g| g.webhooks.clone())
    }

    /// Remove guards whose PIDs are no longer running.
    pub async fn cleanup_dead_pids(&self) {
        let mut guards = self.guards.write().await;
        let dead: Vec<String> = guards
            .iter()
            .filter(|(_, g)| !is_pid_alive(g.pid))
            .map(|(id, _)| id.clone())
            .collect();

        for id in dead {
            tracing::info!(guard_id = %id, "removing guard with dead PID");
            guards.remove(&id);
        }
    }
}

/// Check if a PID is still running.
fn is_pid_alive(pid: u32) -> bool {
    // On Unix, signal 0 checks process existence without sending a signal.
    #[cfg(unix)]
    {
        // Use std::process::Command to check if PID exists instead of libc.
        std::path::Path::new(&format!("/proc/{pid}")).exists()
            || std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Sensitive path patterns that should always be blocked.
const SENSITIVE_PATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws/credentials",
    ".env",
    "id_rsa",
    "id_ed25519",
    ".git/config",
];

/// Evaluate whether an action on a target is allowed.
fn evaluate_action(
    permissions: &PermissionSet,
    mode: GuardMode,
    action: &str,
    target: &str,
) -> CheckResult {
    // Always block sensitive paths
    for sensitive in SENSITIVE_PATHS {
        if target.contains(sensitive) {
            return CheckResult {
                allowed: false,
                reason: format!("Access to sensitive path '{}' is not allowed", target),
                rule: "guard_block_sensitive_paths".to_string(),
            };
        }
    }

    let allowed_patterns = match action {
        "file_read" => &permissions.file_read,
        "file_write" => &permissions.file_write,
        "file_delete" => &permissions.file_delete,
        "shell" => {
            return CheckResult {
                allowed: permissions.shell_policy != "deny",
                reason: if permissions.shell_policy == "deny" {
                    "Shell execution is denied by policy".to_string()
                } else {
                    "Shell execution allowed".to_string()
                },
                rule: "guard_shell_policy".to_string(),
            };
        }
        "network" => {
            let allowed = permissions
                .network_allowlist
                .iter()
                .any(|host| target.contains(host.as_str()));
            return CheckResult {
                allowed,
                reason: if allowed {
                    format!("Network access to '{}' is in the allowlist", target)
                } else {
                    format!("Network access to '{}' is not in the allowlist", target)
                },
                rule: "guard_network_allowlist".to_string(),
            };
        }
        "tool_use" => {
            let allowed = permissions.tools.iter().any(|t| t == target);
            return CheckResult {
                allowed,
                reason: if allowed {
                    format!("Tool '{}' is allowed", target)
                } else {
                    format!("Tool '{}' is not in the allowed tools list", target)
                },
                rule: "guard_tool_allowlist".to_string(),
            };
        }
        _ => {
            return CheckResult {
                allowed: mode != GuardMode::Enforce,
                reason: format!("Unknown action type '{}'", action),
                rule: "guard_unknown_action".to_string(),
            };
        }
    };

    if allowed_patterns.is_empty() {
        return CheckResult {
            allowed: false,
            reason: format!("No patterns configured for action '{}'", action),
            rule: format!("guard_{}_empty", action),
        };
    }

    let matched = allowed_patterns.iter().any(|pattern| {
        let pattern = pattern.replace("~", &std::env::var("HOME").unwrap_or_default());
        glob::Pattern::new(&pattern)
            .map(|p| p.matches(target))
            .unwrap_or(false)
    });

    CheckResult {
        allowed: matched,
        reason: if matched {
            format!(
                "Path '{}' matches allowed patterns for '{}'",
                target, action
            )
        } else {
            format!(
                "Path '{}' does not match any allowed pattern for '{}'",
                target, action
            )
        },
        rule: format!("guard_{}_pattern", action),
    }
}

/// Generate policy rule names from a permission set.
fn generate_policy_rules(permissions: &PermissionSet) -> Vec<String> {
    let mut rules = vec!["guard_block_sensitive_paths".to_string()];

    if !permissions.file_read.is_empty() {
        rules.push("guard_file_read_pattern".to_string());
    }
    if !permissions.file_write.is_empty() {
        rules.push("guard_file_write_pattern".to_string());
    }
    if !permissions.file_delete.is_empty() {
        rules.push("guard_file_delete_pattern".to_string());
    }
    rules.push("guard_shell_policy".to_string());
    if !permissions.network_allowlist.is_empty() {
        rules.push("guard_network_allowlist".to_string());
    }
    if !permissions.tools.is_empty() {
        rules.push("guard_tool_allowlist".to_string());
    }
    if permissions.max_file_size.is_some() {
        rules.push("guard_max_file_size".to_string());
    }
    if permissions.max_files_per_minute.is_some() {
        rules.push("guard_rate_limit_files".to_string());
    }
    if permissions.max_network_requests_per_minute.is_some() {
        rules.push("guard_rate_limit_network".to_string());
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn test_register_and_get() {
        let registry = GuardRegistry::new();
        let (id, rules) = registry
            .register(
                "test-agent".into(),
                1234,
                test_permissions(),
                GuardMode::Enforce,
            )
            .await;
        assert!(!id.is_empty());
        assert!(rules > 0);

        let info = registry.get(&id).await.unwrap();
        assert_eq!(info["agent_name"], "test-agent");
        assert_eq!(info["status"], "active");
    }

    #[tokio::test]
    async fn test_deregister() {
        let registry = GuardRegistry::new();
        let (id, _) = registry
            .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        assert!(registry.deregister(&id).await);
        assert!(registry.get(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_deregister_nonexistent() {
        let registry = GuardRegistry::new();
        assert!(!registry.deregister("nonexistent").await);
    }

    #[tokio::test]
    async fn test_list() {
        let registry = GuardRegistry::new();
        registry
            .register("a1".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        registry
            .register("a2".into(), 2, test_permissions(), GuardMode::Monitor)
            .await;
        let list = registry.list().await;
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn test_check_action_allowed() {
        let registry = GuardRegistry::new();
        let home = std::env::var("HOME").unwrap_or_default();
        let (id, _) = registry
            .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        let result = registry
            .check_action(
                &id,
                "file_read",
                &format!("{}/Projects/workspace/foo.txt", home),
            )
            .await
            .unwrap();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_check_action_blocked_sensitive() {
        let registry = GuardRegistry::new();
        let (id, _) = registry
            .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        let result = registry
            .check_action(&id, "file_read", "~/.ssh/id_rsa")
            .await
            .unwrap();
        assert!(!result.allowed);
        assert_eq!(result.rule, "guard_block_sensitive_paths");
    }

    #[tokio::test]
    async fn test_check_shell_denied() {
        let registry = GuardRegistry::new();
        let (id, _) = registry
            .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        let result = registry
            .check_action(&id, "shell", "rm -rf /")
            .await
            .unwrap();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_check_network_allowed() {
        let registry = GuardRegistry::new();
        let (id, _) = registry
            .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        let result = registry
            .check_action(&id, "network", "api.anthropic.com")
            .await
            .unwrap();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_check_network_blocked() {
        let registry = GuardRegistry::new();
        let (id, _) = registry
            .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        let result = registry
            .check_action(&id, "network", "evil.com")
            .await
            .unwrap();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_check_tool_allowed() {
        let registry = GuardRegistry::new();
        let (id, _) = registry
            .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        let result = registry
            .check_action(&id, "tool_use", "read_file")
            .await
            .unwrap();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_check_tool_blocked() {
        let registry = GuardRegistry::new();
        let (id, _) = registry
            .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        let result = registry
            .check_action(&id, "tool_use", "execute_shell")
            .await
            .unwrap();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_stats_updated_after_check() {
        let registry = GuardRegistry::new();
        let (id, _) = registry
            .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        registry
            .check_action(&id, "file_read", "~/.ssh/id_rsa")
            .await;
        let stats = registry.get_stats(&id).await.unwrap();
        assert_eq!(stats["checks_total"], 1);
        assert_eq!(stats["checks_blocked"], 1);
    }

    #[tokio::test]
    async fn test_webhook_registration() {
        let registry = GuardRegistry::new();
        let (id, _) = registry
            .register("test".into(), 1, test_permissions(), GuardMode::Enforce)
            .await;
        let reg = WebhookRegistration {
            url: "http://127.0.0.1:8080/callback".to_string(),
            events: vec!["blocked".to_string()],
        };
        assert!(registry.register_webhook(&id, reg).await);
        let hooks = registry.get_webhooks(&id).await.unwrap();
        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn test_generate_policy_rules() {
        let perms = test_permissions();
        let rules = generate_policy_rules(&perms);
        assert!(rules.contains(&"guard_block_sensitive_paths".to_string()));
        assert!(rules.contains(&"guard_shell_policy".to_string()));
        assert!(rules.contains(&"guard_network_allowlist".to_string()));
    }

    #[test]
    fn test_sensitive_path_detection() {
        let perms = test_permissions();
        let result = evaluate_action(&perms, GuardMode::Enforce, "file_read", "/home/.ssh/id_rsa");
        assert!(!result.allowed);

        let result = evaluate_action(
            &perms,
            GuardMode::Enforce,
            "file_read",
            "/home/.aws/credentials",
        );
        assert!(!result.allowed);

        let result = evaluate_action(&perms, GuardMode::Enforce, "file_read", "/path/.env");
        assert!(!result.allowed);
    }
}
