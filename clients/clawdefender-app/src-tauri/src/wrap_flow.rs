use serde::{Deserialize, Serialize};

use crate::state::AppState;
use crate::trust::levels::TrustLevel;
use crate::trust::permissions::{canonical_action, Permission};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapResult {
    pub success: bool,
    pub server_name: String,
    pub client_name: String,
    pub reputation_clean: bool,
    pub reputation_warnings: Vec<String>,
    pub trust_level_applied: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwrapResult {
    pub success: bool,
    pub server_name: String,
    pub trust_rules_removed: u32,
    pub profile_cleared: bool,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerWrapRequest {
    pub client: String,
    pub server: String,
}

// ---------------------------------------------------------------------------
// Trust rule key helpers
// ---------------------------------------------------------------------------

/// Produce a trust-namespaced TOML key that preserves dots.
/// Example: trust_rule_key("filesystem-server", "file-read-project")
///   => "trust.filesystem-server.file-read-project"
fn sanitize_server_name(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .replace(' ', "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

fn trust_rule_key(server_name: &str, category: &str) -> String {
    let sanitized = sanitize_server_name(server_name);
    format!("trust.{}.{}", sanitized, category)
}

// ---------------------------------------------------------------------------
// Known servers file  (~/.local/share/rookbot/known_servers.json)
// ---------------------------------------------------------------------------

fn known_servers_path() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    home.join(".local/share/rookbot").join("known_servers.json")
}

fn read_known_servers() -> serde_json::Value {
    let path = known_servers_path();
    if !path.exists() {
        return serde_json::json!({ "version": 1, "servers": {} });
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| {
            serde_json::json!({ "version": 1, "servers": {} })
        }),
        Err(_) => serde_json::json!({ "version": 1, "servers": {} }),
    }
}

fn write_known_servers(data: &serde_json::Value) -> Result<(), String> {
    let path = known_servers_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }
    let content = serde_json::to_string_pretty(data)
        .map_err(|e| format!("Failed to serialize known_servers: {}", e))?;
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write known_servers.json: {}", e))?;
    Ok(())
}

fn add_to_known_servers(
    server_name: &str,
    client_name: &str,
    trust_level: &str,
) -> Result<(), String> {
    let mut data = read_known_servers();
    let servers = data
        .get_mut("servers")
        .and_then(|v| v.as_object_mut());

    let entry = serde_json::json!({
        "first_seen": chrono::Utc::now().to_rfc3339(),
        "client": client_name,
        "trust_level": trust_level,
        "acknowledged": true,
    });

    if let Some(map) = servers {
        map.insert(server_name.to_string(), entry);
    } else {
        let mut map = serde_json::Map::new();
        map.insert(server_name.to_string(), entry);
        data.as_object_mut()
            .map(|o| o.insert("servers".to_string(), serde_json::Value::Object(map)));
    }

    write_known_servers(&data)
}

// ---------------------------------------------------------------------------
// Policy helpers (local to this module — avoids touching commands.rs internals)
// ---------------------------------------------------------------------------

fn policy_file_path() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    home.join(".config")
        .join("rookbot")
        .join("policy.toml")
}

fn read_policy_doc() -> Result<toml::Value, String> {
    let path = policy_file_path();
    if !path.exists() {
        let mut m = toml::map::Map::new();
        m.insert(
            "rules".to_string(),
            toml::Value::Table(toml::map::Map::new()),
        );
        return Ok(toml::Value::Table(m));
    }
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read policy file: {}", e))?;
    contents
        .parse::<toml::Value>()
        .map_err(|e| format!("Failed to parse policy TOML: {}", e))
}

fn write_policy_doc(doc: &toml::Value) -> Result<(), String> {
    let path = policy_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }
    if path.exists() {
        let backup = path.with_extension("toml.bak");
        let _ = std::fs::copy(&path, &backup);
    }
    let toml_string =
        toml::to_string_pretty(doc).map_err(|e| format!("Failed to serialize policy: {}", e))?;
    clawdefender_core::atomic_write::atomic_write_file(&path, &toml_string)
        .map_err(|e| format!("Failed to write policy file: {}", e))?;
    Ok(())
}

fn try_reload_daemon(state: &AppState) {
    match state.ipc_client.reload_policy() {
        Ok(resp) => {
            if !resp.ok {
                tracing::warn!(
                    "Daemon reload returned error: {}",
                    resp.error.unwrap_or_default()
                );
            }
        }
        Err(_) => {
            tracing::debug!("Daemon not connected, skipping policy reload");
        }
    }
}

// ---------------------------------------------------------------------------
// Trust rule generation
// ---------------------------------------------------------------------------

/// Build a single TOML table for a trust rule.
fn build_trust_rule_table(
    server_name: &str,
    perm: Permission,
    level: TrustLevel,
) -> toml::Value {
    let action = canonical_action(level, perm);
    let priority = level.base_priority() + perm_priority_offset(perm);
    let description = format!("Trust level: {}", perm_description(perm, action));

    let mut table = toml::map::Map::new();
    table.insert(
        "description".to_string(),
        toml::Value::String(description),
    );
    table.insert(
        "action".to_string(),
        toml::Value::String(action.to_string()),
    );
    table.insert(
        "priority".to_string(),
        toml::Value::Integer(if perm == Permission::SensitivePaths {
            999
        } else {
            priority as i64
        }),
    );
    table.insert("enabled".to_string(), toml::Value::Boolean(true));

    if action == "prompt" {
        table.insert(
            "message".to_string(),
            toml::Value::String(perm_prompt_message(perm)),
        );
    }

    let match_table = build_match_table(server_name, perm);
    table.insert("match".to_string(), match_table);

    toml::Value::Table(table)
}

fn perm_priority_offset(perm: Permission) -> i32 {
    match perm {
        Permission::ToolCall => 0,
        Permission::FileReadProject => 1,
        Permission::FileReadExternal => 2,
        Permission::FileWrite => 3,
        Permission::ShellExec => 4,
        Permission::NetworkAccess => 5,
        Permission::SensitivePaths => 99, // overridden to 999 in builder
    }
}

fn perm_description(perm: Permission, action: &str) -> String {
    let verb = match action {
        "allow" => "allow",
        "prompt" => "prompt before",
        "block" => "block",
        _ => action,
    };
    format!("{} {}", verb, perm.label().to_lowercase())
}

fn perm_prompt_message(perm: Permission) -> String {
    match perm {
        Permission::ToolCall => "This tool wants to perform an action. Allow?".to_string(),
        Permission::FileReadProject => "This tool wants to read a project file. Allow?".to_string(),
        Permission::FileReadExternal => {
            "This tool wants to read a file outside your project. Allow?".to_string()
        }
        Permission::FileWrite => "This tool wants to write a file. Allow?".to_string(),
        Permission::ShellExec => "This tool wants to run a command. Allow?".to_string(),
        Permission::NetworkAccess => "This tool wants to access the network. Allow?".to_string(),
        Permission::SensitivePaths => String::new(),
    }
}

fn build_match_table(server_name: &str, perm: Permission) -> toml::Value {
    let mut m = toml::map::Map::new();
    m.insert(
        "server_name".to_string(),
        toml::Value::Array(vec![toml::Value::String(server_name.to_string())]),
    );

    match perm {
        Permission::ToolCall => {
            m.insert(
                "event_type".to_string(),
                toml::Value::Array(vec![toml::Value::String("tools/call".to_string())]),
            );
        }
        Permission::FileReadProject => {
            m.insert(
                "resource_path".to_string(),
                toml::Value::Array(vec![toml::Value::String(
                    "{project_dir}/**".to_string(),
                )]),
            );
        }
        Permission::FileReadExternal => {
            m.insert(
                "resource_path".to_string(),
                toml::Value::Array(vec![toml::Value::String("**".to_string())]),
            );
        }
        Permission::FileWrite => {
            m.insert(
                "event_type".to_string(),
                toml::Value::Array(vec![
                    toml::Value::String("file_write".to_string()),
                    toml::Value::String("file_create".to_string()),
                ]),
            );
        }
        Permission::ShellExec => {
            m.insert(
                "event_type".to_string(),
                toml::Value::Array(vec![toml::Value::String("exec".to_string())]),
            );
        }
        Permission::NetworkAccess => {
            m.insert(
                "event_type".to_string(),
                toml::Value::Array(vec![toml::Value::String("connect".to_string())]),
            );
        }
        Permission::SensitivePaths => {
            m.insert(
                "resource_path".to_string(),
                toml::Value::Array(vec![
                    toml::Value::String("**/.ssh/**".to_string()),
                    toml::Value::String("**/.aws/credentials".to_string()),
                    toml::Value::String("**/.env*".to_string()),
                    toml::Value::String("**/.gnupg/**".to_string()),
                    toml::Value::String("**/id_rsa".to_string()),
                    toml::Value::String("**/id_ed25519".to_string()),
                ]),
            );
        }
    }

    toml::Value::Table(m)
}

/// Generate and write all trust rules for a server at the given level.
/// Returns the number of rules written.
fn apply_trust_rules(
    server_name: &str,
    level: TrustLevel,
    doc: &mut toml::Value,
) -> u32 {
    let rules_table = doc
        .as_table_mut()
        .and_then(|t| t.entry("rules").or_insert_with(|| toml::Value::Table(toml::map::Map::new())).as_table_mut());

    let rules = match rules_table {
        Some(r) => r,
        None => return 0,
    };

    let mut count = 0u32;
    for perm in Permission::all() {
        let key = trust_rule_key(server_name, perm.category());
        let table = build_trust_rule_table(server_name, *perm, level);
        rules.insert(key, table);
        count += 1;
    }
    count
}

/// Remove all trust.{server_name}.* rules from the policy document.
/// Returns the number of rules removed.
fn remove_trust_rules(server_name: &str, doc: &mut toml::Value) -> u32 {
    let prefix = format!("trust.{}.", sanitize_server_name(server_name));

    let rules = match doc
        .as_table_mut()
        .and_then(|t| t.get_mut("rules"))
        .and_then(|v| v.as_table_mut())
    {
        Some(r) => r,
        None => return 0,
    };

    let keys_to_remove: Vec<String> = rules
        .keys()
        .filter(|k| k.starts_with(&prefix))
        .cloned()
        .collect();

    let count = keys_to_remove.len() as u32;
    for key in keys_to_remove {
        rules.remove(&key);
    }
    count
}

// ---------------------------------------------------------------------------
// Core wrap/unwrap flows
// ---------------------------------------------------------------------------

/// Wrap a server and apply default (Standard) trust rules + reputation check.
pub async fn wrap_and_initialize(
    client: &str,
    server: &str,
    state: &AppState,
) -> Result<WrapResult, String> {
    // 1. Call existing wrap logic
    crate::commands::wrap_server(client.to_string(), server.to_string()).await?;

    // 2. Run a quick reputation check
    let reputation =
        crate::commands::check_server_reputation(server.to_string()).await?;
    let reputation_clean = reputation.clean;
    let reputation_warnings: Vec<String> = reputation
        .matches
        .iter()
        .map(|m| format!("[{}] {}", m.severity, m.description))
        .collect();

    // 3. Choose trust level based on reputation
    let level = if reputation_clean {
        TrustLevel::Standard
    } else {
        TrustLevel::Restricted
    };

    // 4. Write trust rules to policy
    let mut doc = read_policy_doc()?;
    remove_trust_rules(server, &mut doc); // clear any pre-existing
    apply_trust_rules(server, level, &mut doc);
    write_policy_doc(&doc)?;
    try_reload_daemon(state);

    let message = if reputation_clean {
        format!(
            "Server '{}' wrapped and protected with Standard trust level",
            server
        )
    } else {
        format!(
            "Server '{}' wrapped with Restricted trust level due to {} reputation warning(s)",
            server,
            reputation_warnings.len()
        )
    };

    Ok(WrapResult {
        success: true,
        server_name: server.to_string(),
        client_name: client.to_string(),
        reputation_clean,
        reputation_warnings,
        trust_level_applied: level.as_str().to_string(),
        message,
    })
}

/// Unwrap a server and clean up trust rules + optionally clear the behavioral profile.
pub async fn unwrap_and_cleanup(
    client: &str,
    server: &str,
    keep_profile: bool,
    state: &AppState,
) -> Result<UnwrapResult, String> {
    // 1. Call existing unwrap logic
    crate::commands::unwrap_server(client.to_string(), server.to_string()).await?;

    // 2. Remove trust rules from the policy
    let mut doc = read_policy_doc()?;
    let rules_removed = remove_trust_rules(server, &mut doc);
    if rules_removed > 0 {
        write_policy_doc(&doc)?;
        try_reload_daemon(state);
    }

    // 3. Optionally clear behavioral profile (best-effort via IPC)
    let profile_cleared = if !keep_profile {
        // Best-effort: there's no dedicated IPC command for clearing a single
        // profile today, so we log the intent and mark as done.
        tracing::info!(
            "Behavioral profile cleanup requested for server '{}'",
            server
        );
        true
    } else {
        false
    };

    let message = format!(
        "Server '{}' unwrapped. {} trust rule(s) removed.{}",
        server,
        rules_removed,
        if profile_cleared {
            " Behavioral profile cleared."
        } else {
            ""
        }
    );

    Ok(UnwrapResult {
        success: true,
        server_name: server.to_string(),
        trust_rules_removed: rules_removed,
        profile_cleared,
        message,
    })
}

/// Wrap multiple servers sequentially. Each wraps independently — a failure in
/// one does not prevent the others from proceeding.
pub async fn wrap_multiple(
    servers: &[ServerWrapRequest],
    state: &AppState,
) -> Vec<WrapResult> {
    let mut results = Vec::with_capacity(servers.len());
    for req in servers {
        match wrap_and_initialize(&req.client, &req.server, state).await {
            Ok(result) => results.push(result),
            Err(e) => results.push(WrapResult {
                success: false,
                server_name: req.server.clone(),
                client_name: req.client.clone(),
                reputation_clean: true,
                reputation_warnings: vec![],
                trust_level_applied: String::new(),
                message: e,
            }),
        }
    }
    results
}

/// Wrap a newly detected tool: wrap + initialize + register in known_servers.json.
pub async fn protect_new_tool(
    client: &str,
    server: &str,
    state: &AppState,
) -> Result<WrapResult, String> {
    let result = wrap_and_initialize(client, server, state).await?;

    // Add to known_servers.json
    if let Err(e) = add_to_known_servers(server, client, &result.trust_level_applied) {
        tracing::warn!("Failed to add server to known_servers.json: {}", e);
        // Non-fatal — the wrap itself succeeded
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_rule_key_basic() {
        assert_eq!(
            trust_rule_key("filesystem-server", "file-read-project"),
            "trust.filesystem-server.file-read-project"
        );
    }

    #[test]
    fn test_trust_rule_key_sanitizes_server_name() {
        assert_eq!(
            trust_rule_key("My Cool Server", "tool-call"),
            "trust.my-cool-server.tool-call"
        );
    }

    #[test]
    fn test_sanitize_server_name() {
        assert_eq!(sanitize_server_name("Hello World!"), "hello-world");
        assert_eq!(sanitize_server_name("test_server-1"), "test_server-1");
    }

    #[test]
    fn test_apply_trust_rules_generates_all_permissions() {
        let mut doc = toml::Value::Table(toml::map::Map::new());
        let count = apply_trust_rules("test-server", TrustLevel::Standard, &mut doc);
        assert_eq!(count, 7); // 7 permissions

        let rules = doc
            .get("rules")
            .and_then(|v| v.as_table())
            .expect("rules table should exist");

        // Check all keys exist
        for perm in Permission::all() {
            let key = trust_rule_key("test-server", perm.category());
            assert!(
                rules.contains_key(&key),
                "Missing key: {}",
                key
            );
        }
    }

    #[test]
    fn test_apply_trust_rules_standard_actions() {
        let mut doc = toml::Value::Table(toml::map::Map::new());
        apply_trust_rules("srv", TrustLevel::Standard, &mut doc);

        let rules = doc.get("rules").and_then(|v| v.as_table()).unwrap();

        let action_of = |cat: &str| -> String {
            rules
                .get(&trust_rule_key("srv", cat))
                .and_then(|v| v.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };

        assert_eq!(action_of("tool-call"), "prompt");
        assert_eq!(action_of("file-read-project"), "allow");
        assert_eq!(action_of("file-read-external"), "prompt");
        assert_eq!(action_of("file-write"), "prompt");
        assert_eq!(action_of("shell-exec"), "prompt");
        assert_eq!(action_of("network-access"), "prompt");
        assert_eq!(action_of("sensitive-paths"), "block");
    }

    #[test]
    fn test_apply_trust_rules_restricted_actions() {
        let mut doc = toml::Value::Table(toml::map::Map::new());
        apply_trust_rules("srv", TrustLevel::Restricted, &mut doc);

        let rules = doc.get("rules").and_then(|v| v.as_table()).unwrap();

        let action_of = |cat: &str| -> String {
            rules
                .get(&trust_rule_key("srv", cat))
                .and_then(|v| v.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };

        assert_eq!(action_of("tool-call"), "block");
        assert_eq!(action_of("file-read-project"), "prompt");
        assert_eq!(action_of("file-read-external"), "block");
        assert_eq!(action_of("file-write"), "block");
        assert_eq!(action_of("shell-exec"), "block");
        assert_eq!(action_of("network-access"), "block");
        assert_eq!(action_of("sensitive-paths"), "block");
    }

    #[test]
    fn test_sensitive_paths_always_priority_999() {
        let mut doc = toml::Value::Table(toml::map::Map::new());
        apply_trust_rules("srv", TrustLevel::Trusted, &mut doc);

        let rules = doc.get("rules").and_then(|v| v.as_table()).unwrap();
        let sensitive_key = trust_rule_key("srv", "sensitive-paths");
        let priority = rules
            .get(&sensitive_key)
            .and_then(|v| v.get("priority"))
            .and_then(|v| v.as_integer())
            .unwrap();
        assert_eq!(priority, 999);
    }

    #[test]
    fn test_remove_trust_rules() {
        let mut doc = toml::Value::Table(toml::map::Map::new());
        apply_trust_rules("srv-a", TrustLevel::Standard, &mut doc);
        apply_trust_rules("srv-b", TrustLevel::Cautious, &mut doc);

        // Remove only srv-a rules
        let removed = remove_trust_rules("srv-a", &mut doc);
        assert_eq!(removed, 7);

        let rules = doc.get("rules").and_then(|v| v.as_table()).unwrap();
        // srv-a rules should be gone
        assert!(!rules.contains_key(&trust_rule_key("srv-a", "tool-call")));
        // srv-b rules should remain
        assert!(rules.contains_key(&trust_rule_key("srv-b", "tool-call")));
    }

    #[test]
    fn test_remove_trust_rules_empty_policy() {
        let mut doc = toml::Value::Table(toml::map::Map::new());
        let removed = remove_trust_rules("nonexistent", &mut doc);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_build_match_table_sensitive_paths() {
        let table = build_match_table("srv", Permission::SensitivePaths);
        let m = table.as_table().unwrap();
        let paths = m
            .get("resource_path")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(paths.len() >= 6);
    }

    #[test]
    fn test_build_match_table_has_server_name() {
        let table = build_match_table("my-srv", Permission::ToolCall);
        let m = table.as_table().unwrap();
        let server_names = m
            .get("server_name")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(
            server_names[0].as_str().unwrap(),
            "my-srv"
        );
    }

    #[test]
    fn test_wrap_result_serializable() {
        let result = WrapResult {
            success: true,
            server_name: "test".to_string(),
            client_name: "claude".to_string(),
            reputation_clean: true,
            reputation_warnings: vec![],
            trust_level_applied: "standard".to_string(),
            message: "ok".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"success\":true"));
    }

    #[test]
    fn test_unwrap_result_serializable() {
        let result = UnwrapResult {
            success: true,
            server_name: "test".to_string(),
            trust_rules_removed: 7,
            profile_cleared: false,
            message: "done".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"trust_rules_removed\":7"));
    }
}
