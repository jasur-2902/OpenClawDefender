use crate::daemon;
use crate::event_stream;
use crate::state::*;

// --- Daemon management ---

#[tauri::command]
pub async fn get_daemon_status(
    state: tauri::State<'_, AppState>,
) -> Result<DaemonStatus, String> {
    let sock = daemon::socket_path().to_string_lossy().to_string();

    // Try live IPC query first
    if let Ok(metrics) = state.ipc_client.query_status() {
        let status = DaemonStatus {
            running: true,
            pid: None,
            uptime_seconds: None,
            version: None,
            socket_path: sock,
            servers_proxied: 0,
            events_processed: metrics.messages_total,
        };
        state.update_daemon_status(true, Some(status.clone()));
        return Ok(status);
    }

    // Fall back to cached status
    if let Ok(cached) = state.cached_status.lock() {
        if let Some(ref status) = *cached {
            return Ok(status.clone());
        }
    }

    // No cached status — return disconnected defaults
    Ok(DaemonStatus {
        running: false,
        pid: None,
        uptime_seconds: None,
        version: None,
        socket_path: sock,
        servers_proxied: 0,
        events_processed: 0,
    })
}

#[tauri::command]
pub async fn start_daemon(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Already running?
    if state.ipc_client.check_connection() {
        tracing::info!("Daemon already running, nothing to do");
        return Ok(());
    }

    daemon::start_daemon_process()?;

    // Poll up to 5 seconds for the daemon to become reachable
    let mut connected = false;
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if state.ipc_client.check_connection() {
            connected = true;
            break;
        }
    }

    if !connected {
        return Err("Daemon started but did not become reachable within 5 seconds".to_string());
    }

    if let Ok(mut flag) = state.daemon_started_by_gui.lock() {
        *flag = true;
    }
    state.update_daemon_status(true, None);
    tracing::info!("Daemon started successfully");
    Ok(())
}

#[tauri::command]
pub async fn stop_daemon(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Not running? Nothing to do.
    if !state.ipc_client.check_connection() && !daemon::is_daemon_running() {
        tracing::info!("Daemon is not running, nothing to stop");
        return Ok(());
    }

    daemon::stop_daemon_process()?;

    // Poll up to 5 seconds for the daemon to go away
    let mut stopped = false;
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if !daemon::is_daemon_running() {
            stopped = true;
            break;
        }
    }

    if !stopped {
        return Err("Daemon stop requested but it is still running after 5 seconds".to_string());
    }

    if let Ok(mut flag) = state.daemon_started_by_gui.lock() {
        *flag = false;
    }
    state.update_daemon_status(false, None);
    tracing::info!("Daemon stopped successfully");
    Ok(())
}

// --- Server management ---

#[tauri::command]
pub async fn detect_mcp_clients() -> Result<Vec<McpClient>, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;

    let clients_info: Vec<(&str, &str, Vec<std::path::PathBuf>)> = vec![
        (
            "claude",
            "Claude Desktop",
            vec![
                home.join("Library/Application Support/Claude/config.json"),
                home.join("Library/Application Support/Claude/claude_desktop_config.json"),
            ],
        ),
        (
            "cursor",
            "Cursor",
            vec![home.join(".cursor/mcp.json")],
        ),
        (
            "vscode",
            "VS Code",
            vec![home.join(".vscode/mcp.json")],
        ),
        (
            "windsurf",
            "Windsurf",
            vec![home.join(".codeium/windsurf/mcp_config.json")],
        ),
    ];

    let mut results = Vec::new();

    for (name, display_name, paths) in clients_info {
        // Find the first path that exists
        let found_path = paths.iter().find(|p| p.exists());

        if let Some(config_path) = found_path {
            let servers_count = match std::fs::read_to_string(config_path) {
                Ok(contents) => match serde_json::from_str::<serde_json::Value>(&contents) {
                    Ok(config) => {
                        let key = detect_servers_key(&config);
                        config
                            .get(key)
                            .and_then(|v| v.as_object())
                            .map(|obj| obj.len() as u32)
                            .unwrap_or(0)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Malformed JSON in {}: {}",
                            config_path.display(),
                            e
                        );
                        0
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        "Could not read {}: {}",
                        config_path.display(),
                        e
                    );
                    0
                }
            };

            results.push(McpClient {
                name: name.to_string(),
                display_name: display_name.to_string(),
                config_path: config_path.to_string_lossy().to_string(),
                detected: true,
                servers_count,
            });
        } else {
            results.push(McpClient {
                name: name.to_string(),
                display_name: display_name.to_string(),
                config_path: paths[0].to_string_lossy().to_string(),
                detected: false,
                servers_count: 0,
            });
        }
    }

    Ok(results)
}

#[tauri::command]
pub async fn list_mcp_servers(client: String) -> Result<Vec<McpServer>, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;

    let config_paths: Vec<std::path::PathBuf> = match client.as_str() {
        "claude" => vec![
            home.join("Library/Application Support/Claude/config.json"),
            home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        ],
        "cursor" => vec![home.join(".cursor/mcp.json")],
        "vscode" => vec![home.join(".vscode/mcp.json")],
        "windsurf" => vec![home.join(".codeium/windsurf/mcp_config.json")],
        other => return Err(format!("Unknown client: {}", other)),
    };

    let config_path = match config_paths.iter().find(|p| p.exists()) {
        Some(p) => p,
        None => return Ok(vec![]),
    };

    let contents = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;

    let config: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Malformed JSON in {}: {}", config_path.display(), e);
            return Ok(vec![]);
        }
    };

    let key = detect_servers_key(&config);
    let servers_obj = match config.get(key).and_then(|v| v.as_object()) {
        Some(obj) => obj,
        None => return Ok(vec![]),
    };

    let mut servers = Vec::new();
    for (name, entry) in servers_obj {
        let mut command = Vec::new();
        if let Some(cmd) = entry.get("command").and_then(|v| v.as_str()) {
            command.push(cmd.to_string());
        }
        if let Some(args) = entry.get("args").and_then(|v| v.as_array()) {
            for arg in args {
                if let Some(s) = arg.as_str() {
                    command.push(s.to_string());
                }
            }
        }

        let wrapped = entry.get("_clawdefender_original").is_some()
            || entry.get("_clawai_original").is_some();

        let status = if wrapped {
            "running".to_string()
        } else {
            "stopped".to_string()
        };

        servers.push(McpServer {
            name: name.clone(),
            command,
            wrapped,
            status,
            events_count: 0,
        });
    }

    Ok(servers)
}

#[tauri::command]
pub async fn wrap_server(client: String, server: String) -> Result<(), String> {
    tracing::info!("Wrapping server '{}' for client '{}'", server, client);

    let config_path = resolve_config_path(&client)?;

    let contents = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;

    let mut config: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Malformed JSON in {}: {}", config_path.display(), e))?;

    let key = detect_servers_key(&config).to_string();
    let servers_obj = config
        .get_mut(&key)
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| format!("No '{}' object found in {}", key, config_path.display()))?;

    // Collect keys before mutable borrow
    let available_servers: Vec<String> = servers_obj.keys().cloned().collect();
    let entry = servers_obj.get_mut(&server).ok_or_else(|| {
        format!(
            "Server '{}' not found. Available servers: {}",
            server,
            available_servers.join(", ")
        )
    })?;

    // Idempotent: already wrapped
    if entry.get("_clawdefender_original").is_some() || entry.get("_clawai_original").is_some() {
        tracing::info!("Server '{}' is already wrapped, nothing to do", server);
        return Ok(());
    }

    // Create .bak backup BEFORE modifying
    let backup_path = config_path.with_extension("json.bak");
    std::fs::copy(&config_path, &backup_path)
        .map_err(|e| format!("Failed to create backup at {}: {}", backup_path.display(), e))?;

    // Save original command and args
    let original_command = entry
        .get("command")
        .cloned()
        .unwrap_or(serde_json::Value::String(String::new()));
    let original_args = entry
        .get("args")
        .cloned()
        .unwrap_or(serde_json::Value::Array(vec![]));

    let original = serde_json::json!({
        "command": original_command,
        "args": original_args,
    });

    // Build new args: ["proxy", "--", "<original_command>", <original_args...>]
    let mut new_args: Vec<serde_json::Value> = vec![
        serde_json::Value::String("proxy".to_string()),
        serde_json::Value::String("--".to_string()),
    ];
    if let Some(cmd) = original_command.as_str() {
        new_args.push(serde_json::Value::String(cmd.to_string()));
    }
    if let Some(args_arr) = original_args.as_array() {
        new_args.extend(args_arr.iter().cloned());
    }

    let clawdefender_bin = resolve_clawdefender_path();
    let entry_obj = entry
        .as_object_mut()
        .ok_or("Server entry is not a JSON object")?;
    entry_obj.insert(
        "command".to_string(),
        serde_json::Value::String(clawdefender_bin),
    );
    entry_obj.insert("args".to_string(), serde_json::Value::Array(new_args));
    entry_obj.insert("_clawdefender_original".to_string(), original);

    // Write back with pretty formatting + trailing newline
    let output = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&config_path, format!("{}\n", output))
        .map_err(|e| format!("Failed to write {}: {}", config_path.display(), e))?;

    tracing::info!("Successfully wrapped server '{}'", server);
    Ok(())
}

#[tauri::command]
pub async fn unwrap_server(client: String, server: String) -> Result<(), String> {
    tracing::info!("Unwrapping server '{}' for client '{}'", server, client);

    let config_path = resolve_config_path(&client)?;

    let contents = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;

    let mut config: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Malformed JSON in {}: {}", config_path.display(), e))?;

    let key = detect_servers_key(&config).to_string();
    let servers_obj = config
        .get_mut(&key)
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| format!("No '{}' object found in {}", key, config_path.display()))?;

    // Collect keys before mutable borrow
    let available_servers: Vec<String> = servers_obj.keys().cloned().collect();
    let entry = servers_obj.get_mut(&server).ok_or_else(|| {
        format!(
            "Server '{}' not found. Available servers: {}",
            server,
            available_servers.join(", ")
        )
    })?;

    // Find the original data (support both naming conventions)
    let original_key = if entry.get("_clawdefender_original").is_some() {
        "_clawdefender_original"
    } else if entry.get("_clawai_original").is_some() {
        "_clawai_original"
    } else {
        // Idempotent: not wrapped
        tracing::info!("Server '{}' is not wrapped, nothing to do", server);
        return Ok(());
    };

    let original = entry
        .get(original_key)
        .cloned()
        .ok_or("Failed to read original config")?;

    // Create .bak backup BEFORE modifying
    let backup_path = config_path.with_extension("json.bak");
    std::fs::copy(&config_path, &backup_path)
        .map_err(|e| format!("Failed to create backup at {}: {}", backup_path.display(), e))?;

    // Restore original command and args
    let entry_obj = entry
        .as_object_mut()
        .ok_or("Server entry is not a JSON object")?;

    if let Some(cmd) = original.get("command") {
        entry_obj.insert("command".to_string(), cmd.clone());
    }
    if let Some(args) = original.get("args") {
        entry_obj.insert("args".to_string(), args.clone());
    }

    // Remove both original markers
    entry_obj.remove("_clawdefender_original");
    entry_obj.remove("_clawai_original");

    // Write back with pretty formatting + trailing newline
    let output = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&config_path, format!("{}\n", output))
        .map_err(|e| format!("Failed to write {}: {}", config_path.display(), e))?;

    tracing::info!("Successfully unwrapped server '{}'", server);
    Ok(())
}

// --- Policy management ---

/// Path to the policy TOML file.
fn policy_file_path() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_default();
    home.join(".config").join("clawdefender").join("policy.toml")
}

/// Sanitize a rule name into a valid TOML key (lowercase, spaces to hyphens).
fn sanitize_rule_key(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .replace(' ', "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

fn frontend_action_to_toml(action: &str) -> &str {
    match action {
        "deny" => "block",
        "audit" => "log",
        _ => action,
    }
}

fn toml_action_to_frontend(action: &str) -> &str {
    match action {
        "block" => "deny",
        "log" => "audit",
        _ => action,
    }
}

fn infer_resource_from_match(match_table: &toml::Value) -> String {
    if let Some(table) = match_table.as_table() {
        if let Some(types) = table.get("event_type").and_then(|v| v.as_array()) {
            let has_network = types.iter().any(|v| {
                v.as_str()
                    .map(|s| s == "connect" || s == "dns" || s == "bind")
                    .unwrap_or(false)
            });
            if has_network {
                return "network".to_string();
            }
        }
        if table.contains_key("resource_path") {
            return "file".to_string();
        }
    }
    "*".to_string()
}

fn extract_pattern_from_match(match_table: &toml::Value) -> String {
    match_table
        .get("resource_path")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("*")
        .to_string()
}

fn read_policy_file() -> Result<toml::Value, String> {
    let path = policy_file_path();
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read policy file {}: {}", path.display(), e))?;
    contents
        .parse::<toml::Value>()
        .map_err(|e| format!("Failed to parse policy TOML: {}", e))
}

fn write_policy_file(doc: &toml::Value) -> Result<(), String> {
    let path = policy_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }
    if path.exists() {
        let backup = path.with_extension("toml.bak");
        if let Err(e) = std::fs::copy(&path, &backup) {
            tracing::warn!("Failed to create policy backup at {}: {}", backup.display(), e);
        }
    }
    let toml_string =
        toml::to_string_pretty(doc).map_err(|e| format!("Failed to serialize policy: {}", e))?;
    std::fs::write(&path, toml_string)
        .map_err(|e| format!("Failed to write policy file: {}", e))?;
    Ok(())
}

fn toml_to_policy_rules(doc: &toml::Value) -> Vec<PolicyRule> {
    let mut rules = Vec::new();
    if let Some(rules_table) = doc.get("rules").and_then(|v| v.as_table()) {
        for (key, value) in rules_table {
            if let Some(table) = value.as_table() {
                let action_raw = table
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("allow");
                let description = table
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let priority = table
                    .get("priority")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(0) as i32;
                let enabled = table
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let match_section = table
                    .get("match")
                    .cloned()
                    .unwrap_or(toml::Value::Table(toml::map::Map::new()));
                let resource = infer_resource_from_match(&match_section);
                let pattern = extract_pattern_from_match(&match_section);
                rules.push(PolicyRule {
                    name: key.clone(),
                    description,
                    action: toml_action_to_frontend(action_raw).to_string(),
                    resource,
                    pattern,
                    priority,
                    enabled,
                });
            }
        }
    }
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    rules
}

fn policy_rule_to_toml_table(rule: &PolicyRule) -> toml::Value {
    let mut table = toml::map::Map::new();
    table.insert(
        "description".to_string(),
        toml::Value::String(rule.description.clone()),
    );
    table.insert(
        "action".to_string(),
        toml::Value::String(frontend_action_to_toml(&rule.action).to_string()),
    );
    table.insert(
        "priority".to_string(),
        toml::Value::Integer(rule.priority as i64),
    );
    table.insert("enabled".to_string(), toml::Value::Boolean(rule.enabled));
    if let Some(msg) = rule_message_for_action(&rule.action) {
        table.insert("message".to_string(), toml::Value::String(msg));
    }
    let mut match_table = toml::map::Map::new();
    let patterns: Vec<toml::Value> = rule
        .pattern
        .split(',')
        .map(|p| toml::Value::String(p.trim().to_string()))
        .collect();
    if rule.resource == "network" {
        match_table.insert(
            "event_type".to_string(),
            toml::Value::Array(vec![toml::Value::String("connect".to_string())]),
        );
    } else {
        match_table.insert("resource_path".to_string(), toml::Value::Array(patterns));
    }
    table.insert("match".to_string(), toml::Value::Table(match_table));
    toml::Value::Table(table)
}

fn rule_message_for_action(action: &str) -> Option<String> {
    match action {
        "deny" => Some("Access denied by policy".to_string()),
        "prompt" => Some("Allow this operation?".to_string()),
        "audit" => Some("Operation logged".to_string()),
        _ => None,
    }
}

fn default_policy_doc() -> toml::Value {
    let rules = vec![
        PolicyRule {
            name: "block-sensitive-files".to_string(),
            description: "Block access to sensitive configuration files".to_string(),
            action: "deny".to_string(),
            resource: "file".to_string(),
            pattern: "**/.env*,**/.ssh/*".to_string(),
            priority: 100,
            enabled: true,
        },
        PolicyRule {
            name: "prompt-write-operations".to_string(),
            description: "Prompt user before any file write operations".to_string(),
            action: "prompt".to_string(),
            resource: "file".to_string(),
            pattern: "**/*".to_string(),
            priority: 50,
            enabled: true,
        },
        PolicyRule {
            name: "audit-network-access".to_string(),
            description: "Log all network access attempts".to_string(),
            action: "audit".to_string(),
            resource: "network".to_string(),
            pattern: "*".to_string(),
            priority: 10,
            enabled: true,
        },
    ];
    let mut rules_table = toml::map::Map::new();
    for rule in &rules {
        let key = sanitize_rule_key(&rule.name);
        rules_table.insert(key, policy_rule_to_toml_table(rule));
    }
    let mut doc = toml::map::Map::new();
    doc.insert("rules".to_string(), toml::Value::Table(rules_table));
    toml::Value::Table(doc)
}

fn try_reload_daemon(state: &AppState) {
    match state.ipc_client.reload_policy() {
        Ok(resp) => {
            if resp.ok {
                tracing::info!("Daemon policy reloaded successfully");
            } else {
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

#[tauri::command]
pub async fn get_policy() -> Result<Policy, String> {
    let path = policy_file_path();
    let now = chrono::Utc::now().to_rfc3339();

    if !path.exists() {
        let doc = default_policy_doc();
        write_policy_file(&doc)?;
        let rules = toml_to_policy_rules(&doc);
        return Ok(Policy {
            name: "default".to_string(),
            version: "1.0.0".to_string(),
            rules,
            created_at: now.clone(),
            updated_at: now,
        });
    }

    let doc = read_policy_file()?;
    let rules = toml_to_policy_rules(&doc);

    let (created_at, updated_at) = match std::fs::metadata(&path) {
        Ok(meta) => {
            let modified = meta
                .modified()
                .ok()
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                })
                .unwrap_or_else(|| now.clone());
            let created = meta
                .created()
                .ok()
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                })
                .unwrap_or_else(|| now.clone());
            (created, modified)
        }
        Err(_) => (now.clone(), now),
    };

    Ok(Policy {
        name: "default".to_string(),
        version: "1.0.0".to_string(),
        rules,
        created_at,
        updated_at,
    })
}

#[tauri::command]
pub async fn add_rule(
    state: tauri::State<'_, AppState>,
    rule: PolicyRule,
) -> Result<(), String> {
    let name = rule.name.trim().to_string();
    if name.is_empty() {
        return Err("Rule name cannot be empty".to_string());
    }

    let path = policy_file_path();
    let mut doc = if path.exists() {
        read_policy_file()?
    } else {
        let mut m = toml::map::Map::new();
        m.insert(
            "rules".to_string(),
            toml::Value::Table(toml::map::Map::new()),
        );
        toml::Value::Table(m)
    };

    let key = sanitize_rule_key(&name);
    if key.is_empty() {
        return Err("Rule name must contain at least one alphanumeric character".to_string());
    }

    if let Some(rules) = doc.get("rules").and_then(|v| v.as_table()) {
        if rules.contains_key(&key) {
            return Err(format!("Rule '{}' already exists", key));
        }
    }

    if let Some(rules) = doc.get_mut("rules").and_then(|v| v.as_table_mut()) {
        rules.insert(key.clone(), policy_rule_to_toml_table(&rule));
    } else {
        let mut rules_table = toml::map::Map::new();
        rules_table.insert(key.clone(), policy_rule_to_toml_table(&rule));
        if let Some(table) = doc.as_table_mut() {
            table.insert("rules".to_string(), toml::Value::Table(rules_table));
        }
    }

    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!("Added policy rule: {}", name);
    Ok(())
}

#[tauri::command]
pub async fn update_rule(
    state: tauri::State<'_, AppState>,
    rule: PolicyRule,
) -> Result<(), String> {
    let path = policy_file_path();
    if !path.exists() {
        return Err("Policy file does not exist".to_string());
    }

    let mut doc = read_policy_file()?;
    let key = sanitize_rule_key(&rule.name);

    let exists = doc
        .get("rules")
        .and_then(|v| v.as_table())
        .map(|t| t.contains_key(&key))
        .unwrap_or(false);

    if !exists {
        return Err(format!("Rule '{}' not found", key));
    }

    if let Some(rules) = doc.get_mut("rules").and_then(|v| v.as_table_mut()) {
        rules.insert(key.clone(), policy_rule_to_toml_table(&rule));
    }

    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!("Updated policy rule: {}", key);
    Ok(())
}

#[tauri::command]
pub async fn delete_rule(
    state: tauri::State<'_, AppState>,
    rule_name: String,
) -> Result<(), String> {
    let path = policy_file_path();
    if !path.exists() {
        return Err("Policy file does not exist".to_string());
    }

    let mut doc = read_policy_file()?;
    let key = sanitize_rule_key(&rule_name);

    let removed = doc
        .get_mut("rules")
        .and_then(|v| v.as_table_mut())
        .map(|t| t.remove(&key).is_some())
        .unwrap_or(false);

    if !removed {
        return Err(format!("Rule '{}' not found", key));
    }

    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!("Deleted policy rule: {}", key);
    Ok(())
}

#[tauri::command]
pub async fn reload_policy(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    match state.ipc_client.reload_policy() {
        Ok(resp) => {
            if resp.ok {
                tracing::info!("Policy reloaded successfully");
                Ok(())
            } else {
                Err(format!(
                    "Daemon reload failed: {}",
                    resp.error.unwrap_or_else(|| "unknown error".to_string())
                ))
            }
        }
        Err(_) => {
            tracing::debug!("Daemon not connected, policy reload skipped");
            Ok(())
        }
    }
}

#[tauri::command]
pub async fn list_templates() -> Result<Vec<PolicyTemplate>, String> {
    Ok(vec![
        PolicyTemplate {
            name: "strict".to_string(),
            description: "Maximum security - deny by default, prompt for everything".to_string(),
            rules_count: 12,
            category: "security".to_string(),
        },
        PolicyTemplate {
            name: "balanced".to_string(),
            description: "Balanced security - block dangerous operations, audit the rest"
                .to_string(),
            rules_count: 8,
            category: "security".to_string(),
        },
        PolicyTemplate {
            name: "permissive".to_string(),
            description: "Minimal restrictions - audit everything, block only known threats"
                .to_string(),
            rules_count: 4,
            category: "security".to_string(),
        },
        PolicyTemplate {
            name: "developer".to_string(),
            description: "Developer-friendly - allow most operations with audit logging"
                .to_string(),
            rules_count: 6,
            category: "workflow".to_string(),
        },
    ])
}

fn template_rules(name: &str) -> Result<Vec<PolicyRule>, String> {
    match name {
        "strict" => Ok(vec![
            PolicyRule { name: "block-env-files".into(), description: "Block access to .env files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.env*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-ssh-keys".into(), description: "Block access to SSH keys".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.ssh/*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-aws-credentials".into(), description: "Block access to AWS credentials".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.aws/credentials".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-gnupg".into(), description: "Block access to GPG keys".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.gnupg/*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-kube-config".into(), description: "Block access to Kubernetes config".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.kube/config".into(), priority: 95, enabled: true },
            PolicyRule { name: "block-docker-config".into(), description: "Block access to Docker credentials".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.docker/config.json".into(), priority: 95, enabled: true },
            PolicyRule { name: "prompt-all-writes".into(), description: "Prompt before any file write".into(), action: "prompt".into(), resource: "file".into(), pattern: "**/*".into(), priority: 80, enabled: true },
            PolicyRule { name: "prompt-network-access".into(), description: "Prompt before any network access".into(), action: "prompt".into(), resource: "network".into(), pattern: "*".into(), priority: 80, enabled: true },
            PolicyRule { name: "prompt-system-dirs".into(), description: "Prompt before accessing system directories".into(), action: "prompt".into(), resource: "file".into(), pattern: "/etc/**,/usr/**,/System/**".into(), priority: 75, enabled: true },
            PolicyRule { name: "audit-all-reads".into(), description: "Log all file read operations".into(), action: "audit".into(), resource: "file".into(), pattern: "**/*".into(), priority: 10, enabled: true },
            PolicyRule { name: "audit-all-network".into(), description: "Log all network activity".into(), action: "audit".into(), resource: "network".into(), pattern: "*".into(), priority: 10, enabled: true },
            PolicyRule { name: "block-private-keys".into(), description: "Block access to private key files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/*.pem,**/*.key,**/id_rsa,**/id_ed25519".into(), priority: 100, enabled: true },
        ]),
        "balanced" => Ok(vec![
            PolicyRule { name: "block-env-files".into(), description: "Block access to .env files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.env*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-ssh-keys".into(), description: "Block access to SSH keys".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.ssh/*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-private-keys".into(), description: "Block access to private key files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/*.pem,**/*.key".into(), priority: 100, enabled: true },
            PolicyRule { name: "prompt-write-operations".into(), description: "Prompt before file writes outside project".into(), action: "prompt".into(), resource: "file".into(), pattern: "**/*".into(), priority: 50, enabled: true },
            PolicyRule { name: "prompt-network-unknown".into(), description: "Prompt for unrecognized network destinations".into(), action: "prompt".into(), resource: "network".into(), pattern: "*".into(), priority: 50, enabled: true },
            PolicyRule { name: "audit-file-reads".into(), description: "Log file read operations".into(), action: "audit".into(), resource: "file".into(), pattern: "**/*".into(), priority: 10, enabled: true },
            PolicyRule { name: "audit-network".into(), description: "Log all network access".into(), action: "audit".into(), resource: "network".into(), pattern: "*".into(), priority: 10, enabled: true },
            PolicyRule { name: "block-system-dirs".into(), description: "Block writes to system directories".into(), action: "deny".into(), resource: "file".into(), pattern: "/etc/**,/usr/**,/System/**".into(), priority: 90, enabled: true },
        ]),
        "permissive" => Ok(vec![
            PolicyRule { name: "block-env-files".into(), description: "Block access to .env files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.env*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-ssh-keys".into(), description: "Block access to SSH private keys".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.ssh/id_*".into(), priority: 100, enabled: true },
            PolicyRule { name: "audit-all-operations".into(), description: "Log all file operations".into(), action: "audit".into(), resource: "file".into(), pattern: "**/*".into(), priority: 5, enabled: true },
            PolicyRule { name: "audit-all-network".into(), description: "Log all network access".into(), action: "audit".into(), resource: "network".into(), pattern: "*".into(), priority: 5, enabled: true },
        ]),
        "developer" => Ok(vec![
            PolicyRule { name: "block-env-files".into(), description: "Block access to .env files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.env*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-ssh-keys".into(), description: "Block access to SSH keys".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.ssh/*".into(), priority: 100, enabled: true },
            PolicyRule { name: "allow-project-writes".into(), description: "Allow writes within project directories".into(), action: "allow".into(), resource: "file".into(), pattern: "**/*".into(), priority: 50, enabled: true },
            PolicyRule { name: "audit-file-operations".into(), description: "Log all file operations".into(), action: "audit".into(), resource: "file".into(), pattern: "**/*".into(), priority: 10, enabled: true },
            PolicyRule { name: "audit-network".into(), description: "Log all network access".into(), action: "audit".into(), resource: "network".into(), pattern: "*".into(), priority: 10, enabled: true },
            PolicyRule { name: "prompt-system-writes".into(), description: "Prompt before writing to system directories".into(), action: "prompt".into(), resource: "file".into(), pattern: "/etc/**,/usr/**".into(), priority: 80, enabled: true },
        ]),
        _ => Err(format!("Unknown template: {}", name)),
    }
}

#[tauri::command]
pub async fn apply_template(
    state: tauri::State<'_, AppState>,
    name: String,
) -> Result<(), String> {
    let rules = template_rules(&name)?;
    let mut rules_table = toml::map::Map::new();
    for rule in &rules {
        let key = sanitize_rule_key(&rule.name);
        rules_table.insert(key, policy_rule_to_toml_table(rule));
    }
    let mut doc = toml::map::Map::new();
    doc.insert("rules".to_string(), toml::Value::Table(rules_table));
    let doc = toml::Value::Table(doc);
    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!("Applied policy template: {}", name);
    Ok(())
}

// --- Event stream ---

#[tauri::command]
pub async fn get_recent_events(
    state: tauri::State<'_, AppState>,
    count: u32,
) -> Result<Vec<AuditEvent>, String> {
    let count = count.min(10_000) as usize;

    // 1. Read events from the in-memory buffer (populated by the event stream watcher)
    let buffer_events: Vec<AuditEvent> = state
        .event_buffer
        .lock()
        .map(|buf| buf.clone())
        .unwrap_or_default();

    if buffer_events.len() >= count {
        // Buffer has enough — take the last `count` events, reverse for newest-first
        let start = buffer_events.len() - count;
        let mut result: Vec<AuditEvent> = buffer_events[start..].to_vec();
        result.reverse();
        return Ok(result);
    }

    // 2. Buffer doesn't have enough — supplement with historical events from audit.jsonl
    let needed = count - buffer_events.len();
    let historical = read_historical_events(needed, &buffer_events);

    // 3. Merge: historical (oldest) + buffer events, deduplicate by id
    let mut seen = std::collections::HashSet::new();
    let mut merged: Vec<AuditEvent> = Vec::with_capacity(count);

    // Add buffer events first (they are more recent / authoritative)
    for event in &buffer_events {
        if seen.insert(event.id.clone()) {
            merged.push(event.clone());
        }
    }

    // Add historical events that aren't already in the buffer
    for event in historical {
        if seen.insert(event.id.clone()) {
            merged.push(event);
        }
    }

    // Sort newest-first by timestamp (descending)
    merged.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Truncate to requested count
    merged.truncate(count);

    Ok(merged)
}

/// Read historical events from the audit.jsonl file on disk.
/// Reads from the end of the file efficiently for large files.
/// Excludes events whose IDs are already in `existing` to avoid duplicates.
pub(crate) fn read_historical_events(needed: usize, existing: &[AuditEvent]) -> Vec<AuditEvent> {
    let path = event_stream::audit_log_path();
    if !path.exists() {
        return Vec::new();
    }

    // For efficiency, read the last chunk of the file rather than the whole thing.
    // 64 KB per event is generous; most JSONL lines are < 1 KB.
    const CHUNK_SIZE: u64 = 256 * 1024; // 256 KB

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to open audit.jsonl for history");
            return Vec::new();
        }
    };

    let file_len = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return Vec::new(),
    };

    // Determine how much to read
    let read_from = if file_len > CHUNK_SIZE {
        file_len - CHUNK_SIZE
    } else {
        0
    };

    let mut reader = std::io::BufReader::new(&file);
    if read_from > 0 {
        use std::io::{Seek, SeekFrom};
        if reader.seek(SeekFrom::Start(read_from)).is_err() {
            return Vec::new();
        }
        // Skip the first partial line after seeking
        let mut partial = String::new();
        use std::io::BufRead;
        let _ = reader.read_line(&mut partial);
    }

    // Build a set of existing IDs for deduplication
    let existing_ids: std::collections::HashSet<&str> =
        existing.iter().map(|e| e.id.as_str()).collect();

    // Parse lines from the chunk, collecting all valid events
    let mut events: Vec<AuditEvent> = Vec::new();
    let mut seq: u64 = 100_000; // High seq offset to avoid collisions with live stream IDs

    use std::io::BufRead;
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<event_stream::DaemonAuditRecord>(&line) {
            Ok(record) => {
                let event = event_stream::to_audit_event(&record, seq);
                seq += 1;
                if !existing_ids.contains(event.id.as_str()) {
                    events.push(event);
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "Skipping malformed historical audit line");
            }
        }
    }

    // Take the last `needed` events (newest from the file)
    if events.len() > needed {
        events.drain(..events.len() - needed);
    }

    events
}

// --- Behavioral engine ---

#[tauri::command]
pub async fn get_profiles() -> Result<Vec<ServerProfileSummary>, String> {
    Ok(vec![
        ServerProfileSummary {
            server_name: "filesystem".to_string(),
            tools_count: 5,
            total_calls: 342,
            anomaly_score: 0.12,
            status: "normal".to_string(),
            last_activity: chrono::Utc::now().to_rfc3339(),
        },
        ServerProfileSummary {
            server_name: "github".to_string(),
            tools_count: 8,
            total_calls: 156,
            anomaly_score: 0.05,
            status: "normal".to_string(),
            last_activity: (chrono::Utc::now() - chrono::Duration::minutes(15)).to_rfc3339(),
        },
        ServerProfileSummary {
            server_name: "everything".to_string(),
            tools_count: 12,
            total_calls: 905,
            anomaly_score: 0.67,
            status: "anomalous".to_string(),
            last_activity: (chrono::Utc::now() - chrono::Duration::minutes(2)).to_rfc3339(),
        },
    ])
}

#[tauri::command]
pub async fn get_behavioral_status() -> Result<BehavioralStatus, String> {
    Ok(BehavioralStatus {
        enabled: true,
        profiles_count: 3,
        total_anomalies: 7,
        learning_servers: 1,
        monitoring_servers: 2,
    })
}

// --- Guards ---

#[tauri::command]
pub async fn list_guards() -> Result<Vec<GuardSummary>, String> {
    Ok(vec![
        GuardSummary {
            name: "secrets-guard".to_string(),
            guard_type: "content".to_string(),
            enabled: true,
            triggers_count: 3,
            last_triggered: Some((chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339()),
            description: "Detects and blocks exposure of secrets and API keys".to_string(),
        },
        GuardSummary {
            name: "path-traversal-guard".to_string(),
            guard_type: "filesystem".to_string(),
            enabled: true,
            triggers_count: 1,
            last_triggered: Some((chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339()),
            description: "Prevents path traversal attacks in file operations".to_string(),
        },
        GuardSummary {
            name: "rate-limit-guard".to_string(),
            guard_type: "rate".to_string(),
            enabled: true,
            triggers_count: 0,
            last_triggered: None,
            description: "Rate limits tool calls to prevent abuse".to_string(),
        },
    ])
}

// --- Scanner ---

#[tauri::command]
pub async fn start_scan(command: Vec<String>, modules: Vec<String>) -> Result<String, String> {
    tracing::info!("Starting scan with command {:?}, modules {:?} (mock)", command, modules);
    Ok("scan-001".to_string())
}

#[tauri::command]
pub async fn get_scan_progress(scan_id: String) -> Result<ScanProgress, String> {
    Ok(ScanProgress {
        scan_id,
        status: "completed".to_string(),
        progress_percent: 100.0,
        modules_completed: 4,
        modules_total: 4,
        findings_count: 2,
        current_module: None,
    })
}

// --- System health ---

#[tauri::command]
pub async fn run_doctor() -> Result<Vec<DoctorCheck>, String> {
    Ok(vec![
        DoctorCheck {
            name: "Daemon Process".to_string(),
            status: "pass".to_string(),
            message: "Daemon is running (PID 12345)".to_string(),
            fix_suggestion: None,
        },
        DoctorCheck {
            name: "Socket Connection".to_string(),
            status: "pass".to_string(),
            message: "Successfully connected to daemon socket".to_string(),
            fix_suggestion: None,
        },
        DoctorCheck {
            name: "Policy File".to_string(),
            status: "pass".to_string(),
            message: "Policy file is valid".to_string(),
            fix_suggestion: None,
        },
        DoctorCheck {
            name: "MCP Clients".to_string(),
            status: "warn".to_string(),
            message: "1 of 2 detected clients have unwrapped servers".to_string(),
            fix_suggestion: Some("Run 'Wrap All' to protect all MCP servers".to_string()),
        },
    ])
}

#[tauri::command]
pub async fn get_system_info() -> Result<SystemInfo, String> {
    let home = dirs::home_dir().unwrap_or_default();
    Ok(SystemInfo {
        os: "macOS".to_string(),
        os_version: "14.0".to_string(),
        arch: std::env::consts::ARCH.to_string(),
        daemon_version: Some("0.10.0".to_string()),
        app_version: "0.10.0".to_string(),
        config_dir: home.join(".clawdefender").to_string_lossy().to_string(),
        log_dir: home.join(".clawdefender/logs").to_string_lossy().to_string(),
    })
}

// --- Prompt handling ---

#[tauri::command]
pub async fn respond_to_prompt(
    state: tauri::State<'_, AppState>,
    prompt_id: String,
    decision: String,
) -> Result<(), String> {
    tracing::info!("Responding to prompt {}: {}", prompt_id, decision);

    // 1. Remove the prompt from pending_prompts (idempotent — missing ID is not an error)
    let removed_prompt = if let Ok(mut prompts) = state.pending_prompts.lock() {
        if let Some(pos) = prompts.iter().position(|p| p.id == prompt_id) {
            Some(prompts.remove(pos))
        } else {
            tracing::debug!("Prompt {} not found in pending list (already handled or expired)", prompt_id);
            None
        }
    } else {
        tracing::warn!("Failed to lock pending_prompts mutex");
        None
    };

    // 2. For policy-affecting decisions, update the policy file
    match decision.as_str() {
        "allow_always" => {
            if let Some(ref prompt) = removed_prompt {
                let rule_name = format!("auto-allow-{}-{}", prompt.server_name, prompt.tool_name);
                let resource = if prompt.resource.starts_with("http://")
                    || prompt.resource.starts_with("https://")
                    || prompt.resource.contains(':')
                {
                    "network"
                } else {
                    "file"
                };
                let rule = PolicyRule {
                    name: rule_name.clone(),
                    description: format!(
                        "Auto-allowed: {} {} on {} (from prompt {})",
                        prompt.server_name, prompt.tool_name, prompt.resource, prompt_id
                    ),
                    action: "allow".to_string(),
                    resource: resource.to_string(),
                    pattern: prompt.resource.clone(),
                    priority: 60,
                    enabled: true,
                };

                // Read or create the policy file
                let path = policy_file_path();
                let mut doc = if path.exists() {
                    read_policy_file()?
                } else {
                    let mut m = toml::map::Map::new();
                    m.insert(
                        "rules".to_string(),
                        toml::Value::Table(toml::map::Map::new()),
                    );
                    toml::Value::Table(m)
                };

                let key = sanitize_rule_key(&rule_name);
                // Only add if the rule doesn't already exist (idempotent)
                let already_exists = doc
                    .get("rules")
                    .and_then(|v| v.as_table())
                    .map(|t| t.contains_key(&key))
                    .unwrap_or(false);

                if !already_exists {
                    if let Some(rules) = doc.get_mut("rules").and_then(|v| v.as_table_mut()) {
                        rules.insert(key.clone(), policy_rule_to_toml_table(&rule));
                    }
                    write_policy_file(&doc)?;
                    try_reload_daemon(&state);
                    tracing::info!("Added allow-always policy rule: {}", key);
                } else {
                    tracing::debug!("Policy rule {} already exists, skipping", key);
                }
            } else {
                tracing::info!(
                    "Prompt {} not found for allow_always — decision recorded but no policy rule created",
                    prompt_id
                );
            }
        }
        "deny" | "allow_once" | "allow_session" => {
            // These decisions don't create persistent policy rules.
            // "deny" is a one-time denial, "allow_once" and "allow_session" are transient.
            tracing::info!("Decision '{}' recorded for prompt {} (no policy change)", decision, prompt_id);
        }
        other => {
            tracing::warn!("Unknown decision '{}' for prompt {}", other, prompt_id);
        }
    }

    Ok(())
}

// --- Onboarding ---

#[tauri::command]
pub async fn check_onboarding_complete(
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let completed = state
        .onboarding_complete
        .lock()
        .map(|g| *g)
        .unwrap_or(false);
    Ok(completed)
}

#[tauri::command]
pub async fn complete_onboarding(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Set in-memory flag
    if let Ok(mut guard) = state.onboarding_complete.lock() {
        *guard = true;
    }

    // Persist to disk so it survives app restarts
    let flag_path = AppState::onboarding_flag_path();
    if let Some(parent) = flag_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&flag_path, "1").map_err(|e| e.to_string())?;

    tracing::info!("Onboarding completed, flag written to {}", flag_path.display());
    Ok(())
}

// --- Settings ---

fn config_toml_path() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    home.join(".config/clawdefender/config.toml")
}

fn default_settings() -> AppSettings {
    AppSettings {
        theme: "dark".to_string(),
        notifications_enabled: true,
        auto_start_daemon: true,
        minimize_to_tray: true,
        log_level: "info".to_string(),
        prompt_timeout_seconds: 15,
        event_retention_days: 30,
    }
}

fn get_str<'a>(table: &'a toml::Value, section: &str, key: &str, default: &'a str) -> String {
    table
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

fn get_bool(table: &toml::Value, section: &str, key: &str, default: bool) -> bool {
    table
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}

fn get_u32(table: &toml::Value, section: &str, key: &str, default: u32) -> u32 {
    table
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_integer())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(default)
}

#[tauri::command]
pub async fn get_settings() -> Result<AppSettings, String> {
    let path = config_toml_path();
    if !path.exists() {
        return Ok(default_settings());
    }

    let content = std::fs::read_to_string(&path).map_err(|e| {
        format!("Failed to read config.toml: {}", e)
    })?;

    let table: toml::Value = content
        .parse()
        .unwrap_or(toml::Value::Table(Default::default()));

    let defaults = default_settings();
    Ok(AppSettings {
        theme: get_str(&table, "ui", "theme", &defaults.theme),
        notifications_enabled: get_bool(&table, "ui", "notifications", defaults.notifications_enabled),
        auto_start_daemon: get_bool(&table, "ui", "auto_start_daemon", defaults.auto_start_daemon),
        minimize_to_tray: get_bool(&table, "ui", "minimize_to_tray", defaults.minimize_to_tray),
        log_level: get_str(&table, "ui", "log_level", &defaults.log_level),
        prompt_timeout_seconds: get_u32(&table, "network_policy", "prompt_timeout_seconds", defaults.prompt_timeout_seconds),
        event_retention_days: get_u32(&table, "ui", "event_retention_days", defaults.event_retention_days),
    })
}

#[tauri::command]
pub async fn update_settings(
    settings: AppSettings,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path = config_toml_path();

    // Read existing config to preserve unknown sections
    let mut table: toml::Value = if path.exists() {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            format!("Failed to read config.toml: {}", e)
        })?;
        content
            .parse()
            .unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    // Ensure [ui] section exists
    if table.get("ui").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("ui".to_string(), toml::Value::Table(Default::default()));
    }
    let ui = table
        .get_mut("ui")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [ui] section")?;

    ui.insert("theme".to_string(), toml::Value::String(settings.theme.clone()));
    ui.insert("notifications".to_string(), toml::Value::Boolean(settings.notifications_enabled));
    ui.insert("auto_start_daemon".to_string(), toml::Value::Boolean(settings.auto_start_daemon));
    ui.insert("minimize_to_tray".to_string(), toml::Value::Boolean(settings.minimize_to_tray));
    ui.insert("log_level".to_string(), toml::Value::String(settings.log_level.clone()));
    ui.insert("event_retention_days".to_string(), toml::Value::Integer(settings.event_retention_days as i64));

    // Ensure [network_policy] section exists
    if table.get("network_policy").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("network_policy".to_string(), toml::Value::Table(Default::default()));
    }
    let net = table
        .get_mut("network_policy")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [network_policy] section")?;

    net.insert("prompt_timeout_seconds".to_string(), toml::Value::Integer(settings.prompt_timeout_seconds as i64));

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!("Failed to create config directory: {}", e)
        })?;
    }

    let output = toml::to_string_pretty(&table).map_err(|e| {
        format!("Failed to serialize config: {}", e)
    })?;
    std::fs::write(&path, output).map_err(|e| {
        format!("Failed to write config.toml: {}", e)
    })?;

    tracing::info!("Settings saved to {}", path.display());

    // If daemon is connected, notify about config change
    if state.ipc_client.check_connection() {
        tracing::info!("Daemon is connected, config reload will take effect on next query");
    }

    Ok(())
}

// --- Threat Intelligence ---

#[tauri::command]
pub async fn get_feed_status() -> Result<FeedStatus, String> {
    Ok(FeedStatus {
        version: "1.0.0".to_string(),
        last_updated: chrono::Utc::now().to_rfc3339(),
        next_check: (chrono::Utc::now() + chrono::Duration::hours(6)).to_rfc3339(),
        entries_count: 247,
    })
}

#[tauri::command]
pub async fn force_feed_update() -> Result<String, String> {
    tracing::info!("Force feed update (mock)");
    Ok("Feed updated to v1.0.1".to_string())
}

#[tauri::command]
pub async fn get_blocklist_matches() -> Result<Vec<BlocklistAlert>, String> {
    Ok(vec![])
}

#[tauri::command]
pub async fn get_rule_packs() -> Result<Vec<RulePackInfo>, String> {
    Ok(vec![
        RulePackInfo {
            id: "filesystem-safety".to_string(),
            name: "Filesystem Safety".to_string(),
            installed: true,
            version: "1.2.0".to_string(),
            rule_count: 8,
            description: "Rules for safe filesystem operations".to_string(),
        },
        RulePackInfo {
            id: "network-security".to_string(),
            name: "Network Security".to_string(),
            installed: false,
            version: "1.0.0".to_string(),
            rule_count: 12,
            description: "Rules for network access control".to_string(),
        },
        RulePackInfo {
            id: "data-exfiltration".to_string(),
            name: "Data Exfiltration Prevention".to_string(),
            installed: true,
            version: "1.1.0".to_string(),
            rule_count: 6,
            description: "Prevents unauthorized data transfer".to_string(),
        },
    ])
}

#[tauri::command]
pub async fn install_rule_pack(id: String) -> Result<(), String> {
    tracing::info!("Installing rule pack {} (mock)", id);
    Ok(())
}

#[tauri::command]
pub async fn uninstall_rule_pack(id: String) -> Result<(), String> {
    tracing::info!("Uninstalling rule pack {} (mock)", id);
    Ok(())
}

#[tauri::command]
pub async fn get_ioc_stats() -> Result<IoCStats, String> {
    Ok(IoCStats {
        network: 45,
        file: 128,
        behavioral: 34,
        total: 207,
        last_updated: chrono::Utc::now().to_rfc3339(),
    })
}

#[tauri::command]
pub async fn get_telemetry_status() -> Result<TelemetryStatus, String> {
    Ok(TelemetryStatus {
        enabled: false,
        last_report: None,
        installation_id: None,
    })
}

#[tauri::command]
pub async fn toggle_telemetry(enabled: bool) -> Result<(), String> {
    tracing::info!("Telemetry toggled to {} (mock)", enabled);
    Ok(())
}

#[tauri::command]
pub async fn get_telemetry_preview() -> Result<TelemetryPreview, String> {
    Ok(TelemetryPreview {
        categories: vec![
            "Blocklist match counts".to_string(),
            "Anomaly score distributions".to_string(),
            "IoC match rates by category".to_string(),
            "Kill chain detection triggers".to_string(),
            "Scanner finding categories".to_string(),
        ],
        description: "All data is anonymous and aggregated. No file paths, server names, API keys, or personal information is collected.".to_string(),
    })
}

#[tauri::command]
pub async fn check_server_reputation(name: String) -> Result<ReputationResult, String> {
    Ok(ReputationResult {
        server_name: name,
        clean: true,
        matches: vec![],
    })
}

// --- Network Extension ---

#[tauri::command]
pub async fn get_network_extension_status() -> Result<NetworkExtensionStatus, String> {
    Ok(NetworkExtensionStatus {
        loaded: true,
        filter_active: true,
        dns_active: true,
        filtering_count: 847,
        mock_mode: true,
    })
}

#[tauri::command]
pub async fn activate_network_extension() -> Result<String, String> {
    tracing::info!("Activating network extension (mock)");
    Ok("Network extension activated successfully (mock mode)".to_string())
}

#[tauri::command]
pub async fn deactivate_network_extension() -> Result<String, String> {
    tracing::info!("Deactivating network extension (mock)");
    Ok("Network extension deactivated".to_string())
}

#[tauri::command]
pub async fn get_network_settings() -> Result<NetworkSettings, String> {
    Ok(NetworkSettings {
        filter_enabled: true,
        dns_enabled: true,
        filter_all_processes: false,
        default_action: "prompt".to_string(),
        prompt_timeout: 30,
        block_private_ranges: false,
        block_doh: true,
        log_dns: true,
    })
}

#[tauri::command]
pub async fn update_network_settings(settings: NetworkSettings) -> Result<(), String> {
    tracing::info!("Updating network settings: filter_enabled={}, dns_enabled={} (mock)", settings.filter_enabled, settings.dns_enabled);
    Ok(())
}

// --- Network Connection Log ---

#[tauri::command]
pub async fn get_network_connections(limit: u32) -> Result<Vec<NetworkConnectionEvent>, String> {
    let now = chrono::Utc::now();
    let mock_connections: Vec<NetworkConnectionEvent> = (0..limit.min(20))
        .map(|i| {
            let (action, reason) = match i % 5 {
                0 => ("blocked", "IoC match: known C2 domain"),
                1 => ("prompted", "Destination unknown to server profile"),
                _ => ("allowed", "Rule 'allow_https': HTTPS traffic allowed"),
            };
            let (dest_ip, dest_domain, port, protocol, tls) = match i % 4 {
                0 => ("93.184.216.34", Some("example.com"), 443u16, "tcp", true),
                1 => ("140.82.121.4", Some("api.github.com"), 443, "tcp", true),
                2 => ("8.8.8.8", None, 53, "udp", false),
                _ => ("172.217.14.206", Some("googleapis.com"), 443, "tcp", true),
            };
            let server = match i % 3 {
                0 => Some("filesystem"),
                1 => Some("github"),
                _ => Some("everything"),
            };
            NetworkConnectionEvent {
                id: format!("net-{}", 2000 + i),
                timestamp: (now - chrono::Duration::seconds(i as i64 * 45))
                    .to_rfc3339(),
                pid: 10000 + (i % 5),
                process_name: server.unwrap_or("unknown").to_string(),
                server_name: server.map(|s| s.to_string()),
                destination_ip: dest_ip.to_string(),
                destination_port: port,
                destination_domain: dest_domain.map(|d| d.to_string()),
                protocol: protocol.to_string(),
                tls,
                action: action.to_string(),
                reason: reason.to_string(),
                rule: if action == "allowed" {
                    Some("allow_https".to_string())
                } else {
                    None
                },
                ioc_match: action == "blocked",
                anomaly_score: if i % 5 == 1 { Some(0.72) } else { None },
                behavioral: if i % 5 == 1 {
                    Some("Server has never networked before".to_string())
                } else {
                    None
                },
                kill_chain: if action == "blocked" {
                    Some("C2 Communication".to_string())
                } else {
                    None
                },
                bytes_sent: (i as u64 + 1) * 256,
                bytes_received: (i as u64 + 1) * 1024,
                duration_ms: (i as u64 + 1) * 50,
            }
        })
        .collect();
    Ok(mock_connections)
}

#[tauri::command]
pub async fn get_network_summary() -> Result<NetworkSummaryData, String> {
    Ok(NetworkSummaryData {
        total_allowed: 47,
        total_blocked: 2,
        total_prompted: 1,
        top_destinations: vec![
            DestinationCount {
                destination: "api.github.com".to_string(),
                count: 18,
            },
            DestinationCount {
                destination: "googleapis.com".to_string(),
                count: 12,
            },
            DestinationCount {
                destination: "example.com".to_string(),
                count: 8,
            },
            DestinationCount {
                destination: "cdn.jsdelivr.net".to_string(),
                count: 5,
            },
            DestinationCount {
                destination: "registry.npmjs.org".to_string(),
                count: 4,
            },
        ],
        period: "last_24h".to_string(),
    })
}

#[tauri::command]
pub async fn get_network_traffic_by_server() -> Result<Vec<ServerTrafficData>, String> {
    Ok(vec![
        ServerTrafficData {
            server_name: "filesystem".to_string(),
            total_connections: 15,
            connections_allowed: 14,
            connections_blocked: 1,
            connections_prompted: 0,
            bytes_sent: 4096,
            bytes_received: 32768,
            unique_destinations: 3,
            period: "last_24h".to_string(),
        },
        ServerTrafficData {
            server_name: "github".to_string(),
            total_connections: 28,
            connections_allowed: 27,
            connections_blocked: 0,
            connections_prompted: 1,
            bytes_sent: 12288,
            bytes_received: 98304,
            unique_destinations: 5,
            period: "last_24h".to_string(),
        },
        ServerTrafficData {
            server_name: "everything".to_string(),
            total_connections: 7,
            connections_allowed: 6,
            connections_blocked: 1,
            connections_prompted: 0,
            bytes_sent: 2048,
            bytes_received: 8192,
            unique_destinations: 4,
            period: "last_24h".to_string(),
        },
    ])
}

#[tauri::command]
pub async fn export_network_log(format: String, range: String) -> Result<String, String> {
    let home = dirs::home_dir().unwrap_or_default();
    let filename = format!(
        "clawdefender-network-log-{}.{}",
        range,
        if format == "csv" { "csv" } else { "json" }
    );
    let path = home.join(".clawdefender/exports").join(&filename);
    tracing::info!(
        "Exporting network log as {} for range {} (mock) -> {}",
        format,
        range,
        path.display()
    );
    Ok(path.to_string_lossy().to_string())
}

// --- Kill process ---

#[tauri::command]
pub async fn kill_agent_process(pid: u32) -> Result<String, String> {
    // Security: reject system processes and guard against PID 0 (which signals
    // the entire process group) and PID 1 (init/launchd). Use a conservative
    // floor of 500 to exclude core macOS system services.
    if pid < 500 {
        return Err(format!(
            "Refusing to kill PID {} — likely a system process (PID < 500)",
            pid
        ));
    }

    // Security: guard against u32-to-i32 overflow. PIDs above i32::MAX are invalid.
    let pid_i32 = i32::try_from(pid).map_err(|_| {
        format!("Invalid PID {} — exceeds maximum valid process ID", pid)
    })?;

    // Check the process exists before attempting to kill it
    let exists = unsafe { libc::kill(pid_i32, 0) } == 0;
    if !exists {
        return Err(format!("Process {} does not exist or is not accessible", pid));
    }

    tracing::info!("Sending SIGTERM to PID {}", pid);
    let term_result = unsafe { libc::kill(pid_i32, libc::SIGTERM) };
    if term_result != 0 {
        return Err(format!(
            "Failed to send SIGTERM to PID {}: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }

    // Wait up to 3 seconds for the process to exit
    for _ in 0..6 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let still_alive = unsafe { libc::kill(pid_i32, 0) } == 0;
        if !still_alive {
            return Ok(format!("Process {} terminated successfully (SIGTERM)", pid));
        }
    }

    // Process still alive after 3 seconds — escalate to SIGKILL
    tracing::warn!("PID {} did not exit after SIGTERM, sending SIGKILL", pid);
    let kill_result = unsafe { libc::kill(pid_i32, libc::SIGKILL) };
    if kill_result != 0 {
        return Err(format!(
            "Failed to send SIGKILL to PID {}: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }

    // Brief wait to confirm SIGKILL took effect
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let still_alive = unsafe { libc::kill(pid_i32, 0) } == 0;
    if still_alive {
        Err(format!("Process {} could not be killed", pid))
    } else {
        Ok(format!("Process {} killed (SIGKILL after SIGTERM timeout)", pid))
    }
}

fn resolve_config_path(client: &str) -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;

    let candidates: Vec<std::path::PathBuf> = match client {
        "claude" => vec![
            home.join("Library/Application Support/Claude/config.json"),
            home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        ],
        "cursor" => vec![home.join(".cursor/mcp.json")],
        "vscode" => vec![home.join(".vscode/mcp.json")],
        "windsurf" => vec![home.join(".codeium/windsurf/mcp_config.json")],
        other => return Err(format!("Unknown client: {}", other)),
    };

    candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .ok_or_else(|| {
            format!(
                "Config file not found for client '{}'. Looked in: {}",
                client,
                candidates
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

fn resolve_clawdefender_path() -> String {
    // First try: sidecar binary next to the current executable
    // (In a Tauri app, current_exe is the GUI binary — the CLI sidecar
    //  is in the same directory or a sibling `binaries/` folder.)
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            // Check same directory
            let sibling = exe_dir.join("clawdefender");
            if sibling.exists() {
                return sibling.to_string_lossy().to_string();
            }
            // Check Tauri sidecar binaries directory
            let sidecar = exe_dir.join("binaries").join("clawdefender");
            if sidecar.exists() {
                return sidecar.to_string_lossy().to_string();
            }
        }
    }
    // Fallback: search PATH
    if let Ok(output) = std::process::Command::new("which")
        .arg("clawdefender")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return path;
            }
        }
    }
    // Also check common locations
    let home = std::env::var("HOME").unwrap_or_default();
    let cargo_path = format!("{}/.cargo/bin/clawdefender", home);
    if std::path::Path::new(&cargo_path).exists() {
        return cargo_path;
    }
    "clawdefender".to_string()
}

fn detect_servers_key(config: &serde_json::Value) -> &str {
    if config.get("mcpServers").and_then(|v| v.as_object()).is_some() {
        "mcpServers"
    } else if config.get("servers").and_then(|v| v.as_object()).is_some() {
        "servers"
    } else {
        "mcpServers" // default
    }
}

mod dirs {
    use std::path::PathBuf;
    pub fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn make_audit_event(id: &str, timestamp: &str) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            timestamp: timestamp.to_string(),
            event_type: "proxy".to_string(),
            server_name: "test-server".to_string(),
            tool_name: Some("test_tool".to_string()),
            action: "tools/call".to_string(),
            decision: "allow".to_string(),
            risk_level: "info".to_string(),
            details: "test details".to_string(),
            resource: None,
        }
    }

    // --- kill_agent_process tests ---

    #[tokio::test]
    async fn test_kill_agent_process_rejects_pid_0() {
        let result = kill_agent_process(0).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PID 0"));
    }

    #[tokio::test]
    async fn test_kill_agent_process_rejects_pid_1() {
        let result = kill_agent_process(1).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("system process"));
    }

    #[tokio::test]
    async fn test_kill_agent_process_rejects_low_pid() {
        let result = kill_agent_process(499).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PID < 500"));
    }

    #[tokio::test]
    async fn test_kill_agent_process_nonexistent_pid() {
        // PID 99999 is unlikely to exist
        let result = kill_agent_process(99999).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[tokio::test]
    async fn test_kill_agent_process_rejects_overflow_pid() {
        let result = kill_agent_process(u32::MAX).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("exceeds maximum") || err.contains("system process"));
    }

    // --- read_historical_events tests ---
    // These tests use a shared mutex to serialize HOME env var manipulation,
    // since env vars are process-global and tests run in parallel.

    use std::sync::Mutex as TestMutex;
    static HOME_MUTEX: TestMutex<()> = TestMutex::new(());

    #[test]
    fn test_read_historical_events_with_temp_file() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let audit_dir = tmp.path().join(".local/share/clawdefender");
        std::fs::create_dir_all(&audit_dir).unwrap();

        let mut file = std::fs::File::create(audit_dir.join("audit.jsonl")).unwrap();
        for i in 0..5 {
            let record = serde_json::json!({
                "timestamp": format!("2025-01-15T10:3{}:00Z", i),
                "source": "proxy",
                "event_summary": format!("Event {}", i),
                "action_taken": "allowed",
                "server_name": "test-server",
                "policy_action": "allow",
                "classification": "info"
            });
            writeln!(file, "{}", record).unwrap();
        }
        file.flush().unwrap();

        let events = read_historical_events(10, &[]);
        assert_eq!(events.len(), 5);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_read_historical_events_empty_file() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let audit_dir = tmp.path().join(".local/share/clawdefender");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::File::create(audit_dir.join("audit.jsonl")).unwrap();

        let events = read_historical_events(10, &[]);
        assert!(events.is_empty());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_read_historical_events_missing_file() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let events = read_historical_events(10, &[]);
        assert!(events.is_empty());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_read_historical_events_deduplication() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let audit_dir = tmp.path().join(".local/share/clawdefender");
        std::fs::create_dir_all(&audit_dir).unwrap();

        let mut file = std::fs::File::create(audit_dir.join("audit.jsonl")).unwrap();
        for i in 0..3 {
            let record = serde_json::json!({
                "timestamp": format!("2025-01-15T10:3{}:00Z", i),
                "source": "proxy",
                "event_summary": format!("Event {}", i),
                "action_taken": "allowed",
            });
            writeln!(file, "{}", record).unwrap();
        }
        file.flush().unwrap();

        let existing = vec![make_audit_event("evt-100000", "2025-01-15T10:30:00Z")];

        let events = read_historical_events(10, &existing);
        assert_eq!(events.len(), 2);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    // --- sanitize_rule_key tests ---

    #[test]
    fn test_sanitize_rule_key() {
        assert_eq!(sanitize_rule_key("Block Sensitive Files"), "block-sensitive-files");
        assert_eq!(sanitize_rule_key("  spaces  "), "spaces");
        assert_eq!(sanitize_rule_key("UPPER_case"), "upper_case");
        assert_eq!(sanitize_rule_key("special!@#chars"), "specialchars");
    }

    #[test]
    fn test_sanitize_rule_key_empty() {
        assert_eq!(sanitize_rule_key(""), "");
        assert_eq!(sanitize_rule_key("!!!"), "");
    }

    // --- policy action conversion tests ---

    #[test]
    fn test_frontend_action_to_toml() {
        assert_eq!(frontend_action_to_toml("deny"), "block");
        assert_eq!(frontend_action_to_toml("audit"), "log");
        assert_eq!(frontend_action_to_toml("allow"), "allow");
        assert_eq!(frontend_action_to_toml("prompt"), "prompt");
    }

    #[test]
    fn test_toml_action_to_frontend() {
        assert_eq!(toml_action_to_frontend("block"), "deny");
        assert_eq!(toml_action_to_frontend("log"), "audit");
        assert_eq!(toml_action_to_frontend("allow"), "allow");
        assert_eq!(toml_action_to_frontend("prompt"), "prompt");
    }

    // --- detect_servers_key tests ---

    #[test]
    fn test_detect_servers_key_mcp_servers() {
        let config = serde_json::json!({"mcpServers": {"a": {}}});
        assert_eq!(detect_servers_key(&config), "mcpServers");
    }

    #[test]
    fn test_detect_servers_key_servers() {
        let config = serde_json::json!({"servers": {"a": {}}});
        assert_eq!(detect_servers_key(&config), "servers");
    }

    #[test]
    fn test_detect_servers_key_default() {
        let config = serde_json::json!({"other": "stuff"});
        assert_eq!(detect_servers_key(&config), "mcpServers");
    }
}
