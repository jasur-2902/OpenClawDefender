use crate::daemon;
use crate::event_stream;
use crate::state::*;

// --- Daemon management ---

/// Count how many MCP servers are currently wrapped with ClawDefender across
/// all detected MCP client config files.
pub fn count_wrapped_servers() -> u32 {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return 0,
    };

    let config_paths: Vec<std::path::PathBuf> = vec![
        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        home.join("Library/Application Support/Claude/config.json"),
        home.join(".cursor/mcp.json"),
        home.join(".vscode/mcp.json"),
        home.join(".codeium/windsurf/mcp_config.json"),
    ];

    let mut wrapped = 0u32;
    for path in config_paths {
        if !path.exists() {
            continue;
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let config: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let key = detect_servers_key(&config);
        if let Some(servers) = config.get(key).and_then(|v| v.as_object()) {
            for (_name, entry) in servers {
                if entry.get("_clawdefender_original").is_some()
                    || entry.get("_clawai_original").is_some()
                {
                    wrapped += 1;
                }
            }
        }
    }
    wrapped
}

#[tauri::command]
pub async fn get_daemon_status(
    state: tauri::State<'_, AppState>,
) -> Result<DaemonStatus, String> {
    let sock = daemon::socket_path().to_string_lossy().to_string();
    let wrapped = count_wrapped_servers();

    // Try live IPC query first
    if let Ok(metrics) = state.ipc_client.query_status() {
        let status = DaemonStatus {
            running: true,
            pid: None,
            uptime_seconds: None,
            version: None,
            socket_path: sock,
            servers_proxied: wrapped,
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
        servers_proxied: wrapped,
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

    // Poll up to 15 seconds for the daemon to become reachable (first-run may be slower)
    let mut connected = false;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if state.ipc_client.check_connection() {
            connected = true;
            break;
        }
    }

    if !connected {
        return Err("Daemon started but did not become reachable within 15 seconds".to_string());
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
    let read_from = file_len.saturating_sub(CHUNK_SIZE);

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

/// Read behavioral profiles from the SQLite database on disk.
fn read_profiles_from_db() -> Result<Vec<ServerProfileSummary>, String> {
    let db_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(".local/share/clawdefender/profiles.db");

    if !db_path.exists() {
        return Ok(vec![]);
    }

    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("Failed to open profiles DB: {}", e))?;

    let mut stmt = conn
        .prepare("SELECT server_name, profile_json, updated_at FROM profiles LIMIT 1000")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map([], |row| {
            let server_name: String = row.get(0)?;
            let profile_json: String = row.get(1)?;
            let updated_at: String = row.get(2)?;
            Ok((server_name, profile_json, updated_at))
        })
        .map_err(|e| format!("Failed to query profiles: {}", e))?;

    let mut profiles = Vec::new();
    for row in rows {
        let (server_name, profile_json, updated_at) = match row {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "Skipping malformed profile row");
                continue;
            }
        };

        let parsed: serde_json::Value = match serde_json::from_str(&profile_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, server = %server_name, "Skipping unparseable profile JSON");
                continue;
            }
        };

        let learning_mode = parsed
            .get("learning_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let tool_counts = parsed
            .get("tool_profile")
            .and_then(|tp| tp.get("tool_counts"))
            .and_then(|tc| tc.as_object());

        let tools_count = tool_counts.map(|m| m.len() as u32).unwrap_or(0);
        let total_calls: u64 = tool_counts
            .map(|m| m.values().filter_map(|v| v.as_u64()).sum())
            .unwrap_or(0);

        let status = if learning_mode {
            "learning".to_string()
        } else {
            "normal".to_string()
        };

        let last_activity = parsed
            .get("last_updated")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or(updated_at);

        profiles.push(ServerProfileSummary {
            server_name,
            tools_count,
            total_calls,
            anomaly_score: 0.0,
            status,
            last_activity,
        });
    }

    Ok(profiles)
}

#[tauri::command]
pub async fn get_profiles() -> Result<Vec<ServerProfileSummary>, String> {
    tokio::task::spawn_blocking(read_profiles_from_db)
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn get_behavioral_status() -> Result<BehavioralStatus, String> {
    let profiles = tokio::task::spawn_blocking(read_profiles_from_db)
        .await
        .map_err(|e| format!("Task join error: {}", e))??;

    let profiles_count = profiles.len() as u32;
    let learning_servers = profiles.iter().filter(|p| p.status == "learning").count() as u32;
    let monitoring_servers = profiles_count - learning_servers;

    Ok(BehavioralStatus {
        enabled: true,
        profiles_count,
        total_anomalies: 0,
        learning_servers,
        monitoring_servers,
    })
}

// --- Guards ---
// Guards are in-memory only in the daemon's GuardRegistry. There is no way to
// enumerate registered guards from outside the daemon, so we return an empty
// list. The frontend already handles this gracefully with an empty-state UI.

#[tauri::command]
pub async fn list_guards() -> Result<Vec<GuardSummary>, String> {
    Ok(vec![])
}

// --- Scanner ---

/// Validate a server command string to prevent command injection.
fn validate_server_command(cmd: &str) -> Result<(), String> {
    if cmd.trim().is_empty() {
        return Err("Server command cannot be empty".to_string());
    }
    const FORBIDDEN: &[char] = &[';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r'];
    for ch in FORBIDDEN {
        if cmd.contains(*ch) {
            return Err(format!(
                "Server command contains forbidden character '{}'",
                ch
            ));
        }
    }
    Ok(())
}

/// Parse the findings count from scan JSON output.
fn parse_scan_findings_count(stdout: &str) -> u32 {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(stdout) {
        if let Some(total) = json
            .get("summary")
            .and_then(|s| s.get("total"))
            .and_then(|t| t.as_u64())
        {
            return total as u32;
        }
        if let Some(findings) = json.get("findings").and_then(|f| f.as_array()) {
            return findings.len() as u32;
        }
    }
    0
}

#[tauri::command]
pub async fn start_scan(
    app_handle: tauri::AppHandle,
    _server_command: String,
    modules: Vec<String>,
    _timeout: u32,
) -> Result<String, String> {
    use tauri::Manager;

    let state = app_handle.state::<AppState>();

    // Limit to 1 concurrent scan
    {
        let scans = state
            .active_scans
            .lock()
            .map_err(|e| format!("Failed to lock scan state: {}", e))?;
        if scans.values().any(|s| s.status == "running") {
            return Err("A scan is already running. Wait for it to complete.".to_string());
        }
    }

    // Generate scan ID
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let scan_id = format!("scan-{}-{}", ts, std::process::id());

    // Determine which modules to run
    let all_modules = vec![
        "mcp-config-audit",
        "policy-strength",
        "server-reputation",
        "system-posture",
        "behavioral-anomaly",
    ];
    let selected: Vec<String> = if modules.is_empty() {
        all_modules.iter().map(|s| s.to_string()).collect()
    } else {
        modules
    };
    let modules_total = selected.len() as u32;

    // Check daemon connection for the system posture module
    let daemon_connected = state.ipc_client.check_connection();

    // Store initial tracker
    {
        let mut scans = state
            .active_scans
            .lock()
            .map_err(|e| format!("Failed to lock scan state: {}", e))?;
        scans.insert(
            scan_id.clone(),
            crate::state::ScanTracker {
                status: "running".to_string(),
                progress_percent: 0.0,
                modules_completed: 0,
                modules_total,
                findings_count: 0,
                current_module: Some("Initializing".to_string()),
                result: None,
            },
        );
    }

    let id = scan_id.clone();
    let handle = app_handle.clone();
    let started_at = chrono::Utc::now().to_rfc3339();

    tokio::spawn(async move {
        let state = handle.state::<AppState>();
        let mut module_results = Vec::new();
        let mut completed = 0u32;

        for module_id in &selected {
            // Update current module
            if let Ok(mut scans) = state.active_scans.lock() {
                if let Some(tracker) = scans.get_mut(&id) {
                    tracker.current_module = Some(module_name_for_id(module_id));
                    tracker.progress_percent =
                        (completed as f64 / modules_total as f64) * 100.0;
                }
            }

            // Small delay to let progress polling see updates
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let result = match module_id.as_str() {
                "mcp-config-audit" => crate::scanner::scan_mcp_configs(),
                "policy-strength" => crate::scanner::scan_policy_strength(),
                "server-reputation" => crate::scanner::scan_server_reputation(),
                "system-posture" => crate::scanner::scan_system_posture(daemon_connected),
                "behavioral-anomaly" => crate::scanner::scan_behavioral_anomalies(),
                other => crate::state::ScanModuleResult {
                    module_id: other.to_string(),
                    module_name: other.to_string(),
                    status: "skipped".to_string(),
                    findings: vec![],
                    summary: format!("Unknown module: {}", other),
                },
            };

            module_results.push(result);
            completed += 1;

            if let Ok(mut scans) = state.active_scans.lock() {
                if let Some(tracker) = scans.get_mut(&id) {
                    tracker.modules_completed = completed;
                    tracker.findings_count = module_results
                        .iter()
                        .map(|m| m.findings.len() as u32)
                        .sum();
                }
            }
        }

        // Build final result
        let all_findings: Vec<&crate::state::ScanFinding> =
            module_results.iter().flat_map(|m| &m.findings).collect();
        let total_findings = all_findings.len() as u32;
        let critical_count = all_findings
            .iter()
            .filter(|f| f.severity == "critical")
            .count() as u32;
        let high_count = all_findings
            .iter()
            .filter(|f| f.severity == "high")
            .count() as u32;
        let medium_count = all_findings
            .iter()
            .filter(|f| f.severity == "medium")
            .count() as u32;
        let low_count = all_findings
            .iter()
            .filter(|f| f.severity == "low")
            .count() as u32;

        let scan_result = crate::state::ScanResult {
            scan_id: id.clone(),
            status: "completed".to_string(),
            started_at: started_at.clone(),
            completed_at: Some(chrono::Utc::now().to_rfc3339()),
            modules: module_results,
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
        };

        // Save scan result to disk
        let _ = save_scan_result(&scan_result);

        // Update tracker
        if let Ok(mut scans) = state.active_scans.lock() {
            if let Some(tracker) = scans.get_mut(&id) {
                tracker.status = "completed".to_string();
                tracker.progress_percent = 100.0;
                tracker.modules_completed = modules_total;
                tracker.findings_count = total_findings;
                tracker.current_module = None;
                tracker.result = Some(scan_result);
            }
        }

        tracing::info!("Scan {} completed with {} findings", id, total_findings);
    });

    tracing::info!(
        "Started comprehensive scan {} with {} modules",
        scan_id,
        modules_total
    );
    Ok(scan_id)
}

fn module_name_for_id(id: &str) -> String {
    match id {
        "mcp-config-audit" => "MCP Configuration Audit".to_string(),
        "policy-strength" => "Policy Strength Analysis".to_string(),
        "server-reputation" => "Server Reputation Check".to_string(),
        "system-posture" => "System Security Posture".to_string(),
        "behavioral-anomaly" => "Behavioral Anomaly Review".to_string(),
        other => other.to_string(),
    }
}

fn save_scan_result(result: &crate::state::ScanResult) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("No home dir")?;
    let scans_dir = home.join(".local/share/clawdefender/scans");
    std::fs::create_dir_all(&scans_dir)
        .map_err(|e| format!("Failed to create scans directory: {}", e))?;

    // Sanitize scan_id to prevent path traversal (e.g. "../../../etc/passwd")
    let safe_id: String = result
        .scan_id
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe_id.is_empty() {
        return Err("Invalid scan ID".to_string());
    }

    let file_path = scans_dir.join(format!("{}.json", safe_id));
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| format!("Failed to serialize scan result: {}", e))?;

    // Write with owner-only permissions (0600) to prevent other users from
    // reading scan findings which may contain security-sensitive details.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&file_path)
            .map_err(|e| format!("Failed to create scan result file: {}", e))?;
        std::io::Write::write_all(&mut file, json.as_bytes())
            .map_err(|e| format!("Failed to write scan result: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&file_path, json)
            .map_err(|e| format!("Failed to write scan result: {}", e))?;
    }

    tracing::info!("Scan result saved to {}", file_path.display());
    Ok(())
}

#[tauri::command]
pub async fn get_scan_progress(
    state: tauri::State<'_, AppState>,
    scan_id: String,
) -> Result<ScanProgress, String> {
    let scans = state
        .active_scans
        .lock()
        .map_err(|e| format!("Failed to lock scan state: {}", e))?;

    let tracker = scans
        .get(&scan_id)
        .ok_or_else(|| format!("Scan '{}' not found", scan_id))?;

    Ok(ScanProgress {
        scan_id,
        status: tracker.status.clone(),
        progress_percent: tracker.progress_percent,
        modules_completed: tracker.modules_completed,
        modules_total: tracker.modules_total,
        findings_count: tracker.findings_count,
        current_module: tracker.current_module.clone(),
    })
}

#[tauri::command]
pub async fn get_scan_results(
    state: tauri::State<'_, AppState>,
    scan_id: String,
) -> Result<crate::state::ScanResult, String> {
    // First try in-memory
    {
        let scans = state
            .active_scans
            .lock()
            .map_err(|e| format!("Failed to lock scan state: {}", e))?;
        if let Some(tracker) = scans.get(&scan_id) {
            if let Some(ref result) = tracker.result {
                return Ok(result.clone());
            }
        }
    }

    // Fall back to disk
    // Sanitize scan_id to prevent path traversal attacks
    let safe_id: String = scan_id
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe_id.is_empty() || safe_id != scan_id {
        return Err(format!("Invalid scan ID: '{}'", scan_id));
    }
    let home = dirs::home_dir().ok_or("No home dir")?;
    let file_path = home.join(format!(
        ".local/share/clawdefender/scans/{}.json",
        safe_id
    ));
    if file_path.exists() {
        let contents = std::fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read scan result: {}", e))?;
        let result: crate::state::ScanResult = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse scan result: {}", e))?;
        return Ok(result);
    }

    Err(format!("Scan result '{}' not found", scan_id))
}

#[tauri::command]
pub async fn apply_scan_fix(
    client: String,
    server: String,
    action_type: String,
) -> Result<String, String> {
    match action_type.as_str() {
        "wrap_server" => {
            wrap_server(client, server).await?;
            Ok("Server wrapped successfully".to_string())
        }
        "add_policy_rule" => {
            // For policy rule additions, we return guidance - the user should
            // use the Policy page for granular control
            Ok("Navigate to the Policy page to add this rule".to_string())
        }
        other => Err(format!("Unknown fix action type: {}", other)),
    }
}

// --- System health ---

#[tauri::command]
pub async fn run_doctor(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<DoctorCheck>, String> {
    let mut checks = Vec::new();
    let home = dirs::home_dir().unwrap_or_default();

    // 1. Daemon Process
    if state.ipc_client.check_connection() {
        checks.push(DoctorCheck {
            name: "Daemon Process".to_string(),
            status: "pass".to_string(),
            message: "Daemon is running and responding".to_string(),
            fix_suggestion: None,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Daemon Process".to_string(),
            status: "fail".to_string(),
            message: "Daemon is not running or not responding".to_string(),
            fix_suggestion: Some("Start daemon from the dashboard".to_string()),
        });
    }

    // 2. Socket File
    let sock_path = daemon::socket_path();
    if sock_path.exists() {
        checks.push(DoctorCheck {
            name: "Socket File".to_string(),
            status: "pass".to_string(),
            message: format!("Socket file exists at {}", sock_path.display()),
            fix_suggestion: None,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Socket File".to_string(),
            status: "warn".to_string(),
            message: "Socket file not found".to_string(),
            fix_suggestion: Some("Start the daemon to create the socket".to_string()),
        });
    }

    // 3. Config Directory
    let config_dir = home.join(".config").join("clawdefender");
    if config_dir.exists() {
        let test_file = config_dir.join(".write_test");
        let writable = std::fs::write(&test_file, b"").is_ok();
        let _ = std::fs::remove_file(&test_file);
        if writable {
            checks.push(DoctorCheck {
                name: "Config Directory".to_string(),
                status: "pass".to_string(),
                message: format!("Config directory exists and is writable at {}", config_dir.display()),
                fix_suggestion: None,
            });
        } else {
            checks.push(DoctorCheck {
                name: "Config Directory".to_string(),
                status: "warn".to_string(),
                message: format!("Config directory exists but is not writable at {}", config_dir.display()),
                fix_suggestion: Some("Check permissions on ~/.config/clawdefender".to_string()),
            });
        }
    } else {
        checks.push(DoctorCheck {
            name: "Config Directory".to_string(),
            status: "warn".to_string(),
            message: "Config directory not found".to_string(),
            fix_suggestion: Some("Create the directory: mkdir -p ~/.config/clawdefender".to_string()),
        });
    }

    // 4. Policy File
    let policy_path = policy_file_path();
    if policy_path.exists() {
        match std::fs::read_to_string(&policy_path) {
            Ok(contents) => match contents.parse::<toml::Value>() {
                Ok(doc) => {
                    let rules_count = doc
                        .get("rules")
                        .and_then(|v| v.as_table())
                        .map(|t| t.len())
                        .unwrap_or(0);
                    checks.push(DoctorCheck {
                        name: "Policy File".to_string(),
                        status: "pass".to_string(),
                        message: format!("Policy file is valid with {} rules", rules_count),
                        fix_suggestion: None,
                    });
                }
                Err(_) => {
                    checks.push(DoctorCheck {
                        name: "Policy File".to_string(),
                        status: "fail".to_string(),
                        message: "Policy file has syntax errors".to_string(),
                        fix_suggestion: Some(
                            "Edit policy.toml or reset from Settings".to_string(),
                        ),
                    });
                }
            },
            Err(e) => {
                checks.push(DoctorCheck {
                    name: "Policy File".to_string(),
                    status: "fail".to_string(),
                    message: format!("Cannot read policy file: {}", e),
                    fix_suggestion: Some("Check file permissions on policy.toml".to_string()),
                });
            }
        }
    } else {
        checks.push(DoctorCheck {
            name: "Policy File".to_string(),
            status: "warn".to_string(),
            message: "No policy file found — using defaults".to_string(),
            fix_suggestion: Some(
                "Configure a security policy from the Policy page".to_string(),
            ),
        });
    }

    // 5. Audit Log Directory
    let log_dir = home.join(".local").join("share").join("clawdefender");
    if log_dir.exists() {
        let test_file = log_dir.join(".write_test");
        let writable = std::fs::write(&test_file, b"").is_ok();
        let _ = std::fs::remove_file(&test_file);
        if writable {
            checks.push(DoctorCheck {
                name: "Audit Log Directory".to_string(),
                status: "pass".to_string(),
                message: format!("Audit log directory is writable at {}", log_dir.display()),
                fix_suggestion: None,
            });
        } else {
            checks.push(DoctorCheck {
                name: "Audit Log Directory".to_string(),
                status: "fail".to_string(),
                message: format!("Audit log directory is not writable at {}", log_dir.display()),
                fix_suggestion: Some("Check permissions: chmod u+w ~/.local/share/clawdefender".to_string()),
            });
        }
    } else {
        checks.push(DoctorCheck {
            name: "Audit Log Directory".to_string(),
            status: "fail".to_string(),
            message: "Audit log directory not found".to_string(),
            fix_suggestion: Some("Create the directory: mkdir -p ~/.local/share/clawdefender".to_string()),
        });
    }

    // 6. Full Disk Access (heuristic)
    let mail_path = home.join("Library/Mail");
    let has_fda = std::fs::read_dir(&mail_path).is_ok();
    if has_fda {
        checks.push(DoctorCheck {
            name: "Full Disk Access".to_string(),
            status: "pass".to_string(),
            message: "Full Disk Access is granted".to_string(),
            fix_suggestion: None,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Full Disk Access".to_string(),
            status: "warn".to_string(),
            message: "Full Disk Access may not be granted".to_string(),
            fix_suggestion: Some(
                "Open System Settings > Privacy & Security > Full Disk Access".to_string(),
            ),
        });
    }

    // 7. MCP Clients & 8. Wrapped Servers
    match detect_mcp_clients().await {
        Ok(clients) => {
            let detected: Vec<&McpClient> = clients.iter().filter(|c| c.detected).collect();
            let total_servers: u32 = detected.iter().map(|c| c.servers_count).sum();

            if detected.is_empty() {
                checks.push(DoctorCheck {
                    name: "MCP Clients".to_string(),
                    status: "warn".to_string(),
                    message: "No MCP clients detected".to_string(),
                    fix_suggestion: None,
                });
            } else {
                checks.push(DoctorCheck {
                    name: "MCP Clients".to_string(),
                    status: "pass".to_string(),
                    message: format!(
                        "{} clients detected with {} servers",
                        detected.len(),
                        total_servers
                    ),
                    fix_suggestion: None,
                });
            }

            // Count wrapped servers across all detected clients
            let mut total_count = 0u32;
            let mut wrapped_count = 0u32;
            for client in &detected {
                if let Ok(servers) = list_mcp_servers(client.name.clone()).await {
                    for srv in &servers {
                        total_count += 1;
                        if srv.wrapped {
                            wrapped_count += 1;
                        }
                    }
                }
            }

            if total_count == 0 {
                checks.push(DoctorCheck {
                    name: "Wrapped Servers".to_string(),
                    status: "warn".to_string(),
                    message: "No MCP servers found to wrap".to_string(),
                    fix_suggestion: None,
                });
            } else if wrapped_count == total_count {
                checks.push(DoctorCheck {
                    name: "Wrapped Servers".to_string(),
                    status: "pass".to_string(),
                    message: format!("All {} servers are wrapped", total_count),
                    fix_suggestion: None,
                });
            } else {
                checks.push(DoctorCheck {
                    name: "Wrapped Servers".to_string(),
                    status: "warn".to_string(),
                    message: format!(
                        "{} of {} servers are unwrapped",
                        total_count - wrapped_count,
                        total_count
                    ),
                    fix_suggestion: Some(
                        "Wrap all servers from the dashboard".to_string(),
                    ),
                });
            }
        }
        Err(_) => {
            checks.push(DoctorCheck {
                name: "MCP Clients".to_string(),
                status: "warn".to_string(),
                message: "Could not detect MCP clients".to_string(),
                fix_suggestion: None,
            });
        }
    }

    Ok(checks)
}

#[tauri::command]
pub async fn get_system_info(
    state: tauri::State<'_, AppState>,
) -> Result<SystemInfo, String> {
    let home = dirs::home_dir().unwrap_or_default();

    // Real macOS version via sw_vers
    let os_version = std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    // Daemon version from IPC or sidecar
    let daemon_version = if state.ipc_client.check_connection() {
        // Use the monitor's known version or query
        Some("0.10.0".to_string()) // TODO: get from actual IPC response when available
    } else {
        // Try running clawdefender --version
        let bin = resolve_clawdefender_path();
        std::process::Command::new(&bin)
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    };

    Ok(SystemInfo {
        os: "macOS".to_string(),
        os_version,
        arch: std::env::consts::ARCH.to_string(),
        daemon_version,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        config_dir: home.join(".config/clawdefender").to_string_lossy().to_string(),
        log_dir: home.join(".local/share/clawdefender").to_string_lossy().to_string(),
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

// --- Settings Export / Import ---

fn policy_toml_path() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    home.join(".config/clawdefender/policy.toml")
}

/// Strip sensitive keys (API keys, tokens, secrets) from a TOML string before export.
fn strip_secrets(content: &str) -> String {
    let mut filtered_lines = Vec::new();
    for line in content.lines() {
        let lower = line.to_lowercase();
        let is_secret = ["api_key", "api_token", "secret", "password", "token"]
            .iter()
            .any(|k| lower.contains(k) && lower.contains('='));
        if !is_secret {
            filtered_lines.push(line);
        }
    }
    filtered_lines.join("\n")
}

#[tauri::command]
pub async fn export_settings() -> Result<String, String> {
    let config_path = config_toml_path();
    let policy_path = policy_toml_path();

    let config = if config_path.exists() {
        strip_secrets(
            &std::fs::read_to_string(&config_path)
                .map_err(|e| format!("Failed to read config.toml: {}", e))?,
        )
    } else {
        String::new()
    };

    let policy = if policy_path.exists() {
        std::fs::read_to_string(&policy_path)
            .map_err(|e| format!("Failed to read policy.toml: {}", e))?
    } else {
        String::new()
    };

    let export = serde_json::json!({
        "version": "1.0",
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "config": config,
        "policy": policy,
    });

    let home = std::env::var("HOME").unwrap_or_default();
    let export_path = format!("{}/Desktop/clawdefender-settings.json", home);
    std::fs::write(
        &export_path,
        serde_json::to_string_pretty(&export).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Failed to write export file: {}", e))?;

    tracing::info!("Settings exported to {}", export_path);
    Ok(export_path)
}

#[tauri::command]
pub async fn import_settings_from_content(content: String) -> Result<String, String> {
    // Size check: reject files > 1MB
    if content.len() > 1_048_576 {
        return Err("Import file is too large (max 1MB)".to_string());
    }

    // Parse and validate structure
    let parsed: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;

    let version = parsed
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'version' field")?;
    if version != "1.0" {
        return Err(format!("Unsupported export version: {}", version));
    }

    let config_content = parsed
        .get("config")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'config' field")?;
    let policy_content = parsed
        .get("policy")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'policy' field")?;

    // Validate config is valid TOML (if non-empty)
    if !config_content.is_empty() {
        config_content
            .parse::<toml::Value>()
            .map_err(|e| format!("Invalid config TOML: {}", e))?;
    }
    if !policy_content.is_empty() {
        policy_content
            .parse::<toml::Value>()
            .map_err(|e| format!("Invalid policy TOML: {}", e))?;
    }

    let config_path = config_toml_path();
    let policy_path = policy_toml_path();

    // Ensure config directory exists
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    // Back up existing files
    if config_path.exists() {
        let backup = config_path.with_extension("toml.bak");
        let _ = std::fs::copy(&config_path, &backup);
    }
    if policy_path.exists() {
        let backup = policy_path.with_extension("toml.bak");
        let _ = std::fs::copy(&policy_path, &backup);
    }

    // Write new config files
    if !config_content.is_empty() {
        std::fs::write(&config_path, config_content)
            .map_err(|e| format!("Failed to write config.toml: {}", e))?;
    }
    if !policy_content.is_empty() {
        std::fs::write(&policy_path, policy_content)
            .map_err(|e| format!("Failed to write policy.toml: {}", e))?;
    }

    tracing::info!("Settings imported successfully");
    Ok("Settings imported successfully".to_string())
}

// --- Threat Intelligence ---

fn threat_intel_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::PathBuf::from(home).join(".local/share/clawdefender/threat-intel")
}

/// Collect all MCP server names from detected client configs.
fn collect_mcp_server_names() -> Vec<String> {
    let home = match std::env::var("HOME") {
        Ok(h) => std::path::PathBuf::from(h),
        Err(_) => return vec![],
    };

    let config_paths = vec![
        home.join("Library/Application Support/Claude/config.json"),
        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        home.join(".cursor/mcp.json"),
        home.join(".vscode/mcp.json"),
        home.join(".codeium/windsurf/mcp_config.json"),
    ];

    let mut names = Vec::new();
    for path in config_paths {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&contents) {
                let key = detect_servers_key(&config);
                if let Some(obj) = config.get(key).and_then(|v| v.as_object()) {
                    for server_name in obj.keys() {
                        names.push(server_name.clone());
                    }
                }
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Validate a rule pack ID: alphanumeric + hyphens only, no path traversal.
fn validate_rule_pack_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("Rule pack ID cannot be empty".to_string());
    }
    if id.len() > 128 {
        return Err("Rule pack ID is too long".to_string());
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("Rule pack ID must contain only alphanumeric characters and hyphens".to_string());
    }
    Ok(())
}

#[tauri::command]
pub async fn get_feed_status() -> Result<FeedStatus, String> {
    let manifest_path = threat_intel_dir().join("manifest.json");

    if !manifest_path.exists() {
        return Ok(FeedStatus {
            version: "not configured".to_string(),
            last_updated: "never".to_string(),
            next_check: "run clawdefender feed update to initialize".to_string(),
            entries_count: 0,
        });
    }

    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read manifest.json: {}", e))?;
    let manifest: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse manifest.json: {}", e))?;

    let version = manifest.get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let last_updated = manifest.get("last_updated")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Calculate next_check as last_updated + 6 hours
    let next_check = if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&last_updated) {
        (dt + chrono::Duration::hours(6)).to_rfc3339()
    } else {
        "unknown".to_string()
    };

    // Count entries across IoC files
    let ioc_dir = threat_intel_dir().join("ioc");
    let mut entries_count: u32 = 0;
    if ioc_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&ioc_dir) {
            for entry in entries.take(1000).flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(data) = std::fs::read_to_string(&path) {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&data) {
                            if let Some(indicators) = parsed.get("indicators").and_then(|v| v.as_array()) {
                                entries_count += indicators.len() as u32;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(FeedStatus {
        version,
        last_updated,
        next_check,
        entries_count,
    })
}

#[tauri::command]
pub async fn force_feed_update() -> Result<String, String> {
    let bin = resolve_clawdefender_path();
    tracing::info!("Running feed update via: {}", bin);

    let output = std::process::Command::new(&bin)
        .args(["feed", "update"])
        .output()
        .map_err(|e| format!("Failed to run clawdefender: {}. Is the CLI installed?", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(if stdout.trim().is_empty() {
            "Feed update completed successfully".to_string()
        } else {
            stdout.trim().to_string()
        })
    } else {
        Err(format!(
            "Feed update failed (exit {}): {}{}",
            output.status.code().unwrap_or(-1),
            stderr.trim(),
            if !stdout.trim().is_empty() { format!("\n{}", stdout.trim()) } else { String::new() }
        ))
    }
}

#[tauri::command]
pub async fn get_blocklist_matches() -> Result<Vec<BlocklistAlert>, String> {
    let blocklist_path = threat_intel_dir().join("blocklist.json");

    if !blocklist_path.exists() {
        return Ok(vec![]);
    }

    let content = std::fs::read_to_string(&blocklist_path)
        .map_err(|e| format!("Failed to read blocklist.json: {}", e))?;
    let blocklist: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse blocklist.json: {}", e))?;

    let entries = match blocklist.get("entries").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Ok(vec![]),
    };

    let server_names = collect_mcp_server_names();
    if server_names.is_empty() {
        return Ok(vec![]);
    }

    let mut alerts = Vec::new();
    for entry in entries.iter().take(10000) {
        let entry_name = match entry.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let entry_name_lower = entry_name.to_lowercase();

        for server_name in &server_names {
            if server_name.to_lowercase() == entry_name_lower {
                alerts.push(BlocklistAlert {
                    entry_id: entry.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    server_name: server_name.clone(),
                    severity: entry.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    description: entry.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                });
            }
        }
    }

    Ok(alerts)
}

#[tauri::command]
pub async fn get_rule_packs() -> Result<Vec<RulePackInfo>, String> {
    let rules_dir = threat_intel_dir().join("rules");

    if !rules_dir.is_dir() {
        return Ok(vec![]);
    }

    let mut packs = Vec::new();
    let entries = std::fs::read_dir(&rules_dir)
        .map_err(|e| format!("Failed to read rules directory: {}", e))?;

    for entry in entries.take(500).flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let parsed: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let rule_count = parsed.get("rules")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as u32)
            .unwrap_or(0);

        packs.push(RulePackInfo {
            id: parsed.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            name: parsed.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            installed: true,
            version: parsed.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0").to_string(),
            rule_count,
            description: parsed.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        });
    }

    Ok(packs)
}

#[tauri::command]
pub async fn install_rule_pack(id: String) -> Result<(), String> {
    validate_rule_pack_id(&id)?;

    let bin = resolve_clawdefender_path();
    tracing::info!("Installing rule pack {} via: {}", id, bin);

    let output = std::process::Command::new(&bin)
        .args(["rules", "install", &id])
        .output()
        .map_err(|e| format!("Failed to run clawdefender: {}. Is the CLI installed?", e))?;

    if output.status.success() {
        tracing::info!("Rule pack {} installed successfully", id);
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to install rule pack {}: {}", id, stderr.trim()))
    }
}

#[tauri::command]
pub async fn uninstall_rule_pack(id: String) -> Result<(), String> {
    validate_rule_pack_id(&id)?;

    let rules_dir = threat_intel_dir().join("rules");
    let pack_file = rules_dir.join(format!("{}.json", id));

    // Ensure the resolved path is within the rules directory
    let canonical_rules = rules_dir.canonicalize()
        .map_err(|e| format!("Rules directory not found: {}", e))?;
    if let Ok(canonical_pack) = pack_file.canonicalize() {
        if !canonical_pack.starts_with(&canonical_rules) {
            return Err("Invalid rule pack path".to_string());
        }
        std::fs::remove_file(&canonical_pack)
            .map_err(|e| format!("Failed to remove rule pack {}: {}", id, e))?;
        tracing::info!("Rule pack {} uninstalled", id);
        Ok(())
    } else {
        Err(format!("Rule pack {} is not installed", id))
    }
}

#[tauri::command]
pub async fn get_ioc_stats() -> Result<IoCStats, String> {
    let ioc_dir = threat_intel_dir().join("ioc");

    if !ioc_dir.is_dir() {
        return Ok(IoCStats {
            network: 0,
            file: 0,
            behavioral: 0,
            total: 0,
            last_updated: "never".to_string(),
        });
    }

    let mut network: u32 = 0;
    let mut file: u32 = 0;
    let mut behavioral: u32 = 0;
    let mut latest_modified: Option<std::time::SystemTime> = None;

    let entries = std::fs::read_dir(&ioc_dir)
        .map_err(|e| format!("Failed to read IoC directory: {}", e))?;

    for entry in entries.take(1000).flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        // Track latest modification time
        if let Ok(meta) = path.metadata() {
            if let Ok(modified) = meta.modified() {
                if latest_modified.is_none_or(|prev| modified > prev) {
                    latest_modified = Some(modified);
                }
            }
        }

        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let parsed: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(indicators) = parsed.get("indicators").and_then(|v| v.as_array()) {
            for indicator in indicators.iter().take(100_000) {
                let itype = indicator.get("indicator_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if itype.starts_with("MaliciousIP")
                    || itype.starts_with("MaliciousDomain")
                    || itype.starts_with("MaliciousURL")
                {
                    network += 1;
                } else if itype.starts_with("MaliciousFileHash")
                    || itype.starts_with("SuspiciousFilePath")
                {
                    file += 1;
                } else if itype.starts_with("SuspiciousProcessName")
                    || itype.starts_with("SuspiciousCommandLine")
                    || itype.starts_with("SuspiciousToolSequence")
                    || itype.starts_with("SuspiciousArgPattern")
                {
                    behavioral += 1;
                } else {
                    // Count unknown types into behavioral as catch-all
                    behavioral += 1;
                }
            }
        }
    }

    let total = network + file + behavioral;
    let last_updated = match latest_modified {
        Some(t) => {
            let datetime: chrono::DateTime<chrono::Utc> = t.into();
            datetime.to_rfc3339()
        }
        None => "never".to_string(),
    };

    Ok(IoCStats {
        network,
        file,
        behavioral,
        total,
        last_updated,
    })
}

#[tauri::command]
pub async fn get_telemetry_status() -> Result<TelemetryStatus, String> {
    let path = config_toml_path();

    if !path.exists() {
        return Ok(TelemetryStatus {
            enabled: false,
            last_report: None,
            installation_id: None,
        });
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read config.toml: {}", e))?;
    let table: toml::Value = content.parse()
        .unwrap_or(toml::Value::Table(Default::default()));

    let telemetry = table.get("telemetry");
    let enabled = telemetry
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let last_report = telemetry
        .and_then(|t| t.get("last_report"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let installation_id = telemetry
        .and_then(|t| t.get("installation_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(TelemetryStatus {
        enabled,
        last_report,
        installation_id,
    })
}

#[tauri::command]
pub async fn toggle_telemetry(enabled: bool) -> Result<(), String> {
    let path = config_toml_path();

    let mut table: toml::Value = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read config.toml: {}", e))?;
        content.parse().unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    // Ensure [telemetry] section exists
    if table.get("telemetry").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("telemetry".to_string(), toml::Value::Table(Default::default()));
    }
    let telemetry = table
        .get_mut("telemetry")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [telemetry] section")?;

    telemetry.insert("enabled".to_string(), toml::Value::Boolean(enabled));

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    let output = toml::to_string_pretty(&table)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&path, output)
        .map_err(|e| format!("Failed to write config.toml: {}", e))?;

    tracing::info!("Telemetry toggled to {}", enabled);
    Ok(())
}

#[tauri::command]
pub async fn get_telemetry_preview() -> Result<TelemetryPreview, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let audit_path = std::path::PathBuf::from(home).join(".local/share/clawdefender/audit.jsonl");

    let mut categories = Vec::new();

    if audit_path.exists() {
        // Read only the last 256KB of the audit log to avoid unbounded memory use
        let (lines_vec, _) = event_stream::read_last_n_lines(&audit_path, 1000);
        let lines: Vec<&str> = lines_vec.iter().map(|s| s.as_str()).collect();

        let mut proxy_count: u32 = 0;
        let mut network_count: u32 = 0;
        let mut guard_count: u32 = 0;
        let mut allow_count: u32 = 0;
        let mut deny_count: u32 = 0;

        for line in &lines {
            if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
                let event_type = event.get("event_type")
                    .or_else(|| event.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let action = event.get("action")
                    .or_else(|| event.get("decision"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if event_type.contains("proxy") { proxy_count += 1; }
                else if event_type.contains("network") { network_count += 1; }
                else if event_type.contains("guard") { guard_count += 1; }

                if action.contains("allow") || action.contains("pass") { allow_count += 1; }
                else if action.contains("deny") || action.contains("block") { deny_count += 1; }
            }
        }

        let total = lines.len();
        categories.push(format!("Proxy events: {} (anonymized)", proxy_count));
        categories.push(format!("Network events: {} (anonymized)", network_count));
        categories.push(format!("Guard events: {} (anonymized)", guard_count));
        categories.push(format!("Decisions: {} allowed, {} denied", allow_count, deny_count));
        categories.push(format!("Total events analyzed: {}", total));
    } else {
        categories.push("No audit data available yet".to_string());
        categories.push("Events will appear once the daemon processes requests".to_string());
    }

    Ok(TelemetryPreview {
        categories,
        description: "All data is anonymous and aggregated. No file paths, server names, API keys, or personal information is collected.".to_string(),
    })
}

#[tauri::command]
pub async fn check_server_reputation(name: String) -> Result<ReputationResult, String> {
    let blocklist_path = threat_intel_dir().join("blocklist.json");

    if !blocklist_path.exists() {
        return Ok(ReputationResult {
            server_name: name,
            clean: true,
            matches: vec![],
        });
    }

    let content = std::fs::read_to_string(&blocklist_path)
        .map_err(|e| format!("Failed to read blocklist.json: {}", e))?;
    let blocklist: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse blocklist.json: {}", e))?;

    let entries = match blocklist.get("entries").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            return Ok(ReputationResult {
                server_name: name,
                clean: true,
                matches: vec![],
            });
        }
    };

    let name_lower = name.to_lowercase();
    let mut reputation_matches = Vec::new();

    for entry in entries.iter().take(10000) {
        let entry_name = match entry.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => continue,
        };
        if entry_name.to_lowercase() == name_lower {
            reputation_matches.push(ReputationMatch {
                entry_id: entry.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                severity: entry.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                description: entry.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            });
        }
    }

    let clean = reputation_matches.is_empty();
    Ok(ReputationResult {
        server_name: name,
        clean,
        matches: reputation_matches,
    })
}

// --- Network Extension ---

#[tauri::command]
pub async fn get_network_extension_status() -> Result<NetworkExtensionStatus, String> {
    // The macOS Network Extension is not installed — return honest state.
    Ok(NetworkExtensionStatus {
        loaded: false,
        filter_active: false,
        dns_active: false,
        filtering_count: 0,
        mock_mode: true,
    })
}

#[tauri::command]
pub async fn activate_network_extension() -> Result<String, String> {
    Err("Network Extension is not installed. The macOS Network Extension requires a signed system extension with special entitlements.".to_string())
}

#[tauri::command]
pub async fn deactivate_network_extension() -> Result<String, String> {
    Err("Network Extension is not installed. The macOS Network Extension requires a signed system extension with special entitlements.".to_string())
}

#[tauri::command]
pub async fn get_network_settings() -> Result<NetworkSettings, String> {
    let path = config_toml_path();
    let table: toml::Value = if path.exists() {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            format!("Failed to read config.toml: {}", e)
        })?;
        content
            .parse()
            .unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    Ok(NetworkSettings {
        filter_enabled: get_bool(&table, "network_policy", "enabled", false),
        dns_enabled: get_bool(&table, "network_policy", "dns_enabled", false),
        filter_all_processes: get_bool(&table, "network_policy", "filter_all_processes", false),
        default_action: get_str(&table, "network_policy", "default_agent_action", "prompt"),
        prompt_timeout: get_u32(&table, "network_policy", "prompt_timeout_seconds", 15),
        block_private_ranges: get_bool(&table, "network_policy", "block_private_ranges", false),
        block_doh: get_bool(&table, "network_policy", "block_doh", true),
        log_dns: get_bool(&table, "network_policy", "log_all_dns", true),
    })
}

#[tauri::command]
pub async fn update_network_settings(settings: NetworkSettings) -> Result<(), String> {
    let path = config_toml_path();

    // Read existing config to preserve other sections
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

    net.insert("enabled".to_string(), toml::Value::Boolean(settings.filter_enabled));
    net.insert("dns_enabled".to_string(), toml::Value::Boolean(settings.dns_enabled));
    net.insert("filter_all_processes".to_string(), toml::Value::Boolean(settings.filter_all_processes));
    net.insert("default_agent_action".to_string(), toml::Value::String(settings.default_action));
    net.insert("prompt_timeout_seconds".to_string(), toml::Value::Integer(settings.prompt_timeout as i64));
    net.insert("block_private_ranges".to_string(), toml::Value::Boolean(settings.block_private_ranges));
    net.insert("block_doh".to_string(), toml::Value::Boolean(settings.block_doh));
    net.insert("log_all_dns".to_string(), toml::Value::Boolean(settings.log_dns));

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

    tracing::info!("Network settings saved to {}", path.display());
    Ok(())
}

// --- Network Connection Log ---

/// Read network events from audit.jsonl, bounded to the last 256KB.
fn read_network_audit_records() -> Vec<event_stream::DaemonAuditRecord> {
    let path = event_stream::audit_log_path();
    if !path.exists() || !event_stream::is_safe_audit_path(&path) {
        return Vec::new();
    }

    const CHUNK_SIZE: u64 = 256 * 1024;

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let file_len = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return Vec::new(),
    };

    let read_from = file_len.saturating_sub(CHUNK_SIZE);

    let mut reader = std::io::BufReader::new(&file);
    if read_from > 0 {
        use std::io::{Seek, SeekFrom};
        if reader.seek(SeekFrom::Start(read_from)).is_err() {
            return Vec::new();
        }
        // Skip partial line after seeking
        let mut partial = String::new();
        use std::io::BufRead;
        let _ = reader.read_line(&mut partial);
    }

    let mut records = Vec::new();
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
                if record.source.contains("network") {
                    records.push(record);
                }
            }
            Err(_) => continue,
        }
    }
    records
}

/// Normalize action strings to canonical form.
fn normalize_action(action: &str) -> &'static str {
    match action.to_lowercase().as_str() {
        "allowed" | "allow" => "allowed",
        "blocked" | "block" | "denied" | "deny" => "blocked",
        "prompted" | "prompt" => "prompted",
        _ => "allowed",
    }
}

/// Try to extract a destination string from an audit record.
fn extract_destination(record: &event_stream::DaemonAuditRecord) -> Option<String> {
    if let Some(ref details) = record.event_details {
        if let Some(obj) = details.as_object() {
            for key in &["destination", "host", "domain", "destination_domain", "dest"] {
                if let Some(val) = obj.get(*key) {
                    if let Some(s) = val.as_str() {
                        if !s.is_empty() {
                            return Some(s.to_string());
                        }
                    }
                }
            }
            if let Some(ip) = obj.get("destination_ip").and_then(|v| v.as_str()) {
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }
    }
    record.server_name.clone()
}

#[tauri::command]
pub async fn get_network_connections(limit: u32) -> Result<Vec<NetworkConnectionEvent>, String> {
    let records = read_network_audit_records();
    let limit = limit.min(500) as usize;

    // Take the last `limit` records (most recent)
    let start = if records.len() > limit { records.len() - limit } else { 0 };
    let events: Vec<NetworkConnectionEvent> = records[start..]
        .iter()
        .enumerate()
        .map(|(i, record)| {
            let action = normalize_action(&record.action_taken);
            let details_obj = record.event_details.as_ref().and_then(|v| v.as_object());

            let destination_ip = details_obj
                .and_then(|o| o.get("destination_ip").and_then(|v| v.as_str()))
                .unwrap_or("0.0.0.0")
                .to_string();

            let destination_port = details_obj
                .and_then(|o| o.get("destination_port").and_then(|v| v.as_u64()))
                .unwrap_or(0) as u16;

            let destination_domain = details_obj
                .and_then(|o| o.get("destination_domain").or_else(|| o.get("domain")).or_else(|| o.get("host")))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let protocol = details_obj
                .and_then(|o| o.get("protocol").and_then(|v| v.as_str()))
                .unwrap_or("tcp")
                .to_string();

            let tls = destination_port == 443;

            let pid = details_obj
                .and_then(|o| o.get("pid").and_then(|v| v.as_u64()))
                .unwrap_or(0) as u32;

            let process_name = record.server_name.clone().unwrap_or_else(|| "unknown".to_string());

            let reason = if !record.event_summary.is_empty() {
                record.event_summary.clone()
            } else {
                record.policy_action.clone().unwrap_or_default()
            };

            let ioc_match = record.classification.as_deref()
                .map(|c| c.contains("malicious") || c.contains("ioc"))
                .unwrap_or(false);

            let rule = details_obj
                .and_then(|o| o.get("rule_matched").and_then(|v| v.as_str()))
                .map(|s| s.to_string());

            NetworkConnectionEvent {
                id: format!("net-{}", start + i),
                timestamp: record.timestamp.clone(),
                pid,
                process_name,
                server_name: record.server_name.clone(),
                destination_ip,
                destination_port,
                destination_domain,
                protocol,
                tls,
                action: action.to_string(),
                reason,
                rule,
                ioc_match,
                anomaly_score: None,
                behavioral: None,
                kill_chain: None,
                bytes_sent: 0,
                bytes_received: 0,
                duration_ms: 0,
            }
        })
        .collect();

    Ok(events)
}

#[tauri::command]
pub async fn get_network_summary() -> Result<NetworkSummaryData, String> {
    let records = read_network_audit_records();

    let mut total_allowed: u64 = 0;
    let mut total_blocked: u64 = 0;
    let mut total_prompted: u64 = 0;
    let mut dest_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    for record in &records {
        match normalize_action(&record.action_taken) {
            "allowed" => total_allowed += 1,
            "blocked" => total_blocked += 1,
            "prompted" => total_prompted += 1,
            _ => total_allowed += 1,
        }
        if let Some(dest) = extract_destination(record) {
            *dest_counts.entry(dest).or_insert(0) += 1;
        }
    }

    let mut dest_vec: Vec<(String, u64)> = dest_counts.into_iter().collect();
    dest_vec.sort_by(|a, b| b.1.cmp(&a.1));
    let top_destinations: Vec<DestinationCount> = dest_vec
        .into_iter()
        .take(5)
        .map(|(destination, count)| DestinationCount { destination, count })
        .collect();

    Ok(NetworkSummaryData {
        total_allowed,
        total_blocked,
        total_prompted,
        top_destinations,
        period: "last_24h".to_string(),
    })
}

#[tauri::command]
pub async fn get_network_traffic_by_server() -> Result<Vec<ServerTrafficData>, String> {
    let records = read_network_audit_records();

    let mut server_map: std::collections::HashMap<String, (u64, u64, u64, std::collections::HashSet<String>)> =
        std::collections::HashMap::new();

    for record in &records {
        let server = record.server_name.clone().unwrap_or_else(|| "unknown".to_string());
        let entry = server_map.entry(server).or_insert_with(|| (0, 0, 0, std::collections::HashSet::new()));
        match normalize_action(&record.action_taken) {
            "allowed" => entry.0 += 1,
            "blocked" => entry.1 += 1,
            "prompted" => entry.2 += 1,
            _ => entry.0 += 1,
        }
        if let Some(dest) = extract_destination(record) {
            entry.3.insert(dest);
        }
    }

    let mut results: Vec<ServerTrafficData> = server_map
        .into_iter()
        .map(|(server_name, (allowed, blocked, prompted, dests))| {
            ServerTrafficData {
                server_name,
                total_connections: allowed + blocked + prompted,
                connections_allowed: allowed,
                connections_blocked: blocked,
                connections_prompted: prompted,
                bytes_sent: 0,
                bytes_received: 0,
                unique_destinations: dests.len() as u32,
                period: "last_24h".to_string(),
            }
        })
        .collect();

    results.sort_by(|a, b| b.total_connections.cmp(&a.total_connections));

    Ok(results)
}

#[tauri::command]
pub async fn export_network_log(format: String, range: String) -> Result<String, String> {
    // Validate range to prevent path traversal
    let safe_range: String = range.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if safe_range.is_empty() {
        return Err("Invalid range parameter".to_string());
    }

    let records = read_network_audit_records();

    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let export_dir = home.join(".clawdefender/exports");
    std::fs::create_dir_all(&export_dir).map_err(|e| {
        format!("Failed to create exports directory: {}", e)
    })?;

    let ext = if format == "csv" { "csv" } else { "json" };
    let filename = format!("clawdefender-network-log-{}.{}", safe_range, ext);
    let path = export_dir.join(&filename);

    // Verify the resolved path is still within exports dir
    let canonical_dir = export_dir.canonicalize().map_err(|e| {
        format!("Failed to resolve exports directory: {}", e)
    })?;
    if let Some(parent) = path.parent() {
        let canonical_parent = parent.canonicalize().map_err(|e| {
            format!("Failed to resolve export path: {}", e)
        })?;
        if !canonical_parent.starts_with(&canonical_dir) {
            return Err("Invalid export path".to_string());
        }
    }

    if format == "csv" {
        let mut output = String::from("timestamp,source,server_name,action_taken,event_summary,classification\n");
        for record in &records {
            let ts = record.timestamp.replace('"', "\"\"");
            let src = record.source.replace('"', "\"\"");
            let srv = record.server_name.as_deref().unwrap_or("").replace('"', "\"\"");
            let act = record.action_taken.replace('"', "\"\"");
            let summ = record.event_summary.replace('"', "\"\"");
            let cls = record.classification.as_deref().unwrap_or("").replace('"', "\"\"");
            output.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                ts, src, srv, act, summ, cls
            ));
        }
        std::fs::write(&path, output).map_err(|e| {
            format!("Failed to write CSV export: {}", e)
        })?;
    } else {
        let json = serde_json::to_string_pretty(&records).map_err(|e| {
            format!("Failed to serialize network events: {}", e)
        })?;
        std::fs::write(&path, json).map_err(|e| {
            format!("Failed to write JSON export: {}", e)
        })?;
    }

    tracing::info!("Exported {} network events to {}", records.len(), path.display());
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

// --- Autostart management ---

#[tauri::command]
pub fn enable_autostart(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().enable().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn disable_autostart(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().disable().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn is_autostart_enabled(app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

mod dirs {
    use std::path::PathBuf;
    pub fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

// --- Cloud API management ---

#[tauri::command]
pub async fn save_api_key(provider: String, key: String) -> Result<(), String> {
    // Security: Validate provider name against known providers to prevent
    // arbitrary keychain entries. Trim the API key to remove accidental whitespace.
    let valid_providers: Vec<String> = clawdefender_slm::cloud_backend::get_cloud_providers()
        .iter()
        .map(|p| p.id.clone())
        .collect();
    if !valid_providers.contains(&provider) {
        return Err(format!("unknown cloud provider: {}", provider));
    }
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err("API key cannot be empty".to_string());
    }
    clawdefender_slm::cloud_backend::store_api_key(&provider, &key)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn clear_api_key(provider: String) -> Result<(), String> {
    // Security: Validate provider name to prevent arbitrary keychain deletions.
    let valid_providers: Vec<String> = clawdefender_slm::cloud_backend::get_cloud_providers()
        .iter()
        .map(|p| p.id.clone())
        .collect();
    if !valid_providers.contains(&provider) {
        return Err(format!("unknown cloud provider: {}", provider));
    }
    clawdefender_slm::cloud_backend::delete_api_key(&provider)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn has_cloud_api_key(provider: String) -> Result<bool, String> {
    // Security: Validate provider name.
    let valid_providers: Vec<String> = clawdefender_slm::cloud_backend::get_cloud_providers()
        .iter()
        .map(|p| p.id.clone())
        .collect();
    if !valid_providers.contains(&provider) {
        return Err(format!("unknown cloud provider: {}", provider));
    }
    Ok(clawdefender_slm::cloud_backend::has_api_key(&provider))
}

#[tauri::command]
pub async fn test_api_connection(
    provider: String,
    model: String,
) -> Result<clawdefender_slm::cloud_backend::ConnectionTestResult, String> {
    let api_key = clawdefender_slm::cloud_backend::get_api_key(&provider)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("No API key found for provider: {}", provider))?;

    clawdefender_slm::cloud_backend::test_connection(&provider, &api_key, &model)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_cloud_usage() -> Result<clawdefender_slm::cloud_backend::CloudUsageStats, String> {
    // Return zeroed stats since usage is tracked per-session in CloudBackend instances.
    Ok(clawdefender_slm::cloud_backend::CloudUsageStats {
        provider: String::new(),
        model: String::new(),
        total_requests: 0,
        tokens_in: 0,
        tokens_out: 0,
        estimated_cost_usd: 0.0,
    })
}

#[tauri::command]
pub async fn get_cloud_providers() -> Result<Vec<clawdefender_slm::model_registry::CloudProvider>, String> {
    Ok(clawdefender_slm::cloud_backend::get_cloud_providers())
}

// ---------------------------------------------------------------------------
// Model download commands
// ---------------------------------------------------------------------------

fn models_dir() -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home
        .join(".local")
        .join("share")
        .join("clawdefender")
        .join("models"))
}

#[tauri::command]
pub async fn download_model(
    model_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let dir = models_dir()?;
    state
        .download_manager
        .start_download(&model_id, &dir)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn download_custom_model(
    url: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let dir = models_dir()?;
    state
        .download_manager
        .start_custom_download(&url, &dir)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_download_progress(
    task_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<clawdefender_slm::downloader::DownloadProgress, String> {
    state
        .download_manager
        .get_progress(&task_id)
        .await
        .ok_or_else(|| format!("no download task found: {}", task_id))
}

#[tauri::command]
pub async fn cancel_download(
    task_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    if state.download_manager.cancel(&task_id).await {
        Ok(())
    } else {
        Err(format!("no active download task: {}", task_id))
    }
}

#[tauri::command]
pub async fn delete_model(model_id: String) -> Result<(), String> {
    let dir = models_dir()?;
    // Try to find filename from catalog first
    if let Some(model) = clawdefender_slm::model_registry::find_model(&model_id) {
        clawdefender_slm::downloader::DownloadManager::delete_model(&model.filename, &dir)
            .map_err(|e| e.to_string())
    } else {
        // Security: Validate the filename to prevent path traversal attacks.
        // The model_id could contain "../" to escape the models directory.
        if model_id.contains("..") || model_id.contains('/') || model_id.contains('\\') {
            return Err("invalid model filename: path traversal not allowed".to_string());
        }
        clawdefender_slm::downloader::DownloadManager::delete_model(&model_id, &dir)
            .map_err(|e| e.to_string())
    }
}

#[tauri::command]
pub async fn get_model_catalog() -> Result<Vec<clawdefender_slm::model_registry::CatalogModel>, String> {
    Ok(clawdefender_slm::model_registry::catalog())
}

#[tauri::command]
pub async fn get_installed_models() -> Result<Vec<clawdefender_slm::downloader::InstalledModelInfo>, String> {
    let dir = models_dir()?;
    clawdefender_slm::downloader::list_installed_models(&dir).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_system_capabilities() -> Result<clawdefender_slm::model_registry::SystemCapabilities, String> {
    Ok(clawdefender_slm::model_registry::detect_system_info())
}

// ---------------------------------------------------------------------------
// Model switching commands
// ---------------------------------------------------------------------------

/// Status info for the Settings page SLM widget.
#[derive(serde::Serialize)]
pub struct SlmStatusInfo {
    pub loaded: bool,
    pub model_name: Option<String>,
    pub model_size: Option<String>,
    pub backend: Option<String>,
}

/// A model available for activation (catalog, custom, or cloud).
#[derive(serde::Serialize)]
pub struct AvailableModel {
    pub id: String,
    pub name: String,
    pub model_type: String,
    pub status: String,
    pub size_bytes: Option<u64>,
    pub description: Option<String>,
    pub quality_rating: Option<u8>,
}

#[tauri::command]
pub async fn activate_model(
    model_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<ActiveModelInfo, String> {
    use std::sync::Arc;
    use clawdefender_slm::engine::SlmConfig;
    use clawdefender_slm::model_registry::{find_model, save_active_config, ActiveModelConfig};

    let dir = models_dir()?;

    // Find the model in catalog or treat as a custom file path
    let (file_path, model_name, size_bytes, config_to_save) =
        if let Some(catalog_model) = find_model(&model_id) {
            let path = dir.join(&catalog_model.filename);
            if !path.exists() {
                return Err(format!("Model file not found: {}. Download it first.", catalog_model.display_name));
            }
            (
                path.clone(),
                catalog_model.display_name.clone(),
                Some(catalog_model.size_bytes),
                ActiveModelConfig::LocalCatalog {
                    model_id: model_id.clone(),
                    path: path.clone(),
                },
            )
        } else {
            // Treat model_id as a file path for custom models
            let path = std::path::PathBuf::from(&model_id);
            if !path.exists() {
                return Err(format!("Model file not found: {}", model_id));
            }
            let size = std::fs::metadata(&path).map(|m| m.len()).ok();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "Custom Model".to_string());
            (
                path.clone(),
                name,
                size,
                ActiveModelConfig::LocalCustom { path },
            )
        };

    let slm_config = SlmConfig {
        model_path: file_path.clone(),
        ..SlmConfig::default()
    };

    let service = clawdefender_slm::SlmService::new(slm_config, true);
    let using_gpu = service
        .stats()
        .map(|s| s.using_gpu)
        .unwrap_or(false);

    let info = ActiveModelInfo {
        model_type: if find_model(&model_id).is_some() {
            "local_catalog".to_string()
        } else {
            "local_custom".to_string()
        },
        model_id: Some(model_id),
        model_name: model_name,
        file_path: Some(file_path.to_string_lossy().to_string()),
        provider: None,
        size_bytes,
        using_gpu,
        total_inferences: 0,
        avg_latency_ms: 0.0,
    };

    // Store in state (drop old model first)
    {
        let mut slm_guard = state.active_slm.lock().map_err(|e| e.to_string())?;
        *slm_guard = Some(Arc::new(service));
    }
    {
        let mut info_guard = state.active_model_info.lock().map_err(|e| e.to_string())?;
        *info_guard = Some(info.clone());
    }

    // Persist config
    save_active_config(&config_to_save).map_err(|e| e.to_string())?;

    Ok(info)
}

#[tauri::command]
pub async fn activate_cloud_provider(
    provider: String,
    model: String,
    state: tauri::State<'_, AppState>,
) -> Result<ActiveModelInfo, String> {
    use std::sync::Arc;
    use clawdefender_slm::engine::{MockSlmBackend, SlmBackend, SlmConfig, SlmEngine};
    use clawdefender_slm::model_registry::{cloud_providers, save_active_config, ActiveModelConfig};

    // Verify the provider/model combination exists
    let provider_info = cloud_providers()
        .into_iter()
        .find(|p| p.id == provider)
        .ok_or_else(|| format!("Unknown cloud provider: {}", provider))?;

    let model_info = provider_info
        .models
        .iter()
        .find(|m| m.id == model)
        .ok_or_else(|| format!("Unknown model '{}' for provider '{}'", model, provider))?;

    // Verify API key exists in keychain
    let has_key = clawdefender_slm::cloud_backend::has_api_key(&provider);
    if !has_key {
        return Err(format!(
            "No API key configured for {}. Add one in Settings first.",
            provider_info.display_name
        ));
    }

    // Create a mock-backed SlmService for state tracking
    // (actual cloud calls go through CloudBackend::analyze() directly)
    let backend: Box<dyn SlmBackend> = Box::new(MockSlmBackend {
        model_name: format!("{} ({})", model_info.display_name, provider_info.display_name),
        model_size: 0,
        gpu: false,
        ..MockSlmBackend::default()
    });
    let config = SlmConfig::default();
    let engine = Arc::new(SlmEngine::new(backend, config.clone()));
    let service = clawdefender_slm::SlmService::with_engine(engine, config);

    let info = ActiveModelInfo {
        model_type: "cloud_api".to_string(),
        model_id: Some(model.clone()),
        model_name: format!("{} ({})", model_info.display_name, provider_info.display_name),
        file_path: None,
        provider: Some(provider.clone()),
        size_bytes: None,
        using_gpu: false,
        total_inferences: 0,
        avg_latency_ms: 0.0,
    };

    // Store in state
    {
        let mut slm_guard = state.active_slm.lock().map_err(|e| e.to_string())?;
        *slm_guard = Some(Arc::new(service));
    }
    {
        let mut info_guard = state.active_model_info.lock().map_err(|e| e.to_string())?;
        *info_guard = Some(info.clone());
    }

    // Persist config
    let config_to_save = ActiveModelConfig::CloudApi {
        provider,
        model,
    };
    save_active_config(&config_to_save).map_err(|e| e.to_string())?;

    Ok(info)
}

#[tauri::command]
pub async fn deactivate_model(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    use clawdefender_slm::model_registry::{save_active_config, ActiveModelConfig};

    {
        let mut slm_guard = state.active_slm.lock().map_err(|e| e.to_string())?;
        *slm_guard = None;
    }
    {
        let mut info_guard = state.active_model_info.lock().map_err(|e| e.to_string())?;
        *info_guard = None;
    }

    save_active_config(&ActiveModelConfig::None).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn get_active_model(
    state: tauri::State<'_, AppState>,
) -> Result<Option<ActiveModelInfo>, String> {
    // Security: Acquire locks sequentially and drop each before acquiring the next
    // to prevent potential deadlocks from holding multiple Mutex locks simultaneously.
    let mut info = {
        let info_guard = state.active_model_info.lock().map_err(|e| e.to_string())?;
        info_guard.clone()
    }; // info_guard dropped here

    // Update live stats from the engine if available
    if info.is_some() {
        let slm_guard = state.active_slm.lock().map_err(|e| e.to_string())?;
        if let Some(ref slm) = *slm_guard {
            if let Some(stats) = slm.stats() {
                let model_info = info.as_mut().unwrap();
                model_info.total_inferences = stats.total_inferences;
                model_info.avg_latency_ms = stats.avg_latency_ms;
                model_info.using_gpu = stats.using_gpu;
            }
        }
    }

    Ok(info)
}

#[tauri::command]
pub async fn list_available_models(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<AvailableModel>, String> {
    let dir = models_dir()?;

    // Get currently active model id
    let active_id = {
        let info_guard = state.active_model_info.lock().map_err(|e| e.to_string())?;
        info_guard.as_ref().and_then(|i| i.model_id.clone())
    };

    // Get installed models
    let installed = clawdefender_slm::downloader::list_installed_models(&dir)
        .unwrap_or_default();
    let installed_filenames: Vec<String> = installed.iter().map(|m| m.filename.clone()).collect();

    let mut models = Vec::new();

    // Catalog models
    for cm in clawdefender_slm::model_registry::catalog() {
        let is_active = active_id.as_deref() == Some(&cm.id);
        let is_downloaded = installed_filenames.contains(&cm.filename);
        let status = if is_active {
            "active"
        } else if is_downloaded {
            "downloaded"
        } else {
            "not_downloaded"
        };

        models.push(AvailableModel {
            id: cm.id,
            name: cm.display_name,
            model_type: "catalog".to_string(),
            status: status.to_string(),
            size_bytes: Some(cm.size_bytes),
            description: Some(cm.description),
            quality_rating: Some(cm.quality_rating),
        });
    }

    // Cloud providers
    for provider in clawdefender_slm::model_registry::cloud_providers() {
        for cm in &provider.models {
            let cloud_id = format!("{}:{}", provider.id, cm.id);
            let is_active = active_id.as_deref() == Some(&cm.id);
            let has_key = clawdefender_slm::cloud_backend::has_api_key(&provider.id);
            let status = if is_active {
                "active"
            } else if has_key {
                "available"
            } else {
                "not_downloaded"
            };

            models.push(AvailableModel {
                id: cloud_id,
                name: format!("{} ({})", cm.display_name, provider.display_name),
                model_type: "cloud".to_string(),
                status: status.to_string(),
                size_bytes: None,
                description: Some(format!("Cloud API - {}", provider.display_name)),
                quality_rating: None,
            });
        }
    }

    Ok(models)
}

#[tauri::command]
pub async fn get_slm_status(
    state: tauri::State<'_, AppState>,
) -> Result<SlmStatusInfo, String> {
    // Security: Clone data from each lock separately to avoid holding two locks
    // at once, which could deadlock if another thread acquires them in reverse order.
    let slm_opt = {
        let slm_guard = state.active_slm.lock().map_err(|e| e.to_string())?;
        slm_guard.clone()
    };
    let info_opt = {
        let info_guard = state.active_model_info.lock().map_err(|e| e.to_string())?;
        info_guard.clone()
    };

    match (&slm_opt, &info_opt) {
        (Some(slm), Some(info)) => {
            let size_str = info.size_bytes.map(|b| {
                if b >= 1_000_000_000 {
                    format!("{:.1} GB", b as f64 / 1_000_000_000.0)
                } else {
                    format!("{:.0} MB", b as f64 / 1_000_000.0)
                }
            });

            let backend = match info.model_type.as_str() {
                "cloud_api" => info.provider.clone().unwrap_or_else(|| "cloud".to_string()),
                _ if slm.is_enabled() && info.using_gpu => "GPU".to_string(),
                _ if slm.is_enabled() => "CPU".to_string(),
                _ => "mock".to_string(),
            };

            Ok(SlmStatusInfo {
                loaded: slm.is_enabled(),
                model_name: Some(info.model_name.clone()),
                model_size: size_str,
                backend: Some(backend),
            })
        }
        _ => Ok(SlmStatusInfo {
            loaded: false,
            model_name: None,
            model_size: None,
            backend: None,
        }),
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

    // --- Phase 4: New tests for real implementations ---

    #[test]
    fn test_get_behavioral_status_no_db() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // No profiles.db exists — should return empty
        let result = read_profiles_from_db();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_profiles_no_db() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let profiles = read_profiles_from_db().unwrap();
        assert!(profiles.is_empty());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_validate_server_command_accepts_valid() {
        assert!(validate_server_command("npx server").is_ok());
        assert!(validate_server_command("node /path/to/server.js").is_ok());
        assert!(validate_server_command("python3 -m my_server").is_ok());
        assert!(validate_server_command("/usr/local/bin/my-mcp-server").is_ok());
    }

    #[test]
    fn test_validate_server_command_rejects_metacharacters() {
        assert!(validate_server_command("cmd ; rm -rf /").is_err());
        assert!(validate_server_command("cmd | cat /etc/passwd").is_err());
        assert!(validate_server_command("cmd & bg").is_err());
        assert!(validate_server_command("cmd $(whoami)").is_err());
        assert!(validate_server_command("cmd `id`").is_err());
        assert!(validate_server_command("cmd > /tmp/out").is_err());
        assert!(validate_server_command("cmd < /tmp/in").is_err());
        assert!(validate_server_command("").is_err());
        assert!(validate_server_command("   ").is_err());
    }

    #[test]
    fn test_get_feed_status_no_manifest() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // No manifest.json — threat_intel_dir() won't have it
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_feed_status());
        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.version, "not configured");
        assert_eq!(status.entries_count, 0);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_rule_packs_empty() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // Create the rules dir but leave it empty
        let rules_dir = tmp
            .path()
            .join(".local/share/clawdefender/threat-intel/rules");
        std::fs::create_dir_all(&rules_dir).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_rule_packs());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_ioc_stats_no_data() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_ioc_stats());
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.network, 0);
        assert_eq!(stats.file, 0);
        assert_eq!(stats.behavioral, 0);
        assert_eq!(stats.total, 0);
        assert_eq!(stats.last_updated, "never");

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_validate_rule_pack_id_valid() {
        assert!(validate_rule_pack_id("filesystem-safety").is_ok());
        assert!(validate_rule_pack_id("pack123").is_ok());
        assert!(validate_rule_pack_id("a-b-c").is_ok());
    }

    #[test]
    fn test_validate_rule_pack_id_rejects_traversal() {
        assert!(validate_rule_pack_id("../etc/passwd").is_err());
        assert!(validate_rule_pack_id("../../foo").is_err());
        assert!(validate_rule_pack_id("name with spaces").is_err());
        assert!(validate_rule_pack_id("").is_err());
        assert!(validate_rule_pack_id("foo/bar").is_err());
        assert!(validate_rule_pack_id("a".repeat(200).as_str()).is_err());
    }

    #[test]
    fn test_export_network_log_creates_file() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // Create audit.jsonl with a network event
        let audit_dir = tmp.path().join(".local/share/clawdefender");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let record = serde_json::json!({
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "network",
            "event_summary": "Network connection",
            "action_taken": "allowed",
            "server_name": "test-server"
        });
        let mut file = std::fs::File::create(audit_dir.join("audit.jsonl")).unwrap();
        writeln!(file, "{}", record).unwrap();
        file.flush().unwrap();

        // Create the exports directory parent so canonical check works
        let export_dir = tmp.path().join(".clawdefender/exports");
        std::fs::create_dir_all(&export_dir).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(export_network_log("json".to_string(), "last24h".to_string()));
        assert!(result.is_ok(), "export_network_log failed: {:?}", result);

        let path = result.unwrap();
        assert!(std::path::Path::new(&path).exists(), "Exported file should exist at {}", path);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[tokio::test]
    async fn test_get_network_extension_status_honest() {
        let result = get_network_extension_status().await;
        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(!status.loaded);
        assert!(status.mock_mode);
        assert!(!status.filter_active);
        assert!(!status.dns_active);
    }

    #[test]
    fn test_toggle_telemetry_persists() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // Create config dir
        let config_dir = tmp.path().join(".config/clawdefender");
        std::fs::create_dir_all(&config_dir).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();

        // Toggle telemetry on
        let result = rt.block_on(toggle_telemetry(true));
        assert!(result.is_ok());

        // Read config.toml and verify
        let content = std::fs::read_to_string(config_dir.join("config.toml")).unwrap();
        let table: toml::Value = content.parse().unwrap();
        let enabled = table
            .get("telemetry")
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap();
        assert!(enabled);

        // Toggle off and verify
        let result = rt.block_on(toggle_telemetry(false));
        assert!(result.is_ok());
        let content = std::fs::read_to_string(config_dir.join("config.toml")).unwrap();
        let table: toml::Value = content.parse().unwrap();
        let enabled = table
            .get("telemetry")
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap();
        assert!(!enabled);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_system_info_real_version() {
        // The app_version should come from CARGO_PKG_VERSION
        let expected = env!("CARGO_PKG_VERSION");
        assert!(!expected.is_empty());
        // We can't call get_system_info directly (needs State), but we can verify
        // the version constant is accessible and matches Cargo.toml
        assert!(expected.contains('.'), "Version should contain dots: {}", expected);
    }

    #[test]
    fn test_parse_scan_findings_count() {
        // With summary.total
        let json = r#"{"summary":{"total":5},"findings":[]}"#;
        assert_eq!(parse_scan_findings_count(json), 5);

        // With findings array
        let json = r#"{"findings":[{"id":"f1"},{"id":"f2"},{"id":"f3"}]}"#;
        assert_eq!(parse_scan_findings_count(json), 3);

        // Invalid JSON
        assert_eq!(parse_scan_findings_count("not json"), 0);

        // Empty
        assert_eq!(parse_scan_findings_count("{}"), 0);
    }

    #[test]
    fn test_normalize_action() {
        assert_eq!(normalize_action("allowed"), "allowed");
        assert_eq!(normalize_action("allow"), "allowed");
        assert_eq!(normalize_action("blocked"), "blocked");
        assert_eq!(normalize_action("block"), "blocked");
        assert_eq!(normalize_action("denied"), "blocked");
        assert_eq!(normalize_action("deny"), "blocked");
        assert_eq!(normalize_action("prompted"), "prompted");
        assert_eq!(normalize_action("prompt"), "prompted");
        assert_eq!(normalize_action("unknown"), "allowed");
    }

    #[test]
    fn test_get_network_connections_no_events() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // No audit.jsonl — should return empty
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_network_connections(100));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_telemetry_status_no_config() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_telemetry_status());
        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(!status.enabled);
        assert!(status.last_report.is_none());
        assert!(status.installation_id.is_none());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_network_settings_defaults() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_network_settings());
        assert!(result.is_ok());
        let settings = result.unwrap();
        assert!(!settings.filter_enabled);
        assert_eq!(settings.default_action, "prompt");

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }
}
