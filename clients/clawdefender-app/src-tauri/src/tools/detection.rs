use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use super::capabilities::{infer_capabilities, suggest_trust_level, ServerCapabilities};

/// Information about a newly detected MCP server not yet in known_servers.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewServerInfo {
    pub server_name: String,
    pub client_name: String,
    pub client_display_name: String,
    pub command: Vec<String>,
    pub first_detected: String,
    pub capabilities: ServerCapabilities,
    pub suggested_trust_level: String,
}

/// Entry in the persisted known_servers.json file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownServerEntry {
    pub first_seen: String,
    pub client: String,
    pub trust_level: String,
    pub acknowledged: bool,
}

/// Top-level structure of known_servers.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownServersFile {
    pub version: u32,
    pub servers: HashMap<String, KnownServerEntry>,
}

impl Default for KnownServersFile {
    fn default() -> Self {
        Self {
            version: 1,
            servers: HashMap::new(),
        }
    }
}

/// Represents a discovered MCP server from client config files.
#[derive(Debug, Clone)]
pub struct DiscoveredServer {
    pub server_name: String,
    pub client_name: String,
    pub client_display_name: String,
    pub command: Vec<String>,
    pub wrapped: bool,
}

fn known_servers_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".local/share/clawdefender/known_servers.json")
}

/// Read the known servers file from disk. Returns default if not found.
pub fn load_known_servers() -> KnownServersFile {
    let path = known_servers_path();
    if !path.exists() {
        return KnownServersFile::default();
    }
    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => KnownServersFile::default(),
    }
}

/// Write the known servers file to disk.
fn save_known_servers(data: &KnownServersFile) -> Result<(), String> {
    let path = known_servers_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create data directory: {}", e))?;
    }
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| format!("Failed to serialize known servers: {}", e))?;
    std::fs::write(&path, json)
        .map_err(|e| format!("Failed to write known servers: {}", e))?;
    Ok(())
}

/// Acknowledge a server by adding it to known_servers.json.
pub fn acknowledge_server(server_name: &str, trust_level: &str) -> Result<(), String> {
    let mut data = load_known_servers();
    let now = chrono::Utc::now().to_rfc3339();
    if let Some(entry) = data.servers.get_mut(server_name) {
        entry.acknowledged = true;
        entry.trust_level = trust_level.to_string();
    } else {
        data.servers.insert(
            server_name.to_string(),
            KnownServerEntry {
                first_seen: now,
                client: String::new(),
                trust_level: trust_level.to_string(),
                acknowledged: true,
            },
        );
    }
    save_known_servers(&data)
}

/// Dismiss a new server by marking it acknowledged with default trust.
pub fn dismiss_server(server_name: &str) -> Result<(), String> {
    acknowledge_server(server_name, "standard")
}

/// Get the list of known (acknowledged) server names.
pub fn get_known_server_names() -> Vec<String> {
    let data = load_known_servers();
    data.servers.keys().cloned().collect()
}

/// Detect all MCP servers across all client config files (non-Tauri, standalone version).
/// This reads config files directly without going through Tauri commands.
pub fn discover_all_servers() -> Vec<DiscoveredServer> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };

    let clients_info: Vec<(&str, &str, Vec<PathBuf>)> = vec![
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

    let mut servers = Vec::new();

    for (client_name, display_name, paths) in clients_info {
        let config_path = match paths.iter().find(|p| p.exists()) {
            Some(p) => p,
            None => continue,
        };

        let contents = match std::fs::read_to_string(config_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let config: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let key = if config.get("mcpServers").and_then(|v| v.as_object()).is_some() {
            "mcpServers"
        } else if config.get("servers").and_then(|v| v.as_object()).is_some() {
            "servers"
        } else {
            "mcpServers"
        };

        let servers_obj = match config.get(key).and_then(|v| v.as_object()) {
            Some(obj) => obj,
            None => continue,
        };

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

            servers.push(DiscoveredServer {
                server_name: name.clone(),
                client_name: client_name.to_string(),
                client_display_name: display_name.to_string(),
                command,
                wrapped,
            });
        }
    }

    servers
}

/// Compare discovered servers against known_servers.json and return new ones.
pub fn detect_new_servers() -> Vec<NewServerInfo> {
    let all_servers = discover_all_servers();
    let known = load_known_servers();
    let now = chrono::Utc::now().to_rfc3339();

    let mut new_servers = Vec::new();

    for server in &all_servers {
        if known.servers.contains_key(&server.server_name) {
            continue;
        }

        let caps = infer_capabilities(&server.server_name, &server.command);
        let suggested = suggest_trust_level(&caps);

        new_servers.push(NewServerInfo {
            server_name: server.server_name.clone(),
            client_name: server.client_name.clone(),
            client_display_name: server.client_display_name.clone(),
            command: server.command.clone(),
            first_detected: now.clone(),
            capabilities: caps,
            suggested_trust_level: suggested,
        });
    }

    // Also auto-register discovered servers as known (but unacknowledged) so we
    // can track first_seen even if the user doesn't immediately acknowledge.
    if !new_servers.is_empty() {
        let mut data = load_known_servers();
        for ns in &new_servers {
            data.servers
                .entry(ns.server_name.clone())
                .or_insert_with(|| KnownServerEntry {
                    first_seen: ns.first_detected.clone(),
                    client: ns.client_name.clone(),
                    trust_level: ns.suggested_trust_level.clone(),
                    acknowledged: false,
                });
        }
        let _ = save_known_servers(&data);
    }

    new_servers
}

/// Return only unacknowledged new servers.
pub fn get_unacknowledged_servers() -> Vec<NewServerInfo> {
    let all_servers = discover_all_servers();
    let known = load_known_servers();
    let now = chrono::Utc::now().to_rfc3339();

    let mut result = Vec::new();
    for server in &all_servers {
        if let Some(entry) = known.servers.get(&server.server_name) {
            if entry.acknowledged {
                continue;
            }
        }

        let caps = infer_capabilities(&server.server_name, &server.command);
        let suggested = suggest_trust_level(&caps);

        result.push(NewServerInfo {
            server_name: server.server_name.clone(),
            client_name: server.client_name.clone(),
            client_display_name: server.client_display_name.clone(),
            command: server.command.clone(),
            first_detected: known
                .servers
                .get(&server.server_name)
                .map(|e| e.first_seen.clone())
                .unwrap_or_else(|| now.clone()),
            capabilities: caps,
            suggested_trust_level: suggested,
        });
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_servers_default() {
        let data = KnownServersFile::default();
        assert_eq!(data.version, 1);
        assert!(data.servers.is_empty());
    }

    #[test]
    fn test_known_servers_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_servers.json");

        let mut data = KnownServersFile::default();
        data.servers.insert(
            "test-server".to_string(),
            KnownServerEntry {
                first_seen: "2026-01-01T00:00:00Z".to_string(),
                client: "claude".to_string(),
                trust_level: "standard".to_string(),
                acknowledged: true,
            },
        );

        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(&path, &json).unwrap();

        let loaded: KnownServersFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.servers.len(), 1);
        assert!(loaded.servers.contains_key("test-server"));
        assert!(loaded.servers["test-server"].acknowledged);
    }

    #[test]
    fn test_serialization() {
        let info = NewServerInfo {
            server_name: "test".to_string(),
            client_name: "claude".to_string(),
            client_display_name: "Claude Desktop".to_string(),
            command: vec!["npx".to_string(), "test-server".to_string()],
            first_detected: "2026-01-01T00:00:00Z".to_string(),
            capabilities: ServerCapabilities::default(),
            suggested_trust_level: "standard".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test"));
        let parsed: NewServerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.server_name, "test");
    }
}
