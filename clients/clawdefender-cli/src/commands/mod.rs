pub mod behavioral;
pub mod chat;
pub mod config;
pub mod daemon;
pub mod doctor;
pub mod usage;
pub mod init;
pub mod log;
pub mod model;
pub mod policy;
pub mod profile_cmd;
pub mod proxy;
pub mod scan;
pub mod serve;
pub mod status;
pub mod unwrap;
pub mod wrap;

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Known MCP client config file locations.
pub struct McpClient {
    pub name: &'static str,
    pub display_name: &'static str,
    pub config_path: PathBuf,
    /// The JSON key used for the servers object in this client's config.
    /// Claude Desktop uses `"mcpServers"`, Cursor may use `"mcpServers"` or `"servers"`.
    pub servers_key: &'static str,
}

/// The standard MCP servers key used by Claude Desktop and most clients.
pub const SERVERS_KEY_MCP: &str = "mcpServers";

/// Return the list of known MCP client config paths.
pub fn known_clients() -> Vec<McpClient> {
    let home = match std::env::var_os("HOME") {
        Some(h) => PathBuf::from(h),
        None => return Vec::new(),
    };

    let mut clients = vec![
        McpClient {
            name: "cursor",
            display_name: "Cursor",
            config_path: home.join(".cursor/mcp.json"),
            servers_key: SERVERS_KEY_MCP,
        },
        McpClient {
            name: "vscode",
            display_name: "VS Code",
            config_path: home.join(".vscode/mcp.json"),
            servers_key: SERVERS_KEY_MCP,
        },
        McpClient {
            name: "windsurf",
            display_name: "Windsurf",
            config_path: home.join(".codeium/windsurf/mcp_config.json"),
            servers_key: SERVERS_KEY_MCP,
        },
    ];

    // Claude Desktop path is platform-specific.
    #[cfg(target_os = "macos")]
    clients.insert(0, McpClient {
        name: "claude",
        display_name: "Claude Desktop",
        config_path: home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        servers_key: SERVERS_KEY_MCP,
    });

    #[cfg(target_os = "linux")]
    clients.insert(0, McpClient {
        name: "claude",
        display_name: "Claude Desktop",
        config_path: home.join(".config/Claude/claude_desktop_config.json"),
        servers_key: SERVERS_KEY_MCP,
    });

    clients
}

/// Detect the correct servers key for a config file.
/// Cursor configs may use `"mcpServers"` (standard) or `"servers"` (legacy/alternate).
/// Returns the key that exists in the config, preferring `"mcpServers"`.
pub fn detect_servers_key(config: &Value) -> &'static str {
    if config.get("mcpServers").and_then(|v| v.as_object()).is_some() {
        "mcpServers"
    } else if config.get("servers").and_then(|v| v.as_object()).is_some() {
        "servers"
    } else {
        // Default to standard key.
        SERVERS_KEY_MCP
    }
}

/// Find the MCP client config that contains a given server name.
/// If `client_hint` is "auto", tries each known client in order.
/// Otherwise, returns the specific client matching the hint.
pub fn find_client_config(server_name: &str, client_hint: &str) -> anyhow::Result<McpClient> {
    let clients = known_clients();

    if client_hint != "auto" {
        let client = clients
            .into_iter()
            .find(|c| c.name == client_hint)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Unknown client: {client_hint}\nKnown clients: claude, cursor, vscode, windsurf"
                )
            })?;
        if !client.config_path.exists() {
            anyhow::bail!(
                "{} config not found at {}\nIs {} installed?",
                client.display_name,
                client.config_path.display(),
                client.display_name,
            );
        }
        return Ok(client);
    }

    // Auto-detect: find the first client config containing the server_name.
    // Checks both `mcpServers` and `servers` keys to handle Cursor's alternate format.
    for mut client in clients {
        if !client.config_path.exists() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&client.config_path) {
            if let Ok(json) = serde_json::from_str::<Value>(&content) {
                let key = detect_servers_key(&json);
                if json
                    .get(key)
                    .and_then(|s| s.as_object())
                    .map(|s| s.contains_key(server_name))
                    .unwrap_or(false)
                {
                    client.servers_key = key;
                    return Ok(client);
                }
            }
        }
    }

    // Not found — give a helpful error.
    let installed: Vec<String> = known_clients()
        .into_iter()
        .filter(|c| c.config_path.exists())
        .map(|c| format!("  - {} ({})", c.display_name, c.config_path.display()))
        .collect();

    if installed.is_empty() {
        anyhow::bail!(
            "Server \"{server_name}\" not found.\n\
             No MCP client configs detected. Install Claude Desktop, Cursor, or VS Code."
        );
    }

    anyhow::bail!(
        "Server \"{server_name}\" not found in any MCP client config.\n\
         \n\
         Checked:\n{}\n\
         \n\
         Make sure the server name matches exactly.",
        installed.join("\n")
    );
}

/// Read and parse an MCP client config file.
pub fn read_config(path: &Path) -> anyhow::Result<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {e}", path.display()))?;
    let json: Value = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {e}", path.display()))?;
    Ok(json)
}

/// Write a JSON value back to an MCP client config file with 2-space indent.
pub fn write_config(path: &Path, value: &Value) -> anyhow::Result<()> {
    let content = serde_json::to_string_pretty(value)?;
    std::fs::write(path, content + "\n")?;
    Ok(())
}

/// Create a .bak backup of a config file.
pub fn backup_config(path: &Path) -> anyhow::Result<()> {
    let backup = path.with_extension("json.bak");
    std::fs::copy(path, &backup)?;
    Ok(())
}

/// Check if a server entry is already wrapped by ClawDefender.
/// Also checks for legacy `_clawai_original` key for backward compatibility.
pub fn is_wrapped(server: &Value) -> bool {
    server.get("_clawdefender_original").is_some() || server.get("_clawai_original").is_some()
}

/// List all server names in a config.
/// Checks both `mcpServers` and `servers` keys to handle different client formats.
pub fn list_servers(config: &Value) -> Vec<String> {
    let key = detect_servers_key(config);
    config
        .get(key)
        .and_then(|s| s.as_object())
        .map(|s| s.keys().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_detect_servers_key_standard() {
        let config = json!({
            "mcpServers": {
                "my-server": {"command": "npx", "args": []}
            }
        });
        assert_eq!(detect_servers_key(&config), "mcpServers");
    }

    #[test]
    fn test_detect_servers_key_cursor_alternate() {
        // Some Cursor versions use "servers" instead of "mcpServers".
        let config = json!({
            "servers": {
                "my-server": {"command": "npx", "args": []}
            }
        });
        assert_eq!(detect_servers_key(&config), "servers");
    }

    #[test]
    fn test_detect_servers_key_prefers_mcp_servers() {
        // If both keys exist, prefer "mcpServers".
        let config = json!({
            "mcpServers": {
                "server-a": {"command": "npx", "args": []}
            },
            "servers": {
                "server-b": {"command": "node", "args": []}
            }
        });
        assert_eq!(detect_servers_key(&config), "mcpServers");
    }

    #[test]
    fn test_detect_servers_key_empty_config() {
        let config = json!({});
        assert_eq!(detect_servers_key(&config), SERVERS_KEY_MCP);
    }

    #[test]
    fn test_detect_servers_key_non_object_value() {
        // If "servers" exists but is not an object, fall through.
        let config = json!({
            "servers": "not an object"
        });
        assert_eq!(detect_servers_key(&config), SERVERS_KEY_MCP);
    }

    #[test]
    fn test_list_servers_with_alternate_key() {
        let config = json!({
            "servers": {
                "cursor-server": {"command": "npx", "args": []},
                "another": {"command": "node", "args": []}
            }
        });
        let mut servers = list_servers(&config);
        servers.sort();
        assert_eq!(servers, vec!["another", "cursor-server"]);
    }

    #[test]
    fn test_list_servers_standard() {
        let config = json!({
            "mcpServers": {
                "my-server": {"command": "npx", "args": []}
            }
        });
        assert_eq!(list_servers(&config), vec!["my-server"]);
    }

    #[test]
    fn test_is_wrapped_with_clawdefender_original() {
        let server = json!({
            "command": "clawdefender",
            "args": ["proxy", "--", "npx"],
            "_clawdefender_original": {"command": "npx", "args": []}
        });
        assert!(is_wrapped(&server));
    }

    #[test]
    fn test_is_wrapped_with_legacy_clawai_original() {
        let server = json!({
            "command": "clawdefender",
            "args": ["proxy", "--", "npx"],
            "_clawai_original": {"command": "npx", "args": []}
        });
        assert!(is_wrapped(&server));
    }

    #[test]
    fn test_is_not_wrapped() {
        let server = json!({
            "command": "npx",
            "args": ["-y", "@mcp/server"]
        });
        assert!(!is_wrapped(&server));
    }

    #[test]
    fn test_known_clients_includes_cursor() {
        let clients = known_clients();
        assert!(clients.iter().any(|c| c.name == "cursor"), "should include cursor");
    }

    #[test]
    fn test_known_clients_includes_vscode() {
        let clients = known_clients();
        assert!(clients.iter().any(|c| c.name == "vscode"), "should include vscode");
    }

    #[test]
    fn test_known_clients_includes_windsurf() {
        let clients = known_clients();
        assert!(clients.iter().any(|c| c.name == "windsurf"), "should include windsurf");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_known_clients_includes_claude_on_macos() {
        let clients = known_clients();
        let claude = clients.iter().find(|c| c.name == "claude").unwrap();
        assert!(claude.config_path.to_string_lossy().contains("Library/Application Support"));
    }
}
