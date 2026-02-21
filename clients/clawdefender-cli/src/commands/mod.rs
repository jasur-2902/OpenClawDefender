pub mod behavioral;
pub mod chat;
pub mod config;
pub mod daemon;
pub mod doctor;
pub mod guard;
pub mod network;
pub mod threat_intel;
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

/// Return the path to the honeypot canary directory: `~/.config/clawdefender/honeypot/`.
pub fn honeypot_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(home.join(".config/clawdefender/honeypot"))
}

// ---------------------------------------------------------------------------
// DXT Extension Support
// ---------------------------------------------------------------------------

/// Represents a discovered DXT extension with its MCP config.
pub struct DxtExtension {
    pub id: String,
    pub display_name: String,
    pub installations_path: PathBuf,
}

/// Path to Claude Desktop's extensions-installations.json.
pub fn dxt_installations_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;

    #[cfg(target_os = "macos")]
    let path = home.join("Library/Application Support/Claude/extensions-installations.json");

    #[cfg(target_os = "linux")]
    let path = home.join(".config/Claude/extensions-installations.json");

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let path = {
        let _ = home;
        return None;
    };

    Some(path)
}

/// Find a DXT extension by name (matches against manifest.name, manifest.display_name,
/// or the extension id, case-insensitive).
pub fn find_dxt_extension(server_name: &str) -> Option<DxtExtension> {
    let path = dxt_installations_path()?;
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;
    let extensions = json.get("extensions")?.as_object()?;

    let needle = server_name.to_lowercase();
    for (id, entry) in extensions {
        let manifest = entry.get("manifest")?;
        let name = manifest.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let display = manifest.get("display_name").and_then(|v| v.as_str()).unwrap_or("");

        if id.to_lowercase() == needle
            || name.to_lowercase() == needle
            || display.to_lowercase() == needle
        {
            // Only return if this extension has an mcp_config
            if manifest.pointer("/server/mcp_config").is_some() {
                let label = if !display.is_empty() {
                    display.to_string()
                } else if !name.is_empty() {
                    name.to_string()
                } else {
                    id.clone()
                };
                return Some(DxtExtension {
                    id: id.clone(),
                    display_name: label,
                    installations_path: path,
                });
            }
        }
    }
    None
}

/// List all DXT extensions that have an mcp_config. Returns (display_name, id) pairs.
pub fn list_dxt_extensions() -> Vec<(String, String)> {
    let Some(path) = dxt_installations_path() else {
        return Vec::new();
    };
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&content) else {
        return Vec::new();
    };
    let Some(extensions) = json.get("extensions").and_then(|v| v.as_object()) else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for (id, entry) in extensions {
        if let Some(manifest) = entry.get("manifest") {
            if manifest.pointer("/server/mcp_config").is_some() {
                let display = manifest
                    .get("display_name")
                    .and_then(|v| v.as_str())
                    .or_else(|| manifest.get("name").and_then(|v| v.as_str()))
                    .unwrap_or(id.as_str());
                result.push((display.to_string(), id.clone()));
            }
        }
    }
    result
}

/// Check if a DXT extension entry's mcp_config is already wrapped by ClawDefender.
pub fn is_dxt_wrapped(ext_entry: &Value) -> bool {
    ext_entry
        .pointer("/manifest/server/mcp_config/_clawdefender_original")
        .is_some()
}

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
    // Newer versions use "config.json", older versions used "claude_desktop_config.json".
    #[cfg(target_os = "macos")]
    {
        let claude_dir = home.join("Library/Application Support/Claude");
        let config_path = if claude_dir.join("config.json").exists() {
            claude_dir.join("config.json")
        } else {
            claude_dir.join("claude_desktop_config.json")
        };
        clients.insert(0, McpClient {
            name: "claude",
            display_name: "Claude Desktop",
            config_path,
            servers_key: SERVERS_KEY_MCP,
        });
    }

    #[cfg(target_os = "linux")]
    {
        let claude_dir = home.join(".config/Claude");
        let config_path = if claude_dir.join("config.json").exists() {
            claude_dir.join("config.json")
        } else {
            claude_dir.join("claude_desktop_config.json")
        };
        clients.insert(0, McpClient {
            name: "claude",
            display_name: "Claude Desktop",
            config_path,
            servers_key: SERVERS_KEY_MCP,
        });
    }

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

    let dxt_exts = list_dxt_extensions();
    let dxt_lines: Vec<String> = dxt_exts
        .iter()
        .map(|(name, id)| format!("  - {} (DXT: {})", name, id))
        .collect();

    if installed.is_empty() && dxt_lines.is_empty() {
        anyhow::bail!(
            "Server \"{server_name}\" not found.\n\
             No MCP client configs detected. Install Claude Desktop, Cursor, or VS Code."
        );
    }

    let mut checked = installed.join("\n");
    if !dxt_lines.is_empty() {
        if !checked.is_empty() {
            checked.push('\n');
        }
        checked.push_str(&format!(
            "\nDXT extensions:\n{}",
            dxt_lines.join("\n")
        ));
    }

    anyhow::bail!(
        "Server \"{server_name}\" not found in any MCP client config.\n\
         \n\
         Checked:\n{checked}\n\
         \n\
         Make sure the server name matches exactly."
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

    #[test]
    fn test_is_dxt_wrapped() {
        let entry = json!({
            "manifest": {
                "name": "test-ext",
                "server": {
                    "mcp_config": {
                        "command": "clawdefender",
                        "args": ["proxy", "--", "node", "server.js"],
                        "_clawdefender_original": {
                            "command": "node",
                            "args": ["server.js"]
                        }
                    }
                }
            }
        });
        assert!(is_dxt_wrapped(&entry));
    }

    #[test]
    fn test_is_dxt_not_wrapped() {
        let entry = json!({
            "manifest": {
                "name": "test-ext",
                "server": {
                    "mcp_config": {
                        "command": "node",
                        "args": ["server.js"]
                    }
                }
            }
        });
        assert!(!is_dxt_wrapped(&entry));
    }

    #[test]
    fn test_find_dxt_extension_by_name() {
        // This test uses the real filesystem path so it only verifies the None case
        // when no extensions-installations.json exists. Integration tests with temp
        // files are in wrap.rs and unwrap.rs.
        // If the file doesn't exist on this machine, find should return None.
        let result = find_dxt_extension("nonexistent-extension-xyz");
        assert!(result.is_none());
    }

    #[test]
    fn test_list_dxt_extensions_returns_vec() {
        // Should not panic even if the file doesn't exist.
        let exts = list_dxt_extensions();
        // We can't assert the contents since it depends on the local machine,
        // but it should return a Vec without errors.
        let _ = exts;
    }
}
