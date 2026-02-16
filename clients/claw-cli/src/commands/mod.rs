pub mod doctor;
pub mod init;
pub mod log;
pub mod policy;
pub mod proxy;
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
}

/// Return the list of known MCP client config paths.
pub fn known_clients() -> Vec<McpClient> {
    let home = match std::env::var_os("HOME") {
        Some(h) => PathBuf::from(h),
        None => return Vec::new(),
    };

    vec![
        McpClient {
            name: "claude",
            display_name: "Claude Desktop",
            config_path: home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        },
        McpClient {
            name: "cursor",
            display_name: "Cursor",
            config_path: home.join(".cursor/mcp.json"),
        },
        McpClient {
            name: "vscode",
            display_name: "VS Code",
            config_path: home.join(".vscode/mcp.json"),
        },
    ]
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
                    "Unknown client: {client_hint}\nKnown clients: claude, cursor, vscode"
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
    for client in clients {
        if !client.config_path.exists() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&client.config_path) {
            if let Ok(json) = serde_json::from_str::<Value>(&content) {
                if json
                    .get("mcpServers")
                    .and_then(|s| s.as_object())
                    .map(|s| s.contains_key(server_name))
                    .unwrap_or(false)
                {
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

/// Check if a server entry is already wrapped by ClawAI.
pub fn is_wrapped(server: &Value) -> bool {
    server.get("_clawai_original").is_some()
}

/// List all server names in a config.
pub fn list_servers(config: &Value) -> Vec<String> {
    config
        .get("mcpServers")
        .and_then(|s| s.as_object())
        .map(|s| s.keys().cloned().collect())
        .unwrap_or_default()
}
