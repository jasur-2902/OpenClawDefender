//! `clawdefender unwrap <server_name>` — restore an MCP server's original config.

use anyhow::{bail, Result};

use super::{backup_config, detect_servers_key, find_client_config, is_wrapped, list_servers, read_config, write_config};

pub fn run(server_name: &str, client_hint: &str) -> Result<()> {
    let client = find_client_config(server_name, client_hint)?;
    let mut config = read_config(&client.config_path)?;

    let servers_key = detect_servers_key(&config);
    let servers = config
        .get_mut(servers_key)
        .and_then(|s| s.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("No MCP servers found in {}", client.config_path.display()))?;

    let server = match servers.get_mut(server_name) {
        Some(s) => s,
        None => {
            let available = list_servers(&config);
            bail!(
                "Server \"{}\" not found in {}.\n\nAvailable servers:\n{}",
                server_name,
                client.display_name,
                available.iter().map(|s| format!("  - {s}")).collect::<Vec<_>>().join("\n"),
            );
        }
    };

    if !is_wrapped(server) {
        println!("This server is not wrapped by ClawDefender.");
        return Ok(());
    }

    // Support both new `_clawdefender_original` and legacy `_clawai_original` keys.
    let original = server
        .get("_clawdefender_original")
        .or_else(|| server.get("_clawai_original"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Missing _clawdefender_original in server config"))?;

    // Backup before modifying.
    backup_config(&client.config_path)?;

    // Restore original command/args and remove _clawdefender_original.
    let server_obj = server.as_object_mut().unwrap();
    if let Some(cmd) = original.get("command") {
        server_obj.insert("command".to_string(), cmd.clone());
    }
    if let Some(args) = original.get("args") {
        server_obj.insert("args".to_string(), args.clone());
    }
    server_obj.remove("_clawdefender_original");
    server_obj.remove("_clawai_original"); // Remove legacy key if present.

    write_config(&client.config_path, &config)?;

    println!("Unwrapped \"{}\" in {}", server_name, client.display_name);
    println!();
    println!("The original MCP server configuration has been restored.");
    println!("Restart {} for changes to take effect.", client.display_name);

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::is_wrapped;

    /// Unwrap restores original command/args and removes _clawdefender_original.
    #[test]
    fn test_unwrap_restores_original() {
        let mut config = json!({
            "mcpServers": {
                "test-server": {
                    "command": "clawdefender",
                    "args": ["proxy", "--", "npx", "-y", "@mcp/server"],
                    "_clawdefender_original": {
                        "command": "npx",
                        "args": ["-y", "@mcp/server"]
                    }
                }
            }
        });

        let server = config["mcpServers"]["test-server"].as_object_mut().unwrap();
        assert!(is_wrapped(&serde_json::Value::Object(server.clone())));

        let original = server.get("_clawdefender_original").cloned().unwrap();
        server.insert("command".to_string(), original["command"].clone());
        server.insert("args".to_string(), original["args"].clone());
        server.remove("_clawdefender_original");

        assert_eq!(config["mcpServers"]["test-server"]["command"], "npx");
        let args = config["mcpServers"]["test-server"]["args"].as_array().unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "-y");
        assert_eq!(args[1], "@mcp/server");
        assert!(!is_wrapped(&config["mcpServers"]["test-server"]));
    }

    /// Wrap then unwrap should produce the original config.
    #[test]
    fn test_wrap_then_unwrap_roundtrip() {
        let original_config = json!({
            "mcpServers": {
                "fs-server": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "~/Projects"],
                    "env": {"NODE_ENV": "production"}
                }
            }
        });

        // Wrap.
        let mut config = original_config.clone();
        let server = config["mcpServers"]["fs-server"].as_object_mut().unwrap();
        let orig_cmd = server["command"].clone();
        let orig_args = server["args"].clone();

        let mut proxy_args = vec![json!("proxy"), json!("--")];
        proxy_args.push(orig_cmd.clone());
        proxy_args.extend(orig_args.as_array().unwrap().iter().cloned());

        server.insert("command".to_string(), json!("clawdefender"));
        server.insert("args".to_string(), json!(proxy_args));
        server.insert(
            "_clawdefender_original".to_string(),
            json!({"command": orig_cmd, "args": orig_args}),
        );

        assert!(is_wrapped(&config["mcpServers"]["fs-server"]));

        // Unwrap.
        let server = config["mcpServers"]["fs-server"].as_object_mut().unwrap();
        let original = server.get("_clawdefender_original").cloned().unwrap();
        server.insert("command".to_string(), original["command"].clone());
        server.insert("args".to_string(), original["args"].clone());
        server.remove("_clawdefender_original");

        // Should match original (modulo _clawdefender_original being removed).
        assert_eq!(
            config["mcpServers"]["fs-server"]["command"],
            original_config["mcpServers"]["fs-server"]["command"]
        );
        assert_eq!(
            config["mcpServers"]["fs-server"]["args"],
            original_config["mcpServers"]["fs-server"]["args"]
        );
        assert_eq!(
            config["mcpServers"]["fs-server"]["env"],
            original_config["mcpServers"]["fs-server"]["env"]
        );
    }

    /// Cursor configs using "servers" key should also unwrap correctly.
    #[test]
    fn test_unwrap_cursor_servers_key() {
        use super::super::detect_servers_key;

        let mut config = json!({
            "servers": {
                "cursor-server": {
                    "command": "clawdefender",
                    "args": ["proxy", "--", "node", "server.js"],
                    "_clawdefender_original": {
                        "command": "node",
                        "args": ["server.js"]
                    }
                }
            }
        });

        let key = detect_servers_key(&config);
        assert_eq!(key, "servers");

        let server = config[key]["cursor-server"].as_object_mut().unwrap();
        assert!(is_wrapped(&serde_json::Value::Object(server.clone())));

        let original = server.get("_clawdefender_original").cloned().unwrap();
        server.insert("command".to_string(), original["command"].clone());
        server.insert("args".to_string(), original["args"].clone());
        server.remove("_clawdefender_original");

        assert_eq!(config["servers"]["cursor-server"]["command"], "node");
        assert!(!is_wrapped(&config["servers"]["cursor-server"]));
    }

    /// Legacy _clawai_original key should be handled by unwrap.
    #[test]
    fn test_unwrap_legacy_clawai_original() {
        let mut config = json!({
            "mcpServers": {
                "legacy-server": {
                    "command": "clawdefender",
                    "args": ["proxy", "--", "python", "server.py"],
                    "_clawai_original": {
                        "command": "python",
                        "args": ["server.py"]
                    }
                }
            }
        });

        let server = config["mcpServers"]["legacy-server"].as_object_mut().unwrap();
        assert!(is_wrapped(&serde_json::Value::Object(server.clone())));

        // Simulate unwrap logic: check _clawdefender_original first, then _clawai_original.
        let original = server
            .get("_clawdefender_original")
            .or_else(|| server.get("_clawai_original"))
            .cloned()
            .unwrap();

        server.insert("command".to_string(), original["command"].clone());
        server.insert("args".to_string(), original["args"].clone());
        server.remove("_clawdefender_original");
        server.remove("_clawai_original");

        assert_eq!(config["mcpServers"]["legacy-server"]["command"], "python");
        assert!(!is_wrapped(&config["mcpServers"]["legacy-server"]));
    }
}
