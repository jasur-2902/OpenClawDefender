//! `clawai unwrap <server_name>` — restore an MCP server's original config.

use anyhow::{bail, Result};

use super::{backup_config, find_client_config, is_wrapped, list_servers, read_config, write_config};

pub fn run(server_name: &str, client_hint: &str) -> Result<()> {
    let client = find_client_config(server_name, client_hint)?;
    let mut config = read_config(&client.config_path)?;

    let servers = config
        .get_mut("mcpServers")
        .and_then(|s| s.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("No mcpServers found in {}", client.config_path.display()))?;

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
        println!("This server is not wrapped by ClawAI.");
        return Ok(());
    }

    let original = server
        .get("_clawai_original")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Missing _clawai_original in server config"))?;

    // Backup before modifying.
    backup_config(&client.config_path)?;

    // Restore original command/args and remove _clawai_original.
    let server_obj = server.as_object_mut().unwrap();
    if let Some(cmd) = original.get("command") {
        server_obj.insert("command".to_string(), cmd.clone());
    }
    if let Some(args) = original.get("args") {
        server_obj.insert("args".to_string(), args.clone());
    }
    server_obj.remove("_clawai_original");

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

    /// Unwrap restores original command/args and removes _clawai_original.
    #[test]
    fn test_unwrap_restores_original() {
        let mut config = json!({
            "mcpServers": {
                "test-server": {
                    "command": "clawai",
                    "args": ["proxy", "--", "npx", "-y", "@mcp/server"],
                    "_clawai_original": {
                        "command": "npx",
                        "args": ["-y", "@mcp/server"]
                    }
                }
            }
        });

        let server = config["mcpServers"]["test-server"].as_object_mut().unwrap();
        assert!(is_wrapped(&serde_json::Value::Object(server.clone())));

        let original = server.get("_clawai_original").cloned().unwrap();
        server.insert("command".to_string(), original["command"].clone());
        server.insert("args".to_string(), original["args"].clone());
        server.remove("_clawai_original");

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

        server.insert("command".to_string(), json!("clawai"));
        server.insert("args".to_string(), json!(proxy_args));
        server.insert(
            "_clawai_original".to_string(),
            json!({"command": orig_cmd, "args": orig_args}),
        );

        assert!(is_wrapped(&config["mcpServers"]["fs-server"]));

        // Unwrap.
        let server = config["mcpServers"]["fs-server"].as_object_mut().unwrap();
        let original = server.get("_clawai_original").cloned().unwrap();
        server.insert("command".to_string(), original["command"].clone());
        server.insert("args".to_string(), original["args"].clone());
        server.remove("_clawai_original");

        // Should match original (modulo _clawai_original being removed).
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
}
