//! `clawdefender wrap <server_name>` — rewrite MCP client config to route through ClawDefender.

use anyhow::{bail, Result};
use serde_json::{json, Value};

use super::{
    backup_config, detect_servers_key, find_client_config, find_dxt_extension, is_dxt_wrapped,
    is_wrapped, known_clients, list_dxt_extensions, list_servers, read_config, write_config,
    DxtExtension,
};

/// Wrap all MCP servers across all detected clients and DXT extensions.
pub fn run_all(client_hint: &str) -> Result<()> {
    let mut wrapped = 0u32;
    let mut skipped = 0u32;
    let mut errors = Vec::new();

    // Wrap servers in traditional MCP client configs.
    let clients = if client_hint == "auto" {
        known_clients()
    } else {
        known_clients()
            .into_iter()
            .filter(|c| c.name == client_hint)
            .collect()
    };

    for client in &clients {
        if !client.config_path.exists() {
            continue;
        }
        let config = match read_config(&client.config_path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: {e}", client.display_name));
                continue;
            }
        };
        let servers = list_servers(&config);
        for server_name in &servers {
            match run(server_name, client.name) {
                Ok(()) => wrapped += 1,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("already wrapped") {
                        skipped += 1;
                    } else {
                        errors.push(format!("{}/{}: {e}", client.display_name, server_name));
                    }
                }
            }
        }
    }

    // Wrap DXT extensions.
    for (display_name, id) in list_dxt_extensions() {
        if let Some(ext) = find_dxt_extension(&id) {
            match wrap_dxt_extension(&ext, &id) {
                Ok(()) => wrapped += 1,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("already wrapped") {
                        skipped += 1;
                    } else {
                        errors.push(format!("DXT {display_name}: {e}"));
                    }
                }
            }
        }
    }

    println!();
    println!("Wrap all complete: {wrapped} wrapped, {skipped} already wrapped.");
    if !errors.is_empty() {
        println!();
        println!("Errors:");
        for e in &errors {
            println!("  - {e}");
        }
    }

    Ok(())
}

pub fn run(server_name: &str, client_hint: &str) -> Result<()> {
    // Try traditional mcpServers config first, then fall back to DXT extensions.
    match try_wrap_traditional(server_name, client_hint) {
        Ok(()) => Ok(()),
        Err(traditional_err) => {
            // Traditional lookup failed — try DXT extensions before giving up.
            if let Some(ext) = find_dxt_extension(server_name) {
                return wrap_dxt_extension(&ext, server_name);
            }
            Err(traditional_err)
        }
    }
}

/// Try to wrap a server found in a traditional mcpServers config.
fn try_wrap_traditional(server_name: &str, client_hint: &str) -> Result<()> {
    let client = find_client_config(server_name, client_hint)?;
    let mut config = read_config(&client.config_path)?;

    let servers_key = detect_servers_key(&config);
    let servers = config
        .get_mut(servers_key)
        .and_then(|s| s.as_object_mut())
        .ok_or_else(|| {
            anyhow::anyhow!("No MCP servers found in {}", client.config_path.display())
        })?;

    let server = match servers.get_mut(server_name) {
        Some(s) => s,
        None => {
            let available = list_servers(&config);
            if available.is_empty() {
                bail!(
                    "No MCP servers configured in {}",
                    client.config_path.display()
                );
            }
            bail!(
                "Server \"{}\" not found in {}.\n\nAvailable servers:\n{}",
                server_name,
                client.display_name,
                available
                    .iter()
                    .map(|s| format!("  - {s}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
    };

    // Already wrapped — idempotent success.
    if is_wrapped(server) {
        println!(
            "\"{}\" is already wrapped by ClawDefender in {}.",
            server_name, client.display_name
        );
        return Ok(());
    }

    // Save original command/args.
    let original_command = server.get("command").cloned().unwrap_or(Value::Null);
    let original_args = server.get("args").cloned().unwrap_or(json!([]));

    let original_command_str = original_command
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Server \"{}\" has no \"command\" field", server_name))?;

    let mut proxy_args: Vec<Value> = vec![json!("proxy"), json!("--")];
    proxy_args.push(json!(original_command_str));
    if let Some(arr) = original_args.as_array() {
        proxy_args.extend(arr.iter().cloned());
    }

    // Store original for unwrap.
    let mut original = serde_json::Map::new();
    original.insert("command".to_string(), original_command.clone());
    original.insert("args".to_string(), original_args);

    // Backup before modifying.
    backup_config(&client.config_path)?;

    // Resolve the absolute path to the clawdefender binary.
    // Claude Desktop (and other MCP clients) may not inherit the user's shell PATH,
    // so we must write the full path to avoid "command not found" errors.
    let clawdefender_bin = resolve_clawdefender_path();

    // Rewrite the server entry.
    let server_obj = server.as_object_mut().unwrap();
    server_obj.insert("command".to_string(), json!(clawdefender_bin));
    server_obj.insert("args".to_string(), json!(proxy_args));
    server_obj.insert(
        "_clawdefender_original".to_string(),
        Value::Object(original),
    );

    write_config(&client.config_path, &config)?;

    println!("Wrapped \"{}\" in {}", server_name, client.display_name);
    println!();
    println!("ClawDefender will now intercept all MCP communication with this server.");
    println!(
        "Restart {} for changes to take effect.",
        client.display_name
    );
    println!();
    println!("To undo: clawdefender unwrap {}", server_name);

    Ok(())
}

/// Wrap a DXT extension by rewriting its mcp_config in extensions-installations.json.
fn wrap_dxt_extension(ext: &DxtExtension, server_name: &str) -> Result<()> {
    let mut root: Value = read_config(&ext.installations_path)?;

    if root
        .pointer(&format!(
            "/extensions/{}/manifest/server/mcp_config",
            ext.id
        ))
        .is_none()
    {
        bail!("DXT extension \"{}\" has no mcp_config", ext.id);
    }

    let ext_entry = root
        .pointer(&format!("/extensions/{}", ext.id))
        .cloned()
        .unwrap_or(Value::Null);
    if is_dxt_wrapped(&ext_entry) {
        println!(
            "\"{}\" (DXT: {}) is already wrapped by ClawDefender.",
            ext.display_name, ext.id
        );
        return Ok(());
    }

    // Re-borrow mutably after the cloned read above.
    let mcp_config = root
        .pointer_mut(&format!(
            "/extensions/{}/manifest/server/mcp_config",
            ext.id
        ))
        .unwrap();

    let original_command = mcp_config.get("command").cloned().unwrap_or(Value::Null);
    let original_args = mcp_config.get("args").cloned().unwrap_or(json!([]));

    let original_command_str = original_command.as_str().ok_or_else(|| {
        anyhow::anyhow!("DXT extension \"{}\" mcp_config has no \"command\"", ext.id)
    })?;

    let mut proxy_args: Vec<Value> = vec![json!("proxy"), json!("--")];
    proxy_args.push(json!(original_command_str));
    if let Some(arr) = original_args.as_array() {
        proxy_args.extend(arr.iter().cloned());
    }

    let mut original = serde_json::Map::new();
    original.insert("command".to_string(), original_command.clone());
    original.insert("args".to_string(), original_args);

    backup_config(&ext.installations_path)?;

    let clawdefender_bin = resolve_clawdefender_path();

    let mcp_obj = mcp_config.as_object_mut().unwrap();
    mcp_obj.insert("command".to_string(), json!(clawdefender_bin));
    mcp_obj.insert("args".to_string(), json!(proxy_args));
    mcp_obj.insert(
        "_clawdefender_original".to_string(),
        Value::Object(original),
    );

    write_config(&ext.installations_path, &root)?;

    println!("Wrapped \"{}\" (DXT: {})", ext.display_name, ext.id);
    println!();
    println!("ClawDefender will now intercept all MCP communication with this extension.");
    println!("Restart Claude Desktop for changes to take effect.");
    println!();
    println!("To undo: clawdefender unwrap {}", server_name);

    Ok(())
}

/// Resolve the absolute path to the `clawdefender` binary.
///
/// Claude Desktop and other MCP clients may not inherit the user's shell PATH
/// (e.g. paths set in .zshrc, .bashrc, or Homebrew paths like /opt/homebrew/bin).
/// We resolve the full path at wrap-time so the config contains an absolute path
/// that works regardless of the client's PATH.
fn resolve_clawdefender_path() -> String {
    // First try: the currently running binary (most reliable).
    if let Ok(current_exe) = std::env::current_exe() {
        if let Ok(resolved) = current_exe.canonicalize() {
            return resolved.to_string_lossy().to_string();
        }
        return current_exe.to_string_lossy().to_string();
    }

    // Fallback: search PATH for "clawdefender".
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

    // Last resort: return just the name (will only work if client happens to have it in PATH).
    "clawdefender".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_config(servers: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, r#"{{"mcpServers": {servers}}}"#).unwrap();
        (dir, path)
    }

    /// Wrap a server in a temp config and verify the JSON structure.
    #[test]
    fn test_wrap_modifies_config_correctly() {
        let (_dir, path) = make_config(
            r#"{"my-server": {"command": "npx", "args": ["-y", "@mcp/server", "~/Projects"]}}"#,
        );

        // Read, wrap manually (we can't use find_client_config in test because
        // it looks at real filesystem paths, so test the core logic directly).
        let mut config: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let server = config["mcpServers"]["my-server"].as_object_mut().unwrap();

        // Simulate wrap.
        let orig_cmd = server["command"].clone();
        let orig_args = server["args"].clone();

        let mut proxy_args: Vec<Value> = vec![json!("proxy"), json!("--")];
        proxy_args.push(orig_cmd.clone());
        if let Some(arr) = orig_args.as_array() {
            proxy_args.extend(arr.iter().cloned());
        }

        let mut original = serde_json::Map::new();
        original.insert("command".to_string(), orig_cmd);
        original.insert("args".to_string(), orig_args);

        server.insert("command".to_string(), json!("clawdefender"));
        server.insert("args".to_string(), json!(proxy_args));
        server.insert(
            "_clawdefender_original".to_string(),
            Value::Object(original),
        );

        // Verify.
        assert_eq!(config["mcpServers"]["my-server"]["command"], "clawdefender");
        let args = config["mcpServers"]["my-server"]["args"]
            .as_array()
            .unwrap();
        assert_eq!(args[0], "proxy");
        assert_eq!(args[1], "--");
        assert_eq!(args[2], "npx");
        assert_eq!(args[3], "-y");
        assert_eq!(args[4], "@mcp/server");
        assert_eq!(args[5], "~/Projects");

        // _clawdefender_original preserved.
        let orig = &config["mcpServers"]["my-server"]["_clawdefender_original"];
        assert_eq!(orig["command"], "npx");
        assert_eq!(orig["args"][0], "-y");
    }

    /// Double-wrap should be idempotent.
    #[test]
    fn test_double_wrap_is_idempotent() {
        let config_json = json!({
            "mcpServers": {
                "test-server": {
                    "command": "clawdefender",
                    "args": ["proxy", "--", "npx", "server"],
                    "_clawdefender_original": {
                        "command": "npx",
                        "args": ["server"]
                    }
                }
            }
        });

        let server = &config_json["mcpServers"]["test-server"];
        assert!(is_wrapped(server));
    }

    /// Other servers should not be modified.
    #[test]
    fn test_wrap_preserves_other_servers() {
        let mut config = json!({
            "mcpServers": {
                "server-a": {"command": "node", "args": ["a.js"]},
                "server-b": {"command": "python", "args": ["b.py"]}
            }
        });

        // Wrap only server-a.
        let server_a = config["mcpServers"]["server-a"].as_object_mut().unwrap();
        let orig_cmd = server_a["command"].clone();
        let orig_args = server_a["args"].clone();
        server_a.insert("command".to_string(), json!("clawdefender"));
        server_a.insert("args".to_string(), json!(["proxy", "--", "node", "a.js"]));
        server_a.insert(
            "_clawdefender_original".to_string(),
            json!({"command": orig_cmd, "args": orig_args}),
        );

        // server-b should be unchanged.
        assert_eq!(config["mcpServers"]["server-b"]["command"], "python");
        assert_eq!(config["mcpServers"]["server-b"]["args"][0], "b.py");
        assert!(!is_wrapped(&config["mcpServers"]["server-b"]));
    }

    /// resolve_clawdefender_path should return an absolute path.
    #[test]
    fn test_resolve_clawdefender_path_returns_absolute() {
        let path = resolve_clawdefender_path();
        // In test environments, current_exe() should succeed and return an absolute path.
        // The resolved path should start with '/' on Unix.
        assert!(path.starts_with('/'), "Expected absolute path, got: {path}");
    }

    // --- DXT Extension wrap tests ---

    fn make_dxt_installations(extensions_json: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("extensions-installations.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{extensions_json}").unwrap();
        (dir, path)
    }

    #[test]
    fn test_wrap_dxt_extension() {
        use super::super::{
            backup_config, is_dxt_wrapped, read_config, write_config, DxtExtension,
        };

        let (_dir, path) = make_dxt_installations(
            &serde_json::to_string(&json!({
                "extensions": {
                    "com.example.test-ext": {
                        "manifest": {
                            "name": "test-ext",
                            "display_name": "Test Extension",
                            "server": {
                                "mcp_config": {
                                    "command": "node",
                                    "args": ["server.js", "--port", "3000"]
                                }
                            }
                        }
                    }
                }
            }))
            .unwrap(),
        );

        let ext = DxtExtension {
            id: "com.example.test-ext".to_string(),
            display_name: "Test Extension".to_string(),
            installations_path: path.clone(),
        };

        // Simulate wrap_dxt_extension logic (we can't call run() because it uses real paths).
        let mut root: Value = read_config(&path).unwrap();
        let mcp_config = root
            .pointer_mut("/extensions/com.example.test-ext/manifest/server/mcp_config")
            .unwrap();

        let orig_cmd = mcp_config.get("command").cloned().unwrap();
        let orig_args = mcp_config.get("args").cloned().unwrap();

        let mut proxy_args: Vec<Value> = vec![json!("proxy"), json!("--")];
        proxy_args.push(orig_cmd.clone());
        proxy_args.extend(orig_args.as_array().unwrap().iter().cloned());

        let mcp_obj = mcp_config.as_object_mut().unwrap();
        mcp_obj.insert("command".to_string(), json!("clawdefender"));
        mcp_obj.insert("args".to_string(), json!(proxy_args));
        mcp_obj.insert(
            "_clawdefender_original".to_string(),
            json!({
                "command": orig_cmd,
                "args": orig_args,
            }),
        );

        write_config(&path, &root).unwrap();

        // Verify structure.
        let result: Value = read_config(&path).unwrap();
        let mcp = result
            .pointer("/extensions/com.example.test-ext/manifest/server/mcp_config")
            .unwrap();
        assert_eq!(mcp["command"], "clawdefender");
        let args = mcp["args"].as_array().unwrap();
        assert_eq!(args[0], "proxy");
        assert_eq!(args[1], "--");
        assert_eq!(args[2], "node");
        assert_eq!(args[3], "server.js");
        assert_eq!(args[4], "--port");
        assert_eq!(args[5], "3000");
        assert!(mcp.get("_clawdefender_original").is_some());

        let ext_entry = result.pointer("/extensions/com.example.test-ext").unwrap();
        assert!(is_dxt_wrapped(ext_entry));
    }

    #[test]
    fn test_wrap_dxt_preserves_dirname_token() {
        use super::super::{read_config, write_config};

        let (_dir, path) = make_dxt_installations(
            &serde_json::to_string(&json!({
                "extensions": {
                    "com.example.dirname-ext": {
                        "manifest": {
                            "name": "dirname-ext",
                            "server": {
                                "mcp_config": {
                                    "command": "node",
                                    "args": ["${__dirname}/dist/index.js"]
                                }
                            }
                        }
                    }
                }
            }))
            .unwrap(),
        );

        let mut root: Value = read_config(&path).unwrap();
        let mcp_config = root
            .pointer_mut("/extensions/com.example.dirname-ext/manifest/server/mcp_config")
            .unwrap();

        let orig_cmd = mcp_config.get("command").cloned().unwrap();
        let orig_args = mcp_config.get("args").cloned().unwrap();

        let mut proxy_args: Vec<Value> = vec![json!("proxy"), json!("--")];
        proxy_args.push(orig_cmd.clone());
        proxy_args.extend(orig_args.as_array().unwrap().iter().cloned());

        let mcp_obj = mcp_config.as_object_mut().unwrap();
        mcp_obj.insert("command".to_string(), json!("clawdefender"));
        mcp_obj.insert("args".to_string(), json!(proxy_args));
        mcp_obj.insert(
            "_clawdefender_original".to_string(),
            json!({
                "command": orig_cmd,
                "args": orig_args,
            }),
        );

        write_config(&path, &root).unwrap();

        let result: Value = read_config(&path).unwrap();
        let args = result
            .pointer("/extensions/com.example.dirname-ext/manifest/server/mcp_config/args")
            .unwrap()
            .as_array()
            .unwrap();
        // ${__dirname} token should be preserved as-is.
        assert_eq!(args[3], "${__dirname}/dist/index.js");
    }

    #[test]
    fn test_wrap_dxt_idempotent() {
        use super::super::is_dxt_wrapped;

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
        // Already wrapped — wrap_dxt_extension would return early.
        assert!(is_dxt_wrapped(&entry));
    }

    #[test]
    fn test_wrap_dxt_roundtrip() {
        use super::super::{is_dxt_wrapped, read_config, write_config};

        let original_json = json!({
            "extensions": {
                "com.example.roundtrip": {
                    "manifest": {
                        "name": "roundtrip-ext",
                        "display_name": "Roundtrip Extension",
                        "server": {
                            "mcp_config": {
                                "command": "python",
                                "args": ["-m", "my_server", "--verbose"],
                                "env": {"PYTHONPATH": "/usr/local/lib"}
                            }
                        }
                    }
                }
            }
        });

        let (_dir, path) = make_dxt_installations(&serde_json::to_string(&original_json).unwrap());

        // Wrap.
        let mut root: Value = read_config(&path).unwrap();
        let mcp_config = root
            .pointer_mut("/extensions/com.example.roundtrip/manifest/server/mcp_config")
            .unwrap();

        let orig_cmd = mcp_config.get("command").cloned().unwrap();
        let orig_args = mcp_config.get("args").cloned().unwrap();

        let mut proxy_args: Vec<Value> = vec![json!("proxy"), json!("--")];
        proxy_args.push(orig_cmd.clone());
        proxy_args.extend(orig_args.as_array().unwrap().iter().cloned());

        let mcp_obj = mcp_config.as_object_mut().unwrap();
        mcp_obj.insert("command".to_string(), json!("clawdefender"));
        mcp_obj.insert("args".to_string(), json!(proxy_args));
        mcp_obj.insert(
            "_clawdefender_original".to_string(),
            json!({
                "command": orig_cmd,
                "args": orig_args,
            }),
        );

        write_config(&path, &root).unwrap();

        let wrapped: Value = read_config(&path).unwrap();
        assert!(is_dxt_wrapped(
            wrapped
                .pointer("/extensions/com.example.roundtrip")
                .unwrap()
        ));

        // Unwrap.
        let mut root2: Value = read_config(&path).unwrap();
        let mcp_config2 = root2
            .pointer_mut("/extensions/com.example.roundtrip/manifest/server/mcp_config")
            .unwrap();
        let mcp_obj2 = mcp_config2.as_object_mut().unwrap();

        let original = mcp_obj2.get("_clawdefender_original").cloned().unwrap();
        mcp_obj2.insert("command".to_string(), original["command"].clone());
        mcp_obj2.insert("args".to_string(), original["args"].clone());
        mcp_obj2.remove("_clawdefender_original");

        write_config(&path, &root2).unwrap();

        // Verify restored.
        let restored: Value = read_config(&path).unwrap();
        let mcp_restored = restored
            .pointer("/extensions/com.example.roundtrip/manifest/server/mcp_config")
            .unwrap();
        assert_eq!(mcp_restored["command"], "python");
        assert_eq!(
            mcp_restored["args"],
            json!(["-m", "my_server", "--verbose"])
        );
        assert_eq!(mcp_restored["env"]["PYTHONPATH"], "/usr/local/lib");
        assert!(!is_dxt_wrapped(
            restored
                .pointer("/extensions/com.example.roundtrip")
                .unwrap()
        ));
    }
}
