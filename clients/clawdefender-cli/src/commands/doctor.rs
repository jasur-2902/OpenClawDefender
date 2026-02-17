//! `clawdefender doctor` — run diagnostic checks on the ClawDefender installation.

use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use clawdefender_core::config::ClawConfig;
use clawdefender_slm::model_manager::ModelManager;

use super::{is_wrapped, known_clients, read_config};

pub fn run(config: &ClawConfig) -> Result<()> {
    println!("ClawDefender Doctor");
    println!();

    // 1. Check binary on PATH.
    check("clawdefender binary on PATH", which_clawdefender());

    // 2. Check config dir exists.
    let config_dir = config
        .policy_path
        .parent()
        .unwrap_or(Path::new("~/.config/clawdefender"));
    check(
        "Config directory exists",
        config_dir.exists(),
    );

    // 3. Check policy file parses.
    let policy_ok = if config.policy_path.exists() {
        let content = std::fs::read_to_string(&config.policy_path);
        match content {
            Ok(c) => clawdefender_core::policy::rule::parse_policy_toml(&c).is_ok(),
            Err(_) => false,
        }
    } else {
        false
    };
    check(
        &format!("Policy file parses ({})", config.policy_path.display()),
        policy_ok,
    );

    // 4. Check audit log dir writable.
    let audit_dir = config
        .audit_log_path
        .parent()
        .unwrap_or(Path::new("/tmp"));
    let audit_writable = if audit_dir.exists() {
        // Try creating a temp file.
        let test_file = audit_dir.join(".clawdefender_doctor_test");
        let ok = std::fs::write(&test_file, "test").is_ok();
        let _ = std::fs::remove_file(&test_file);
        ok
    } else {
        false
    };
    check(
        &format!("Audit log directory writable ({})", audit_dir.display()),
        audit_writable,
    );

    // 5. Check for MCP client installations.
    println!();
    println!("MCP Clients:");
    let clients = known_clients();
    for client in &clients {
        let exists = client.config_path.exists();
        check(
            &format!("{} config ({})", client.display_name, client.config_path.display()),
            exists,
        );
    }

    // 6. SLM checks.
    println!();
    println!("SLM (Small Language Model):");

    check(
        "SLM enabled in config",
        config.slm.enabled,
    );

    let model_installed = if let Some(ref model_path) = config.slm.model_path {
        model_path.exists()
    } else {
        // Check if any model is installed in default directory.
        ModelManager::default_dir()
            .ok()
            .and_then(|mgr| mgr.list_installed().ok())
            .map(|list| !list.is_empty())
            .unwrap_or(false)
    };
    check("SLM model installed", model_installed);

    if !model_installed {
        println!("    Hint: Run `clawdefender model download` to install a model,");
        println!("    or `clawdefender model list` to see available models.");
    }

    // Check for Apple Silicon (Metal GPU support).
    let is_arm = std::env::consts::ARCH == "aarch64";
    check(
        &format!("Metal GPU available (arch: {})", std::env::consts::ARCH),
        is_arm,
    );
    if !is_arm {
        println!("    Hint: Metal acceleration requires Apple Silicon (arm64).");
        println!("    CPU-only inference will be slower.");
    }

    check(
        "SLM config valid (context_size > 0)",
        config.slm.context_size > 0,
    );

    // 7. MCP server checks.
    println!();
    println!("MCP Server (Cooperative Security):");

    check(
        "MCP server enabled in config",
        config.mcp_server.enabled,
    );

    if config.mcp_server.enabled {
        check(
            &format!("MCP server HTTP port configured ({})", config.mcp_server.http_port),
            config.mcp_server.http_port > 0,
        );

        // Check if MCP server HTTP endpoint is reachable.
        let http_url = format!("http://127.0.0.1:{}", config.mcp_server.http_port);
        let http_reachable = TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", config.mcp_server.http_port).parse().unwrap(),
            Duration::from_secs(1),
        ).is_ok();
        check(
            &format!("MCP server HTTP endpoint reachable ({})", http_url),
            http_reachable,
        );
        if !http_reachable {
            println!("    Hint: Start the daemon or run `clawdefender serve` to enable the MCP server.");
        }
    }

    // 8. Check for wrapped servers.
    println!();
    println!("Wrapped Servers:");
    let mut found_any = false;
    for client in &clients {
        if !client.config_path.exists() {
            continue;
        }
        if let Ok(config_json) = read_config(&client.config_path) {
            if let Some(servers) = config_json.get("mcpServers").and_then(|s| s.as_object()) {
                for (name, server) in servers {
                    if is_wrapped(server) {
                        println!("  [wrapped] {} in {}", name, client.display_name);
                        found_any = true;
                    }
                }
            }
        }
    }
    if !found_any {
        println!("  (none)");
    }

    Ok(())
}

fn check(label: &str, ok: bool) {
    if ok {
        println!("  ok  {label}");
    } else {
        println!("  FAIL  {label}");
    }
}

fn which_clawdefender() -> bool {
    std::process::Command::new("which")
        .arg("clawdefender")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
