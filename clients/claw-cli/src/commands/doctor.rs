//! `clawai doctor` — run diagnostic checks on the ClawAI installation.

use std::path::Path;

use anyhow::Result;
use claw_core::config::ClawConfig;

use super::{is_wrapped, known_clients, read_config};

pub fn run(config: &ClawConfig) -> Result<()> {
    println!("ClawAI Doctor");
    println!();

    // 1. Check binary on PATH.
    check("clawai binary on PATH", which_clawai());

    // 2. Check config dir exists.
    let config_dir = config
        .policy_path
        .parent()
        .unwrap_or(Path::new("~/.config/clawai"));
    check(
        "Config directory exists",
        config_dir.exists(),
    );

    // 3. Check policy file parses.
    let policy_ok = if config.policy_path.exists() {
        let content = std::fs::read_to_string(&config.policy_path);
        match content {
            Ok(c) => claw_core::policy::rule::parse_policy_toml(&c).is_ok(),
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
        let test_file = audit_dir.join(".clawai_doctor_test");
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

    // 6. Check for wrapped servers.
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

fn which_clawai() -> bool {
    std::process::Command::new("which")
        .arg("clawai")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
