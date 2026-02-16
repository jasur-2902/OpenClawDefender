//! `clawai status` — check if the ClawAI daemon is running and show wrapped servers.

use std::os::unix::net::UnixStream;

use anyhow::Result;
use claw_core::config::ClawConfig;

use super::{is_wrapped, known_clients, read_config};

pub fn run(config: &ClawConfig) -> Result<()> {
    let socket_path = &config.daemon_socket_path;

    println!("ClawAI Status");
    println!("  Socket: {}", socket_path.display());

    // Check daemon status.
    match UnixStream::connect(socket_path) {
        Ok(_stream) => {
            println!("  Daemon: running");
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => {
                println!("  Daemon: not running (socket not found)");
            }
            std::io::ErrorKind::ConnectionRefused => {
                println!("  Daemon: not running (connection refused)");
            }
            _ => {
                println!("  Daemon: unknown ({e})");
            }
        },
    }

    println!("  Policy: {}", config.policy_path.display());
    println!("  Audit:  {}", config.audit_log_path.display());

    // Scan for wrapped servers.
    println!();
    println!("Wrapped Servers:");
    let clients = known_clients();
    let mut found = false;
    for client in &clients {
        if !client.config_path.exists() {
            continue;
        }
        if let Ok(config_json) = read_config(&client.config_path) {
            if let Some(servers) = config_json.get("mcpServers").and_then(|s| s.as_object()) {
                for (name, server) in servers {
                    if is_wrapped(server) {
                        println!("  - {} ({})", name, client.display_name);
                        found = true;
                    }
                }
            }
        }
    }
    if !found {
        println!("  (none)");
        println!();
        println!("Wrap an MCP server: clawai wrap <server-name>");
    }

    Ok(())
}
