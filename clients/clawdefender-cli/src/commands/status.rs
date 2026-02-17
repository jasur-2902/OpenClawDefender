//! `clawdefender status` — check if the ClawDefender daemon is running and show wrapped servers.

use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::Result;
use clawdefender_core::config::ClawConfig;

use super::{is_wrapped, known_clients, read_config};

pub fn run(config: &ClawConfig) -> Result<()> {
    let socket_path = &config.daemon_socket_path;

    println!("ClawDefender Status");
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

    // MCP server status.
    if config.mcp_server.enabled {
        let addr = format!("127.0.0.1:{}", config.mcp_server.http_port);
        let reachable = TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_secs(1),
        ).is_ok();
        if reachable {
            println!("  MCP Server: running (http://{})", addr);
        } else {
            println!("  MCP Server: not reachable (http://{})", addr);
        }
    } else {
        println!("  MCP Server: disabled");
    }

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
        println!("Wrap an MCP server: clawdefender wrap <server-name>");
    }

    Ok(())
}
