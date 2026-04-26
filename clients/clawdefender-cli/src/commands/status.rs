//! `rookbot status` — check if the Rookbot daemon is running and show wrapped servers.

use std::net::TcpStream;
use std::time::Duration;

use anyhow::Result;
use clawdefender_core::config::ClawConfig;

use crate::ipc_client::DaemonClient;
use crate::output::Output;

use super::{detect_servers_key, is_wrapped, known_clients, read_config};

pub fn run(config: &ClawConfig, out: &Output, ipc: &DaemonClient) -> Result<()> {
    out.header("Rookbot Status");
    out.kv("Socket", &config.daemon_socket_path.display().to_string());

    // Check daemon status.
    if ipc.is_daemon_running() {
        out.kv("Daemon", "running");
    } else {
        out.kv("Daemon", "not running");
        out.hint("Start it with: rookbot daemon start");
    }

    // Policy rule count.
    let rule_count = if config.policy_path.exists() {
        std::fs::read_to_string(&config.policy_path)
            .ok()
            .and_then(|c| clawdefender_core::policy::rule::parse_policy_toml(&c).ok())
            .map(|rules| rules.len())
            .unwrap_or(0)
    } else {
        0
    };
    out.kv(
        "Policy",
        &format!("{} ({} rule(s))", config.policy_path.display(), rule_count),
    );
    out.kv("Audit", &config.audit_log_path.display().to_string());

    // MCP server status.
    if config.mcp_server.enabled {
        let addr = format!("127.0.0.1:{}", config.mcp_server.http_port);
        let reachable =
            TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(1)).is_ok();
        if reachable {
            out.kv("MCP Server", &format!("running (http://{})", addr));
        } else {
            out.kv("MCP Server", &format!("not reachable (http://{})", addr));
        }
    } else {
        out.kv("MCP Server", "disabled");
    }

    // Guard API status.
    if config.guard_api.enabled {
        let guard_addr = format!("127.0.0.1:{}", config.guard_api.port);
        let guard_reachable =
            TcpStream::connect_timeout(&guard_addr.parse().unwrap(), Duration::from_secs(1))
                .is_ok();
        if guard_reachable {
            out.kv("Guard API", &format!("running (http://{})", guard_addr));
        } else {
            out.kv(
                "Guard API",
                &format!("not reachable (http://{})", guard_addr),
            );
        }
    } else {
        out.kv("Guard API", "disabled");
    }

    // Scan for wrapped servers.
    out.blank();
    out.header("Wrapped Servers");
    let clients = known_clients();
    let mut found = false;
    for client in &clients {
        if !client.config_path.exists() {
            continue;
        }
        if let Ok(config_json) = read_config(&client.config_path) {
            let key = detect_servers_key(&config_json);
            if let Some(servers) = config_json.get(key).and_then(|s| s.as_object()) {
                for (name, server) in servers {
                    if is_wrapped(server) {
                        out.println(&format!("  - {} ({})", name, client.display_name));
                        found = true;
                    }
                }
            }
        }
    }
    if !found {
        out.println("  (none)");
        out.blank();
        out.hint("Wrap an MCP server: rookbot wrap <server-name>");
    }

    Ok(())
}
