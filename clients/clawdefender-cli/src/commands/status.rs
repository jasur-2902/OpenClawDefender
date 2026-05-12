//! `rookbot status` — check if the Rookbot daemon is running and show wrapped servers.

use std::net::TcpStream;
use std::time::Duration;

use anyhow::Result;
use clawdefender_core::audit::logger::FileAuditLogger;
use clawdefender_core::audit::AuditLogger;
use clawdefender_core::config::settings::LogRotation;
use clawdefender_core::config::ClawConfig;

use crate::ipc_client::DaemonClient;
use crate::output::Output;

use super::{detect_servers_key, is_wrapped, known_clients, read_config};

pub fn run(config: &ClawConfig, out: &Output, ipc: &DaemonClient) -> Result<()> {
    // ── Title ───────────────────────────────────────────────────
    let shield = if out.no_color { "" } else { "\u{1f6e1}\u{fe0f}  " };
    out.println(&format!("{}{}", shield, out.bold("Rookbot Status")));
    out.println(&"\u{2501}".repeat(36));
    out.blank();

    // ── Daemon ──────────────────────────────────────────────────
    let daemon_running = ipc.is_daemon_running();
    if daemon_running {
        let indicator = if out.no_color { "[ok]" } else { "\u{1f7e2}" };
        out.println(&format!(
            "  {:<16} {} {}",
            out.bold("Daemon"),
            indicator,
            out.green("Running")
        ));
    } else {
        let indicator = if out.no_color { "[!!]" } else { "\u{1f534}" };
        out.println(&format!(
            "  {:<16} {} {}",
            out.bold("Daemon"),
            indicator,
            out.red("Not running")
        ));
        out.hint("Start with: rookbot daemon start");
    }

    // ── Policy ──────────────────────────────────────────────────
    let rule_count = if config.policy_path.exists() {
        std::fs::read_to_string(&config.policy_path)
            .ok()
            .and_then(|c| clawdefender_core::policy::rule::parse_policy_toml(&c).ok())
            .map(|rules| rules.len())
            .unwrap_or(0)
    } else {
        0
    };
    out.println(&format!(
        "  {:<16} {} rules loaded",
        out.bold("Policy"),
        rule_count
    ));

    // ── Audit Log ───────────────────────────────────────────────
    let event_count = get_event_count(config);
    out.println(&format!(
        "  {:<16} {} events recorded",
        out.bold("Audit Log"),
        format_number(event_count)
    ));

    // ── MCP Server ──────────────────────────────────────────────
    if config.mcp_server.enabled {
        let addr = format!("127.0.0.1:{}", config.mcp_server.http_port);
        let reachable =
            TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(1)).is_ok();
        if reachable {
            let indicator = if out.no_color { "[ok]" } else { "\u{1f7e2}" };
            out.println(&format!(
                "  {:<16} {} {} ({})",
                out.bold("MCP Server"),
                indicator,
                out.green("Running"),
                out.dim(&format!("localhost:{}", config.mcp_server.http_port))
            ));
        } else {
            let indicator = if out.no_color { "[!!]" } else { "\u{1f534}" };
            out.println(&format!(
                "  {:<16} {} {}",
                out.bold("MCP Server"),
                indicator,
                out.red("Not reachable")
            ));
        }
    } else {
        let indicator = if out.no_color { "[--]" } else { "\u{26aa}" };
        out.println(&format!(
            "  {:<16} {} {}",
            out.bold("MCP Server"),
            indicator,
            out.dim("Disabled")
        ));
    }

    // ── Guard API ───────────────────────────────────────────────
    if config.guard_api.enabled {
        let guard_addr = format!("127.0.0.1:{}", config.guard_api.port);
        let guard_reachable =
            TcpStream::connect_timeout(&guard_addr.parse().unwrap(), Duration::from_secs(1))
                .is_ok();
        if guard_reachable {
            let indicator = if out.no_color { "[ok]" } else { "\u{1f7e2}" };
            out.println(&format!(
                "  {:<16} {} {} ({})",
                out.bold("Guard API"),
                indicator,
                out.green("Running"),
                out.dim(&format!("localhost:{}", config.guard_api.port))
            ));
        } else {
            let indicator = if out.no_color { "[!!]" } else { "\u{1f534}" };
            out.println(&format!(
                "  {:<16} {} {}",
                out.bold("Guard API"),
                indicator,
                out.red("Not reachable")
            ));
        }
    } else {
        let indicator = if out.no_color { "[--]" } else { "\u{26aa}" };
        out.println(&format!(
            "  {:<16} {} {}",
            out.bold("Guard API"),
            indicator,
            out.dim("Disabled")
        ));
    }

    // ── Wrapped servers ─────────────────────────────────────────
    out.blank();
    out.println(&format!("  {}", out.bold("Protected Servers")));
    out.println(&format!("  {}", "\u{2500}".repeat(20)));

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
                        out.println(&format!(
                            "  {} {}  {}",
                            out.green("\u{25cf}"),
                            name,
                            out.dim(&format!("({})", client.display_name))
                        ));
                        found = true;
                    }
                }
            }
        }
    }
    if !found {
        out.println(&format!("  {}", out.dim("(none)")));
        out.blank();
        out.hint("Wrap an MCP server: rookbot wrap <server-name>");
    }

    out.blank();
    out.println(&format!(
        "  {}",
        out.dim("Tip: Use `rookbot watch` for live event monitoring")
    ));

    Ok(())
}

/// Count total events in the audit log.
fn get_event_count(config: &ClawConfig) -> u64 {
    let log_path = &config.audit_log_path;
    if !log_path.exists() {
        return 0;
    }
    let logger = FileAuditLogger::new(
        log_path.to_path_buf(),
        LogRotation {
            max_size_mb: 0,
            max_files: 0,
        },
    );
    match logger {
        Ok(l) => l.stats().map(|s| s.total_events).unwrap_or(0),
        Err(_) => 0,
    }
}

/// Format a number with comma separators.
fn format_number(n: u64) -> String {
    if n < 1_000 {
        return n.to_string();
    }
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
