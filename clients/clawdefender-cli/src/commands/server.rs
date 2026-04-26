//! `rookbot server` — MCP server management commands.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

use super::{
    detect_servers_key, is_wrapped, known_clients, list_dxt_extensions, list_servers, read_config,
};
use clawdefender_core::config::ClawConfig;

#[derive(Subcommand, Debug)]
pub enum ServerAction {
    /// List all detected MCP servers.
    List,
    /// Wrap a server through Rookbot proxy.
    Protect {
        name: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Unwrap a server, restore original config.
    Unprotect { name: String },
    /// Block all tool calls from a server.
    Block { name: String },
    /// Unblock a previously blocked server.
    Unblock { name: String },
    /// Set trust level for a server.
    Trust {
        name: String,
        level: String, // untrusted, unknown, verified, trusted
    },
    /// Show behavioral profile for a server.
    Profile { name: String },
    /// Show daily activity history for a server.
    History {
        name: String,
        #[arg(long, default_value = "7")]
        days: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ServerState {
    #[serde(default)]
    blocked: Vec<String>,
    #[serde(default)]
    trust_levels: HashMap<String, String>,
}

/// Run the server subcommand.
pub fn run(action: &ServerAction, config: &ClawConfig) -> Result<()> {
    match action {
        ServerAction::List => list(),
        ServerAction::Protect { name, all } => {
            if *all {
                super::wrap::run_all("auto")
            } else if let Some(server_name) = name {
                super::wrap::run(server_name, "auto")
            } else {
                bail!("Specify a server name or use --all to protect all servers.\n\nExample: rookbot server protect my-server");
            }
        }
        ServerAction::Unprotect { name } => super::unwrap::run(name, "auto"),
        ServerAction::Block { name } => block(name),
        ServerAction::Unblock { name } => unblock(name),
        ServerAction::Trust { name, level } => set_trust(name, level),
        ServerAction::Profile { name } => profile(name, config),
        ServerAction::History { name, days } => history(name, *days, config),
    }
}

/// List all detected MCP servers.
fn list() -> Result<()> {
    let clients = known_clients();
    let mut total_servers = 0usize;

    println!("Detected MCP Servers");
    println!("====================");
    println!();

    for client in &clients {
        if !client.config_path.exists() {
            continue;
        }
        let Ok(config) = read_config(&client.config_path) else {
            continue;
        };
        let servers = list_servers(&config);
        if servers.is_empty() {
            continue;
        }

        println!(
            "  {} ({}):",
            client.display_name,
            client.config_path.display()
        );
        for server_name in &servers {
            let servers_key = detect_servers_key(&config);
            if let Some(server) = config
                .get(servers_key)
                .and_then(|s| s.as_object())
                .and_then(|s| s.get(server_name))
            {
                let wrapped = is_wrapped(server);
                let status = if wrapped { "[PROTECTED]" } else { "" };
                println!("    - {} {}", server_name, status);
                total_servers += 1;
            }
        }
        println!();
    }

    // List DXT extensions.
    let dxt_exts = list_dxt_extensions();
    if !dxt_exts.is_empty() {
        println!("  DXT Extensions:");
        for (display_name, id) in &dxt_exts {
            println!("    - {} ({})", display_name, id);
            total_servers += 1;
        }
        println!();
    }

    if total_servers == 0 {
        println!("  No MCP servers detected.");
        println!();
        println!(
            "  Install an MCP client (Claude Desktop, Cursor, VS Code) and configure servers."
        );
    } else {
        println!("  {} server(s) detected", total_servers);
    }

    Ok(())
}

/// Block all tool calls from a server.
fn block(name: &str) -> Result<()> {
    let mut state = load_server_state()?;
    if !state.blocked.contains(&name.to_string()) {
        state.blocked.push(name.to_string());
        save_server_state(&state)?;
    }
    println!("Blocked server: {}", name);
    println!();
    println!("All tool calls from this server will be rejected.");
    Ok(())
}

/// Unblock a previously blocked server.
fn unblock(name: &str) -> Result<()> {
    let mut state = load_server_state()?;
    state.blocked.retain(|s| s != name);
    save_server_state(&state)?;
    println!("Unblocked server: {}", name);
    Ok(())
}

/// Set trust level for a server.
fn set_trust(name: &str, level: &str) -> Result<()> {
    let valid_levels = ["untrusted", "unknown", "verified", "trusted"];
    if !valid_levels.contains(&level) {
        bail!(
            "Invalid trust level: {}\nValid levels: untrusted, unknown, verified, trusted",
            level
        );
    }

    let mut state = load_server_state()?;
    state
        .trust_levels
        .insert(name.to_string(), level.to_string());
    save_server_state(&state)?;

    println!("Set trust level for \"{}\": {}", name, level);
    Ok(())
}

/// Show behavioral profile for a server.
fn profile(name: &str, config: &ClawConfig) -> Result<()> {
    println!("Behavioral Profile: {}", name);
    println!("===================");
    println!();

    // Try to read audit log and summarize activity for this server.
    use clawdefender_core::audit::logger::FileAuditLogger;
    use clawdefender_core::audit::{AuditFilter, AuditLogger};

    let logger = FileAuditLogger::new(config.audit_log_path.clone(), config.log_rotation.clone())?;
    let filter = AuditFilter {
        source: Some(name.to_string()),
        limit: 1000,
        ..Default::default()
    };
    let records = logger.query(&filter)?;

    if records.is_empty() {
        println!("  No activity recorded for this server.");
        return Ok(());
    }

    let mut tool_calls = HashMap::new();
    let mut actions = HashMap::new();

    for record in &records {
        if let Some(ref tool) = record.tool_name {
            *tool_calls.entry(tool.clone()).or_insert(0u64) += 1;
        }
        *actions.entry(record.action_taken.clone()).or_insert(0u64) += 1;
    }

    println!("  Total events:     {}", records.len());
    println!();
    println!("  Actions taken:");
    for (action, count) in &actions {
        println!("    {:<10} {}", action, count);
    }
    println!();

    if !tool_calls.is_empty() {
        println!("  Top tools:");
        let mut tools: Vec<_> = tool_calls.iter().collect();
        tools.sort_by(|a, b| b.1.cmp(a.1));
        for (tool, count) in tools.iter().take(10) {
            println!("    {:<30} {}", tool, count);
        }
    }

    Ok(())
}

/// Show daily activity history for a server.
fn history(name: &str, days: u32, config: &ClawConfig) -> Result<()> {
    println!("Activity History: {} (last {} days)", name, days);
    println!("================");
    println!();

    use chrono::{Duration, Utc};
    use clawdefender_core::audit::logger::FileAuditLogger;
    use clawdefender_core::audit::{AuditFilter, AuditLogger};

    let logger = FileAuditLogger::new(config.audit_log_path.clone(), config.log_rotation.clone())?;
    let since = Utc::now() - Duration::days(days as i64);

    let filter = AuditFilter {
        source: Some(name.to_string()),
        from: Some(since),
        limit: 0,
        ..Default::default()
    };
    let records = logger.query(&filter)?;

    if records.is_empty() {
        println!("  No activity in the last {} days.", days);
        return Ok(());
    }

    // Group by day.
    use std::collections::BTreeMap;
    let mut daily: BTreeMap<String, u64> = BTreeMap::new();
    for record in &records {
        let date = record.timestamp.format("%Y-%m-%d").to_string();
        *daily.entry(date).or_insert(0) += 1;
    }

    println!("  Date           Events");
    println!("  {}", "-".repeat(26));
    for (date, count) in &daily {
        println!("  {:<14} {}", date, count);
    }
    println!();
    println!("  {} event(s) total", records.len());

    Ok(())
}

/// Load server state from ~/.local/share/rookbot/server_state.json.
fn load_server_state() -> Result<ServerState> {
    let path = server_state_path()?;
    if !path.exists() {
        return Ok(ServerState::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let state: ServerState = serde_json::from_str(&content)?;
    Ok(state)
}

/// Save server state to ~/.local/share/rookbot/server_state.json.
fn save_server_state(state: &ServerState) -> Result<()> {
    let path = server_state_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, content)?;
    Ok(())
}

/// Return the path to server_state.json.
fn server_state_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")?;
    Ok(PathBuf::from(home).join(".local/share/rookbot/server_state.json"))
}
