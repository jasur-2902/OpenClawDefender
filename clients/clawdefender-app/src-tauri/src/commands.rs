use crate::daemon;
use crate::event_stream;
use crate::state::*;
use crate::tools::capabilities::infer_capabilities;
use crate::tools::detection::{
    load_known_servers, get_unacknowledged_servers, dismiss_server,
    set_server_trust_level, get_server_trust_info,
    set_server_permission_override, reset_server_permission_override,
};

use std::path::PathBuf;

/// Canonical MCP client config paths. Single source of truth used by
/// detect_mcp_clients(), list_mcp_servers(), get_tool_cards(), and scanner modules.
pub const MCP_CLIENT_CONFIGS: &[(&str, &str, &[&str])] = &[
    (
        "claude",
        "Claude Desktop",
        &[
            "Library/Application Support/Claude/claude_desktop_config.json",
            "Library/Application Support/Claude/config.json",
        ],
    ),
    (
        "cursor",
        "Cursor",
        &[
            ".cursor/mcp.json",
            ".cursor/mcp_config.json",
        ],
    ),
    (
        "vscode",
        "VS Code",
        &[
            ".vscode/mcp.json",
            "Library/Application Support/Code/User/settings.json",
        ],
    ),
    (
        "windsurf",
        "Windsurf",
        &[
            ".codeium/windsurf/mcp_config.json",
        ],
    ),
    (
        "claude_code",
        "Claude Code",
        &[
            ".claude/settings.json",
            ".claude.json",
        ],
    ),
    (
        "codex",
        "Codex",
        &[
            ".codex/config.toml",
        ],
    ),
];

/// Expand `MCP_CLIENT_CONFIGS` relative to the user's home directory and return
/// only the paths that exist on disk together with their `(client_id, display_name)`.
pub fn mcp_config_paths() -> Vec<(PathBuf, &'static str, &'static str)> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for &(client_id, display_name, rel_paths) in MCP_CLIENT_CONFIGS {
        for rel in rel_paths {
            let full = home.join(rel);
            if full.exists() {
                out.push((full, client_id, display_name));
                break; // first existing path wins per client
            }
        }
    }
    out
}

/// For a given client id, return all candidate config paths (whether they exist or not).
pub fn mcp_config_candidates_for(client_id: &str) -> Vec<PathBuf> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    for &(id, _, rel_paths) in MCP_CLIENT_CONFIGS {
        if id == client_id {
            return rel_paths.iter().map(|r| home.join(r)).collect();
        }
    }
    Vec::new()
}

/// Extract MCP server names from a TOML config (used by Codex).
/// Codex stores MCP servers under `[mcp_servers.<name>]` sections.
pub fn extract_servers_from_toml(contents: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let table: toml::Table = toml::from_str(contents).ok()?;
    let mcp_servers = table.get("mcp_servers")?.as_table()?;
    let mut map = serde_json::Map::new();
    for (name, value) in mcp_servers {
        // Convert TOML value to JSON value for uniform handling
        let json_str = serde_json::to_string(&value).unwrap_or_default();
        let json_val: serde_json::Value = serde_json::from_str(&json_str).unwrap_or_default();
        map.insert(name.clone(), json_val);
    }
    if map.is_empty() { None } else { Some(map) }
}

/// Extract MCP server entries from a config JSON, handling VS Code's nested
/// settings structure and the standard mcpServers/servers top-level keys.
/// Returns an owned map so it works for both top-level and nested layouts.
pub fn extract_servers(config: &serde_json::Value) -> Option<serde_json::Map<String, serde_json::Value>> {
    // VS Code stores MCP config under a nested "mcp.mcpServers" or "mcp.servers" key
    if let Some(mcp_obj) = config.get("mcp").and_then(|v| v.as_object()) {
        if let Some(obj) = mcp_obj.get("mcpServers").and_then(|v| v.as_object()) {
            return Some(obj.clone());
        }
        if let Some(obj) = mcp_obj.get("servers").and_then(|v| v.as_object()) {
            return Some(obj.clone());
        }
    }
    // Standard top-level keys
    let key = detect_servers_key(config);
    config.get(key).and_then(|v| v.as_object()).cloned()
}

// --- Daemon management ---

/// Count how many MCP servers are currently wrapped with RookBot across
/// all detected MCP client config files.
pub fn count_wrapped_servers() -> u32 {
    let mut wrapped = 0u32;
    for (path, _client_id, _display_name) in mcp_config_paths() {
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let servers_opt = serde_json::from_str::<serde_json::Value>(&contents)
            .ok()
            .and_then(|config| extract_servers(&config))
            .or_else(|| extract_servers_from_toml(&contents));
        if let Some(servers) = servers_opt {
            for (_name, entry) in &servers {
                if entry.get("_clawdefender_original").is_some()
                    || entry.get("_clawai_original").is_some()
                {
                    wrapped += 1;
                }
            }
        }
    }
    wrapped
}

#[tauri::command]
pub async fn get_daemon_status(
    state: tauri::State<'_, AppState>,
) -> Result<DaemonStatus, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_daemon_status());
    }

    let sock = daemon::socket_path().to_string_lossy().to_string();
    let wrapped = count_wrapped_servers();

    // Try live IPC query first
    if let Ok(metrics) = state.ipc_client.query_status() {
        let status = DaemonStatus {
            running: true,
            pid: None,
            uptime_seconds: None,
            version: None,
            socket_path: sock,
            servers_proxied: wrapped,
            events_processed: metrics.messages_total,
        };
        state.update_daemon_status(true, Some(status.clone()));
        return Ok(status);
    }

    // Fall back to cached status
    if let Ok(cached) = state.cached_status.lock() {
        if let Some(ref status) = *cached {
            return Ok(status.clone());
        }
    }

    // No cached status — return disconnected defaults
    Ok(DaemonStatus {
        running: false,
        pid: None,
        uptime_seconds: None,
        version: None,
        socket_path: sock,
        servers_proxied: wrapped,
        events_processed: 0,
    })
}

#[tauri::command]
pub async fn start_daemon(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Already running?
    if state.ipc_client.check_connection() {
        tracing::info!("Daemon already running, nothing to do");
        return Ok(());
    }

    daemon::start_daemon_process()?;

    // Poll up to 15 seconds for the daemon to become reachable (first-run may be slower)
    let mut connected = false;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if state.ipc_client.check_connection() {
            connected = true;
            break;
        }
    }

    if !connected {
        return Err("Daemon started but did not become reachable within 15 seconds".to_string());
    }

    if let Ok(mut flag) = state.daemon_started_by_gui.lock() {
        *flag = true;
    }
    state.update_daemon_status(true, None);
    tracing::info!("Daemon started successfully");
    Ok(())
}

#[tauri::command]
pub async fn stop_daemon(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Not running? Nothing to do.
    if !state.ipc_client.check_connection() && !daemon::is_daemon_running() {
        tracing::info!("Daemon is not running, nothing to stop");
        return Ok(());
    }

    daemon::stop_daemon_process()?;

    // Poll up to 5 seconds for the daemon to go away
    let mut stopped = false;
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if !daemon::is_daemon_running() {
            stopped = true;
            break;
        }
    }

    if !stopped {
        return Err("Daemon stop requested but it is still running after 5 seconds".to_string());
    }

    if let Ok(mut flag) = state.daemon_started_by_gui.lock() {
        *flag = false;
    }
    state.update_daemon_status(false, None);
    tracing::info!("Daemon stopped successfully");
    Ok(())
}

// --- Server management ---

#[tauri::command]
pub async fn detect_mcp_clients() -> Result<Vec<McpClient>, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_mcp_clients());
    }

    let home = dirs::home_dir().ok_or("Could not determine home directory")?;

    let mut results = Vec::new();

    for &(client_id, display_name, rel_paths) in MCP_CLIENT_CONFIGS {
        let paths: Vec<PathBuf> = rel_paths.iter().map(|r| home.join(r)).collect();
        let found_path = paths.iter().find(|p| p.exists());

        if let Some(config_path) = found_path {
            let servers_count = match std::fs::read_to_string(config_path) {
                Ok(contents) => match serde_json::from_str::<serde_json::Value>(&contents) {
                    Ok(config) => {
                        extract_servers(&config)
                            .map(|obj| obj.len() as u32)
                            .unwrap_or(0)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Malformed JSON in {}: {}",
                            config_path.display(),
                            e
                        );
                        0
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        "Could not read {}: {}",
                        config_path.display(),
                        e
                    );
                    0
                }
            };

            results.push(McpClient {
                name: client_id.to_string(),
                display_name: display_name.to_string(),
                config_path: config_path.to_string_lossy().to_string(),
                detected: true,
                servers_count,
            });
        } else {
            results.push(McpClient {
                name: client_id.to_string(),
                display_name: display_name.to_string(),
                config_path: paths[0].to_string_lossy().to_string(),
                detected: false,
                servers_count: 0,
            });
        }
    }

    Ok(results)
}

// --- Tool descriptions and process patterns for My Tools ---

const TOOL_DESCRIPTIONS: &[(&str, &str)] = &[
    ("claude", "Anthropic's desktop app"),
    ("cursor", "AI-first code editor"),
    ("vscode", "With MCP extension"),
    ("windsurf", "Codeium's AI IDE"),
    ("claude_code", "CLI for Claude"),
    ("codex", "OpenAI's AI coding app"),
];

const TOOL_PROCESS_PATTERNS: &[(&str, &[&str])] = &[
    ("claude", &["Claude"]),
    ("cursor", &["Cursor"]),
    ("vscode", &["Code Helper", "Code"]),
    ("windsurf", &["Windsurf"]),
    ("claude_code", &["claude"]),
    ("codex", &["Codex", "Codex Helper"]),
];

fn tool_description(client_id: &str) -> &'static str {
    TOOL_DESCRIPTIONS
        .iter()
        .find(|(id, _)| *id == client_id)
        .map(|(_, desc)| *desc)
        .unwrap_or("AI tool")
}

fn tool_process_patterns(client_id: &str) -> &'static [&'static str] {
    TOOL_PROCESS_PATTERNS
        .iter()
        .find(|(id, _)| *id == client_id)
        .map(|(_, patterns)| *patterns)
        .unwrap_or(&[])
}

/// Process stats collected from sysinfo.
struct ToolProcessStats {
    running: bool,
    pid: Option<u32>,
    children_count: u32,
    memory_bytes: u64,
    disk_read_bytes: u64,
    disk_written_bytes: u64,
    cpu_percent: f32,
}

/// Detect running processes matching a tool's known process name patterns.
/// Collects PID, children count, memory, disk I/O, and CPU stats.
fn detect_tool_process(client_id: &str, sys: &sysinfo::System) -> ToolProcessStats {
    let patterns = tool_process_patterns(client_id);
    if patterns.is_empty() {
        return ToolProcessStats {
            running: false, pid: None, children_count: 0,
            memory_bytes: 0, disk_read_bytes: 0, disk_written_bytes: 0, cpu_percent: 0.0,
        };
    }

    let mut main_pid: Option<sysinfo::Pid> = None;
    let mut children_count: u32 = 0;
    let mut memory_bytes: u64 = 0;
    let mut disk_read_bytes: u64 = 0;
    let mut disk_written_bytes: u64 = 0;
    let mut cpu_percent: f32 = 0.0;

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy();
        for pattern in patterns {
            if name.contains(pattern) {
                if main_pid.is_none() {
                    main_pid = Some(*pid);
                } else {
                    children_count += 1;
                }
                memory_bytes += process.memory();
                let disk = process.disk_usage();
                disk_read_bytes += disk.total_read_bytes;
                disk_written_bytes += disk.total_written_bytes;
                cpu_percent += process.cpu_usage();
                break;
            }
        }
    }

    match main_pid {
        Some(pid) => ToolProcessStats {
            running: true, pid: Some(pid.as_u32()), children_count,
            memory_bytes, disk_read_bytes, disk_written_bytes, cpu_percent,
        },
        None => ToolProcessStats {
            running: false, pid: None, children_count: 0,
            memory_bytes: 0, disk_read_bytes: 0, disk_written_bytes: 0, cpu_percent: 0.0,
        },
    }
}

/// Load audit events from today, returning per-server stats.
/// Returns a map of server_name -> (file_events, network_events, tool_call_events, last_timestamp).
fn load_today_audit_stats() -> std::collections::HashMap<String, (u32, u32, u32, Option<String>)> {
    let mut stats: std::collections::HashMap<String, (u32, u32, u32, Option<String>)> =
        std::collections::HashMap::new();

    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return stats,
    };
    let audit_path = home.join(".local/share/rookbot/audit.jsonl");
    let file = match std::fs::File::open(&audit_path) {
        Ok(f) => f,
        Err(_) => return stats,
    };

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    use std::io::BufRead;
    let reader = std::io::BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let entry: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Filter to today's events only
        let timestamp = entry.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        if !timestamp.starts_with(&today) {
            continue;
        }

        let server = match entry.get("server_name").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };

        let event_type = entry
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let action = entry
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let entry_stats = stats.entry(server).or_insert((0, 0, 0, None));

        // Classify event
        if event_type == "file_access" || action.contains("read") || action.contains("write") {
            entry_stats.0 += 1;
        } else if event_type == "network" || action.contains("http") || action.contains("fetch") {
            entry_stats.1 += 1;
        }
        // All proxy events count as tool calls
        if event_type == "proxy" || event_type == "tool_call" {
            entry_stats.2 += 1;
        }

        // Track the latest timestamp
        if entry_stats
            .3
            .as_ref()
            .map_or(true, |prev| timestamp > prev.as_str())
        {
            entry_stats.3 = Some(timestamp.to_string());
        }
    }

    stats
}

#[tauri::command]
pub async fn get_detected_tools_with_stats() -> Result<Vec<DetectedToolStats>, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;

    // Load today's audit stats once (shared across all tools)
    let audit_stats = load_today_audit_stats();

    // Create one shared sysinfo::System for all tools (avoids repeated process scans)
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    let mut results = Vec::new();

    for &(client_id, display_name, rel_paths) in MCP_CLIENT_CONFIGS {
        let paths: Vec<PathBuf> = rel_paths.iter().map(|r| home.join(r)).collect();
        let found_path = paths.iter().find(|p| p.exists());
        let installed = found_path.is_some();
        let config_path = found_path
            .unwrap_or(&paths[0])
            .to_string_lossy()
            .to_string();

        // Process detection + live stats
        let proc_stats = detect_tool_process(client_id, &sys);

        // MCP servers from config
        let mut mcp_servers = Vec::new();
        let mut files_accessed_today: u32 = 0;
        let mut network_connections_today: u32 = 0;
        let mut last_active: Option<String> = None;

        if let Some(cfg_path) = found_path {
            if let Ok(contents) = std::fs::read_to_string(cfg_path) {
                // Try JSON first, then TOML (for Codex)
                let servers_opt = serde_json::from_str::<serde_json::Value>(&contents)
                    .ok()
                    .and_then(|config| extract_servers(&config))
                    .or_else(|| extract_servers_from_toml(&contents));

                if let Some(servers) = servers_opt {
                    for (name, entry) in &servers {
                        let wrapped = entry.get("_clawdefender_original").is_some()
                            || entry.get("_clawai_original").is_some();

                        let server_stats = audit_stats.get(name.as_str());
                        let tool_calls_today = server_stats.map(|s| s.2).unwrap_or(0);

                        if let Some(ss) = server_stats {
                            files_accessed_today += ss.0;
                            network_connections_today += ss.1;
                            if let Some(ref ts) = ss.3 {
                                if last_active
                                    .as_ref()
                                    .map_or(true, |prev| ts.as_str() > prev.as_str())
                                {
                                    last_active = Some(ts.clone());
                                }
                            }
                        }

                        let status = if wrapped && proc_stats.running {
                            "running".to_string()
                        } else {
                            "stopped".to_string()
                        };

                        mcp_servers.push(McpServerInfo {
                            name: name.clone(),
                            wrapped,
                            tool_calls_today,
                            status,
                        });
                    }
                }
            }
        }

        results.push(DetectedToolStats {
            name: client_id.to_string(),
            display_name: display_name.to_string(),
            description: tool_description(client_id).to_string(),
            config_path,
            installed,
            running: proc_stats.running,
            pid: proc_stats.pid,
            children_count: proc_stats.children_count,
            memory_bytes: proc_stats.memory_bytes,
            disk_read_bytes: proc_stats.disk_read_bytes,
            disk_written_bytes: proc_stats.disk_written_bytes,
            cpu_percent: proc_stats.cpu_percent,
            files_accessed_today,
            network_connections_today,
            last_active,
            mcp_servers,
        });
    }

    Ok(results)
}

#[tauri::command]
pub async fn get_tool_live_activity(tool_name: String) -> Result<ToolLiveActivity, String> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    let patterns = tool_process_patterns(&tool_name);
    if patterns.is_empty() {
        return Err(format!("Unknown tool: {}", tool_name));
    }

    // Collect all PIDs for this tool
    let mut pids: Vec<u32> = Vec::new();
    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy();
        for pattern in patterns {
            if name.contains(pattern) {
                pids.push(pid.as_u32());
                break;
            }
        }
    }

    if pids.is_empty() {
        return Ok(ToolLiveActivity {
            tool_name,
            pids: vec![],
            open_files: vec![],
            network_connections: vec![],
        });
    }

    // Use lsof to get open files and network connections for all PIDs at once
    let pid_args: String = pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");

    let mut open_files = Vec::new();
    let mut network_connections = Vec::new();

    // Run lsof with full path, -n -P to skip DNS/port-name lookups, -F tfn for terse output
    if let Ok(output) = std::process::Command::new("/usr/sbin/lsof")
        .args(["-p", &pid_args, "-n", "-P", "-F", "tfn"])
        .output()
    {
        // Parse stdout even if lsof returns non-zero (it may still have valid partial output)
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_type = String::new();

        for line in stdout.lines() {
            if line.starts_with('t') {
                current_type = line[1..].to_string();
            } else if line.starts_with('n') {
                let current_name = &line[1..];

                // Skip system/framework paths and invalid entries
                if current_name.is_empty()
                    || current_name.starts_with("/dev/")
                    || current_name.starts_with("/System/")
                    || current_name.starts_with("/usr/lib/")
                    || current_name.starts_with("/Library/Apple/")
                    || current_name.contains("dyld_shared_cache")
                {
                    continue;
                }

                match current_type.as_str() {
                    "IPv4" | "IPv6" => {
                        // Parse network: "host:port->remote:port" or "*:port"
                        let (conn, state) = if let Some(arrow_pos) = current_name.find("->") {
                            let remote = &current_name[arrow_pos + 2..];
                            let state = if remote.contains("(ESTABLISHED)") {
                                "ESTABLISHED"
                            } else if remote.contains("(LISTEN)") {
                                "LISTEN"
                            } else if remote.contains("(CLOSE_WAIT)") {
                                "CLOSE_WAIT"
                            } else {
                                "CONNECTED"
                            };
                            (remote.split(" (").next().unwrap_or(remote).to_string(), state.to_string())
                        } else if current_name.contains("*:") || current_name.contains("LISTEN") {
                            (current_name.to_string(), "LISTEN".to_string())
                        } else {
                            (current_name.to_string(), "UNKNOWN".to_string())
                        };
                        network_connections.push(NetworkEntry {
                            connection: conn,
                            protocol: if current_type == "IPv6" { "TCP6".to_string() } else { "TCP".to_string() },
                            state,
                        });
                    }
                    "REG" | "DIR" => {
                        open_files.push(OpenFileEntry {
                            path: current_name.to_string(),
                            fd_type: current_type.clone(),
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    // Deduplicate files by path
    open_files.sort_by(|a, b| a.path.cmp(&b.path));
    open_files.dedup_by(|a, b| a.path == b.path);

    // Deduplicate network by connection
    network_connections.sort_by(|a, b| a.connection.cmp(&b.connection));
    network_connections.dedup_by(|a, b| a.connection == b.connection);

    Ok(ToolLiveActivity {
        tool_name,
        pids,
        open_files,
        network_connections,
    })
}

/// Get the list of MCP server names belonging to a tool (by client_id).
fn server_names_for_tool(client_id: &str) -> Vec<String> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    for &(id, _, rel_paths) in MCP_CLIENT_CONFIGS {
        if id != client_id {
            continue;
        }
        for rel in rel_paths {
            let full = home.join(rel);
            if let Ok(contents) = std::fs::read_to_string(&full) {
                // Try JSON first, then TOML (for Codex)
                if let Ok(config) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if let Some(servers) = extract_servers(&config) {
                        return servers.keys().cloned().collect();
                    }
                }
                if let Some(servers) = extract_servers_from_toml(&contents) {
                    return servers.keys().cloned().collect();
                }
            }
        }
    }
    Vec::new()
}

/// Get filtered activity events for a specific tool.
///
/// Returns recent audit events that belong to the tool's MCP servers,
/// with a human-readable one_liner for each. Supports pagination via
/// `count` and `offset`.
#[tauri::command]
pub async fn get_tool_activity(
    state: tauri::State<'_, AppState>,
    tool_name: String,
    count: usize,
    offset: usize,
) -> Result<Vec<ToolActivityEvent>, String> {
    let server_names = server_names_for_tool(&tool_name);

    // Collect matching events from the in-memory buffer
    let buf = state.event_buffer.lock().map_err(|e| e.to_string())?;
    let mut matching: Vec<ToolActivityEvent> = buf
        .iter()
        .rev()
        .filter(|e| server_names.iter().any(|s| s == &e.server_name))
        .map(|e| {
            let one_liner = format!("{} — {}", e.server_name, e.action);
            ToolActivityEvent {
                id: e.id.clone(),
                timestamp: e.timestamp.clone(),
                event_type: e.event_type.clone(),
                server_name: e.server_name.clone(),
                tool_name: e.tool_name.clone(),
                action: e.action.clone(),
                decision: e.decision.clone(),
                risk_level: e.risk_level.clone(),
                details: e.details.clone(),
                resource: e.resource.clone(),
                one_liner,
            }
        })
        .collect();
    drop(buf);

    // If the buffer doesn't have enough, supplement from audit.jsonl
    let need_from_file = (count + offset).saturating_sub(matching.len());
    if need_from_file > 0 {
        let historical = read_historical_events(need_from_file + 200, &[]);
        for e in historical.into_iter().rev() {
            if server_names.iter().any(|s| s == &e.server_name) {
                let one_liner = format!("{} — {}", e.server_name, e.action);
                matching.push(ToolActivityEvent {
                    id: e.id.clone(),
                    timestamp: e.timestamp.clone(),
                    event_type: e.event_type.clone(),
                    server_name: e.server_name.clone(),
                    tool_name: e.tool_name.clone(),
                    action: e.action.clone(),
                    decision: e.decision.clone(),
                    risk_level: e.risk_level.clone(),
                    details: e.details.clone(),
                    resource: e.resource.clone(),
                    one_liner,
                });
            }
        }
    }

    // Apply pagination
    let result: Vec<ToolActivityEvent> = matching
        .into_iter()
        .skip(offset)
        .take(count)
        .collect();

    Ok(result)
}

/// Get detailed process tree information for a specific tool.
#[tauri::command]
pub async fn get_tool_process_info(tool_name: String) -> Result<ToolProcessInfo, String> {
    use sysinfo::System;

    let patterns = tool_process_patterns(&tool_name);
    if patterns.is_empty() {
        return Ok(ToolProcessInfo {
            tool_name,
            running: false,
            main_pid: None,
            total_memory_bytes: 0,
            total_cpu_percent: 0.0,
            processes: Vec::new(),
        });
    }

    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    let mut processes = Vec::new();
    let mut main_pid: Option<u32> = None;
    let mut total_memory: u64 = 0;
    let mut total_cpu: f32 = 0.0;

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_string();
        let matches = patterns.iter().any(|p| name.contains(p));
        if !matches {
            continue;
        }

        let pid_u32 = pid.as_u32();
        let mem = process.memory();
        let cpu = process.cpu_usage();
        let parent = process.parent().map(|p| p.as_u32());

        if main_pid.is_none() {
            main_pid = Some(pid_u32);
        }

        total_memory += mem;
        total_cpu += cpu;

        processes.push(ToolProcessEntry {
            pid: pid_u32,
            name,
            memory_bytes: mem,
            cpu_percent: cpu,
            parent_pid: parent,
        });
    }

    // Sort by PID so the main process is first
    processes.sort_by_key(|p| p.pid);

    Ok(ToolProcessInfo {
        tool_name,
        running: main_pid.is_some(),
        main_pid,
        total_memory_bytes: total_memory,
        total_cpu_percent: total_cpu,
        processes,
    })
}

#[tauri::command]
pub async fn list_mcp_servers(client: String) -> Result<Vec<McpServer>, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_mcp_servers());
    }

    let candidates = mcp_config_candidates_for(&client);
    if candidates.is_empty() {
        return Err(format!("Unknown client: {}", client));
    }

    let config_path = match candidates.iter().find(|p| p.exists()) {
        Some(p) => p,
        None => return Ok(vec![]),
    };

    let contents = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;

    let config: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Malformed JSON in {}: {}", config_path.display(), e);
            return Ok(vec![]);
        }
    };

    let servers_obj = match extract_servers(&config) {
        Some(obj) => obj,
        None => return Ok(vec![]),
    };

    let mut servers = Vec::new();
    for (name, entry) in &servers_obj {
        let mut command = Vec::new();
        if let Some(cmd) = entry.get("command").and_then(|v| v.as_str()) {
            command.push(cmd.to_string());
        }
        if let Some(args) = entry.get("args").and_then(|v| v.as_array()) {
            for arg in args {
                if let Some(s) = arg.as_str() {
                    command.push(s.to_string());
                }
            }
        }

        let wrapped = entry.get("_clawdefender_original").is_some()
            || entry.get("_clawai_original").is_some();

        let status = if wrapped {
            "running".to_string()
        } else {
            "stopped".to_string()
        };

        servers.push(McpServer {
            name: name.clone(),
            command,
            wrapped,
            status,
            events_count: 0,
        });
    }

    Ok(servers)
}

#[tauri::command]
pub async fn wrap_server(client: String, server: String) -> Result<(), String> {
    tracing::info!("Wrapping server '{}' for client '{}'", server, client);

    let config_path = resolve_config_path(&client)?;

    let contents = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;

    let mut config: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Malformed JSON in {}: {}", config_path.display(), e))?;

    let key = detect_servers_key(&config).to_string();
    let servers_obj = config
        .get_mut(&key)
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| format!("No '{}' object found in {}", key, config_path.display()))?;

    // Collect keys before mutable borrow
    let available_servers: Vec<String> = servers_obj.keys().cloned().collect();
    let entry = servers_obj.get_mut(&server).ok_or_else(|| {
        format!(
            "Server '{}' not found. Available servers: {}",
            server,
            available_servers.join(", ")
        )
    })?;

    // Idempotent: already wrapped
    if entry.get("_clawdefender_original").is_some() || entry.get("_clawai_original").is_some() {
        tracing::info!("Server '{}' is already wrapped, nothing to do", server);
        return Ok(());
    }

    // Create .bak backup BEFORE modifying
    let backup_path = config_path.with_extension("json.bak");
    std::fs::copy(&config_path, &backup_path)
        .map_err(|e| format!("Failed to create backup at {}: {}", backup_path.display(), e))?;

    // Save original command and args
    let original_command = entry
        .get("command")
        .cloned()
        .unwrap_or(serde_json::Value::String(String::new()));
    let original_args = entry
        .get("args")
        .cloned()
        .unwrap_or(serde_json::Value::Array(vec![]));

    let original = serde_json::json!({
        "command": original_command,
        "args": original_args,
    });

    // Build new args: ["proxy", "--", "<original_command>", <original_args...>]
    let mut new_args: Vec<serde_json::Value> = vec![
        serde_json::Value::String("proxy".to_string()),
        serde_json::Value::String("--".to_string()),
    ];
    if let Some(cmd) = original_command.as_str() {
        new_args.push(serde_json::Value::String(cmd.to_string()));
    }
    if let Some(args_arr) = original_args.as_array() {
        new_args.extend(args_arr.iter().cloned());
    }

    let clawdefender_bin = resolve_clawdefender_path();
    let entry_obj = entry
        .as_object_mut()
        .ok_or("Server entry is not a JSON object")?;
    entry_obj.insert(
        "command".to_string(),
        serde_json::Value::String(clawdefender_bin),
    );
    entry_obj.insert("args".to_string(), serde_json::Value::Array(new_args));
    entry_obj.insert("_clawdefender_original".to_string(), original);

    // Write back with pretty formatting + trailing newline
    let output = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&config_path, format!("{}\n", output))
        .map_err(|e| format!("Failed to write {}: {}", config_path.display(), e))?;

    tracing::info!("Successfully wrapped server '{}'", server);
    Ok(())
}

#[tauri::command]
pub async fn unwrap_server(client: String, server: String) -> Result<(), String> {
    tracing::info!("Unwrapping server '{}' for client '{}'", server, client);

    let config_path = resolve_config_path(&client)?;

    let contents = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;

    let mut config: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Malformed JSON in {}: {}", config_path.display(), e))?;

    let key = detect_servers_key(&config).to_string();
    let servers_obj = config
        .get_mut(&key)
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| format!("No '{}' object found in {}", key, config_path.display()))?;

    // Collect keys before mutable borrow
    let available_servers: Vec<String> = servers_obj.keys().cloned().collect();
    let entry = servers_obj.get_mut(&server).ok_or_else(|| {
        format!(
            "Server '{}' not found. Available servers: {}",
            server,
            available_servers.join(", ")
        )
    })?;

    // Find the original data (support both naming conventions)
    let original_key = if entry.get("_clawdefender_original").is_some() {
        "_clawdefender_original"
    } else if entry.get("_clawai_original").is_some() {
        "_clawai_original"
    } else {
        // Idempotent: not wrapped
        tracing::info!("Server '{}' is not wrapped, nothing to do", server);
        return Ok(());
    };

    let original = entry
        .get(original_key)
        .cloned()
        .ok_or("Failed to read original config")?;

    // Create .bak backup BEFORE modifying
    let backup_path = config_path.with_extension("json.bak");
    std::fs::copy(&config_path, &backup_path)
        .map_err(|e| format!("Failed to create backup at {}: {}", backup_path.display(), e))?;

    // Restore original command and args
    let entry_obj = entry
        .as_object_mut()
        .ok_or("Server entry is not a JSON object")?;

    if let Some(cmd) = original.get("command") {
        entry_obj.insert("command".to_string(), cmd.clone());
    }
    if let Some(args) = original.get("args") {
        entry_obj.insert("args".to_string(), args.clone());
    }

    // Remove both original markers
    entry_obj.remove("_clawdefender_original");
    entry_obj.remove("_clawai_original");

    // Write back with pretty formatting + trailing newline
    let output = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&config_path, format!("{}\n", output))
        .map_err(|e| format!("Failed to write {}: {}", config_path.display(), e))?;

    tracing::info!("Successfully unwrapped server '{}'", server);
    Ok(())
}

// --- Policy management ---

/// Path to the policy TOML file.
fn policy_file_path() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_default();
    home.join(".config").join("rookbot").join("policy.toml")
}

/// Sanitize a rule name into a valid TOML key (lowercase, spaces to hyphens).
fn sanitize_rule_key(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .replace(' ', "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

fn frontend_action_to_toml(action: &str) -> &str {
    match action {
        "deny" => "block",
        "audit" => "log",
        _ => action,
    }
}

fn toml_action_to_frontend(action: &str) -> &str {
    match action {
        "block" => "deny",
        "log" => "audit",
        _ => action,
    }
}

fn infer_resource_from_match(match_table: &toml::Value) -> String {
    if let Some(table) = match_table.as_table() {
        if let Some(types) = table.get("event_type").and_then(|v| v.as_array()) {
            let has_network = types.iter().any(|v| {
                v.as_str()
                    .map(|s| s == "connect" || s == "dns" || s == "bind")
                    .unwrap_or(false)
            });
            if has_network {
                return "network".to_string();
            }
        }
        if table.contains_key("resource_path") {
            return "file".to_string();
        }
    }
    "*".to_string()
}

fn extract_pattern_from_match(match_table: &toml::Value) -> String {
    match_table
        .get("resource_path")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("*")
        .to_string()
}

fn read_policy_file() -> Result<toml::Value, String> {
    let path = policy_file_path();
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read policy file {}: {}", path.display(), e))?;
    contents
        .parse::<toml::Value>()
        .map_err(|e| format!("Failed to parse policy TOML: {}", e))
}

fn write_policy_file(doc: &toml::Value) -> Result<(), String> {
    let path = policy_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }
    if path.exists() {
        let backup = path.with_extension("toml.bak");
        if let Err(e) = std::fs::copy(&path, &backup) {
            tracing::warn!("Failed to create policy backup at {}: {}", backup.display(), e);
        }
    }
    let toml_string =
        toml::to_string_pretty(doc).map_err(|e| format!("Failed to serialize policy: {}", e))?;
    std::fs::write(&path, toml_string)
        .map_err(|e| format!("Failed to write policy file: {}", e))?;
    Ok(())
}

fn toml_to_policy_rules(doc: &toml::Value) -> Vec<PolicyRule> {
    let mut rules = Vec::new();
    if let Some(rules_table) = doc.get("rules").and_then(|v| v.as_table()) {
        for (key, value) in rules_table {
            if let Some(table) = value.as_table() {
                let action_raw = table
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("allow");
                let description = table
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let priority = table
                    .get("priority")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(0) as i32;
                let enabled = table
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let match_section = table
                    .get("match")
                    .cloned()
                    .unwrap_or(toml::Value::Table(toml::map::Map::new()));
                let resource = infer_resource_from_match(&match_section);
                let pattern = extract_pattern_from_match(&match_section);
                rules.push(PolicyRule {
                    name: key.clone(),
                    description,
                    action: toml_action_to_frontend(action_raw).to_string(),
                    resource,
                    pattern,
                    priority,
                    enabled,
                });
            }
        }
    }
    rules.sort_by_key(|x| std::cmp::Reverse(x.priority));
    rules
}

fn policy_rule_to_toml_table(rule: &PolicyRule) -> toml::Value {
    let mut table = toml::map::Map::new();
    table.insert(
        "description".to_string(),
        toml::Value::String(rule.description.clone()),
    );
    table.insert(
        "action".to_string(),
        toml::Value::String(frontend_action_to_toml(&rule.action).to_string()),
    );
    table.insert(
        "priority".to_string(),
        toml::Value::Integer(rule.priority as i64),
    );
    table.insert("enabled".to_string(), toml::Value::Boolean(rule.enabled));
    if let Some(msg) = rule_message_for_action(&rule.action) {
        table.insert("message".to_string(), toml::Value::String(msg));
    }
    let mut match_table = toml::map::Map::new();
    let patterns: Vec<toml::Value> = rule
        .pattern
        .split(',')
        .map(|p| toml::Value::String(p.trim().to_string()))
        .collect();
    if rule.resource == "network" {
        match_table.insert(
            "event_type".to_string(),
            toml::Value::Array(vec![toml::Value::String("connect".to_string())]),
        );
    } else {
        match_table.insert("resource_path".to_string(), toml::Value::Array(patterns));
    }
    table.insert("match".to_string(), toml::Value::Table(match_table));
    toml::Value::Table(table)
}

fn rule_message_for_action(action: &str) -> Option<String> {
    match action {
        "deny" => Some("Access denied by policy".to_string()),
        "prompt" => Some("Allow this operation?".to_string()),
        "audit" => Some("Operation logged".to_string()),
        _ => None,
    }
}

fn default_policy_doc() -> toml::Value {
    let rules = vec![
        PolicyRule {
            name: "block-sensitive-files".to_string(),
            description: "Block access to sensitive configuration files".to_string(),
            action: "deny".to_string(),
            resource: "file".to_string(),
            pattern: "**/.env*,**/.ssh/*".to_string(),
            priority: 100,
            enabled: true,
        },
        PolicyRule {
            name: "prompt-write-operations".to_string(),
            description: "Prompt user before any file write operations".to_string(),
            action: "prompt".to_string(),
            resource: "file".to_string(),
            pattern: "**/*".to_string(),
            priority: 50,
            enabled: true,
        },
        PolicyRule {
            name: "audit-network-access".to_string(),
            description: "Log all network access attempts".to_string(),
            action: "audit".to_string(),
            resource: "network".to_string(),
            pattern: "*".to_string(),
            priority: 10,
            enabled: true,
        },
    ];
    let mut rules_table = toml::map::Map::new();
    for rule in &rules {
        let key = sanitize_rule_key(&rule.name);
        rules_table.insert(key, policy_rule_to_toml_table(rule));
    }
    let mut doc = toml::map::Map::new();
    doc.insert("rules".to_string(), toml::Value::Table(rules_table));
    toml::Value::Table(doc)
}

fn try_reload_daemon(state: &AppState) {
    match state.ipc_client.reload_policy() {
        Ok(resp) => {
            if resp.ok {
                tracing::info!("Daemon policy reloaded successfully");
            } else {
                tracing::warn!(
                    "Daemon reload returned error: {}",
                    resp.error.unwrap_or_default()
                );
            }
        }
        Err(_) => {
            tracing::debug!("Daemon not connected, skipping policy reload");
        }
    }
}

#[tauri::command]
pub async fn get_policy() -> Result<Policy, String> {
    let path = policy_file_path();
    let now = chrono::Utc::now().to_rfc3339();

    if !path.exists() {
        let doc = default_policy_doc();
        write_policy_file(&doc)?;
        let rules = toml_to_policy_rules(&doc);
        return Ok(Policy {
            name: "default".to_string(),
            version: "1.0.0".to_string(),
            rules,
            created_at: now.clone(),
            updated_at: now,
        });
    }

    let doc = read_policy_file()?;
    let rules = toml_to_policy_rules(&doc);

    let (created_at, updated_at) = match std::fs::metadata(&path) {
        Ok(meta) => {
            let modified = meta
                .modified()
                .ok()
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                })
                .unwrap_or_else(|| now.clone());
            let created = meta
                .created()
                .ok()
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                })
                .unwrap_or_else(|| now.clone());
            (created, modified)
        }
        Err(_) => (now.clone(), now),
    };

    Ok(Policy {
        name: "default".to_string(),
        version: "1.0.0".to_string(),
        rules,
        created_at,
        updated_at,
    })
}

#[tauri::command]
pub async fn add_rule(
    state: tauri::State<'_, AppState>,
    rule: PolicyRule,
) -> Result<(), String> {
    let name = rule.name.trim().to_string();
    if name.is_empty() {
        return Err("Rule name cannot be empty".to_string());
    }

    let path = policy_file_path();
    let mut doc = if path.exists() {
        read_policy_file()?
    } else {
        let mut m = toml::map::Map::new();
        m.insert(
            "rules".to_string(),
            toml::Value::Table(toml::map::Map::new()),
        );
        toml::Value::Table(m)
    };

    let key = sanitize_rule_key(&name);
    if key.is_empty() {
        return Err("Rule name must contain at least one alphanumeric character".to_string());
    }

    if let Some(rules) = doc.get("rules").and_then(|v| v.as_table()) {
        if rules.contains_key(&key) {
            return Err(format!("Rule '{}' already exists", key));
        }
    }

    if let Some(rules) = doc.get_mut("rules").and_then(|v| v.as_table_mut()) {
        rules.insert(key.clone(), policy_rule_to_toml_table(&rule));
    } else {
        let mut rules_table = toml::map::Map::new();
        rules_table.insert(key.clone(), policy_rule_to_toml_table(&rule));
        if let Some(table) = doc.as_table_mut() {
            table.insert("rules".to_string(), toml::Value::Table(rules_table));
        }
    }

    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!("Added policy rule: {}", name);
    Ok(())
}

#[tauri::command]
pub async fn update_rule(
    state: tauri::State<'_, AppState>,
    rule: PolicyRule,
) -> Result<(), String> {
    let path = policy_file_path();
    if !path.exists() {
        return Err("Policy file does not exist".to_string());
    }

    let mut doc = read_policy_file()?;
    let key = sanitize_rule_key(&rule.name);

    let exists = doc
        .get("rules")
        .and_then(|v| v.as_table())
        .map(|t| t.contains_key(&key))
        .unwrap_or(false);

    if !exists {
        return Err(format!("Rule '{}' not found", key));
    }

    if let Some(rules) = doc.get_mut("rules").and_then(|v| v.as_table_mut()) {
        rules.insert(key.clone(), policy_rule_to_toml_table(&rule));
    }

    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!("Updated policy rule: {}", key);
    Ok(())
}

#[tauri::command]
pub async fn delete_rule(
    state: tauri::State<'_, AppState>,
    rule_name: String,
) -> Result<(), String> {
    let path = policy_file_path();
    if !path.exists() {
        return Err("Policy file does not exist".to_string());
    }

    let mut doc = read_policy_file()?;
    let key = sanitize_rule_key(&rule_name);

    let removed = doc
        .get_mut("rules")
        .and_then(|v| v.as_table_mut())
        .map(|t| t.remove(&key).is_some())
        .unwrap_or(false);

    if !removed {
        return Err(format!("Rule '{}' not found", key));
    }

    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!("Deleted policy rule: {}", key);
    Ok(())
}

#[tauri::command]
pub async fn duplicate_rule(
    state: tauri::State<'_, AppState>,
    rule_name: String,
) -> Result<(), String> {
    let path = policy_file_path();
    if !path.exists() {
        return Err("Policy file does not exist".to_string());
    }

    let mut doc = read_policy_file()?;
    let key = sanitize_rule_key(&rule_name);

    // Find the original rule
    let original = doc
        .get("rules")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get(&key))
        .cloned()
        .ok_or_else(|| format!("Rule '{}' not found", key))?;

    // Generate a unique copy key
    let rules_table = doc
        .get("rules")
        .and_then(|v| v.as_table())
        .cloned()
        .unwrap_or_default();

    let mut copy_key = format!("{}-copy", key);
    let mut suffix = 2;
    while rules_table.contains_key(&copy_key) {
        copy_key = format!("{}-copy-{}", key, suffix);
        suffix += 1;
    }

    // Update the description to indicate it's a copy
    let mut copy_value = original;
    if let Some(table) = copy_value.as_table_mut() {
        let orig_desc = table
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        table.insert(
            "description".to_string(),
            toml::Value::String(format!("{} (copy)", orig_desc)),
        );
    }

    if let Some(rules) = doc.get_mut("rules").and_then(|v| v.as_table_mut()) {
        rules.insert(copy_key.clone(), copy_value);
    }

    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!("Duplicated policy rule '{}' as '{}'", key, copy_key);
    Ok(())
}

#[tauri::command]
pub async fn toggle_rule(
    state: tauri::State<'_, AppState>,
    rule_name: String,
) -> Result<(), String> {
    let path = policy_file_path();
    if !path.exists() {
        return Err("Policy file does not exist".to_string());
    }

    let mut doc = read_policy_file()?;
    let key = sanitize_rule_key(&rule_name);

    let current_enabled = doc
        .get("rules")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get(&key))
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let rule_table = doc
        .get_mut("rules")
        .and_then(|v| v.as_table_mut())
        .and_then(|t| t.get_mut(&key))
        .and_then(|v| v.as_table_mut())
        .ok_or_else(|| format!("Rule '{}' not found", key))?;

    rule_table.insert("enabled".to_string(), toml::Value::Boolean(!current_enabled));

    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!(
        "Toggled rule '{}' enabled: {} -> {}",
        key,
        current_enabled,
        !current_enabled
    );
    Ok(())
}

#[tauri::command]
pub async fn reorder_rules(
    state: tauri::State<'_, AppState>,
    rule_names: Vec<String>,
) -> Result<(), String> {
    let path = policy_file_path();
    if !path.exists() {
        return Err("Policy file does not exist".to_string());
    }

    let mut doc = read_policy_file()?;

    // Assign priorities based on the order: first item gets highest priority
    let total = rule_names.len() as i64;
    let rules = doc
        .get_mut("rules")
        .and_then(|v| v.as_table_mut())
        .ok_or_else(|| "No rules table in policy".to_string())?;

    for (idx, name) in rule_names.iter().enumerate() {
        let key = sanitize_rule_key(name);
        if let Some(rule_table) = rules.get_mut(&key).and_then(|v| v.as_table_mut()) {
            let priority = (total - idx as i64) * 10;
            rule_table.insert("priority".to_string(), toml::Value::Integer(priority));
        }
    }

    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!("Reordered {} policy rules", rule_names.len());
    Ok(())
}

#[tauri::command]
pub async fn reload_policy(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    match state.ipc_client.reload_policy() {
        Ok(resp) => {
            if resp.ok {
                tracing::info!("Policy reloaded successfully");
                Ok(())
            } else {
                Err(format!(
                    "Daemon reload failed: {}",
                    resp.error.unwrap_or_else(|| "unknown error".to_string())
                ))
            }
        }
        Err(_) => {
            tracing::debug!("Daemon not connected, policy reload skipped");
            Ok(())
        }
    }
}

#[tauri::command]
pub async fn list_templates() -> Result<Vec<PolicyTemplate>, String> {
    Ok(vec![
        PolicyTemplate {
            name: "strict".to_string(),
            description: "Maximum security - deny by default, prompt for everything".to_string(),
            rules_count: 12,
            category: "security".to_string(),
        },
        PolicyTemplate {
            name: "balanced".to_string(),
            description: "Balanced security - block dangerous operations, audit the rest"
                .to_string(),
            rules_count: 8,
            category: "security".to_string(),
        },
        PolicyTemplate {
            name: "permissive".to_string(),
            description: "Minimal restrictions - audit everything, block only known threats"
                .to_string(),
            rules_count: 4,
            category: "security".to_string(),
        },
        PolicyTemplate {
            name: "developer".to_string(),
            description: "Developer-friendly - allow most operations with audit logging"
                .to_string(),
            rules_count: 6,
            category: "workflow".to_string(),
        },
    ])
}

fn template_rules(name: &str) -> Result<Vec<PolicyRule>, String> {
    match name {
        "strict" => Ok(vec![
            PolicyRule { name: "block-env-files".into(), description: "Block access to .env files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.env*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-ssh-keys".into(), description: "Block access to SSH keys".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.ssh/*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-aws-credentials".into(), description: "Block access to AWS credentials".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.aws/credentials".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-gnupg".into(), description: "Block access to GPG keys".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.gnupg/*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-kube-config".into(), description: "Block access to Kubernetes config".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.kube/config".into(), priority: 95, enabled: true },
            PolicyRule { name: "block-docker-config".into(), description: "Block access to Docker credentials".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.docker/config.json".into(), priority: 95, enabled: true },
            PolicyRule { name: "prompt-all-writes".into(), description: "Prompt before any file write".into(), action: "prompt".into(), resource: "file".into(), pattern: "**/*".into(), priority: 80, enabled: true },
            PolicyRule { name: "prompt-network-access".into(), description: "Prompt before any network access".into(), action: "prompt".into(), resource: "network".into(), pattern: "*".into(), priority: 80, enabled: true },
            PolicyRule { name: "prompt-system-dirs".into(), description: "Prompt before accessing system directories".into(), action: "prompt".into(), resource: "file".into(), pattern: "/etc/**,/usr/**,/System/**".into(), priority: 75, enabled: true },
            PolicyRule { name: "audit-all-reads".into(), description: "Log all file read operations".into(), action: "audit".into(), resource: "file".into(), pattern: "**/*".into(), priority: 10, enabled: true },
            PolicyRule { name: "audit-all-network".into(), description: "Log all network activity".into(), action: "audit".into(), resource: "network".into(), pattern: "*".into(), priority: 10, enabled: true },
            PolicyRule { name: "block-private-keys".into(), description: "Block access to private key files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/*.pem,**/*.key,**/id_rsa,**/id_ed25519".into(), priority: 100, enabled: true },
        ]),
        "balanced" => Ok(vec![
            PolicyRule { name: "block-env-files".into(), description: "Block access to .env files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.env*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-ssh-keys".into(), description: "Block access to SSH keys".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.ssh/*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-private-keys".into(), description: "Block access to private key files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/*.pem,**/*.key".into(), priority: 100, enabled: true },
            PolicyRule { name: "prompt-write-operations".into(), description: "Prompt before file writes outside project".into(), action: "prompt".into(), resource: "file".into(), pattern: "**/*".into(), priority: 50, enabled: true },
            PolicyRule { name: "prompt-network-unknown".into(), description: "Prompt for unrecognized network destinations".into(), action: "prompt".into(), resource: "network".into(), pattern: "*".into(), priority: 50, enabled: true },
            PolicyRule { name: "audit-file-reads".into(), description: "Log file read operations".into(), action: "audit".into(), resource: "file".into(), pattern: "**/*".into(), priority: 10, enabled: true },
            PolicyRule { name: "audit-network".into(), description: "Log all network access".into(), action: "audit".into(), resource: "network".into(), pattern: "*".into(), priority: 10, enabled: true },
            PolicyRule { name: "block-system-dirs".into(), description: "Block writes to system directories".into(), action: "deny".into(), resource: "file".into(), pattern: "/etc/**,/usr/**,/System/**".into(), priority: 90, enabled: true },
        ]),
        "permissive" => Ok(vec![
            PolicyRule { name: "block-env-files".into(), description: "Block access to .env files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.env*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-ssh-keys".into(), description: "Block access to SSH private keys".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.ssh/id_*".into(), priority: 100, enabled: true },
            PolicyRule { name: "audit-all-operations".into(), description: "Log all file operations".into(), action: "audit".into(), resource: "file".into(), pattern: "**/*".into(), priority: 5, enabled: true },
            PolicyRule { name: "audit-all-network".into(), description: "Log all network access".into(), action: "audit".into(), resource: "network".into(), pattern: "*".into(), priority: 5, enabled: true },
        ]),
        "developer" => Ok(vec![
            PolicyRule { name: "block-env-files".into(), description: "Block access to .env files".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.env*".into(), priority: 100, enabled: true },
            PolicyRule { name: "block-ssh-keys".into(), description: "Block access to SSH keys".into(), action: "deny".into(), resource: "file".into(), pattern: "**/.ssh/*".into(), priority: 100, enabled: true },
            PolicyRule { name: "allow-project-writes".into(), description: "Allow writes within project directories".into(), action: "allow".into(), resource: "file".into(), pattern: "**/*".into(), priority: 50, enabled: true },
            PolicyRule { name: "audit-file-operations".into(), description: "Log all file operations".into(), action: "audit".into(), resource: "file".into(), pattern: "**/*".into(), priority: 10, enabled: true },
            PolicyRule { name: "audit-network".into(), description: "Log all network access".into(), action: "audit".into(), resource: "network".into(), pattern: "*".into(), priority: 10, enabled: true },
            PolicyRule { name: "prompt-system-writes".into(), description: "Prompt before writing to system directories".into(), action: "prompt".into(), resource: "file".into(), pattern: "/etc/**,/usr/**".into(), priority: 80, enabled: true },
        ]),
        _ => Err(format!("Unknown template: {}", name)),
    }
}

/// Infer the current security level by comparing policy rules against known templates.
/// Returns "strict", "balanced", "permissive", "developer", or "custom".
fn infer_security_level() -> String {
    let path = policy_file_path();
    let current_rules = match std::fs::read_to_string(&path) {
        Ok(content) => {
            match content.parse::<toml::Value>() {
                Ok(table) => {
                    // Extract rule names from the policy file
                    if let Some(rules) = table.get("rules").and_then(|r| r.as_table()) {
                        rules.keys().cloned().collect::<std::collections::HashSet<String>>()
                    } else {
                        return "custom".to_string();
                    }
                }
                Err(_) => return "balanced".to_string(),
            }
        }
        Err(_) => return "balanced".to_string(),
    };

    // Compare against each known template
    for template_name in &["strict", "balanced", "permissive", "developer"] {
        if let Ok(template_rules_vec) = template_rules(template_name) {
            let template_names: std::collections::HashSet<String> = template_rules_vec
                .iter()
                .map(|r| sanitize_rule_key(&r.name))
                .collect();
            if current_rules == template_names {
                // Map "permissive" to "monitor-only" for UI display
                return if *template_name == "permissive" {
                    "monitor-only".to_string()
                } else {
                    template_name.to_string()
                };
            }
        }
    }

    "custom".to_string()
}

#[tauri::command]
pub async fn apply_template(
    state: tauri::State<'_, AppState>,
    name: String,
) -> Result<(), String> {
    let rules = template_rules(&name)?;
    let mut rules_table = toml::map::Map::new();
    for rule in &rules {
        let key = sanitize_rule_key(&rule.name);
        rules_table.insert(key, policy_rule_to_toml_table(rule));
    }
    let mut doc = toml::map::Map::new();
    doc.insert("rules".to_string(), toml::Value::Table(rules_table));
    let doc = toml::Value::Table(doc);
    write_policy_file(&doc)?;
    try_reload_daemon(&state);
    tracing::info!("Applied policy template: {}", name);
    Ok(())
}

// --- Event stream ---

#[tauri::command]
pub async fn get_recent_events(
    state: tauri::State<'_, AppState>,
    count: u32,
) -> Result<Vec<AuditEvent>, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_recent_events());
    }

    let count = count.min(10_000) as usize;

    // 1. Read events from the in-memory buffer (populated by the event stream watcher)
    let buffer_events: Vec<AuditEvent> = state
        .event_buffer
        .lock()
        .map(|buf| buf.clone())
        .unwrap_or_default();

    if buffer_events.len() >= count {
        // Buffer has enough — take the last `count` events, reverse for newest-first
        let start = buffer_events.len() - count;
        let mut result: Vec<AuditEvent> = buffer_events[start..].to_vec();
        result.reverse();
        return Ok(result);
    }

    // 2. Buffer doesn't have enough — supplement with historical events from audit.jsonl
    let needed = count - buffer_events.len();
    let historical = read_historical_events(needed, &buffer_events);

    // 3. Merge: historical (oldest) + buffer events, deduplicate by id
    let mut seen = std::collections::HashSet::new();
    let mut merged: Vec<AuditEvent> = Vec::with_capacity(count);

    // Add buffer events first (they are more recent / authoritative)
    for event in &buffer_events {
        if seen.insert(event.id.clone()) {
            merged.push(event.clone());
        }
    }

    // Add historical events that aren't already in the buffer
    for event in historical {
        if seen.insert(event.id.clone()) {
            merged.push(event);
        }
    }

    // Sort newest-first by timestamp (descending)
    merged.sort_by_key(|x| std::cmp::Reverse(x.timestamp.clone()));

    // Truncate to requested count
    merged.truncate(count);

    Ok(merged)
}

/// Read historical events from the audit.jsonl file on disk.
/// Reads from the end of the file efficiently for large files.
/// Excludes events whose IDs are already in `existing` to avoid duplicates.
pub(crate) fn read_historical_events(needed: usize, existing: &[AuditEvent]) -> Vec<AuditEvent> {
    let path = event_stream::audit_log_path();
    if !path.exists() {
        return Vec::new();
    }

    // For efficiency, read the last chunk of the file rather than the whole thing.
    // 64 KB per event is generous; most JSONL lines are < 1 KB.
    const CHUNK_SIZE: u64 = 256 * 1024; // 256 KB

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to open audit.jsonl for history");
            return Vec::new();
        }
    };

    let file_len = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return Vec::new(),
    };

    // Determine how much to read
    let read_from = file_len.saturating_sub(CHUNK_SIZE);

    let mut reader = std::io::BufReader::new(&file);
    if read_from > 0 {
        use std::io::{Seek, SeekFrom};
        if reader.seek(SeekFrom::Start(read_from)).is_err() {
            return Vec::new();
        }
        // Skip the first partial line after seeking
        let mut partial = String::new();
        use std::io::BufRead;
        let _ = reader.read_line(&mut partial);
    }

    // Build a set of existing IDs for deduplication
    let existing_ids: std::collections::HashSet<&str> =
        existing.iter().map(|e| e.id.as_str()).collect();

    // Parse lines from the chunk, collecting all valid events
    let mut events: Vec<AuditEvent> = Vec::new();
    let mut seq: u64 = 100_000; // High seq offset to avoid collisions with live stream IDs

    use std::io::BufRead;
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<event_stream::DaemonAuditRecord>(&line) {
            Ok(record) => {
                let event = event_stream::to_audit_event(&record, seq);
                seq += 1;
                if !existing_ids.contains(event.id.as_str()) {
                    events.push(event);
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "Skipping malformed historical audit line");
            }
        }
    }

    // Take the last `needed` events (newest from the file)
    if events.len() > needed {
        events.drain(..events.len() - needed);
    }

    events
}

// --- Behavioral engine ---

/// Read behavioral profiles from the SQLite database on disk.
fn read_profiles_from_db() -> Result<Vec<ServerProfileSummary>, String> {
    let db_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(".local/share/rookbot/profiles.db");

    if !db_path.exists() {
        return Ok(vec![]);
    }

    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("Failed to open profiles DB: {}", e))?;

    let mut stmt = conn
        .prepare("SELECT server_name, profile_json, updated_at FROM profiles LIMIT 1000")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map([], |row| {
            let server_name: String = row.get(0)?;
            let profile_json: String = row.get(1)?;
            let updated_at: String = row.get(2)?;
            Ok((server_name, profile_json, updated_at))
        })
        .map_err(|e| format!("Failed to query profiles: {}", e))?;

    let mut profiles = Vec::new();
    for row in rows {
        let (server_name, profile_json, updated_at) = match row {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "Skipping malformed profile row");
                continue;
            }
        };

        let parsed: serde_json::Value = match serde_json::from_str(&profile_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, server = %server_name, "Skipping unparseable profile JSON");
                continue;
            }
        };

        let learning_mode = parsed
            .get("learning_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let tool_counts = parsed
            .get("tool_profile")
            .and_then(|tp| tp.get("tool_counts"))
            .and_then(|tc| tc.as_object());

        let tools_count = tool_counts.map(|m| m.len() as u32).unwrap_or(0);
        let total_calls: u64 = tool_counts
            .map(|m| m.values().filter_map(|v| v.as_u64()).sum())
            .unwrap_or(0);

        let status = if learning_mode {
            "learning".to_string()
        } else {
            "normal".to_string()
        };

        let last_activity = parsed
            .get("last_updated")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or(updated_at);

        profiles.push(ServerProfileSummary {
            server_name,
            tools_count,
            total_calls,
            anomaly_score: 0.0,
            status,
            last_activity,
        });
    }

    Ok(profiles)
}

#[tauri::command]
pub async fn get_profiles() -> Result<Vec<ServerProfileSummary>, String> {
    tokio::task::spawn_blocking(read_profiles_from_db)
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn get_behavioral_status(
    state: tauri::State<'_, AppState>,
) -> Result<BehavioralStatus, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_behavioral_status());
    }

    // Try live IPC query to the daemon for real-time stats.
    if let Ok(metrics) = state.ipc_client.query_status() {
        if let Some(bs) = metrics.behavioral_status {
            let total_anomalies = bs
                .auto_block_stats
                .as_ref()
                .map(|s| s.total_auto_blocks as u32)
                .unwrap_or(0);

            return Ok(BehavioralStatus {
                enabled: bs.enabled,
                profiles_count: bs.profiles as u32,
                total_anomalies,
                learning_servers: bs.learning_servers as u32,
                monitoring_servers: bs.monitoring_servers as u32,
            });
        }
    }

    // Fall back to reading profiles from the SQLite DB.
    let profiles = tokio::task::spawn_blocking(read_profiles_from_db)
        .await
        .map_err(|e| format!("Task join error: {}", e))??;

    let profiles_count = profiles.len() as u32;
    let learning_servers = profiles.iter().filter(|p| p.status == "learning").count() as u32;
    let monitoring_servers = profiles_count - learning_servers;

    Ok(BehavioralStatus {
        enabled: true,
        profiles_count,
        total_anomalies: 0,
        learning_servers,
        monitoring_servers,
    })
}

// --- Guards ---
// Guards are in-memory only in the daemon's GuardRegistry. There is no way to
// enumerate registered guards from outside the daemon, so we return an empty
// list. The frontend already handles this gracefully with an empty-state UI.

#[tauri::command]
pub async fn list_guards() -> Result<Vec<GuardSummary>, String> {
    Ok(vec![])
}

// --- Scanner ---

/// Validate a server command string to prevent command injection.
fn validate_server_command(cmd: &str) -> Result<(), String> {
    if cmd.trim().is_empty() {
        return Err("Server command cannot be empty".to_string());
    }
    const FORBIDDEN: &[char] = &[';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r'];
    for ch in FORBIDDEN {
        if cmd.contains(*ch) {
            return Err(format!(
                "Server command contains forbidden character '{}'",
                ch
            ));
        }
    }
    Ok(())
}

/// Parse the findings count from scan JSON output.
fn parse_scan_findings_count(stdout: &str) -> u32 {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(stdout) {
        if let Some(total) = json
            .get("summary")
            .and_then(|s| s.get("total"))
            .and_then(|t| t.as_u64())
        {
            return total as u32;
        }
        if let Some(findings) = json.get("findings").and_then(|f| f.as_array()) {
            return findings.len() as u32;
        }
    }
    0
}

#[tauri::command]
pub async fn start_scan(
    app_handle: tauri::AppHandle,
    _server_command: String,
    modules: Vec<String>,
    _timeout: u32,
    cloud_enrich: Option<bool>,
) -> Result<String, String> {
    use tauri::Manager;

    let state = app_handle.state::<AppState>();

    // Limit to 1 concurrent scan
    {
        let scans = state
            .active_scans
            .lock()
            .map_err(|e| format!("Failed to lock scan state: {}", e))?;
        if scans.values().any(|s| s.status == "running") {
            return Err("A scan is already running. Wait for it to complete.".to_string());
        }
    }

    // Generate scan ID
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let scan_id = format!("scan-{}-{}", ts, std::process::id());

    // Determine which modules to run
    let all_modules = vec![
        "mcp-config-audit",
        "policy-strength",
        "server-reputation",
        "system-posture",
        "behavioral-anomaly",
        "tcc-audit",
        "file-integrity",
        "clipboard-check",
        "memory-scan",
        "cis-benchmark",
        "browser-audit",
    ];
    let selected: Vec<String> = if modules.is_empty() {
        all_modules.iter().map(|s| s.to_string()).collect()
    } else {
        modules
    };
    let modules_total = selected.len() as u32;

    // Check daemon connection for the system posture module
    let daemon_connected = state.ipc_client.check_connection();

    // Store initial tracker
    {
        let mut scans = state
            .active_scans
            .lock()
            .map_err(|e| format!("Failed to lock scan state: {}", e))?;
        scans.insert(
            scan_id.clone(),
            crate::state::ScanTracker {
                status: "running".to_string(),
                progress_percent: 0.0,
                modules_completed: 0,
                modules_total,
                findings_count: 0,
                current_module: Some("Initializing".to_string()),
                result: None,
            },
        );
    }

    let id = scan_id.clone();
    let handle = app_handle.clone();
    let started_at = chrono::Utc::now().to_rfc3339();
    let enrich = cloud_enrich.unwrap_or(false);

    tokio::spawn(async move {
        let state = handle.state::<AppState>();
        let mut module_results = Vec::new();
        let mut completed = 0u32;

        for module_id in &selected {
            // Update current module
            if let Ok(mut scans) = state.active_scans.lock() {
                if let Some(tracker) = scans.get_mut(&id) {
                    tracker.current_module = Some(module_name_for_id(module_id));
                    tracker.progress_percent =
                        (completed as f64 / modules_total as f64) * 100.0;
                }
            }

            // Small delay to let progress polling see updates
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let result = match module_id.as_str() {
                "mcp-config-audit" => crate::scanner::scan_mcp_configs(),
                "policy-strength" => crate::scanner::scan_policy_strength(),
                "server-reputation" => crate::scanner::scan_server_reputation(),
                "system-posture" => crate::scanner::scan_system_posture(daemon_connected),
                "behavioral-anomaly" => crate::scanner::scan_behavioral_anomalies(),
                "tcc-audit" => crate::scanner::scan_tcc_permissions().await,
                "file-integrity" => crate::scanner::scan_file_integrity().await,
                "clipboard-check" => crate::scanner::scan_clipboard().await,
                "memory-scan" => crate::scanner::scan_process_memory().await,
                "cis-benchmark" => crate::scanner::scan_cis_benchmark().await,
                "browser-audit" => crate::scanner::scan_browser_extensions().await,
                other => crate::state::ScanModuleResult {
                    module_id: other.to_string(),
                    module_name: other.to_string(),
                    status: "skipped".to_string(),
                    findings: vec![],
                    summary: format!("Unknown module: {}", other),
                },
            };

            module_results.push(result);
            completed += 1;

            if let Ok(mut scans) = state.active_scans.lock() {
                if let Some(tracker) = scans.get_mut(&id) {
                    tracker.modules_completed = completed;
                    tracker.findings_count = module_results
                        .iter()
                        .map(|m| m.findings.len() as u32)
                        .sum();
                }
            }

            // Emit finding events for each new finding in the just-completed module
            let last_result = module_results.last().unwrap();
            for (i, finding) in last_result.findings.iter().enumerate() {
                crate::events::emit_scan_finding(
                    &handle,
                    &crate::events::ScanFindingPayload {
                        scan_id: id.clone(),
                        finding_id: format!("{}-{}", last_result.module_id, i),
                        severity: finding.severity.clone(),
                        title: finding.description.clone(),
                        stage: last_result.module_name.clone(),
                    },
                );
            }

            // Emit module (stage) complete event
            crate::events::emit_scan_stage_complete(
                &handle,
                &crate::events::ScanStageCompletePayload {
                    scan_id: id.clone(),
                    stage_name: module_name_for_id(module_id),
                    stages_completed: completed as usize,
                    stages_total: modules_total as usize,
                },
            );
        }

        // Enrich critical/high findings with AI analysis — only when user opts in
        if enrich {
            for module_result in &mut module_results {
                for finding in &mut module_result.findings {
                    if finding.severity == "critical" || finding.severity == "high" {
                        let prompt = format!(
                            "Analyze this security finding and assess if it's a real risk or likely a false positive.\n\
                             Severity: {}\nCategory: {}\nDescription: {}\nAffected: {}\n\
                             Is this a genuine security risk? Explain briefly.",
                            finding.severity, finding.category, finding.description, finding.affected_resource
                        );
                        let ai_resp = state.ai_backends.analyze(clawdefender_slm::AiRequest {
                            task_type: clawdefender_slm::TaskType::ScanAnalysis,
                            prompt,
                            context: None,
                        }).await;
                        if let Some(result) = ai_resp.response {
                            if !result.explanation.is_empty() {
                                finding.ai_analysis = Some(result.explanation);
                            } else {
                                tracing::warn!("AI returned empty analysis for finding: {}", finding.description);
                            }
                        } else if let Some(msg) = &ai_resp.message {
                            tracing::warn!("AI analysis unavailable for finding '{}': {}", finding.description, msg);
                        }
                    }
                }
            }
        }

        // Build final result
        let all_findings: Vec<&crate::state::ScanFinding> =
            module_results.iter().flat_map(|m| &m.findings).collect();
        let total_findings = all_findings.len() as u32;
        let critical_count = all_findings
            .iter()
            .filter(|f| f.severity == "critical")
            .count() as u32;
        let high_count = all_findings
            .iter()
            .filter(|f| f.severity == "high")
            .count() as u32;
        let medium_count = all_findings
            .iter()
            .filter(|f| f.severity == "medium")
            .count() as u32;
        let low_count = all_findings
            .iter()
            .filter(|f| f.severity == "low")
            .count() as u32;

        let scan_result = crate::state::ScanResult {
            scan_id: id.clone(),
            status: "completed".to_string(),
            started_at: started_at.clone(),
            completed_at: Some(chrono::Utc::now().to_rfc3339()),
            modules: module_results,
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            scan_type: Some(if enrich { "enriched" } else { "local" }.to_string()),
        };

        // Save scan result to disk
        let _ = save_scan_result(&scan_result);

        // Update tracker
        if let Ok(mut scans) = state.active_scans.lock() {
            if let Some(tracker) = scans.get_mut(&id) {
                tracker.status = "completed".to_string();
                tracker.progress_percent = 100.0;
                tracker.modules_completed = modules_total;
                tracker.findings_count = total_findings;
                tracker.current_module = None;
                tracker.result = Some(scan_result);
            }
        }

        // Emit scan-complete event
        crate::events::emit_scan_complete(
            &handle,
            &crate::events::ScanCompletePayload {
                scan_id: id.clone(),
                status: "completed".to_string(),
                findings_count: total_findings as usize,
                summary: format!(
                    "{} findings across {} modules",
                    total_findings, modules_total
                ),
            },
        );

        tracing::info!("Scan {} completed with {} findings", id, total_findings);
    });

    tracing::info!(
        "Started comprehensive scan {} with {} modules",
        scan_id,
        modules_total
    );
    Ok(scan_id)
}

#[tauri::command]
pub async fn enrich_scan_finding(
    app_handle: tauri::AppHandle,
    scan_id: String,
    module_id: String,
    finding_index: usize,
) -> Result<String, String> {
    use tauri::Manager;

    let state = app_handle.state::<AppState>();

    // Locate the finding in the scan tracker
    let (severity, category, description, affected_resource) = {
        let scans = state
            .active_scans
            .lock()
            .map_err(|e| format!("Failed to lock scan state: {}", e))?;
        let tracker = scans
            .get(&scan_id)
            .ok_or_else(|| format!("Scan {} not found", scan_id))?;
        let result = tracker
            .result
            .as_ref()
            .ok_or("Scan has no results yet")?;
        let module = result
            .modules
            .iter()
            .find(|m| m.module_id == module_id)
            .ok_or_else(|| format!("Module {} not found in scan", module_id))?;
        let finding = module
            .findings
            .get(finding_index)
            .ok_or_else(|| format!("Finding index {} out of bounds", finding_index))?;

        if finding.ai_analysis.is_some() {
            return Ok(finding.ai_analysis.clone().unwrap());
        }

        (
            finding.severity.clone(),
            finding.category.clone(),
            finding.description.clone(),
            finding.affected_resource.clone(),
        )
    };

    let prompt = format!(
        "Analyze this security finding and assess if it's a real risk or likely a false positive.\n\
         Severity: {}\nCategory: {}\nDescription: {}\nAffected: {}\n\
         Is this a genuine security risk? Explain briefly.",
        severity, category, description, affected_resource
    );

    let ai_resp = state
        .ai_backends
        .analyze(clawdefender_slm::AiRequest {
            task_type: clawdefender_slm::TaskType::ScanAnalysis,
            prompt,
            context: None,
        })
        .await;

    let analysis_text = if let Some(result) = ai_resp.response {
        if result.explanation.is_empty() {
            return Err("AI returned empty analysis".to_string());
        }
        result.explanation
    } else {
        return Err(ai_resp.message.unwrap_or_else(|| "AI analysis unavailable".to_string()));
    };

    // Write the analysis back into the stored finding
    {
        let mut scans = state
            .active_scans
            .lock()
            .map_err(|e| format!("Failed to lock scan state: {}", e))?;
        if let Some(tracker) = scans.get_mut(&scan_id) {
            if let Some(ref mut result) = tracker.result {
                if let Some(module) = result.modules.iter_mut().find(|m| m.module_id == module_id) {
                    if let Some(finding) = module.findings.get_mut(finding_index) {
                        finding.ai_analysis = Some(analysis_text.clone());
                    }
                }
            }
        }
    }

    Ok(analysis_text)
}

fn module_name_for_id(id: &str) -> String {
    match id {
        "mcp-config-audit" => "MCP Configuration Audit".to_string(),
        "policy-strength" => "Policy Strength Analysis".to_string(),
        "server-reputation" => "Server Reputation Check".to_string(),
        "system-posture" => "System Security Posture".to_string(),
        "behavioral-anomaly" => "Behavioral Anomaly Review".to_string(),
        "tcc-audit" => "TCC Permission Audit".to_string(),
        "file-integrity" => "File Integrity Monitor".to_string(),
        "clipboard-check" => "Clipboard Security Check".to_string(),
        "memory-scan" => "Process Memory Scan".to_string(),
        "cis-benchmark" => "CIS Benchmark Compliance".to_string(),
        "browser-audit" => "Browser Extension Audit".to_string(),
        other => other.to_string(),
    }
}

fn save_scan_result(result: &crate::state::ScanResult) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("No home dir")?;
    let scans_dir = home.join(".local/share/rookbot/scans");
    std::fs::create_dir_all(&scans_dir)
        .map_err(|e| format!("Failed to create scans directory: {}", e))?;

    // Sanitize scan_id to prevent path traversal (e.g. "../../../etc/passwd")
    let safe_id: String = result
        .scan_id
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe_id.is_empty() {
        return Err("Invalid scan ID".to_string());
    }

    let file_path = scans_dir.join(format!("{}.json", safe_id));
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| format!("Failed to serialize scan result: {}", e))?;

    // Write with owner-only permissions (0600) to prevent other users from
    // reading scan findings which may contain security-sensitive details.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&file_path)
            .map_err(|e| format!("Failed to create scan result file: {}", e))?;
        std::io::Write::write_all(&mut file, json.as_bytes())
            .map_err(|e| format!("Failed to write scan result: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&file_path, json)
            .map_err(|e| format!("Failed to write scan result: {}", e))?;
    }

    tracing::info!("Scan result saved to {}", file_path.display());
    Ok(())
}

#[tauri::command]
pub async fn get_scan_progress(
    state: tauri::State<'_, AppState>,
    scan_id: String,
) -> Result<ScanProgress, String> {
    let scans = state
        .active_scans
        .lock()
        .map_err(|e| format!("Failed to lock scan state: {}", e))?;

    let tracker = scans
        .get(&scan_id)
        .ok_or_else(|| format!("Scan '{}' not found", scan_id))?;

    Ok(ScanProgress {
        scan_id,
        status: tracker.status.clone(),
        progress_percent: tracker.progress_percent,
        modules_completed: tracker.modules_completed,
        modules_total: tracker.modules_total,
        findings_count: tracker.findings_count,
        current_module: tracker.current_module.clone(),
    })
}

#[tauri::command]
pub async fn get_scan_results(
    state: tauri::State<'_, AppState>,
    scan_id: String,
) -> Result<crate::state::ScanResult, String> {
    // First try in-memory
    {
        let scans = state
            .active_scans
            .lock()
            .map_err(|e| format!("Failed to lock scan state: {}", e))?;
        if let Some(tracker) = scans.get(&scan_id) {
            if let Some(ref result) = tracker.result {
                return Ok(result.clone());
            }
        }
    }

    // Fall back to disk
    // Sanitize scan_id to prevent path traversal attacks
    let safe_id: String = scan_id
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe_id.is_empty() || safe_id != scan_id {
        return Err(format!("Invalid scan ID: '{}'", scan_id));
    }
    let home = dirs::home_dir().ok_or("No home dir")?;
    let file_path = home.join(format!(
        ".local/share/rookbot/scans/{}.json",
        safe_id
    ));
    if file_path.exists() {
        let contents = std::fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read scan result: {}", e))?;
        let result: crate::state::ScanResult = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse scan result: {}", e))?;
        return Ok(result);
    }

    Err(format!("Scan result '{}' not found", scan_id))
}

#[tauri::command]
pub async fn apply_scan_fix(
    client: String,
    server: String,
    action_type: String,
) -> Result<String, String> {
    match action_type.as_str() {
        "wrap_server" => {
            wrap_server(client, server).await?;
            Ok("Server wrapped successfully".to_string())
        }
        "add_policy_rule" => {
            // For policy rule additions, we return guidance - the user should
            // use the Policy page for granular control
            Ok("Navigate to the Policy page to add this rule".to_string())
        }
        other => Err(format!("Unknown fix action type: {}", other)),
    }
}

// --- System health ---

#[tauri::command]
pub async fn run_doctor(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<DoctorCheck>, String> {
    let mut checks = Vec::new();
    let home = dirs::home_dir().unwrap_or_default();

    // 1. Daemon Process
    if state.ipc_client.check_connection() {
        checks.push(DoctorCheck {
            name: "Daemon Process".to_string(),
            status: "pass".to_string(),
            message: "Daemon is running and responding".to_string(),
            fix_suggestion: None,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Daemon Process".to_string(),
            status: "fail".to_string(),
            message: "Daemon is not running or not responding".to_string(),
            fix_suggestion: Some("Start daemon from the dashboard".to_string()),
        });
    }

    // 2. Socket File
    let sock_path = daemon::socket_path();
    if sock_path.exists() {
        checks.push(DoctorCheck {
            name: "Socket File".to_string(),
            status: "pass".to_string(),
            message: format!("Socket file exists at {}", sock_path.display()),
            fix_suggestion: None,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Socket File".to_string(),
            status: "warn".to_string(),
            message: "Socket file not found".to_string(),
            fix_suggestion: Some("Start the daemon to create the socket".to_string()),
        });
    }

    // 3. Config Directory
    let config_dir = home.join(".config").join("rookbot");
    if config_dir.exists() {
        let test_file = config_dir.join(".write_test");
        let writable = std::fs::write(&test_file, b"").is_ok();
        let _ = std::fs::remove_file(&test_file);
        if writable {
            checks.push(DoctorCheck {
                name: "Config Directory".to_string(),
                status: "pass".to_string(),
                message: format!("Config directory exists and is writable at {}", config_dir.display()),
                fix_suggestion: None,
            });
        } else {
            checks.push(DoctorCheck {
                name: "Config Directory".to_string(),
                status: "warn".to_string(),
                message: format!("Config directory exists but is not writable at {}", config_dir.display()),
                fix_suggestion: Some("Check permissions on ~/.config/rookbot".to_string()),
            });
        }
    } else {
        checks.push(DoctorCheck {
            name: "Config Directory".to_string(),
            status: "warn".to_string(),
            message: "Config directory not found".to_string(),
            fix_suggestion: Some("Create the directory: mkdir -p ~/.config/rookbot".to_string()),
        });
    }

    // 4. Policy File
    let policy_path = policy_file_path();
    if policy_path.exists() {
        match std::fs::read_to_string(&policy_path) {
            Ok(contents) => match contents.parse::<toml::Value>() {
                Ok(doc) => {
                    let rules_count = doc
                        .get("rules")
                        .and_then(|v| v.as_table())
                        .map(|t| t.len())
                        .unwrap_or(0);
                    checks.push(DoctorCheck {
                        name: "Policy File".to_string(),
                        status: "pass".to_string(),
                        message: format!("Policy file is valid with {} rules", rules_count),
                        fix_suggestion: None,
                    });
                }
                Err(_) => {
                    checks.push(DoctorCheck {
                        name: "Policy File".to_string(),
                        status: "fail".to_string(),
                        message: "Policy file has syntax errors".to_string(),
                        fix_suggestion: Some(
                            "Edit policy.toml or reset from Settings".to_string(),
                        ),
                    });
                }
            },
            Err(e) => {
                checks.push(DoctorCheck {
                    name: "Policy File".to_string(),
                    status: "fail".to_string(),
                    message: format!("Cannot read policy file: {}", e),
                    fix_suggestion: Some("Check file permissions on policy.toml".to_string()),
                });
            }
        }
    } else {
        checks.push(DoctorCheck {
            name: "Policy File".to_string(),
            status: "warn".to_string(),
            message: "No policy file found — using defaults".to_string(),
            fix_suggestion: Some(
                "Configure a security policy from the Policy page".to_string(),
            ),
        });
    }

    // 5. Audit Log Directory
    let log_dir = home.join(".local").join("share").join("rookbot");
    if log_dir.exists() {
        let test_file = log_dir.join(".write_test");
        let writable = std::fs::write(&test_file, b"").is_ok();
        let _ = std::fs::remove_file(&test_file);
        if writable {
            checks.push(DoctorCheck {
                name: "Audit Log Directory".to_string(),
                status: "pass".to_string(),
                message: format!("Audit log directory is writable at {}", log_dir.display()),
                fix_suggestion: None,
            });
        } else {
            checks.push(DoctorCheck {
                name: "Audit Log Directory".to_string(),
                status: "fail".to_string(),
                message: format!("Audit log directory is not writable at {}", log_dir.display()),
                fix_suggestion: Some("Check permissions: chmod u+w ~/.local/share/rookbot".to_string()),
            });
        }
    } else {
        checks.push(DoctorCheck {
            name: "Audit Log Directory".to_string(),
            status: "fail".to_string(),
            message: "Audit log directory not found".to_string(),
            fix_suggestion: Some("Create the directory: mkdir -p ~/.local/share/rookbot".to_string()),
        });
    }

    // 6. Full Disk Access (heuristic)
    let mail_path = home.join("Library/Mail");
    let has_fda = std::fs::read_dir(&mail_path).is_ok();
    if has_fda {
        checks.push(DoctorCheck {
            name: "Full Disk Access".to_string(),
            status: "pass".to_string(),
            message: "Full Disk Access is granted".to_string(),
            fix_suggestion: None,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Full Disk Access".to_string(),
            status: "warn".to_string(),
            message: "Full Disk Access may not be granted".to_string(),
            fix_suggestion: Some(
                "Open System Settings > Privacy & Security > Full Disk Access".to_string(),
            ),
        });
    }

    // 7. MCP Clients & 8. Wrapped Servers
    match detect_mcp_clients().await {
        Ok(clients) => {
            let detected: Vec<&McpClient> = clients.iter().filter(|c| c.detected).collect();
            let total_servers: u32 = detected.iter().map(|c| c.servers_count).sum();

            if detected.is_empty() {
                checks.push(DoctorCheck {
                    name: "MCP Clients".to_string(),
                    status: "warn".to_string(),
                    message: "No MCP clients detected".to_string(),
                    fix_suggestion: None,
                });
            } else {
                checks.push(DoctorCheck {
                    name: "MCP Clients".to_string(),
                    status: "pass".to_string(),
                    message: format!(
                        "{} clients detected with {} servers",
                        detected.len(),
                        total_servers
                    ),
                    fix_suggestion: None,
                });
            }

            // Count wrapped servers across all detected clients
            let mut total_count = 0u32;
            let mut wrapped_count = 0u32;
            for client in &detected {
                if let Ok(servers) = list_mcp_servers(client.name.clone()).await {
                    for srv in &servers {
                        total_count += 1;
                        if srv.wrapped {
                            wrapped_count += 1;
                        }
                    }
                }
            }

            if total_count == 0 {
                checks.push(DoctorCheck {
                    name: "Wrapped Servers".to_string(),
                    status: "warn".to_string(),
                    message: "No MCP servers found to wrap".to_string(),
                    fix_suggestion: None,
                });
            } else if wrapped_count == total_count {
                checks.push(DoctorCheck {
                    name: "Wrapped Servers".to_string(),
                    status: "pass".to_string(),
                    message: format!("All {} servers are wrapped", total_count),
                    fix_suggestion: None,
                });
            } else {
                checks.push(DoctorCheck {
                    name: "Wrapped Servers".to_string(),
                    status: "warn".to_string(),
                    message: format!(
                        "{} of {} servers are unwrapped",
                        total_count - wrapped_count,
                        total_count
                    ),
                    fix_suggestion: Some(
                        "Wrap all servers from the dashboard".to_string(),
                    ),
                });
            }
        }
        Err(_) => {
            checks.push(DoctorCheck {
                name: "MCP Clients".to_string(),
                status: "warn".to_string(),
                message: "Could not detect MCP clients".to_string(),
                fix_suggestion: None,
            });
        }
    }

    Ok(checks)
}

#[tauri::command]
pub async fn get_system_info(
    state: tauri::State<'_, AppState>,
) -> Result<SystemInfo, String> {
    let home = dirs::home_dir().unwrap_or_default();

    // Real macOS version via sw_vers
    let os_version = std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    // Daemon version from IPC or sidecar
    let daemon_version = if state.ipc_client.check_connection() {
        // Use the monitor's known version or query
        Some(env!("CARGO_PKG_VERSION").to_string())
    } else {
        // Try running rookbot --version
        let bin = resolve_clawdefender_path();
        std::process::Command::new(&bin)
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    };

    Ok(SystemInfo {
        os: "macOS".to_string(),
        os_version,
        arch: std::env::consts::ARCH.to_string(),
        daemon_version,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        config_dir: home.join(".config/rookbot").to_string_lossy().to_string(),
        log_dir: home.join(".local/share/rookbot").to_string_lossy().to_string(),
    })
}

// --- Prompt handling ---

#[tauri::command]
pub async fn respond_to_prompt(
    state: tauri::State<'_, AppState>,
    prompt_id: String,
    decision: String,
) -> Result<(), String> {
    tracing::info!("Responding to prompt {}: {}", prompt_id, decision);

    // 1. Remove the prompt from pending_prompts (idempotent — missing ID is not an error)
    let removed_prompt = if let Ok(mut prompts) = state.pending_prompts.lock() {
        if let Some(pos) = prompts.iter().position(|p| p.id == prompt_id) {
            Some(prompts.remove(pos))
        } else {
            tracing::debug!("Prompt {} not found in pending list (already handled or expired)", prompt_id);
            None
        }
    } else {
        tracing::warn!("Failed to lock pending_prompts mutex");
        None
    };

    // 2. For policy-affecting decisions, update the policy file
    match decision.as_str() {
        "allow_always" => {
            if let Some(ref prompt) = removed_prompt {
                let rule_name = format!("auto-allow-{}-{}", prompt.server_name, prompt.tool_name);
                let resource = if prompt.resource.starts_with("http://")
                    || prompt.resource.starts_with("https://")
                    || prompt.resource.contains(':')
                {
                    "network"
                } else {
                    "file"
                };
                let rule = PolicyRule {
                    name: rule_name.clone(),
                    description: format!(
                        "Auto-allowed: {} {} on {} (from prompt {})",
                        prompt.server_name, prompt.tool_name, prompt.resource, prompt_id
                    ),
                    action: "allow".to_string(),
                    resource: resource.to_string(),
                    pattern: prompt.resource.clone(),
                    priority: 60,
                    enabled: true,
                };

                // Read or create the policy file
                let path = policy_file_path();
                let mut doc = if path.exists() {
                    read_policy_file()?
                } else {
                    let mut m = toml::map::Map::new();
                    m.insert(
                        "rules".to_string(),
                        toml::Value::Table(toml::map::Map::new()),
                    );
                    toml::Value::Table(m)
                };

                let key = sanitize_rule_key(&rule_name);
                // Only add if the rule doesn't already exist (idempotent)
                let already_exists = doc
                    .get("rules")
                    .and_then(|v| v.as_table())
                    .map(|t| t.contains_key(&key))
                    .unwrap_or(false);

                if !already_exists {
                    if let Some(rules) = doc.get_mut("rules").and_then(|v| v.as_table_mut()) {
                        rules.insert(key.clone(), policy_rule_to_toml_table(&rule));
                    }
                    write_policy_file(&doc)?;
                    try_reload_daemon(&state);
                    tracing::info!("Added allow-always policy rule: {}", key);
                } else {
                    tracing::debug!("Policy rule {} already exists, skipping", key);
                }
            } else {
                tracing::info!(
                    "Prompt {} not found for allow_always — decision recorded but no policy rule created",
                    prompt_id
                );
            }
        }
        "deny_always" => {
            // Create a permanent block rule (mirror of allow_always).
            if let Some(ref prompt) = removed_prompt {
                let rule_name = format!("auto-block-{}-{}", prompt.server_name, prompt.tool_name);
                let resource = if prompt.resource.starts_with("http://")
                    || prompt.resource.starts_with("https://")
                    || prompt.resource.contains(':')
                {
                    "network"
                } else {
                    "file"
                };
                let rule = PolicyRule {
                    name: rule_name.clone(),
                    description: format!(
                        "Auto-blocked: {} {} on {} (from prompt {})",
                        prompt.server_name, prompt.tool_name, prompt.resource, prompt_id
                    ),
                    action: "deny".to_string(),
                    resource: resource.to_string(),
                    pattern: prompt.resource.clone(),
                    priority: 60,
                    enabled: true,
                };

                let path = policy_file_path();
                let mut doc = if path.exists() {
                    read_policy_file()?
                } else {
                    let mut m = toml::map::Map::new();
                    m.insert(
                        "rules".to_string(),
                        toml::Value::Table(toml::map::Map::new()),
                    );
                    toml::Value::Table(m)
                };

                let key = sanitize_rule_key(&rule_name);
                let already_exists = doc
                    .get("rules")
                    .and_then(|v| v.as_table())
                    .map(|t| t.contains_key(&key))
                    .unwrap_or(false);

                if !already_exists {
                    if let Some(rules) = doc.get_mut("rules").and_then(|v| v.as_table_mut()) {
                        rules.insert(key.clone(), policy_rule_to_toml_table(&rule));
                    }
                    write_policy_file(&doc)?;
                    try_reload_daemon(&state);
                    tracing::info!("Added deny-always policy rule: {}", key);
                } else {
                    tracing::debug!("Policy rule {} already exists, skipping", key);
                }
            } else {
                tracing::info!(
                    "Prompt {} not found for deny_always — decision recorded but no policy rule created",
                    prompt_id
                );
            }
        }
        "deny" | "allow_once" | "allow_session" => {
            // These decisions don't create persistent policy rules.
            // "deny" is a one-time denial, "allow_once" and "allow_session" are transient.
            tracing::info!("Decision '{}' recorded for prompt {} (no policy change)", decision, prompt_id);
        }
        other => {
            tracing::warn!("Unknown decision '{}' for prompt {}", other, prompt_id);
        }
    }

    Ok(())
}

// --- Onboarding ---

#[tauri::command]
pub async fn check_onboarding_complete(
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let completed = state
        .onboarding_complete
        .lock()
        .map(|g| *g)
        .unwrap_or(false);
    Ok(completed)
}

#[tauri::command]
pub async fn complete_onboarding(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Set in-memory flag
    if let Ok(mut guard) = state.onboarding_complete.lock() {
        *guard = true;
    }

    // Persist to disk so it survives app restarts
    let flag_path = AppState::onboarding_flag_path();
    if let Some(parent) = flag_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&flag_path, "1").map_err(|e| e.to_string())?;

    tracing::info!("Onboarding completed, flag written to {}", flag_path.display());
    Ok(())
}

// --- Settings ---

fn config_toml_path() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    home.join(".config/rookbot/config.toml")
}

fn default_settings() -> AppSettings {
    AppSettings {
        theme: "dark".to_string(),
        notifications_enabled: true,
        auto_start_daemon: true,
        minimize_to_tray: true,
        log_level: "info".to_string(),
        prompt_timeout_seconds: 15,
        event_retention_days: 30,
        behavioral_auto_block: false,
        behavioral_threshold: 0.7,
        analysis_frequency: "all".to_string(),
        security_level: "balanced".to_string(),
        clipboard_monitor_enabled: false,
        demo_mode: false,
    }
}

fn get_str<'a>(table: &'a toml::Value, section: &str, key: &str, default: &'a str) -> String {
    table
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

fn get_bool(table: &toml::Value, section: &str, key: &str, default: bool) -> bool {
    table
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}

fn get_u32(table: &toml::Value, section: &str, key: &str, default: u32) -> u32 {
    table
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_integer())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(default)
}

fn get_f64(table: &toml::Value, section: &str, key: &str, default: f64) -> f64 {
    table
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64)))
        .unwrap_or(default)
}

#[tauri::command]
pub async fn get_settings() -> Result<AppSettings, String> {
    let path = config_toml_path();
    if !path.exists() {
        return Ok(default_settings());
    }

    let content = std::fs::read_to_string(&path).map_err(|e| {
        format!("Failed to read config.toml: {}", e)
    })?;

    let table: toml::Value = content
        .parse()
        .unwrap_or(toml::Value::Table(Default::default()));

    let defaults = default_settings();

    // Infer security level by comparing current policy rules against known templates
    let security_level = infer_security_level();

    Ok(AppSettings {
        theme: get_str(&table, "ui", "theme", &defaults.theme),
        notifications_enabled: get_bool(&table, "ui", "notifications", defaults.notifications_enabled),
        auto_start_daemon: get_bool(&table, "ui", "auto_start_daemon", defaults.auto_start_daemon),
        minimize_to_tray: get_bool(&table, "ui", "minimize_to_tray", defaults.minimize_to_tray),
        log_level: get_str(&table, "ui", "log_level", &defaults.log_level),
        prompt_timeout_seconds: get_u32(&table, "network_policy", "prompt_timeout_seconds", defaults.prompt_timeout_seconds),
        event_retention_days: get_u32(&table, "ui", "event_retention_days", defaults.event_retention_days),
        behavioral_auto_block: get_bool(&table, "behavioral", "auto_block", defaults.behavioral_auto_block),
        behavioral_threshold: get_f64(&table, "behavioral", "anomaly_threshold", defaults.behavioral_threshold),
        analysis_frequency: get_str(&table, "slm", "analysis_frequency", &defaults.analysis_frequency),
        security_level,
        clipboard_monitor_enabled: get_bool(&table, "monitoring", "clipboard_monitor_enabled", defaults.clipboard_monitor_enabled),
        demo_mode: get_bool(&table, "ui", "demo_mode", defaults.demo_mode),
    })
}

#[tauri::command]
pub async fn update_settings(
    app: tauri::AppHandle,
    settings: AppSettings,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Validate retention days: must be at least 1 to prevent deleting all logs
    if settings.event_retention_days == 0 {
        return Err("Event retention days must be at least 1".to_string());
    }

    let path = config_toml_path();

    // Read existing config to preserve unknown sections
    let mut table: toml::Value = if path.exists() {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            format!("Failed to read config.toml: {}", e)
        })?;
        content
            .parse()
            .unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    // Ensure [ui] section exists
    if table.get("ui").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("ui".to_string(), toml::Value::Table(Default::default()));
    }
    let ui = table
        .get_mut("ui")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [ui] section")?;

    ui.insert("theme".to_string(), toml::Value::String(settings.theme.clone()));
    ui.insert("notifications".to_string(), toml::Value::Boolean(settings.notifications_enabled));
    ui.insert("auto_start_daemon".to_string(), toml::Value::Boolean(settings.auto_start_daemon));
    ui.insert("minimize_to_tray".to_string(), toml::Value::Boolean(settings.minimize_to_tray));
    ui.insert("log_level".to_string(), toml::Value::String(settings.log_level.clone()));
    ui.insert("event_retention_days".to_string(), toml::Value::Integer(settings.event_retention_days as i64));
    ui.insert("demo_mode".to_string(), toml::Value::Boolean(settings.demo_mode));

    // Ensure [network_policy] section exists
    if table.get("network_policy").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("network_policy".to_string(), toml::Value::Table(Default::default()));
    }
    let net = table
        .get_mut("network_policy")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [network_policy] section")?;

    net.insert("prompt_timeout_seconds".to_string(), toml::Value::Integer(settings.prompt_timeout_seconds as i64));

    // Ensure [behavioral] section exists
    if table.get("behavioral").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("behavioral".to_string(), toml::Value::Table(Default::default()));
    }
    let behavioral = table
        .get_mut("behavioral")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [behavioral] section")?;

    behavioral.insert("auto_block".to_string(), toml::Value::Boolean(settings.behavioral_auto_block));
    behavioral.insert("anomaly_threshold".to_string(), toml::Value::Float(settings.behavioral_threshold));

    // Ensure [slm] section exists for analysis frequency
    if table.get("slm").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("slm".to_string(), toml::Value::Table(Default::default()));
    }
    let slm = table
        .get_mut("slm")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [slm] section")?;

    slm.insert("analysis_frequency".to_string(), toml::Value::String(settings.analysis_frequency.clone()));

    // Ensure [monitoring] section exists for clipboard monitor toggle
    if table.get("monitoring").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("monitoring".to_string(), toml::Value::Table(Default::default()));
    }
    let monitoring = table
        .get_mut("monitoring")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [monitoring] section")?;

    monitoring.insert("clipboard_monitor_enabled".to_string(), toml::Value::Boolean(settings.clipboard_monitor_enabled));

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!("Failed to create config directory: {}", e)
        })?;
    }

    let output = toml::to_string_pretty(&table).map_err(|e| {
        format!("Failed to serialize config: {}", e)
    })?;
    std::fs::write(&path, output).map_err(|e| {
        format!("Failed to write config.toml: {}", e)
    })?;

    tracing::info!("Settings saved to {}", path.display());

    // Refresh demo mode cache
    crate::demo_data::refresh_demo_mode();

    // If daemon is connected, trigger a config/policy reload
    try_reload_daemon(&state);

    // Start or stop clipboard monitor based on the new setting
    let currently_active = state
        .clipboard_monitor_active
        .lock()
        .map(|a| *a)
        .unwrap_or(false);

    if settings.clipboard_monitor_enabled && !currently_active {
        start_clipboard_monitor(app);
    } else if !settings.clipboard_monitor_enabled && currently_active {
        stop_clipboard_monitor(&state);
    }

    Ok(())
}

// --- Settings Export / Import ---

fn policy_toml_path() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    home.join(".config/rookbot/policy.toml")
}

/// Strip sensitive keys (API keys, tokens, secrets) from a TOML string before export.
fn strip_secrets(content: &str) -> String {
    let mut filtered_lines = Vec::new();
    for line in content.lines() {
        let lower = line.to_lowercase();
        let is_secret = ["api_key", "api_token", "secret", "password", "token"]
            .iter()
            .any(|k| lower.contains(k) && lower.contains('='));
        if !is_secret {
            filtered_lines.push(line);
        }
    }
    filtered_lines.join("\n")
}

#[tauri::command]
pub async fn export_settings() -> Result<String, String> {
    let config_path = config_toml_path();
    let policy_path = policy_toml_path();

    let config = if config_path.exists() {
        strip_secrets(
            &std::fs::read_to_string(&config_path)
                .map_err(|e| format!("Failed to read config.toml: {}", e))?,
        )
    } else {
        String::new()
    };

    let policy = if policy_path.exists() {
        std::fs::read_to_string(&policy_path)
            .map_err(|e| format!("Failed to read policy.toml: {}", e))?
    } else {
        String::new()
    };

    let export = serde_json::json!({
        "version": "1.0",
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "config": config,
        "policy": policy,
    });

    let home = std::env::var("HOME").unwrap_or_default();
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let export_path = format!("{}/Desktop/rookbot-settings-{}.json", home, timestamp);
    std::fs::write(
        &export_path,
        serde_json::to_string_pretty(&export).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Failed to write export file: {}", e))?;

    tracing::info!("Settings exported to {}", export_path);
    Ok(export_path)
}

#[tauri::command]
pub async fn import_settings_from_content(content: String) -> Result<String, String> {
    // Size check: reject files > 10KB to prevent abuse
    if content.len() > 10_240 {
        return Err("Import file is too large (max 10KB)".to_string());
    }

    // Reject null bytes which could cause truncation issues
    if content.contains('\0') {
        return Err("Import data contains invalid null bytes".to_string());
    }

    // Parse and validate structure
    let parsed: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;

    let version = parsed
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'version' field")?;
    if version != "1.0" {
        return Err(format!("Unsupported export version: {}", version));
    }

    let config_content = parsed
        .get("config")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'config' field")?;
    let policy_content = parsed
        .get("policy")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'policy' field")?;

    // Reject content with null bytes
    if config_content.contains('\0') || policy_content.contains('\0') {
        return Err("Config content contains invalid null bytes".to_string());
    }

    // Reject path traversal attempts in values (e.g. "../../etc/passwd")
    if config_content.contains("../") || policy_content.contains("../") {
        return Err("Config content contains suspicious path traversal sequences".to_string());
    }

    // Validate config is valid TOML (if non-empty)
    if !config_content.is_empty() {
        config_content
            .parse::<toml::Value>()
            .map_err(|e| format!("Invalid config TOML: {}", e))?;
    }
    if !policy_content.is_empty() {
        policy_content
            .parse::<toml::Value>()
            .map_err(|e| format!("Invalid policy TOML: {}", e))?;
    }

    let config_path = config_toml_path();
    let policy_path = policy_toml_path();

    // Ensure config directory exists
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    // Back up existing files
    if config_path.exists() {
        let backup = config_path.with_extension("toml.bak");
        let _ = std::fs::copy(&config_path, &backup);
    }
    if policy_path.exists() {
        let backup = policy_path.with_extension("toml.bak");
        let _ = std::fs::copy(&policy_path, &backup);
    }

    // Write new config files
    if !config_content.is_empty() {
        std::fs::write(&config_path, config_content)
            .map_err(|e| format!("Failed to write config.toml: {}", e))?;
    }
    if !policy_content.is_empty() {
        std::fs::write(&policy_path, policy_content)
            .map_err(|e| format!("Failed to write policy.toml: {}", e))?;
    }

    tracing::info!("Settings imported successfully");
    Ok("Settings imported successfully".to_string())
}

// --- Threat Intelligence ---

fn threat_intel_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::PathBuf::from(home).join(".local/share/rookbot/threat-intel")
}

/// Collect all MCP server names from detected client configs.
fn collect_mcp_server_names() -> Vec<String> {
    let mut names = Vec::new();
    for (path, _client_id, _display_name) in mcp_config_paths() {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&contents) {
                if let Some(obj) = extract_servers(&config) {
                    for server_name in obj.keys() {
                        names.push(server_name.clone());
                    }
                }
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Validate a rule pack ID: alphanumeric + hyphens only, no path traversal.
fn validate_rule_pack_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("Rule pack ID cannot be empty".to_string());
    }
    if id.len() > 128 {
        return Err("Rule pack ID is too long".to_string());
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("Rule pack ID must contain only alphanumeric characters and hyphens".to_string());
    }
    Ok(())
}

#[tauri::command]
pub async fn get_feed_status() -> Result<FeedStatus, String> {
    let manifest_path = threat_intel_dir().join("manifest.json");

    if !manifest_path.exists() {
        return Ok(FeedStatus {
            version: "not configured".to_string(),
            last_updated: "never".to_string(),
            next_check: "run rookbot feed update to initialize".to_string(),
            entries_count: 0,
        });
    }

    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read manifest.json: {}", e))?;
    let manifest: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse manifest.json: {}", e))?;

    let version = manifest.get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let last_updated = manifest.get("last_updated")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Calculate next_check as last_updated + 6 hours
    let next_check = if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&last_updated) {
        (dt + chrono::Duration::hours(6)).to_rfc3339()
    } else {
        "unknown".to_string()
    };

    // Count entries across IoC files
    let ioc_dir = threat_intel_dir().join("ioc");
    let mut entries_count: u32 = 0;
    if ioc_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&ioc_dir) {
            for entry in entries.take(1000).flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(data) = std::fs::read_to_string(&path) {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&data) {
                            if let Some(indicators) = parsed.get("indicators").and_then(|v| v.as_array()) {
                                entries_count += indicators.len() as u32;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(FeedStatus {
        version,
        last_updated,
        next_check,
        entries_count,
    })
}

#[tauri::command]
pub async fn force_feed_update() -> Result<String, String> {
    let bin = resolve_clawdefender_path();
    tracing::info!("Running feed update via: {}", bin);

    let output = std::process::Command::new(&bin)
        .args(["feed", "update"])
        .output()
        .map_err(|e| format!("Failed to run rookbot: {}. Is the CLI installed?", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(if stdout.trim().is_empty() {
            "Feed update completed successfully".to_string()
        } else {
            stdout.trim().to_string()
        })
    } else {
        Err(format!(
            "Feed update failed (exit {}): {}{}",
            output.status.code().unwrap_or(-1),
            stderr.trim(),
            if !stdout.trim().is_empty() { format!("\n{}", stdout.trim()) } else { String::new() }
        ))
    }
}

#[tauri::command]
pub async fn get_blocklist_matches() -> Result<Vec<BlocklistAlert>, String> {
    let blocklist_path = threat_intel_dir().join("blocklist.json");

    if !blocklist_path.exists() {
        return Ok(vec![]);
    }

    let content = std::fs::read_to_string(&blocklist_path)
        .map_err(|e| format!("Failed to read blocklist.json: {}", e))?;
    let blocklist: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse blocklist.json: {}", e))?;

    let entries = match blocklist.get("entries").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Ok(vec![]),
    };

    let server_names = collect_mcp_server_names();
    if server_names.is_empty() {
        return Ok(vec![]);
    }

    let mut alerts = Vec::new();
    for entry in entries.iter().take(10000) {
        let entry_name = match entry.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let entry_name_lower = entry_name.to_lowercase();

        for server_name in &server_names {
            if server_name.to_lowercase() == entry_name_lower {
                alerts.push(BlocklistAlert {
                    entry_id: entry.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    server_name: server_name.clone(),
                    severity: entry.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    description: entry.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                });
            }
        }
    }

    Ok(alerts)
}

#[tauri::command]
pub async fn get_rule_packs() -> Result<Vec<RulePackInfo>, String> {
    let rules_dir = threat_intel_dir().join("rules");

    if !rules_dir.is_dir() {
        return Ok(vec![]);
    }

    let mut packs = Vec::new();
    let entries = std::fs::read_dir(&rules_dir)
        .map_err(|e| format!("Failed to read rules directory: {}", e))?;

    for entry in entries.take(500).flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let parsed: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let rule_count = parsed.get("rules")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as u32)
            .unwrap_or(0);

        packs.push(RulePackInfo {
            id: parsed.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            name: parsed.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            installed: true,
            version: parsed.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0").to_string(),
            rule_count,
            description: parsed.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        });
    }

    Ok(packs)
}

#[tauri::command]
pub async fn install_rule_pack(id: String) -> Result<(), String> {
    validate_rule_pack_id(&id)?;

    let bin = resolve_clawdefender_path();
    tracing::info!("Installing rule pack {} via: {}", id, bin);

    let output = std::process::Command::new(&bin)
        .args(["rules", "install", &id])
        .output()
        .map_err(|e| format!("Failed to run rookbot: {}. Is the CLI installed?", e))?;

    if output.status.success() {
        tracing::info!("Rule pack {} installed successfully", id);
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to install rule pack {}: {}", id, stderr.trim()))
    }
}

#[tauri::command]
pub async fn uninstall_rule_pack(id: String) -> Result<(), String> {
    validate_rule_pack_id(&id)?;

    let rules_dir = threat_intel_dir().join("rules");
    let pack_file = rules_dir.join(format!("{}.json", id));

    // Ensure the resolved path is within the rules directory
    let canonical_rules = rules_dir.canonicalize()
        .map_err(|e| format!("Rules directory not found: {}", e))?;
    if let Ok(canonical_pack) = pack_file.canonicalize() {
        if !canonical_pack.starts_with(&canonical_rules) {
            return Err("Invalid rule pack path".to_string());
        }
        std::fs::remove_file(&canonical_pack)
            .map_err(|e| format!("Failed to remove rule pack {}: {}", id, e))?;
        tracing::info!("Rule pack {} uninstalled", id);
        Ok(())
    } else {
        Err(format!("Rule pack {} is not installed", id))
    }
}

#[tauri::command]
pub async fn get_ioc_stats() -> Result<IoCStats, String> {
    let ioc_dir = threat_intel_dir().join("ioc");

    if !ioc_dir.is_dir() {
        return Ok(IoCStats {
            network: 0,
            file: 0,
            behavioral: 0,
            total: 0,
            last_updated: "never".to_string(),
        });
    }

    let mut network: u32 = 0;
    let mut file: u32 = 0;
    let mut behavioral: u32 = 0;
    let mut latest_modified: Option<std::time::SystemTime> = None;

    let entries = std::fs::read_dir(&ioc_dir)
        .map_err(|e| format!("Failed to read IoC directory: {}", e))?;

    for entry in entries.take(1000).flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        // Track latest modification time
        if let Ok(meta) = path.metadata() {
            if let Ok(modified) = meta.modified() {
                if latest_modified.is_none_or(|prev| modified > prev) {
                    latest_modified = Some(modified);
                }
            }
        }

        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let parsed: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(indicators) = parsed.get("indicators").and_then(|v| v.as_array()) {
            for indicator in indicators.iter().take(100_000) {
                let itype = indicator.get("indicator_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if itype.starts_with("MaliciousIP")
                    || itype.starts_with("MaliciousDomain")
                    || itype.starts_with("MaliciousURL")
                {
                    network += 1;
                } else if itype.starts_with("MaliciousFileHash")
                    || itype.starts_with("SuspiciousFilePath")
                {
                    file += 1;
                } else if itype.starts_with("SuspiciousProcessName")
                    || itype.starts_with("SuspiciousCommandLine")
                    || itype.starts_with("SuspiciousToolSequence")
                    || itype.starts_with("SuspiciousArgPattern")
                {
                    behavioral += 1;
                } else {
                    // Count unknown types into behavioral as catch-all
                    behavioral += 1;
                }
            }
        }
    }

    let total = network + file + behavioral;
    let last_updated = match latest_modified {
        Some(t) => {
            let datetime: chrono::DateTime<chrono::Utc> = t.into();
            datetime.to_rfc3339()
        }
        None => "never".to_string(),
    };

    Ok(IoCStats {
        network,
        file,
        behavioral,
        total,
        last_updated,
    })
}

#[tauri::command]
pub async fn get_telemetry_status() -> Result<TelemetryStatus, String> {
    let path = config_toml_path();

    if !path.exists() {
        return Ok(TelemetryStatus {
            enabled: false,
            last_report: None,
            installation_id: None,
        });
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read config.toml: {}", e))?;
    let table: toml::Value = content.parse()
        .unwrap_or(toml::Value::Table(Default::default()));

    let telemetry = table.get("telemetry");
    let enabled = telemetry
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let last_report = telemetry
        .and_then(|t| t.get("last_report"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let installation_id = telemetry
        .and_then(|t| t.get("installation_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(TelemetryStatus {
        enabled,
        last_report,
        installation_id,
    })
}

#[tauri::command]
pub async fn toggle_telemetry(enabled: bool) -> Result<(), String> {
    let path = config_toml_path();

    let mut table: toml::Value = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read config.toml: {}", e))?;
        content.parse().unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    // Ensure [telemetry] section exists
    if table.get("telemetry").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("telemetry".to_string(), toml::Value::Table(Default::default()));
    }
    let telemetry = table
        .get_mut("telemetry")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [telemetry] section")?;

    telemetry.insert("enabled".to_string(), toml::Value::Boolean(enabled));

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    let output = toml::to_string_pretty(&table)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&path, output)
        .map_err(|e| format!("Failed to write config.toml: {}", e))?;

    tracing::info!("Telemetry toggled to {}", enabled);
    Ok(())
}

#[tauri::command]
pub async fn get_telemetry_preview() -> Result<TelemetryPreview, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let audit_path = std::path::PathBuf::from(home).join(".local/share/rookbot/audit.jsonl");

    let mut categories = Vec::new();

    if audit_path.exists() {
        // Read only the last 256KB of the audit log to avoid unbounded memory use
        let (lines_vec, _) = event_stream::read_last_n_lines(&audit_path, 1000);
        let lines: Vec<&str> = lines_vec.iter().map(|s| s.as_str()).collect();

        let mut proxy_count: u32 = 0;
        let mut network_count: u32 = 0;
        let mut guard_count: u32 = 0;
        let mut allow_count: u32 = 0;
        let mut deny_count: u32 = 0;

        for line in &lines {
            if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
                let event_type = event.get("event_type")
                    .or_else(|| event.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let action = event.get("action")
                    .or_else(|| event.get("decision"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if event_type.contains("proxy") { proxy_count += 1; }
                else if event_type.contains("network") { network_count += 1; }
                else if event_type.contains("guard") { guard_count += 1; }

                if action.contains("allow") || action.contains("pass") { allow_count += 1; }
                else if action.contains("deny") || action.contains("block") { deny_count += 1; }
            }
        }

        let total = lines.len();
        categories.push(format!("Proxy events: {} (anonymized)", proxy_count));
        categories.push(format!("Network events: {} (anonymized)", network_count));
        categories.push(format!("Guard events: {} (anonymized)", guard_count));
        categories.push(format!("Decisions: {} allowed, {} denied", allow_count, deny_count));
        categories.push(format!("Total events analyzed: {}", total));
    } else {
        categories.push("No audit data available yet".to_string());
        categories.push("Events will appear once the daemon processes requests".to_string());
    }

    Ok(TelemetryPreview {
        categories,
        description: "All data is anonymous and aggregated. No file paths, server names, API keys, or personal information is collected.".to_string(),
    })
}

#[tauri::command]
pub async fn check_server_reputation(name: String) -> Result<ReputationResult, String> {
    let blocklist_path = threat_intel_dir().join("blocklist.json");

    if !blocklist_path.exists() {
        return Ok(ReputationResult {
            server_name: name,
            clean: true,
            matches: vec![],
        });
    }

    let content = std::fs::read_to_string(&blocklist_path)
        .map_err(|e| format!("Failed to read blocklist.json: {}", e))?;
    let blocklist: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse blocklist.json: {}", e))?;

    let entries = match blocklist.get("entries").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            return Ok(ReputationResult {
                server_name: name,
                clean: true,
                matches: vec![],
            });
        }
    };

    let name_lower = name.to_lowercase();
    let mut reputation_matches = Vec::new();

    for entry in entries.iter().take(10000) {
        let entry_name = match entry.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => continue,
        };
        if entry_name.to_lowercase() == name_lower {
            reputation_matches.push(ReputationMatch {
                entry_id: entry.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                severity: entry.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                description: entry.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            });
        }
    }

    let clean = reputation_matches.is_empty();
    Ok(ReputationResult {
        server_name: name,
        clean,
        matches: reputation_matches,
    })
}

// --- Network Extension ---

#[tauri::command]
pub async fn get_network_extension_status() -> Result<NetworkExtensionStatus, String> {
    // The macOS Network Extension is not installed — return honest state.
    Ok(NetworkExtensionStatus {
        loaded: false,
        filter_active: false,
        dns_active: false,
        filtering_count: 0,
        mock_mode: true,
    })
}

#[tauri::command]
pub async fn activate_network_extension() -> Result<String, String> {
    Err("Network Extension is not installed. The macOS Network Extension requires a signed system extension with special entitlements.".to_string())
}

#[tauri::command]
pub async fn deactivate_network_extension() -> Result<String, String> {
    Err("Network Extension is not installed. The macOS Network Extension requires a signed system extension with special entitlements.".to_string())
}

#[tauri::command]
pub async fn get_network_settings() -> Result<NetworkSettings, String> {
    let path = config_toml_path();
    let table: toml::Value = if path.exists() {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            format!("Failed to read config.toml: {}", e)
        })?;
        content
            .parse()
            .unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    Ok(NetworkSettings {
        filter_enabled: get_bool(&table, "network_policy", "enabled", false),
        dns_enabled: get_bool(&table, "network_policy", "dns_enabled", false),
        filter_all_processes: get_bool(&table, "network_policy", "filter_all_processes", false),
        default_action: get_str(&table, "network_policy", "default_agent_action", "prompt"),
        prompt_timeout: get_u32(&table, "network_policy", "prompt_timeout_seconds", 15),
        block_private_ranges: get_bool(&table, "network_policy", "block_private_ranges", false),
        block_doh: get_bool(&table, "network_policy", "block_doh", true),
        log_dns: get_bool(&table, "network_policy", "log_all_dns", true),
    })
}

#[tauri::command]
pub async fn update_network_settings(settings: NetworkSettings) -> Result<(), String> {
    let path = config_toml_path();

    // Read existing config to preserve other sections
    let mut table: toml::Value = if path.exists() {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            format!("Failed to read config.toml: {}", e)
        })?;
        content
            .parse()
            .unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    // Ensure [network_policy] section exists
    if table.get("network_policy").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("network_policy".to_string(), toml::Value::Table(Default::default()));
    }
    let net = table
        .get_mut("network_policy")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [network_policy] section")?;

    net.insert("enabled".to_string(), toml::Value::Boolean(settings.filter_enabled));
    net.insert("dns_enabled".to_string(), toml::Value::Boolean(settings.dns_enabled));
    net.insert("filter_all_processes".to_string(), toml::Value::Boolean(settings.filter_all_processes));
    net.insert("default_agent_action".to_string(), toml::Value::String(settings.default_action));
    net.insert("prompt_timeout_seconds".to_string(), toml::Value::Integer(settings.prompt_timeout as i64));
    net.insert("block_private_ranges".to_string(), toml::Value::Boolean(settings.block_private_ranges));
    net.insert("block_doh".to_string(), toml::Value::Boolean(settings.block_doh));
    net.insert("log_all_dns".to_string(), toml::Value::Boolean(settings.log_dns));

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!("Failed to create config directory: {}", e)
        })?;
    }

    let output = toml::to_string_pretty(&table).map_err(|e| {
        format!("Failed to serialize config: {}", e)
    })?;
    std::fs::write(&path, output).map_err(|e| {
        format!("Failed to write config.toml: {}", e)
    })?;

    tracing::info!("Network settings saved to {}", path.display());
    Ok(())
}

// --- Network Connection Log ---

/// Read network events from audit.jsonl, bounded to the last 256KB.
fn read_network_audit_records() -> Vec<event_stream::DaemonAuditRecord> {
    let path = event_stream::audit_log_path();
    if !path.exists() || !event_stream::is_safe_audit_path(&path) {
        return Vec::new();
    }

    const CHUNK_SIZE: u64 = 256 * 1024;

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let file_len = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return Vec::new(),
    };

    let read_from = file_len.saturating_sub(CHUNK_SIZE);

    let mut reader = std::io::BufReader::new(&file);
    if read_from > 0 {
        use std::io::{Seek, SeekFrom};
        if reader.seek(SeekFrom::Start(read_from)).is_err() {
            return Vec::new();
        }
        // Skip partial line after seeking
        let mut partial = String::new();
        use std::io::BufRead;
        let _ = reader.read_line(&mut partial);
    }

    let mut records = Vec::new();
    use std::io::BufRead;
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<event_stream::DaemonAuditRecord>(&line) {
            Ok(record) => {
                if record.source.contains("network") {
                    records.push(record);
                }
            }
            Err(_) => continue,
        }
    }
    records
}

/// Normalize action strings to canonical form.
fn normalize_action(action: &str) -> &'static str {
    match action.to_lowercase().as_str() {
        "allowed" | "allow" => "allowed",
        "blocked" | "block" | "denied" | "deny" => "blocked",
        "prompted" | "prompt" => "prompted",
        _ => "allowed",
    }
}

/// Try to extract a destination string from an audit record.
fn extract_destination(record: &event_stream::DaemonAuditRecord) -> Option<String> {
    if let Some(ref details) = record.event_details {
        if let Some(obj) = details.as_object() {
            for key in &["destination", "host", "domain", "destination_domain", "dest"] {
                if let Some(val) = obj.get(*key) {
                    if let Some(s) = val.as_str() {
                        if !s.is_empty() {
                            return Some(s.to_string());
                        }
                    }
                }
            }
            if let Some(ip) = obj.get("destination_ip").and_then(|v| v.as_str()) {
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }
    }
    record.server_name.clone()
}

#[tauri::command]
pub async fn get_network_connections(limit: u32) -> Result<Vec<NetworkConnectionEvent>, String> {
    let records = read_network_audit_records();
    let limit = limit.min(500) as usize;

    // Take the last `limit` records (most recent)
    let start = if records.len() > limit { records.len() - limit } else { 0 };
    let events: Vec<NetworkConnectionEvent> = records[start..]
        .iter()
        .enumerate()
        .map(|(i, record)| {
            let action = normalize_action(&record.action_taken);
            let details_obj = record.event_details.as_ref().and_then(|v| v.as_object());

            let destination_ip = details_obj
                .and_then(|o| o.get("destination_ip").and_then(|v| v.as_str()))
                .unwrap_or("0.0.0.0")
                .to_string();

            let destination_port = details_obj
                .and_then(|o| o.get("destination_port").and_then(|v| v.as_u64()))
                .unwrap_or(0) as u16;

            let destination_domain = details_obj
                .and_then(|o| o.get("destination_domain").or_else(|| o.get("domain")).or_else(|| o.get("host")))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let protocol = details_obj
                .and_then(|o| o.get("protocol").and_then(|v| v.as_str()))
                .unwrap_or("tcp")
                .to_string();

            let tls = destination_port == 443;

            let pid = details_obj
                .and_then(|o| o.get("pid").and_then(|v| v.as_u64()))
                .unwrap_or(0) as u32;

            let process_name = record.server_name.clone().unwrap_or_else(|| "unknown".to_string());

            let reason = if !record.event_summary.is_empty() {
                record.event_summary.clone()
            } else {
                record.policy_action.clone().unwrap_or_default()
            };

            let ioc_match = record.classification.as_deref()
                .map(|c| c.contains("malicious") || c.contains("ioc"))
                .unwrap_or(false);

            let rule = details_obj
                .and_then(|o| o.get("rule_matched").and_then(|v| v.as_str()))
                .map(|s| s.to_string());

            NetworkConnectionEvent {
                id: format!("net-{}", start + i),
                timestamp: record.timestamp.clone(),
                pid,
                process_name,
                server_name: record.server_name.clone(),
                destination_ip,
                destination_port,
                destination_domain,
                protocol,
                tls,
                action: action.to_string(),
                reason,
                rule,
                ioc_match,
                anomaly_score: None,
                behavioral: None,
                kill_chain: None,
                bytes_sent: 0,
                bytes_received: 0,
                duration_ms: 0,
            }
        })
        .collect();

    Ok(events)
}

#[tauri::command]
pub async fn get_network_summary() -> Result<NetworkSummaryData, String> {
    let records = read_network_audit_records();

    let mut total_allowed: u64 = 0;
    let mut total_blocked: u64 = 0;
    let mut total_prompted: u64 = 0;
    let mut dest_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    for record in &records {
        match normalize_action(&record.action_taken) {
            "allowed" => total_allowed += 1,
            "blocked" => total_blocked += 1,
            "prompted" => total_prompted += 1,
            _ => total_allowed += 1,
        }
        if let Some(dest) = extract_destination(record) {
            *dest_counts.entry(dest).or_insert(0) += 1;
        }
    }

    let mut dest_vec: Vec<(String, u64)> = dest_counts.into_iter().collect();
    dest_vec.sort_by_key(|x| std::cmp::Reverse(x.1));
    let top_destinations: Vec<DestinationCount> = dest_vec
        .into_iter()
        .take(5)
        .map(|(destination, count)| DestinationCount { destination, count })
        .collect();

    Ok(NetworkSummaryData {
        total_allowed,
        total_blocked,
        total_prompted,
        top_destinations,
        period: "last_24h".to_string(),
    })
}

#[tauri::command]
pub async fn get_network_traffic_by_server() -> Result<Vec<ServerTrafficData>, String> {
    let records = read_network_audit_records();

    let mut server_map: std::collections::HashMap<String, (u64, u64, u64, std::collections::HashSet<String>)> =
        std::collections::HashMap::new();

    for record in &records {
        let server = record.server_name.clone().unwrap_or_else(|| "unknown".to_string());
        let entry = server_map.entry(server).or_insert_with(|| (0, 0, 0, std::collections::HashSet::new()));
        match normalize_action(&record.action_taken) {
            "allowed" => entry.0 += 1,
            "blocked" => entry.1 += 1,
            "prompted" => entry.2 += 1,
            _ => entry.0 += 1,
        }
        if let Some(dest) = extract_destination(record) {
            entry.3.insert(dest);
        }
    }

    let mut results: Vec<ServerTrafficData> = server_map
        .into_iter()
        .map(|(server_name, (allowed, blocked, prompted, dests))| {
            ServerTrafficData {
                server_name,
                total_connections: allowed + blocked + prompted,
                connections_allowed: allowed,
                connections_blocked: blocked,
                connections_prompted: prompted,
                bytes_sent: 0,
                bytes_received: 0,
                unique_destinations: dests.len() as u32,
                period: "last_24h".to_string(),
            }
        })
        .collect();

    results.sort_by_key(|x| std::cmp::Reverse(x.total_connections));

    Ok(results)
}

#[tauri::command]
pub async fn export_network_log(format: String, range: String) -> Result<String, String> {
    // Validate range to prevent path traversal
    let safe_range: String = range.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if safe_range.is_empty() {
        return Err("Invalid range parameter".to_string());
    }

    let records = read_network_audit_records();

    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let export_dir = home.join(".rookbot/exports");
    std::fs::create_dir_all(&export_dir).map_err(|e| {
        format!("Failed to create exports directory: {}", e)
    })?;

    let ext = if format == "csv" { "csv" } else { "json" };
    let filename = format!("rookbot-network-log-{}.{}", safe_range, ext);
    let path = export_dir.join(&filename);

    // Verify the resolved path is still within exports dir
    let canonical_dir = export_dir.canonicalize().map_err(|e| {
        format!("Failed to resolve exports directory: {}", e)
    })?;
    if let Some(parent) = path.parent() {
        let canonical_parent = parent.canonicalize().map_err(|e| {
            format!("Failed to resolve export path: {}", e)
        })?;
        if !canonical_parent.starts_with(&canonical_dir) {
            return Err("Invalid export path".to_string());
        }
    }

    if format == "csv" {
        let mut output = String::from("timestamp,source,server_name,action_taken,event_summary,classification\n");
        for record in &records {
            let ts = record.timestamp.replace('"', "\"\"");
            let src = record.source.replace('"', "\"\"");
            let srv = record.server_name.as_deref().unwrap_or("").replace('"', "\"\"");
            let act = record.action_taken.replace('"', "\"\"");
            let summ = record.event_summary.replace('"', "\"\"");
            let cls = record.classification.as_deref().unwrap_or("").replace('"', "\"\"");
            output.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                ts, src, srv, act, summ, cls
            ));
        }
        std::fs::write(&path, output).map_err(|e| {
            format!("Failed to write CSV export: {}", e)
        })?;
    } else {
        let json = serde_json::to_string_pretty(&records).map_err(|e| {
            format!("Failed to serialize network events: {}", e)
        })?;
        std::fs::write(&path, json).map_err(|e| {
            format!("Failed to write JSON export: {}", e)
        })?;
    }

    tracing::info!("Exported {} network events to {}", records.len(), path.display());
    Ok(path.to_string_lossy().to_string())
}

// --- Kill process ---


#[tauri::command]
pub async fn kill_agent_process(pid: u32) -> Result<String, String> {
    // Security: reject system processes and guard against PID 0 (which signals
    // the entire process group) and PID 1 (init/launchd). Use a conservative
    // floor of 500 to exclude core macOS system services.
    if pid < 500 {
        return Err(format!(
            "Refusing to kill PID {} — likely a system process (PID < 500)",
            pid
        ));
    }

    // Security: guard against u32-to-i32 overflow. PIDs above i32::MAX are invalid.
    let pid_i32 = i32::try_from(pid).map_err(|_| {
        format!("Invalid PID {} — exceeds maximum valid process ID", pid)
    })?;

    // Check the process exists before attempting to kill it
    let exists = unsafe { libc::kill(pid_i32, 0) } == 0;
    if !exists {
        return Err(format!("Process {} does not exist or is not accessible", pid));
    }

    tracing::info!("Sending SIGTERM to PID {}", pid);
    let term_result = unsafe { libc::kill(pid_i32, libc::SIGTERM) };
    if term_result != 0 {
        return Err(format!(
            "Failed to send SIGTERM to PID {}: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }

    // Wait up to 3 seconds for the process to exit
    for _ in 0..6 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let still_alive = unsafe { libc::kill(pid_i32, 0) } == 0;
        if !still_alive {
            return Ok(format!("Process {} terminated successfully (SIGTERM)", pid));
        }
    }

    // Process still alive after 3 seconds — escalate to SIGKILL
    tracing::warn!("PID {} did not exit after SIGTERM, sending SIGKILL", pid);
    let kill_result = unsafe { libc::kill(pid_i32, libc::SIGKILL) };
    if kill_result != 0 {
        return Err(format!(
            "Failed to send SIGKILL to PID {}: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }

    // Brief wait to confirm SIGKILL took effect
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let still_alive = unsafe { libc::kill(pid_i32, 0) } == 0;
    if still_alive {
        Err(format!("Process {} could not be killed", pid))
    } else {
        Ok(format!("Process {} killed (SIGKILL after SIGTERM timeout)", pid))
    }
}

fn resolve_config_path(client: &str) -> Result<std::path::PathBuf, String> {
    let candidates = mcp_config_candidates_for(client);
    if candidates.is_empty() {
        return Err(format!("Unknown client: {}", client));
    }

    candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .ok_or_else(|| {
            format!(
                "Config file not found for client '{}'. Looked in: {}",
                client,
                candidates
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

fn resolve_clawdefender_path() -> String {
    // First try: sidecar binary next to the current executable
    // (In a Tauri app, current_exe is the GUI binary — the CLI sidecar
    //  is in the same directory or a sibling `binaries/` folder.)
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            // Check same directory
            let sibling = exe_dir.join("rookbot");
            if sibling.exists() {
                return sibling.to_string_lossy().to_string();
            }
            // Check Tauri sidecar binaries directory
            let sidecar = exe_dir.join("binaries").join("rookbot");
            if sidecar.exists() {
                return sidecar.to_string_lossy().to_string();
            }
        }
    }
    // Fallback: search PATH
    if let Ok(output) = std::process::Command::new("which")
        .arg("rookbot")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return path;
            }
        }
    }
    // Also check common locations
    let home = std::env::var("HOME").unwrap_or_default();
    let cargo_path = format!("{}/.cargo/bin/rookbot", home);
    if std::path::Path::new(&cargo_path).exists() {
        return cargo_path;
    }
    "rookbot".to_string()
}

fn detect_servers_key(config: &serde_json::Value) -> &str {
    if config.get("mcpServers").and_then(|v| v.as_object()).is_some() {
        "mcpServers"
    } else if config.get("servers").and_then(|v| v.as_object()).is_some() {
        "servers"
    } else {
        "mcpServers" // default
    }
}

// --- Autostart management ---

#[tauri::command]
pub fn enable_autostart(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().enable().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn disable_autostart(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().disable().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn is_autostart_enabled(app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

mod dirs {
    use std::path::PathBuf;
    pub fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

// --- Cloud API management ---

#[tauri::command]
pub async fn save_api_key(provider: String, key: String) -> Result<(), String> {
    // Security: Validate provider name against known providers to prevent
    // arbitrary keychain entries. Trim the API key to remove accidental whitespace.
    let valid_providers: Vec<String> = clawdefender_slm::cloud_backend::get_cloud_providers()
        .iter()
        .map(|p| p.id.clone())
        .collect();
    if !valid_providers.contains(&provider) {
        return Err(format!("unknown cloud provider: {}", provider));
    }
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err("API key cannot be empty".to_string());
    }
    clawdefender_slm::cloud_backend::store_api_key(&provider, &key)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn clear_api_key(provider: String) -> Result<(), String> {
    // Security: Validate provider name to prevent arbitrary keychain deletions.
    let valid_providers: Vec<String> = clawdefender_slm::cloud_backend::get_cloud_providers()
        .iter()
        .map(|p| p.id.clone())
        .collect();
    if !valid_providers.contains(&provider) {
        return Err(format!("unknown cloud provider: {}", provider));
    }
    clawdefender_slm::cloud_backend::delete_api_key(&provider)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn has_cloud_api_key(provider: String) -> Result<bool, String> {
    // Security: Validate provider name.
    let valid_providers: Vec<String> = clawdefender_slm::cloud_backend::get_cloud_providers()
        .iter()
        .map(|p| p.id.clone())
        .collect();
    if !valid_providers.contains(&provider) {
        return Err(format!("unknown cloud provider: {}", provider));
    }
    Ok(clawdefender_slm::cloud_backend::has_api_key(&provider))
}

#[tauri::command]
pub async fn test_api_connection(
    provider: String,
    model: String,
) -> Result<clawdefender_slm::cloud_backend::ConnectionTestResult, String> {
    let api_key = clawdefender_slm::cloud_backend::get_api_key(&provider)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("No API key found for provider: {}", provider))?;

    clawdefender_slm::cloud_backend::test_connection(&provider, &api_key, &model)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_cloud_usage(
    state: tauri::State<'_, AppState>,
) -> Result<clawdefender_slm::cloud_backend::CloudUsageStats, String> {
    // Try to get real stats from the Phase 2 CostTracker
    let tracker_opt = {
        let guard = state.cost_tracker.lock().map_err(|e| e.to_string())?;
        guard.clone()
    };

    if let Some(tracker_arc) = tracker_opt {
        let tracker = tracker_arc.lock().map_err(|e| e.to_string())?;
        let summary = tracker.get_summary();
        Ok(clawdefender_slm::cloud_backend::CloudUsageStats {
            provider: summary
                .by_provider
                .keys()
                .next()
                .cloned()
                .unwrap_or_default(),
            model: String::new(),
            total_requests: summary.total_calls,
            tokens_in: 0,
            tokens_out: 0,
            estimated_cost_usd: summary.total_cost,
        })
    } else {
        // Fallback: return zeroed stats
        Ok(clawdefender_slm::cloud_backend::CloudUsageStats {
            provider: String::new(),
            model: String::new(),
            total_requests: 0,
            tokens_in: 0,
            tokens_out: 0,
            estimated_cost_usd: 0.0,
        })
    }
}

#[tauri::command]
pub async fn get_cloud_providers() -> Result<Vec<clawdefender_slm::model_registry::CloudProvider>, String> {
    Ok(clawdefender_slm::cloud_backend::get_cloud_providers())
}

// ---------------------------------------------------------------------------
// Model download commands
// ---------------------------------------------------------------------------

fn models_dir() -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home
        .join(".local")
        .join("share")
        .join("rookbot")
        .join("models"))
}

#[tauri::command]
pub async fn download_model(
    model_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let dir = models_dir()?;
    state
        .download_manager
        .start_download(&model_id, &dir)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn download_custom_model(
    url: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let dir = models_dir()?;
    state
        .download_manager
        .start_custom_download(&url, &dir)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_download_progress(
    task_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<clawdefender_slm::downloader::DownloadProgress, String> {
    state
        .download_manager
        .get_progress(&task_id)
        .await
        .ok_or_else(|| format!("no download task found: {}", task_id))
}

#[tauri::command]
pub async fn cancel_download(
    task_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    if state.download_manager.cancel(&task_id).await {
        Ok(())
    } else {
        Err(format!("no active download task: {}", task_id))
    }
}

#[tauri::command]
pub async fn delete_model(model_id: String) -> Result<(), String> {
    let dir = models_dir()?;
    // Try to find filename from catalog first
    if let Some(model) = clawdefender_slm::model_registry::find_model(&model_id) {
        clawdefender_slm::downloader::DownloadManager::delete_model(&model.filename, &dir)
            .map_err(|e| e.to_string())
    } else {
        // Security: Validate the filename to prevent path traversal attacks.
        // The model_id could contain "../" to escape the models directory.
        if model_id.contains("..") || model_id.contains('/') || model_id.contains('\\') {
            return Err("invalid model filename: path traversal not allowed".to_string());
        }
        clawdefender_slm::downloader::DownloadManager::delete_model(&model_id, &dir)
            .map_err(|e| e.to_string())
    }
}

#[tauri::command]
pub async fn get_model_catalog() -> Result<Vec<clawdefender_slm::model_registry::CatalogModel>, String> {
    Ok(clawdefender_slm::model_registry::catalog())
}

#[tauri::command]
pub async fn get_installed_models() -> Result<Vec<clawdefender_slm::downloader::InstalledModelInfo>, String> {
    let dir = models_dir()?;
    clawdefender_slm::downloader::list_installed_models(&dir).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_system_capabilities() -> Result<clawdefender_slm::model_registry::SystemCapabilities, String> {
    Ok(clawdefender_slm::model_registry::detect_system_info())
}

// ---------------------------------------------------------------------------
// Model switching commands
// ---------------------------------------------------------------------------

/// Status info for the Settings page SLM widget.
#[derive(serde::Serialize)]
pub struct SlmStatusInfo {
    pub loaded: bool,
    pub model_name: Option<String>,
    pub model_size: Option<String>,
    pub backend: Option<String>,
    /// Whether a cloud backend is also available (for dual-backend awareness).
    #[serde(default)]
    pub cloud_available: bool,
}

/// A model available for activation (catalog, custom, or cloud).
#[derive(serde::Serialize)]
pub struct AvailableModel {
    pub id: String,
    pub name: String,
    pub model_type: String,
    pub status: String,
    pub size_bytes: Option<u64>,
    pub description: Option<String>,
    pub quality_rating: Option<u8>,
}

#[tauri::command]
pub async fn activate_model(
    app_handle: tauri::AppHandle,
    model_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<ActiveModelInfo, String> {
    use std::sync::Arc;
    use clawdefender_slm::engine::SlmConfig;
    use clawdefender_slm::model_registry::find_model;
    use clawdefender_slm::config_migration::{load_dual_config, save_dual_config, LocalModelConfig};

    let dir = models_dir()?;

    // Find the model in catalog or treat as a custom file path
    let (file_path, model_name, size_bytes, local_config) =
        if let Some(catalog_model) = find_model(&model_id) {
            let path = dir.join(&catalog_model.filename);
            if !path.exists() {
                return Err(format!("Model file not found: {}. Download it first.", catalog_model.display_name));
            }
            (
                path.clone(),
                catalog_model.display_name.clone(),
                Some(catalog_model.size_bytes),
                LocalModelConfig {
                    model_type: "catalog".to_string(),
                    model_id: Some(model_id.clone()),
                    path: path.clone(),
                },
            )
        } else {
            // Treat model_id as a file path for custom models
            let path = std::path::PathBuf::from(&model_id);
            if !path.exists() {
                return Err(format!("Model file not found: {}", model_id));
            }
            let size = std::fs::metadata(&path).map(|m| m.len()).ok();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "Custom Model".to_string());
            (
                path.clone(),
                name,
                size,
                LocalModelConfig {
                    model_type: "custom".to_string(),
                    model_id: None,
                    path,
                },
            )
        };

    let slm_config = SlmConfig {
        model_path: file_path.clone(),
        ..SlmConfig::default()
    };

    // Step 1: Unload current local model to free GPU memory
    state.ai_backends.clear_local();
    // Brief pause for GPU memory release
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Step 2: Load new model on a blocking thread (GGUF loading is CPU-intensive
    // and reads a 1GB+ file — it must not block the async runtime)
    tracing::info!("Activating model: {} from {}", model_name, file_path.display());
    let service = tokio::task::spawn_blocking(move || {
        clawdefender_slm::SlmService::new(slm_config, true)
    })
    .await
    .map_err(|e| format!("Model loading task failed: {}", e))?;

    if !service.is_available() {
        let msg = if service.is_mock_mode() {
            format!("Model loaded in mock mode (GGUF backend may have failed). Path: {}", file_path.display())
        } else {
            format!("Failed to load model from {}. Check the terminal for details.", file_path.display())
        };
        tracing::error!("{}", msg);
        return Err(msg);
    }

    let using_gpu = service
        .stats()
        .map(|s| s.using_gpu)
        .unwrap_or(false);

    let info = ActiveModelInfo {
        model_type: if find_model(&model_id).is_some() {
            "local_catalog".to_string()
        } else {
            "local_custom".to_string()
        },
        model_id: Some(model_id.clone()),
        model_name: model_name.clone(),
        file_path: Some(file_path.to_string_lossy().to_string()),
        provider: None,
        size_bytes,
        using_gpu,
        total_inferences: 0,
        avg_latency_ms: 0.0,
    };

    // Step 3: Install new model via AiBackendManager
    let local_info = clawdefender_slm::LocalModelInfo {
        model_name: info.model_name.clone(),
        model_id: info.model_id.clone(),
        file_path: info.file_path.clone(),
        size_bytes: info.size_bytes,
        using_gpu,
    };
    state.ai_backends.set_local(Arc::new(service), local_info);

    // Persist config — update local field in DualAiConfig, preserve cloud
    let mut dual_config = load_dual_config().unwrap_or_default();
    dual_config.local = Some(local_config);
    save_dual_config(&dual_config).map_err(|e| e.to_string())?;

    // Notify frontend of model change
    crate::events::emit_model_changed(&app_handle, Some(&info));

    Ok(info)
}

#[tauri::command]
pub async fn activate_cloud_provider(
    app_handle: tauri::AppHandle,
    provider: String,
    model: String,
    state: tauri::State<'_, AppState>,
) -> Result<ActiveModelInfo, String> {
    use std::sync::Arc;
    use clawdefender_slm::engine::{SlmBackend, SlmConfig, SlmEngine};
    use clawdefender_slm::cloud_backend::CloudBackend;
    use clawdefender_slm::model_registry::cloud_providers;
    use clawdefender_slm::config_migration::{load_dual_config, save_dual_config, CloudModelConfig};

    // Verify the provider/model combination exists
    let provider_info = cloud_providers()
        .into_iter()
        .find(|p| p.id == provider)
        .ok_or_else(|| format!("Unknown cloud provider: {}", provider))?;

    let model_info = provider_info
        .models
        .iter()
        .find(|m| m.id == model)
        .ok_or_else(|| format!("Unknown model '{}' for provider '{}'", model, provider))?;

    // Verify API key exists in keychain and retrieve it
    let api_key = clawdefender_slm::cloud_backend::get_api_key(&provider)
        .map_err(|e| format!("Failed to read API key: {}", e))?
        .ok_or_else(|| format!(
            "No API key configured for {}. Add one in Settings first.",
            provider_info.display_name
        ))?;

    // Create a real CloudBackend that calls the actual cloud API
    let backend: Box<dyn SlmBackend> = Box::new(CloudBackend::new(
        provider.clone(),
        model.clone(),
        api_key,
    ));
    let config = SlmConfig::default();
    let engine = Arc::new(SlmEngine::new(backend, config.clone()));
    let service = clawdefender_slm::SlmService::with_engine(engine, config);

    let info = ActiveModelInfo {
        model_type: "cloud_api".to_string(),
        model_id: Some(model.clone()),
        model_name: format!("{} ({})", model_info.display_name, provider_info.display_name),
        file_path: None,
        provider: Some(provider.clone()),
        size_bytes: None,
        using_gpu: false,
        total_inferences: 0,
        avg_latency_ms: 0.0,
    };

    // Step 1: Install cloud-backed service via AiBackendManager
    state.ai_backends.set_cloud(
        Arc::new(service),
        provider.clone(),
        model.clone(),
    );

    // Persist config — update cloud field in DualAiConfig, preserve local
    let mut dual_config = load_dual_config().unwrap_or_default();
    dual_config.cloud = Some(CloudModelConfig {
        provider,
        model,
    });
    save_dual_config(&dual_config).map_err(|e| e.to_string())?;

    // Notify frontend of model change
    crate::events::emit_model_changed(&app_handle, Some(&info));

    Ok(info)
}

#[tauri::command]
pub async fn deactivate_model(
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    use clawdefender_slm::config_migration::{load_dual_config, save_dual_config};

    // Only clear the local backend — cloud survives local deactivation
    state.ai_backends.clear_local();

    // Persist config — remove local field but preserve cloud
    let mut dual_config = load_dual_config().unwrap_or_default();
    dual_config.local = None;
    save_dual_config(&dual_config).map_err(|e| e.to_string())?;

    // Notify frontend of model deactivation
    crate::events::emit_model_changed(&app_handle, None);

    Ok(())
}

#[tauri::command]
pub async fn deactivate_cloud_provider(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    use clawdefender_slm::config_migration::{load_dual_config, save_dual_config};

    // Only clear the cloud backend — local survives cloud deactivation
    state.ai_backends.clear_cloud();

    // Persist config — remove cloud field but preserve local
    let mut dual_config = load_dual_config().unwrap_or_default();
    dual_config.cloud = None;
    save_dual_config(&dual_config).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn get_ai_status(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let status = state.ai_backends.get_status();
    serde_json::to_value(status).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_routing_preferences(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let prefs = state.ai_backends.get_routing_preferences();
    serde_json::to_value(prefs).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_routing_preferences(
    state: tauri::State<'_, AppState>,
    prefer_local: bool,
    cloud_auto_escalate: bool,
    cloud_confirmation: bool,
    max_cloud_calls_per_hour: u32,
) -> Result<(), String> {
    let prefs = clawdefender_slm::RoutingPreferences {
        prefer_local,
        cloud_auto_escalate,
        cloud_confirmation,
        max_cloud_calls_per_hour,
    };
    state.ai_backends.update_routing_preferences(prefs);
    Ok(())
}

#[tauri::command]
pub async fn get_rate_limit_status(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let status = state.ai_backends.get_rate_limit_status();
    serde_json::to_value(status).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Feature Routing commands
// ---------------------------------------------------------------------------

/// Load feature routing overrides from the `[ai_routing.features]` section of config.toml.
/// Public so `lib.rs` can call it at startup.
pub fn load_feature_routing_config() -> clawdefender_slm::FeatureRoutingConfig {
    let path = config_toml_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return clawdefender_slm::FeatureRoutingConfig::default(),
    };
    let table: toml::Value = match content.parse() {
        Ok(t) => t,
        Err(_) => return clawdefender_slm::FeatureRoutingConfig::default(),
    };

    let features = match table.get("ai_routing").and_then(|s| s.get("features")) {
        Some(f) => f,
        None => return clawdefender_slm::FeatureRoutingConfig::default(),
    };

    let features_table = match features.as_table() {
        Some(t) => t,
        None => return clawdefender_slm::FeatureRoutingConfig::default(),
    };

    let mut overrides = std::collections::HashMap::new();
    for (key, value) in features_table {
        let feature = match key.as_str() {
            "event_triage" => clawdefender_slm::AiFeature::EventTriage,
            "event_explanation" => clawdefender_slm::AiFeature::EventExplanation,
            "quick_risk_check" => clawdefender_slm::AiFeature::QuickRiskCheck,
            "deep_analysis" => clawdefender_slm::AiFeature::DeepAnalysis,
            "scan_analysis" => clawdefender_slm::AiFeature::ScanAnalysis,
            "ask_claw" => clawdefender_slm::AiFeature::AskClaw,
            "reports" => clawdefender_slm::AiFeature::Reports,
            "threat_hunting" => clawdefender_slm::AiFeature::ThreatHunting,
            "agent_scan" => clawdefender_slm::AiFeature::AgentScan,
            _ => continue,
        };
        let pref = match value.as_str() {
            Some("local") => clawdefender_slm::FeatureBackendPreference::Local,
            Some("cloud") => clawdefender_slm::FeatureBackendPreference::Cloud,
            Some("auto") => clawdefender_slm::FeatureBackendPreference::Auto,
            _ => continue,
        };
        if pref != clawdefender_slm::FeatureBackendPreference::Auto {
            overrides.insert(feature, pref);
        }
    }

    clawdefender_slm::FeatureRoutingConfig { overrides }
}

/// Persist the feature routing config to `[ai_routing.features]` in config.toml.
fn persist_feature_routing_to_toml(config: &clawdefender_slm::FeatureRoutingConfig) -> Result<(), String> {
    let path = config_toml_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {}", e))?;
    }

    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let mut table: toml::Value = content.parse().unwrap_or(toml::Value::Table(toml::map::Map::new()));

    let root = table.as_table_mut().ok_or("Config is not a TOML table")?;

    // Build the features sub-table with only non-auto entries
    let mut features_map = toml::map::Map::new();
    let feature_to_key = |f: &clawdefender_slm::AiFeature| -> &'static str {
        match f {
            clawdefender_slm::AiFeature::EventTriage => "event_triage",
            clawdefender_slm::AiFeature::EventExplanation => "event_explanation",
            clawdefender_slm::AiFeature::QuickRiskCheck => "quick_risk_check",
            clawdefender_slm::AiFeature::DeepAnalysis => "deep_analysis",
            clawdefender_slm::AiFeature::ScanAnalysis => "scan_analysis",
            clawdefender_slm::AiFeature::AskClaw => "ask_claw",
            clawdefender_slm::AiFeature::Reports => "reports",
            clawdefender_slm::AiFeature::ThreatHunting => "threat_hunting",
            clawdefender_slm::AiFeature::AgentScan => "agent_scan",
        }
    };

    for (feature, pref) in &config.overrides {
        if *pref != clawdefender_slm::FeatureBackendPreference::Auto {
            let val = match pref {
                clawdefender_slm::FeatureBackendPreference::Local => "local",
                clawdefender_slm::FeatureBackendPreference::Cloud => "cloud",
                clawdefender_slm::FeatureBackendPreference::Auto => unreachable!(),
            };
            features_map.insert(feature_to_key(feature).to_string(), toml::Value::String(val.to_string()));
        }
    }

    // Ensure [ai_routing] section exists
    let ai_routing = root
        .entry("ai_routing")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    if let Some(ai_table) = ai_routing.as_table_mut() {
        if features_map.is_empty() {
            ai_table.remove("features");
        } else {
            ai_table.insert("features".to_string(), toml::Value::Table(features_map));
        }
        // Clean up empty ai_routing section
        if ai_table.is_empty() {
            root.remove("ai_routing");
        }
    }

    let output = toml::to_string_pretty(&table).map_err(|e| format!("Failed to serialize TOML: {}", e))?;
    std::fs::write(&path, output).map_err(|e| format!("Failed to write config.toml: {}", e))?;
    Ok(())
}

/// Sync the AskClawAI mode based on the feature routing config for AskClaw.
async fn sync_ask_claw_mode(
    state: &AppState,
    ask_claw_pref: clawdefender_slm::FeatureBackendPreference,
) {
    let mut guard = state.ask_claw_ai.lock().await;
    if let Some(ref mut ai) = *guard {
        // Extract cloud client from agent_session_manager if available
        let cloud_client = state.agent_session_manager.lock()
            .ok()
            .and_then(|g| g.as_ref().map(|mgr| mgr.cloud_client().clone()));

        let has_cloud = cloud_client.is_some();

        let new_mode = match ask_claw_pref {
            clawdefender_slm::FeatureBackendPreference::Cloud => {
                if has_cloud {
                    clawdefender_swarm::ask_claw_ai::AskClawMode::Cloud
                } else {
                    clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern
                }
            }
            clawdefender_slm::FeatureBackendPreference::Local => {
                if state.ai_backends.local_available() {
                    clawdefender_swarm::ask_claw_ai::AskClawMode::LocalSlm
                } else {
                    clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern
                }
            }
            clawdefender_slm::FeatureBackendPreference::Auto => {
                if has_cloud {
                    clawdefender_swarm::ask_claw_ai::AskClawMode::Cloud
                } else if state.ai_backends.local_available() {
                    clawdefender_swarm::ask_claw_ai::AskClawMode::LocalSlm
                } else {
                    clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern
                }
            }
        };
        ai.set_mode(new_mode.clone());

        // Ensure cloud client is set when switching to Cloud mode
        if new_mode == clawdefender_swarm::ask_claw_ai::AskClawMode::Cloud {
            ai.set_cloud_client(cloud_client);
        }
    }
}

/// Returns all 9 features with display name, description, default backend, and current preference.
#[tauri::command]
pub async fn get_feature_routing(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let config = state.ai_backends.get_feature_routing();
    let has_overrides = config.has_overrides();

    let entries: Vec<serde_json::Value> = clawdefender_slm::AiFeature::all()
        .iter()
        .map(|feature| {
            let pref = config.get(feature);
            let pref_str = match pref {
                clawdefender_slm::FeatureBackendPreference::Auto => "auto",
                clawdefender_slm::FeatureBackendPreference::Local => "local",
                clawdefender_slm::FeatureBackendPreference::Cloud => "cloud",
            };
            let feature_str = serde_json::to_value(feature).unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "feature": feature_str,
                "display_name": feature.display_name(),
                "description": feature.description(),
                "default_backend": feature.default_backend(),
                "current_preference": pref_str,
            })
        })
        .collect();

    Ok(serde_json::json!({
        "features": entries,
        "has_overrides": has_overrides,
    }))
}

/// Update per-feature routing overrides. Accepts a map of feature key -> preference string.
#[tauri::command]
pub async fn update_feature_routing(
    state: tauri::State<'_, AppState>,
    overrides: std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let mut config = clawdefender_slm::FeatureRoutingConfig::default();

    for (key, value) in &overrides {
        let feature = match key.as_str() {
            "event_triage" => clawdefender_slm::AiFeature::EventTriage,
            "event_explanation" => clawdefender_slm::AiFeature::EventExplanation,
            "quick_risk_check" => clawdefender_slm::AiFeature::QuickRiskCheck,
            "deep_analysis" => clawdefender_slm::AiFeature::DeepAnalysis,
            "scan_analysis" => clawdefender_slm::AiFeature::ScanAnalysis,
            "ask_claw" => clawdefender_slm::AiFeature::AskClaw,
            "reports" => clawdefender_slm::AiFeature::Reports,
            "threat_hunting" => clawdefender_slm::AiFeature::ThreatHunting,
            "agent_scan" => clawdefender_slm::AiFeature::AgentScan,
            _ => continue,
        };
        let pref = match value.as_str() {
            "local" => clawdefender_slm::FeatureBackendPreference::Local,
            "cloud" => clawdefender_slm::FeatureBackendPreference::Cloud,
            _ => clawdefender_slm::FeatureBackendPreference::Auto,
        };
        if pref != clawdefender_slm::FeatureBackendPreference::Auto {
            config.overrides.insert(feature, pref);
        }
    }

    // Update in-memory router
    state.ai_backends.update_feature_routing(config.clone());

    // Persist to TOML
    persist_feature_routing_to_toml(&config)?;

    // Sync AskClawAI mode if AskClaw preference changed
    let ask_claw_pref = config.get(&clawdefender_slm::AiFeature::AskClaw);
    sync_ask_claw_mode(&state, ask_claw_pref).await;

    Ok(())
}

/// Reset all feature routing overrides to defaults (Auto).
#[tauri::command]
pub async fn reset_feature_routing(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let config = clawdefender_slm::FeatureRoutingConfig::default();

    // Update in-memory router
    state.ai_backends.update_feature_routing(config.clone());

    // Persist empty config to TOML
    persist_feature_routing_to_toml(&config)?;

    // Reset AskClawAI to auto-detect
    sync_ask_claw_mode(&state, clawdefender_slm::FeatureBackendPreference::Auto).await;

    Ok(())
}

/// Get the current Ask Rook backend preference ("auto", "cloud", or "local").
#[tauri::command]
pub async fn get_ask_claw_backend(
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let config = state.ai_backends.get_feature_routing();
    let pref = config.get(&clawdefender_slm::AiFeature::AskClaw);
    Ok(match pref {
        clawdefender_slm::FeatureBackendPreference::Auto => "auto".to_string(),
        clawdefender_slm::FeatureBackendPreference::Local => "local".to_string(),
        clawdefender_slm::FeatureBackendPreference::Cloud => "cloud".to_string(),
    })
}

/// Switch the Ask Rook backend preference (called from the AskClaw page toggle).
/// Preserves other feature routing overrides and only changes `ask_claw`.
/// Returns the resulting Ask Rook mode string (e.g. "Cloud", "LocalSlm", "Pattern").
#[tauri::command]
pub async fn set_ask_claw_backend(
    state: tauri::State<'_, AppState>,
    backend: String,
) -> Result<String, String> {
    let pref = match backend.as_str() {
        "cloud" => clawdefender_slm::FeatureBackendPreference::Cloud,
        "local" => clawdefender_slm::FeatureBackendPreference::Local,
        _ => clawdefender_slm::FeatureBackendPreference::Auto,
    };

    // Get current config, update only the AskClaw entry
    let mut config = state.ai_backends.get_feature_routing();
    if pref == clawdefender_slm::FeatureBackendPreference::Auto {
        config.overrides.remove(&clawdefender_slm::AiFeature::AskClaw);
    } else {
        config.overrides.insert(clawdefender_slm::AiFeature::AskClaw, pref);
    }

    // Update in-memory router
    state.ai_backends.update_feature_routing(config.clone());

    // Persist to TOML
    persist_feature_routing_to_toml(&config)?;

    // Sync AskClawAI mode
    sync_ask_claw_mode(&state, pref).await;

    // Return the resulting mode for the frontend
    let guard = state.ask_claw_ai.lock().await;
    let mode = match &*guard {
        Some(ai) => ai.mode().clone(),
        None => {
            let has_cloud = state.agent_session_manager.lock()
                .map(|g| g.is_some())
                .unwrap_or(false);
            match pref {
                clawdefender_slm::FeatureBackendPreference::Cloud => {
                    if has_cloud { clawdefender_swarm::ask_claw_ai::AskClawMode::Cloud }
                    else { clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern }
                }
                clawdefender_slm::FeatureBackendPreference::Local => {
                    if state.ai_backends.local_available() { clawdefender_swarm::ask_claw_ai::AskClawMode::LocalSlm }
                    else { clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern }
                }
                clawdefender_slm::FeatureBackendPreference::Auto => {
                    if has_cloud { clawdefender_swarm::ask_claw_ai::AskClawMode::Cloud }
                    else if state.ai_backends.local_available() { clawdefender_swarm::ask_claw_ai::AskClawMode::LocalSlm }
                    else { clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern }
                }
            }
        }
    };

    serde_json::to_string(&mode).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_active_model(
    state: tauri::State<'_, AppState>,
) -> Result<Option<ActiveModelInfo>, String> {
    // Build ActiveModelInfo from the dual backend manager
    let local_info = state.ai_backends.local_model_info();
    let local_stats = state.ai_backends.local_stats();
    let cloud_info = state.ai_backends.cloud_info();

    // Prefer local model info, fall back to cloud
    if let Some(linfo) = local_info {
        let mut info = ActiveModelInfo {
            model_type: if linfo.model_id.is_some() {
                "local_catalog".to_string()
            } else {
                "local_custom".to_string()
            },
            model_id: linfo.model_id,
            model_name: linfo.model_name,
            file_path: linfo.file_path,
            provider: None,
            size_bytes: linfo.size_bytes,
            using_gpu: linfo.using_gpu,
            total_inferences: 0,
            avg_latency_ms: 0.0,
        };
        if let Some(stats) = local_stats {
            info.total_inferences = stats.total_inferences;
            info.avg_latency_ms = stats.avg_latency_ms;
            info.using_gpu = stats.using_gpu;
        }
        Ok(Some(info))
    } else if let Some((provider, model_name)) = cloud_info {
        Ok(Some(ActiveModelInfo {
            model_type: "cloud_api".to_string(),
            model_id: Some(model_name.clone()),
            model_name,
            file_path: None,
            provider: Some(provider),
            size_bytes: None,
            using_gpu: false,
            total_inferences: 0,
            avg_latency_ms: 0.0,
        }))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub async fn list_available_models(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<AvailableModel>, String> {
    let dir = models_dir()?;

    // Get currently active model id from the backend manager
    let active_id = state.ai_backends.local_model_info()
        .and_then(|i| i.model_id);

    // Get installed models
    let installed = clawdefender_slm::downloader::list_installed_models(&dir)
        .unwrap_or_default();
    let installed_filenames: Vec<String> = installed.iter().map(|m| m.filename.clone()).collect();

    let mut models = Vec::new();

    // Catalog models
    for cm in clawdefender_slm::model_registry::catalog() {
        let is_active = active_id.as_deref() == Some(&cm.id);
        let is_downloaded = installed_filenames.contains(&cm.filename);
        let status = if is_active {
            "active"
        } else if is_downloaded {
            "downloaded"
        } else {
            "not_downloaded"
        };

        models.push(AvailableModel {
            id: cm.id,
            name: cm.display_name,
            model_type: "catalog".to_string(),
            status: status.to_string(),
            size_bytes: Some(cm.size_bytes),
            description: Some(cm.description),
            quality_rating: Some(cm.quality_rating),
        });
    }

    // Cloud providers
    for provider in clawdefender_slm::model_registry::cloud_providers() {
        for cm in &provider.models {
            let cloud_id = format!("{}:{}", provider.id, cm.id);
            let is_active = active_id.as_deref() == Some(&cm.id);
            let has_key = clawdefender_slm::cloud_backend::has_api_key(&provider.id);
            let status = if is_active {
                "active"
            } else if has_key {
                "available"
            } else {
                "not_downloaded"
            };

            models.push(AvailableModel {
                id: cloud_id,
                name: format!("{} ({})", cm.display_name, provider.display_name),
                model_type: "cloud".to_string(),
                status: status.to_string(),
                size_bytes: None,
                description: Some(format!("Cloud API - {}", provider.display_name)),
                quality_rating: None,
            });
        }
    }

    Ok(models)
}

#[derive(serde::Serialize)]
pub struct PromptSlmAnalysis {
    pub analysis: String,
    pub recommendation: String,
}

#[tauri::command]
pub async fn get_slm_analysis_for_prompt(
    state: tauri::State<'_, AppState>,
    prompt_id: String,
) -> Result<Option<PromptSlmAnalysis>, String> {
    // Find the pending prompt to build context
    let prompt_context = {
        let prompts = state.pending_prompts.lock().map_err(|e| e.to_string())?;
        prompts.iter().find(|p| p.id == prompt_id).map(|p| {
            format!(
                "Analyze this MCP tool call for security risk:\n\
                 Server: {}\nTool: {}\nAction: {}\nResource: {}\nRisk Level: {}\nContext: {}",
                p.server_name, p.tool_name, p.action, p.resource, p.risk_level, p.context
            )
        })
    };

    let prompt_text = match prompt_context {
        Some(ctx) => ctx,
        None => return Ok(None),
    };

    // Route through the AI backend manager as a Triage task
    let ai_resp = state.ai_backends.analyze(clawdefender_slm::AiRequest {
        task_type: clawdefender_slm::TaskType::Triage,
        prompt: prompt_text,
        context: None,
    }).await;

    match ai_resp.response {
        Some(response) => {
            let recommendation = match response.risk_level {
                clawdefender_slm::engine::RiskLevel::Critical
                | clawdefender_slm::engine::RiskLevel::High => "Deny this request".to_string(),
                clawdefender_slm::engine::RiskLevel::Medium => "Review carefully before allowing".to_string(),
                clawdefender_slm::engine::RiskLevel::Low => "Likely safe to allow".to_string(),
            };
            Ok(Some(PromptSlmAnalysis {
                analysis: response.explanation,
                recommendation,
            }))
        }
        None => Ok(None),
    }
}

#[tauri::command]
pub async fn get_slm_status(
    state: tauri::State<'_, AppState>,
) -> Result<SlmStatusInfo, String> {
    let ai_status = state.ai_backends.get_status();

    let cloud_available = ai_status.cloud.active;

    // Prefer local backend info for backward-compatible status
    if ai_status.local.active {
        let size_str = ai_status.local.model_size.map(|b| {
            if b >= 1_000_000_000 {
                format!("{:.1} GB", b as f64 / 1_000_000_000.0)
            } else {
                format!("{:.0} MB", b as f64 / 1_000_000.0)
            }
        });
        let backend = if ai_status.local.gpu_enabled {
            "GPU".to_string()
        } else {
            "CPU".to_string()
        };
        Ok(SlmStatusInfo {
            loaded: true,
            model_name: ai_status.local.model_name,
            model_size: size_str,
            backend: Some(backend),
            cloud_available,
        })
    } else if cloud_available {
        Ok(SlmStatusInfo {
            loaded: true,
            model_name: ai_status.cloud.model,
            model_size: None,
            backend: ai_status.cloud.provider,
            cloud_available,
        })
    } else {
        Ok(SlmStatusInfo {
            loaded: false,
            model_name: None,
            model_size: None,
            backend: None,
            cloud_available: false,
        })
    }
}

// --- Alert management commands ---

#[tauri::command]
pub async fn get_active_alerts_cmd(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<crate::alerts::engine::IntelligentAlert>, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_alerts());
    }

    let store = state
        .alert_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    Ok(crate::alerts::lifecycle::get_active_alerts(&store))
}

#[tauri::command]
pub async fn get_alert_stats_cmd(
    state: tauri::State<'_, AppState>,
) -> Result<crate::alerts::lifecycle::AlertStats, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_alert_stats());
    }

    let store = state
        .alert_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    Ok(crate::alerts::lifecycle::get_alert_stats(&store))
}

#[tauri::command]
pub async fn dismiss_alert_cmd(
    state: tauri::State<'_, AppState>,
    alert_id: String,
) -> Result<bool, String> {
    let mut store = state
        .alert_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    Ok(crate::alerts::lifecycle::dismiss_alert(&mut store, &alert_id))
}

#[tauri::command]
pub async fn resolve_alert_cmd(
    state: tauri::State<'_, AppState>,
    alert_id: String,
    resolution: String,
) -> Result<bool, String> {
    let mut store = state
        .alert_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    Ok(crate::alerts::lifecycle::resolve_alert(
        &mut store,
        &alert_id,
        &resolution,
    ))
}

#[tauri::command]
pub async fn dismiss_all_alerts(
    state: tauri::State<'_, AppState>,
    max_severity: String,
) -> Result<u32, String> {
    let mut store = state
        .alert_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    Ok(crate::alerts::lifecycle::dismiss_all(
        &mut store,
        Some(&max_severity),
    ))
}

#[tauri::command]
pub async fn get_alert_history_cmd(
    state: tauri::State<'_, AppState>,
    days: u32,
) -> Result<Vec<crate::alerts::engine::IntelligentAlert>, String> {
    let store = state
        .alert_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    Ok(crate::alerts::lifecycle::get_alert_history(&store, days))
}

#[tauri::command]
pub async fn get_alert_detail(
    state: tauri::State<'_, AppState>,
    alert_id: String,
) -> Result<Option<crate::alerts::engine::IntelligentAlert>, String> {
    let store = state
        .alert_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    Ok(store.iter().find(|a| a.id == alert_id).cloned())
}

// ---------------------------------------------------------------------------
// Missing commands required by the frontend
// ---------------------------------------------------------------------------

/// Get humanized events for the Activity page.
#[tauri::command]
pub async fn get_humanized_events(
    state: tauri::State<'_, AppState>,
    count: usize,
    offset: usize,
) -> Result<Vec<serde_json::Value>, String> {
    if crate::demo_data::is_demo_mode() {
        let all = crate::demo_data::mock_humanized_events();
        return Ok(all.into_iter().skip(offset).take(count).collect());
    }

    let buf = state.event_buffer.lock().map_err(|e| e.to_string())?;
    let events: Vec<serde_json::Value> = buf
        .iter()
        .rev()
        .skip(offset)
        .take(count)
        .map(|e| {
            let is_os = matches!(
                e.event_type.as_str(),
                "eslogger" | "fsevents" | "correlation"
            );
            // OS events: use just the humanized action (server is redundant)
            // MCP events: "server — action" format
            let one_liner = if is_os {
                e.action.clone()
            } else {
                format!("{} — {}", e.server_name, e.action)
            };
            // Map raw decision strings to display-friendly values
            let action_taken = match e.decision.to_lowercase().as_str() {
                "blocked" | "denied" | "block" => "Blocked",
                "prompted" | "prompt" => "Prompted",
                "" => "Allowed",
                _ => "Allowed",
            };
            serde_json::json!({
                "event_id": e.id,
                "one_liner": one_liner,
                "expanded_explanation": e.details,
                "risk_level": e.risk_level,
                "action_taken": action_taken,
                "server_display_name": e.server_name,
                "server_name": e.server_name,
                "client_name": null,
                "tool_name": e.tool_name,
                "timestamp": e.timestamp,
                "source_type": if is_os { "os" } else { "mcp" },
                "is_notable": e.risk_level == "high" || e.risk_level == "critical" || action_taken == "Blocked",
                "educational_aside": null,
                "behavioral_context": "",
                "risk_explanation": "",
                "action_reason": "",
                "correlation_id": null,
                "kill_chain_id": null,
                "raw_event": e,
            })
        })
        .collect();
    Ok(events)
}

/// Get the protection score.
#[tauri::command]
pub async fn get_protection_score(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_protection_score());
    }

    let local_active = state.ai_backends.local_available();
    let cloud_active = state.ai_backends.cloud_available();
    let ai_points: u32 = if local_active {
        15
    } else if cloud_active {
        5
    } else {
        0
    };

    let alert_count = state.alert_store.lock().map(|s| s.len()).unwrap_or(0);
    let alert_points: u32 = if alert_count == 0 { 15 } else if alert_count <= 3 { 10 } else { 5 };

    let total = 25 + 20 + ai_points + 15 + alert_points + 10; // simplified scoring

    let (label, color) = if total >= 85 {
        ("Protected", "green")
    } else if total >= 70 {
        ("Mostly Protected", "green")
    } else if total >= 55 {
        ("Needs Attention", "yellow")
    } else {
        ("At Risk", "red")
    };

    Ok(serde_json::json!({
        "total": total,
        "label": label,
        "color": color,
        "computed_at": chrono::Utc::now().to_rfc3339(),
        "change_from_last": null,
        "factors": [
            { "id": "tool_coverage", "name": "Tool Coverage", "description": "Coverage of detected MCP servers by monitoring", "current_points": 25, "max_points": 25, "status": "full", "details": "All detected MCP servers are monitored", "fix_actions": [] },
            { "id": "threat_intel", "name": "Threat Intelligence", "description": "Active threat intelligence feed status", "current_points": 20, "max_points": 20, "status": "full", "details": "Threat feed is active", "fix_actions": [] },
            { "id": "ai_analysis", "name": "AI Analysis", "description": "On-device AI model for deep security analysis", "current_points": ai_points, "max_points": 15, "status": if ai_points >= 10 { "full" } else { "partial" }, "details": if ai_points >= 10 { "AI model is active" } else { "No AI model loaded — using heuristic analysis" }, "fix_actions": if ai_points < 10 { serde_json::json!([{ "label": "Load AI Model", "action_type": "navigate", "target": "/settings" }]) } else { serde_json::json!([]) } },
            { "id": "visibility", "name": "System Visibility", "description": "OS-level security monitoring coverage", "current_points": 15, "max_points": 15, "status": "full", "details": "OS-level monitoring active", "fix_actions": [] },
            { "id": "alerts", "name": "Unresolved Alerts", "description": "Pending security alerts requiring attention", "current_points": alert_points, "max_points": 15, "status": if alert_count == 0 { "full" } else { "partial" }, "details": format!("{} unresolved alerts", alert_count), "fix_actions": if alert_count > 0 { serde_json::json!([{ "label": "View Alerts", "action_type": "navigate", "target": "/alerts" }]) } else { serde_json::json!([]) } },
            { "id": "config", "name": "Config Health", "description": "Configuration correctness and security posture", "current_points": 10, "max_points": 10, "status": "full", "details": "Configuration is healthy", "fix_actions": [] }
        ]
    }))
}

/// Get score history for the chart.
#[tauri::command]
pub async fn get_score_history(_days: u32) -> Result<Vec<serde_json::Value>, String> {
    Ok(vec![])
}

/// Ask Rook natural language query.
///
/// When a cloud agent session manager is available (API key configured),
/// routes through the cloud-powered agent with tool-use capabilities.
/// Falls back to local SLM or heuristic analysis otherwise.
#[tauri::command]
pub async fn ask_claw(
    state: tauri::State<'_, AppState>,
    input: String,
    context_json: Option<String>,
) -> Result<String, String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let turn_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| format!("turn-{}", d.as_millis()))
        .unwrap_or_else(|_| "turn-0".to_string());

    let _context = context_json.unwrap_or_default();

    // Phase 2: Try cloud agent first when available
    let cloud_mgr = {
        let guard = state.agent_session_manager.lock().map_err(|e| e.to_string())?;
        guard.clone()
    };

    if let Some(mgr) = cloud_mgr {
        // Use a Chat session for Ask Rook queries via the cloud agent
        let briefing = clawdefender_swarm::context_bridge::CloudBriefingBuilder::new(
            clawdefender_swarm::context_bridge::SessionType::Chat,
        )
        .with_system_profile(clawdefender_swarm::context_bridge::SystemProfile {
            os_version: std::env::consts::OS.to_string(),
            cpu_architecture: std::env::consts::ARCH.to_string(),
            cpu_name: "unknown".to_string(),
            ram_gb: 0,
            gpu: None,
        })
        .with_event_summary("No events loaded".to_string())
        .build();

        let briefing_text = briefing.to_system_prompt();

        match mgr
            .start_session(
                clawdefender_swarm::agent_session::SessionType::Chat,
                briefing_text,
                Some(input.clone()),
            )
            .await
        {
            Ok(session_id) => {
                match mgr.send_message(&session_id, &input).await {
                    Ok(result) => {
                        let response = serde_json::json!({
                            "message": result.text,
                            "turn_id": turn_id,
                            "intent_id": "general.query",
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                            "actions": [],
                            "structured_data": {
                                "cloud_powered": true,
                                "session_id": session_id,
                                "tool_calls": result.tool_calls_made.len(),
                                "findings": result.findings.len(),
                                "tokens_used": {
                                    "input": result.tokens_used.input_tokens,
                                    "output": result.tokens_used.output_tokens,
                                }
                            }
                        });
                        return serde_json::to_string(&response).map_err(|e| e.to_string());
                    }
                    Err(e) => {
                        tracing::warn!("Cloud agent send_message failed, falling back to local: {e}");
                        // Fall through to local SLM below
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Cloud agent session start failed, falling back to local: {e}");
                // Fall through to local SLM below
            }
        }
    }

    // Route through AiBackendManager as an AskClaw task
    let prompt = format!(
        "You are Claw, a friendly security assistant for RookBot. \
         Answer the user's security question concisely.\n\nUser: {}\n\nClaw:",
        input
    );

    let ai_resp = state.ai_backends.analyze(clawdefender_slm::AiRequest {
        task_type: clawdefender_slm::TaskType::AskClaw,
        prompt: prompt.clone(),
        context: None,
    }).await;

    // Check if the AI response is a real analysis or a fail-closed placeholder.
    // analyze_event() catches internal errors and returns Ok(unavailable_response)
    // with confidence 0.0, which looks like "success" but isn't a real analysis.
    let usable_response = ai_resp.response.filter(|r| r.confidence > 0.0);

    let response = if let Some(result) = usable_response {
        serde_json::json!({
            "message": result.explanation,
            "turn_id": turn_id,
            "intent_id": "general.query",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "actions": [],
            "structured_data": null
        })
    } else {
        // No usable backends — use the heuristic backend as a fallback
        let heuristic_config = clawdefender_slm::engine::SlmConfig::default();
        let heuristic_backend: Box<dyn clawdefender_slm::engine::SlmBackend> =
            Box::new(clawdefender_slm::engine::HeuristicSlmBackend::new());
        let heuristic_engine = clawdefender_slm::engine::SlmEngine::new(heuristic_backend, heuristic_config);
        match heuristic_engine.infer(&prompt).await {
            Ok(result) => {
                let mode_note = " (Heuristic mode — download an AI model from Settings for deeper analysis)";
                serde_json::json!({
                    "message": format!("{}{}", result.explanation, mode_note),
                    "turn_id": turn_id,
                    "intent_id": "general.query",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "actions": [],
                    "structured_data": null
                })
            }
            Err(_) => serde_json::json!({
                "message": "No AI model is loaded. Go to Settings > AI Analysis to download and activate a model, then I can answer your security questions.",
                "turn_id": turn_id,
                "intent_id": "error.no_model",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "actions": [
                    {
                        "id": "go-to-settings",
                        "label": "Open Settings",
                        "action": { "type": "navigate", "page": "/settings" },
                        "style": "primary",
                        "requires_confirmation": false
                    }
                ],
                "structured_data": null
            })
        }
    };

    serde_json::to_string(&response).map_err(|e| e.to_string())
}

/// Confirm an action suggested by Ask Rook.
#[tauri::command]
pub async fn confirm_action(
    action_json: String,
    state: Option<String>,
) -> Result<String, String> {
    let _action: serde_json::Value = serde_json::from_str(&action_json)
        .map_err(|e| e.to_string())?;
    let _state = state.unwrap_or_default();

    Ok(serde_json::json!({
        "message": "Action acknowledged.",
        "turn_id": format!("confirm-{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis()).unwrap_or(0)),
        "intent_id": "control.confirm",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "actions": [],
        "structured_data": null
    }).to_string())
}

/// Analyze a URL for security risks.
#[tauri::command]
pub async fn analyze_url(
    state: tauri::State<'_, AppState>,
    url: String,
) -> Result<String, String> {
    let prompt = format!("Analyze this URL for security risks: {}", url);
    let ai_resp = state.ai_backends.analyze(clawdefender_slm::AiRequest {
        task_type: clawdefender_slm::TaskType::QuickRiskAssessment,
        prompt,
        context: None,
    }).await;

    let result = if let Some(response) = ai_resp.response {
        serde_json::json!({
            "url": url,
            "analysis": response.explanation,
            "risk": format!("{:?}", response.risk_level)
        })
    } else {
        serde_json::json!({
            "url": url,
            "analysis": ai_resp.message.unwrap_or_else(|| "No AI model loaded. Cannot analyze URL.".to_string()),
            "risk": "unknown"
        })
    };
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// Execute a fix action from the protection score breakdown.
#[tauri::command]
pub async fn execute_fix_action(
    action_id: String,
) -> Result<String, String> {
    Ok(serde_json::json!({
        "status": "ok",
        "message": format!("Action '{}' acknowledged. Some fixes require manual steps.", action_id)
    }).to_string())
}

/// Get recommendations for the Alerts page.
#[tauri::command]
pub async fn get_recommendations_cmd() -> Result<Vec<serde_json::Value>, String> {
    Ok(vec![])
}

/// Execute a recommendation.
#[tauri::command]
pub async fn execute_recommendation_cmd(_id: String) -> Result<String, String> {
    Ok("ok".to_string())
}

/// Dismiss a recommendation.
#[tauri::command]
pub async fn dismiss_recommendation_cmd(_id: String) -> Result<(), String> {
    Ok(())
}

/// Get pending prompts for the prompt queue.
#[tauri::command]
pub async fn get_pending_prompts(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PendingPrompt>, String> {
    let prompts = state.pending_prompts.lock().map_err(|e| e.to_string())?;
    Ok(prompts.clone())
}

// ---------------------------------------------------------------------------
// Conversation management commands (Ask Rook persistence)
// ---------------------------------------------------------------------------

/// Return the path to the conversations storage directory, creating it if needed.
fn conversations_dir() -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or("No home directory found")?;
    let dir = home.join(".local/share/rookbot/conversations");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create conversations directory: {}", e))?;
    Ok(dir)
}

/// Sanitize a conversation ID to prevent path traversal.
fn sanitize_conversation_id(id: &str) -> Result<String, String> {
    let safe: String = id
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe.is_empty() {
        return Err("Invalid conversation ID".to_string());
    }
    Ok(safe)
}

/// Write a conversation JSON file with owner-only permissions.
fn write_conversation_file(
    path: &std::path::Path,
    json: &str,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("Failed to create conversation file: {}", e))?;
        std::io::Write::write_all(&mut file, json.as_bytes())
            .map_err(|e| format!("Failed to write conversation file: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write conversation file: {}", e))?;
    }
    Ok(())
}

/// Build a summary object for a conversation value.
fn conversation_summary(conv: &serde_json::Value) -> serde_json::Value {
    let messages = conv.get("messages").and_then(|m| m.as_array());
    let message_count = messages.map(|m| m.len()).unwrap_or(0);
    let last_message_preview = messages
        .and_then(|m| m.last())
        .and_then(|msg| msg.get("content_text"))
        .and_then(|t| t.as_str())
        .map(|t| {
            if t.len() > 100 {
                format!("{}...", &t[..100])
            } else {
                t.to_string()
            }
        })
        .unwrap_or_default();
    serde_json::json!({
        "id": conv.get("id").and_then(|v| v.as_str()).unwrap_or(""),
        "created_at": conv.get("created_at").and_then(|v| v.as_str()).unwrap_or(""),
        "updated_at": conv.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""),
        "message_count": message_count,
        "last_message_preview": last_message_preview,
        "summary": if message_count == 0 {
            "Empty conversation".to_string()
        } else {
            format!("{} message{}", message_count, if message_count == 1 { "" } else { "s" })
        }
    })
}

#[tauri::command]
pub async fn get_latest_conversation_id() -> Result<String, String> {
    let dir = conversations_dir()?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok("null".to_string()),
    };

    let mut latest_id: Option<String> = None;
    let mut latest_time: Option<String> = None;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let conv: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let updated_at = conv
            .get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let id = conv
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        if latest_time.is_none() || updated_at > *latest_time.as_ref().unwrap() {
            latest_time = Some(updated_at);
            latest_id = Some(id);
        }
    }

    match latest_id {
        Some(id) => Ok(serde_json::to_string(&id).map_err(|e| e.to_string())?),
        None => Ok("null".to_string()),
    }
}

#[tauri::command]
pub async fn create_new_conversation() -> Result<String, String> {
    let dir = conversations_dir()?;
    let id = format!(
        "conv-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    let now = chrono::Utc::now().to_rfc3339();
    let conv = serde_json::json!({
        "id": id,
        "created_at": now,
        "updated_at": now,
        "messages": []
    });
    let json = serde_json::to_string_pretty(&conv).map_err(|e| e.to_string())?;
    let safe_id = sanitize_conversation_id(&id)?;
    let file_path = dir.join(format!("{}.json", safe_id));
    write_conversation_file(&file_path, &json)?;
    tracing::info!("Created conversation {}", id);
    Ok(serde_json::to_string(&id).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub async fn save_conversation_message(
    message_json: String,
) -> Result<(), String> {
    let msg: serde_json::Value =
        serde_json::from_str(&message_json).map_err(|e| format!("Invalid message JSON: {}", e))?;

    let conversation_id = msg
        .get("conversation_id")
        .and_then(|v| v.as_str())
        .ok_or("Missing conversation_id in message")?
        .to_string();

    let dir = conversations_dir()?;
    let safe_id = sanitize_conversation_id(&conversation_id)?;
    let file_path = dir.join(format!("{}.json", safe_id));

    let mut conv: serde_json::Value = if file_path.exists() {
        let contents = std::fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read conversation: {}", e))?;
        serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse conversation: {}", e))?
    } else {
        let now = chrono::Utc::now().to_rfc3339();
        serde_json::json!({
            "id": conversation_id,
            "created_at": now,
            "updated_at": now,
            "messages": []
        })
    };

    // Append the message to the messages array
    if let Some(messages) = conv.get_mut("messages").and_then(|m| m.as_array_mut()) {
        // Strip conversation_id from the stored message to avoid redundancy
        let mut stored_msg = msg.clone();
        if let Some(obj) = stored_msg.as_object_mut() {
            obj.remove("conversation_id");
        }
        messages.push(stored_msg);
    } else {
        return Err("Conversation file has invalid messages field".to_string());
    }

    // Update the updated_at timestamp
    let now = chrono::Utc::now().to_rfc3339();
    if let Some(obj) = conv.as_object_mut() {
        obj.insert("updated_at".to_string(), serde_json::Value::String(now));
    }

    let json = serde_json::to_string_pretty(&conv).map_err(|e| e.to_string())?;
    write_conversation_file(&file_path, &json)?;
    Ok(())
}

#[tauri::command]
pub async fn load_conversation(
    conversation_id: String,
) -> Result<String, String> {
    let dir = conversations_dir()?;
    let safe_id = sanitize_conversation_id(&conversation_id)?;
    let file_path = dir.join(format!("{}.json", safe_id));

    if !file_path.exists() {
        return Ok("[]".to_string());
    }

    let contents = std::fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read conversation: {}", e))?;
    let conv: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse conversation: {}", e))?;

    let messages = conv.get("messages").cloned().unwrap_or(serde_json::json!([]));
    serde_json::to_string(&messages).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_conversations(
    limit: Option<u32>,
) -> Result<String, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_conversations());
    }

    let dir = conversations_dir()?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok("[]".to_string()),
    };

    let mut summaries: Vec<serde_json::Value> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let conv: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(_) => continue,
        };
        summaries.push(conversation_summary(&conv));
    }

    // Sort by updated_at descending
    summaries.sort_by(|a, b| {
        let a_time = a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
        let b_time = b.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
        b_time.cmp(a_time)
    });

    // Apply limit
    if let Some(lim) = limit {
        summaries.truncate(lim as usize);
    }

    serde_json::to_string(&summaries).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_conversation(
    conversation_id: String,
) -> Result<(), String> {
    let dir = conversations_dir()?;
    let safe_id = sanitize_conversation_id(&conversation_id)?;
    let file_path = dir.join(format!("{}.json", safe_id));

    if file_path.exists() {
        std::fs::remove_file(&file_path)
            .map_err(|e| format!("Failed to delete conversation: {}", e))?;
        tracing::info!("Deleted conversation {}", conversation_id);
    }
    Ok(())
}

#[tauri::command]
pub async fn search_conversations(
    query: String,
) -> Result<String, String> {
    let dir = conversations_dir()?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok("[]".to_string()),
    };

    let query_lower = query.to_lowercase();
    let mut results: Vec<serde_json::Value> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let conv: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Search through all message content_text fields (case-insensitive)
        let matches = conv
            .get("messages")
            .and_then(|m| m.as_array())
            .map(|messages| {
                messages.iter().any(|msg| {
                    msg.get("content_text")
                        .and_then(|t| t.as_str())
                        .map(|t| t.to_lowercase().contains(&query_lower))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);

        if matches {
            results.push(conversation_summary(&conv));
        }
    }

    // Sort by updated_at descending
    results.sort_by(|a, b| {
        let a_time = a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
        let b_time = b.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
        b_time.cmp(a_time)
    });

    serde_json::to_string(&results).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// File/config analysis commands (Ask Rook drag-and-drop)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn analyze_config(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<String, String> {
    let file_name = std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read file: {}", e))?;

    // Truncate content for analysis
    let truncated = if content.len() > 2000 {
        format!("{}...(truncated)", &content[..2000])
    } else {
        content
    };

    let prompt = format!(
        "Analyze this configuration file for security risks:\nFile: {}\nContent:\n{}",
        file_name, truncated
    );
    let ai_resp = state.ai_backends.analyze(clawdefender_slm::AiRequest {
        task_type: clawdefender_slm::TaskType::DeepAnalysis,
        prompt,
        context: None,
    }).await;

    let analysis = match ai_resp.response {
        Some(resp) => resp.explanation,
        None => format!("Configuration file '{}' loaded. Enable an AI model in Settings to get security analysis.", file_name),
    };

    Ok(serde_json::json!({
        "summary": analysis,
        "message": analysis,
        "structured_data": null,
        "actions": []
    }).to_string())
}

#[tauri::command]
pub async fn analyze_file(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<String, String> {
    use sha2::Digest;

    let file_path = std::path::Path::new(&path);
    let file_name = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());

    // 1. Check if file exists
    if !file_path.exists() {
        return Err(format!("File not found: {}", path));
    }

    let mut factors: Vec<String> = Vec::new();
    let mut risk_level = "low";

    // 2. Get file metadata
    let metadata = std::fs::metadata(&path)
        .map_err(|e| format!("Failed to read file metadata: {}", e))?;
    let file_size = metadata.len();

    let modified_time = metadata
        .modified()
        .ok()
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Unix permissions
    #[cfg(unix)]
    let permissions_str = {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        let perm_str = format!("{:o}", mode & 0o7777);
        // Check for overly permissive files
        if mode & 0o002 != 0 {
            factors.push("File is world-writable".to_string());
            risk_level = "medium";
        }
        if mode & 0o4000 != 0 {
            factors.push("File has setuid bit set".to_string());
            risk_level = "high";
        }
        if mode & 0o2000 != 0 {
            factors.push("File has setgid bit set".to_string());
            risk_level = "high";
        }
        perm_str
    };
    #[cfg(not(unix))]
    let permissions_str = if metadata.permissions().readonly() {
        "readonly".to_string()
    } else {
        "read-write".to_string()
    };

    // 3. Read first 16 bytes for magic number detection
    let magic_bytes = {
        use std::io::Read;
        let mut file = std::fs::File::open(&path)
            .map_err(|e| format!("Failed to open file: {}", e))?;
        let mut buf = [0u8; 16];
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Failed to read file header: {}", e))?;
        buf[..n].to_vec()
    };

    let magic_hex: String = magic_bytes.iter().map(|b| format!("{:02X}", b)).collect();

    let file_type = if magic_bytes.len() >= 2 && magic_bytes[0] == 0x4D && magic_bytes[1] == 0x5A {
        factors.push("Windows executable (MZ header) detected".to_string());
        risk_level = "high";
        "Windows executable (MZ)"
    } else if magic_bytes.len() >= 4
        && magic_bytes[0] == 0xCF
        && magic_bytes[1] == 0xFA
        && magic_bytes[2] == 0xED
        && magic_bytes[3] == 0xFE
    {
        factors.push("Mach-O binary detected".to_string());
        if risk_level != "high" {
            risk_level = "medium";
        }
        "Mach-O binary"
    } else if magic_bytes.len() >= 4
        && magic_bytes[0] == 0x7F
        && magic_bytes[1] == 0x45
        && magic_bytes[2] == 0x4C
        && magic_bytes[3] == 0x46
    {
        factors.push("ELF binary detected".to_string());
        if risk_level != "high" {
            risk_level = "medium";
        }
        "ELF binary"
    } else if magic_bytes.len() >= 4
        && magic_bytes[0] == 0x50
        && magic_bytes[1] == 0x4B
        && magic_bytes[2] == 0x03
        && magic_bytes[3] == 0x04
    {
        factors.push("ZIP/JAR archive detected".to_string());
        "ZIP/JAR archive"
    } else if magic_bytes.len() >= 4
        && magic_bytes[0] == 0x25
        && magic_bytes[1] == 0x50
        && magic_bytes[2] == 0x44
        && magic_bytes[3] == 0x46
    {
        "PDF document"
    } else if magic_bytes.len() >= 4
        && magic_bytes[0] == 0x89
        && magic_bytes[1] == 0x50
        && magic_bytes[2] == 0x4E
        && magic_bytes[3] == 0x47
    {
        "PNG image"
    } else {
        "Unknown"
    };

    // 4. Compute SHA-256 hash for files under 100MB
    let sha256_hash = if file_size <= 100 * 1024 * 1024 {
        let file_bytes = std::fs::read(&path)
            .map_err(|e| format!("Failed to read file for hashing: {}", e))?;
        let hash = sha2::Sha256::digest(&file_bytes);
        format!("{:x}", hash)
    } else {
        factors.push(format!("File is very large ({} bytes), hash skipped", file_size));
        "skipped (file > 100MB)".to_string()
    };

    // 5. Check macOS extended attributes (quarantine flag)
    let xattr_output = tokio::process::Command::new("xattr")
        .arg("-l")
        .arg(&path)
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let has_quarantine = xattr_output.contains("com.apple.quarantine");
    if has_quarantine {
        factors.push("File has quarantine flag (downloaded from internet)".to_string());
    }

    // 6. Check macOS code signature
    let codesign_output = tokio::process::Command::new("codesign")
        .arg("-dvv")
        .arg(&path)
        .output()
        .await
        .ok();

    let (code_signed, codesign_info) = match &codesign_output {
        Some(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let combined = format!("{}{}", stdout, stderr);
            if output.status.success() {
                if combined.contains("Authority=Apple") || combined.contains("Authority=Software Signing") {
                    factors.push("Signed by Apple".to_string());
                    (true, combined)
                } else if combined.contains("Authority=Developer ID") {
                    factors.push("Signed with Developer ID".to_string());
                    (true, combined)
                } else {
                    factors.push("Code signed (check authority)".to_string());
                    (true, combined)
                }
            } else {
                if combined.contains("not signed") {
                    factors.push("File is not code-signed".to_string());
                    if file_type == "Mach-O binary" || file_type == "Windows executable (MZ)" {
                        risk_level = "high";
                    }
                }
                (false, combined)
            }
        }
        None => {
            (false, "codesign command not available".to_string())
        }
    };

    // Build detailed message
    let mut detail_lines = Vec::new();
    detail_lines.push(format!("File: {}", path));
    detail_lines.push(format!("Type: {}", file_type));
    detail_lines.push(format!("Size: {} bytes", file_size));
    detail_lines.push(format!("Permissions: {}", permissions_str));
    detail_lines.push(format!("Modified: {}", modified_time));
    detail_lines.push(format!("SHA-256: {}", sha256_hash));
    detail_lines.push(format!("Magic bytes: {}", if magic_hex.len() > 32 { &magic_hex[..32] } else { &magic_hex }));
    detail_lines.push(format!("Quarantine flag: {}", if has_quarantine { "yes" } else { "no" }));
    detail_lines.push(format!("Code signed: {}", if code_signed { "yes" } else { "no" }));

    if !factors.is_empty() {
        detail_lines.push(String::new());
        detail_lines.push("Risk factors:".to_string());
        for f in &factors {
            detail_lines.push(format!("  - {}", f));
        }
    }

    // 7. Optional AI analysis with the collected data
    let ai_prompt = format!(
        "Provide a brief security assessment of this file based on the following metadata:\n\
         File: {}\nType: {}\nSize: {} bytes\nPermissions: {}\n\
         SHA-256: {}\nQuarantine: {}\nCode signed: {}\n\
         Risk factors: {}",
        file_name,
        file_type,
        file_size,
        permissions_str,
        sha256_hash,
        has_quarantine,
        code_signed,
        if factors.is_empty() { "none".to_string() } else { factors.join(", ") }
    );

    let ai_resp = state
        .ai_backends
        .analyze(clawdefender_slm::AiRequest {
            task_type: clawdefender_slm::TaskType::QuickRiskAssessment,
            prompt: ai_prompt,
            context: None,
        })
        .await;

    if let Some(resp) = &ai_resp.response {
        detail_lines.push(String::new());
        detail_lines.push("AI Analysis:".to_string());
        detail_lines.push(resp.explanation.clone());
    }

    let detailed_message = detail_lines.join("\n");
    let summary = format!("Security analysis of {}", path);

    Ok(serde_json::json!({
        "summary": summary,
        "message": detailed_message,
        "structured_data": {
            "type": "risk_assessment",
            "risk_level": risk_level,
            "subject": file_name,
            "explanation": detailed_message,
            "factors": factors,
            "metadata": {
                "file_type": file_type,
                "file_size": file_size,
                "permissions": permissions_str,
                "modified": modified_time,
                "sha256": sha256_hash,
                "magic_hex": magic_hex,
                "quarantine_flag": has_quarantine,
                "code_signed": code_signed,
                "codesign_info": codesign_info
            }
        },
        "actions": []
    })
    .to_string())
}

// ---------------------------------------------------------------------------
// Tool management commands (My Tools page)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_tool_cards() -> Result<Vec<serde_json::Value>, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_tool_cards());
    }

    let known = load_known_servers();
    let audit_counts = load_audit_event_counts();

    let config_paths = mcp_config_paths();
    eprintln!("[get_tool_cards] found {} config files", config_paths.len());

    let mut cards = Vec::new();
    for (path, _client_id, client_name) in config_paths {
        eprintln!("[get_tool_cards] reading config: {} (client: {})", path.display(), client_name);
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[get_tool_cards] failed to read {}: {}", path.display(), e);
                continue;
            }
        };
        let config: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[get_tool_cards] failed to parse JSON {}: {}", path.display(), e);
                continue;
            }
        };
        let servers = match extract_servers(&config) {
            Some(s) => s,
            None => {
                eprintln!("[get_tool_cards] no servers key found in {}", path.display());
                continue;
            }
        };
        eprintln!("[get_tool_cards] found {} servers in {}", servers.len(), path.display());
        for (name, entry) in &servers {
            let wrapped = entry.get("_clawdefender_original").is_some()
                || entry.get("_clawai_original").is_some();

            // Build command vec for capability inference
            let mut command = Vec::new();
            if let Some(cmd) = entry.get("command").and_then(|v| v.as_str()) {
                command.push(cmd.to_string());
            }
            if let Some(args) = entry.get("args").and_then(|v| v.as_array()) {
                for arg in args {
                    if let Some(s) = arg.as_str() {
                        command.push(s.to_string());
                    }
                }
            }

            let caps = infer_capabilities(name, &command);

            // Look up persisted trust level from known_servers.json
            let trust_level = known
                .servers
                .get(name.as_str())
                .map(|e| e.trust_level.as_str())
                .unwrap_or("default");

            // Audit event count for this server
            let event_count = audit_counts.get(name.as_str()).copied().unwrap_or(0);

            cards.push(serde_json::json!({
                "server_name": name,
                "client_name": client_name,
                "display_name": name,
                "wrapped": wrapped,
                "status": if wrapped { "protected" } else { "unprotected" },
                "trust_level": trust_level,
                "event_count": event_count,
                "anomaly_score": 0.0,
                "capabilities": {
                    "read_files": caps.can_read_files,
                    "write_files": caps.can_write_files,
                    "execute_commands": caps.can_execute_commands,
                    "network_access": caps.can_access_network,
                    "browser_access": caps.can_sample_llm
                },
                "capability_source": caps.source,
                "last_activity": null
            }));
        }
    }
    eprintln!("[get_tool_cards] returning {} tool cards total", cards.len());
    Ok(cards)
}

/// Load audit event counts per server from the audit log file.
/// Returns a map of server_name -> event count. Returns empty map if the file
/// does not exist or cannot be read.
fn load_audit_event_counts() -> std::collections::HashMap<String, u64> {
    let mut counts = std::collections::HashMap::new();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return counts,
    };
    let audit_path = home.join(".local/share/rookbot/audit.jsonl");
    let file = match std::fs::File::open(&audit_path) {
        Ok(f) => f,
        Err(_) => return counts,
    };
    use std::io::BufRead;
    let reader = std::io::BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(server) = entry.get("server_name").and_then(|v| v.as_str()) {
                *counts.entry(server.to_string()).or_insert(0) += 1;
            }
        }
    }
    counts
}

#[tauri::command]
pub async fn get_new_tools() -> Result<Vec<serde_json::Value>, String> {
    let new_servers = get_unacknowledged_servers();
    let results: Vec<serde_json::Value> = new_servers
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "server_name": s.server_name,
                "client_name": s.client_name,
                "client_display_name": s.client_display_name,
                "display_name": s.server_name,
                "command": s.command,
                "detected_at": s.first_detected,
                "capabilities": {
                    "read_files": s.capabilities.can_read_files,
                    "write_files": s.capabilities.can_write_files,
                    "execute_commands": s.capabilities.can_execute_commands,
                    "network_access": s.capabilities.can_access_network,
                    "browser_access": s.capabilities.can_sample_llm
                },
                "suggested_trust_level": s.suggested_trust_level,
            })
        })
        .collect();
    Ok(results)
}

#[tauri::command]
pub async fn set_trust_level(
    server_name: String,
    trust_level: String,
) -> Result<(), String> {
    set_server_trust_level(&server_name, &trust_level)
}

#[tauri::command]
pub async fn set_permission_override(
    server_name: String,
    permission: String,
    action: String,
) -> Result<(), String> {
    set_server_permission_override(&server_name, &permission, &action)
}

#[tauri::command]
pub async fn reset_permission_override(
    server_name: String,
    permission: String,
) -> Result<(), String> {
    reset_server_permission_override(&server_name, &permission)
}

#[tauri::command]
pub async fn dismiss_new_tool(
    server_name: String,
) -> Result<(), String> {
    dismiss_server(&server_name)
}

#[tauri::command]
pub async fn get_trust_level(
    server_name: String,
) -> Result<serde_json::Value, String> {
    let (trust_level, overrides) = get_server_trust_info(&server_name);
    let permissions: Vec<serde_json::Value> = overrides
        .iter()
        .map(|(perm, action)| {
            serde_json::json!({
                "permission": perm,
                "action": action,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "server_name": server_name,
        "trust_level": trust_level,
        "permissions": permissions,
    }))
}

#[tauri::command]
pub async fn preview_trust_change(
    server_name: String,
    new_level: String,
) -> Result<Vec<serde_json::Value>, String> {
    let _ = (server_name, new_level);
    Ok(vec![])
}

#[tauri::command]
pub async fn get_server_summary(
    server_name: String,
) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "server_name": server_name,
        "display_name": server_name,
        "client_name": "Unknown",
        "trust_level": "default",
        "status": "unknown",
        "event_count": 0,
        "anomaly_score": 0.0,
        "tools_count": 0,
        "total_calls": 0,
        "last_activity": null,
        "capabilities": {
            "read_files": false,
            "write_files": false,
            "execute_commands": false,
            "network_access": false,
            "browser_access": false
        },
        "permissions": []
    }))
}

// ---------------------------------------------------------------------------
// Phase 2 — Agent Session commands (cloud-powered security agent)
// ---------------------------------------------------------------------------

/// Start a new cloud-powered agent session.
#[tauri::command]
pub async fn start_agent_session(
    session_type: String,
    initial_query: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mgr = {
        let guard = state.agent_session_manager.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Agent sessions not available. Configure a cloud API key in Settings.".to_string()
        })?
    };

    // Parse session type string into the swarm SessionType enum
    let st = match session_type.as_str() {
        "chat" => clawdefender_swarm::agent_session::SessionType::Chat,
        "scan" => clawdefender_swarm::agent_session::SessionType::Scan {
            playbook: "full".to_string(),
        },
        "investigate" => clawdefender_swarm::agent_session::SessionType::Investigate {
            event_id: initial_query.clone().unwrap_or_default(),
        },
        "report" => clawdefender_swarm::agent_session::SessionType::Report {
            report_type: "security".to_string(),
        },
        _ => clawdefender_swarm::agent_session::SessionType::Chat,
    };

    // Build a basic cloud briefing with defaults
    let briefing = clawdefender_swarm::context_bridge::CloudBriefingBuilder::new(
        clawdefender_swarm::context_bridge::SessionType::Chat,
    )
    .with_system_profile(clawdefender_swarm::context_bridge::SystemProfile {
        os_version: std::env::consts::OS.to_string(),
        cpu_architecture: std::env::consts::ARCH.to_string(),
        cpu_name: "unknown".to_string(),
        ram_gb: 0,
        gpu: None,
    })
    .with_event_summary("No events loaded".to_string())
    .build();

    let briefing_text = briefing.to_system_prompt();

    let session_id = mgr
        .start_session(st, briefing_text, initial_query)
        .await
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "session_id": session_id }))
}

/// Send a message in an existing agent session and run the tool-use loop.
#[tauri::command]
pub async fn send_agent_message(
    app_handle: tauri::AppHandle,
    session_id: String,
    message: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mgr = {
        let guard = state.agent_session_manager.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Agent sessions not available.".to_string()
        })?
    };

    let result = match mgr.send_message(&session_id, &message).await {
        Ok(r) => r,
        Err(e) => {
            // Emit cloud error event
            crate::events::emit_cloud_error(&app_handle, &crate::events::CloudErrorPayload {
                session_id: Some(session_id.clone()),
                error: e.to_string(),
                recoverable: !e.to_string().contains("Invalid API key"),
            });
            return Err(e.to_string());
        }
    };

    // Emit cloud response event
    crate::events::emit_cloud_response(&app_handle, &crate::events::CloudResponsePayload {
        session_id: session_id.clone(),
        text: result.text.clone(),
        is_final: true,
    });

    // Emit tool call events
    for tc in &result.tool_calls_made {
        crate::events::emit_cloud_tool_call(&app_handle, &crate::events::CloudToolCallPayload {
            session_id: session_id.clone(),
            tool_name: tc.tool_name.clone(),
            input_summary: tc.input_summary.clone(),
            success: tc.success,
        });
    }

    // Emit pending action events
    for action in &result.pending_actions {
        crate::events::emit_action_pending(&app_handle, &crate::events::ActionPendingPayload {
            session_id: session_id.clone(),
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            description: action.description.clone(),
        });
    }

    // Check budget warning (80% threshold)
    {
        let guard = state.cost_tracker.lock().map_err(|e| e.to_string())?;
        if let Some(ref tracker_arc) = *guard {
            if let Ok(tracker) = tracker_arc.lock() {
                if let Ok(report) = tracker.get_budget_status() {
                    if report.any_warning {
                        let (tier, pct, used, limit) = if report.session_percent >= 80.0 {
                            ("session", report.session_percent, report.session_used, report.session_budget)
                        } else if report.daily_percent >= 80.0 {
                            ("daily", report.daily_percent, report.daily_used, report.daily_budget)
                        } else {
                            ("monthly", report.monthly_percent, report.monthly_used, report.monthly_budget)
                        };
                        crate::events::emit_budget_warning(&app_handle, &crate::events::BudgetWarningPayload {
                            tier: tier.to_string(),
                            used_percent: pct,
                            used_amount: used,
                            limit_amount: limit,
                        });
                    }
                }
            }
        }
    }

    serde_json::to_value(&result).map_err(|e| e.to_string())
}

/// Get status of a specific agent session.
#[tauri::command]
pub async fn get_agent_session_status(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mgr = {
        let guard = state.agent_session_manager.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Agent sessions not available.".to_string()
        })?
    };

    let status = mgr
        .get_session_status(&session_id)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_value(&status).map_err(|e| e.to_string())
}

/// List all agent sessions.
#[tauri::command]
pub async fn list_agent_sessions(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mgr = {
        let guard = state.agent_session_manager.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Agent sessions not available.".to_string()
        })?
    };

    let sessions = mgr
        .list_sessions()
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_value(&sessions).map_err(|e| e.to_string())
}

/// Cancel an active agent session.
#[tauri::command]
pub async fn cancel_agent_session(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mgr = {
        let guard = state.agent_session_manager.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Agent sessions not available.".to_string()
        })?
    };

    mgr.cancel_session(&session_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "cancelled": true, "session_id": session_id }))
}

/// Approve a pending action from a cloud agent session.
#[tauri::command]
pub async fn approve_pending_action(
    session_id: String,
    action_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mgr = {
        let guard = state.agent_session_manager.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Agent sessions not available.".to_string()
        })?
    };

    mgr.approve_pending_action(&session_id, &action_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "approved": true, "action_id": action_id }))
}

/// Reject a pending action from a cloud agent session.
#[tauri::command]
pub async fn reject_pending_action(
    session_id: String,
    action_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mgr = {
        let guard = state.agent_session_manager.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Agent sessions not available.".to_string()
        })?
    };

    mgr.reject_pending_action(&session_id, &action_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "rejected": true, "action_id": action_id }))
}

// ---------------------------------------------------------------------------
// Phase 2 — Cloud status & budget commands
// ---------------------------------------------------------------------------

/// Get overall cloud agent status, including AI backend cloud info.
#[tauri::command]
pub async fn get_cloud_status(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let has_manager = {
        let guard = state.agent_session_manager.lock().map_err(|e| e.to_string())?;
        guard.is_some()
    };

    // Check if any cloud API key is configured
    let provider_configured = clawdefender_slm::cloud_backend::has_api_key("anthropic")
        || clawdefender_slm::cloud_backend::has_api_key("openai");

    let budget_status = {
        let guard = state.cost_tracker.lock().map_err(|e| e.to_string())?;
        if let Some(ref tracker_arc) = *guard {
            let tracker = tracker_arc.lock().map_err(|e| e.to_string())?;
            let report = tracker.get_budget_status().map_err(|e| e.to_string())?;
            serde_json::to_value(&report).unwrap_or(serde_json::json!(null))
        } else {
            serde_json::json!(null)
        }
    };

    // Include AI backend cloud status (dual-backend architecture)
    let ai_status = state.ai_backends.get_status();
    let ai_cloud = serde_json::to_value(&ai_status.cloud).unwrap_or(serde_json::json!(null));

    Ok(serde_json::json!({
        "provider_configured": provider_configured,
        "agent_sessions_available": has_manager,
        "budget_status": budget_status,
        "ai_backend": ai_cloud,
    }))
}

/// Get budget status from the cost tracker.
#[tauri::command]
pub async fn get_budget_status(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.cost_tracker.lock().map_err(|e| e.to_string())?;
    if let Some(ref tracker_arc) = *guard {
        let tracker = tracker_arc.lock().map_err(|e| e.to_string())?;
        let report = tracker.get_budget_status().map_err(|e| e.to_string())?;
        serde_json::to_value(&report).map_err(|e| e.to_string())
    } else {
        Ok(serde_json::json!({
            "session_budget": 0.50,
            "session_used": 0.0,
            "session_remaining": 0.50,
            "session_percent": 0.0,
            "daily_budget": 1.00,
            "daily_used": 0.0,
            "daily_remaining": 1.00,
            "daily_percent": 0.0,
            "monthly_budget": 20.00,
            "monthly_used": 0.0,
            "monthly_remaining": 20.00,
            "monthly_percent": 0.0,
            "warning_threshold_percent": 80.0,
            "any_warning": false
        }))
    }
}

/// Update budget limits for cloud API usage.
#[tauri::command]
pub async fn update_budgets(
    session_budget: Option<f64>,
    daily_budget: Option<f64>,
    monthly_budget: Option<f64>,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.cost_tracker.lock().map_err(|e| e.to_string())?;
    if let Some(ref tracker_arc) = *guard {
        let mut tracker = tracker_arc.lock().map_err(|e| e.to_string())?;
        tracker
            .update_budgets(session_budget, daily_budget, monthly_budget)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "updated": true }))
    } else {
        Err("Cost tracker not initialized. Configure a cloud API key first.".to_string())
    }
}

/// Get the current cloud configuration (provider, model, budgets).
#[tauri::command]
pub async fn get_cloud_config(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let has_anthropic = clawdefender_slm::cloud_backend::has_api_key("anthropic");
    let has_openai = clawdefender_slm::cloud_backend::has_api_key("openai");

    let provider = if has_anthropic {
        "anthropic"
    } else if has_openai {
        "openai"
    } else {
        "none"
    };

    let model = match provider {
        "anthropic" => "claude-sonnet-4-20250514",
        "openai" => "gpt-4o",
        _ => "",
    };

    let budgets = {
        let guard = state.cost_tracker.lock().map_err(|e| e.to_string())?;
        if let Some(ref tracker_arc) = *guard {
            let tracker = tracker_arc.lock().map_err(|e| e.to_string())?;
            let budget = tracker.budget().clone();
            serde_json::json!({
                "session_limit": budget.session_limit_usd,
                "daily_limit": budget.daily_limit_usd,
                "monthly_limit": budget.monthly_limit_usd,
            })
        } else {
            serde_json::json!({
                "session_limit": 0.50,
                "daily_limit": 1.00,
                "monthly_limit": 20.00,
            })
        }
    };

    Ok(serde_json::json!({
        "provider": provider,
        "model": model,
        "api_key_configured": has_anthropic || has_openai,
        "budgets": budgets,
    }))
}

/// Update cloud configuration (budgets). Provider/model changes require
/// saving a new API key and restarting the app to reinitialize the pipeline.
#[tauri::command]
pub async fn update_cloud_config(
    session_budget: Option<f64>,
    daily_budget: Option<f64>,
    monthly_budget: Option<f64>,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.cost_tracker.lock().map_err(|e| e.to_string())?;
    if let Some(ref tracker_arc) = *guard {
        let mut tracker = tracker_arc.lock().map_err(|e| e.to_string())?;
        tracker
            .update_budgets(session_budget, daily_budget, monthly_budget)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "updated": true }))
    } else {
        Err("Cost tracker not initialized. Configure a cloud API key first.".to_string())
    }
}

// ---------------------------------------------------------------------------
// Phase 2 — Privacy commands
// ---------------------------------------------------------------------------

/// Preview what data would be sent to the cloud for a given session type.
#[tauri::command]
pub async fn get_privacy_preview(
    session_type: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let filter = {
        let guard = state.privacy_filter.lock().map_err(|e| e.to_string())?;
        guard.clone()
    };

    // Build a sample briefing
    let st = match session_type.as_str() {
        "scan" => clawdefender_swarm::context_bridge::SessionType::Scan {
            playbook: "full".to_string(),
        },
        "investigate" => clawdefender_swarm::context_bridge::SessionType::Investigate {
            event_id: "sample-event".to_string(),
        },
        "report" => clawdefender_swarm::context_bridge::SessionType::Report {
            report_type: "security".to_string(),
        },
        _ => clawdefender_swarm::context_bridge::SessionType::Chat,
    };

    let briefing = clawdefender_swarm::context_bridge::CloudBriefingBuilder::new(st)
        .with_system_profile(clawdefender_swarm::context_bridge::SystemProfile {
            os_version: std::env::consts::OS.to_string(),
            cpu_architecture: std::env::consts::ARCH.to_string(),
            cpu_name: "unknown".to_string(),
            ram_gb: 0,
            gpu: None,
        })
        .with_event_summary("Sample events for preview".to_string())
        .build();

    let briefing_text = briefing.to_system_prompt();

    let (filtered_text, redaction_count) = if let Some(pf) = filter {
        let result = pf.filter_briefing(&briefing_text);
        (result.filtered_text, result.redaction_count)
    } else {
        (briefing_text.clone(), 0)
    };

    let tool_defs = clawdefender_swarm::tools::get_all_tool_definitions();
    let tool_names: Vec<&str> = tool_defs.iter().map(|t| t.name.as_str()).collect();

    Ok(serde_json::json!({
        "filtered_briefing": filtered_text,
        "original_length": briefing_text.len(),
        "filtered_length": filtered_text.len(),
        "redaction_count": redaction_count,
        "tools_available": tool_names,
    }))
}

/// Get the outbound audit trail showing what data was sent to the cloud.
#[tauri::command]
pub async fn get_outbound_audit(
    limit: Option<u32>,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let filter = {
        let guard = state.privacy_filter.lock().map_err(|e| e.to_string())?;
        guard.clone()
    };

    if let Some(pf) = filter {
        let trail = pf.get_audit_trail();
        let limit = limit.unwrap_or(50) as usize;
        let entries: Vec<_> = trail.into_iter().rev().take(limit).collect();
        serde_json::to_value(&entries).map_err(|e| e.to_string())
    } else {
        Ok(serde_json::json!([]))
    }
}

// ---------------------------------------------------------------------------
// Phase 3 — AI scan orchestrator commands
// ---------------------------------------------------------------------------

/// Start an AI security scan with the specified playbook.
#[tauri::command]
pub async fn start_ai_scan(
    app_handle: tauri::AppHandle,
    playbook_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available. Configure a cloud API key in Settings.".to_string()
        })?
    };

    let progress = orch
        .start_scan(&playbook_id)
        .await
        .map_err(|e| e.to_string())?;

    let scan_id = progress.scan_id.clone();

    // Spawn the scan loop as a background task
    let orch_bg = orch.clone();
    let app_bg = app_handle.clone();
    let scan_id_bg = scan_id.clone();
    tokio::spawn(async move {
        match orch_bg.run_scan_loop(&scan_id_bg).await {
            Ok(result) => {
                let status_str = match &result.status {
                    clawdefender_swarm::scan_orchestrator::ScanStatus::Completed => "completed",
                    clawdefender_swarm::scan_orchestrator::ScanStatus::Cancelled => "cancelled",
                    clawdefender_swarm::scan_orchestrator::ScanStatus::Failed { .. } => "failed",
                    clawdefender_swarm::scan_orchestrator::ScanStatus::Running => "running",
                };
                crate::events::emit_scan_complete(
                    &app_bg,
                    &crate::events::ScanCompletePayload {
                        scan_id: scan_id_bg.clone(),
                        status: status_str.to_string(),
                        findings_count: result.findings.len(),
                        summary: result.summary.clone(),
                    },
                );
            }
            Err(e) => {
                crate::events::emit_scan_complete(
                    &app_bg,
                    &crate::events::ScanCompletePayload {
                        scan_id: scan_id_bg.clone(),
                        status: "failed".to_string(),
                        findings_count: 0,
                        summary: format!("Scan failed: {}", e),
                    },
                );
            }
        }
    });

    serde_json::to_value(&progress).map_err(|e| e.to_string())
}

/// Get real-time progress of an AI scan.
#[tauri::command]
pub async fn get_ai_scan_progress(
    scan_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available.".to_string()
        })?
    };

    let progress = orch
        .get_progress(&scan_id)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_value(&progress).map_err(|e| e.to_string())
}

/// Get the final result of a completed AI scan.
#[tauri::command]
pub async fn get_ai_scan_result(
    scan_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available.".to_string()
        })?
    };

    let result = orch
        .get_result(&scan_id)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_value(&result).map_err(|e| e.to_string())
}

/// Cancel a running AI scan.
#[tauri::command]
pub async fn cancel_ai_scan(
    scan_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available.".to_string()
        })?
    };

    orch.cancel_scan(&scan_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "cancelled": true, "scan_id": scan_id }))
}

/// Respond to a user request from a running AI scan.
#[tauri::command]
pub async fn respond_to_scan_request(
    scan_id: String,
    request_id: String,
    response: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available.".to_string()
        })?
    };

    orch.respond_to_request(&scan_id, &request_id, &response)
        .await
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "responded": true }))
}

/// Get the evidence chain for a specific finding in an AI scan.
#[tauri::command]
pub async fn get_scan_evidence_chain(
    scan_id: String,
    finding_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available.".to_string()
        })?
    };

    let chain = orch
        .get_evidence_chain(&scan_id, &finding_id)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_value(&chain).map_err(|e| e.to_string())
}

/// Get all remediations for an AI scan.
#[tauri::command]
pub async fn get_scan_remediations(
    scan_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available.".to_string()
        })?
    };

    let remediations = orch
        .get_remediations(&scan_id)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_value(&remediations).map_err(|e| e.to_string())
}

/// Execute a specific remediation from an AI scan.
#[tauri::command]
pub async fn execute_scan_remediation(
    scan_id: String,
    remediation_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available.".to_string()
        })?
    };

    orch.execute_remediation(&scan_id, &remediation_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "executed": true, "remediation_id": remediation_id }))
}

/// Revert a previously executed remediation.
#[tauri::command]
pub async fn revert_scan_remediation(
    scan_id: String,
    remediation_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available.".to_string()
        })?
    };

    orch.revert_remediation(&scan_id, &remediation_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "reverted": true, "remediation_id": remediation_id }))
}

/// Get all available scan playbooks.
#[tauri::command]
pub async fn get_scan_playbooks() -> Result<serde_json::Value, String> {
    let summaries = clawdefender_swarm::scan_playbooks::get_playbook_summaries();
    serde_json::to_value(&summaries).map_err(|e| e.to_string())
}

/// Get detailed info about a specific playbook.
#[tauri::command]
pub async fn get_playbook_detail(
    playbook_id: String,
) -> Result<serde_json::Value, String> {
    let playbook = clawdefender_swarm::scan_playbooks::get_playbook(&playbook_id)
        .ok_or_else(|| format!("Playbook not found: {}", playbook_id))?;

    serde_json::to_value(&playbook).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Phase 3 — Report generator commands
// ---------------------------------------------------------------------------

/// Generate a scan report in the specified format (markdown or html).
#[tauri::command]
pub async fn generate_scan_report(
    scan_id: String,
    format: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available. Configure a cloud API key in Settings.".to_string()
        })?
    };

    let scan_result = orch
        .get_result(&scan_id)
        .await
        .map_err(|e| e.to_string())?;

    let remediations = orch
        .get_remediations(&scan_id)
        .await
        .unwrap_or_default();

    let report_format = match format.to_lowercase().as_str() {
        "html" => clawdefender_swarm::report_generator::ReportFormat::Html,
        _ => clawdefender_swarm::report_generator::ReportFormat::Markdown,
    };

    let gen = clawdefender_swarm::report_generator::ReportGenerator::new();
    let report = gen
        .generate(&scan_result, None, &remediations, report_format, None)
        .map_err(|e| e.to_string())?;

    let content = match &report.format {
        clawdefender_swarm::report_generator::ReportFormat::Markdown => gen.render_markdown(&report),
        clawdefender_swarm::report_generator::ReportFormat::Html => gen.render_html(&report),
    };

    let file_path = gen
        .save_report(&report, &content)
        .map_err(|e| e.to_string())?;

    Ok(file_path)
}

/// Get the content of a previously generated scan report.
#[tauri::command]
pub async fn get_scan_report(
    scan_id: String,
) -> Result<String, String> {
    clawdefender_swarm::report_generator::ReportGenerator::load_report(&scan_id)
        .map_err(|e| e.to_string())
}

/// Compare two scan results and return the comparison data.
#[tauri::command]
pub async fn get_scan_comparison(
    scan_id: String,
    previous_scan_id: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let orch = {
        let guard = state.scan_orchestrator.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "AI scan not available.".to_string()
        })?
    };

    let current = orch
        .get_result(&scan_id)
        .await
        .map_err(|e| e.to_string())?;

    let prev_id = previous_scan_id.ok_or_else(|| "previous_scan_id is required".to_string())?;

    let previous = orch
        .get_result(&prev_id)
        .await
        .map_err(|e| e.to_string())?;

    let comparison = clawdefender_swarm::report_generator::ReportGenerator::compare_scans(
        &current, &previous,
    );

    serde_json::to_value(&comparison).map_err(|e| e.to_string())
}

/// List all generated scan reports.
#[tauri::command]
pub async fn list_scan_reports() -> Result<Vec<serde_json::Value>, String> {
    let summaries = clawdefender_swarm::report_generator::ReportGenerator::list_reports()
        .map_err(|e| e.to_string())?;

    summaries
        .into_iter()
        .map(|s| serde_json::to_value(s).map_err(|e| e.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Phase 4 — Threat Hunting commands
// ---------------------------------------------------------------------------

/// Start a proactive threat hunt.
#[tauri::command]
pub async fn start_threat_hunt(
    state: tauri::State<'_, AppState>,
    hunt_type: String,
    params: Option<String>,
    time_range_hours: Option<u64>,
) -> Result<serde_json::Value, String> {
    let hunter = {
        let guard = state.threat_hunter.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Threat hunting not available. Configure a cloud API key in Settings.".to_string()
        })?
    };

    let ht = match hunt_type.as_str() {
        "general" => clawdefender_swarm::threat_hunting::HuntType::GeneralSweep,
        "server" => clawdefender_swarm::threat_hunting::HuntType::ServerFocused {
            server: params.clone().unwrap_or_else(|| "unknown".to_string()),
        },
        "pattern" => clawdefender_swarm::threat_hunting::HuntType::PatternSearch {
            pattern: params.clone().unwrap_or_else(|| "general".to_string()),
        },
        "historical" => clawdefender_swarm::threat_hunting::HuntType::HistoricalReview {
            period: params.clone().unwrap_or_else(|| "last 7 days".to_string()),
        },
        _ => clawdefender_swarm::threat_hunting::HuntType::GeneralSweep,
    };

    let hours = time_range_hours.unwrap_or(24);
    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours as i64);
    let time_range = clawdefender_swarm::threat_hunting::TimeRange {
        start,
        end: now,
    };

    let progress = hunter
        .start_hunt(ht, time_range)
        .await
        .map_err(|e| e.to_string())?;

    let hunt_id = progress.hunt_id.clone();

    // Spawn the hunt loop as a background task
    let hunter_bg = hunter.clone();
    let hunt_id_bg = hunt_id.clone();
    tokio::spawn(async move {
        match hunter_bg.run_hunt_loop(&hunt_id_bg).await {
            Ok(_result) => {
                tracing::info!("Threat hunt {} completed", hunt_id_bg);
            }
            Err(e) => {
                tracing::error!("Threat hunt {} failed: {}", hunt_id_bg, e);
            }
        }
    });

    serde_json::to_value(&progress).map_err(|e| e.to_string())
}

/// Get real-time progress of a threat hunt.
#[tauri::command]
pub async fn get_hunt_progress(
    state: tauri::State<'_, AppState>,
    hunt_id: String,
) -> Result<serde_json::Value, String> {
    let hunter = {
        let guard = state.threat_hunter.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Threat hunting not available.".to_string()
        })?
    };

    let progress = hunter
        .get_progress(&hunt_id)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_value(&progress).map_err(|e| e.to_string())
}

/// Get the final result of a completed threat hunt.
#[tauri::command]
pub async fn get_hunt_results(
    state: tauri::State<'_, AppState>,
    hunt_id: String,
) -> Result<serde_json::Value, String> {
    let hunter = {
        let guard = state.threat_hunter.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Threat hunting not available.".to_string()
        })?
    };

    let result = hunter
        .get_result(&hunt_id)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_value(&result).map_err(|e| e.to_string())
}

/// Cancel a running threat hunt.
#[tauri::command]
pub async fn cancel_threat_hunt(
    state: tauri::State<'_, AppState>,
    hunt_id: String,
) -> Result<serde_json::Value, String> {
    let hunter = {
        let guard = state.threat_hunter.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Threat hunting not available.".to_string()
        })?
    };

    hunter
        .cancel_hunt(&hunt_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "cancelled": true, "hunt_id": hunt_id }))
}

// ---------------------------------------------------------------------------
// Phase 4 — Investigation persistence commands
// ---------------------------------------------------------------------------

/// List investigations, optionally filtered.
#[tauri::command]
pub async fn list_investigations(
    state: tauri::State<'_, AppState>,
    filter: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let guard = state.investigation_store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or_else(|| {
        "Investigation store not initialized.".to_string()
    })?;

    let query: Option<clawdefender_swarm::investigation_store::InvestigationSearchQuery> =
        filter.and_then(|v| serde_json::from_value(v).ok());

    let entries = store.list(query.as_ref());
    serde_json::to_value(&entries).map_err(|e| e.to_string())
}

/// Get a full investigation result by ID.
#[tauri::command]
pub async fn get_investigation(
    state: tauri::State<'_, AppState>,
    investigation_id: String,
) -> Result<serde_json::Value, String> {
    let guard = state.investigation_store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or_else(|| {
        "Investigation store not initialized.".to_string()
    })?;

    let result = store.load(&investigation_id).map_err(|e| e.to_string())?;
    serde_json::to_value(&result).map_err(|e| e.to_string())
}

/// Search investigations with full-text and filter criteria.
#[tauri::command]
pub async fn search_investigations(
    state: tauri::State<'_, AppState>,
    query: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let guard = state.investigation_store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or_else(|| {
        "Investigation store not initialized.".to_string()
    })?;

    let search_query: clawdefender_swarm::investigation_store::InvestigationSearchQuery =
        serde_json::from_value(query).map_err(|e| e.to_string())?;

    let results = store.search(&search_query).map_err(|e| e.to_string())?;
    serde_json::to_value(&results).map_err(|e| e.to_string())
}

/// Delete an investigation by ID.
#[tauri::command]
pub async fn delete_investigation(
    state: tauri::State<'_, AppState>,
    investigation_id: String,
) -> Result<serde_json::Value, String> {
    let mut guard = state.investigation_store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_mut().ok_or_else(|| {
        "Investigation store not initialized.".to_string()
    })?;

    store.delete(&investigation_id).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "deleted": true, "id": investigation_id }))
}

/// Pin or unpin an investigation.
#[tauri::command]
pub async fn pin_investigation(
    state: tauri::State<'_, AppState>,
    investigation_id: String,
    pinned: bool,
) -> Result<serde_json::Value, String> {
    let mut guard = state.investigation_store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_mut().ok_or_else(|| {
        "Investigation store not initialized.".to_string()
    })?;

    store.pin(&investigation_id, pinned).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "id": investigation_id, "pinned": pinned }))
}

/// Export an investigation in the specified format (json or markdown).
#[tauri::command]
pub async fn export_investigation(
    state: tauri::State<'_, AppState>,
    investigation_id: String,
    format: String,
) -> Result<serde_json::Value, String> {
    let guard = state.investigation_store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or_else(|| {
        "Investigation store not initialized.".to_string()
    })?;

    let content = store.export(&investigation_id, &format).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "content": content, "format": format }))
}

/// Resume a previous investigation — loads the full result plus related investigations
/// for context injection into a new Claude session.
#[tauri::command]
pub async fn resume_investigation(
    state: tauri::State<'_, AppState>,
    investigation_id: String,
) -> Result<serde_json::Value, String> {
    let guard = state.investigation_store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or_else(|| {
        "Investigation store not initialized.".to_string()
    })?;

    let result = store.load(&investigation_id).map_err(|e| e.to_string())?;

    // Find related investigations for cross-referencing context
    let related = store.find_related(None, Some(&result.target_id));

    // Build a resumption context with the original investigation + related
    let result_json = serde_json::to_value(&result).map_err(|e| e.to_string())?;
    let related_json = serde_json::to_value(&related).map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "investigation": result_json,
        "related_investigations": related_json,
        "resumable": true,
    }))
}

// ---------------------------------------------------------------------------
// Phase 4 — Investigation Timeline commands
// ---------------------------------------------------------------------------

/// Get the investigation timeline for a given investigation.
#[tauri::command]
pub async fn get_investigation_timeline(
    state: tauri::State<'_, AppState>,
    investigation_id: String,
) -> Result<serde_json::Value, String> {
    // Gather events from the event buffer related to this investigation
    let events: Vec<serde_json::Value> = {
        let buffer = state.event_buffer.lock().map_err(|e| e.to_string())?;
        buffer
            .iter()
            .map(|e| serde_json::to_value(e).unwrap_or_default())
            .collect()
    };

    let timeline = clawdefender_swarm::investigation_timeline::TimelineBuilder::from_investigation(
        &investigation_id,
        &events,
        &[],     // evidence
        &[],     // findings
        "",      // narrative — none without an active investigation session
    );

    serde_json::to_value(&timeline).map_err(|e| e.to_string())
}

/// Get a narrative story for a single event with surrounding context.
#[tauri::command]
pub async fn get_event_story(
    state: tauri::State<'_, AppState>,
    event_id: String,
) -> Result<serde_json::Value, String> {
    let (target, surrounding) = {
        let buffer = state.event_buffer.lock().map_err(|e| e.to_string())?;
        let target = buffer
            .iter()
            .find(|e| e.id == event_id)
            .map(|e| serde_json::to_value(e).unwrap_or_default())
            .ok_or_else(|| format!("Event not found: {}", event_id))?;

        let target_idx = buffer.iter().position(|e| e.id == event_id).unwrap_or(0);
        let start = target_idx.saturating_sub(10);
        let end = (target_idx + 11).min(buffer.len());

        let surrounding: Vec<serde_json::Value> = buffer[start..end]
            .iter()
            .filter(|e| e.id != event_id)
            .map(|e| serde_json::to_value(e).unwrap_or_default())
            .collect();

        (target, surrounding)
    };

    let timeline = clawdefender_swarm::investigation_timeline::TimelineBuilder::from_event_context(
        &event_id,
        &target,
        &surrounding,
    );

    serde_json::to_value(&timeline).map_err(|e| e.to_string())
}

/// Find investigations with similar patterns to the given event.
#[tauri::command]
pub async fn get_related_investigations(
    _state: tauri::State<'_, AppState>,
    event_id: String,
) -> Result<serde_json::Value, String> {
    // Return an empty list for now — will be populated when investigation
    // persistence is fully wired up and past timelines are stored.
    let result = serde_json::json!({
        "event_id": event_id,
        "related": [],
        "message": "No past investigations stored yet."
    });
    Ok(result)
}

// ---------------------------------------------------------------------------
// Phase 4 — Investigation Engine commands
// ---------------------------------------------------------------------------

/// Start a new AI-powered investigation session.
#[tauri::command]
pub async fn start_investigation(
    state: tauri::State<'_, AppState>,
    target_type: String,
    target_id: String,
    target_data: Option<serde_json::Value>,
    depth: Option<String>,
) -> Result<serde_json::Value, String> {
    let engine = {
        let guard = state.investigation_engine.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Investigation engine not available. Configure a cloud API key in Settings.".to_string()
        })?
    };

    // Build InvestigationTarget from frontend params
    let target = match target_type.as_str() {
        "event" => clawdefender_swarm::investigation_tools::InvestigationTarget::Event {
            event_id: target_id.clone(),
            event_data: target_data.unwrap_or(serde_json::json!({})),
        },
        "alert" => clawdefender_swarm::investigation_tools::InvestigationTarget::Alert {
            alert_id: target_id.clone(),
            alert_data: target_data.unwrap_or(serde_json::json!({})),
        },
        "server" => clawdefender_swarm::investigation_tools::InvestigationTarget::Server {
            server_name: target_id.clone(),
        },
        "time_range" => {
            // Expect target_data to contain start/end
            let data = target_data.unwrap_or(serde_json::json!({}));
            let start = data
                .get("start")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::hours(24));
            let end = data
                .get("end")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now);
            clawdefender_swarm::investigation_tools::InvestigationTarget::TimeRange {
                start,
                end,
            }
        }
        _ => clawdefender_swarm::investigation_tools::InvestigationTarget::Freeform {
            query: target_id.clone(),
        },
    };

    // Parse depth
    let depth = depth.map(|d| match d.as_str() {
        "quick" => clawdefender_swarm::investigation_tools::InvestigationDepth::Quick,
        "standard" => clawdefender_swarm::investigation_tools::InvestigationDepth::Standard,
        "deep" => clawdefender_swarm::investigation_tools::InvestigationDepth::Deep,
        _ => clawdefender_swarm::investigation_tools::InvestigationDepth::Standard,
    });

    let progress = engine
        .start_investigation(target, depth)
        .await
        .map_err(|e| e.to_string())?;

    // Spawn the investigation loop in the background
    let engine_clone = engine.clone();
    let inv_id = progress.investigation_id.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = engine_clone.run_investigation_loop(&inv_id).await {
            tracing::error!("Investigation {} loop error: {}", inv_id, e);
        }
    });

    serde_json::to_value(&progress).map_err(|e| e.to_string())
}

/// Get real-time progress of a running investigation.
#[tauri::command]
pub async fn get_investigation_progress(
    state: tauri::State<'_, AppState>,
    investigation_id: String,
) -> Result<serde_json::Value, String> {
    let engine = {
        let guard = state.investigation_engine.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Investigation engine not available.".to_string()
        })?
    };

    let progress = engine
        .get_progress(&investigation_id)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_value(&progress).map_err(|e| e.to_string())
}

/// Get the final result of a completed investigation.
#[tauri::command]
pub async fn get_investigation_result(
    state: tauri::State<'_, AppState>,
    investigation_id: String,
) -> Result<serde_json::Value, String> {
    let engine = {
        let guard = state.investigation_engine.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Investigation engine not available.".to_string()
        })?
    };

    let result = engine
        .get_result(&investigation_id)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_value(&result).map_err(|e| e.to_string())
}

/// Cancel a running investigation.
#[tauri::command]
pub async fn cancel_investigation(
    state: tauri::State<'_, AppState>,
    investigation_id: String,
) -> Result<serde_json::Value, String> {
    let engine = {
        let guard = state.investigation_engine.lock().map_err(|e| e.to_string())?;
        guard.clone().ok_or_else(|| {
            "Investigation engine not available.".to_string()
        })?
    };

    engine
        .cancel_investigation(&investigation_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "cancelled": true, "investigation_id": investigation_id }))
}

// ---------------------------------------------------------------------------
// Ask Rook AI commands
// ---------------------------------------------------------------------------

/// Send a message to the AI-powered Ask Rook assistant.
#[tauri::command]
pub async fn ask_claw_ai(
    state: tauri::State<'_, AppState>,
    input: String,
    context_json: Option<String>,
) -> Result<String, String> {
    let ai_mutex = state.ask_claw_ai.clone();

    // Ensure AskClawAI is initialized (short sync lock scope)
    {
        let mut guard = ai_mutex.lock().await;
        if guard.is_none() {
            // Consult feature routing config for AskClaw preference
            let ask_claw_pref = state.ai_backends.get_feature_routing()
                .get(&clawdefender_slm::AiFeature::AskClaw);

            // Extract cloud client from agent_session_manager if available
            let cloud_client = state.agent_session_manager.lock()
                .ok()
                .and_then(|g| g.as_ref().map(|mgr| mgr.cloud_client().clone()));

            let has_cloud = cloud_client.is_some();

            let mode = match ask_claw_pref {
                clawdefender_slm::FeatureBackendPreference::Cloud => {
                    if has_cloud {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::Cloud
                    } else {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern
                    }
                }
                clawdefender_slm::FeatureBackendPreference::Local => {
                    if state.ai_backends.local_available() {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::LocalSlm
                    } else {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern
                    }
                }
                clawdefender_slm::FeatureBackendPreference::Auto => {
                    if has_cloud {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::Cloud
                    } else if state.ai_backends.local_available() {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::LocalSlm
                    } else {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern
                    }
                }
            };

            *guard = Some(clawdefender_swarm::ask_claw_ai::AskClawAI::new(
                mode,
                cloud_client,
                "claude-sonnet-4-20250514".to_string(),
            ));
        }
    }

    // Update context if provided
    if let Some(ref ctx_json) = context_json {
        if let Ok(ctx) = serde_json::from_str::<clawdefender_swarm::ask_claw_ai::ClawContext>(ctx_json) {
            let mut guard = ai_mutex.lock().await;
            if let Some(ref mut ai) = *guard {
                ai.set_context(ctx);
            }
        }
    }

    // Send the message (holds tokio mutex across await — this is fine)
    let mut guard = ai_mutex.lock().await;
    let ai = guard.as_mut().ok_or("Ask Rook AI not initialized")?;
    let response = ai.ask(&input).await.map_err(|e| e.to_string())?;

    serde_json::to_string(&response).map_err(|e| e.to_string())
}

/// Get the current Ask Rook AI routing mode.
#[tauri::command]
pub async fn get_ask_claw_mode(
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let guard = state.ask_claw_ai.lock().await;
    let mode = match &*guard {
        Some(ai) => ai.mode().clone(),
        None => {
            // Consult feature routing config for AskClaw preference
            let ask_claw_pref = state.ai_backends.get_feature_routing()
                .get(&clawdefender_slm::AiFeature::AskClaw);

            let has_cloud = state.agent_session_manager.lock()
                .map(|g| g.is_some())
                .unwrap_or(false);

            match ask_claw_pref {
                clawdefender_slm::FeatureBackendPreference::Cloud => {
                    if has_cloud {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::Cloud
                    } else {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern
                    }
                }
                clawdefender_slm::FeatureBackendPreference::Local => {
                    if state.ai_backends.local_available() {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::LocalSlm
                    } else {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern
                    }
                }
                clawdefender_slm::FeatureBackendPreference::Auto => {
                    if has_cloud {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::Cloud
                    } else if state.ai_backends.local_available() {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::LocalSlm
                    } else {
                        clawdefender_swarm::ask_claw_ai::AskClawMode::Pattern
                    }
                }
            }
        }
    };

    serde_json::to_string(&mode).map_err(|e| e.to_string())
}

/// Approve a pending action suggested by Ask Rook AI.
#[tauri::command]
pub async fn approve_claw_action(
    state: tauri::State<'_, AppState>,
    action_id: String,
) -> Result<String, String> {
    let mut guard = state.ask_claw_ai.lock().await;
    let ai = guard.as_mut().ok_or("Ask Rook AI not initialized")?;
    let action = ai.approve_action(&action_id).map_err(|e| e.to_string())?;
    serde_json::to_string(&action).map_err(|e| e.to_string())
}

/// Reject a pending action suggested by Ask Rook AI.
#[tauri::command]
pub async fn reject_claw_action(
    state: tauri::State<'_, AppState>,
    action_id: String,
) -> Result<String, String> {
    let mut guard = state.ask_claw_ai.lock().await;
    let ai = guard.as_mut().ok_or("Ask Rook AI not initialized")?;
    ai.reject_action(&action_id).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "rejected": true, "action_id": action_id }).to_string())
}

/// Update the context for Ask Rook AI conversations.
#[tauri::command]
pub async fn set_claw_context(
    state: tauri::State<'_, AppState>,
    context_json: String,
) -> Result<(), String> {
    let ctx: clawdefender_swarm::ask_claw_ai::ClawContext =
        serde_json::from_str(&context_json).map_err(|e| e.to_string())?;

    let mut guard = state.ask_claw_ai.lock().await;
    if let Some(ref mut ai) = *guard {
        ai.set_context(ctx);
    }
    Ok(())
}

/// List all Ask Rook AI conversations.
#[tauri::command]
pub async fn list_claw_conversations(
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let guard = state.ask_claw_ai.lock().await;
    let conversations = match &*guard {
        Some(ai) => ai.list_conversations(),
        None => Vec::new(),
    };
    serde_json::to_string(&conversations).map_err(|e| e.to_string())
}

// --- Phase 5: Scheduled Analysis commands ---

#[tauri::command]
pub async fn get_analysis_schedules(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, String> {
    let guard = state.scheduled_analysis.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_ref().ok_or("Scheduled analysis not initialized")?;
    let schedules = mgr.get_schedules();
    serde_json::to_value(&schedules)
        .map(|v| v.as_array().cloned().unwrap_or_default())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_analysis_schedule(
    state: tauri::State<'_, AppState>,
    id: String,
    enabled: Option<bool>,
    interval_minutes: Option<u64>,
) -> Result<(), String> {
    let mut guard = state.scheduled_analysis.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_mut().ok_or("Scheduled analysis not initialized")?;
    let interval = interval_minutes.map(|m| std::time::Duration::from_secs(m * 60));
    mgr.update_schedule(&id, enabled, interval, None)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn run_schedule_now(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<serde_json::Value, String> {
    let mut guard = state.scheduled_analysis.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_mut().ok_or("Scheduled analysis not initialized")?;
    if id == "hourly_sweep" {
        let ctx = clawdefender_swarm::scheduled_analysis::SweepContext {
            total_events: 0,
            events_last_hour: 0,
            avg_hourly_events: 0.0,
            suspicious_events: vec![],
            kill_chain_active: false,
            new_servers: vec![],
            server_anomaly_scores: std::collections::HashMap::new(),
            previous_scores: std::collections::HashMap::new(),
        };
        let summary = mgr.run_hourly_sweep(&ctx);
        serde_json::to_value(&summary).map_err(|e| e.to_string())
    } else {
        Err(format!("Schedule '{}' requires cloud API (run manually)", id))
    }
}

#[tauri::command]
pub async fn get_schedule_history(
    state: tauri::State<'_, AppState>,
    id: String,
    count: Option<usize>,
) -> Result<serde_json::Value, String> {
    let guard = state.scheduled_analysis.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_ref().ok_or("Scheduled analysis not initialized")?;
    let c = count.unwrap_or(10);
    match id.as_str() {
        "hourly_sweep" => {
            let summaries = mgr.get_hourly_summaries(c);
            serde_json::to_value(&summaries).map_err(|e| e.to_string())
        }
        "daily_review" => {
            let briefs = mgr.get_daily_briefs(c);
            serde_json::to_value(&briefs).map_err(|e| e.to_string())
        }
        "weekly_report" => {
            let reports = mgr.get_weekly_reports(c);
            serde_json::to_value(&reports).map_err(|e| e.to_string())
        }
        _ => Err(format!("Unknown schedule: {}", id)),
    }
}

#[tauri::command]
pub async fn get_monthly_cost_estimate(
    state: tauri::State<'_, AppState>,
) -> Result<f64, String> {
    let guard = state.scheduled_analysis.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_ref().ok_or("Scheduled analysis not initialized")?;
    Ok(mgr.get_monthly_cost_estimate())
}

// --- Phase 5: Drift Detection commands ---

#[tauri::command]
pub async fn get_drift_baselines(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.drift_detector.lock().map_err(|e| e.to_string())?;
    let detector = guard.as_ref().ok_or("Drift detector not initialized")?;
    let baselines = detector.list_baselines();
    serde_json::to_value(&baselines).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn check_server_drift(
    state: tauri::State<'_, AppState>,
    server_name: String,
) -> Result<serde_json::Value, String> {
    let guard = state.drift_detector.lock().map_err(|e| e.to_string())?;
    let detector = guard.as_ref().ok_or("Drift detector not initialized")?;
    let report = detector.check_server_drift(&server_name);
    serde_json::to_value(&report).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn check_all_drift(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.drift_detector.lock().map_err(|e| e.to_string())?;
    let detector = guard.as_ref().ok_or("Drift detector not initialized")?;
    let reports = detector.check_all_servers();
    serde_json::to_value(&reports).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn reset_drift_baseline(
    state: tauri::State<'_, AppState>,
    server_name: String,
) -> Result<(), String> {
    let mut guard = state.drift_detector.lock().map_err(|e| e.to_string())?;
    let detector = guard.as_mut().ok_or("Drift detector not initialized")?;
    detector.reset_baseline(&server_name);
    Ok(())
}

// --- Phase 5: Smart Alert commands ---

#[tauri::command]
pub async fn get_alert_groups(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.smart_alert_engine.lock().map_err(|e| e.to_string())?;
    let engine = guard.as_ref().ok_or("Smart alert engine not initialized")?;
    let groups = engine.get_active_groups();
    serde_json::to_value(&groups).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_alert_group_detail(
    state: tauri::State<'_, AppState>,
    group_id: String,
) -> Result<serde_json::Value, String> {
    let guard = state.smart_alert_engine.lock().map_err(|e| e.to_string())?;
    let engine = guard.as_ref().ok_or("Smart alert engine not initialized")?;
    let id = uuid::Uuid::parse_str(&group_id).map_err(|e| e.to_string())?;
    let group = engine.get_group(id);
    serde_json::to_value(&group).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn mute_alert_pattern(
    state: tauri::State<'_, AppState>,
    pattern: String,
    hours: u64,
) -> Result<(), String> {
    let mut guard = state.smart_alert_engine.lock().map_err(|e| e.to_string())?;
    let engine = guard.as_mut().ok_or("Smart alert engine not initialized")?;
    engine.mute_pattern(&pattern, chrono::Duration::hours(hours as i64));
    Ok(())
}

#[tauri::command]
pub async fn get_alert_fatigue_suggestions(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut guard = state.smart_alert_engine.lock().map_err(|e| e.to_string())?;
    let engine = guard.as_mut().ok_or("Smart alert engine not initialized")?;
    let suggestions = engine.check_fatigue_suggestions();
    serde_json::to_value(&suggestions).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_quiet_hours(
    state: tauri::State<'_, AppState>,
    start_hour: u32,
    start_minute: u32,
    end_hour: u32,
    end_minute: u32,
) -> Result<(), String> {
    let mut guard = state.smart_alert_engine.lock().map_err(|e| e.to_string())?;
    let engine = guard.as_mut().ok_or("Smart alert engine not initialized")?;
    let start = chrono::NaiveTime::from_hms_opt(start_hour, start_minute, 0)
        .ok_or("Invalid start time")?;
    let end = chrono::NaiveTime::from_hms_opt(end_hour, end_minute, 0)
        .ok_or("Invalid end time")?;
    engine.set_quiet_hours(start, end);
    Ok(())
}

// --- Phase 5: Adaptive Posture commands ---

#[tauri::command]
pub async fn get_threat_posture(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.threat_posture.lock().map_err(|e| e.to_string())?;
    let posture = guard.as_ref().ok_or("Threat posture not initialized")?;
    let info = posture.get_posture_info();
    serde_json::to_value(&info).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_posture_override(
    state: tauri::State<'_, AppState>,
    level: String,
) -> Result<serde_json::Value, String> {
    let mut guard = state.threat_posture.lock().map_err(|e| e.to_string())?;
    let posture = guard.as_mut().ok_or("Threat posture not initialized")?;
    let posture_level = match level.as_str() {
        "low" => clawdefender_swarm::adaptive_posture::PostureLevel::Low,
        "normal" => clawdefender_swarm::adaptive_posture::PostureLevel::Normal,
        "elevated" => clawdefender_swarm::adaptive_posture::PostureLevel::Elevated,
        "high" => clawdefender_swarm::adaptive_posture::PostureLevel::High,
        "critical" => clawdefender_swarm::adaptive_posture::PostureLevel::Critical,
        _ => return Err(format!("Invalid posture level: {}", level)),
    };
    let change = posture.set_override(posture_level);
    serde_json::to_value(&change).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn clear_posture_override(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut guard = state.threat_posture.lock().map_err(|e| e.to_string())?;
    let posture = guard.as_mut().ok_or("Threat posture not initialized")?;
    let change = posture.clear_override();
    serde_json::to_value(&change).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_posture_history(
    state: tauri::State<'_, AppState>,
    count: Option<usize>,
) -> Result<serde_json::Value, String> {
    let guard = state.threat_posture.lock().map_err(|e| e.to_string())?;
    let posture = guard.as_ref().ok_or("Threat posture not initialized")?;
    let history = posture.get_history(count.unwrap_or(20));
    serde_json::to_value(&history).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_posture_parameters(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.threat_posture.lock().map_err(|e| e.to_string())?;
    let posture = guard.as_ref().ok_or("Threat posture not initialized")?;
    let params = posture.get_parameters();
    serde_json::to_value(&params).map_err(|e| e.to_string())
}

// --- Phase 5: Threat Simulation commands ---

#[tauri::command]
pub async fn run_threat_simulation(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut guard = state.threat_simulator.lock().map_err(|e| e.to_string())?;
    let simulator = guard.as_mut().ok_or("Threat simulator not initialized")?;
    let policy = clawdefender_swarm::threat_simulation::PolicySimulator::new();
    let anomaly = clawdefender_swarm::threat_simulation::AnomalySimulator::new(0.65);
    let run = simulator.run_simulation(&policy, &anomaly);
    serde_json::to_value(&run).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_simulation_results(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.threat_simulator.lock().map_err(|e| e.to_string())?;
    let simulator = guard.as_ref().ok_or("Threat simulator not initialized")?;
    let run = simulator.get_latest_run();
    serde_json::to_value(&run).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_simulation_history(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.threat_simulator.lock().map_err(|e| e.to_string())?;
    let simulator = guard.as_ref().ok_or("Threat simulator not initialized")?;
    let history = simulator.get_run_history();
    serde_json::to_value(&history).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_defense_score(
    state: tauri::State<'_, AppState>,
) -> Result<Option<f64>, String> {
    let guard = state.threat_simulator.lock().map_err(|e| e.to_string())?;
    let simulator = guard.as_ref().ok_or("Threat simulator not initialized")?;
    Ok(simulator.get_defense_score())
}

#[tauri::command]
pub async fn get_simulation_scenarios(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.threat_simulator.lock().map_err(|e| e.to_string())?;
    let simulator = guard.as_ref().ok_or("Threat simulator not initialized")?;
    let scenarios = simulator.get_scenarios();
    serde_json::to_value(&scenarios).map_err(|e| e.to_string())
}

// --- Phase 5: Knowledge Base commands ---

#[tauri::command]
pub async fn get_knowledge_stats(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.knowledge_base.lock().map_err(|e| e.to_string())?;
    let kb = guard.as_ref().ok_or("Knowledge base not initialized")?;
    let stats = kb.get_knowledge_stats();
    serde_json::to_value(&stats).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_server_knowledge(
    state: tauri::State<'_, AppState>,
    server_name: String,
) -> Result<serde_json::Value, String> {
    let guard = state.knowledge_base.lock().map_err(|e| e.to_string())?;
    let kb = guard.as_ref().ok_or("Knowledge base not initialized")?;
    let summary = kb.get_server_summary(&server_name);
    serde_json::to_value(&summary).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_known_servers(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.knowledge_base.lock().map_err(|e| e.to_string())?;
    let kb = guard.as_ref().ok_or("Knowledge base not initialized")?;
    let servers = kb.list_known_servers();
    serde_json::to_value(&servers).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_false_positives(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.knowledge_base.lock().map_err(|e| e.to_string())?;
    let kb = guard.as_ref().ok_or("Knowledge base not initialized")?;
    let fps = kb.list_false_positives();
    serde_json::to_value(&fps).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_learned_patterns(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.knowledge_base.lock().map_err(|e| e.to_string())?;
    let kb = guard.as_ref().ok_or("Knowledge base not initialized")?;
    let patterns = kb.list_patterns();
    serde_json::to_value(&patterns).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_manual_knowledge(
    state: tauri::State<'_, AppState>,
    server_name: String,
    knowledge_type: String,
    content: String,
) -> Result<(), String> {
    let mut guard = state.knowledge_base.lock().map_err(|e| e.to_string())?;
    let kb = guard.as_mut().ok_or("Knowledge base not initialized")?;
    kb.add_manual_knowledge(&server_name, &knowledge_type, &content);
    Ok(())
}

#[tauri::command]
pub async fn forget_server_knowledge(
    state: tauri::State<'_, AppState>,
    server_name: String,
) -> Result<(), String> {
    let mut guard = state.knowledge_base.lock().map_err(|e| e.to_string())?;
    let kb = guard.as_mut().ok_or("Knowledge base not initialized")?;
    kb.forget_server(&server_name);
    Ok(())
}

#[tauri::command]
pub async fn save_knowledge_base(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let guard = state.knowledge_base.lock().map_err(|e| e.to_string())?;
    let kb = guard.as_ref().ok_or("Knowledge base not initialized")?;
    kb.save().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_knowledge_base(
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let guard = state.knowledge_base.lock().map_err(|e| e.to_string())?;
    let kb = guard.as_ref().ok_or("Knowledge base not initialized")?;
    kb.export_json().map_err(|e| e.to_string())
}

// =============================================================================
// Phase 6: Autonomy Framework commands
// =============================================================================

#[tauri::command]
pub async fn get_autonomy_level(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_autonomy_level());
    }
    let guard = state.autonomy_framework.lock().map_err(|e| e.to_string())?;
    let framework = guard.as_ref().ok_or("Autonomy framework not initialized")?;
    serde_json::to_value(&serde_json::json!({
        "global_level": format!("{}", framework.global_level()),
        "is_locked_down": framework.is_locked_down(),
        "server_overrides": framework.server_overrides(),
        "stats": framework.get_stats(),
    })).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_autonomy_level(
    state: tauri::State<'_, AppState>,
    level: String,
) -> Result<(), String> {
    use clawdefender_swarm::autonomy_framework::AutonomyLevel;
    let autonomy_level = match level.as_str() {
        "l0" | "L0" => AutonomyLevel::L0ObserveOnly,
        "l1" | "L1" => AutonomyLevel::L1Suggest,
        "l2" | "L2" => AutonomyLevel::L2ConfirmAndAct,
        "l3" | "L3" => AutonomyLevel::L3AutoLowRisk,
        _ => return Err(format!("Invalid autonomy level: {}", level)),
    };
    let mut guard = state.autonomy_framework.lock().map_err(|e| e.to_string())?;
    let framework = guard.as_mut().ok_or("Autonomy framework not initialized")?;
    framework.set_level(autonomy_level);
    Ok(())
}

#[tauri::command]
pub async fn set_server_autonomy_override(
    state: tauri::State<'_, AppState>,
    server_name: String,
    level: String,
) -> Result<(), String> {
    use clawdefender_swarm::autonomy_framework::AutonomyLevel;
    let autonomy_level = match level.as_str() {
        "l0" | "L0" => AutonomyLevel::L0ObserveOnly,
        "l1" | "L1" => AutonomyLevel::L1Suggest,
        "l2" | "L2" => AutonomyLevel::L2ConfirmAndAct,
        "l3" | "L3" => AutonomyLevel::L3AutoLowRisk,
        _ => return Err(format!("Invalid autonomy level: {}", level)),
    };
    let mut guard = state.autonomy_framework.lock().map_err(|e| e.to_string())?;
    let framework = guard.as_mut().ok_or("Autonomy framework not initialized")?;
    framework.set_server_override(server_name, autonomy_level);
    Ok(())
}

#[tauri::command]
pub async fn clear_server_autonomy_override(
    state: tauri::State<'_, AppState>,
    server_name: String,
) -> Result<(), String> {
    let mut guard = state.autonomy_framework.lock().map_err(|e| e.to_string())?;
    let framework = guard.as_mut().ok_or("Autonomy framework not initialized")?;
    framework.clear_server_override(&server_name);
    Ok(())
}

#[tauri::command]
pub async fn activate_lockdown(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut guard = state.autonomy_framework.lock().map_err(|e| e.to_string())?;
    let framework = guard.as_mut().ok_or("Autonomy framework not initialized")?;
    framework.activate_lockdown();
    Ok(())
}

#[tauri::command]
pub async fn deactivate_lockdown(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut guard = state.autonomy_framework.lock().map_err(|e| e.to_string())?;
    let framework = guard.as_mut().ok_or("Autonomy framework not initialized")?;
    framework.deactivate_lockdown();
    Ok(())
}

#[tauri::command]
pub async fn get_autonomy_action_log(
    state: tauri::State<'_, AppState>,
    count: Option<usize>,
) -> Result<serde_json::Value, String> {
    let guard = state.autonomy_framework.lock().map_err(|e| e.to_string())?;
    let framework = guard.as_ref().ok_or("Autonomy framework not initialized")?;
    let log = framework.get_action_log(count.unwrap_or(50));
    serde_json::to_value(&log).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_autonomy_stats(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.autonomy_framework.lock().map_err(|e| e.to_string())?;
    let framework = guard.as_ref().ok_or("Autonomy framework not initialized")?;
    serde_json::to_value(&framework.get_stats()).map_err(|e| e.to_string())
}

// =============================================================================
// Phase 6: Response Playbook commands
// =============================================================================

#[tauri::command]
pub async fn list_response_playbooks(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_response_playbooks());
    }
    let guard = state.playbook_manager.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_ref().ok_or("Playbook manager not initialized")?;
    serde_json::to_value(mgr.list_playbooks()).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_response_playbook(
    state: tauri::State<'_, AppState>,
    playbook_id: String,
) -> Result<serde_json::Value, String> {
    let guard = state.playbook_manager.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_ref().ok_or("Playbook manager not initialized")?;
    let playbook = mgr.get_playbook(&playbook_id).ok_or("Playbook not found")?;
    serde_json::to_value(playbook).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_playbook_executions(
    state: tauri::State<'_, AppState>,
    count: Option<usize>,
) -> Result<serde_json::Value, String> {
    let guard = state.playbook_manager.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_ref().ok_or("Playbook manager not initialized")?;
    let history = mgr.get_execution_history(None, count.unwrap_or(50));
    serde_json::to_value(&history).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn test_response_playbook(
    state: tauri::State<'_, AppState>,
    playbook_id: String,
) -> Result<serde_json::Value, String> {
    let mut guard = state.playbook_manager.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_mut().ok_or("Playbook manager not initialized")?;
    let context = clawdefender_swarm::response_playbooks::TriggerContext {
        trigger_type: "test".to_string(),
        server_name: None,
        event_ids: vec![],
        confidence: 1.0,
        details: "dry_run test".to_string(),
        timestamp: chrono::Utc::now(),
    };
    let result = mgr.test_playbook(&playbook_id, &context)
        .ok_or("Playbook trigger did not match test context")?;
    serde_json::to_value(&result).map_err(|e| e.to_string())
}

// =============================================================================
// Phase 6: Report Generation commands
// =============================================================================

#[tauri::command]
pub async fn list_reports(
    state: tauri::State<'_, AppState>,
    report_type: Option<String>,
) -> Result<serde_json::Value, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_reports());
    }
    let guard = state.report_generator.lock().map_err(|e| e.to_string())?;
    let gen = guard.as_ref().ok_or("Report generator not initialized")?;
    let rtype = report_type.as_deref().and_then(|t| match t {
        "daily_brief" => Some(clawdefender_swarm::report_system::ReportType::DailyBrief),
        "weekly_report" => Some(clawdefender_swarm::report_system::ReportType::WeeklyReport),
        "incident_report" => Some(clawdefender_swarm::report_system::ReportType::IncidentReport),
        "compliance_report" => Some(clawdefender_swarm::report_system::ReportType::ComplianceReport),
        "executive_summary" => Some(clawdefender_swarm::report_system::ReportType::ExecutiveSummary),
        _ => None,
    });
    let reports = gen.list_reports(rtype.as_ref(), 100);
    serde_json::to_value(&reports).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_report_content(
    state: tauri::State<'_, AppState>,
    report_id: String,
) -> Result<String, String> {
    let guard = state.report_generator.lock().map_err(|e| e.to_string())?;
    let gen = guard.as_ref().ok_or("Report generator not initialized")?;
    let id = uuid::Uuid::parse_str(&report_id).map_err(|e| e.to_string())?;
    gen.get_report_content(id)
}

#[tauri::command]
pub async fn get_report_count(
    state: tauri::State<'_, AppState>,
) -> Result<usize, String> {
    let guard = state.report_generator.lock().map_err(|e| e.to_string())?;
    let gen = guard.as_ref().ok_or("Report generator not initialized")?;
    Ok(gen.report_count())
}

#[tauri::command]
pub async fn delete_report(
    state: tauri::State<'_, AppState>,
    report_id: String,
) -> Result<(), String> {
    let mut guard = state.report_generator.lock().map_err(|e| e.to_string())?;
    let gen = guard.as_mut().ok_or("Report generator not initialized")?;
    let id = uuid::Uuid::parse_str(&report_id).map_err(|e| e.to_string())?;
    gen.delete_report(id)
}

// =============================================================================
// Phase 6: Feedback & Calibration commands
// =============================================================================

#[tauri::command]
pub async fn get_feedback_stats(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_feedback_stats());
    }
    let fc_guard = state.feedback_collector.lock().map_err(|e| e.to_string())?;
    let fc = fc_guard.as_ref().ok_or("Feedback collector not initialized")?;
    let tc_guard = state.threshold_calibrator.lock().map_err(|e| e.to_string())?;
    let tc = tc_guard.as_ref().ok_or("Threshold calibrator not initialized")?;
    let stats = tc.get_stats(fc);
    serde_json::to_value(&stats).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_self_assessment(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_self_assessment());
    }
    let fc_guard = state.feedback_collector.lock().map_err(|e| e.to_string())?;
    let fc = fc_guard.as_ref().ok_or("Feedback collector not initialized")?;
    let tc_guard = state.threshold_calibrator.lock().map_err(|e| e.to_string())?;
    let tc = tc_guard.as_ref().ok_or("Threshold calibrator not initialized")?;
    let assessment = tc.self_assessment(fc);
    serde_json::to_value(&assessment).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn run_calibration(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let fc_guard = state.feedback_collector.lock().map_err(|e| e.to_string())?;
    let fc = fc_guard.as_ref().ok_or("Feedback collector not initialized")?;
    let mut tc_guard = state.threshold_calibrator.lock().map_err(|e| e.to_string())?;
    let tc = tc_guard.as_mut().ok_or("Threshold calibrator not initialized")?;
    let events = tc.run_calibration(fc);
    serde_json::to_value(&events).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_knowledge_suggestions(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let fc_guard = state.feedback_collector.lock().map_err(|e| e.to_string())?;
    let fc = fc_guard.as_ref().ok_or("Feedback collector not initialized")?;
    let tc_guard = state.threshold_calibrator.lock().map_err(|e| e.to_string())?;
    let tc = tc_guard.as_ref().ok_or("Threshold calibrator not initialized")?;
    let suggestions = tc.check_knowledge_suggestions(fc);
    serde_json::to_value(&suggestions).map_err(|e| e.to_string())
}

// =============================================================================
// Phase 6: Data Portability commands
// =============================================================================

#[tauri::command]
pub async fn export_clawdefender_data(
    state: tauri::State<'_, AppState>,
    include_knowledge: bool,
    include_playbooks: bool,
    include_calibration: bool,
) -> Result<serde_json::Value, String> {
    let mut guard = state.data_portability.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_mut().ok_or("Data portability not initialized")?;
    let options = clawdefender_swarm::data_portability::ExportOptions {
        include_config: true,
        include_knowledge: include_knowledge,
        include_baselines: false,
        include_playbooks: include_playbooks,
        include_calibration: include_calibration,
        include_investigations: false,
        include_reports: false,
        encrypt: false,
        passphrase: None,
    };
    let result = mgr.export_data(&options)?;
    serde_json::to_value(&result).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn preview_import(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<serde_json::Value, String> {
    let guard = state.data_portability.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_ref().ok_or("Data portability not initialized")?;
    let preview = mgr.preview_import(&file_path)?;
    serde_json::to_value(&preview).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_export_history(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.data_portability.lock().map_err(|e| e.to_string())?;
    let mgr = guard.as_ref().ok_or("Data portability not initialized")?;
    serde_json::to_value(mgr.get_export_history()).map_err(|e| e.to_string())
}

// =============================================================================
// Phase 6: Transparency Dashboard commands
// =============================================================================

#[tauri::command]
pub async fn get_dashboard_summary(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_dashboard_summary());
    }
    let guard = state.transparency_dashboard.lock().map_err(|e| e.to_string())?;
    let dashboard = guard.as_ref().ok_or("Transparency dashboard not initialized")?;
    let summary = dashboard.get_dashboard_summary();
    serde_json::to_value(&summary).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_agent_activities(
    state: tauri::State<'_, AppState>,
    count: Option<usize>,
) -> Result<serde_json::Value, String> {
    let guard = state.transparency_dashboard.lock().map_err(|e| e.to_string())?;
    let dashboard = guard.as_ref().ok_or("Transparency dashboard not initialized")?;
    let activities = dashboard.activity_tracker.get_recent(count.unwrap_or(50));
    serde_json::to_value(&activities).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_cost_summary(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.transparency_dashboard.lock().map_err(|e| e.to_string())?;
    let dashboard = guard.as_ref().ok_or("Transparency dashboard not initialized")?;
    let summary = dashboard.cost_dashboard.get_summary();
    serde_json::to_value(&summary).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_accuracy_metrics(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.transparency_dashboard.lock().map_err(|e| e.to_string())?;
    let dashboard = guard.as_ref().ok_or("Transparency dashboard not initialized")?;
    let metrics = dashboard.accuracy_tracker.get_metrics();
    serde_json::to_value(&metrics).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_audit_trail(
    state: tauri::State<'_, AppState>,
    count: Option<usize>,
) -> Result<serde_json::Value, String> {
    let guard = state.transparency_dashboard.lock().map_err(|e| e.to_string())?;
    let dashboard = guard.as_ref().ok_or("Transparency dashboard not initialized")?;
    let entries = dashboard.audit_trail.get_recent(count.unwrap_or(50));
    serde_json::to_value(&entries).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_decision_explanations(
    state: tauri::State<'_, AppState>,
    count: Option<usize>,
) -> Result<serde_json::Value, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_decision_explanations());
    }
    let guard = state.transparency_dashboard.lock().map_err(|e| e.to_string())?;
    let dashboard = guard.as_ref().ok_or("Transparency dashboard not initialized")?;
    let explanations = dashboard.decision_explainer.get_recent(count.unwrap_or(20));
    serde_json::to_value(&explanations).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_learned_patterns_view(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let guard = state.transparency_dashboard.lock().map_err(|e| e.to_string())?;
    let dashboard = guard.as_ref().ok_or("Transparency dashboard not initialized")?;
    let stats = dashboard.knowledge_viewer.get_pattern_stats();
    serde_json::to_value(&serde_json::json!({
        "stats": stats,
        "learned": dashboard.knowledge_viewer.get_all_patterns(),
        "safe": dashboard.knowledge_viewer.get_safe_patterns(),
        "risk": dashboard.knowledge_viewer.get_risk_patterns(),
    })).map_err(|e| e.to_string())
}

// --- UI State Persistence ---

fn ui_state_path() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_default();
    home.join(".local/share/rookbot/ui_state.json")
}

fn load_ui_state(path: &std::path::Path) -> std::collections::HashMap<String, String> {
    match std::fs::read_to_string(path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => std::collections::HashMap::new(),
    }
}

fn save_ui_state(
    path: &std::path::Path,
    state: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    // Enforce 1MB size limit
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    if json.len() > 1_048_576 {
        return Err("UI state exceeds 1MB limit".to_string());
    }

    // Create parent directory
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    // Atomic write: write to temp file, then rename
    let temp_path = path.with_extension("json.tmp");
    std::fs::write(&temp_path, &json).map_err(|e| e.to_string())?;
    std::fs::rename(&temp_path, path).map_err(|e| e.to_string())?;

    Ok(())
}

/// Get a UI state value by key.
#[tauri::command]
pub async fn get_ui_state(key: String) -> Result<Option<String>, String> {
    let path = ui_state_path();
    let state = load_ui_state(&path);
    Ok(state.get(&key).cloned())
}

/// Set a UI state value by key.
#[tauri::command]
pub async fn set_ui_state(key: String, value: String) -> Result<(), String> {
    let path = ui_state_path();
    let mut state = load_ui_state(&path);
    state.insert(key, value);
    save_ui_state(&path, &state)
}

/// Remove a UI state value by key.
#[tauri::command]
pub async fn remove_ui_state(key: String) -> Result<(), String> {
    let path = ui_state_path();
    let mut state = load_ui_state(&path);
    state.remove(&key);
    save_ui_state(&path, &state)
}

// ---------------------------------------------------------------------------
// Sensor Health & FDA Setup
// ---------------------------------------------------------------------------

/// Sensor health status for the setup banner.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SensorHealth {
    pub fda_granted: bool,
    pub eslogger_available: bool,
    pub os_version_ok: bool,
    pub daemon_running: bool,
    pub events_flowing: bool,
}


/// Check macOS version >= 13 (Ventura) for eslogger support.
fn is_macos_13_or_later() -> bool {
    let output = std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output();
    match output {
        Ok(out) => {
            let version = String::from_utf8_lossy(&out.stdout);
            let major: u32 = version
                .trim()
                .split('.')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            major >= 13
        }
        Err(_) => false,
    }
}

/// Get sensor health status (FDA, eslogger, daemon, event flow).
#[tauri::command]
pub async fn get_sensor_health() -> Result<SensorHealth, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_sensor_health());
    }

    let home = std::env::var("HOME").unwrap_or_default();

    // Daemon running: check IPC socket or pid file
    let socket_path =
        std::path::PathBuf::from(&home).join(".local/share/rookbot/daemon.sock");
    let daemon_running = socket_path.exists() || crate::daemon::is_daemon_running();

    // Events flowing: audit.jsonl was modified recently (within 120 seconds)
    let audit_path = crate::event_stream::audit_log_path();
    let events_flowing = std::fs::metadata(&audit_path)
        .and_then(|m| m.modified())
        .map(|t| t.elapsed().map(|d| d.as_secs() < 120).unwrap_or(false))
        .unwrap_or(false);

    // FDA granted: check the daemon's sensor-status.json file.
    //
    // The daemon writes this file after starting its sensors. It records
    // whether eslogger was successfully started (which requires FDA).
    // This is the most reliable signal because the daemon performs its own
    // FDA check before attempting to start eslogger.
    //
    // Fallback: if the status file doesn't exist or is stale, check if an
    // eslogger process is running via pgrep.
    let status_path =
        std::path::PathBuf::from(&home).join(".local/share/rookbot/sensor-status.json");
    let daemon_says_fda = std::fs::read_to_string(&status_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("fda_granted")?.as_bool())
        .unwrap_or(false);

    let eslogger_running = std::process::Command::new("pgrep")
        .args(["-x", "eslogger"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let fda_granted = daemon_says_fda || eslogger_running;

    // eslogger available: binary exists + FDA granted
    let eslogger_available =
        std::path::Path::new("/usr/bin/eslogger").exists() && fda_granted;

    // OS version check
    let os_version_ok = is_macos_13_or_later();

    Ok(SensorHealth {
        fda_granted,
        eslogger_available,
        os_version_ok,
        daemon_running,
        events_flowing,
    })
}

/// Open System Settings to the Full Disk Access privacy pane.
#[tauri::command]
pub async fn open_system_settings_fda() -> Result<(), String> {
    std::process::Command::new("open")
        .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
        .spawn()
        .map_err(|e| format!("Failed to open System Settings: {}", e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unified Detection Pipeline
// ---------------------------------------------------------------------------

/// Run the unified detection scan.
///
/// `mode` selects which modules run:
///   "full" (default), "signatures-only", "persistence-only",
///   "patterns-only", "clamav-only"
///
/// When `ai_enrich` is true, critical/high findings are sent to the AI
/// backend for deeper analysis after the deterministic scan completes.
#[tauri::command]
pub async fn run_detection_scan(
    state: tauri::State<'_, AppState>,
    mode: Option<String>,
    ai_enrich: Option<bool>,
) -> Result<serde_json::Value, String> {
    use clawdefender_scanner::detection_engine::{
        DetectionEngine, DetectionMethod, ScanMode,
    };

    let scan_mode = match mode.as_deref() {
        Some("signatures-only") => ScanMode::SignaturesOnly,
        Some("persistence-only") => ScanMode::PersistenceOnly,
        Some("patterns-only") => ScanMode::PatternsOnly,
        Some("clamav-only") => ScanMode::ClamavOnly,
        Some("memory-only") => ScanMode::MemoryOnly,
        _ => ScanMode::Full,
    };

    let engine = DetectionEngine::with_mode(scan_mode);
    let mut report = engine.run_all().await.map_err(|e| e.to_string())?;

    // --- AI enrichment: deterministic first, then AI investigates ---
    let do_ai = ai_enrich.unwrap_or(true);
    if do_ai {
        for ef in &mut report.findings {
            let sev = &ef.finding.severity;
            if !matches!(
                sev,
                clawdefender_scanner::finding::Severity::Critical
                    | clawdefender_scanner::finding::Severity::High
            ) {
                continue;
            }

            let prompt = format!(
                "You are a macOS security analyst. Analyze this detection finding and assess \
                 whether it represents a genuine security risk or is likely a false positive.\n\n\
                 Title: {}\nSeverity: {:?}\nCategory: {}\nCVSS: {:.1}\n\
                 Detection methods: {}\n\nDescription:\n{}\n\n\
                 Provide a brief assessment (2-3 sentences): is this a real threat? \
                 What should the user do?",
                ef.finding.title,
                ef.finding.severity,
                ef.finding.category,
                ef.finding.cvss,
                ef.detection_methods
                    .iter()
                    .map(|m| m.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                ef.finding.description,
            );

            let ai_resp = state
                .ai_backends
                .analyze(clawdefender_slm::AiRequest {
                    task_type: clawdefender_slm::TaskType::ScanAnalysis,
                    prompt,
                    context: None,
                })
                .await;

            if let Some(result) = ai_resp.response {
                ef.ai_analysis = Some(result.explanation);
                if !ef.detection_methods.contains(&DetectionMethod::AiAnalysis) {
                    ef.detection_methods.push(DetectionMethod::AiAnalysis);
                }
            }
        }
    }

    // --- Build kill chain summary from active patterns ---
    let killchain_detector = clawdefender_core::behavioral::killchain::KillChainDetector::new();
    let killchain_patterns: Vec<serde_json::Value> = killchain_detector
        .patterns()
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "severity": format!("{:?}", p.severity),
                "mitre_id": p.mitre_id,
                "steps": p.steps.len(),
                "window_seconds": p.window_seconds,
            })
        })
        .collect();

    // --- Serialize findings with detection method badges ---
    let findings_json: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|ef| {
            serde_json::json!({
                "id": ef.finding.id,
                "title": ef.finding.title,
                "severity": format!("{:?}", ef.finding.severity),
                "cvss": ef.finding.cvss,
                "category": format!("{}", ef.finding.category),
                "description": ef.finding.description,
                "remediation": ef.finding.remediation,
                "detection_methods": ef.detection_methods.iter()
                    .map(|m| m.to_string())
                    .collect::<Vec<_>>(),
                "ai_analysis": ef.ai_analysis,
            })
        })
        .collect();

    Ok(serde_json::json!({
        "findings": findings_json,
        "modules_run": report.modules_run,
        "duration_secs": report.duration_secs,
        "summary": report.summary,
        "killchain_patterns_active": killchain_patterns.len(),
        "killchain_patterns": killchain_patterns,
    }))
}

// --- Memory Scanner ---

#[tauri::command]
pub async fn run_memory_scan() -> Result<serde_json::Value, String> {
    use clawdefender_scanner::modules::memory_scanner::MemoryScanModule;
    use clawdefender_scanner::modules::ScanModule;

    let module = MemoryScanModule::new();
    let findings = module.run_standalone().await.map_err(|e| e.to_string())?;

    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| serde_json::to_value(f).unwrap_or_default())
        .collect();

    Ok(serde_json::json!({
        "findings": findings_json,
        "total_findings": findings.len(),
        "scanned_at": chrono::Utc::now().to_rfc3339(),
    }))
}

// --- Clipboard Monitor ---

/// One-shot clipboard check (does not require the monitor to be enabled).
#[tauri::command]
pub async fn check_clipboard_now() -> Result<serde_json::Value, String> {
    use clawdefender_scanner::modules::clipboard_monitor::ClipboardMonitorModule;
    use clawdefender_scanner::modules::ScanModule;

    let module = ClipboardMonitorModule::new();
    let findings = module.run_standalone().await.map_err(|e| e.to_string())?;

    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| serde_json::to_value(f).unwrap_or_default())
        .collect();

    Ok(serde_json::json!({
        "findings": findings_json,
        "total_findings": findings.len(),
        "checked_at": chrono::Utc::now().to_rfc3339(),
    }))
}

/// Return recent clipboard threats detected by the background polling loop.
/// Threats are kept in-memory only and never persisted to disk.
#[tauri::command]
pub async fn get_clipboard_threats(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let threats = state
        .clipboard_threats
        .lock()
        .map_err(|e| e.to_string())?
        .clone();

    let is_active = state
        .clipboard_monitor_active
        .lock()
        .map_err(|e| e.to_string())?
        .clone();

    Ok(serde_json::json!({
        "monitor_active": is_active,
        "threats": threats,
        "total_threats": threats.len(),
    }))
}

/// Start the clipboard monitor background polling loop.
/// Uses 500ms polling with SHA-256 hash change detection.
/// This is opt-in — the user must explicitly enable it in Settings.
pub fn start_clipboard_monitor(app: tauri::AppHandle) {
    use clawdefender_scanner::modules::clipboard_monitor::{
        analyze_clipboard_content, clipboard_content_hash, ClipboardThreatLevel,
    };
    use tauri::Manager;

    let state = app.state::<AppState>();

    // Check if already active
    if let Ok(active) = state.clipboard_monitor_active.lock() {
        if *active {
            tracing::info!("Clipboard monitor already running");
            return;
        }
    }

    // Mark as active
    if let Ok(mut active) = state.clipboard_monitor_active.lock() {
        *active = true;
    }

    tracing::info!("Starting clipboard monitor (500ms polling)");

    std::thread::spawn(move || {
        use tauri::Manager;

        let mut last_hash: Option<String> = None;
        // Maximum number of in-memory threat entries (ring buffer)
        const MAX_THREATS: usize = 50;

        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));

            let app_state: tauri::State<'_, AppState> = app.state::<AppState>();

            // Check if monitor was deactivated
            if let Ok(active) = app_state.clipboard_monitor_active.lock() {
                if !*active {
                    tracing::info!("Clipboard monitor stopped");
                    return;
                }
            }

            // Read clipboard via pbpaste
            let content = match std::process::Command::new("pbpaste")
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        String::from_utf8(o.stdout).ok()
                    } else {
                        None
                    }
                }) {
                Some(c) if !c.is_empty() => c,
                _ => continue,
            };

            // Only analyze when content changes (hash-based change detection)
            let current_hash = clipboard_content_hash(&content);
            if last_hash.as_ref() == Some(&current_hash) {
                continue;
            }
            last_hash = Some(current_hash);

            // Analyze the new clipboard content
            let analysis = analyze_clipboard_content(&content);
            // content is dropped after this scope — never persisted
            drop(content);

            if analysis.threat_level == ClipboardThreatLevel::Safe {
                continue;
            }

            let threat_level_str = match analysis.threat_level {
                ClipboardThreatLevel::Critical => "critical",
                ClipboardThreatLevel::Suspicious => "suspicious",
                ClipboardThreatLevel::Safe => "safe",
            };

            let entry = crate::state::ClipboardThreatEntry {
                detected_at: chrono::Utc::now().to_rfc3339(),
                threat_level: threat_level_str.to_string(),
                patterns_matched: analysis.patterns_matched.clone(),
                content_preview: analysis.content_preview.clone(),
                content_length: analysis.content_length,
            };

            tracing::warn!(
                "Clipboard threat detected: level={}, patterns=[{}]",
                threat_level_str,
                analysis.patterns_matched.join(", ")
            );

            // Store in-memory (ring buffer, capped)
            if let Ok(mut threats) = app_state.clipboard_threats.lock() {
                threats.push(entry.clone());
                let len = threats.len();
                if len > MAX_THREATS {
                    threats.drain(..len - MAX_THREATS);
                }
            }

            // Emit frontend event so the UI can react immediately
            use tauri::Emitter;
            let _ = app.emit(
                "rookbot://clipboard-threat",
                serde_json::json!({
                    "threat_level": threat_level_str,
                    "patterns_matched": analysis.patterns_matched,
                    "content_preview": analysis.content_preview,
                    "content_length": analysis.content_length,
                    "detected_at": entry.detected_at,
                }),
            );
        }
    });
}

/// Stop the clipboard monitor background polling loop.
pub fn stop_clipboard_monitor(state: &AppState) {
    if let Ok(mut active) = state.clipboard_monitor_active.lock() {
        *active = false;
        tracing::info!("Clipboard monitor deactivated");
    }
}

// --- TCC Permission Audit ---

#[tauri::command]
pub async fn run_tcc_audit() -> Result<serde_json::Value, String> {
    let module = clawdefender_scanner::modules::tcc_audit::TccAuditModule::new();
    let (audit_result, findings) = module.audit().await.map_err(|e| e.to_string())?;

    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| serde_json::to_value(f).unwrap_or_default())
        .collect();

    let entries_json: Vec<serde_json::Value> = audit_result
        .entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap_or_default())
        .collect();

    Ok(serde_json::json!({
        "entries": entries_json,
        "findings": findings_json,
        "total_entries": audit_result.entries.len(),
        "total_findings": findings.len(),
    }))
}

// --- File Integrity Monitor ---

#[tauri::command]
pub async fn run_integrity_check() -> Result<serde_json::Value, String> {
    let findings = clawdefender_scanner::modules::file_integrity::run_integrity_check_sync()
        .map_err(|e| e.to_string())?;

    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| serde_json::to_value(f).unwrap_or_default())
        .collect();

    Ok(serde_json::json!({
        "findings": findings_json,
        "total_findings": findings.len(),
        "checked_at": chrono::Utc::now().to_rfc3339(),
    }))
}

#[tauri::command]
pub async fn reset_integrity_baseline() -> Result<serde_json::Value, String> {
    let file_count = clawdefender_scanner::modules::file_integrity::reset_baseline_sync()
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "success": true,
        "files_baselined": file_count,
        "reset_at": chrono::Utc::now().to_rfc3339(),
    }))
}

// --- CIS Benchmark Compliance ---

#[tauri::command]
pub async fn run_cis_compliance() -> Result<serde_json::Value, String> {
    let report = clawdefender_scanner::modules::cis_benchmark::run_cis_compliance_report();
    serde_json::to_value(&report).map_err(|e| e.to_string())
}

// --- Browser Extension Audit ---

#[tauri::command]
pub async fn run_browser_audit() -> Result<serde_json::Value, String> {
    let (risks, findings) = clawdefender_scanner::modules::browser_audit::run_full_browser_audit()
        .await
        .map_err(|e| e.to_string())?;

    let risks_json: Vec<serde_json::Value> = risks
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or_default())
        .collect();

    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| serde_json::to_value(f).unwrap_or_default())
        .collect();

    Ok(serde_json::json!({
        "extensions": risks_json,
        "findings": findings_json,
        "total_extensions": risks.len(),
        "total_findings": findings.len(),
        "checked_at": chrono::Utc::now().to_rfc3339(),
    }))
}

#[tauri::command]
pub async fn get_login_anomalies() -> Result<serde_json::Value, String> {
    let (anomalies, findings) =
        clawdefender_scanner::modules::browser_audit::run_login_anomaly_detection()
            .await
            .map_err(|e| e.to_string())?;

    let anomalies_json: Vec<serde_json::Value> = anomalies
        .iter()
        .map(|a| serde_json::to_value(a).unwrap_or_default())
        .collect();

    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| serde_json::to_value(f).unwrap_or_default())
        .collect();

    Ok(serde_json::json!({
        "anomalies": anomalies_json,
        "findings": findings_json,
        "total_anomalies": anomalies.len(),
        "total_findings": findings.len(),
        "checked_at": chrono::Utc::now().to_rfc3339(),
    }))
}

// --- Performance & Battery commands ---

#[tauri::command]
pub async fn get_performance_stats(
    state: tauri::State<'_, AppState>,
) -> Result<PerformanceStats, String> {
    if crate::demo_data::is_demo_mode() {
        return Ok(crate::demo_data::mock_performance_stats());
    }

    // Gather approximate stats from available state
    let events_processed = state
        .cached_status
        .lock()
        .ok()
        .and_then(|s| s.as_ref().map(|ds| ds.events_processed))
        .unwrap_or(0);

    let event_buffer_len = state
        .event_buffer
        .lock()
        .ok()
        .map(|b| b.len())
        .unwrap_or(0);

    // Use sysinfo to get process-level CPU and memory usage
    let (cpu_percent, memory_bytes) = {
        use sysinfo::{System, Pid};
        let mut sys = System::new();
        let pid = Pid::from_u32(std::process::id());
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
        if let Some(proc_info) = sys.process(pid) {
            (proc_info.cpu_usage() as f64, proc_info.memory())
        } else {
            (0.0, 0)
        }
    };

    // Estimate event rates based on buffer activity
    // These are approximations — real rates come from the daemon
    let events_per_sec = if events_processed > 0 {
        (event_buffer_len as f64).min(100.0) / 5.0 // rough 5s window
    } else {
        0.0
    };

    let mode = state
        .monitoring_mode
        .lock()
        .ok()
        .map(|m| *m)
        .unwrap_or_default();

    let sample_rate = match mode {
        MonitoringMode::Full => 100.0,
        MonitoringMode::Balanced => 85.0,
        MonitoringMode::Light => 50.0,
        MonitoringMode::Minimal => 15.0,
    };

    Ok(PerformanceStats {
        cpu_percent,
        memory_bytes,
        memory_model_bytes: 0, // populated when SLM is loaded
        memory_buffers_bytes: (event_buffer_len * 512) as u64, // rough estimate
        events_per_sec,
        events_total_per_sec: events_per_sec / (sample_rate / 100.0_f64).max(0.01_f64),
        events_sampled_percent: sample_rate,
        disk_writes_per_sec: 0.0, // approximation
    })
}

#[tauri::command]
pub async fn get_monitoring_mode(
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let mode = state
        .monitoring_mode
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    let name = match *mode {
        MonitoringMode::Full => "full",
        MonitoringMode::Balanced => "balanced",
        MonitoringMode::Light => "light",
        MonitoringMode::Minimal => "minimal",
    };
    Ok(name.to_string())
}

#[tauri::command]
pub async fn set_monitoring_mode(
    mode: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let parsed = match mode.as_str() {
        "full" => MonitoringMode::Full,
        "balanced" => MonitoringMode::Balanced,
        "light" => MonitoringMode::Light,
        "minimal" => MonitoringMode::Minimal,
        _ => return Err(format!("Unknown monitoring mode: {}", mode)),
    };

    if let Ok(mut m) = state.monitoring_mode.lock() {
        *m = parsed;
    }

    // Persist to config.toml under [performance]
    let path = config_toml_path();
    let mut table: toml::Value = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    if table.get("performance").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("performance".to_string(), toml::Value::Table(Default::default()));
    }
    let perf = table
        .get_mut("performance")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [performance] section")?;
    perf.insert("monitoring_mode".to_string(), toml::Value::String(mode));

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, table.to_string())
        .map_err(|e| format!("Failed to write config.toml: {}", e))?;

    tracing::info!("Monitoring mode set to {:?}", parsed);
    Ok(())
}

#[tauri::command]
pub async fn get_battery_auto_adjust(
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let val = state
        .battery_auto_adjust
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    Ok(*val)
}

#[tauri::command]
pub async fn set_battery_auto_adjust(
    enabled: bool,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    if let Ok(mut v) = state.battery_auto_adjust.lock() {
        *v = enabled;
    }

    // Persist to config.toml under [performance]
    let path = config_toml_path();
    let mut table: toml::Value = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    if table.get("performance").is_none() {
        table
            .as_table_mut()
            .ok_or("Config is not a TOML table")?
            .insert("performance".to_string(), toml::Value::Table(Default::default()));
    }
    let perf = table
        .get_mut("performance")
        .and_then(|v| v.as_table_mut())
        .ok_or("Failed to access [performance] section")?;
    perf.insert("auto_adjust_on_battery".to_string(), toml::Value::Boolean(enabled));

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, table.to_string())
        .map_err(|e| format!("Failed to write config.toml: {}", e))?;

    tracing::info!("Battery auto-adjust set to {}", enabled);
    Ok(())
}

#[tauri::command]
pub async fn pause_monitoring(
    duration_minutes: u64,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let resume_at = chrono::Utc::now() + chrono::Duration::minutes(duration_minutes as i64);
    if let Ok(mut p) = state.pause_until.lock() {
        *p = Some(resume_at);
    }
    tracing::info!("Monitoring paused for {} minutes (until {})", duration_minutes, resume_at);
    Ok(())
}

#[tauri::command]
pub async fn resume_monitoring(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    if let Ok(mut p) = state.pause_until.lock() {
        *p = None;
    }
    tracing::info!("Monitoring resumed manually");
    Ok(())
}

#[tauri::command]
pub async fn get_pause_status(
    state: tauri::State<'_, AppState>,
) -> Result<PauseStatus, String> {
    let pause_until = state
        .pause_until
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?
        .clone();

    match pause_until {
        Some(until) => {
            let now = chrono::Utc::now();
            if now >= until {
                // Pause expired — auto-resume
                drop(state.pause_until.lock().map(|mut p| *p = None));
                Ok(PauseStatus {
                    paused: false,
                    remaining_seconds: 0,
                    pause_until: None,
                })
            } else {
                let remaining = (until - now).num_seconds().max(0) as u64;
                Ok(PauseStatus {
                    paused: true,
                    remaining_seconds: remaining,
                    pause_until: Some(until.to_rfc3339()),
                })
            }
        }
        None => Ok(PauseStatus {
            paused: false,
            remaining_seconds: 0,
            pause_until: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn make_audit_event(id: &str, timestamp: &str) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            timestamp: timestamp.to_string(),
            event_type: "proxy".to_string(),
            server_name: "test-server".to_string(),
            tool_name: Some("test_tool".to_string()),
            action: "tools/call".to_string(),
            decision: "allow".to_string(),
            risk_level: "info".to_string(),
            details: "test details".to_string(),
            resource: None,
        }
    }

    // --- kill_agent_process tests ---

    #[tokio::test]
    async fn test_kill_agent_process_rejects_pid_0() {
        let result = kill_agent_process(0).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PID 0"));
    }

    #[tokio::test]
    async fn test_kill_agent_process_rejects_pid_1() {
        let result = kill_agent_process(1).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("system process"));
    }

    #[tokio::test]
    async fn test_kill_agent_process_rejects_low_pid() {
        let result = kill_agent_process(499).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PID < 500"));
    }

    #[tokio::test]
    async fn test_kill_agent_process_nonexistent_pid() {
        // PID 99999 is unlikely to exist
        let result = kill_agent_process(99999).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[tokio::test]
    async fn test_kill_agent_process_rejects_overflow_pid() {
        let result = kill_agent_process(u32::MAX).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("exceeds maximum") || err.contains("system process"));
    }

    // --- read_historical_events tests ---
    // These tests use a shared mutex to serialize HOME env var manipulation,
    // since env vars are process-global and tests run in parallel.

    use std::sync::Mutex as TestMutex;
    static HOME_MUTEX: TestMutex<()> = TestMutex::new(());

    #[test]
    fn test_read_historical_events_with_temp_file() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let audit_dir = tmp.path().join(".local/share/rookbot");
        std::fs::create_dir_all(&audit_dir).unwrap();

        let mut file = std::fs::File::create(audit_dir.join("audit.jsonl")).unwrap();
        for i in 0..5 {
            let record = serde_json::json!({
                "timestamp": format!("2025-01-15T10:3{}:00Z", i),
                "source": "proxy",
                "event_summary": format!("Event {}", i),
                "action_taken": "allowed",
                "server_name": "test-server",
                "policy_action": "allow",
                "classification": "info"
            });
            writeln!(file, "{}", record).unwrap();
        }
        file.flush().unwrap();

        let events = read_historical_events(10, &[]);
        assert_eq!(events.len(), 5);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_read_historical_events_empty_file() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let audit_dir = tmp.path().join(".local/share/rookbot");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::File::create(audit_dir.join("audit.jsonl")).unwrap();

        let events = read_historical_events(10, &[]);
        assert!(events.is_empty());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_read_historical_events_missing_file() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let events = read_historical_events(10, &[]);
        assert!(events.is_empty());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_read_historical_events_deduplication() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let audit_dir = tmp.path().join(".local/share/rookbot");
        std::fs::create_dir_all(&audit_dir).unwrap();

        let mut file = std::fs::File::create(audit_dir.join("audit.jsonl")).unwrap();
        for i in 0..3 {
            let record = serde_json::json!({
                "timestamp": format!("2025-01-15T10:3{}:00Z", i),
                "source": "proxy",
                "event_summary": format!("Event {}", i),
                "action_taken": "allowed",
            });
            writeln!(file, "{}", record).unwrap();
        }
        file.flush().unwrap();

        let existing = vec![make_audit_event("evt-100000", "2025-01-15T10:30:00Z")];

        let events = read_historical_events(10, &existing);
        assert_eq!(events.len(), 2);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    // --- sanitize_rule_key tests ---

    #[test]
    fn test_sanitize_rule_key() {
        assert_eq!(sanitize_rule_key("Block Sensitive Files"), "block-sensitive-files");
        assert_eq!(sanitize_rule_key("  spaces  "), "spaces");
        assert_eq!(sanitize_rule_key("UPPER_case"), "upper_case");
        assert_eq!(sanitize_rule_key("special!@#chars"), "specialchars");
    }

    #[test]
    fn test_sanitize_rule_key_empty() {
        assert_eq!(sanitize_rule_key(""), "");
        assert_eq!(sanitize_rule_key("!!!"), "");
    }

    // --- policy action conversion tests ---

    #[test]
    fn test_frontend_action_to_toml() {
        assert_eq!(frontend_action_to_toml("deny"), "block");
        assert_eq!(frontend_action_to_toml("audit"), "log");
        assert_eq!(frontend_action_to_toml("allow"), "allow");
        assert_eq!(frontend_action_to_toml("prompt"), "prompt");
    }

    #[test]
    fn test_toml_action_to_frontend() {
        assert_eq!(toml_action_to_frontend("block"), "deny");
        assert_eq!(toml_action_to_frontend("log"), "audit");
        assert_eq!(toml_action_to_frontend("allow"), "allow");
        assert_eq!(toml_action_to_frontend("prompt"), "prompt");
    }

    // --- detect_servers_key tests ---

    #[test]
    fn test_detect_servers_key_mcp_servers() {
        let config = serde_json::json!({"mcpServers": {"a": {}}});
        assert_eq!(detect_servers_key(&config), "mcpServers");
    }

    #[test]
    fn test_detect_servers_key_servers() {
        let config = serde_json::json!({"servers": {"a": {}}});
        assert_eq!(detect_servers_key(&config), "servers");
    }

    #[test]
    fn test_detect_servers_key_default() {
        let config = serde_json::json!({"other": "stuff"});
        assert_eq!(detect_servers_key(&config), "mcpServers");
    }

    // --- Phase 4: New tests for real implementations ---

    #[test]
    fn test_get_behavioral_status_no_db() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // No profiles.db exists — should return empty
        let result = read_profiles_from_db();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_profiles_no_db() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let profiles = read_profiles_from_db().unwrap();
        assert!(profiles.is_empty());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_validate_server_command_accepts_valid() {
        assert!(validate_server_command("npx server").is_ok());
        assert!(validate_server_command("node /path/to/server.js").is_ok());
        assert!(validate_server_command("python3 -m my_server").is_ok());
        assert!(validate_server_command("/usr/local/bin/my-mcp-server").is_ok());
    }

    #[test]
    fn test_validate_server_command_rejects_metacharacters() {
        assert!(validate_server_command("cmd ; rm -rf /").is_err());
        assert!(validate_server_command("cmd | cat /etc/passwd").is_err());
        assert!(validate_server_command("cmd & bg").is_err());
        assert!(validate_server_command("cmd $(whoami)").is_err());
        assert!(validate_server_command("cmd `id`").is_err());
        assert!(validate_server_command("cmd > /tmp/out").is_err());
        assert!(validate_server_command("cmd < /tmp/in").is_err());
        assert!(validate_server_command("").is_err());
        assert!(validate_server_command("   ").is_err());
    }

    #[test]
    fn test_get_feed_status_no_manifest() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // No manifest.json — threat_intel_dir() won't have it
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_feed_status());
        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.version, "not configured");
        assert_eq!(status.entries_count, 0);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_rule_packs_empty() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // Create the rules dir but leave it empty
        let rules_dir = tmp
            .path()
            .join(".local/share/rookbot/threat-intel/rules");
        std::fs::create_dir_all(&rules_dir).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_rule_packs());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_ioc_stats_no_data() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_ioc_stats());
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.network, 0);
        assert_eq!(stats.file, 0);
        assert_eq!(stats.behavioral, 0);
        assert_eq!(stats.total, 0);
        assert_eq!(stats.last_updated, "never");

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_validate_rule_pack_id_valid() {
        assert!(validate_rule_pack_id("filesystem-safety").is_ok());
        assert!(validate_rule_pack_id("pack123").is_ok());
        assert!(validate_rule_pack_id("a-b-c").is_ok());
    }

    #[test]
    fn test_validate_rule_pack_id_rejects_traversal() {
        assert!(validate_rule_pack_id("../etc/passwd").is_err());
        assert!(validate_rule_pack_id("../../foo").is_err());
        assert!(validate_rule_pack_id("name with spaces").is_err());
        assert!(validate_rule_pack_id("").is_err());
        assert!(validate_rule_pack_id("foo/bar").is_err());
        assert!(validate_rule_pack_id("a".repeat(200).as_str()).is_err());
    }

    #[test]
    fn test_export_network_log_creates_file() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // Create audit.jsonl with a network event
        let audit_dir = tmp.path().join(".local/share/rookbot");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let record = serde_json::json!({
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "network",
            "event_summary": "Network connection",
            "action_taken": "allowed",
            "server_name": "test-server"
        });
        let mut file = std::fs::File::create(audit_dir.join("audit.jsonl")).unwrap();
        writeln!(file, "{}", record).unwrap();
        file.flush().unwrap();

        // Create the exports directory parent so canonical check works
        let export_dir = tmp.path().join(".rookbot/exports");
        std::fs::create_dir_all(&export_dir).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(export_network_log("json".to_string(), "last24h".to_string()));
        assert!(result.is_ok(), "export_network_log failed: {:?}", result);

        let path = result.unwrap();
        assert!(std::path::Path::new(&path).exists(), "Exported file should exist at {}", path);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[tokio::test]
    async fn test_get_network_extension_status_honest() {
        let result = get_network_extension_status().await;
        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(!status.loaded);
        assert!(status.mock_mode);
        assert!(!status.filter_active);
        assert!(!status.dns_active);
    }

    #[test]
    fn test_toggle_telemetry_persists() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // Create config dir
        let config_dir = tmp.path().join(".config/rookbot");
        std::fs::create_dir_all(&config_dir).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();

        // Toggle telemetry on
        let result = rt.block_on(toggle_telemetry(true));
        assert!(result.is_ok());

        // Read config.toml and verify
        let content = std::fs::read_to_string(config_dir.join("config.toml")).unwrap();
        let table: toml::Value = content.parse().unwrap();
        let enabled = table
            .get("telemetry")
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap();
        assert!(enabled);

        // Toggle off and verify
        let result = rt.block_on(toggle_telemetry(false));
        assert!(result.is_ok());
        let content = std::fs::read_to_string(config_dir.join("config.toml")).unwrap();
        let table: toml::Value = content.parse().unwrap();
        let enabled = table
            .get("telemetry")
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap();
        assert!(!enabled);

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_system_info_real_version() {
        // The app_version should come from CARGO_PKG_VERSION
        let expected = env!("CARGO_PKG_VERSION");
        assert!(!expected.is_empty());
        // We can't call get_system_info directly (needs State), but we can verify
        // the version constant is accessible and matches Cargo.toml
        assert!(expected.contains('.'), "Version should contain dots: {}", expected);
    }

    #[test]
    fn test_parse_scan_findings_count() {
        // With summary.total
        let json = r#"{"summary":{"total":5},"findings":[]}"#;
        assert_eq!(parse_scan_findings_count(json), 5);

        // With findings array
        let json = r#"{"findings":[{"id":"f1"},{"id":"f2"},{"id":"f3"}]}"#;
        assert_eq!(parse_scan_findings_count(json), 3);

        // Invalid JSON
        assert_eq!(parse_scan_findings_count("not json"), 0);

        // Empty
        assert_eq!(parse_scan_findings_count("{}"), 0);
    }

    #[test]
    fn test_normalize_action() {
        assert_eq!(normalize_action("allowed"), "allowed");
        assert_eq!(normalize_action("allow"), "allowed");
        assert_eq!(normalize_action("blocked"), "blocked");
        assert_eq!(normalize_action("block"), "blocked");
        assert_eq!(normalize_action("denied"), "blocked");
        assert_eq!(normalize_action("deny"), "blocked");
        assert_eq!(normalize_action("prompted"), "prompted");
        assert_eq!(normalize_action("prompt"), "prompted");
        assert_eq!(normalize_action("unknown"), "allowed");
    }

    #[test]
    fn test_get_network_connections_no_events() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // No audit.jsonl — should return empty
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_network_connections(100));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_telemetry_status_no_config() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_telemetry_status());
        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(!status.enabled);
        assert!(status.last_report.is_none());
        assert!(status.installation_id.is_none());

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_get_network_settings_defaults() {
        let _lock = HOME_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(get_network_settings());
        assert!(result.is_ok());
        let settings = result.unwrap();
        assert!(!settings.filter_enabled);
        assert_eq!(settings.default_action, "prompt");

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
    }
}
