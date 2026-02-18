use crate::state::*;

// --- Daemon management ---

#[tauri::command]
pub async fn get_daemon_status() -> Result<DaemonStatus, String> {
    Ok(DaemonStatus {
        running: true,
        pid: Some(12345),
        uptime_seconds: Some(3600),
        version: Some("0.10.0".to_string()),
        socket_path: dirs::home_dir()
            .unwrap_or_default()
            .join(".clawdefender/daemon.sock")
            .to_string_lossy()
            .to_string(),
        servers_proxied: 3,
        events_processed: 1247,
    })
}

#[tauri::command]
pub async fn start_daemon() -> Result<(), String> {
    tracing::info!("Starting daemon (mock)");
    Ok(())
}

#[tauri::command]
pub async fn stop_daemon() -> Result<(), String> {
    tracing::info!("Stopping daemon (mock)");
    Ok(())
}

// --- Server management ---

#[tauri::command]
pub async fn detect_mcp_clients() -> Result<Vec<McpClient>, String> {
    Ok(vec![
        McpClient {
            name: "claude-desktop".to_string(),
            display_name: "Claude Desktop".to_string(),
            config_path: dirs::home_dir()
                .unwrap_or_default()
                .join("Library/Application Support/Claude/claude_desktop_config.json")
                .to_string_lossy()
                .to_string(),
            detected: true,
            servers_count: 2,
        },
        McpClient {
            name: "claude-code".to_string(),
            display_name: "Claude Code (CLI)".to_string(),
            config_path: dirs::home_dir()
                .unwrap_or_default()
                .join(".claude/settings.json")
                .to_string_lossy()
                .to_string(),
            detected: true,
            servers_count: 1,
        },
    ])
}

#[tauri::command]
pub async fn list_mcp_servers(client: String) -> Result<Vec<McpServer>, String> {
    let servers = match client.as_str() {
        "claude-desktop" => vec![
            McpServer {
                name: "filesystem".to_string(),
                command: vec!["npx".to_string(), "@modelcontextprotocol/server-filesystem".to_string()],
                wrapped: true,
                status: "running".to_string(),
                events_count: 342,
            },
            McpServer {
                name: "github".to_string(),
                command: vec!["npx".to_string(), "@modelcontextprotocol/server-github".to_string()],
                wrapped: false,
                status: "running".to_string(),
                events_count: 0,
            },
        ],
        _ => vec![
            McpServer {
                name: "everything".to_string(),
                command: vec!["npx".to_string(), "@modelcontextprotocol/server-everything".to_string()],
                wrapped: true,
                status: "running".to_string(),
                events_count: 905,
            },
        ],
    };
    Ok(servers)
}

#[tauri::command]
pub async fn wrap_server(client: String, server: String) -> Result<(), String> {
    tracing::info!("Wrapping server {} for client {} (mock)", server, client);
    Ok(())
}

#[tauri::command]
pub async fn unwrap_server(client: String, server: String) -> Result<(), String> {
    tracing::info!("Unwrapping server {} for client {} (mock)", server, client);
    Ok(())
}

// --- Policy management ---

#[tauri::command]
pub async fn get_policy() -> Result<Policy, String> {
    Ok(Policy {
        name: "default".to_string(),
        version: "1.0.0".to_string(),
        rules: vec![
            PolicyRule {
                name: "block-sensitive-files".to_string(),
                description: "Block access to sensitive configuration files".to_string(),
                action: "deny".to_string(),
                resource: "file".to_string(),
                pattern: "**/.env*".to_string(),
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
        ],
        created_at: "2025-01-15T10:00:00Z".to_string(),
        updated_at: "2025-02-10T14:30:00Z".to_string(),
    })
}

#[tauri::command]
pub async fn update_rule(rule: PolicyRule) -> Result<(), String> {
    tracing::info!("Updating rule: {} (mock)", rule.name);
    Ok(())
}

#[tauri::command]
pub async fn add_rule(rule: PolicyRule) -> Result<(), String> {
    tracing::info!("Adding rule: {} (mock)", rule.name);
    Ok(())
}

#[tauri::command]
pub async fn delete_rule(rule_name: String) -> Result<(), String> {
    tracing::info!("Deleting rule: {} (mock)", rule_name);
    Ok(())
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
            description: "Balanced security - block dangerous operations, audit the rest".to_string(),
            rules_count: 8,
            category: "security".to_string(),
        },
        PolicyTemplate {
            name: "permissive".to_string(),
            description: "Minimal restrictions - audit everything, block only known threats".to_string(),
            rules_count: 4,
            category: "security".to_string(),
        },
        PolicyTemplate {
            name: "developer".to_string(),
            description: "Developer-friendly - allow most operations with audit logging".to_string(),
            rules_count: 6,
            category: "workflow".to_string(),
        },
    ])
}

#[tauri::command]
pub async fn apply_template(name: String) -> Result<(), String> {
    tracing::info!("Applying template: {} (mock)", name);
    Ok(())
}

#[tauri::command]
pub async fn reload_policy() -> Result<(), String> {
    tracing::info!("Reloading policy (mock)");
    Ok(())
}

// --- Event stream ---

#[tauri::command]
pub async fn get_recent_events(count: u32) -> Result<Vec<AuditEvent>, String> {
    let mut events = Vec::new();
    let now = chrono::Utc::now();
    for i in 0..count.min(10) {
        events.push(AuditEvent {
            id: format!("evt-{}", 1000 + i),
            timestamp: (now - chrono::Duration::seconds(i as i64 * 30))
                .to_rfc3339(),
            event_type: if i % 3 == 0 { "tool_call" } else { "resource_access" }.to_string(),
            server_name: if i % 2 == 0 { "filesystem" } else { "github" }.to_string(),
            tool_name: Some(if i % 3 == 0 { "read_file" } else if i % 3 == 1 { "write_file" } else { "list_directory" }.to_string()),
            action: if i % 3 == 0 { "read" } else { "write" }.to_string(),
            decision: if i % 4 == 0 { "denied" } else { "allowed" }.to_string(),
            risk_level: match i % 4 {
                0 => "critical",
                1 => "high",
                2 => "medium",
                _ => "low",
            }.to_string(),
            details: format!("Mock event #{}", i),
            resource: Some(format!("/home/user/project/file{}.txt", i)),
        });
    }
    Ok(events)
}

// --- Behavioral engine ---

#[tauri::command]
pub async fn get_profiles() -> Result<Vec<ServerProfileSummary>, String> {
    Ok(vec![
        ServerProfileSummary {
            server_name: "filesystem".to_string(),
            tools_count: 5,
            total_calls: 342,
            anomaly_score: 0.12,
            status: "normal".to_string(),
            last_activity: chrono::Utc::now().to_rfc3339(),
        },
        ServerProfileSummary {
            server_name: "github".to_string(),
            tools_count: 8,
            total_calls: 156,
            anomaly_score: 0.05,
            status: "normal".to_string(),
            last_activity: (chrono::Utc::now() - chrono::Duration::minutes(15)).to_rfc3339(),
        },
        ServerProfileSummary {
            server_name: "everything".to_string(),
            tools_count: 12,
            total_calls: 905,
            anomaly_score: 0.67,
            status: "anomalous".to_string(),
            last_activity: (chrono::Utc::now() - chrono::Duration::minutes(2)).to_rfc3339(),
        },
    ])
}

#[tauri::command]
pub async fn get_behavioral_status() -> Result<BehavioralStatus, String> {
    Ok(BehavioralStatus {
        enabled: true,
        profiles_count: 3,
        total_anomalies: 7,
        learning_servers: 1,
        monitoring_servers: 2,
    })
}

// --- Guards ---

#[tauri::command]
pub async fn list_guards() -> Result<Vec<GuardSummary>, String> {
    Ok(vec![
        GuardSummary {
            name: "secrets-guard".to_string(),
            guard_type: "content".to_string(),
            enabled: true,
            triggers_count: 3,
            last_triggered: Some((chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339()),
            description: "Detects and blocks exposure of secrets and API keys".to_string(),
        },
        GuardSummary {
            name: "path-traversal-guard".to_string(),
            guard_type: "filesystem".to_string(),
            enabled: true,
            triggers_count: 1,
            last_triggered: Some((chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339()),
            description: "Prevents path traversal attacks in file operations".to_string(),
        },
        GuardSummary {
            name: "rate-limit-guard".to_string(),
            guard_type: "rate".to_string(),
            enabled: true,
            triggers_count: 0,
            last_triggered: None,
            description: "Rate limits tool calls to prevent abuse".to_string(),
        },
    ])
}

// --- Scanner ---

#[tauri::command]
pub async fn start_scan(command: Vec<String>, modules: Vec<String>) -> Result<String, String> {
    tracing::info!("Starting scan with command {:?}, modules {:?} (mock)", command, modules);
    Ok("scan-001".to_string())
}

#[tauri::command]
pub async fn get_scan_progress(scan_id: String) -> Result<ScanProgress, String> {
    Ok(ScanProgress {
        scan_id,
        status: "completed".to_string(),
        progress_percent: 100.0,
        modules_completed: 4,
        modules_total: 4,
        findings_count: 2,
        current_module: None,
    })
}

// --- System health ---

#[tauri::command]
pub async fn run_doctor() -> Result<Vec<DoctorCheck>, String> {
    Ok(vec![
        DoctorCheck {
            name: "Daemon Process".to_string(),
            status: "pass".to_string(),
            message: "Daemon is running (PID 12345)".to_string(),
            fix_suggestion: None,
        },
        DoctorCheck {
            name: "Socket Connection".to_string(),
            status: "pass".to_string(),
            message: "Successfully connected to daemon socket".to_string(),
            fix_suggestion: None,
        },
        DoctorCheck {
            name: "Policy File".to_string(),
            status: "pass".to_string(),
            message: "Policy file is valid".to_string(),
            fix_suggestion: None,
        },
        DoctorCheck {
            name: "MCP Clients".to_string(),
            status: "warn".to_string(),
            message: "1 of 2 detected clients have unwrapped servers".to_string(),
            fix_suggestion: Some("Run 'Wrap All' to protect all MCP servers".to_string()),
        },
    ])
}

#[tauri::command]
pub async fn get_system_info() -> Result<SystemInfo, String> {
    let home = dirs::home_dir().unwrap_or_default();
    Ok(SystemInfo {
        os: "macOS".to_string(),
        os_version: "14.0".to_string(),
        arch: std::env::consts::ARCH.to_string(),
        daemon_version: Some("0.10.0".to_string()),
        app_version: "0.10.0".to_string(),
        config_dir: home.join(".clawdefender").to_string_lossy().to_string(),
        log_dir: home.join(".clawdefender/logs").to_string_lossy().to_string(),
    })
}

// --- Prompt handling ---

#[tauri::command]
pub async fn respond_to_prompt(prompt_id: String, decision: String) -> Result<(), String> {
    tracing::info!("Responding to prompt {}: {} (mock)", prompt_id, decision);
    Ok(())
}

// --- Onboarding ---

#[tauri::command]
pub async fn check_onboarding_complete() -> Result<bool, String> {
    Ok(false)
}

#[tauri::command]
pub async fn complete_onboarding() -> Result<(), String> {
    tracing::info!("Completing onboarding (mock)");
    Ok(())
}

// --- Settings ---

#[tauri::command]
pub async fn get_settings() -> Result<AppSettings, String> {
    Ok(AppSettings {
        theme: "dark".to_string(),
        notifications_enabled: true,
        auto_start_daemon: true,
        minimize_to_tray: true,
        log_level: "info".to_string(),
        prompt_timeout_seconds: 30,
        event_retention_days: 30,
    })
}

#[tauri::command]
pub async fn update_settings(settings: AppSettings) -> Result<(), String> {
    tracing::info!("Updating settings: theme={} (mock)", settings.theme);
    Ok(())
}

// --- Threat Intelligence ---

#[tauri::command]
pub async fn get_feed_status() -> Result<FeedStatus, String> {
    Ok(FeedStatus {
        version: "1.0.0".to_string(),
        last_updated: chrono::Utc::now().to_rfc3339(),
        next_check: (chrono::Utc::now() + chrono::Duration::hours(6)).to_rfc3339(),
        entries_count: 247,
    })
}

#[tauri::command]
pub async fn force_feed_update() -> Result<String, String> {
    tracing::info!("Force feed update (mock)");
    Ok("Feed updated to v1.0.1".to_string())
}

#[tauri::command]
pub async fn get_blocklist_matches() -> Result<Vec<BlocklistAlert>, String> {
    Ok(vec![])
}

#[tauri::command]
pub async fn get_rule_packs() -> Result<Vec<RulePackInfo>, String> {
    Ok(vec![
        RulePackInfo {
            id: "filesystem-safety".to_string(),
            name: "Filesystem Safety".to_string(),
            installed: true,
            version: "1.2.0".to_string(),
            rule_count: 8,
            description: "Rules for safe filesystem operations".to_string(),
        },
        RulePackInfo {
            id: "network-security".to_string(),
            name: "Network Security".to_string(),
            installed: false,
            version: "1.0.0".to_string(),
            rule_count: 12,
            description: "Rules for network access control".to_string(),
        },
        RulePackInfo {
            id: "data-exfiltration".to_string(),
            name: "Data Exfiltration Prevention".to_string(),
            installed: true,
            version: "1.1.0".to_string(),
            rule_count: 6,
            description: "Prevents unauthorized data transfer".to_string(),
        },
    ])
}

#[tauri::command]
pub async fn install_rule_pack(id: String) -> Result<(), String> {
    tracing::info!("Installing rule pack {} (mock)", id);
    Ok(())
}

#[tauri::command]
pub async fn uninstall_rule_pack(id: String) -> Result<(), String> {
    tracing::info!("Uninstalling rule pack {} (mock)", id);
    Ok(())
}

#[tauri::command]
pub async fn get_ioc_stats() -> Result<IoCStats, String> {
    Ok(IoCStats {
        network: 45,
        file: 128,
        behavioral: 34,
        total: 207,
        last_updated: chrono::Utc::now().to_rfc3339(),
    })
}

#[tauri::command]
pub async fn get_telemetry_status() -> Result<TelemetryStatus, String> {
    Ok(TelemetryStatus {
        enabled: false,
        last_report: None,
        installation_id: None,
    })
}

#[tauri::command]
pub async fn toggle_telemetry(enabled: bool) -> Result<(), String> {
    tracing::info!("Telemetry toggled to {} (mock)", enabled);
    Ok(())
}

#[tauri::command]
pub async fn get_telemetry_preview() -> Result<TelemetryPreview, String> {
    Ok(TelemetryPreview {
        categories: vec![
            "Blocklist match counts".to_string(),
            "Anomaly score distributions".to_string(),
            "IoC match rates by category".to_string(),
            "Kill chain detection triggers".to_string(),
            "Scanner finding categories".to_string(),
        ],
        description: "All data is anonymous and aggregated. No file paths, server names, API keys, or personal information is collected.".to_string(),
    })
}

#[tauri::command]
pub async fn check_server_reputation(name: String) -> Result<ReputationResult, String> {
    Ok(ReputationResult {
        server_name: name,
        clean: true,
        matches: vec![],
    })
}

// --- Network Extension ---

#[tauri::command]
pub async fn get_network_extension_status() -> Result<NetworkExtensionStatus, String> {
    Ok(NetworkExtensionStatus {
        loaded: true,
        filter_active: true,
        dns_active: true,
        filtering_count: 847,
        mock_mode: true,
    })
}

#[tauri::command]
pub async fn activate_network_extension() -> Result<String, String> {
    tracing::info!("Activating network extension (mock)");
    Ok("Network extension activated successfully (mock mode)".to_string())
}

#[tauri::command]
pub async fn deactivate_network_extension() -> Result<String, String> {
    tracing::info!("Deactivating network extension (mock)");
    Ok("Network extension deactivated".to_string())
}

#[tauri::command]
pub async fn get_network_settings() -> Result<NetworkSettings, String> {
    Ok(NetworkSettings {
        filter_enabled: true,
        dns_enabled: true,
        filter_all_processes: false,
        default_action: "prompt".to_string(),
        prompt_timeout: 30,
        block_private_ranges: false,
        block_doh: true,
        log_dns: true,
    })
}

#[tauri::command]
pub async fn update_network_settings(settings: NetworkSettings) -> Result<(), String> {
    tracing::info!("Updating network settings: filter_enabled={}, dns_enabled={} (mock)", settings.filter_enabled, settings.dns_enabled);
    Ok(())
}

// --- Network Connection Log ---

#[tauri::command]
pub async fn get_network_connections(limit: u32) -> Result<Vec<NetworkConnectionEvent>, String> {
    let now = chrono::Utc::now();
    let mock_connections: Vec<NetworkConnectionEvent> = (0..limit.min(20))
        .map(|i| {
            let (action, reason) = match i % 5 {
                0 => ("blocked", "IoC match: known C2 domain"),
                1 => ("prompted", "Destination unknown to server profile"),
                _ => ("allowed", "Rule 'allow_https': HTTPS traffic allowed"),
            };
            let (dest_ip, dest_domain, port, protocol, tls) = match i % 4 {
                0 => ("93.184.216.34", Some("example.com"), 443u16, "tcp", true),
                1 => ("140.82.121.4", Some("api.github.com"), 443, "tcp", true),
                2 => ("8.8.8.8", None, 53, "udp", false),
                _ => ("172.217.14.206", Some("googleapis.com"), 443, "tcp", true),
            };
            let server = match i % 3 {
                0 => Some("filesystem"),
                1 => Some("github"),
                _ => Some("everything"),
            };
            NetworkConnectionEvent {
                id: format!("net-{}", 2000 + i),
                timestamp: (now - chrono::Duration::seconds(i as i64 * 45))
                    .to_rfc3339(),
                pid: 10000 + (i % 5),
                process_name: server.unwrap_or("unknown").to_string(),
                server_name: server.map(|s| s.to_string()),
                destination_ip: dest_ip.to_string(),
                destination_port: port,
                destination_domain: dest_domain.map(|d| d.to_string()),
                protocol: protocol.to_string(),
                tls,
                action: action.to_string(),
                reason: reason.to_string(),
                rule: if action == "allowed" {
                    Some("allow_https".to_string())
                } else {
                    None
                },
                ioc_match: action == "blocked",
                anomaly_score: if i % 5 == 1 { Some(0.72) } else { None },
                behavioral: if i % 5 == 1 {
                    Some("Server has never networked before".to_string())
                } else {
                    None
                },
                kill_chain: if action == "blocked" {
                    Some("C2 Communication".to_string())
                } else {
                    None
                },
                bytes_sent: (i as u64 + 1) * 256,
                bytes_received: (i as u64 + 1) * 1024,
                duration_ms: (i as u64 + 1) * 50,
            }
        })
        .collect();
    Ok(mock_connections)
}

#[tauri::command]
pub async fn get_network_summary() -> Result<NetworkSummaryData, String> {
    Ok(NetworkSummaryData {
        total_allowed: 47,
        total_blocked: 2,
        total_prompted: 1,
        top_destinations: vec![
            DestinationCount {
                destination: "api.github.com".to_string(),
                count: 18,
            },
            DestinationCount {
                destination: "googleapis.com".to_string(),
                count: 12,
            },
            DestinationCount {
                destination: "example.com".to_string(),
                count: 8,
            },
            DestinationCount {
                destination: "cdn.jsdelivr.net".to_string(),
                count: 5,
            },
            DestinationCount {
                destination: "registry.npmjs.org".to_string(),
                count: 4,
            },
        ],
        period: "last_24h".to_string(),
    })
}

#[tauri::command]
pub async fn get_network_traffic_by_server() -> Result<Vec<ServerTrafficData>, String> {
    Ok(vec![
        ServerTrafficData {
            server_name: "filesystem".to_string(),
            total_connections: 15,
            connections_allowed: 14,
            connections_blocked: 1,
            connections_prompted: 0,
            bytes_sent: 4096,
            bytes_received: 32768,
            unique_destinations: 3,
            period: "last_24h".to_string(),
        },
        ServerTrafficData {
            server_name: "github".to_string(),
            total_connections: 28,
            connections_allowed: 27,
            connections_blocked: 0,
            connections_prompted: 1,
            bytes_sent: 12288,
            bytes_received: 98304,
            unique_destinations: 5,
            period: "last_24h".to_string(),
        },
        ServerTrafficData {
            server_name: "everything".to_string(),
            total_connections: 7,
            connections_allowed: 6,
            connections_blocked: 1,
            connections_prompted: 0,
            bytes_sent: 2048,
            bytes_received: 8192,
            unique_destinations: 4,
            period: "last_24h".to_string(),
        },
    ])
}

#[tauri::command]
pub async fn export_network_log(format: String, range: String) -> Result<String, String> {
    let home = dirs::home_dir().unwrap_or_default();
    let filename = format!(
        "clawdefender-network-log-{}.{}",
        range,
        if format == "csv" { "csv" } else { "json" }
    );
    let path = home.join(".clawdefender/exports").join(&filename);
    tracing::info!(
        "Exporting network log as {} for range {} (mock) -> {}",
        format,
        range,
        path.display()
    );
    Ok(path.to_string_lossy().to_string())
}

mod dirs {
    use std::path::PathBuf;
    pub fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}
