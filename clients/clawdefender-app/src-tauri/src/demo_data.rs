//! Demo mode mock data factory.
//!
//! When `[ui] demo_mode = true` in config.toml, data-fetching commands
//! return mock data from this module so every page looks populated.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::alerts::engine::{AlertAction, AlertStatus, AlertType, IntelligentAlert};
use crate::alerts::lifecycle::AlertStats;
use crate::commands::SensorHealth;
use crate::state::*;

// ── Cached demo mode flag ────────────────────────────────────────

static DEMO_MODE: AtomicBool = AtomicBool::new(false);

/// Call this on startup and whenever settings are saved to refresh the cached flag.
pub fn refresh_demo_mode() {
    let enabled = read_demo_mode_from_config();
    DEMO_MODE.store(enabled, Ordering::Relaxed);
}

/// Fast check — no I/O, just reads the atomic.
pub fn is_demo_mode() -> bool {
    DEMO_MODE.load(Ordering::Relaxed)
}

fn read_demo_mode_from_config() -> bool {
    let home = dirs::home_dir().unwrap_or_default();
    let path = home.join(".config/rookbot/config.toml");
    if !path.exists() {
        return false;
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|c| c.parse::<toml::Value>().ok())
        .and_then(|t| t.get("ui")?.get("demo_mode")?.as_bool())
        .unwrap_or(false)
}

// ── Mock factories ───────────────────────────────────────────────

pub fn mock_daemon_status() -> DaemonStatus {
    DaemonStatus {
        running: true,
        pid: Some(42001),
        uptime_seconds: Some(86400),
        version: Some("1.4.0".to_string()),
        socket_path: "/tmp/rookbot.sock".to_string(),
        servers_proxied: 5,
        events_processed: 12_847,
    }
}

pub fn mock_protection_score() -> serde_json::Value {
    serde_json::json!({
        "total": 87,
        "label": "Protected",
        "color": "green",
        "computed_at": chrono::Utc::now().to_rfc3339(),
        "change_from_last": 3,
        "factors": [
            { "id": "tool_coverage", "name": "Tool Coverage", "description": "Coverage of detected MCP servers by monitoring", "current_points": 25, "max_points": 25, "status": "full", "details": "All 5 MCP servers monitored", "fix_actions": [] },
            { "id": "threat_intel", "name": "Threat Intelligence", "description": "Active threat intelligence feed status", "current_points": 20, "max_points": 20, "status": "full", "details": "Feed v2.8 — updated 2h ago", "fix_actions": [] },
            { "id": "ai_analysis", "name": "AI Analysis", "description": "On-device AI model for deep security analysis", "current_points": 15, "max_points": 15, "status": "full", "details": "Heuristic Analyzer active", "fix_actions": [] },
            { "id": "visibility", "name": "System Visibility", "description": "OS-level security monitoring coverage", "current_points": 15, "max_points": 15, "status": "full", "details": "eslogger + FSEvents active", "fix_actions": [] },
            { "id": "alerts", "name": "Unresolved Alerts", "description": "Pending security alerts requiring attention", "current_points": 2, "max_points": 15, "status": "partial", "details": "5 unresolved alerts", "fix_actions": [{ "label": "View Alerts", "action_type": "navigate", "target": "/alerts" }] },
            { "id": "config", "name": "Config Health", "description": "Configuration correctness and security posture", "current_points": 10, "max_points": 10, "status": "full", "details": "Configuration is healthy", "fix_actions": [] }
        ]
    })
}

pub fn mock_alerts() -> Vec<IntelligentAlert> {
    let now = chrono::Utc::now().to_rfc3339();
    vec![
        IntelligentAlert {
            id: "demo-alert-1".to_string(),
            alert_type: AlertType::KillChain,
            severity: "critical".to_string(),
            status: AlertStatus::Active,
            title: "Credential exfiltration attempt detected".to_string(),
            description: "filesystem_server read ~/.ssh/id_rsa then attempted outbound connection to unknown host".to_string(),
            recommendation: "Block the server and review its configuration".to_string(),
            source_events: vec!["evt-1001".to_string(), "evt-1002".to_string()],
            server_name: Some("filesystem_server".to_string()),
            created_at: now.clone(),
            updated_at: now.clone(),
            resolved_at: None,
            resolved_by: None,
            dedup_key: "demo-dedup-1".to_string(),
            dedup_count: 1,
            actions: vec![
                AlertAction { id: "block".to_string(), label: "Block Server".to_string(), action_type: "block_server".to_string(), params: None },
                AlertAction { id: "dismiss".to_string(), label: "Dismiss".to_string(), action_type: "dismiss".to_string(), params: None },
            ],
            kill_chain: None,
            ai_summary: Some("This pattern matches a credential theft attack chain.".to_string()),
            ai_risk_level: Some("critical".to_string()),
            ai_confidence: Some(0.95),
            ai_recommendation: Some("Block immediately and investigate".to_string()),
        },
        IntelligentAlert {
            id: "demo-alert-2".to_string(),
            alert_type: AlertType::Anomaly,
            severity: "high".to_string(),
            status: AlertStatus::Active,
            title: "New outbound connection to unknown host".to_string(),
            description: "brave-search MCP server connected to 45.33.32.156:8443 — not in known destinations".to_string(),
            recommendation: "Investigate the destination IP and consider adding it to the blocklist".to_string(),
            source_events: vec!["evt-1003".to_string()],
            server_name: Some("brave-search".to_string()),
            created_at: now.clone(),
            updated_at: now.clone(),
            resolved_at: None,
            resolved_by: None,
            dedup_key: "demo-dedup-2".to_string(),
            dedup_count: 1,
            actions: vec![
                AlertAction { id: "block".to_string(), label: "Block IP".to_string(), action_type: "block_destination".to_string(), params: None },
                AlertAction { id: "dismiss".to_string(), label: "Dismiss".to_string(), action_type: "dismiss".to_string(), params: None },
            ],
            kill_chain: None,
            ai_summary: None,
            ai_risk_level: Some("high".to_string()),
            ai_confidence: None,
            ai_recommendation: None,
        },
        IntelligentAlert {
            id: "demo-alert-3".to_string(),
            alert_type: AlertType::Anomaly,
            severity: "medium".to_string(),
            status: AlertStatus::Active,
            title: "Unusual file access pattern from filesystem_server".to_string(),
            description: "48 file reads in 30 seconds across multiple directories — above baseline".to_string(),
            recommendation: "Review if this burst is expected behavior for the current task".to_string(),
            source_events: vec!["evt-1004".to_string(), "evt-1005".to_string()],
            server_name: Some("filesystem_server".to_string()),
            created_at: now.clone(),
            updated_at: now.clone(),
            resolved_at: None,
            resolved_by: None,
            dedup_key: "demo-dedup-3".to_string(),
            dedup_count: 3,
            actions: vec![
                AlertAction { id: "dismiss".to_string(), label: "Dismiss".to_string(), action_type: "dismiss".to_string(), params: None },
            ],
            kill_chain: None,
            ai_summary: None,
            ai_risk_level: Some("medium".to_string()),
            ai_confidence: None,
            ai_recommendation: None,
        },
        IntelligentAlert {
            id: "demo-alert-4".to_string(),
            alert_type: AlertType::Correlation,
            severity: "medium".to_string(),
            status: AlertStatus::Active,
            title: "MCP file read correlated with OS Open event".to_string(),
            description: "readFile(\"/Users/demo/project/.env\") matched eslogger open event — confidence 0.94".to_string(),
            recommendation: "Verify that .env access is intentional for this task".to_string(),
            source_events: vec!["evt-1006".to_string()],
            server_name: Some("filesystem_server".to_string()),
            created_at: now.clone(),
            updated_at: now.clone(),
            resolved_at: None,
            resolved_by: None,
            dedup_key: "demo-dedup-4".to_string(),
            dedup_count: 1,
            actions: vec![
                AlertAction { id: "dismiss".to_string(), label: "Dismiss".to_string(), action_type: "dismiss".to_string(), params: None },
            ],
            kill_chain: None,
            ai_summary: None,
            ai_risk_level: Some("medium".to_string()),
            ai_confidence: None,
            ai_recommendation: None,
        },
        IntelligentAlert {
            id: "demo-alert-5".to_string(),
            alert_type: AlertType::Discovery,
            severity: "info".to_string(),
            status: AlertStatus::Active,
            title: "New MCP server detected: sequential-thinking".to_string(),
            description: "A new MCP server 'sequential-thinking' was added to Claude Desktop config".to_string(),
            recommendation: "Review the server configuration and set appropriate trust level".to_string(),
            source_events: vec![],
            server_name: Some("sequential-thinking".to_string()),
            created_at: now.clone(),
            updated_at: now.clone(),
            resolved_at: None,
            resolved_by: None,
            dedup_key: "demo-dedup-5".to_string(),
            dedup_count: 1,
            actions: vec![
                AlertAction { id: "review".to_string(), label: "Review".to_string(), action_type: "navigate".to_string(), params: Some(serde_json::json!({"target": "/tools"})) },
                AlertAction { id: "dismiss".to_string(), label: "Dismiss".to_string(), action_type: "dismiss".to_string(), params: None },
            ],
            kill_chain: None,
            ai_summary: None,
            ai_risk_level: Some("info".to_string()),
            ai_confidence: None,
            ai_recommendation: None,
        },
    ]
}

pub fn mock_alert_stats() -> AlertStats {
    AlertStats {
        total_active: 5,
        dangerous_count: 1,
        suspicious_count: 1,
        unusual_count: 2,
        info_count: 1,
        resolved_this_week: 8,
        blocked_this_week: 3,
        avg_resolution_minutes: 12.5,
    }
}

pub fn mock_humanized_events() -> Vec<serde_json::Value> {
    let base_time = chrono::Utc::now();
    let events_data = vec![
        ("Claude Desktop", "filesystem_server", "readFile", "/Users/demo/project/src/index.ts", "Allowed", "low", "mcp"),
        ("Cursor", "brave-search", "search", "rust async patterns", "Allowed", "low", "mcp"),
        ("VS Code", "github-mcp", "createPullRequest", "feat: add auth middleware", "Prompted", "medium", "mcp"),
        ("Claude Desktop", "filesystem_server", "writeFile", "/Users/demo/project/src/auth.ts", "Allowed", "low", "mcp"),
        ("Windsurf", "filesystem_server", "listDirectory", "/Users/demo/.ssh", "Blocked", "high", "mcp"),
        ("System", "node", "Executed node", "/usr/local/bin/node --max-old-space-size=4096", "Allowed", "low", "os"),
        ("System", "Claude Desktop", "Connected to api.anthropic.com:443", "", "Allowed", "low", "os"),
        ("Cursor", "sequential-thinking", "think", "Planning authentication flow", "Allowed", "low", "mcp"),
        ("Claude Code", "filesystem_server", "readFile", "/Users/demo/project/package.json", "Allowed", "low", "mcp"),
        ("System", "Code Helper", "Opened /Users/demo/project/tsconfig.json", "", "Allowed", "low", "os"),
        ("Claude Desktop", "filesystem_server", "readFile", "/Users/demo/project/.env", "Prompted", "medium", "mcp"),
        ("System", "python3", "Executed python3", "/usr/bin/python3 -m pytest", "Allowed", "medium", "os"),
        ("Cursor", "brave-search", "search", "Next.js 14 server actions", "Allowed", "low", "mcp"),
        ("VS Code", "github-mcp", "listPullRequests", "owner/repo", "Allowed", "low", "mcp"),
        ("Claude Desktop", "memory-server", "saveMemory", "Project architecture notes", "Allowed", "low", "mcp"),
    ];

    events_data
        .iter()
        .enumerate()
        .map(|(i, (client, server, tool, resource, decision, risk, source))| {
            let ts = base_time - chrono::Duration::seconds((i as i64) * 45);
            let one_liner = if *source == "os" {
                tool.to_string()
            } else {
                format!("{server} — {tool}(\"{resource}\")")
            };
            let action_taken = match *decision {
                "Blocked" => "Blocked",
                "Prompted" => "Prompted",
                _ => "Allowed",
            };
            serde_json::json!({
                "event_id": format!("demo-evt-{}", i),
                "one_liner": one_liner,
                "expanded_explanation": format!("{client} → {server} called {tool} on {resource}"),
                "risk_level": risk,
                "action_taken": action_taken,
                "server_display_name": server,
                "server_name": server,
                "client_name": client,
                "tool_name": tool,
                "timestamp": ts.to_rfc3339(),
                "source_type": source,
                "is_notable": *risk == "high" || *risk == "critical" || *decision == "Blocked",
                "educational_aside": null,
                "behavioral_context": "",
                "risk_explanation": "",
                "action_reason": "",
                "correlation_id": null,
                "kill_chain_id": null,
                "raw_event": {
                    "id": format!("demo-evt-{}", i),
                    "timestamp": ts.to_rfc3339(),
                    "event_type": source,
                    "server_name": server,
                    "tool_name": tool,
                    "action": tool,
                    "decision": decision.to_lowercase(),
                    "risk_level": risk,
                    "details": format!("{client} → {server} {tool}"),
                    "resource": resource,
                }
            })
        })
        .collect()
}

pub fn mock_recent_events() -> Vec<AuditEvent> {
    let base_time = chrono::Utc::now();
    (0..30)
        .map(|i| {
            let ts = base_time - chrono::Duration::seconds(i * 30);
            let (server, tool, action, decision, risk) = match i % 6 {
                0 => ("filesystem_server", Some("readFile".to_string()), "readFile /src/main.rs", "allowed", "low"),
                1 => ("brave-search", Some("search".to_string()), "search \"rust patterns\"", "allowed", "low"),
                2 => ("github-mcp", Some("createPR".to_string()), "createPullRequest", "prompted", "medium"),
                3 => ("filesystem_server", Some("writeFile".to_string()), "writeFile /tmp/output.json", "allowed", "low"),
                4 => ("sequential-thinking", Some("think".to_string()), "think", "allowed", "low"),
                _ => ("filesystem_server", Some("listDir".to_string()), "listDirectory ~/.ssh", "blocked", "high"),
            };
            AuditEvent {
                id: format!("demo-raw-{}", i),
                timestamp: ts.to_rfc3339(),
                event_type: "proxy".to_string(),
                server_name: server.to_string(),
                tool_name: tool,
                action: action.to_string(),
                decision: decision.to_string(),
                risk_level: risk.to_string(),
                details: format!("{} — {}", server, action),
                resource: None,
            }
        })
        .collect()
}

pub fn mock_tool_cards() -> Vec<serde_json::Value> {
    serde_json::json!([
        {
            "client_id": "claude",
            "client_name": "Claude Desktop",
            "installed": true,
            "running": true,
            "config_path": "~/Library/Application Support/Claude/claude_desktop_config.json",
            "servers": [
                { "name": "filesystem_server", "wrapped": true, "status": "active", "tool_calls_today": 234 },
                { "name": "memory-server", "wrapped": true, "status": "active", "tool_calls_today": 12 },
                { "name": "sequential-thinking", "wrapped": false, "status": "active", "tool_calls_today": 45 }
            ],
            "total_events_today": 291,
            "trust_level": "trusted",
            "risk_summary": "low"
        },
        {
            "client_id": "cursor",
            "client_name": "Cursor",
            "installed": true,
            "running": true,
            "config_path": "~/.cursor/mcp.json",
            "servers": [
                { "name": "brave-search", "wrapped": true, "status": "active", "tool_calls_today": 89 },
                { "name": "sequential-thinking", "wrapped": true, "status": "active", "tool_calls_today": 67 }
            ],
            "total_events_today": 156,
            "trust_level": "trusted",
            "risk_summary": "low"
        },
        {
            "client_id": "vscode",
            "client_name": "VS Code",
            "installed": true,
            "running": true,
            "config_path": "~/.vscode/mcp.json",
            "servers": [
                { "name": "github-mcp", "wrapped": true, "status": "active", "tool_calls_today": 34 }
            ],
            "total_events_today": 34,
            "trust_level": "trusted",
            "risk_summary": "low"
        },
        {
            "client_id": "windsurf",
            "client_name": "Windsurf",
            "installed": true,
            "running": false,
            "config_path": "~/.windsurf/mcp.json",
            "servers": [
                { "name": "filesystem_server", "wrapped": true, "status": "inactive", "tool_calls_today": 0 }
            ],
            "total_events_today": 0,
            "trust_level": "default",
            "risk_summary": "none"
        },
        {
            "client_id": "claude-code",
            "client_name": "Claude Code",
            "installed": true,
            "running": true,
            "config_path": "~/.claude/settings.json",
            "servers": [
                { "name": "filesystem_server", "wrapped": true, "status": "active", "tool_calls_today": 178 }
            ],
            "total_events_today": 178,
            "trust_level": "trusted",
            "risk_summary": "low"
        }
    ]).as_array().unwrap().clone()
}

pub fn mock_mcp_clients() -> Vec<McpClient> {
    vec![
        McpClient {
            name: "claude".to_string(),
            display_name: "Claude Desktop".to_string(),
            config_path: "~/Library/Application Support/Claude/claude_desktop_config.json".to_string(),
            detected: true,
            servers_count: 3,
        },
        McpClient {
            name: "cursor".to_string(),
            display_name: "Cursor".to_string(),
            config_path: "~/.cursor/mcp.json".to_string(),
            detected: true,
            servers_count: 2,
        },
        McpClient {
            name: "vscode".to_string(),
            display_name: "VS Code".to_string(),
            config_path: "~/.vscode/mcp.json".to_string(),
            detected: true,
            servers_count: 1,
        },
    ]
}

pub fn mock_mcp_servers() -> Vec<McpServer> {
    vec![
        McpServer { name: "filesystem_server".to_string(), command: vec!["npx".to_string(), "-y".to_string(), "@anthropic/filesystem-server".to_string()], wrapped: true, status: "active".to_string(), events_count: 412 },
        McpServer { name: "brave-search".to_string(), command: vec!["npx".to_string(), "-y".to_string(), "@anthropic/brave-search-server".to_string()], wrapped: true, status: "active".to_string(), events_count: 89 },
        McpServer { name: "github-mcp".to_string(), command: vec!["npx".to_string(), "-y".to_string(), "@anthropic/github-mcp-server".to_string()], wrapped: true, status: "active".to_string(), events_count: 34 },
        McpServer { name: "memory-server".to_string(), command: vec!["npx".to_string(), "-y".to_string(), "@anthropic/memory-server".to_string()], wrapped: true, status: "active".to_string(), events_count: 12 },
        McpServer { name: "sequential-thinking".to_string(), command: vec!["npx".to_string(), "-y".to_string(), "@anthropic/sequential-thinking".to_string()], wrapped: false, status: "active".to_string(), events_count: 112 },
        McpServer { name: "postgres-server".to_string(), command: vec!["npx".to_string(), "-y".to_string(), "@anthropic/postgres-server".to_string()], wrapped: true, status: "inactive".to_string(), events_count: 0 },
        McpServer { name: "puppeteer".to_string(), command: vec!["npx".to_string(), "-y".to_string(), "@anthropic/puppeteer-server".to_string()], wrapped: true, status: "inactive".to_string(), events_count: 0 },
        McpServer { name: "sqlite-server".to_string(), command: vec!["npx".to_string(), "-y".to_string(), "@anthropic/sqlite-server".to_string()], wrapped: false, status: "inactive".to_string(), events_count: 0 },
    ]
}

pub fn mock_behavioral_status() -> BehavioralStatus {
    BehavioralStatus {
        enabled: true,
        profiles_count: 4,
        total_anomalies: 3,
        learning_servers: 2,
        monitoring_servers: 4,
    }
}

pub fn mock_sensor_health() -> SensorHealth {
    SensorHealth {
        fda_granted: true,
        eslogger_available: true,
        os_version_ok: true,
        daemon_running: true,
        events_flowing: true,
    }
}

pub fn mock_performance_stats() -> PerformanceStats {
    PerformanceStats {
        cpu_percent: 2.3,
        memory_bytes: 47_185_920, // ~45MB
        memory_model_bytes: 0,
        memory_buffers_bytes: 8_388_608,
        events_per_sec: 12.4,
        events_total_per_sec: 18.7,
        events_sampled_percent: 100.0,
        disk_writes_per_sec: 1.2,
    }
}

pub fn mock_conversations() -> String {
    serde_json::json!([
        {
            "id": "demo-conv-1",
            "title": "How do I block a specific MCP server?",
            "preview": "You can block a server by navigating to My Tools...",
            "created_at": "2025-01-15T10:30:00Z",
            "updated_at": "2025-01-15T10:35:00Z",
            "message_count": 4
        },
        {
            "id": "demo-conv-2",
            "title": "Explain the kill chain alert",
            "preview": "A kill chain alert means RookBot detected a sequence...",
            "created_at": "2025-01-14T14:20:00Z",
            "updated_at": "2025-01-14T14:25:00Z",
            "message_count": 6
        }
    ]).to_string()
}

// ── Agent Transparency mock data ─────────────────────────────────

pub fn mock_dashboard_summary() -> serde_json::Value {
    let now = chrono::Utc::now();
    serde_json::json!({
        "activity_summary": {
            "total": 1247,
            "by_type": {
                "triage": 523,
                "investigation": 312,
                "response": 198,
                "monitoring": 214
            },
            "by_server": {
                "filesystem_server": 456,
                "brave-search": 234,
                "github-mcp": 189,
                "sequential-thinking": 178,
                "memory-server": 190
            },
            "last_24h": 87,
            "last_7d": 412
        },
        "cost_summary": {
            "total_operations": 3421,
            "total_duration_ms": 245_800,
            "by_type": {
                "triage": { "count": 1580, "total_duration_ms": 94_800, "avg_duration_ms": 60 },
                "investigation": { "count": 890, "total_duration_ms": 89_000, "avg_duration_ms": 100 },
                "response": { "count": 512, "total_duration_ms": 35_840, "avg_duration_ms": 70 },
                "correlation": { "count": 439, "total_duration_ms": 26_160, "avg_duration_ms": 60 }
            },
            "last_24h_operations": 156,
            "last_7d_operations": 892,
            "avg_duration_ms": 72
        },
        "accuracy_metrics": {
            "total_assessments": 847,
            "correct": 724,
            "incorrect": 123,
            "accuracy_rate": 0.855,
            "by_type": {
                "triage": { "total": 412, "correct": 367, "accuracy_rate": 0.891 },
                "alert_relevance": { "total": 235, "correct": 198, "accuracy_rate": 0.843 },
                "investigation": { "total": 200, "correct": 159, "accuracy_rate": 0.795 }
            },
            "trend": "improving"
        },
        "pattern_stats": {
            "total_learned": 156,
            "safe_count": 112,
            "risk_count": 44,
            "by_category": {
                "file_access": 67,
                "network": 34,
                "process": 28,
                "mcp_tool_call": 27
            },
            "by_server": {
                "filesystem_server": 58,
                "brave-search": 32,
                "github-mcp": 29,
                "sequential-thinking": 21,
                "memory-server": 16
            }
        },
        "audit_summary": {
            "total_entries": 2341,
            "permissions_requested": 189,
            "permissions_granted": 156,
            "permissions_denied": 33,
            "actions_executed": 478,
            "actions_blocked": 12,
            "lockdowns_activated": 1,
            "level_changes": 3
        },
        "recent_decisions": [
            {
                "id": "demo-dec-1",
                "timestamp": (now - chrono::Duration::minutes(5)).to_rfc3339(),
                "decision_type": "triage",
                "input_summary": "filesystem_server readFile on /Users/demo/.aws/credentials",
                "reasoning": [
                    "Accessing cloud credentials file",
                    "Server has no prior history of accessing AWS configs",
                    "Pattern matches known credential theft vectors"
                ],
                "conclusion": "Blocked — sensitive credential file access from untrusted context",
                "confidence": 0.92,
                "factors": [
                    { "name": "file_sensitivity", "value": "critical", "weight": 0.4, "direction": "risk" },
                    { "name": "server_trust", "value": "medium", "weight": 0.3, "direction": "risk" },
                    { "name": "behavioral_history", "value": "no_prior_access", "weight": 0.3, "direction": "risk" }
                ],
                "server_name": "filesystem_server"
            },
            {
                "id": "demo-dec-2",
                "timestamp": (now - chrono::Duration::minutes(12)).to_rfc3339(),
                "decision_type": "investigation",
                "input_summary": "Burst of 48 file reads in 30s from filesystem_server",
                "reasoning": [
                    "High-frequency file access detected",
                    "Pattern consistent with directory traversal or bulk read",
                    "All files within project workspace — likely code indexing"
                ],
                "conclusion": "Allowed — legitimate bulk read within project boundaries",
                "confidence": 0.78,
                "factors": [
                    { "name": "access_frequency", "value": "high", "weight": 0.3, "direction": "risk" },
                    { "name": "file_scope", "value": "within_project", "weight": 0.4, "direction": "safe" },
                    { "name": "known_pattern", "value": "code_indexing", "weight": 0.3, "direction": "safe" }
                ],
                "server_name": "filesystem_server"
            },
            {
                "id": "demo-dec-3",
                "timestamp": (now - chrono::Duration::minutes(28)).to_rfc3339(),
                "decision_type": "response",
                "input_summary": "brave-search connected to unrecognized IP 45.33.32.156:8443",
                "reasoning": [
                    "Outbound connection to non-standard port",
                    "IP not in known search provider ranges",
                    "Server behavior deviates from established network pattern"
                ],
                "conclusion": "Flagged for user review — suspicious outbound connection",
                "confidence": 0.85,
                "factors": [
                    { "name": "destination_trust", "value": "unknown", "weight": 0.4, "direction": "risk" },
                    { "name": "port_analysis", "value": "non_standard", "weight": 0.3, "direction": "risk" },
                    { "name": "behavioral_deviation", "value": "moderate", "weight": 0.3, "direction": "risk" }
                ],
                "server_name": "brave-search"
            },
            {
                "id": "demo-dec-4",
                "timestamp": (now - chrono::Duration::minutes(45)).to_rfc3339(),
                "decision_type": "triage",
                "input_summary": "github-mcp createPullRequest on owner/repo",
                "reasoning": [
                    "Standard Git workflow action",
                    "Server has established trust for repository operations",
                    "User previously approved similar actions"
                ],
                "conclusion": "Allowed — routine repository operation from trusted server",
                "confidence": 0.94,
                "factors": [
                    { "name": "action_type", "value": "routine", "weight": 0.3, "direction": "safe" },
                    { "name": "server_trust", "value": "high", "weight": 0.4, "direction": "safe" },
                    { "name": "user_precedent", "value": "approved", "weight": 0.3, "direction": "safe" }
                ],
                "server_name": "github-mcp"
            },
            {
                "id": "demo-dec-5",
                "timestamp": (now - chrono::Duration::hours(1)).to_rfc3339(),
                "decision_type": "correlation",
                "input_summary": "MCP readFile matched eslogger open event for .env file",
                "reasoning": [
                    "Cross-layer correlation confirmed file access",
                    "Environment file may contain secrets",
                    "Access occurred during active coding session"
                ],
                "conclusion": "Prompted user — .env file access requires explicit approval",
                "confidence": 0.88,
                "factors": [
                    { "name": "cross_layer_match", "value": "confirmed", "weight": 0.3, "direction": "neutral" },
                    { "name": "file_sensitivity", "value": "high", "weight": 0.4, "direction": "risk" },
                    { "name": "session_context", "value": "active_coding", "weight": 0.3, "direction": "safe" }
                ],
                "server_name": "filesystem_server"
            }
        ],
        "generated_at": now.to_rfc3339()
    })
}

pub fn mock_autonomy_level() -> serde_json::Value {
    serde_json::json!({
        "global_level": "L1Recommend",
        "is_locked_down": false,
        "server_overrides": {
            "filesystem_server": "L2ActWithApproval",
            "brave-search": "L1Recommend"
        },
        "stats": {
            "global_level": "L1Recommend",
            "total_actions": 478,
            "approved_actions": 412,
            "denied_actions": 33,
            "auto_executed": 33,
            "approval_rate": 0.862,
            "days_at_current_level": 12,
            "countdown_cancellations": 4
        }
    })
}

pub fn mock_feedback_stats() -> serde_json::Value {
    serde_json::json!({
        "triage_override_count": 23,
        "alert_dismissal_count": 15,
        "suggestion_approval_rate": 0.82,
        "calibration_events": 8,
        "last_calibration": (chrono::Utc::now() - chrono::Duration::hours(6)).to_rfc3339()
    })
}

pub fn mock_self_assessment() -> serde_json::Value {
    serde_json::json!({
        "triage_accuracy": 0.891,
        "alert_relevance": 0.843,
        "suggestion_acceptance": 0.82,
        "overall_accuracy": 0.855,
        "trend": "improving",
        "areas_for_improvement": [
            "Reduce false positives on bulk file read patterns",
            "Improve network destination classification",
            "Better context awareness for dev vs. production environments"
        ]
    })
}

pub fn mock_decision_explanations() -> serde_json::Value {
    let now = chrono::Utc::now();
    serde_json::json!([
        {
            "id": "demo-dec-exp-1",
            "timestamp": (now - chrono::Duration::minutes(5)).to_rfc3339(),
            "decision_type": "triage",
            "input_summary": "filesystem_server readFile on /Users/demo/.aws/credentials",
            "reasoning": [
                "Accessing cloud credentials file",
                "Server has no prior history of accessing AWS configs",
                "Pattern matches known credential theft vectors",
                "Risk level elevated due to sensitivity of target file"
            ],
            "conclusion": "Blocked — sensitive credential file access from untrusted context",
            "confidence": 0.92,
            "factors": [
                { "name": "file_sensitivity", "value": "critical", "weight": 0.4, "direction": "risk" },
                { "name": "server_trust", "value": "medium", "weight": 0.3, "direction": "risk" },
                { "name": "behavioral_history", "value": "no_prior_access", "weight": 0.3, "direction": "risk" }
            ],
            "server_name": "filesystem_server"
        },
        {
            "id": "demo-dec-exp-2",
            "timestamp": (now - chrono::Duration::minutes(12)).to_rfc3339(),
            "decision_type": "investigation",
            "input_summary": "Burst of 48 file reads in 30s from filesystem_server",
            "reasoning": [
                "High-frequency file access detected (48 reads in 30s)",
                "Pattern consistent with code indexing or project scan",
                "All accessed files are within the project workspace",
                "Similar patterns seen during prior Cursor indexing sessions"
            ],
            "conclusion": "Allowed — legitimate bulk read within project boundaries",
            "confidence": 0.78,
            "factors": [
                { "name": "access_frequency", "value": "high (48/30s)", "weight": 0.3, "direction": "risk" },
                { "name": "file_scope", "value": "within_project", "weight": 0.4, "direction": "safe" },
                { "name": "known_pattern", "value": "code_indexing", "weight": 0.3, "direction": "safe" }
            ],
            "server_name": "filesystem_server"
        },
        {
            "id": "demo-dec-exp-3",
            "timestamp": (now - chrono::Duration::minutes(28)).to_rfc3339(),
            "decision_type": "response",
            "input_summary": "brave-search connected to unrecognized IP 45.33.32.156:8443",
            "reasoning": [
                "Outbound connection to non-standard port 8443",
                "IP 45.33.32.156 not in known Brave Search API ranges",
                "Server behavior deviates from established network pattern",
                "No DNS resolution observed — direct IP connection"
            ],
            "conclusion": "Flagged for user review — suspicious outbound connection",
            "confidence": 0.85,
            "factors": [
                { "name": "destination_trust", "value": "unknown_ip", "weight": 0.4, "direction": "risk" },
                { "name": "port_analysis", "value": "non_standard_8443", "weight": 0.3, "direction": "risk" },
                { "name": "behavioral_deviation", "value": "moderate", "weight": 0.3, "direction": "risk" }
            ],
            "server_name": "brave-search"
        },
        {
            "id": "demo-dec-exp-4",
            "timestamp": (now - chrono::Duration::minutes(45)).to_rfc3339(),
            "decision_type": "triage",
            "input_summary": "github-mcp createPullRequest on owner/repo",
            "reasoning": [
                "Standard Git workflow action — creating pull request",
                "github-mcp has established trust for repository operations",
                "User previously approved 12 similar PR creation actions",
                "Repository is in the allowed list"
            ],
            "conclusion": "Allowed — routine repository operation from trusted server",
            "confidence": 0.94,
            "factors": [
                { "name": "action_type", "value": "git_workflow", "weight": 0.3, "direction": "safe" },
                { "name": "server_trust", "value": "high", "weight": 0.4, "direction": "safe" },
                { "name": "user_precedent", "value": "12_prior_approvals", "weight": 0.3, "direction": "safe" }
            ],
            "server_name": "github-mcp"
        },
        {
            "id": "demo-dec-exp-5",
            "timestamp": (now - chrono::Duration::hours(1)).to_rfc3339(),
            "decision_type": "correlation",
            "input_summary": "MCP readFile matched eslogger open event for .env file",
            "reasoning": [
                "Cross-layer correlation confirmed: MCP readFile → OS open()",
                "Target file .env likely contains secrets (API keys, DB passwords)",
                "Access occurred during active coding session (VS Code focused)",
                "No prior .env access from this server in the last 7 days"
            ],
            "conclusion": "Prompted user — .env file access requires explicit approval",
            "confidence": 0.88,
            "factors": [
                { "name": "cross_layer_match", "value": "confirmed_0.94", "weight": 0.2, "direction": "neutral" },
                { "name": "file_sensitivity", "value": "secrets_file", "weight": 0.4, "direction": "risk" },
                { "name": "session_context", "value": "active_coding", "weight": 0.2, "direction": "safe" },
                { "name": "historical_access", "value": "never_accessed", "weight": 0.2, "direction": "risk" }
            ],
            "server_name": "filesystem_server"
        },
        {
            "id": "demo-dec-exp-6",
            "timestamp": (now - chrono::Duration::hours(2)).to_rfc3339(),
            "decision_type": "triage",
            "input_summary": "sequential-thinking think: Planning authentication flow",
            "reasoning": [
                "Think action is read-only and non-destructive",
                "sequential-thinking server is sandboxed (no I/O)",
                "Content is about planning — no sensitive data involved"
            ],
            "conclusion": "Allowed — safe read-only reasoning action",
            "confidence": 0.97,
            "factors": [
                { "name": "action_type", "value": "read_only", "weight": 0.5, "direction": "safe" },
                { "name": "server_sandbox", "value": "no_io_capability", "weight": 0.3, "direction": "safe" },
                { "name": "content_analysis", "value": "no_secrets", "weight": 0.2, "direction": "safe" }
            ],
            "server_name": "sequential-thinking"
        },
        {
            "id": "demo-dec-exp-7",
            "timestamp": (now - chrono::Duration::hours(3)).to_rfc3339(),
            "decision_type": "response",
            "input_summary": "filesystem_server writeFile to /etc/hosts",
            "reasoning": [
                "Writing to system-critical file /etc/hosts",
                "Requires elevated privileges — unusual for MCP server",
                "No legitimate coding workflow requires modifying hosts file",
                "Potential DNS hijack or redirection attempt"
            ],
            "conclusion": "Blocked — write to system file outside of project scope",
            "confidence": 0.96,
            "factors": [
                { "name": "target_path", "value": "system_critical", "weight": 0.5, "direction": "risk" },
                { "name": "privilege_required", "value": "elevated", "weight": 0.3, "direction": "risk" },
                { "name": "workflow_relevance", "value": "none", "weight": 0.2, "direction": "risk" }
            ],
            "server_name": "filesystem_server"
        }
    ])
}

pub fn mock_response_playbooks() -> serde_json::Value {
    serde_json::json!([
        {
            "id": "pb-credential-theft",
            "name": "Credential Theft Response",
            "description": "Automatically blocks server access and alerts when credential file access is detected from an untrusted context",
            "trigger": { "type": "pattern_match", "pattern": "credential_access", "min_confidence": 0.85 },
            "actions": [
                { "action_type": "block_server", "description": "Immediately block the offending server", "parameters": {}, "delay_after_secs": 0, "continue_on_failure": false, "risk_level": "low" },
                { "action_type": "create_alert", "description": "Create a critical security alert", "parameters": { "severity": "critical" }, "delay_after_secs": 0, "continue_on_failure": true, "risk_level": "low" },
                { "action_type": "notify_user", "description": "Send desktop notification to user", "parameters": { "urgency": "high" }, "delay_after_secs": 1, "continue_on_failure": true, "risk_level": "low" }
            ],
            "enabled": true,
            "autonomy_required": "L2ActWithApproval",
            "is_builtin": true
        },
        {
            "id": "pb-data-exfil",
            "name": "Data Exfiltration Prevention",
            "description": "Monitors for patterns of bulk data read followed by network activity and intervenes if threshold exceeded",
            "trigger": { "type": "kill_chain", "stages": ["bulk_read", "network_connect"], "time_window_secs": 60 },
            "actions": [
                { "action_type": "throttle_server", "description": "Rate-limit the server's operations", "parameters": { "max_ops_per_sec": 2 }, "delay_after_secs": 0, "continue_on_failure": false, "risk_level": "low" },
                { "action_type": "create_alert", "description": "Flag for investigation", "parameters": { "severity": "high" }, "delay_after_secs": 0, "continue_on_failure": true, "risk_level": "low" }
            ],
            "enabled": true,
            "autonomy_required": "L2ActWithApproval",
            "is_builtin": true
        },
        {
            "id": "pb-system-file-guard",
            "name": "System File Guard",
            "description": "Blocks any MCP server from writing to system-critical paths (/etc, /System, /Library)",
            "trigger": { "type": "path_match", "paths": ["/etc/*", "/System/*", "/Library/*"], "action": "write" },
            "actions": [
                { "action_type": "block_action", "description": "Block the write operation", "parameters": {}, "delay_after_secs": 0, "continue_on_failure": false, "risk_level": "low" },
                { "action_type": "log_event", "description": "Log detailed audit entry", "parameters": { "level": "warn" }, "delay_after_secs": 0, "continue_on_failure": true, "risk_level": "low" }
            ],
            "enabled": true,
            "autonomy_required": "L1Recommend",
            "is_builtin": true
        },
        {
            "id": "pb-custom-review",
            "name": "Code Review Workflow",
            "description": "When github-mcp creates a PR, automatically run checks and notify team channel",
            "trigger": { "type": "tool_call", "server": "github-mcp", "tool": "createPullRequest" },
            "actions": [
                { "action_type": "webhook", "description": "Notify team Slack channel", "parameters": { "url": "https://hooks.slack.com/..." }, "delay_after_secs": 2, "continue_on_failure": true, "risk_level": "low" },
                { "action_type": "log_event", "description": "Log PR creation", "parameters": {}, "delay_after_secs": 0, "continue_on_failure": true, "risk_level": "low" }
            ],
            "enabled": false,
            "autonomy_required": "L3FullAuto",
            "is_builtin": false
        }
    ])
}

pub fn mock_reports() -> serde_json::Value {
    let now = chrono::Utc::now();
    serde_json::json!([
        {
            "id": "rpt-001",
            "report_type": "daily_brief",
            "generated_at": (now - chrono::Duration::hours(2)).to_rfc3339(),
            "period_start": (now - chrono::Duration::hours(26)).to_rfc3339(),
            "period_end": (now - chrono::Duration::hours(2)).to_rfc3339(),
            "format": "markdown",
            "file_path": "~/.local/share/rookbot/reports/daily-2025-01-15.md",
            "summary": "87 agent actions, 3 blocks, 1 alert escalation. All systems nominal.",
            "size_bytes": 4_892
        },
        {
            "id": "rpt-002",
            "report_type": "weekly_report",
            "generated_at": (now - chrono::Duration::days(1)).to_rfc3339(),
            "period_start": (now - chrono::Duration::days(8)).to_rfc3339(),
            "period_end": (now - chrono::Duration::days(1)).to_rfc3339(),
            "format": "markdown",
            "file_path": "~/.local/share/rookbot/reports/weekly-2025-w02.md",
            "summary": "412 activities this week. Accuracy improved 3% to 85.5%. 2 new patterns learned.",
            "size_bytes": 12_340
        },
        {
            "id": "rpt-003",
            "report_type": "incident_report",
            "generated_at": (now - chrono::Duration::days(3)).to_rfc3339(),
            "period_start": (now - chrono::Duration::days(3) - chrono::Duration::minutes(15)).to_rfc3339(),
            "period_end": (now - chrono::Duration::days(3)).to_rfc3339(),
            "format": "markdown",
            "file_path": "~/.local/share/rookbot/reports/incident-2025-01-12-cred-access.md",
            "summary": "Credential exfiltration attempt blocked. filesystem_server attempted to read SSH keys followed by outbound connection.",
            "size_bytes": 8_210
        }
    ])
}

// ── Demo event stream templates ──────────────────────────────────

/// Returns a synthetic humanized event for the event stream.
/// `index` is used to rotate through templates.
pub fn mock_stream_event(index: usize) -> serde_json::Value {
    let templates = vec![
        ("Claude Desktop", "filesystem_server", "readFile", "/Users/demo/project/src/components/App.tsx", "Allowed", "low"),
        ("Cursor", "brave-search", "search", "tokio select macro examples", "Allowed", "low"),
        ("VS Code", "github-mcp", "getFileContents", "src/lib.rs", "Allowed", "low"),
        ("Claude Desktop", "memory-server", "loadMemory", "project-context", "Allowed", "low"),
        ("Claude Code", "filesystem_server", "writeFile", "/Users/demo/project/src/utils.ts", "Allowed", "low"),
        ("Cursor", "sequential-thinking", "think", "Evaluating authentication approaches", "Allowed", "low"),
        ("Claude Desktop", "filesystem_server", "readFile", "/Users/demo/.npmrc", "Prompted", "medium"),
        ("System", "node", "Executed node", "/usr/local/bin/node server.js", "Allowed", "low"),
        ("System", "Cursor", "Connected to api.cursor.sh:443", "", "Allowed", "low"),
        ("Claude Desktop", "filesystem_server", "listDirectory", "/Users/demo/project/tests", "Allowed", "low"),
        ("VS Code", "github-mcp", "createIssue", "Bug: login redirect fails", "Allowed", "low"),
        ("Cursor", "brave-search", "search", "React 19 new hooks API", "Allowed", "low"),
        ("Claude Code", "filesystem_server", "readFile", "/Users/demo/project/Cargo.toml", "Allowed", "low"),
        ("System", "python3", "Connected to pypi.org:443", "", "Allowed", "low"),
        ("Claude Desktop", "filesystem_server", "readFile", "/Users/demo/project/.env.local", "Prompted", "medium"),
        ("Windsurf", "filesystem_server", "listDirectory", "/Users/demo/.ssh", "Blocked", "high"),
        ("System", "git", "Executed git push origin main", "", "Allowed", "medium"),
        ("Cursor", "brave-search", "search", "serde rename_all camelCase", "Allowed", "low"),
        ("Claude Desktop", "sequential-thinking", "think", "Planning database migration strategy", "Allowed", "low"),
        ("VS Code", "github-mcp", "listPullRequests", "state:open", "Allowed", "low"),
    ];

    let t = &templates[index % templates.len()];
    let now = chrono::Utc::now();
    let one_liner = if t.0 == "System" {
        t.2.to_string()
    } else {
        format!("{} — {}(\"{}\")", t.1, t.2, t.3)
    };

    serde_json::json!({
        "event_id": format!("demo-stream-{}-{}", index, now.timestamp_millis()),
        "one_liner": one_liner,
        "expanded_explanation": format!("{} → {} called {} on {}", t.0, t.1, t.2, t.3),
        "risk_level": t.5,
        "action_taken": t.4,
        "server_display_name": t.1,
        "server_name": t.1,
        "client_name": t.0,
        "tool_name": t.2,
        "timestamp": now.to_rfc3339(),
        "source_type": if t.0 == "System" { "os" } else { "mcp" },
        "is_notable": t.5 == "high" || t.4 == "Blocked",
        "educational_aside": null,
        "behavioral_context": "",
        "risk_explanation": "",
        "action_reason": "",
        "correlation_id": null,
        "kill_chain_id": null,
    })
}
