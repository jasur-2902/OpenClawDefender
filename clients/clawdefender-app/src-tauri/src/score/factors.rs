use crate::state::AppState;
use super::calculator::{ScoreFactor, FixAction};

// ---------------------------------------------------------------------------
// Helpers shared across factors
// ---------------------------------------------------------------------------

fn factor_status(current: u32, max: u32) -> &'static str {
    if current == max {
        "full"
    } else if current > 0 {
        "partial"
    } else {
        "empty"
    }
}

fn threat_intel_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::PathBuf::from(home).join(".local/share/clawdefender/threat-intel")
}

fn config_toml_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::PathBuf::from(home).join(".config/clawdefender/config.toml")
}

fn detect_servers_key(config: &serde_json::Value) -> &'static str {
    if config.get("mcpServers").and_then(|v| v.as_object()).is_some() {
        "mcpServers"
    } else if config.get("servers").and_then(|v| v.as_object()).is_some() {
        "servers"
    } else {
        "mcpServers"
    }
}

// ---------------------------------------------------------------------------
// 1. Tool Coverage (25 points)
// ---------------------------------------------------------------------------

/// Scan all known MCP client configs and count total vs wrapped servers.
///
/// If 0 servers are detected at all, the user has nothing to protect so they
/// get full points (25).  Otherwise: `(wrapped / total) * 25`.
pub fn compute_tool_coverage() -> ScoreFactor {
    const MAX: u32 = 25;
    let home = match std::env::var("HOME") {
        Ok(h) => std::path::PathBuf::from(h),
        Err(_) => {
            return ScoreFactor {
                id: "tool_coverage".into(),
                name: "Tool Coverage".into(),
                description: "No home directory found — cannot detect MCP servers.".into(),
                max_points: MAX,
                current_points: 0,
                status: "empty".into(),
                fix_actions: vec![],
                details: "Cannot determine home directory.".into(),
            };
        }
    };

    let config_paths: Vec<(&str, std::path::PathBuf)> = vec![
        ("Claude Desktop", home.join("Library/Application Support/Claude/claude_desktop_config.json")),
        ("Claude Desktop", home.join("Library/Application Support/Claude/config.json")),
        ("Cursor", home.join(".cursor/mcp.json")),
        ("VS Code", home.join(".vscode/mcp.json")),
        ("Windsurf", home.join(".codeium/windsurf/mcp_config.json")),
    ];

    let mut total_servers: u32 = 0;
    let mut wrapped_servers: u32 = 0;
    let mut unwrapped_names: Vec<String> = Vec::new();

    for (_client, path) in &config_paths {
        if !path.exists() {
            continue;
        }
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let config: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let key = detect_servers_key(&config);
        if let Some(servers) = config.get(key).and_then(|v| v.as_object()) {
            for (name, entry) in servers {
                total_servers += 1;
                if entry.get("_clawdefender_original").is_some()
                    || entry.get("_clawai_original").is_some()
                {
                    wrapped_servers += 1;
                } else {
                    unwrapped_names.push(name.clone());
                }
            }
        }
    }

    // 0 servers detected => nothing to protect => full score
    if total_servers == 0 {
        return ScoreFactor {
            id: "tool_coverage".into(),
            name: "Tool Coverage".into(),
            description: "No MCP servers detected — nothing to protect.".into(),
            max_points: MAX,
            current_points: MAX,
            status: "full".into(),
            fix_actions: vec![],
            details: "No MCP servers found in any client configuration.".into(),
        };
    }

    let points = ((wrapped_servers as f64 / total_servers as f64) * MAX as f64).round() as u32;
    let points = points.min(MAX);

    let description = if points == MAX {
        format!("All {} MCP servers are protected.", total_servers)
    } else {
        format!(
            "{} of {} servers protected. {} unprotected.",
            wrapped_servers,
            total_servers,
            total_servers - wrapped_servers,
        )
    };

    let fix_actions: Vec<FixAction> = unwrapped_names
        .iter()
        .take(5) // limit fix actions to 5
        .map(|name| FixAction {
            label: format!("Protect {}", name),
            action_type: "navigate".into(),
            target: "/guards".into(),
            params: Some(serde_json::json!({ "server": name })),
        })
        .collect();

    ScoreFactor {
        id: "tool_coverage".into(),
        name: "Tool Coverage".into(),
        description,
        max_points: MAX,
        current_points: points,
        status: factor_status(points, MAX).into(),
        fix_actions,
        details: format!("{}/{} servers wrapped", wrapped_servers, total_servers),
    }
}

// ---------------------------------------------------------------------------
// 2. Threat Intelligence (20 points)
// ---------------------------------------------------------------------------

/// Check how fresh the threat intelligence feed is.
///
/// Within 24h: 20 points. Each additional day overdue: -5. Floor 0.
pub fn compute_threat_intel() -> ScoreFactor {
    const MAX: u32 = 20;
    let manifest_path = threat_intel_dir().join("manifest.json");

    if !manifest_path.exists() {
        return ScoreFactor {
            id: "threat_intel".into(),
            name: "Threat Intelligence".into(),
            description: "Threat feed not configured. Run a feed update to initialize.".into(),
            max_points: MAX,
            current_points: 0,
            status: "empty".into(),
            fix_actions: vec![FixAction {
                label: "Update threat feed".into(),
                action_type: "command".into(),
                target: "force_feed_update".into(),
                params: None,
            }],
            details: "No manifest.json found.".into(),
        };
    }

    let last_updated = (|| -> Option<chrono::DateTime<chrono::Utc>> {
        let content = std::fs::read_to_string(&manifest_path).ok()?;
        let manifest: serde_json::Value = serde_json::from_str(&content).ok()?;
        let ts = manifest.get("last_updated")?.as_str()?;
        chrono::DateTime::parse_from_rfc3339(ts)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    })();

    let Some(last) = last_updated else {
        return ScoreFactor {
            id: "threat_intel".into(),
            name: "Threat Intelligence".into(),
            description: "Cannot read feed timestamp.".into(),
            max_points: MAX,
            current_points: 0,
            status: "empty".into(),
            fix_actions: vec![FixAction {
                label: "Update threat feed".into(),
                action_type: "command".into(),
                target: "force_feed_update".into(),
                params: None,
            }],
            details: "manifest.json unreadable.".into(),
        };
    };

    let now = chrono::Utc::now();
    let hours_ago = (now - last).num_hours();

    let points = if hours_ago <= 24 {
        MAX
    } else {
        let days_overdue = ((hours_ago - 24) / 24) + 1;
        MAX.saturating_sub((days_overdue as u32) * 5)
    };

    let description = if points == MAX {
        "Threat feed is up to date.".into()
    } else if points > 0 {
        format!("Feed is {} hours old. Update recommended.", hours_ago)
    } else {
        format!("Feed is {} hours old. Significantly outdated.", hours_ago)
    };

    let fix_actions = if points < MAX {
        vec![FixAction {
            label: "Update now".into(),
            action_type: "command".into(),
            target: "force_feed_update".into(),
            params: None,
        }]
    } else {
        vec![]
    };

    ScoreFactor {
        id: "threat_intel".into(),
        name: "Threat Intelligence".into(),
        description,
        max_points: MAX,
        current_points: points,
        status: factor_status(points, MAX).into(),
        fix_actions,
        details: format!("Last updated {} hours ago", hours_ago),
    }
}

// ---------------------------------------------------------------------------
// 3. AI Analysis (15 points)
// ---------------------------------------------------------------------------

/// Check SLM model status.
///
/// Real local SLM: 15. Cloud-only API: 5. Mock/none: 0.
pub fn compute_ai_analysis(state: &AppState) -> ScoreFactor {
    const MAX: u32 = 15;

    let model_info = state
        .active_model_info
        .lock()
        .ok()
        .and_then(|guard| guard.clone());

    let (points, description, fix_actions) = match model_info {
        Some(ref info) if info.model_type == "local_catalog" || info.model_type == "local_custom" => {
            if info.mock_mode {
                (0, "AI model is in mock mode.".into(), vec![FixAction {
                    label: "Set up AI analysis".into(),
                    action_type: "navigate".into(),
                    target: "/settings".into(),
                    params: Some(serde_json::json!({ "section": "ai" })),
                }])
            } else {
                (MAX, format!("Local AI model active: {}.", info.model_name), vec![])
            }
        }
        Some(ref info) if info.model_type == "cloud_api" => {
            (5, format!("Cloud AI provider active: {}. Local model recommended for privacy.", info.model_name), vec![FixAction {
                label: "Download local model".into(),
                action_type: "navigate".into(),
                target: "/settings".into(),
                params: Some(serde_json::json!({ "section": "ai" })),
            }])
        }
        _ => {
            (0, "No AI model configured.".into(), vec![FixAction {
                label: "Set up AI analysis".into(),
                action_type: "navigate".into(),
                target: "/settings".into(),
                params: Some(serde_json::json!({ "section": "ai" })),
            }])
        }
    };

    ScoreFactor {
        id: "ai_analysis".into(),
        name: "AI Analysis".into(),
        description,
        max_points: MAX,
        current_points: points,
        status: factor_status(points, MAX).into(),
        fix_actions,
        details: model_info
            .map(|i| i.model_name)
            .unwrap_or_else(|| "None".into()),
    }
}

// ---------------------------------------------------------------------------
// 4. System Visibility (15 points)
// ---------------------------------------------------------------------------

/// Check FDA/daemon status.
///
/// Daemon running + FDA: 15. Daemon running, no FDA: 5. Daemon off: 0.
pub fn compute_system_visibility(state: &AppState) -> ScoreFactor {
    const MAX: u32 = 15;

    let daemon_connected = state
        .daemon_connected
        .lock()
        .map(|g| *g)
        .unwrap_or(false);

    if !daemon_connected {
        return ScoreFactor {
            id: "system_visibility".into(),
            name: "System Visibility".into(),
            description: "Daemon is not running. Start it for full monitoring.".into(),
            max_points: MAX,
            current_points: 0,
            status: "empty".into(),
            fix_actions: vec![FixAction {
                label: "Start daemon".into(),
                action_type: "command".into(),
                target: "start_daemon".into(),
                params: None,
            }],
            details: "Daemon not connected.".into(),
        };
    }

    // Check FDA by looking for eslogger access / TCC.db
    // We approximate: if the audit log exists and is being written to, FDA is likely granted.
    let audit_path = crate::event_stream::audit_log_path();
    let has_fda = audit_path.exists() && {
        std::fs::metadata(&audit_path)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
    };

    if has_fda {
        ScoreFactor {
            id: "system_visibility".into(),
            name: "System Visibility".into(),
            description: "Full system visibility. Daemon running with Full Disk Access.".into(),
            max_points: MAX,
            current_points: MAX,
            status: "full".into(),
            fix_actions: vec![],
            details: "Daemon connected, FDA granted.".into(),
        }
    } else {
        ScoreFactor {
            id: "system_visibility".into(),
            name: "System Visibility".into(),
            description: "Daemon running but Full Disk Access not detected. Auto-discovery limited.".into(),
            max_points: MAX,
            current_points: 5,
            status: "partial".into(),
            fix_actions: vec![FixAction {
                label: "Grant Full Disk Access".into(),
                action_type: "external".into(),
                target: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles".into(),
                params: None,
            }],
            details: "Daemon connected, FDA not detected.".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Unresolved Alerts (15 points)
// ---------------------------------------------------------------------------

/// Count unresolved medium+ alerts. 0 = 15pts. -3 per alert. Floor 0.
pub fn compute_unresolved_alerts(state: &AppState) -> ScoreFactor {
    const MAX: u32 = 15;

    let unresolved_count = state
        .alert_state
        .lock()
        .map(|store| {
            store
                .iter()
                .filter(|a| {
                    a.status == crate::alerts::engine::AlertStatus::Active
                        && matches!(
                            a.severity.as_str(),
                            "dangerous" | "suspicious" | "medium" | "high" | "critical"
                        )
                })
                .count() as u32
        })
        .unwrap_or(0);

    let points = MAX.saturating_sub(unresolved_count * 3);

    let description = if unresolved_count == 0 {
        "No unresolved alerts. All clear.".into()
    } else if points > 0 {
        format!("{} unresolved alert(s). Review them to improve your score.", unresolved_count)
    } else {
        format!("{} unresolved alerts. Your protection is degraded.", unresolved_count)
    };

    let fix_actions = if unresolved_count > 0 {
        vec![FixAction {
            label: format!("Review {} alert(s)", unresolved_count),
            action_type: "navigate".into(),
            target: "/alerts".into(),
            params: None,
        }]
    } else {
        vec![]
    };

    ScoreFactor {
        id: "unresolved_alerts".into(),
        name: "Unresolved Alerts".into(),
        description,
        max_points: MAX,
        current_points: points,
        status: factor_status(points, MAX).into(),
        fix_actions,
        details: format!("{} unresolved medium+ alerts", unresolved_count),
    }
}

// ---------------------------------------------------------------------------
// 6. Configuration Health (10 points)
// ---------------------------------------------------------------------------

/// Sum of sub-factors:
/// - Autostart enabled: 3
/// - Protection level explicitly set: 3
/// - At least one trust level customized: 2
/// - Behavioral profiles active: 2
pub fn compute_config_health() -> ScoreFactor {
    const MAX: u32 = 10;
    let mut points: u32 = 0;
    let mut fix_actions: Vec<FixAction> = Vec::new();
    let mut sub_details: Vec<&str> = Vec::new();

    // Autostart enabled (3 points)
    // We check the LaunchAgent plist exists as a proxy since we cannot call
    // the Tauri autostart API from non-command context.
    let autostart = check_autostart_enabled();
    if autostart {
        points += 3;
        sub_details.push("autostart:yes");
    } else {
        sub_details.push("autostart:no");
        fix_actions.push(FixAction {
            label: "Enable autostart".into(),
            action_type: "command".into(),
            target: "enable_autostart".into(),
            params: None,
        });
    }

    // Protection level explicitly set (3 points)
    let protection_set = check_protection_level_set();
    if protection_set {
        points += 3;
        sub_details.push("protection_level:set");
    } else {
        sub_details.push("protection_level:default");
        fix_actions.push(FixAction {
            label: "Set protection level".into(),
            action_type: "navigate".into(),
            target: "/settings".into(),
            params: Some(serde_json::json!({ "section": "protection" })),
        });
    }

    // Trust level customized (2 points)
    let trust_customized = check_trust_customized();
    if trust_customized {
        points += 2;
        sub_details.push("trust:customized");
    } else {
        sub_details.push("trust:default");
        fix_actions.push(FixAction {
            label: "Customize trust levels".into(),
            action_type: "navigate".into(),
            target: "/guards".into(),
            params: None,
        });
    }

    // Behavioral profiles active (2 points)
    let profiles_active = check_behavioral_profiles_active();
    if profiles_active {
        points += 2;
        sub_details.push("behavioral:active");
    } else {
        sub_details.push("behavioral:inactive");
        fix_actions.push(FixAction {
            label: "Enable behavioral analysis".into(),
            action_type: "navigate".into(),
            target: "/behavioral".into(),
            params: None,
        });
    }

    let description = if points == MAX {
        "All configuration sub-factors in place.".into()
    } else {
        format!("{}/{} configuration points. Some settings need attention.", points, MAX)
    };

    ScoreFactor {
        id: "config_health".into(),
        name: "Configuration Health".into(),
        description,
        max_points: MAX,
        current_points: points,
        status: factor_status(points, MAX).into(),
        fix_actions,
        details: sub_details.join(", "),
    }
}

// ---------------------------------------------------------------------------
// Configuration health sub-checks
// ---------------------------------------------------------------------------

fn check_autostart_enabled() -> bool {
    // Check if the LaunchAgent plist exists (standard Tauri autostart location)
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return false,
    };
    let plist = std::path::PathBuf::from(&home)
        .join("Library/LaunchAgents")
        .join("com.clawdefender.app.plist");
    if plist.exists() {
        return true;
    }
    // Also check config.toml
    let path = config_toml_path();
    if let Ok(content) = std::fs::read_to_string(&path) {
        if let Ok(table) = content.parse::<toml::Value>() {
            if let Some(val) = table.get("ui")
                .and_then(|u| u.get("auto_start_daemon"))
                .and_then(|v| v.as_bool())
            {
                return val;
            }
        }
    }
    false
}

fn check_protection_level_set() -> bool {
    // Check if security_level is explicitly set in config or a template has been applied
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return false,
    };
    let policy_path = std::path::PathBuf::from(&home)
        .join(".config/clawdefender/policy.toml");
    // If policy.toml exists and has been modified, consider protection level set
    if policy_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&policy_path) {
            // If it has more than just the default/empty content
            return content.len() > 20;
        }
    }
    false
}

fn check_trust_customized() -> bool {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return false,
    };
    let trust_path = std::path::PathBuf::from(&home)
        .join(".config/clawdefender/trust.toml");
    trust_path.exists()
}

fn check_behavioral_profiles_active() -> bool {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return false,
    };
    let profiles_dir = std::path::PathBuf::from(&home)
        .join(".local/share/clawdefender/behavioral");
    if !profiles_dir.is_dir() {
        return false;
    }
    // At least one .json profile file means profiles are active
    std::fs::read_dir(&profiles_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .any(|e| {
                    e.path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        == Some("json")
                })
        })
        .unwrap_or(false)
}
