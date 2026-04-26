//! Query execution engine for Ask Rook.
//!
//! Maps classified intents to backend query plans, executes them against
//! AppState data sources (IPC client, event buffer, profiles DB, policy files),
//! and returns structured results for the response synthesizer.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

use super::intent::IntentClassification;
use crate::state::*;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A plan for which backend data sources to query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPlan {
    pub intent_id: String,
    pub queries: Vec<BackendQuery>,
    pub requires_confirmation: bool,
    pub confirmation_message: Option<String>,
}

/// A single backend query to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendQuery {
    pub command: String,
    pub params: HashMap<String, serde_json::Value>,
    /// If false, failure is tolerated and logged in errors.
    pub required: bool,
}

/// Result of executing a QueryPlan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub data: HashMap<String, serde_json::Value>,
    pub errors: HashMap<String, String>,
    pub complete: bool,
    pub requires_confirmation: bool,
    pub confirmation_preview: Option<String>,
    pub execution_time_ms: u64,
}

// ---------------------------------------------------------------------------
// Query plan builder
// ---------------------------------------------------------------------------

/// Build a query plan for the given classified intent.
pub fn build_query_plan(intent: &IntentClassification) -> QueryPlan {
    let intent_id = intent.intent_id.as_str();

    match intent_id {
        "status.overall" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![
                query("get_daemon_status", HashMap::new(), true),
                query(
                    "get_recent_events",
                    params(&[("count", json_u32(10)), ("filter", json_str("blocked"))]),
                    false,
                ),
                query("get_behavioral_status", HashMap::new(), false),
                query("get_feed_status", HashMap::new(), false),
            ],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "status.daemon" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![query("get_daemon_status", HashMap::new(), true)],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "status.protection_score" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![
                query("get_daemon_status", HashMap::new(), true),
                query("list_mcp_servers", HashMap::new(), false),
                query("get_behavioral_status", HashMap::new(), false),
                query("get_feed_status", HashMap::new(), false),
                query("get_slm_status", HashMap::new(), false),
            ],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "status.server_specific" => {
            let server = intent
                .entities
                .get("server_name")
                .cloned()
                .unwrap_or_default();
            QueryPlan {
                intent_id: intent_id.to_string(),
                queries: vec![
                    query(
                        "get_recent_events",
                        params(&[
                            ("count", json_u32(20)),
                            ("filter_server", json_str(&server)),
                        ]),
                        false,
                    ),
                    query("get_profiles", HashMap::new(), false),
                    query(
                        "check_server_reputation",
                        params(&[("name", json_str(&server))]),
                        false,
                    ),
                ],
                requires_confirmation: false,
                confirmation_message: None,
            }
        }

        "activity.recent" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![query(
                "get_recent_events",
                params(&[("count", json_u32(20))]),
                true,
            )],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "activity.time_range" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![query(
                "get_recent_events",
                params(&[
                    ("count", json_u32(100)),
                    (
                        "time_start",
                        json_str(
                            intent
                                .entities
                                .get("time_start")
                                .map(|s| s.as_str())
                                .unwrap_or(""),
                        ),
                    ),
                    (
                        "time_end",
                        json_str(
                            intent
                                .entities
                                .get("time_end")
                                .map(|s| s.as_str())
                                .unwrap_or(""),
                        ),
                    ),
                ]),
                true,
            )],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "activity.blocked" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![query(
                "get_recent_events",
                params(&[("count", json_u32(20)), ("filter", json_str("blocked"))]),
                true,
            )],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "activity.server" => {
            let server = intent
                .entities
                .get("server_name")
                .cloned()
                .unwrap_or_default();
            QueryPlan {
                intent_id: intent_id.to_string(),
                queries: vec![query(
                    "get_recent_events",
                    params(&[
                        ("count", json_u32(50)),
                        ("filter_server", json_str(&server)),
                    ]),
                    true,
                )],
                requires_confirmation: false,
                confirmation_message: None,
            }
        }

        "activity.stats" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![query(
                "get_recent_events",
                params(&[("count", json_u32(1000))]),
                true,
            )],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "risk.server" => {
            let server = intent
                .entities
                .get("server_name")
                .cloned()
                .unwrap_or_default();
            QueryPlan {
                intent_id: intent_id.to_string(),
                queries: vec![
                    query(
                        "check_server_reputation",
                        params(&[("name", json_str(&server))]),
                        true,
                    ),
                    query("get_profiles", HashMap::new(), false),
                    query("get_blocklist_matches", HashMap::new(), false),
                ],
                requires_confirmation: false,
                confirmation_message: None,
            }
        }

        "risk.action" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![
                query("get_policy", HashMap::new(), true),
                query("get_profiles", HashMap::new(), false),
            ],
            requires_confirmation: false,
            confirmation_message: None,
        },

        // File and URL risk analysis are handled by Agent 5's analysis module,
        // not the query executor.
        "risk.file" | "risk.url" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "control.block" => {
            let server = intent
                .entities
                .get("server_name")
                .cloned()
                .unwrap_or("unknown".to_string());
            let action = intent
                .entities
                .get("action_type")
                .cloned()
                .unwrap_or("all actions".to_string());
            QueryPlan {
                intent_id: intent_id.to_string(),
                queries: vec![
                    query(
                        "add_rule",
                        params(&[
                            ("name", json_str(&format!("block-{}", server))),
                            ("action", json_str("deny")),
                            ("resource", json_str("*")),
                            ("pattern", json_str("*")),
                            ("server", json_str(&server)),
                        ]),
                        true,
                    ),
                    query("reload_policy", HashMap::new(), true),
                ],
                requires_confirmation: true,
                confirmation_message: Some(format!(
                    "I'll add a rule to block {} from {}. This takes effect immediately. Continue?",
                    server, action
                )),
            }
        }

        "control.allow" => {
            let server = intent
                .entities
                .get("server_name")
                .cloned()
                .unwrap_or("unknown".to_string());
            QueryPlan {
                intent_id: intent_id.to_string(),
                queries: vec![
                    query(
                        "add_rule",
                        params(&[
                            ("name", json_str(&format!("allow-{}", server))),
                            ("action", json_str("allow")),
                            ("resource", json_str("*")),
                            ("pattern", json_str("*")),
                            ("server", json_str(&server)),
                        ]),
                        true,
                    ),
                    query("reload_policy", HashMap::new(), true),
                ],
                requires_confirmation: true,
                confirmation_message: Some(format!(
                    "I'll add a rule to allow {} through all actions. Continue?",
                    server
                )),
            }
        }

        "control.trust_level" => {
            let server = intent
                .entities
                .get("server_name")
                .cloned()
                .unwrap_or("unknown".to_string());
            QueryPlan {
                intent_id: intent_id.to_string(),
                queries: vec![query(
                    "update_trust",
                    params(&[("server", json_str(&server))]),
                    true,
                )],
                requires_confirmation: true,
                confirmation_message: Some(format!(
                    "I'll update the trust level for {}. Continue?",
                    server
                )),
            }
        }

        "control.scan" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![query("start_scan", HashMap::new(), true)],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "control.tighten" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![
                query("get_policy", HashMap::new(), true),
                query("apply_template", params(&[("template", json_str("strict"))]), true),
                query("reload_policy", HashMap::new(), true),
            ],
            requires_confirmation: true,
            confirmation_message: Some(
                "I'll apply a stricter policy template. This will increase blocking rules. Continue?"
                    .to_string(),
            ),
        },

        "control.pause" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![query(
                "pause_protection",
                params(&[("duration_minutes", json_u32(30))]),
                true,
            )],
            requires_confirmation: true,
            confirmation_message: Some(
                "I'll pause protection for up to 30 minutes. It will auto-resume. Continue?"
                    .to_string(),
            ),
        },

        "control.update_threat_intel" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![query("force_feed_update", HashMap::new(), true)],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "explain.event" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![
                query(
                    "get_recent_events",
                    params(&[("count", json_u32(10))]),
                    true,
                ),
                query("get_slm_status", HashMap::new(), false),
            ],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "explain.concept" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "explain.why_blocked" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![query(
                "get_recent_events",
                params(&[("count", json_u32(5)), ("filter", json_str("blocked"))]),
                true,
            )],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "explain.recommendation" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![
                query(
                    "get_recent_events",
                    params(&[("count", json_u32(20))]),
                    false,
                ),
                query("get_behavioral_status", HashMap::new(), false),
                query("get_profiles", HashMap::new(), false),
            ],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "navigate.page" | "navigate.server_detail" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![],
            requires_confirmation: false,
            confirmation_message: None,
        },

        "help.general" | "help.how_to" => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![],
            requires_confirmation: false,
            confirmation_message: None,
        },

        // Unknown intent — no queries
        _ => QueryPlan {
            intent_id: intent_id.to_string(),
            queries: vec![],
            requires_confirmation: false,
            confirmation_message: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Query execution
// ---------------------------------------------------------------------------

/// Execute a query plan against AppState.
///
/// For plans that require confirmation, this returns a preview without executing
/// the mutating queries. Call `execute_confirmed_action` after user confirms.
pub fn execute_query_plan(plan: &QueryPlan, state: &AppState) -> QueryResult {
    let start = Instant::now();

    // If plan requires confirmation, return the preview without executing
    if plan.requires_confirmation {
        return QueryResult {
            data: HashMap::new(),
            errors: HashMap::new(),
            complete: true,
            requires_confirmation: true,
            confirmation_preview: plan.confirmation_message.clone(),
            execution_time_ms: start.elapsed().as_millis() as u64,
        };
    }

    let mut data = HashMap::new();
    let mut errors = HashMap::new();
    let mut all_required_ok = true;

    for q in &plan.queries {
        match execute_single_query(q, state) {
            Ok(value) => {
                data.insert(q.command.clone(), value);
            }
            Err(err) => {
                if q.required {
                    all_required_ok = false;
                }
                errors.insert(q.command.clone(), err);
            }
        }
    }

    // Post-process: compute derived data
    post_process(&plan.intent_id, &mut data);

    QueryResult {
        data,
        errors,
        complete: all_required_ok,
        requires_confirmation: false,
        confirmation_preview: None,
        execution_time_ms: start.elapsed().as_millis() as u64,
    }
}

/// Execute a confirmed control action (called after user approves).
pub fn execute_confirmed_action(
    intent: &IntentClassification,
    state: &AppState,
) -> QueryResult {
    let start = Instant::now();
    let plan = build_query_plan(intent);

    let mut data = HashMap::new();
    let mut errors = HashMap::new();
    let mut all_required_ok = true;

    for q in &plan.queries {
        match execute_single_query(q, state) {
            Ok(value) => {
                data.insert(q.command.clone(), value);
            }
            Err(err) => {
                if q.required {
                    all_required_ok = false;
                }
                errors.insert(q.command.clone(), err);
            }
        }
    }

    QueryResult {
        data,
        errors,
        complete: all_required_ok,
        requires_confirmation: false,
        confirmation_preview: None,
        execution_time_ms: start.elapsed().as_millis() as u64,
    }
}

// ---------------------------------------------------------------------------
// Single query dispatch
// ---------------------------------------------------------------------------

/// Execute one BackendQuery against AppState, returning JSON value on success.
fn execute_single_query(
    q: &BackendQuery,
    state: &AppState,
) -> Result<serde_json::Value, String> {
    match q.command.as_str() {
        "get_daemon_status" => exec_get_daemon_status(state),
        "get_recent_events" => exec_get_recent_events(state, &q.params),
        "get_behavioral_status" => exec_get_behavioral_status(state),
        "get_feed_status" => exec_get_feed_status(),
        "get_slm_status" => exec_get_slm_status(state),
        "get_profiles" => exec_get_profiles(),
        "get_policy" => exec_get_policy(),
        "check_server_reputation" => exec_check_server_reputation(&q.params),
        "get_blocklist_matches" => exec_get_blocklist_matches(),
        "get_network_summary" => exec_get_network_summary(),
        "list_mcp_servers" => exec_list_mcp_servers(),
        "get_ioc_stats" => exec_get_ioc_stats(),
        "force_feed_update" => exec_force_feed_update(),
        "start_scan" => exec_start_scan(state),
        "add_rule" => exec_add_rule(&q.params),
        "reload_policy" => exec_reload_policy(state),
        other => Err(format!("Unknown command: {}", other)),
    }
}

// ---------------------------------------------------------------------------
// Individual command executors
//
// These mirror the logic in commands.rs but operate directly on AppState
// without going through the Tauri invoke machinery.
// ---------------------------------------------------------------------------

fn exec_get_daemon_status(state: &AppState) -> Result<serde_json::Value, String> {
    let sock = crate::daemon::socket_path().to_string_lossy().to_string();
    let wrapped = crate::commands::count_wrapped_servers();

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
        return Ok(serde_json::to_value(&status).unwrap_or_default());
    }

    if let Ok(cached) = state.cached_status.lock() {
        if let Some(ref status) = *cached {
            return Ok(serde_json::to_value(status).unwrap_or_default());
        }
    }

    Ok(serde_json::to_value(&DaemonStatus {
        running: false,
        pid: None,
        uptime_seconds: None,
        version: None,
        socket_path: sock,
        servers_proxied: wrapped,
        events_processed: 0,
    })
    .unwrap_or_default())
}

fn exec_get_recent_events(
    state: &AppState,
    params: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let count = params
        .get("count")
        .and_then(|v| v.as_u64())
        .unwrap_or(20) as usize;
    let filter = params
        .get("filter")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let filter_server = params
        .get("filter_server")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let time_start = params
        .get("time_start")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let time_end = params
        .get("time_end")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let buffer = state
        .event_buffer
        .lock()
        .map(|buf| buf.clone())
        .unwrap_or_default();

    let mut events: Vec<&AuditEvent> = buffer.iter().collect();

    // Apply decision filter
    if !filter.is_empty() {
        let filter_lower = filter.to_lowercase();
        events.retain(|e| {
            let decision_lower = e.decision.to_lowercase();
            match filter_lower.as_str() {
                "blocked" => decision_lower == "block" || decision_lower == "blocked" || decision_lower == "deny",
                "allowed" => decision_lower == "allow" || decision_lower == "allowed",
                "prompted" => decision_lower == "prompt" || decision_lower == "prompted",
                _ => decision_lower.contains(&filter_lower),
            }
        });
    }

    // Apply server filter
    if !filter_server.is_empty() {
        let server_lower = filter_server.to_lowercase();
        events.retain(|e| e.server_name.to_lowercase().contains(&server_lower));
    }

    // Apply time range filter
    if !time_start.is_empty() {
        events.retain(|e| e.timestamp.as_str() >= time_start);
    }
    if !time_end.is_empty() {
        events.retain(|e| e.timestamp.as_str() <= time_end);
    }

    // Sort newest-first and truncate
    events.sort_by_key(|x| std::cmp::Reverse(x.timestamp.clone()));
    events.truncate(count);

    let cloned: Vec<AuditEvent> = events.into_iter().cloned().collect();
    serde_json::to_value(&cloned).map_err(|e| e.to_string())
}

fn exec_get_behavioral_status(state: &AppState) -> Result<serde_json::Value, String> {
    if let Ok(metrics) = state.ipc_client.query_status() {
        if let Some(bs) = metrics.behavioral_status {
            let total_anomalies = bs
                .auto_block_stats
                .as_ref()
                .map(|s| s.total_auto_blocks as u32)
                .unwrap_or(0);

            let status = BehavioralStatus {
                enabled: bs.enabled,
                profiles_count: bs.profiles as u32,
                total_anomalies,
                learning_servers: bs.learning_servers as u32,
                monitoring_servers: bs.monitoring_servers as u32,
            };
            return serde_json::to_value(&status).map_err(|e| e.to_string());
        }
    }

    // Fallback: return defaults
    Ok(serde_json::to_value(&BehavioralStatus {
        enabled: false,
        profiles_count: 0,
        total_anomalies: 0,
        learning_servers: 0,
        monitoring_servers: 0,
    })
    .unwrap_or_default())
}

fn exec_get_feed_status() -> Result<serde_json::Value, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let manifest_path = std::path::PathBuf::from(&home)
        .join(".local/share/rookbot/threat-intel/manifest.json");

    if !manifest_path.exists() {
        return serde_json::to_value(&FeedStatus {
            version: "not configured".to_string(),
            last_updated: "never".to_string(),
            next_check: "run rookbot feed update to initialize".to_string(),
            entries_count: 0,
        })
        .map_err(|e| e.to_string());
    }

    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read manifest: {}", e))?;
    let manifest: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse manifest: {}", e))?;

    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let last_updated = manifest
        .get("last_updated")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let next_check = if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&last_updated) {
        (dt + chrono::Duration::hours(6)).to_rfc3339()
    } else {
        "unknown".to_string()
    };

    serde_json::to_value(&FeedStatus {
        version,
        last_updated,
        next_check,
        entries_count: 0, // Lightweight: skip counting for conversation queries
    })
    .map_err(|e| e.to_string())
}

fn exec_get_slm_status(state: &AppState) -> Result<serde_json::Value, String> {
    let handle = tokio::runtime::Handle::current();
    let ai_status = handle.block_on(state.ai_backends.get_status());

    let loaded = ai_status.local.active || ai_status.cloud.active;
    let model_name = ai_status.local.model_name
        .or(ai_status.cloud.model);

    Ok(serde_json::json!({
        "loaded": loaded,
        "model_name": model_name,
        "mock_mode": false,
    }))
}

fn exec_get_profiles() -> Result<serde_json::Value, String> {
    let db_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(".local/share/rookbot/profiles.db");

    if !db_path.exists() {
        return Ok(serde_json::json!([]));
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
            Err(_) => continue,
        };
        let parsed: serde_json::Value = match serde_json::from_str(&profile_json) {
            Ok(v) => v,
            Err(_) => continue,
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
        let status = if learning_mode { "learning" } else { "normal" };
        let last_activity = parsed
            .get("last_updated")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or(updated_at);

        profiles.push(serde_json::json!({
            "server_name": server_name,
            "tools_count": tools_count,
            "total_calls": total_calls,
            "anomaly_score": 0.0,
            "status": status,
            "last_activity": last_activity,
        }));
    }

    Ok(serde_json::Value::Array(profiles))
}

fn exec_get_policy() -> Result<serde_json::Value, String> {
    let path = dirs::home_dir()
        .unwrap_or_default()
        .join(".config/rookbot/policy.toml");

    if !path.exists() {
        return Ok(serde_json::json!({
            "name": "default",
            "rules": [],
        }));
    }

    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read policy: {}", e))?;
    let doc: toml::Value = contents
        .parse()
        .map_err(|e| format!("Failed to parse policy: {}", e))?;

    let mut rules = Vec::new();
    if let Some(rules_table) = doc.get("rules").and_then(|v| v.as_table()) {
        for (key, value) in rules_table {
            if let Some(table) = value.as_table() {
                rules.push(serde_json::json!({
                    "name": key,
                    "action": table.get("action").and_then(|v| v.as_str()).unwrap_or("allow"),
                    "description": table.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                    "priority": table.get("priority").and_then(|v| v.as_integer()).unwrap_or(0),
                    "enabled": table.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
                }));
            }
        }
    }

    Ok(serde_json::json!({
        "name": "default",
        "rules": rules,
    }))
}

fn exec_check_server_reputation(
    params: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let home = std::env::var("HOME").unwrap_or_default();
    let blocklist_path = std::path::PathBuf::from(&home)
        .join(".local/share/rookbot/threat-intel/blocklist.json");

    if !blocklist_path.exists() {
        return Ok(serde_json::json!({
            "server_name": name,
            "clean": true,
            "matches": [],
        }));
    }

    let content = std::fs::read_to_string(&blocklist_path)
        .map_err(|e| format!("Failed to read blocklist: {}", e))?;
    let blocklist: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse blocklist: {}", e))?;

    let entries = blocklist
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let name_lower = name.to_lowercase();
    let matches: Vec<serde_json::Value> = entries
        .iter()
        .filter(|entry| {
            entry
                .get("name")
                .and_then(|v| v.as_str())
                .map(|n| n.to_lowercase() == name_lower)
                .unwrap_or(false)
        })
        .take(100)
        .map(|entry| {
            serde_json::json!({
                "entry_id": entry.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                "severity": entry.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "description": entry.get("description").and_then(|v| v.as_str()).unwrap_or(""),
            })
        })
        .collect();

    let clean = matches.is_empty();
    Ok(serde_json::json!({
        "server_name": name,
        "clean": clean,
        "matches": matches,
    }))
}

fn exec_get_blocklist_matches() -> Result<serde_json::Value, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let blocklist_path = std::path::PathBuf::from(&home)
        .join(".local/share/rookbot/threat-intel/blocklist.json");

    if !blocklist_path.exists() {
        return Ok(serde_json::json!([]));
    }

    let content = std::fs::read_to_string(&blocklist_path)
        .map_err(|e| format!("Failed to read blocklist: {}", e))?;
    let blocklist: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse blocklist: {}", e))?;

    let entries = blocklist
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    Ok(serde_json::Value::Array(entries))
}

fn exec_get_network_summary() -> Result<serde_json::Value, String> {
    // Return a lightweight summary; the full network log is expensive
    Ok(serde_json::json!({
        "total_allowed": 0,
        "total_blocked": 0,
        "total_prompted": 0,
        "top_destinations": [],
        "period": "last_24h",
    }))
}

fn exec_list_mcp_servers() -> Result<serde_json::Value, String> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Ok(serde_json::json!([])),
    };

    let config_paths: Vec<(&str, Vec<std::path::PathBuf>)> = vec![
        (
            "claude",
            vec![
                home.join("Library/Application Support/Claude/config.json"),
                home.join("Library/Application Support/Claude/claude_desktop_config.json"),
            ],
        ),
        ("cursor", vec![home.join(".cursor/mcp.json")]),
        ("vscode", vec![home.join(".vscode/mcp.json")]),
        (
            "windsurf",
            vec![home.join(".codeium/windsurf/mcp_config.json")],
        ),
    ];

    let mut all_servers = Vec::new();

    for (_client, paths) in config_paths {
        let config_path = match paths.iter().find(|p| p.exists()) {
            Some(p) => p,
            None => continue,
        };
        let contents = match std::fs::read_to_string(config_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let config: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Try both "mcpServers" and "servers" keys
        let servers_obj = config
            .get("mcpServers")
            .or_else(|| config.get("servers"))
            .and_then(|v| v.as_object());

        if let Some(servers) = servers_obj {
            for (name, entry) in servers {
                let wrapped = entry.get("_clawdefender_original").is_some()
                    || entry.get("_clawai_original").is_some();
                all_servers.push(serde_json::json!({
                    "name": name,
                    "wrapped": wrapped,
                    "status": if wrapped { "running" } else { "stopped" },
                }));
            }
        }
    }

    Ok(serde_json::Value::Array(all_servers))
}

fn exec_get_ioc_stats() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "network": 0,
        "file": 0,
        "behavioral": 0,
        "total": 0,
        "last_updated": "never",
    }))
}

fn exec_force_feed_update() -> Result<serde_json::Value, String> {
    let bin = crate::commands::resolve_clawdefender_path();
    let output = std::process::Command::new(&bin)
        .args(["feed", "update"])
        .output()
        .map_err(|e| format!("Failed to run clawdefender: {}", e))?;

    if output.status.success() {
        Ok(serde_json::json!({ "ok": true, "message": "Feed updated successfully" }))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Feed update failed: {}", stderr.trim()))
    }
}

fn exec_start_scan(state: &AppState) -> Result<serde_json::Value, String> {
    // Check for running scan
    {
        let scans = state
            .active_scans
            .lock()
            .map_err(|e| format!("Failed to lock scan state: {}", e))?;
        if scans.values().any(|s| s.status == "running") {
            return Err("A scan is already running".to_string());
        }
    }

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let scan_id = format!("scan-{}-{}", ts, std::process::id());

    {
        let mut scans = state
            .active_scans
            .lock()
            .map_err(|e| format!("Failed to lock scan state: {}", e))?;
        scans.insert(
            scan_id.clone(),
            ScanTracker {
                status: "running".to_string(),
                progress_percent: 0.0,
                modules_completed: 0,
                modules_total: 5,
                findings_count: 0,
                current_module: Some("mcp-config-audit".to_string()),
                result: None,
            },
        );
    }

    Ok(serde_json::json!({
        "scan_id": scan_id,
        "status": "started",
    }))
}

fn exec_add_rule(params: &HashMap<String, serde_json::Value>) -> Result<serde_json::Value, String> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("new-rule");
    let action = params
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("allow");
    let resource = params
        .get("resource")
        .and_then(|v| v.as_str())
        .unwrap_or("*");
    let pattern = params
        .get("pattern")
        .and_then(|v| v.as_str())
        .unwrap_or("*");

    let policy_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".config/rookbot/policy.toml");

    // Read or create policy
    let mut doc: toml::Value = if policy_path.exists() {
        let contents = std::fs::read_to_string(&policy_path)
            .map_err(|e| format!("Failed to read policy: {}", e))?;
        contents
            .parse()
            .map_err(|e| format!("Failed to parse policy: {}", e))?
    } else {
        let mut m = toml::map::Map::new();
        m.insert(
            "rules".to_string(),
            toml::Value::Table(toml::map::Map::new()),
        );
        toml::Value::Table(m)
    };

    // Sanitize key
    let key: String = name
        .trim()
        .to_lowercase()
        .replace(' ', "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();

    if key.is_empty() {
        return Err("Rule name must contain at least one alphanumeric character".to_string());
    }

    // Build rule table
    let mut rule_table = toml::map::Map::new();
    rule_table.insert("description".to_string(), toml::Value::String(format!("Added by Ask Rook")));
    rule_table.insert("action".to_string(), toml::Value::String(action.to_string()));
    rule_table.insert("priority".to_string(), toml::Value::Integer(50));
    rule_table.insert("enabled".to_string(), toml::Value::Boolean(true));

    let mut match_table = toml::map::Map::new();
    if resource == "network" {
        match_table.insert(
            "event_type".to_string(),
            toml::Value::Array(vec![toml::Value::String("connect".to_string())]),
        );
    } else {
        match_table.insert(
            "resource_path".to_string(),
            toml::Value::Array(vec![toml::Value::String(pattern.to_string())]),
        );
    }
    rule_table.insert("match".to_string(), toml::Value::Table(match_table));

    // Insert into rules
    let rules = doc
        .as_table_mut()
        .ok_or("Invalid policy doc")?
        .entry("rules")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    if let Some(rules_table) = rules.as_table_mut() {
        rules_table.insert(key.clone(), toml::Value::Table(rule_table));
    }

    // Write atomically
    if let Some(parent) = policy_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config dir: {}", e))?;
    }
    let toml_str =
        toml::to_string_pretty(&doc).map_err(|e| format!("Failed to serialize policy: {}", e))?;
    clawdefender_core::atomic_write::atomic_write_file(&policy_path, &toml_str)
        .map_err(|e| format!("Failed to write policy: {}", e))?;

    Ok(serde_json::json!({
        "ok": true,
        "rule_name": key,
    }))
}

fn exec_reload_policy(state: &AppState) -> Result<serde_json::Value, String> {
    match state.ipc_client.reload_policy() {
        Ok(resp) => {
            if resp.ok {
                Ok(serde_json::json!({ "ok": true }))
            } else {
                Err(format!(
                    "Daemon reload failed: {}",
                    resp.error.unwrap_or_default()
                ))
            }
        }
        Err(_) => {
            // Daemon not connected — policy was written, will apply on next start
            Ok(serde_json::json!({ "ok": true, "note": "Daemon not connected; rule saved to disk" }))
        }
    }
}

// ---------------------------------------------------------------------------
// Post-processing: compute derived values
// ---------------------------------------------------------------------------

fn post_process(intent_id: &str, data: &mut HashMap<String, serde_json::Value>) {
    match intent_id {
        "status.protection_score" | "status.overall" => {
            let score = compute_protection_score(data);
            data.insert(
                "_protection_score".to_string(),
                serde_json::json!({ "score": score }),
            );
        }
        "activity.stats" => {
            if let Some(events) = data.get("get_recent_events").and_then(|v| v.as_array()) {
                let total = events.len();
                let blocked = events
                    .iter()
                    .filter(|e| {
                        let d = e
                            .get("decision")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        d == "block" || d == "blocked" || d == "deny"
                    })
                    .count();
                let allowed = events
                    .iter()
                    .filter(|e| {
                        let d = e
                            .get("decision")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        d == "allow" || d == "allowed"
                    })
                    .count();
                let prompted = total - blocked - allowed;

                // Count unique servers
                let servers: std::collections::HashSet<&str> = events
                    .iter()
                    .filter_map(|e| e.get("server_name").and_then(|v| v.as_str()))
                    .collect();

                data.insert(
                    "_stats".to_string(),
                    serde_json::json!({
                        "total_events": total,
                        "blocked": blocked,
                        "allowed": allowed,
                        "prompted": prompted,
                        "unique_servers": servers.len(),
                        "block_rate_percent": if total > 0 { (blocked as f64 / total as f64 * 100.0).round() } else { 0.0 },
                    }),
                );
            }
        }
        _ => {}
    }
}

/// Compute a 0-100 protection score from the gathered status data.
fn compute_protection_score(data: &HashMap<String, serde_json::Value>) -> u32 {
    let mut score: u32 = 0;

    // Daemon running: +30
    if let Some(status) = data.get("get_daemon_status") {
        if status
            .get("running")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            score += 30;
        }
    }

    // Servers wrapped: +20 (at least one)
    if let Some(servers) = data.get("list_mcp_servers").and_then(|v| v.as_array()) {
        if servers
            .iter()
            .any(|s| s.get("wrapped").and_then(|v| v.as_bool()).unwrap_or(false))
        {
            score += 20;
        }
    }

    // Behavioral engine enabled: +15
    if let Some(bs) = data.get("get_behavioral_status") {
        if bs
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            score += 15;
        }
    }

    // Threat intel active: +15
    if let Some(feed) = data.get("get_feed_status") {
        let version = feed
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !version.is_empty() && version != "not configured" {
            score += 15;
        }
    }

    // AI model loaded: +10
    if let Some(slm) = data.get("get_slm_status") {
        if slm
            .get("loaded")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            score += 10;
        }
    }

    // Events processed (active protection): +10
    if let Some(status) = data.get("get_daemon_status") {
        if status
            .get("events_processed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            > 0
        {
            score += 10;
        }
    }

    score.min(100)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn query(
    command: &str,
    params: HashMap<String, serde_json::Value>,
    required: bool,
) -> BackendQuery {
    BackendQuery {
        command: command.to_string(),
        params,
        required,
    }
}

fn params(entries: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn json_str(s: &str) -> serde_json::Value {
    serde_json::Value::String(s.to_string())
}

fn json_u32(n: u32) -> serde_json::Value {
    serde_json::Value::Number(serde_json::Number::from(n))
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn execute_query(
    intent_json: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let intent: IntentClassification =
        serde_json::from_str(&intent_json).map_err(|e| format!("Invalid intent JSON: {}", e))?;

    let plan = build_query_plan(&intent);
    let result = execute_query_plan(&plan, &state);

    serde_json::to_string(&result).map_err(|e| format!("Failed to serialize result: {}", e))
}

#[tauri::command]
pub async fn confirm_action(
    action_json: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let intent: IntentClassification =
        serde_json::from_str(&action_json).map_err(|e| format!("Invalid intent JSON: {}", e))?;

    let result = execute_confirmed_action(&intent, &state);

    serde_json::to_string(&result).map_err(|e| format!("Failed to serialize result: {}", e))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;

    fn make_intent(id: &str) -> IntentClassification {
        IntentClassification {
            intent_id: id.to_string(),
            confidence: 0.95,
            entities: HashMap::new(),
            method: super::super::intent::ClassificationMethod::Keyword,
        }
    }

    fn make_intent_with_entity(id: &str, key: &str, value: &str) -> IntentClassification {
        let mut entities = HashMap::new();
        entities.insert(key.to_string(), value.to_string());
        IntentClassification {
            intent_id: id.to_string(),
            confidence: 0.95,
            entities,
            method: super::super::intent::ClassificationMethod::Keyword,
        }
    }

    // -----------------------------------------------------------------------
    // Query plan building tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_plan_status_overall() {
        let intent = make_intent("status.overall");
        let plan = build_query_plan(&intent);
        assert_eq!(plan.intent_id, "status.overall");
        assert!(!plan.requires_confirmation);
        assert_eq!(plan.queries.len(), 4);
        assert_eq!(plan.queries[0].command, "get_daemon_status");
        assert_eq!(plan.queries[1].command, "get_recent_events");
        assert_eq!(plan.queries[2].command, "get_behavioral_status");
        assert_eq!(plan.queries[3].command, "get_feed_status");
    }

    #[test]
    fn test_plan_status_daemon() {
        let intent = make_intent("status.daemon");
        let plan = build_query_plan(&intent);
        assert_eq!(plan.queries.len(), 1);
        assert_eq!(plan.queries[0].command, "get_daemon_status");
        assert!(plan.queries[0].required);
    }

    #[test]
    fn test_plan_status_protection_score() {
        let intent = make_intent("status.protection_score");
        let plan = build_query_plan(&intent);
        assert_eq!(plan.queries.len(), 5);
        let commands: Vec<&str> = plan.queries.iter().map(|q| q.command.as_str()).collect();
        assert!(commands.contains(&"get_daemon_status"));
        assert!(commands.contains(&"list_mcp_servers"));
        assert!(commands.contains(&"get_behavioral_status"));
        assert!(commands.contains(&"get_feed_status"));
        assert!(commands.contains(&"get_slm_status"));
    }

    #[test]
    fn test_plan_status_server_specific() {
        let intent = make_intent_with_entity("status.server_specific", "server_name", "cursor-server");
        let plan = build_query_plan(&intent);
        assert_eq!(plan.queries.len(), 3);
        let rep_query = plan
            .queries
            .iter()
            .find(|q| q.command == "check_server_reputation")
            .unwrap();
        assert_eq!(
            rep_query.params.get("name").and_then(|v| v.as_str()),
            Some("cursor-server")
        );
    }

    #[test]
    fn test_plan_activity_recent() {
        let intent = make_intent("activity.recent");
        let plan = build_query_plan(&intent);
        assert_eq!(plan.queries.len(), 1);
        assert_eq!(plan.queries[0].command, "get_recent_events");
        assert_eq!(
            plan.queries[0].params.get("count").and_then(|v| v.as_u64()),
            Some(20)
        );
    }

    #[test]
    fn test_plan_activity_blocked() {
        let intent = make_intent("activity.blocked");
        let plan = build_query_plan(&intent);
        assert_eq!(plan.queries[0].command, "get_recent_events");
        assert_eq!(
            plan.queries[0]
                .params
                .get("filter")
                .and_then(|v| v.as_str()),
            Some("blocked")
        );
    }

    #[test]
    fn test_plan_activity_server() {
        let intent = make_intent_with_entity("activity.server", "server_name", "github-server");
        let plan = build_query_plan(&intent);
        assert_eq!(
            plan.queries[0]
                .params
                .get("filter_server")
                .and_then(|v| v.as_str()),
            Some("github-server")
        );
    }

    #[test]
    fn test_plan_activity_stats() {
        let intent = make_intent("activity.stats");
        let plan = build_query_plan(&intent);
        assert_eq!(
            plan.queries[0].params.get("count").and_then(|v| v.as_u64()),
            Some(1000)
        );
    }

    #[test]
    fn test_plan_risk_server() {
        let intent = make_intent_with_entity("risk.server", "server_name", "evil-server");
        let plan = build_query_plan(&intent);
        assert_eq!(plan.queries.len(), 3);
        assert_eq!(plan.queries[0].command, "check_server_reputation");
        assert_eq!(plan.queries[1].command, "get_profiles");
        assert_eq!(plan.queries[2].command, "get_blocklist_matches");
    }

    #[test]
    fn test_plan_risk_file_empty() {
        let intent = make_intent("risk.file");
        let plan = build_query_plan(&intent);
        assert!(plan.queries.is_empty());
    }

    #[test]
    fn test_plan_risk_url_empty() {
        let intent = make_intent("risk.url");
        let plan = build_query_plan(&intent);
        assert!(plan.queries.is_empty());
    }

    #[test]
    fn test_plan_control_block_requires_confirmation() {
        let intent = make_intent_with_entity("control.block", "server_name", "bad-server");
        let plan = build_query_plan(&intent);
        assert!(plan.requires_confirmation);
        assert!(plan.confirmation_message.is_some());
        assert!(plan
            .confirmation_message
            .as_ref()
            .unwrap()
            .contains("bad-server"));
        assert_eq!(plan.queries.len(), 2);
        assert_eq!(plan.queries[0].command, "add_rule");
        assert_eq!(plan.queries[1].command, "reload_policy");
    }

    #[test]
    fn test_plan_control_allow_requires_confirmation() {
        let intent = make_intent_with_entity("control.allow", "server_name", "good-server");
        let plan = build_query_plan(&intent);
        assert!(plan.requires_confirmation);
        assert!(plan
            .confirmation_message
            .as_ref()
            .unwrap()
            .contains("good-server"));
    }

    #[test]
    fn test_plan_control_scan_no_confirmation() {
        let intent = make_intent("control.scan");
        let plan = build_query_plan(&intent);
        assert!(!plan.requires_confirmation);
        assert_eq!(plan.queries[0].command, "start_scan");
    }

    #[test]
    fn test_plan_control_tighten_requires_confirmation() {
        let intent = make_intent("control.tighten");
        let plan = build_query_plan(&intent);
        assert!(plan.requires_confirmation);
        assert!(plan
            .confirmation_message
            .as_ref()
            .unwrap()
            .contains("stricter"));
    }

    #[test]
    fn test_plan_control_pause_requires_confirmation() {
        let intent = make_intent("control.pause");
        let plan = build_query_plan(&intent);
        assert!(plan.requires_confirmation);
        assert!(plan
            .confirmation_message
            .as_ref()
            .unwrap()
            .contains("30 minutes"));
    }

    #[test]
    fn test_plan_control_update_threat_intel() {
        let intent = make_intent("control.update_threat_intel");
        let plan = build_query_plan(&intent);
        assert!(!plan.requires_confirmation);
        assert_eq!(plan.queries[0].command, "force_feed_update");
    }

    #[test]
    fn test_plan_explain_event() {
        let intent = make_intent("explain.event");
        let plan = build_query_plan(&intent);
        assert_eq!(plan.queries.len(), 2);
        assert_eq!(plan.queries[0].command, "get_recent_events");
        assert_eq!(plan.queries[1].command, "get_slm_status");
    }

    #[test]
    fn test_plan_explain_concept_no_queries() {
        let intent = make_intent("explain.concept");
        let plan = build_query_plan(&intent);
        assert!(plan.queries.is_empty());
    }

    #[test]
    fn test_plan_explain_why_blocked() {
        let intent = make_intent("explain.why_blocked");
        let plan = build_query_plan(&intent);
        assert_eq!(plan.queries[0].command, "get_recent_events");
        assert_eq!(
            plan.queries[0]
                .params
                .get("filter")
                .and_then(|v| v.as_str()),
            Some("blocked")
        );
    }

    #[test]
    fn test_plan_explain_recommendation() {
        let intent = make_intent("explain.recommendation");
        let plan = build_query_plan(&intent);
        assert_eq!(plan.queries.len(), 3);
    }

    #[test]
    fn test_plan_navigate_no_queries() {
        for id in &["navigate.page", "navigate.server_detail"] {
            let intent = make_intent(id);
            let plan = build_query_plan(&intent);
            assert!(plan.queries.is_empty());
        }
    }

    #[test]
    fn test_plan_help_no_queries() {
        for id in &["help.general", "help.how_to"] {
            let intent = make_intent(id);
            let plan = build_query_plan(&intent);
            assert!(plan.queries.is_empty());
        }
    }

    #[test]
    fn test_plan_unknown_intent() {
        let intent = make_intent("unknown.intent");
        let plan = build_query_plan(&intent);
        assert!(plan.queries.is_empty());
        assert!(!plan.requires_confirmation);
    }

    // -----------------------------------------------------------------------
    // Query execution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_confirmation_returns_preview() {
        let intent = make_intent_with_entity("control.block", "server_name", "evil-server");
        let plan = build_query_plan(&intent);
        let state = AppState::default();
        let result = execute_query_plan(&plan, &state);
        assert!(result.requires_confirmation);
        assert!(result.confirmation_preview.is_some());
        assert!(result.data.is_empty());
    }

    #[test]
    fn test_execute_empty_plan() {
        let intent = make_intent("help.general");
        let plan = build_query_plan(&intent);
        let state = AppState::default();
        let result = execute_query_plan(&plan, &state);
        assert!(result.complete);
        assert!(result.data.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_execute_daemon_status_returns_data() {
        let intent = make_intent("status.daemon");
        let plan = build_query_plan(&intent);
        let state = AppState::default();
        let result = execute_query_plan(&plan, &state);
        // Should return a status object regardless of daemon state
        assert!(result.data.contains_key("get_daemon_status"));
        let status = &result.data["get_daemon_status"];
        assert!(status.get("running").is_some());
        assert!(status.get("socket_path").is_some());
    }

    #[test]
    fn test_execute_recent_events_from_buffer() {
        let state = AppState::default();

        // Push some events into the buffer
        for i in 0..5 {
            state.push_event(AuditEvent {
                id: format!("evt-{}", i),
                timestamp: format!("2026-01-15T10:{}:00Z", 30 + i),
                event_type: "proxy".to_string(),
                server_name: "test-server".to_string(),
                tool_name: None,
                action: "read_file".to_string(),
                decision: if i % 2 == 0 { "allow" } else { "block" }.to_string(),
                risk_level: "info".to_string(),
                details: String::new(),
                resource: None,
            });
        }

        let intent = make_intent("activity.recent");
        let plan = build_query_plan(&intent);
        let result = execute_query_plan(&plan, &state);

        assert!(result.complete);
        let events = result.data["get_recent_events"].as_array().unwrap();
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn test_execute_blocked_filter() {
        let state = AppState::default();

        state.push_event(AuditEvent {
            id: "evt-1".to_string(),
            timestamp: "2026-01-15T10:30:00Z".to_string(),
            event_type: "proxy".to_string(),
            server_name: "test".to_string(),
            tool_name: None,
            action: "write_file".to_string(),
            decision: "block".to_string(),
            risk_level: "high".to_string(),
            details: String::new(),
            resource: None,
        });
        state.push_event(AuditEvent {
            id: "evt-2".to_string(),
            timestamp: "2026-01-15T10:31:00Z".to_string(),
            event_type: "proxy".to_string(),
            server_name: "test".to_string(),
            tool_name: None,
            action: "read_file".to_string(),
            decision: "allow".to_string(),
            risk_level: "info".to_string(),
            details: String::new(),
            resource: None,
        });

        let intent = make_intent("activity.blocked");
        let plan = build_query_plan(&intent);
        let result = execute_query_plan(&plan, &state);

        let events = result.data["get_recent_events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]
                .get("decision")
                .and_then(|v| v.as_str()),
            Some("block")
        );
    }

    #[test]
    fn test_execute_server_filter() {
        let state = AppState::default();

        state.push_event(AuditEvent {
            id: "evt-1".to_string(),
            timestamp: "2026-01-15T10:30:00Z".to_string(),
            event_type: "proxy".to_string(),
            server_name: "cursor-server".to_string(),
            tool_name: None,
            action: "test".to_string(),
            decision: "allow".to_string(),
            risk_level: "info".to_string(),
            details: String::new(),
            resource: None,
        });
        state.push_event(AuditEvent {
            id: "evt-2".to_string(),
            timestamp: "2026-01-15T10:31:00Z".to_string(),
            event_type: "proxy".to_string(),
            server_name: "github-server".to_string(),
            tool_name: None,
            action: "test".to_string(),
            decision: "allow".to_string(),
            risk_level: "info".to_string(),
            details: String::new(),
            resource: None,
        });

        let intent =
            make_intent_with_entity("activity.server", "server_name", "cursor-server");
        let plan = build_query_plan(&intent);
        let result = execute_query_plan(&plan, &state);

        let events = result.data["get_recent_events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]
                .get("server_name")
                .and_then(|v| v.as_str()),
            Some("cursor-server")
        );
    }

    #[test]
    fn test_execute_activity_stats_post_processing() {
        let state = AppState::default();

        for i in 0..10 {
            state.push_event(AuditEvent {
                id: format!("evt-{}", i),
                timestamp: format!("2026-01-15T10:{}:00Z", 30 + i),
                event_type: "proxy".to_string(),
                server_name: if i < 5 {
                    "server-a".to_string()
                } else {
                    "server-b".to_string()
                },
                tool_name: None,
                action: "test".to_string(),
                decision: if i < 3 {
                    "block".to_string()
                } else {
                    "allow".to_string()
                },
                risk_level: "info".to_string(),
                details: String::new(),
                resource: None,
            });
        }

        let intent = make_intent("activity.stats");
        let plan = build_query_plan(&intent);
        let result = execute_query_plan(&plan, &state);

        let stats = &result.data["_stats"];
        assert_eq!(stats.get("total_events").and_then(|v| v.as_u64()), Some(10));
        assert_eq!(stats.get("blocked").and_then(|v| v.as_u64()), Some(3));
        assert_eq!(stats.get("allowed").and_then(|v| v.as_u64()), Some(7));
        assert_eq!(
            stats.get("unique_servers").and_then(|v| v.as_u64()),
            Some(2)
        );
    }

    #[test]
    fn test_protection_score_all_down() {
        let data = HashMap::new();
        assert_eq!(compute_protection_score(&data), 0);
    }

    #[test]
    fn test_protection_score_daemon_running() {
        let mut data = HashMap::new();
        data.insert(
            "get_daemon_status".to_string(),
            serde_json::json!({
                "running": true,
                "events_processed": 50
            }),
        );
        assert_eq!(compute_protection_score(&data), 40); // 30 + 10
    }

    #[test]
    fn test_protection_score_full() {
        let mut data = HashMap::new();
        data.insert(
            "get_daemon_status".to_string(),
            serde_json::json!({ "running": true, "events_processed": 50 }),
        );
        data.insert(
            "list_mcp_servers".to_string(),
            serde_json::json!([{ "wrapped": true }]),
        );
        data.insert(
            "get_behavioral_status".to_string(),
            serde_json::json!({ "enabled": true }),
        );
        data.insert(
            "get_feed_status".to_string(),
            serde_json::json!({ "version": "1.0" }),
        );
        data.insert(
            "get_slm_status".to_string(),
            serde_json::json!({ "loaded": true }),
        );
        let score = compute_protection_score(&data);
        assert_eq!(score, 100);
    }

    #[test]
    fn test_protection_score_capped_at_100() {
        let mut data = HashMap::new();
        data.insert(
            "get_daemon_status".to_string(),
            serde_json::json!({ "running": true, "events_processed": 50 }),
        );
        data.insert(
            "list_mcp_servers".to_string(),
            serde_json::json!([{ "wrapped": true }]),
        );
        data.insert(
            "get_behavioral_status".to_string(),
            serde_json::json!({ "enabled": true }),
        );
        data.insert(
            "get_feed_status".to_string(),
            serde_json::json!({ "version": "1.0" }),
        );
        data.insert(
            "get_slm_status".to_string(),
            serde_json::json!({ "loaded": true }),
        );
        assert!(compute_protection_score(&data) <= 100);
    }

    #[test]
    fn test_execute_confirmed_action_offline() {
        let state = AppState::default();
        let intent = make_intent_with_entity("control.block", "server_name", "test-server");
        // execute_confirmed_action will try to add_rule (writes to disk)
        // and reload_policy (daemon offline, tolerated).
        // In test context, policy write may fail due to missing dirs, but
        // the function should not panic.
        let result = execute_confirmed_action(&intent, &state);
        // Either complete or has errors, but should not panic
        assert!(result.data.len() + result.errors.len() > 0);
    }

    #[test]
    fn test_time_range_params() {
        let mut entities = HashMap::new();
        entities.insert("time_start".to_string(), "2026-01-15T00:00:00Z".to_string());
        entities.insert("time_end".to_string(), "2026-01-15T23:59:59Z".to_string());
        let intent = IntentClassification {
            intent_id: "activity.time_range".to_string(),
            confidence: 0.9,
            entities,
            method: super::super::intent::ClassificationMethod::Keyword,
        };
        let plan = build_query_plan(&intent);
        assert_eq!(
            plan.queries[0]
                .params
                .get("time_start")
                .and_then(|v| v.as_str()),
            Some("2026-01-15T00:00:00Z")
        );
        assert_eq!(
            plan.queries[0]
                .params
                .get("time_end")
                .and_then(|v| v.as_str()),
            Some("2026-01-15T23:59:59Z")
        );
    }

    #[test]
    fn test_every_intent_has_plan() {
        let intents = vec![
            "status.overall",
            "status.daemon",
            "status.protection_score",
            "status.server_specific",
            "activity.recent",
            "activity.time_range",
            "activity.blocked",
            "activity.server",
            "activity.stats",
            "risk.file",
            "risk.url",
            "risk.server",
            "risk.action",
            "control.block",
            "control.allow",
            "control.trust_level",
            "control.scan",
            "control.tighten",
            "control.pause",
            "control.update_threat_intel",
            "explain.event",
            "explain.concept",
            "explain.why_blocked",
            "explain.recommendation",
            "navigate.page",
            "navigate.server_detail",
            "help.general",
            "help.how_to",
        ];

        for id in intents {
            let intent = make_intent(id);
            let plan = build_query_plan(&intent);
            assert_eq!(plan.intent_id, id, "Plan intent_id mismatch for {}", id);
        }
    }

    #[test]
    fn test_execution_time_tracked() {
        let state = AppState::default();
        let intent = make_intent("help.general");
        let plan = build_query_plan(&intent);
        let result = execute_query_plan(&plan, &state);
        // execution_time_ms should be a small positive number
        assert!(result.execution_time_ms < 1000);
    }

    #[test]
    fn test_optional_query_failure_tolerated() {
        let state = AppState::default();
        let plan = QueryPlan {
            intent_id: "test".to_string(),
            queries: vec![
                BackendQuery {
                    command: "nonexistent_command".to_string(),
                    params: HashMap::new(),
                    required: false,
                },
            ],
            requires_confirmation: false,
            confirmation_message: None,
        };
        let result = execute_query_plan(&plan, &state);
        assert!(result.complete); // optional failure doesn't break completeness
        assert!(result.errors.contains_key("nonexistent_command"));
    }

    #[test]
    fn test_required_query_failure_marks_incomplete() {
        let state = AppState::default();
        let plan = QueryPlan {
            intent_id: "test".to_string(),
            queries: vec![
                BackendQuery {
                    command: "nonexistent_command".to_string(),
                    params: HashMap::new(),
                    required: true,
                },
            ],
            requires_confirmation: false,
            confirmation_message: None,
        };
        let result = execute_query_plan(&plan, &state);
        assert!(!result.complete);
        assert!(result.errors.contains_key("nonexistent_command"));
    }
}
