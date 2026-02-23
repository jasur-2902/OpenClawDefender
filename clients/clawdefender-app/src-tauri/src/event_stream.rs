use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;
use tracing::{debug, info, warn};

use crate::events::{self, AlertPayload, AutoBlockPayload, SuspiciousEventPayload};
use crate::state::{AppState, AuditEvent, PendingPrompt};

// ## Event Pipeline Architecture
//
// Events flow through 5 stages from MCP proxy to the GUI:
//
// 1. MCP Client (e.g. Claude Desktop) spawns wrapped server:
//    `clawdefender proxy -- <server-command>`
//
// 2. Proxy intercepts JSON-RPC messages in stdio.rs:
//    - Classifies: Pass / Log / Review / Block
//    - Evaluates policy engine
//    - Creates enriched AuditRecord with: server_name, tool_name,
//      arguments, jsonrpc_method, classification, policy_action
//    - Writes to audit.jsonl via FileAuditLogger
//
// 3. FileAuditLogger writes to ~/.local/share/clawdefender/audit.jsonl:
//    - JSON-lines format, one AuditRecord per line
//    - Session-start/session-end records include server_name
//    - Log rotation and retention handled automatically
//
// 4. This module (event_stream) watches audit.jsonl:
//    - Polls every 500ms for new lines
//    - Parses each line as DaemonAuditRecord
//    - Maps to AuditEvent via to_audit_event()
//    - Emits Tauri events to the frontend
//
// 5. Frontend receives events:
//    - Timeline.tsx: virtualized list with server, tool, resource, decision
//    - Dashboard.tsx: recent activity feed and stat cards
//    - eventStore.ts: Zustand store for state management
//
// ## Field Mapping (audit.jsonl -> AuditEvent)
//
// | audit.jsonl field  | AuditEvent field | Notes                    |
// |-------------------|-----------------|--------------------------|
// | timestamp         | timestamp       | ISO 8601 string          |
// | source            | event_type      | "mcp-proxy", "system"    |
// | server_name       | server_name     | "unknown" if None        |
// | tool_name         | tool_name       | Optional                 |
// | event_summary     | action          | Human-readable label     |
// | policy_action     | decision        | "allowed"/"blocked"/etc  |
// | classification    | risk_level      | Normalized to low/med/hi |
// | arguments         | resource        | Extracted path/uri/url   |

/// Poll interval for checking audit.jsonl for new lines.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Maximum number of lines to backfill on startup.
const BACKFILL_LIMIT: usize = 100;

/// Security: remove pending prompts that have exceeded their timeout.
/// Unanswered prompts default to deny (fail-closed) to prevent agents from
/// silently bypassing security by ignoring prompts.
fn expire_timed_out_prompts(app: &AppHandle) {
    let state = app.state::<AppState>();
    let now = chrono::Utc::now();

    let result = state.pending_prompts.lock();
    if let Ok(mut prompts) = result {
        let before_len = prompts.len();
        prompts.retain(|prompt| {
            if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&prompt.timestamp) {
                let elapsed = now.signed_duration_since(created);
                if elapsed.num_seconds() > prompt.timeout_seconds as i64 {
                    warn!(
                        prompt_id = %prompt.id,
                        server = %prompt.server_name,
                        tool = %prompt.tool_name,
                        "Prompt timed out after {}s — auto-denying (fail-closed)",
                        prompt.timeout_seconds
                    );
                    return false; // remove expired prompt
                }
            }
            true // keep non-expired prompts
        });
        if prompts.len() < before_len {
            debug!(
                expired = before_len - prompts.len(),
                "Expired timed-out prompts"
            );
        }
    }
}

/// The daemon's audit record format (subset of fields we care about).
/// Uses `default` on all optional fields so deserialization is lenient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonAuditRecord {
    pub timestamp: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub event_summary: String,
    #[serde(default)]
    pub action_taken: String,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub jsonrpc_method: Option<String>,
    #[serde(default)]
    pub policy_action: Option<String>,
    #[serde(default)]
    pub classification: Option<String>,
    #[serde(default)]
    pub event_details: Option<serde_json::Value>,
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
    #[serde(default)]
    pub slm_analysis: Option<SlmAnalysisField>,
}

/// SLM analysis data embedded in audit records by the event router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmAnalysisField {
    pub risk_level: String,
    pub explanation: String,
    pub confidence: f32,
    #[serde(default)]
    pub latency_ms: u64,
    #[serde(default)]
    pub model: String,
}

/// Path to the audit.jsonl file.
/// Security note: this path is under the user's home directory and is controlled
/// by the daemon. We check that it is not a symlink to prevent symlink attacks
/// where an attacker replaces audit.jsonl with a symlink to a malicious file.
pub fn audit_log_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/share/clawdefender/audit.jsonl")
}

/// Check that the audit log path is a regular file (not a symlink).
pub(crate) fn is_safe_audit_path(path: &PathBuf) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => !meta.file_type().is_symlink(),
        Err(_) => false, // file doesn't exist yet, caller should check existence first
    }
}

/// Normalize classification/risk strings to the TypeScript union type:
/// "low" | "medium" | "high" | "critical".
fn normalize_risk_level(raw: &str) -> &'static str {
    match raw.to_lowercase().as_str() {
        "critical" | "crit" => "critical",
        "high" | "block" | "blocked" => "high",
        "medium" | "med" | "review" | "prompt" | "prompted" => "medium",
        "low" | "info" | "pass" | "log" | "logged" | "allow" | "allowed" => "low",
        _ => "low",
    }
}

/// Build a human-readable description from a daemon audit record.
fn build_human_details(record: &DaemonAuditRecord) -> String {
    let server = record.server_name.as_deref().unwrap_or("unknown");
    let tool = record.tool_name.as_deref();
    let method = record.jsonrpc_method.as_deref();

    // Try to extract a resource path from arguments for context
    let resource = record.arguments.as_ref().and_then(|args| {
        args.get("path")
            .or_else(|| args.get("uri"))
            .or_else(|| args.get("url"))
            .or_else(|| args.get("command"))
            .and_then(|v| v.as_str())
    });

    match (method, tool, resource) {
        (Some("tools/call"), Some(t), Some(r)) => format!("{server} {t} {r}"),
        (Some("tools/call"), Some(t), None) => format!("{server} called {t}"),
        (Some("resources/read"), _, Some(r)) => format!("{server} read resource {r}"),
        (Some("resources/read"), _, None) => format!("{server} read resource"),
        (Some("sampling/createMessage"), _, _) => format!("{server} AI sampling request"),
        (Some("tools/list"), _, _) | (Some("resources/list"), _, _) => {
            format!("{server} discovery request")
        }
        _ => {
            // Fallback: use event_summary if it's meaningful
            if record.event_summary == "session-start" {
                format!("{server} session started")
            } else if record.event_summary == "session-end" {
                format!("{server} session ended")
            } else if !record.event_summary.is_empty() {
                if server != "unknown" {
                    format!("{server}: {}", record.event_summary)
                } else {
                    record.event_summary.clone()
                }
            } else {
                record.event_summary.clone()
            }
        }
    }
}

/// Convert a daemon audit record to the GUI's AuditEvent.
pub fn to_audit_event(record: &DaemonAuditRecord, seq: u64) -> AuditEvent {
    let decision = record
        .policy_action
        .as_deref()
        .unwrap_or(&record.action_taken)
        .to_string();

    let raw_risk = record
        .classification
        .as_deref()
        .unwrap_or("info");
    let risk_level = normalize_risk_level(raw_risk).to_string();

    // Use event_summary which now contains human-readable labels from the proxy
    // (e.g. "File Read", "Shell Command"), falling back to jsonrpc_method.
    // Session events get human-friendly names instead of raw identifiers.
    let action = if record.event_summary == "session-start" {
        "Session Started".to_string()
    } else if record.event_summary == "session-end" {
        "Session Ended".to_string()
    } else if !record.event_summary.is_empty() {
        record.event_summary.clone()
    } else {
        record
            .jsonrpc_method
            .as_deref()
            .unwrap_or(&record.event_summary)
            .to_string()
    };

    // Build details: if SLM analysis is present, encode as JSON so the
    // frontend SlmAnalysisSection can parse it.
    let details = if let Some(ref slm) = record.slm_analysis {
        serde_json::json!({
            "description": build_human_details(record),
            "slm_analysis": {
                "risk_level": slm.risk_level,
                "explanation": slm.explanation,
                "confidence": slm.confidence,
            }
        }).to_string()
    } else {
        build_human_details(record)
    };

    let resource = record.arguments.as_ref().and_then(|args| {
        // Try to extract a meaningful resource path from arguments
        args.get("path")
            .or_else(|| args.get("uri"))
            .or_else(|| args.get("url"))
            .or_else(|| args.get("command"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    AuditEvent {
        id: format!("evt-{}", seq),
        timestamp: record.timestamp.clone(),
        event_type: record.source.clone(),
        server_name: record.server_name.clone().unwrap_or_else(|| "unknown".into()),
        tool_name: record.tool_name.clone(),
        action,
        decision,
        risk_level,
        details,
        resource,
    }
}

/// Determine a risk level string from the audit event for alert classification.
fn effective_risk(event: &AuditEvent) -> &str {
    event.risk_level.as_str()
}

/// Sanitize a resource path for display in notifications.
/// Replaces the user's home directory with ~ and truncates long paths
/// to avoid leaking sensitive information to shoulder surfers.
fn sanitize_path_for_notification(path: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let sanitized = if !home.is_empty() && path.starts_with(&home) {
        format!("~{}", &path[home.len()..])
    } else {
        path.to_string()
    };
    // Truncate very long paths, keeping the last component visible
    if sanitized.len() > 60 {
        let last_slash = sanitized.rfind('/').unwrap_or(0);
        if last_slash > 10 {
            format!("...{}", &sanitized[last_slash..])
        } else {
            format!("{}...", &sanitized[..57])
        }
    } else {
        sanitized
    }
}

/// Check whether the user has notifications enabled in config.toml.
fn notifications_enabled_in_config() -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = std::path::PathBuf::from(home).join(".config/clawdefender/config.toml");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return true, // default to enabled if config is missing
    };
    let table: toml::Value = match content.parse() {
        Ok(t) => t,
        Err(_) => return true,
    };
    table
        .get("ui")
        .and_then(|ui| ui.get("notifications"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// Send a native macOS notification if the main window is not focused
/// and the user has notifications enabled.
fn send_native_notification(app: &AppHandle, title: &str, body: &str, sound: bool) {
    // Check user preference
    if !notifications_enabled_in_config() {
        return;
    }

    // Check if main window is focused — skip notification if the user can see the in-app UI
    if let Some(window) = app.get_webview_window("main") {
        if let Ok(true) = window.is_focused() {
            return;
        }
    }

    let mut builder = app.notification().builder().title(title).body(body);
    if sound {
        builder = builder.sound("default");
    }
    if let Err(e) = builder.show() {
        debug!(error = %e, "Failed to send native notification (permission may be denied)");
    }
}

/// Process a single parsed audit event: push to state and emit frontend events.
fn process_event(app: &AppHandle, event: AuditEvent) {
    let state = app.state::<AppState>();
    let risk = effective_risk(&event);

    // Emit alert for critical/high risk events
    if risk == "critical" || risk == "high" || risk == "block" || risk == "review" {
        let alert = AlertPayload {
            id: event.id.clone(),
            level: risk.to_string(),
            message: format!("{} — {}", event.server_name, event.action),
            details: event.details.clone(),
            events: vec![SuspiciousEventPayload {
                timestamp: event.timestamp.clone(),
                action: event.action.clone(),
            }],
            kill_chain: None,
            pid: None,
        };
        events::emit_alert(app, &alert);

        send_native_notification(
            app,
            "ClawDefender \u{2014} Security Alert",
            &format!("{} \u{2014} {}", event.server_name, event.action),
            true,
        );
    }

    // Create a pending prompt for "prompted" decisions
    if event.decision == "prompted" || event.decision == "prompt" {
        let prompt = PendingPrompt {
            id: event.id.clone(),
            timestamp: event.timestamp.clone(),
            server_name: event.server_name.clone(),
            tool_name: event.tool_name.clone().unwrap_or_else(|| "unknown".into()),
            action: event.action.clone(),
            resource: event.resource.clone().unwrap_or_default(),
            risk_level: event.risk_level.clone(),
            context: event.details.clone(),
            timeout_seconds: 30,
        };
        state.push_prompt(prompt.clone());
        events::emit_prompt(app, &prompt);

        let resource_display = if event.resource.as_deref().unwrap_or("").is_empty() {
            event.action.clone()
        } else {
            sanitize_path_for_notification(event.resource.as_deref().unwrap_or(""))
        };
        send_native_notification(
            app,
            "ClawDefender \u{2014} Action Required",
            &format!("{} wants to {}", event.server_name, resource_display),
            true,
        );
    }

    // Emit auto-block event for denied/blocked decisions
    if event.decision == "denied" || event.decision == "blocked" || event.decision == "block" {
        let auto_block = AutoBlockPayload {
            id: event.id.clone(),
            server_name: event.server_name.clone(),
            action: event.action.clone(),
            anomaly_score: 0.0,
        };
        events::emit_auto_block(app, &auto_block);

        send_native_notification(
            app,
            "ClawDefender \u{2014} Blocked",
            &format!("Blocked {} by {}", event.action, event.server_name),
            false,
        );
    }

    // Always push to state and emit the audit event
    events::emit_audit_event(app, &event);
    state.push_event(event);
}

/// Read the last N lines from a file for backfill.
/// Returns the lines and the file position after the last line.
/// Uses a bounded ring buffer to avoid reading the entire file into memory.
pub(crate) fn read_last_n_lines(path: &PathBuf, n: usize) -> (Vec<String>, u64) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return (Vec::new(), 0),
    };

    let end_pos = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return (Vec::new(), 0),
    };

    // Use a ring buffer of capacity n to avoid storing all lines in memory.
    // This keeps memory usage bounded regardless of file size.
    let reader = BufReader::new(&file);
    let mut ring: std::collections::VecDeque<String> = std::collections::VecDeque::with_capacity(n);
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };
        if ring.len() == n {
            ring.pop_front();
        }
        ring.push_back(line);
    }

    (ring.into_iter().collect(), end_pos)
}

/// Spawns a background thread that monitors the audit.jsonl file for new lines
/// and feeds them into the GUI as real-time events.
pub fn start_event_stream(app: AppHandle) {
    thread::spawn(move || {
        let path = audit_log_path();
        let mut seq: u64 = 0;
        let mut last_size: u64 = 0;

        info!(path = %path.display(), "Event stream: starting audit.jsonl watcher");

        // Backfill: read last N events from the file if it exists
        if path.exists() && is_safe_audit_path(&path) {
            let (lines, end_pos) = read_last_n_lines(&path, BACKFILL_LIMIT);
            last_size = end_pos;

            for line in &lines {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<DaemonAuditRecord>(line) {
                    Ok(record) => {
                        let event = to_audit_event(&record, seq);
                        seq += 1;
                        // For backfill, only push to state (don't emit alerts/prompts for old events)
                        let state = app.state::<AppState>();
                        state.push_event(event);
                    }
                    Err(e) => {
                        debug!(error = %e, "Skipping malformed backfill line");
                    }
                }
            }

            if !lines.is_empty() {
                info!(count = lines.len(), "Event stream: backfilled events from audit.jsonl");
            }
        }

        // Main polling loop
        loop {
            thread::sleep(POLL_INTERVAL);

            // Security: expire pending prompts that have timed out.
            // Unanswered prompts auto-deny to prevent silent allow-by-inaction.
            expire_timed_out_prompts(&app);

            // If the file doesn't exist, reset and wait
            if !path.exists() {
                if last_size > 0 {
                    debug!("audit.jsonl disappeared, resetting position");
                    last_size = 0;
                }
                continue;
            }

            // Security: reject symlinks to prevent reading attacker-controlled files
            if !is_safe_audit_path(&path) {
                warn!("audit.jsonl is a symlink — skipping for security");
                continue;
            }

            // Check file size
            let current_size = match std::fs::metadata(&path) {
                Ok(m) => m.len(),
                Err(_) => continue,
            };

            // File was truncated/rotated — reset to beginning
            if current_size < last_size {
                info!("audit.jsonl truncated (rotation?), resetting to start");
                last_size = 0;
            }

            // No new data
            if current_size == last_size {
                continue;
            }

            // Read new bytes from last_size to current_size
            let mut file = match File::open(&path) {
                Ok(f) => f,
                Err(_) => continue,
            };

            if file.seek(SeekFrom::Start(last_size)).is_err() {
                continue;
            }

            let reader = BufReader::new(&file);
            for line_result in reader.lines() {
                match line_result {
                    Ok(line) => {
                        if line.trim().is_empty() {
                            continue;
                        }

                        match serde_json::from_str::<DaemonAuditRecord>(&line) {
                            Ok(record) => {
                                let event = to_audit_event(&record, seq);
                                seq += 1;
                                process_event(&app, event);
                            }
                            Err(e) => {
                                warn!(error = %e, "Skipping malformed audit line");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Error reading audit.jsonl line");
                        break;
                    }
                }
            }

            last_size = current_size;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn sample_audit_json() -> &'static str {
        r#"{"timestamp":"2025-01-15T10:30:00Z","source":"proxy","event_summary":"Tool call","action_taken":"allowed","server_name":"filesystem","tool_name":"read_file","jsonrpc_method":"tools/call","policy_action":"allow","classification":"info"}"#
    }

    fn sample_audit_json_minimal() -> &'static str {
        r#"{"timestamp":"2025-01-15T10:30:00Z"}"#
    }

    #[test]
    fn test_parse_valid_audit_record() {
        let record: DaemonAuditRecord =
            serde_json::from_str(sample_audit_json()).expect("should parse valid JSON");
        assert_eq!(record.timestamp, "2025-01-15T10:30:00Z");
        assert_eq!(record.source, "proxy");
        assert_eq!(record.server_name, Some("filesystem".into()));
        assert_eq!(record.tool_name, Some("read_file".into()));
        assert_eq!(record.policy_action, Some("allow".into()));
        assert_eq!(record.classification, Some("info".into()));
    }

    #[test]
    fn test_parse_malformed_line_returns_error() {
        let result = serde_json::from_str::<DaemonAuditRecord>("not valid json {{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_line() {
        let result = serde_json::from_str::<DaemonAuditRecord>("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_optional_fields() {
        let record: DaemonAuditRecord =
            serde_json::from_str(sample_audit_json_minimal()).expect("should parse minimal JSON");
        assert_eq!(record.timestamp, "2025-01-15T10:30:00Z");
        assert_eq!(record.source, ""); // default
        assert_eq!(record.event_summary, ""); // default
        assert_eq!(record.server_name, None);
        assert_eq!(record.tool_name, None);
        assert_eq!(record.policy_action, None);
        assert_eq!(record.classification, None);
        assert_eq!(record.event_details, None);
        assert_eq!(record.arguments, None);
    }

    #[test]
    fn test_to_audit_event_basic() {
        let record: DaemonAuditRecord =
            serde_json::from_str(sample_audit_json()).unwrap();
        let event = to_audit_event(&record, 42);
        assert_eq!(event.id, "evt-42");
        assert_eq!(event.timestamp, "2025-01-15T10:30:00Z");
        assert_eq!(event.event_type, "proxy");
        assert_eq!(event.server_name, "filesystem");
        assert_eq!(event.tool_name, Some("read_file".into()));
        assert_eq!(event.decision, "allow");
        assert_eq!(event.risk_level, "low"); // "info" normalizes to "low"
        assert_eq!(event.action, "Tool call"); // event_summary is now preferred
    }

    #[test]
    fn test_to_audit_event_minimal_defaults() {
        let record: DaemonAuditRecord =
            serde_json::from_str(sample_audit_json_minimal()).unwrap();
        let event = to_audit_event(&record, 0);
        assert_eq!(event.id, "evt-0");
        assert_eq!(event.server_name, "unknown");
        assert_eq!(event.decision, ""); // action_taken default is empty string
        assert_eq!(event.risk_level, "low"); // "info" normalizes to "low"
    }

    #[test]
    fn test_audit_log_path_contains_expected_suffix() {
        let path = audit_log_path();
        assert!(
            path.to_string_lossy().ends_with(".local/share/clawdefender/audit.jsonl"),
            "path should end with .local/share/clawdefender/audit.jsonl, got: {}",
            path.display()
        );
    }

    #[test]
    fn test_is_safe_audit_path_regular_file() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("audit.jsonl");
        std::fs::write(&file_path, "{}").unwrap();
        assert!(is_safe_audit_path(&file_path));
    }

    #[test]
    fn test_is_safe_audit_path_rejects_symlink() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target.jsonl");
        std::fs::write(&target, "{}").unwrap();
        let link = tmp.path().join("audit.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(!is_safe_audit_path(&link));
    }

    #[test]
    fn test_is_safe_audit_path_nonexistent_file() {
        let path = PathBuf::from("/tmp/nonexistent-clawdefender-test-file-xyz.jsonl");
        assert!(!is_safe_audit_path(&path));
    }

    #[test]
    fn test_read_last_n_lines_basic() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.jsonl");
        let mut file = std::fs::File::create(&path).unwrap();
        for i in 0..10 {
            writeln!(file, "line {}", i).unwrap();
        }
        file.flush().unwrap();

        let (lines, pos) = read_last_n_lines(&path, 3);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line 7");
        assert_eq!(lines[1], "line 8");
        assert_eq!(lines[2], "line 9");
        assert!(pos > 0);
    }

    #[test]
    fn test_read_last_n_lines_fewer_lines_than_requested() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.jsonl");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "only line").unwrap();
        file.flush().unwrap();

        let (lines, _) = read_last_n_lines(&path, 100);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "only line");
    }

    #[test]
    fn test_read_last_n_lines_empty_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("empty.jsonl");
        std::fs::File::create(&path).unwrap();

        let (lines, _) = read_last_n_lines(&path, 10);
        assert!(lines.is_empty());
    }

    #[test]
    fn test_read_last_n_lines_nonexistent_file() {
        let path = PathBuf::from("/tmp/nonexistent-clawdefender-read-test.jsonl");
        let (lines, pos) = read_last_n_lines(&path, 10);
        assert!(lines.is_empty());
        assert_eq!(pos, 0);
    }

    #[test]
    fn test_read_last_n_lines_backfill_limit() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("large.jsonl");
        let mut file = std::fs::File::create(&path).unwrap();
        for i in 0..200 {
            writeln!(file, "line {}", i).unwrap();
        }
        file.flush().unwrap();

        // Read last 100 (simulating BACKFILL_LIMIT)
        let (lines, _) = read_last_n_lines(&path, 100);
        assert_eq!(lines.len(), 100);
        assert_eq!(lines[0], "line 100");
        assert_eq!(lines[99], "line 199");
    }
}
