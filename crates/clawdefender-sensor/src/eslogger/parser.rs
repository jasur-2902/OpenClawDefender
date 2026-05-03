//! Parser for eslogger NDJSON output.
//!
//! Handles the REAL macOS eslogger output format where:
//! - `event_type` is a numeric u32 (e.g. 9 = exec, 10 = open)
//! - Process PID lives at `process.audit_token.pid`
//! - `process.executable` is an object `{"path": "..."}`
//! - Timestamp field is `time` (RFC 3339) instead of `timestamp`
//! - Event payloads are nested under their type key (e.g. `event.exec`)
//!
//! The parser normalizes the real format into the existing [`EsloggerEvent`]
//! struct so all downstream code remains unchanged.

use anyhow::{Context, Result};
use serde_json::Value;
use tracing::warn;

use super::types::EsloggerEvent;
use super::types::EsloggerProcess;

/// Known event types that we can handle.
const KNOWN_EVENT_TYPES: &[&str] = &[
    "exec",
    "open",
    "close",
    "create",
    "rename",
    "unlink",
    "write",
    "uipc_connect",
    "fork",
    "exit",
    "pty_grant",
    "setmode",
    // High-value, low-noise events
    "kextload",
    "setuid",
    "setgid",
    "link",
    "btm_launch_item_add",
    "login_login",
    "login_logout",
    "authentication",
    "xp_malware_detected",
    "gatekeeper_user_override",
    // Medium-value events (filtered aggressively)
    "get_task",
    "trace",
    "proc_check",
];

/// Maximum JSON line length we will attempt to parse (1 MB).
/// Lines exceeding this are rejected to prevent memory abuse.
const MAX_JSON_LINE_LENGTH: usize = 1_048_576;

/// Map a numeric eslogger event_type to its string name.
fn event_type_from_number(n: u64) -> Option<&'static str> {
    match n {
        9 => Some("exec"),
        10 => Some("open"),
        11 => Some("fork"),
        13 => Some("create"),
        15 => Some("exit"),
        16 => Some("get_task"),
        17 => Some("kextload"),
        18 => Some("link"),
        19 => Some("setuid"),
        20 => Some("setgid"),
        22 => Some("setmode"),
        23 => Some("rename"),
        25 => Some("pty_grant"),
        27 => Some("close"),
        30 => Some("trace"),
        32 => Some("unlink"),
        34 => Some("proc_check"),
        38 => Some("uipc_connect"),
        42 => Some("write"),
        46 => Some("authentication"),
        57 => Some("login_login"),
        58 => Some("login_logout"),
        63 => Some("gatekeeper_user_override"),
        64 => Some("xp_malware_detected"),
        66 => Some("btm_launch_item_add"),
        _ => None,
    }
}

/// Helper: extract a nested string like `obj.executable.path`.
fn nested_str(v: &Value, outer: &str, inner: &str) -> String {
    v.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string()
}

/// Helper: extract a nested u64 like `audit_token.pid`.
fn nested_u64(v: &Value, outer: &str, inner: &str) -> u64 {
    v.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|n| n.as_u64())
        .unwrap_or(0)
}

/// Extract process info from the real eslogger format.
///
/// Real format:
/// ```json
/// {
///   "audit_token": {"pid": 1234},
///   "ppid": 1,
///   "executable": {"path": "/usr/bin/node"},
///   "signing_id": "com.nodejs.node",
///   "team_id": null
/// }
/// ```
fn extract_process(proc_val: &Value) -> EsloggerProcess {
    let pid = nested_u64(proc_val, "audit_token", "pid") as u32;
    let ppid = proc_val
        .get("ppid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let executable_path = nested_str(proc_val, "executable", "path");
    let signing_id = proc_val
        .get("signing_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let team_id = proc_val
        .get("team_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let audit_token = proc_val.get("audit_token").cloned();

    EsloggerProcess {
        pid,
        ppid,
        executable_path,
        signing_id,
        team_id,
        audit_token,
    }
}

/// Extract the flattened event payload from the real eslogger nested structure.
///
/// Real eslogger nests event data under the type key, e.g.:
/// ```json
/// {"exec": {"target": {"executable": {"path": "/target"}}, "args": ["arg1"]}}
/// ```
///
/// We flatten this into the simple format expected by the existing type structs:
/// ```json
/// {"target_path": "/target", "args": ["arg1"]}
/// ```
fn extract_event_payload(event_type: &str, event_val: &Value) -> Value {
    // Get the inner object for this event type (e.g. event.exec, event.open)
    let inner = match event_val.get(event_type) {
        Some(v) => v,
        None => return event_val.clone(),
    };

    match event_type {
        "exec" => {
            let target_path = inner
                .get("target")
                .and_then(|t| t.get("executable"))
                .and_then(|e| e.get("path"))
                .and_then(|p| p.as_str())
                .unwrap_or("");
            let args = inner
                .get("args")
                .cloned()
                .unwrap_or(Value::Array(Vec::new()));
            serde_json::json!({
                "target_path": target_path,
                "args": args,
            })
        }
        "open" => {
            let path = inner
                .get("file")
                .and_then(|f| f.get("path"))
                .and_then(|p| p.as_str())
                .unwrap_or("");
            let flags = inner.get("fflag").and_then(|f| f.as_u64()).unwrap_or(0);
            serde_json::json!({
                "path": path,
                "flags": flags,
            })
        }
        "close" => {
            let path = inner
                .get("target")
                .and_then(|t| t.get("path"))
                .and_then(|p| p.as_str())
                // Also try target.executable.path as fallback
                .or_else(|| {
                    inner
                        .get("target")
                        .and_then(|t| t.get("executable"))
                        .and_then(|e| e.get("path"))
                        .and_then(|p| p.as_str())
                })
                .unwrap_or("");
            serde_json::json!({
                "path": path,
            })
        }
        "create" => {
            // destination can be either:
            //   { "existing_file": { "path": "..." } }
            //   { "new_path": { "dir": { "path": "..." }, "filename": "..." } }
            let dest = inner.get("destination");
            let path = if let Some(existing) =
                dest.and_then(|d| d.get("existing_file"))
            {
                existing
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string()
            } else if let Some(new_path) = dest.and_then(|d| d.get("new_path")) {
                let dir = new_path
                    .get("dir")
                    .and_then(|d| d.get("path"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("");
                let filename = new_path
                    .get("filename")
                    .and_then(|f| f.as_str())
                    .unwrap_or("");
                if dir.is_empty() && filename.is_empty() {
                    String::new()
                } else {
                    format!("{}/{}", dir.trim_end_matches('/'), filename)
                }
            } else {
                String::new()
            };
            // Map create to an open-like payload so downstream treats it as a file operation
            serde_json::json!({
                "path": path,
                "flags": 0u32,
            })
        }
        "rename" => {
            // source and destination may be file objects with nested path, or have a
            // .path directly
            let source = inner
                .get("source")
                .and_then(|s| {
                    s.get("path")
                        .and_then(|p| p.as_str())
                        .or_else(|| s.as_str())
                })
                .unwrap_or("");
            let dest = inner
                .get("destination")
                .and_then(|d| {
                    d.get("path")
                        .and_then(|p| p.as_str())
                        .or_else(|| d.as_str())
                })
                .unwrap_or("");
            // Also try "destination.new_path" pattern
            let dest = if dest.is_empty() {
                inner
                    .get("destination")
                    .and_then(|d| d.get("new_path"))
                    .and_then(|np| {
                        let dir = np
                            .get("dir")
                            .and_then(|d| d.get("path"))
                            .and_then(|p| p.as_str())
                            .unwrap_or("");
                        let filename = np.get("filename").and_then(|f| f.as_str()).unwrap_or("");
                        Some(format!("{}/{}", dir.trim_end_matches('/'), filename))
                    })
                    .unwrap_or_default()
            } else {
                dest.to_string()
            };
            serde_json::json!({
                "source": source,
                "dest": dest,
            })
        }
        "unlink" => {
            let path = inner
                .get("target")
                .and_then(|t| t.get("path").and_then(|p| p.as_str()))
                .unwrap_or("");
            serde_json::json!({
                "path": path,
            })
        }
        "fork" => {
            let child_pid = inner
                .get("child")
                .and_then(|c| c.get("audit_token"))
                .and_then(|at| at.get("pid"))
                .and_then(|p| p.as_u64())
                .unwrap_or(0);
            serde_json::json!({
                "child_pid": child_pid,
            })
        }
        "exit" => {
            let stat = inner.get("stat").and_then(|s| s.as_i64()).unwrap_or(-1);
            serde_json::json!({
                "status": stat,
            })
        }
        "write" => {
            // Write events: target file path
            let path = inner
                .get("target")
                .and_then(|t| t.get("path").and_then(|p| p.as_str()))
                .unwrap_or("");
            serde_json::json!({
                "path": path,
                "flags": 0u32,
            })
        }
        "uipc_connect" => {
            // Unix domain socket connect: extract socket path and address info
            let address = inner
                .get("file")
                .and_then(|f| f.get("path").and_then(|p| p.as_str()))
                .or_else(|| {
                    inner
                        .get("address")
                        .and_then(|a| a.as_str())
                })
                .unwrap_or("");
            let port = inner.get("port").and_then(|p| p.as_u64()).unwrap_or(0);
            serde_json::json!({
                "address": address,
                "port": port,
                "socket_type": "unix",
            })
        }
        "pty_grant" => {
            let path = inner
                .get("dev")
                .and_then(|d| d.get("path").and_then(|p| p.as_str()))
                .or_else(|| inner.get("path").and_then(|p| p.as_str()))
                .unwrap_or("");
            serde_json::json!({
                "path": path,
            })
        }
        "setmode" => {
            let path = inner
                .get("target")
                .and_then(|t| t.get("path").and_then(|p| p.as_str()))
                .unwrap_or("");
            let mode = inner.get("mode").and_then(|m| m.as_u64()).unwrap_or(0);
            serde_json::json!({
                "path": path,
                "mode": mode,
            })
        }
        "kextload" => {
            let identifier = inner
                .get("identifier")
                .and_then(|i| i.as_str())
                .unwrap_or("");
            serde_json::json!({
                "identifier": identifier,
            })
        }
        "setuid" | "setgid" => {
            // These typically don't have a path in real eslogger, but we extract
            // the uid/gid and set path to empty
            let path = inner
                .get("target")
                .and_then(|t| t.get("path").and_then(|p| p.as_str()))
                .or_else(|| inner.get("path").and_then(|p| p.as_str()))
                .unwrap_or("");
            serde_json::json!({
                "path": path,
            })
        }
        "link" => {
            let path = inner
                .get("target")
                .and_then(|t| t.get("path").and_then(|p| p.as_str()))
                .or_else(|| inner.get("path").and_then(|p| p.as_str()))
                .unwrap_or("");
            serde_json::json!({
                "path": path,
            })
        }
        "btm_launch_item_add" => {
            let item_url = inner
                .get("item")
                .and_then(|i| i.get("url").and_then(|u| u.as_str()))
                .or_else(|| inner.get("item_url").and_then(|u| u.as_str()))
                .unwrap_or("");
            let item_type = inner
                .get("item")
                .and_then(|i| i.get("type").and_then(|t| t.as_str()))
                .or_else(|| inner.get("item_type").and_then(|t| t.as_str()))
                .unwrap_or("");
            serde_json::json!({
                "item_url": item_url,
                "item_type": item_type,
            })
        }
        "authentication" => {
            let success = inner
                .get("success")
                .and_then(|s| s.as_bool())
                .unwrap_or(false);
            serde_json::json!({
                "success": success,
            })
        }
        "xp_malware_detected" => {
            let name = inner
                .get("name")
                .and_then(|n| n.as_str())
                .or_else(|| {
                    inner
                        .get("malware_identifier")
                        .and_then(|m| m.as_str())
                })
                .unwrap_or("");
            serde_json::json!({
                "name": name,
            })
        }
        "gatekeeper_user_override" => {
            let path = inner
                .get("file")
                .and_then(|f| f.get("path").and_then(|p| p.as_str()))
                .or_else(|| inner.get("path").and_then(|p| p.as_str()))
                .unwrap_or("");
            serde_json::json!({
                "path": path,
            })
        }
        "get_task" | "trace" | "proc_check" => {
            let target_pid = inner
                .get("target")
                .and_then(|t| t.get("audit_token"))
                .and_then(|at| at.get("pid"))
                .and_then(|p| p.as_u64())
                .or_else(|| inner.get("target_pid").and_then(|p| p.as_u64()))
                .unwrap_or(0);
            serde_json::json!({
                "target_pid": target_pid,
            })
        }
        "login_login" | "login_logout" => {
            serde_json::json!({})
        }
        _ => inner.clone(),
    }
}

/// Map an eslogger event type name to the downstream event type name
/// expected by the `From<EsloggerEvent> for OsEvent` implementation.
///
/// Some real eslogger event types don't have direct counterparts in the
/// downstream `OsEventKind` enum, so we map them to the closest match:
/// - "create" and "write" produce Open-like payloads -> "open"
/// - "uipc_connect" produces Connect-like payloads -> "connect"
fn downstream_event_type(event_type: &str) -> &str {
    match event_type {
        "create" | "write" => "open",
        "uipc_connect" => "connect",
        other => other,
    }
}

/// Detect whether a JSON value looks like the real eslogger format
/// (numeric event_type) vs the simplified test format (string event_type).
fn is_real_eslogger_format(root: &Value) -> bool {
    matches!(root.get("event_type"), Some(Value::Number(_)))
}

/// Parse a single JSON line from REAL macOS eslogger output into an [`EsloggerEvent`].
///
/// The real format has:
/// - `event_type` as a numeric u32
/// - `process.audit_token.pid` for the process PID
/// - `process.executable.path` for the executable path
/// - `time` for the timestamp (RFC 3339)
/// - Event data nested under the type key (e.g. `event.exec`)
///
/// This function normalizes the real format into the existing [`EsloggerEvent`]
/// struct so all downstream code remains unchanged.
///
/// Also supports the simplified test format for backward compatibility.
///
/// Returns an error for malformed JSON, unknown event types, or oversized lines.
pub fn parse_event(json_line: &str) -> Result<EsloggerEvent> {
    if json_line.len() > MAX_JSON_LINE_LENGTH {
        warn!(
            len = json_line.len(),
            max = MAX_JSON_LINE_LENGTH,
            "rejecting oversized eslogger JSON line"
        );
        anyhow::bail!(
            "eslogger JSON line exceeds maximum length ({} > {})",
            json_line.len(),
            MAX_JSON_LINE_LENGTH
        );
    }

    let root: Value =
        serde_json::from_str(json_line).context("failed to parse eslogger JSON line")?;

    if is_real_eslogger_format(&root) {
        parse_real_format(&root)
    } else {
        parse_simplified_format(&root)
    }
}

/// Parse the real macOS eslogger NDJSON format (numeric event_type).
fn parse_real_format(root: &Value) -> Result<EsloggerEvent> {
    // Extract numeric event_type and map to string
    let event_type_num = root
        .get("event_type")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid numeric event_type"))?;

    let event_type = event_type_from_number(event_type_num).ok_or_else(|| {
        anyhow::anyhow!("unknown numeric event type: {}", event_type_num)
    })?;

    if !KNOWN_EVENT_TYPES.contains(&event_type) {
        warn!(event_type = %event_type, num = event_type_num, "unknown eslogger event type");
        anyhow::bail!("unknown event type: {}", event_type);
    }

    // Extract process info from nested structure
    let proc_val = root
        .get("process")
        .ok_or_else(|| anyhow::anyhow!("missing process field"))?;
    let process = extract_process(proc_val);

    // Extract and flatten event payload
    let event_val = root.get("event").cloned().unwrap_or(Value::Object(
        serde_json::Map::new(),
    ));
    let event = extract_event_payload(event_type, &event_val);

    // Extract timestamp from `time` field (RFC 3339)
    let timestamp = root
        .get("time")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Map to downstream event type name for the From<EsloggerEvent> impl
    let downstream_type = downstream_event_type(event_type);

    Ok(EsloggerEvent {
        event_type: downstream_type.to_string(),
        process,
        event,
        timestamp,
    })
}

/// Legacy event types accepted in the simplified format for backward
/// compatibility. These are not real eslogger event types but were used
/// in earlier test fixtures.
const LEGACY_EVENT_TYPES: &[&str] = &["connect", "symlink"];

/// Parse the simplified test format (string event_type, flat structure).
///
/// This preserves backward compatibility with the old format used in tests
/// and any external callers that might use the simplified format.
fn parse_simplified_format(root: &Value) -> Result<EsloggerEvent> {
    let event_type = root
        .get("event_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid event_type"))?
        .to_string();

    if !KNOWN_EVENT_TYPES.contains(&event_type.as_str())
        && !LEGACY_EVENT_TYPES.contains(&event_type.as_str())
    {
        warn!(event_type = %event_type, "unknown eslogger event type");
        anyhow::bail!("unknown event type: {}", event_type);
    }

    // Extract process - in simplified format, fields are flat
    let proc_val = root
        .get("process")
        .ok_or_else(|| anyhow::anyhow!("missing process field"))?;

    let pid = proc_val
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let ppid = proc_val
        .get("ppid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let executable_path = proc_val
        .get("executable")
        .and_then(|v| v.as_str())
        .or_else(|| proc_val.get("executable_path").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let signing_id = proc_val
        .get("signing_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let team_id = proc_val
        .get("team_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let audit_token = proc_val.get("audit_token").cloned();

    let process = EsloggerProcess {
        pid,
        ppid,
        executable_path,
        signing_id,
        team_id,
        audit_token,
    };

    // Extract event payload (already flat in simplified format)
    let event = root
        .get("event")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    // Extract timestamp
    let timestamp = root
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(EsloggerEvent {
        event_type,
        process,
        event,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdefender_core::event::os::{OsEvent, OsEventKind};

    // =======================================================================
    // Simplified format test data (backward compatibility)
    // =======================================================================

    fn simplified_exec_event_json() -> &'static str {
        r#"{
            "event_type": "exec",
            "process": {
                "pid": 1234,
                "ppid": 1,
                "executable": "/usr/bin/node",
                "signing_id": "com.nodejs.node",
                "team_id": null,
                "audit_token": null
            },
            "event": {
                "target_path": "/usr/local/bin/npm",
                "args": ["npm", "install", "lodash"]
            },
            "timestamp": "2026-01-15T10:30:00Z"
        }"#
    }

    fn simplified_open_event_json() -> &'static str {
        r#"{
            "event_type": "open",
            "process": {
                "pid": 9999,
                "ppid": 1,
                "executable": "/usr/bin/python3",
                "signing_id": "com.apple.python3",
                "team_id": "apple"
            },
            "event": {
                "path": "/etc/passwd",
                "flags": 0
            },
            "timestamp": "2026-01-15T10:32:00Z"
        }"#
    }

    // =======================================================================
    // Real eslogger format test data
    // =======================================================================

    fn real_exec_event_json() -> &'static str {
        r#"{
            "version": 10,
            "event_type": 9,
            "process": {
                "audit_token": {"pid": 1234, "pidversion": 42},
                "ppid": 1,
                "executable": {"path": "/usr/bin/node"},
                "signing_id": "com.nodejs.node",
                "team_id": null
            },
            "event": {
                "exec": {
                    "target": {
                        "executable": {"path": "/usr/local/bin/npm"},
                        "audit_token": {"pid": 5678}
                    },
                    "args": ["npm", "install", "lodash"]
                }
            },
            "time": "2026-04-28T11:19:41.007083347Z"
        }"#
    }

    fn real_open_event_json() -> &'static str {
        r#"{
            "version": 10,
            "event_type": 10,
            "process": {
                "audit_token": {"pid": 9999},
                "ppid": 1,
                "executable": {"path": "/usr/bin/python3"},
                "signing_id": "com.apple.python3",
                "team_id": "apple"
            },
            "event": {
                "open": {
                    "file": {"path": "/etc/passwd"},
                    "fflag": 0
                }
            },
            "time": "2026-04-28T11:20:00.000Z"
        }"#
    }

    fn real_fork_event_json() -> &'static str {
        r#"{
            "version": 10,
            "event_type": 11,
            "process": {
                "audit_token": {"pid": 100},
                "ppid": 1,
                "executable": {"path": "/bin/bash"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "fork": {
                    "child": {
                        "audit_token": {"pid": 200},
                        "executable": {"path": "/bin/bash"}
                    }
                }
            },
            "time": "2026-04-28T11:21:00.000Z"
        }"#
    }

    fn real_close_event_json() -> &'static str {
        r#"{
            "version": 10,
            "event_type": 27,
            "process": {
                "audit_token": {"pid": 500},
                "ppid": 1,
                "executable": {"path": "/usr/bin/vim"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "close": {
                    "target": {"path": "/tmp/test.txt"}
                }
            },
            "time": "2026-04-28T11:22:00.000Z"
        }"#
    }

    fn real_unlink_event_json() -> &'static str {
        r#"{
            "version": 10,
            "event_type": 32,
            "process": {
                "audit_token": {"pid": 600},
                "ppid": 1,
                "executable": {"path": "/bin/rm"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "unlink": {
                    "target": {"path": "/tmp/to_delete.txt"}
                }
            },
            "time": "2026-04-28T11:23:00.000Z"
        }"#
    }

    fn real_rename_event_json() -> &'static str {
        r#"{
            "version": 10,
            "event_type": 23,
            "process": {
                "audit_token": {"pid": 700},
                "ppid": 1,
                "executable": {"path": "/bin/mv"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "rename": {
                    "source": {"path": "/tmp/old.txt"},
                    "destination": {"path": "/tmp/new.txt"}
                }
            },
            "time": "2026-04-28T11:24:00.000Z"
        }"#
    }

    fn real_exit_event_json() -> &'static str {
        r#"{
            "version": 10,
            "event_type": 15,
            "process": {
                "audit_token": {"pid": 800},
                "ppid": 1,
                "executable": {"path": "/usr/bin/sleep"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "exit": {
                    "stat": 0
                }
            },
            "time": "2026-04-28T11:25:00.000Z"
        }"#
    }

    fn real_create_existing_file_json() -> &'static str {
        r#"{
            "version": 10,
            "event_type": 13,
            "process": {
                "audit_token": {"pid": 900},
                "ppid": 1,
                "executable": {"path": "/usr/bin/touch"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "create": {
                    "destination": {
                        "existing_file": {"path": "/tmp/existing.txt"}
                    }
                }
            },
            "time": "2026-04-28T11:26:00.000Z"
        }"#
    }

    fn real_create_new_path_json() -> &'static str {
        r#"{
            "version": 10,
            "event_type": 13,
            "process": {
                "audit_token": {"pid": 901},
                "ppid": 1,
                "executable": {"path": "/usr/bin/touch"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "create": {
                    "destination": {
                        "new_path": {
                            "dir": {"path": "/tmp"},
                            "filename": "brand_new.txt"
                        }
                    }
                }
            },
            "time": "2026-04-28T11:27:00.000Z"
        }"#
    }

    // =======================================================================
    // Simplified format tests (backward compatibility)
    // =======================================================================

    #[test]
    fn parse_simplified_exec_event() {
        let event = parse_event(simplified_exec_event_json()).expect("should parse exec event");
        assert_eq!(event.event_type, "exec");
        assert_eq!(event.process.pid, 1234);
        assert_eq!(event.process.ppid, 1);
        assert_eq!(event.process.executable_path, "/usr/bin/node");
        assert_eq!(event.process.signing_id.as_deref(), Some("com.nodejs.node"));
    }

    #[test]
    fn parse_simplified_open_event() {
        let event = parse_event(simplified_open_event_json()).expect("should parse open event");
        assert_eq!(event.event_type, "open");
        assert_eq!(event.process.pid, 9999);
        assert_eq!(
            event.process.signing_id.as_deref(),
            Some("com.apple.python3")
        );
    }

    #[test]
    fn unknown_event_type_returns_error() {
        let json = r#"{
            "event_type": "something_new",
            "process": {
                "pid": 100,
                "ppid": 1,
                "executable": "/bin/test"
            },
            "event": {},
            "timestamp": "2026-01-15T10:00:00Z"
        }"#;
        let result = parse_event(json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("unknown event type"), "got: {err_msg}");
    }

    #[test]
    fn malformed_json_returns_error() {
        let result = parse_event("{not valid json}");
        assert!(result.is_err());
    }

    #[test]
    fn missing_optional_fields_still_parses() {
        let json = r#"{
            "event_type": "exec",
            "process": {
                "pid": 42,
                "ppid": 1,
                "executable": "/bin/sh"
            },
            "event": {
                "target_path": "/bin/ls"
            },
            "timestamp": "2026-01-15T10:00:00Z"
        }"#;
        let event = parse_event(json).expect("should parse with missing optional fields");
        assert!(event.process.signing_id.is_none());
        assert!(event.process.team_id.is_none());
        assert!(event.process.audit_token.is_none());
    }

    #[test]
    fn convert_simplified_exec_to_os_event() {
        let es_event = parse_event(simplified_exec_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        assert_eq!(os_event.pid, 1234);
        assert_eq!(os_event.ppid, 1);
        assert_eq!(os_event.process_path, "/usr/bin/node");
        match &os_event.kind {
            OsEventKind::Exec { target_path, args } => {
                assert_eq!(target_path, "/usr/local/bin/npm");
                assert_eq!(args, &["npm", "install", "lodash"]);
            }
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    #[test]
    fn convert_simplified_open_to_os_event() {
        let es_event = parse_event(simplified_open_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        match &os_event.kind {
            OsEventKind::Open { path, flags } => {
                assert_eq!(path, "/etc/passwd");
                assert_eq!(*flags, 0);
            }
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn new_event_types_are_known() {
        let new_types = [
            "kextload",
            "setuid",
            "setgid",
            "link",
            "create",
            "write",
            "uipc_connect",
            "btm_launch_item_add",
            "login_login",
            "login_logout",
            "authentication",
            "xp_malware_detected",
            "gatekeeper_user_override",
            "get_task",
            "trace",
            "proc_check",
        ];
        for event_type in &new_types {
            assert!(
                KNOWN_EVENT_TYPES.contains(event_type),
                "{event_type} should be in KNOWN_EVENT_TYPES"
            );
        }
    }

    #[test]
    fn connect_and_symlink_are_not_known() {
        assert!(
            !KNOWN_EVENT_TYPES.contains(&"connect"),
            "connect should not be in KNOWN_EVENT_TYPES"
        );
        assert!(
            !KNOWN_EVENT_TYPES.contains(&"symlink"),
            "symlink should not be in KNOWN_EVENT_TYPES"
        );
    }

    #[test]
    fn parse_simplified_kextload_event() {
        let json = r#"{
            "event_type": "kextload",
            "process": { "pid": 100, "ppid": 1, "executable": "/usr/sbin/kextd" },
            "event": { "identifier": "com.malware.rootkit" },
            "timestamp": "2026-01-15T10:00:00Z"
        }"#;
        let event = parse_event(json).unwrap();
        let os: OsEvent = event.into();
        match &os.kind {
            OsEventKind::Kextload { identifier } => {
                assert_eq!(identifier, "com.malware.rootkit");
            }
            other => panic!("expected Kextload, got {other:?}"),
        }
    }

    #[test]
    fn parse_simplified_btm_launch_item_add_event() {
        let json = r#"{
            "event_type": "btm_launch_item_add",
            "process": { "pid": 200, "ppid": 1, "executable": "/usr/bin/installer" },
            "event": { "item_url": "/Library/LaunchDaemons/com.evil.daemon.plist", "item_type": "daemon" },
            "timestamp": "2026-01-15T10:00:00Z"
        }"#;
        let event = parse_event(json).unwrap();
        let os: OsEvent = event.into();
        match &os.kind {
            OsEventKind::BtmLaunchItemAdd {
                item_url,
                item_type,
            } => {
                assert_eq!(item_url, "/Library/LaunchDaemons/com.evil.daemon.plist");
                assert_eq!(item_type, "daemon");
            }
            other => panic!("expected BtmLaunchItemAdd, got {other:?}"),
        }
    }

    #[test]
    fn parse_simplified_authentication_event() {
        let json = r#"{
            "event_type": "authentication",
            "process": { "pid": 300, "ppid": 1, "executable": "/usr/bin/sudo" },
            "event": { "success": true },
            "timestamp": "2026-01-15T10:00:00Z"
        }"#;
        let event = parse_event(json).unwrap();
        let os: OsEvent = event.into();
        match &os.kind {
            OsEventKind::Authentication { success } => {
                assert!(*success);
            }
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    #[test]
    fn parse_simplified_get_task_event() {
        let json = r#"{
            "event_type": "get_task",
            "process": { "pid": 400, "ppid": 1, "executable": "/tmp/injector" },
            "event": { "target_pid": 12345 },
            "timestamp": "2026-01-15T10:00:00Z"
        }"#;
        let event = parse_event(json).unwrap();
        let os: OsEvent = event.into();
        match &os.kind {
            OsEventKind::GetTask { target_pid } => {
                assert_eq!(*target_pid, 12345);
            }
            other => panic!("expected GetTask, got {other:?}"),
        }
    }

    #[test]
    fn parse_simplified_xp_malware_detected_event() {
        let json = r#"{
            "event_type": "xp_malware_detected",
            "process": { "pid": 500, "ppid": 1, "executable": "/usr/libexec/XProtectService" },
            "event": { "name": "OSX.Trojan.Generic" },
            "timestamp": "2026-01-15T10:00:00Z"
        }"#;
        let event = parse_event(json).unwrap();
        let os: OsEvent = event.into();
        match &os.kind {
            OsEventKind::XpMalwareDetected { name } => {
                assert_eq!(name, "OSX.Trojan.Generic");
            }
            other => panic!("expected XpMalwareDetected, got {other:?}"),
        }
    }

    #[test]
    fn parse_simplified_login_events() {
        for event_type in &["login_login", "login_logout"] {
            let json = format!(
                r#"{{
                    "event_type": "{event_type}",
                    "process": {{ "pid": 600, "ppid": 1, "executable": "/usr/sbin/loginwindow" }},
                    "event": {{}},
                    "timestamp": "2026-01-15T10:00:00Z"
                }}"#
            );
            let event = parse_event(&json).unwrap();
            let os: OsEvent = event.into();
            match (&os.kind, *event_type) {
                (OsEventKind::LoginLogin, "login_login") => {}
                (OsEventKind::LoginLogout, "login_logout") => {}
                other => panic!("expected login event for {event_type}, got {other:?}"),
            }
        }
    }

    // =======================================================================
    // Real eslogger format tests
    // =======================================================================

    #[test]
    fn parse_real_exec_event() {
        let event = parse_event(real_exec_event_json()).expect("should parse real exec event");
        assert_eq!(event.event_type, "exec");
        assert_eq!(event.process.pid, 1234);
        assert_eq!(event.process.ppid, 1);
        assert_eq!(event.process.executable_path, "/usr/bin/node");
        assert_eq!(event.process.signing_id.as_deref(), Some("com.nodejs.node"));
        assert_eq!(event.timestamp, "2026-04-28T11:19:41.007083347Z");
    }

    #[test]
    fn convert_real_exec_to_os_event() {
        let es_event = parse_event(real_exec_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        assert_eq!(os_event.pid, 1234);
        assert_eq!(os_event.ppid, 1);
        assert_eq!(os_event.process_path, "/usr/bin/node");
        match &os_event.kind {
            OsEventKind::Exec { target_path, args } => {
                assert_eq!(target_path, "/usr/local/bin/npm");
                assert_eq!(args, &["npm", "install", "lodash"]);
            }
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    #[test]
    fn parse_real_open_event() {
        let event = parse_event(real_open_event_json()).expect("should parse real open event");
        assert_eq!(event.event_type, "open");
        assert_eq!(event.process.pid, 9999);
        assert_eq!(
            event.process.signing_id.as_deref(),
            Some("com.apple.python3")
        );
        assert_eq!(event.process.team_id.as_deref(), Some("apple"));
    }

    #[test]
    fn convert_real_open_to_os_event() {
        let es_event = parse_event(real_open_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        assert_eq!(os_event.pid, 9999);
        match &os_event.kind {
            OsEventKind::Open { path, flags } => {
                assert_eq!(path, "/etc/passwd");
                assert_eq!(*flags, 0);
            }
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn parse_real_fork_event() {
        let event = parse_event(real_fork_event_json()).expect("should parse real fork event");
        assert_eq!(event.event_type, "fork");
        assert_eq!(event.process.pid, 100);
    }

    #[test]
    fn convert_real_fork_to_os_event() {
        let es_event = parse_event(real_fork_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        match &os_event.kind {
            OsEventKind::Fork { child_pid } => {
                assert_eq!(*child_pid, 200);
            }
            other => panic!("expected Fork, got {other:?}"),
        }
    }

    #[test]
    fn parse_real_close_event() {
        let event = parse_event(real_close_event_json()).expect("should parse real close event");
        assert_eq!(event.event_type, "close");
        assert_eq!(event.process.pid, 500);
    }

    #[test]
    fn convert_real_close_to_os_event() {
        let es_event = parse_event(real_close_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        match &os_event.kind {
            OsEventKind::Close { path } => {
                assert_eq!(path, "/tmp/test.txt");
            }
            other => panic!("expected Close, got {other:?}"),
        }
    }

    #[test]
    fn parse_real_unlink_event() {
        let event = parse_event(real_unlink_event_json()).expect("should parse real unlink event");
        assert_eq!(event.event_type, "unlink");
        assert_eq!(event.process.pid, 600);
    }

    #[test]
    fn convert_real_unlink_to_os_event() {
        let es_event = parse_event(real_unlink_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        match &os_event.kind {
            OsEventKind::Unlink { path } => {
                assert_eq!(path, "/tmp/to_delete.txt");
            }
            other => panic!("expected Unlink, got {other:?}"),
        }
    }

    #[test]
    fn parse_real_rename_event() {
        let event = parse_event(real_rename_event_json()).expect("should parse real rename event");
        assert_eq!(event.event_type, "rename");
        assert_eq!(event.process.pid, 700);
    }

    #[test]
    fn convert_real_rename_to_os_event() {
        let es_event = parse_event(real_rename_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        match &os_event.kind {
            OsEventKind::Rename { source, dest } => {
                assert_eq!(source, "/tmp/old.txt");
                assert_eq!(dest, "/tmp/new.txt");
            }
            other => panic!("expected Rename, got {other:?}"),
        }
    }

    #[test]
    fn parse_real_exit_event() {
        let event = parse_event(real_exit_event_json()).expect("should parse real exit event");
        assert_eq!(event.event_type, "exit");
        assert_eq!(event.process.pid, 800);
    }

    #[test]
    fn convert_real_exit_to_os_event() {
        let es_event = parse_event(real_exit_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        match &os_event.kind {
            OsEventKind::Exit { status } => {
                assert_eq!(*status, 0);
            }
            other => panic!("expected Exit, got {other:?}"),
        }
    }

    #[test]
    fn parse_real_create_existing_file() {
        let event = parse_event(real_create_existing_file_json())
            .expect("should parse real create event (existing_file)");
        // create is mapped to "open" for downstream compatibility
        assert_eq!(event.event_type, "open");
        assert_eq!(event.process.pid, 900);
        let os_event: OsEvent = event.into();
        match &os_event.kind {
            OsEventKind::Open { path, .. } => {
                assert_eq!(path, "/tmp/existing.txt");
            }
            other => panic!("expected Open (from create), got {other:?}"),
        }
    }

    #[test]
    fn parse_real_create_new_path() {
        let event = parse_event(real_create_new_path_json())
            .expect("should parse real create event (new_path)");
        // create is mapped to "open" for downstream compatibility
        assert_eq!(event.event_type, "open");
        assert_eq!(event.process.pid, 901);
        let os_event: OsEvent = event.into();
        match &os_event.kind {
            OsEventKind::Open { path, .. } => {
                assert_eq!(path, "/tmp/brand_new.txt");
            }
            other => panic!("expected Open (from create), got {other:?}"),
        }
    }

    #[test]
    fn unknown_numeric_event_type_returns_error() {
        let json = r#"{
            "version": 10,
            "event_type": 99999,
            "process": {
                "audit_token": {"pid": 100},
                "ppid": 1,
                "executable": {"path": "/bin/test"}
            },
            "event": {},
            "time": "2026-04-28T11:00:00Z"
        }"#;
        let result = parse_event(json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown numeric event type"),
            "got: {err_msg}"
        );
    }

    #[test]
    fn real_format_with_missing_process_fields_uses_defaults() {
        let json = r#"{
            "version": 10,
            "event_type": 9,
            "process": {
                "audit_token": {},
                "ppid": 0,
                "executable": {"path": ""},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "exec": {
                    "target": {"executable": {"path": "/bin/ls"}},
                    "args": []
                }
            },
            "time": "2026-04-28T12:00:00Z"
        }"#;
        let event = parse_event(json).expect("should parse with missing fields");
        assert_eq!(event.process.pid, 0);
        assert_eq!(event.process.ppid, 0);
        assert_eq!(event.process.executable_path, "");
        assert!(event.process.signing_id.is_none());
    }

    #[test]
    fn event_type_number_mapping_covers_all_known() {
        // Verify all numeric IDs resolve to known event types
        let mappings: &[(u64, &str)] = &[
            (9, "exec"),
            (10, "open"),
            (11, "fork"),
            (13, "create"),
            (15, "exit"),
            (16, "get_task"),
            (17, "kextload"),
            (18, "link"),
            (19, "setuid"),
            (20, "setgid"),
            (22, "setmode"),
            (23, "rename"),
            (25, "pty_grant"),
            (27, "close"),
            (30, "trace"),
            (32, "unlink"),
            (34, "proc_check"),
            (38, "uipc_connect"),
            (42, "write"),
            (46, "authentication"),
            (57, "login_login"),
            (58, "login_logout"),
            (63, "gatekeeper_user_override"),
            (64, "xp_malware_detected"),
            (66, "btm_launch_item_add"),
        ];
        for (num, expected_name) in mappings {
            let name = event_type_from_number(*num);
            assert_eq!(
                name,
                Some(*expected_name),
                "event_type {num} should map to {expected_name}"
            );
            assert!(
                KNOWN_EVENT_TYPES.contains(expected_name),
                "{expected_name} (event_type={num}) should be in KNOWN_EVENT_TYPES"
            );
        }
    }

    #[test]
    fn real_uipc_connect_event() {
        let json = r#"{
            "version": 10,
            "event_type": 38,
            "process": {
                "audit_token": {"pid": 1100},
                "ppid": 1,
                "executable": {"path": "/usr/bin/curl"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "uipc_connect": {
                    "file": {"path": "/var/run/mDNSResponder"},
                    "port": 0
                }
            },
            "time": "2026-04-28T13:00:00Z"
        }"#;
        let event = parse_event(json).expect("should parse uipc_connect event");
        // uipc_connect is mapped to "connect" for downstream compatibility
        assert_eq!(event.event_type, "connect");
        let os_event: OsEvent = event.into();
        match &os_event.kind {
            OsEventKind::Connect {
                address,
                port,
                protocol,
            } => {
                assert_eq!(address, "/var/run/mDNSResponder");
                assert_eq!(*port, 0);
                assert_eq!(protocol, "unix");
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[test]
    fn real_write_event() {
        let json = r#"{
            "version": 10,
            "event_type": 42,
            "process": {
                "audit_token": {"pid": 1200},
                "ppid": 1,
                "executable": {"path": "/usr/bin/vim"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "write": {
                    "target": {"path": "/tmp/output.txt"}
                }
            },
            "time": "2026-04-28T13:01:00Z"
        }"#;
        let event = parse_event(json).expect("should parse write event");
        // write is mapped to "open" for downstream compatibility
        assert_eq!(event.event_type, "open");
        let os_event: OsEvent = event.into();
        match &os_event.kind {
            OsEventKind::Open { path, .. } => {
                assert_eq!(path, "/tmp/output.txt");
            }
            other => panic!("expected Open (from write), got {other:?}"),
        }
    }

    #[test]
    fn real_get_task_event() {
        let json = r#"{
            "version": 10,
            "event_type": 16,
            "process": {
                "audit_token": {"pid": 1300},
                "ppid": 1,
                "executable": {"path": "/tmp/injector"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "get_task": {
                    "target": {
                        "audit_token": {"pid": 12345}
                    }
                }
            },
            "time": "2026-04-28T13:02:00Z"
        }"#;
        let event = parse_event(json).expect("should parse real get_task event");
        let os: OsEvent = event.into();
        match &os.kind {
            OsEventKind::GetTask { target_pid } => {
                assert_eq!(*target_pid, 12345);
            }
            other => panic!("expected GetTask, got {other:?}"),
        }
    }

    #[test]
    fn real_authentication_event() {
        let json = r#"{
            "version": 10,
            "event_type": 46,
            "process": {
                "audit_token": {"pid": 1400},
                "ppid": 1,
                "executable": {"path": "/usr/bin/sudo"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "authentication": {
                    "success": true
                }
            },
            "time": "2026-04-28T13:03:00Z"
        }"#;
        let event = parse_event(json).expect("should parse real authentication event");
        let os: OsEvent = event.into();
        match &os.kind {
            OsEventKind::Authentication { success } => {
                assert!(*success);
            }
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    #[test]
    fn real_xp_malware_detected_event() {
        let json = r#"{
            "version": 10,
            "event_type": 64,
            "process": {
                "audit_token": {"pid": 1500},
                "ppid": 1,
                "executable": {"path": "/usr/libexec/XProtectService"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "xp_malware_detected": {
                    "name": "OSX.Trojan.Generic"
                }
            },
            "time": "2026-04-28T13:04:00Z"
        }"#;
        let event = parse_event(json).expect("should parse real xp_malware_detected event");
        let os: OsEvent = event.into();
        match &os.kind {
            OsEventKind::XpMalwareDetected { name } => {
                assert_eq!(name, "OSX.Trojan.Generic");
            }
            other => panic!("expected XpMalwareDetected, got {other:?}"),
        }
    }

    #[test]
    fn real_kextload_event() {
        let json = r#"{
            "version": 10,
            "event_type": 17,
            "process": {
                "audit_token": {"pid": 1600},
                "ppid": 1,
                "executable": {"path": "/usr/sbin/kextd"},
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "kextload": {
                    "identifier": "com.malware.rootkit"
                }
            },
            "time": "2026-04-28T13:05:00Z"
        }"#;
        let event = parse_event(json).expect("should parse real kextload event");
        let os: OsEvent = event.into();
        match &os.kind {
            OsEventKind::Kextload { identifier } => {
                assert_eq!(identifier, "com.malware.rootkit");
            }
            other => panic!("expected Kextload, got {other:?}"),
        }
    }

    #[test]
    fn real_login_events() {
        for (num, expected_type) in &[(57, "login_login"), (58, "login_logout")] {
            let json = format!(
                r#"{{
                    "version": 10,
                    "event_type": {num},
                    "process": {{
                        "audit_token": {{"pid": 1700}},
                        "ppid": 1,
                        "executable": {{"path": "/usr/sbin/loginwindow"}},
                        "signing_id": null,
                        "team_id": null
                    }},
                    "event": {{
                        "{expected_type}": {{}}
                    }},
                    "time": "2026-04-28T13:06:00Z"
                }}"#
            );
            let event = parse_event(&json).unwrap();
            assert_eq!(event.event_type, *expected_type);
            let os: OsEvent = event.into();
            match (&os.kind, *expected_type) {
                (OsEventKind::LoginLogin, "login_login") => {}
                (OsEventKind::LoginLogout, "login_logout") => {}
                other => panic!("expected login event for {expected_type}, got {other:?}"),
            }
        }
    }

    #[test]
    fn oversized_line_rejected() {
        let huge = "a".repeat(MAX_JSON_LINE_LENGTH + 1);
        let result = parse_event(&huge);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("maximum length"),
            "error should mention maximum length, got: {err}"
        );
    }
}
