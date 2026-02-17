//! Type definitions for eslogger JSON events.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use tracing::warn;
use unicode_normalization::UnicodeNormalization;

use clawdefender_core::event::os::{OsEvent, OsEventKind};

/// Maximum allowed length for any string field from eslogger output.
const MAX_FIELD_LENGTH: usize = 4096;

/// Top-level event emitted by eslogger in JSON format.
#[derive(Debug, Clone, Deserialize)]
pub struct EsloggerEvent {
    /// The ES event type, e.g. "exec", "open", "connect".
    pub event_type: String,
    /// The process that triggered the event.
    pub process: EsloggerProcess,
    /// Event-specific payload (varies by event_type).
    pub event: serde_json::Value,
    /// ISO-8601 timestamp string from eslogger.
    pub timestamp: String,
}

/// Process information attached to each eslogger event.
#[derive(Debug, Clone, Deserialize)]
pub struct EsloggerProcess {
    pub pid: u32,
    pub ppid: u32,
    #[serde(rename = "executable", alias = "executable_path")]
    pub executable_path: String,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
    pub audit_token: Option<serde_json::Value>,
}

/// Data for an `exec` event.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecEventData {
    pub target_path: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// Data for an `open` event.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenEventData {
    pub path: String,
    #[serde(default)]
    pub flags: u32,
}

/// Data for a `connect` event.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectEventData {
    pub address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default = "default_socket_type")]
    pub socket_type: String,
}

fn default_socket_type() -> String {
    "tcp".to_string()
}

/// Data for a `fork` event.
#[derive(Debug, Clone, Deserialize)]
pub struct ForkEventData {
    pub child_pid: u32,
}

/// Data for an `exit` event.
#[derive(Debug, Clone, Deserialize)]
pub struct ExitEventData {
    #[serde(default)]
    pub status: i32,
}

/// Data for a `close` event.
#[derive(Debug, Clone, Deserialize)]
pub struct CloseEventData {
    pub path: String,
}

/// Data for a `rename` event.
#[derive(Debug, Clone, Deserialize)]
pub struct RenameEventData {
    pub source: String,
    pub dest: String,
}

/// Data for an `unlink` event.
#[derive(Debug, Clone, Deserialize)]
pub struct UnlinkEventData {
    pub path: String,
}

/// Data for a `pty_grant` event.
#[derive(Debug, Clone, Deserialize)]
pub struct PtyGrantEventData {
    pub path: String,
}

/// Data for a `setmode` event.
#[derive(Debug, Clone, Deserialize)]
pub struct SetModeEventData {
    pub path: String,
    pub mode: u32,
}

/// Truncate a string field to [`MAX_FIELD_LENGTH`] bytes on a char boundary.
fn truncate_field(s: &str) -> String {
    if s.len() <= MAX_FIELD_LENGTH {
        s.to_string()
    } else {
        warn!(
            len = s.len(),
            max = MAX_FIELD_LENGTH,
            "truncating oversized eslogger field"
        );
        let mut end = MAX_FIELD_LENGTH;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

/// Strip null bytes from a string, truncating at the first null.
/// Logs a warning if null bytes are found.
fn strip_null_bytes(s: &str) -> String {
    if let Some(pos) = s.find('\0') {
        warn!(path = %&s[..pos], "null byte found in eslogger field, truncating");
        s[..pos].to_string()
    } else {
        s.to_string()
    }
}

/// Sanitize a filesystem path from eslogger output.
///
/// 1. Remove null bytes (truncate at first null)
/// 2. Normalize to Unicode NFC
/// 3. Resolve `..` and `.` components (logical canonicalization without touching the filesystem)
/// 4. Enforce max field length
pub fn sanitize_path(path: &str) -> String {
    // Step 1: strip null bytes
    let clean = strip_null_bytes(path);

    // Step 2: Unicode NFC normalization
    let normalized: String = clean.nfc().collect();

    // Step 3: resolve .. and . components logically
    let canonicalized = logical_canonicalize(&normalized);

    // Step 4: enforce max length
    truncate_field(&canonicalized)
}

/// Logically resolve `.` and `..` path components without filesystem access.
/// Preserves leading `/` for absolute paths.
fn logical_canonicalize(path: &str) -> String {
    let is_absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                // Don't pop past root
                if !parts.is_empty() && *parts.last().unwrap() != ".." {
                    parts.pop();
                }
            }
            other => parts.push(other),
        }
    }

    let joined = parts.join("/");
    if is_absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

impl From<EsloggerEvent> for OsEvent {
    fn from(ev: EsloggerEvent) -> Self {
        let timestamp: DateTime<Utc> = ev
            .timestamp
            .parse()
            .unwrap_or_else(|_| Utc::now());

        let kind = match ev.event_type.as_str() {
            "exec" => {
                let data: ExecEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(ExecEventData {
                        target_path: String::new(),
                        args: Vec::new(),
                    });
                OsEventKind::Exec {
                    target_path: sanitize_path(&data.target_path),
                    args: data.args.into_iter().map(|a| truncate_field(&a)).collect(),
                }
            }
            "open" => {
                let data: OpenEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(OpenEventData {
                        path: String::new(),
                        flags: 0,
                    });
                OsEventKind::Open {
                    path: sanitize_path(&data.path),
                    flags: data.flags,
                }
            }
            "close" => {
                let data: CloseEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(CloseEventData {
                        path: String::new(),
                    });
                OsEventKind::Close {
                    path: sanitize_path(&data.path),
                }
            }
            "rename" => {
                let data: RenameEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(RenameEventData {
                        source: String::new(),
                        dest: String::new(),
                    });
                OsEventKind::Rename {
                    source: sanitize_path(&data.source),
                    dest: sanitize_path(&data.dest),
                }
            }
            "unlink" => {
                let data: UnlinkEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(UnlinkEventData {
                        path: String::new(),
                    });
                OsEventKind::Unlink {
                    path: sanitize_path(&data.path),
                }
            }
            "connect" => {
                let data: ConnectEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(ConnectEventData {
                        address: String::new(),
                        port: 0,
                        socket_type: "tcp".to_string(),
                    });
                OsEventKind::Connect {
                    address: truncate_field(&data.address),
                    port: data.port,
                    protocol: truncate_field(&data.socket_type),
                }
            }
            "fork" => {
                let data: ForkEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(ForkEventData {
                        child_pid: 0,
                    });
                OsEventKind::Fork {
                    child_pid: data.child_pid,
                }
            }
            "exit" => {
                let data: ExitEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(ExitEventData { status: -1 });
                OsEventKind::Exit {
                    status: data.status,
                }
            }
            "pty_grant" => {
                let data: PtyGrantEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(PtyGrantEventData {
                        path: String::new(),
                    });
                OsEventKind::PtyGrant {
                    path: sanitize_path(&data.path),
                }
            }
            "setmode" => {
                let data: SetModeEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(SetModeEventData {
                        path: String::new(),
                        mode: 0,
                    });
                OsEventKind::SetMode {
                    path: sanitize_path(&data.path),
                    mode: data.mode,
                }
            }
            // Unknown event types map to Exec with empty fields as a fallback.
            // The parser layer should filter these before conversion.
            other => OsEventKind::Exec {
                target_path: format!("<unknown event_type: {other}>"),
                args: Vec::new(),
            },
        };

        OsEvent {
            timestamp,
            pid: ev.process.pid,
            ppid: ev.process.ppid,
            process_path: sanitize_path(&ev.process.executable_path),
            kind,
            signing_id: ev.process.signing_id.map(|s| truncate_field(&s)),
            team_id: ev.process.team_id.map(|s| truncate_field(&s)),
        }
    }
}
