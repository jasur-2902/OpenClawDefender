//! Type definitions for eslogger JSON events.

use chrono::{DateTime, Utc};
use serde::Deserialize;

use claw_core::event::os::{OsEvent, OsEventKind};

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
                    target_path: data.target_path,
                    args: data.args,
                }
            }
            "open" => {
                let data: OpenEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(OpenEventData {
                        path: String::new(),
                        flags: 0,
                    });
                OsEventKind::Open {
                    path: data.path,
                    flags: data.flags,
                }
            }
            "close" => {
                let data: CloseEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(CloseEventData {
                        path: String::new(),
                    });
                OsEventKind::Close { path: data.path }
            }
            "rename" => {
                let data: RenameEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(RenameEventData {
                        source: String::new(),
                        dest: String::new(),
                    });
                OsEventKind::Rename {
                    source: data.source,
                    dest: data.dest,
                }
            }
            "unlink" => {
                let data: UnlinkEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(UnlinkEventData {
                        path: String::new(),
                    });
                OsEventKind::Unlink { path: data.path }
            }
            "connect" => {
                let data: ConnectEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(ConnectEventData {
                        address: String::new(),
                        port: 0,
                        socket_type: "tcp".to_string(),
                    });
                OsEventKind::Connect {
                    address: data.address,
                    port: data.port,
                    protocol: data.socket_type,
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
                OsEventKind::PtyGrant { path: data.path }
            }
            "setmode" => {
                let data: SetModeEventData =
                    serde_json::from_value(ev.event.clone()).unwrap_or(SetModeEventData {
                        path: String::new(),
                        mode: 0,
                    });
                OsEventKind::SetMode {
                    path: data.path,
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
            process_path: ev.process.executable_path,
            kind,
            signing_id: ev.process.signing_id,
            team_id: ev.process.team_id,
        }
    }
}
