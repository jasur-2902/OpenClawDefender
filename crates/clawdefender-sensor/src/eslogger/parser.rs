//! Parser for eslogger NDJSON output.

use anyhow::{Context, Result};
use tracing::warn;

use super::types::EsloggerEvent;

/// Known event types that we can handle.
const KNOWN_EVENT_TYPES: &[&str] = &[
    "exec", "open", "close", "rename", "unlink", "connect", "fork", "exit", "pty_grant", "setmode",
];

/// Maximum JSON line length we will attempt to parse (1 MB).
/// Lines exceeding this are rejected to prevent memory abuse.
const MAX_JSON_LINE_LENGTH: usize = 1_048_576;

/// Parse a single JSON line from eslogger output into an [`EsloggerEvent`].
///
/// Returns an error for malformed JSON, unknown event types, or oversized lines.
pub fn parse_event(json_line: &str) -> Result<EsloggerEvent> {
    if json_line.len() > MAX_JSON_LINE_LENGTH {
        warn!(
            len = json_line.len(),
            max = MAX_JSON_LINE_LENGTH,
            "rejecting oversized eslogger JSON line"
        );
        anyhow::bail!("eslogger JSON line exceeds maximum length ({} > {})", json_line.len(), MAX_JSON_LINE_LENGTH);
    }

    let event: EsloggerEvent =
        serde_json::from_str(json_line).context("failed to parse eslogger JSON line")?;

    if !KNOWN_EVENT_TYPES.contains(&event.event_type.as_str()) {
        warn!(event_type = %event.event_type, "unknown eslogger event type");
        anyhow::bail!("unknown event type: {}", event.event_type);
    }

    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdefender_core::event::os::{OsEvent, OsEventKind};

    fn exec_event_json() -> &'static str {
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

    fn connect_event_json() -> &'static str {
        r#"{
            "event_type": "connect",
            "process": {
                "pid": 5678,
                "ppid": 1234,
                "executable": "/usr/bin/curl",
                "signing_id": null,
                "team_id": null
            },
            "event": {
                "address": "93.184.216.34",
                "port": 443,
                "socket_type": "tcp"
            },
            "timestamp": "2026-01-15T10:31:00Z"
        }"#
    }

    fn open_event_json() -> &'static str {
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

    #[test]
    fn parse_exec_event() {
        let event = parse_event(exec_event_json()).expect("should parse exec event");
        assert_eq!(event.event_type, "exec");
        assert_eq!(event.process.pid, 1234);
        assert_eq!(event.process.ppid, 1);
        assert_eq!(event.process.executable_path, "/usr/bin/node");
        assert_eq!(event.process.signing_id.as_deref(), Some("com.nodejs.node"));
    }

    #[test]
    fn parse_connect_event() {
        let event = parse_event(connect_event_json()).expect("should parse connect event");
        assert_eq!(event.event_type, "connect");
        assert_eq!(event.process.pid, 5678);
    }

    #[test]
    fn parse_open_event() {
        let event = parse_event(open_event_json()).expect("should parse open event");
        assert_eq!(event.event_type, "open");
        assert_eq!(event.process.pid, 9999);
        assert_eq!(event.process.signing_id.as_deref(), Some("com.apple.python3"));
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
    fn convert_exec_to_os_event() {
        let es_event = parse_event(exec_event_json()).unwrap();
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
    fn convert_connect_to_os_event() {
        let es_event = parse_event(connect_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        match &os_event.kind {
            OsEventKind::Connect {
                address,
                port,
                protocol,
            } => {
                assert_eq!(address, "93.184.216.34");
                assert_eq!(*port, 443);
                assert_eq!(protocol, "tcp");
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[test]
    fn convert_open_to_os_event() {
        let es_event = parse_event(open_event_json()).unwrap();
        let os_event: OsEvent = es_event.into();
        match &os_event.kind {
            OsEventKind::Open { path, flags } => {
                assert_eq!(path, "/etc/passwd");
                assert_eq!(*flags, 0);
            }
            other => panic!("expected Open, got {other:?}"),
        }
    }
}
