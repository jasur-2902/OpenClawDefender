//! JSON-RPC newline-delimited stream parser.

use anyhow::{Context, Result};
use tracing::warn;

use super::types::JsonRpcMessage;

/// Parse a single JSON-RPC message from bytes.
pub fn parse_message(bytes: &[u8]) -> Result<JsonRpcMessage> {
    serde_json::from_slice(bytes).context("failed to parse JSON-RPC message")
}

/// Serialize a [`JsonRpcMessage`] to JSON bytes with a trailing newline.
pub fn serialize_message(msg: &JsonRpcMessage) -> Vec<u8> {
    let mut buf = serde_json::to_vec(msg).expect("JsonRpcMessage serialization cannot fail");
    buf.push(b'\n');
    buf
}

/// A streaming parser that extracts newline-delimited JSON-RPC messages from
/// an arbitrary byte stream.
pub struct StreamParser {
    buf: Vec<u8>,
}

impl StreamParser {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append a chunk of bytes to the internal buffer.
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Try to extract the next complete newline-delimited message.
    ///
    /// Returns `None` if no complete message is available yet.
    /// Returns `Some(Err(_))` if a complete line was found but contained
    /// malformed JSON — the line is consumed and parsing continues on the
    /// next call.
    pub fn next_message(&mut self) -> Option<Result<JsonRpcMessage>> {
        loop {
            let newline_pos = self.buf.iter().position(|&b| b == b'\n')?;
            let line: Vec<u8> = self.buf.drain(..=newline_pos).collect();
            let trimmed = line.strip_suffix(b"\n").unwrap_or(&line);

            // Skip empty lines.
            if trimmed.is_empty() {
                continue;
            }

            match parse_message(trimmed) {
                Ok(msg) => return Some(Ok(msg)),
                Err(e) => {
                    warn!("skipping malformed JSON-RPC line: {e}");
                    return Some(Err(e));
                }
            }
        }
    }
}

impl Default for StreamParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonrpc::types::{JsonRpcId, JsonRpcRequest};

    fn sample_request_json() -> String {
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec"}}"#.into()
    }

    fn sample_notification_json() -> String {
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.into()
    }

    fn sample_response_json() -> String {
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#.into()
    }

    // -----------------------------------------------------------------------
    // parse_message
    // -----------------------------------------------------------------------

    #[test]
    fn parse_valid_request() {
        let msg = parse_message(sample_request_json().as_bytes()).unwrap();
        match msg {
            JsonRpcMessage::Request(r) => assert_eq!(r.method, "tools/call"),
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn parse_valid_notification() {
        let msg = parse_message(sample_notification_json().as_bytes()).unwrap();
        match msg {
            JsonRpcMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/initialized");
            }
            _ => panic!("expected notification"),
        }
    }

    #[test]
    fn parse_valid_response() {
        let msg = parse_message(sample_response_json().as_bytes()).unwrap();
        match msg {
            JsonRpcMessage::Response(r) => {
                assert!(r.result.is_some());
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn parse_malformed_json() {
        assert!(parse_message(b"not json").is_err());
    }

    #[test]
    fn parse_empty_bytes() {
        assert!(parse_message(b"").is_err());
    }

    #[test]
    fn parse_truncated_json() {
        assert!(parse_message(br#"{"jsonrpc":"2.0","id":1,"meth"#).is_err());
    }

    #[test]
    fn parse_missing_fields() {
        // Object with no id and no method
        assert!(parse_message(br#"{"jsonrpc":"2.0"}"#).is_err());
    }

    #[test]
    fn parse_unicode_in_arguments() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"日本語ツール","arguments":{"text":"こんにちは"}}}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        match msg {
            JsonRpcMessage::Request(r) => {
                assert_eq!(r.method, "tools/call");
                let name = r.params.as_ref().unwrap()["name"].as_str().unwrap();
                assert_eq!(name, "日本語ツール");
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn parse_null_params() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":null}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        match msg {
            JsonRpcMessage::Request(r) => {
                // serde deserializes explicit null as None for Option fields
                assert!(r.params.is_none());
                assert_eq!(r.method, "initialize");
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn parse_large_message() {
        let big_arg = "x".repeat(100_000);
        let json = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"data":"{}"}}}}"#,
            big_arg
        );
        let msg = parse_message(json.as_bytes()).unwrap();
        match msg {
            JsonRpcMessage::Request(r) => assert_eq!(r.method, "tools/call"),
            _ => panic!("expected request"),
        }
    }

    // -----------------------------------------------------------------------
    // serialize_message
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_roundtrip() {
        let original = JsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: JsonRpcId::Number(7),
            method: "ping".into(),
            params: None,
        });
        let bytes = serialize_message(&original);
        assert!(bytes.ends_with(b"\n"));
        let parsed = parse_message(&bytes[..bytes.len() - 1]).unwrap();
        match parsed {
            JsonRpcMessage::Request(r) => {
                assert_eq!(r.id, JsonRpcId::Number(7));
                assert_eq!(r.method, "ping");
            }
            _ => panic!("expected request"),
        }
    }

    // -----------------------------------------------------------------------
    // StreamParser
    // -----------------------------------------------------------------------

    #[test]
    fn stream_single_message() {
        let mut parser = StreamParser::new();
        let mut data = sample_request_json();
        data.push('\n');
        parser.feed(data.as_bytes());
        let msg = parser.next_message().unwrap().unwrap();
        match msg {
            JsonRpcMessage::Request(r) => assert_eq!(r.method, "tools/call"),
            _ => panic!("expected request"),
        }
        assert!(parser.next_message().is_none());
    }

    #[test]
    fn stream_multiple_messages_in_one_chunk() {
        let mut parser = StreamParser::new();
        let mut data = sample_request_json();
        data.push('\n');
        data.push_str(&sample_notification_json());
        data.push('\n');
        parser.feed(data.as_bytes());

        let m1 = parser.next_message().unwrap().unwrap();
        assert!(matches!(m1, JsonRpcMessage::Request(_)));

        let m2 = parser.next_message().unwrap().unwrap();
        assert!(matches!(m2, JsonRpcMessage::Notification(_)));

        assert!(parser.next_message().is_none());
    }

    #[test]
    fn stream_partial_message_across_feeds() {
        let mut parser = StreamParser::new();
        let full = format!("{}\n", sample_request_json());
        let (first_half, second_half) = full.as_bytes().split_at(full.len() / 2);

        parser.feed(first_half);
        assert!(parser.next_message().is_none());

        parser.feed(second_half);
        let msg = parser.next_message().unwrap().unwrap();
        assert!(matches!(msg, JsonRpcMessage::Request(_)));
    }

    #[test]
    fn stream_byte_by_byte() {
        let mut parser = StreamParser::new();
        let full = format!("{}\n", sample_request_json());
        for &b in full.as_bytes() {
            parser.feed(&[b]);
        }
        let msg = parser.next_message().unwrap().unwrap();
        assert!(matches!(msg, JsonRpcMessage::Request(_)));
        assert!(parser.next_message().is_none());
    }

    #[test]
    fn stream_malformed_line_skipped() {
        let mut parser = StreamParser::new();
        let data = format!("not valid json\n{}\n", sample_request_json());
        parser.feed(data.as_bytes());

        // First message is the malformed one — returns an error.
        let m1 = parser.next_message().unwrap();
        assert!(m1.is_err());

        // Second message should parse correctly.
        let m2 = parser.next_message().unwrap().unwrap();
        assert!(matches!(m2, JsonRpcMessage::Request(_)));
    }

    #[test]
    fn stream_empty_lines_skipped() {
        let mut parser = StreamParser::new();
        let data = format!("\n\n{}\n\n", sample_request_json());
        parser.feed(data.as_bytes());

        let msg = parser.next_message().unwrap().unwrap();
        assert!(matches!(msg, JsonRpcMessage::Request(_)));
    }
}
