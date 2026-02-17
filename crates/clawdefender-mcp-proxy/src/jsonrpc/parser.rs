//! JSON-RPC newline-delimited stream parser.

use anyhow::{Context, Result};
use tracing::{error, warn};

use super::types::JsonRpcMessage;

/// Maximum size for a single JSON-RPC message line (10 MB).
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum buffer size before we clear it to prevent memory exhaustion (20 MB).
const MAX_BUFFER_SIZE: usize = 20 * 1024 * 1024;

/// Maximum JSON nesting depth to prevent stack overflow attacks.
const MAX_JSON_DEPTH: usize = 128;

/// Parse a single JSON-RPC message from bytes.
pub fn parse_message(bytes: &[u8]) -> Result<JsonRpcMessage> {
    // Enforce maximum message size
    if bytes.len() > MAX_MESSAGE_SIZE {
        anyhow::bail!(
            "JSON-RPC message exceeds maximum size ({} bytes > {} bytes)",
            bytes.len(),
            MAX_MESSAGE_SIZE
        );
    }

    // Check JSON nesting depth before full parse
    if exceeds_json_depth(bytes, MAX_JSON_DEPTH) {
        anyhow::bail!(
            "JSON-RPC message exceeds maximum nesting depth ({})",
            MAX_JSON_DEPTH
        );
    }

    serde_json::from_slice(bytes).context("failed to parse JSON-RPC message")
}

/// Check if a JSON byte slice exceeds a maximum nesting depth.
/// This is a fast pre-parse check that only counts `{` and `[` brackets.
fn exceeds_json_depth(bytes: &[u8], max_depth: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape = false;

    for &b in bytes {
        if escape {
            escape = false;
            continue;
        }
        if b == b'\\' && in_string {
            escape = true;
            continue;
        }
        if b == b'"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match b {
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth {
                    return true;
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    false
}

/// Serialize a [`JsonRpcMessage`] to JSON bytes with a trailing newline.
pub fn serialize_message(msg: &JsonRpcMessage) -> Vec<u8> {
    let mut buf = serde_json::to_vec(msg).expect("JsonRpcMessage serialization cannot fail");
    buf.push(b'\n');
    buf
}

/// A parsed JSON-RPC message together with the original raw bytes (without trailing newline).
/// This supports transparent proxying: we parse for classification but forward original bytes.
#[derive(Debug, Clone)]
pub struct RawJsonRpcMessage {
    /// The parsed message, for classification and policy evaluation.
    pub parsed: JsonRpcMessage,
    /// The original raw bytes as received (without trailing newline).
    /// When forwarding, use these bytes to preserve exact formatting.
    pub raw_bytes: Vec<u8>,
}

impl RawJsonRpcMessage {
    /// Get the raw bytes with a trailing newline appended, ready to forward.
    pub fn raw_bytes_with_newline(&self) -> Vec<u8> {
        let mut buf = self.raw_bytes.clone();
        buf.push(b'\n');
        buf
    }
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
    ///
    /// If the buffer exceeds the maximum allowed size without a newline,
    /// the buffer is cleared and an error is logged.
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);

        // Safety check: if buffer grows too large without any newline, clear it
        if self.buf.len() > MAX_BUFFER_SIZE && !self.buf.contains(&b'\n') {
            error!(
                "StreamParser buffer exceeded {} bytes without a newline, clearing to prevent memory exhaustion",
                MAX_BUFFER_SIZE
            );
            self.buf.clear();
        }
    }

    /// Try to extract the next complete newline-delimited message.
    ///
    /// Returns `None` if no complete message is available yet.
    /// Returns `Some(Err(_))` if a complete line was found but contained
    /// malformed JSON or exceeded size limits — the line is consumed and
    /// parsing continues on the next call.
    pub fn next_message(&mut self) -> Option<Result<JsonRpcMessage>> {
        self.next_raw_message().map(|r| r.map(|raw| raw.parsed))
    }

    /// Try to extract the next complete newline-delimited message along with
    /// its original raw bytes (for transparent forwarding).
    ///
    /// Returns `None` if no complete message is available yet.
    pub fn next_raw_message(&mut self) -> Option<Result<RawJsonRpcMessage>> {
        loop {
            let newline_pos = self.buf.iter().position(|&b| b == b'\n')?;

            // Check if this line exceeds the maximum message size
            if newline_pos > MAX_MESSAGE_SIZE {
                warn!(
                    "skipping oversized JSON-RPC line ({} bytes > {} byte limit)",
                    newline_pos, MAX_MESSAGE_SIZE
                );
                // Drain the oversized line and continue to next
                self.buf.drain(..=newline_pos);
                continue;
            }

            let line: Vec<u8> = self.buf.drain(..=newline_pos).collect();
            let trimmed = line.strip_suffix(b"\n").unwrap_or(&line);

            // Skip empty lines.
            if trimmed.is_empty() {
                continue;
            }

            match parse_message(trimmed) {
                Ok(msg) => {
                    return Some(Ok(RawJsonRpcMessage {
                        parsed: msg,
                        raw_bytes: trimmed.to_vec(),
                    }));
                }
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

    // -----------------------------------------------------------------------
    // Security hardening tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_rejects_oversized_message() {
        let huge = "x".repeat(MAX_MESSAGE_SIZE + 1);
        let result = parse_message(huge.as_bytes());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum size"));
    }

    #[test]
    fn parse_rejects_deeply_nested_json() {
        // Build JSON with depth > MAX_JSON_DEPTH
        let open: String = "{\"a\":".repeat(200);
        let close: String = "}".repeat(200);
        let json = format!("{}null{}", open, close);
        let result = parse_message(json.as_bytes());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nesting depth"));
    }

    #[test]
    fn stream_oversized_line_skipped() {
        let mut parser = StreamParser::new();
        // Create a line that exceeds MAX_MESSAGE_SIZE, then a valid message
        let oversized = "x".repeat(MAX_MESSAGE_SIZE + 100);
        let data = format!("{}\n{}\n", oversized, sample_request_json());
        parser.feed(data.as_bytes());

        // The oversized line should be skipped, and the valid message returned
        let msg = parser.next_message().unwrap().unwrap();
        assert!(matches!(msg, JsonRpcMessage::Request(_)));
    }

    #[test]
    fn stream_buffer_overflow_protection() {
        let mut parser = StreamParser::new();
        // Feed data without newlines that exceeds buffer limit
        let chunk = "x".repeat(MAX_BUFFER_SIZE + 100);
        parser.feed(chunk.as_bytes());
        // Buffer should have been cleared
        assert!(parser.next_message().is_none());
        // Parser should still work after clearing
        let data = format!("{}\n", sample_request_json());
        parser.feed(data.as_bytes());
        let msg = parser.next_message().unwrap().unwrap();
        assert!(matches!(msg, JsonRpcMessage::Request(_)));
    }

    // -----------------------------------------------------------------------
    // Proxy transparency regression tests
    // -----------------------------------------------------------------------

    #[test]
    fn raw_message_preserves_exact_bytes() {
        let mut parser = StreamParser::new();
        // Use specific formatting: extra spaces, specific key order
        let original = r#"{"jsonrpc" : "2.0",  "id":1, "method":"tools/call","params":{"name":"exec"}}"#;
        let data = format!("{}\n", original);
        parser.feed(data.as_bytes());

        let raw_msg = parser.next_raw_message().unwrap().unwrap();

        // The raw bytes must exactly match the original input
        assert_eq!(
            std::str::from_utf8(&raw_msg.raw_bytes).unwrap(),
            original,
            "raw bytes must preserve exact formatting"
        );

        // The parsed message should still be correct
        match &raw_msg.parsed {
            JsonRpcMessage::Request(r) => {
                assert_eq!(r.method, "tools/call");
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn raw_message_preserves_unicode_escapes() {
        let mut parser = StreamParser::new();
        // Send a message with Unicode escape sequences
        let original = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"\u65e5\u672c\u8a9e"}}"#;
        let data = format!("{}\n", original);
        parser.feed(data.as_bytes());

        let raw_msg = parser.next_raw_message().unwrap().unwrap();

        // Raw bytes must preserve the escape sequences exactly
        assert_eq!(
            std::str::from_utf8(&raw_msg.raw_bytes).unwrap(),
            original,
            "raw bytes must preserve Unicode escape sequences"
        );
    }

    #[test]
    fn raw_message_preserves_key_ordering() {
        let mut parser = StreamParser::new();
        // Non-standard key ordering: params before method
        let original = r#"{"params":{"name":"read"},"jsonrpc":"2.0","id":42,"method":"tools/call"}"#;
        let data = format!("{}\n", original);
        parser.feed(data.as_bytes());

        let raw_msg = parser.next_raw_message().unwrap().unwrap();

        assert_eq!(
            std::str::from_utf8(&raw_msg.raw_bytes).unwrap(),
            original,
            "raw bytes must preserve key ordering"
        );
    }

    #[test]
    fn raw_bytes_with_newline_appends_newline() {
        let mut parser = StreamParser::new();
        let original = sample_request_json();
        let data = format!("{}\n", original);
        parser.feed(data.as_bytes());

        let raw_msg = parser.next_raw_message().unwrap().unwrap();
        let with_nl = raw_msg.raw_bytes_with_newline();

        assert!(with_nl.ends_with(b"\n"));
        assert_eq!(&with_nl[..with_nl.len() - 1], original.as_bytes());
    }

    #[test]
    fn raw_message_notification_no_id() {
        let mut parser = StreamParser::new();
        let original = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let data = format!("{}\n", original);
        parser.feed(data.as_bytes());

        let raw_msg = parser.next_raw_message().unwrap().unwrap();
        assert!(matches!(raw_msg.parsed, JsonRpcMessage::Notification(_)));
        assert_eq!(
            std::str::from_utf8(&raw_msg.raw_bytes).unwrap(),
            original
        );
    }

    #[test]
    fn raw_message_null_id_response() {
        let mut parser = StreamParser::new();
        let original = r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#;
        let data = format!("{}\n", original);
        parser.feed(data.as_bytes());

        let raw_msg = parser.next_raw_message().unwrap().unwrap();
        match &raw_msg.parsed {
            JsonRpcMessage::Response(r) => {
                assert_eq!(r.id, crate::jsonrpc::types::JsonRpcId::Null);
            }
            _ => panic!("expected response with null id"),
        }
        assert_eq!(
            std::str::from_utf8(&raw_msg.raw_bytes).unwrap(),
            original
        );
    }
}
