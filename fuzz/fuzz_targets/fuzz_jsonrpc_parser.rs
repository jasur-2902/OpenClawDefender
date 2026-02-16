//! Fuzz target for the JSON-RPC parser.
//!
//! Feeds arbitrary bytes into the JSON-RPC parsing pipeline to ensure it never
//! panics on malformed input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse arbitrary bytes as a UTF-8 string, then as JSON-RPC.
    if let Ok(text) = std::str::from_utf8(data) {
        // Try parsing as a generic JSON value first.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            // If it looks like JSON, attempt to extract JSON-RPC fields.
            // The parser should handle any shape without panicking.
            let _ = value.get("jsonrpc");
            let _ = value.get("method");
            let _ = value.get("id");
            let _ = value.get("params");
        }
    }
});
