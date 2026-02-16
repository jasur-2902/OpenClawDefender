//! Fuzz target for the eslogger event parser.
//!
//! Feeds arbitrary bytes as JSON to the eslogger event deserialization path
//! to ensure it never panics on malformed input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Try to deserialize arbitrary JSON as an OsEvent.
        // The deserializer should return Err, never panic.
        let _ = serde_json::from_str::<claw_core::event::os::OsEvent>(text);
    }
});
