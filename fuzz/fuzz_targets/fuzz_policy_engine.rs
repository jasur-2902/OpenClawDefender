//! Fuzz target for the policy engine TOML parser and rule matching.
//!
//! Feeds arbitrary bytes as TOML policy content and event context data to
//! ensure no panics occur on malformed input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Attempt to parse arbitrary text as a policy TOML file.
        // This should return Err on invalid input, never panic.
        let _ = clawdefender_core::policy::rule::parse_policy_toml(text);
    }
});
