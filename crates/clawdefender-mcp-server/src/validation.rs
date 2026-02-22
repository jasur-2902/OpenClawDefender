//! Input validation and sanitization for MCP server tool parameters.
//!
//! Prevents abuse vectors including:
//! - Oversized payloads (audit log pollution)
//! - Newline injection in string fields
//! - Null byte injection
//! - Unicode homoglyph / direction-override tricks

use anyhow::{bail, Result};

/// Maximum payload size for reportAction (10 KB).
pub const MAX_REPORT_ACTION_PAYLOAD_BYTES: usize = 10 * 1024;

/// Maximum length for individual string fields.
pub const MAX_STRING_FIELD_LENGTH: usize = 4096;

/// Validate and sanitize a string field.
///
/// Rejects strings containing:
/// - Null bytes (`\0`)
/// - Unicode direction overrides (U+202A..U+202E, U+2066..U+2069)
/// - More than `MAX_STRING_FIELD_LENGTH` characters
pub fn validate_string_field(name: &str, value: &str) -> Result<()> {
    if value.len() > MAX_STRING_FIELD_LENGTH {
        bail!(
            "Field '{}' exceeds maximum length ({} > {})",
            name,
            value.len(),
            MAX_STRING_FIELD_LENGTH
        );
    }

    if value.contains('\0') {
        bail!("Field '{}' contains null byte", name);
    }

    // Check for Unicode bidirectional override characters
    for ch in value.chars() {
        if is_bidi_control(ch) {
            bail!(
                "Field '{}' contains Unicode bidirectional control character U+{:04X}",
                name,
                ch as u32
            );
        }
    }

    Ok(())
}

/// Sanitize a string by stripping control characters (except common whitespace).
pub fn sanitize_string(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t' || *c == '\r')
        .filter(|c| !is_bidi_control(*c))
        .collect()
}

/// Check if a character is a Unicode bidirectional control character.
fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{202A}' // LEFT-TO-RIGHT EMBEDDING
        | '\u{202B}' // RIGHT-TO-LEFT EMBEDDING
        | '\u{202C}' // POP DIRECTIONAL FORMATTING
        | '\u{202D}' // LEFT-TO-RIGHT OVERRIDE
        | '\u{202E}' // RIGHT-TO-LEFT OVERRIDE
        | '\u{2066}' // LEFT-TO-RIGHT ISOLATE
        | '\u{2067}' // RIGHT-TO-LEFT ISOLATE
        | '\u{2068}' // FIRST STRONG ISOLATE
        | '\u{2069}' // POP DIRECTIONAL ISOLATE
        | '\u{200F}' // RIGHT-TO-LEFT MARK
        | '\u{200E}' // LEFT-TO-RIGHT MARK
    )
}

/// Validate the total size of a JSON payload (for reportAction).
pub fn validate_payload_size(json_bytes: usize) -> Result<()> {
    if json_bytes > MAX_REPORT_ACTION_PAYLOAD_BYTES {
        bail!(
            "Payload exceeds maximum size ({} > {} bytes)",
            json_bytes,
            MAX_REPORT_ACTION_PAYLOAD_BYTES
        );
    }
    Ok(())
}

/// Validate a resource path for scope escalation.
///
/// Ensures the resource path does not contain wildcard characters that could
/// match broader than intended when used in policy rules.
pub fn validate_resource_path_exact(path: &str) -> Result<()> {
    validate_string_field("resource", path)?;

    // Ensure the path doesn't contain glob metacharacters
    if path.contains('*') || path.contains('?') || path.contains('[') {
        bail!("Resource path must be exact (no wildcards): '{}'", path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_string_passes() {
        assert!(validate_string_field("test", "hello world").is_ok());
    }

    #[test]
    fn null_byte_rejected() {
        assert!(validate_string_field("test", "hello\0world").is_err());
    }

    #[test]
    fn bidi_override_rejected() {
        let value = format!("normal\u{202E}reversed");
        assert!(validate_string_field("test", &value).is_err());
    }

    #[test]
    fn oversized_string_rejected() {
        let long = "a".repeat(MAX_STRING_FIELD_LENGTH + 1);
        assert!(validate_string_field("test", &long).is_err());
    }

    #[test]
    fn sanitize_strips_control_chars() {
        let input = "hello\x01\x02world\ttab\nnewline";
        let sanitized = sanitize_string(input);
        assert_eq!(sanitized, "helloworld\ttab\nnewline");
    }

    #[test]
    fn sanitize_strips_bidi() {
        let input = format!("safe\u{202E}text");
        let sanitized = sanitize_string(&input);
        assert_eq!(sanitized, "safetext");
    }

    #[test]
    fn payload_size_within_limit() {
        assert!(validate_payload_size(1024).is_ok());
    }

    #[test]
    fn payload_size_exceeds_limit() {
        assert!(validate_payload_size(MAX_REPORT_ACTION_PAYLOAD_BYTES + 1).is_err());
    }

    #[test]
    fn exact_path_no_wildcards() {
        assert!(validate_resource_path_exact("/home/user/.ssh/config").is_ok());
    }

    #[test]
    fn exact_path_rejects_glob() {
        assert!(validate_resource_path_exact("/home/user/.ssh/*").is_err());
    }

    #[test]
    fn exact_path_rejects_question_mark() {
        assert!(validate_resource_path_exact("/home/user/.ssh/id_?sa").is_err());
    }

    #[test]
    fn exact_path_rejects_bracket() {
        assert!(validate_resource_path_exact("/home/user/.ssh/id_[rsa]").is_err());
    }
}
