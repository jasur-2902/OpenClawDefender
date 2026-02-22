//! HTTP authentication for the REST API.
//!
//! Reads the server token from `~/.local/share/clawdefender/server-token`
//! and validates `Authorization: Bearer <token>` headers.

use std::fs;
use std::path::PathBuf;

/// Return the path where the server token is stored.
pub fn token_path() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local").join("share")
    });
    base.join("clawdefender").join("server-token")
}

/// Read the server token from disk. Returns `None` if the file does not exist.
pub fn read_token() -> Option<String> {
    let path = token_path();
    fs::read_to_string(&path).ok().map(|t| t.trim().to_string())
}

/// Validate a bearer token from an HTTP `Authorization` header value.
///
/// Returns `true` if the token matches the expected token exactly (constant-time).
pub fn validate_bearer_token(auth_header: &str, expected_token: &str) -> bool {
    let token = match auth_header.strip_prefix("Bearer ") {
        Some(t) => t,
        None => return false,
    };
    constant_time_eq(token.as_bytes(), expected_token.as_bytes())
}

/// Extract and validate the bearer token from an HTTP request's headers.
/// Returns Ok(()) if valid, Err(message) if invalid.
pub fn authenticate(auth_header: Option<&str>, expected_token: &str) -> Result<(), &'static str> {
    match auth_header {
        None => Err("missing Authorization header"),
        Some(header) => {
            if validate_bearer_token(header, expected_token) {
                Ok(())
            } else {
                Err("invalid token")
            }
        }
    }
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_correct_token() {
        assert!(validate_bearer_token("Bearer abc123def456", "abc123def456"));
    }

    #[test]
    fn test_validate_wrong_token() {
        assert!(!validate_bearer_token("Bearer wrong", "abc123def456"));
    }

    #[test]
    fn test_validate_missing_prefix() {
        assert!(!validate_bearer_token("abc123def456", "abc123def456"));
    }

    #[test]
    fn test_validate_empty_token() {
        assert!(!validate_bearer_token("Bearer ", "abc123def456"));
    }

    #[test]
    fn test_authenticate_missing_header() {
        assert!(authenticate(None, "token123").is_err());
    }

    #[test]
    fn test_authenticate_valid() {
        assert!(authenticate(Some("Bearer token123"), "token123").is_ok());
    }

    #[test]
    fn test_authenticate_invalid() {
        assert!(authenticate(Some("Bearer wrong"), "token123").is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
