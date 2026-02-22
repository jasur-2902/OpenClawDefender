//! HTTP authentication for the MCP server.
//!
//! On daemon startup a random 256-bit token is generated and written to
//! `~/.local/share/clawdefender/server-token`.  HTTP clients must present
//! this token via `Authorization: Bearer <token>`.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use rand::Rng;
use tracing::info;

/// Length of the generated token in bytes (256 bits).
const TOKEN_BYTES: usize = 32;

/// Return the path where the server token is stored.
pub fn token_path() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local").join("share")
    });
    base.join("clawdefender").join("server-token")
}

/// Generate a new random 256-bit token, write it to disk, and return the
/// hex-encoded token string.
pub fn generate_and_store_token() -> Result<String> {
    let mut rng = rand::rng();
    let mut bytes = [0u8; TOKEN_BYTES];
    rng.fill(&mut bytes);

    let token = hex::encode(bytes);

    let path = token_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create token directory: {}", parent.display()))?;
    }

    fs::write(&path, &token)
        .with_context(|| format!("failed to write server token to {}", path.display()))?;

    // Set restrictive permissions (owner-only read/write).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }

    info!("server token written to {}", path.display());
    Ok(token)
}

/// Read the server token from disk. Returns `None` if the file does not exist.
pub fn read_token() -> Option<String> {
    let path = token_path();
    fs::read_to_string(&path).ok().map(|t| t.trim().to_string())
}

/// Validate a bearer token from an HTTP `Authorization` header.
///
/// Returns `true` if the token matches the stored token exactly.
pub fn validate_bearer_token(auth_header: &str, expected_token: &str) -> bool {
    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
    // Constant-time comparison to prevent timing attacks.
    constant_time_eq(token.as_bytes(), expected_token.as_bytes())
}

/// Constant-time byte comparison.
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
    fn validate_correct_token() {
        assert!(validate_bearer_token("Bearer abc123def456", "abc123def456"));
    }

    #[test]
    fn validate_wrong_token() {
        assert!(!validate_bearer_token("Bearer wrong", "abc123def456"));
    }

    #[test]
    fn validate_missing_bearer_prefix() {
        assert!(!validate_bearer_token("abc123def456", "abc123def456"));
    }

    #[test]
    fn validate_empty_token() {
        assert!(!validate_bearer_token("Bearer ", "abc123def456"));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer_string"));
    }

    #[test]
    fn generate_token_format() {
        // Just test the token generation logic without filesystem side effects.
        let mut rng = rand::rng();
        let mut bytes = [0u8; TOKEN_BYTES];
        rng.fill(&mut bytes);
        let token = hex::encode(bytes);
        assert_eq!(token.len(), 64); // 32 bytes = 64 hex chars
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
