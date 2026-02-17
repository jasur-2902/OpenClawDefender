//! Error types for the threat intelligence subsystem.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThreatIntelError {
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("hash mismatch for {file}: expected {expected}, got {actual}")]
    HashMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("feed fetch error: {0}")]
    FetchError(String),

    #[error("cache error: {0}")]
    CacheError(String),

    #[error("deserialization error: {0}")]
    DeserializeError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("no feed data available (no cache, no network, no bundled baseline)")]
    NoDataAvailable,
}

pub type Result<T> = std::result::Result<T, ThreatIntelError>;
