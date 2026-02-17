//! Blocklist & known-malicious server registry.
//!
//! This module maintains a database of known-malicious, vulnerable, and
//! compromised MCP servers and provides a matching engine to check servers
//! against it at runtime.
//!
//! # Overview
//!
//! - [`types`] defines the blocklist data model (entries, severity, match
//!   results, overrides).
//! - [`matching`] provides [`BlocklistMatcher`] which holds a parsed blocklist
//!   and can check a server by name, version, or SHA-256 hash.
//!
//! The matcher supports atomic runtime updates so that new feed data can be
//! applied without restarting the daemon. An override mechanism allows users
//! to explicitly accept risk and run a blocked server after confirming with
//! the required confirmation text.

pub mod matching;
pub mod types;

#[cfg(test)]
mod tests;

// Re-exports for convenience.
pub use matching::BlocklistMatcher;
pub use types::*;
