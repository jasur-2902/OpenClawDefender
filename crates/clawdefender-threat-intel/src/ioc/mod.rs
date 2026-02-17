//! IoC (Indicator of Compromise) matching engine.
//!
//! This module provides real-time matching of events against known indicators
//! of compromise. It supports IP/CIDR ranges, domains (with wildcards), URLs,
//! file hashes, file path globs, process names, command-line regex patterns,
//! tool sequences, and tool argument patterns.

pub mod database;
pub mod engine;
pub mod types;

#[cfg(test)]
mod tests;

pub use database::IoCDatabase;
pub use engine::IoCEngine;
pub use types::*;
