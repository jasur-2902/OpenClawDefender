//! Anonymous telemetry system for ClawDefender.
//!
//! This module implements an opt-in, privacy-preserving telemetry system that
//! collects aggregate usage data to help improve ClawDefender's threat detection.
//!
//! # Privacy Guarantees
//!
//! - **No file paths**: Only categories like "credential directory" are recorded.
//! - **No server names**: Only blocklist entry IDs (e.g. "CLAW-2026-001") are sent.
//! - **No IP addresses**: The user's IP is never included in reports.
//! - **No usernames, API keys, or identifiable data**.
//! - **No tool names or argument values**.
//! - **Installation ID**: A random UUID v4, not derived from any user data.
//! - **Reports contain only counts and distributions**.
//!
//! # Opt-in Model
//!
//! Telemetry is **disabled by default**. Users must explicitly opt in via the CLI
//! or configuration. Opting out clears the installation ID and stops all collection.

pub mod aggregator;
pub mod consent;
pub mod reporter;
pub mod types;

#[cfg(test)]
mod tests;

pub use aggregator::TelemetryAggregator;
pub use consent::ConsentManager;
pub use reporter::TelemetryReporter;
pub use types::{TelemetryConfig, TelemetryReport};
