//! Correlation engine: links MCP-level events to OS-level events.
//!
//! The engine maintains sliding windows of MCP and OS events, applies matching
//! rules to connect tool calls / resource reads to their actual OS side-effects,
//! and assigns severity ratings to uncorrelated (unexpected) OS activity.

pub mod engine;
pub mod rules;
pub mod severity;

pub use engine::CorrelationEngine;
pub use rules::{MatchResult, MatchRule};
pub use severity::rate_uncorrelated;
