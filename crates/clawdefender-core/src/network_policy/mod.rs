//! Network-specific policy engine for ClawDefender.
//!
//! Decides whether each outbound connection from an AI agent should be allowed,
//! blocked, or prompted to the user. Combines static rules, IoC intelligence,
//! guard restrictions, behavioral context, and kill-chain signals into a single
//! decision.

pub mod engine;
pub mod rate_limiter;
pub mod rules;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod security_tests;
