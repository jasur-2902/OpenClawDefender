//! ClawDefender Agent Guard — self-protection for AI agents.
//!
//! This crate provides `AgentGuard`, a Rust implementation of agent-level
//! permission enforcement. It can operate in two modes:
//!
//! - **Connected mode**: Registers with the ClawDefender daemon for full
//!   OS-level monitoring and policy enforcement.
//! - **Embedded fallback mode**: Lightweight in-process permission checking
//!   when the daemon is unavailable.

pub mod api;
pub mod api_auth;
pub mod connection;
pub mod fallback;
pub mod guard;
pub mod installer;
pub mod openapi;
pub mod policy_gen;
pub mod registry;
pub mod selftest;
pub mod types;
pub mod webhooks;

pub use guard::GuardBuilder;
pub use types::*;
