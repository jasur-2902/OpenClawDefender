//! Multi-agent swarm coordination for ClawDefender.

pub mod audit_hasher;
pub mod chat;
pub mod chat_server;
pub mod commander;
pub mod data_minimizer;
pub mod keychain;
pub mod llm_client;
pub mod output_sanitizer;
pub mod cost;
pub mod prompts;

pub use commander::SwarmVerdict;
