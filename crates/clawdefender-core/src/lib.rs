//! # clawdefender-core
//!
//! Core type system for ClawDefender -- a firewall for AI agents.
//!
//! This crate defines the shared types, traits, and protocols used across all
//! ClawDefender components: the MCP proxy, the eslogger sensor, the policy engine,
//! the audit subsystem, and the macOS menu-bar UI.

pub mod audit;
pub mod config;
pub mod correlation;
pub mod event;
pub mod ipc;
pub mod policy;
pub mod rate_limit;
