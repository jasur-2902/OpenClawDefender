//! Configuration loading and management.
//!
//! ClawAI configuration is stored in TOML format. The primary config file lives
//! at `~/.config/clawai/config.toml` by default.

pub mod settings;

pub use settings::ClawConfig;
