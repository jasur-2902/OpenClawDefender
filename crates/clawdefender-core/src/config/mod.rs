//! Configuration loading and management.
//!
//! RookBot configuration is stored in TOML format. The primary config file lives
//! at `~/.config/rookbot/config.toml` by default.

pub mod settings;

pub use settings::ClawConfig;
