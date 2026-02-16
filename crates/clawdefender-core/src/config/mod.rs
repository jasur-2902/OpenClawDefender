//! Configuration loading and management.
//!
//! ClawDefender configuration is stored in TOML format. The primary config file lives
//! at `~/.config/clawdefender/config.toml` by default.

pub mod settings;

pub use settings::ClawConfig;
