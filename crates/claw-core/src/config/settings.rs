//! Application settings and TOML configuration parsing.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Top-level ClawAI configuration, loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClawConfig {
    /// Path to the Unix domain socket for daemon-UI IPC.
    #[serde(default = "default_socket_path")]
    pub daemon_socket_path: PathBuf,

    /// Path to the JSON-lines audit log file.
    #[serde(default = "default_audit_log_path")]
    pub audit_log_path: PathBuf,

    /// Log rotation settings.
    #[serde(default)]
    pub log_rotation: LogRotation,

    /// eslogger / Endpoint Security configuration.
    #[serde(default)]
    pub eslogger: EsloggerConfig,

    /// Small language model configuration for local inference.
    #[serde(default)]
    pub slm: SlmConfig,

    /// API key configuration for cloud providers.
    #[serde(default)]
    pub api_keys: ApiKeyConfig,

    /// UI appearance and behavior settings.
    #[serde(default)]
    pub ui: UiConfig,

    /// Whether the user has opted in to anonymous telemetry.
    #[serde(default)]
    pub telemetry_opt_in: bool,

    /// Path to the policy rules file.
    #[serde(default = "default_policy_path")]
    pub policy_path: PathBuf,
}

/// Log rotation settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotation {
    /// Maximum size of a single log file in megabytes before rotation.
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
    /// Maximum number of rotated log files to keep.
    #[serde(default = "default_max_files")]
    pub max_files: u32,
}

/// Configuration for the eslogger / Endpoint Security subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsloggerConfig {
    /// ES event types to subscribe to (e.g. `["exec", "open", "connect"]`).
    #[serde(default = "default_es_events")]
    pub events: Vec<String>,
    /// Internal ring-buffer size for event batching.
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    /// Whether the eslogger sensor is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Configuration for the local small language model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlmConfig {
    /// Path to the GGUF model file, if using a local model.
    pub model_path: Option<PathBuf>,
    /// Whether the SLM subsystem is enabled.
    #[serde(default)]
    pub enabled: bool,
}

/// API key configuration for cloud AI providers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Provider name (e.g. `"openai"`, `"anthropic"`).
    pub provider: Option<String>,
    /// Name of the environment variable holding the API key.
    pub key_env_var: Option<String>,
}

/// UI appearance and behavior settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Color theme name (e.g. `"dark"`, `"light"`).
    #[serde(default = "default_theme")]
    pub theme: String,
    /// Whether to show macOS notifications for blocked events.
    #[serde(default = "default_true")]
    pub notifications: bool,
}

// --- Default value functions ---

fn default_socket_path() -> PathBuf {
    dirs_next_fallback(".local/share/clawai/clawai.sock")
}

fn default_audit_log_path() -> PathBuf {
    dirs_next_fallback(".local/share/clawai/audit.jsonl")
}

fn default_policy_path() -> PathBuf {
    dirs_next_fallback(".config/clawai/policy.toml")
}

fn default_max_size_mb() -> u64 {
    50
}

fn default_max_files() -> u32 {
    10
}

fn default_es_events() -> Vec<String> {
    vec![
        "exec".into(),
        "open".into(),
        "close".into(),
        "rename".into(),
        "unlink".into(),
        "connect".into(),
        "fork".into(),
        "exit".into(),
    ]
}

fn default_buffer_size() -> usize {
    4096
}

fn default_true() -> bool {
    true
}

fn default_theme() -> String {
    "dark".to_string()
}

/// Resolve a path relative to the user's home directory.
fn dirs_next_fallback(relative: &str) -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(relative)
    } else {
        PathBuf::from("/tmp").join(relative)
    }
}

// --- Trait impls ---

impl Default for ClawConfig {
    fn default() -> Self {
        Self {
            daemon_socket_path: default_socket_path(),
            audit_log_path: default_audit_log_path(),
            log_rotation: LogRotation::default(),
            eslogger: EsloggerConfig::default(),
            slm: SlmConfig::default(),
            api_keys: ApiKeyConfig::default(),
            ui: UiConfig::default(),
            telemetry_opt_in: false,
            policy_path: default_policy_path(),
        }
    }
}

impl Default for LogRotation {
    fn default() -> Self {
        Self {
            max_size_mb: default_max_size_mb(),
            max_files: default_max_files(),
        }
    }
}

impl Default for EsloggerConfig {
    fn default() -> Self {
        Self {
            events: default_es_events(),
            buffer_size: default_buffer_size(),
            enabled: true,
        }
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            notifications: true,
        }
    }
}

impl ClawConfig {
    /// Load configuration from a TOML file at the given path.
    ///
    /// If the file does not exist, returns the default configuration.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path)?;
        let config: ClawConfig = toml::from_str(&contents)?;
        Ok(config)
    }
}
