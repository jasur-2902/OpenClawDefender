//! Application settings and TOML configuration parsing.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Top-level ClawDefender configuration, loaded from a TOML file.
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

    /// Cloud swarm analysis settings.
    #[serde(default)]
    pub swarm: SwarmSettings,

    /// UI appearance and behavior settings.
    #[serde(default)]
    pub ui: UiConfig,

    /// Whether the user has opted in to anonymous telemetry.
    #[serde(default)]
    pub telemetry_opt_in: bool,

    /// Path to the policy rules file.
    #[serde(default = "default_policy_path")]
    pub policy_path: PathBuf,

    /// Path to the sensor configuration file.
    #[serde(default = "default_sensor_config_path")]
    pub sensor_config_path: PathBuf,

    /// MCP server configuration.
    #[serde(default)]
    pub mcp_server: McpServerConfig,

    /// Behavioral baseline engine configuration.
    #[serde(default)]
    pub behavioral: BehavioralConfig,

    /// Prompt injection detection configuration.
    #[serde(default)]
    pub injection_detector: InjectionDetectorSettings,

    /// Guard API configuration.
    #[serde(default)]
    pub guard_api: GuardApiConfig,

    /// Threat intelligence feed configuration.
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,

    /// Network policy engine configuration.
    #[serde(default)]
    pub network_policy: NetworkPolicyConfig,
}

/// Network policy engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyConfig {
    /// Whether network policy enforcement is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Default action for agent network connections.
    #[serde(default = "default_agent_action")]
    pub default_agent_action: String,
    /// Seconds to wait for user prompt response.
    #[serde(default = "default_prompt_timeout")]
    pub prompt_timeout_seconds: u32,
    /// Action to take when prompt times out.
    #[serde(default = "default_timeout_action")]
    pub timeout_action: String,
    /// Max connections per minute per PID before alerting.
    #[serde(default = "default_rate_limit_conn")]
    pub rate_limit_connections_per_min: u32,
    /// Max unique destinations per 10s per PID before alerting.
    #[serde(default = "default_rate_limit_dest")]
    pub rate_limit_unique_dest_per_10s: u32,
    /// Whether to block connections to private IP ranges.
    #[serde(default)]
    pub block_private_ranges: bool,
    /// Whether to log all DNS queries.
    #[serde(default = "default_true")]
    pub log_all_dns: bool,
}

fn default_agent_action() -> String {
    "prompt".to_string()
}

fn default_prompt_timeout() -> u32 {
    15
}

fn default_timeout_action() -> String {
    "block".to_string()
}

fn default_rate_limit_conn() -> u32 {
    100
}

fn default_rate_limit_dest() -> u32 {
    10
}

impl Default for NetworkPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_agent_action: default_agent_action(),
            prompt_timeout_seconds: default_prompt_timeout(),
            timeout_action: default_timeout_action(),
            rate_limit_connections_per_min: default_rate_limit_conn(),
            rate_limit_unique_dest_per_10s: default_rate_limit_dest(),
            block_private_ranges: false,
            log_all_dns: true,
        }
    }
}

/// Behavioral baseline engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralConfig {
    /// Whether the behavioral baseline engine is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Number of events required before learning completes.
    #[serde(default = "default_learning_event_threshold")]
    pub learning_event_threshold: u64,
    /// Minutes that must elapse before learning completes.
    #[serde(default = "default_learning_time_minutes")]
    pub learning_time_minutes: u64,
    /// Anomaly score threshold for alerting.
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: f64,
    /// Anomaly score threshold for automatic blocking.
    #[serde(default = "default_auto_block_threshold")]
    pub auto_block_threshold: f64,
    /// Whether automatic blocking is enabled.
    #[serde(default)]
    pub auto_block_enabled: bool,
}

fn default_learning_event_threshold() -> u64 {
    100
}

fn default_learning_time_minutes() -> u64 {
    30
}

fn default_anomaly_threshold() -> f64 {
    0.7
}

fn default_auto_block_threshold() -> f64 {
    0.9
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            learning_event_threshold: default_learning_event_threshold(),
            learning_time_minutes: default_learning_time_minutes(),
            anomaly_threshold: default_anomaly_threshold(),
            auto_block_threshold: default_auto_block_threshold(),
            auto_block_enabled: false,
        }
    }
}

/// Prompt injection detection settings (stored in ClawConfig).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionDetectorSettings {
    /// Whether injection detection is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Score threshold above which a message is flagged (0.0 - 1.0).
    #[serde(default = "default_injection_threshold")]
    pub threshold: f64,
    /// Optional path to a custom patterns TOML file.
    #[serde(default)]
    pub patterns_path: Option<PathBuf>,
    /// Whether to automatically block flagged messages.
    #[serde(default)]
    pub auto_block: bool,
}

fn default_injection_threshold() -> f64 {
    0.6
}

impl Default for InjectionDetectorSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_injection_threshold(),
            patterns_path: None,
            auto_block: false,
        }
    }
}

/// Threat intelligence feed configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    /// Whether the threat intel subsystem is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Feed base URL.
    #[serde(default = "default_feed_url")]
    pub feed_url: String,
    /// How often to check for updates, in hours.
    #[serde(default = "default_update_interval_hours")]
    pub update_interval_hours: u64,
    /// Automatically apply downloaded rule packs.
    #[serde(default = "default_true")]
    pub auto_apply_rules: bool,
    /// Automatically apply downloaded blocklist.
    #[serde(default = "default_true")]
    pub auto_apply_blocklist: bool,
    /// Automatically apply downloaded patterns.
    #[serde(default = "default_true")]
    pub auto_apply_patterns: bool,
    /// Automatically apply downloaded IoCs.
    #[serde(default = "default_true")]
    pub auto_apply_iocs: bool,
    /// Send a notification when the feed is updated.
    #[serde(default = "default_true")]
    pub notify_on_update: bool,
}

fn default_feed_url() -> String {
    "https://feed.clawdefender.io/v1/".to_string()
}

fn default_update_interval_hours() -> u64 {
    6
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            feed_url: default_feed_url(),
            update_interval_hours: default_update_interval_hours(),
            auto_apply_rules: true,
            auto_apply_blocklist: true,
            auto_apply_patterns: true,
            auto_apply_iocs: true,
            notify_on_update: true,
        }
    }
}

/// Guard API configuration (REST API for agent guard management).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardApiConfig {
    /// Whether the guard API is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Port for the guard API server.
    #[serde(default = "default_guard_api_port")]
    pub port: u16,
}

fn default_guard_api_port() -> u16 {
    3202
}

impl Default for GuardApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_guard_api_port(),
        }
    }
}

/// Configuration for the ClawDefender MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// Whether the MCP server is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether to use stdio transport.
    #[serde(default = "default_true")]
    pub stdio: bool,
    /// HTTP port for the MCP server.
    #[serde(default = "default_mcp_server_port")]
    pub http_port: u16,
}

fn default_mcp_server_port() -> u16 {
    3201
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            stdio: true,
            http_port: default_mcp_server_port(),
        }
    }
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
    /// Extra process names to ignore in the pre-filter.
    #[serde(default)]
    pub ignore_processes: Vec<String>,
    /// Extra path prefixes to ignore in the pre-filter.
    #[serde(default)]
    pub ignore_paths: Vec<String>,
}

/// Unified sensor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorConfig {
    /// Eslogger sensor settings.
    #[serde(default)]
    pub eslogger: EsloggerSensorConfig,
    /// FSEvents sensor settings.
    #[serde(default)]
    pub fsevents: FsEventsSensorConfig,
    /// Correlation engine settings.
    #[serde(default)]
    pub correlation: CorrelationConfig,
    /// Process tree settings.
    #[serde(default)]
    pub process_tree: ProcessTreeConfig,
}

/// Eslogger-specific sensor config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsloggerSensorConfig {
    /// Whether the eslogger sensor is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// ES event types to subscribe to.
    #[serde(default = "default_es_events")]
    pub events: Vec<String>,
    /// Channel buffer capacity.
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
    /// Extra process names to ignore.
    #[serde(default)]
    pub ignore_processes: Vec<String>,
    /// Extra path prefixes to ignore.
    #[serde(default)]
    pub ignore_paths: Vec<String>,
}

/// FSEvents sensor config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FsEventsSensorConfig {
    /// Whether FSEvents monitoring is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Paths to watch.
    #[serde(default)]
    pub watch_paths: Vec<PathBuf>,
}

/// Correlation engine config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Window in milliseconds for correlating MCP events to OS events.
    #[serde(default = "default_correlation_window_ms")]
    pub window_ms: u64,
}

/// Process tree config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeConfig {
    /// How often to refresh the process tree (seconds).
    #[serde(default = "default_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
}

fn default_channel_capacity() -> usize {
    10_000
}

fn default_correlation_window_ms() -> u64 {
    500
}

fn default_refresh_interval_secs() -> u64 {
    5
}

impl SensorConfig {
    /// Load sensor configuration from a TOML file.
    ///
    /// Returns default configuration if the file does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path)?;
        let config: SensorConfig = toml::from_str(&contents)?;
        Ok(config)
    }
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            eslogger: EsloggerSensorConfig::default(),
            fsevents: FsEventsSensorConfig::default(),
            correlation: CorrelationConfig::default(),
            process_tree: ProcessTreeConfig::default(),
        }
    }
}

impl Default for EsloggerSensorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            events: default_es_events(),
            channel_capacity: default_channel_capacity(),
            ignore_processes: Vec::new(),
            ignore_paths: Vec::new(),
        }
    }
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            window_ms: default_correlation_window_ms(),
        }
    }
}

impl Default for ProcessTreeConfig {
    fn default() -> Self {
        Self {
            refresh_interval_secs: default_refresh_interval_secs(),
        }
    }
}

/// Configuration for the local small language model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmConfig {
    /// Whether the SLM subsystem is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path to the GGUF model file, if using a local model.
    pub model_path: Option<PathBuf>,
    /// Context window size in tokens.
    #[serde(default = "default_slm_context_size")]
    pub context_size: u32,
    /// Maximum number of tokens to generate per inference.
    #[serde(default = "default_slm_max_output_tokens")]
    pub max_output_tokens: u32,
    /// Sampling temperature (lower = more deterministic).
    #[serde(default = "default_slm_temperature")]
    pub temperature: f32,
    /// Whether to use GPU acceleration (Metal on macOS).
    #[serde(default = "default_true")]
    pub use_gpu: bool,
    /// Number of CPU threads for inference (None = auto-detect).
    pub threads: Option<u32>,
}

fn default_slm_context_size() -> u32 {
    2048
}

fn default_slm_max_output_tokens() -> u32 {
    256
}

fn default_slm_temperature() -> f32 {
    0.1
}

impl Default for SlmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model_path: None,
            context_size: default_slm_context_size(),
            max_output_tokens: default_slm_max_output_tokens(),
            temperature: default_slm_temperature(),
            use_gpu: true,
            threads: None,
        }
    }
}

/// Configuration for the cloud swarm multi-agent analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmSettings {
    /// Whether swarm analysis is enabled (default: true if API key exists).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Preferred LLM provider name (e.g. "anthropic", "openai").
    pub preferred_provider: Option<String>,
    /// Maximum daily spend in USD.
    #[serde(default = "default_daily_budget")]
    pub daily_budget_usd: f64,
    /// Maximum monthly spend in USD.
    #[serde(default = "default_monthly_budget")]
    pub monthly_budget_usd: f64,
    /// Timeout in seconds for swarm analysis.
    #[serde(default = "default_swarm_timeout")]
    pub timeout_secs: u64,
    /// Minimum SLM risk level that triggers swarm escalation (default: "HIGH").
    #[serde(default = "default_escalation_threshold")]
    pub escalation_threshold: String,
    /// Port for the chat web server.
    #[serde(default = "default_chat_port")]
    pub chat_port: u16,
}

fn default_daily_budget() -> f64 {
    1.00
}

fn default_monthly_budget() -> f64 {
    20.00
}

fn default_swarm_timeout() -> u64 {
    10
}

fn default_escalation_threshold() -> String {
    "HIGH".to_string()
}

fn default_chat_port() -> u16 {
    3200
}

impl Default for SwarmSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            preferred_provider: None,
            daily_budget_usd: default_daily_budget(),
            monthly_budget_usd: default_monthly_budget(),
            timeout_secs: default_swarm_timeout(),
            escalation_threshold: default_escalation_threshold(),
            chat_port: default_chat_port(),
        }
    }
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
    dirs_next_fallback(".local/share/clawdefender/clawdefender.sock")
}

fn default_audit_log_path() -> PathBuf {
    dirs_next_fallback(".local/share/clawdefender/audit.jsonl")
}

fn default_policy_path() -> PathBuf {
    dirs_next_fallback(".config/clawdefender/policy.toml")
}

fn default_sensor_config_path() -> PathBuf {
    dirs_next_fallback(".config/clawdefender/sensor.toml")
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
            swarm: SwarmSettings::default(),
            ui: UiConfig::default(),
            telemetry_opt_in: false,
            policy_path: default_policy_path(),
            sensor_config_path: default_sensor_config_path(),
            mcp_server: McpServerConfig::default(),
            behavioral: BehavioralConfig::default(),
            injection_detector: InjectionDetectorSettings::default(),
            guard_api: GuardApiConfig::default(),
            threat_intel: ThreatIntelConfig::default(),
            network_policy: NetworkPolicyConfig::default(),
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
            ignore_processes: Vec::new(),
            ignore_paths: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults_have_swarm_section() {
        let config = ClawConfig::default();
        assert!(config.swarm.enabled);
        assert_eq!(config.swarm.escalation_threshold, "HIGH");
        assert!((config.swarm.daily_budget_usd - 1.0).abs() < f64::EPSILON);
        assert!((config.swarm.monthly_budget_usd - 20.0).abs() < f64::EPSILON);
        assert_eq!(config.swarm.timeout_secs, 10);
        assert_eq!(config.swarm.chat_port, 3200);
        assert!(config.swarm.preferred_provider.is_none());
    }

    #[test]
    fn test_config_parses_swarm_section_from_toml() {
        let toml_str = r#"
[swarm]
enabled = false
preferred_provider = "anthropic"
daily_budget_usd = 5.0
monthly_budget_usd = 100.0
timeout_secs = 30
escalation_threshold = "MEDIUM"
chat_port = 4000
"#;
        let config: ClawConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.swarm.enabled);
        assert_eq!(config.swarm.preferred_provider.as_deref(), Some("anthropic"));
        assert!((config.swarm.daily_budget_usd - 5.0).abs() < f64::EPSILON);
        assert!((config.swarm.monthly_budget_usd - 100.0).abs() < f64::EPSILON);
        assert_eq!(config.swarm.timeout_secs, 30);
        assert_eq!(config.swarm.escalation_threshold, "MEDIUM");
        assert_eq!(config.swarm.chat_port, 4000);
    }

    #[test]
    fn test_config_parses_empty_toml_uses_defaults() {
        let config: ClawConfig = toml::from_str("").unwrap();
        assert!(config.swarm.enabled);
        assert_eq!(config.swarm.escalation_threshold, "HIGH");
    }
}
