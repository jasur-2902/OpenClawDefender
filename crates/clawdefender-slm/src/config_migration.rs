//! Migration from single-backend `ActiveModelConfig` to dual-backend `DualAiConfig`.
//!
//! When upgrading from ClawDefender v1 (single AI backend) to v2 (dual local+cloud),
//! this module detects the old config format and transparently migrates it to the new
//! `DualAiConfig` structure. API keys remain in the macOS Keychain and are never
//! written to the config file.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::model_registry::ActiveModelConfig;

// ---------------------------------------------------------------------------
// New dual-backend config types
// ---------------------------------------------------------------------------

/// New dual-backend config format (version 2).
///
/// Supports simultaneous local and cloud AI backends with routing preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualAiConfig {
    /// Config format version. `2` for the dual-backend format.
    pub version: u32,
    /// Local model configuration (GGUF-based inference).
    pub local: Option<LocalModelConfig>,
    /// Cloud model configuration (API-based inference).
    pub cloud: Option<CloudModelConfig>,
    /// Routing preferences between local and cloud.
    #[serde(default)]
    pub routing: RoutingConfig,
}

impl Default for DualAiConfig {
    fn default() -> Self {
        Self {
            version: 2,
            local: None,
            cloud: None,
            routing: RoutingConfig::default(),
        }
    }
}

/// Configuration for a locally-running GGUF model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalModelConfig {
    /// `"catalog"` for curated models, `"custom"` for user-supplied GGUF files.
    pub model_type: String,
    /// Catalog model ID (e.g. `"qwen3-1.7b-q4"`), `None` for custom models.
    pub model_id: Option<String>,
    /// Path to the GGUF model file on disk.
    pub path: PathBuf,
}

/// Configuration for a cloud AI provider.
///
/// The API key is stored in the macOS Keychain, not in this struct or on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudModelConfig {
    /// Provider identifier (e.g. `"anthropic"`, `"openai"`, `"google"`).
    pub provider: String,
    /// Model identifier for API calls (e.g. `"claude-sonnet-4-20250514"`).
    pub model: String,
}

/// Routing preferences for dual-backend operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// When both backends are available, prefer local inference.
    pub prefer_local: bool,
    /// Automatically escalate to cloud when local model confidence is low.
    pub cloud_auto_escalate: bool,
    /// Prompt the user for confirmation before each cloud API call.
    pub cloud_confirmation: bool,
    /// Rate limit: maximum cloud API calls per hour.
    pub max_cloud_calls_per_hour: u32,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            prefer_local: true,
            cloud_auto_escalate: true,
            cloud_confirmation: false,
            max_cloud_calls_per_hour: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Config path
// ---------------------------------------------------------------------------

/// Return the path to the model configuration file.
///
/// Same location as the v1 config: `~/.local/share/clawdefender/model_config.toml`.
fn model_config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| anyhow::anyhow!("cannot determine home directory"))?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("clawdefender")
        .join("model_config.toml"))
}

// ---------------------------------------------------------------------------
// Migration (internal, path-parameterized)
// ---------------------------------------------------------------------------

/// Convert old v1 TOML content to a `DualAiConfig`.
///
/// Tries v2 format first, then falls back to v1 `ActiveModelConfig`.
fn migrate_from_content(content: &str) -> Result<DualAiConfig> {
    // Try new format first
    if let Ok(new_config) = toml::from_str::<DualAiConfig>(content) {
        if new_config.version == 2 {
            return Ok(new_config);
        }
    }

    // Fall back to old format
    let old_config: ActiveModelConfig = toml::from_str(content)?;

    let new_config = match old_config {
        ActiveModelConfig::LocalCatalog { model_id, path } => DualAiConfig {
            version: 2,
            local: Some(LocalModelConfig {
                model_type: "catalog".to_string(),
                model_id: Some(model_id),
                path,
            }),
            cloud: detect_cloud_from_keychain(),
            routing: RoutingConfig::default(),
        },
        ActiveModelConfig::LocalCustom { path } => DualAiConfig {
            version: 2,
            local: Some(LocalModelConfig {
                model_type: "custom".to_string(),
                model_id: None,
                path,
            }),
            cloud: detect_cloud_from_keychain(),
            routing: RoutingConfig::default(),
        },
        ActiveModelConfig::CloudApi { provider, model } => DualAiConfig {
            version: 2,
            local: None,
            cloud: Some(CloudModelConfig { provider, model }),
            routing: RoutingConfig::default(),
        },
        ActiveModelConfig::None => DualAiConfig {
            version: 2,
            local: None,
            cloud: detect_cloud_from_keychain(),
            routing: RoutingConfig::default(),
        },
    };

    Ok(new_config)
}

/// Migrate config at a specific path, writing the result back.
fn migrate_at_path(config_path: &Path) -> Result<DualAiConfig> {
    if !config_path.exists() {
        return Ok(DualAiConfig::default());
    }

    let content = std::fs::read_to_string(config_path)?;
    let new_config = migrate_from_content(&content)?;

    // If we migrated from v1, write the v2 config back
    if toml::from_str::<DualAiConfig>(&content)
        .map(|c| c.version != 2)
        .unwrap_or(true)
    {
        save_dual_config_to(config_path, &new_config)?;
        info!("Migrated model config from v1 to v2 (dual-backend)");
    }

    Ok(new_config)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Migrate from old `ActiveModelConfig` format to new `DualAiConfig` format.
///
/// Called on startup when loading config. The function:
/// 1. If no config file exists, returns a default `DualAiConfig`.
/// 2. Tries to parse as the new v2 format first.
/// 3. Falls back to parsing the old v1 `ActiveModelConfig` format and migrates it.
/// 4. Writes the migrated config back to disk.
pub fn migrate_model_config() -> Result<DualAiConfig> {
    let config_path = model_config_path()?;
    migrate_at_path(&config_path)
}

/// Check if any cloud API key exists in the Keychain, and if so, infer cloud config.
fn detect_cloud_from_keychain() -> Option<CloudModelConfig> {
    #[cfg(feature = "cloud")]
    {
        for provider in &["anthropic", "openai", "google"] {
            if crate::cloud_backend::has_api_key(provider) {
                return Some(CloudModelConfig {
                    provider: provider.to_string(),
                    model: default_model_for_provider(provider),
                });
            }
        }
    }
    None
}

/// Return the default/recommended model ID for a given cloud provider.
pub fn default_model_for_provider(provider: &str) -> String {
    match provider {
        "anthropic" => "claude-sonnet-4-20250514".to_string(),
        "openai" => "gpt-4o".to_string(),
        "google" => "gemini-2.5-pro".to_string(),
        _ => "unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Save / Load
// ---------------------------------------------------------------------------

/// Save a `DualAiConfig` to the default model config file.
pub fn save_dual_config(config: &DualAiConfig) -> Result<()> {
    let path = model_config_path()?;
    save_dual_config_to(&path, config)
}

/// Save a `DualAiConfig` to a specific path.
fn save_dual_config_to(path: &Path, config: &DualAiConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
}

/// Load the dual AI config, migrating from v1 if necessary.
///
/// This is the primary entry point for loading model configuration.
pub fn load_dual_config() -> Result<DualAiConfig> {
    migrate_model_config()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a temp config file with the given content, return its path.
    fn write_temp_config(content: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let config_dir = tmp
            .path()
            .join(".local")
            .join("share")
            .join("clawdefender");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("model_config.toml");
        std::fs::write(&config_path, content).unwrap();
        (tmp, config_path)
    }

    #[test]
    fn test_migrate_local_catalog() {
        let old_toml = r#"
type = "LocalCatalog"
model_id = "qwen3-1.7b-q4"
path = "/models/qwen3.gguf"
"#;
        let (_tmp, path) = write_temp_config(old_toml);

        let config = migrate_at_path(&path).unwrap();
        assert_eq!(config.version, 2);
        let local = config.local.expect("local should be Some");
        assert_eq!(local.model_type, "catalog");
        assert_eq!(local.model_id.as_deref(), Some("qwen3-1.7b-q4"));
        assert_eq!(local.path, PathBuf::from("/models/qwen3.gguf"));
    }

    #[test]
    fn test_migrate_local_custom() {
        let old_toml = r#"
type = "LocalCustom"
path = "/custom/my-model.gguf"
"#;
        let (_tmp, path) = write_temp_config(old_toml);

        let config = migrate_at_path(&path).unwrap();
        assert_eq!(config.version, 2);
        let local = config.local.expect("local should be Some");
        assert_eq!(local.model_type, "custom");
        assert!(local.model_id.is_none());
        assert_eq!(local.path, PathBuf::from("/custom/my-model.gguf"));
    }

    #[test]
    fn test_migrate_cloud_api() {
        let old_toml = r#"
type = "CloudApi"
provider = "anthropic"
model = "claude-sonnet-4-20250514"
"#;
        let (_tmp, path) = write_temp_config(old_toml);

        let config = migrate_at_path(&path).unwrap();
        assert_eq!(config.version, 2);
        assert!(config.local.is_none());
        let cloud = config.cloud.expect("cloud should be Some");
        assert_eq!(cloud.provider, "anthropic");
        assert_eq!(cloud.model, "claude-sonnet-4-20250514");
    }

    #[test]
    fn test_migrate_none() {
        let old_toml = r#"
type = "None"
"#;
        let (_tmp, path) = write_temp_config(old_toml);

        let config = migrate_at_path(&path).unwrap();
        assert_eq!(config.version, 2);
        assert!(config.local.is_none());
    }

    #[test]
    fn test_new_format_preserved() {
        let v2_toml = r#"
version = 2

[local]
model_type = "catalog"
model_id = "qwen3-4b-q4"
path = "/models/qwen3-4b.gguf"

[cloud]
provider = "openai"
model = "gpt-4o"

[routing]
prefer_local = false
cloud_auto_escalate = true
cloud_confirmation = true
max_cloud_calls_per_hour = 50
"#;
        let (_tmp, path) = write_temp_config(v2_toml);

        let config = migrate_at_path(&path).unwrap();
        assert_eq!(config.version, 2);
        let local = config.local.expect("local should be Some");
        assert_eq!(local.model_id.as_deref(), Some("qwen3-4b-q4"));
        let cloud = config.cloud.expect("cloud should be Some");
        assert_eq!(cloud.provider, "openai");
        assert_eq!(cloud.model, "gpt-4o");
        assert!(!config.routing.prefer_local);
        assert!(config.routing.cloud_confirmation);
        assert_eq!(config.routing.max_cloud_calls_per_hour, 50);
    }

    #[test]
    fn test_default_routing_config() {
        let rc = RoutingConfig::default();
        assert!(rc.prefer_local);
        assert!(rc.cloud_auto_escalate);
        assert!(!rc.cloud_confirmation);
        assert_eq!(rc.max_cloud_calls_per_hour, 10);
    }

    #[test]
    fn test_default_dual_ai_config() {
        let config = DualAiConfig::default();
        assert_eq!(config.version, 2);
        assert!(config.local.is_none());
        assert!(config.cloud.is_none());
        assert!(config.routing.prefer_local);
    }

    #[test]
    fn test_roundtrip_serialization() {
        let config = DualAiConfig {
            version: 2,
            local: Some(LocalModelConfig {
                model_type: "catalog".to_string(),
                model_id: Some("qwen3-1.7b-q4".to_string()),
                path: PathBuf::from("/models/test.gguf"),
            }),
            cloud: Some(CloudModelConfig {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
            }),
            routing: RoutingConfig {
                prefer_local: false,
                cloud_auto_escalate: true,
                cloud_confirmation: true,
                max_cloud_calls_per_hour: 25,
            },
        };

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: DualAiConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(parsed.version, 2);
        let local = parsed.local.expect("local should roundtrip");
        assert_eq!(local.model_type, "catalog");
        assert_eq!(local.model_id.as_deref(), Some("qwen3-1.7b-q4"));
        assert_eq!(local.path, PathBuf::from("/models/test.gguf"));
        let cloud = parsed.cloud.expect("cloud should roundtrip");
        assert_eq!(cloud.provider, "anthropic");
        assert_eq!(cloud.model, "claude-sonnet-4-20250514");
        assert!(!parsed.routing.prefer_local);
        assert!(parsed.routing.cloud_confirmation);
        assert_eq!(parsed.routing.max_cloud_calls_per_hour, 25);
    }

    #[test]
    fn test_roundtrip_no_optional_fields() {
        let config = DualAiConfig {
            version: 2,
            local: None,
            cloud: None,
            routing: RoutingConfig::default(),
        };

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: DualAiConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(parsed.version, 2);
        assert!(parsed.local.is_none());
        assert!(parsed.cloud.is_none());
        assert!(parsed.routing.prefer_local);
    }

    #[test]
    fn test_no_config_file_returns_default() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let nonexistent = tmp.path().join("nonexistent.toml");

        let config = migrate_at_path(&nonexistent).unwrap();
        assert_eq!(config.version, 2);
        assert!(config.local.is_none());
        assert!(config.cloud.is_none());
    }

    #[test]
    fn test_default_model_for_provider() {
        assert_eq!(
            default_model_for_provider("anthropic"),
            "claude-sonnet-4-20250514"
        );
        assert_eq!(default_model_for_provider("openai"), "gpt-4o");
        assert_eq!(default_model_for_provider("google"), "gemini-2.5-pro");
        assert_eq!(default_model_for_provider("unknown"), "unknown");
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let config_path = tmp.path().join("model_config.toml");

        let config = DualAiConfig {
            version: 2,
            local: Some(LocalModelConfig {
                model_type: "custom".to_string(),
                model_id: None,
                path: PathBuf::from("/tmp/model.gguf"),
            }),
            cloud: None,
            routing: RoutingConfig::default(),
        };

        save_dual_config_to(&config_path, &config).unwrap();
        let loaded = migrate_at_path(&config_path).unwrap();

        assert_eq!(loaded.version, 2);
        let local = loaded.local.expect("local should persist");
        assert_eq!(local.model_type, "custom");
        assert!(local.model_id.is_none());
        assert_eq!(local.path, PathBuf::from("/tmp/model.gguf"));
    }

    #[test]
    fn test_migration_writes_back_v2() {
        let old_toml = r#"
type = "LocalCatalog"
model_id = "gemma3-1b-q4"
path = "/models/gemma.gguf"
"#;
        let (_tmp, path) = write_temp_config(old_toml);

        // Migrate — should write v2 back
        let _config = migrate_at_path(&path).unwrap();

        // Read the file again — should now be v2 format
        let content = std::fs::read_to_string(&path).unwrap();
        let reloaded: DualAiConfig = toml::from_str(&content).unwrap();
        assert_eq!(reloaded.version, 2);
        assert!(reloaded.local.is_some());
    }

    #[test]
    fn test_migrate_from_content_v1_local_catalog() {
        let old = r#"
type = "LocalCatalog"
model_id = "qwen3-1.7b-q4"
path = "/models/qwen3.gguf"
"#;
        let config = migrate_from_content(old).unwrap();
        assert_eq!(config.version, 2);
        let local = config.local.unwrap();
        assert_eq!(local.model_type, "catalog");
        assert_eq!(local.model_id.as_deref(), Some("qwen3-1.7b-q4"));
    }

    #[test]
    fn test_migrate_from_content_v2_passthrough() {
        let v2 = r#"
version = 2

[routing]
prefer_local = true
cloud_auto_escalate = false
cloud_confirmation = false
max_cloud_calls_per_hour = 5
"#;
        let config = migrate_from_content(v2).unwrap();
        assert_eq!(config.version, 2);
        assert!(!config.routing.cloud_auto_escalate);
        assert_eq!(config.routing.max_cloud_calls_per_hour, 5);
    }
}
