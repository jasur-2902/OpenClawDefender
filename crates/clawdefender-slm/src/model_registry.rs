//! Curated model catalog, cloud provider definitions, system detection,
//! and active-model configuration persistence.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::info;

// ---------------------------------------------------------------------------
// Local catalog models
// ---------------------------------------------------------------------------

/// A model entry in the curated catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogModel {
    /// Unique identifier, e.g. "qwen3-1.7b-q4".
    pub id: String,
    /// Human-friendly display name.
    pub display_name: String,
    /// Model family, e.g. "Qwen3".
    pub family: String,
    /// Quantization level, e.g. "Q4_K_M".
    pub quantization: String,
    /// GGUF filename on disk.
    pub filename: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Direct HuggingFace download URL.
    pub download_url: String,
    /// Expected SHA-256 hex digest (all zeros = skip verification).
    pub sha256: String,
    /// Minimum recommended RAM in GB.
    pub min_ram_gb: u32,
    /// Estimated tokens/sec on Apple Silicon.
    pub tokens_per_sec_apple: f32,
    /// Estimated tokens/sec on Intel.
    pub tokens_per_sec_intel: f32,
    /// Quality rating 1-5.
    pub quality_rating: u8,
    /// One-line description.
    pub description: String,
    /// Whether this is the default recommendation.
    pub is_default: bool,
}

const PLACEHOLDER_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Return the curated catalog of local GGUF models.
pub fn catalog() -> Vec<CatalogModel> {
    vec![
        CatalogModel {
            id: "qwen3-1.7b-q4".into(),
            display_name: "Qwen3 1.7B".into(),
            family: "Qwen3".into(),
            quantization: "Q4_K_M".into(),
            filename: "qwen3-1.7b-q4_k_m.gguf".into(),
            size_bytes: 1_100_000_000,
            download_url: "https://huggingface.co/Qwen/Qwen3-1.7B-GGUF/resolve/main/qwen3-1.7b-q4_k_m.gguf".into(),
            sha256: PLACEHOLDER_SHA256.into(),
            min_ram_gb: 4,
            tokens_per_sec_apple: 55.0,
            tokens_per_sec_intel: 20.0,
            quality_rating: 4,
            description: "Recommended: Fast, thinking mode, works on all Macs".into(),
            is_default: true,
        },
        CatalogModel {
            id: "qwen3-4b-q4".into(),
            display_name: "Qwen3 4B".into(),
            family: "Qwen3".into(),
            quantization: "Q4_K_M".into(),
            filename: "qwen3-4b-q4_k_m.gguf".into(),
            size_bytes: 2_500_000_000,
            download_url: "https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/main/qwen3-4b-q4_k_m.gguf".into(),
            sha256: PLACEHOLDER_SHA256.into(),
            min_ram_gb: 8,
            tokens_per_sec_apple: 35.0,
            tokens_per_sec_intel: 12.0,
            quality_rating: 5,
            description: "Best quality under 3GB, reasoning + thinking mode".into(),
            is_default: false,
        },
        CatalogModel {
            id: "phi4-mini-3.8b-q4".into(),
            display_name: "Phi-4 Mini Instruct 3.8B".into(),
            family: "Phi-4".into(),
            quantization: "Q4_K_M".into(),
            filename: "Phi-4-mini-instruct-Q4_K_M.gguf".into(),
            size_bytes: 2_500_000_000,
            download_url: "https://huggingface.co/unsloth/Phi-4-mini-instruct-GGUF/resolve/main/Phi-4-mini-instruct-Q4_K_M.gguf".into(),
            sha256: PLACEHOLDER_SHA256.into(),
            min_ram_gb: 8,
            tokens_per_sec_apple: 32.0,
            tokens_per_sec_intel: 11.0,
            quality_rating: 4,
            description: "Strong reasoning & coding, great instruction following".into(),
            is_default: false,
        },
        CatalogModel {
            id: "gemma3-1b-q4".into(),
            display_name: "Gemma 3 1B".into(),
            family: "Gemma3".into(),
            quantization: "Q4_K_M".into(),
            filename: "gemma-3-1b-it-Q4_K_M.gguf".into(),
            size_bytes: 800_000_000,
            download_url: "https://huggingface.co/ggml-org/gemma-3-1b-it-GGUF/resolve/main/gemma-3-1b-it-Q4_K_M.gguf".into(),
            sha256: PLACEHOLDER_SHA256.into(),
            min_ram_gb: 2,
            tokens_per_sec_apple: 80.0,
            tokens_per_sec_intel: 35.0,
            quality_rating: 3,
            description: "Lightweight: Fastest, 128K context, 140+ languages".into(),
            is_default: false,
        },
        CatalogModel {
            id: "gemma3-4b-q4".into(),
            display_name: "Gemma 3 4B".into(),
            family: "Gemma3".into(),
            quantization: "Q4_K_M".into(),
            filename: "gemma-3-4b-it-Q4_K_M.gguf".into(),
            size_bytes: 2_500_000_000,
            download_url: "https://huggingface.co/ggml-org/gemma-3-4b-it-GGUF/resolve/main/gemma-3-4b-it-Q4_K_M.gguf".into(),
            sha256: PLACEHOLDER_SHA256.into(),
            min_ram_gb: 8,
            tokens_per_sec_apple: 33.0,
            tokens_per_sec_intel: 12.0,
            quality_rating: 5,
            description: "Multimodal (text+image), 128K context, excellent quality".into(),
            is_default: false,
        },
    ]
}

/// Look up a catalog model by its id.
pub fn find_model(id: &str) -> Option<CatalogModel> {
    catalog().into_iter().find(|m| m.id == id)
}

/// Return the default catalog model (the one marked `is_default`).
pub fn default_model() -> CatalogModel {
    catalog()
        .into_iter()
        .find(|m| m.is_default)
        .expect("catalog must contain a default model")
}

// ---------------------------------------------------------------------------
// Model recommendation
// ---------------------------------------------------------------------------

/// Recommend a catalog model based on available RAM and CPU architecture.
pub fn recommend_model(ram_gb: u64, _is_apple_silicon: bool) -> CatalogModel {
    if ram_gb < 8 {
        // Low RAM: smallest model
        find_model("gemma3-1b-q4").unwrap_or_else(default_model)
    } else if ram_gb < 16 {
        // 8-15 GB: mid-size
        find_model("qwen3-1.7b-q4").unwrap_or_else(default_model)
    } else {
        // 16+ GB: best quality
        find_model("qwen3-4b-q4").unwrap_or_else(default_model)
    }
}

// ---------------------------------------------------------------------------
// System detection
// ---------------------------------------------------------------------------

/// Detected system capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCapabilities {
    /// Total physical RAM in bytes.
    pub total_ram_bytes: u64,
    /// Total physical RAM in GB (rounded).
    pub total_ram_gb: u64,
    /// CPU architecture string (e.g. "arm64", "x86_64").
    pub arch: String,
    /// Whether the system is Apple Silicon (arm64 on macOS).
    pub is_apple_silicon: bool,
}

/// Detect system RAM and CPU architecture.
///
/// On macOS uses `sysctl hw.memsize` and `uname -m`.
/// Falls back to conservative defaults on error.
pub fn detect_system_info() -> SystemCapabilities {
    let total_ram_bytes = detect_ram_bytes().unwrap_or(8_000_000_000);
    let arch = detect_arch().unwrap_or_else(|| std::env::consts::ARCH.to_string());
    let is_apple_silicon = cfg!(target_os = "macos") && arch == "arm64";
    let total_ram_gb = total_ram_bytes / (1024 * 1024 * 1024);

    SystemCapabilities {
        total_ram_bytes,
        total_ram_gb,
        arch,
        is_apple_silicon,
    }
}

fn detect_ram_bytes() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("sysctl")
            .arg("-n")
            .arg("hw.memsize")
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.trim().parse::<u64>().ok()
    }
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("grep")
            .args(["MemTotal", "/proc/meminfo"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        // MemTotal:       16384000 kB
        let kb: u64 = stdout
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kb * 1024)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

fn detect_arch() -> Option<String> {
    let output = std::process::Command::new("uname")
        .arg("-m")
        .output()
        .ok()?;
    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if arch.is_empty() {
        None
    } else {
        Some(arch)
    }
}

// ---------------------------------------------------------------------------
// Cloud providers
// ---------------------------------------------------------------------------

/// A cloud AI provider with its available models.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudProvider {
    /// Provider identifier, e.g. "anthropic".
    pub id: String,
    /// Human-friendly name.
    pub display_name: String,
    /// Available models.
    pub models: Vec<CloudModel>,
    /// API endpoint base URL.
    pub api_endpoint: String,
}

/// A model offered by a cloud provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudModel {
    /// Model identifier used in API calls.
    pub id: String,
    /// Human-friendly display name.
    pub display_name: String,
    /// Cost per 1K input tokens (USD).
    pub cost_per_1k_input: f64,
    /// Cost per 1K output tokens (USD).
    pub cost_per_1k_output: f64,
    /// Whether this model is recommended for ClawDefender.
    pub recommended: bool,
}

/// Return the built-in list of cloud providers.
pub fn cloud_providers() -> Vec<CloudProvider> {
    vec![
        CloudProvider {
            id: "anthropic".into(),
            display_name: "Anthropic".into(),
            api_endpoint: "https://api.anthropic.com/v1".into(),
            models: vec![
                CloudModel {
                    id: "claude-sonnet-4-20250514".into(),
                    display_name: "Claude Sonnet 4".into(),
                    cost_per_1k_input: 0.003,
                    cost_per_1k_output: 0.015,
                    recommended: true,
                },
                CloudModel {
                    id: "claude-haiku-4-20250506".into(),
                    display_name: "Claude Haiku 4".into(),
                    cost_per_1k_input: 0.0008,
                    cost_per_1k_output: 0.004,
                    recommended: false,
                },
            ],
        },
        CloudProvider {
            id: "openai".into(),
            display_name: "OpenAI".into(),
            api_endpoint: "https://api.openai.com/v1".into(),
            models: vec![
                CloudModel {
                    id: "gpt-4o-mini".into(),
                    display_name: "GPT-4o Mini".into(),
                    cost_per_1k_input: 0.00015,
                    cost_per_1k_output: 0.0006,
                    recommended: false,
                },
                CloudModel {
                    id: "gpt-4o".into(),
                    display_name: "GPT-4o".into(),
                    cost_per_1k_input: 0.0025,
                    cost_per_1k_output: 0.01,
                    recommended: true,
                },
            ],
        },
        CloudProvider {
            id: "google".into(),
            display_name: "Google".into(),
            api_endpoint: "https://generativelanguage.googleapis.com/v1beta".into(),
            models: vec![
                CloudModel {
                    id: "gemini-2.0-flash".into(),
                    display_name: "Gemini Flash".into(),
                    cost_per_1k_input: 0.0001,
                    cost_per_1k_output: 0.0004,
                    recommended: false,
                },
                CloudModel {
                    id: "gemini-2.5-pro".into(),
                    display_name: "Gemini Pro".into(),
                    cost_per_1k_input: 0.00125,
                    cost_per_1k_output: 0.01,
                    recommended: true,
                },
            ],
        },
    ]
}

// ---------------------------------------------------------------------------
// Active model configuration
// ---------------------------------------------------------------------------

/// The currently active model configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ActiveModelConfig {
    /// A model from the curated catalog, downloaded locally.
    LocalCatalog {
        model_id: String,
        path: PathBuf,
    },
    /// A user-supplied local GGUF file.
    LocalCustom {
        path: PathBuf,
    },
    /// A cloud API model.
    CloudApi {
        provider: String,
        model: String,
    },
    /// No model configured.
    None,
}

impl Default for ActiveModelConfig {
    fn default() -> Self {
        Self::None
    }
}

/// Return the default path for the model configuration file.
fn config_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| anyhow::anyhow!("cannot determine home directory"))?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("clawdefender")
        .join("model_config.toml"))
}

/// Load the active model configuration from disk.
///
/// Returns `ActiveModelConfig::None` if the config file does not exist.
pub fn load_active_config() -> anyhow::Result<ActiveModelConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(ActiveModelConfig::None);
    }
    let content = std::fs::read_to_string(&path)?;
    let config: ActiveModelConfig = toml::from_str(&content)?;
    info!(path = %path.display(), "loaded active model config");
    Ok(config)
}

/// Save the active model configuration to disk.
pub fn save_active_config(config: &ActiveModelConfig) -> anyhow::Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(config)?;
    std::fs::write(&path, content)?;
    info!(path = %path.display(), "saved active model config");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_five_models() {
        let models = catalog();
        assert_eq!(models.len(), 5);
    }

    #[test]
    fn catalog_has_exactly_one_default() {
        let defaults: Vec<_> = catalog().into_iter().filter(|m| m.is_default).collect();
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0].id, "qwen3-1.7b-q4");
    }

    #[test]
    fn all_models_have_valid_fields() {
        for m in catalog() {
            assert!(!m.id.is_empty());
            assert!(!m.display_name.is_empty());
            assert!(!m.filename.is_empty());
            assert!(m.filename.ends_with(".gguf"));
            assert!(m.size_bytes > 0);
            assert!(!m.download_url.is_empty());
            assert!(m.download_url.starts_with("https://huggingface.co/"));
            assert_eq!(m.sha256.len(), 64);
            assert!(m.min_ram_gb > 0);
            assert!(m.quality_rating >= 1 && m.quality_rating <= 5);
            assert!(m.tokens_per_sec_apple > 0.0);
            assert!(m.tokens_per_sec_intel > 0.0);
        }
    }

    #[test]
    fn find_model_returns_some_for_valid_id() {
        assert!(find_model("qwen3-1.7b-q4").is_some());
        assert!(find_model("gemma3-1b-q4").is_some());
    }

    #[test]
    fn find_model_returns_none_for_invalid_id() {
        assert!(find_model("nonexistent").is_none());
    }

    #[test]
    fn default_model_is_qwen3_1_7b() {
        let m = default_model();
        assert_eq!(m.id, "qwen3-1.7b-q4");
        assert!(m.is_default);
    }

    #[test]
    fn recommend_low_ram() {
        let m = recommend_model(4, true);
        assert_eq!(m.id, "gemma3-1b-q4");
    }

    #[test]
    fn recommend_mid_ram() {
        let m = recommend_model(8, true);
        assert_eq!(m.id, "qwen3-1.7b-q4");
    }

    #[test]
    fn recommend_high_ram() {
        let m = recommend_model(32, false);
        assert_eq!(m.id, "qwen3-4b-q4");
    }

    #[test]
    fn detect_system_info_returns_reasonable_values() {
        let info = detect_system_info();
        // Should have at least 1 GB on any dev machine.
        assert!(info.total_ram_gb >= 1);
        assert!(!info.arch.is_empty());
    }

    #[test]
    fn cloud_providers_not_empty() {
        let providers = cloud_providers();
        assert_eq!(providers.len(), 3);
        for p in &providers {
            assert!(!p.id.is_empty());
            assert!(!p.models.is_empty());
            assert!(!p.api_endpoint.is_empty());
        }
    }

    #[test]
    fn cloud_providers_have_recommended_models() {
        for p in cloud_providers() {
            let has_recommended = p.models.iter().any(|m| m.recommended);
            assert!(has_recommended, "provider {} lacks a recommended model", p.id);
        }
    }

    #[test]
    fn active_model_config_serialization_roundtrip() {
        let config = ActiveModelConfig::LocalCatalog {
            model_id: "qwen3-1.7b-q4".into(),
            path: PathBuf::from("/tmp/test.gguf"),
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: ActiveModelConfig = toml::from_str(&toml_str).unwrap();
        match parsed {
            ActiveModelConfig::LocalCatalog { model_id, path } => {
                assert_eq!(model_id, "qwen3-1.7b-q4");
                assert_eq!(path, PathBuf::from("/tmp/test.gguf"));
            }
            _ => panic!("expected LocalCatalog variant"),
        }
    }

    #[test]
    fn active_model_config_cloud_roundtrip() {
        let config = ActiveModelConfig::CloudApi {
            provider: "anthropic".into(),
            model: "claude-sonnet-4-20250514".into(),
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: ActiveModelConfig = toml::from_str(&toml_str).unwrap();
        match parsed {
            ActiveModelConfig::CloudApi { provider, model } => {
                assert_eq!(provider, "anthropic");
                assert_eq!(model, "claude-sonnet-4-20250514");
            }
            _ => panic!("expected CloudApi variant"),
        }
    }

    #[test]
    fn active_model_config_none_roundtrip() {
        let config = ActiveModelConfig::None;
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: ActiveModelConfig = toml::from_str(&toml_str).unwrap();
        assert!(matches!(parsed, ActiveModelConfig::None));
    }
}
