//! Small language model integration for policy decisions.
//!
//! This crate provides:
//! - `engine` -- the core SLM inference engine with concurrency control
//! - `model_manager` -- download, verify, and list GGUF model files
//! - `analyzer` -- risk analysis pipeline and prompt templates
//! - `context` -- per-server context tracking for SLM analysis
//! - `noise_filter` -- filters out benign developer activity
//! - `profiles` -- built-in activity profiles for the noise filter
//! - `sanitizer` -- prompt injection prevention
//! - `output_validator` -- validates and constrains SLM output
//! - `gguf_backend` -- real GGUF inference via llama.cpp (requires `gguf` feature)

pub mod analyzer;
#[cfg(feature = "cloud")]
pub mod cloud_backend;
pub mod context;
#[cfg(feature = "download")]
pub mod downloader;
pub mod engine;
#[cfg(feature = "gguf")]
pub mod gguf_backend;
pub mod model_manager;
pub mod model_registry;
pub mod noise_filter;
pub mod output_validator;
pub mod profiles;
pub mod sanitizer;

use std::sync::Arc;

use anyhow::Result;
use tracing::info;

#[cfg(any(not(feature = "gguf"), test))]
use crate::engine::MockSlmBackend;
use crate::engine::{RiskLevel, SlmBackend, SlmConfig, SlmEngine, SlmResponse, SlmStats};

/// Top-level service that owns the SLM engine and exposes a simple API
/// for the rest of ClawDefender.
pub struct SlmService {
    engine: Option<Arc<SlmEngine>>,
    config: SlmConfig,
    enabled: bool,
}

impl SlmService {
    /// Create a new enabled service backed by the given engine.
    pub fn with_engine(engine: Arc<SlmEngine>, config: SlmConfig) -> Self {
        Self {
            engine: Some(engine),
            config,
            enabled: true,
        }
    }

    /// Create a new service, loading the engine if enabled and the model file exists.
    ///
    /// If `enabled` is false or the model path does not exist, the service is created
    /// in disabled mode and `analyze_event` returns `RiskLevel::Low` immediately.
    ///
    /// When the `gguf` feature is enabled and the model file exists, the real
    /// llama.cpp backend is used. Otherwise falls back to the mock backend.
    pub fn new(config: SlmConfig, enabled: bool) -> Self {
        if !enabled {
            return Self::disabled(config);
        }

        if !config.model_path.exists() {
            info!(
                path = %config.model_path.display(),
                "SLM model file not found, running in disabled mode"
            );
            return Self::disabled(config);
        }

        #[cfg(feature = "gguf")]
        {
            match crate::gguf_backend::GgufBackend::load(&config) {
                Ok(backend) => {
                    info!(
                        path = %config.model_path.display(),
                        "SLM loaded with GGUF backend (llama.cpp)"
                    );
                    let backend: Box<dyn SlmBackend> = Box::new(backend);
                    let engine = Arc::new(SlmEngine::new(backend, config.clone()));
                    return Self {
                        engine: Some(engine),
                        config,
                        enabled: true,
                    };
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %config.model_path.display(),
                        "Failed to load GGUF model, falling back to disabled mode"
                    );
                    return Self::disabled(config);
                }
            }
        }

        #[cfg(not(feature = "gguf"))]
        {
            // Without the gguf feature, use the mock backend when the model path exists.
            // This is useful for testing and development.
            info!(
                path = %config.model_path.display(),
                "SLM model path exists -- using mock backend (compile with `gguf` feature for real inference)"
            );
            let backend: Box<dyn SlmBackend> = Box::new(MockSlmBackend::default());
            let engine = Arc::new(SlmEngine::new(backend, config.clone()));

            Self {
                engine: Some(engine),
                config,
                enabled: true,
            }
        }
    }

    /// Create a disabled (no-op) service.
    pub fn disabled(config: SlmConfig) -> Self {
        Self {
            engine: None,
            config,
            enabled: false,
        }
    }

    /// Returns true if the SLM engine is loaded and ready.
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.engine.is_some()
    }

    /// Check if the SLM model is available (alias for is_enabled).
    pub fn is_available(&self) -> bool {
        self.is_enabled()
    }

    /// Analyze an event by running SLM inference.
    ///
    /// Returns `RiskLevel::Low` immediately if the service is disabled.
    pub async fn analyze_event(&self, prompt: &str) -> Result<SlmResponse> {
        if let Some(ref engine) = self.engine {
            engine.infer(prompt).await
        } else {
            Ok(Self::disabled_response())
        }
    }

    /// Analyze a scanner finding for deeper risk assessment.
    ///
    /// Constructs a security-focused prompt from the finding details and
    /// runs SLM inference. Returns a graceful fallback if disabled.
    pub async fn analyze_scan_finding(
        &self,
        finding_type: &str,
        severity: &str,
        description: &str,
        file_path: &str,
    ) -> Result<SlmResponse> {
        if !self.is_enabled() {
            return Ok(Self::disabled_response());
        }

        let prompt = format!(
            "Analyze this security scanner finding for risk assessment.\n\n\
             Finding Type: {finding_type}\n\
             Severity: {severity}\n\
             Description: {description}\n\
             File: {file_path}\n\n\
             Is this a real security risk or a false positive? Assess the risk level."
        );

        self.analyze_event(&prompt).await
    }

    /// Assess an MCP server configuration for security risks.
    ///
    /// Examines server config details and provides risk analysis.
    /// Returns a graceful fallback if disabled.
    pub async fn assess_server_config(
        &self,
        server_name: &str,
        command: &str,
        args: &[String],
        env_vars: &[String],
    ) -> Result<SlmResponse> {
        if !self.is_enabled() {
            return Ok(Self::disabled_response());
        }

        let args_str = args.join(" ");
        // SECURITY: Only send env var *names* to the SLM, never values.
        // Env vars may contain API keys, tokens, or other secrets.
        let env_names: Vec<String> = env_vars
            .iter()
            .map(|v| v.split('=').next().unwrap_or(v).to_string())
            .collect();
        let env_str = if env_names.is_empty() {
            "none".to_string()
        } else {
            env_names.join(", ")
        };

        let prompt = format!(
            "Assess this MCP server configuration for security risks.\n\n\
             Server Name: {server_name}\n\
             Command: {command}\n\
             Arguments: {args_str}\n\
             Environment Variables: {env_str}\n\n\
             Does this configuration pose any security risks? Check for:\n\
             - Excessive permissions\n\
             - Suspicious commands or arguments\n\
             - Potential for data exfiltration\n\
             - Unsafe environment variable usage"
        );

        self.analyze_event(&prompt).await
    }

    /// Return engine statistics, or None if disabled.
    pub fn stats(&self) -> Option<SlmStats> {
        self.engine.as_ref().map(|e| e.stats())
    }

    /// Access the config.
    pub fn config(&self) -> &SlmConfig {
        &self.config
    }

    /// Get a reference to the engine Arc, if loaded.
    pub fn engine(&self) -> Option<&Arc<SlmEngine>> {
        self.engine.as_ref()
    }

    /// Return a human-readable status string for UI display.
    pub fn status_display(&self) -> String {
        if let Some(stats) = self.stats() {
            format!(
                "Model loaded: {} ({:.0} MB, {})",
                stats.model_name,
                stats.model_size_bytes as f64 / 1_000_000.0,
                if stats.using_gpu { "GPU" } else { "CPU" }
            )
        } else {
            "No model loaded - place a GGUF model in ~/.local/share/clawdefender/models/".to_string()
        }
    }

    /// Default response when the service is disabled.
    fn disabled_response() -> SlmResponse {
        SlmResponse {
            risk_level: RiskLevel::Low,
            explanation: "SLM disabled".to_string(),
            confidence: 0.0,
            tokens_used: 0,
            latency_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_service_returns_low() {
        let svc = SlmService::disabled(SlmConfig::default());
        assert!(!svc.is_enabled());
        assert!(!svc.is_available());
        let resp = svc.analyze_event("test").await.unwrap();
        assert_eq!(resp.risk_level, RiskLevel::Low);
        assert_eq!(resp.latency_ms, 0);
    }

    #[tokio::test]
    async fn disabled_stats_is_none() {
        let svc = SlmService::disabled(SlmConfig::default());
        assert!(svc.stats().is_none());
    }

    #[tokio::test]
    async fn enabled_service_with_mock() {
        let backend = Box::new(MockSlmBackend::default());
        let config = SlmConfig::default();
        let engine = Arc::new(SlmEngine::new(backend, config.clone()));
        let svc = SlmService::with_engine(engine, config);
        assert!(svc.is_enabled());
        assert!(svc.is_available());

        let resp = svc.analyze_event("test prompt").await.unwrap();
        assert_eq!(resp.risk_level, RiskLevel::Low);
        assert!(resp.confidence > 0.0);

        let stats = svc.stats().unwrap();
        assert_eq!(stats.total_inferences, 1);
    }

    #[test]
    fn new_with_missing_model_path_is_disabled() {
        let config = SlmConfig {
            model_path: "/nonexistent/model.gguf".into(),
            ..Default::default()
        };
        let svc = SlmService::new(config, true);
        assert!(!svc.is_enabled());
    }

    #[test]
    fn new_with_enabled_false_is_disabled() {
        let svc = SlmService::new(SlmConfig::default(), false);
        assert!(!svc.is_enabled());
    }

    #[tokio::test]
    async fn analyze_scan_finding_disabled_returns_low() {
        let svc = SlmService::disabled(SlmConfig::default());
        let resp = svc
            .analyze_scan_finding("exposed_secret", "HIGH", "API key in source", "/src/config.rs")
            .await
            .unwrap();
        assert_eq!(resp.risk_level, RiskLevel::Low);
        assert_eq!(resp.explanation, "SLM disabled");
    }

    #[tokio::test]
    async fn assess_server_config_disabled_returns_low() {
        let svc = SlmService::disabled(SlmConfig::default());
        let resp = svc
            .assess_server_config("test-server", "node", &["server.js".into()], &[])
            .await
            .unwrap();
        assert_eq!(resp.risk_level, RiskLevel::Low);
        assert_eq!(resp.explanation, "SLM disabled");
    }

    #[tokio::test]
    async fn analyze_scan_finding_with_mock() {
        let backend = Box::new(MockSlmBackend::default());
        let config = SlmConfig::default();
        let engine = Arc::new(SlmEngine::new(backend, config.clone()));
        let svc = SlmService::with_engine(engine, config);

        let resp = svc
            .analyze_scan_finding("weak_permission", "MEDIUM", "World-readable config", "/etc/app.conf")
            .await
            .unwrap();
        assert_eq!(resp.risk_level, RiskLevel::Low); // Mock always returns Low
        assert!(resp.confidence > 0.0);
    }

    #[tokio::test]
    async fn assess_server_config_with_mock() {
        let backend = Box::new(MockSlmBackend::default());
        let config = SlmConfig::default();
        let engine = Arc::new(SlmEngine::new(backend, config.clone()));
        let svc = SlmService::with_engine(engine, config);

        let resp = svc
            .assess_server_config(
                "filesystem-server",
                "node",
                &["index.js".into()],
                &["HOME=/root".into()],
            )
            .await
            .unwrap();
        assert_eq!(resp.risk_level, RiskLevel::Low); // Mock always returns Low
    }

    #[test]
    fn status_display_disabled() {
        let svc = SlmService::disabled(SlmConfig::default());
        let status = svc.status_display();
        assert!(status.contains("No model loaded"));
    }

    #[test]
    fn status_display_enabled() {
        let backend = Box::new(MockSlmBackend::default());
        let config = SlmConfig::default();
        let engine = Arc::new(SlmEngine::new(backend, config.clone()));
        let svc = SlmService::with_engine(engine, config);
        let status = svc.status_display();
        assert!(status.contains("Model loaded"));
        assert!(status.contains("mock-model-q4"));
    }
}
