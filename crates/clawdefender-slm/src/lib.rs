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
pub mod backend_manager;
pub mod clustering;
#[cfg(feature = "cloud")]
pub mod cloud_backend;
pub mod config_migration;
pub mod context;
pub mod context_window;
#[cfg(feature = "download")]
pub mod downloader;
pub mod engine;
#[cfg(feature = "gguf")]
pub mod gguf_backend;
pub mod model_manager;
pub mod model_registry;
pub mod noise_filter;
pub mod offline_intel;
pub mod output_validator;
pub mod pipeline;
pub mod profiles;
pub mod sanitizer;
pub mod task_router;
pub mod triage;

use std::sync::Arc;

use anyhow::Result;
use tracing::{info, warn};

#[cfg(any(not(feature = "gguf"), test))]
use crate::engine::MockSlmBackend;
use crate::engine::{HeuristicSlmBackend, RiskLevel, SlmBackend, SlmConfig, SlmEngine, SlmResponse, SlmStats};

pub use backend_manager::{
    AiBackendManager, AiRequest, AiResponse, AiStatus, BackendStatus, LocalModelInfo, TaskType,
};
pub use task_router::{
    AiFeature, FeatureBackendPreference, FeatureRoutingConfig, RateLimitStatus, RoutingDecision,
    RoutingPreferences, TaskRouter,
};

/// Top-level service that owns the SLM engine and exposes a simple API
/// for the rest of RookBot.
///
/// Supports an automatic fallback chain: if the primary engine fails,
/// the service tries the fallback engine before giving up.
/// Typical chain: GGUF (local) -> Cloud API -> Mock (analysis unavailable).
pub struct SlmService {
    engine: Option<Arc<SlmEngine>>,
    /// Fallback engine used when the primary engine's inference fails.
    fallback_engine: Option<Arc<SlmEngine>>,
    config: SlmConfig,
    enabled: bool,
    mock_mode: bool,
}

impl std::fmt::Debug for SlmService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlmService")
            .field("enabled", &self.enabled)
            .field("mock_mode", &self.mock_mode)
            .field("has_engine", &self.engine.is_some())
            .field("has_fallback", &self.fallback_engine.is_some())
            .finish()
    }
}

impl SlmService {
    /// Create a new enabled service backed by the given engine.
    pub fn with_engine(engine: Arc<SlmEngine>, config: SlmConfig) -> Self {
        Self {
            engine: Some(engine),
            fallback_engine: None,
            config,
            enabled: true,
            mock_mode: false,
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
                "SLM model file not found, using heuristic analyzer (no download required)"
            );
            let backend: Box<dyn SlmBackend> = Box::new(HeuristicSlmBackend::new());
            let engine = Arc::new(SlmEngine::new(backend, config.clone()));
            return Self {
                engine: Some(engine),
                fallback_engine: None,
                config,
                enabled: true,
                mock_mode: false,
            };
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
                        fallback_engine: None,
                        config,
                        enabled: true,
                        mock_mode: false,
                    };
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %config.model_path.display(),
                        "Failed to load GGUF model, falling back to heuristic analyzer"
                    );
                    let backend: Box<dyn SlmBackend> = Box::new(HeuristicSlmBackend::new());
                    let engine = Arc::new(SlmEngine::new(backend, config.clone()));
                    return Self {
                        engine: Some(engine),
                        fallback_engine: None,
                        config,
                        enabled: true,
                        mock_mode: false,
                    };
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
                fallback_engine: None,
                config,
                enabled: true,
                mock_mode: true,
            }
        }
    }

    /// Create a disabled (no-op) service.
    pub fn disabled(config: SlmConfig) -> Self {
        Self {
            engine: None,
            fallback_engine: None,
            config,
            enabled: false,
            mock_mode: false,
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

    /// Returns true if the service is using the mock backend instead of a real model.
    pub fn is_mock_mode(&self) -> bool {
        self.mock_mode
    }

    /// Explicitly set mock mode (e.g. for cloud API models that use MockSlmBackend).
    pub fn set_mock_mode(&mut self, mock: bool) {
        self.mock_mode = mock;
    }

    /// Add a fallback engine to this service.
    ///
    /// When the primary engine fails, the fallback is tried before returning
    /// an error. This enables automatic fallback chains like:
    /// GGUF (local) -> Cloud API -> Mock (analysis unavailable).
    pub fn with_fallback(mut self, fallback: Arc<SlmEngine>) -> Self {
        // If we have a fallback but no primary, promote fallback to primary.
        if self.engine.is_none() {
            self.engine = Some(Arc::clone(&fallback));
            self.enabled = true;
        } else {
            self.fallback_engine = Some(fallback);
        }
        self
    }

    /// Analyze an event by running SLM inference.
    ///
    /// Uses the fallback chain: primary engine first, then fallback engine.
    /// Returns `RiskLevel::Low` immediately if the service is disabled.
    pub async fn analyze_event(&self, prompt: &str) -> Result<SlmResponse> {
        if let Some(ref engine) = self.engine {
            match engine.infer(prompt).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    // Primary failed -- try fallback if available.
                    if let Some(ref fallback) = self.fallback_engine {
                        warn!(
                            error = %e,
                            primary = engine.stats().model_name,
                            fallback = fallback.stats().model_name,
                            "Primary SLM inference failed, falling back"
                        );
                        match fallback.infer(prompt).await {
                            Ok(resp) => return Ok(resp),
                            Err(fallback_err) => {
                                warn!(
                                    error = %fallback_err,
                                    "Fallback SLM inference also failed"
                                );
                                return Ok(Self::unavailable_response());
                            }
                        }
                    }
                    // No fallback available -- return unavailable.
                    warn!(error = %e, "SLM inference failed with no fallback");
                    return Ok(Self::unavailable_response());
                }
            }
        }
        Ok(Self::disabled_response())
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
            "No model loaded - place a GGUF model in ~/.local/share/rookbot/models/"
                .to_string()
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

    /// Response when all backends in the fallback chain have failed.
    /// Fail-closed to HIGH risk since we cannot analyze the event.
    fn unavailable_response() -> SlmResponse {
        SlmResponse {
            risk_level: RiskLevel::High,
            explanation: "Analysis unavailable: all SLM backends failed (fail-closed to HIGH)"
                .to_string(),
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

        let stats = svc.stats().unwrap();
        assert_eq!(stats.total_inferences, 1);
    }

    #[test]
    fn new_with_missing_model_path_uses_heuristic() {
        let config = SlmConfig {
            model_path: "/nonexistent/model.gguf".into(),
            ..Default::default()
        };
        let svc = SlmService::new(config, true);
        // Now uses heuristic analyzer instead of disabled mode
        assert!(svc.is_enabled());
        let stats = svc.stats().unwrap();
        assert_eq!(stats.model_name, "heuristic-analyzer");
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
            .analyze_scan_finding(
                "weak_permission",
                "MEDIUM",
                "World-readable config",
                "/etc/app.conf",
            )
            .await
            .unwrap();
        assert_eq!(resp.risk_level, RiskLevel::Low); // Mock always returns Low
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

    // -- Fallback chain tests --

    /// A backend that always fails, used to test fallback behavior.
    struct FailingBackend;

    impl SlmBackend for FailingBackend {
        fn infer<'a>(
            &'a self,
            _prompt: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>>
        {
            Box::pin(async { Err(anyhow::anyhow!("simulated backend failure")) })
        }
        fn model_name(&self) -> &str {
            "failing-backend"
        }
        fn model_size_bytes(&self) -> u64 {
            0
        }
        fn using_gpu(&self) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn fallback_chain_uses_fallback_on_primary_failure() {
        let primary = Box::new(FailingBackend);
        let primary_engine = Arc::new(SlmEngine::new(primary, SlmConfig::default()));

        let fallback = Box::new(MockSlmBackend::default());
        let fallback_engine = Arc::new(SlmEngine::new(fallback, SlmConfig::default()));

        let svc = SlmService::with_engine(primary_engine, SlmConfig::default())
            .with_fallback(fallback_engine);

        let resp = svc.analyze_event("test").await.unwrap();
        // Should get the mock response from fallback, not an error
        assert_eq!(resp.risk_level, RiskLevel::Low);
        assert!(resp.explanation.contains("safe") || resp.explanation.contains("MOCK"));
    }

    #[tokio::test]
    async fn fallback_chain_returns_unavailable_when_both_fail() {
        let primary = Box::new(FailingBackend);
        let primary_engine = Arc::new(SlmEngine::new(primary, SlmConfig::default()));

        let fallback = Box::new(FailingBackend);
        let fallback_engine = Arc::new(SlmEngine::new(fallback, SlmConfig::default()));

        let svc = SlmService::with_engine(primary_engine, SlmConfig::default())
            .with_fallback(fallback_engine);

        let resp = svc.analyze_event("test").await.unwrap();
        // Fail-closed to HIGH when all backends fail
        assert_eq!(resp.risk_level, RiskLevel::High);
        assert!(resp.explanation.contains("unavailable"));
    }

    #[tokio::test]
    async fn fallback_chain_uses_primary_when_it_succeeds() {
        let primary = Box::new(MockSlmBackend {
            response_text:
                "RISK: MEDIUM\nCONFIDENCE: 0.7\nEXPLANATION: Primary analysis".to_string(),
            ..Default::default()
        });
        let primary_engine = Arc::new(SlmEngine::new(primary, SlmConfig::default()));

        let fallback = Box::new(MockSlmBackend::default());
        let fallback_engine = Arc::new(SlmEngine::new(fallback, SlmConfig::default()));

        let svc = SlmService::with_engine(primary_engine, SlmConfig::default())
            .with_fallback(fallback_engine);

        let resp = svc.analyze_event("test").await.unwrap();
        // Should use primary result
        assert_eq!(resp.risk_level, RiskLevel::Medium);
        assert!(resp.explanation.contains("Primary analysis"));
    }

    #[test]
    fn with_fallback_promotes_when_no_primary() {
        let fallback = Box::new(MockSlmBackend::default());
        let fallback_engine = Arc::new(SlmEngine::new(fallback, SlmConfig::default()));

        let svc = SlmService::disabled(SlmConfig::default()).with_fallback(fallback_engine);

        // Should be enabled now since fallback was promoted
        assert!(svc.is_enabled());
    }

    #[test]
    fn unavailable_response_is_fail_closed() {
        let resp = SlmService::unavailable_response();
        assert_eq!(resp.risk_level, RiskLevel::High);
        assert!(resp.explanation.contains("fail-closed"));
    }
}
