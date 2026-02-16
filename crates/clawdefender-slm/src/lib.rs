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

pub mod analyzer;
pub mod context;
pub mod engine;
pub mod model_manager;
pub mod noise_filter;
pub mod output_validator;
pub mod profiles;
pub mod sanitizer;

use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use crate::engine::{
    MockSlmBackend, RiskLevel, SlmBackend, SlmConfig, SlmEngine, SlmResponse, SlmStats,
};

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

        // In a real build with llama-cpp, we would load the model here.
        // For now, use the mock backend so the service is functional for testing.
        info!(
            path = %config.model_path.display(),
            "SLM model path exists -- using mock backend (real llama-cpp TBD)"
        );
        let backend: Box<dyn SlmBackend> = Box::new(MockSlmBackend::default());
        let engine = Arc::new(SlmEngine::new(backend, config.clone()));

        Self {
            engine: Some(engine),
            config,
            enabled: true,
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

    /// Analyze an event by running SLM inference.
    ///
    /// Returns `RiskLevel::Low` immediately if the service is disabled.
    pub async fn analyze_event(&self, prompt: &str) -> Result<SlmResponse> {
        if let Some(ref engine) = self.engine {
            engine.infer(prompt).await
        } else {
            Ok(SlmResponse {
                risk_level: RiskLevel::Low,
                explanation: "SLM disabled".to_string(),
                confidence: 0.0,
                tokens_used: 0,
                latency_ms: 0,
            })
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_service_returns_low() {
        let svc = SlmService::disabled(SlmConfig::default());
        assert!(!svc.is_enabled());
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
}
