//! SLM inference engine: loads and runs a quantized small language model locally.
//!
//! Uses a trait-based design so a real llama-cpp backend can be swapped in behind a
//! feature flag while tests and CI use the mock implementation.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tracing::warn;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the SLM engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmConfig {
    /// Path to the GGUF model file.
    pub model_path: PathBuf,
    /// Context window size in tokens.
    #[serde(default = "default_context_size")]
    pub context_size: u32,
    /// Maximum number of tokens to generate per inference.
    #[serde(default = "default_max_output_tokens")]
    pub max_output_tokens: u32,
    /// Sampling temperature (lower = more deterministic).
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    /// Number of CPU threads for inference.
    #[serde(default = "default_threads")]
    pub threads: u32,
    /// Whether to use GPU acceleration (Metal on macOS).
    #[serde(default = "default_use_gpu")]
    pub use_gpu: bool,
    /// Batch size for prompt evaluation.
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
}

fn default_context_size() -> u32 {
    1024
}
fn default_max_output_tokens() -> u32 {
    256
}
fn default_temperature() -> f32 {
    0.1
}
fn default_threads() -> u32 {
    (num_cpus::get() / 2).max(1) as u32
}
fn default_use_gpu() -> bool {
    true
}
fn default_batch_size() -> u32 {
    512
}

impl Default for SlmConfig {
    fn default() -> Self {
        Self {
            model_path: PathBuf::new(),
            context_size: default_context_size(),
            max_output_tokens: default_max_output_tokens(),
            temperature: default_temperature(),
            threads: default_threads(),
            use_gpu: default_use_gpu(),
            batch_size: default_batch_size(),
        }
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Risk level assessed by the SLM for a given event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Response from an SLM inference call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmResponse {
    /// Assessed risk level.
    pub risk_level: RiskLevel,
    /// Human-readable explanation of the risk assessment.
    pub explanation: String,
    /// Model's confidence in the assessment (0.0 to 1.0).
    pub confidence: f32,
    /// Number of tokens consumed (prompt + completion).
    pub tokens_used: u32,
    /// Wall-clock latency of this inference in milliseconds.
    pub latency_ms: u64,
}

/// Runtime statistics for the SLM engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmStats {
    pub total_inferences: u64,
    pub total_tokens_generated: u64,
    pub avg_latency_ms: f64,
    pub last_inference_ms: u64,
    pub model_name: String,
    pub model_size_bytes: u64,
    pub using_gpu: bool,
}

// ---------------------------------------------------------------------------
// Backend trait
// ---------------------------------------------------------------------------

/// Trait abstracting over the raw model backend (real llama-cpp or mock).
///
/// Uses manual desugaring of async fn to avoid requiring the `async-trait` crate.
pub trait SlmBackend: Send + Sync {
    /// Run inference on the given prompt and return the raw text output.
    fn infer<'a>(
        &'a self,
        prompt: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>;

    /// Name of the loaded model.
    fn model_name(&self) -> &str;

    /// Size of the model file in bytes.
    fn model_size_bytes(&self) -> u64;

    /// Whether GPU acceleration is active.
    fn using_gpu(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The core SLM inference engine. Wraps a backend with concurrency control and stats.
pub struct SlmEngine {
    backend: Box<dyn SlmBackend>,
    config: SlmConfig,
    /// Semaphore(1) serializes inference calls -- only one runs at a time.
    semaphore: Semaphore,
    /// Bounded queue: at most `MAX_QUEUED` pending requests beyond the active one.
    queue_semaphore: Semaphore,
    // Stats counters (lock-free).
    total_inferences: AtomicU64,
    total_tokens: AtomicU64,
    total_latency_ms: AtomicU64,
    last_latency_ms: AtomicU64,
}

const MAX_QUEUED: usize = 10;
const SLOW_INFERENCE_MS: u64 = 2000;

impl SlmEngine {
    /// Create a new engine wrapping the given backend.
    pub fn new(backend: Box<dyn SlmBackend>, config: SlmConfig) -> Self {
        Self {
            backend,
            config,
            semaphore: Semaphore::new(1),
            queue_semaphore: Semaphore::new(MAX_QUEUED),
            total_inferences: AtomicU64::new(0),
            total_tokens: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            last_latency_ms: AtomicU64::new(0),
        }
    }

    /// Run inference, respecting concurrency limits.
    ///
    /// - At most 1 inference runs at a time (semaphore).
    /// - At most `MAX_QUEUED` requests wait in the queue; excess are dropped with a
    ///   default low-risk response.
    /// - If inference takes longer than 2 s a warning is logged but the result is
    ///   returned anyway.
    pub async fn infer(&self, prompt: &str) -> Result<SlmResponse> {
        // Try to enter the bounded queue.
        let queue_permit = match self.queue_semaphore.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("SLM inference queue full ({MAX_QUEUED}), dropping request");
                return Ok(SlmResponse {
                    risk_level: RiskLevel::Low,
                    explanation: "Inference skipped: queue full".to_string(),
                    confidence: 0.0,
                    tokens_used: 0,
                    latency_ms: 0,
                });
            }
        };

        // Wait for the single inference slot.
        let _infer_permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("inference semaphore closed"))?;
        // Release queue spot now that we hold the inference slot.
        drop(queue_permit);

        let start = Instant::now();
        let raw_output = self
            .backend
            .infer(prompt)
            .await
            .context("SLM backend inference failed")?;
        let latency_ms = start.elapsed().as_millis() as u64;

        if latency_ms > SLOW_INFERENCE_MS {
            warn!(
                latency_ms,
                "SLM inference exceeded {SLOW_INFERENCE_MS}ms threshold"
            );
        }

        let response = parse_slm_output(&raw_output, latency_ms);

        // Update stats (relaxed ordering is fine for counters).
        self.total_inferences.fetch_add(1, Ordering::Relaxed);
        self.total_tokens
            .fetch_add(response.tokens_used as u64, Ordering::Relaxed);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
        self.last_latency_ms.store(latency_ms, Ordering::Relaxed);

        Ok(response)
    }

    /// Return current engine statistics.
    pub fn stats(&self) -> SlmStats {
        let total = self.total_inferences.load(Ordering::Relaxed);
        let total_lat = self.total_latency_ms.load(Ordering::Relaxed);
        let avg = if total > 0 {
            total_lat as f64 / total as f64
        } else {
            0.0
        };
        SlmStats {
            total_inferences: total,
            total_tokens_generated: self.total_tokens.load(Ordering::Relaxed),
            avg_latency_ms: avg,
            last_inference_ms: self.last_latency_ms.load(Ordering::Relaxed),
            model_name: self.backend.model_name().to_string(),
            model_size_bytes: self.backend.model_size_bytes(),
            using_gpu: self.backend.using_gpu(),
        }
    }

    /// Access the engine config.
    pub fn config(&self) -> &SlmConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Output parser
// ---------------------------------------------------------------------------

/// Parse raw model output text into a structured `SlmResponse`.
///
/// Expected format from the prompt template:
/// ```text
/// RISK: <low|medium|high|critical>
/// CONFIDENCE: <0.0-1.0>
/// EXPLANATION: <text>
/// ```
///
/// Falls back to Low risk if parsing fails.
pub fn parse_slm_output(raw: &str, latency_ms: u64) -> SlmResponse {
    let mut risk_level = RiskLevel::Low;
    let mut confidence: f32 = 0.5;
    let mut explanation = String::new();
    let tokens_approx = (raw.len() / 4).max(1) as u32;

    for line in raw.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("RISK:") {
            risk_level = match rest.trim().to_lowercase().as_str() {
                "low" => RiskLevel::Low,
                "medium" => RiskLevel::Medium,
                "high" => RiskLevel::High,
                "critical" => RiskLevel::Critical,
                _ => RiskLevel::Low,
            };
        } else if let Some(rest) = line.strip_prefix("CONFIDENCE:") {
            confidence = rest.trim().parse().unwrap_or(0.5);
        } else if let Some(rest) = line.strip_prefix("EXPLANATION:") {
            explanation = rest.trim().to_string();
        }
    }

    if explanation.is_empty() {
        explanation = raw.trim().to_string();
    }

    SlmResponse {
        risk_level,
        explanation,
        confidence,
        tokens_used: tokens_approx,
        latency_ms,
    }
}

// ---------------------------------------------------------------------------
// Mock backend for testing
// ---------------------------------------------------------------------------

/// A mock SLM backend that returns configurable responses without loading a real model.
pub struct MockSlmBackend {
    pub model_name: String,
    pub model_size: u64,
    pub gpu: bool,
    pub response_text: String,
    pub latency: std::time::Duration,
}

impl Default for MockSlmBackend {
    fn default() -> Self {
        Self {
            model_name: "mock-model-q4".to_string(),
            model_size: 1_000_000,
            gpu: false,
            response_text:
                "RISK: low\nCONFIDENCE: 0.9\nEXPLANATION: This operation appears safe."
                    .to_string(),
            latency: std::time::Duration::from_millis(5),
        }
    }
}

impl SlmBackend for MockSlmBackend {
    fn infer<'a>(
        &'a self,
        _prompt: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
        let latency = self.latency;
        let text = self.response_text.clone();
        Box::pin(async move {
            if !latency.is_zero() {
                tokio::time::sleep(latency).await;
            }
            Ok(text)
        })
    }

    fn model_name(&self) -> &str {
        &self.model_name
    }

    fn model_size_bytes(&self) -> u64 {
        self.model_size
    }

    fn using_gpu(&self) -> bool {
        self.gpu
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_engine() -> SlmEngine {
        let backend = MockSlmBackend::default();
        SlmEngine::new(Box::new(backend), SlmConfig::default())
    }

    fn mock_engine_with_response(text: &str) -> SlmEngine {
        let backend = MockSlmBackend {
            response_text: text.to_string(),
            ..Default::default()
        };
        SlmEngine::new(Box::new(backend), SlmConfig::default())
    }

    // -- parse_slm_output tests --

    #[test]
    fn parse_valid_output() {
        let raw = "RISK: high\nCONFIDENCE: 0.85\nEXPLANATION: Attempting to read SSH keys";
        let resp = parse_slm_output(raw, 42);
        assert_eq!(resp.risk_level, RiskLevel::High);
        assert!((resp.confidence - 0.85).abs() < 0.01);
        assert_eq!(resp.explanation, "Attempting to read SSH keys");
        assert_eq!(resp.latency_ms, 42);
    }

    #[test]
    fn parse_critical_output() {
        let raw = "RISK: critical\nCONFIDENCE: 0.95\nEXPLANATION: Data exfiltration detected";
        let resp = parse_slm_output(raw, 100);
        assert_eq!(resp.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn parse_unknown_risk_defaults_low() {
        let raw = "RISK: banana\nCONFIDENCE: 0.5\nEXPLANATION: weird";
        let resp = parse_slm_output(raw, 0);
        assert_eq!(resp.risk_level, RiskLevel::Low);
    }

    #[test]
    fn parse_empty_output_defaults() {
        let resp = parse_slm_output("", 0);
        assert_eq!(resp.risk_level, RiskLevel::Low);
        assert!((resp.confidence - 0.5).abs() < 0.01);
    }

    #[test]
    fn risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::Low), "LOW");
        assert_eq!(format!("{}", RiskLevel::Critical), "CRITICAL");
    }

    #[test]
    fn default_config_values() {
        let cfg = SlmConfig::default();
        assert_eq!(cfg.context_size, 1024);
        assert_eq!(cfg.max_output_tokens, 256);
        assert!((cfg.temperature - 0.1).abs() < 0.01);
        assert!(cfg.use_gpu);
        assert_eq!(cfg.batch_size, 512);
        assert!(cfg.threads >= 1);
    }

    #[test]
    fn stats_initial() {
        let engine = mock_engine();
        let stats = engine.stats();
        assert_eq!(stats.total_inferences, 0);
        assert_eq!(stats.total_tokens_generated, 0);
        assert!((stats.avg_latency_ms).abs() < 0.01);
        assert_eq!(stats.model_name, "mock-model-q4");
    }

    // -- async engine tests --

    #[tokio::test]
    async fn infer_returns_parsed_response() {
        let engine = mock_engine();
        let resp = engine.infer("test prompt").await.unwrap();
        assert_eq!(resp.risk_level, RiskLevel::Low);
        assert!((resp.confidence - 0.9).abs() < 0.01);
        assert!(!resp.explanation.is_empty());
    }

    #[tokio::test]
    async fn infer_updates_stats() {
        let engine = mock_engine();
        engine.infer("prompt 1").await.unwrap();
        engine.infer("prompt 2").await.unwrap();
        let stats = engine.stats();
        assert_eq!(stats.total_inferences, 2);
        assert!(stats.total_tokens_generated > 0);
    }

    #[tokio::test]
    async fn infer_high_risk() {
        let engine = mock_engine_with_response(
            "RISK: high\nCONFIDENCE: 0.88\nEXPLANATION: Suspicious file access",
        );
        let resp = engine.infer("analyze this").await.unwrap();
        assert_eq!(resp.risk_level, RiskLevel::High);
    }

    #[tokio::test]
    async fn serialization_roundtrip() {
        let resp = SlmResponse {
            risk_level: RiskLevel::Medium,
            explanation: "test".to_string(),
            confidence: 0.7,
            tokens_used: 42,
            latency_ms: 100,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: SlmResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.risk_level, RiskLevel::Medium);
        assert_eq!(parsed.tokens_used, 42);
    }

    #[tokio::test]
    async fn queue_full_returns_default() {
        // Create engine with a backend that sleeps long enough to fill the queue.
        let backend = MockSlmBackend {
            latency: std::time::Duration::from_secs(10),
            ..Default::default()
        };
        let engine = std::sync::Arc::new(SlmEngine::new(
            Box::new(backend),
            SlmConfig::default(),
        ));

        // Spawn 1 (running) + MAX_QUEUED (waiting) tasks to fill capacity.
        let mut handles = Vec::new();
        for _ in 0..=MAX_QUEUED {
            let eng = engine.clone();
            handles.push(tokio::spawn(async move {
                eng.infer("fill").await
            }));
        }

        // Give tasks time to acquire permits.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // This request should be dropped.
        let resp = engine.infer("overflow").await.unwrap();
        assert_eq!(resp.risk_level, RiskLevel::Low);
        assert_eq!(resp.confidence, 0.0);
        assert!(resp.explanation.contains("queue full"));

        // Clean up (abort the long-running tasks).
        for h in handles {
            h.abort();
        }
    }
}
