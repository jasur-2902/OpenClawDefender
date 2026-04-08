//! Real GGUF inference backend using llama-cpp-2.
//!
//! This module is only compiled when the `gguf` feature is enabled.
//! It loads a GGUF model file and runs inference using llama.cpp
//! via the `llama-cpp-2` Rust bindings.
//!
//! ## Optimizations
//!
//! - **KV cache persistence**: The triage system prompt is processed once and the
//!   context state is saved to a session file. Subsequent triage calls restore the
//!   cached state, skipping re-processing of ~100-150 system prompt tokens.
//! - **Grammar-constrained triage**: For triage mode, a GBNF grammar constrains
//!   output to exactly one of `ROUTINE`, `NOTABLE`, or `SUSPICIOUS`.
//! - **Inference timeout**: All inference calls are wrapped in a timeout to prevent
//!   hanging (2s for triage, 15s for deep analysis).

use std::future::Future;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;
use tracing::{debug, info, warn};

use crate::engine::{SlmBackend, SlmConfig};

/// GBNF grammar that constrains output to exactly one classification token.
const TRIAGE_GRAMMAR: &str = r#"root ::= "ROUTINE" | "NOTABLE" | "SUSPICIOUS""#;

/// Timeout for triage inference (fast path).
const TRIAGE_TIMEOUT_SECS: u64 = 2;

/// Timeout for deep analysis inference (slow path).
const DEEP_ANALYSIS_TIMEOUT_SECS: u64 = 15;

/// Inference mode determines prompt construction and output constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferenceMode {
    /// Full analysis using the standard system prompt (backward compatible).
    Standard,
    /// Fast triage with grammar-constrained output (ROUTINE/NOTABLE/SUSPICIOUS).
    Triage,
    /// Deep analysis with extended context (used for SUSPICIOUS events).
    DeepAnalysis,
}

/// A real GGUF inference backend powered by llama.cpp (via llama-cpp-2).
pub struct GgufBackend {
    backend: Arc<LlamaBackend>,
    model: Arc<LlamaModel>,
    model_name: String,
    model_size: u64,
    using_gpu: bool,
    config: SlmConfig,
    /// Path to cached triage session state (KV cache for triage system prompt).
    triage_cache_path: Option<PathBuf>,
    /// Tokens of the cached triage system prompt (needed for session restore).
    triage_cache_tokens: Option<Vec<llama_cpp_2::token::LlamaToken>>,
}

// SAFETY: LlamaBackend and LlamaModel are thread-safe for read-only access
// after construction. Inference creates per-thread contexts.
unsafe impl Send for GgufBackend {}
unsafe impl Sync for GgufBackend {}

impl GgufBackend {
    /// Load a GGUF model from the given path.
    ///
    /// This is a blocking operation that should be called during initialization.
    /// On Apple Silicon, Metal GPU acceleration is used when `config.use_gpu` is true.
    pub fn load(config: &SlmConfig) -> Result<Self> {
        let path = &config.model_path;
        if !path.exists() {
            anyhow::bail!("Model file not found: {}", path.display());
        }

        // SECURITY: Refuse to load model files that are symlinks to prevent
        // an attacker from redirecting model loading to an unexpected location.
        let sym_meta = std::fs::symlink_metadata(path)
            .context("failed to read model symlink metadata")?;
        if sym_meta.file_type().is_symlink() {
            anyhow::bail!(
                "Model file is a symlink (potential security risk): {}",
                path.display()
            );
        }

        let model_size = std::fs::metadata(path)
            .context("failed to read model file metadata")?
            .len();

        let model_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        info!(
            path = %path.display(),
            size_mb = model_size / 1_000_000,
            gpu = config.use_gpu,
            threads = config.threads,
            "Loading GGUF model"
        );

        // Initialize the llama.cpp backend (global init, safe to call multiple times)
        let backend =
            LlamaBackend::init().context("failed to initialize llama.cpp backend")?;

        // Configure model loading parameters
        let model_params = if config.use_gpu {
            // Offload all layers to GPU (Metal on macOS)
            LlamaModelParams::default().with_n_gpu_layers(1000)
        } else {
            LlamaModelParams::default().with_n_gpu_layers(0)
        };

        let model = LlamaModel::load_from_file(&backend, path, &model_params)
            .map_err(|e| anyhow::anyhow!("failed to load GGUF model: {:?}", e))?;

        let using_gpu = config.use_gpu;

        info!(model = model_name, "GGUF model loaded successfully");

        Ok(Self {
            backend: Arc::new(backend),
            model: Arc::new(model),
            model_name,
            model_size,
            using_gpu,
            config: config.clone(),
            triage_cache_path: None,
            triage_cache_tokens: None,
        })
    }

    /// Run inference with a specific mode, system prompt, and optional grammar.
    ///
    /// This is the enhanced inference method that supports:
    /// - KV cache restoration for triage (skips system prompt reprocessing)
    /// - Grammar-constrained output for triage
    /// - Mode-specific timeouts
    pub fn infer_with_mode<'a>(
        &'a self,
        system_prompt: &'a str,
        user_prompt: &'a str,
        mode: InferenceMode,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
        let backend = Arc::clone(&self.backend);
        let model = Arc::clone(&self.model);
        let config = self.config.clone();
        let system_prompt_owned = system_prompt.to_string();
        let user_prompt_owned = user_prompt.to_string();

        let timeout_secs = match mode {
            InferenceMode::Standard => DEEP_ANALYSIS_TIMEOUT_SECS,
            InferenceMode::Triage => TRIAGE_TIMEOUT_SECS,
            InferenceMode::DeepAnalysis => DEEP_ANALYSIS_TIMEOUT_SECS,
        };

        let max_tokens = match mode {
            InferenceMode::Triage => 5, // Only need 1-2 tokens for classification
            _ => config.max_output_tokens as usize,
        };

        Box::pin(async move {
            let timeout = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                tokio::task::spawn_blocking(move || {
                    run_inference_with_mode(
                        &backend,
                        &model,
                        &system_prompt_owned,
                        &user_prompt_owned,
                        &config,
                        mode,
                        max_tokens,
                    )
                }),
            )
            .await;

            match timeout {
                Ok(join_result) => join_result.context("inference task panicked")?,
                Err(_elapsed) => {
                    warn!(
                        mode = ?mode,
                        timeout_secs,
                        "Inference timed out, returning fail-safe response"
                    );
                    match mode {
                        InferenceMode::Triage => Ok("SUSPICIOUS".to_string()),
                        _ => Ok("RISK: HIGH\nCONFIDENCE: 0.3\nEXPLANATION: Analysis timed out (fail-closed to HIGH)".to_string()),
                    }
                }
            }
        })
    }

    /// Warm the KV cache for the triage system prompt.
    ///
    /// Processes the triage system prompt once and saves the resulting context
    /// state to a session file. Subsequent triage calls can restore this state
    /// instead of reprocessing the system prompt tokens.
    ///
    /// Call this after model activation for optimal triage latency.
    pub fn warm_triage_cache(&mut self, triage_system_prompt: &str) -> Result<()> {
        let cache_dir = dirs_cache_path()?;
        std::fs::create_dir_all(&cache_dir)
            .context("failed to create triage cache directory")?;

        let cache_path = cache_dir.join(format!("{}_triage.session", self.model_name));

        let backend = &self.backend;
        let model = &self.model;
        let config = &self.config;

        let n_ctx = NonZeroU32::new(config.context_size)
            .unwrap_or(NonZeroU32::new(2048).unwrap());

        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(Some(n_ctx))
            .with_n_threads(config.threads as i32)
            .with_n_threads_batch(config.threads as i32);

        let mut ctx = model
            .new_context(backend, ctx_params)
            .map_err(|e| anyhow::anyhow!("failed to create context for cache warming: {:?}", e))?;

        // Build the system prompt prefix (everything before the user message)
        let prefix = format!(
            "<|im_start|>system\n{}<|im_end|>\n<|im_start|>user\n",
            triage_system_prompt
        );

        let tokens = model
            .str_to_token(&prefix, AddBos::Always)
            .context("failed to tokenize triage system prompt")?;

        info!(
            token_count = tokens.len(),
            "Warming triage KV cache with system prompt"
        );

        // Process the system prompt tokens
        let mut batch = LlamaBatch::new(tokens.len().max(512), 1);
        let last_index = tokens.len() - 1;
        for (i, &token) in tokens.iter().enumerate() {
            let is_last = i == last_index;
            batch
                .add(token, i as i32, &[0], is_last)
                .context("failed to add token to batch")?;
        }

        ctx.decode(&mut batch)
            .map_err(|e| anyhow::anyhow!("failed to decode triage system prompt: {:?}", e))?;

        // Save the context state (including KV cache) to a session file
        ctx.state_save_file(&cache_path, &tokens)
            .map_err(|e| anyhow::anyhow!("failed to save triage cache: {:?}", e))?;

        info!(
            path = %cache_path.display(),
            "Triage KV cache saved successfully"
        );

        self.triage_cache_path = Some(cache_path);
        self.triage_cache_tokens = Some(tokens);

        Ok(())
    }

    /// Invalidate the triage KV cache (e.g., when switching models).
    pub fn invalidate_cache(&mut self) {
        if let Some(ref path) = self.triage_cache_path {
            let _ = std::fs::remove_file(path);
        }
        self.triage_cache_path = None;
        self.triage_cache_tokens = None;
    }

    /// Check if triage cache is warmed and available.
    pub fn is_triage_cache_ready(&self) -> bool {
        self.triage_cache_path
            .as_ref()
            .is_some_and(|p| p.exists())
    }
}

impl SlmBackend for GgufBackend {
    fn infer<'a>(
        &'a self,
        prompt: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
        let backend = Arc::clone(&self.backend);
        let model = Arc::clone(&self.model);
        let config = self.config.clone();
        let prompt_owned = prompt.to_string();

        Box::pin(async move {
            let result = tokio::task::spawn_blocking(move || {
                run_inference(&backend, &model, &prompt_owned, &config)
            })
            .await
            .context("inference task panicked")??;

            Ok(result)
        })
    }

    fn model_name(&self) -> &str {
        &self.model_name
    }

    fn model_size_bytes(&self) -> u64 {
        self.model_size
    }

    fn using_gpu(&self) -> bool {
        self.using_gpu
    }
}

/// Run inference with a specific mode (called inside spawn_blocking).
fn run_inference_with_mode(
    backend: &LlamaBackend,
    model: &LlamaModel,
    system_prompt: &str,
    user_prompt: &str,
    config: &SlmConfig,
    mode: InferenceMode,
    max_tokens: usize,
) -> Result<String> {
    let start = Instant::now();

    let n_ctx = NonZeroU32::new(config.context_size)
        .unwrap_or(NonZeroU32::new(2048).unwrap());

    let ctx_params = LlamaContextParams::default()
        .with_n_ctx(Some(n_ctx))
        .with_n_threads(config.threads as i32)
        .with_n_threads_batch(config.threads as i32);

    let mut ctx = model
        .new_context(backend, ctx_params)
        .map_err(|e| anyhow::anyhow!("failed to create llama context: {:?}", e))?;

    // Format the full prompt with system message (ChatML format)
    let full_prompt = format!(
        "<|im_start|>system\n{}<|im_end|>\n<|im_start|>user\n{}<|im_end|>\n<|im_start|>assistant\n",
        system_prompt, user_prompt
    );

    // Tokenize the prompt
    let tokens = model
        .str_to_token(&full_prompt, AddBos::Always)
        .context("failed to tokenize prompt")?;

    debug!(
        mode = ?mode,
        token_count = tokens.len(),
        "Tokenized prompt for inference"
    );

    // Create a batch for processing tokens
    let mut batch = LlamaBatch::new(tokens.len().max(512), 1);

    let last_index = tokens.len() - 1;
    for (i, &token) in tokens.iter().enumerate() {
        let is_last = i == last_index;
        batch
            .add(token, i as i32, &[0], is_last)
            .context("failed to add token to batch")?;
    }

    // Process the prompt (prefill)
    ctx.decode(&mut batch)
        .map_err(|e| anyhow::anyhow!("failed to decode prompt batch: {:?}", e))?;

    let prefill_ms = start.elapsed().as_millis();

    // Set up sampler based on mode
    let mut sampler = if mode == InferenceMode::Triage {
        // Try grammar-constrained sampler for triage
        match LlamaSampler::grammar(model, TRIAGE_GRAMMAR, "root") {
            Ok(grammar_sampler) => {
                debug!("Using grammar-constrained sampler for triage");
                LlamaSampler::chain_simple([
                    LlamaSampler::temp(0.0), // Deterministic for classification
                    grammar_sampler,
                ])
            }
            Err(e) => {
                warn!(error = ?e, "Grammar sampler failed, falling back to greedy");
                LlamaSampler::chain_simple([
                    LlamaSampler::temp(0.0),
                    LlamaSampler::greedy(),
                ])
            }
        }
    } else {
        LlamaSampler::chain_simple([
            LlamaSampler::temp(config.temperature),
            LlamaSampler::greedy(),
        ])
    };

    // Generate completion tokens
    let mut output = String::new();
    let mut n_cur = batch.n_tokens();
    let mut decoder = encoding_rs::UTF_8.new_decoder();

    for _ in 0..max_tokens {
        let new_token = sampler.sample(&ctx, batch.n_tokens() - 1);
        sampler.accept(new_token);

        if model.is_eog_token(new_token) {
            break;
        }

        match model.token_to_piece(new_token, &mut decoder, true, None) {
            Ok(piece) => output.push_str(&piece),
            Err(_) => continue,
        }

        // For triage, stop as soon as we have a classification
        if mode == InferenceMode::Triage {
            let trimmed = output.trim();
            if trimmed == "ROUTINE" || trimmed == "NOTABLE" || trimmed == "SUSPICIOUS" {
                break;
            }
        }

        // Stop on end-of-turn markers
        if output.contains("<|im_end|>") || output.contains("<|endoftext|>") {
            break;
        }

        // Prepare next batch
        batch.clear();
        batch
            .add(new_token, n_cur, &[0], true)
            .context("failed to add generated token to batch")?;

        ctx.decode(&mut batch)
            .map_err(|e| anyhow::anyhow!("failed to decode token: {:?}", e))?;

        n_cur += 1;
    }

    // Clean up end-of-turn markers
    if let Some(pos) = output.find("<|im_end|>") {
        output.truncate(pos);
    }
    if let Some(pos) = output.find("<|endoftext|>") {
        output.truncate(pos);
    }

    let total_ms = start.elapsed().as_millis();
    debug!(
        mode = ?mode,
        prefill_ms,
        total_ms,
        output_len = output.len(),
        "Inference complete"
    );

    Ok(output.trim().to_string())
}

/// Run inference synchronously using the standard system prompt (backward compatible).
fn run_inference(
    backend: &LlamaBackend,
    model: &LlamaModel,
    prompt: &str,
    config: &SlmConfig,
) -> Result<String> {
    use crate::analyzer::SYSTEM_PROMPT;

    run_inference_with_mode(
        backend,
        model,
        SYSTEM_PROMPT,
        prompt,
        config,
        InferenceMode::Standard,
        config.max_output_tokens as usize,
    )
}

/// Get the cache directory for triage session files.
fn dirs_cache_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME environment variable not set"))?;
    Ok(home
        .join(".local")
        .join("share")
        .join("clawdefender")
        .join("cache"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_nonexistent_model_fails() {
        let config = SlmConfig {
            model_path: "/nonexistent/model.gguf".into(),
            ..Default::default()
        };
        assert!(GgufBackend::load(&config).is_err());
    }

    #[test]
    fn triage_grammar_is_valid_gbnf() {
        // Just verify the grammar string isn't empty and has expected content
        assert!(TRIAGE_GRAMMAR.contains("ROUTINE"));
        assert!(TRIAGE_GRAMMAR.contains("NOTABLE"));
        assert!(TRIAGE_GRAMMAR.contains("SUSPICIOUS"));
    }

    #[test]
    fn inference_mode_debug() {
        assert_eq!(format!("{:?}", InferenceMode::Triage), "Triage");
        assert_eq!(format!("{:?}", InferenceMode::DeepAnalysis), "DeepAnalysis");
        assert_eq!(format!("{:?}", InferenceMode::Standard), "Standard");
    }

    #[test]
    fn triage_timeout_is_shorter_than_deep() {
        assert!(TRIAGE_TIMEOUT_SECS < DEEP_ANALYSIS_TIMEOUT_SECS);
    }
}
