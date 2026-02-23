//! Real GGUF inference backend using llama-cpp.
//!
//! This module is only compiled when the `gguf` feature is enabled.
//! It loads a GGUF model file and runs inference using llama.cpp
//! via the `llama_cpp` Rust bindings.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::engine::{SlmBackend, SlmConfig};

/// A real GGUF inference backend powered by llama.cpp.
pub struct GgufBackend {
    model: Arc<llama_cpp::LlamaModel>,
    model_name: String,
    model_size: u64,
    using_gpu: bool,
    config: SlmConfig,
}

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

        let mut params = llama_cpp::LlamaParams::default();
        if config.use_gpu {
            // Load all layers to GPU (Metal on macOS)
            params.n_gpu_layers = u32::MAX;
        } else {
            params.n_gpu_layers = 0;
        }

        let model = llama_cpp::LlamaModel::load_from_file(path, params)
            .context("failed to load GGUF model")?;

        let using_gpu = config.use_gpu;

        info!(
            model = model_name,
            "GGUF model loaded successfully"
        );

        Ok(Self {
            model: Arc::new(model),
            model_name,
            model_size,
            using_gpu,
            config: config.clone(),
        })
    }
}

impl SlmBackend for GgufBackend {
    fn infer<'a>(
        &'a self,
        prompt: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
        let model = Arc::clone(&self.model);
        let config = self.config.clone();
        let prompt_owned = prompt.to_string();

        Box::pin(async move {
            // Run inference in a blocking task to avoid blocking the async runtime.
            let result = tokio::task::spawn_blocking(move || {
                run_inference(&model, &prompt_owned, &config)
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

/// Run inference synchronously (called inside spawn_blocking).
fn run_inference(
    model: &llama_cpp::LlamaModel,
    prompt: &str,
    config: &SlmConfig,
) -> Result<String> {
    use crate::analyzer::SYSTEM_PROMPT;

    let mut session_params = llama_cpp::SessionParams::default();
    session_params.n_ctx = config.context_size;
    session_params.n_threads = config.threads;
    session_params.n_threads_batch = config.threads;

    let mut session = model
        .create_session(session_params)
        .context("failed to create inference session")?;

    // Feed system prompt + user prompt
    let full_prompt = format!(
        "<|im_start|>system\n{}<|im_end|>\n<|im_start|>user\n{}<|im_end|>\n<|im_start|>assistant\n",
        SYSTEM_PROMPT, prompt
    );

    session
        .advance_context(&full_prompt)
        .context("failed to feed prompt to model")?;

    // Generate completion
    let completions = session
        .start_completing()
        .context("failed to start completion")?;
    let mut output = String::new();
    let max_tokens = config.max_output_tokens as usize;

    for token in completions.into_strings() {
        output.push_str(&token);
        if output.len() > max_tokens * 4 {
            // Rough char-based limit as safety stop
            break;
        }
        // Stop on end-of-turn markers
        if output.contains("<|im_end|>") || output.contains("<|endoftext|>") {
            break;
        }
    }

    // Clean up end-of-turn markers
    if let Some(pos) = output.find("<|im_end|>") {
        output.truncate(pos);
    }
    if let Some(pos) = output.find("<|endoftext|>") {
        output.truncate(pos);
    }

    debug!(output_len = output.len(), "GGUF inference complete");
    Ok(output.trim().to_string())
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
}
