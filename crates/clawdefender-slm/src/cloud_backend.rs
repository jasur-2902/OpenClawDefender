//! Cloud API backend for inference via Anthropic, OpenAI, and Google APIs.
//!
//! API keys are stored exclusively in the macOS Keychain via the `security` CLI tool.
//! Keys are never written to config files, logs, or error messages.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::engine::{parse_slm_output, SlmResponse};
use crate::model_registry::{cloud_providers, CloudProvider};

// ---------------------------------------------------------------------------
// Keychain constants
// ---------------------------------------------------------------------------

const KEYCHAIN_SERVICE: &str = "com.clawdefender.api-keys";

// ---------------------------------------------------------------------------
// Keychain operations (macOS `security` CLI)
// ---------------------------------------------------------------------------

/// Store an API key in the macOS Keychain.
///
/// Overwrites any existing key for the same provider.
pub fn store_api_key(provider: &str, key: &str) -> Result<()> {
    // Delete any existing entry first (ignore errors if it doesn't exist).
    let _ = delete_api_key(provider);

    let output = std::process::Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            provider,
            "-w",
            key,
            "-U", // update if exists
        ])
        .output()
        .context("failed to execute security command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to store API key in Keychain: {}", stderr.trim());
    }

    Ok(())
}

/// Retrieve an API key from the macOS Keychain.
///
/// Returns `None` if no key is stored for the provider.
pub fn get_api_key(provider: &str) -> Result<Option<String>> {
    let output = std::process::Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            provider,
            "-w",
        ])
        .output()
        .context("failed to execute security command")?;

    if !output.status.success() {
        // Exit code != 0 means the item was not found (errSecItemNotFound = 44).
        return Ok(None);
    }

    let key = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if key.is_empty() {
        return Ok(None);
    }

    Ok(Some(key))
}

/// Delete an API key from the macOS Keychain.
pub fn delete_api_key(provider: &str) -> Result<()> {
    let output = std::process::Command::new("security")
        .args([
            "delete-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            provider,
        ])
        .output()
        .context("failed to execute security command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Not-found is not an error for deletion.
        if !stderr.contains("could not be found") && !stderr.contains("SecKeychainSearchCopyNext") {
            bail!("failed to delete API key from Keychain: {}", stderr.trim());
        }
    }

    Ok(())
}

/// Check whether an API key exists in the Keychain for the given provider.
pub fn has_api_key(provider: &str) -> bool {
    get_api_key(provider).ok().flatten().is_some()
}

// ---------------------------------------------------------------------------
// Cloud backend
// ---------------------------------------------------------------------------

/// Cloud inference backend that calls external AI provider APIs.
pub struct CloudBackend {
    provider: String,
    model: String,
    api_key: String,
    client: reqwest::Client,
    tokens_in: AtomicU64,
    tokens_out: AtomicU64,
    total_requests: AtomicU64,
}

impl CloudBackend {
    /// Create a new cloud backend.
    ///
    /// The API key is passed in directly (retrieved from Keychain by the caller).
    pub fn new(provider: String, model: String, api_key: String) -> Self {
        Self {
            provider,
            model,
            api_key,
            client: reqwest::Client::new(),
            tokens_in: AtomicU64::new(0),
            tokens_out: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
        }
    }

    /// Run inference against the cloud provider and return a parsed `SlmResponse`.
    pub async fn analyze(&self, prompt: &str) -> Result<SlmResponse> {
        let start = Instant::now();
        let raw_text = self.call_provider(prompt).await?;
        let latency_ms = start.elapsed().as_millis() as u64;

        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let response = parse_slm_output(&raw_text, latency_ms);
        Ok(response)
    }

    /// Call the appropriate provider API and return the raw response text.
    async fn call_provider(&self, prompt: &str) -> Result<String> {
        match self.provider.as_str() {
            "anthropic" => self.call_anthropic(prompt).await,
            "openai" => self.call_openai(prompt).await,
            "google" => self.call_google(prompt).await,
            other => bail!("unsupported cloud provider: {}", other),
        }
    }

    async fn call_anthropic(&self, prompt: &str) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 256,
            "messages": [{"role": "user", "content": prompt}]
        });

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Anthropic API request failed")?;

        let status = resp.status();
        let json: serde_json::Value = resp.json().await.context("failed to parse Anthropic response")?;

        if !status.is_success() {
            let msg = json["error"]["message"]
                .as_str()
                .unwrap_or("unknown error");
            bail!("Anthropic API error ({}): {}", status, msg);
        }

        // Track token usage from response.
        if let Some(usage) = json.get("usage") {
            if let Some(input) = usage["input_tokens"].as_u64() {
                self.tokens_in.fetch_add(input, Ordering::Relaxed);
            }
            if let Some(output) = usage["output_tokens"].as_u64() {
                self.tokens_out.fetch_add(output, Ordering::Relaxed);
            }
        }

        // Extract text from content array.
        let text = json["content"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|block| block["text"].as_str())
            .unwrap_or("")
            .to_string();

        Ok(text)
    }

    async fn call_openai(&self, prompt: &str) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 256,
            "messages": [{"role": "user", "content": prompt}]
        });

        let resp = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("OpenAI API request failed")?;

        let status = resp.status();
        let json: serde_json::Value = resp.json().await.context("failed to parse OpenAI response")?;

        if !status.is_success() {
            let msg = json["error"]["message"]
                .as_str()
                .unwrap_or("unknown error");
            bail!("OpenAI API error ({}): {}", status, msg);
        }

        // Track token usage.
        if let Some(usage) = json.get("usage") {
            if let Some(input) = usage["prompt_tokens"].as_u64() {
                self.tokens_in.fetch_add(input, Ordering::Relaxed);
            }
            if let Some(output) = usage["completion_tokens"].as_u64() {
                self.tokens_out.fetch_add(output, Ordering::Relaxed);
            }
        }

        let text = json["choices"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|choice| choice["message"]["content"].as_str())
            .unwrap_or("")
            .to_string();

        Ok(text)
    }

    async fn call_google(&self, prompt: &str) -> Result<String> {
        // Security: Pass API key via header instead of URL query parameter.
        // Query parameters can leak into server access logs, proxy logs, and error messages.
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
            self.model
        );

        let body = serde_json::json!({
            "contents": [{"parts": [{"text": prompt}]}]
        });

        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-goog-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .context("Google API request failed")?;

        let status = resp.status();
        let json: serde_json::Value = resp.json().await.context("failed to parse Google response")?;

        if !status.is_success() {
            let msg = json["error"]["message"]
                .as_str()
                .unwrap_or("unknown error");
            bail!("Google API error ({}): {}", status, msg);
        }

        // Track token usage.
        if let Some(usage) = json.get("usageMetadata") {
            if let Some(input) = usage["promptTokenCount"].as_u64() {
                self.tokens_in.fetch_add(input, Ordering::Relaxed);
            }
            if let Some(output) = usage["candidatesTokenCount"].as_u64() {
                self.tokens_out.fetch_add(output, Ordering::Relaxed);
            }
        }

        let text = json["candidates"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|c| c["content"]["parts"].as_array())
            .and_then(|parts| parts.first())
            .and_then(|part| part["text"].as_str())
            .unwrap_or("")
            .to_string();

        Ok(text)
    }

    /// Return current usage statistics.
    pub fn usage_stats(&self) -> CloudUsageStats {
        let tokens_in = self.tokens_in.load(Ordering::Relaxed);
        let tokens_out = self.tokens_out.load(Ordering::Relaxed);

        // Look up cost rates from the provider registry.
        let (cost_in, cost_out) = cost_rates(&self.provider, &self.model);
        let estimated_cost = (tokens_in as f64 / 1000.0) * cost_in
            + (tokens_out as f64 / 1000.0) * cost_out;

        CloudUsageStats {
            provider: self.provider.clone(),
            model: self.model.clone(),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            tokens_in,
            tokens_out,
            estimated_cost_usd: estimated_cost,
        }
    }
}

/// Look up cost rates for a provider/model combination.
fn cost_rates(provider: &str, model: &str) -> (f64, f64) {
    for p in cloud_providers() {
        if p.id == provider {
            for m in &p.models {
                if m.id == model {
                    return (m.cost_per_1k_input, m.cost_per_1k_output);
                }
            }
        }
    }
    (0.0, 0.0)
}

// ---------------------------------------------------------------------------
// Connection test
// ---------------------------------------------------------------------------

/// Result of testing a connection to a cloud provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTestResult {
    pub success: bool,
    pub latency_ms: u64,
    pub error: Option<String>,
    pub model_name: String,
}

/// Test connectivity to a cloud provider by sending a minimal request.
pub async fn test_connection(
    provider: &str,
    api_key: &str,
    model: &str,
) -> Result<ConnectionTestResult> {
    let backend = CloudBackend::new(
        provider.to_string(),
        model.to_string(),
        api_key.to_string(),
    );

    let start = Instant::now();
    let result = backend.call_provider("Hello").await;
    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(_) => Ok(ConnectionTestResult {
            success: true,
            latency_ms,
            error: None,
            model_name: model.to_string(),
        }),
        Err(e) => Ok(ConnectionTestResult {
            success: false,
            latency_ms,
            error: Some(e.to_string()),
            model_name: model.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Usage stats
// ---------------------------------------------------------------------------

/// Cumulative usage statistics for a cloud backend session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudUsageStats {
    pub provider: String,
    pub model: String,
    pub total_requests: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub estimated_cost_usd: f64,
}

// ---------------------------------------------------------------------------
// Helper: get cloud providers list (re-export for Tauri commands)
// ---------------------------------------------------------------------------

/// Return the list of cloud providers (delegates to model_registry).
pub fn get_cloud_providers() -> Vec<CloudProvider> {
    cloud_providers()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_rates_known_provider() {
        let (cost_in, cost_out) = cost_rates("anthropic", "claude-sonnet-4-20250514");
        assert!(cost_in > 0.0);
        assert!(cost_out > 0.0);
    }

    #[test]
    fn cost_rates_unknown_provider() {
        let (cost_in, cost_out) = cost_rates("unknown", "unknown-model");
        assert_eq!(cost_in, 0.0);
        assert_eq!(cost_out, 0.0);
    }

    #[test]
    fn cloud_backend_initial_usage() {
        let backend = CloudBackend::new(
            "anthropic".into(),
            "claude-sonnet-4-20250514".into(),
            "test-key".into(),
        );
        let stats = backend.usage_stats();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.tokens_in, 0);
        assert_eq!(stats.tokens_out, 0);
        assert_eq!(stats.estimated_cost_usd, 0.0);
        assert_eq!(stats.provider, "anthropic");
        assert_eq!(stats.model, "claude-sonnet-4-20250514");
    }

    #[test]
    fn get_cloud_providers_returns_three() {
        let providers = get_cloud_providers();
        assert_eq!(providers.len(), 3);
    }

    #[test]
    fn connection_test_result_serialization() {
        let result = ConnectionTestResult {
            success: true,
            latency_ms: 150,
            error: None,
            model_name: "gpt-4o".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ConnectionTestResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.latency_ms, 150);
        assert!(parsed.error.is_none());
    }

    #[test]
    fn connection_test_result_with_error_serialization() {
        let result = ConnectionTestResult {
            success: false,
            latency_ms: 0,
            error: Some("connection refused".into()),
            model_name: "gpt-4o".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ConnectionTestResult = serde_json::from_str(&json).unwrap();
        assert!(!parsed.success);
        assert_eq!(parsed.error, Some("connection refused".into()));
    }

    #[test]
    fn cloud_usage_stats_serialization() {
        let stats = CloudUsageStats {
            provider: "openai".into(),
            model: "gpt-4o".into(),
            total_requests: 10,
            tokens_in: 500,
            tokens_out: 200,
            estimated_cost_usd: 0.0033,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: CloudUsageStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.provider, "openai");
        assert_eq!(parsed.total_requests, 10);
        assert_eq!(parsed.tokens_in, 500);
        assert_eq!(parsed.tokens_out, 200);
        assert!(parsed.estimated_cost_usd > 0.0);
    }

    #[test]
    fn provider_api_endpoints_are_https() {
        for p in get_cloud_providers() {
            assert!(
                p.api_endpoint.starts_with("https://"),
                "provider {} has non-HTTPS endpoint: {}",
                p.id,
                p.api_endpoint
            );
        }
    }

    #[test]
    fn google_api_url_construction() {
        // Verify the URL construction logic for Google API
        let model = "gemini-2.0-flash";
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
            model
        );
        assert!(url.contains("gemini-2.0-flash"));
        assert!(url.starts_with("https://"));
        assert!(url.ends_with(":generateContent"));
    }

    #[test]
    fn cost_rates_all_recommended_models_have_costs() {
        for p in get_cloud_providers() {
            for m in &p.models {
                if m.recommended {
                    let (ci, co) = cost_rates(&p.id, &m.id);
                    assert!(
                        ci > 0.0 && co > 0.0,
                        "recommended model {}/{} has zero cost rates",
                        p.id,
                        m.id
                    );
                }
            }
        }
    }
}
