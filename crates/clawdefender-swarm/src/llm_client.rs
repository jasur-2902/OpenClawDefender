//! Unified LLM client supporting Anthropic and OpenAI APIs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;

use crate::keychain::{KeyStore, Provider};

/// Request to an LLM provider.
#[derive(Debug, Clone)]
pub struct LlmRequest {
    pub provider: Provider,
    pub model: String,
    pub system_prompt: String,
    pub user_prompt: String,
    pub max_tokens: u32,
    pub temperature: f32,
}

/// Response from an LLM provider.
#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub content: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub model: String,
    pub latency_ms: u64,
}

impl LlmResponse {
    /// Create a fallback response used when the LLM is unavailable.
    pub fn fallback(model: &str) -> Self {
        Self {
            content: "Analysis unavailable".to_string(),
            input_tokens: 0,
            output_tokens: 0,
            model: model.to_string(),
            latency_ms: 0,
        }
    }
}

/// Trait for LLM clients.
#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse>;
}

// ---------------------------------------------------------------------------
// HTTP LLM Client (real API calls)
// ---------------------------------------------------------------------------

pub struct HttpLlmClient {
    http: reqwest::Client,
    keychain: Arc<dyn KeyStore>,
}

impl HttpLlmClient {
    pub fn new(keychain: Arc<dyn KeyStore>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("Failed to build HTTP client");

        Self { http, keychain }
    }

    async fn call_anthropic(&self, request: &LlmRequest, api_key: &str) -> Result<LlmResponse> {
        let start = Instant::now();

        let body = serde_json::json!({
            "model": request.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "system": request.system_prompt,
            "messages": [
                { "role": "user", "content": request.user_prompt }
            ]
        });

        let resp = self
            .http
            .post("https://api.anthropic.com/v1/messages")
            .header("anthropic-version", "2023-06-01")
            .header("x-api-key", api_key)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if status.as_u16() == 429 || status.is_server_error() {
            anyhow::bail!("Anthropic API returned {status}");
        }

        let resp_body: AnthropicResponse = resp.error_for_status()?.json().await?;

        let content = resp_body
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default();

        Ok(LlmResponse {
            content,
            input_tokens: resp_body.usage.input_tokens,
            output_tokens: resp_body.usage.output_tokens,
            model: resp_body.model,
            latency_ms: start.elapsed().as_millis() as u64,
        })
    }

    async fn call_openai(
        &self,
        request: &LlmRequest,
        api_key: &str,
        base_url: Option<&str>,
    ) -> Result<LlmResponse> {
        let start = Instant::now();

        let url = format!(
            "{}/v1/chat/completions",
            base_url.unwrap_or("https://api.openai.com")
        );

        let body = serde_json::json!({
            "model": request.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [
                { "role": "system", "content": request.system_prompt },
                { "role": "user", "content": request.user_prompt }
            ]
        });

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if status.as_u16() == 429 || status.is_server_error() {
            anyhow::bail!("OpenAI API returned {status}");
        }

        let resp_body: OpenAiResponse = resp.error_for_status()?.json().await?;

        let content = resp_body
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        Ok(LlmResponse {
            content,
            input_tokens: resp_body.usage.prompt_tokens,
            output_tokens: resp_body.usage.completion_tokens,
            model: resp_body.model,
            latency_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Execute a request with one retry on transient errors (429, 5xx).
    async fn call_with_retry(&self, request: &LlmRequest) -> Result<LlmResponse> {
        let api_key = self.keychain.get(&request.provider)?;

        let result = match &request.provider {
            Provider::Anthropic => self.call_anthropic(request, &api_key).await,
            Provider::OpenAi => self.call_openai(request, &api_key, None).await,
            Provider::Custom { base_url } => {
                self.call_openai(request, &api_key, Some(base_url)).await
            }
        };

        match result {
            Ok(resp) => Ok(resp),
            Err(e) => {
                let err_str = format!("{e}");
                let is_retryable = err_str.contains("429")
                    || err_str.contains("500")
                    || err_str.contains("502")
                    || err_str.contains("503");

                if is_retryable {
                    tracing::warn!("LLM request failed with retryable error, retrying in 2s");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                    match &request.provider {
                        Provider::Anthropic => self.call_anthropic(request, &api_key).await,
                        Provider::OpenAi => self.call_openai(request, &api_key, None).await,
                        Provider::Custom { base_url } => {
                            self.call_openai(request, &api_key, Some(base_url)).await
                        }
                    }
                } else {
                    Err(e)
                }
            }
        }
    }
}

#[async_trait]
impl LlmClient for HttpLlmClient {
    async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse> {
        match self.call_with_retry(request).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::warn!("LLM request failed, returning fallback: {e}");
                Ok(LlmResponse::fallback(&request.model))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Mock LLM Client (for testing)
// ---------------------------------------------------------------------------

pub struct MockLlmClient {
    responses: Arc<Mutex<HashMap<String, LlmResponse>>>,
    call_log: Arc<Mutex<Vec<LlmRequest>>>,
}

impl MockLlmClient {
    pub fn new() -> Self {
        Self {
            responses: Arc::new(Mutex::new(HashMap::new())),
            call_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a canned response for a given model.
    pub fn add_response(&self, model: &str, response: LlmResponse) {
        self.responses
            .lock()
            .unwrap()
            .insert(model.to_string(), response);
    }

    /// Return all requests that were made to this mock.
    pub fn calls(&self) -> Vec<LlmRequest> {
        self.call_log.lock().unwrap().clone()
    }
}

impl Default for MockLlmClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LlmClient for MockLlmClient {
    async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse> {
        self.call_log.lock().unwrap().push(request.clone());

        let responses = self.responses.lock().unwrap();
        match responses.get(&request.model) {
            Some(resp) => Ok(resp.clone()),
            None => Ok(LlmResponse::fallback(&request.model)),
        }
    }
}

// ---------------------------------------------------------------------------
// API response types (serde)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
    model: String,
    usage: AnthropicUsage,
}

#[derive(Deserialize)]
struct AnthropicContent {
    text: String,
}

#[derive(Deserialize)]
struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

#[derive(Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
    model: String,
    usage: OpenAiUsage,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

#[derive(Deserialize)]
struct OpenAiMessage {
    content: String,
}

#[derive(Deserialize)]
struct OpenAiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::MemoryKeyStore;

    #[tokio::test]
    async fn test_mock_client_returns_registered_response() {
        let mock = MockLlmClient::new();
        mock.add_response(
            "claude-sonnet-4-20250514",
            LlmResponse {
                content: "This is safe".to_string(),
                input_tokens: 100,
                output_tokens: 20,
                model: "claude-sonnet-4-20250514".to_string(),
                latency_ms: 42,
            },
        );

        let request = LlmRequest {
            provider: Provider::Anthropic,
            model: "claude-sonnet-4-20250514".to_string(),
            system_prompt: "You are a security analyst.".to_string(),
            user_prompt: "Analyze this tool call.".to_string(),
            max_tokens: 1024,
            temperature: 0.0,
        };

        let resp = mock.complete(&request).await.unwrap();
        assert_eq!(resp.content, "This is safe");
        assert_eq!(resp.input_tokens, 100);
        assert_eq!(resp.output_tokens, 20);
    }

    #[tokio::test]
    async fn test_mock_client_fallback_for_unknown_model() {
        let mock = MockLlmClient::new();

        let request = LlmRequest {
            provider: Provider::OpenAi,
            model: "gpt-4o-mini".to_string(),
            system_prompt: "test".to_string(),
            user_prompt: "test".to_string(),
            max_tokens: 100,
            temperature: 0.0,
        };

        let resp = mock.complete(&request).await.unwrap();
        assert_eq!(resp.content, "Analysis unavailable");
    }

    #[tokio::test]
    async fn test_mock_client_records_calls() {
        let mock = MockLlmClient::new();

        let request = LlmRequest {
            provider: Provider::Anthropic,
            model: "claude-sonnet-4-20250514".to_string(),
            system_prompt: "sys".to_string(),
            user_prompt: "user".to_string(),
            max_tokens: 512,
            temperature: 0.5,
        };

        mock.complete(&request).await.unwrap();
        mock.complete(&request).await.unwrap();

        let calls = mock.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].model, "claude-sonnet-4-20250514");
    }

    #[tokio::test]
    async fn test_http_client_fails_open_on_missing_key() {
        let store = Arc::new(MemoryKeyStore::new());
        // Do NOT store any key — the client should fail open.
        let client = HttpLlmClient::new(store);

        let request = LlmRequest {
            provider: Provider::Anthropic,
            model: "claude-sonnet-4-20250514".to_string(),
            system_prompt: "test".to_string(),
            user_prompt: "test".to_string(),
            max_tokens: 100,
            temperature: 0.0,
        };

        let resp = client.complete(&request).await.unwrap();
        assert_eq!(resp.content, "Analysis unavailable");
    }

    #[test]
    fn test_fallback_response() {
        let resp = LlmResponse::fallback("test-model");
        assert_eq!(resp.content, "Analysis unavailable");
        assert_eq!(resp.input_tokens, 0);
        assert_eq!(resp.output_tokens, 0);
        assert_eq!(resp.model, "test-model");
    }

    #[test]
    fn test_api_key_never_in_fallback() {
        let resp = LlmResponse::fallback("test-model");
        let debug = format!("{:?}", resp);
        assert!(!debug.contains("sk-ant-"));
        assert!(!debug.contains("sk-"));
    }
}
