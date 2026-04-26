//! Cloud API orchestration layer for multi-provider LLM communication.
//!
//! Provides a unified interface to Claude (Anthropic) and OpenAI-compatible APIs
//! with tool-use response parsing, retry logic, and a middleware pipeline for
//! privacy filtering and cost tracking.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cost::{BudgetExceededError, CostGuard, UsageRecord};
use crate::privacy::PrivacyFilter;
use crate::tools::{ToolCall, ToolResult};

// ---------------------------------------------------------------------------
// Core message types
// ---------------------------------------------------------------------------

/// A message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String, // "user", "assistant", "tool"
    pub content: MessageContent,
}

/// Message content can be a plain string or an array of content blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

/// A single block of content within a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
}

// ---------------------------------------------------------------------------
// Request / Response
// ---------------------------------------------------------------------------

/// Unified request to any cloud provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<Message>,
    pub tools: Vec<Value>,
    pub max_tokens: u32,
    pub stream: bool,
}

/// Unified response from any cloud provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub id: String,
    pub content: Vec<ContentBlock>,
    pub stop_reason: StopReason,
    pub usage: TokenUsage,
    pub model: String,
}

/// Why the model stopped generating.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    Unknown(String),
}

/// Token counts from a single API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

// ---------------------------------------------------------------------------
// CloudProvider trait
// ---------------------------------------------------------------------------

/// Abstraction over cloud LLM providers (Anthropic, OpenAI, etc.).
#[async_trait]
pub trait CloudProvider: Send + Sync {
    async fn send_message(&self, request: &AgentRequest) -> Result<AgentResponse>;
    fn provider_name(&self) -> &str;
    fn supports_tools(&self) -> bool;
    fn supports_streaming(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    #[error("Invalid API key")]
    InvalidApiKey,
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    #[error("Server error: {status}")]
    ServerError { status: u16 },
    #[error("API overloaded")]
    Overloaded,
    #[error("Cloud API unreachable: {0}")]
    Unreachable(String),
    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),
    #[error("Budget exceeded: {0}")]
    BudgetExceeded(String),
    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),
}

// ---------------------------------------------------------------------------
// Anthropic provider
// ---------------------------------------------------------------------------

/// Anthropic (Claude) API provider.
pub struct AnthropicProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl AnthropicProvider {
    pub fn new(api_key: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            api_key,
            base_url: "https://api.anthropic.com".to_string(),
        }
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    fn build_request_body(&self, request: &AgentRequest) -> Value {
        let messages: Vec<Value> = request
            .messages
            .iter()
            .map(|m| {
                let content = match &m.content {
                    MessageContent::Text(t) => serde_json::json!(t),
                    MessageContent::Blocks(blocks) => {
                        let block_values: Vec<Value> = blocks
                            .iter()
                            .map(|b| serde_json::to_value(b).unwrap_or_default())
                            .collect();
                        serde_json::json!(block_values)
                    }
                };
                serde_json::json!({
                    "role": m.role,
                    "content": content,
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "model": request.model,
            "system": request.system,
            "messages": messages,
            "max_tokens": request.max_tokens,
        });

        if !request.tools.is_empty() {
            body["tools"] = serde_json::json!(request.tools);
        }

        body
    }

    fn parse_response(&self, body: &Value) -> Result<AgentResponse, CloudError> {
        let id = body["id"].as_str().unwrap_or("unknown").to_string();

        let model = body["model"].as_str().unwrap_or("unknown").to_string();

        let stop_reason = match body["stop_reason"].as_str() {
            Some("end_turn") => StopReason::EndTurn,
            Some("tool_use") => StopReason::ToolUse,
            Some("max_tokens") => StopReason::MaxTokens,
            Some(other) => StopReason::Unknown(other.to_string()),
            None => StopReason::Unknown("missing".to_string()),
        };

        let usage = TokenUsage {
            input_tokens: body["usage"]["input_tokens"].as_u64().unwrap_or(0),
            output_tokens: body["usage"]["output_tokens"].as_u64().unwrap_or(0),
        };

        let content =
            self.parse_content_blocks(body["content"].as_array().cloned().unwrap_or_default());

        Ok(AgentResponse {
            id,
            content,
            stop_reason,
            usage,
            model,
        })
    }

    fn parse_content_blocks(&self, blocks: Vec<Value>) -> Vec<ContentBlock> {
        blocks
            .into_iter()
            .filter_map(|block| match block["type"].as_str()? {
                "text" => Some(ContentBlock::Text {
                    text: block["text"].as_str().unwrap_or("").to_string(),
                }),
                "tool_use" => Some(ContentBlock::ToolUse {
                    id: block["id"].as_str().unwrap_or("").to_string(),
                    name: block["name"].as_str().unwrap_or("").to_string(),
                    input: block["input"].clone(),
                }),
                _ => None,
            })
            .collect()
    }
}

#[async_trait]
impl CloudProvider for AnthropicProvider {
    async fn send_message(&self, request: &AgentRequest) -> Result<AgentResponse> {
        let url = format!("{}/v1/messages", self.base_url);
        let body = self.build_request_body(request);

        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    CloudError::Unreachable("request timed out".to_string())
                } else {
                    CloudError::RequestError(e)
                }
            })?;

        let status = resp.status().as_u16();
        if status == 401 {
            return Err(CloudError::InvalidApiKey.into());
        }
        if status == 429 {
            return Err(CloudError::RateLimited {
                retry_after_secs: 1,
            }
            .into());
        }
        if status == 529 {
            return Err(CloudError::Overloaded.into());
        }
        if status >= 500 {
            return Err(CloudError::ServerError { status }.into());
        }
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(CloudError::UnexpectedResponse(format!("HTTP {status}: {text}")).into());
        }

        let resp_body: Value = resp.json().await.map_err(|e| {
            CloudError::UnexpectedResponse(format!("Failed to parse response JSON: {e}"))
        })?;

        self.parse_response(&resp_body)
            .map_err(|e| anyhow::anyhow!(e))
    }

    fn provider_name(&self) -> &str {
        "anthropic"
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn supports_streaming(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// OpenAI provider
// ---------------------------------------------------------------------------

/// OpenAI-compatible API provider.
pub struct OpenAIProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl OpenAIProvider {
    pub fn new(api_key: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            api_key,
            base_url: "https://api.openai.com/v1".to_string(),
        }
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    /// Convert Anthropic-style tool definitions to OpenAI function calling format.
    fn convert_tools_to_openai(tools: &[Value]) -> Vec<Value> {
        tools
            .iter()
            .map(|tool| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool["description"],
                        "parameters": tool["input_schema"],
                    }
                })
            })
            .collect()
    }

    /// Build message array in OpenAI chat format.
    fn build_messages(system: &str, messages: &[Message]) -> Vec<Value> {
        let mut out = vec![serde_json::json!({
            "role": "system",
            "content": system,
        })];

        for msg in messages {
            match &msg.content {
                MessageContent::Text(t) => {
                    out.push(serde_json::json!({
                        "role": msg.role,
                        "content": t,
                    }));
                }
                MessageContent::Blocks(blocks) => {
                    // For tool results, produce individual messages.
                    // For text/tool_use, combine into one message.
                    let mut texts = Vec::new();
                    let mut tool_calls_out = Vec::new();

                    for block in blocks {
                        match block {
                            ContentBlock::Text { text } => {
                                texts.push(text.clone());
                            }
                            ContentBlock::ToolUse { id, name, input } => {
                                tool_calls_out.push(serde_json::json!({
                                    "id": id,
                                    "type": "function",
                                    "function": {
                                        "name": name,
                                        "arguments": input.to_string(),
                                    }
                                }));
                            }
                            ContentBlock::ToolResult {
                                tool_use_id,
                                content,
                                is_error,
                            } => {
                                out.push(serde_json::json!({
                                    "role": "tool",
                                    "tool_call_id": tool_use_id,
                                    "content": content,
                                }));
                                let _ = is_error; // OpenAI doesn't have an is_error field
                            }
                        }
                    }

                    if !texts.is_empty() || !tool_calls_out.is_empty() {
                        let mut m = serde_json::json!({
                            "role": msg.role,
                            "content": if texts.is_empty() { Value::Null } else { Value::String(texts.join("\n")) },
                        });
                        if !tool_calls_out.is_empty() {
                            m["tool_calls"] = Value::Array(tool_calls_out);
                        }
                        out.push(m);
                    }
                }
            }
        }

        out
    }

    /// Parse an OpenAI response into our unified format.
    fn parse_response(body: &Value) -> Result<AgentResponse, CloudError> {
        let id = body["id"].as_str().unwrap_or("unknown").to_string();

        let model = body["model"].as_str().unwrap_or("unknown").to_string();

        let choice = body["choices"]
            .as_array()
            .and_then(|c| c.first())
            .ok_or_else(|| CloudError::UnexpectedResponse("no choices in response".to_string()))?;

        let finish_reason = choice["finish_reason"].as_str().unwrap_or("");
        let stop_reason = match finish_reason {
            "stop" => StopReason::EndTurn,
            "tool_calls" => StopReason::ToolUse,
            "length" => StopReason::MaxTokens,
            other => StopReason::Unknown(other.to_string()),
        };

        let usage = TokenUsage {
            input_tokens: body["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
            output_tokens: body["usage"]["completion_tokens"].as_u64().unwrap_or(0),
        };

        let mut content = Vec::new();

        // Text content
        if let Some(text) = choice["message"]["content"].as_str() {
            if !text.is_empty() {
                content.push(ContentBlock::Text {
                    text: text.to_string(),
                });
            }
        }

        // Tool calls
        if let Some(tool_calls) = choice["message"]["tool_calls"].as_array() {
            for tc in tool_calls {
                let id = tc["id"].as_str().unwrap_or("").to_string();
                let name = tc["function"]["name"].as_str().unwrap_or("").to_string();
                let args_str = tc["function"]["arguments"].as_str().unwrap_or("{}");
                let input: Value = serde_json::from_str(args_str).unwrap_or(serde_json::json!({}));

                content.push(ContentBlock::ToolUse { id, name, input });
            }
        }

        Ok(AgentResponse {
            id,
            content,
            stop_reason,
            usage,
            model,
        })
    }
}

#[async_trait]
impl CloudProvider for OpenAIProvider {
    async fn send_message(&self, request: &AgentRequest) -> Result<AgentResponse> {
        let url = format!("{}/chat/completions", self.base_url);

        let messages = Self::build_messages(&request.system, &request.messages);
        let mut body = serde_json::json!({
            "model": request.model,
            "messages": messages,
            "max_tokens": request.max_tokens,
        });

        if !request.tools.is_empty() {
            body["tools"] = Value::Array(Self::convert_tools_to_openai(&request.tools));
        }

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    CloudError::Unreachable("request timed out".to_string())
                } else {
                    CloudError::RequestError(e)
                }
            })?;

        let status = resp.status().as_u16();
        if status == 401 {
            return Err(CloudError::InvalidApiKey.into());
        }
        if status == 429 {
            return Err(CloudError::RateLimited {
                retry_after_secs: 1,
            }
            .into());
        }
        if status >= 500 {
            return Err(CloudError::ServerError { status }.into());
        }
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(CloudError::UnexpectedResponse(format!("HTTP {status}: {text}")).into());
        }

        let resp_body: Value = resp.json().await.map_err(|e| {
            CloudError::UnexpectedResponse(format!("Failed to parse response JSON: {e}"))
        })?;

        Self::parse_response(&resp_body).map_err(|e| anyhow::anyhow!(e))
    }

    fn provider_name(&self) -> &str {
        "openai"
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn supports_streaming(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Retry logic
// ---------------------------------------------------------------------------

/// Send a request with retry logic for transient errors.
///
/// - HTTP 401 -> return InvalidApiKey immediately (no retry)
/// - HTTP 429 -> exponential backoff (1s, 2s, 4s), max 3 retries
/// - HTTP 500/502/503 -> retry once after 2 seconds
/// - HTTP 529 -> wait 30 seconds, retry once
/// - Timeout -> return Unreachable
pub async fn send_with_retry(
    provider: &dyn CloudProvider,
    request: &AgentRequest,
) -> Result<AgentResponse, CloudError> {
    let result = provider.send_message(request).await;

    match result {
        Ok(resp) => return Ok(resp),
        Err(e) => {
            let err_str = format!("{e}");

            // No retry for auth errors
            if err_str.contains("Invalid API key") {
                return Err(CloudError::InvalidApiKey);
            }

            // Rate limited: exponential backoff, max 3 retries
            if err_str.contains("Rate limited") {
                let delays = [1, 2, 4];
                for delay in delays {
                    tracing::warn!(
                        "Rate limited, retrying in {delay}s (provider: {})",
                        provider.provider_name()
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                    match provider.send_message(request).await {
                        Ok(resp) => return Ok(resp),
                        Err(retry_err) => {
                            let retry_str = format!("{retry_err}");
                            if !retry_str.contains("Rate limited") {
                                // Different error type, stop retrying
                                return Err(classify_error(&retry_str));
                            }
                        }
                    }
                }
                return Err(CloudError::RateLimited {
                    retry_after_secs: 8,
                });
            }

            // API overloaded (529): wait 30s, retry once
            if err_str.contains("overloaded") {
                tracing::warn!(
                    "API overloaded, retrying in 30s (provider: {})",
                    provider.provider_name()
                );
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                return provider
                    .send_message(request)
                    .await
                    .map_err(|e| classify_error(&format!("{e}")));
            }

            // Server errors (5xx): retry once after 2s
            if err_str.contains("Server error") {
                tracing::warn!(
                    "Server error, retrying in 2s (provider: {})",
                    provider.provider_name()
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                return provider
                    .send_message(request)
                    .await
                    .map_err(|e| classify_error(&format!("{e}")));
            }

            // Timeout / unreachable
            if err_str.contains("timed out") || err_str.contains("unreachable") {
                return Err(CloudError::Unreachable(err_str));
            }

            Err(classify_error(&err_str))
        }
    }
}

fn classify_error(err_str: &str) -> CloudError {
    if err_str.contains("Invalid API key") {
        CloudError::InvalidApiKey
    } else if err_str.contains("Rate limited") {
        CloudError::RateLimited {
            retry_after_secs: 1,
        }
    } else if err_str.contains("overloaded") {
        CloudError::Overloaded
    } else if err_str.contains("timed out") || err_str.contains("unreachable") {
        CloudError::Unreachable(err_str.to_string())
    } else {
        CloudError::UnexpectedResponse(err_str.to_string())
    }
}

// ---------------------------------------------------------------------------
// CloudApiClient — main orchestrator
// ---------------------------------------------------------------------------

/// Main interface for sending requests through the full middleware pipeline.
///
/// Pipeline:
/// 1. Privacy filter outbound (system prompt + messages)
/// 2. Budget check (cost guard)
/// 3. Send with retry
/// 4. Record token usage (cost tracker)
/// 5. Privacy filter inbound (response)
pub struct CloudApiClient {
    provider: Box<dyn CloudProvider>,
    privacy_filter: Option<Arc<PrivacyFilter>>,
    cost_guard: Option<Arc<CostGuard>>,
}

impl CloudApiClient {
    pub fn new(provider: Box<dyn CloudProvider>) -> Self {
        Self {
            provider,
            privacy_filter: None,
            cost_guard: None,
        }
    }

    pub fn with_privacy(mut self, filter: Arc<PrivacyFilter>) -> Self {
        self.privacy_filter = Some(filter);
        self
    }

    pub fn with_cost_guard(mut self, guard: Arc<CostGuard>) -> Self {
        self.cost_guard = Some(guard);
        self
    }

    /// Send a message through the full middleware pipeline.
    pub async fn send(&self, request: &AgentRequest) -> Result<AgentResponse, CloudError> {
        // 1. Privacy filter outbound
        let filtered_request = if let Some(filter) = &self.privacy_filter {
            let mut req = request.clone();
            let system_result = filter.filter_briefing(&req.system);
            req.system = system_result.filtered_text;

            req.messages = req
                .messages
                .into_iter()
                .map(|mut m| {
                    m.content = filter_message_content(&**filter, m.content);
                    m
                })
                .collect();

            req
        } else {
            request.clone()
        };

        // 2. Budget check
        if let Some(guard) = &self.cost_guard {
            guard.check_budget().await.map_err(|e| match e {
                BudgetExceededError::SessionBudget { used, limit } => CloudError::BudgetExceeded(
                    format!("Session budget exceeded: ${used:.4} of ${limit:.4}"),
                ),
                BudgetExceededError::DailyBudget { used, limit } => CloudError::BudgetExceeded(
                    format!("Daily budget exceeded: ${used:.4} of ${limit:.4}"),
                ),
                BudgetExceededError::MonthlyBudget { used, limit } => CloudError::BudgetExceeded(
                    format!("Monthly budget exceeded: ${used:.4} of ${limit:.4}"),
                ),
            })?;
        }

        // 3. Send with retry
        let response = send_with_retry(&*self.provider, &filtered_request).await?;

        // 4. Record token usage
        if let Some(guard) = &self.cost_guard {
            let record = UsageRecord {
                timestamp: chrono::Utc::now().to_rfc3339(),
                provider: self.provider.provider_name().to_string(),
                model: response.model.clone(),
                input_tokens: response.usage.input_tokens as u32,
                output_tokens: response.usage.output_tokens as u32,
                estimated_cost_usd: 0.0, // actual cost computed by CostGuard/Tracker
                event_id: None,
                specialist: None,
            };
            // Best-effort: don't fail the request if recording fails.
            let _ = guard.record_usage(record).await;
        }

        // 5. Privacy filter inbound
        let filtered_response = if let Some(filter) = &self.privacy_filter {
            let mut resp = response;
            resp.content = resp
                .content
                .into_iter()
                .map(|block| match block {
                    ContentBlock::Text { text } => {
                        let result = filter.filter_response(&text);
                        ContentBlock::Text {
                            text: result.filtered_text,
                        }
                    }
                    other => other,
                })
                .collect();
            resp
        } else {
            response
        };

        Ok(filtered_response)
    }
}

/// Filter message content through the privacy filter.
fn filter_message_content(filter: &PrivacyFilter, content: MessageContent) -> MessageContent {
    match content {
        MessageContent::Text(t) => {
            let result = filter.filter_text(&t);
            MessageContent::Text(result.filtered_text)
        }
        MessageContent::Blocks(blocks) => {
            let filtered: Vec<ContentBlock> = blocks
                .into_iter()
                .map(|block| match block {
                    ContentBlock::Text { text } => {
                        let result = filter.filter_text(&text);
                        ContentBlock::Text {
                            text: result.filtered_text,
                        }
                    }
                    ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                    } => {
                        let result = filter.filter_tool_result(&content);
                        ContentBlock::ToolResult {
                            tool_use_id,
                            content: result.filtered_text,
                            is_error,
                        }
                    }
                    other => other,
                })
                .collect();
            MessageContent::Blocks(filtered)
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract all tool calls from an agent response.
pub fn extract_tool_calls(response: &AgentResponse) -> Vec<ToolCall> {
    response
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::ToolUse { id, name, input } => Some(ToolCall {
                id: id.clone(),
                name: name.clone(),
                input: input.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// Extract concatenated text from all text blocks in a response.
pub fn extract_text(response: &AgentResponse) -> String {
    response
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build a message containing tool results to send back to the model.
pub fn build_tool_result_message(results: Vec<ToolResult>) -> Message {
    let blocks: Vec<ContentBlock> = results
        .into_iter()
        .map(|r| ContentBlock::ToolResult {
            tool_use_id: r.tool_use_id,
            content: r.content,
            is_error: if r.is_error { Some(true) } else { None },
        })
        .collect();

    Message {
        role: "user".to_string(),
        content: MessageContent::Blocks(blocks),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Request serialization -----------------------------------------------

    #[test]
    fn test_anthropic_request_serialization() {
        let provider = AnthropicProvider::new("test-key".to_string());
        let request = AgentRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            system: "You are a security agent.".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text("What is happening?".to_string()),
            }],
            tools: vec![serde_json::json!({
                "name": "query_events",
                "description": "Query events",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "time_range": { "type": "string" }
                    },
                    "required": ["time_range"]
                }
            })],
            max_tokens: 4096,
            stream: false,
        };

        let body = provider.build_request_body(&request);

        assert_eq!(body["model"], "claude-sonnet-4-20250514");
        assert_eq!(body["system"], "You are a security agent.");
        assert_eq!(body["max_tokens"], 4096);
        assert!(body["tools"].is_array());
        assert_eq!(body["tools"].as_array().unwrap().len(), 1);
        assert!(body["messages"].is_array());
        assert_eq!(body["messages"][0]["role"], "user");
    }

    // -- Response parsing ----------------------------------------------------

    #[test]
    fn test_response_parsing() {
        let provider = AnthropicProvider::new("test-key".to_string());
        let body = serde_json::json!({
            "id": "msg_01XFDUDYJgAACzvnptvVoYEL",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "content": [
                {
                    "type": "text",
                    "text": "The system appears secure."
                }
            ],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 1200,
                "output_tokens": 350
            }
        });

        let resp = provider.parse_response(&body).unwrap();
        assert_eq!(resp.id, "msg_01XFDUDYJgAACzvnptvVoYEL");
        assert_eq!(resp.model, "claude-sonnet-4-20250514");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert_eq!(resp.usage.input_tokens, 1200);
        assert_eq!(resp.usage.output_tokens, 350);
        assert_eq!(resp.content.len(), 1);
        match &resp.content[0] {
            ContentBlock::Text { text } => {
                assert_eq!(text, "The system appears secure.");
            }
            _ => panic!("Expected text block"),
        }
    }

    #[test]
    fn test_tool_use_response_parsing() {
        let provider = AnthropicProvider::new("test-key".to_string());
        let body = serde_json::json!({
            "id": "msg_tool_01",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "content": [
                {
                    "type": "text",
                    "text": "Let me investigate."
                },
                {
                    "type": "tool_use",
                    "id": "toolu_01A",
                    "name": "query_events",
                    "input": {
                        "time_range": "last_hour",
                        "server": "FileManager"
                    }
                }
            ],
            "stop_reason": "tool_use",
            "usage": {
                "input_tokens": 800,
                "output_tokens": 200
            }
        });

        let resp = provider.parse_response(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        assert_eq!(resp.content.len(), 2);

        match &resp.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Let me investigate."),
            _ => panic!("Expected text block"),
        }

        match &resp.content[1] {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "toolu_01A");
                assert_eq!(name, "query_events");
                assert_eq!(input["time_range"], "last_hour");
                assert_eq!(input["server"], "FileManager");
            }
            _ => panic!("Expected tool_use block"),
        }
    }

    // -- Extract helpers -----------------------------------------------------

    #[test]
    fn test_extract_tool_calls() {
        let response = AgentResponse {
            id: "msg_1".to_string(),
            content: vec![
                ContentBlock::Text {
                    text: "Analyzing...".to_string(),
                },
                ContentBlock::ToolUse {
                    id: "tool_1".to_string(),
                    name: "query_events".to_string(),
                    input: serde_json::json!({"time_range": "last_hour"}),
                },
                ContentBlock::ToolUse {
                    id: "tool_2".to_string(),
                    name: "get_server_profile".to_string(),
                    input: serde_json::json!({"server_name": "FileManager"}),
                },
            ],
            stop_reason: StopReason::ToolUse,
            usage: TokenUsage {
                input_tokens: 500,
                output_tokens: 100,
            },
            model: "claude-sonnet-4-20250514".to_string(),
        };

        let calls = extract_tool_calls(&response);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "query_events");
        assert_eq!(calls[0].id, "tool_1");
        assert_eq!(calls[1].name, "get_server_profile");
        assert_eq!(calls[1].id, "tool_2");
    }

    #[test]
    fn test_extract_text() {
        let response = AgentResponse {
            id: "msg_2".to_string(),
            content: vec![
                ContentBlock::Text {
                    text: "First paragraph.".to_string(),
                },
                ContentBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "query_events".to_string(),
                    input: serde_json::json!({}),
                },
                ContentBlock::Text {
                    text: "Second paragraph.".to_string(),
                },
            ],
            stop_reason: StopReason::EndTurn,
            usage: TokenUsage {
                input_tokens: 100,
                output_tokens: 50,
            },
            model: "test".to_string(),
        };

        let text = extract_text(&response);
        assert_eq!(text, "First paragraph.\nSecond paragraph.");
    }

    // -- Stop reason parsing -------------------------------------------------

    #[test]
    fn test_stop_reason_parsing() {
        let provider = AnthropicProvider::new("k".to_string());

        let make_body = |stop_reason: &str| {
            serde_json::json!({
                "id": "msg_1",
                "model": "test",
                "content": [],
                "stop_reason": stop_reason,
                "usage": { "input_tokens": 0, "output_tokens": 0 }
            })
        };

        let resp = provider.parse_response(&make_body("end_turn")).unwrap();
        assert_eq!(resp.stop_reason, StopReason::EndTurn);

        let resp = provider.parse_response(&make_body("tool_use")).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);

        let resp = provider.parse_response(&make_body("max_tokens")).unwrap();
        assert_eq!(resp.stop_reason, StopReason::MaxTokens);

        let resp = provider
            .parse_response(&make_body("something_else"))
            .unwrap();
        assert_eq!(
            resp.stop_reason,
            StopReason::Unknown("something_else".to_string())
        );
    }

    // -- Error mapping -------------------------------------------------------

    #[test]
    fn test_error_mapping() {
        let err = classify_error("Invalid API key");
        assert!(matches!(err, CloudError::InvalidApiKey));

        let err = classify_error("Rate limited, retry after 1s");
        assert!(matches!(err, CloudError::RateLimited { .. }));

        let err = classify_error("API overloaded");
        assert!(matches!(err, CloudError::Overloaded));

        let err = classify_error("request timed out");
        assert!(matches!(err, CloudError::Unreachable(_)));

        let err = classify_error("something random");
        assert!(matches!(err, CloudError::UnexpectedResponse(_)));
    }

    // -- Build tool result message -------------------------------------------

    #[test]
    fn test_build_tool_result_message() {
        let results = vec![
            ToolResult {
                tool_use_id: "toolu_01".to_string(),
                content: "{\"events\": []}".to_string(),
                is_error: false,
            },
            ToolResult {
                tool_use_id: "toolu_02".to_string(),
                content: "Error: not found".to_string(),
                is_error: true,
            },
        ];

        let msg = build_tool_result_message(results);
        assert_eq!(msg.role, "user");

        match &msg.content {
            MessageContent::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);

                match &blocks[0] {
                    ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                    } => {
                        assert_eq!(tool_use_id, "toolu_01");
                        assert_eq!(content, "{\"events\": []}");
                        assert_eq!(*is_error, None); // no error => None
                    }
                    _ => panic!("Expected ToolResult block"),
                }

                match &blocks[1] {
                    ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                    } => {
                        assert_eq!(tool_use_id, "toolu_02");
                        assert_eq!(content, "Error: not found");
                        assert_eq!(*is_error, Some(true));
                    }
                    _ => panic!("Expected ToolResult block"),
                }
            }
            _ => panic!("Expected Blocks content"),
        }
    }

    // -- OpenAI response parsing ---------------------------------------------

    #[test]
    fn test_openai_response_parsing() {
        let body = serde_json::json!({
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "The system is secure.",
                },
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": 500,
                "completion_tokens": 100,
                "total_tokens": 600,
            }
        });

        let resp = OpenAIProvider::parse_response(&body).unwrap();
        assert_eq!(resp.id, "chatcmpl-abc123");
        assert_eq!(resp.model, "gpt-4o");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert_eq!(resp.usage.input_tokens, 500);
        assert_eq!(resp.usage.output_tokens, 100);
        assert_eq!(resp.content.len(), 1);
        match &resp.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "The system is secure."),
            _ => panic!("Expected text block"),
        }
    }

    #[test]
    fn test_openai_tool_call_response_parsing() {
        let body = serde_json::json!({
            "id": "chatcmpl-tool",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc123",
                        "type": "function",
                        "function": {
                            "name": "query_events",
                            "arguments": "{\"time_range\":\"last_hour\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {
                "prompt_tokens": 300,
                "completion_tokens": 50,
            }
        });

        let resp = OpenAIProvider::parse_response(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        assert_eq!(resp.content.len(), 1);
        match &resp.content[0] {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_abc123");
                assert_eq!(name, "query_events");
                assert_eq!(input["time_range"], "last_hour");
            }
            _ => panic!("Expected ToolUse block"),
        }
    }

    // -- OpenAI tool conversion ----------------------------------------------

    #[test]
    fn test_openai_tool_conversion() {
        let anthropic_tools = vec![serde_json::json!({
            "name": "query_events",
            "description": "Query events",
            "input_schema": {
                "type": "object",
                "properties": {
                    "time_range": { "type": "string" }
                },
                "required": ["time_range"]
            }
        })];

        let openai_tools = OpenAIProvider::convert_tools_to_openai(&anthropic_tools);
        assert_eq!(openai_tools.len(), 1);
        assert_eq!(openai_tools[0]["type"], "function");
        assert_eq!(openai_tools[0]["function"]["name"], "query_events");
        assert_eq!(openai_tools[0]["function"]["parameters"]["type"], "object");
    }

    // -- Message content serialization ---------------------------------------

    #[test]
    fn test_message_content_text_serde() {
        let msg = Message {
            role: "user".to_string(),
            content: MessageContent::Text("Hello".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Message = serde_json::from_str(&json).unwrap();
        match parsed.content {
            MessageContent::Text(t) => assert_eq!(t, "Hello"),
            _ => panic!("Expected Text"),
        }
    }

    #[test]
    fn test_message_content_blocks_serde() {
        let msg = Message {
            role: "assistant".to_string(),
            content: MessageContent::Blocks(vec![
                ContentBlock::Text {
                    text: "I'll check.".to_string(),
                },
                ContentBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "query_events".to_string(),
                    input: serde_json::json!({"time_range": "last_hour"}),
                },
            ]),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Message = serde_json::from_str(&json).unwrap();
        match parsed.content {
            MessageContent::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);
            }
            _ => panic!("Expected Blocks"),
        }
    }

    // -- Content block serialization -----------------------------------------

    #[test]
    fn test_content_block_text_serde() {
        let block = ContentBlock::Text {
            text: "hello".to_string(),
        };
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "hello");
    }

    #[test]
    fn test_content_block_tool_use_serde() {
        let block = ContentBlock::ToolUse {
            id: "t1".to_string(),
            name: "query_events".to_string(),
            input: serde_json::json!({"time_range": "last_hour"}),
        };
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "tool_use");
        assert_eq!(json["id"], "t1");
        assert_eq!(json["name"], "query_events");
    }

    #[test]
    fn test_content_block_tool_result_serde() {
        let block = ContentBlock::ToolResult {
            tool_use_id: "t1".to_string(),
            content: "result data".to_string(),
            is_error: None,
        };
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "tool_result");
        assert_eq!(json["tool_use_id"], "t1");
        assert_eq!(json["content"], "result data");
        // is_error should be skipped when None
        assert!(json.get("is_error").is_none());
    }

    #[test]
    fn test_content_block_tool_result_with_error() {
        let block = ContentBlock::ToolResult {
            tool_use_id: "t1".to_string(),
            content: "Error: failed".to_string(),
            is_error: Some(true),
        };
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["is_error"], true);
    }
}
