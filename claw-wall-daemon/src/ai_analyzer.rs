use log::{info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Verdict returned by the AI security analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiVerdict {
    Allow,
    Block,
}

const SYSTEM_PROMPT: &str = "You are an AI security analyzer. Evaluate this system \
process/network connection initiated by an autonomous agent. Does this match known \
prompt-injection or data exfiltration behaviors? Respond strictly with 'ALLOW' or 'BLOCK'.";

const TIMEOUT: Duration = Duration::from_secs(5);

/// Async AI client for analyzing firewall events against LLM-based security heuristics.
pub struct AiAnalyzer {
    api_key: String,
    client: Client,
}

// --- Anthropic request/response types ---

#[derive(Serialize)]
struct AnthropicRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<Message<'a>>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
}

#[derive(Deserialize)]
struct AnthropicContent {
    text: String,
}

// --- OpenAI request/response types ---

#[derive(Serialize)]
struct OpenAiRequest<'a> {
    model: &'a str,
    messages: Vec<OpenAiMessage<'a>>,
    max_tokens: u32,
}

#[derive(Serialize)]
struct OpenAiMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessageResp,
}

#[derive(Deserialize)]
struct OpenAiMessageResp {
    content: String,
}

impl AiAnalyzer {
    /// Create a new AI analyzer with the given API key.
    pub fn new(api_key: String) -> Self {
        let client = Client::builder()
            .timeout(TIMEOUT)
            .build()
            .expect("Failed to build reqwest client");

        Self { api_key, client }
    }

    /// Analyze an event description and return Allow or Block.
    /// On ANY failure (timeout, rate limit, invalid key, parse error), defaults to Allow.
    pub async fn analyze(&self, event_description: &str) -> AiVerdict {
        if self.api_key.is_empty() {
            return AiVerdict::Allow;
        }

        let result = if self.api_key.starts_with("sk-ant-") {
            self.call_anthropic(event_description).await
        } else {
            self.call_openai(event_description).await
        };

        match result {
            Ok(text) => parse_verdict(&text),
            Err(e) => {
                warn!("AI analysis failed, defaulting to Allow: {e}");
                AiVerdict::Allow
            }
        }
    }

    async fn call_anthropic(&self, event_description: &str) -> Result<String, reqwest::Error> {
        let body = AnthropicRequest {
            model: "claude-sonnet-4-5-20250929",
            max_tokens: 16,
            system: SYSTEM_PROMPT,
            messages: vec![Message {
                role: "user",
                content: event_description,
            }],
        };

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let parsed: AnthropicResponse = resp.json().await?;
        Ok(parsed
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default())
    }

    async fn call_openai(&self, event_description: &str) -> Result<String, reqwest::Error> {
        let body = OpenAiRequest {
            model: "gpt-4o-mini",
            max_tokens: 16,
            messages: vec![
                OpenAiMessage {
                    role: "system",
                    content: SYSTEM_PROMPT,
                },
                OpenAiMessage {
                    role: "user",
                    content: event_description,
                },
            ],
        };

        let resp = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let parsed: OpenAiResponse = resp.json().await?;
        Ok(parsed
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default())
    }
}

/// Parse the AI response text into a verdict. Defaults to Allow on ambiguous responses.
fn parse_verdict(text: &str) -> AiVerdict {
    let normalized = text.trim().to_uppercase();
    if normalized.contains("BLOCK") {
        info!("AI verdict: BLOCK");
        AiVerdict::Block
    } else {
        info!("AI verdict: ALLOW");
        AiVerdict::Allow
    }
}
