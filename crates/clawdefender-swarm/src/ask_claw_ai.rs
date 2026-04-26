//! AI-powered Ask Rook assistant with dual-mode routing.
//!
//! Upgrades Ask Rook from pattern-based NLU to a real Claude-powered conversation
//! while preserving the existing pattern-based system as a fallback. Supports
//! three modes: Cloud (Claude API), LocalSlm, and Pattern (heuristic fallback).

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cloud_api::{
    extract_text, AgentRequest, CloudApiClient, Message, MessageContent,
};

// ---------------------------------------------------------------------------
// Configuration & mode
// ---------------------------------------------------------------------------

/// Routing mode for Ask Rook queries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AskClawMode {
    /// Route through Claude API with full tool-use capabilities.
    Cloud,
    /// Route through the local SLM model.
    LocalSlm,
    /// Fall back to keyword-based pattern matching.
    Pattern,
}

impl Default for AskClawMode {
    fn default() -> Self {
        Self::Pattern
    }
}

// ---------------------------------------------------------------------------
// Question classification
// ---------------------------------------------------------------------------

/// Classifies the type of question for context-aware routing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuestionType {
    /// "What's the status?" / "Is everything secure?"
    StatusQuery,
    /// "What happened at 3pm?" / "Show recent events"
    EventQuery,
    /// "Tell me about server X" / "What does this MCP server do?"
    ServerQuery,
    /// "What does this event mean?" / "Explain this finding"
    ExplainEvent,
    /// "Investigate event X" / "Deep dive into this alert"
    InvestigateRequest,
    /// "How do I configure policy?" / "Help me set up a rule"
    ConfigHelp,
    /// "Block this server" / "Enable strict mode"
    ActionRequest,
    /// General security question
    GeneralSecurity,
}

impl QuestionType {
    /// Classify a question based on keyword patterns.
    pub fn classify(input: &str) -> Self {
        let lower = input.to_lowercase();

        if lower.contains("investigate") || lower.contains("deep dive") || lower.contains("dig into") {
            return Self::InvestigateRequest;
        }
        if lower.contains("status") || lower.contains("overview") || lower.contains("everything ok")
            || lower.contains("secure?") || lower.contains("dashboard")
        {
            return Self::StatusQuery;
        }
        if lower.contains("event") || lower.contains("happened") || lower.contains("recent")
            || lower.contains("log") || lower.contains("activity")
        {
            return Self::EventQuery;
        }
        if lower.contains("server") && (lower.contains("tell me") || lower.contains("about") || lower.contains("what does")) {
            return Self::ServerQuery;
        }
        if lower.contains("explain") || lower.contains("what does") || lower.contains("mean")
            || lower.contains("why") || lower.contains("understand")
        {
            return Self::ExplainEvent;
        }
        if lower.contains("config") || lower.contains("setup") || lower.contains("rule")
            || lower.contains("policy") || lower.contains("how do i")
        {
            return Self::ConfigHelp;
        }
        if lower.contains("block") || lower.contains("allow") || lower.contains("enable")
            || lower.contains("disable") || lower.contains("execute") || lower.contains("run")
        {
            return Self::ActionRequest;
        }

        Self::GeneralSecurity
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A suggested action that requires user approval before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedAction {
    pub id: String,
    pub action_type: String,
    pub label: String,
    pub description: String,
    pub requires_confirmation: bool,
    pub params: serde_json::Value,
}

/// A reference to relevant context used in the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextReference {
    pub ref_type: String,
    pub id: String,
    pub label: String,
}

/// Summary of a tool call made during the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallSummary {
    pub tool_name: String,
    pub summary: String,
}

/// The full response from Ask Rook AI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AskClawResponse {
    pub message: String,
    pub turn_id: String,
    pub question_type: QuestionType,
    pub mode: AskClawMode,
    pub timestamp: DateTime<Utc>,
    pub suggested_actions: Vec<SuggestedAction>,
    pub context_refs: Vec<ContextReference>,
    pub tool_calls: Vec<ToolCallSummary>,
    pub tokens_used: Option<TokenUsage>,
    pub session_id: Option<String>,
    pub follow_up_suggestions: Vec<String>,
}

/// Token usage from a cloud API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

// ---------------------------------------------------------------------------
// Conversation state
// ---------------------------------------------------------------------------

/// A single turn in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationTurn {
    pub turn_id: String,
    pub role: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub question_type: Option<QuestionType>,
}

/// Pending actions awaiting user approval/rejection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingClawAction {
    pub id: String,
    pub action: SuggestedAction,
    pub status: PendingActionStatus,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Status of a pending action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PendingActionStatus {
    Pending,
    Approved,
    Rejected,
}

/// Active conversation with history and pending actions.
#[derive(Debug, Clone)]
pub struct ConversationState {
    pub id: String,
    pub turns: Vec<ConversationTurn>,
    pub pending_actions: Vec<PendingClawAction>,
    pub created_at: DateTime<Utc>,
    pub cloud_session_id: Option<String>,
}

impl ConversationState {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            turns: Vec::new(),
            pending_actions: Vec::new(),
            created_at: Utc::now(),
            cloud_session_id: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Context for enriching conversations
// ---------------------------------------------------------------------------

/// Pre-loaded context data to inject into the conversation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClawContext {
    pub daemon_running: Option<bool>,
    pub servers_proxied: Option<u32>,
    pub events_processed: Option<u64>,
    pub recent_events_summary: Option<String>,
    pub protection_score: Option<f64>,
    pub active_alerts_count: Option<u32>,
    pub active_model: Option<String>,
    pub custom_context: Option<String>,
}

impl ClawContext {
    /// Format context as a section for the system prompt.
    pub fn to_prompt_section(&self) -> String {
        let mut lines = Vec::new();
        lines.push("## Current System State".to_string());

        if let Some(running) = self.daemon_running {
            lines.push(format!(
                "- Daemon: {}",
                if running { "Running" } else { "Stopped" }
            ));
        }
        if let Some(count) = self.servers_proxied {
            lines.push(format!("- MCP servers proxied: {count}"));
        }
        if let Some(processed) = self.events_processed {
            lines.push(format!("- Events processed: {processed}"));
        }
        if let Some(score) = self.protection_score {
            lines.push(format!("- Protection score: {score:.0}/100"));
        }
        if let Some(alerts) = self.active_alerts_count {
            lines.push(format!("- Active alerts: {alerts}"));
        }
        if let Some(ref model) = self.active_model {
            lines.push(format!("- Active AI model: {model}"));
        }
        if let Some(ref events) = self.recent_events_summary {
            lines.push(format!("- Recent events: {events}"));
        }
        if let Some(ref custom) = self.custom_context {
            lines.push(format!("\n{custom}"));
        }

        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

/// Build the system prompt for cloud mode.
fn build_system_prompt(context: &ClawContext) -> String {
    let mut prompt = String::from(
        r#"You are Claw, the AI security assistant built into RookBot — a desktop app that protects users from rogue MCP (Model Context Protocol) servers.

## Your Role
- You help users understand their security posture, investigate suspicious events, and take protective actions.
- You are friendly, concise, and security-focused.
- When you detect a potential threat, explain it clearly and suggest concrete actions.
- Never downplay security risks, but avoid unnecessary alarm.

## Capabilities
- You can analyze security events, explain findings, and recommend actions.
- When you propose an action that modifies the system (blocking a server, changing a policy rule, etc.), wrap it in an [ACTION] tag so the UI can present it for user approval.

## Action Format
When proposing actions, use this format:
[ACTION type="<action_type>" label="<button_label>" confirm=<yes|no>]
<description of what this action does>
params: <JSON parameters>
[/ACTION]

Example:
[ACTION type="block_server" label="Block suspicious-server" confirm=yes]
Block the server 'suspicious-server' from all MCP clients to prevent further unauthorized access.
params: {"server_name": "suspicious-server"}
[/ACTION]

## Follow-up Suggestions
At the end of your response, you may suggest 2-3 follow-up questions the user might want to ask. Format them as:
[FOLLOWUP]What events happened in the last hour?[/FOLLOWUP]
[FOLLOWUP]Tell me more about this server[/FOLLOWUP]

"#,
    );

    let context_section = context.to_prompt_section();
    if !context_section.is_empty() {
        prompt.push_str(&context_section);
        prompt.push('\n');
    }

    prompt
}

// ---------------------------------------------------------------------------
// [ACTION] tag parsing
// ---------------------------------------------------------------------------

/// Extract `[ACTION ...]...[/ACTION]` blocks from LLM text output.
pub fn extract_actions(text: &str) -> Vec<SuggestedAction> {
    let mut results = Vec::new();
    let mut remaining = text;

    while let Some(start_idx) = remaining.find("[ACTION ") {
        let after_tag = &remaining[start_idx..];

        // Find closing bracket of opening tag
        let Some(tag_end) = after_tag.find(']') else {
            remaining = &remaining[start_idx + 8..];
            continue;
        };

        let tag_line = &after_tag[..tag_end];

        // Find the end tag
        let Some(end_idx) = after_tag.find("[/ACTION]") else {
            remaining = &remaining[start_idx + tag_end..];
            continue;
        };

        let body = after_tag[tag_end + 1..end_idx].trim();

        // Parse tag attributes
        let action_type = parse_tag_attr_quoted(tag_line, "type").unwrap_or_else(|| "unknown".to_string());
        let label = parse_tag_attr_quoted(tag_line, "label").unwrap_or_else(|| "Execute".to_string());
        let confirm = parse_tag_attr_simple(tag_line, "confirm")
            .map(|v| v == "yes" || v == "true")
            .unwrap_or(true);

        // Parse body for description and params
        let (description, params) = parse_action_body(body);

        results.push(SuggestedAction {
            id: format!("action-{}", Uuid::new_v4().as_simple()),
            action_type,
            label,
            description,
            requires_confirmation: confirm,
            params,
        });

        remaining = &remaining[start_idx + end_idx + 9..];
    }

    results
}

/// Extract `[FOLLOWUP]...[/FOLLOWUP]` blocks from LLM text output.
pub fn extract_followups(text: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut remaining = text;

    while let Some(start) = remaining.find("[FOLLOWUP]") {
        let after = &remaining[start + 10..];
        if let Some(end) = after.find("[/FOLLOWUP]") {
            let suggestion = after[..end].trim().to_string();
            if !suggestion.is_empty() {
                results.push(suggestion);
            }
            remaining = &after[end + 11..];
        } else {
            break;
        }
    }

    results
}

/// Strip [ACTION] and [FOLLOWUP] tags from the response text to get the clean message.
pub fn strip_tags(text: &str) -> String {
    let mut result = text.to_string();

    // Remove [ACTION ...]...[/ACTION] blocks
    while let Some(start) = result.find("[ACTION ") {
        if let Some(end) = result[start..].find("[/ACTION]") {
            result = format!("{}{}", &result[..start], &result[start + end + 9..]);
        } else {
            break;
        }
    }

    // Remove [FOLLOWUP]...[/FOLLOWUP] blocks
    while let Some(start) = result.find("[FOLLOWUP]") {
        if let Some(end) = result[start..].find("[/FOLLOWUP]") {
            result = format!("{}{}", &result[..start], &result[start + end + 11..]);
        } else {
            break;
        }
    }

    result.trim().to_string()
}

/// Parse a quoted attribute from a tag line like `[ACTION type="block_server" label="Block"]`.
fn parse_tag_attr_quoted(tag: &str, key: &str) -> Option<String> {
    let search = format!("{key}=\"");
    let idx = tag.find(&search)?;
    let after = &tag[idx + search.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

/// Parse an unquoted attribute from a tag line like `[ACTION confirm=yes]`.
fn parse_tag_attr_simple(tag: &str, key: &str) -> Option<String> {
    let search = format!("{key}=");
    let idx = tag.find(&search)?;
    let after = &tag[idx + search.len()..];
    // Value ends at next space, quote, or bracket
    let value: String = after
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ']' && *c != '"')
        .collect();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Parse the body of an [ACTION] block into description and params.
fn parse_action_body(body: &str) -> (String, serde_json::Value) {
    // Look for a "params:" line
    if let Some(params_idx) = body.find("params:") {
        let description = body[..params_idx].trim().to_string();
        let params_str = body[params_idx + 7..].trim();
        let params = serde_json::from_str(params_str).unwrap_or(serde_json::Value::Null);
        (description, params)
    } else {
        (body.to_string(), serde_json::Value::Null)
    }
}

// ---------------------------------------------------------------------------
// AskClawAI manager
// ---------------------------------------------------------------------------

/// The main Ask Rook AI manager that routes queries through the appropriate mode.
pub struct AskClawAI {
    mode: AskClawMode,
    context: ClawContext,
    conversations: HashMap<String, ConversationState>,
    active_conversation_id: Option<String>,
    cloud_client: Option<Arc<CloudApiClient>>,
    model: String,
}

impl AskClawAI {
    /// Create a new AskClawAI instance.
    pub fn new(mode: AskClawMode, cloud_client: Option<Arc<CloudApiClient>>, model: String) -> Self {
        Self {
            mode,
            context: ClawContext::default(),
            conversations: HashMap::new(),
            active_conversation_id: None,
            cloud_client,
            model,
        }
    }

    /// Get the current routing mode.
    pub fn mode(&self) -> &AskClawMode {
        &self.mode
    }

    /// Set the routing mode.
    pub fn set_mode(&mut self, mode: AskClawMode) {
        self.mode = mode;
    }

    /// Set the cloud API client.
    pub fn set_cloud_client(&mut self, client: Option<Arc<CloudApiClient>>) {
        self.cloud_client = client;
    }

    /// Update the current context.
    pub fn set_context(&mut self, context: ClawContext) {
        self.context = context;
    }

    /// Get the current context.
    pub fn context(&self) -> &ClawContext {
        &self.context
    }

    /// Get or create the active conversation.
    fn ensure_conversation(&mut self) -> &mut ConversationState {
        if self.active_conversation_id.is_none()
            || !self
                .conversations
                .contains_key(self.active_conversation_id.as_deref().unwrap_or(""))
        {
            let conv = ConversationState::new();
            let id = conv.id.clone();
            self.conversations.insert(id.clone(), conv);
            self.active_conversation_id = Some(id);
        }

        let id = self.active_conversation_id.as_ref().unwrap();
        self.conversations.get_mut(id).unwrap()
    }

    /// Ask a question and get a response.
    pub async fn ask(&mut self, input: &str) -> Result<AskClawResponse> {
        let question_type = QuestionType::classify(input);
        let turn_id = format!("turn-{}", Uuid::new_v4().as_simple());

        // Record the user turn
        let conv = self.ensure_conversation();
        conv.turns.push(ConversationTurn {
            turn_id: turn_id.clone(),
            role: "user".to_string(),
            content: input.to_string(),
            timestamp: Utc::now(),
            question_type: Some(question_type.clone()),
        });

        let response = match self.mode {
            AskClawMode::Cloud => self.ask_cloud(input, &turn_id, &question_type).await,
            AskClawMode::LocalSlm | AskClawMode::Pattern => {
                self.ask_pattern(input, &turn_id, &question_type)
            }
        };

        match response {
            Ok(resp) => {
                // Record the assistant turn
                let conv = self.ensure_conversation();
                conv.turns.push(ConversationTurn {
                    turn_id: resp.turn_id.clone(),
                    role: "assistant".to_string(),
                    content: resp.message.clone(),
                    timestamp: resp.timestamp,
                    question_type: Some(resp.question_type.clone()),
                });

                // Store any pending actions
                for action in &resp.suggested_actions {
                    let pending = PendingClawAction {
                        id: action.id.clone(),
                        action: action.clone(),
                        status: PendingActionStatus::Pending,
                        created_at: Utc::now(),
                        resolved_at: None,
                    };
                    let conv = self.ensure_conversation();
                    conv.pending_actions.push(pending);
                }

                Ok(resp)
            }
            Err(e) => {
                // On cloud failure, try pattern fallback
                if self.mode == AskClawMode::Cloud {
                    tracing::warn!("Cloud mode failed, falling back to pattern: {e}");
                    self.ask_pattern(input, &turn_id, &question_type)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Cloud mode: send to Claude API.
    async fn ask_cloud(
        &mut self,
        _input: &str,
        turn_id: &str,
        question_type: &QuestionType,
    ) -> Result<AskClawResponse> {
        let client = self.cloud_client.clone().ok_or_else(|| {
            anyhow::anyhow!("Cloud client not configured")
        })?;

        let system_prompt = build_system_prompt(&self.context);

        // Build message history from conversation turns
        let conv = self.ensure_conversation();
        let mut messages = Vec::new();

        // Include recent conversation history (sliding window)
        let window_start = if conv.turns.len() > 20 {
            conv.turns.len() - 20
        } else {
            0
        };

        for turn in &conv.turns[window_start..] {
            messages.push(Message {
                role: turn.role.clone(),
                content: MessageContent::Text(turn.content.clone()),
            });
        }

        let session_id = conv.cloud_session_id.clone();

        let request = AgentRequest {
            model: self.model.clone(),
            system: system_prompt,
            messages,
            tools: Vec::new(), // Ask Rook doesn't use tools directly; actions are tag-based
            max_tokens: 2048,
            stream: false,
        };

        let response = client.send(&request).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let raw_text = extract_text(&response);

        // Parse structured output
        let suggested_actions = extract_actions(&raw_text);
        let follow_ups = extract_followups(&raw_text);
        let clean_message = strip_tags(&raw_text);

        let tokens = TokenUsage {
            input_tokens: response.usage.input_tokens,
            output_tokens: response.usage.output_tokens,
        };

        Ok(AskClawResponse {
            message: clean_message,
            turn_id: turn_id.to_string(),
            question_type: question_type.clone(),
            mode: AskClawMode::Cloud,
            timestamp: Utc::now(),
            suggested_actions,
            context_refs: Vec::new(),
            tool_calls: Vec::new(),
            tokens_used: Some(tokens),
            session_id,
            follow_up_suggestions: follow_ups,
        })
    }

    /// Pattern/local fallback mode.
    fn ask_pattern(
        &self,
        _input: &str,
        turn_id: &str,
        question_type: &QuestionType,
    ) -> Result<AskClawResponse> {
        let message = match question_type {
            QuestionType::StatusQuery => {
                let mut parts = vec!["Here's your current security status:".to_string()];
                if let Some(running) = self.context.daemon_running {
                    parts.push(format!(
                        "- Daemon: {}",
                        if running { "Running" } else { "Not running" }
                    ));
                }
                if let Some(score) = self.context.protection_score {
                    parts.push(format!("- Protection score: {score:.0}/100"));
                }
                if let Some(alerts) = self.context.active_alerts_count {
                    parts.push(format!("- Active alerts: {alerts}"));
                }
                if let Some(servers) = self.context.servers_proxied {
                    parts.push(format!("- Servers protected: {servers}"));
                }
                if parts.len() == 1 {
                    parts.push("- No detailed status available. Make sure the daemon is running.".to_string());
                }
                parts.join("\n")
            }
            QuestionType::EventQuery => {
                if let Some(ref summary) = self.context.recent_events_summary {
                    format!("Recent activity summary:\n{summary}")
                } else {
                    "No recent events to display. Events will appear here once the daemon starts monitoring MCP traffic.".to_string()
                }
            }
            QuestionType::ActionRequest => {
                "I understand you want to take an action. In pattern mode, I can only suggest you navigate to the relevant page. For AI-powered actions, configure a Cloud API key in Settings.".to_string()
            }
            QuestionType::InvestigateRequest => {
                "To run a deep investigation, I need cloud AI capabilities. Please configure an API key in Settings > Cloud AI, then I can investigate events and provide detailed analysis.".to_string()
            }
            QuestionType::ConfigHelp => {
                "For configuration help:\n- Policy rules: Go to the Policy page to add, edit, or remove rules\n- Server management: Use the Servers page to wrap/unwrap MCP servers\n- AI settings: Configure models in Settings > AI Analysis\n\nFor more detailed guidance, enable Cloud AI mode.".to_string()
            }
            QuestionType::ServerQuery => {
                "To see details about your MCP servers, visit the Servers page. Each server card shows its trust level, event count, and protection status.".to_string()
            }
            QuestionType::ExplainEvent => {
                "I can provide basic explanations in pattern mode. For detailed AI-powered analysis of events, configure a Cloud API key in Settings.".to_string()
            }
            QuestionType::GeneralSecurity => {
                "I'm Claw, your security assistant. I can help with:\n- Checking your security status\n- Explaining events and findings\n- Managing MCP server protection\n- Investigating suspicious activity\n\nFor the best experience, configure Cloud AI in Settings.".to_string()
            }
        };

        Ok(AskClawResponse {
            message,
            turn_id: turn_id.to_string(),
            question_type: question_type.clone(),
            mode: if self.mode == AskClawMode::LocalSlm {
                AskClawMode::LocalSlm
            } else {
                AskClawMode::Pattern
            },
            timestamp: Utc::now(),
            suggested_actions: Vec::new(),
            context_refs: Vec::new(),
            tool_calls: Vec::new(),
            tokens_used: None,
            session_id: None,
            follow_up_suggestions: vec![
                "What's my security status?".to_string(),
                "Show recent events".to_string(),
            ],
        })
    }

    /// Approve a pending action by ID.
    pub fn approve_action(&mut self, action_id: &str) -> Result<SuggestedAction> {
        let conv = self.ensure_conversation();
        for pending in &mut conv.pending_actions {
            if pending.id == action_id && pending.status == PendingActionStatus::Pending {
                pending.status = PendingActionStatus::Approved;
                pending.resolved_at = Some(Utc::now());
                return Ok(pending.action.clone());
            }
        }
        bail!("Action '{}' not found or already resolved", action_id)
    }

    /// Reject a pending action by ID.
    pub fn reject_action(&mut self, action_id: &str) -> Result<()> {
        let conv = self.ensure_conversation();
        for pending in &mut conv.pending_actions {
            if pending.id == action_id && pending.status == PendingActionStatus::Pending {
                pending.status = PendingActionStatus::Rejected;
                pending.resolved_at = Some(Utc::now());
                return Ok(());
            }
        }
        bail!("Action '{}' not found or already resolved", action_id)
    }

    /// List all conversations with basic metadata.
    pub fn list_conversations(&self) -> Vec<ConversationSummary> {
        let mut summaries: Vec<ConversationSummary> = self
            .conversations
            .values()
            .map(|conv| {
                let last_message = conv.turns.last().map(|t| t.content.clone());
                let first_user_msg = conv
                    .turns
                    .iter()
                    .find(|t| t.role == "user")
                    .map(|t| t.content.clone());
                ConversationSummary {
                    id: conv.id.clone(),
                    created_at: conv.created_at,
                    turn_count: conv.turns.len(),
                    pending_actions: conv
                        .pending_actions
                        .iter()
                        .filter(|a| a.status == PendingActionStatus::Pending)
                        .count(),
                    preview: first_user_msg.or(last_message).unwrap_or_default(),
                    is_active: Some(&conv.id) == self.active_conversation_id.as_ref(),
                }
            })
            .collect();

        summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        summaries
    }

    /// Start a new conversation, making it the active one.
    pub fn new_conversation(&mut self) -> String {
        let conv = ConversationState::new();
        let id = conv.id.clone();
        self.conversations.insert(id.clone(), conv);
        self.active_conversation_id = Some(id.clone());
        id
    }

    /// Switch to an existing conversation by ID.
    pub fn switch_conversation(&mut self, id: &str) -> Result<()> {
        if self.conversations.contains_key(id) {
            self.active_conversation_id = Some(id.to_string());
            Ok(())
        } else {
            bail!("Conversation '{}' not found", id)
        }
    }

    /// Get the active conversation ID.
    pub fn active_conversation_id(&self) -> Option<&str> {
        self.active_conversation_id.as_deref()
    }
}

/// Summary of a conversation for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub turn_count: usize,
    pub pending_actions: usize,
    pub preview: String,
    pub is_active: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // QuestionType classification
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_status() {
        assert_eq!(QuestionType::classify("What's the status?"), QuestionType::StatusQuery);
        assert_eq!(QuestionType::classify("Is everything secure?"), QuestionType::StatusQuery);
        assert_eq!(QuestionType::classify("Give me an overview"), QuestionType::StatusQuery);
    }

    #[test]
    fn test_classify_event() {
        assert_eq!(QuestionType::classify("What happened at 3pm?"), QuestionType::EventQuery);
        assert_eq!(QuestionType::classify("Show recent events"), QuestionType::EventQuery);
        assert_eq!(QuestionType::classify("Check the activity log"), QuestionType::EventQuery);
    }

    #[test]
    fn test_classify_investigate() {
        assert_eq!(
            QuestionType::classify("Investigate this event"),
            QuestionType::InvestigateRequest
        );
        assert_eq!(
            QuestionType::classify("Deep dive into alert-123"),
            QuestionType::InvestigateRequest
        );
    }

    #[test]
    fn test_classify_action() {
        assert_eq!(QuestionType::classify("Block this server"), QuestionType::ActionRequest);
        assert_eq!(QuestionType::classify("Enable strict mode"), QuestionType::ActionRequest);
    }

    #[test]
    fn test_classify_config_help() {
        assert_eq!(
            QuestionType::classify("How do I add a rule?"),
            QuestionType::ConfigHelp
        );
        assert_eq!(
            QuestionType::classify("Help me setup policy"),
            QuestionType::ConfigHelp
        );
    }

    #[test]
    fn test_classify_general() {
        assert_eq!(
            QuestionType::classify("What is MCP?"),
            QuestionType::GeneralSecurity
        );
    }

    // -----------------------------------------------------------------------
    // [ACTION] tag parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_actions_basic() {
        let text = r#"Here's what I recommend:
[ACTION type="block_server" label="Block evil-server" confirm=yes]
Block the server 'evil-server' to prevent unauthorized access.
params: {"server_name": "evil-server"}
[/ACTION]
Let me know if you want to proceed."#;

        let actions = extract_actions(text);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_type, "block_server");
        assert_eq!(actions[0].label, "Block evil-server");
        assert!(actions[0].requires_confirmation);
        assert_eq!(
            actions[0].params["server_name"].as_str().unwrap(),
            "evil-server"
        );
    }

    #[test]
    fn test_extract_actions_multiple() {
        let text = r#"I found two issues:
[ACTION type="add_rule" label="Add deny rule" confirm=yes]
Add a deny rule for sensitive resources.
params: {"rule": "deny_sensitive"}
[/ACTION]
Also:
[ACTION type="enable_guard" label="Enable anomaly guard" confirm=no]
Enable the behavioral anomaly guard.
params: {"guard": "anomaly"}
[/ACTION]"#;

        let actions = extract_actions(text);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].action_type, "add_rule");
        assert!(actions[0].requires_confirmation);
        assert_eq!(actions[1].action_type, "enable_guard");
        assert!(!actions[1].requires_confirmation);
    }

    #[test]
    fn test_extract_actions_no_params() {
        let text = r#"[ACTION type="navigate" label="Go to Settings" confirm=no]
Open the Settings page for configuration.
[/ACTION]"#;

        let actions = extract_actions(text);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_type, "navigate");
        assert!(actions[0].params.is_null());
        assert!(actions[0].description.contains("Settings page"));
    }

    #[test]
    fn test_extract_actions_empty_text() {
        let actions = extract_actions("No actions here");
        assert!(actions.is_empty());
    }

    // -----------------------------------------------------------------------
    // [FOLLOWUP] tag parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_followups() {
        let text = r#"Here's your status.
[FOLLOWUP]What events happened recently?[/FOLLOWUP]
[FOLLOWUP]Show me server details[/FOLLOWUP]"#;

        let followups = extract_followups(text);
        assert_eq!(followups.len(), 2);
        assert_eq!(followups[0], "What events happened recently?");
        assert_eq!(followups[1], "Show me server details");
    }

    #[test]
    fn test_extract_followups_empty() {
        let followups = extract_followups("No followups here");
        assert!(followups.is_empty());
    }

    // -----------------------------------------------------------------------
    // Tag stripping
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_tags() {
        let text = r#"Here's the analysis.
[ACTION type="test" label="Test" confirm=yes]
Do something.
[/ACTION]
More text.
[FOLLOWUP]Ask me more[/FOLLOWUP]"#;

        let clean = strip_tags(text);
        assert!(clean.contains("Here's the analysis."));
        assert!(clean.contains("More text."));
        assert!(!clean.contains("[ACTION"));
        assert!(!clean.contains("[FOLLOWUP]"));
    }

    // -----------------------------------------------------------------------
    // Context formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_prompt_section() {
        let ctx = ClawContext {
            daemon_running: Some(true),
            servers_proxied: Some(3),
            events_processed: Some(1500),
            protection_score: Some(85.5),
            active_alerts_count: Some(2),
            active_model: Some("claude-sonnet-4-20250514".to_string()),
            recent_events_summary: None,
            custom_context: None,
        };

        let section = ctx.to_prompt_section();
        assert!(section.contains("Daemon: Running"));
        assert!(section.contains("MCP servers proxied: 3"));
        assert!(section.contains("Protection score: 86/100"));
        assert!(section.contains("Active alerts: 2"));
    }

    #[test]
    fn test_context_empty() {
        let ctx = ClawContext::default();
        let section = ctx.to_prompt_section();
        assert!(section.contains("Current System State"));
    }

    // -----------------------------------------------------------------------
    // AskClawAI — pattern mode
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ask_pattern_mode() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());
        ai.set_context(ClawContext {
            daemon_running: Some(true),
            protection_score: Some(90.0),
            active_alerts_count: Some(0),
            servers_proxied: Some(2),
            ..Default::default()
        });

        let resp = ai.ask("What's the status?").await.unwrap();
        assert_eq!(resp.question_type, QuestionType::StatusQuery);
        assert_eq!(resp.mode, AskClawMode::Pattern);
        assert!(resp.message.contains("Daemon: Running"));
        assert!(resp.message.contains("Protection score: 90/100"));
    }

    #[tokio::test]
    async fn test_ask_pattern_events() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());
        ai.set_context(ClawContext {
            recent_events_summary: Some("3 events in the last hour".to_string()),
            ..Default::default()
        });

        let resp = ai.ask("Show recent events").await.unwrap();
        assert_eq!(resp.question_type, QuestionType::EventQuery);
        assert!(resp.message.contains("3 events in the last hour"));
    }

    #[tokio::test]
    async fn test_ask_pattern_general() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());
        let resp = ai.ask("What is MCP?").await.unwrap();
        assert_eq!(resp.question_type, QuestionType::GeneralSecurity);
        assert!(resp.message.contains("security assistant"));
    }

    // -----------------------------------------------------------------------
    // Conversation management
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_conversation_tracking() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());

        ai.ask("What's the status?").await.unwrap();
        ai.ask("Show events").await.unwrap();

        let conversations = ai.list_conversations();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].turn_count, 4); // 2 user + 2 assistant
        assert!(conversations[0].is_active);
    }

    #[tokio::test]
    async fn test_new_conversation() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());

        ai.ask("First question").await.unwrap();
        let first_id = ai.active_conversation_id().unwrap().to_string();

        let second_id = ai.new_conversation();
        assert_ne!(first_id, second_id);

        ai.ask("Second question").await.unwrap();

        let conversations = ai.list_conversations();
        assert_eq!(conversations.len(), 2);
    }

    #[tokio::test]
    async fn test_switch_conversation() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());

        ai.ask("First").await.unwrap();
        let first_id = ai.active_conversation_id().unwrap().to_string();

        ai.new_conversation();
        ai.ask("Second").await.unwrap();

        ai.switch_conversation(&first_id).unwrap();
        assert_eq!(ai.active_conversation_id().unwrap(), first_id);
    }

    #[tokio::test]
    async fn test_switch_nonexistent_conversation() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());
        assert!(ai.switch_conversation("nonexistent").is_err());
    }

    // -----------------------------------------------------------------------
    // Pending action management
    // -----------------------------------------------------------------------

    #[test]
    fn test_approve_action() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());
        let conv = ai.ensure_conversation();
        conv.pending_actions.push(PendingClawAction {
            id: "action-1".to_string(),
            action: SuggestedAction {
                id: "action-1".to_string(),
                action_type: "block_server".to_string(),
                label: "Block".to_string(),
                description: "Block a server".to_string(),
                requires_confirmation: true,
                params: serde_json::Value::Null,
            },
            status: PendingActionStatus::Pending,
            created_at: Utc::now(),
            resolved_at: None,
        });

        let approved = ai.approve_action("action-1").unwrap();
        assert_eq!(approved.action_type, "block_server");
    }

    #[test]
    fn test_reject_action() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());
        let conv = ai.ensure_conversation();
        conv.pending_actions.push(PendingClawAction {
            id: "action-2".to_string(),
            action: SuggestedAction {
                id: "action-2".to_string(),
                action_type: "enable_guard".to_string(),
                label: "Enable".to_string(),
                description: "Enable guard".to_string(),
                requires_confirmation: true,
                params: serde_json::Value::Null,
            },
            status: PendingActionStatus::Pending,
            created_at: Utc::now(),
            resolved_at: None,
        });

        ai.reject_action("action-2").unwrap();
        // Trying again should fail
        assert!(ai.reject_action("action-2").is_err());
    }

    #[test]
    fn test_approve_nonexistent_action() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());
        ai.ensure_conversation();
        assert!(ai.approve_action("nonexistent").is_err());
    }

    // -----------------------------------------------------------------------
    // Mode and context
    // -----------------------------------------------------------------------

    #[test]
    fn test_mode_default() {
        assert_eq!(AskClawMode::default(), AskClawMode::Pattern);
    }

    #[test]
    fn test_set_mode() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());
        assert_eq!(*ai.mode(), AskClawMode::Pattern);
        ai.set_mode(AskClawMode::Cloud);
        assert_eq!(*ai.mode(), AskClawMode::Cloud);
    }

    // -----------------------------------------------------------------------
    // System prompt
    // -----------------------------------------------------------------------

    #[test]
    fn test_system_prompt_contains_persona() {
        let ctx = ClawContext::default();
        let prompt = build_system_prompt(&ctx);
        assert!(prompt.contains("You are Claw"));
        assert!(prompt.contains("RookBot"));
        assert!(prompt.contains("[ACTION"));
        assert!(prompt.contains("[FOLLOWUP]"));
    }

    #[test]
    fn test_system_prompt_includes_context() {
        let ctx = ClawContext {
            daemon_running: Some(true),
            servers_proxied: Some(5),
            ..Default::default()
        };
        let prompt = build_system_prompt(&ctx);
        assert!(prompt.contains("Daemon: Running"));
        assert!(prompt.contains("MCP servers proxied: 5"));
    }

    // -----------------------------------------------------------------------
    // Quoted attribute parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_tag_attr_quoted() {
        let tag = r#"[ACTION type="block_server" label="Block It" confirm=yes"#;
        assert_eq!(
            parse_tag_attr_quoted(tag, "type"),
            Some("block_server".to_string())
        );
        assert_eq!(
            parse_tag_attr_quoted(tag, "label"),
            Some("Block It".to_string())
        );
        assert_eq!(parse_tag_attr_quoted(tag, "nonexistent"), None);
    }

    #[test]
    fn test_parse_tag_attr_simple() {
        let tag = r#"[ACTION type="test" confirm=yes]"#;
        assert_eq!(
            parse_tag_attr_simple(tag, "confirm"),
            Some("yes".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // Follow-up suggestions in pattern mode
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_pattern_mode_has_followups() {
        let mut ai = AskClawAI::new(AskClawMode::Pattern, None, String::new());
        let resp = ai.ask("Hello").await.unwrap();
        assert!(!resp.follow_up_suggestions.is_empty());
    }
}
