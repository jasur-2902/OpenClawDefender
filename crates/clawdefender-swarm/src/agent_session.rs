//! Multi-turn agent session system with tool-use loops, history management,
//! and session persistence.
//!
//! This module provides [`AgentSessionManager`] which orchestrates conversations
//! with a cloud LLM provider, executing tool calls in a loop until the model
//! produces a final response or hits the iteration limit.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::cloud_api::{
    extract_text, extract_tool_calls, build_tool_result_message,
    AgentRequest, AgentResponse, CloudApiClient, ContentBlock, Message,
    MessageContent,
};
use crate::tool_sandbox::ToolSandbox;
use crate::tools::get_all_tool_definitions;

/// Maximum tool-use loop iterations per turn.
const MAX_TOOL_ITERATIONS: usize = 15;

/// Maximum messages to include in a request (sliding window).
const MAX_MESSAGES_IN_REQUEST: usize = 20;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The purpose of an agent session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionType {
    Scan { playbook: String },
    Investigate { event_id: String },
    Chat,
    Report { report_type: String },
}

/// A security finding discovered during a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub source_tool: Option<String>,
}

/// An action proposed by the agent that requires user approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAction {
    pub id: String,
    pub action_type: String,
    pub description: String,
    pub proposed_by: String,
    pub created_at: String,
    pub status: ActionStatus,
    pub details: serde_json::Value,
}

/// Status of a pending action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionStatus {
    Pending,
    Approved,
    Rejected,
}

/// Summary of session state for status queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    pub id: String,
    pub session_type: SessionType,
    pub created_at: String,
    pub message_count: usize,
    pub tool_call_count: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub estimated_cost: f64,
    pub findings_count: usize,
    pub pending_actions_count: usize,
    pub is_active: bool,
}

/// Brief summary of a session for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub session_type: SessionType,
    pub created_at: String,
    pub summary: String,
    pub message_count: usize,
    pub estimated_cost: f64,
}

/// Result of a single agent turn (user message -> agent response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTurnResult {
    pub text: String,
    pub tool_calls_made: Vec<ToolCallSummary>,
    pub findings: Vec<Finding>,
    pub pending_actions: Vec<PendingAction>,
    pub tokens_used: TokenUsage,
}

/// Summary of a single tool call within a turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallSummary {
    pub tool_name: String,
    pub input_summary: String,
    pub success: bool,
}

/// Token counts for a turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

// ---------------------------------------------------------------------------
// AgentSession — persistent session state
// ---------------------------------------------------------------------------

/// A complete agent session with conversation history and accumulated state.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentSession {
    pub id: String,
    pub session_type: SessionType,
    pub created_at: String,

    // Conversation state
    pub messages: Vec<Message>,
    pub tool_calls: Vec<ToolCallSummary>,
    pub findings: Vec<Finding>,
    pub pending_actions: Vec<PendingAction>,

    // Cost tracking
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub estimated_cost: f64,

    // Context
    pub initial_briefing: String,
    pub context_updates: Vec<String>,

    // State
    pub is_active: bool,
}

// ---------------------------------------------------------------------------
// AgentSessionManager
// ---------------------------------------------------------------------------

/// Manages agent sessions: creation, message sending with tool-use loops,
/// persistence, and lifecycle operations.
pub struct AgentSessionManager {
    sessions: Mutex<HashMap<String, AgentSession>>,
    cloud_client: Arc<CloudApiClient>,
    tool_sandbox: Arc<ToolSandbox>,
    model: String,
    sessions_dir: PathBuf,
}

impl AgentSessionManager {
    /// Create a new session manager.
    pub fn new(
        cloud_client: Arc<CloudApiClient>,
        tool_sandbox: Arc<ToolSandbox>,
        model: String,
        sessions_dir: PathBuf,
    ) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            cloud_client,
            tool_sandbox,
            model,
            sessions_dir,
        }
    }

    /// Get a reference to the cloud API client.
    pub fn cloud_client(&self) -> &Arc<CloudApiClient> {
        &self.cloud_client
    }

    /// Start a new agent session. Returns the session ID.
    pub async fn start_session(
        &self,
        session_type: SessionType,
        initial_briefing: String,
        initial_query: Option<String>,
    ) -> Result<String> {
        let session_id = format!("agent-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().to_rfc3339();

        let mut messages = Vec::new();
        if let Some(query) = initial_query {
            messages.push(Message {
                role: "user".to_string(),
                content: MessageContent::Text(query),
            });
        }

        let session = AgentSession {
            id: session_id.clone(),
            session_type,
            created_at: now,
            messages,
            tool_calls: Vec::new(),
            findings: Vec::new(),
            pending_actions: Vec::new(),
            input_tokens: 0,
            output_tokens: 0,
            estimated_cost: 0.0,
            initial_briefing,
            context_updates: Vec::new(),
            is_active: true,
        };

        self.save_session(&session).await?;

        let mut sessions = self.sessions.lock().await;
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    /// Send a user message in an existing session and run the tool-use loop.
    pub async fn send_message(
        &self,
        session_id: &str,
        message: &str,
    ) -> Result<AgentTurnResult> {
        // Get session (clone out to release lock)
        let mut session = {
            let sessions = self.sessions.lock().await;
            match sessions.get(session_id) {
                Some(s) => {
                    if !s.is_active {
                        bail!("Session {} is no longer active", session_id);
                    }
                    // Clone fields we need; we'll reconstruct
                    AgentSession {
                        id: s.id.clone(),
                        session_type: s.session_type.clone(),
                        created_at: s.created_at.clone(),
                        messages: s.messages.clone(),
                        tool_calls: s.tool_calls.clone(),
                        findings: s.findings.clone(),
                        pending_actions: s.pending_actions.clone(),
                        input_tokens: s.input_tokens,
                        output_tokens: s.output_tokens,
                        estimated_cost: s.estimated_cost,
                        initial_briefing: s.initial_briefing.clone(),
                        context_updates: s.context_updates.clone(),
                        is_active: s.is_active,
                    }
                }
                None => {
                    // Try loading from disk
                    drop(sessions);
                    let loaded = self.load_session(session_id).await?;
                    if !loaded.is_active {
                        bail!("Session {} is no longer active", session_id);
                    }
                    loaded
                }
            }
        };

        // Add user message
        session.messages.push(Message {
            role: "user".to_string(),
            content: MessageContent::Text(message.to_string()),
        });

        // Determine system prompt
        let system = if session.context_updates.is_empty() {
            session.initial_briefing.clone()
        } else {
            session.context_updates.last().unwrap().clone()
        };

        // Build tool definitions for the API
        let tools = tool_definitions_to_api_format();

        // Track turn-level stats
        let mut turn_tool_calls: Vec<ToolCallSummary> = Vec::new();
        let mut turn_findings: Vec<Finding> = Vec::new();
        let mut turn_pending_actions: Vec<PendingAction> = Vec::new();
        let mut turn_input_tokens: u64 = 0;
        let mut turn_output_tokens: u64 = 0;
        let mut final_text = String::new();

        // Tool-use loop
        for _iteration in 0..MAX_TOOL_ITERATIONS {
            // Build request with sliding window of messages
            let request_messages = sliding_window(&session.messages, MAX_MESSAGES_IN_REQUEST);

            let request = AgentRequest {
                model: self.model.clone(),
                system: system.clone(),
                messages: request_messages,
                tools: tools.clone(),
                max_tokens: 4096,
                stream: false,
            };

            // Send to cloud
            let response = self
                .cloud_client
                .send(&request)
                .await
                .map_err(|e| anyhow::anyhow!("Cloud API error: {}", e))?;

            // Accumulate tokens
            turn_input_tokens += response.usage.input_tokens;
            turn_output_tokens += response.usage.output_tokens;

            // Check if the response contains tool calls
            let tool_calls = extract_tool_calls(&response);

            if tool_calls.is_empty() {
                // No tool calls — this is the final response
                final_text = extract_text(&response);

                // Add assistant message to history
                session.messages.push(Message {
                    role: "assistant".to_string(),
                    content: response_to_message_content(&response),
                });
                break;
            }

            // Add the assistant message (with tool_use blocks) to history
            session.messages.push(Message {
                role: "assistant".to_string(),
                content: response_to_message_content(&response),
            });

            // Execute each tool call
            let mut tool_results = Vec::new();
            for tc in &tool_calls {
                let result = self
                    .tool_sandbox
                    .execute_tool(tc, session_id)
                    .await;

                // Summarize for tracking
                let input_json = serde_json::to_string(&tc.input).unwrap_or_default();
                let input_summary = if input_json.len() > 120 {
                    format!("{}...", &input_json[..120])
                } else {
                    input_json
                };

                turn_tool_calls.push(ToolCallSummary {
                    tool_name: tc.name.clone(),
                    input_summary,
                    success: !result.is_error,
                });

                // Extract findings from certain tool results
                if !result.is_error {
                    if let Some(finding) = extract_finding_from_tool_result(&tc.name, &result.content) {
                        turn_findings.push(finding);
                    }
                    if let Some(action) = extract_pending_action_from_tool_result(&tc.name, &result.content) {
                        turn_pending_actions.push(action);
                    }
                }

                tool_results.push(crate::tools::ToolResult {
                    tool_use_id: result.tool_use_id,
                    content: result.content,
                    is_error: result.is_error,
                });
            }

            // Add tool results as a user message
            let tool_result_message = build_tool_result_message(tool_results);
            session.messages.push(tool_result_message);

            // If this is the last iteration, extract whatever text we have
            if _iteration == MAX_TOOL_ITERATIONS - 1 {
                final_text = extract_text(&response);
                if final_text.is_empty() {
                    final_text = "I've completed my investigation using the available tools. Please review the findings above.".to_string();
                }
            }
        }

        // Update session state
        session.input_tokens += turn_input_tokens;
        session.output_tokens += turn_output_tokens;
        session.tool_calls.extend(turn_tool_calls.clone());
        session.findings.extend(turn_findings.clone());
        session.pending_actions.extend(turn_pending_actions.clone());

        // Rough cost estimate (use Sonnet pricing as default)
        let turn_cost = (turn_input_tokens as f64 / 1_000_000.0) * 3.0
            + (turn_output_tokens as f64 / 1_000_000.0) * 15.0;
        session.estimated_cost += turn_cost;

        // Save session
        self.save_session(&session).await?;

        // Update in-memory map
        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(session_id.to_string(), session);
        }

        Ok(AgentTurnResult {
            text: final_text,
            tool_calls_made: turn_tool_calls,
            findings: turn_findings,
            pending_actions: turn_pending_actions,
            tokens_used: TokenUsage {
                input_tokens: turn_input_tokens,
                output_tokens: turn_output_tokens,
            },
        })
    }

    /// Get the status of a session.
    pub async fn get_session_status(&self, id: &str) -> Result<SessionStatus> {
        let session = self.get_session(id).await?;
        Ok(SessionStatus {
            id: session.id,
            session_type: session.session_type,
            created_at: session.created_at,
            message_count: session.messages.len(),
            tool_call_count: session.tool_calls.len(),
            input_tokens: session.input_tokens,
            output_tokens: session.output_tokens,
            estimated_cost: session.estimated_cost,
            findings_count: session.findings.len(),
            pending_actions_count: session.pending_actions.len(),
            is_active: session.is_active,
        })
    }

    /// List all sessions (from memory and disk).
    pub async fn list_sessions(&self) -> Result<Vec<SessionSummary>> {
        let mut summaries = Vec::new();

        // From in-memory sessions
        let sessions = self.sessions.lock().await;
        for session in sessions.values() {
            summaries.push(session_to_summary(session));
        }
        drop(sessions);

        // Also scan sessions_dir for persisted sessions not in memory
        if self.sessions_dir.exists() {
            if let Ok(mut entries) = tokio::fs::read_dir(&self.sessions_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("json") {
                        let stem = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_string();

                        // Skip if already in memory
                        let sessions = self.sessions.lock().await;
                        if sessions.contains_key(&stem) {
                            continue;
                        }
                        drop(sessions);

                        if let Ok(data) = tokio::fs::read_to_string(&path).await {
                            if let Ok(session) = serde_json::from_str::<AgentSession>(&data) {
                                summaries.push(session_to_summary(&session));
                            }
                        }
                    }
                }
            }
        }

        Ok(summaries)
    }

    /// Cancel (deactivate) a session.
    pub async fn cancel_session(&self, id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(id) {
            session.is_active = false;
            let session_clone = AgentSession {
                id: session.id.clone(),
                session_type: session.session_type.clone(),
                created_at: session.created_at.clone(),
                messages: session.messages.clone(),
                tool_calls: session.tool_calls.clone(),
                findings: session.findings.clone(),
                pending_actions: session.pending_actions.clone(),
                input_tokens: session.input_tokens,
                output_tokens: session.output_tokens,
                estimated_cost: session.estimated_cost,
                initial_briefing: session.initial_briefing.clone(),
                context_updates: session.context_updates.clone(),
                is_active: session.is_active,
            };
            drop(sessions);
            self.save_session(&session_clone).await?;
            return Ok(());
        }
        drop(sessions);

        // Try loading from disk
        let mut session = self.load_session(id).await?;
        session.is_active = false;
        self.save_session(&session).await?;
        let mut sessions = self.sessions.lock().await;
        sessions.insert(id.to_string(), session);
        Ok(())
    }

    /// Approve a pending action within a session.
    pub async fn approve_pending_action(
        &self,
        session_id: &str,
        action_id: &str,
    ) -> Result<()> {
        self.update_action_status(session_id, action_id, ActionStatus::Approved)
            .await
    }

    /// Reject a pending action within a session.
    pub async fn reject_pending_action(
        &self,
        session_id: &str,
        action_id: &str,
    ) -> Result<()> {
        self.update_action_status(session_id, action_id, ActionStatus::Rejected)
            .await
    }

    /// Save a session to disk as a JSON file.
    pub async fn save_session(&self, session: &AgentSession) -> Result<()> {
        tokio::fs::create_dir_all(&self.sessions_dir).await?;
        let path = self.sessions_dir.join(format!("{}.json", session.id));
        let data = serde_json::to_string_pretty(session)?;
        tokio::fs::write(path, data).await?;
        Ok(())
    }

    /// Load a session from disk.
    pub async fn load_session(&self, id: &str) -> Result<AgentSession> {
        let path = self.sessions_dir.join(format!("{}.json", id));
        let data = tokio::fs::read_to_string(&path)
            .await
            .map_err(|_| anyhow::anyhow!("Session not found: {}", id))?;
        let session: AgentSession = serde_json::from_str(&data)?;
        Ok(session)
    }

    /// Remove sessions older than `max_age_days` from disk.
    pub async fn cleanup_expired_sessions(&self, max_age_days: u32) -> Result<()> {
        if !self.sessions_dir.exists() {
            return Ok(());
        }

        let cutoff = chrono::Utc::now()
            - chrono::Duration::days(max_age_days as i64);

        let mut entries = tokio::fs::read_dir(&self.sessions_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            if let Ok(data) = tokio::fs::read_to_string(&path).await {
                if let Ok(session) = serde_json::from_str::<AgentSession>(&data) {
                    if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&session.created_at) {
                        if created < cutoff {
                            let _ = tokio::fs::remove_file(&path).await;
                            let mut sessions = self.sessions.lock().await;
                            sessions.remove(&session.id);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // -- Internal helpers ---------------------------------------------------

    async fn get_session(&self, id: &str) -> Result<AgentSession> {
        let sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get(id) {
            return Ok(AgentSession {
                id: session.id.clone(),
                session_type: session.session_type.clone(),
                created_at: session.created_at.clone(),
                messages: session.messages.clone(),
                tool_calls: session.tool_calls.clone(),
                findings: session.findings.clone(),
                pending_actions: session.pending_actions.clone(),
                input_tokens: session.input_tokens,
                output_tokens: session.output_tokens,
                estimated_cost: session.estimated_cost,
                initial_briefing: session.initial_briefing.clone(),
                context_updates: session.context_updates.clone(),
                is_active: session.is_active,
            });
        }
        drop(sessions);
        self.load_session(id).await
    }

    async fn update_action_status(
        &self,
        session_id: &str,
        action_id: &str,
        status: ActionStatus,
    ) -> Result<()> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(session_id) {
            let action = session
                .pending_actions
                .iter_mut()
                .find(|a| a.id == action_id)
                .ok_or_else(|| anyhow::anyhow!("Action not found: {}", action_id))?;
            action.status = status;

            let session_clone = AgentSession {
                id: session.id.clone(),
                session_type: session.session_type.clone(),
                created_at: session.created_at.clone(),
                messages: session.messages.clone(),
                tool_calls: session.tool_calls.clone(),
                findings: session.findings.clone(),
                pending_actions: session.pending_actions.clone(),
                input_tokens: session.input_tokens,
                output_tokens: session.output_tokens,
                estimated_cost: session.estimated_cost,
                initial_briefing: session.initial_briefing.clone(),
                context_updates: session.context_updates.clone(),
                is_active: session.is_active,
            };
            drop(sessions);
            self.save_session(&session_clone).await?;
            return Ok(());
        }
        drop(sessions);

        let mut session = self.load_session(session_id).await?;
        let action = session
            .pending_actions
            .iter_mut()
            .find(|a| a.id == action_id)
            .ok_or_else(|| anyhow::anyhow!("Action not found: {}", action_id))?;
        action.status = status;
        self.save_session(&session).await?;
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session_id.to_string(), session);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Convert tool definitions to the JSON format expected by the cloud API.
fn tool_definitions_to_api_format() -> Vec<serde_json::Value> {
    get_all_tool_definitions()
        .into_iter()
        .map(|def| {
            serde_json::json!({
                "name": def.name,
                "description": def.description,
                "input_schema": def.input_schema,
            })
        })
        .collect()
}

/// Take the last `max` messages from the history.
fn sliding_window(messages: &[Message], max: usize) -> Vec<Message> {
    if messages.len() <= max {
        messages.to_vec()
    } else {
        messages[messages.len() - max..].to_vec()
    }
}

/// Convert an AgentResponse's content blocks into a MessageContent for history.
fn response_to_message_content(response: &AgentResponse) -> MessageContent {
    if response.content.len() == 1 {
        if let ContentBlock::Text { text } = &response.content[0] {
            return MessageContent::Text(text.clone());
        }
    }
    MessageContent::Blocks(response.content.clone())
}

/// Build a SessionSummary from a full AgentSession.
fn session_to_summary(session: &AgentSession) -> SessionSummary {
    let summary = if session.messages.is_empty() {
        "No messages yet".to_string()
    } else {
        // Use first user message as summary
        session
            .messages
            .iter()
            .find(|m| m.role == "user")
            .map(|m| match &m.content {
                MessageContent::Text(t) => {
                    if t.len() > 80 {
                        format!("{}...", &t[..80])
                    } else {
                        t.clone()
                    }
                }
                MessageContent::Blocks(_) => "Tool interaction".to_string(),
            })
            .unwrap_or_else(|| "Session started".to_string())
    };

    SessionSummary {
        id: session.id.clone(),
        session_type: session.session_type.clone(),
        created_at: session.created_at.clone(),
        summary,
        message_count: session.messages.len(),
        estimated_cost: session.estimated_cost,
    }
}

/// Try to extract a Finding from a tool result (for create_alert tool).
fn extract_finding_from_tool_result(tool_name: &str, content: &str) -> Option<Finding> {
    if tool_name == "create_alert" && content.contains("Alert created") {
        // Parse the action ID from the response
        let id = content
            .split("id: ")
            .nth(1)
            .and_then(|s| s.split(')').next())
            .unwrap_or("unknown")
            .to_string();

        Some(Finding {
            id,
            severity: "unknown".to_string(),
            title: "Alert from tool".to_string(),
            description: content.to_string(),
            evidence: Vec::new(),
            source_tool: Some(tool_name.to_string()),
        })
    } else {
        None
    }
}

/// Try to extract a PendingAction from a tool result.
fn extract_pending_action_from_tool_result(
    tool_name: &str,
    content: &str,
) -> Option<PendingAction> {
    let action_tools = [
        "suggest_policy_change",
        "create_alert",
        "suggest_remediation",
    ];
    if action_tools.contains(&tool_name) && content.contains("Awaiting user approval") {
        let id = content
            .split("id: ")
            .nth(1)
            .and_then(|s| s.split(')').next())
            .unwrap_or("unknown")
            .to_string();

        Some(PendingAction {
            id,
            action_type: tool_name.to_string(),
            description: content.to_string(),
            proposed_by: "agent".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: ActionStatus::Pending,
            details: serde_json::Value::Null,
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_api::{CloudProvider, StopReason, TokenUsage as CloudTokenUsage};
    use async_trait::async_trait;

    /// A mock cloud provider that returns configurable responses.
    struct MockCloudProvider {
        responses: std::sync::Mutex<Vec<AgentResponse>>,
    }

    impl MockCloudProvider {
        fn new(responses: Vec<AgentResponse>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses),
            }
        }

        fn text_response(text: &str) -> AgentResponse {
            AgentResponse {
                id: "msg-mock".to_string(),
                content: vec![ContentBlock::Text {
                    text: text.to_string(),
                }],
                stop_reason: StopReason::EndTurn,
                usage: CloudTokenUsage {
                    input_tokens: 100,
                    output_tokens: 50,
                },
                model: "mock-model".to_string(),
            }
        }

        fn tool_use_response(tool_name: &str, tool_id: &str, input: serde_json::Value) -> AgentResponse {
            AgentResponse {
                id: "msg-mock-tool".to_string(),
                content: vec![
                    ContentBlock::Text {
                        text: "Let me check.".to_string(),
                    },
                    ContentBlock::ToolUse {
                        id: tool_id.to_string(),
                        name: tool_name.to_string(),
                        input,
                    },
                ],
                stop_reason: StopReason::ToolUse,
                usage: CloudTokenUsage {
                    input_tokens: 80,
                    output_tokens: 40,
                },
                model: "mock-model".to_string(),
            }
        }
    }

    #[async_trait]
    impl CloudProvider for MockCloudProvider {
        async fn send_message(&self, _request: &AgentRequest) -> Result<AgentResponse> {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Ok(Self::text_response("No more mock responses"))
            } else {
                Ok(responses.remove(0))
            }
        }

        fn provider_name(&self) -> &str {
            "mock"
        }

        fn supports_tools(&self) -> bool {
            true
        }

        fn supports_streaming(&self) -> bool {
            false
        }
    }

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn make_manager(
        provider: MockCloudProvider,
        sessions_dir: PathBuf,
    ) -> AgentSessionManager {
        let client = Arc::new(CloudApiClient::new(Box::new(provider)));
        let sandbox = Arc::new(ToolSandbox::new());
        AgentSessionManager::new(
            client,
            sandbox,
            "mock-model".to_string(),
            sessions_dir,
        )
    }

    #[tokio::test]
    async fn test_session_creation() {
        let dir = temp_dir();
        let mgr = make_manager(
            MockCloudProvider::new(vec![]),
            dir.path().join("sessions"),
        );

        let id = mgr
            .start_session(SessionType::Chat, "You are a security agent.".into(), None)
            .await
            .unwrap();

        assert!(id.starts_with("agent-"));

        let status = mgr.get_session_status(&id).await.unwrap();
        assert_eq!(status.message_count, 0);
        assert!(status.is_active);
        assert_eq!(status.input_tokens, 0);
        assert_eq!(status.output_tokens, 0);
    }

    #[tokio::test]
    async fn test_session_creation_with_initial_query() {
        let dir = temp_dir();
        let mgr = make_manager(
            MockCloudProvider::new(vec![MockCloudProvider::text_response(
                "I'll investigate.",
            )]),
            dir.path().join("sessions"),
        );

        let id = mgr
            .start_session(
                SessionType::Investigate {
                    event_id: "evt-42".into(),
                },
                "You are a security agent.".into(),
                Some("What happened with event evt-42?".into()),
            )
            .await
            .unwrap();

        let status = mgr.get_session_status(&id).await.unwrap();
        assert_eq!(status.message_count, 1); // initial query
    }

    #[tokio::test]
    async fn test_session_persistence() {
        let dir = temp_dir();
        let sessions_dir = dir.path().join("sessions");

        let id;
        {
            let mgr = make_manager(
                MockCloudProvider::new(vec![]),
                sessions_dir.clone(),
            );
            id = mgr
                .start_session(
                    SessionType::Chat,
                    "Test briefing.".into(),
                    None,
                )
                .await
                .unwrap();
        }

        // Create a new manager and load from disk
        {
            let mgr = make_manager(
                MockCloudProvider::new(vec![]),
                sessions_dir,
            );
            let loaded = mgr.load_session(&id).await.unwrap();
            assert_eq!(loaded.id, id);
            assert_eq!(loaded.initial_briefing, "Test briefing.");
            assert!(loaded.is_active);
        }
    }

    #[tokio::test]
    async fn test_session_listing() {
        let dir = temp_dir();
        let mgr = make_manager(
            MockCloudProvider::new(vec![]),
            dir.path().join("sessions"),
        );

        mgr.start_session(SessionType::Chat, "Briefing 1".into(), None)
            .await
            .unwrap();
        mgr.start_session(
            SessionType::Scan {
                playbook: "full".into(),
            },
            "Briefing 2".into(),
            None,
        )
        .await
        .unwrap();
        mgr.start_session(
            SessionType::Report {
                report_type: "weekly".into(),
            },
            "Briefing 3".into(),
            None,
        )
        .await
        .unwrap();

        let sessions = mgr.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 3);
    }

    #[tokio::test]
    async fn test_session_cancellation() {
        let dir = temp_dir();
        let mgr = make_manager(
            MockCloudProvider::new(vec![]),
            dir.path().join("sessions"),
        );

        let id = mgr
            .start_session(SessionType::Chat, "Briefing".into(), None)
            .await
            .unwrap();

        let status = mgr.get_session_status(&id).await.unwrap();
        assert!(status.is_active);

        mgr.cancel_session(&id).await.unwrap();

        let status = mgr.get_session_status(&id).await.unwrap();
        assert!(!status.is_active);
    }

    #[tokio::test]
    async fn test_pending_action_workflow() {
        let dir = temp_dir();
        let mgr = make_manager(
            MockCloudProvider::new(vec![]),
            dir.path().join("sessions"),
        );

        let id = mgr
            .start_session(SessionType::Chat, "Briefing".into(), None)
            .await
            .unwrap();

        // Manually add pending actions for testing
        {
            let mut sessions = mgr.sessions.lock().await;
            let session = sessions.get_mut(&id).unwrap();
            session.pending_actions.push(PendingAction {
                id: "action-1".into(),
                action_type: "policy_change".into(),
                description: "Block evil-server".into(),
                proposed_by: "agent".into(),
                created_at: chrono::Utc::now().to_rfc3339(),
                status: ActionStatus::Pending,
                details: serde_json::Value::Null,
            });
            session.pending_actions.push(PendingAction {
                id: "action-2".into(),
                action_type: "remediation".into(),
                description: "Fix config".into(),
                proposed_by: "agent".into(),
                created_at: chrono::Utc::now().to_rfc3339(),
                status: ActionStatus::Pending,
                details: serde_json::Value::Null,
            });
        }

        // Approve action-1
        mgr.approve_pending_action(&id, "action-1").await.unwrap();

        // Reject action-2
        mgr.reject_pending_action(&id, "action-2").await.unwrap();

        // Verify statuses
        let session = mgr.get_session(&id).await.unwrap();
        assert_eq!(session.pending_actions[0].status, ActionStatus::Approved);
        assert_eq!(session.pending_actions[1].status, ActionStatus::Rejected);
    }

    #[tokio::test]
    async fn test_token_tracking() {
        let dir = temp_dir();
        let mgr = make_manager(
            MockCloudProvider::new(vec![
                MockCloudProvider::text_response("First response"),
                MockCloudProvider::text_response("Second response"),
            ]),
            dir.path().join("sessions"),
        );

        let id = mgr
            .start_session(SessionType::Chat, "Briefing".into(), None)
            .await
            .unwrap();

        let result1 = mgr.send_message(&id, "Hello").await.unwrap();
        assert_eq!(result1.tokens_used.input_tokens, 100);
        assert_eq!(result1.tokens_used.output_tokens, 50);

        let result2 = mgr.send_message(&id, "Another question").await.unwrap();
        assert_eq!(result2.tokens_used.input_tokens, 100);
        assert_eq!(result2.tokens_used.output_tokens, 50);

        // Verify cumulative tokens on session
        let status = mgr.get_session_status(&id).await.unwrap();
        assert_eq!(status.input_tokens, 200);
        assert_eq!(status.output_tokens, 100);
        assert!(status.estimated_cost > 0.0);
    }

    #[tokio::test]
    async fn test_send_message_basic() {
        let dir = temp_dir();
        let mgr = make_manager(
            MockCloudProvider::new(vec![MockCloudProvider::text_response(
                "The system is secure.",
            )]),
            dir.path().join("sessions"),
        );

        let id = mgr
            .start_session(SessionType::Chat, "You are a security agent.".into(), None)
            .await
            .unwrap();

        let result = mgr.send_message(&id, "Is the system safe?").await.unwrap();
        assert_eq!(result.text, "The system is secure.");
        assert!(result.tool_calls_made.is_empty());

        // Verify messages recorded
        let status = mgr.get_session_status(&id).await.unwrap();
        assert_eq!(status.message_count, 2); // user + assistant
    }

    #[tokio::test]
    async fn test_tool_use_loop() {
        let dir = temp_dir();
        let mgr = make_manager(
            MockCloudProvider::new(vec![
                // First: model wants to call a tool
                MockCloudProvider::tool_use_response(
                    "get_policy",
                    "tool_01",
                    serde_json::json!({}),
                ),
                // Second: model gives final answer after seeing tool result
                MockCloudProvider::text_response("Based on the policy, everything looks good."),
            ]),
            dir.path().join("sessions"),
        );

        let id = mgr
            .start_session(SessionType::Chat, "You are a security agent.".into(), None)
            .await
            .unwrap();

        let result = mgr
            .send_message(&id, "What's our policy?")
            .await
            .unwrap();

        assert_eq!(result.text, "Based on the policy, everything looks good.");
        assert_eq!(result.tool_calls_made.len(), 1);
        assert_eq!(result.tool_calls_made[0].tool_name, "get_policy");
        assert!(result.tool_calls_made[0].success);

        // Should have accumulated tokens from both API calls
        assert!(result.tokens_used.input_tokens > 0);
        assert!(result.tokens_used.output_tokens > 0);
    }

    #[tokio::test]
    async fn test_inactive_session_rejects_messages() {
        let dir = temp_dir();
        let mgr = make_manager(
            MockCloudProvider::new(vec![]),
            dir.path().join("sessions"),
        );

        let id = mgr
            .start_session(SessionType::Chat, "Briefing".into(), None)
            .await
            .unwrap();

        mgr.cancel_session(&id).await.unwrap();

        let result = mgr.send_message(&id, "Hello").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no longer active"));
    }

    #[tokio::test]
    async fn test_sliding_window() {
        let messages: Vec<Message> = (0..30)
            .map(|i| Message {
                role: "user".to_string(),
                content: MessageContent::Text(format!("Message {}", i)),
            })
            .collect();

        let windowed = sliding_window(&messages, 20);
        assert_eq!(windowed.len(), 20);
        // Should contain messages 10-29
        match &windowed[0].content {
            MessageContent::Text(t) => assert_eq!(t, "Message 10"),
            _ => panic!("Expected text"),
        }
    }

    #[test]
    fn test_tool_definitions_format() {
        let tools = tool_definitions_to_api_format();
        assert!(!tools.is_empty());
        for tool in &tools {
            assert!(tool.get("name").is_some());
            assert!(tool.get("description").is_some());
            assert!(tool.get("input_schema").is_some());
        }
    }

    #[test]
    fn test_session_summary_generation() {
        let session = AgentSession {
            id: "test-id".into(),
            session_type: SessionType::Chat,
            created_at: "2025-01-01T00:00:00Z".into(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text("What is going on?".into()),
            }],
            tool_calls: Vec::new(),
            findings: Vec::new(),
            pending_actions: Vec::new(),
            input_tokens: 100,
            output_tokens: 50,
            estimated_cost: 0.01,
            initial_briefing: "Test".into(),
            context_updates: Vec::new(),
            is_active: true,
        };

        let summary = session_to_summary(&session);
        assert_eq!(summary.id, "test-id");
        assert_eq!(summary.message_count, 1);
        assert_eq!(summary.summary, "What is going on?");
    }

    #[test]
    fn test_extract_finding_from_alert() {
        let finding = extract_finding_from_tool_result(
            "create_alert",
            "Alert created (id: abc-123). Awaiting user approval.",
        );
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.id, "abc-123");
        assert_eq!(f.source_tool, Some("create_alert".to_string()));
    }

    #[test]
    fn test_extract_pending_action_from_tool() {
        let action = extract_pending_action_from_tool_result(
            "suggest_policy_change",
            "Action proposed (id: xyz-789). Awaiting user approval.",
        );
        assert!(action.is_some());
        let a = action.unwrap();
        assert_eq!(a.id, "xyz-789");
        assert_eq!(a.action_type, "suggest_policy_change");
        assert_eq!(a.status, ActionStatus::Pending);
    }

    #[test]
    fn test_no_finding_from_regular_tool() {
        let finding = extract_finding_from_tool_result(
            "query_events",
            "{\"events\": []}",
        );
        assert!(finding.is_none());
    }
}
