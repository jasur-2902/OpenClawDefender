//! Investigation session engine — runs focused, agentic root-cause analysis
//! investigations using Claude and investigation-specific tools.
//!
//! The engine manages the lifecycle of investigations: creation, the agentic
//! tool-use loop, progress tracking, auto-escalation, and result extraction.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::cloud_api::{
    build_tool_result_message, extract_text, extract_tool_calls, AgentRequest, AgentResponse,
    CloudApiClient, ContentBlock, Message, MessageContent,
};
use crate::investigation_tools::{
    InvestigationContext, InvestigationDepth, InvestigationSuggestion, InvestigationTarget,
    InvestigationToolExecutor, get_investigation_prompt, get_investigation_tools,
};
use crate::tool_sandbox::ToolSandbox;
use crate::tools::ToolResult;

// ---------------------------------------------------------------------------
// Constants / guardrails
// ---------------------------------------------------------------------------

/// Maximum messages in a single API request (sliding window).
const MAX_MESSAGES_IN_REQUEST: usize = 40;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Current status of an investigation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InvestigationStatus {
    Initializing,
    Running,
    AwaitingUser,
    Complete,
    Failed { error: String },
    Cancelled,
}

/// One of the 5 investigation questions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationQuestion {
    pub question: String,
    pub answer: Option<String>,
    pub answered: bool,
}

/// A root cause hypothesis with supporting evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCause {
    pub description: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

/// Real-time progress snapshot for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationProgress {
    pub investigation_id: String,
    pub status: InvestigationStatus,
    pub target_summary: String,
    pub depth: InvestigationDepth,
    pub questions_answered: usize,
    pub questions_total: usize,
    pub tool_calls_count: usize,
    pub max_tool_calls: usize,
    pub elapsed_secs: u64,
    pub findings_count: usize,
    pub current_activity: String,
}

/// Assessment of an incident's impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    pub data_accessed: Vec<String>,
    pub data_modified: Vec<String>,
    pub data_exfiltrated: bool,
    pub blast_radius: String,
    pub severity: String,
}

/// Complete result of a finished investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationResult {
    pub investigation_id: String,
    pub target: InvestigationTarget,
    pub depth: InvestigationDepth,
    pub status: InvestigationStatus,

    // The 5 answers
    pub what_happened: String,
    pub why_it_happened: String,
    pub part_of_larger: Option<String>,
    pub impact: ImpactAssessment,
    pub recommendations: Vec<String>,

    // Supporting data
    pub related_events: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub suggestions: Vec<InvestigationSuggestion>,

    // Verdict
    pub verdict: String,
    pub confidence: f64,
    pub narrative: String,

    // Cost
    pub total_tool_calls: usize,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub estimated_cost_usd: f64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Mutable state for a single running investigation.
struct InvestigationState {
    investigation_id: String,
    target: InvestigationTarget,
    depth: InvestigationDepth,
    status: InvestigationStatus,

    // Conversation
    messages: Vec<Message>,
    system_prompt: String,

    // Progress tracking
    tool_calls: usize,
    questions_answered: Vec<InvestigationQuestion>,
    findings: Vec<serde_json::Value>,
    suggestions: Vec<InvestigationSuggestion>,
    evidence_ids: Vec<String>,
    related_events: Vec<String>,

    // Raw text from Claude
    accumulated_text: String,
    current_activity: String,

    // Verdict & impact
    verdict: Option<String>,
    confidence: Option<f64>,
    impact: Option<ImpactAssessment>,

    // Cost
    input_tokens: u64,
    output_tokens: u64,
    started_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// InvestigationEngine
// ---------------------------------------------------------------------------

/// Manages investigation sessions: creation, the agentic loop, progress
/// queries, cancellation, and result extraction.
pub struct InvestigationEngine {
    investigations: Mutex<HashMap<String, InvestigationState>>,
    results: Mutex<HashMap<String, InvestigationResult>>,
    cloud_client: Arc<CloudApiClient>,
    tool_sandbox: Arc<ToolSandbox>,
    investigation_tool_executor: InvestigationToolExecutor,
    model: String,
}

impl InvestigationEngine {
    pub fn new(
        cloud_client: Arc<CloudApiClient>,
        tool_sandbox: Arc<ToolSandbox>,
        model: String,
    ) -> Self {
        Self {
            investigations: Mutex::new(HashMap::new()),
            results: Mutex::new(HashMap::new()),
            cloud_client,
            tool_sandbox,
            investigation_tool_executor: InvestigationToolExecutor::new(),
            model,
        }
    }

    /// Start a new investigation. Returns initial progress.
    pub async fn start_investigation(
        &self,
        target: InvestigationTarget,
        depth: Option<InvestigationDepth>,
    ) -> Result<InvestigationProgress> {
        let investigation_id = format!("inv-{}", uuid::Uuid::new_v4());

        // Auto-select depth if not provided
        let depth = depth.unwrap_or_else(|| auto_select_depth(&target));

        // Build context
        let context = build_context(&target).await;

        // Build system prompt
        let system_prompt = get_investigation_prompt(&target, &context);

        // Build initial user message
        let user_message = build_initial_user_message(&target);

        let target_summary = summarize_target(&target);

        let questions = build_initial_questions();

        let state = InvestigationState {
            investigation_id: investigation_id.clone(),
            target: target.clone(),
            depth: depth.clone(),
            status: InvestigationStatus::Running,
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text(user_message),
            }],
            system_prompt,
            tool_calls: 0,
            questions_answered: questions,
            findings: Vec::new(),
            suggestions: Vec::new(),
            evidence_ids: Vec::new(),
            related_events: Vec::new(),
            accumulated_text: String::new(),
            current_activity: "Starting investigation...".to_string(),
            verdict: None,
            confidence: None,
            impact: None,
            input_tokens: 0,
            output_tokens: 0,
            started_at: Utc::now(),
        };

        let progress = InvestigationProgress {
            investigation_id: investigation_id.clone(),
            status: InvestigationStatus::Running,
            target_summary,
            depth: depth.clone(),
            questions_answered: 0,
            questions_total: 5,
            tool_calls_count: 0,
            max_tool_calls: depth.max_tool_calls(),
            elapsed_secs: 0,
            findings_count: 0,
            current_activity: "Starting investigation...".to_string(),
        };

        let mut investigations = self.investigations.lock().await;
        investigations.insert(investigation_id.clone(), state);

        Ok(progress)
    }

    /// Run the main agentic investigation loop. Returns the final result.
    pub async fn run_investigation_loop(
        &self,
        investigation_id: &str,
    ) -> Result<InvestigationResult> {
        let start_time = Instant::now();

        loop {
            // Check guardrails
            let (max_tool_calls, max_duration, status, tool_calls, _depth) = {
                let investigations = self.investigations.lock().await;
                let state = investigations
                    .get(investigation_id)
                    .ok_or_else(|| anyhow::anyhow!("Investigation not found: {}", investigation_id))?;

                (
                    state.depth.max_tool_calls(),
                    state.depth.max_duration_secs(),
                    state.status.clone(),
                    state.tool_calls,
                    state.depth.clone(),
                )
            };

            // Check if cancelled or already complete
            if status != InvestigationStatus::Running
                && status != InvestigationStatus::Initializing
            {
                break;
            }

            // Check tool call limit
            if tool_calls >= max_tool_calls {
                self.set_activity(investigation_id, "Max tool calls reached, finalizing...".to_string())
                    .await;
                self.finalize_investigation(investigation_id, InvestigationStatus::Complete)
                    .await?;
                break;
            }

            // Check duration limit
            if start_time.elapsed().as_secs() >= max_duration {
                self.set_activity(investigation_id, "Time limit reached, finalizing...".to_string())
                    .await;
                self.finalize_investigation(investigation_id, InvestigationStatus::Complete)
                    .await?;
                break;
            }

            // Run a single turn
            match self.run_single_turn(investigation_id).await {
                Ok(completed) => {
                    if completed {
                        self.finalize_investigation(investigation_id, InvestigationStatus::Complete)
                            .await?;
                        break;
                    }

                    // Check auto-escalation
                    let should_escalate = {
                        let investigations = self.investigations.lock().await;
                        if let Some(state) = investigations.get(investigation_id) {
                            should_escalate(state)
                        } else {
                            false
                        }
                    };

                    if should_escalate {
                        let mut investigations = self.investigations.lock().await;
                        if let Some(state) = investigations.get_mut(investigation_id) {
                            state.depth = InvestigationDepth::Deep;
                            state.current_activity =
                                "Escalating to deep investigation...".to_string();
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Investigation {} turn error: {}", investigation_id, e);
                    self.finalize_investigation(
                        investigation_id,
                        InvestigationStatus::Failed {
                            error: e.to_string(),
                        },
                    )
                    .await?;
                    break;
                }
            }
        }

        // Return the result
        let results = self.results.lock().await;
        results
            .get(investigation_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Investigation result not found after finalization"))
    }

    /// Get real-time progress for an investigation.
    pub async fn get_progress(
        &self,
        investigation_id: &str,
    ) -> Result<InvestigationProgress> {
        // Check running investigations
        let investigations = self.investigations.lock().await;
        if let Some(state) = investigations.get(investigation_id) {
            let elapsed = Utc::now()
                .signed_duration_since(state.started_at)
                .num_seconds()
                .unsigned_abs();

            let answered = state
                .questions_answered
                .iter()
                .filter(|q| q.answered)
                .count();

            return Ok(InvestigationProgress {
                investigation_id: investigation_id.to_string(),
                status: state.status.clone(),
                target_summary: summarize_target(&state.target),
                depth: state.depth.clone(),
                questions_answered: answered,
                questions_total: 5,
                tool_calls_count: state.tool_calls,
                max_tool_calls: state.depth.max_tool_calls(),
                elapsed_secs: elapsed,
                findings_count: state.findings.len(),
                current_activity: state.current_activity.clone(),
            });
        }
        drop(investigations);

        // Check completed results
        let results = self.results.lock().await;
        if let Some(result) = results.get(investigation_id) {
            return Ok(InvestigationProgress {
                investigation_id: investigation_id.to_string(),
                status: result.status.clone(),
                target_summary: summarize_target(&result.target),
                depth: result.depth.clone(),
                questions_answered: 5,
                questions_total: 5,
                tool_calls_count: result.total_tool_calls,
                max_tool_calls: result.depth.max_tool_calls(),
                elapsed_secs: result
                    .completed_at
                    .map(|c| c.signed_duration_since(result.started_at).num_seconds().unsigned_abs())
                    .unwrap_or(0),
                findings_count: result.evidence_ids.len(),
                current_activity: "Investigation complete".to_string(),
            });
        }

        bail!("Investigation not found: {}", investigation_id)
    }

    /// Get the final result of a completed investigation.
    pub async fn get_result(
        &self,
        investigation_id: &str,
    ) -> Result<InvestigationResult> {
        let results = self.results.lock().await;
        results
            .get(investigation_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Investigation result not found: {}", investigation_id))
    }

    /// Cancel a running investigation.
    pub async fn cancel_investigation(
        &self,
        investigation_id: &str,
    ) -> Result<()> {
        let mut investigations = self.investigations.lock().await;
        if let Some(state) = investigations.get_mut(investigation_id) {
            if state.status == InvestigationStatus::Running {
                state.status = InvestigationStatus::Cancelled;
                state.current_activity = "Investigation cancelled by user.".to_string();
            }
            return Ok(());
        }
        bail!(
            "Investigation not found or already completed: {}",
            investigation_id
        )
    }

    /// List all investigations (running and completed).
    pub async fn list_investigations(&self) -> Vec<InvestigationProgress> {
        let mut list = Vec::new();

        // Running
        let investigations = self.investigations.lock().await;
        for state in investigations.values() {
            let elapsed = Utc::now()
                .signed_duration_since(state.started_at)
                .num_seconds()
                .unsigned_abs();

            let answered = state
                .questions_answered
                .iter()
                .filter(|q| q.answered)
                .count();

            list.push(InvestigationProgress {
                investigation_id: state.investigation_id.clone(),
                status: state.status.clone(),
                target_summary: summarize_target(&state.target),
                depth: state.depth.clone(),
                questions_answered: answered,
                questions_total: 5,
                tool_calls_count: state.tool_calls,
                max_tool_calls: state.depth.max_tool_calls(),
                elapsed_secs: elapsed,
                findings_count: state.findings.len(),
                current_activity: state.current_activity.clone(),
            });
        }
        drop(investigations);

        // Completed
        let results = self.results.lock().await;
        for result in results.values() {
            list.push(InvestigationProgress {
                investigation_id: result.investigation_id.clone(),
                status: result.status.clone(),
                target_summary: summarize_target(&result.target),
                depth: result.depth.clone(),
                questions_answered: 5,
                questions_total: 5,
                tool_calls_count: result.total_tool_calls,
                max_tool_calls: result.depth.max_tool_calls(),
                elapsed_secs: result
                    .completed_at
                    .map(|c| c.signed_duration_since(result.started_at).num_seconds().unsigned_abs())
                    .unwrap_or(0),
                findings_count: result.evidence_ids.len(),
                current_activity: "Investigation complete".to_string(),
            });
        }

        list
    }

    // -----------------------------------------------------------------------
    // Agentic loop internals
    // -----------------------------------------------------------------------

    /// Execute a single turn: send messages to Claude, process response,
    /// execute tool calls if any. Returns `true` if the investigation is
    /// complete.
    async fn run_single_turn(&self, investigation_id: &str) -> Result<bool> {
        // Build request
        let request = {
            let investigations = self.investigations.lock().await;
            let state = investigations
                .get(investigation_id)
                .ok_or_else(|| anyhow::anyhow!("Investigation not found"))?;

            let session_type = crate::agent_session::SessionType::Investigate {
                event_id: investigation_id.to_string(),
            };
            let tools = get_investigation_tools(&session_type);
            let tool_json: Vec<serde_json::Value> = tools
                .iter()
                .map(|def| {
                    serde_json::json!({
                        "name": def.name,
                        "description": def.description,
                        "input_schema": def.input_schema,
                    })
                })
                .collect();

            let request_messages = sliding_window(&state.messages, MAX_MESSAGES_IN_REQUEST);

            AgentRequest {
                model: self.model.clone(),
                system: state.system_prompt.clone(),
                messages: request_messages,
                tools: tool_json,
                max_tokens: 4096,
                stream: false,
            }
        };

        // Send to Claude
        let response = self
            .cloud_client
            .send(&request)
            .await
            .map_err(|e| anyhow::anyhow!("Cloud API error: {}", e))?;

        // Update tokens
        {
            let mut investigations = self.investigations.lock().await;
            if let Some(state) = investigations.get_mut(investigation_id) {
                state.input_tokens += response.usage.input_tokens;
                state.output_tokens += response.usage.output_tokens;
            }
        }

        // Extract text and tool calls
        let tool_calls = extract_tool_calls(&response);
        let text = extract_text(&response);

        // Process text output
        let investigation_complete = if !text.is_empty() {
            self.process_text_output(investigation_id, &text).await?
        } else {
            false
        };

        // Add assistant message to history
        {
            let mut investigations = self.investigations.lock().await;
            if let Some(state) = investigations.get_mut(investigation_id) {
                state.messages.push(Message {
                    role: "assistant".to_string(),
                    content: response_to_message_content(&response),
                });
            }
        }

        if investigation_complete {
            return Ok(true);
        }

        // If no tool calls, the model finished
        if tool_calls.is_empty() {
            return Ok(true);
        }

        // Execute tool calls
        let mut tool_results = Vec::new();
        for tc in &tool_calls {
            // Update activity
            {
                let mut investigations = self.investigations.lock().await;
                if let Some(state) = investigations.get_mut(investigation_id) {
                    state.current_activity = format!("Running tool: {}...", tc.name);
                }
            }

            // Execute via investigation tool executor first, fall back to sandbox
            let result = if self.investigation_tool_executor.handles_tool(&tc.name) {
                match self
                    .investigation_tool_executor
                    .execute_tool(&tc.name, &tc.input)
                    .await
                {
                    Ok(output) => ToolResult {
                        tool_use_id: tc.id.clone(),
                        content: output,
                        is_error: false,
                    },
                    Err(err) => ToolResult {
                        tool_use_id: tc.id.clone(),
                        content: err,
                        is_error: true,
                    },
                }
            } else {
                self.tool_sandbox
                    .execute_tool(tc, investigation_id)
                    .await
            };

            // Record evidence
            {
                let mut investigations = self.investigations.lock().await;
                if let Some(state) = investigations.get_mut(investigation_id) {
                    state.tool_calls += 1;
                    let evidence_id =
                        format!("ev-{}-{}", investigation_id, state.tool_calls);
                    state.evidence_ids.push(evidence_id);

                    // Handle suggest_investigation tool specially
                    if tc.name == "suggest_investigation" && !result.is_error {
                        if let Ok(parsed) =
                            serde_json::from_str::<serde_json::Value>(&result.content)
                        {
                            let suggestion = InvestigationSuggestion {
                                id: parsed
                                    .get("suggestion_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_string(),
                                parent_investigation_id: investigation_id.to_string(),
                                suggested_target: InvestigationTarget::Freeform {
                                    query: parsed
                                        .get("target_id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                },
                                reason: parsed
                                    .get("reason")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                priority: parsed
                                    .get("priority")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("medium")
                                    .to_string(),
                            };
                            state.suggestions.push(suggestion);
                        }
                    }
                }
            }

            tool_results.push(result);
        }

        // Add tool results to message history
        {
            let mut investigations = self.investigations.lock().await;
            if let Some(state) = investigations.get_mut(investigation_id) {
                let tool_result_msg = build_tool_result_message(
                    tool_results
                        .into_iter()
                        .map(|r| ToolResult {
                            tool_use_id: r.tool_use_id,
                            content: r.content,
                            is_error: r.is_error,
                        })
                        .collect(),
                );
                state.messages.push(tool_result_msg);
            }
        }

        Ok(false)
    }

    /// Process text output from Claude, extracting verdicts, impacts,
    /// timeline entries, and question answers.
    /// Returns `true` if INVESTIGATION COMPLETE was found.
    async fn process_text_output(
        &self,
        investigation_id: &str,
        text: &str,
    ) -> Result<bool> {
        let mut complete = false;

        // Check for INVESTIGATION COMPLETE
        if text.contains("INVESTIGATION COMPLETE") {
            complete = true;
        }

        // Extract verdict
        let verdict = extract_verdict(text);
        let impact = extract_impact(text);
        let answered = extract_answered_questions(text);

        // Apply to investigation state
        {
            let mut investigations = self.investigations.lock().await;
            if let Some(state) = investigations.get_mut(investigation_id) {
                state.accumulated_text.push_str(text);
                state.accumulated_text.push('\n');

                if let Some((v, c)) = &verdict {
                    state.verdict = Some(v.clone());
                    state.confidence = Some(*c);
                }

                if let Some(imp) = impact {
                    state.impact = Some(imp);
                }

                // Update question answers
                for (idx, answer) in &answered {
                    if *idx < state.questions_answered.len() {
                        state.questions_answered[*idx].answer = Some(answer.clone());
                        state.questions_answered[*idx].answered = true;
                    }
                }

                // Check if all questions answered
                let all_answered = state.questions_answered.iter().all(|q| q.answered);
                if all_answered {
                    complete = true;
                }

                if complete {
                    state.current_activity = "Finalizing investigation...".to_string();
                }
            }
        }

        Ok(complete)
    }

    /// Finalize an investigation: build result, move from active to results.
    async fn finalize_investigation(
        &self,
        investigation_id: &str,
        final_status: InvestigationStatus,
    ) -> Result<()> {
        let result = {
            let mut investigations = self.investigations.lock().await;
            let state = investigations
                .get_mut(investigation_id)
                .ok_or_else(|| anyhow::anyhow!("Investigation not found: {}", investigation_id))?;

            state.status = final_status.clone();

            let cost = estimate_cost(state.input_tokens, state.output_tokens);

            // Extract answers from accumulated text
            let what_happened = state
                .questions_answered
                .get(0)
                .and_then(|q| q.answer.clone())
                .unwrap_or_else(|| extract_section(&state.accumulated_text, "WHAT HAPPENED"));
            let why_it_happened = state
                .questions_answered
                .get(1)
                .and_then(|q| q.answer.clone())
                .unwrap_or_else(|| extract_section(&state.accumulated_text, "WHY"));
            let part_of_larger = state
                .questions_answered
                .get(2)
                .and_then(|q| q.answer.clone());
            let recommendations_text = state
                .questions_answered
                .get(4)
                .and_then(|q| q.answer.clone())
                .unwrap_or_default();
            let recommendations: Vec<String> = if recommendations_text.is_empty() {
                Vec::new()
            } else {
                recommendations_text
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| l.trim().trim_start_matches("- ").to_string())
                    .collect()
            };

            let impact = state.impact.clone().unwrap_or_else(|| ImpactAssessment {
                data_accessed: Vec::new(),
                data_modified: Vec::new(),
                data_exfiltrated: false,
                blast_radius: "Unknown".to_string(),
                severity: "Unknown".to_string(),
            });

            let verdict = state
                .verdict
                .clone()
                .unwrap_or_else(|| "Benign".to_string());
            let confidence = state.confidence.unwrap_or(0.5);

            // Build narrative from accumulated text
            let narrative = if state.accumulated_text.len() > 1000 {
                state.accumulated_text[..1000].to_string()
            } else {
                state.accumulated_text.clone()
            };

            let result = InvestigationResult {
                investigation_id: investigation_id.to_string(),
                target: state.target.clone(),
                depth: state.depth.clone(),
                status: final_status,
                what_happened,
                why_it_happened,
                part_of_larger,
                impact,
                recommendations,
                related_events: state.related_events.clone(),
                evidence_ids: state.evidence_ids.clone(),
                suggestions: state.suggestions.clone(),
                verdict,
                confidence,
                narrative,
                total_tool_calls: state.tool_calls,
                total_input_tokens: state.input_tokens,
                total_output_tokens: state.output_tokens,
                estimated_cost_usd: cost,
                started_at: state.started_at,
                completed_at: Some(Utc::now()),
            };

            // Remove from active investigations
            investigations.remove(investigation_id);

            result
        };

        // Store in results map
        let mut results = self.results.lock().await;
        results.insert(investigation_id.to_string(), result);

        Ok(())
    }

    async fn set_activity(&self, investigation_id: &str, activity: String) {
        let mut investigations = self.investigations.lock().await;
        if let Some(state) = investigations.get_mut(investigation_id) {
            state.current_activity = activity;
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Auto-select investigation depth based on the target.
fn auto_select_depth(target: &InvestigationTarget) -> InvestigationDepth {
    match target {
        InvestigationTarget::Event { event_data, .. } => {
            let severity = event_data
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("MEDIUM");
            InvestigationDepth::auto_select(severity)
        }
        InvestigationTarget::Alert { alert_data, .. } => {
            let severity = alert_data
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("HIGH");
            InvestigationDepth::auto_select(severity)
        }
        InvestigationTarget::Server { .. } => InvestigationDepth::Standard,
        InvestigationTarget::TimeRange { .. } => InvestigationDepth::Standard,
        InvestigationTarget::Freeform { .. } => InvestigationDepth::Standard,
    }
}

/// Build investigation context for a target.
async fn build_context(target: &InvestigationTarget) -> InvestigationContext {
    match target {
        InvestigationTarget::Event { event_id, .. } => {
            InvestigationContext::build_for_event(event_id, None).await
        }
        InvestigationTarget::Alert { alert_id, .. } => {
            InvestigationContext::build_for_event(alert_id, None).await
        }
        InvestigationTarget::Server { server_name } => {
            InvestigationContext::build_for_server(server_name).await
        }
        InvestigationTarget::TimeRange { start, end } => {
            InvestigationContext::build_for_time_range(*start, *end).await
        }
        InvestigationTarget::Freeform { .. } => InvestigationContext {
            target_event: None,
            session_events: Vec::new(),
            surrounding_events: Vec::new(),
            kill_chain: None,
            past_investigations: Vec::new(),
            user_decisions: Vec::new(),
            server_profile: None,
        },
    }
}

/// Build the initial user message for an investigation.
fn build_initial_user_message(target: &InvestigationTarget) -> String {
    match target {
        InvestigationTarget::Event { event_id, .. } => {
            format!(
                "Begin investigating event {}. Start by gathering context, then \
                 answer the 5 investigation questions. Emit [VERDICT] and [IMPACT] \
                 tags when you reach conclusions. Signal INVESTIGATION COMPLETE when done.",
                event_id
            )
        }
        InvestigationTarget::Alert { alert_id, .. } => {
            format!(
                "Begin investigating alert {}. Determine if this is a true positive \
                 or false positive. Emit [VERDICT] and [IMPACT] tags when you reach \
                 conclusions. Signal INVESTIGATION COMPLETE when done.",
                alert_id
            )
        }
        InvestigationTarget::Server { server_name } => {
            format!(
                "Begin a comprehensive security review of MCP server '{}'. \
                 Check behavioral profile, tool usage, file access, and network activity. \
                 Emit [VERDICT] and [IMPACT] tags. Signal INVESTIGATION COMPLETE when done.",
                server_name
            )
        }
        InvestigationTarget::TimeRange { start, end } => {
            format!(
                "Review all MCP activity between {} and {}. Look for anomalies, \
                 coordinated activity, and suspicious patterns. Emit [VERDICT] and \
                 [IMPACT] tags. Signal INVESTIGATION COMPLETE when done.",
                start.to_rfc3339(),
                end.to_rfc3339()
            )
        }
        InvestigationTarget::Freeform { query } => {
            format!(
                "Investigate the following: {}. Use available tools to answer \
                 thoroughly. Emit [VERDICT] and [IMPACT] tags. Signal \
                 INVESTIGATION COMPLETE when done.",
                query
            )
        }
    }
}

/// Summarize an investigation target for display.
fn summarize_target(target: &InvestigationTarget) -> String {
    match target {
        InvestigationTarget::Event { event_id, .. } => {
            format!("Event: {}", event_id)
        }
        InvestigationTarget::Alert { alert_id, .. } => {
            format!("Alert: {}", alert_id)
        }
        InvestigationTarget::Server { server_name } => {
            format!("Server: {}", server_name)
        }
        InvestigationTarget::TimeRange { start, end } => {
            format!(
                "Time range: {} to {}",
                start.format("%Y-%m-%d %H:%M"),
                end.format("%Y-%m-%d %H:%M")
            )
        }
        InvestigationTarget::Freeform { query } => {
            let truncated = if query.len() > 60 {
                format!("{}...", &query[..60])
            } else {
                query.clone()
            };
            format!("Query: {}", truncated)
        }
    }
}

/// Build the initial set of 5 investigation questions.
fn build_initial_questions() -> Vec<InvestigationQuestion> {
    vec![
        InvestigationQuestion {
            question: "What happened?".to_string(),
            answer: None,
            answered: false,
        },
        InvestigationQuestion {
            question: "Why did it happen?".to_string(),
            answer: None,
            answered: false,
        },
        InvestigationQuestion {
            question: "Is this part of something larger?".to_string(),
            answer: None,
            answered: false,
        },
        InvestigationQuestion {
            question: "What is the impact?".to_string(),
            answer: None,
            answered: false,
        },
        InvestigationQuestion {
            question: "What action should be taken?".to_string(),
            answer: None,
            answered: false,
        },
    ]
}

/// Check whether an investigation should be escalated from Standard to Deep.
fn should_escalate(state: &InvestigationState) -> bool {
    if state.depth != InvestigationDepth::Standard {
        return false;
    }

    // Escalate if verdict is ConfirmedThreat
    if let Some(ref verdict) = state.verdict {
        if verdict == "ConfirmedThreat" {
            return true;
        }
    }

    // Escalate if suggestions were made (found something bigger)
    if !state.suggestions.is_empty() {
        return true;
    }

    // Escalate if kill chain detected in accumulated text
    if state.accumulated_text.contains("kill chain")
        || state.accumulated_text.contains("Kill Chain")
        || state.accumulated_text.contains("coordinated attack")
    {
        return true;
    }

    false
}

/// Extract [VERDICT confidence=<N>]...[/VERDICT] from text.
fn extract_verdict(text: &str) -> Option<(String, f64)> {
    let re = Regex::new(
        r"\[VERDICT\s+confidence=(\d+)\]\s*(FalsePositive|Benign|Suspicious|ConfirmedThreat)\s*\[/VERDICT\]",
    )
    .ok()?;

    re.captures(text).map(|cap| {
        let confidence: f64 = cap[1].parse().unwrap_or(50.0) / 100.0;
        let verdict = cap[2].to_string();
        (verdict, confidence)
    })
}

/// Extract [IMPACT]...[/IMPACT] from text.
fn extract_impact(text: &str) -> Option<ImpactAssessment> {
    let start = text.find("[IMPACT]")?;
    let end = text.find("[/IMPACT]")?;
    if end <= start {
        return None;
    }

    let body = &text[start + 8..end];

    let data_accessed = extract_impact_field(body, "data_accessed");
    let data_modified = extract_impact_field(body, "data_modified");
    let data_exfiltrated = body
        .lines()
        .any(|l| l.contains("data_exfiltrated") && !l.contains("none"));
    let blast_radius = extract_impact_single_field(body, "blast_radius")
        .unwrap_or_else(|| "Unknown".to_string());

    Some(ImpactAssessment {
        data_accessed,
        data_modified,
        data_exfiltrated,
        blast_radius,
        severity: "Unknown".to_string(),
    })
}

/// Extract a list field from impact body text.
fn extract_impact_field(body: &str, field: &str) -> Vec<String> {
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&format!("{}:", field)) {
            let value = rest.trim();
            if value == "none" || value.is_empty() {
                return Vec::new();
            }
            return value
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    Vec::new()
}

/// Extract a single-value field from impact body text.
fn extract_impact_single_field(body: &str, field: &str) -> Option<String> {
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&format!("{}:", field)) {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Extract which investigation questions have been answered from Claude's text.
fn extract_answered_questions(text: &str) -> Vec<(usize, String)> {
    let mut answers = Vec::new();

    // Try numbered format: "1. " / "2. " etc.
    let question_patterns = [
        (0, &["1.", "WHAT HAPPENED", "What happened"] as &[&str]),
        (1, &["2.", "WHY", "Why did it happen"]),
        (2, &["3.", "PART OF", "part of something larger"]),
        (3, &["4.", "IMPACT", "What is the impact"]),
        (4, &["5.", "ACTION", "What action", "RECOMMEND"]),
    ];

    let lines: Vec<&str> = text.lines().collect();

    for (idx, patterns) in &question_patterns {
        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let matches = patterns
                .iter()
                .any(|p| trimmed.starts_with(p) || trimmed.contains(p));

            if matches && trimmed.len() > 20 {
                // Collect the answer: this line plus a few following lines
                let mut answer_lines = vec![trimmed.to_string()];
                for subsequent in lines.iter().skip(line_idx + 1).take(5) {
                    let sub_trimmed = subsequent.trim();
                    if sub_trimmed.is_empty() {
                        break;
                    }
                    // Stop if we hit the next question
                    let is_next_question = question_patterns
                        .iter()
                        .any(|(qi, ps)| {
                            *qi != *idx
                                && ps.iter().any(|p| sub_trimmed.starts_with(p))
                        });
                    if is_next_question {
                        break;
                    }
                    answer_lines.push(sub_trimmed.to_string());
                }
                answers.push((*idx, answer_lines.join(" ")));
                break;
            }
        }
    }

    answers
}

/// Extract a named section from text (e.g., "WHAT HAPPENED: ...").
fn extract_section(text: &str, section_name: &str) -> String {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.to_uppercase().contains(&section_name.to_uppercase()) {
            let content = trimmed
                .split(':')
                .skip(1)
                .collect::<Vec<_>>()
                .join(":")
                .trim()
                .to_string();
            if !content.is_empty() {
                return content;
            }
        }
    }
    String::new()
}

/// Estimate cost based on token usage (Sonnet pricing).
fn estimate_cost(input_tokens: u64, output_tokens: u64) -> f64 {
    let input_cost = (input_tokens as f64 / 1_000_000.0) * 3.0;
    let output_cost = (output_tokens as f64 / 1_000_000.0) * 15.0;
    ((input_cost + output_cost) * 10000.0).round() / 10000.0
}

/// Take the last `max` messages from the history (sliding window).
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- Depth auto-selection -----------------------------------------------

    #[test]
    fn test_auto_select_depth_event_critical() {
        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({"severity": "CRITICAL"}),
        };
        assert_eq!(auto_select_depth(&target), InvestigationDepth::Deep);
    }

    #[test]
    fn test_auto_select_depth_event_high() {
        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({"severity": "HIGH"}),
        };
        assert_eq!(auto_select_depth(&target), InvestigationDepth::Deep);
    }

    #[test]
    fn test_auto_select_depth_event_medium() {
        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({"severity": "MEDIUM"}),
        };
        assert_eq!(auto_select_depth(&target), InvestigationDepth::Standard);
    }

    #[test]
    fn test_auto_select_depth_event_low() {
        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({"severity": "LOW"}),
        };
        assert_eq!(auto_select_depth(&target), InvestigationDepth::Quick);
    }

    #[test]
    fn test_auto_select_depth_event_no_severity() {
        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({}),
        };
        // Default for events with no severity is MEDIUM -> Standard
        assert_eq!(auto_select_depth(&target), InvestigationDepth::Standard);
    }

    #[test]
    fn test_auto_select_depth_alert() {
        let target = InvestigationTarget::Alert {
            alert_id: "alert-1".into(),
            alert_data: json!({"severity": "CRITICAL"}),
        };
        assert_eq!(auto_select_depth(&target), InvestigationDepth::Deep);
    }

    #[test]
    fn test_auto_select_depth_alert_no_severity() {
        let target = InvestigationTarget::Alert {
            alert_id: "alert-1".into(),
            alert_data: json!({}),
        };
        // Default for alerts with no severity is HIGH -> Deep
        assert_eq!(auto_select_depth(&target), InvestigationDepth::Deep);
    }

    #[test]
    fn test_auto_select_depth_server() {
        let target = InvestigationTarget::Server {
            server_name: "web-01".into(),
        };
        assert_eq!(auto_select_depth(&target), InvestigationDepth::Standard);
    }

    #[test]
    fn test_auto_select_depth_time_range() {
        let target = InvestigationTarget::TimeRange {
            start: Utc::now() - chrono::Duration::hours(2),
            end: Utc::now(),
        };
        assert_eq!(auto_select_depth(&target), InvestigationDepth::Standard);
    }

    #[test]
    fn test_auto_select_depth_freeform() {
        let target = InvestigationTarget::Freeform {
            query: "check SSH keys".into(),
        };
        assert_eq!(auto_select_depth(&target), InvestigationDepth::Standard);
    }

    // -- Auto-escalation ---------------------------------------------------

    #[test]
    fn test_should_escalate_standard_with_confirmed_threat() {
        let state = make_test_state(InvestigationDepth::Standard);
        let mut state = state;
        state.verdict = Some("ConfirmedThreat".to_string());
        assert!(should_escalate(&state));
    }

    #[test]
    fn test_should_escalate_standard_with_suggestions() {
        let mut state = make_test_state(InvestigationDepth::Standard);
        state.suggestions.push(InvestigationSuggestion {
            id: "s-1".into(),
            parent_investigation_id: "inv-1".into(),
            suggested_target: InvestigationTarget::Server {
                server_name: "evil".into(),
            },
            reason: "suspicious".into(),
            priority: "high".into(),
        });
        assert!(should_escalate(&state));
    }

    #[test]
    fn test_should_escalate_standard_with_kill_chain() {
        let mut state = make_test_state(InvestigationDepth::Standard);
        state.accumulated_text = "Found evidence of a kill chain pattern.".to_string();
        assert!(should_escalate(&state));
    }

    #[test]
    fn test_should_not_escalate_already_deep() {
        let mut state = make_test_state(InvestigationDepth::Deep);
        state.verdict = Some("ConfirmedThreat".to_string());
        assert!(!should_escalate(&state));
    }

    #[test]
    fn test_should_not_escalate_quick() {
        let mut state = make_test_state(InvestigationDepth::Quick);
        state.verdict = Some("ConfirmedThreat".to_string());
        assert!(!should_escalate(&state));
    }

    #[test]
    fn test_should_not_escalate_benign() {
        let state = make_test_state(InvestigationDepth::Standard);
        assert!(!should_escalate(&state));
    }

    // -- Verdict extraction ------------------------------------------------

    #[test]
    fn test_extract_verdict_confirmed_threat() {
        let text = "After analysis:\n\n[VERDICT confidence=85]\nConfirmedThreat\n[/VERDICT]";
        let result = extract_verdict(text);
        assert!(result.is_some());
        let (verdict, confidence) = result.unwrap();
        assert_eq!(verdict, "ConfirmedThreat");
        assert!((confidence - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_extract_verdict_false_positive() {
        let text = "[VERDICT confidence=95]\nFalsePositive\n[/VERDICT]";
        let result = extract_verdict(text);
        assert!(result.is_some());
        let (verdict, confidence) = result.unwrap();
        assert_eq!(verdict, "FalsePositive");
        assert!((confidence - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_extract_verdict_benign() {
        let text = "[VERDICT confidence=70]\nBenign\n[/VERDICT]";
        let result = extract_verdict(text);
        assert!(result.is_some());
        let (verdict, _) = result.unwrap();
        assert_eq!(verdict, "Benign");
    }

    #[test]
    fn test_extract_verdict_suspicious() {
        let text = "[VERDICT confidence=60]\nSuspicious\n[/VERDICT]";
        let result = extract_verdict(text);
        assert!(result.is_some());
        let (verdict, _) = result.unwrap();
        assert_eq!(verdict, "Suspicious");
    }

    #[test]
    fn test_extract_verdict_none() {
        let text = "No verdict here, just analysis.";
        assert!(extract_verdict(text).is_none());
    }

    #[test]
    fn test_extract_verdict_malformed() {
        let text = "[VERDICT]\nBenign\n[/VERDICT]"; // Missing confidence
        assert!(extract_verdict(text).is_none());
    }

    // -- Impact extraction -------------------------------------------------

    #[test]
    fn test_extract_impact_full() {
        let text = r#"
Some analysis.

[IMPACT]
data_accessed: /etc/passwd, /home/user/.ssh/id_rsa
data_modified: none
data_exfiltrated: evidence of data sent to external IP
blast_radius: 2 servers affected
[/IMPACT]

More text.
"#;
        let result = extract_impact(text);
        assert!(result.is_some());
        let impact = result.unwrap();
        assert_eq!(impact.data_accessed.len(), 2);
        assert!(impact.data_accessed.contains(&"/etc/passwd".to_string()));
        assert!(impact.data_accessed.contains(&"/home/user/.ssh/id_rsa".to_string()));
        assert!(impact.data_modified.is_empty());
        assert!(impact.data_exfiltrated);
        assert_eq!(impact.blast_radius, "2 servers affected");
    }

    #[test]
    fn test_extract_impact_none() {
        let text = "No impact block here.";
        assert!(extract_impact(text).is_none());
    }

    #[test]
    fn test_extract_impact_no_exfiltration() {
        let text = r#"[IMPACT]
data_accessed: /var/log/syslog
data_modified: none
data_exfiltrated: none
blast_radius: 1 server
[/IMPACT]"#;
        let result = extract_impact(text);
        assert!(result.is_some());
        let impact = result.unwrap();
        assert_eq!(impact.data_accessed, vec!["/var/log/syslog"]);
        assert!(!impact.data_exfiltrated);
    }

    // -- Answer extraction -------------------------------------------------

    #[test]
    fn test_extract_answered_questions_numbered() {
        let text = r#"
1. WHAT HAPPENED: The MCP server accessed /etc/passwd and then made a network connection to 192.168.1.100.

2. WHY: This was triggered by a user prompt asking for system information.

3. PART OF: No, this appears to be an isolated incident.

4. IMPACT: Minimal impact, only read access to a non-sensitive file.

5. ACTION: No immediate action required. Consider adding a policy rule.
"#;
        let answers = extract_answered_questions(text);
        assert!(!answers.is_empty());
        // Should find at least some answers
        assert!(answers.len() >= 2);
    }

    #[test]
    fn test_extract_answered_questions_headings() {
        let text = r#"
WHAT HAPPENED: The server read configuration files and sent data externally.

WHY: Automated scan triggered by cron job.
"#;
        let answers = extract_answered_questions(text);
        assert!(!answers.is_empty());
    }

    #[test]
    fn test_extract_answered_questions_none() {
        let text = "Analyzing the server profile now...";
        let answers = extract_answered_questions(text);
        assert!(answers.is_empty());
    }

    // -- Target summarization ----------------------------------------------

    #[test]
    fn test_summarize_target_event() {
        let target = InvestigationTarget::Event {
            event_id: "evt-42".into(),
            event_data: json!({}),
        };
        assert_eq!(summarize_target(&target), "Event: evt-42");
    }

    #[test]
    fn test_summarize_target_alert() {
        let target = InvestigationTarget::Alert {
            alert_id: "alert-7".into(),
            alert_data: json!({}),
        };
        assert_eq!(summarize_target(&target), "Alert: alert-7");
    }

    #[test]
    fn test_summarize_target_server() {
        let target = InvestigationTarget::Server {
            server_name: "web-01".into(),
        };
        assert_eq!(summarize_target(&target), "Server: web-01");
    }

    #[test]
    fn test_summarize_target_freeform_short() {
        let target = InvestigationTarget::Freeform {
            query: "check SSH".into(),
        };
        assert_eq!(summarize_target(&target), "Query: check SSH");
    }

    #[test]
    fn test_summarize_target_freeform_long() {
        let target = InvestigationTarget::Freeform {
            query: "a".repeat(100),
        };
        let summary = summarize_target(&target);
        assert!(summary.len() < 80);
        assert!(summary.ends_with("..."));
    }

    // -- Initial questions -------------------------------------------------

    #[test]
    fn test_build_initial_questions() {
        let questions = build_initial_questions();
        assert_eq!(questions.len(), 5);
        assert!(!questions[0].answered);
        assert!(questions[0].answer.is_none());
        assert!(questions[0].question.contains("What happened"));
    }

    // -- User message building ---------------------------------------------

    #[test]
    fn test_build_initial_user_message_event() {
        let target = InvestigationTarget::Event {
            event_id: "evt-42".into(),
            event_data: json!({}),
        };
        let msg = build_initial_user_message(&target);
        assert!(msg.contains("evt-42"));
        assert!(msg.contains("INVESTIGATION COMPLETE"));
    }

    #[test]
    fn test_build_initial_user_message_alert() {
        let target = InvestigationTarget::Alert {
            alert_id: "alert-7".into(),
            alert_data: json!({}),
        };
        let msg = build_initial_user_message(&target);
        assert!(msg.contains("alert-7"));
        assert!(msg.contains("true positive"));
    }

    #[test]
    fn test_build_initial_user_message_server() {
        let target = InvestigationTarget::Server {
            server_name: "web-01".into(),
        };
        let msg = build_initial_user_message(&target);
        assert!(msg.contains("web-01"));
        assert!(msg.contains("comprehensive security review"));
    }

    #[test]
    fn test_build_initial_user_message_freeform() {
        let target = InvestigationTarget::Freeform {
            query: "check SSH keys".into(),
        };
        let msg = build_initial_user_message(&target);
        assert!(msg.contains("check SSH keys"));
    }

    // -- Cost estimation ---------------------------------------------------

    #[test]
    fn test_estimate_cost() {
        let cost = estimate_cost(50_000, 20_000);
        assert!((cost - 0.45).abs() < 0.001);
    }

    #[test]
    fn test_estimate_cost_zero() {
        assert_eq!(estimate_cost(0, 0), 0.0);
    }

    // -- Sliding window ----------------------------------------------------

    #[test]
    fn test_sliding_window_small() {
        let messages: Vec<Message> = (0..5)
            .map(|i| Message {
                role: "user".to_string(),
                content: MessageContent::Text(format!("msg {}", i)),
            })
            .collect();
        let window = sliding_window(&messages, 40);
        assert_eq!(window.len(), 5);
    }

    #[test]
    fn test_sliding_window_large() {
        let messages: Vec<Message> = (0..50)
            .map(|i| Message {
                role: "user".to_string(),
                content: MessageContent::Text(format!("msg {}", i)),
            })
            .collect();
        let window = sliding_window(&messages, 40);
        assert_eq!(window.len(), 40);
    }

    // -- Impact field extraction -------------------------------------------

    #[test]
    fn test_extract_impact_field_list() {
        let body = "data_accessed: /etc/passwd, /home/user/.ssh/id_rsa\ndata_modified: none";
        let result = extract_impact_field(body, "data_accessed");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"/etc/passwd".to_string()));
    }

    #[test]
    fn test_extract_impact_field_none() {
        let body = "data_accessed: none";
        let result = extract_impact_field(body, "data_accessed");
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_impact_field_missing() {
        let body = "something: else";
        let result = extract_impact_field(body, "data_accessed");
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_impact_single_field() {
        let body = "blast_radius: 3 servers";
        let result = extract_impact_single_field(body, "blast_radius");
        assert_eq!(result, Some("3 servers".to_string()));
    }

    // -- Section extraction ------------------------------------------------

    #[test]
    fn test_extract_section() {
        let text = "WHAT HAPPENED: Server read /etc/passwd\nOther stuff";
        let result = extract_section(text, "WHAT HAPPENED");
        assert_eq!(result, "Server read /etc/passwd");
    }

    #[test]
    fn test_extract_section_missing() {
        let text = "No relevant section here.";
        let result = extract_section(text, "WHAT HAPPENED");
        assert!(result.is_empty());
    }

    // -- Progress and result types serde -----------------------------------

    #[test]
    fn test_investigation_status_serde() {
        let statuses = vec![
            InvestigationStatus::Initializing,
            InvestigationStatus::Running,
            InvestigationStatus::AwaitingUser,
            InvestigationStatus::Complete,
            InvestigationStatus::Cancelled,
            InvestigationStatus::Failed {
                error: "timeout".into(),
            },
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let parsed: InvestigationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, status);
        }
    }

    #[test]
    fn test_investigation_progress_serde() {
        let progress = InvestigationProgress {
            investigation_id: "inv-1".into(),
            status: InvestigationStatus::Running,
            target_summary: "Event: evt-42".into(),
            depth: InvestigationDepth::Standard,
            questions_answered: 2,
            questions_total: 5,
            tool_calls_count: 5,
            max_tool_calls: 15,
            elapsed_secs: 45,
            findings_count: 1,
            current_activity: "Checking server profile...".into(),
        };
        let json = serde_json::to_string(&progress).unwrap();
        let parsed: InvestigationProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.investigation_id, "inv-1");
        assert_eq!(parsed.questions_answered, 2);
    }

    #[test]
    fn test_investigation_result_serde() {
        let result = InvestigationResult {
            investigation_id: "inv-1".into(),
            target: InvestigationTarget::Event {
                event_id: "evt-42".into(),
                event_data: json!({}),
            },
            depth: InvestigationDepth::Standard,
            status: InvestigationStatus::Complete,
            what_happened: "Server accessed files".into(),
            why_it_happened: "User triggered".into(),
            part_of_larger: None,
            impact: ImpactAssessment {
                data_accessed: vec!["/etc/passwd".into()],
                data_modified: Vec::new(),
                data_exfiltrated: false,
                blast_radius: "1 server".into(),
                severity: "Low".into(),
            },
            recommendations: vec!["Add policy rule".into()],
            related_events: vec!["evt-43".into()],
            evidence_ids: vec!["ev-1".into()],
            suggestions: Vec::new(),
            verdict: "Benign".into(),
            confidence: 0.85,
            narrative: "The investigation found...".into(),
            total_tool_calls: 5,
            total_input_tokens: 10000,
            total_output_tokens: 3000,
            estimated_cost_usd: 0.075,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        let parsed: InvestigationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.investigation_id, "inv-1");
        assert_eq!(parsed.verdict, "Benign");
        assert_eq!(parsed.total_tool_calls, 5);
    }

    #[test]
    fn test_impact_assessment_serde() {
        let impact = ImpactAssessment {
            data_accessed: vec!["/etc/hosts".into()],
            data_modified: vec!["/tmp/test".into()],
            data_exfiltrated: true,
            blast_radius: "3 servers".into(),
            severity: "High".into(),
        };
        let json = serde_json::to_string(&impact).unwrap();
        let parsed: ImpactAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.data_accessed, vec!["/etc/hosts"]);
        assert!(parsed.data_exfiltrated);
    }

    #[test]
    fn test_investigation_question_serde() {
        let q = InvestigationQuestion {
            question: "What happened?".into(),
            answer: Some("Server read files".into()),
            answered: true,
        };
        let json = serde_json::to_string(&q).unwrap();
        let parsed: InvestigationQuestion = serde_json::from_str(&json).unwrap();
        assert!(parsed.answered);
        assert_eq!(parsed.answer, Some("Server read files".to_string()));
    }

    #[test]
    fn test_root_cause_serde() {
        let rc = RootCause {
            description: "Prompt injection via malicious MCP response".into(),
            confidence: 0.9,
            evidence: vec!["ev-1".into(), "ev-2".into()],
        };
        let json = serde_json::to_string(&rc).unwrap();
        let parsed: RootCause = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.confidence, 0.9);
        assert_eq!(parsed.evidence.len(), 2);
    }

    // -- Integration-level tests with mock ---------------------------------

    use crate::cloud_api::{CloudProvider, StopReason, TokenUsage as CloudTokenUsage};
    use async_trait::async_trait;

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

        fn tool_use_response(
            tool_name: &str,
            tool_id: &str,
            input: serde_json::Value,
        ) -> AgentResponse {
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
                Ok(Self::text_response(
                    "INVESTIGATION COMPLETE\n\n[VERDICT confidence=80]\nBenign\n[/VERDICT]",
                ))
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

    fn make_engine(provider: MockCloudProvider) -> InvestigationEngine {
        let client = Arc::new(CloudApiClient::new(Box::new(provider)));
        let sandbox = Arc::new(ToolSandbox::new());
        InvestigationEngine::new(client, sandbox, "mock-model".to_string())
    }

    fn make_test_state(depth: InvestigationDepth) -> InvestigationState {
        InvestigationState {
            investigation_id: "inv-test".into(),
            target: InvestigationTarget::Event {
                event_id: "evt-1".into(),
                event_data: json!({}),
            },
            depth,
            status: InvestigationStatus::Running,
            messages: Vec::new(),
            system_prompt: String::new(),
            tool_calls: 0,
            questions_answered: build_initial_questions(),
            findings: Vec::new(),
            suggestions: Vec::new(),
            evidence_ids: Vec::new(),
            related_events: Vec::new(),
            accumulated_text: String::new(),
            current_activity: String::new(),
            verdict: None,
            confidence: None,
            impact: None,
            input_tokens: 0,
            output_tokens: 0,
            started_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_start_investigation_event() {
        let engine = make_engine(MockCloudProvider::new(vec![]));
        let target = InvestigationTarget::Event {
            event_id: "evt-42".into(),
            event_data: json!({"severity": "HIGH"}),
        };
        let progress = engine
            .start_investigation(target, None)
            .await
            .unwrap();

        assert!(progress.investigation_id.starts_with("inv-"));
        assert_eq!(progress.status, InvestigationStatus::Running);
        assert_eq!(progress.depth, InvestigationDepth::Deep); // HIGH -> Deep
        assert_eq!(progress.questions_total, 5);
        assert_eq!(progress.questions_answered, 0);
        assert_eq!(progress.tool_calls_count, 0);
    }

    #[tokio::test]
    async fn test_start_investigation_server() {
        let engine = make_engine(MockCloudProvider::new(vec![]));
        let target = InvestigationTarget::Server {
            server_name: "web-01".into(),
        };
        let progress = engine
            .start_investigation(target, Some(InvestigationDepth::Quick))
            .await
            .unwrap();

        assert_eq!(progress.depth, InvestigationDepth::Quick);
        assert!(progress.target_summary.contains("web-01"));
    }

    #[tokio::test]
    async fn test_start_investigation_freeform() {
        let engine = make_engine(MockCloudProvider::new(vec![]));
        let target = InvestigationTarget::Freeform {
            query: "Has any server accessed SSH keys?".into(),
        };
        let progress = engine
            .start_investigation(target, None)
            .await
            .unwrap();

        assert_eq!(progress.depth, InvestigationDepth::Standard);
        assert!(progress.target_summary.contains("SSH keys"));
    }

    #[tokio::test]
    async fn test_investigation_loop_simple_completion() {
        let engine = make_engine(MockCloudProvider::new(vec![
            MockCloudProvider::text_response(
                r#"After thorough analysis:

1. WHAT HAPPENED: The server accessed system files for routine monitoring.
2. WHY: This was an automated health check triggered by user configuration.
3. PART OF: No, this is not part of any attack chain.
4. IMPACT: No sensitive data accessed.
5. ACTION: No action needed.

[VERDICT confidence=95]
FalsePositive
[/VERDICT]

[IMPACT]
data_accessed: /var/log/syslog
data_modified: none
data_exfiltrated: none
blast_radius: 1 server
[/IMPACT]

INVESTIGATION COMPLETE"#,
            ),
        ]));

        let target = InvestigationTarget::Event {
            event_id: "evt-42".into(),
            event_data: json!({"severity": "LOW"}),
        };

        let progress = engine
            .start_investigation(target, None)
            .await
            .unwrap();
        let inv_id = progress.investigation_id.clone();

        let result = engine.run_investigation_loop(&inv_id).await.unwrap();
        assert_eq!(result.status, InvestigationStatus::Complete);
        assert_eq!(result.verdict, "FalsePositive");
        assert!((result.confidence - 0.95).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_investigation_loop_with_tool_calls() {
        let engine = make_engine(MockCloudProvider::new(vec![
            MockCloudProvider::tool_use_response(
                "get_full_session",
                "tool_01",
                json!({"server_name": "test-server"}),
            ),
            MockCloudProvider::text_response(
                "[VERDICT confidence=70]\nBenign\n[/VERDICT]\n\nINVESTIGATION COMPLETE",
            ),
        ]));

        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({"severity": "LOW"}),
        };

        let progress = engine.start_investigation(target, None).await.unwrap();
        let inv_id = progress.investigation_id.clone();

        let result = engine.run_investigation_loop(&inv_id).await.unwrap();
        assert_eq!(result.status, InvestigationStatus::Complete);
        assert!(result.total_tool_calls >= 1);
    }

    #[tokio::test]
    async fn test_investigation_cancellation() {
        let engine = make_engine(MockCloudProvider::new(vec![]));
        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({}),
        };

        let progress = engine.start_investigation(target, None).await.unwrap();
        let inv_id = progress.investigation_id.clone();

        engine.cancel_investigation(&inv_id).await.unwrap();

        let progress = engine.get_progress(&inv_id).await.unwrap();
        assert_eq!(progress.status, InvestigationStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_investigation_cancel_nonexistent() {
        let engine = make_engine(MockCloudProvider::new(vec![]));
        let result = engine.cancel_investigation("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_investigations() {
        let engine = make_engine(MockCloudProvider::new(vec![]));

        let t1 = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({}),
        };
        let t2 = InvestigationTarget::Server {
            server_name: "web-01".into(),
        };

        engine.start_investigation(t1, None).await.unwrap();
        engine.start_investigation(t2, None).await.unwrap();

        let list = engine.list_investigations().await;
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn test_get_progress_running() {
        let engine = make_engine(MockCloudProvider::new(vec![]));
        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({}),
        };

        let progress = engine.start_investigation(target, None).await.unwrap();
        let inv_id = progress.investigation_id.clone();

        let live = engine.get_progress(&inv_id).await.unwrap();
        assert_eq!(live.status, InvestigationStatus::Running);
        assert_eq!(live.questions_total, 5);
    }

    #[tokio::test]
    async fn test_get_progress_not_found() {
        let engine = make_engine(MockCloudProvider::new(vec![]));
        let result = engine.get_progress("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_result_completed() {
        let engine = make_engine(MockCloudProvider::new(vec![
            MockCloudProvider::text_response(
                "[VERDICT confidence=80]\nBenign\n[/VERDICT]\n\nINVESTIGATION COMPLETE",
            ),
        ]));

        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({}),
        };

        let progress = engine.start_investigation(target, None).await.unwrap();
        let inv_id = progress.investigation_id.clone();

        engine.run_investigation_loop(&inv_id).await.unwrap();

        let result = engine.get_result(&inv_id).await.unwrap();
        assert_eq!(result.verdict, "Benign");
        assert_eq!(result.status, InvestigationStatus::Complete);
    }

    #[tokio::test]
    async fn test_get_result_not_found() {
        let engine = make_engine(MockCloudProvider::new(vec![]));
        let result = engine.get_result("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_investigation_token_tracking() {
        let engine = make_engine(MockCloudProvider::new(vec![
            MockCloudProvider::text_response(
                "[VERDICT confidence=80]\nBenign\n[/VERDICT]\n\nINVESTIGATION COMPLETE",
            ),
        ]));

        let target = InvestigationTarget::Event {
            event_id: "evt-1".into(),
            event_data: json!({}),
        };

        let progress = engine.start_investigation(target, None).await.unwrap();
        let inv_id = progress.investigation_id.clone();

        let result = engine.run_investigation_loop(&inv_id).await.unwrap();
        assert!(result.total_input_tokens > 0);
        assert!(result.total_output_tokens > 0);
        assert!(result.estimated_cost_usd > 0.0);
    }
}
