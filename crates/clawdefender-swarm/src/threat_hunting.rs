//! Proactive threat hunting engine — launches AI-driven hunts that investigate
//! without a specific trigger, looking for threats the rule-based system might
//! have missed.
//!
//! The hunter feeds Claude threat-hunting prompts, provides scan tools, and
//! loops through the tool-use cycle until the model signals HUNT COMPLETE
//! or guardrails are hit (max tool calls, max duration).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::cloud_api::{
    build_tool_result_message, extract_text, extract_tool_calls, AgentRequest, AgentResponse,
    CloudApiClient, ContentBlock, Message, MessageContent,
};
use crate::scan_tools::{get_available_tools, ScanToolExecutor};
use crate::tool_sandbox::ToolSandbox;
use crate::tools::ToolResult;

// ---------------------------------------------------------------------------
// Constants / guardrails
// ---------------------------------------------------------------------------

/// Maximum tool-call iterations before we force completion.
const MAX_TOOL_CALLS: usize = 50;

/// Maximum wall-clock time for a single hunt.
const MAX_HUNT_DURATION: Duration = Duration::from_secs(900); // 15 min

/// Maximum messages to send in a single API request (sliding window).
const MAX_MESSAGES_IN_REQUEST: usize = 40;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// The type of threat hunt to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HuntType {
    GeneralSweep,
    ServerFocused { server: String },
    PatternSearch { pattern: String },
    HistoricalReview { period: String },
}

/// A time range for the hunt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// A single finding discovered during a hunt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntFinding {
    pub id: String,
    pub pattern_name: String,
    pub description: String,
    pub involved_servers: Vec<String>,
    pub involved_events: Vec<String>,
    pub time_range: TimeRange,
    pub confidence: f64,
    pub severity: String,
    pub recommended_investigation: String,
}

/// Current status of a hunt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HuntStatus {
    Running,
    Completed,
    Cancelled,
    Failed { error: String },
}

/// Real-time progress snapshot for a hunt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntProgress {
    pub hunt_id: String,
    pub hunt_type: HuntType,
    pub status: HuntStatus,
    pub patterns_checked: Vec<String>,
    pub findings_count: usize,
    pub tool_calls_count: usize,
    pub elapsed_secs: u64,
}

/// Complete result of a finished (or failed) hunt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntResult {
    pub hunt_id: String,
    pub hunt_type: HuntType,
    pub time_range: TimeRange,
    pub status: HuntStatus,
    pub findings: Vec<HuntFinding>,
    pub patterns_checked: Vec<String>,
    pub summary: String,
    pub total_tool_calls: usize,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub estimated_cost_usd: f64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Temporal comparison between two periods for a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodComparison {
    pub server: String,
    pub period_a: PeriodStats,
    pub period_b: PeriodStats,
    pub changes: Vec<String>,
}

/// Statistics for a single period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodStats {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub event_count: usize,
    pub unique_tools: usize,
    pub unique_files: usize,
    pub unique_network_destinations: usize,
    pub anomaly_score_avg: f64,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Internal mutable state for a single running hunt.
struct HuntState {
    hunt_id: String,
    hunt_type: HuntType,
    time_range: TimeRange,
    status: HuntStatus,
    findings: Vec<HuntFinding>,
    patterns_checked: Vec<String>,
    tool_calls: usize,
    summary: String,
    input_tokens: u64,
    output_tokens: u64,
    started_at: DateTime<Utc>,

    // Conversation
    messages: Vec<Message>,
    system_prompt: String,
}

// ---------------------------------------------------------------------------
// ThreatHunter
// ---------------------------------------------------------------------------

/// Manages AI-powered threat hunts — creation, the agentic loop, progress
/// queries, cancellation, and result persistence.
pub struct ThreatHunter {
    hunts: Mutex<HashMap<String, HuntState>>,
    results: Mutex<HashMap<String, HuntResult>>,
    cloud_client: Arc<CloudApiClient>,
    tool_sandbox: Arc<ToolSandbox>,
    scan_tool_executor: Arc<ScanToolExecutor>,
    model: String,
    hunts_dir: PathBuf,
}

impl ThreatHunter {
    pub fn new(
        cloud_client: Arc<CloudApiClient>,
        tool_sandbox: Arc<ToolSandbox>,
        model: String,
        hunts_dir: PathBuf,
    ) -> Self {
        Self {
            hunts: Mutex::new(HashMap::new()),
            results: Mutex::new(HashMap::new()),
            cloud_client,
            tool_sandbox,
            scan_tool_executor: Arc::new(ScanToolExecutor::new()),
            model,
            hunts_dir,
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Start a new threat hunt. Returns progress immediately; the hunt loop
    /// runs via a separate call to `run_hunt_loop`.
    pub async fn start_hunt(
        &self,
        hunt_type: HuntType,
        time_range: TimeRange,
    ) -> Result<HuntProgress> {
        let hunt_id = format!("hunt-{}", uuid::Uuid::new_v4());
        let now = Utc::now();

        let system_prompt = build_hunt_prompt(&hunt_type);

        let state = HuntState {
            hunt_id: hunt_id.clone(),
            hunt_type: hunt_type.clone(),
            time_range: time_range.clone(),
            status: HuntStatus::Running,
            findings: Vec::new(),
            patterns_checked: Vec::new(),
            tool_calls: 0,
            summary: String::new(),
            input_tokens: 0,
            output_tokens: 0,
            started_at: now,
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text(
                    "Begin the threat hunt. Use the available tools to investigate and \
                     emit [HUNT_FINDING] blocks as you discover issues. Signal \
                     HUNT COMPLETE when finished."
                        .to_string(),
                ),
            }],
            system_prompt,
        };

        let progress = HuntProgress {
            hunt_id: hunt_id.clone(),
            hunt_type,
            status: HuntStatus::Running,
            patterns_checked: Vec::new(),
            findings_count: 0,
            tool_calls_count: 0,
            elapsed_secs: 0,
        };

        let mut hunts = self.hunts.lock().await;
        hunts.insert(hunt_id, state);

        Ok(progress)
    }

    /// Run the agentic hunt loop for a given hunt ID.
    pub async fn run_hunt_loop(&self, hunt_id: &str) -> Result<HuntResult> {
        let start_time = Instant::now();

        loop {
            // Check guardrails
            if start_time.elapsed() > MAX_HUNT_DURATION {
                self.set_hunt_summary(hunt_id, "Hunt terminated: max duration exceeded.".into())
                    .await;
                self.finalize_hunt(hunt_id, HuntStatus::Completed).await?;
                break;
            }

            {
                let hunts = self.hunts.lock().await;
                if let Some(state) = hunts.get(hunt_id) {
                    if state.status != HuntStatus::Running {
                        break;
                    }
                    if state.tool_calls >= MAX_TOOL_CALLS {
                        drop(hunts);
                        self.set_hunt_summary(
                            hunt_id,
                            "Hunt terminated: max tool calls reached.".into(),
                        )
                        .await;
                        self.finalize_hunt(hunt_id, HuntStatus::Completed).await?;
                        break;
                    }
                } else {
                    bail!("Hunt not found: {}", hunt_id);
                }
            }

            // Run a single turn of the agentic loop
            match self.run_single_turn(hunt_id).await {
                Ok(completed) => {
                    if completed {
                        self.finalize_hunt(hunt_id, HuntStatus::Completed).await?;
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("Hunt {} turn error: {}", hunt_id, e);
                    self.finalize_hunt(
                        hunt_id,
                        HuntStatus::Failed {
                            error: e.to_string(),
                        },
                    )
                    .await?;
                    break;
                }
            }
        }

        // Return the completed result
        let results = self.results.lock().await;
        results
            .get(hunt_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Hunt result not found after finalization"))
    }

    /// Get real-time progress for a hunt.
    pub async fn get_progress(&self, hunt_id: &str) -> Result<HuntProgress> {
        // Check running hunts first
        let hunts = self.hunts.lock().await;
        if let Some(state) = hunts.get(hunt_id) {
            let elapsed = Utc::now()
                .signed_duration_since(state.started_at)
                .num_seconds()
                .unsigned_abs();

            return Ok(HuntProgress {
                hunt_id: hunt_id.to_string(),
                hunt_type: state.hunt_type.clone(),
                status: state.status.clone(),
                patterns_checked: state.patterns_checked.clone(),
                findings_count: state.findings.len(),
                tool_calls_count: state.tool_calls,
                elapsed_secs: elapsed,
            });
        }
        drop(hunts);

        // Check completed results
        let results = self.results.lock().await;
        if let Some(result) = results.get(hunt_id) {
            return Ok(HuntProgress {
                hunt_id: hunt_id.to_string(),
                hunt_type: result.hunt_type.clone(),
                status: result.status.clone(),
                patterns_checked: result.patterns_checked.clone(),
                findings_count: result.findings.len(),
                tool_calls_count: result.total_tool_calls,
                elapsed_secs: 0,
            });
        }
        drop(results);

        // Try loading from disk
        let result = self.load_hunt_result(hunt_id).await?;
        Ok(HuntProgress {
            hunt_id: hunt_id.to_string(),
            hunt_type: result.hunt_type.clone(),
            status: result.status.clone(),
            patterns_checked: result.patterns_checked.clone(),
            findings_count: result.findings.len(),
            tool_calls_count: result.total_tool_calls,
            elapsed_secs: 0,
        })
    }

    /// Get the final result of a completed hunt.
    pub async fn get_result(&self, hunt_id: &str) -> Result<HuntResult> {
        let results = self.results.lock().await;
        if let Some(result) = results.get(hunt_id) {
            return Ok(result.clone());
        }
        drop(results);

        self.load_hunt_result(hunt_id).await
    }

    /// Cancel a running hunt.
    pub async fn cancel_hunt(&self, hunt_id: &str) -> Result<()> {
        let mut hunts = self.hunts.lock().await;
        if let Some(state) = hunts.get_mut(hunt_id) {
            if state.status == HuntStatus::Running {
                state.status = HuntStatus::Cancelled;
                state.summary = "Hunt cancelled by user.".to_string();
            }
            return Ok(());
        }
        bail!("Hunt not found or already completed: {}", hunt_id);
    }

    /// List all hunts (active and recently completed).
    pub async fn list_hunts(&self) -> Vec<HuntProgress> {
        let mut all = Vec::new();

        // Active hunts
        let hunts = self.hunts.lock().await;
        for state in hunts.values() {
            let elapsed = Utc::now()
                .signed_duration_since(state.started_at)
                .num_seconds()
                .unsigned_abs();

            all.push(HuntProgress {
                hunt_id: state.hunt_id.clone(),
                hunt_type: state.hunt_type.clone(),
                status: state.status.clone(),
                patterns_checked: state.patterns_checked.clone(),
                findings_count: state.findings.len(),
                tool_calls_count: state.tool_calls,
                elapsed_secs: elapsed,
            });
        }
        drop(hunts);

        // Completed results in memory
        let results = self.results.lock().await;
        for result in results.values() {
            all.push(HuntProgress {
                hunt_id: result.hunt_id.clone(),
                hunt_type: result.hunt_type.clone(),
                status: result.status.clone(),
                patterns_checked: result.patterns_checked.clone(),
                findings_count: result.findings.len(),
                tool_calls_count: result.total_tool_calls,
                elapsed_secs: 0,
            });
        }

        all
    }

    // -----------------------------------------------------------------------
    // Agentic loop internals
    // -----------------------------------------------------------------------

    /// Execute a single turn: send messages to Claude, process response,
    /// execute tool calls if any. Returns `true` if the hunt is complete.
    async fn run_single_turn(&self, hunt_id: &str) -> Result<bool> {
        // Build the API request
        let request = {
            let hunts = self.hunts.lock().await;
            let state = hunts
                .get(hunt_id)
                .ok_or_else(|| anyhow::anyhow!("Hunt not found"))?;

            let tools = get_available_tools(&crate::agent_session::SessionType::Scan {
                playbook: "threat_hunt".to_string(),
            });
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

        // Process the response
        let tool_calls = extract_tool_calls(&response);
        let text = extract_text(&response);

        // Update tokens
        {
            let mut hunts = self.hunts.lock().await;
            if let Some(state) = hunts.get_mut(hunt_id) {
                state.input_tokens += response.usage.input_tokens;
                state.output_tokens += response.usage.output_tokens;
            }
        }

        // Process text output: extract findings and hunt completion
        let hunt_complete = if !text.is_empty() {
            self.process_text_output(hunt_id, &text).await?
        } else {
            false
        };

        // Add assistant message to history
        {
            let mut hunts = self.hunts.lock().await;
            if let Some(state) = hunts.get_mut(hunt_id) {
                state.messages.push(Message {
                    role: "assistant".to_string(),
                    content: response_to_message_content(&response),
                });
            }
        }

        if hunt_complete {
            return Ok(true);
        }

        // If no tool calls, the model finished without explicit HUNT COMPLETE
        if tool_calls.is_empty() {
            return Ok(true);
        }

        // Execute tool calls
        let mut tool_results = Vec::new();

        for tc in &tool_calls {
            let result = if self.scan_tool_executor.handles_tool(&tc.name) {
                match self
                    .scan_tool_executor
                    .execute_scan_tool(&tc.name, &tc.input)
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
                self.tool_sandbox.execute_tool(tc, hunt_id).await
            };

            // Update tool call count
            {
                let mut hunts = self.hunts.lock().await;
                if let Some(state) = hunts.get_mut(hunt_id) {
                    state.tool_calls += 1;
                }
            }

            tool_results.push(result);
        }

        // Add tool results to message history
        {
            let mut hunts = self.hunts.lock().await;
            if let Some(state) = hunts.get_mut(hunt_id) {
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

    /// Process text output from Claude, extracting findings and the
    /// HUNT COMPLETE signal. Returns `true` if HUNT COMPLETE was found.
    async fn process_text_output(&self, hunt_id: &str, text: &str) -> Result<bool> {
        let mut hunt_complete = false;

        // Extract findings
        let findings = extract_hunt_findings(text);

        // Check for HUNT COMPLETE
        if text.contains("HUNT COMPLETE") {
            hunt_complete = true;
        }

        // Apply to hunt state
        {
            let mut hunts = self.hunts.lock().await;
            if let Some(state) = hunts.get_mut(hunt_id) {
                // Add findings
                for mut finding in findings {
                    finding.id = format!("HF-{}", state.findings.len() + 1);
                    state.findings.push(finding);
                }

                // Update summary if hunt is complete
                if hunt_complete {
                    state.summary = extract_summary(text);
                }
            }
        }

        Ok(hunt_complete)
    }

    /// Finalize a hunt: move from active hunts to results, persist to disk.
    async fn finalize_hunt(&self, hunt_id: &str, final_status: HuntStatus) -> Result<()> {
        let result = {
            let mut hunts = self.hunts.lock().await;
            let state = hunts
                .get_mut(hunt_id)
                .ok_or_else(|| anyhow::anyhow!("Hunt not found: {}", hunt_id))?;

            state.status = final_status.clone();

            let cost = estimate_cost(state.input_tokens, state.output_tokens);

            let result = HuntResult {
                hunt_id: hunt_id.to_string(),
                hunt_type: state.hunt_type.clone(),
                time_range: state.time_range.clone(),
                status: final_status,
                findings: state.findings.clone(),
                patterns_checked: state.patterns_checked.clone(),
                summary: state.summary.clone(),
                total_tool_calls: state.tool_calls,
                total_input_tokens: state.input_tokens,
                total_output_tokens: state.output_tokens,
                estimated_cost_usd: cost,
                started_at: state.started_at,
                completed_at: Some(Utc::now()),
            };

            // Remove from active hunts
            hunts.remove(hunt_id);

            result
        };

        // Store in results map
        {
            let mut results = self.results.lock().await;
            results.insert(hunt_id.to_string(), result.clone());
        }

        // Persist to disk
        self.save_hunt_result(&result).await?;

        Ok(())
    }

    async fn set_hunt_summary(&self, hunt_id: &str, summary: String) {
        let mut hunts = self.hunts.lock().await;
        if let Some(state) = hunts.get_mut(hunt_id) {
            state.summary = summary;
        }
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    async fn save_hunt_result(&self, result: &HuntResult) -> Result<()> {
        tokio::fs::create_dir_all(&self.hunts_dir).await?;
        let path = self.hunts_dir.join(format!("{}.json", result.hunt_id));
        let data = serde_json::to_string_pretty(result)?;
        tokio::fs::write(path, data).await?;
        Ok(())
    }

    async fn load_hunt_result(&self, hunt_id: &str) -> Result<HuntResult> {
        let path = self.hunts_dir.join(format!("{}.json", hunt_id));
        let data = tokio::fs::read_to_string(&path)
            .await
            .map_err(|_| anyhow::anyhow!("Hunt result not found: {}", hunt_id))?;
        let result: HuntResult = serde_json::from_str(&data)?;
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Prompt templates
// ---------------------------------------------------------------------------

/// Build the system prompt for a given hunt type.
pub fn build_hunt_prompt(hunt_type: &HuntType) -> String {
    match hunt_type {
        HuntType::GeneralSweep => {
            "You are a threat hunter reviewing this system's recent security activity.\n\
             Your job is to find threats that the automated system might have missed:\n\
             1. Look for patterns ACROSS servers (coordinated activity)\n\
             2. Look for GRADUAL changes (slow privilege escalation)\n\
             3. Look for TIMING anomalies (unusual hours)\n\
             4. Look for SUBTLE exfiltration (small data amounts to unusual destinations)\n\
             5. Cross-reference with threat intelligence\n\n\
             Report findings using [HUNT_FINDING] tags:\n\
             [HUNT_FINDING pattern=\"cross-server relay\" severity=\"high\" confidence=0.8]\n\
             Description of what you found, which servers are involved, evidence chain.\n\
             [/HUNT_FINDING]\n\n\
             When done, output: HUNT COMPLETE"
                .to_string()
        }
        HuntType::ServerFocused { server } => {
            format!(
                "You are a threat hunter focused on the MCP server '{server}'.\n\
                 Investigate this server thoroughly:\n\
                 1. Review all recent activity for behavioral changes\n\
                 2. Check for unusual tool usage patterns\n\
                 3. Look for data access anomalies\n\
                 4. Verify network destinations are expected\n\
                 5. Compare current behavior against baseline\n\n\
                 Report findings using [HUNT_FINDING] tags:\n\
                 [HUNT_FINDING pattern=\"behavioral change\" severity=\"medium\" confidence=0.7]\n\
                 Description of what you found.\n\
                 [/HUNT_FINDING]\n\n\
                 When done, output: HUNT COMPLETE"
            )
        }
        HuntType::PatternSearch { pattern } => {
            format!(
                "You are a threat hunter searching for the attack pattern: '{pattern}'.\n\
                 Search across ALL servers for signs of this pattern:\n\
                 1. Check each server for indicators of this attack\n\
                 2. Look for partial implementations of the attack chain\n\
                 3. Check for precursor activities\n\
                 4. Review network traffic for related indicators\n\
                 5. Cross-reference tool usage with known attack sequences\n\n\
                 Report findings using [HUNT_FINDING] tags:\n\
                 [HUNT_FINDING pattern=\"{pattern}\" severity=\"high\" confidence=0.9]\n\
                 Description of what you found.\n\
                 [/HUNT_FINDING]\n\n\
                 When done, output: HUNT COMPLETE"
            )
        }
        HuntType::HistoricalReview { period } => {
            format!(
                "You are a threat hunter performing a historical review for the period: '{period}'.\n\
                 Compare current activity with historical baseline:\n\
                 1. Identify any drift in server behavior over time\n\
                 2. Look for new tools or capabilities that appeared\n\
                 3. Check for new network destinations\n\
                 4. Review changes in data access patterns\n\
                 5. Flag any indicators that emerged gradually\n\n\
                 Report findings using [HUNT_FINDING] tags:\n\
                 [HUNT_FINDING pattern=\"behavioral drift\" severity=\"medium\" confidence=0.6]\n\
                 Description of what you found.\n\
                 [/HUNT_FINDING]\n\n\
                 When done, output: HUNT COMPLETE"
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Extract `[HUNT_FINDING pattern="..." severity="..." confidence=N.N]...[/HUNT_FINDING]`
/// blocks from text.
pub fn extract_hunt_findings(text: &str) -> Vec<HuntFinding> {
    let mut findings = Vec::new();
    let mut remaining = text;

    while let Some(start_idx) = remaining.find("[HUNT_FINDING ") {
        let after_tag = &remaining[start_idx..];
        let Some(tag_end) = after_tag.find(']') else {
            remaining = &remaining[start_idx + 14..];
            continue;
        };

        let tag_line = &after_tag[..tag_end];
        let Some(end_idx) = after_tag.find("[/HUNT_FINDING]") else {
            remaining = &remaining[start_idx + tag_end..];
            continue;
        };

        let body = after_tag[tag_end + 1..end_idx].trim();

        // Parse tag attributes
        let pattern_name = parse_tag_attr(tag_line, "pattern").unwrap_or_else(|| "unknown".into());
        let severity = parse_tag_attr(tag_line, "severity").unwrap_or_else(|| "medium".into());
        let confidence = parse_tag_attr(tag_line, "confidence")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.5);

        // Parse involved servers from body
        let involved_servers = parse_body_list(body, "Servers");
        let involved_events = parse_body_list(body, "Events");
        let recommended_investigation = parse_body_field(body, "Investigation").unwrap_or_default();

        findings.push(HuntFinding {
            id: String::new(), // Assigned later
            pattern_name,
            description: body.to_string(),
            involved_servers,
            involved_events,
            time_range: TimeRange {
                start: Utc::now(),
                end: Utc::now(),
            },
            confidence,
            severity,
            recommended_investigation,
        });

        remaining = &remaining[start_idx + end_idx + 15..];
    }

    findings
}

/// Parse a `key=value` or `key="value"` attribute from a tag line.
fn parse_tag_attr(tag: &str, key: &str) -> Option<String> {
    let search = format!("{key}=");
    let idx = tag.find(&search)?;
    let after = &tag[idx + search.len()..];

    if let Some(content) = after.strip_prefix('"') {
        // Quoted value
        let end = content.find('"')?;
        Some(content[..end].to_string())
    } else {
        // Unquoted value
        let value = after
            .split_whitespace()
            .next()
            .unwrap_or(after)
            .trim_end_matches(']');
        Some(value.to_string())
    }
}

/// Extract a `Key: value` field from body text.
fn parse_body_field(body: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Extract a comma-separated list from a `Key: a, b, c` field in body text.
fn parse_body_list(body: &str, key: &str) -> Vec<String> {
    parse_body_field(body, key)
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

/// Extract a summary from the final hunt output.
fn extract_summary(text: &str) -> String {
    if let Some(idx) = text.find("HUNT COMPLETE") {
        let after = text[idx + 13..].trim();
        if !after.is_empty() {
            let summary = if after.len() > 500 {
                format!("{}...", &after[..500])
            } else {
                after.to_string()
            };
            return summary;
        }
    }

    if text.len() > 500 {
        format!("{}...", &text[text.len() - 500..])
    } else {
        text.to_string()
    }
}

/// Estimate cost based on token usage (Sonnet pricing as default).
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

/// Generate a PeriodComparison between two time windows for a server.
pub fn compare_periods(
    server: &str,
    period_a_start: DateTime<Utc>,
    period_a_end: DateTime<Utc>,
    period_b_start: DateTime<Utc>,
    period_b_end: DateTime<Utc>,
) -> PeriodComparison {
    // Placeholder — real implementation would query the event store
    let period_a = PeriodStats {
        start: period_a_start,
        end: period_a_end,
        event_count: 0,
        unique_tools: 0,
        unique_files: 0,
        unique_network_destinations: 0,
        anomaly_score_avg: 0.0,
    };

    let period_b = PeriodStats {
        start: period_b_start,
        end: period_b_end,
        event_count: 0,
        unique_tools: 0,
        unique_files: 0,
        unique_network_destinations: 0,
        anomaly_score_avg: 0.0,
    };

    PeriodComparison {
        server: server.to_string(),
        period_a,
        period_b,
        changes: vec!["No baseline data available for comparison".to_string()],
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

    // -- Finding extraction tests -------------------------------------------

    #[test]
    fn test_extract_hunt_findings_single() {
        let text = r#"
I found something suspicious:

[HUNT_FINDING pattern="cross-server relay" severity="high" confidence=0.85]
Server A reads credentials then Server B exfiltrates data.
Servers: web-01, db-01
Events: evt-1, evt-2
Investigation: Check network logs for unusual outbound traffic.
[/HUNT_FINDING]

Continuing analysis.
"#;
        let findings = extract_hunt_findings(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_name, "cross-server relay");
        assert_eq!(findings[0].severity, "high");
        assert!((findings[0].confidence - 0.85).abs() < 0.01);
        assert_eq!(findings[0].involved_servers, vec!["web-01", "db-01"]);
        assert_eq!(findings[0].involved_events, vec!["evt-1", "evt-2"]);
        assert!(findings[0]
            .recommended_investigation
            .contains("network logs"));
    }

    #[test]
    fn test_extract_hunt_findings_multiple() {
        let text = r#"
[HUNT_FINDING pattern="data exfiltration" severity="critical" confidence=0.9]
Large data transfer detected.
Servers: evil-server
[/HUNT_FINDING]

Some text between findings.

[HUNT_FINDING pattern="timing anomaly" severity="low" confidence=0.4]
Unusual activity at 3 AM.
Servers: web-01
[/HUNT_FINDING]
"#;
        let findings = extract_hunt_findings(text);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].pattern_name, "data exfiltration");
        assert_eq!(findings[0].severity, "critical");
        assert_eq!(findings[1].pattern_name, "timing anomaly");
        assert_eq!(findings[1].severity, "low");
    }

    #[test]
    fn test_extract_hunt_findings_none() {
        let text = "No findings here, just analysis.";
        let findings = extract_hunt_findings(text);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_extract_hunt_findings_malformed_no_end_tag() {
        let text = r#"
[HUNT_FINDING pattern="test" severity="medium" confidence=0.5]
This has no closing tag.
"#;
        let findings = extract_hunt_findings(text);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_extract_hunt_findings_unquoted_attrs() {
        let text = r#"
[HUNT_FINDING pattern=relay severity=high confidence=0.7]
Some finding description.
[/HUNT_FINDING]
"#;
        let findings = extract_hunt_findings(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_name, "relay");
        assert_eq!(findings[0].severity, "high");
        assert!((findings[0].confidence - 0.7).abs() < 0.01);
    }

    // -- Tag attribute parsing tests ----------------------------------------

    #[test]
    fn test_parse_tag_attr_quoted() {
        assert_eq!(
            parse_tag_attr(
                r#"[HUNT_FINDING pattern="cross-server" severity="high"]"#,
                "pattern"
            ),
            Some("cross-server".to_string())
        );
    }

    #[test]
    fn test_parse_tag_attr_unquoted() {
        assert_eq!(
            parse_tag_attr("[HUNT_FINDING confidence=0.85]", "confidence"),
            Some("0.85".to_string())
        );
    }

    #[test]
    fn test_parse_tag_attr_missing() {
        assert_eq!(
            parse_tag_attr("[HUNT_FINDING pattern=test]", "missing"),
            None
        );
    }

    // -- Body field parsing tests -------------------------------------------

    #[test]
    fn test_parse_body_field() {
        let body = "Servers: web-01, db-01\nEvents: evt-1\nInvestigation: Check logs";
        assert_eq!(
            parse_body_field(body, "Investigation"),
            Some("Check logs".to_string())
        );
    }

    #[test]
    fn test_parse_body_field_missing() {
        let body = "Servers: web-01";
        assert_eq!(parse_body_field(body, "Missing"), None);
    }

    #[test]
    fn test_parse_body_list() {
        let body = "Servers: web-01, db-01, api-server";
        let list = parse_body_list(body, "Servers");
        assert_eq!(list, vec!["web-01", "db-01", "api-server"]);
    }

    #[test]
    fn test_parse_body_list_empty() {
        let body = "No servers field here.";
        let list = parse_body_list(body, "Servers");
        assert!(list.is_empty());
    }

    // -- Summary extraction tests -------------------------------------------

    #[test]
    fn test_extract_summary_after_hunt_complete() {
        let text = "Analysis done.\n\nHUNT COMPLETE\n\nFound 2 issues, 1 critical.";
        let summary = extract_summary(text);
        assert!(summary.contains("Found 2 issues"));
    }

    #[test]
    fn test_extract_summary_fallback() {
        let text = "Some output without the completion marker.";
        let summary = extract_summary(text);
        assert_eq!(summary, text);
    }

    // -- Prompt template tests ----------------------------------------------

    #[test]
    fn test_build_hunt_prompt_general_sweep() {
        let prompt = build_hunt_prompt(&HuntType::GeneralSweep);
        assert!(prompt.contains("threat hunter"));
        assert!(prompt.contains("ACROSS servers"));
        assert!(prompt.contains("HUNT_FINDING"));
        assert!(prompt.contains("HUNT COMPLETE"));
    }

    #[test]
    fn test_build_hunt_prompt_server_focused() {
        let prompt = build_hunt_prompt(&HuntType::ServerFocused {
            server: "evil-server".into(),
        });
        assert!(prompt.contains("evil-server"));
        assert!(prompt.contains("behavioral changes"));
    }

    #[test]
    fn test_build_hunt_prompt_pattern_search() {
        let prompt = build_hunt_prompt(&HuntType::PatternSearch {
            pattern: "credential theft".into(),
        });
        assert!(prompt.contains("credential theft"));
        assert!(prompt.contains("attack pattern"));
    }

    #[test]
    fn test_build_hunt_prompt_historical_review() {
        let prompt = build_hunt_prompt(&HuntType::HistoricalReview {
            period: "last 7 days".into(),
        });
        assert!(prompt.contains("last 7 days"));
        assert!(prompt.contains("historical"));
    }

    // -- Cost estimation tests ----------------------------------------------

    #[test]
    fn test_estimate_cost() {
        let cost = estimate_cost(50_000, 20_000);
        assert!((cost - 0.45).abs() < 0.001);
    }

    #[test]
    fn test_estimate_cost_zero() {
        assert_eq!(estimate_cost(0, 0), 0.0);
    }

    // -- Period comparison tests --------------------------------------------

    #[test]
    fn test_compare_periods() {
        let now = Utc::now();
        let earlier = now - chrono::Duration::hours(24);

        let comparison = compare_periods(
            "web-01",
            earlier,
            now,
            now,
            now + chrono::Duration::hours(24),
        );

        assert_eq!(comparison.server, "web-01");
        assert!(!comparison.changes.is_empty());
        assert_eq!(comparison.period_a.event_count, 0);
        assert_eq!(comparison.period_b.event_count, 0);
    }

    // -- Data structure serde tests -----------------------------------------

    #[test]
    fn test_hunt_type_serde() {
        let types = vec![
            HuntType::GeneralSweep,
            HuntType::ServerFocused {
                server: "web-01".into(),
            },
            HuntType::PatternSearch {
                pattern: "exfil".into(),
            },
            HuntType::HistoricalReview {
                period: "7d".into(),
            },
        ];
        for ht in &types {
            let json = serde_json::to_string(ht).unwrap();
            let parsed: HuntType = serde_json::from_str(&json).unwrap();
            // Verify round-trip succeeds
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_hunt_status_serde() {
        let statuses = vec![
            HuntStatus::Running,
            HuntStatus::Completed,
            HuntStatus::Cancelled,
            HuntStatus::Failed {
                error: "timeout".into(),
            },
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let parsed: HuntStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, status);
        }
    }

    #[test]
    fn test_hunt_finding_serde() {
        let now = Utc::now();
        let finding = HuntFinding {
            id: "HF-1".into(),
            pattern_name: "cross-server relay".into(),
            description: "Suspicious activity".into(),
            involved_servers: vec!["web-01".into(), "db-01".into()],
            involved_events: vec!["evt-1".into()],
            time_range: TimeRange {
                start: now,
                end: now,
            },
            confidence: 0.85,
            severity: "high".into(),
            recommended_investigation: "Check logs".into(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let parsed: HuntFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "HF-1");
        assert_eq!(parsed.pattern_name, "cross-server relay");
        assert!((parsed.confidence - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_hunt_result_serde() {
        let now = Utc::now();
        let result = HuntResult {
            hunt_id: "hunt-001".into(),
            hunt_type: HuntType::GeneralSweep,
            time_range: TimeRange {
                start: now,
                end: now,
            },
            status: HuntStatus::Completed,
            findings: vec![],
            patterns_checked: vec!["cross-server".into()],
            summary: "No threats found.".into(),
            total_tool_calls: 10,
            total_input_tokens: 50000,
            total_output_tokens: 20000,
            estimated_cost_usd: 0.45,
            started_at: now,
            completed_at: Some(now),
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        let parsed: HuntResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hunt_id, "hunt-001");
        assert_eq!(parsed.total_tool_calls, 10);
    }

    #[test]
    fn test_hunt_progress_serde() {
        let progress = HuntProgress {
            hunt_id: "hunt-001".into(),
            hunt_type: HuntType::GeneralSweep,
            status: HuntStatus::Running,
            patterns_checked: vec!["relay".into()],
            findings_count: 2,
            tool_calls_count: 5,
            elapsed_secs: 120,
        };
        let json = serde_json::to_string(&progress).unwrap();
        let parsed: HuntProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hunt_id, "hunt-001");
        assert_eq!(parsed.findings_count, 2);
    }

    #[test]
    fn test_period_comparison_serde() {
        let now = Utc::now();
        let comparison = PeriodComparison {
            server: "web-01".into(),
            period_a: PeriodStats {
                start: now,
                end: now,
                event_count: 100,
                unique_tools: 5,
                unique_files: 10,
                unique_network_destinations: 3,
                anomaly_score_avg: 0.2,
            },
            period_b: PeriodStats {
                start: now,
                end: now,
                event_count: 150,
                unique_tools: 8,
                unique_files: 12,
                unique_network_destinations: 5,
                anomaly_score_avg: 0.4,
            },
            changes: vec!["Event count increased by 50%".into()],
        };
        let json = serde_json::to_string(&comparison).unwrap();
        let parsed: PeriodComparison = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.server, "web-01");
        assert_eq!(parsed.period_a.event_count, 100);
        assert_eq!(parsed.period_b.event_count, 150);
    }

    // -- Sliding window tests -----------------------------------------------

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
        match &window[0].content {
            MessageContent::Text(t) => assert_eq!(t, "msg 10"),
            _ => panic!("Expected text"),
        }
    }

    // -- Integration tests with mock provider --------------------------------

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
                Ok(Self::text_response("HUNT COMPLETE\n\nNo threats found."))
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

    fn make_hunter(provider: MockCloudProvider, hunts_dir: PathBuf) -> ThreatHunter {
        let client = Arc::new(CloudApiClient::new(Box::new(provider)));
        let sandbox = Arc::new(ToolSandbox::new());
        ThreatHunter::new(client, sandbox, "mock-model".to_string(), hunts_dir)
    }

    fn default_time_range() -> TimeRange {
        let now = Utc::now();
        TimeRange {
            start: now - chrono::Duration::hours(24),
            end: now,
        }
    }

    #[tokio::test]
    async fn test_start_hunt() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(MockCloudProvider::new(vec![]), dir.path().join("hunts"));

        let progress = hunter
            .start_hunt(HuntType::GeneralSweep, default_time_range())
            .await
            .unwrap();

        assert!(progress.hunt_id.starts_with("hunt-"));
        assert_eq!(progress.status, HuntStatus::Running);
        assert_eq!(progress.findings_count, 0);
        assert_eq!(progress.tool_calls_count, 0);
    }

    #[tokio::test]
    async fn test_start_hunt_server_focused() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(MockCloudProvider::new(vec![]), dir.path().join("hunts"));

        let progress = hunter
            .start_hunt(
                HuntType::ServerFocused {
                    server: "evil-server".into(),
                },
                default_time_range(),
            )
            .await
            .unwrap();

        assert!(progress.hunt_id.starts_with("hunt-"));
        assert_eq!(progress.status, HuntStatus::Running);
    }

    #[tokio::test]
    async fn test_start_hunt_pattern_search() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(MockCloudProvider::new(vec![]), dir.path().join("hunts"));

        let progress = hunter
            .start_hunt(
                HuntType::PatternSearch {
                    pattern: "credential theft".into(),
                },
                default_time_range(),
            )
            .await
            .unwrap();

        assert!(progress.hunt_id.starts_with("hunt-"));
    }

    #[tokio::test]
    async fn test_start_hunt_historical_review() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(MockCloudProvider::new(vec![]), dir.path().join("hunts"));

        let progress = hunter
            .start_hunt(
                HuntType::HistoricalReview {
                    period: "last 7 days".into(),
                },
                default_time_range(),
            )
            .await
            .unwrap();

        assert!(progress.hunt_id.starts_with("hunt-"));
    }

    #[tokio::test]
    async fn test_hunt_loop_simple_completion() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(
            MockCloudProvider::new(vec![MockCloudProvider::text_response(
                r#"
[HUNT_FINDING pattern="cross-server relay" severity="high" confidence=0.8]
Server A reads credentials then Server B exfiltrates data.
Servers: web-01, db-01
Events: evt-1, evt-2
Investigation: Check network logs.
[/HUNT_FINDING]

HUNT COMPLETE

Found 1 high-severity threat. Recommend immediate investigation.
"#,
            )]),
            dir.path().join("hunts"),
        );

        let progress = hunter
            .start_hunt(HuntType::GeneralSweep, default_time_range())
            .await
            .unwrap();
        let hunt_id = progress.hunt_id.clone();

        let result = hunter.run_hunt_loop(&hunt_id).await.unwrap();
        assert_eq!(result.status, HuntStatus::Completed);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, "high");
        assert_eq!(result.findings[0].pattern_name, "cross-server relay");
        assert!(result.summary.contains("immediate investigation"));
    }

    #[tokio::test]
    async fn test_hunt_loop_with_tool_calls() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(
            MockCloudProvider::new(vec![
                MockCloudProvider::tool_use_response(
                    "get_policy",
                    "tool_01",
                    serde_json::json!({}),
                ),
                MockCloudProvider::text_response("HUNT COMPLETE\n\nNo threats found."),
            ]),
            dir.path().join("hunts"),
        );

        let progress = hunter
            .start_hunt(HuntType::GeneralSweep, default_time_range())
            .await
            .unwrap();
        let hunt_id = progress.hunt_id.clone();

        let result = hunter.run_hunt_loop(&hunt_id).await.unwrap();
        assert_eq!(result.status, HuntStatus::Completed);
        assert!(result.total_tool_calls >= 1);
    }

    #[tokio::test]
    async fn test_cancel_hunt() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(MockCloudProvider::new(vec![]), dir.path().join("hunts"));

        let progress = hunter
            .start_hunt(HuntType::GeneralSweep, default_time_range())
            .await
            .unwrap();
        let hunt_id = progress.hunt_id.clone();

        hunter.cancel_hunt(&hunt_id).await.unwrap();

        let progress = hunter.get_progress(&hunt_id).await.unwrap();
        assert_eq!(progress.status, HuntStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_cancel_nonexistent_hunt() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(MockCloudProvider::new(vec![]), dir.path().join("hunts"));

        let result = hunter.cancel_hunt("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_hunt_result_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let hunts_dir = dir.path().join("hunts");

        let hunt_id;
        {
            let hunter = make_hunter(
                MockCloudProvider::new(vec![MockCloudProvider::text_response(
                    "HUNT COMPLETE\n\nAll clear.",
                )]),
                hunts_dir.clone(),
            );

            let progress = hunter
                .start_hunt(HuntType::GeneralSweep, default_time_range())
                .await
                .unwrap();
            hunt_id = progress.hunt_id.clone();

            let _result = hunter.run_hunt_loop(&hunt_id).await.unwrap();
        }

        // Load from disk with a new hunter
        {
            let hunter = make_hunter(MockCloudProvider::new(vec![]), hunts_dir);

            let loaded = hunter.load_hunt_result(&hunt_id).await.unwrap();
            assert_eq!(loaded.hunt_id, hunt_id);
            assert_eq!(loaded.status, HuntStatus::Completed);
        }
    }

    #[tokio::test]
    async fn test_get_progress_running() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(MockCloudProvider::new(vec![]), dir.path().join("hunts"));

        let progress = hunter
            .start_hunt(HuntType::GeneralSweep, default_time_range())
            .await
            .unwrap();
        let hunt_id = progress.hunt_id.clone();

        let live_progress = hunter.get_progress(&hunt_id).await.unwrap();
        assert_eq!(live_progress.status, HuntStatus::Running);
    }

    #[tokio::test]
    async fn test_list_hunts() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(MockCloudProvider::new(vec![]), dir.path().join("hunts"));

        hunter
            .start_hunt(HuntType::GeneralSweep, default_time_range())
            .await
            .unwrap();
        hunter
            .start_hunt(
                HuntType::ServerFocused {
                    server: "web-01".into(),
                },
                default_time_range(),
            )
            .await
            .unwrap();

        let hunts = hunter.list_hunts().await;
        assert_eq!(hunts.len(), 2);
    }

    #[tokio::test]
    async fn test_get_result_after_completion() {
        let dir = tempfile::tempdir().unwrap();
        let hunter = make_hunter(
            MockCloudProvider::new(vec![MockCloudProvider::text_response(
                "HUNT COMPLETE\n\nClean.",
            )]),
            dir.path().join("hunts"),
        );

        let progress = hunter
            .start_hunt(HuntType::GeneralSweep, default_time_range())
            .await
            .unwrap();
        let hunt_id = progress.hunt_id.clone();

        hunter.run_hunt_loop(&hunt_id).await.unwrap();

        let result = hunter.get_result(&hunt_id).await.unwrap();
        assert_eq!(result.status, HuntStatus::Completed);
        assert_eq!(result.hunt_id, hunt_id);
    }
}
