//! AI scan orchestrator — launches playbook-driven security scans, manages
//! the agentic investigation loop, collects findings, and persists results.
//!
//! The orchestrator feeds Claude a playbook's system prompt, provides scan-specific
//! tools, and loops through the tool-use cycle until the model signals SCAN COMPLETE
//! or guardrails are hit (max tool calls, max duration).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::cloud_api::{
    build_tool_result_message, extract_text, extract_tool_calls, AgentRequest, AgentResponse,
    CloudApiClient, ContentBlock, Message, MessageContent,
};
use crate::evidence::EvidenceStore;
use crate::remediation::{extract_remediations, RemediationEngine};
use crate::scan_playbooks::{get_playbook, ScanPlaybook};
use crate::scan_tools::{get_available_tools, ScanToolExecutor};
use crate::tool_sandbox::ToolSandbox;
use crate::tools::ToolResult;

// ---------------------------------------------------------------------------
// Constants / guardrails
// ---------------------------------------------------------------------------

/// Maximum tool-call iterations before we force completion.
const MAX_TOOL_CALLS: usize = 250;

/// Maximum wall-clock time for a single scan.
const MAX_SCAN_DURATION: Duration = Duration::from_secs(1800); // 30 min

/// Maximum messages to send in a single API request (sliding window).
const MAX_MESSAGES_IN_REQUEST: usize = 40;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Current status of a scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanStatus {
    Running,
    Completed,
    Cancelled,
    Failed { error: String },
}

/// Severity of a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl FindingSeverity {
    fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Self::Critical,
            "HIGH" => Self::High,
            "MEDIUM" => Self::Medium,
            "LOW" => Self::Low,
            "INFO" => Self::Info,
            _ => Self::High, // Fail-closed: default to HIGH for safety
        }
    }
}

/// A single finding extracted from Claude's output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub id: String,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub evidence_ids: Vec<String>,
    pub remediation_hint: String,
    pub stage: String,
    pub discovered_at: String,
}

/// Complete result of a finished (or failed) scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiScanResult {
    pub scan_id: String,
    pub playbook_id: String,
    pub playbook_name: String,
    pub status: ScanStatus,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_secs: u64,
    pub findings: Vec<ScanFinding>,
    pub stages_completed: Vec<String>,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    #[serde(rename = "tool_calls_used")]
    pub total_tool_calls: usize,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    #[serde(rename = "estimated_cost")]
    pub estimated_cost_usd: f64,
    pub evidence_count: usize,
    pub summary: String,
}

/// Real-time progress snapshot for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiScanProgress {
    pub scan_id: String,
    pub status: ScanStatus,
    pub playbook_id: String,
    pub playbook_name: String,
    pub current_stage: Option<String>,
    pub stages_completed: Vec<String>,
    pub stages_total: usize,
    pub findings_count: usize,
    #[serde(rename = "tool_calls_used")]
    pub tool_calls_count: usize,
    pub elapsed_secs: u64,
    pub estimated_total_secs: u64,
    /// Calculated progress percentage (0-100).
    pub progress_percent: f64,
}

/// A request from the model that needs user confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUserRequest {
    pub id: String,
    pub scan_id: String,
    pub question: String,
    pub context: String,
}

/// Internal mutable state for a single running scan.
struct ScanState {
    scan_id: String,
    playbook: ScanPlaybook,
    status: ScanStatus,
    started_at: String,

    // Conversation
    messages: Vec<Message>,
    system_prompt: String,

    // Progress
    current_stage: Option<String>,
    stages_completed: Vec<String>,
    total_tool_calls: usize,

    // Findings & evidence
    findings: Vec<ScanFinding>,
    evidence_store: EvidenceStore,
    remediation_engine: RemediationEngine,

    // Tokens
    total_input_tokens: u64,
    total_output_tokens: u64,

    // User interaction
    pending_user_requests: Vec<ScanUserRequest>,
    user_responses: HashMap<String, String>,

    // Summary
    summary: String,
}

// ---------------------------------------------------------------------------
// ScanOrchestrator
// ---------------------------------------------------------------------------

/// Manages AI-powered security scans — creation, the agentic loop, progress
/// queries, cancellation, and result persistence.
pub struct ScanOrchestrator {
    scans: Mutex<HashMap<String, ScanState>>,
    results: Mutex<HashMap<String, AiScanResult>>,
    cloud_client: Arc<CloudApiClient>,
    tool_sandbox: Arc<ToolSandbox>,
    scan_tool_executor: Arc<ScanToolExecutor>,
    model: String,
    scans_dir: PathBuf,
}

impl ScanOrchestrator {
    pub fn new(
        cloud_client: Arc<CloudApiClient>,
        tool_sandbox: Arc<ToolSandbox>,
        model: String,
        scans_dir: PathBuf,
    ) -> Self {
        Self {
            scans: Mutex::new(HashMap::new()),
            results: Mutex::new(HashMap::new()),
            cloud_client,
            tool_sandbox,
            scan_tool_executor: Arc::new(ScanToolExecutor::new()),
            model,
            scans_dir,
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Start a new AI scan. Returns the scan ID immediately; the scan loop
    /// runs on a background task. The caller receives an `AiScanProgress`
    /// with the initial state.
    pub async fn start_scan(&self, playbook_id: &str) -> Result<AiScanProgress> {
        let playbook = get_playbook(playbook_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown playbook: {}", playbook_id))?;

        let scan_id = format!("scan-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().to_rfc3339();

        let first_stage = playbook.stages.first().map(|s| s.name.clone());

        let state = ScanState {
            scan_id: scan_id.clone(),
            playbook: playbook.clone(),
            status: ScanStatus::Running,
            started_at: now,
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text(
                    "Begin the scan. Start with Stage 1 and work through each stage \
                     systematically. Use the available tools to investigate, and emit \
                     [FINDING] and [REMEDIATION] blocks as you discover issues. Signal \
                     STAGE COMPLETE: <stage_name> after each stage, and SCAN COMPLETE \
                     when finished."
                        .to_string(),
                ),
            }],
            system_prompt: playbook.system_prompt.clone(),
            current_stage: first_stage.clone(),
            stages_completed: Vec::new(),
            total_tool_calls: 0,
            findings: Vec::new(),
            evidence_store: EvidenceStore::new(scan_id.clone()),
            remediation_engine: RemediationEngine::new(scan_id.clone()),
            total_input_tokens: 0,
            total_output_tokens: 0,
            pending_user_requests: Vec::new(),
            user_responses: HashMap::new(),
            summary: String::new(),
        };

        let progress = AiScanProgress {
            scan_id: scan_id.clone(),
            status: ScanStatus::Running,
            playbook_id: playbook.id.clone(),
            playbook_name: playbook.name.clone(),
            current_stage: first_stage,
            stages_completed: Vec::new(),
            stages_total: playbook.stages.len(),
            findings_count: 0,
            tool_calls_count: 0,
            elapsed_secs: 0,
            estimated_total_secs: playbook.estimated_duration_secs,
            progress_percent: 0.0,
        };

        let mut scans = self.scans.lock().await;
        scans.insert(scan_id.clone(), state);

        Ok(progress)
    }

    /// Run the agentic scan loop for a given scan ID. This is intended to be
    /// spawned as a background task.
    pub async fn run_scan_loop(&self, scan_id: &str) -> Result<AiScanResult> {
        let start_time = Instant::now();

        loop {
            // Check guardrails
            if start_time.elapsed() > MAX_SCAN_DURATION {
                self.set_scan_summary(scan_id, "Scan terminated: max duration exceeded.".into())
                    .await;
                self.finalize_scan(scan_id, ScanStatus::Completed).await?;
                break;
            }

            {
                let scans = self.scans.lock().await;
                if let Some(state) = scans.get(scan_id) {
                    if state.status != ScanStatus::Running {
                        break;
                    }
                    if state.total_tool_calls >= MAX_TOOL_CALLS {
                        drop(scans);
                        self.set_scan_summary(
                            scan_id,
                            "Scan terminated: max tool calls reached.".into(),
                        )
                        .await;
                        self.finalize_scan(scan_id, ScanStatus::Completed).await?;
                        break;
                    }
                } else {
                    bail!("Scan not found: {}", scan_id);
                }
            }

            // Run a single turn of the agentic loop
            match self.run_single_turn(scan_id).await {
                Ok(completed) => {
                    if completed {
                        self.finalize_scan(scan_id, ScanStatus::Completed).await?;
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("Scan {} turn error: {}", scan_id, e);
                    self.finalize_scan(
                        scan_id,
                        ScanStatus::Failed {
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
            .get(scan_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Scan result not found after finalization"))
    }

    /// Get real-time progress for a scan.
    pub async fn get_progress(&self, scan_id: &str) -> Result<AiScanProgress> {
        // Check running scans first
        let scans = self.scans.lock().await;
        if let Some(state) = scans.get(scan_id) {
            let elapsed = chrono::Utc::now()
                .signed_duration_since(
                    chrono::DateTime::parse_from_rfc3339(&state.started_at)
                        .unwrap_or_else(|_| chrono::Utc::now().into()),
                )
                .num_seconds()
                .unsigned_abs();

            let total = state.playbook.stages.len();
            let completed = state.stages_completed.len();
            let progress_percent = if total > 0 {
                (completed as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            return Ok(AiScanProgress {
                scan_id: scan_id.to_string(),
                status: state.status.clone(),
                playbook_id: state.playbook.id.clone(),
                playbook_name: state.playbook.name.clone(),
                current_stage: state.current_stage.clone(),
                stages_completed: state.stages_completed.clone(),
                stages_total: total,
                findings_count: state.findings.len(),
                tool_calls_count: state.total_tool_calls,
                elapsed_secs: elapsed,
                estimated_total_secs: state.playbook.estimated_duration_secs,
                progress_percent,
            });
        }
        drop(scans);

        // Check completed results
        let results = self.results.lock().await;
        if let Some(result) = results.get(scan_id) {
            return Ok(AiScanProgress {
                scan_id: scan_id.to_string(),
                status: result.status.clone(),
                playbook_id: result.playbook_id.clone(),
                playbook_name: result.playbook_name.clone(),
                current_stage: None,
                stages_completed: result.stages_completed.clone(),
                stages_total: result.stages_completed.len(),
                findings_count: result.findings.len(),
                tool_calls_count: result.total_tool_calls,
                elapsed_secs: result.duration_secs,
                estimated_total_secs: 0,
                progress_percent: 100.0,
            });
        }
        drop(results);

        // Try loading from disk
        let result = self.load_scan_result(scan_id).await?;
        Ok(AiScanProgress {
            scan_id: scan_id.to_string(),
            status: result.status.clone(),
            playbook_id: result.playbook_id.clone(),
            playbook_name: result.playbook_name.clone(),
            current_stage: None,
            stages_completed: result.stages_completed.clone(),
            stages_total: result.stages_completed.len(),
            findings_count: result.findings.len(),
            tool_calls_count: result.total_tool_calls,
            elapsed_secs: 0,
            estimated_total_secs: 0,
            progress_percent: 100.0,
        })
    }

    /// Get the final result of a completed scan.
    pub async fn get_result(&self, scan_id: &str) -> Result<AiScanResult> {
        let results = self.results.lock().await;
        if let Some(result) = results.get(scan_id) {
            return Ok(result.clone());
        }
        drop(results);

        self.load_scan_result(scan_id).await
    }

    /// Cancel a running scan.
    pub async fn cancel_scan(&self, scan_id: &str) -> Result<()> {
        let mut scans = self.scans.lock().await;
        if let Some(state) = scans.get_mut(scan_id) {
            if state.status == ScanStatus::Running {
                state.status = ScanStatus::Cancelled;
                state.summary = "Scan cancelled by user.".to_string();
            }
            return Ok(());
        }
        bail!("Scan not found or already completed: {}", scan_id);
    }

    /// Respond to a user request from the scan.
    pub async fn respond_to_request(
        &self,
        scan_id: &str,
        request_id: &str,
        response: &str,
    ) -> Result<()> {
        let mut scans = self.scans.lock().await;
        if let Some(state) = scans.get_mut(scan_id) {
            state
                .user_responses
                .insert(request_id.to_string(), response.to_string());
            state
                .pending_user_requests
                .retain(|r| r.id != request_id);
            return Ok(());
        }
        bail!("Scan not found: {}", scan_id);
    }

    /// Get the evidence chain for a specific finding.
    pub async fn get_evidence_chain(
        &self,
        scan_id: &str,
        finding_id: &str,
    ) -> Result<crate::evidence::EvidenceChain> {
        let scans = self.scans.lock().await;
        if let Some(state) = scans.get(scan_id) {
            return Ok(state.evidence_store.get_evidence_chain(finding_id));
        }
        bail!("Scan not found: {}", scan_id);
    }

    /// Get all remediations for a scan.
    pub async fn get_remediations(
        &self,
        scan_id: &str,
    ) -> Result<Vec<crate::remediation::Remediation>> {
        let scans = self.scans.lock().await;
        if let Some(state) = scans.get(scan_id) {
            return Ok(state.remediation_engine.get_all().to_vec());
        }
        bail!("Scan not found: {}", scan_id);
    }

    /// Execute a specific remediation.
    pub async fn execute_remediation(
        &self,
        scan_id: &str,
        remediation_id: &str,
    ) -> Result<()> {
        let mut scans = self.scans.lock().await;
        if let Some(state) = scans.get_mut(scan_id) {
            return state.remediation_engine.execute(remediation_id);
        }
        bail!("Scan not found: {}", scan_id);
    }

    /// Revert a specific remediation.
    pub async fn revert_remediation(
        &self,
        scan_id: &str,
        remediation_id: &str,
    ) -> Result<()> {
        let mut scans = self.scans.lock().await;
        if let Some(state) = scans.get_mut(scan_id) {
            return state.remediation_engine.revert(remediation_id);
        }
        bail!("Scan not found: {}", scan_id);
    }

    // -----------------------------------------------------------------------
    // Agentic loop internals
    // -----------------------------------------------------------------------

    /// Execute a single turn: send messages to Claude, process response,
    /// execute tool calls if any. Returns `true` if the scan is complete.
    async fn run_single_turn(&self, scan_id: &str) -> Result<bool> {
        // Build the API request
        let (request, tool_defs_count) = {
            let scans = self.scans.lock().await;
            let state = scans.get(scan_id).ok_or_else(|| anyhow::anyhow!("Scan not found"))?;

            let tools = get_available_tools(&crate::agent_session::SessionType::Scan {
                playbook: state.playbook.id.clone(),
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

            let request = AgentRequest {
                model: self.model.clone(),
                system: state.system_prompt.clone(),
                messages: request_messages,
                tools: tool_json,
                max_tokens: 4096,
                stream: false,
            };

            (request, tools.len())
        };

        let _ = tool_defs_count; // Used for logging if needed

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
            let mut scans = self.scans.lock().await;
            if let Some(state) = scans.get_mut(scan_id) {
                state.total_input_tokens += response.usage.input_tokens;
                state.total_output_tokens += response.usage.output_tokens;
            }
        }

        // Process text output: extract findings, stage completions, scan completion
        let scan_complete = if !text.is_empty() {
            self.process_text_output(scan_id, &text).await?
        } else {
            false
        };

        // Add assistant message to history
        {
            let mut scans = self.scans.lock().await;
            if let Some(state) = scans.get_mut(scan_id) {
                state.messages.push(Message {
                    role: "assistant".to_string(),
                    content: response_to_message_content(&response),
                });
            }
        }

        if scan_complete {
            return Ok(true);
        }

        // If no tool calls, the model finished without explicit SCAN COMPLETE
        if tool_calls.is_empty() {
            return Ok(true);
        }

        // Execute tool calls
        let mut tool_results = Vec::new();
        let current_stage = {
            let scans = self.scans.lock().await;
            scans
                .get(scan_id)
                .and_then(|s| s.current_stage.clone())
                .unwrap_or_else(|| "unknown".to_string())
        };

        for tc in &tool_calls {
            // Execute via scan tool executor first, fall back to base sandbox
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
                self.tool_sandbox.execute_tool(tc, scan_id).await
            };

            // Record evidence
            {
                let mut scans = self.scans.lock().await;
                if let Some(state) = scans.get_mut(scan_id) {
                    state.evidence_store.record_tool_call(
                        &tc.name,
                        tc.input.clone(),
                        &result.content,
                        &current_stage,
                    );
                    state.total_tool_calls += 1;
                }
            }

            tool_results.push(result);
        }

        // Add tool results to message history
        {
            let mut scans = self.scans.lock().await;
            if let Some(state) = scans.get_mut(scan_id) {
                let tool_result_msg = build_tool_result_message(
                    tool_results
                        .into_iter()
                        .map(|r| crate::tools::ToolResult {
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

    /// Process text output from Claude, extracting findings, remediations,
    /// stage completions, and the SCAN COMPLETE signal.
    /// Returns `true` if SCAN COMPLETE was found.
    async fn process_text_output(&self, scan_id: &str, text: &str) -> Result<bool> {
        let mut scan_complete = false;

        // Extract findings
        let findings = extract_findings(text);

        // Extract remediations
        let remediations = extract_remediations(text, scan_id);

        // Check for stage completions
        let stage_completions = extract_stage_completions(text);

        // Check for SCAN COMPLETE
        if text.contains("SCAN COMPLETE") {
            scan_complete = true;
        }

        // Apply to scan state
        {
            let mut scans = self.scans.lock().await;
            if let Some(state) = scans.get_mut(scan_id) {
                let current_stage = state
                    .current_stage
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());

                // Add findings
                for mut finding in findings {
                    finding.stage = current_stage.clone();
                    finding.id = format!(
                        "FINDING-{}",
                        state.findings.len() + 1
                    );
                    state.findings.push(finding);
                }

                // Add remediations
                if !remediations.is_empty() {
                    state.remediation_engine.add_remediations(remediations);
                }

                // Process stage completions
                for stage_name in &stage_completions {
                    if !state.stages_completed.contains(stage_name) {
                        state.stages_completed.push(stage_name.clone());
                    }
                    // Advance to next stage
                    let next_idx = state
                        .playbook
                        .stages
                        .iter()
                        .position(|s| s.name == *stage_name)
                        .map(|i| i + 1);
                    if let Some(idx) = next_idx {
                        state.current_stage =
                            state.playbook.stages.get(idx).map(|s| s.name.clone());
                    }
                }

                // Update summary if scan is complete
                if scan_complete {
                    // Use the last few paragraphs as summary
                    state.summary = extract_summary(text);

                    // Auto-link evidence
                    state.evidence_store.auto_link_evidence();
                }
            }
        }

        Ok(scan_complete)
    }

    /// Finalize a scan: move from active scans to results, persist to disk.
    async fn finalize_scan(&self, scan_id: &str, final_status: ScanStatus) -> Result<()> {
        let result = {
            let mut scans = self.scans.lock().await;
            let state = scans
                .get_mut(scan_id)
                .ok_or_else(|| anyhow::anyhow!("Scan not found: {}", scan_id))?;

            state.status = final_status.clone();
            state.evidence_store.auto_link_evidence();

            // Deduplicate findings
            deduplicate_findings(&mut state.findings);

            let cost = estimate_cost(state.total_input_tokens, state.total_output_tokens);

            // Compute duration
            let duration_secs = if let Ok(started) = chrono::DateTime::parse_from_rfc3339(&state.started_at) {
                chrono::Utc::now().signed_duration_since(started).num_seconds().unsigned_abs()
            } else {
                0
            };

            // Compute severity counts
            let total_findings = state.findings.len();
            let critical_count = state.findings.iter().filter(|f| f.severity == FindingSeverity::Critical).count();
            let high_count = state.findings.iter().filter(|f| f.severity == FindingSeverity::High).count();
            let medium_count = state.findings.iter().filter(|f| f.severity == FindingSeverity::Medium).count();
            let low_count = state.findings.iter().filter(|f| f.severity == FindingSeverity::Low).count();
            let info_count = state.findings.iter().filter(|f| f.severity == FindingSeverity::Info).count();

            let playbook_name = state.playbook.name.clone();

            let result = AiScanResult {
                scan_id: scan_id.to_string(),
                playbook_id: state.playbook.id.clone(),
                playbook_name,
                status: final_status,
                started_at: state.started_at.clone(),
                completed_at: Some(chrono::Utc::now().to_rfc3339()),
                duration_secs,
                findings: state.findings.clone(),
                stages_completed: state.stages_completed.clone(),
                total_findings,
                critical_count,
                high_count,
                medium_count,
                low_count,
                info_count,
                total_tool_calls: state.total_tool_calls,
                total_input_tokens: state.total_input_tokens,
                total_output_tokens: state.total_output_tokens,
                estimated_cost_usd: cost,
                evidence_count: state.evidence_store.get_all_evidence().len(),
                summary: state.summary.clone(),
            };

            // Remove from active scans
            scans.remove(scan_id);

            result
        };

        // Store in results map
        {
            let mut results = self.results.lock().await;
            results.insert(scan_id.to_string(), result.clone());
        }

        // Persist to disk
        self.save_scan_result(&result).await?;

        Ok(())
    }

    async fn set_scan_summary(&self, scan_id: &str, summary: String) {
        let mut scans = self.scans.lock().await;
        if let Some(state) = scans.get_mut(scan_id) {
            state.summary = summary;
        }
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    async fn save_scan_result(&self, result: &AiScanResult) -> Result<()> {
        tokio::fs::create_dir_all(&self.scans_dir).await?;
        let path = self
            .scans_dir
            .join(format!("{}.json", result.scan_id));
        let data = serde_json::to_string_pretty(result)?;
        tokio::fs::write(path, data).await?;
        Ok(())
    }

    async fn load_scan_result(&self, scan_id: &str) -> Result<AiScanResult> {
        let path = self.scans_dir.join(format!("{}.json", scan_id));
        let data = tokio::fs::read_to_string(&path)
            .await
            .map_err(|_| anyhow::anyhow!("Scan result not found: {}", scan_id))?;
        let result: AiScanResult = serde_json::from_str(&data)?;
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Extract `[FINDING severity=...]...[/FINDING]` blocks from text.
fn extract_findings(text: &str) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let mut remaining = text;

    while let Some(start_idx) = remaining.find("[FINDING ") {
        let after_tag = &remaining[start_idx..];
        let Some(tag_end) = after_tag.find(']') else {
            remaining = &remaining[start_idx + 9..];
            continue;
        };

        let tag_line = &after_tag[..tag_end];
        let Some(end_idx) = after_tag.find("[/FINDING]") else {
            remaining = &remaining[start_idx + tag_end..];
            continue;
        };

        let body = after_tag[tag_end + 1..end_idx].trim();

        // Parse severity from tag: [FINDING severity=HIGH]
        let severity_str = parse_tag_attr(tag_line, "severity").unwrap_or_else(|| "INFO".into());
        let severity = FindingSeverity::from_str(&severity_str);

        let title = parse_body_field(body, "Title").unwrap_or_else(|| "Untitled finding".into());
        let description =
            parse_body_field(body, "Description").unwrap_or_else(|| body.to_string());
        let evidence_hint = parse_body_field(body, "Evidence").unwrap_or_default();
        let remediation_hint = parse_body_field(body, "Remediation").unwrap_or_default();

        findings.push(ScanFinding {
            id: String::new(), // Assigned later
            severity,
            title,
            description,
            evidence_ids: if evidence_hint.is_empty() {
                Vec::new()
            } else {
                vec![evidence_hint]
            },
            remediation_hint,
            stage: String::new(), // Assigned later
            discovered_at: chrono::Utc::now().to_rfc3339(),
        });

        remaining = &remaining[start_idx + end_idx + 10..];
    }

    findings
}

/// Parse a `key=value` attribute from a tag line.
fn parse_tag_attr(tag: &str, key: &str) -> Option<String> {
    let search = format!("{key}=");
    let idx = tag.find(&search)?;
    let after = &tag[idx + search.len()..];
    let value = after
        .split_whitespace()
        .next()
        .unwrap_or(after)
        .trim_end_matches(']');
    Some(value.to_string())
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

/// Extract "STAGE COMPLETE: <name>" signals from text.
fn extract_stage_completions(text: &str) -> Vec<String> {
    let re = Regex::new(r"STAGE COMPLETE:\s*(.+?)(?:\n|$)").expect("regex must compile");
    re.captures_iter(text)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().trim().to_string()))
        .collect()
}

/// Extract a clean, concise summary from the final scan output.
fn extract_summary(text: &str) -> String {
    // Look for text after "SCAN COMPLETE" as the summary
    if let Some(idx) = text.find("SCAN COMPLETE") {
        let after = text[idx + 13..].trim();
        if !after.is_empty() {
            // Strip common prefixes like ":" or "-"
            let cleaned = after.trim_start_matches(|c: char| c == ':' || c == '-' || c == '\n' || c.is_whitespace());
            // Take only the first paragraph (up to double newline or 200 chars)
            let first_para = cleaned
                .split("\n\n")
                .next()
                .unwrap_or(cleaned);
            let summary = if first_para.len() > 200 {
                // Find a sentence boundary near 200 chars
                let truncated = &first_para[..200];
                if let Some(end) = truncated.rfind(". ") {
                    format!("{}.", &truncated[..end])
                } else {
                    format!("{}...", truncated)
                }
            } else {
                first_para.to_string()
            };
            return summary;
        }
    }

    // Fall back: take last paragraph, capped at 200 chars
    let last_para = text
        .rsplit("\n\n")
        .next()
        .unwrap_or(text)
        .trim();
    if last_para.len() > 200 {
        let truncated = &last_para[..200];
        if let Some(end) = truncated.rfind(". ") {
            format!("{}.", &truncated[..end])
        } else {
            format!("{}...", truncated)
        }
    } else {
        last_para.to_string()
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

/// Remove duplicate findings based on title similarity.
fn deduplicate_findings(findings: &mut Vec<ScanFinding>) {
    let mut seen_titles: Vec<String> = Vec::new();
    findings.retain(|f| {
        let normalized = f.title.to_lowercase();
        let normalized = normalized.trim();
        for existing in &seen_titles {
            if existing == normalized || titles_similar(existing, normalized) {
                return false;
            }
        }
        seen_titles.push(normalized.to_string());
        true
    });
}

fn titles_similar(a: &str, b: &str) -> bool {
    let terms_a: std::collections::HashSet<&str> = a.split_whitespace()
        .filter(|w| w.len() > 3)
        .collect();
    let terms_b: std::collections::HashSet<&str> = b.split_whitespace()
        .filter(|w| w.len() > 3)
        .collect();
    if terms_a.is_empty() || terms_b.is_empty() {
        return false;
    }
    let overlap = terms_a.intersection(&terms_b).count();
    let max_terms = std::cmp::max(terms_a.len(), terms_b.len());
    overlap as f64 / max_terms as f64 > 0.6
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_api::{CloudProvider, StopReason, TokenUsage as CloudTokenUsage};
    use async_trait::async_trait;

    // -- Parsing tests -------------------------------------------------------

    #[test]
    fn test_extract_findings_single() {
        let text = r#"
I found an issue:

[FINDING severity=HIGH]
Title: Hardcoded API key in MCP config
Description: The Claude Desktop config contains a hardcoded API key for the weather-server MCP.
Evidence: ev-scan-001-3
Remediation: Move the API key to an environment variable or the system keychain.
[/FINDING]

That's concerning.
"#;
        let findings = extract_findings(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, FindingSeverity::High);
        assert_eq!(findings[0].title, "Hardcoded API key in MCP config");
        assert!(findings[0].description.contains("hardcoded API key"));
        assert_eq!(findings[0].evidence_ids, vec!["ev-scan-001-3"]);
        assert!(findings[0].remediation_hint.contains("environment variable"));
    }

    #[test]
    fn test_extract_findings_multiple() {
        let text = r#"
[FINDING severity=CRITICAL]
Title: SSH private key exposed
Description: MCP server accessed ~/.ssh/id_rsa
Evidence: ev-1
Remediation: Restrict file access
[/FINDING]

Some analysis text.

[FINDING severity=LOW]
Title: Verbose logging enabled
Description: Debug logging may expose sensitive data
Evidence: ev-2
Remediation: Disable debug logging in production
[/FINDING]

[FINDING severity=INFO]
Title: Server running latest version
Description: All servers are up to date
Evidence: ev-3
Remediation: No action needed
[/FINDING]
"#;
        let findings = extract_findings(text);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, FindingSeverity::Critical);
        assert_eq!(findings[1].severity, FindingSeverity::Low);
        assert_eq!(findings[2].severity, FindingSeverity::Info);
    }

    #[test]
    fn test_extract_findings_none() {
        let text = "This is just analysis with no findings.";
        let findings = extract_findings(text);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_extract_findings_malformed_no_end_tag() {
        let text = r#"
[FINDING severity=HIGH]
Title: Incomplete finding
Description: This has no closing tag
"#;
        let findings = extract_findings(text);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_extract_stage_completions() {
        let text = r#"
I've finished reviewing the server inventory.

STAGE COMPLETE: Server Inventory

Now moving on to configuration analysis.
"#;
        let completions = extract_stage_completions(text);
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0], "Server Inventory");
    }

    #[test]
    fn test_extract_stage_completions_multiple() {
        let text = r#"
STAGE COMPLETE: Stage A
Some text.
STAGE COMPLETE: Stage B
"#;
        let completions = extract_stage_completions(text);
        assert_eq!(completions.len(), 2);
        assert_eq!(completions[0], "Stage A");
        assert_eq!(completions[1], "Stage B");
    }

    #[test]
    fn test_extract_stage_completions_none() {
        let text = "No stages completed yet.";
        let completions = extract_stage_completions(text);
        assert!(completions.is_empty());
    }

    #[test]
    fn test_extract_summary_after_scan_complete() {
        let text = r#"
Final analysis done.

SCAN COMPLETE

Overall the system is well-hardened. Found 3 issues, 1 critical.
Top priority: fix the exposed SSH key.
"#;
        let summary = extract_summary(text);
        assert!(summary.contains("well-hardened"));
        assert!(summary.contains("Top priority"));
    }

    #[test]
    fn test_extract_summary_fallback() {
        let text = "Some analysis output without the special completion marker.";
        let summary = extract_summary(text);
        assert_eq!(summary, text);
    }

    #[test]
    fn test_parse_tag_attr() {
        assert_eq!(
            parse_tag_attr("[FINDING severity=HIGH]", "severity"),
            Some("HIGH".to_string())
        );
        assert_eq!(
            parse_tag_attr("[FINDING severity=CRITICAL]", "severity"),
            Some("CRITICAL".to_string())
        );
        assert_eq!(
            parse_tag_attr("[FINDING severity=HIGH]", "missing"),
            None
        );
    }

    #[test]
    fn test_parse_body_field() {
        let body = "Title: Something bad\nDescription: It's really bad\nEvidence: ev-1";
        assert_eq!(
            parse_body_field(body, "Title"),
            Some("Something bad".to_string())
        );
        assert_eq!(
            parse_body_field(body, "Description"),
            Some("It's really bad".to_string())
        );
        assert_eq!(
            parse_body_field(body, "Evidence"),
            Some("ev-1".to_string())
        );
        assert_eq!(parse_body_field(body, "Missing"), None);
    }

    #[test]
    fn test_finding_severity_from_str() {
        assert_eq!(FindingSeverity::from_str("CRITICAL"), FindingSeverity::Critical);
        assert_eq!(FindingSeverity::from_str("HIGH"), FindingSeverity::High);
        assert_eq!(FindingSeverity::from_str("MEDIUM"), FindingSeverity::Medium);
        assert_eq!(FindingSeverity::from_str("LOW"), FindingSeverity::Low);
        assert_eq!(FindingSeverity::from_str("INFO"), FindingSeverity::Info);
        assert_eq!(FindingSeverity::from_str("unknown"), FindingSeverity::High);
        // Case insensitive
        assert_eq!(FindingSeverity::from_str("high"), FindingSeverity::High);
        assert_eq!(FindingSeverity::from_str("Critical"), FindingSeverity::Critical);
    }

    #[test]
    fn test_estimate_cost() {
        // 50k input tokens, 20k output tokens
        // Input: 50000/1M * $3 = $0.15
        // Output: 20000/1M * $15 = $0.30
        // Total: $0.45
        let cost = estimate_cost(50_000, 20_000);
        assert!((cost - 0.45).abs() < 0.001);
    }

    #[test]
    fn test_estimate_cost_zero() {
        assert_eq!(estimate_cost(0, 0), 0.0);
    }

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
        // Should contain messages 10-49
        match &window[0].content {
            MessageContent::Text(t) => assert_eq!(t, "msg 10"),
            _ => panic!("Expected text"),
        }
    }

    #[test]
    fn test_scan_status_serde() {
        let statuses = vec![
            ScanStatus::Running,
            ScanStatus::Completed,
            ScanStatus::Cancelled,
            ScanStatus::Failed {
                error: "timeout".into(),
            },
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let parsed: ScanStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, status);
        }
    }

    #[test]
    fn test_scan_finding_serde() {
        let finding = ScanFinding {
            id: "FINDING-1".into(),
            severity: FindingSeverity::High,
            title: "Test finding".into(),
            description: "A test finding".into(),
            evidence_ids: vec!["ev-1".into()],
            remediation_hint: "Fix it".into(),
            stage: "Server Inventory".into(),
            discovered_at: "2025-01-01T00:05:00Z".into(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let parsed: ScanFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "FINDING-1");
        assert_eq!(parsed.severity, FindingSeverity::High);
        assert_eq!(parsed.title, "Test finding");
    }

    #[test]
    fn test_ai_scan_result_serde() {
        let result = AiScanResult {
            scan_id: "scan-001".into(),
            playbook_id: "mcp_security_audit".into(),
            playbook_name: "MCP Security Audit".into(),
            status: ScanStatus::Completed,
            started_at: "2025-01-01T00:00:00Z".into(),
            completed_at: Some("2025-01-01T00:10:00Z".into()),
            duration_secs: 600,
            findings: vec![ScanFinding {
                id: "FINDING-1".into(),
                severity: FindingSeverity::Critical,
                title: "Bad thing".into(),
                description: "Very bad".into(),
                evidence_ids: vec!["ev-1".into()],
                remediation_hint: "Fix it".into(),
                stage: "Recon".into(),
                discovered_at: "2025-01-01T00:05:00Z".into(),
            }],
            stages_completed: vec!["Stage 1".into(), "Stage 2".into()],
            total_findings: 1,
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            total_tool_calls: 15,
            total_input_tokens: 50000,
            total_output_tokens: 20000,
            estimated_cost_usd: 0.45,
            evidence_count: 0,
            summary: "Scan complete. Found 1 critical issue.".into(),
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        let parsed: AiScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scan_id, "scan-001");
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.total_tool_calls, 15);
    }

    // -- Orchestrator integration tests with mock provider -------------------

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
                Ok(Self::text_response("SCAN COMPLETE\n\nNo issues found."))
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

    fn make_orchestrator(
        provider: MockCloudProvider,
        scans_dir: PathBuf,
    ) -> ScanOrchestrator {
        let client = Arc::new(CloudApiClient::new(Box::new(provider)));
        let sandbox = Arc::new(ToolSandbox::new());
        ScanOrchestrator::new(client, sandbox, "mock-model".to_string(), scans_dir)
    }

    #[tokio::test]
    async fn test_start_scan() {
        let dir = tempfile::tempdir().unwrap();
        let orch = make_orchestrator(
            MockCloudProvider::new(vec![]),
            dir.path().join("scans"),
        );

        let progress = orch.start_scan("mcp_security_audit").await.unwrap();
        assert!(progress.scan_id.starts_with("scan-"));
        assert_eq!(progress.status, ScanStatus::Running);
        assert_eq!(progress.playbook_id, "mcp_security_audit");
        assert_eq!(progress.stages_total, 5);
        assert_eq!(progress.findings_count, 0);
    }

    #[tokio::test]
    async fn test_start_scan_unknown_playbook() {
        let dir = tempfile::tempdir().unwrap();
        let orch = make_orchestrator(
            MockCloudProvider::new(vec![]),
            dir.path().join("scans"),
        );

        let result = orch.start_scan("nonexistent_playbook").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown playbook"));
    }

    #[tokio::test]
    async fn test_scan_loop_simple_completion() {
        let dir = tempfile::tempdir().unwrap();
        let orch = make_orchestrator(
            MockCloudProvider::new(vec![MockCloudProvider::text_response(
                r#"
[FINDING severity=MEDIUM]
Title: Unnecessary network access
Description: Server contacts external API without need
Evidence: tool output
Remediation: Add network restriction policy
[/FINDING]

STAGE COMPLETE: Server Inventory

SCAN COMPLETE

Found 1 medium-severity issue. Overall posture: Good.
"#,
            )]),
            dir.path().join("scans"),
        );

        let progress = orch.start_scan("mcp_security_audit").await.unwrap();
        let scan_id = progress.scan_id.clone();

        let result = orch.run_scan_loop(&scan_id).await.unwrap();
        assert_eq!(result.status, ScanStatus::Completed);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, FindingSeverity::Medium);
        assert!(result.stages_completed.contains(&"Server Inventory".to_string()));
        assert!(result.summary.contains("Overall posture"));
    }

    #[tokio::test]
    async fn test_scan_loop_with_tool_calls() {
        let dir = tempfile::tempdir().unwrap();
        let orch = make_orchestrator(
            MockCloudProvider::new(vec![
                // Turn 1: model calls a tool
                MockCloudProvider::tool_use_response(
                    "get_policy",
                    "tool_01",
                    serde_json::json!({}),
                ),
                // Turn 2: model produces final output
                MockCloudProvider::text_response("SCAN COMPLETE\n\nNo issues found."),
            ]),
            dir.path().join("scans"),
        );

        let progress = orch.start_scan("mcp_security_audit").await.unwrap();
        let scan_id = progress.scan_id.clone();

        let result = orch.run_scan_loop(&scan_id).await.unwrap();
        assert_eq!(result.status, ScanStatus::Completed);
        assert!(result.total_tool_calls >= 1);
    }

    #[tokio::test]
    async fn test_cancel_scan() {
        let dir = tempfile::tempdir().unwrap();
        let orch = make_orchestrator(
            MockCloudProvider::new(vec![]),
            dir.path().join("scans"),
        );

        let progress = orch.start_scan("mcp_security_audit").await.unwrap();
        let scan_id = progress.scan_id.clone();

        orch.cancel_scan(&scan_id).await.unwrap();

        let progress = orch.get_progress(&scan_id).await.unwrap();
        assert_eq!(progress.status, ScanStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_cancel_nonexistent_scan() {
        let dir = tempfile::tempdir().unwrap();
        let orch = make_orchestrator(
            MockCloudProvider::new(vec![]),
            dir.path().join("scans"),
        );

        let result = orch.cancel_scan("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_scan_result_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let scans_dir = dir.path().join("scans");

        let scan_id;
        {
            let orch = make_orchestrator(
                MockCloudProvider::new(vec![MockCloudProvider::text_response(
                    "SCAN COMPLETE\n\nAll clear.",
                )]),
                scans_dir.clone(),
            );

            let progress = orch.start_scan("mcp_security_audit").await.unwrap();
            scan_id = progress.scan_id.clone();

            let _result = orch.run_scan_loop(&scan_id).await.unwrap();
        }

        // Load from disk with a new orchestrator
        {
            let orch = make_orchestrator(
                MockCloudProvider::new(vec![]),
                scans_dir,
            );

            let loaded = orch.load_scan_result(&scan_id).await.unwrap();
            assert_eq!(loaded.scan_id, scan_id);
            assert_eq!(loaded.status, ScanStatus::Completed);
        }
    }

    #[tokio::test]
    async fn test_get_progress_running() {
        let dir = tempfile::tempdir().unwrap();
        let orch = make_orchestrator(
            MockCloudProvider::new(vec![]),
            dir.path().join("scans"),
        );

        let progress = orch.start_scan("mcp_security_audit").await.unwrap();
        let scan_id = progress.scan_id.clone();

        let live_progress = orch.get_progress(&scan_id).await.unwrap();
        assert_eq!(live_progress.status, ScanStatus::Running);
        assert_eq!(live_progress.playbook_id, "mcp_security_audit");
        assert_eq!(live_progress.stages_total, 5);
    }

    #[tokio::test]
    async fn test_respond_to_request() {
        let dir = tempfile::tempdir().unwrap();
        let orch = make_orchestrator(
            MockCloudProvider::new(vec![]),
            dir.path().join("scans"),
        );

        let progress = orch.start_scan("mcp_security_audit").await.unwrap();
        let scan_id = progress.scan_id.clone();

        // Manually add a pending request
        {
            let mut scans = orch.scans.lock().await;
            if let Some(state) = scans.get_mut(&scan_id) {
                state.pending_user_requests.push(ScanUserRequest {
                    id: "req-1".into(),
                    scan_id: scan_id.clone(),
                    question: "Should I check SSH configs?".into(),
                    context: "Stage 2".into(),
                });
            }
        }

        orch.respond_to_request(&scan_id, "req-1", "Yes, please check.")
            .await
            .unwrap();

        // Verify request was consumed
        let scans = orch.scans.lock().await;
        let state = scans.get(&scan_id).unwrap();
        assert!(state.pending_user_requests.is_empty());
        assert_eq!(
            state.user_responses.get("req-1"),
            Some(&"Yes, please check.".to_string())
        );
    }
}
