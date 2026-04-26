//! Response Playbooks — Automated response sequences for threat conditions.
//!
//! Executes pre-defined action sequences when trigger conditions are met,
//! with circuit-breaker protection against runaway loops.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ============================================================================
// Core Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePlaybook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub trigger: PlaybookTrigger,
    pub actions: Vec<PlaybookAction>,
    pub enabled: bool,
    /// Required autonomy level: "L0" (always allowed), "L1", "L2", "L3"
    pub autonomy_required: String,
    pub is_builtin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookTrigger {
    KillChainConfirmed { min_stage: u8, min_confidence: f64 },
    BlocklistMatch { server_name_pattern: Option<String> },
    CriticalAlert,
    ExfiltrationDetected,
    PromptInjectionDetected,
    PostureReachesCritical,
    InferenceFailureSpike { threshold: u32, window_minutes: u32 },
    CustomTrigger { condition: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookAction {
    pub action_type: String,
    pub description: String,
    pub parameters: Value,
    pub delay_after_secs: u64,
    pub continue_on_failure: bool,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecution {
    pub id: Uuid,
    pub playbook_id: String,
    pub playbook_name: String,
    pub triggered_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub trigger_context: String,
    pub actions_attempted: u32,
    pub actions_executed: u32,
    pub actions_blocked: u32,
    pub status: ExecutionStatus,
    pub action_results: Vec<ActionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Running,
    Completed,
    PartiallyCompleted,
    Failed,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action_type: String,
    pub description: String,
    /// "approved", "suggest", "blocked", "denied"
    pub permission_result: String,
    pub executed: bool,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerContext {
    pub trigger_type: String,
    pub server_name: Option<String>,
    pub event_ids: Vec<String>,
    pub confidence: f64,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// Circuit Breaker
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    recent_triggers: Vec<(DateTime<Utc>, String)>,
    max_triggers_per_minute: u32,
    cooldown_active: bool,
    cooldown_until: Option<DateTime<Utc>>,
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            recent_triggers: Vec::new(),
            max_triggers_per_minute: 3,
            cooldown_active: false,
            cooldown_until: None,
        }
    }

    /// Returns false if the same playbook has been triggered too many times recently.
    pub fn should_allow(&mut self, playbook_id: &str) -> bool {
        self.cleanup_old_triggers();

        if self.check_cooldown() {
            debug!(
                "Circuit breaker cooldown active, blocking playbook {}",
                playbook_id
            );
            return false;
        }

        let one_minute_ago = Utc::now() - Duration::minutes(1);
        let recent_count = self
            .recent_triggers
            .iter()
            .filter(|(ts, id)| id == playbook_id && *ts > one_minute_ago)
            .count() as u32;

        if recent_count >= self.max_triggers_per_minute {
            warn!(
                "Circuit breaker tripped for playbook {} ({} triggers in 1 minute)",
                playbook_id, recent_count
            );
            self.cooldown_active = true;
            self.cooldown_until = Some(Utc::now() + Duration::minutes(5));
            return false;
        }

        true
    }

    /// Record that a playbook was triggered.
    pub fn record_trigger(&mut self, playbook_id: &str) {
        self.recent_triggers
            .push((Utc::now(), playbook_id.to_string()));
    }

    /// Returns true if cooldown is currently active. Auto-clears after 5 minutes.
    pub fn check_cooldown(&mut self) -> bool {
        if !self.cooldown_active {
            return false;
        }

        if let Some(until) = self.cooldown_until {
            if Utc::now() >= until {
                info!("Circuit breaker cooldown expired, resuming");
                self.cooldown_active = false;
                self.cooldown_until = None;
                return false;
            }
        }

        true
    }

    fn cleanup_old_triggers(&mut self) {
        let five_minutes_ago = Utc::now() - Duration::minutes(5);
        self.recent_triggers
            .retain(|(ts, _)| *ts > five_minutes_ago);
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Trigger Matching
// ============================================================================

/// Check whether a playbook trigger matches the given context.
pub fn check_trigger_match(trigger: &PlaybookTrigger, context: &TriggerContext) -> bool {
    match trigger {
        PlaybookTrigger::KillChainConfirmed {
            min_stage,
            min_confidence,
        } => {
            if context.trigger_type != "kill_chain_confirmed" {
                return false;
            }
            // Parse stage from details if available, otherwise check confidence only
            let stage = context
                .details
                .split("stage:")
                .nth(1)
                .and_then(|s| s.trim().split_whitespace().next())
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0);
            stage >= *min_stage && context.confidence >= *min_confidence
        }
        PlaybookTrigger::BlocklistMatch {
            server_name_pattern,
        } => {
            if context.trigger_type != "blocklist_match" {
                return false;
            }
            match (server_name_pattern, &context.server_name) {
                (Some(pattern), Some(name)) => name.contains(pattern.as_str()),
                (None, _) => true, // Match any blocklist hit
                (Some(_), None) => false,
            }
        }
        PlaybookTrigger::CriticalAlert => context.trigger_type == "critical_alert",
        PlaybookTrigger::ExfiltrationDetected => context.trigger_type == "exfiltration_detected",
        PlaybookTrigger::PromptInjectionDetected => {
            context.trigger_type == "prompt_injection_detected"
        }
        PlaybookTrigger::PostureReachesCritical => {
            context.trigger_type == "posture_reaches_critical"
        }
        PlaybookTrigger::InferenceFailureSpike {
            threshold,
            window_minutes: _,
        } => {
            if context.trigger_type != "inference_failure_spike" {
                return false;
            }
            // Parse failure count from details
            let count = context
                .details
                .split("count:")
                .nth(1)
                .and_then(|s| s.trim().split_whitespace().next())
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            count >= *threshold
        }
        PlaybookTrigger::CustomTrigger { condition } => {
            context.trigger_type == "custom" && context.details.contains(condition.as_str())
        }
    }
}

// ============================================================================
// Playbook Manager
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookManager {
    playbooks: Vec<ResponsePlaybook>,
    execution_history: Vec<PlaybookExecution>,
    circuit_breaker: CircuitBreaker,
}

impl PlaybookManager {
    /// Create a new manager with 6 default built-in playbooks.
    pub fn new() -> Self {
        let playbooks = vec![
            // Playbook 1 — Kill Chain Response
            ResponsePlaybook {
                id: "pb-kill-chain-response".to_string(),
                name: "Kill Chain Response".to_string(),
                description:
                    "Respond to confirmed kill chain activity at stage 3+ with high confidence"
                        .to_string(),
                trigger: PlaybookTrigger::KillChainConfirmed {
                    min_stage: 3,
                    min_confidence: 0.75,
                },
                actions: vec![
                    PlaybookAction {
                        action_type: "BlockServer".to_string(),
                        description: "Block the offending MCP server".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: false,
                        risk_level: "high".to_string(),
                    },
                    PlaybookAction {
                        action_type: "CreateAlert".to_string(),
                        description: "Create a critical severity alert".to_string(),
                        parameters: json!({"severity": "critical"}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "LaunchInvestigation".to_string(),
                        description: "Launch an automated investigation into the kill chain"
                            .to_string(),
                        parameters: json!({}),
                        delay_after_secs: 1,
                        continue_on_failure: true,
                        risk_level: "medium".to_string(),
                    },
                    PlaybookAction {
                        action_type: "NotifyUser".to_string(),
                        description: "Notify user about the confirmed threat".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "ElevatePosture".to_string(),
                        description: "Elevate threat posture to High".to_string(),
                        parameters: json!({"level": "high"}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "medium".to_string(),
                    },
                ],
                enabled: true,
                autonomy_required: "L2".to_string(),
                is_builtin: true,
            },
            // Playbook 2 — Blocklist Auto-Quarantine
            ResponsePlaybook {
                id: "pb-blocklist-quarantine".to_string(),
                name: "Blocklist Auto-Quarantine".to_string(),
                description: "Quarantine servers that match the blocklist".to_string(),
                trigger: PlaybookTrigger::BlocklistMatch {
                    server_name_pattern: None,
                },
                actions: vec![
                    PlaybookAction {
                        action_type: "CreateAlert".to_string(),
                        description: "Create a high severity alert for blocklist match".to_string(),
                        parameters: json!({"severity": "high"}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "UnwrapServer".to_string(),
                        description: "Unwrap (disconnect) the blocklisted server".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: false,
                        risk_level: "high".to_string(),
                    },
                    PlaybookAction {
                        action_type: "NotifyUser".to_string(),
                        description: "Notify user about blocklist match".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "LaunchInvestigation".to_string(),
                        description: "Launch investigation into the blocklisted server".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 1,
                        continue_on_failure: true,
                        risk_level: "medium".to_string(),
                    },
                ],
                enabled: true,
                autonomy_required: "L2".to_string(),
                is_builtin: true,
            },
            // Playbook 3 — Prompt Injection Block
            ResponsePlaybook {
                id: "pb-prompt-injection-block".to_string(),
                name: "Prompt Injection Block".to_string(),
                description: "Immediately block detected prompt injection attempts".to_string(),
                trigger: PlaybookTrigger::PromptInjectionDetected,
                actions: vec![
                    PlaybookAction {
                        action_type: "BlockRequest".to_string(),
                        description: "Block the injection request".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: false,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "LogInjection".to_string(),
                        description: "Log the injection attempt for analysis".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "CreateAlert".to_string(),
                        description: "Create a high severity alert for prompt injection"
                            .to_string(),
                        parameters: json!({"severity": "high"}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "ElevateThreshold".to_string(),
                        description: "Increase detection sensitivity".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                ],
                enabled: true,
                autonomy_required: "L0".to_string(),
                is_builtin: true,
            },
            // Playbook 4 — Exfiltration Response
            ResponsePlaybook {
                id: "pb-exfiltration-response".to_string(),
                name: "Exfiltration Response".to_string(),
                description: "Respond to detected data exfiltration attempts".to_string(),
                trigger: PlaybookTrigger::ExfiltrationDetected,
                actions: vec![
                    PlaybookAction {
                        action_type: "BlockNetwork".to_string(),
                        description: "Block outgoing network connections from the server"
                            .to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: false,
                        risk_level: "high".to_string(),
                    },
                    PlaybookAction {
                        action_type: "BlockToolCalls".to_string(),
                        description: "Block all tool calls from the server".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "high".to_string(),
                    },
                    PlaybookAction {
                        action_type: "CreateAlert".to_string(),
                        description: "Create a critical severity alert for exfiltration"
                            .to_string(),
                        parameters: json!({"severity": "critical"}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "LaunchInvestigation".to_string(),
                        description: "Launch investigation into the exfiltration attempt"
                            .to_string(),
                        parameters: json!({}),
                        delay_after_secs: 1,
                        continue_on_failure: true,
                        risk_level: "medium".to_string(),
                    },
                    PlaybookAction {
                        action_type: "ElevatePosture".to_string(),
                        description: "Elevate threat posture to Critical".to_string(),
                        parameters: json!({"level": "critical"}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "medium".to_string(),
                    },
                ],
                enabled: true,
                autonomy_required: "L2".to_string(),
                is_builtin: true,
            },
            // Playbook 5 — Graceful Degradation
            ResponsePlaybook {
                id: "pb-graceful-degradation".to_string(),
                name: "Graceful Degradation".to_string(),
                description: "Gracefully degrade when SLM inference failures spike".to_string(),
                trigger: PlaybookTrigger::InferenceFailureSpike {
                    threshold: 5,
                    window_minutes: 10,
                },
                actions: vec![
                    PlaybookAction {
                        action_type: "DeactivateSlm".to_string(),
                        description: "Deactivate the SLM to stop cascading failures".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: false,
                        risk_level: "medium".to_string(),
                    },
                    PlaybookAction {
                        action_type: "SwitchToRuleBased".to_string(),
                        description: "Fall back to rule-based analysis".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 1,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "CreateAlert".to_string(),
                        description: "Create a medium severity alert about degradation".to_string(),
                        parameters: json!({"severity": "medium"}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "LowerPosture".to_string(),
                        description: "Lower posture to Normal during degraded operation"
                            .to_string(),
                        parameters: json!({"level": "normal"}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                ],
                enabled: true,
                autonomy_required: "L1".to_string(),
                is_builtin: true,
            },
            // Playbook 6 — New Untrusted Server
            ResponsePlaybook {
                id: "pb-new-untrusted-server".to_string(),
                name: "New Untrusted Server".to_string(),
                description: "Handle a newly connected unknown MCP server".to_string(),
                trigger: PlaybookTrigger::CustomTrigger {
                    condition: "new_unknown_server".to_string(),
                },
                actions: vec![
                    PlaybookAction {
                        action_type: "CreateAlert".to_string(),
                        description: "Create a medium severity alert for the new server"
                            .to_string(),
                        parameters: json!({"severity": "medium"}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "RunRiskAssessment".to_string(),
                        description: "Run a risk assessment on the new server".to_string(),
                        parameters: json!({}),
                        delay_after_secs: 2,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                    PlaybookAction {
                        action_type: "SuggestWrap".to_string(),
                        description: "Suggest wrapping the server with security controls"
                            .to_string(),
                        parameters: json!({}),
                        delay_after_secs: 0,
                        continue_on_failure: true,
                        risk_level: "low".to_string(),
                    },
                ],
                enabled: true,
                autonomy_required: "L1".to_string(),
                is_builtin: true,
            },
        ];

        Self {
            playbooks,
            execution_history: Vec::new(),
            circuit_breaker: CircuitBreaker::new(),
        }
    }

    // ========================================================================
    // Trigger Evaluation
    // ========================================================================

    /// Evaluate a trigger context against all enabled playbooks.
    /// Returns a list of executions for matching playbooks.
    pub fn evaluate_trigger(&mut self, context: &TriggerContext) -> Vec<PlaybookExecution> {
        let mut executions = Vec::new();

        // Collect matching playbooks first to avoid borrow issues
        let matching: Vec<(String, String, String, Vec<PlaybookAction>)> = self
            .playbooks
            .iter()
            .filter(|pb| pb.enabled && check_trigger_match(&pb.trigger, context))
            .map(|pb| {
                (
                    pb.id.clone(),
                    pb.name.clone(),
                    pb.autonomy_required.clone(),
                    pb.actions.clone(),
                )
            })
            .collect();

        for (pb_id, pb_name, autonomy, actions) in matching {
            if !self.circuit_breaker.should_allow(&pb_id) {
                info!("Circuit breaker blocked playbook '{}', skipping", pb_name);
                let execution = PlaybookExecution {
                    id: Uuid::new_v4(),
                    playbook_id: pb_id.clone(),
                    playbook_name: pb_name,
                    triggered_at: Utc::now(),
                    completed_at: Some(Utc::now()),
                    trigger_context: context.details.clone(),
                    actions_attempted: 0,
                    actions_executed: 0,
                    actions_blocked: actions.len() as u32,
                    status: ExecutionStatus::Interrupted,
                    action_results: Vec::new(),
                };
                executions.push(execution);
                continue;
            }

            self.circuit_breaker.record_trigger(&pb_id);

            let execution = self.simulate_execution(&pb_id, &pb_name, &autonomy, &actions, context);
            executions.push(execution);
        }

        // Store in history, capping at 200
        for exec in &executions {
            self.execution_history.push(exec.clone());
        }
        while self.execution_history.len() > 200 {
            self.execution_history.remove(0);
        }

        executions
    }

    fn simulate_execution(
        &self,
        playbook_id: &str,
        playbook_name: &str,
        autonomy_required: &str,
        actions: &[PlaybookAction],
        context: &TriggerContext,
    ) -> PlaybookExecution {
        let mut action_results = Vec::new();
        let mut actions_executed = 0u32;
        let mut actions_blocked = 0u32;
        let mut all_succeeded = true;
        let mut had_critical_failure = false;

        for action in actions {
            let permission = determine_permission(autonomy_required, &action.risk_level);
            let executed = permission == "approved";
            let success = executed;

            if !executed {
                actions_blocked += 1;
                if !action.continue_on_failure {
                    had_critical_failure = true;
                    action_results.push(ActionResult {
                        action_type: action.action_type.clone(),
                        description: action.description.clone(),
                        permission_result: permission,
                        executed: false,
                        success: false,
                        error: Some("Action blocked by autonomy policy".to_string()),
                    });
                    break;
                }
            } else {
                actions_executed += 1;
            }

            if !success {
                all_succeeded = false;
            }

            action_results.push(ActionResult {
                action_type: action.action_type.clone(),
                description: action.description.clone(),
                permission_result: permission,
                executed,
                success,
                error: None,
            });
        }

        let status = if had_critical_failure {
            ExecutionStatus::Failed
        } else if actions_blocked > 0 {
            ExecutionStatus::PartiallyCompleted
        } else if all_succeeded {
            ExecutionStatus::Completed
        } else {
            ExecutionStatus::Failed
        };

        PlaybookExecution {
            id: Uuid::new_v4(),
            playbook_id: playbook_id.to_string(),
            playbook_name: playbook_name.to_string(),
            triggered_at: Utc::now(),
            completed_at: Some(Utc::now()),
            trigger_context: context.details.clone(),
            actions_attempted: action_results.len() as u32,
            actions_executed,
            actions_blocked,
            status,
            action_results,
        }
    }

    // ========================================================================
    // Dry-Run Testing
    // ========================================================================

    /// Test a playbook against a trigger context without recording in history.
    pub fn test_playbook(&self, id: &str, context: &TriggerContext) -> Option<PlaybookExecution> {
        let pb = self.playbooks.iter().find(|p| p.id == id)?;

        if !check_trigger_match(&pb.trigger, context) {
            // Trigger doesn't match — return None
            return None;
        }

        Some(self.simulate_execution(
            &pb.id,
            &pb.name,
            &pb.autonomy_required,
            &pb.actions,
            context,
        ))
    }

    // ========================================================================
    // CRUD Operations
    // ========================================================================

    /// Create a new custom playbook.
    pub fn create_custom_playbook(&mut self, playbook: ResponsePlaybook) -> Result<(), String> {
        if playbook.is_builtin {
            return Err("Cannot create a built-in playbook via create_custom_playbook".to_string());
        }
        if playbook.id.is_empty() {
            return Err("Playbook id cannot be empty".to_string());
        }
        if self.playbooks.iter().any(|p| p.id == playbook.id) {
            return Err(format!("Playbook with id '{}' already exists", playbook.id));
        }
        self.playbooks.push(playbook);
        Ok(())
    }

    /// Update a playbook's enabled state and/or actions.
    pub fn update_playbook(
        &mut self,
        id: &str,
        enabled: Option<bool>,
        actions: Option<Vec<PlaybookAction>>,
    ) -> Result<(), String> {
        let pb = self
            .playbooks
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| format!("Playbook '{}' not found", id))?;

        if let Some(e) = enabled {
            pb.enabled = e;
        }
        if let Some(a) = actions {
            pb.actions = a;
        }

        Ok(())
    }

    /// Delete a non-builtin playbook.
    pub fn delete_playbook(&mut self, id: &str) -> Result<(), String> {
        let idx = self
            .playbooks
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| format!("Playbook '{}' not found", id))?;

        if self.playbooks[idx].is_builtin {
            return Err("Cannot delete a built-in playbook".to_string());
        }

        self.playbooks.remove(idx);
        Ok(())
    }

    /// Get a playbook by id.
    pub fn get_playbook(&self, id: &str) -> Option<&ResponsePlaybook> {
        self.playbooks.iter().find(|p| p.id == id)
    }

    /// List all playbooks.
    pub fn list_playbooks(&self) -> &[ResponsePlaybook] {
        &self.playbooks
    }

    // ========================================================================
    // Execution History
    // ========================================================================

    /// Get execution history, optionally filtered by playbook_id, capped at `count`.
    pub fn get_execution_history(
        &self,
        playbook_id: Option<&str>,
        count: usize,
    ) -> Vec<&PlaybookExecution> {
        self.execution_history
            .iter()
            .rev()
            .filter(|e| match playbook_id {
                Some(id) => e.playbook_id == id,
                None => true,
            })
            .take(count)
            .collect()
    }

    // ========================================================================
    // Persistence
    // ========================================================================

    fn config_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("clawdefender");
        path.push("playbooks.json");
        path
    }

    /// Save custom playbooks to disk.
    pub fn save(&self) -> Result<(), String> {
        let custom: Vec<&ResponsePlaybook> =
            self.playbooks.iter().filter(|p| !p.is_builtin).collect();
        let json =
            serde_json::to_string_pretty(&custom).map_err(|e| format!("Serialize error: {}", e))?;

        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config dir: {}", e))?;
        }
        fs::write(&path, json).map_err(|e| format!("Failed to write playbooks: {}", e))?;
        info!("Saved {} custom playbooks to {:?}", custom.len(), path);
        Ok(())
    }

    /// Load custom playbooks from disk and merge with builtins.
    pub fn load() -> Result<Self, String> {
        let mut manager = Self::new();
        let path = Self::config_path();

        if path.exists() {
            let data = fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read playbooks: {}", e))?;
            let custom: Vec<ResponsePlaybook> = serde_json::from_str(&data)
                .map_err(|e| format!("Failed to parse playbooks: {}", e))?;

            for pb in custom {
                if !pb.is_builtin && !manager.playbooks.iter().any(|p| p.id == pb.id) {
                    manager.playbooks.push(pb);
                }
            }
            info!("Loaded custom playbooks from {:?}", path);
        }

        Ok(manager)
    }
}

impl Default for PlaybookManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Permission Simulation
// ============================================================================

/// Simulate permission determination based on autonomy level and risk.
/// L0 = always approved, L1 = low/medium approved, L2 = only low approved,
/// L3 = all blocked (must suggest).
fn determine_permission(autonomy_required: &str, risk_level: &str) -> String {
    match autonomy_required {
        "L0" => "approved".to_string(),
        "L1" => match risk_level {
            "low" | "medium" => "approved".to_string(),
            "high" => "suggest".to_string(),
            _ => "blocked".to_string(),
        },
        "L2" => match risk_level {
            "low" => "approved".to_string(),
            "medium" => "suggest".to_string(),
            "high" => "blocked".to_string(),
            _ => "blocked".to_string(),
        },
        "L3" => "suggest".to_string(),
        _ => "denied".to_string(),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context(trigger_type: &str, details: &str, confidence: f64) -> TriggerContext {
        TriggerContext {
            trigger_type: trigger_type.to_string(),
            server_name: None,
            event_ids: vec!["evt-1".to_string()],
            confidence,
            details: details.to_string(),
            timestamp: Utc::now(),
        }
    }

    fn make_context_with_server(
        trigger_type: &str,
        server: &str,
        details: &str,
        confidence: f64,
    ) -> TriggerContext {
        TriggerContext {
            trigger_type: trigger_type.to_string(),
            server_name: Some(server.to_string()),
            event_ids: vec!["evt-1".to_string()],
            confidence,
            details: details.to_string(),
            timestamp: Utc::now(),
        }
    }

    // ============================
    // Trigger Matching Tests
    // ============================

    #[test]
    fn test_kill_chain_trigger_matches() {
        let trigger = PlaybookTrigger::KillChainConfirmed {
            min_stage: 3,
            min_confidence: 0.75,
        };
        let ctx = make_context("kill_chain_confirmed", "stage: 4 detected", 0.85);
        assert!(check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_kill_chain_trigger_low_stage_no_match() {
        let trigger = PlaybookTrigger::KillChainConfirmed {
            min_stage: 3,
            min_confidence: 0.75,
        };
        let ctx = make_context("kill_chain_confirmed", "stage: 2 detected", 0.85);
        assert!(!check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_kill_chain_trigger_low_confidence_no_match() {
        let trigger = PlaybookTrigger::KillChainConfirmed {
            min_stage: 3,
            min_confidence: 0.75,
        };
        let ctx = make_context("kill_chain_confirmed", "stage: 4 detected", 0.50);
        assert!(!check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_kill_chain_trigger_wrong_type() {
        let trigger = PlaybookTrigger::KillChainConfirmed {
            min_stage: 3,
            min_confidence: 0.75,
        };
        let ctx = make_context("exfiltration_detected", "stage: 4 detected", 0.85);
        assert!(!check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_blocklist_match_any() {
        let trigger = PlaybookTrigger::BlocklistMatch {
            server_name_pattern: None,
        };
        let ctx = make_context("blocklist_match", "server matched blocklist", 1.0);
        assert!(check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_blocklist_match_pattern_hit() {
        let trigger = PlaybookTrigger::BlocklistMatch {
            server_name_pattern: Some("malicious".to_string()),
        };
        let ctx =
            make_context_with_server("blocklist_match", "malicious-server-42", "matched", 1.0);
        assert!(check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_blocklist_match_pattern_miss() {
        let trigger = PlaybookTrigger::BlocklistMatch {
            server_name_pattern: Some("malicious".to_string()),
        };
        let ctx = make_context_with_server("blocklist_match", "safe-server", "checked", 1.0);
        assert!(!check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_blocklist_match_pattern_no_server() {
        let trigger = PlaybookTrigger::BlocklistMatch {
            server_name_pattern: Some("malicious".to_string()),
        };
        let ctx = make_context("blocklist_match", "no server", 1.0);
        assert!(!check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_critical_alert_trigger() {
        let trigger = PlaybookTrigger::CriticalAlert;
        let ctx = make_context("critical_alert", "critical issue", 1.0);
        assert!(check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_critical_alert_wrong_type() {
        let trigger = PlaybookTrigger::CriticalAlert;
        let ctx = make_context("blocklist_match", "not critical", 1.0);
        assert!(!check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_exfiltration_trigger() {
        let trigger = PlaybookTrigger::ExfiltrationDetected;
        let ctx = make_context("exfiltration_detected", "data leaving", 0.95);
        assert!(check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_prompt_injection_trigger() {
        let trigger = PlaybookTrigger::PromptInjectionDetected;
        let ctx = make_context("prompt_injection_detected", "injection found", 0.9);
        assert!(check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_posture_critical_trigger() {
        let trigger = PlaybookTrigger::PostureReachesCritical;
        let ctx = make_context("posture_reaches_critical", "posture critical", 1.0);
        assert!(check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_inference_failure_spike_matches() {
        let trigger = PlaybookTrigger::InferenceFailureSpike {
            threshold: 5,
            window_minutes: 10,
        };
        let ctx = make_context("inference_failure_spike", "count: 7 failures", 1.0);
        assert!(check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_inference_failure_spike_below_threshold() {
        let trigger = PlaybookTrigger::InferenceFailureSpike {
            threshold: 5,
            window_minutes: 10,
        };
        let ctx = make_context("inference_failure_spike", "count: 3 failures", 1.0);
        assert!(!check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_custom_trigger_matches() {
        let trigger = PlaybookTrigger::CustomTrigger {
            condition: "new_unknown_server".to_string(),
        };
        let ctx = make_context("custom", "new_unknown_server connected", 1.0);
        assert!(check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_custom_trigger_wrong_condition() {
        let trigger = PlaybookTrigger::CustomTrigger {
            condition: "new_unknown_server".to_string(),
        };
        let ctx = make_context("custom", "some_other_event happened", 1.0);
        assert!(!check_trigger_match(&trigger, &ctx));
    }

    #[test]
    fn test_custom_trigger_wrong_type() {
        let trigger = PlaybookTrigger::CustomTrigger {
            condition: "new_unknown_server".to_string(),
        };
        let ctx = make_context("exfiltration_detected", "new_unknown_server", 1.0);
        assert!(!check_trigger_match(&trigger, &ctx));
    }

    // ============================
    // Circuit Breaker Tests
    // ============================

    #[test]
    fn test_circuit_breaker_allows_first_trigger() {
        let mut cb = CircuitBreaker::new();
        assert!(cb.should_allow("pb-1"));
    }

    #[test]
    fn test_circuit_breaker_allows_under_limit() {
        let mut cb = CircuitBreaker::new();
        cb.record_trigger("pb-1");
        cb.record_trigger("pb-1");
        assert!(cb.should_allow("pb-1")); // 2 < 3
    }

    #[test]
    fn test_circuit_breaker_blocks_at_limit() {
        let mut cb = CircuitBreaker::new();
        cb.record_trigger("pb-1");
        cb.record_trigger("pb-1");
        cb.record_trigger("pb-1");
        assert!(!cb.should_allow("pb-1")); // 3 >= 3
    }

    #[test]
    fn test_circuit_breaker_different_playbooks_independent() {
        let mut cb = CircuitBreaker::new();
        cb.record_trigger("pb-1");
        cb.record_trigger("pb-1");
        cb.record_trigger("pb-1");
        // pb-1 is blocked, but pb-2 should still be allowed
        // (note: cooldown may be active now — test when cooldown is not yet set)
        let mut cb2 = CircuitBreaker::new();
        cb2.record_trigger("pb-1");
        cb2.record_trigger("pb-1");
        assert!(cb2.should_allow("pb-2"));
    }

    #[test]
    fn test_circuit_breaker_cooldown_activates() {
        let mut cb = CircuitBreaker::new();
        cb.record_trigger("pb-1");
        cb.record_trigger("pb-1");
        cb.record_trigger("pb-1");
        cb.should_allow("pb-1"); // triggers cooldown
        assert!(cb.cooldown_active);
        assert!(cb.cooldown_until.is_some());
    }

    #[test]
    fn test_circuit_breaker_cooldown_blocks_all() {
        let mut cb = CircuitBreaker::new();
        cb.cooldown_active = true;
        cb.cooldown_until = Some(Utc::now() + Duration::minutes(5));
        assert!(!cb.should_allow("pb-2"));
    }

    #[test]
    fn test_circuit_breaker_cooldown_expires() {
        let mut cb = CircuitBreaker::new();
        cb.cooldown_active = true;
        cb.cooldown_until = Some(Utc::now() - Duration::seconds(1)); // already expired
        assert!(!cb.check_cooldown());
        assert!(!cb.cooldown_active);
    }

    #[test]
    fn test_circuit_breaker_default() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.max_triggers_per_minute, 3);
        assert!(!cb.cooldown_active);
    }

    // ============================
    // PlaybookManager — Builtin Tests
    // ============================

    #[test]
    fn test_manager_has_six_builtins() {
        let mgr = PlaybookManager::new();
        assert_eq!(mgr.list_playbooks().len(), 6);
        assert!(mgr.list_playbooks().iter().all(|p| p.is_builtin));
    }

    #[test]
    fn test_manager_all_builtins_enabled() {
        let mgr = PlaybookManager::new();
        assert!(mgr.list_playbooks().iter().all(|p| p.enabled));
    }

    #[test]
    fn test_get_builtin_playbook() {
        let mgr = PlaybookManager::new();
        let pb = mgr.get_playbook("pb-kill-chain-response");
        assert!(pb.is_some());
        assert_eq!(pb.unwrap().name, "Kill Chain Response");
    }

    #[test]
    fn test_get_nonexistent_playbook() {
        let mgr = PlaybookManager::new();
        assert!(mgr.get_playbook("nonexistent").is_none());
    }

    #[test]
    fn test_kill_chain_playbook_has_correct_actions() {
        let mgr = PlaybookManager::new();
        let pb = mgr.get_playbook("pb-kill-chain-response").unwrap();
        assert_eq!(pb.actions.len(), 5);
        assert_eq!(pb.actions[0].action_type, "BlockServer");
        assert_eq!(pb.actions[4].action_type, "ElevatePosture");
    }

    #[test]
    fn test_prompt_injection_playbook_l0() {
        let mgr = PlaybookManager::new();
        let pb = mgr.get_playbook("pb-prompt-injection-block").unwrap();
        assert_eq!(pb.autonomy_required, "L0");
    }

    // ============================
    // CRUD Tests
    // ============================

    #[test]
    fn test_create_custom_playbook() {
        let mut mgr = PlaybookManager::new();
        let custom = ResponsePlaybook {
            id: "pb-custom-1".to_string(),
            name: "Custom Test".to_string(),
            description: "A test playbook".to_string(),
            trigger: PlaybookTrigger::CriticalAlert,
            actions: vec![],
            enabled: true,
            autonomy_required: "L1".to_string(),
            is_builtin: false,
        };
        assert!(mgr.create_custom_playbook(custom).is_ok());
        assert_eq!(mgr.list_playbooks().len(), 7);
    }

    #[test]
    fn test_create_duplicate_id_fails() {
        let mut mgr = PlaybookManager::new();
        let custom = ResponsePlaybook {
            id: "pb-kill-chain-response".to_string(),
            name: "Duplicate".to_string(),
            description: "".to_string(),
            trigger: PlaybookTrigger::CriticalAlert,
            actions: vec![],
            enabled: true,
            autonomy_required: "L1".to_string(),
            is_builtin: false,
        };
        assert!(mgr.create_custom_playbook(custom).is_err());
    }

    #[test]
    fn test_create_builtin_fails() {
        let mut mgr = PlaybookManager::new();
        let custom = ResponsePlaybook {
            id: "pb-fake-builtin".to_string(),
            name: "Fake".to_string(),
            description: "".to_string(),
            trigger: PlaybookTrigger::CriticalAlert,
            actions: vec![],
            enabled: true,
            autonomy_required: "L0".to_string(),
            is_builtin: true,
        };
        assert!(mgr.create_custom_playbook(custom).is_err());
    }

    #[test]
    fn test_create_empty_id_fails() {
        let mut mgr = PlaybookManager::new();
        let custom = ResponsePlaybook {
            id: "".to_string(),
            name: "Empty".to_string(),
            description: "".to_string(),
            trigger: PlaybookTrigger::CriticalAlert,
            actions: vec![],
            enabled: true,
            autonomy_required: "L1".to_string(),
            is_builtin: false,
        };
        assert!(mgr.create_custom_playbook(custom).is_err());
    }

    #[test]
    fn test_update_playbook_enabled() {
        let mut mgr = PlaybookManager::new();
        assert!(mgr
            .update_playbook("pb-kill-chain-response", Some(false), None)
            .is_ok());
        let pb = mgr.get_playbook("pb-kill-chain-response").unwrap();
        assert!(!pb.enabled);
    }

    #[test]
    fn test_update_playbook_actions() {
        let mut mgr = PlaybookManager::new();
        let new_actions = vec![PlaybookAction {
            action_type: "Custom".to_string(),
            description: "A custom action".to_string(),
            parameters: json!({}),
            delay_after_secs: 0,
            continue_on_failure: true,
            risk_level: "low".to_string(),
        }];
        assert!(mgr
            .update_playbook("pb-kill-chain-response", None, Some(new_actions))
            .is_ok());
        let pb = mgr.get_playbook("pb-kill-chain-response").unwrap();
        assert_eq!(pb.actions.len(), 1);
    }

    #[test]
    fn test_update_nonexistent_fails() {
        let mut mgr = PlaybookManager::new();
        assert!(mgr
            .update_playbook("nonexistent", Some(true), None)
            .is_err());
    }

    #[test]
    fn test_delete_custom_playbook() {
        let mut mgr = PlaybookManager::new();
        let custom = ResponsePlaybook {
            id: "pb-deleteme".to_string(),
            name: "Delete Me".to_string(),
            description: "".to_string(),
            trigger: PlaybookTrigger::CriticalAlert,
            actions: vec![],
            enabled: true,
            autonomy_required: "L1".to_string(),
            is_builtin: false,
        };
        mgr.create_custom_playbook(custom).unwrap();
        assert_eq!(mgr.list_playbooks().len(), 7);
        assert!(mgr.delete_playbook("pb-deleteme").is_ok());
        assert_eq!(mgr.list_playbooks().len(), 6);
    }

    #[test]
    fn test_delete_builtin_fails() {
        let mut mgr = PlaybookManager::new();
        assert!(mgr.delete_playbook("pb-kill-chain-response").is_err());
    }

    #[test]
    fn test_delete_nonexistent_fails() {
        let mut mgr = PlaybookManager::new();
        assert!(mgr.delete_playbook("nonexistent").is_err());
    }

    // ============================
    // Execution Simulation Tests
    // ============================

    #[test]
    fn test_evaluate_prompt_injection_trigger() {
        let mut mgr = PlaybookManager::new();
        let ctx = make_context("prompt_injection_detected", "injection found", 0.95);
        let executions = mgr.evaluate_trigger(&ctx);
        assert_eq!(executions.len(), 1);
        assert_eq!(executions[0].playbook_id, "pb-prompt-injection-block");
        assert_eq!(executions[0].status, ExecutionStatus::Completed);
        // L0 means all actions should be approved
        assert!(executions[0]
            .action_results
            .iter()
            .all(|r| r.permission_result == "approved"));
    }

    #[test]
    fn test_evaluate_exfiltration_trigger() {
        let mut mgr = PlaybookManager::new();
        let ctx = make_context("exfiltration_detected", "data exfiltration attempt", 0.9);
        let executions = mgr.evaluate_trigger(&ctx);
        assert_eq!(executions.len(), 1);
        assert_eq!(executions[0].playbook_id, "pb-exfiltration-response");
    }

    #[test]
    fn test_evaluate_no_matching_trigger() {
        let mut mgr = PlaybookManager::new();
        let ctx = make_context("unknown_event", "nothing to see here", 0.1);
        let executions = mgr.evaluate_trigger(&ctx);
        assert!(executions.is_empty());
    }

    #[test]
    fn test_evaluate_disabled_playbook_skipped() {
        let mut mgr = PlaybookManager::new();
        mgr.update_playbook("pb-prompt-injection-block", Some(false), None)
            .unwrap();
        let ctx = make_context("prompt_injection_detected", "injection", 0.9);
        let executions = mgr.evaluate_trigger(&ctx);
        assert!(executions.is_empty());
    }

    #[test]
    fn test_execution_history_recorded() {
        let mut mgr = PlaybookManager::new();
        let ctx = make_context("prompt_injection_detected", "injection found", 0.9);
        mgr.evaluate_trigger(&ctx);
        let history = mgr.get_execution_history(None, 10);
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_execution_history_filtered() {
        let mut mgr = PlaybookManager::new();
        let ctx1 = make_context("prompt_injection_detected", "injection", 0.9);
        let ctx2 = make_context("exfiltration_detected", "exfil", 0.9);
        mgr.evaluate_trigger(&ctx1);
        mgr.evaluate_trigger(&ctx2);

        let all = mgr.get_execution_history(None, 10);
        assert_eq!(all.len(), 2);

        let injection_only = mgr.get_execution_history(Some("pb-prompt-injection-block"), 10);
        assert_eq!(injection_only.len(), 1);
    }

    #[test]
    fn test_execution_history_count_limit() {
        let mut mgr = PlaybookManager::new();
        let ctx = make_context("prompt_injection_detected", "injection", 0.9);
        mgr.evaluate_trigger(&ctx);
        mgr.evaluate_trigger(&ctx);
        mgr.evaluate_trigger(&ctx);

        let limited = mgr.get_execution_history(None, 2);
        assert_eq!(limited.len(), 2);
    }

    #[test]
    fn test_execution_history_capped_at_200() {
        let mut mgr = PlaybookManager::new();
        // Each trigger produces 1 execution for prompt_injection
        for _ in 0..210 {
            let ctx = make_context("prompt_injection_detected", "injection", 0.9);
            // Reset circuit breaker to avoid blocking
            mgr.circuit_breaker = CircuitBreaker::new();
            mgr.evaluate_trigger(&ctx);
        }
        assert!(mgr.execution_history.len() <= 200);
    }

    // ============================
    // Dry-Run Tests
    // ============================

    #[test]
    fn test_dry_run_matching_trigger() {
        let mgr = PlaybookManager::new();
        let ctx = make_context("prompt_injection_detected", "injection attempt", 0.9);
        let result = mgr.test_playbook("pb-prompt-injection-block", &ctx);
        assert!(result.is_some());
        let exec = result.unwrap();
        assert_eq!(exec.playbook_id, "pb-prompt-injection-block");
    }

    #[test]
    fn test_dry_run_non_matching_trigger() {
        let mgr = PlaybookManager::new();
        let ctx = make_context("exfiltration_detected", "exfil", 0.9);
        let result = mgr.test_playbook("pb-prompt-injection-block", &ctx);
        assert!(result.is_none());
    }

    #[test]
    fn test_dry_run_nonexistent_playbook() {
        let mgr = PlaybookManager::new();
        let ctx = make_context("critical_alert", "alert", 1.0);
        let result = mgr.test_playbook("nonexistent", &ctx);
        assert!(result.is_none());
    }

    #[test]
    fn test_dry_run_does_not_record_history() {
        let mgr = PlaybookManager::new();
        let ctx = make_context("prompt_injection_detected", "injection", 0.9);
        mgr.test_playbook("pb-prompt-injection-block", &ctx);
        assert!(mgr.execution_history.is_empty());
    }

    // ============================
    // Permission / Autonomy Tests
    // ============================

    #[test]
    fn test_permission_l0_always_approved() {
        assert_eq!(determine_permission("L0", "low"), "approved");
        assert_eq!(determine_permission("L0", "medium"), "approved");
        assert_eq!(determine_permission("L0", "high"), "approved");
    }

    #[test]
    fn test_permission_l1_high_suggest() {
        assert_eq!(determine_permission("L1", "low"), "approved");
        assert_eq!(determine_permission("L1", "medium"), "approved");
        assert_eq!(determine_permission("L1", "high"), "suggest");
    }

    #[test]
    fn test_permission_l2_graduated() {
        assert_eq!(determine_permission("L2", "low"), "approved");
        assert_eq!(determine_permission("L2", "medium"), "suggest");
        assert_eq!(determine_permission("L2", "high"), "blocked");
    }

    #[test]
    fn test_permission_l3_all_suggest() {
        assert_eq!(determine_permission("L3", "low"), "suggest");
        assert_eq!(determine_permission("L3", "high"), "suggest");
    }

    #[test]
    fn test_permission_unknown_level_denied() {
        assert_eq!(determine_permission("L99", "low"), "denied");
    }

    // ============================
    // L2 Execution — Partial Completion
    // ============================

    #[test]
    fn test_l2_playbook_partial_execution() {
        let mgr = PlaybookManager::new();
        // Kill chain response is L2, has high-risk BlockServer as first action
        // with continue_on_failure=false — so it should fail
        let ctx = make_context("kill_chain_confirmed", "stage: 4 detected", 0.85);
        let exec = mgr.test_playbook("pb-kill-chain-response", &ctx).unwrap();
        // BlockServer is high risk, L2 blocks it, continue_on_failure=false → Failed
        assert_eq!(exec.status, ExecutionStatus::Failed);
        assert!(exec.actions_blocked > 0);
    }

    #[test]
    fn test_l0_playbook_full_execution() {
        let mgr = PlaybookManager::new();
        let ctx = make_context("prompt_injection_detected", "injection", 0.9);
        let exec = mgr
            .test_playbook("pb-prompt-injection-block", &ctx)
            .unwrap();
        assert_eq!(exec.status, ExecutionStatus::Completed);
        assert_eq!(exec.actions_blocked, 0);
        assert_eq!(exec.actions_executed, 4);
    }

    // ============================
    // Serialization Tests
    // ============================

    #[test]
    fn test_trigger_serialization() {
        let trigger = PlaybookTrigger::KillChainConfirmed {
            min_stage: 3,
            min_confidence: 0.75,
        };
        let json = serde_json::to_string(&trigger).unwrap();
        let deserialized: PlaybookTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(trigger, deserialized);
    }

    #[test]
    fn test_playbook_serialization() {
        let mgr = PlaybookManager::new();
        let pb = mgr.get_playbook("pb-prompt-injection-block").unwrap();
        let json = serde_json::to_string(pb).unwrap();
        let deserialized: ResponsePlaybook = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, pb.id);
        assert_eq!(deserialized.actions.len(), pb.actions.len());
    }

    #[test]
    fn test_execution_status_serialization() {
        let status = ExecutionStatus::PartiallyCompleted;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"partially_completed\"");
    }

    // ============================
    // Manager Default
    // ============================

    #[test]
    fn test_manager_default() {
        let mgr = PlaybookManager::default();
        assert_eq!(mgr.list_playbooks().len(), 6);
    }

    // ============================
    // Persistence (file-system)
    // ============================

    #[test]
    fn test_save_and_load_roundtrip() {
        // Use a temp dir to avoid touching real config
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbooks.json");

        let mut mgr = PlaybookManager::new();
        let custom = ResponsePlaybook {
            id: "pb-roundtrip-test".to_string(),
            name: "Roundtrip".to_string(),
            description: "roundtrip test".to_string(),
            trigger: PlaybookTrigger::CriticalAlert,
            actions: vec![PlaybookAction {
                action_type: "NotifyUser".to_string(),
                description: "Notify".to_string(),
                parameters: json!({}),
                delay_after_secs: 0,
                continue_on_failure: true,
                risk_level: "low".to_string(),
            }],
            enabled: true,
            autonomy_required: "L1".to_string(),
            is_builtin: false,
        };
        mgr.create_custom_playbook(custom).unwrap();

        // Manually serialize to temp path
        let customs: Vec<&ResponsePlaybook> =
            mgr.playbooks.iter().filter(|p| !p.is_builtin).collect();
        let json = serde_json::to_string_pretty(&customs).unwrap();
        fs::write(&path, &json).unwrap();

        // Deserialize and verify
        let data = fs::read_to_string(&path).unwrap();
        let loaded: Vec<ResponsePlaybook> = serde_json::from_str(&data).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "pb-roundtrip-test");
    }
}
