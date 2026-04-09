//! Autonomy Permission Framework
//!
//! Central permission system that governs what the security agent can do
//! at each trust level. Provides graduated autonomy from observe-only to
//! fully autonomous low-risk actions, with lockdown and escalation support.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Autonomy levels governing agent permissions, ordered from most restrictive
/// to most autonomous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyLevel {
    /// Agent monitors and reports only — all actions require user click.
    L0ObserveOnly,
    /// Agent proposes actions with reasoning — user approves or denies.
    L1Suggest,
    /// Agent executes low-risk after countdown, high-risk needs approval.
    L2ConfirmAndAct,
    /// Agent auto-executes low-risk, medium-risk gets countdown, high-risk needs approval.
    L3AutoLowRisk,
}

impl std::fmt::Display for AutonomyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::L0ObserveOnly => write!(f, "L0 — Observe Only"),
            Self::L1Suggest => write!(f, "L1 — Suggest"),
            Self::L2ConfirmAndAct => write!(f, "L2 — Confirm & Act"),
            Self::L3AutoLowRisk => write!(f, "L3 — Auto Low-Risk"),
        }
    }
}

/// Risk classification for actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRisk {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for ActionRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

/// Categories of actions the agent can perform, each with an inherent risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionCategory {
    // Low risk
    UpdateNoiseFilter,
    AdjustAnomalyThreshold,
    UpdateKnowledgeBase,
    GenerateReport,
    // Medium risk
    AddPolicyRule,
    ModifyTrustLevel,
    BlockServer,
    EnableAutoBlock,
    // High risk
    RemovePolicyRule,
    UnwrapServer,
    KillProcess,
    ModifySystemConfig,
    // Always requires approval
    DeleteData,
    DisableDaemon,
    ExportSensitiveData,
}

impl ActionCategory {
    /// The risk level associated with this action category.
    pub fn risk_level(&self) -> ActionRisk {
        match self {
            Self::UpdateNoiseFilter
            | Self::AdjustAnomalyThreshold
            | Self::UpdateKnowledgeBase
            | Self::GenerateReport => ActionRisk::Low,

            Self::AddPolicyRule
            | Self::ModifyTrustLevel
            | Self::BlockServer
            | Self::EnableAutoBlock => ActionRisk::Medium,

            Self::RemovePolicyRule
            | Self::UnwrapServer
            | Self::KillProcess
            | Self::ModifySystemConfig
            | Self::DeleteData
            | Self::DisableDaemon
            | Self::ExportSensitiveData => ActionRisk::High,
        }
    }

    /// The minimum autonomy level required to execute this action without
    /// further user interaction.
    pub fn required_level(&self) -> AutonomyLevel {
        match self.risk_level() {
            ActionRisk::Low => AutonomyLevel::L2ConfirmAndAct,
            ActionRisk::Medium => AutonomyLevel::L3AutoLowRisk,
            ActionRisk::High => AutonomyLevel::L3AutoLowRisk,
        }
    }

    /// Whether this action always requires explicit user approval regardless
    /// of autonomy level.
    pub fn always_requires_approval(&self) -> bool {
        matches!(
            self,
            Self::DeleteData | Self::DisableDaemon | Self::ExportSensitiveData
        )
    }
}

impl std::fmt::Display for ActionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ---------------------------------------------------------------------------
// Permission result
// ---------------------------------------------------------------------------

/// The result of a permission check for an agent action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PermissionResult {
    /// Action is approved for immediate execution.
    Approved,
    /// Action will execute after a countdown unless the user cancels.
    CountdownConfirm {
        description: String,
        countdown_secs: u64,
    },
    /// Agent suggests this action for user consideration.
    Suggest { description: String },
    /// Action requires explicit user approval before execution.
    RequiresApproval { description: String },
    /// Action is denied outright.
    Denied { reason: String },
}

impl PermissionResult {
    /// Short tag string for logging.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::CountdownConfirm { .. } => "countdown",
            Self::Suggest { .. } => "suggest",
            Self::RequiresApproval { .. } => "requires_approval",
            Self::Denied { .. } => "denied",
        }
    }
}

// ---------------------------------------------------------------------------
// Agent action
// ---------------------------------------------------------------------------

/// A proposed action by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    pub id: Uuid,
    pub category: ActionCategory,
    pub description: String,
    pub server: Option<String>,
    pub risk: ActionRisk,
    pub parameters: serde_json::Value,
}

impl AgentAction {
    pub fn new(
        category: ActionCategory,
        description: impl Into<String>,
        server: Option<String>,
        parameters: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            category,
            description: description.into(),
            server,
            risk: category.risk_level(),
            parameters,
        }
    }
}

// ---------------------------------------------------------------------------
// Action log entry
// ---------------------------------------------------------------------------

/// Record of an action that was checked through the autonomy framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActionLog {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub action: ActionCategory,
    pub description: String,
    pub autonomy_level: AutonomyLevel,
    pub permission_result: String,
    pub executed: bool,
    pub user_response: Option<String>,
    pub outcome: Option<String>,
    pub revertible: bool,
    pub reverted: bool,
    pub server: Option<String>,
}

// ---------------------------------------------------------------------------
// Escalation record
// ---------------------------------------------------------------------------

/// Record of an autonomy-level change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRecord {
    pub timestamp: DateTime<Utc>,
    pub from_level: AutonomyLevel,
    pub to_level: AutonomyLevel,
    pub reason: String,
    pub auto: bool,
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Summary statistics for the autonomy framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyStats {
    pub global_level: AutonomyLevel,
    pub server_override_count: usize,
    pub total_actions: usize,
    pub actions_approved: usize,
    pub actions_denied: usize,
    pub actions_suggested: usize,
    pub lockdown_active: bool,
    pub days_since_install: i64,
}

// ---------------------------------------------------------------------------
// Autonomy Framework
// ---------------------------------------------------------------------------

/// Central permission authority governing agent autonomy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyFramework {
    global_level: AutonomyLevel,
    server_overrides: HashMap<String, AutonomyLevel>,
    action_permissions: HashMap<ActionCategory, AutonomyLevel>,
    escalation_history: Vec<EscalationRecord>,
    lockdown_active: bool,
    action_log: Vec<AgentActionLog>,
    install_date: DateTime<Utc>,
    suggestions_approved: u32,
    suggestions_total: u32,
    countdown_cancellations: u32,
    days_at_current_level: u32,
}

impl Default for AutonomyFramework {
    fn default() -> Self {
        Self {
            global_level: AutonomyLevel::L0ObserveOnly,
            server_overrides: HashMap::new(),
            action_permissions: HashMap::new(),
            escalation_history: Vec::new(),
            lockdown_active: false,
            action_log: Vec::new(),
            install_date: Utc::now(),
            suggestions_approved: 0,
            suggestions_total: 0,
            countdown_cancellations: 0,
            days_at_current_level: 0,
        }
    }
}

impl AutonomyFramework {
    /// Create a new framework at the given level.
    pub fn new(level: AutonomyLevel) -> Self {
        Self {
            global_level: level,
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------------
    // Level accessors
    // -----------------------------------------------------------------------

    /// Returns the current global autonomy level.
    pub fn global_level(&self) -> AutonomyLevel {
        self.global_level
    }

    /// Returns the effective autonomy level for a given server context.
    /// If a server override exists for the server it is returned, otherwise
    /// the global level is used.
    pub fn effective_level(&self, server: Option<&str>) -> AutonomyLevel {
        if let Some(srv) = server {
            if let Some(&lvl) = self.server_overrides.get(srv) {
                return lvl;
            }
        }
        self.global_level
    }

    /// Set the global autonomy level. Records an escalation record.
    pub fn set_level(&mut self, level: AutonomyLevel) {
        if level != self.global_level {
            let record = EscalationRecord {
                timestamp: Utc::now(),
                from_level: self.global_level,
                to_level: level,
                reason: format!("Global level changed from {} to {}", self.global_level, level),
                auto: false,
            };
            info!(
                from = %self.global_level,
                to = %level,
                "Autonomy level changed"
            );
            self.escalation_history.push(record);
            self.global_level = level;
            self.days_at_current_level = 0;
        }
    }

    /// Set an autonomy level override for a specific server.
    pub fn set_server_override(&mut self, server: impl Into<String>, level: AutonomyLevel) {
        let server = server.into();
        info!(server = %server, level = %level, "Server override set");
        self.server_overrides.insert(server, level);
    }

    /// Clear a server-specific override.
    pub fn clear_server_override(&mut self, server: &str) {
        self.server_overrides.remove(server);
    }

    /// Return the server overrides map.
    pub fn server_overrides(&self) -> &HashMap<String, AutonomyLevel> {
        &self.server_overrides
    }

    // -----------------------------------------------------------------------
    // Permission checks
    // -----------------------------------------------------------------------

    /// Check whether an action is permitted under the current framework state.
    pub fn request_permission(&self, action: &AgentAction) -> PermissionResult {
        // Lockdown overrides everything
        if self.lockdown_active {
            return PermissionResult::Denied {
                reason: "System is in lockdown — all agent actions are denied".into(),
            };
        }

        // Actions that always require approval
        if action.category.always_requires_approval() {
            return PermissionResult::RequiresApproval {
                description: format!(
                    "{} always requires explicit approval (risk: {})",
                    action.category, action.risk
                ),
            };
        }

        let effective = self.effective_level(action.server.as_deref());
        let required = self.action_permissions
            .get(&action.category)
            .copied()
            .unwrap_or_else(|| action.category.required_level());

        if effective >= required {
            // At L2 with medium-risk actions, use countdown instead of direct approval
            if effective == AutonomyLevel::L2ConfirmAndAct
                && action.risk == ActionRisk::Medium
            {
                return PermissionResult::CountdownConfirm {
                    description: format!(
                        "Medium-risk action: {} — will execute in countdown",
                        action.description
                    ),
                    countdown_secs: 10,
                };
            }
            // At L3 with medium-risk actions, also use countdown
            if effective == AutonomyLevel::L3AutoLowRisk
                && action.risk == ActionRisk::Medium
            {
                return PermissionResult::CountdownConfirm {
                    description: format!(
                        "Medium-risk action: {} — will execute in countdown",
                        action.description
                    ),
                    countdown_secs: 5,
                };
            }
            PermissionResult::Approved
        } else if effective >= AutonomyLevel::L1Suggest {
            PermissionResult::Suggest {
                description: format!(
                    "Agent suggests: {} (requires {} but current level is {})",
                    action.description, required, effective
                ),
            }
        } else {
            PermissionResult::RequiresApproval {
                description: format!(
                    "{} requires approval at {} (current: {})",
                    action.category, required, effective
                ),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Level progression
    // -----------------------------------------------------------------------

    /// Check whether the agent has met criteria for a level upgrade and return
    /// a human-readable suggestion if so.
    pub fn check_progression_suggestion(&self) -> Option<String> {
        match self.global_level {
            AutonomyLevel::L0ObserveOnly => {
                if self.days_at_current_level >= 7 {
                    Some(
                        "Agent has been at L0 for 7+ days. Consider upgrading to L1 (Suggest) \
                         to allow the agent to propose actions."
                            .into(),
                    )
                } else {
                    None
                }
            }
            AutonomyLevel::L1Suggest => {
                if self.suggestions_total >= 20 && self.approval_rate_meets_threshold(0.9) {
                    Some(format!(
                        "Agent has {}/{} suggestions approved ({:.0}% approval rate). \
                         Consider upgrading to L2 (Confirm & Act).",
                        self.suggestions_approved,
                        self.suggestions_total,
                        self.get_approval_rate() * 100.0,
                    ))
                } else {
                    None
                }
            }
            AutonomyLevel::L2ConfirmAndAct => {
                if self.days_at_current_level >= 30 && self.countdown_cancellations == 0 {
                    Some(
                        "Agent has been at L2 for 30+ days with zero countdown cancellations. \
                         Consider upgrading to L3 (Auto Low-Risk)."
                            .into(),
                    )
                } else {
                    None
                }
            }
            AutonomyLevel::L3AutoLowRisk => None,
        }
    }

    fn approval_rate_meets_threshold(&self, threshold: f64) -> bool {
        if self.suggestions_total == 0 {
            return false;
        }
        (self.suggestions_approved as f64 / self.suggestions_total as f64) >= threshold
    }

    /// Record that a suggestion was made.
    pub fn record_suggestion(&mut self, approved: bool) {
        self.suggestions_total += 1;
        if approved {
            self.suggestions_approved += 1;
        }
    }

    /// Record a countdown cancellation.
    pub fn record_countdown_cancellation(&mut self) {
        self.countdown_cancellations += 1;
    }

    /// Update the days-at-current-level counter (called by scheduler).
    pub fn update_days_at_level(&mut self, days: u32) {
        self.days_at_current_level = days;
    }

    /// Get suggestions counters.
    pub fn suggestions_approved(&self) -> u32 {
        self.suggestions_approved
    }

    pub fn suggestions_total(&self) -> u32 {
        self.suggestions_total
    }

    pub fn countdown_cancellations(&self) -> u32 {
        self.countdown_cancellations
    }

    pub fn days_at_current_level(&self) -> u32 {
        self.days_at_current_level
    }

    // -----------------------------------------------------------------------
    // Lockdown
    // -----------------------------------------------------------------------

    /// Activate lockdown — all agent actions will be denied.
    pub fn activate_lockdown(&mut self) {
        warn!("Lockdown activated — all agent actions denied");
        self.lockdown_active = true;
        self.action_log.push(AgentActionLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action: ActionCategory::ModifySystemConfig,
            description: "Lockdown activated".into(),
            autonomy_level: self.global_level,
            permission_result: "denied".into(),
            executed: false,
            user_response: None,
            outcome: Some("lockdown_activated".into()),
            revertible: true,
            reverted: false,
            server: None,
        });
    }

    /// Deactivate lockdown — restore normal permission checking.
    pub fn deactivate_lockdown(&mut self) {
        info!("Lockdown deactivated");
        self.lockdown_active = false;
        self.action_log.push(AgentActionLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action: ActionCategory::ModifySystemConfig,
            description: "Lockdown deactivated".into(),
            autonomy_level: self.global_level,
            permission_result: "approved".into(),
            executed: true,
            user_response: None,
            outcome: Some("lockdown_deactivated".into()),
            revertible: true,
            reverted: false,
            server: None,
        });
    }

    /// Whether the system is currently locked down.
    pub fn is_locked_down(&self) -> bool {
        self.lockdown_active
    }

    // -----------------------------------------------------------------------
    // Action logging
    // -----------------------------------------------------------------------

    /// Log an action and its permission result.
    pub fn log_action(
        &mut self,
        action: &AgentAction,
        result: &PermissionResult,
        executed: bool,
    ) {
        let entry = AgentActionLog {
            id: action.id,
            timestamp: Utc::now(),
            action: action.category,
            description: action.description.clone(),
            autonomy_level: self.effective_level(action.server.as_deref()),
            permission_result: result.tag().to_string(),
            executed,
            user_response: None,
            outcome: None,
            revertible: matches!(
                action.category,
                ActionCategory::UpdateNoiseFilter
                    | ActionCategory::AdjustAnomalyThreshold
                    | ActionCategory::AddPolicyRule
                    | ActionCategory::ModifyTrustLevel
                    | ActionCategory::BlockServer
                    | ActionCategory::EnableAutoBlock
            ),
            reverted: false,
            server: action.server.clone(),
        };
        self.action_log.push(entry);
    }

    /// Log a user's response to a pending action.
    pub fn log_user_response(&mut self, action_id: Uuid, response: &str) {
        if let Some(entry) = self.action_log.iter_mut().rev().find(|e| e.id == action_id) {
            entry.user_response = Some(response.to_string());
            if response == "approved" {
                entry.executed = true;
            }
        }
    }

    /// Log the outcome of an executed action.
    pub fn log_outcome(&mut self, action_id: Uuid, outcome: &str) {
        if let Some(entry) = self.action_log.iter_mut().rev().find(|e| e.id == action_id) {
            entry.outcome = Some(outcome.to_string());
        }
    }

    /// Get the most recent `count` action log entries (newest first in slice).
    pub fn get_action_log(&self, count: usize) -> &[AgentActionLog] {
        let len = self.action_log.len();
        if count >= len {
            &self.action_log
        } else {
            &self.action_log[len - count..]
        }
    }

    /// Get all action log entries for a specific server.
    pub fn get_actions_by_server(&self, server: &str) -> Vec<&AgentActionLog> {
        self.action_log
            .iter()
            .filter(|e| e.server.as_deref() == Some(server))
            .collect()
    }

    /// Get the full action log.
    pub fn action_log(&self) -> &[AgentActionLog] {
        &self.action_log
    }

    /// Get escalation history.
    pub fn escalation_history(&self) -> &[EscalationRecord] {
        &self.escalation_history
    }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------

    /// Get summary statistics for the framework.
    pub fn get_stats(&self) -> AutonomyStats {
        let days_since_install = (Utc::now() - self.install_date).num_days();
        let actions_approved = self
            .action_log
            .iter()
            .filter(|e| e.permission_result == "approved")
            .count();
        let actions_denied = self
            .action_log
            .iter()
            .filter(|e| e.permission_result == "denied")
            .count();
        let actions_suggested = self
            .action_log
            .iter()
            .filter(|e| e.permission_result == "suggest")
            .count();

        AutonomyStats {
            global_level: self.global_level,
            server_override_count: self.server_overrides.len(),
            total_actions: self.action_log.len(),
            actions_approved,
            actions_denied,
            actions_suggested,
            lockdown_active: self.lockdown_active,
            days_since_install,
        }
    }

    /// Approval rate as a fraction in [0.0, 1.0].
    pub fn get_approval_rate(&self) -> f64 {
        if self.suggestions_total == 0 {
            return 0.0;
        }
        self.suggestions_approved as f64 / self.suggestions_total as f64
    }

    // -----------------------------------------------------------------------
    // Custom action permissions
    // -----------------------------------------------------------------------

    /// Override the required autonomy level for a specific action category.
    pub fn set_action_permission(&mut self, category: ActionCategory, level: AutonomyLevel) {
        self.action_permissions.insert(category, level);
    }

    /// Clear a custom action permission override.
    pub fn clear_action_permission(&mut self, category: &ActionCategory) {
        self.action_permissions.remove(category);
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    fn state_path() -> PathBuf {
        let base = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("clawdefender");
        base.join("autonomy_state.json")
    }

    fn action_log_path() -> PathBuf {
        let base = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("clawdefender");
        base.join("agent_actions.json")
    }

    /// Save the framework state to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::state_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        info!(path = %path.display(), "Autonomy state saved");
        Ok(())
    }

    /// Load framework state from disk, returning defaults if the file
    /// does not exist.
    pub fn load() -> Result<Self> {
        let path = Self::state_path();
        if !path.exists() {
            info!("No saved autonomy state found, using defaults");
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path)?;
        let framework: Self = serde_json::from_str(&data)?;
        info!(path = %path.display(), "Autonomy state loaded");
        Ok(framework)
    }

    /// Save only the action log to disk.
    pub fn save_action_log(&self) -> Result<()> {
        let path = Self::action_log_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.action_log)?;
        std::fs::write(&path, json)?;
        info!(path = %path.display(), "Action log saved");
        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_action(category: ActionCategory) -> AgentAction {
        AgentAction::new(
            category,
            format!("Test {:?}", category),
            None,
            json!({}),
        )
    }

    fn make_action_with_server(category: ActionCategory, server: &str) -> AgentAction {
        AgentAction::new(
            category,
            format!("Test {:?} on {}", category, server),
            Some(server.to_string()),
            json!({}),
        )
    }

    // -----------------------------------------------------------------------
    // AutonomyLevel ordering
    // -----------------------------------------------------------------------

    #[test]
    fn test_level_ordering() {
        assert!(AutonomyLevel::L0ObserveOnly < AutonomyLevel::L1Suggest);
        assert!(AutonomyLevel::L1Suggest < AutonomyLevel::L2ConfirmAndAct);
        assert!(AutonomyLevel::L2ConfirmAndAct < AutonomyLevel::L3AutoLowRisk);
    }

    #[test]
    fn test_level_equality() {
        assert_eq!(AutonomyLevel::L0ObserveOnly, AutonomyLevel::L0ObserveOnly);
        assert_ne!(AutonomyLevel::L0ObserveOnly, AutonomyLevel::L1Suggest);
    }

    #[test]
    fn test_level_display() {
        assert!(AutonomyLevel::L0ObserveOnly.to_string().contains("Observe"));
        assert!(AutonomyLevel::L3AutoLowRisk.to_string().contains("Auto"));
    }

    // -----------------------------------------------------------------------
    // ActionCategory risk classification
    // -----------------------------------------------------------------------

    #[test]
    fn test_low_risk_categories() {
        assert_eq!(ActionCategory::UpdateNoiseFilter.risk_level(), ActionRisk::Low);
        assert_eq!(ActionCategory::AdjustAnomalyThreshold.risk_level(), ActionRisk::Low);
        assert_eq!(ActionCategory::UpdateKnowledgeBase.risk_level(), ActionRisk::Low);
        assert_eq!(ActionCategory::GenerateReport.risk_level(), ActionRisk::Low);
    }

    #[test]
    fn test_medium_risk_categories() {
        assert_eq!(ActionCategory::AddPolicyRule.risk_level(), ActionRisk::Medium);
        assert_eq!(ActionCategory::ModifyTrustLevel.risk_level(), ActionRisk::Medium);
        assert_eq!(ActionCategory::BlockServer.risk_level(), ActionRisk::Medium);
        assert_eq!(ActionCategory::EnableAutoBlock.risk_level(), ActionRisk::Medium);
    }

    #[test]
    fn test_high_risk_categories() {
        assert_eq!(ActionCategory::RemovePolicyRule.risk_level(), ActionRisk::High);
        assert_eq!(ActionCategory::UnwrapServer.risk_level(), ActionRisk::High);
        assert_eq!(ActionCategory::KillProcess.risk_level(), ActionRisk::High);
        assert_eq!(ActionCategory::ModifySystemConfig.risk_level(), ActionRisk::High);
    }

    #[test]
    fn test_always_requires_approval() {
        assert!(ActionCategory::DeleteData.always_requires_approval());
        assert!(ActionCategory::DisableDaemon.always_requires_approval());
        assert!(ActionCategory::ExportSensitiveData.always_requires_approval());
        assert!(!ActionCategory::GenerateReport.always_requires_approval());
        assert!(!ActionCategory::BlockServer.always_requires_approval());
        assert!(!ActionCategory::KillProcess.always_requires_approval());
    }

    #[test]
    fn test_required_level_low_risk() {
        assert_eq!(
            ActionCategory::UpdateNoiseFilter.required_level(),
            AutonomyLevel::L2ConfirmAndAct
        );
    }

    #[test]
    fn test_required_level_medium_risk() {
        assert_eq!(
            ActionCategory::AddPolicyRule.required_level(),
            AutonomyLevel::L3AutoLowRisk
        );
    }

    #[test]
    fn test_required_level_high_risk() {
        assert_eq!(
            ActionCategory::KillProcess.required_level(),
            AutonomyLevel::L3AutoLowRisk
        );
    }

    // -----------------------------------------------------------------------
    // Default framework
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_framework() {
        let fw = AutonomyFramework::default();
        assert_eq!(fw.global_level(), AutonomyLevel::L0ObserveOnly);
        assert!(!fw.is_locked_down());
        assert!(fw.server_overrides().is_empty());
        assert_eq!(fw.suggestions_total(), 0);
        assert_eq!(fw.suggestions_approved(), 0);
    }

    #[test]
    fn test_new_with_level() {
        let fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        assert_eq!(fw.global_level(), AutonomyLevel::L2ConfirmAndAct);
    }

    // -----------------------------------------------------------------------
    // Effective level
    // -----------------------------------------------------------------------

    #[test]
    fn test_effective_level_global() {
        let fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        assert_eq!(fw.effective_level(None), AutonomyLevel::L1Suggest);
        assert_eq!(
            fw.effective_level(Some("unknown.server")),
            AutonomyLevel::L1Suggest
        );
    }

    #[test]
    fn test_effective_level_server_override() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        fw.set_server_override("critical.server", AutonomyLevel::L0ObserveOnly);
        assert_eq!(
            fw.effective_level(Some("critical.server")),
            AutonomyLevel::L0ObserveOnly
        );
        assert_eq!(
            fw.effective_level(Some("other.server")),
            AutonomyLevel::L1Suggest
        );
    }

    #[test]
    fn test_clear_server_override() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        fw.set_server_override("srv", AutonomyLevel::L3AutoLowRisk);
        assert_eq!(
            fw.effective_level(Some("srv")),
            AutonomyLevel::L3AutoLowRisk
        );
        fw.clear_server_override("srv");
        assert_eq!(fw.effective_level(Some("srv")), AutonomyLevel::L1Suggest);
    }

    // -----------------------------------------------------------------------
    // Permission checks — lockdown
    // -----------------------------------------------------------------------

    #[test]
    fn test_lockdown_denies_all() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        fw.activate_lockdown();
        let action = make_action(ActionCategory::GenerateReport);
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::Denied { .. }));
    }

    #[test]
    fn test_lockdown_toggle() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        assert!(!fw.is_locked_down());
        fw.activate_lockdown();
        assert!(fw.is_locked_down());
        fw.deactivate_lockdown();
        assert!(!fw.is_locked_down());
    }

    #[test]
    fn test_lockdown_logs_entries() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        fw.activate_lockdown();
        fw.deactivate_lockdown();
        // activate + deactivate = 2 log entries
        assert_eq!(fw.action_log().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Permission checks — always requires approval
    // -----------------------------------------------------------------------

    #[test]
    fn test_always_requires_approval_at_max_level() {
        let fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        for cat in [
            ActionCategory::DeleteData,
            ActionCategory::DisableDaemon,
            ActionCategory::ExportSensitiveData,
        ] {
            let action = make_action(cat);
            let result = fw.request_permission(&action);
            assert!(
                matches!(result, PermissionResult::RequiresApproval { .. }),
                "{:?} should always require approval",
                cat
            );
        }
    }

    // -----------------------------------------------------------------------
    // Permission checks — L0 (Observe Only)
    // -----------------------------------------------------------------------

    #[test]
    fn test_l0_low_risk_requires_approval() {
        let fw = AutonomyFramework::new(AutonomyLevel::L0ObserveOnly);
        let action = make_action(ActionCategory::GenerateReport);
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::RequiresApproval { .. }));
    }

    #[test]
    fn test_l0_medium_risk_requires_approval() {
        let fw = AutonomyFramework::new(AutonomyLevel::L0ObserveOnly);
        let action = make_action(ActionCategory::BlockServer);
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::RequiresApproval { .. }));
    }

    #[test]
    fn test_l0_high_risk_requires_approval() {
        let fw = AutonomyFramework::new(AutonomyLevel::L0ObserveOnly);
        let action = make_action(ActionCategory::KillProcess);
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::RequiresApproval { .. }));
    }

    // -----------------------------------------------------------------------
    // Permission checks — L1 (Suggest)
    // -----------------------------------------------------------------------

    #[test]
    fn test_l1_low_risk_suggests() {
        let fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        let action = make_action(ActionCategory::UpdateNoiseFilter);
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::Suggest { .. }));
    }

    #[test]
    fn test_l1_medium_risk_suggests() {
        let fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        let action = make_action(ActionCategory::AddPolicyRule);
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::Suggest { .. }));
    }

    #[test]
    fn test_l1_high_risk_suggests() {
        let fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        let action = make_action(ActionCategory::KillProcess);
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::Suggest { .. }));
    }

    // -----------------------------------------------------------------------
    // Permission checks — L2 (Confirm & Act)
    // -----------------------------------------------------------------------

    #[test]
    fn test_l2_low_risk_approved() {
        let fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        let action = make_action(ActionCategory::GenerateReport);
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::Approved));
    }

    #[test]
    fn test_l2_medium_risk_countdown() {
        let fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        let action = make_action(ActionCategory::BlockServer);
        let result = fw.request_permission(&action);
        assert!(
            matches!(result, PermissionResult::Suggest { .. }),
            "L2 cannot auto-execute medium risk (needs L3), so it suggests"
        );
    }

    #[test]
    fn test_l2_high_risk_suggests() {
        let fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        let action = make_action(ActionCategory::KillProcess);
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::Suggest { .. }));
    }

    // -----------------------------------------------------------------------
    // Permission checks — L3 (Auto Low-Risk)
    // -----------------------------------------------------------------------

    #[test]
    fn test_l3_low_risk_approved() {
        let fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        let action = make_action(ActionCategory::UpdateKnowledgeBase);
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::Approved));
    }

    #[test]
    fn test_l3_medium_risk_countdown() {
        let fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        let action = make_action(ActionCategory::AddPolicyRule);
        let result = fw.request_permission(&action);
        assert!(matches!(
            result,
            PermissionResult::CountdownConfirm {
                countdown_secs: 5,
                ..
            }
        ));
    }

    #[test]
    fn test_l3_high_risk_approved() {
        let fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        let action = make_action(ActionCategory::KillProcess);
        let result = fw.request_permission(&action);
        // High risk at L3 — the required level is L3 and the effective level is L3,
        // so it's approved (not a medium-risk countdown path).
        assert!(matches!(result, PermissionResult::Approved));
    }

    // -----------------------------------------------------------------------
    // Permission checks — server override
    // -----------------------------------------------------------------------

    #[test]
    fn test_server_override_restricts() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        fw.set_server_override("locked.srv", AutonomyLevel::L0ObserveOnly);
        let action = make_action_with_server(ActionCategory::GenerateReport, "locked.srv");
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::RequiresApproval { .. }));
    }

    #[test]
    fn test_server_override_promotes() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L0ObserveOnly);
        fw.set_server_override("trusted.srv", AutonomyLevel::L2ConfirmAndAct);
        let action = make_action_with_server(ActionCategory::GenerateReport, "trusted.srv");
        let result = fw.request_permission(&action);
        assert!(matches!(result, PermissionResult::Approved));
    }

    // -----------------------------------------------------------------------
    // Set level records escalation
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_level_records_escalation() {
        let mut fw = AutonomyFramework::default();
        fw.set_level(AutonomyLevel::L1Suggest);
        assert_eq!(fw.global_level(), AutonomyLevel::L1Suggest);
        assert_eq!(fw.escalation_history().len(), 1);
        let record = &fw.escalation_history()[0];
        assert_eq!(record.from_level, AutonomyLevel::L0ObserveOnly);
        assert_eq!(record.to_level, AutonomyLevel::L1Suggest);
        assert!(!record.auto);
    }

    #[test]
    fn test_set_same_level_no_escalation() {
        let mut fw = AutonomyFramework::default();
        fw.set_level(AutonomyLevel::L0ObserveOnly);
        assert!(fw.escalation_history().is_empty());
    }

    #[test]
    fn test_set_level_resets_days() {
        let mut fw = AutonomyFramework::default();
        fw.update_days_at_level(10);
        fw.set_level(AutonomyLevel::L1Suggest);
        assert_eq!(fw.days_at_current_level(), 0);
    }

    // -----------------------------------------------------------------------
    // Level progression
    // -----------------------------------------------------------------------

    #[test]
    fn test_progression_l0_not_ready() {
        let fw = AutonomyFramework::default();
        assert!(fw.check_progression_suggestion().is_none());
    }

    #[test]
    fn test_progression_l0_ready() {
        let mut fw = AutonomyFramework::default();
        fw.update_days_at_level(7);
        let suggestion = fw.check_progression_suggestion();
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("L1"));
    }

    #[test]
    fn test_progression_l1_not_enough_suggestions() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        for _ in 0..10 {
            fw.record_suggestion(true);
        }
        assert!(fw.check_progression_suggestion().is_none());
    }

    #[test]
    fn test_progression_l1_low_approval_rate() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        for _ in 0..15 {
            fw.record_suggestion(true);
        }
        for _ in 0..5 {
            fw.record_suggestion(false);
        }
        // 15/20 = 75% < 90%
        assert!(fw.check_progression_suggestion().is_none());
    }

    #[test]
    fn test_progression_l1_ready() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        for _ in 0..18 {
            fw.record_suggestion(true);
        }
        for _ in 0..2 {
            fw.record_suggestion(false);
        }
        // 18/20 = 90%
        let suggestion = fw.check_progression_suggestion();
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("L2"));
    }

    #[test]
    fn test_progression_l2_not_enough_days() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        fw.update_days_at_level(20);
        assert!(fw.check_progression_suggestion().is_none());
    }

    #[test]
    fn test_progression_l2_has_cancellations() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        fw.update_days_at_level(30);
        fw.record_countdown_cancellation();
        assert!(fw.check_progression_suggestion().is_none());
    }

    #[test]
    fn test_progression_l2_ready() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        fw.update_days_at_level(30);
        let suggestion = fw.check_progression_suggestion();
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("L3"));
    }

    #[test]
    fn test_progression_l3_no_suggestion() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        fw.update_days_at_level(100);
        assert!(fw.check_progression_suggestion().is_none());
    }

    // -----------------------------------------------------------------------
    // Action logging
    // -----------------------------------------------------------------------

    #[test]
    fn test_log_action() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        let action = make_action(ActionCategory::GenerateReport);
        let result = fw.request_permission(&action);
        fw.log_action(&action, &result, true);
        assert_eq!(fw.action_log().len(), 1);
        assert_eq!(fw.action_log()[0].id, action.id);
        assert_eq!(fw.action_log()[0].permission_result, "approved");
        assert!(fw.action_log()[0].executed);
    }

    #[test]
    fn test_log_user_response() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        let action = make_action(ActionCategory::UpdateNoiseFilter);
        let result = fw.request_permission(&action);
        fw.log_action(&action, &result, false);
        fw.log_user_response(action.id, "approved");
        let entry = &fw.action_log()[0];
        assert_eq!(entry.user_response.as_deref(), Some("approved"));
        assert!(entry.executed);
    }

    #[test]
    fn test_log_user_response_denied() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        let action = make_action(ActionCategory::UpdateNoiseFilter);
        let result = fw.request_permission(&action);
        fw.log_action(&action, &result, false);
        fw.log_user_response(action.id, "denied");
        let entry = &fw.action_log()[0];
        assert_eq!(entry.user_response.as_deref(), Some("denied"));
        assert!(!entry.executed);
    }

    #[test]
    fn test_log_outcome() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        let action = make_action(ActionCategory::GenerateReport);
        let result = fw.request_permission(&action);
        fw.log_action(&action, &result, true);
        fw.log_outcome(action.id, "success");
        assert_eq!(fw.action_log()[0].outcome.as_deref(), Some("success"));
    }

    #[test]
    fn test_get_action_log_limit() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        for _ in 0..5 {
            let action = make_action(ActionCategory::GenerateReport);
            let result = PermissionResult::Approved;
            fw.log_action(&action, &result, true);
        }
        assert_eq!(fw.get_action_log(3).len(), 3);
        assert_eq!(fw.get_action_log(10).len(), 5);
    }

    #[test]
    fn test_get_actions_by_server() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        let a1 = make_action_with_server(ActionCategory::GenerateReport, "server-a");
        let a2 = make_action_with_server(ActionCategory::UpdateNoiseFilter, "server-b");
        let a3 = make_action_with_server(ActionCategory::AdjustAnomalyThreshold, "server-a");
        fw.log_action(&a1, &PermissionResult::Approved, true);
        fw.log_action(&a2, &PermissionResult::Approved, true);
        fw.log_action(&a3, &PermissionResult::Approved, true);
        assert_eq!(fw.get_actions_by_server("server-a").len(), 2);
        assert_eq!(fw.get_actions_by_server("server-b").len(), 1);
        assert_eq!(fw.get_actions_by_server("server-c").len(), 0);
    }

    #[test]
    fn test_action_revertible_flag() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        let a1 = make_action(ActionCategory::UpdateNoiseFilter);
        fw.log_action(&a1, &PermissionResult::Approved, true);
        assert!(fw.action_log()[0].revertible);

        let a2 = make_action(ActionCategory::KillProcess);
        fw.log_action(&a2, &PermissionResult::Approved, true);
        assert!(!fw.action_log()[1].revertible);
    }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_stats_empty() {
        let fw = AutonomyFramework::default();
        let stats = fw.get_stats();
        assert_eq!(stats.global_level, AutonomyLevel::L0ObserveOnly);
        assert_eq!(stats.server_override_count, 0);
        assert_eq!(stats.total_actions, 0);
        assert!(!stats.lockdown_active);
    }

    #[test]
    fn test_get_stats_with_data() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        fw.set_server_override("s1", AutonomyLevel::L1Suggest);
        fw.set_server_override("s2", AutonomyLevel::L0ObserveOnly);

        let a1 = make_action(ActionCategory::GenerateReport);
        fw.log_action(&a1, &PermissionResult::Approved, true);
        let a2 = make_action(ActionCategory::KillProcess);
        fw.log_action(
            &a2,
            &PermissionResult::Denied {
                reason: "test".into(),
            },
            false,
        );

        let stats = fw.get_stats();
        assert_eq!(stats.server_override_count, 2);
        assert_eq!(stats.total_actions, 2);
        assert_eq!(stats.actions_approved, 1);
        assert_eq!(stats.actions_denied, 1);
    }

    #[test]
    fn test_approval_rate() {
        let mut fw = AutonomyFramework::default();
        assert_eq!(fw.get_approval_rate(), 0.0);
        fw.record_suggestion(true);
        fw.record_suggestion(true);
        fw.record_suggestion(false);
        assert!((fw.get_approval_rate() - 2.0 / 3.0).abs() < 0.001);
    }

    // -----------------------------------------------------------------------
    // Custom action permissions
    // -----------------------------------------------------------------------

    #[test]
    fn test_custom_action_permission() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        // Default: GenerateReport requires L2
        let action = make_action(ActionCategory::GenerateReport);
        assert!(matches!(
            fw.request_permission(&action),
            PermissionResult::Suggest { .. }
        ));
        // Override to allow at L1
        fw.set_action_permission(ActionCategory::GenerateReport, AutonomyLevel::L1Suggest);
        assert!(matches!(
            fw.request_permission(&action),
            PermissionResult::Approved
        ));
    }

    #[test]
    fn test_clear_custom_action_permission() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L1Suggest);
        fw.set_action_permission(ActionCategory::GenerateReport, AutonomyLevel::L1Suggest);
        fw.clear_action_permission(&ActionCategory::GenerateReport);
        let action = make_action(ActionCategory::GenerateReport);
        assert!(matches!(
            fw.request_permission(&action),
            PermissionResult::Suggest { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // AgentAction constructor
    // -----------------------------------------------------------------------

    #[test]
    fn test_agent_action_new() {
        let action = AgentAction::new(
            ActionCategory::BlockServer,
            "Block malicious server",
            Some("evil.com".to_string()),
            json!({"ip": "1.2.3.4"}),
        );
        assert_eq!(action.category, ActionCategory::BlockServer);
        assert_eq!(action.risk, ActionRisk::Medium);
        assert_eq!(action.server.as_deref(), Some("evil.com"));
        assert_eq!(action.parameters["ip"], "1.2.3.4");
    }

    // -----------------------------------------------------------------------
    // PermissionResult tag
    // -----------------------------------------------------------------------

    #[test]
    fn test_permission_result_tags() {
        assert_eq!(PermissionResult::Approved.tag(), "approved");
        assert_eq!(
            PermissionResult::CountdownConfirm {
                description: String::new(),
                countdown_secs: 5,
            }
            .tag(),
            "countdown"
        );
        assert_eq!(
            PermissionResult::Suggest {
                description: String::new(),
            }
            .tag(),
            "suggest"
        );
        assert_eq!(
            PermissionResult::RequiresApproval {
                description: String::new(),
            }
            .tag(),
            "requires_approval"
        );
        assert_eq!(
            PermissionResult::Denied {
                reason: String::new(),
            }
            .tag(),
            "denied"
        );
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_framework_serialization_roundtrip() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        fw.set_server_override("srv", AutonomyLevel::L0ObserveOnly);
        fw.record_suggestion(true);
        fw.update_days_at_level(5);

        let json = serde_json::to_string(&fw).unwrap();
        let restored: AutonomyFramework = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.global_level(), fw.global_level());
        assert_eq!(
            restored.effective_level(Some("srv")),
            AutonomyLevel::L0ObserveOnly
        );
        assert_eq!(restored.suggestions_approved(), 1);
        assert_eq!(restored.days_at_current_level(), 5);
    }

    #[test]
    fn test_action_category_serialization() {
        let cat = ActionCategory::KillProcess;
        let json = serde_json::to_string(&cat).unwrap();
        let restored: ActionCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, cat);
    }

    #[test]
    fn test_autonomy_level_serialization() {
        let level = AutonomyLevel::L3AutoLowRisk;
        let json = serde_json::to_string(&level).unwrap();
        let restored: AutonomyLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, level);
    }

    // -----------------------------------------------------------------------
    // Persistence (file I/O)
    // -----------------------------------------------------------------------

    #[test]
    fn test_save_and_load() {
        // Use a temporary HOME to avoid clobbering real state
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("autonomy_state.json");

        let mut fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        fw.set_server_override("s1", AutonomyLevel::L1Suggest);
        fw.record_suggestion(true);

        let json = serde_json::to_string_pretty(&fw).unwrap();
        std::fs::write(&state_path, &json).unwrap();

        let data = std::fs::read_to_string(&state_path).unwrap();
        let restored: AutonomyFramework = serde_json::from_str(&data).unwrap();
        assert_eq!(restored.global_level(), AutonomyLevel::L2ConfirmAndAct);
        assert_eq!(
            restored.effective_level(Some("s1")),
            AutonomyLevel::L1Suggest
        );
        assert_eq!(restored.suggestions_approved(), 1);
    }

    #[test]
    fn test_save_action_log_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("agent_actions.json");

        let mut fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        let action = make_action(ActionCategory::GenerateReport);
        fw.log_action(&action, &PermissionResult::Approved, true);

        let json = serde_json::to_string_pretty(fw.action_log()).unwrap();
        std::fs::write(&log_path, &json).unwrap();

        let data = std::fs::read_to_string(&log_path).unwrap();
        let restored: Vec<AgentActionLog> = serde_json::from_str(&data).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].id, action.id);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_lockdown_then_deactivate_resumes_permissions() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L3AutoLowRisk);
        fw.activate_lockdown();
        let action = make_action(ActionCategory::GenerateReport);
        assert!(matches!(
            fw.request_permission(&action),
            PermissionResult::Denied { .. }
        ));
        fw.deactivate_lockdown();
        assert!(matches!(
            fw.request_permission(&action),
            PermissionResult::Approved
        ));
    }

    #[test]
    fn test_multiple_escalations() {
        let mut fw = AutonomyFramework::default();
        fw.set_level(AutonomyLevel::L1Suggest);
        fw.set_level(AutonomyLevel::L2ConfirmAndAct);
        fw.set_level(AutonomyLevel::L3AutoLowRisk);
        assert_eq!(fw.escalation_history().len(), 3);
        assert_eq!(
            fw.escalation_history()[0].to_level,
            AutonomyLevel::L1Suggest
        );
        assert_eq!(
            fw.escalation_history()[2].to_level,
            AutonomyLevel::L3AutoLowRisk
        );
    }

    #[test]
    fn test_log_nonexistent_action_id() {
        let mut fw = AutonomyFramework::default();
        let fake_id = Uuid::new_v4();
        // Should not panic
        fw.log_user_response(fake_id, "approved");
        fw.log_outcome(fake_id, "success");
    }

    #[test]
    fn test_empty_action_log_get() {
        let fw = AutonomyFramework::default();
        assert!(fw.get_action_log(10).is_empty());
        assert!(fw.get_actions_by_server("any").is_empty());
    }

    #[test]
    fn test_countdown_cancellation_tracking() {
        let mut fw = AutonomyFramework::new(AutonomyLevel::L2ConfirmAndAct);
        assert_eq!(fw.countdown_cancellations(), 0);
        fw.record_countdown_cancellation();
        fw.record_countdown_cancellation();
        assert_eq!(fw.countdown_cancellations(), 2);
    }
}
