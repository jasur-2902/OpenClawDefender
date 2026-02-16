//! Policy engine types and traits.
//!
//! Policies are the rules that ClawDefender enforces. Each incoming event is evaluated
//! against the active policy set to produce an action: allow, block, prompt the
//! user, or just log.

pub mod engine;
pub mod matcher;
pub mod rule;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::event::Event;

/// Action the policy engine decides to take for a given event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Allow the operation to proceed.
    Allow,
    /// Block the operation.
    Block,
    /// Ask the user to decide; includes a prompt message.
    Prompt(String),
    /// Allow but log for auditing.
    Log,
}

/// Result of a policy rule matching an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMatch {
    /// Name of the rule that matched.
    pub rule_name: String,
    /// Action dictated by the rule.
    pub action: PolicyAction,
    /// Human-readable explanation.
    pub message: String,
    /// Which field or aspect of the event triggered the match.
    pub matched_field: String,
}

/// A single policy rule combining criteria with an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique name for this rule.
    pub name: String,
    /// Human-readable description of what this rule does.
    pub description: String,
    /// Criteria that determine whether this rule matches an event.
    pub match_criteria: MatchCriteria,
    /// Action to take when this rule matches.
    pub action: PolicyAction,
    /// Message shown to the user or written to the audit log.
    pub message: String,
    /// Priority -- lower numbers are evaluated first.
    pub priority: u32,
}

/// Criteria for matching events against a policy rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchCriteria {
    /// Match events involving these tool names (glob patterns supported).
    pub tool_names: Option<Vec<String>>,
    /// Match events accessing these resource paths (glob patterns supported).
    pub resource_paths: Option<Vec<String>>,
    /// Match events for these MCP methods.
    pub methods: Option<Vec<String>>,
    /// Match events of these types (e.g. `"exec"`, `"connect"`).
    pub event_types: Option<Vec<String>>,
    /// If true, match any event regardless of other criteria.
    pub any: bool,
}

/// Trait for objects that can test whether they match an event.
pub trait Matcher: Send + Sync {
    /// Returns `true` if this matcher matches the given event.
    fn matches(&self, event: &dyn Event) -> bool;

    /// Human-readable description of what this matcher looks for.
    fn description(&self) -> &str;
}

/// Trait for the policy engine that evaluates events against rules.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate an event and return the action to take.
    fn evaluate(&self, event: &dyn Event) -> PolicyAction;

    /// Reload rules from the on-disk policy file.
    fn reload(&mut self) -> Result<()>;

    /// Add a rule that lasts for the current session only.
    fn add_session_rule(&mut self, rule: PolicyRule);

    /// Add a rule that persists across sessions (written to disk).
    fn add_permanent_rule(&mut self, rule: PolicyRule) -> Result<()>;
}
