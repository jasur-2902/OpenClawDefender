//! Prompt types and channel helpers for the TUI prompt system.
//!
//! [`PendingPrompt`] carries a oneshot sender so the proxy/daemon can `await`
//! the user's decision without polling shared state.

use std::time::Duration;

use claw_core::ipc::protocol::UserDecision;

/// A prompt awaiting user approval in the TUI.
pub struct PendingPrompt {
    /// Unique identifier for this prompt.
    pub id: String,
    /// Name of the MCP server that originated the request.
    pub server_name: String,
    /// MCP method (e.g. `tools/call`, `resources/read`).
    pub method: String,
    /// Tool name, if the method is `tools/call`.
    pub tool_name: Option<String>,
    /// Full arguments of the request.
    pub arguments: serde_json::Value,
    /// Name of the policy rule that triggered the prompt.
    pub policy_rule: String,
    /// Human-readable message from the policy rule.
    pub policy_message: String,
    /// When the prompt was received.
    pub received_at: std::time::Instant,
    /// How long before auto-deny.
    pub timeout: Duration,
    /// Channel to send the user's decision back to the caller.
    pub response_tx: Option<tokio::sync::oneshot::Sender<UserDecision>>,
}

impl PendingPrompt {
    /// Seconds remaining before this prompt times out.
    pub fn seconds_remaining(&self) -> u64 {
        self.timeout
            .checked_sub(self.received_at.elapsed())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Whether this prompt has exceeded its timeout.
    pub fn is_expired(&self) -> bool {
        self.received_at.elapsed() >= self.timeout
    }

    /// Resolve this prompt by sending the decision through the oneshot channel.
    /// Returns `true` if the decision was sent successfully.
    pub fn resolve(&mut self, decision: UserDecision) -> bool {
        if let Some(tx) = self.response_tx.take() {
            tx.send(decision).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prompt(timeout: Duration) -> PendingPrompt {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        PendingPrompt {
            id: "test-1".to_string(),
            server_name: "fs-server".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("run_command".to_string()),
            arguments: serde_json::json!({"command": "ls"}),
            policy_rule: "prompt_shell".to_string(),
            policy_message: "Shell execution requires approval".to_string(),
            received_at: std::time::Instant::now(),
            timeout,
            response_tx: Some(tx),
        }
    }

    #[test]
    fn test_seconds_remaining() {
        let prompt = make_prompt(Duration::from_secs(30));
        assert!(prompt.seconds_remaining() <= 30);
        assert!(prompt.seconds_remaining() >= 28); // allow some slack
    }

    #[test]
    fn test_is_expired_false() {
        let prompt = make_prompt(Duration::from_secs(30));
        assert!(!prompt.is_expired());
    }

    #[test]
    fn test_is_expired_true() {
        let prompt = make_prompt(Duration::from_millis(0));
        assert!(prompt.is_expired());
    }

    #[test]
    fn test_resolve_sends_decision() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut prompt = PendingPrompt {
            id: "t".to_string(),
            server_name: "s".to_string(),
            method: "m".to_string(),
            tool_name: None,
            arguments: serde_json::Value::Null,
            policy_rule: "r".to_string(),
            policy_message: "msg".to_string(),
            received_at: std::time::Instant::now(),
            timeout: Duration::from_secs(30),
            response_tx: Some(tx),
        };

        assert!(prompt.resolve(UserDecision::AllowOnce));
        assert_eq!(rx.blocking_recv().unwrap(), UserDecision::AllowOnce);
    }

    #[test]
    fn test_resolve_twice_returns_false() {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let mut prompt = PendingPrompt {
            id: "t".to_string(),
            server_name: "s".to_string(),
            method: "m".to_string(),
            tool_name: None,
            arguments: serde_json::Value::Null,
            policy_rule: "r".to_string(),
            policy_message: "msg".to_string(),
            received_at: std::time::Instant::now(),
            timeout: Duration::from_secs(30),
            response_tx: Some(tx),
        };

        assert!(prompt.resolve(UserDecision::DenyOnce));
        // Second resolve should fail — tx already consumed
        assert!(!prompt.resolve(UserDecision::DenyOnce));
    }
}
