//! Interactive user prompt for policy decisions.
//!
//! The [`PromptResolver`] bridges the daemon (which needs a decision) and the
//! TUI (which renders the modal and captures keystrokes). It uses the shared
//! [`AppState`] to communicate: the daemon submits a prompt, the TUI renders it,
//! and the user's keystroke resolves it.

use std::time::Duration;

use anyhow::Result;

use claw_core::ipc::protocol::UserDecision;

use crate::{PromptRequest, SharedState};

/// Handles submitting prompts to the TUI and waiting for user responses.
pub struct PromptResolver {
    state: SharedState,
}

impl PromptResolver {
    /// Create a new resolver backed by the given shared state.
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }

    /// Submit a prompt for the user to decide on.
    ///
    /// Returns an error if a prompt is already pending.
    pub fn submit_prompt(&self, request: PromptRequest) -> Result<()> {
        let mut s = self
            .state
            .write()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        if s.pending_prompt.is_some() {
            anyhow::bail!("a prompt is already pending");
        }

        s.prompt_decision = None;
        s.pending_prompt = Some(request);
        Ok(())
    }

    /// Poll for a user decision, blocking up to `timeout`.
    ///
    /// Returns `None` if the timeout expires without a decision.
    pub fn wait_for_response(&self, timeout: Duration) -> Result<Option<UserDecision>> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(50);

        while start.elapsed() < timeout {
            {
                let s = self
                    .state
                    .read()
                    .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

                if let Some(decision) = s.prompt_decision {
                    return Ok(Some(decision));
                }

                // If the TUI shut down, bail out.
                if !s.running {
                    anyhow::bail!("TUI is no longer running");
                }
            }
            std::thread::sleep(poll_interval);
        }

        Ok(None)
    }

    /// Consume and return the pending decision, if any.
    pub fn take_decision(&self) -> Result<Option<UserDecision>> {
        let mut s = self
            .state
            .write()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
        Ok(s.prompt_decision.take())
    }

    /// Check whether a prompt is currently pending.
    pub fn is_pending(&self) -> bool {
        self.state
            .read()
            .map(|s| s.pending_prompt.is_some())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};

    use crate::AppState;

    fn make_state() -> SharedState {
        Arc::new(RwLock::new(AppState::default()))
    }

    #[test]
    fn test_submit_prompt() {
        let state = make_state();
        let resolver = PromptResolver::new(state.clone());

        let req = PromptRequest {
            id: "p1".to_string(),
            message: "Allow shell exec?".to_string(),
            event_summary: "bash -c 'curl ...'".to_string(),
            rule_name: "prompt_shell".to_string(),
            options: vec!["Allow Once".to_string(), "Deny Once".to_string()],
        };

        resolver.submit_prompt(req).unwrap();
        assert!(resolver.is_pending());
    }

    #[test]
    fn test_submit_while_pending_fails() {
        let state = make_state();
        let resolver = PromptResolver::new(state.clone());

        let req1 = PromptRequest {
            id: "p1".to_string(),
            message: "first".to_string(),
            event_summary: "e1".to_string(),
            rule_name: "r1".to_string(),
            options: vec![],
        };
        let req2 = PromptRequest {
            id: "p2".to_string(),
            message: "second".to_string(),
            event_summary: "e2".to_string(),
            rule_name: "r2".to_string(),
            options: vec![],
        };

        resolver.submit_prompt(req1).unwrap();
        assert!(resolver.submit_prompt(req2).is_err());
    }

    #[test]
    fn test_take_decision() {
        let state = make_state();
        let resolver = PromptResolver::new(state.clone());

        // No decision yet.
        assert_eq!(resolver.take_decision().unwrap(), None);

        // Simulate the TUI resolving a prompt.
        {
            let mut s = state.write().unwrap();
            s.prompt_decision = Some(UserDecision::AllowOnce);
        }

        assert_eq!(
            resolver.take_decision().unwrap(),
            Some(UserDecision::AllowOnce)
        );

        // Decision is consumed.
        assert_eq!(resolver.take_decision().unwrap(), None);
    }

    #[test]
    fn test_wait_timeout() {
        let state = make_state();
        let resolver = PromptResolver::new(state);

        let result = resolver
            .wait_for_response(Duration::from_millis(100))
            .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_wait_resolves() {
        let state = make_state();
        let resolver = PromptResolver::new(state.clone());

        // Spawn a thread that resolves the prompt after a short delay.
        let s = state.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let mut st = s.write().unwrap();
            st.pending_prompt = None;
            st.prompt_decision = Some(UserDecision::DenySession);
        });

        let result = resolver
            .wait_for_response(Duration::from_secs(2))
            .unwrap();
        assert_eq!(result, Some(UserDecision::DenySession));
    }
}
