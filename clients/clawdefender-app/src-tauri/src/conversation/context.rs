use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Session context that informs intent resolution and response generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationContext {
    /// Session ID.
    pub session_id: String,
    /// Last N conversation turns (for pronoun resolution and follow-ups).
    pub history: Vec<ConversationTurn>,
    /// The page the user is currently viewing.
    pub current_page: Option<String>,
    /// The last server the user interacted with or viewed.
    pub last_server: Option<String>,
    /// The last event the user viewed.
    pub last_event: Option<String>,
    /// Entities from the most recent turn (for "it", "that", etc.).
    pub last_entities: HashMap<String, String>,
}

/// Role of a conversation participant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Claw,
}

/// A single turn in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationTurn {
    /// "user" or "claw".
    pub role: Role,
    /// The message text.
    pub content: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Intent that was classified (for Claw turns).
    pub intent_id: Option<String>,
    /// Entities extracted in this turn.
    pub entities: HashMap<String, String>,
}

/// Maximum number of turns to keep in the sliding window.
const MAX_HISTORY: usize = 10;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl ConversationContext {
    /// Create a new, empty conversation context.
    pub fn new(session_id: String) -> Self {
        Self {
            session_id,
            history: Vec::new(),
            current_page: None,
            last_server: None,
            last_event: None,
            last_entities: HashMap::new(),
        }
    }

    /// Add a user turn to the conversation history.
    pub fn add_turn(
        &mut self,
        role: Role,
        content: &str,
        intent_id: Option<String>,
        entities: HashMap<String, String>,
    ) {
        let turn = ConversationTurn {
            role,
            content: content.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            intent_id,
            entities: entities.clone(),
        };

        self.history.push(turn);

        // Enforce sliding window
        if self.history.len() > MAX_HISTORY {
            let excess = self.history.len() - MAX_HISTORY;
            self.history.drain(..excess);
        }

        // Update last_entities from the most recent entities
        self.update_last_entities(&entities);
    }

    /// Update tracked entities from a new classification.
    pub fn update_from_classification(&mut self, entities: &HashMap<String, String>) {
        self.update_last_entities(entities);
    }

    /// Resolve an entity reference, handling pronouns and implicit references.
    ///
    /// If the key exists in the provided entities, returns it directly.
    /// Otherwise, looks up the most recent value from conversation history.
    pub fn resolve_entity(&self, key: &str, provided: &HashMap<String, String>) -> Option<String> {
        // Direct reference takes priority
        if let Some(value) = provided.get(key) {
            return Some(value.clone());
        }

        // Check last_entities
        if let Some(value) = self.last_entities.get(key) {
            return Some(value.clone());
        }

        // Walk history backwards for the entity
        for turn in self.history.iter().rev() {
            if let Some(value) = turn.entities.get(key) {
                return Some(value.clone());
            }
        }

        None
    }

    /// Resolve pronouns ("it", "this", "that") to their referents.
    ///
    /// Returns a new entities map with pronouns replaced by their resolved values.
    pub fn resolve_pronouns(
        &self,
        message: &str,
        entities: &HashMap<String, String>,
    ) -> HashMap<String, String> {
        let mut resolved = entities.clone();
        let lower = message.to_lowercase();

        let has_pronoun = lower.contains(" it")
            || lower.starts_with("it ")
            || lower.contains(" this")
            || lower.starts_with("this ")
            || lower.contains(" that")
            || lower.starts_with("that ");

        if has_pronoun && !resolved.contains_key("server_name") {
            // Try to resolve "it"/"this"/"that" to a server name
            if let Some(server) = self.resolve_entity("server_name", &HashMap::new()) {
                resolved.insert("server_name".to_string(), server);
            }
        }

        resolved
    }

    /// Check if the message is a follow-up question that needs context expansion.
    ///
    /// Returns the type of follow-up: "why", "more", or None.
    pub fn detect_follow_up(&self, message: &str) -> Option<&'static str> {
        let lower = message.to_lowercase().trim().to_string();

        // "Why?" follow-ups
        if lower == "why"
            || lower == "why?"
            || lower.starts_with("why did")
            || lower.starts_with("why was")
        {
            return Some("why");
        }

        // "Tell me more" follow-ups
        if lower == "more"
            || lower == "details"
            || lower == "tell me more"
            || lower == "go on"
            || lower == "expand"
            || lower.starts_with("more about")
            || lower.starts_with("tell me more")
        {
            return Some("more");
        }

        None
    }

    /// Get the last intent from conversation history.
    pub fn last_intent(&self) -> Option<&str> {
        self.history
            .iter()
            .rev()
            .find_map(|turn| turn.intent_id.as_deref())
    }

    /// Reset the conversation context (clear history and state).
    pub fn reset(&mut self) {
        self.history.clear();
        self.last_server = None;
        self.last_event = None;
        self.last_entities.clear();
    }

    /// Update tracked entities from new extraction results.
    fn update_last_entities(&mut self, entities: &HashMap<String, String>) {
        // Update last_server if a new server was mentioned
        if let Some(server) = entities.get("server_name") {
            self.last_server = Some(server.clone());
        }

        // Update last_event if an event was mentioned
        if let Some(event) = entities.get("event_id") {
            self.last_event = Some(event.clone());
        }

        // Merge all entities into last_entities
        for (key, value) in entities {
            self.last_entities.insert(key.clone(), value.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> ConversationContext {
        ConversationContext::new("test-session".to_string())
    }

    fn entities_with(key: &str, value: &str) -> HashMap<String, String> {
        let mut e = HashMap::new();
        e.insert(key.to_string(), value.to_string());
        e
    }

    // -----------------------------------------------------------------------
    // Basic context operations
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_context() {
        let ctx = make_context();
        assert_eq!(ctx.session_id, "test-session");
        assert!(ctx.history.is_empty());
        assert!(ctx.last_server.is_none());
        assert!(ctx.last_event.is_none());
    }

    #[test]
    fn test_add_turn() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::User,
            "Block cursor-server",
            None,
            entities_with("server_name", "cursor-server"),
        );
        assert_eq!(ctx.history.len(), 1);
        assert_eq!(ctx.history[0].content, "Block cursor-server");
        assert_eq!(ctx.last_server, Some("cursor-server".to_string()));
    }

    #[test]
    fn test_history_sliding_window() {
        let mut ctx = make_context();
        for i in 0..15 {
            ctx.add_turn(
                Role::User,
                &format!("message {}", i),
                None,
                HashMap::new(),
            );
        }
        assert_eq!(ctx.history.len(), MAX_HISTORY);
        assert_eq!(ctx.history[0].content, "message 5");
        assert_eq!(ctx.history[9].content, "message 14");
    }

    #[test]
    fn test_reset() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::User,
            "Block cursor-server",
            None,
            entities_with("server_name", "cursor-server"),
        );
        ctx.reset();
        assert!(ctx.history.is_empty());
        assert!(ctx.last_server.is_none());
        assert!(ctx.last_entities.is_empty());
    }

    // -----------------------------------------------------------------------
    // Entity resolution
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_entity_direct() {
        let ctx = make_context();
        let provided = entities_with("server_name", "cursor-server");
        assert_eq!(
            ctx.resolve_entity("server_name", &provided),
            Some("cursor-server".to_string())
        );
    }

    #[test]
    fn test_resolve_entity_from_last() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::User,
            "Check cursor-server",
            None,
            entities_with("server_name", "cursor-server"),
        );
        assert_eq!(
            ctx.resolve_entity("server_name", &HashMap::new()),
            Some("cursor-server".to_string())
        );
    }

    #[test]
    fn test_resolve_entity_from_history() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::User,
            "Check cursor-server",
            None,
            entities_with("server_name", "cursor-server"),
        );
        // Add a turn without a server_name
        ctx.add_turn(Role::User, "What else?", None, HashMap::new());
        // Should still find cursor-server from the earlier turn
        assert_eq!(
            ctx.resolve_entity("server_name", &HashMap::new()),
            Some("cursor-server".to_string())
        );
    }

    #[test]
    fn test_resolve_entity_missing() {
        let ctx = make_context();
        assert_eq!(ctx.resolve_entity("server_name", &HashMap::new()), None);
    }

    // -----------------------------------------------------------------------
    // Pronoun resolution
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_it_to_server() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::User,
            "Check cursor-server",
            None,
            entities_with("server_name", "cursor-server"),
        );
        let resolved = ctx.resolve_pronouns("block it", &HashMap::new());
        assert_eq!(
            resolved.get("server_name").map(|s| s.as_str()),
            Some("cursor-server")
        );
    }

    #[test]
    fn test_resolve_this_to_server() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::User,
            "Check filesystem-server",
            None,
            entities_with("server_name", "filesystem-server"),
        );
        let resolved = ctx.resolve_pronouns("block this", &HashMap::new());
        assert_eq!(
            resolved.get("server_name").map(|s| s.as_str()),
            Some("filesystem-server")
        );
    }

    #[test]
    fn test_resolve_that_to_server() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::User,
            "Show me github-server",
            None,
            entities_with("server_name", "github-server"),
        );
        let resolved = ctx.resolve_pronouns("allow that", &HashMap::new());
        assert_eq!(
            resolved.get("server_name").map(|s| s.as_str()),
            Some("github-server")
        );
    }

    #[test]
    fn test_pronoun_no_resolution_when_explicit() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::User,
            "Check cursor-server",
            None,
            entities_with("server_name", "cursor-server"),
        );
        // If we already have a server_name, don't override
        let provided = entities_with("server_name", "filesystem-server");
        let resolved = ctx.resolve_pronouns("block it", &provided);
        assert_eq!(
            resolved.get("server_name").map(|s| s.as_str()),
            Some("filesystem-server")
        );
    }

    #[test]
    fn test_pronoun_no_server_in_history() {
        let ctx = make_context();
        let resolved = ctx.resolve_pronouns("block it", &HashMap::new());
        // No server to resolve to — should not have server_name
        assert!(!resolved.contains_key("server_name"));
    }

    // -----------------------------------------------------------------------
    // Follow-up detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_follow_up_why() {
        let ctx = make_context();
        assert_eq!(ctx.detect_follow_up("Why?"), Some("why"));
        assert_eq!(ctx.detect_follow_up("why"), Some("why"));
        assert_eq!(ctx.detect_follow_up("Why did you do that?"), Some("why"));
        assert_eq!(ctx.detect_follow_up("Why was this blocked?"), Some("why"));
    }

    #[test]
    fn test_follow_up_more() {
        let ctx = make_context();
        assert_eq!(ctx.detect_follow_up("Tell me more"), Some("more"));
        assert_eq!(ctx.detect_follow_up("more"), Some("more"));
        assert_eq!(ctx.detect_follow_up("details"), Some("more"));
        assert_eq!(ctx.detect_follow_up("go on"), Some("more"));
        assert_eq!(ctx.detect_follow_up("expand"), Some("more"));
    }

    #[test]
    fn test_no_follow_up() {
        let ctx = make_context();
        assert_eq!(ctx.detect_follow_up("Block cursor-server"), None);
        assert_eq!(ctx.detect_follow_up("Am I safe?"), None);
        assert_eq!(ctx.detect_follow_up("Run a scan"), None);
    }

    // -----------------------------------------------------------------------
    // Last intent tracking
    // -----------------------------------------------------------------------

    #[test]
    fn test_last_intent() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::Claw,
            "Everything looks good.",
            Some("status.overall".to_string()),
            HashMap::new(),
        );
        assert_eq!(ctx.last_intent(), Some("status.overall"));
    }

    #[test]
    fn test_last_intent_multiple_turns() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::Claw,
            "Everything looks good.",
            Some("status.overall".to_string()),
            HashMap::new(),
        );
        ctx.add_turn(Role::User, "Tell me more", None, HashMap::new());
        ctx.add_turn(
            Role::Claw,
            "Blocked 3 events.",
            Some("activity.blocked".to_string()),
            HashMap::new(),
        );
        assert_eq!(ctx.last_intent(), Some("activity.blocked"));
    }

    #[test]
    fn test_last_intent_empty() {
        let ctx = make_context();
        assert_eq!(ctx.last_intent(), None);
    }

    // -----------------------------------------------------------------------
    // update_from_classification
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_from_classification() {
        let mut ctx = make_context();
        let entities = entities_with("server_name", "cursor-server");
        ctx.update_from_classification(&entities);
        assert_eq!(ctx.last_server, Some("cursor-server".to_string()));
        assert_eq!(
            ctx.last_entities.get("server_name").map(|s| s.as_str()),
            Some("cursor-server")
        );
    }

    #[test]
    fn test_update_from_classification_event() {
        let mut ctx = make_context();
        let entities = entities_with("event_id", "evt-123");
        ctx.update_from_classification(&entities);
        assert_eq!(ctx.last_event, Some("evt-123".to_string()));
    }

    // -----------------------------------------------------------------------
    // Serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_serialization() {
        let mut ctx = make_context();
        ctx.add_turn(
            Role::User,
            "Block cursor-server",
            None,
            entities_with("server_name", "cursor-server"),
        );
        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: ConversationContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.session_id, "test-session");
        assert_eq!(deserialized.history.len(), 1);
        assert_eq!(deserialized.last_server, Some("cursor-server".to_string()));
    }

    #[test]
    fn test_turn_serialization() {
        let turn = ConversationTurn {
            role: Role::User,
            content: "test".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            intent_id: Some("status.overall".to_string()),
            entities: entities_with("server_name", "cursor-server"),
        };
        let json = serde_json::to_string(&turn).unwrap();
        let deserialized: ConversationTurn = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.role, Role::User);
        assert_eq!(deserialized.content, "test");
    }
}
