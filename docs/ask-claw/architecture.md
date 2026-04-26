# Ask Claw — Architecture Document

**Version**: 1.0
**Date**: 2026-02-24
**Status**: Foundation — all agents build from this document

---

## 1. Overview

Ask Claw is a conversational interface embedded in the Rookbot Tauri desktop app. Users type natural-language questions or drag in files/URLs, and Claw responds using real data from the 82 existing Tauri commands. The design prioritizes deterministic, fast responses for common queries and reserves LLM inference for tasks that genuinely need language understanding.

### Design Principles

1. **Deterministic first**: Most queries resolve with keyword/pattern matching and template responses. No LLM round-trip for "is the daemon running?"
2. **Graceful degradation**: Every intent has a template-only fallback. If no AI model is loaded, Claw still answers every question — just without natural language polish.
3. **Security by default**: User input is sanitized before touching any LLM. The existing `sanitizer.rs` primitives (`wrap_untrusted`, canary tokens, `sanitize_untrusted_input`) are reused.
4. **Real data only**: Claw never fabricates. Every claim is backed by a Tauri command result. The LLM polishes phrasing — it does not generate facts.
5. **Claw's voice**: All responses follow the voice guide. First person, short sentences, calm authority.

---

## 2. Pipeline Architecture

```
User Input (text / drag-drop / quick action / follow-up)
     |
     v
[1] Input Preprocessor
     - Trim, normalize whitespace
     - Detect input type (text / file_path / URL / event_id)
     - Sanitize via sanitize_untrusted_input()
     |
     v
[2] Context Resolver
     - Resolve pronouns ("block it" -> last mentioned server)
     - Inject session context (current page, last viewed server/event)
     - Attach conversation history (last N turns)
     |
     v
[3] Intent Classifier (deterministic first pass)
     - Keyword/pattern matching against intent registry
     - Returns IntentClassification { intent_id, confidence, entities }
     - If confidence < threshold and LLM available: LLM-assisted classification
     - If no match at all: fallback to help.general
     |
     v
[4] Intent Router
     - Maps IntentClassification to a QueryPlan
     - QueryPlan lists 1-N Tauri commands to call with extracted parameters
     - Checks if intent requires user confirmation before execution
     |
     v
[5] Backend Query Executor
     - Executes QueryPlan by calling Tauri commands in parallel where possible
     - Collects results into QueryResult
     - Handles errors gracefully (partial results are OK)
     |
     v
[6] Response Synthesizer
     - Template-only: fills Handlebars-style template with QueryResult data
     - Template+LLM: generates template response, then asks LLM to humanize
     - LLM-required: sends full context to LLM for free-form response
     - All paths produce a ConversationResponse
     |
     v
[7] Action Extractor
     - Scans response + intent for actionable suggestions
     - Produces ActionButton[] (e.g., "Block this server", "Run scan", "Go to policy editor")
     - Actions that modify state require confirmation
     |
     v
[8] Conversation UI
     - Renders message bubbles (user + Claw)
     - Shows action buttons inline
     - Handles streaming responses (typing indicator)
     - Manages conversation history in React state
```

---

## 3. Data Flow Diagram

```
                    +------------------+
                    |   React Frontend |
                    |                  |
                    |  ConversationPanel
                    |   MessageBubble  |
                    |   ActionButtons  |
                    |   InputBar       |
                    |   QuickActions   |
                    +--------+---------+
                             |
                    invoke("ask_claw")
                    invoke("ask_claw_with_file")
                    invoke("ask_claw_action")
                    invoke("get_conversation_history")
                    invoke("clear_conversation")
                             |
                    +--------v---------+
                    |  Tauri Commands   |
                    |  (commands.rs)    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  ConversationEngine
                    |  (conversation/)  |
                    |                  |
                    |  preprocessor.rs |
                    |  context.rs      |
                    |  classifier.rs   |
                    |  router.rs       |
                    |  executor.rs     |
                    |  synthesizer.rs  |
                    |  actions.rs      |
                    +--------+---------+
                             |
              +--------------+---------------+
              |              |               |
     +--------v---+  +------v------+  +------v------+
     | Existing    |  | SLM Service |  | SQLite      |
     | Tauri Cmds  |  | (optional)  |  | conversations|
     | (82 cmds)   |  | engine.rs   |  | .db         |
     +-------------+  +-------------+  +-------------+
```

---

## 4. Rust Module Structure

All new Rust code lives in a `conversation/` module under the Tauri app's `src-tauri/src/`:

```
clients/clawdefender-app/src-tauri/src/
  conversation/
    mod.rs              -- public API, ConversationEngine struct
    types.rs            -- all shared types (IntentClassification, QueryPlan, etc.)
    preprocessor.rs     -- input normalization, type detection, sanitization
    context.rs          -- ConversationContext, pronoun resolution, session state
    classifier.rs       -- IntentClassifier, keyword patterns, intent registry
    intents.rs          -- complete intent taxonomy definition
    router.rs           -- IntentRouter, maps intents to QueryPlans
    executor.rs         -- QueryExecutor, calls Tauri commands, collects results
    synthesizer.rs      -- ResponseSynthesizer, templates, optional LLM polish
    actions.rs          -- ActionExtractor, produces ActionButton list
    persistence.rs      -- SQLite storage for conversation history
```

### 4.1 Core Types (`types.rs`)

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a conversation turn.
pub type TurnId = String;

/// Unique identifier for a conversation session.
pub type SessionId = String;

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

/// The type of input the user provided.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    /// Free-form text question or command.
    Text,
    /// A file path (dragged or pasted).
    FilePath,
    /// A URL (pasted or dragged).
    Url,
    /// An event ID reference (clicked from event log).
    EventRef,
    /// A quick action button press.
    QuickAction,
    /// A follow-up action button press.
    ActionFollowUp,
}

/// Preprocessed user input ready for classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreprocessedInput {
    /// Original raw input from the user.
    pub raw: String,
    /// Sanitized and normalized text.
    pub sanitized: String,
    /// Detected input type.
    pub input_type: InputType,
    /// Extracted entities from preprocessing (file paths, URLs, server names).
    pub entities: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Intent classification
// ---------------------------------------------------------------------------

/// A classified user intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentClassification {
    /// The intent ID (e.g., "status.overall", "control.block").
    pub intent_id: String,
    /// Classification confidence from 0.0 to 1.0.
    pub confidence: f32,
    /// Extracted named entities relevant to this intent.
    pub entities: HashMap<String, String>,
    /// Whether this was classified by keyword match or LLM.
    pub method: ClassificationMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationMethod {
    /// Matched by keyword/pattern rules (fast, deterministic).
    Keyword,
    /// Classified by the SLM (slower, required for ambiguous input).
    Llm,
    /// Fallback when nothing matched.
    Fallback,
}

// ---------------------------------------------------------------------------
// Query planning and execution
// ---------------------------------------------------------------------------

/// A plan for which backend commands to call to answer the user's question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPlan {
    /// The intent this plan services.
    pub intent_id: String,
    /// Ordered list of backend queries to execute.
    pub queries: Vec<BackendQuery>,
    /// Whether this plan requires user confirmation before executing.
    pub requires_confirmation: bool,
    /// The response strategy for this intent.
    pub response_strategy: ResponseStrategy,
}

/// A single backend query — maps to one Tauri command invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendQuery {
    /// The Tauri command name to invoke (e.g., "get_daemon_status").
    pub command: String,
    /// Parameters to pass, as JSON key-value pairs.
    pub params: HashMap<String, serde_json::Value>,
    /// Human-readable label for this query (for debugging/logging).
    pub label: String,
    /// Whether this query can run in parallel with others.
    pub parallel: bool,
}

/// How the response should be generated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStrategy {
    /// Pure template — no LLM needed. Fastest.
    TemplateOnly,
    /// Template first, then LLM polishes the text. Falls back to template.
    TemplatePlusLlm,
    /// LLM generates the response from structured data. Falls back to
    /// "I need an AI model loaded to answer that in detail."
    LlmRequired,
}

/// Result of executing a QueryPlan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Results keyed by BackendQuery.command name.
    pub data: HashMap<String, serde_json::Value>,
    /// Any errors encountered (command_name -> error message).
    pub errors: HashMap<String, String>,
    /// Whether all queries succeeded.
    pub complete: bool,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A complete response from the conversation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationResponse {
    /// Unique turn ID.
    pub turn_id: TurnId,
    /// The response text in Claw's voice.
    pub message: String,
    /// Optional structured data to render (tables, lists, stats).
    pub structured_data: Option<StructuredData>,
    /// Actionable buttons the user can click.
    pub actions: Vec<ActionButton>,
    /// The intent that was matched.
    pub intent_id: String,
    /// Confidence of the intent classification.
    pub confidence: f32,
    /// How the response was generated.
    pub response_strategy: ResponseStrategy,
    /// Timestamp (ISO 8601).
    pub timestamp: String,
}

/// Structured data that the UI can render as rich content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StructuredData {
    /// A key-value status summary.
    StatusSummary {
        items: Vec<StatusItem>,
    },
    /// A list of events.
    EventList {
        events: Vec<EventSummary>,
        total: u64,
    },
    /// A list of servers.
    ServerList {
        servers: Vec<ServerSummary>,
    },
    /// A single metric with trend.
    Metric {
        label: String,
        value: String,
        trend: Option<String>,
    },
    /// A risk assessment card.
    RiskAssessment {
        subject: String,
        risk_level: String,
        explanation: String,
        factors: Vec<String>,
    },
    /// Policy rules list.
    RuleList {
        rules: Vec<RuleSummary>,
    },
    /// Scan results summary.
    ScanSummary {
        total_findings: u32,
        critical: u32,
        high: u32,
        medium: u32,
        low: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusItem {
    pub label: String,
    pub value: String,
    pub status: String, // "good", "warning", "error"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    pub id: String,
    pub timestamp: String,
    pub server_name: String,
    pub description: String,
    pub decision: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSummary {
    pub name: String,
    pub wrapped: bool,
    pub status: String,
    pub events_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSummary {
    pub name: String,
    pub action: String,
    pub resource: String,
    pub enabled: bool,
}

/// An actionable button attached to a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionButton {
    /// Unique action ID.
    pub id: String,
    /// Button label shown to user.
    pub label: String,
    /// The action to perform when clicked.
    pub action: ActionType,
    /// Visual style: "primary", "secondary", "danger".
    pub style: String,
    /// Whether clicking this action requires a confirmation dialog.
    pub requires_confirmation: bool,
}

/// What happens when the user clicks an action button.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActionType {
    /// Call a Tauri command.
    TauriCommand {
        command: String,
        params: HashMap<String, serde_json::Value>,
    },
    /// Navigate to a page in the app.
    Navigate {
        page: String,
        params: Option<HashMap<String, String>>,
    },
    /// Send a follow-up message to the conversation.
    FollowUp {
        message: String,
    },
    /// Copy text to clipboard.
    CopyToClipboard {
        text: String,
    },
}

// ---------------------------------------------------------------------------
// Conversation context
// ---------------------------------------------------------------------------

/// Session context that informs intent resolution and response generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationContext {
    /// Session ID.
    pub session_id: SessionId,
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

/// A single turn in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationTurn {
    /// Unique turn ID.
    pub turn_id: TurnId,
    /// "user" or "claw".
    pub role: String,
    /// The message text.
    pub message: String,
    /// Intent that was classified (for Claw turns).
    pub intent_id: Option<String>,
    /// Entities extracted in this turn.
    pub entities: HashMap<String, String>,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Persistence types
// ---------------------------------------------------------------------------

/// A stored conversation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConversation {
    pub session_id: SessionId,
    pub started_at: String,
    pub last_activity: String,
    pub turn_count: u32,
    pub summary: Option<String>,
}

/// A stored conversation turn (SQLite row).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTurn {
    pub turn_id: TurnId,
    pub session_id: SessionId,
    pub role: String,
    pub message: String,
    pub intent_id: Option<String>,
    pub entities_json: String,
    pub structured_data_json: Option<String>,
    pub actions_json: Option<String>,
    pub timestamp: String,
}
```

### 4.2 Conversation Engine (`mod.rs`)

```rust
use crate::conversation::types::*;
use crate::conversation::classifier::IntentClassifier;
use crate::conversation::context::ContextResolver;
use crate::conversation::executor::QueryExecutor;
use crate::conversation::preprocessor::InputPreprocessor;
use crate::conversation::router::IntentRouter;
use crate::conversation::synthesizer::ResponseSynthesizer;
use crate::conversation::actions::ActionExtractor;
use crate::conversation::persistence::ConversationStore;
use crate::state::AppState;

use std::sync::Arc;
use tokio::sync::RwLock;

/// The top-level conversation engine. One instance per app session.
pub struct ConversationEngine {
    preprocessor: InputPreprocessor,
    context: Arc<RwLock<ContextResolver>>,
    classifier: IntentClassifier,
    router: IntentRouter,
    executor: QueryExecutor,
    synthesizer: ResponseSynthesizer,
    action_extractor: ActionExtractor,
    store: ConversationStore,
}

impl ConversationEngine {
    /// Create a new engine. Called once at app startup.
    pub fn new(app_state: Arc<AppState>) -> anyhow::Result<Self> {
        let store = ConversationStore::open()?;
        Ok(Self {
            preprocessor: InputPreprocessor::new(),
            context: Arc::new(RwLock::new(ContextResolver::new())),
            classifier: IntentClassifier::new(),
            router: IntentRouter::new(),
            executor: QueryExecutor::new(app_state),
            synthesizer: ResponseSynthesizer::new(),
            action_extractor: ActionExtractor::new(),
            store,
        })
    }

    /// Process a user message and return Claw's response.
    pub async fn process_message(
        &self,
        raw_input: &str,
        input_type: InputType,
        page_context: Option<String>,
    ) -> anyhow::Result<ConversationResponse> {
        // 1. Preprocess
        let preprocessed = self.preprocessor.process(raw_input, input_type)?;

        // 2. Resolve context (pronouns, session state)
        let mut ctx = self.context.write().await;
        ctx.update_page(page_context);
        let resolved = ctx.resolve(&preprocessed);

        // 3. Classify intent
        let intent = self.classifier.classify(&resolved, ctx.history())?;

        // 4. Route to query plan
        let plan = self.router.plan(&intent)?;

        // 5. Check if confirmation needed
        if plan.requires_confirmation {
            return self.build_confirmation_response(&intent, &plan).await;
        }

        // 6. Execute backend queries
        let result = self.executor.execute(&plan).await?;

        // 7. Synthesize response
        let response = self.synthesizer.synthesize(
            &intent,
            &plan,
            &result,
        ).await?;

        // 8. Extract actions
        let actions = self.action_extractor.extract(&intent, &result);

        // 9. Build final response
        let turn_id = generate_turn_id();
        let conversation_response = ConversationResponse {
            turn_id: turn_id.clone(),
            message: response.message,
            structured_data: response.structured_data,
            actions,
            intent_id: intent.intent_id.clone(),
            confidence: intent.confidence,
            response_strategy: plan.response_strategy.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        // 10. Update context and persist
        ctx.push_user_turn(raw_input, &preprocessed.entities);
        ctx.push_claw_turn(
            &conversation_response.message,
            &intent.intent_id,
            &intent.entities,
        );
        drop(ctx);

        self.store.save_turn(&conversation_response)?;

        Ok(conversation_response)
    }

    /// Execute a follow-up action (user clicked an action button).
    pub async fn execute_action(
        &self,
        action: &ActionType,
    ) -> anyhow::Result<ConversationResponse> {
        match action {
            ActionType::TauriCommand { command, params } => {
                let result = self.executor.execute_single(command, params).await?;
                // Build a confirmation response
                Ok(ConversationResponse {
                    turn_id: generate_turn_id(),
                    message: format!("Done."),
                    structured_data: None,
                    actions: vec![],
                    intent_id: "action.executed".to_string(),
                    confidence: 1.0,
                    response_strategy: ResponseStrategy::TemplateOnly,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                })
            }
            ActionType::FollowUp { message } => {
                self.process_message(message, InputType::ActionFollowUp, None).await
            }
            _ => {
                // Navigate and CopyToClipboard are handled client-side
                anyhow::bail!("Action type handled client-side")
            }
        }
    }

    async fn build_confirmation_response(
        &self,
        intent: &IntentClassification,
        plan: &QueryPlan,
    ) -> anyhow::Result<ConversationResponse> {
        let description = self.router.describe_plan(plan);
        Ok(ConversationResponse {
            turn_id: generate_turn_id(),
            message: format!("Before I do that, let me confirm: {}. Go ahead?", description),
            structured_data: None,
            actions: vec![
                ActionButton {
                    id: "confirm".to_string(),
                    label: "Yes, go ahead".to_string(),
                    action: ActionType::FollowUp {
                        message: format!("__confirmed__:{}", intent.intent_id),
                    },
                    style: "primary".to_string(),
                    requires_confirmation: false,
                },
                ActionButton {
                    id: "cancel".to_string(),
                    label: "Cancel".to_string(),
                    action: ActionType::FollowUp {
                        message: "Never mind".to_string(),
                    },
                    style: "secondary".to_string(),
                    requires_confirmation: false,
                },
            ],
            intent_id: intent.intent_id.clone(),
            confidence: intent.confidence,
            response_strategy: ResponseStrategy::TemplateOnly,
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }
}

fn generate_turn_id() -> String {
    format!("turn-{}", uuid::Uuid::new_v4())
}
```

### 4.3 Tauri Command Interface

Five new Tauri commands expose the conversation engine:

```rust
/// Main conversational endpoint.
#[tauri::command]
pub async fn ask_claw(
    state: tauri::State<'_, AppState>,
    engine: tauri::State<'_, ConversationEngine>,
    message: String,
    page_context: Option<String>,
) -> Result<ConversationResponse, String> {
    engine.process_message(&message, InputType::Text, page_context)
        .await
        .map_err(|e| e.to_string())
}

/// File/URL analysis endpoint (drag-and-drop).
#[tauri::command]
pub async fn ask_claw_with_file(
    engine: tauri::State<'_, ConversationEngine>,
    file_path: String,
    page_context: Option<String>,
) -> Result<ConversationResponse, String> {
    let input_type = if file_path.starts_with("http://") || file_path.starts_with("https://") {
        InputType::Url
    } else {
        InputType::FilePath
    };
    engine.process_message(&file_path, input_type, page_context)
        .await
        .map_err(|e| e.to_string())
}

/// Execute an action from a response button.
#[tauri::command]
pub async fn ask_claw_action(
    engine: tauri::State<'_, ConversationEngine>,
    action_json: String,
) -> Result<ConversationResponse, String> {
    let action: ActionType = serde_json::from_str(&action_json)
        .map_err(|e| format!("Invalid action: {}", e))?;
    engine.execute_action(&action)
        .await
        .map_err(|e| e.to_string())
}

/// Get conversation history for the current session.
#[tauri::command]
pub async fn get_conversation_history(
    engine: tauri::State<'_, ConversationEngine>,
    limit: Option<u32>,
) -> Result<Vec<ConversationTurn>, String> {
    engine.store.get_recent_turns(limit.unwrap_or(50))
        .map_err(|e| e.to_string())
}

/// Clear conversation history and reset context.
#[tauri::command]
pub async fn clear_conversation(
    engine: tauri::State<'_, ConversationEngine>,
) -> Result<(), String> {
    engine.context.write().await.reset();
    engine.store.clear_session()
        .map_err(|e| e.to_string())
}
```

---

## 5. Complete Intent Taxonomy

### 5.1 Status Queries

#### `status.overall`

| Field | Value |
|-------|-------|
| Category | Status |
| Trigger phrases | "how's everything?", "what's my status?", "am I protected?", "give me a summary", "how are things looking?", "what's happening?" |
| Backend commands | `get_daemon_status`, `get_behavioral_status`, `get_recent_events` (limit=5), `get_slm_status` |
| Response strategy | Template-only |
| Requires confirmation | No |

Template:
> "{daemon_status}. {servers_count} servers monitored, {events_today} events today. {anomaly_summary}. Protection score: {score}."

#### `status.protection_score`

| Field | Value |
|-------|-------|
| Category | Status |
| Trigger phrases | "what's my protection score?", "how protected am I?", "protection level", "score", "security rating" |
| Backend commands | `get_daemon_status`, `get_behavioral_status`, `list_mcp_servers`, `get_policy` |
| Response strategy | Template+LLM |
| Requires confirmation | No |

Template:
> "Your protection score is {score}/100. {breakdown}."

#### `status.daemon`

| Field | Value |
|-------|-------|
| Category | Status |
| Trigger phrases | "is the daemon running?", "daemon status", "is Rookbot running?", "service status", "is protection active?", "are you running?" |
| Backend commands | `get_daemon_status` |
| Response strategy | Template-only |
| Requires confirmation | No |

Template (running):
> "I'm running. {events_processed} events processed, {servers_proxied} servers protected."

Template (stopped):
> "I'm not running right now. Want me to start?"

#### `status.server_specific`

| Field | Value |
|-------|-------|
| Category | Status |
| Trigger phrases | "what about {server}?", "status of {server}", "how is {server} doing?", "tell me about {server}", "is {server} safe?", "{server} status" |
| Backend commands | `list_mcp_servers`, `get_profiles`, `get_recent_events` (filtered), `check_server_reputation` |
| Response strategy | Template+LLM |
| Requires confirmation | No |
| Entities | `server_name` |

Template:
> "{server_name} is {status}. {events_count} events, {anomaly_info}. {reputation_info}."

#### `status.model`

| Field | Value |
|-------|-------|
| Category | Status |
| Trigger phrases | "what model is loaded?", "AI status", "SLM status", "is the AI model working?", "which model am I using?" |
| Backend commands | `get_slm_status`, `get_active_model` |
| Response strategy | Template-only |
| Requires confirmation | No |

Template:
> "{model_name} is loaded ({size}, {gpu_status}). {inferences} analyses so far, averaging {latency}ms."

---

### 5.2 Activity Queries

#### `activity.recent`

| Field | Value |
|-------|-------|
| Category | Activity |
| Trigger phrases | "what happened recently?", "show me recent events", "recent activity", "what's been going on?", "any activity?", "latest events" |
| Backend commands | `get_recent_events` (limit=10) |
| Response strategy | Template-only |
| Requires confirmation | No |

Template:
> "{count} recent events. {summary}."

#### `activity.time_range`

| Field | Value |
|-------|-------|
| Category | Activity |
| Trigger phrases | "what happened today?", "events this hour", "activity in the last 30 minutes", "what happened yesterday?", "show me today's events" |
| Backend commands | `get_recent_events` (filtered by time) |
| Response strategy | Template-only |
| Requires confirmation | No |
| Entities | `time_range` |

#### `activity.blocked`

| Field | Value |
|-------|-------|
| Category | Activity |
| Trigger phrases | "what did you block?", "blocked events", "show me blocks", "what was denied?", "any threats blocked?", "blocked activity" |
| Backend commands | `get_recent_events` (filtered: decision=blocked) |
| Response strategy | Template+LLM |
| Requires confirmation | No |

Template:
> "I blocked {count} events recently. {details}."

#### `activity.server`

| Field | Value |
|-------|-------|
| Category | Activity |
| Trigger phrases | "what has {server} been doing?", "activity for {server}", "events from {server}", "{server} events", "show me {server} activity" |
| Backend commands | `get_recent_events` (filtered by server), `get_profiles` |
| Response strategy | Template+LLM |
| Requires confirmation | No |
| Entities | `server_name` |

#### `activity.stats`

| Field | Value |
|-------|-------|
| Category | Activity |
| Trigger phrases | "give me stats", "event statistics", "how many events?", "event count", "activity summary", "numbers" |
| Backend commands | `get_recent_events`, `get_network_summary`, `get_behavioral_status` |
| Response strategy | Template-only |
| Requires confirmation | No |

---

### 5.3 Risk Assessment

#### `risk.file`

| Field | Value |
|-------|-------|
| Category | Risk |
| Trigger phrases | "is this file safe?", "check this file", "analyze this file", "scan this", "is this suspicious?" |
| Backend commands | `start_scan` (targeted), `get_slm_analysis_for_prompt` |
| Response strategy | LLM-required |
| Requires confirmation | No |
| Entities | `file_path` |

#### `risk.url`

| Field | Value |
|-------|-------|
| Category | Risk |
| Trigger phrases | "is this URL safe?", "check this link", "is this domain suspicious?", "analyze this URL", "should I trust this?" |
| Backend commands | `check_server_reputation`, `get_blocklist_matches` |
| Response strategy | Template+LLM |
| Requires confirmation | No |
| Entities | `url` |

#### `risk.server`

| Field | Value |
|-------|-------|
| Category | Risk |
| Trigger phrases | "is {server} safe?", "should I trust {server}?", "risk level for {server}", "how risky is {server}?", "is {server} suspicious?" |
| Backend commands | `check_server_reputation`, `get_profiles`, `get_blocklist_matches`, `get_recent_events` (filtered) |
| Response strategy | Template+LLM |
| Requires confirmation | No |
| Entities | `server_name` |

#### `risk.action`

| Field | Value |
|-------|-------|
| Category | Risk |
| Trigger phrases | "should I allow this?", "is this safe to allow?", "what happens if I allow this?", "should I block this?", "what do you recommend?" |
| Backend commands | `get_slm_analysis_for_prompt` (with pending prompt context) |
| Response strategy | LLM-required |
| Requires confirmation | No |

---

### 5.4 Control Actions

#### `control.block`

| Field | Value |
|-------|-------|
| Category | Control |
| Trigger phrases | "block {server}", "block it", "stop {server}", "deny access for {server}", "shut down {server}", "block this server" |
| Backend commands | `add_rule` (action=deny, resource=server_name) |
| Response strategy | Template-only |
| Requires confirmation | **Yes** |
| Entities | `server_name` |

Confirmation:
> "I'll add a rule to block all traffic from {server_name}. Go ahead?"

#### `control.allow`

| Field | Value |
|-------|-------|
| Category | Control |
| Trigger phrases | "allow {server}", "trust {server}", "let it through", "allow this", "unblock {server}", "permit {server}" |
| Backend commands | `add_rule` (action=allow, resource=server_name) |
| Response strategy | Template-only |
| Requires confirmation | **Yes** |
| Entities | `server_name` |

#### `control.trust_level`

| Field | Value |
|-------|-------|
| Category | Control |
| Trigger phrases | "set {server} to strict mode", "tighten security for {server}", "relax rules for {server}", "change trust level for {server}", "make {server} more restricted" |
| Backend commands | `update_rule`, `add_rule` |
| Response strategy | Template-only |
| Requires confirmation | **Yes** |
| Entities | `server_name`, `trust_level` |

#### `control.scan`

| Field | Value |
|-------|-------|
| Category | Control |
| Trigger phrases | "run a scan", "scan my system", "check for problems", "security scan", "audit my setup", "scan everything" |
| Backend commands | `start_scan` |
| Response strategy | Template-only |
| Requires confirmation | No |

Template:
> "Starting a security scan. I'll check your servers, configs, and policies. This takes about 30 seconds."

#### `control.tighten`

| Field | Value |
|-------|-------|
| Category | Control |
| Trigger phrases | "tighten security", "lock everything down", "strict mode", "maximum protection", "paranoid mode", "tighten up" |
| Backend commands | `apply_template` (template="strict") |
| Response strategy | Template-only |
| Requires confirmation | **Yes** |

Confirmation:
> "I'll switch to strict mode. This will prompt you for every tool call. Go ahead?"

#### `control.pause`

| Field | Value |
|-------|-------|
| Category | Control |
| Trigger phrases | "pause protection", "stop monitoring", "disable guards", "take a break", "pause everything", "stand down" |
| Backend commands | `stop_daemon` |
| Response strategy | Template-only |
| Requires confirmation | **Yes** |

Confirmation:
> "I'll stop monitoring. Your AI tools will run without protection. Go ahead?"

#### `control.update_threat_intel`

| Field | Value |
|-------|-------|
| Category | Control |
| Trigger phrases | "update threat intelligence", "refresh threat feed", "update blocklist", "get latest threats", "update IOCs", "refresh feeds" |
| Backend commands | `force_feed_update` |
| Response strategy | Template-only |
| Requires confirmation | No |

Template:
> "Updating threat intelligence feeds. I'll let you know when it's done."

#### `control.wrap`

| Field | Value |
|-------|-------|
| Category | Control |
| Trigger phrases | "protect {server}", "wrap {server}", "add protection to {server}", "monitor {server}", "start watching {server}" |
| Backend commands | `wrap_server` |
| Response strategy | Template-only |
| Requires confirmation | **Yes** |
| Entities | `server_name`, `client_name` |

#### `control.unwrap`

| Field | Value |
|-------|-------|
| Category | Control |
| Trigger phrases | "unprotect {server}", "unwrap {server}", "remove protection from {server}", "stop watching {server}" |
| Backend commands | `unwrap_server` |
| Response strategy | Template-only |
| Requires confirmation | **Yes** |
| Entities | `server_name`, `client_name` |

---

### 5.5 Explanation Queries

#### `explain.event`

| Field | Value |
|-------|-------|
| Category | Explanation |
| Trigger phrases | "what happened with event {id}?", "explain this event", "tell me more about this", "what does this event mean?", "break this down for me" |
| Backend commands | `get_recent_events` (filtered by id) |
| Response strategy | LLM-required |
| Requires confirmation | No |
| Entities | `event_id` |

#### `explain.concept`

| Field | Value |
|-------|-------|
| Category | Explanation |
| Trigger phrases | "what is MCP?", "explain kill chain", "what are behavioral profiles?", "what does anomaly score mean?", "how does protection work?", "what is a guard?" |
| Backend commands | None (knowledge-based) |
| Response strategy | LLM-required |
| Requires confirmation | No |
| Entities | `concept` |

#### `explain.why_blocked`

| Field | Value |
|-------|-------|
| Category | Explanation |
| Trigger phrases | "why was this blocked?", "why did you block that?", "what's wrong with this?", "why was {server} denied?", "explain the block" |
| Backend commands | `get_recent_events` (filtered), `get_policy` |
| Response strategy | Template+LLM |
| Requires confirmation | No |
| Entities | `event_id` or `server_name` |

#### `explain.recommendation`

| Field | Value |
|-------|-------|
| Category | Explanation |
| Trigger phrases | "what should I do?", "any recommendations?", "what do you suggest?", "how can I improve security?", "what's your advice?", "help me improve" |
| Backend commands | `get_daemon_status`, `get_behavioral_status`, `get_scan_results`, `get_policy`, `get_feed_status` |
| Response strategy | LLM-required |
| Requires confirmation | No |

---

### 5.6 Navigation

#### `navigate.page`

| Field | Value |
|-------|-------|
| Category | Navigation |
| Trigger phrases | "go to settings", "show me the dashboard", "open policy editor", "take me to the scanner", "show network log", "open guards page" |
| Backend commands | None |
| Response strategy | Template-only |
| Requires confirmation | No |
| Entities | `page_name` |

Page name mapping:
- "dashboard", "home", "main" -> `/`
- "settings", "config", "preferences" -> `/settings`
- "policy", "rules", "policy editor" -> `/policy`
- "scanner", "scan", "audit" -> `/scanner`
- "network", "network log", "connections" -> `/network`
- "guards", "agents" -> `/guards`
- "behavioral", "profiles", "behavior" -> `/behavioral`
- "events", "activity", "log" -> `/events`

#### `navigate.server_detail`

| Field | Value |
|-------|-------|
| Category | Navigation |
| Trigger phrases | "show me {server}", "go to {server} details", "open {server}", "view {server} profile" |
| Backend commands | None |
| Response strategy | Template-only |
| Requires confirmation | No |
| Entities | `server_name` |

---

### 5.7 Help

#### `help.general`

| Field | Value |
|-------|-------|
| Category | Help |
| Trigger phrases | "help", "what can you do?", "how does this work?", "what can I ask you?", "commands", "guide me" |
| Backend commands | None |
| Response strategy | Template-only |
| Requires confirmation | No |

Template:
> "I can help you with a few things. Ask me about your protection status, recent activity, or server risks. You can also tell me to block or allow servers, run scans, or tighten security. Try 'how's everything?' to start."

#### `help.how_to`

| Field | Value |
|-------|-------|
| Category | Help |
| Trigger phrases | "how do I block a server?", "how do I add a rule?", "how to run a scan?", "how do I change settings?", "how to update threat feeds?" |
| Backend commands | None |
| Response strategy | LLM-required |
| Requires confirmation | No |
| Entities | `topic` |

---

## 6. Response Strategy Matrix

| Intent ID | Strategy | LLM Fallback |
|-----------|----------|--------------|
| status.overall | Template-only | N/A |
| status.protection_score | Template+LLM | Template with raw data |
| status.daemon | Template-only | N/A |
| status.server_specific | Template+LLM | Template with raw data |
| status.model | Template-only | N/A |
| activity.recent | Template-only | N/A |
| activity.time_range | Template-only | N/A |
| activity.blocked | Template+LLM | Template with count + list |
| activity.server | Template+LLM | Template with raw events |
| activity.stats | Template-only | N/A |
| risk.file | LLM-required | "I need an AI model loaded to analyze files in detail. Run a scan instead?" |
| risk.url | Template+LLM | Template with blocklist match result |
| risk.server | Template+LLM | Template with reputation data |
| risk.action | LLM-required | "I need an AI model loaded to give you a detailed recommendation." |
| control.block | Template-only | N/A |
| control.allow | Template-only | N/A |
| control.trust_level | Template-only | N/A |
| control.scan | Template-only | N/A |
| control.tighten | Template-only | N/A |
| control.pause | Template-only | N/A |
| control.update_threat_intel | Template-only | N/A |
| control.wrap | Template-only | N/A |
| control.unwrap | Template-only | N/A |
| explain.event | LLM-required | "I need an AI model loaded to explain events in detail. Here are the raw details: {data}." |
| explain.concept | LLM-required | "I need an AI model loaded to explain that. Check the Rookbot documentation for now." |
| explain.why_blocked | Template+LLM | Template with matching rule + event data |
| explain.recommendation | LLM-required | "I need an AI model loaded to give personalized recommendations. In the meantime, try running a scan." |
| navigate.page | Template-only | N/A |
| navigate.server_detail | Template-only | N/A |
| help.general | Template-only | N/A |
| help.how_to | LLM-required | "I need an AI model loaded to walk you through that. Check the settings page for common tasks." |

---

## 7. Conversation State Model

### 7.1 React State (Client-Side)

```typescript
interface ConversationState {
  /** Current session ID */
  sessionId: string;
  /** Ordered list of messages in the current conversation */
  messages: ConversationMessage[];
  /** Whether Claw is currently processing a message */
  isLoading: boolean;
  /** The current page the user is viewing (for context) */
  currentPage: string;
  /** Whether the conversation panel is open */
  isOpen: boolean;
  /** Input draft text */
  draftInput: string;
}

interface ConversationMessage {
  turnId: string;
  role: 'user' | 'claw';
  message: string;
  structuredData?: StructuredData;
  actions?: ActionButton[];
  intentId?: string;
  confidence?: number;
  timestamp: string;
}
```

### 7.2 Context Resolution

The `ContextResolver` (Rust-side) maintains a sliding window of the last 10 conversation turns and performs:

1. **Pronoun resolution**: "block it" looks at the last server entity mentioned. "why?" looks at the last Claw response.
2. **Page context**: If the user is on the network log page and says "what's happening?", the intent shifts to `activity.recent` with a network filter.
3. **Entity carryover**: If the user asks "tell me about cursor-server" and then "is it safe?", "it" resolves to "cursor-server".

Resolution rules:
- "it", "this", "that" -> `last_entities["server_name"]` or `last_entities["event_id"]`
- "why?" -> reclassify as `explain.why_blocked` with last event context
- "more" / "details" -> re-query last intent with expanded data
- Unresolved pronouns: "I'm not sure what you're referring to. Can you be more specific?"

### 7.3 SQLite Persistence

Database file: `~/.clawdefender/conversations.db`

```sql
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    turn_count INTEGER DEFAULT 0,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS turns (
    turn_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL, -- 'user' or 'claw'
    message TEXT NOT NULL,
    intent_id TEXT,
    entities_json TEXT DEFAULT '{}',
    structured_data_json TEXT,
    actions_json TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX idx_turns_session ON turns(session_id, timestamp);
CREATE INDEX idx_turns_timestamp ON turns(timestamp);
```

Session lifecycle:
- New session starts on app launch or after 30 minutes of inactivity.
- Sessions older than 30 days are auto-pruned.
- Maximum 1000 turns per session.

---

## 8. TypeScript Component Structure

```
clients/clawdefender-app/src/
  components/
    conversation/
      ConversationPanel.tsx     -- Main sliding panel container
      MessageList.tsx           -- Scrollable message list
      MessageBubble.tsx         -- Single message bubble (user or Claw)
      StructuredDataCard.tsx    -- Renders StructuredData variants
      ActionButtonGroup.tsx     -- Row of action buttons
      InputBar.tsx              -- Text input + drag-drop zone
      QuickActions.tsx          -- Suggested quick action chips
      TypingIndicator.tsx       -- "Claw is thinking..." animation
      ConversationHeader.tsx    -- Panel header with clear/close
  hooks/
    useConversation.ts          -- Core conversation state + Tauri invoke calls
    useConversationShortcuts.ts -- Keyboard shortcuts (Cmd+K to open)
    useDragDrop.ts              -- Drag-and-drop file/URL detection
  types/
    conversation.ts             -- TypeScript interfaces matching Rust types
```

### 8.1 Key TypeScript Types (`types/conversation.ts`)

```typescript
export type InputType = 'text' | 'file_path' | 'url' | 'event_ref' | 'quick_action' | 'action_follow_up';

export type ResponseStrategy = 'template_only' | 'template_plus_llm' | 'llm_required';

export type ClassificationMethod = 'keyword' | 'llm' | 'fallback';

export interface ConversationResponse {
  turn_id: string;
  message: string;
  structured_data?: StructuredData;
  actions: ActionButton[];
  intent_id: string;
  confidence: number;
  response_strategy: ResponseStrategy;
  timestamp: string;
}

export interface ActionButton {
  id: string;
  label: string;
  action: ActionType;
  style: 'primary' | 'secondary' | 'danger';
  requires_confirmation: boolean;
}

export type ActionType =
  | { type: 'tauri_command'; command: string; params: Record<string, unknown> }
  | { type: 'navigate'; page: string; params?: Record<string, string> }
  | { type: 'follow_up'; message: string }
  | { type: 'copy_to_clipboard'; text: string };

export type StructuredData =
  | { type: 'status_summary'; items: StatusItem[] }
  | { type: 'event_list'; events: EventSummary[]; total: number }
  | { type: 'server_list'; servers: ServerSummary[] }
  | { type: 'metric'; label: string; value: string; trend?: string }
  | { type: 'risk_assessment'; subject: string; risk_level: string; explanation: string; factors: string[] }
  | { type: 'rule_list'; rules: RuleSummary[] }
  | { type: 'scan_summary'; total_findings: number; critical: number; high: number; medium: number; low: number };

export interface StatusItem {
  label: string;
  value: string;
  status: 'good' | 'warning' | 'error';
}

export interface EventSummary {
  id: string;
  timestamp: string;
  server_name: string;
  description: string;
  decision: string;
  risk_level: string;
}

export interface ServerSummary {
  name: string;
  wrapped: boolean;
  status: string;
  events_count: number;
}

export interface RuleSummary {
  name: string;
  action: string;
  resource: string;
  enabled: boolean;
}

export interface ConversationTurn {
  turn_id: string;
  role: 'user' | 'claw';
  message: string;
  intent_id?: string;
  entities: Record<string, string>;
  timestamp: string;
}
```

### 8.2 Hook API (`hooks/useConversation.ts`)

```typescript
export function useConversation() {
  // State
  const [messages, setMessages] = useState<ConversationMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isOpen, setIsOpen] = useState(false);

  // Send a text message
  async function sendMessage(text: string): Promise<void>;

  // Send a file/URL for analysis
  async function sendFile(filePath: string): Promise<void>;

  // Execute an action button
  async function executeAction(action: ActionType): Promise<void>;

  // Clear conversation
  async function clearConversation(): Promise<void>;

  // Toggle panel visibility
  function toggle(): void;

  // Load history on mount
  async function loadHistory(): Promise<void>;

  return {
    messages, isLoading, isOpen,
    sendMessage, sendFile, executeAction,
    clearConversation, toggle, loadHistory,
  };
}
```

---

## 9. Intent Classifier Design

### 9.1 Keyword-First Classification

The classifier uses a two-phase approach:

**Phase 1 — Deterministic keyword matching** (always runs, <1ms):

Each intent has a list of keyword patterns. The classifier scores each intent by counting matching patterns and boosts the score for exact phrase matches. The highest-scoring intent above a confidence threshold (0.6) wins.

```rust
struct IntentPattern {
    intent_id: &'static str,
    /// Exact phrases that strongly indicate this intent.
    exact_phrases: &'static [&'static str],
    /// Keywords where any 2+ present suggest this intent.
    keywords: &'static [&'static str],
    /// Regex patterns for more complex matching.
    patterns: Vec<Regex>,
    /// Entity extraction patterns (named capture groups).
    entity_patterns: Vec<Regex>,
}
```

**Phase 2 — LLM-assisted classification** (only if Phase 1 confidence < 0.6 and SLM available):

The SLM receives a structured prompt:
```
Classify this user message into one of these intents: [list].
User message: "{sanitized_input}"
Context: User is on {page}, last discussed {last_entity}.
Respond with: INTENT: <intent_id>
```

### 9.2 Entity Extraction

Entities are extracted during classification:

| Entity | Extraction method |
|--------|-------------------|
| `server_name` | Match against known server names from `list_mcp_servers` |
| `event_id` | Regex for event ID patterns (e.g., `evt-[a-f0-9]+`) |
| `file_path` | Regex for file paths starting with `/` or `~` or `./` |
| `url` | Regex for `https?://` |
| `page_name` | Match against known page name keywords |
| `time_range` | Keyword extraction: "today", "this hour", "last N minutes" |
| `concept` | Remainder after stripping "what is" / "explain" prefix |

---

## 10. Security Considerations

### 10.1 Input Sanitization

All user input passes through `sanitize_untrusted_input()` from `crates/clawdefender-slm/src/sanitizer.rs` before reaching any LLM. The existing defenses apply:

1. **Truncation**: Max 2048 bytes per message.
2. **Tag stripping**: HTML/XML tags removed.
3. **Injection pattern filtering**: "ignore previous instructions" and similar patterns stripped.
4. **Special char escaping**: Angle brackets and braces escaped.

### 10.2 LLM Prompt Construction

When the SLM is used for classification or response generation:

1. User input is wrapped with `wrap_untrusted()` (nonce-tagged delimiters).
2. System prompts include canary tokens via `build_verified_system_prompt()`.
3. SLM responses are verified with `verify_canary()`.
4. If canary verification fails, the response is discarded and the template fallback is used.

### 10.3 Action Safety

- All control actions (`control.*`) require user confirmation via action buttons.
- The confirmation dialog clearly states what will happen.
- Actions are executed through the same Tauri command paths as the rest of the app (same permission model).
- No new file system access, network access, or privilege escalation is introduced.

### 10.4 Data Handling

- Conversation history is stored locally in SQLite (`~/.clawdefender/conversations.db`).
- No conversation data is sent externally unless the user has configured a cloud LLM provider.
- When cloud LLM is used, only the sanitized query + structured data is sent — never raw event logs or file contents.

---

## 11. Error Handling

| Error condition | Behavior |
|----------------|----------|
| Daemon not running | Respond with status + offer to start daemon |
| SLM not loaded | Fall back to template-only for all intents |
| Tauri command fails | Partial results OK; report what worked + what failed |
| Intent unclear | Fall back to `help.general` with "I'm not sure what you mean. Try asking about..." |
| SQLite error | Log error; conversation works without persistence |
| Input too long | Truncate and process; no error shown to user |

---

## 12. Performance Targets

| Metric | Target |
|--------|--------|
| Template-only response | < 100ms |
| Template+LLM response | < 2s |
| LLM-required response | < 5s |
| Intent classification (keyword) | < 5ms |
| Intent classification (LLM) | < 1s |
| SQLite persist | < 10ms |
| UI render after response | < 16ms (one frame) |

---

## 13. Quick Actions

Pre-defined quick action chips shown when the conversation starts or is empty:

```typescript
const QUICK_ACTIONS = [
  { label: "How's everything?", message: "how's everything?" },
  { label: "Recent activity", message: "what happened recently?" },
  { label: "Run a scan", message: "run a scan" },
  { label: "Any threats?", message: "what did you block?" },
  { label: "Protection score", message: "what's my protection score?" },
];
```

Context-aware quick actions based on current page:

| Page | Additional quick actions |
|------|------------------------|
| Dashboard | "Any issues?", "Start daemon" (if stopped) |
| Policy Editor | "Tighten security", "Explain this rule" |
| Scanner | "Run a scan", "Any critical findings?" |
| Network Log | "Suspicious connections?", "Top destinations" |
| Behavioral | "Any anomalies?", "Learning progress" |
| Settings | "Export settings", "Check system health" |
