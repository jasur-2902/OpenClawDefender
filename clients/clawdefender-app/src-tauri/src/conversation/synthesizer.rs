//! Response Synthesizer for Ask Claw.
//!
//! Takes a QueryResult + IntentClassification + ConversationContext and
//! produces a ConversationResponse following Claw's voice guide.
//!
//! Three response strategies:
//! - TemplateOnly:    fast, deterministic, no LLM round-trip
//! - TemplatePlusLlm: template assembles data, LLM humanizes
//! - LlmRequired:     full LLM response; falls back to template if unavailable

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::context::ConversationContext;
use super::formatter;
use super::intent::IntentClassification;
use super::templates;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// How the response was generated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStrategy {
    TemplateOnly,
    TemplatePlusLlm,
    LlmRequired,
    Fallback,
}

/// Structured data the UI can render as rich content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StructuredData {
    EventList {
        events: Vec<serde_json::Value>,
        total: u64,
    },
    ServerCard(serde_json::Value),
    StatsSummary(serde_json::Value),
    ProtectionScore(serde_json::Value),
}

/// An actionable button attached to a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionButton {
    pub id: String,
    pub label: String,
    pub action_type: ActionType,
    pub data: Option<serde_json::Value>,
    pub style: String,
}

/// What happens when the user clicks an action button.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Navigate,
    Confirm,
    Dismiss,
    Command,
}

/// The complete response from the synthesizer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationResponse {
    pub turn_id: String,
    pub message: String,
    pub structured_data: Option<StructuredData>,
    pub actions: Vec<ActionButton>,
    pub intent_id: String,
    pub confidence: f32,
    pub response_strategy: ResponseStrategy,
    pub suggestions: Vec<String>,
    pub requires_confirmation: bool,
    pub confirmation_preview: Option<String>,
    pub timestamp: String,
}

/// Result of executing a query plan — data keyed by command name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub data: HashMap<String, serde_json::Value>,
    pub errors: HashMap<String, String>,
    pub complete: bool,
}

// ---------------------------------------------------------------------------
// ResponseSynthesizer
// ---------------------------------------------------------------------------

pub struct ResponseSynthesizer;

impl ResponseSynthesizer {
    pub fn new() -> Self {
        Self
    }

    /// Synthesize a response from a query result, intent, and context.
    pub fn synthesize(
        &self,
        query_result: &QueryResult,
        intent: &IntentClassification,
        _context: &ConversationContext,
        slm_available: bool,
    ) -> ConversationResponse {
        let intent_id = intent.intent_id.as_str();

        let (strategy, message, structured_data, actions, requires_confirmation, confirmation_preview) =
            match intent_id {
                // ---------------------------------------------------------
                // Status intents (TemplateOnly)
                // ---------------------------------------------------------
                "status.overall" => self.synth_status_overall(query_result),
                "status.daemon" => self.synth_status_daemon(query_result),
                "status.protection_score" => self.synth_status_protection_score(query_result),

                // ---------------------------------------------------------
                // Status intents (TemplatePlusLlm)
                // ---------------------------------------------------------
                "status.server_specific" => {
                    self.synth_status_server_specific(query_result, intent, slm_available)
                }

                // ---------------------------------------------------------
                // Activity intents (TemplateOnly)
                // ---------------------------------------------------------
                "activity.recent" => self.synth_activity_recent(query_result),
                "activity.blocked" => self.synth_activity_blocked(query_result, intent),
                "activity.stats" => self.synth_activity_stats(query_result, intent),

                // ---------------------------------------------------------
                // Control intents (TemplateOnly, confirmation)
                // ---------------------------------------------------------
                "control.block" => self.synth_control_block(intent),
                "control.scan" => self.synth_control_scan(),
                "control.pause" => self.synth_control_pause(intent),
                "control.allow" => self.synth_control_allow(intent),
                "control.start_daemon" => self.synth_control_start_daemon(),
                "control.stop_daemon" => self.synth_control_stop_daemon(),

                // ---------------------------------------------------------
                // Navigation (TemplateOnly)
                // ---------------------------------------------------------
                "navigate.page" | "navigate.dashboard" | "navigate.settings"
                | "navigate.policy" | "navigate.activity" | "navigate.alerts"
                | "navigate.guards" | "navigate.scanner" | "navigate.behavioral"
                | "navigate.network" => self.synth_navigate(intent),

                // ---------------------------------------------------------
                // Help (TemplateOnly)
                // ---------------------------------------------------------
                "help.general" => self.synth_help_general(),

                // ---------------------------------------------------------
                // Explain intents
                // ---------------------------------------------------------
                "explain.why_blocked" => {
                    self.synth_explain_why_blocked(query_result, intent, slm_available)
                }
                "explain.concept" => self.synth_explain_concept(slm_available),
                "explain.recommendation" => self.synth_explain_recommendation(slm_available),
                "explain.event" => {
                    self.synth_explain_event(query_result, intent)
                }

                // ---------------------------------------------------------
                // Risk intents
                // ---------------------------------------------------------
                "risk.server" => {
                    self.synth_risk_server(query_result, intent, slm_available)
                }

                // ---------------------------------------------------------
                // Fallback
                // ---------------------------------------------------------
                _ => self.synth_fallback(),
            };

        let suggestions = self.generate_suggestions(intent_id, intent);

        ConversationResponse {
            turn_id: generate_turn_id(),
            message,
            structured_data,
            actions,
            intent_id: intent.intent_id.clone(),
            confidence: intent.confidence,
            response_strategy: strategy,
            suggestions,
            requires_confirmation,
            confirmation_preview,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // =====================================================================
    // Status synthesizers
    // =====================================================================

    fn synth_status_overall(
        &self,
        qr: &QueryResult,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let server_count = qr
            .data
            .get("list_mcp_servers")
            .or_else(|| qr.data.get("get_behavioral_status"))
            .and_then(|v| {
                v.get("servers")
                    .and_then(|s| s.as_array())
                    .map(|a| a.len() as u64)
                    .or_else(|| v.get("server_count").and_then(|c| c.as_u64()))
            })
            .unwrap_or(0);

        let (event_count, blocked_count) = extract_event_counts(qr);

        let message = if blocked_count == 0 && event_count == 0 {
            templates::STATUS_OVERALL_CLEAR
                .replace("{server_count}", &server_count.to_string())
        } else if blocked_count == 0 {
            templates::STATUS_OVERALL_CLEAR_WITH_EVENTS
                .replace("{server_count}", &server_count.to_string())
                .replace("{event_count}", &event_count.to_string())
        } else {
            templates::STATUS_OVERALL_WATCHING
                .replace("{server_count}", &server_count.to_string())
                .replace("{event_count}", &event_count.to_string())
                .replace("{blocked_count}", &blocked_count.to_string())
        };

        (
            ResponseStrategy::TemplateOnly,
            message,
            None,
            vec![],
            false,
            None,
        )
    }

    fn synth_status_daemon(
        &self,
        qr: &QueryResult,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let daemon_data = qr.data.get("get_daemon_status");
        let running = daemon_data
            .and_then(|v| v.get("running").and_then(|r| r.as_bool()))
            .unwrap_or(false);

        if running {
            let uptime_secs = daemon_data
                .and_then(|v| v.get("uptime_seconds").and_then(|u| u.as_u64()))
                .unwrap_or(0);
            let server_count = daemon_data
                .and_then(|v| v.get("server_count").and_then(|c| c.as_u64()))
                .unwrap_or(0);

            let message = templates::STATUS_DAEMON_RUNNING
                .replace("{uptime}", &formatter::format_uptime(uptime_secs))
                .replace("{server_count}", &server_count.to_string());

            (ResponseStrategy::TemplateOnly, message, None, vec![], false, None)
        } else {
            let actions = vec![ActionButton {
                id: "start_daemon".to_string(),
                label: templates::ACTION_START_DAEMON.to_string(),
                action_type: ActionType::Command,
                data: Some(serde_json::json!({"command": "start_daemon"})),
                style: "primary".to_string(),
            }];

            (
                ResponseStrategy::TemplateOnly,
                templates::STATUS_DAEMON_STOPPED.to_string(),
                None,
                actions,
                false,
                None,
            )
        }
    }

    fn synth_status_protection_score(
        &self,
        qr: &QueryResult,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let score = extract_protection_score(qr);
        let (_label, description) = formatter::protection_score_description(score);

        let top_factor = if score < 100 {
            extract_top_factor(qr)
        } else {
            None
        };

        let message = if let Some(factor) = &top_factor {
            templates::STATUS_PROTECTION_SCORE_WITH_FACTOR
                .replace("{score}", &score.to_string())
                .replace("{description}", &description)
                .replace("{top_factor}", factor)
        } else {
            templates::STATUS_PROTECTION_SCORE
                .replace("{score}", &score.to_string())
                .replace("{description}", &description)
        };

        let structured = StructuredData::ProtectionScore(serde_json::json!({
            "score": score,
            "description": description,
            "top_factor": top_factor,
        }));

        (
            ResponseStrategy::TemplateOnly,
            message,
            Some(structured),
            vec![],
            false,
            None,
        )
    }

    fn synth_status_server_specific(
        &self,
        qr: &QueryResult,
        intent: &IntentClassification,
        _slm_available: bool,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let server_name = intent
            .entities
            .get("server_name")
            .cloned()
            .unwrap_or_else(|| "this server".to_string());

        let status = qr
            .data
            .get("list_mcp_servers")
            .and_then(|v| {
                v.as_array().and_then(|servers| {
                    servers.iter().find(|s| {
                        s.get("name")
                            .and_then(|n| n.as_str())
                            .map(|n| n.contains(&server_name))
                            .unwrap_or(false)
                    })
                })
            })
            .and_then(|s| s.get("status").and_then(|st| st.as_str()))
            .unwrap_or("unknown");

        let event_count = qr
            .data
            .get("get_recent_events")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as u64)
            .unwrap_or(0);

        let risk_summary = qr
            .data
            .get("check_server_reputation")
            .and_then(|v| v.get("summary").and_then(|s| s.as_str()))
            .unwrap_or("No reputation data available");

        let message = templates::STATUS_SERVER_SPECIFIC
            .replace("{server_name}", &server_name)
            .replace("{status}", status)
            .replace("{event_count}", &event_count.to_string())
            .replace("{risk_summary}", risk_summary);

        let structured = qr
            .data
            .get("check_server_reputation")
            .cloned()
            .map(StructuredData::ServerCard);

        (
            ResponseStrategy::TemplatePlusLlm,
            message,
            structured,
            vec![],
            false,
            None,
        )
    }

    // =====================================================================
    // Activity synthesizers
    // =====================================================================

    fn synth_activity_recent(
        &self,
        qr: &QueryResult,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let events = qr
            .data
            .get("get_recent_events")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let total = events.len() as u64;
        let structured = if !events.is_empty() {
            Some(StructuredData::EventList {
                events: events.clone(),
                total,
            })
        } else {
            None
        };

        let message = if events.is_empty() {
            "Nothing's happened yet. When your AI tools start making requests, I'll show activity here.".to_string()
        } else {
            templates::ACTIVITY_RECENT.to_string()
        };

        (ResponseStrategy::TemplateOnly, message, structured, vec![], false, None)
    }

    fn synth_activity_blocked(
        &self,
        qr: &QueryResult,
        intent: &IntentClassification,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let events = qr
            .data
            .get("get_recent_events")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let blocked: Vec<serde_json::Value> = events
            .into_iter()
            .filter(|e| {
                e.get("decision")
                    .and_then(|d| d.as_str())
                    .map(|d| d == "blocked" || d == "denied")
                    .unwrap_or(false)
            })
            .collect();

        let time_context = intent
            .entities
            .get("time_range")
            .cloned()
            .unwrap_or_else(|| "recently".to_string());

        let count = blocked.len();

        if count == 0 {
            let message = templates::ACTIVITY_BLOCKED_NONE
                .replace("{time_context}", &time_context);
            return (ResponseStrategy::TemplateOnly, message, None, vec![], false, None);
        }

        let structured = StructuredData::EventList {
            events: blocked,
            total: count as u64,
        };

        let message = templates::ACTIVITY_BLOCKED
            .replace("{count}", &count.to_string())
            .replace("{time_context}", &time_context);

        (
            ResponseStrategy::TemplateOnly,
            message,
            Some(structured),
            vec![],
            false,
            None,
        )
    }

    fn synth_activity_stats(
        &self,
        qr: &QueryResult,
        intent: &IntentClassification,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let (event_count, blocked_count) = extract_event_counts(qr);
        let allowed = event_count.saturating_sub(blocked_count);

        let time_period = intent
            .entities
            .get("time_range")
            .cloned()
            .unwrap_or_else(|| "today".to_string());

        let message = if blocked_count == 0 {
            templates::ACTIVITY_STATS_QUIET
                .replace("{total}", &event_count.to_string())
                .replace("{time_period}", &time_period)
        } else {
            let notable = format!(
                "Most common: {}",
                extract_most_common_server(qr).unwrap_or_else(|| "various servers".to_string())
            );
            templates::ACTIVITY_STATS
                .replace("{total}", &event_count.to_string())
                .replace("{time_period}", &time_period)
                .replace("{blocked}", &blocked_count.to_string())
                .replace("{allowed}", &allowed.to_string())
                .replace("{notable_summary}", &notable)
        };

        let structured = StructuredData::StatsSummary(serde_json::json!({
            "total": event_count,
            "blocked": blocked_count,
            "allowed": allowed,
            "time_period": time_period,
        }));

        (
            ResponseStrategy::TemplateOnly,
            message,
            Some(structured),
            vec![],
            false,
            None,
        )
    }

    // =====================================================================
    // Control synthesizers
    // =====================================================================

    fn synth_control_block(
        &self,
        intent: &IntentClassification,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let server = intent
            .entities
            .get("server_name")
            .cloned()
            .unwrap_or_else(|| "this server".to_string());
        let action = intent
            .entities
            .get("action")
            .cloned()
            .unwrap_or_else(|| "all actions".to_string());

        let impact = format!("This will prevent {} from performing {}", server, action);

        let message = templates::CONTROL_BLOCK_CONFIRM
            .replace("{server}", &server)
            .replace("{action}", &action)
            .replace("{impact}", &impact);

        let actions = vec![
            ActionButton {
                id: "confirm_block".to_string(),
                label: templates::ACTION_CONFIRM.to_string(),
                action_type: ActionType::Confirm,
                data: Some(serde_json::json!({
                    "server": server,
                    "action": action,
                })),
                style: "primary".to_string(),
            },
            ActionButton {
                id: "cancel_block".to_string(),
                label: templates::ACTION_CANCEL.to_string(),
                action_type: ActionType::Dismiss,
                data: None,
                style: "secondary".to_string(),
            },
        ];

        let preview = format!("Block {} from {}", server, action);

        (
            ResponseStrategy::TemplateOnly,
            message,
            None,
            actions,
            true,
            Some(preview),
        )
    }

    fn synth_control_scan(
        &self,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        (
            ResponseStrategy::TemplateOnly,
            templates::CONTROL_SCAN_START.to_string(),
            None,
            vec![ActionButton {
                id: "start_scan".to_string(),
                label: "Start Scan".to_string(),
                action_type: ActionType::Command,
                data: Some(serde_json::json!({"command": "start_scan"})),
                style: "primary".to_string(),
            }],
            false,
            None,
        )
    }

    fn synth_control_pause(
        &self,
        intent: &IntentClassification,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        // Mandatory: max 30 minutes
        let duration = intent
            .entities
            .get("duration")
            .cloned()
            .unwrap_or_else(|| "30 minutes".to_string());

        let message = templates::CONTROL_PAUSE_CONFIRM
            .replace("{duration}", &duration);

        let actions = vec![
            ActionButton {
                id: "confirm_pause".to_string(),
                label: templates::ACTION_PAUSE_CONFIRM.to_string(),
                action_type: ActionType::Confirm,
                data: Some(serde_json::json!({
                    "duration": duration,
                    "max_minutes": 30,
                })),
                style: "danger".to_string(),
            },
            ActionButton {
                id: "cancel_pause".to_string(),
                label: templates::ACTION_PAUSE_CANCEL.to_string(),
                action_type: ActionType::Dismiss,
                data: None,
                style: "primary".to_string(),
            },
        ];

        let preview = format!("Pause protection for {}", duration);

        (
            ResponseStrategy::TemplateOnly,
            message,
            None,
            actions,
            true,
            Some(preview),
        )
    }

    fn synth_control_allow(
        &self,
        intent: &IntentClassification,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let server = intent
            .entities
            .get("server_name")
            .cloned()
            .unwrap_or_else(|| "this server".to_string());
        let action = intent
            .entities
            .get("action")
            .cloned()
            .unwrap_or_else(|| "this action".to_string());

        let message = templates::CONTROL_ALLOW_CONFIRM
            .replace("{server}", &server)
            .replace("{action}", &action);

        let actions = vec![
            ActionButton {
                id: "confirm_allow".to_string(),
                label: templates::ACTION_CONFIRM.to_string(),
                action_type: ActionType::Confirm,
                data: Some(serde_json::json!({
                    "server": server,
                    "action": action,
                })),
                style: "primary".to_string(),
            },
            ActionButton {
                id: "cancel_allow".to_string(),
                label: templates::ACTION_CANCEL.to_string(),
                action_type: ActionType::Dismiss,
                data: None,
                style: "secondary".to_string(),
            },
        ];

        (
            ResponseStrategy::TemplateOnly,
            message,
            None,
            actions,
            true,
            Some(format!("Allow {} to {}", server, action)),
        )
    }

    fn synth_control_start_daemon(
        &self,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        (
            ResponseStrategy::TemplateOnly,
            templates::CONTROL_START_DAEMON.to_string(),
            None,
            vec![ActionButton {
                id: "start_daemon".to_string(),
                label: templates::ACTION_START_DAEMON.to_string(),
                action_type: ActionType::Command,
                data: Some(serde_json::json!({"command": "start_daemon"})),
                style: "primary".to_string(),
            }],
            false,
            None,
        )
    }

    fn synth_control_stop_daemon(
        &self,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        (
            ResponseStrategy::TemplateOnly,
            templates::CONTROL_STOP_DAEMON.to_string(),
            None,
            vec![],
            true,
            Some("Stop the daemon".to_string()),
        )
    }

    // =====================================================================
    // Navigation synthesizers
    // =====================================================================

    fn synth_navigate(
        &self,
        intent: &IntentClassification,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let page = intent
            .entities
            .get("page")
            .cloned()
            .or_else(|| {
                // Extract page from intent_id like "navigate.dashboard"
                intent
                    .intent_id
                    .strip_prefix("navigate.")
                    .map(|p| p.to_string())
            })
            .unwrap_or_else(|| "dashboard".to_string());

        let page_name = templates::page_display_name(&page);
        let message = templates::NAVIGATE_PAGE.replace("{page_name}", page_name);

        let actions = vec![ActionButton {
            id: format!("navigate_{}", page),
            label: format!("Go to {}", page_name),
            action_type: ActionType::Navigate,
            data: Some(serde_json::json!({"page": page})),
            style: "primary".to_string(),
        }];

        (ResponseStrategy::TemplateOnly, message, None, actions, false, None)
    }

    // =====================================================================
    // Help synthesizers
    // =====================================================================

    fn synth_help_general(
        &self,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        (
            ResponseStrategy::TemplateOnly,
            templates::HELP_GENERAL.to_string(),
            None,
            vec![],
            false,
            None,
        )
    }

    // =====================================================================
    // Explain synthesizers
    // =====================================================================

    fn synth_explain_why_blocked(
        &self,
        qr: &QueryResult,
        intent: &IntentClassification,
        _slm_available: bool,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let event = qr
            .data
            .get("get_recent_events")
            .and_then(|v| v.as_array())
            .and_then(|events| {
                let event_id = intent.entities.get("event_id");
                if let Some(eid) = event_id {
                    events
                        .iter()
                        .find(|e| {
                            e.get("id")
                                .and_then(|id| id.as_str())
                                .map(|id| id == eid.as_str())
                                .unwrap_or(false)
                        })
                        .cloned()
                } else {
                    // Find the most recent blocked event
                    events
                        .iter()
                        .find(|e| {
                            e.get("decision")
                                .and_then(|d| d.as_str())
                                .map(|d| d == "blocked" || d == "denied")
                                .unwrap_or(false)
                        })
                        .cloned()
                }
            });

        let message = if let Some(ref evt) = event {
            let reason = evt
                .get("rule_reason")
                .or_else(|| evt.get("reason"))
                .and_then(|r| r.as_str())
                .unwrap_or("it matched a security rule");
            let detail = evt
                .get("detail")
                .or_else(|| evt.get("description"))
                .and_then(|d| d.as_str())
                .unwrap_or("");
            templates::EXPLAIN_WHY_BLOCKED
                .replace("{reason}", reason)
                .replace("{detail}", detail)
        } else {
            "I couldn't find the specific blocked event. Try asking about recent blocked activity to see what I've stopped.".to_string()
        };

        let structured = event.map(|e| StructuredData::EventList {
            events: vec![e],
            total: 1,
        });

        (
            ResponseStrategy::TemplatePlusLlm,
            message,
            structured,
            vec![],
            false,
            None,
        )
    }

    fn synth_explain_concept(
        &self,
        slm_available: bool,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        if !slm_available {
            return (
                ResponseStrategy::Fallback,
                templates::EXPLAIN_CONCEPT_NO_LLM.to_string(),
                None,
                vec![],
                false,
                None,
            );
        }

        // When LLM is available, the caller should invoke the LLM with
        // a prompt built by build_llm_prompt(). For now we return a
        // placeholder that the engine replaces with the LLM response.
        (
            ResponseStrategy::LlmRequired,
            String::new(), // Filled by the engine after LLM call
            None,
            vec![],
            false,
            None,
        )
    }

    fn synth_explain_recommendation(
        &self,
        slm_available: bool,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        if !slm_available {
            return (
                ResponseStrategy::Fallback,
                templates::EXPLAIN_RECOMMENDATION_NO_LLM.to_string(),
                None,
                vec![],
                false,
                None,
            );
        }

        (
            ResponseStrategy::LlmRequired,
            String::new(),
            None,
            vec![],
            false,
            None,
        )
    }

    fn synth_explain_event(
        &self,
        qr: &QueryResult,
        _intent: &IntentClassification,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let event = qr
            .data
            .get("get_recent_events")
            .and_then(|v| v.as_array())
            .and_then(|events| events.first())
            .cloned();

        let message = if let Some(ref evt) = event {
            let summary = formatter::event_summary(evt);
            let detail = evt
                .get("detail")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            templates::EXPLAIN_EVENT
                .replace("{summary}", &summary)
                .replace("{detail}", detail)
        } else {
            "I couldn't find that event. Try asking about recent activity to see what's been happening.".to_string()
        };

        let structured = event.map(|e| StructuredData::EventList {
            events: vec![e],
            total: 1,
        });

        (ResponseStrategy::TemplateOnly, message, structured, vec![], false, None)
    }

    // =====================================================================
    // Risk synthesizers
    // =====================================================================

    fn synth_risk_server(
        &self,
        qr: &QueryResult,
        intent: &IntentClassification,
        _slm_available: bool,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        let server_name = intent
            .entities
            .get("server_name")
            .cloned()
            .unwrap_or_else(|| "this server".to_string());

        let reputation = qr
            .data
            .get("check_server_reputation")
            .and_then(|v| v.get("summary").and_then(|s| s.as_str()))
            .unwrap_or("No reputation data available");

        let profile_summary = qr
            .data
            .get("get_profiles")
            .and_then(|v| {
                v.as_array().and_then(|profiles| {
                    profiles.iter().find(|p| {
                        p.get("name")
                            .and_then(|n| n.as_str())
                            .map(|n| n.contains(&server_name))
                            .unwrap_or(false)
                    })
                })
            })
            .map(|p| formatter::server_summary(p))
            .unwrap_or_else(|| "No behavioral profile available yet".to_string());

        let message = templates::RISK_SERVER
            .replace("{server_name}", &server_name)
            .replace("{reputation}", reputation)
            .replace("{profile_summary}", &profile_summary);

        let structured = qr
            .data
            .get("check_server_reputation")
            .cloned()
            .map(StructuredData::ServerCard);

        (
            ResponseStrategy::TemplatePlusLlm,
            message,
            structured,
            vec![],
            false,
            None,
        )
    }

    // =====================================================================
    // Fallback
    // =====================================================================

    fn synth_fallback(
        &self,
    ) -> (ResponseStrategy, String, Option<StructuredData>, Vec<ActionButton>, bool, Option<String>) {
        (
            ResponseStrategy::Fallback,
            templates::HELP_FALLBACK.to_string(),
            None,
            vec![],
            false,
            None,
        )
    }

    // =====================================================================
    // Suggestion generation
    // =====================================================================

    fn generate_suggestions(
        &self,
        intent_id: &str,
        intent: &IntentClassification,
    ) -> Vec<String> {
        let base = match intent_id {
            "status.overall" => templates::SUGGESTIONS_STATUS_OVERALL,
            "status.daemon" => templates::SUGGESTIONS_STATUS_DAEMON,
            "status.protection_score" => templates::SUGGESTIONS_STATUS_PROTECTION_SCORE,
            "status.server_specific" => templates::SUGGESTIONS_STATUS_SERVER,
            "activity.recent" => templates::SUGGESTIONS_ACTIVITY_RECENT,
            "activity.blocked" => templates::SUGGESTIONS_ACTIVITY_BLOCKED,
            "activity.stats" => templates::SUGGESTIONS_ACTIVITY_STATS,
            "control.block" => templates::SUGGESTIONS_CONTROL_BLOCK,
            "control.scan" => templates::SUGGESTIONS_CONTROL_SCAN,
            "control.pause" => templates::SUGGESTIONS_CONTROL_PAUSE,
            id if id.starts_with("navigate.") => templates::SUGGESTIONS_NAVIGATE,
            "help.general" => templates::SUGGESTIONS_HELP,
            "explain.event" | "explain.why_blocked" => templates::SUGGESTIONS_EXPLAIN_EVENT,
            "explain.concept" | "explain.recommendation" => templates::SUGGESTIONS_EXPLAIN_CONCEPT,
            "risk.server" => templates::SUGGESTIONS_RISK,
            _ => templates::SUGGESTIONS_FALLBACK,
        };

        let server_name = intent.entities.get("server_name");

        base.iter()
            .map(|s| {
                if let Some(name) = server_name {
                    s.replace("{server}", name)
                } else {
                    s.to_string()
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// LLM prompt construction
// ---------------------------------------------------------------------------

/// Build an LLM prompt for intents that need language generation.
///
/// Uses the sanitizer to wrap untrusted data and add canary tokens.
pub fn build_llm_prompt(
    user_query: &str,
    query_result: &QueryResult,
    intent: &IntentClassification,
) -> LlmPrompt {
    use clawdefender_slm::sanitizer;

    // 1. Build system prompt with canary
    let (system_prompt, canary) =
        sanitizer::build_verified_system_prompt(templates::LLM_SYSTEM_PROMPT);

    // 2. Sanitize and wrap query result data
    let data_json = serde_json::to_string_pretty(&query_result.data).unwrap_or_default();
    let sanitized_data = sanitizer::sanitize_untrusted_input(&data_json, 4096);
    let (wrapped_data, _data_nonce) = sanitizer::wrap_untrusted(&sanitized_data);

    // 3. Sanitize and wrap user query
    let sanitized_query = sanitizer::sanitize_untrusted_input(user_query, 1024);
    let (wrapped_query, _query_nonce) = sanitizer::wrap_untrusted(&sanitized_query);

    // 4. Assemble the full prompt
    let user_prompt = format!(
        "Intent: {}\n\nContext data:\n{}\n\nUser question:\n{}",
        intent.intent_id, wrapped_data, wrapped_query
    );

    LlmPrompt {
        system: system_prompt,
        user: user_prompt,
        canary,
    }
}

/// Verify an LLM response contains the canary token.
///
/// If the canary is missing, the response may have been hijacked.
pub fn verify_llm_response(response: &str, canary: &str) -> bool {
    clawdefender_slm::sanitizer::verify_canary(response, canary)
}

/// Strip the canary token from a verified LLM response.
pub fn strip_canary(response: &str, canary: &str) -> String {
    response.replace(canary, "").trim().to_string()
}

/// A constructed LLM prompt ready for inference.
#[derive(Debug, Clone)]
pub struct LlmPrompt {
    pub system: String,
    pub user: String,
    pub canary: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_event_counts(qr: &QueryResult) -> (u64, u64) {
    let events = qr
        .data
        .get("get_recent_events")
        .and_then(|v| v.as_array());

    let total = events.map(|a| a.len() as u64).unwrap_or(0);

    let blocked = events
        .map(|events| {
            events
                .iter()
                .filter(|e| {
                    e.get("decision")
                        .and_then(|d| d.as_str())
                        .map(|d| d == "blocked" || d == "denied")
                        .unwrap_or(false)
                })
                .count() as u64
        })
        .unwrap_or(0);

    (total, blocked)
}

fn extract_protection_score(qr: &QueryResult) -> u32 {
    // Try multiple possible sources for the score
    qr.data
        .get("get_daemon_status")
        .and_then(|v| v.get("protection_score").and_then(|s| s.as_u64()))
        .or_else(|| {
            qr.data
                .get("get_behavioral_status")
                .and_then(|v| v.get("protection_score").and_then(|s| s.as_u64()))
        })
        .unwrap_or(0) as u32
}

fn extract_top_factor(qr: &QueryResult) -> Option<String> {
    qr.data
        .get("get_daemon_status")
        .or_else(|| qr.data.get("get_behavioral_status"))
        .and_then(|v| v.get("score_factors").and_then(|f| f.as_array()))
        .and_then(|factors| factors.first())
        .and_then(|f| f.get("reason").and_then(|r| r.as_str()))
        .map(|r| r.to_string())
}

fn extract_most_common_server(qr: &QueryResult) -> Option<String> {
    let events = qr
        .data
        .get("get_recent_events")
        .and_then(|v| v.as_array())?;

    let mut counts: HashMap<String, usize> = HashMap::new();
    for event in events {
        if let Some(server) = event.get("server_name").and_then(|s| s.as_str()) {
            *counts.entry(server.to_string()).or_insert(0) += 1;
        }
    }

    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(name, _)| name)
}

fn generate_turn_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("turn-{:x}", ts)
}

// ---------------------------------------------------------------------------
// Tauri command
// ---------------------------------------------------------------------------

/// Tauri command: synthesize a response from pre-computed components.
#[tauri::command]
pub fn synthesize_response(
    query_result_json: String,
    intent_json: String,
    context_json: String,
) -> Result<String, String> {
    let query_result: QueryResult =
        serde_json::from_str(&query_result_json).map_err(|e| format!("Invalid query_result: {}", e))?;
    let intent: IntentClassification =
        serde_json::from_str(&intent_json).map_err(|e| format!("Invalid intent: {}", e))?;
    let context: ConversationContext =
        serde_json::from_str(&context_json).map_err(|e| format!("Invalid context: {}", e))?;

    let synthesizer = ResponseSynthesizer::new();
    let response = synthesizer.synthesize(&query_result, &intent, &context, false);

    serde_json::to_string(&response).map_err(|e| format!("Serialization error: {}", e))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_intent(intent_id: &str) -> IntentClassification {
        IntentClassification {
            intent_id: intent_id.to_string(),
            confidence: 0.95,
            entities: HashMap::new(),
            method: super::super::intent::ClassificationMethod::Keyword,
        }
    }

    fn make_context() -> ConversationContext {
        ConversationContext::new("test-session".to_string())
    }

    fn make_empty_qr() -> QueryResult {
        QueryResult {
            data: HashMap::new(),
            errors: HashMap::new(),
            complete: true,
        }
    }

    // -------------------------------------------------------------------
    // Template voice tests
    // -------------------------------------------------------------------

    #[test]
    fn test_status_overall_all_clear() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let intent = make_intent("status.overall");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert_eq!(response.response_strategy, ResponseStrategy::TemplateOnly);
        assert!(response.message.contains("All clear"));
        assert!(response.message.contains("monitoring"));
        // Voice guide: first person
        assert!(response.message.contains("I'm") || response.message.contains("I "));
        // Voice guide: no exclamation marks
        assert!(!response.message.contains('!'));
    }

    #[test]
    fn test_status_overall_with_blocked() {
        let synth = ResponseSynthesizer::new();
        let mut qr = make_empty_qr();
        qr.data.insert(
            "get_recent_events".to_string(),
            serde_json::json!([
                {"server_name": "test", "decision": "allowed"},
                {"server_name": "test", "decision": "blocked"},
                {"server_name": "test", "decision": "blocked"},
            ]),
        );
        let intent = make_intent("status.overall");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("keeping an eye"));
        assert!(response.message.contains("2 were blocked"));
    }

    #[test]
    fn test_status_daemon_running() {
        let synth = ResponseSynthesizer::new();
        let mut qr = make_empty_qr();
        qr.data.insert(
            "get_daemon_status".to_string(),
            serde_json::json!({
                "running": true,
                "uptime_seconds": 3600,
                "server_count": 3
            }),
        );
        let intent = make_intent("status.daemon");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("running"));
        assert!(response.message.contains("3 servers"));
        assert!(response.actions.is_empty());
    }

    #[test]
    fn test_status_daemon_stopped_has_start_button() {
        let synth = ResponseSynthesizer::new();
        let mut qr = make_empty_qr();
        qr.data.insert(
            "get_daemon_status".to_string(),
            serde_json::json!({"running": false}),
        );
        let intent = make_intent("status.daemon");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("stopped"));
        assert_eq!(response.actions.len(), 1);
        assert_eq!(response.actions[0].label, "Start daemon");
    }

    #[test]
    fn test_status_protection_score() {
        let synth = ResponseSynthesizer::new();
        let mut qr = make_empty_qr();
        qr.data.insert(
            "get_daemon_status".to_string(),
            serde_json::json!({"protection_score": 85}),
        );
        let intent = make_intent("status.protection_score");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("85"));
        assert!(response.message.contains("Looking good"));
        assert!(response.structured_data.is_some());
    }

    // -------------------------------------------------------------------
    // Activity tests
    // -------------------------------------------------------------------

    #[test]
    fn test_activity_recent_empty() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let intent = make_intent("activity.recent");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("Nothing"));
        assert!(response.structured_data.is_none());
    }

    #[test]
    fn test_activity_recent_with_events() {
        let synth = ResponseSynthesizer::new();
        let mut qr = make_empty_qr();
        qr.data.insert(
            "get_recent_events".to_string(),
            serde_json::json!([
                {"server_name": "test", "decision": "allowed", "description": "read file"}
            ]),
        );
        let intent = make_intent("activity.recent");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("been happening"));
        assert!(response.structured_data.is_some());
    }

    #[test]
    fn test_activity_blocked_none() {
        let synth = ResponseSynthesizer::new();
        let mut qr = make_empty_qr();
        qr.data.insert(
            "get_recent_events".to_string(),
            serde_json::json!([
                {"server_name": "test", "decision": "allowed"}
            ]),
        );
        let intent = make_intent("activity.blocked");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("haven't blocked"));
    }

    // -------------------------------------------------------------------
    // Control tests
    // -------------------------------------------------------------------

    #[test]
    fn test_control_block_requires_confirmation() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let mut intent = make_intent("control.block");
        intent
            .entities
            .insert("server_name".to_string(), "claude-server".to_string());
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.requires_confirmation);
        assert!(response.message.contains("claude-server"));
        assert_eq!(response.actions.len(), 2);
        assert_eq!(response.actions[0].label, "Do it");
        assert_eq!(response.actions[1].label, "Never mind");
    }

    #[test]
    fn test_control_pause_requires_confirmation() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let intent = make_intent("control.pause");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.requires_confirmation);
        assert!(response.message.contains("pause"));
        assert_eq!(response.actions.len(), 2);
        assert_eq!(response.actions[0].label, "Pause");
        assert_eq!(response.actions[0].style, "danger");
        assert_eq!(response.actions[1].label, "Keep protecting");
    }

    #[test]
    fn test_control_scan_has_action() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let intent = make_intent("control.scan");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("scan"));
        assert!(!response.actions.is_empty());
    }

    // -------------------------------------------------------------------
    // Navigate tests
    // -------------------------------------------------------------------

    #[test]
    fn test_navigate_page() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let mut intent = make_intent("navigate.page");
        intent
            .entities
            .insert("page".to_string(), "settings".to_string());
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("Opening Settings"));
        assert_eq!(response.actions.len(), 1);
    }

    #[test]
    fn test_navigate_dashboard_from_intent_id() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let intent = make_intent("navigate.dashboard");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("Dashboard"));
    }

    // -------------------------------------------------------------------
    // Help tests
    // -------------------------------------------------------------------

    #[test]
    fn test_help_general() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let intent = make_intent("help.general");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert!(response.message.contains("help you"));
    }

    // -------------------------------------------------------------------
    // Explain tests
    // -------------------------------------------------------------------

    #[test]
    fn test_explain_concept_no_llm_fallback() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let intent = make_intent("explain.concept");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert_eq!(response.response_strategy, ResponseStrategy::Fallback);
        assert!(response.message.contains("AI model"));
        assert!(response.message.contains("Settings"));
    }

    #[test]
    fn test_explain_concept_with_llm() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let intent = make_intent("explain.concept");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, true);

        assert_eq!(response.response_strategy, ResponseStrategy::LlmRequired);
    }

    // -------------------------------------------------------------------
    // Fallback tests
    // -------------------------------------------------------------------

    #[test]
    fn test_unknown_intent_fallback() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let intent = make_intent("some.unknown.intent");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert_eq!(response.response_strategy, ResponseStrategy::Fallback);
        assert!(response.message.contains("not sure"));
    }

    // -------------------------------------------------------------------
    // Suggestion tests
    // -------------------------------------------------------------------

    #[test]
    fn test_suggestions_after_status_overall() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let intent = make_intent("status.overall");
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        assert_eq!(response.suggestions.len(), 3);
        assert!(response.suggestions.contains(&"What happened today?".to_string()));
    }

    #[test]
    fn test_suggestions_after_control_block_with_server() {
        let synth = ResponseSynthesizer::new();
        let qr = make_empty_qr();
        let mut intent = make_intent("control.block");
        intent
            .entities
            .insert("server_name".to_string(), "claude-server".to_string());
        let ctx = make_context();

        let response = synth.synthesize(&qr, &intent, &ctx, false);

        // Suggestions should have {server} replaced with the actual name
        let has_server_ref = response
            .suggestions
            .iter()
            .any(|s| s.contains("claude-server"));
        assert!(
            has_server_ref,
            "Suggestions should reference the server name: {:?}",
            response.suggestions
        );
    }

    // -------------------------------------------------------------------
    // LLM prompt construction tests
    // -------------------------------------------------------------------

    #[test]
    fn test_llm_prompt_includes_sanitizer_wrapping() {
        let qr = QueryResult {
            data: {
                let mut d = HashMap::new();
                d.insert(
                    "test".to_string(),
                    serde_json::json!({"key": "value"}),
                );
                d
            },
            errors: HashMap::new(),
            complete: true,
        };
        let intent = make_intent("explain.concept");

        let prompt = build_llm_prompt("what is prompt injection?", &qr, &intent);

        // System prompt should contain the canary instruction
        assert!(prompt.system.contains("VERIFICATION"));
        assert!(prompt.system.contains(&prompt.canary));

        // User prompt should contain UNTRUSTED_INPUT tags
        assert!(prompt.user.contains("UNTRUSTED_INPUT_"));
        assert!(prompt.user.contains("WARNING"));
    }

    #[test]
    fn test_verify_llm_response_with_canary() {
        let qr = make_empty_qr();
        let intent = make_intent("explain.concept");
        let prompt = build_llm_prompt("test", &qr, &intent);

        let good_response = format!("This is a helpful response. {}", prompt.canary);
        assert!(verify_llm_response(&good_response, &prompt.canary));

        let bad_response = "This is a hijacked response.";
        assert!(!verify_llm_response(bad_response, &prompt.canary));
    }

    #[test]
    fn test_strip_canary_from_response() {
        let canary = "abc123";
        let response = format!("A clean response. {}", canary);
        let stripped = strip_canary(&response, canary);
        assert_eq!(stripped, "A clean response.");
        assert!(!stripped.contains(canary));
    }

    // -------------------------------------------------------------------
    // Tauri command test
    // -------------------------------------------------------------------

    #[test]
    fn test_synthesize_response_command() {
        let qr = make_empty_qr();
        let intent = make_intent("help.general");
        let ctx = make_context();

        let result = synthesize_response(
            serde_json::to_string(&qr).unwrap(),
            serde_json::to_string(&intent).unwrap(),
            serde_json::to_string(&ctx).unwrap(),
        );

        assert!(result.is_ok());
        let response: ConversationResponse =
            serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(response.intent_id, "help.general");
        assert!(!response.message.is_empty());
    }

    // -------------------------------------------------------------------
    // Voice guide compliance tests
    // -------------------------------------------------------------------

    #[test]
    fn test_all_templates_no_exclamation_marks() {
        let templates_to_check = [
            templates::STATUS_OVERALL_CLEAR,
            templates::STATUS_OVERALL_CLEAR_WITH_EVENTS,
            templates::STATUS_OVERALL_WATCHING,
            templates::STATUS_DAEMON_RUNNING,
            templates::STATUS_DAEMON_STOPPED,
            templates::STATUS_PROTECTION_SCORE,
            templates::ACTIVITY_RECENT,
            templates::ACTIVITY_BLOCKED,
            templates::ACTIVITY_BLOCKED_NONE,
            templates::CONTROL_BLOCK_CONFIRM,
            templates::CONTROL_SCAN_START,
            templates::CONTROL_PAUSE_CONFIRM,
            templates::NAVIGATE_PAGE,
            templates::HELP_GENERAL,
            templates::HELP_FALLBACK,
        ];

        for template in &templates_to_check {
            assert!(
                !template.contains('!'),
                "Template contains exclamation mark: {}",
                template
            );
        }
    }

    #[test]
    fn test_all_templates_first_person() {
        // Templates that should use first person ("I") rather than "we"
        let templates_to_check = [
            templates::STATUS_OVERALL_CLEAR,
            templates::STATUS_OVERALL_CLEAR_WITH_EVENTS,
            templates::STATUS_OVERALL_WATCHING,
            templates::ACTIVITY_BLOCKED,
            templates::ACTIVITY_BLOCKED_NONE,
            templates::CONTROL_BLOCK_CONFIRM,
            templates::CONTROL_SCAN_START,
            templates::CONTROL_PAUSE_CONFIRM,
        ];

        for template in &templates_to_check {
            assert!(
                !template.contains(" we ") && !template.contains("We "),
                "Template uses 'we' instead of 'I': {}",
                template
            );
        }
    }

    #[test]
    fn test_no_emoji_in_templates() {
        let templates_to_check = [
            templates::STATUS_OVERALL_CLEAR,
            templates::STATUS_OVERALL_WATCHING,
            templates::STATUS_DAEMON_RUNNING,
            templates::STATUS_DAEMON_STOPPED,
            templates::ACTIVITY_RECENT,
            templates::ACTIVITY_BLOCKED,
            templates::CONTROL_BLOCK_CONFIRM,
            templates::CONTROL_PAUSE_CONFIRM,
            templates::HELP_GENERAL,
            templates::HELP_FALLBACK,
        ];

        for template in &templates_to_check {
            // Check that there are no non-ASCII characters that could be emoji
            // (Claw's voice guide forbids emoji in security messages)
            let has_emoji = template.chars().any(|c| {
                let cp = c as u32;
                // Common emoji ranges
                (0x1F600..=0x1F64F).contains(&cp)
                    || (0x1F300..=0x1F5FF).contains(&cp)
                    || (0x1F680..=0x1F6FF).contains(&cp)
                    || (0x2600..=0x26FF).contains(&cp)
                    || (0x2700..=0x27BF).contains(&cp)
            });
            assert!(!has_emoji, "Template contains emoji: {}", template);
        }
    }
}
