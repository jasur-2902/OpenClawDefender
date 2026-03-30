use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::state::{AuditEvent, ServerProfileSummary};

use super::context::{
    generate_behavioral_context, risk_explanation_from_anomaly, threat_level_from_anomaly,
};
use super::display_names::DisplayNameRegistry;
use super::templates::{classify_event, render_template};

/// A fully humanized event ready for frontend display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanizedEvent {
    pub event_id: String,
    pub timestamp: String,
    pub server_display_name: String,
    pub client_name: Option<String>,
    pub one_liner: String,
    pub expanded_explanation: String,
    pub educational_aside: Option<String>,
    pub behavioral_context: String,
    pub risk_level: String,
    pub risk_explanation: String,
    pub action_taken: String,
    pub action_reason: String,
    pub is_notable: bool,
    pub correlation_id: Option<String>,
    pub kill_chain_id: Option<String>,
    pub raw_event: AuditEvent,
}

/// What action Claw took on an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionTaken {
    Allowed,
    Blocked,
    Prompted,
    AutoBlocked,
}

impl ActionTaken {
    pub fn from_decision(decision: &str, details: &str) -> Self {
        let d = decision.to_lowercase();
        let det = details.to_lowercase();

        if d == "prompted" || d == "prompt" {
            return ActionTaken::Prompted;
        }
        if d == "blocked" || d == "denied" || d == "block" {
            if det.contains("auto") {
                return ActionTaken::AutoBlocked;
            }
            return ActionTaken::Blocked;
        }
        ActionTaken::Allowed
    }

    pub fn label(&self) -> &'static str {
        match self {
            ActionTaken::Allowed => "Allowed",
            ActionTaken::Blocked => "Blocked",
            ActionTaken::Prompted => "Prompted",
            ActionTaken::AutoBlocked => "AutoBlocked",
        }
    }

    pub fn reason(&self, server: &str) -> String {
        match self {
            ActionTaken::Allowed => "Matched an allow policy rule.".to_string(),
            ActionTaken::Blocked => format!("Policy rule blocked this action by \"{}\".", server),
            ActionTaken::Prompted => {
                "Your policy requires human approval for this action.".to_string()
            }
            ActionTaken::AutoBlocked => format!(
                "Auto-blocked because \"{}\" exceeded risk thresholds.",
                server
            ),
        }
    }
}

/// Context for humanization, carrying display name registry and any shared state.
pub struct HumanizationContext {
    pub display_names: DisplayNameRegistry,
}

impl Default for HumanizationContext {
    fn default() -> Self {
        Self {
            display_names: DisplayNameRegistry::new(),
        }
    }
}

/// Humanize a single audit event.
pub fn humanize_event(
    event: &AuditEvent,
    profile: Option<&ServerProfileSummary>,
    context: &HumanizationContext,
) -> HumanizedEvent {
    let client_name: Option<String> = None; // TODO: derive from server config when available

    let server_display = context
        .display_names
        .resolve_server(&event.server_name, client_name.as_deref());

    let tool_display = event
        .tool_name
        .as_deref()
        .map(|t| context.display_names.resolve_tool(t))
        .unwrap_or_else(|| event.action.clone());

    let resource_display = event
        .resource
        .as_deref()
        .map(|r| context.display_names.resolve_resource(r))
        .unwrap_or_default();

    // Command preview for shell events
    let command_preview = if event.tool_name.as_deref() == Some("execute_command")
        || event.tool_name.as_deref() == Some("run_command")
    {
        event
            .resource
            .as_deref()
            .unwrap_or(&event.details)
            .to_string()
    } else {
        String::new()
    };

    // Destination for network events
    let destination = event.resource.as_deref().unwrap_or("unknown destination");

    // Behavioral analysis
    let behavioral_context = generate_behavioral_context(profile);
    let anomaly_score = profile.map(|p| p.anomaly_score).unwrap_or(0.0);

    // Classify the event
    let is_first_occurrence = false; // Would need per-action tracking
    let is_rate_spike = anomaly_score >= 0.7;
    let pattern = classify_event(event, is_first_occurrence, is_rate_spike);

    // Render template
    let template = render_template(
        &pattern,
        &server_display,
        &tool_display,
        &resource_display,
        &command_preview,
        &event.action,
        destination,
    );

    // Determine action taken
    let action = ActionTaken::from_decision(&event.decision, &event.details);

    // Risk level: use template risk, but override with behavioral if anomaly is higher
    let behavioral_risk = threat_level_from_anomaly(anomaly_score);
    let risk_level = higher_risk(template.risk_level, behavioral_risk);

    // Risk explanation: combine template and behavioral
    let risk_explanation = if anomaly_score >= 0.4 {
        format!(
            "{} {}",
            template.risk_explanation,
            risk_explanation_from_anomaly(anomaly_score)
        )
    } else {
        template.risk_explanation
    };

    // Kill chain detection
    let kill_chain_id = if event.details.to_lowercase().contains("kill_chain")
        || event.details.to_lowercase().contains("kill chain")
    {
        Some(format!("kc-{}", event.server_name))
    } else {
        None
    };

    // Extract SLM analysis from event details if present and blend with description.
    let (expanded_explanation, risk_explanation, is_slm_notable) =
        if let Some(slm) = extract_slm_from_event_details(&event.details) {
            let blended_explanation = format!(
                "{}. AI Analysis: {}",
                template.expanded_explanation, slm.explanation
            );
            let blended_risk = format!(
                "{} AI classified this as {} risk ({:.0}% confidence).",
                risk_explanation, slm.risk_level, slm.confidence * 100.0
            );
            let notable = slm.risk_level == "high" || slm.risk_level == "critical";
            (blended_explanation, blended_risk, notable)
        } else {
            (template.expanded_explanation, risk_explanation, false)
        };

    HumanizedEvent {
        event_id: event.id.clone(),
        timestamp: event.timestamp.clone(),
        server_display_name: server_display,
        client_name,
        one_liner: template.one_liner,
        expanded_explanation,
        educational_aside: template.educational_aside,
        behavioral_context,
        risk_level: risk_level.to_string(),
        risk_explanation,
        action_taken: action.label().to_string(),
        action_reason: action.reason(&event.server_name),
        is_notable: template.is_notable
            || event.decision == "blocked"
            || event.decision == "denied"
            || anomaly_score >= 0.7
            || is_slm_notable,
        correlation_id: None,
        kill_chain_id,
        raw_event: event.clone(),
    }
}

/// Humanize a batch of events.
pub fn humanize_events(
    events: &[AuditEvent],
    profiles: &HashMap<String, ServerProfileSummary>,
) -> Vec<HumanizedEvent> {
    let context = HumanizationContext::default();

    events
        .iter()
        .map(|event| {
            let profile = profiles.get(&event.server_name);
            humanize_event(event, profile, &context)
        })
        .collect()
}

/// Extracted SLM analysis for humanization.
struct SlmInfo {
    risk_level: String,
    explanation: String,
    confidence: f32,
}

/// Extract SLM analysis from event details JSON (encoded by event_stream).
fn extract_slm_from_event_details(details: &str) -> Option<SlmInfo> {
    let parsed: serde_json::Value = serde_json::from_str(details).ok()?;
    let slm = parsed.get("slm_analysis")?;
    let risk_level = slm.get("risk_level")?.as_str()?.to_string();
    let explanation = slm
        .get("explanation")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let confidence = slm
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0) as f32;
    if explanation.is_empty() {
        return None;
    }
    Some(SlmInfo {
        risk_level,
        explanation,
        confidence,
    })
}

/// Return the higher of two risk levels.
fn higher_risk<'a>(a: &'a str, b: &'a str) -> &'a str {
    let rank = |r: &str| -> u8 {
        match r {
            "dangerous" => 5,
            "suspicious" => 4,
            "unusual" => 3,
            "blocked" => 3,
            "normal" => 2,
            "info" => 1,
            _ => 0,
        }
    };

    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}
