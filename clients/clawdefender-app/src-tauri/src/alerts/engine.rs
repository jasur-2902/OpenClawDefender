use serde::{Deserialize, Serialize};

use crate::state::AuditEvent;
use super::dedup::dedup_key;
use super::kill_chain::{check_kill_chain, KillChainNarrative};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertType {
    Anomaly,
    KillChain,
    Block,
    ThreatIntel,
    Correlation,
    Timeout,
    Discovery,
    Vulnerability,
    Analysis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertStatus {
    Active,
    Reviewed,
    Resolved,
    Dismissed,
    AutoExpired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertAction {
    pub id: String,
    pub label: String,
    pub action_type: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligentAlert {
    pub id: String,
    pub alert_type: AlertType,
    pub severity: String,
    pub status: AlertStatus,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub source_events: Vec<String>,
    pub server_name: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub resolved_at: Option<String>,
    pub resolved_by: Option<String>,
    pub dedup_key: String,
    pub dedup_count: u32,
    pub actions: Vec<AlertAction>,
    pub kill_chain: Option<KillChainNarrative>,
    /// SLM natural language explanation (populated for Analysis alerts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_summary: Option<String>,
    /// SLM risk classification: "safe", "suspicious", "dangerous", "critical".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_risk_level: Option<String>,
    /// SLM confidence score (0.0 - 1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_confidence: Option<f32>,
    /// SLM recommended action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_recommendation: Option<String>,
}

// ---------------------------------------------------------------------------
// Alert ID generation (simple sequential + random suffix, no uuid crate needed)
// ---------------------------------------------------------------------------

fn generate_alert_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = chrono::Utc::now().timestamp_millis();
    format!("alert-{}-{}", now, seq)
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ---------------------------------------------------------------------------
// Alert promotion: AuditEvent -> Vec<IntelligentAlert>
// ---------------------------------------------------------------------------

/// Process a single event against the alert promotion rules.
/// Returns zero or more alerts that should be stored.
pub fn process_event(event: &AuditEvent, events_buffer: &[AuditEvent]) -> Vec<IntelligentAlert> {
    let mut alerts: Vec<IntelligentAlert> = Vec::new();

    // Rule 2: Kill chain detection (highest priority — supersedes individual alerts)
    if let Some(narrative) = check_kill_chain(event, events_buffer) {
        let kill_chain_event_ids: Vec<String> = narrative.steps.iter().map(|s| s.event_id.clone()).collect();
        let summary = narrative.summary.clone();
        let alert = build_alert(
            AlertType::KillChain,
            "dangerous",
            &format!("I detected a multi-step attack pattern from {}", event.server_name),
            &summary,
            "I recommend restricting this server immediately and reviewing the attack chain.",
            kill_chain_event_ids,
            Some(&event.server_name),
            vec![
                make_action("restrict", "Restrict Server", "restrict"),
                make_action("view", "View Kill Chain", "view_details"),
                make_action("dismiss", "Dismiss", "dismiss"),
            ],
            Some(narrative),
        );
        alerts.push(alert);
        // Kill chain supersedes individual event alerts — return early
        return alerts;
    }

    // Rule 1: Anomaly — risk_level is "high" or "critical" (anomaly score >= 0.7)
    if event.risk_level == "high" || event.risk_level == "critical" {
        let severity = if event.risk_level == "critical" { "dangerous" } else { "suspicious" };
        let alert = build_alert(
            AlertType::Anomaly,
            severity,
            &format!("I noticed unusual behavior from {} — {}", event.server_name, event.action),
            &format!(
                "The server \"{}\" triggered a {} risk event: {}. This behavior deviates from what I have learned.",
                event.server_name, event.risk_level, event.details
            ),
            "Review this server's recent activity. If this looks wrong, consider restricting it.",
            vec![event.id.clone()],
            Some(&event.server_name),
            vec![
                make_action("restrict", "Restrict Server", "restrict"),
                make_action("allow", "Allow", "allow"),
                make_action("dismiss", "Dismiss", "dismiss"),
            ],
            None,
        );
        alerts.push(alert);
    }

    // Rule 3: Auto-block — decision is "blocked"/"denied" and automatic
    let decision_lower = event.decision.to_lowercase();
    if (decision_lower == "blocked" || decision_lower == "denied" || decision_lower == "block")
        && event.details.to_lowercase().contains("auto")
    {
        let alert = build_alert(
            AlertType::Block,
            "suspicious",
            &format!("I blocked {} automatically — it looked dangerous", event.server_name),
            &format!(
                "I blocked an action by \"{}\" automatically because it combined multiple high-risk signals: {}. You can review this decision and override it.",
                event.server_name, event.action
            ),
            "Review the blocked action. If this was legitimate, you can allow it.",
            vec![event.id.clone()],
            Some(&event.server_name),
            vec![
                make_action("allow", "Allow This Action", "allow"),
                make_action("view", "View Details", "view_details"),
                make_action("dismiss", "Dismiss", "dismiss"),
            ],
            None,
        );
        alerts.push(alert);
    }

    // Rule 4: IoC match — details contains "ioc" or "indicator" or "blocklist"
    let details_lower = event.details.to_lowercase();
    if details_lower.contains("ioc") || details_lower.contains("indicator") || details_lower.contains("blocklist") {
        let alert = build_alert(
            AlertType::ThreatIntel,
            "dangerous",
            &format!("I found a threat intelligence match on {}", event.server_name),
            &format!(
                "The server \"{}\" matched a known indicator of compromise. This could mean the server is communicating with known malicious infrastructure.",
                event.server_name
            ),
            "I recommend restricting this server immediately and investigating further.",
            vec![event.id.clone()],
            Some(&event.server_name),
            vec![
                make_action("restrict", "Restrict Server", "restrict"),
                make_action("view", "View Details", "view_details"),
                make_action("ask", "Ask Claw", "ask_claw"),
            ],
            None,
        );
        alerts.push(alert);
    }

    // Rule 5: Uncorrelated — details contains "uncorrelated"
    if details_lower.contains("uncorrelated") {
        let alert = build_alert(
            AlertType::Correlation,
            "suspicious",
            "I noticed system activity that does not match any server request",
            &format!(
                "A system event occurred ({}) that I cannot trace back to any MCP tool call. This could be normal background activity, or it could be a process acting on its own.",
                event.details
            ),
            "Investigate what caused this activity. If no server should be doing this, check for background processes.",
            vec![event.id.clone()],
            Some(&event.server_name),
            vec![
                make_action("view", "View Details", "view_details"),
                make_action("dismiss", "Dismiss", "dismiss"),
            ],
            None,
        );
        alerts.push(alert);
    }

    // Rule 6: Timeout — details contains "timed out" or "timeout"
    if details_lower.contains("timed out") || details_lower.contains("timeout") {
        let alert = build_alert(
            AlertType::Timeout,
            "info",
            &format!("A prompt for {} timed out — I denied it automatically", event.server_name),
            &format!(
                "A security prompt for \"{}\" was not answered in time, so I denied the action automatically (fail-closed). The action was: {}.",
                event.server_name, event.action
            ),
            "No action needed. The request was safely denied. You can review and allow it if needed.",
            vec![event.id.clone()],
            Some(&event.server_name),
            vec![
                make_action("allow", "Allow This Action", "allow"),
                make_action("dismiss", "Dismiss", "dismiss"),
            ],
            None,
        );
        alerts.push(alert);
    }

    // Rule 7: New tool — event_type indicates new tool detection
    let action_lower = event.action.to_lowercase();
    if event.event_type.contains("new_tool") || action_lower.contains("new tool") || action_lower.contains("first time") {
        let alert = build_alert(
            AlertType::Discovery,
            "info",
            &format!("{} has a new tool I have not seen before", event.server_name),
            &format!(
                "The server \"{}\" is using a capability I have not observed in previous sessions. This could be a new workflow or something unexpected.",
                event.server_name
            ),
            "Take a look at what this new tool does. If it looks normal, you can dismiss this.",
            vec![event.id.clone()],
            Some(&event.server_name),
            vec![
                make_action("view", "View Tool", "view_details"),
                make_action("dismiss", "Dismiss", "dismiss"),
            ],
            None,
        );
        alerts.push(alert);
    }

    // Rule 8: Vulnerability — details contains "vulnerability" or "CVE"
    if details_lower.contains("vulnerability") || details_lower.contains("cve") {
        let alert = build_alert(
            AlertType::Vulnerability,
            "dangerous",
            &format!("I found a vulnerability related to {}", event.server_name),
            &format!(
                "A vulnerability was detected related to the server \"{}\": {}. This may expose your system to attack.",
                event.server_name, event.details
            ),
            "I recommend updating the affected server and reviewing its permissions.",
            vec![event.id.clone()],
            Some(&event.server_name),
            vec![
                make_action("restrict", "Restrict Server", "restrict"),
                make_action("view", "View Details", "view_details"),
                make_action("dismiss", "Dismiss", "dismiss"),
            ],
            None,
        );
        alerts.push(alert);
    }

    // Rule 9: SLM high risk — details contains SLM analysis with risk "high"/"critical"
    if let Some(slm) = extract_slm_analysis(&event.details) {
        let slm_risk = slm.risk_level.to_lowercase();
        if slm_risk == "high" || slm_risk == "critical" {
            // Avoid duplicate if we already generated an Anomaly alert for this event
            let already_has_anomaly = alerts.iter().any(|a| a.alert_type == AlertType::Anomaly);
            if !already_has_anomaly {
                let severity = if slm_risk == "critical" { "dangerous" } else { "suspicious" };
                let description = if slm.explanation.is_empty() {
                    format!(
                        "My on-device AI analysis of this action by \"{}\" returned a {} risk assessment. The action was: {}.",
                        event.server_name, slm.risk_level, event.action
                    )
                } else {
                    format!(
                        "My on-device AI analysis of this action by \"{}\" flagged it as {} risk: {}",
                        event.server_name, slm.risk_level, slm.explanation
                    )
                };
                let ai_recommendation = match slm_risk.as_str() {
                    "critical" => "Deny this request and restrict the server.",
                    "high" => "Review this action carefully before allowing.",
                    _ => "Review this action carefully.",
                };
                let mut alert = build_alert(
                    AlertType::Analysis,
                    severity,
                    &format!("My AI analysis flagged {} as {} risk", event.server_name, slm.risk_level),
                    &description,
                    ai_recommendation,
                    vec![event.id.clone()],
                    Some(&event.server_name),
                    vec![
                        make_action("restrict", "Restrict Server", "restrict"),
                        make_action("allow", "Allow", "allow"),
                        make_action("dismiss", "Dismiss", "dismiss"),
                    ],
                    None,
                );
                alert.ai_summary = Some(if slm.explanation.is_empty() {
                    format!("{} risk action detected", slm.risk_level)
                } else {
                    slm.explanation.clone()
                });
                alert.ai_risk_level = Some(slm.risk_level.clone());
                alert.ai_confidence = Some(slm.confidence);
                alert.ai_recommendation = Some(ai_recommendation.to_string());
                alerts.push(alert);
            }
        }
    }

    alerts
}

// ---------------------------------------------------------------------------
// SLM analysis extraction
// ---------------------------------------------------------------------------

/// Extracted SLM analysis from event details JSON.
struct SlmData {
    risk_level: String,
    explanation: String,
    confidence: f32,
}

/// Try to extract SLM analysis from event details.
/// The event_stream module encodes SLM data as JSON in details when present.
fn extract_slm_analysis(details: &str) -> Option<SlmData> {
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
    Some(SlmData {
        risk_level,
        explanation,
        confidence,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_alert(
    alert_type: AlertType,
    severity: &str,
    title: &str,
    description: &str,
    recommendation: &str,
    source_events: Vec<String>,
    server_name: Option<&str>,
    actions: Vec<AlertAction>,
    kill_chain: Option<KillChainNarrative>,
) -> IntelligentAlert {
    let now = now_iso();
    // Build a temporary alert to compute its dedup_key
    let mut alert = IntelligentAlert {
        id: generate_alert_id(),
        alert_type: alert_type.clone(),
        severity: severity.to_string(),
        status: AlertStatus::Active,
        title: title.to_string(),
        description: description.to_string(),
        recommendation: recommendation.to_string(),
        source_events,
        server_name: server_name.map(|s| s.to_string()),
        created_at: now.clone(),
        updated_at: now,
        resolved_at: None,
        resolved_by: None,
        dedup_key: String::new(),
        dedup_count: 1,
        actions,
        kill_chain,
        ai_summary: None,
        ai_risk_level: None,
        ai_confidence: None,
        ai_recommendation: None,
    };

    // Compute dedup_key from the first source event info
    let server = server_name.unwrap_or("unknown");
    let action_str = alert.title.as_str();
    alert.dedup_key = dedup_key(server, action_str, &alert.alert_type);

    alert
}

fn make_action(id: &str, label: &str, action_type: &str) -> AlertAction {
    AlertAction {
        id: id.to_string(),
        label: label.to_string(),
        action_type: action_type.to_string(),
        params: None,
    }
}
