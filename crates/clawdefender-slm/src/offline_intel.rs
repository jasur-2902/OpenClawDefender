//! Offline intelligence generation: useful analysis the SLM provides without cloud connectivity.
//!
//! Provides server behavior summaries, anomaly explanations, security tips, and
//! risk assessments for new servers — all generated locally using the SLM engine
//! or rule-based heuristics.

use std::collections::HashMap;
use std::sync::RwLock;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::engine::SlmEngine;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Hourly behavior summary for a single MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSummary {
    pub server_name: String,
    /// Human-readable summary, e.g. "34 tool calls in the last hour, primarily file reads in ~/project/. Normal pattern."
    pub summary: String,
    pub event_count: u64,
    /// One of: "normal", "elevated", "high"
    pub anomaly_level: String,
    pub generated_at: DateTime<Utc>,
}

/// Human-readable explanation of why an event was flagged as anomalous.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyExplanation {
    pub event_id: String,
    pub explanation: String,
    /// Which anomaly dimensions triggered (e.g. "unknown_tool", "sensitive_target").
    pub anomaly_dimensions: Vec<String>,
    pub generated_at: DateTime<Utc>,
}

/// Contextual security advice generated from system state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTip {
    pub id: String,
    pub tip: String,
    /// One of: "info", "warning", "action_needed"
    pub priority: String,
    pub generated_at: DateTime<Utc>,
}

/// Risk assessment for a newly-detected MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRiskAssessment {
    pub server_name: String,
    /// One of: "LOW", "MEDIUM", "HIGH"
    pub risk_level: String,
    pub reasoning: String,
    /// One of: "trusted", "verified", "untrusted"
    pub recommended_trust: String,
    pub generated_at: DateTime<Utc>,
}

/// Aggregated offline intelligence data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OfflineIntelligence {
    pub server_summaries: Vec<ServerSummary>,
    pub security_tips: Vec<SecurityTip>,
    pub anomaly_explanations: Vec<AnomalyExplanation>,
    pub server_assessments: Vec<ServerRiskAssessment>,
    pub last_summary_update: Option<DateTime<Utc>>,
    pub last_tips_update: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Generates and caches offline intelligence using the local SLM engine
/// and rule-based heuristics.
pub struct OfflineIntelEngine {
    cache: RwLock<OfflineIntelligence>,
}

impl OfflineIntelEngine {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(OfflineIntelligence::default()),
        }
    }

    /// Generate a server behavior summary using the SLM.
    ///
    /// Produces a 1-2 sentence natural language summary of the server's recent activity.
    pub async fn generate_server_summary(
        &self,
        slm: &SlmEngine,
        server_name: &str,
        event_count: u64,
        primary_tools: &[String],
        primary_targets: &[String],
        anomaly_score: f64,
    ) -> Result<ServerSummary> {
        let anomaly_level = if anomaly_score < 0.3 {
            "normal"
        } else if anomaly_score < 0.7 {
            "elevated"
        } else {
            "high"
        };

        let tools_str = if primary_tools.is_empty() {
            "none".to_string()
        } else {
            primary_tools.join(", ")
        };

        let targets_str = if primary_targets.is_empty() {
            "none".to_string()
        } else {
            primary_targets.join(", ")
        };

        let prompt = format!(
            "Summarize this MCP server's activity in 1-2 sentences.\n\
             Server: {server_name}\n\
             Events: {event_count} in the last hour\n\
             Tools used: {tools_str}\n\
             Primary targets: {targets_str}\n\
             Anomaly level: {anomaly_score:.2}"
        );

        let raw_output = slm
            .raw_infer(&prompt)
            .await
            .context("SLM inference failed for server summary")?;

        let summary_text = raw_output.trim().to_string();
        let summary = ServerSummary {
            server_name: server_name.to_string(),
            summary: if summary_text.is_empty() {
                format!(
                    "{event_count} events in the last hour using {tools_str}. \
                     Anomaly level: {anomaly_level}."
                )
            } else {
                summary_text
            },
            event_count,
            anomaly_level: anomaly_level.to_string(),
            generated_at: Utc::now(),
        };

        // Cache the summary.
        if let Ok(mut cache) = self.cache.write() {
            cache
                .server_summaries
                .retain(|s| s.server_name != server_name);
            cache.server_summaries.push(summary.clone());
            cache.last_summary_update = Some(Utc::now());
        }

        Ok(summary)
    }

    /// Generate a human-readable anomaly explanation (rule-based, no SLM needed).
    ///
    /// Maps anomaly dimension names and scores to plain-English text.
    pub fn explain_anomaly(
        &self,
        event_id: &str,
        dimensions: &[(String, f64)],
        event_description: &str,
    ) -> AnomalyExplanation {
        let mut explanations: Vec<String> = Vec::new();
        let mut dimension_names: Vec<String> = Vec::new();

        for (dimension, score) in dimensions {
            dimension_names.push(dimension.clone());
            explanations.push(explain_dimension(dimension, *score, event_description));
        }

        let combined = if explanations.is_empty() {
            format!("Event flagged for review: {event_description}")
        } else {
            explanations.join(" ")
        };

        let explanation = AnomalyExplanation {
            event_id: event_id.to_string(),
            explanation: combined,
            anomaly_dimensions: dimension_names,
            generated_at: Utc::now(),
        };

        // Cache by event_id.
        if let Ok(mut cache) = self.cache.write() {
            cache
                .anomaly_explanations
                .retain(|e| e.event_id != event_id);
            cache.anomaly_explanations.push(explanation.clone());
        }

        explanation
    }

    /// Generate security tips based on the current system state using the SLM.
    pub async fn generate_security_tips(
        &self,
        slm: &SlmEngine,
        wrapped_count: u32,
        total_servers: u32,
        has_model: bool,
        policy_summary: &str,
    ) -> Result<Vec<SecurityTip>> {
        let model_status = if has_model {
            "loaded"
        } else {
            "not loaded"
        };

        let prompt = format!(
            "Based on this system state, provide 3 actionable security tips. \
             Each tip should be one sentence.\n\
             Wrapped servers: {wrapped_count}/{total_servers}\n\
             AI model: {model_status}\n\
             Policy: {policy_summary}\n\
             Format each tip as: [priority] tip text\n\
             Where priority is: INFO, WARNING, or ACTION_NEEDED"
        );

        let raw_output = slm
            .raw_infer(&prompt)
            .await
            .context("SLM inference failed for security tips")?;

        let tips = parse_security_tips(&raw_output);

        // Cache the tips.
        if let Ok(mut cache) = self.cache.write() {
            cache.security_tips = tips.clone();
            cache.last_tips_update = Some(Utc::now());
        }

        Ok(tips)
    }

    /// Quick risk assessment for a newly-detected MCP server using the SLM.
    pub async fn assess_new_server(
        &self,
        slm: &SlmEngine,
        server_name: &str,
        command: &str,
        args: &[String],
        capabilities: &[String],
    ) -> Result<ServerRiskAssessment> {
        let args_str = if args.is_empty() {
            "none".to_string()
        } else {
            args.join(", ")
        };

        let caps_str = if capabilities.is_empty() {
            "none".to_string()
        } else {
            capabilities.join(", ")
        };

        let prompt = format!(
            "Assess this new MCP server's risk level.\n\
             Server: {server_name}\n\
             Command: {command}\n\
             Arguments: {args_str}\n\
             Capabilities: {caps_str}\n\
             Respond in format:\n\
             RISK: LOW|MEDIUM|HIGH\n\
             REASONING: one sentence\n\
             TRUST: trusted|verified|untrusted"
        );

        let raw_output = slm
            .raw_infer(&prompt)
            .await
            .context("SLM inference failed for server assessment")?;

        let assessment = parse_server_assessment(server_name, &raw_output);

        // Cache the assessment.
        if let Ok(mut cache) = self.cache.write() {
            cache
                .server_assessments
                .retain(|a| a.server_name != server_name);
            cache.server_assessments.push(assessment.clone());
        }

        Ok(assessment)
    }

    /// Get a snapshot of all cached intelligence data.
    pub fn get_intelligence(&self) -> OfflineIntelligence {
        self.cache
            .read()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    /// Get cached server summaries.
    pub fn get_server_summaries(&self) -> Vec<ServerSummary> {
        self.cache
            .read()
            .map(|c| c.server_summaries.clone())
            .unwrap_or_default()
    }

    /// Get cached security tips.
    pub fn get_security_tips(&self) -> Vec<SecurityTip> {
        self.cache
            .read()
            .map(|c| c.security_tips.clone())
            .unwrap_or_default()
    }

    /// Get a cached anomaly explanation by event ID.
    pub fn get_anomaly_explanation(&self, event_id: &str) -> Option<AnomalyExplanation> {
        self.cache
            .read()
            .ok()
            .and_then(|c| c.anomaly_explanations.iter().find(|e| e.event_id == event_id).cloned())
    }
}

impl Default for OfflineIntelEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Rule-based anomaly dimension explanations
// ---------------------------------------------------------------------------

fn explain_dimension(dimension: &str, score: f64, _event_desc: &str) -> String {
    match dimension {
        "unknown_tool" => format!(
            "This server used an unfamiliar tool (anomaly score: {:.0}%).",
            score * 100.0
        ),
        "sensitive_target" => {
            "This access targets a sensitive location (SSH keys, credentials, or system files)."
                .to_string()
        }
        "abnormal_rate" => format!(
            "Activity rate is {:.0}x higher than the server's normal baseline.",
            score * 10.0
        ),
        "unusual_hour" => {
            "This activity occurred outside the server's normal operating hours.".to_string()
        }
        "network_anomaly" => {
            "Network connection to an unfamiliar or suspicious destination.".to_string()
        }
        "first_time_access" => {
            "This is the first time this server has accessed this resource.".to_string()
        }
        _ => format!("Unusual behavior detected in the '{}' dimension.", dimension),
    }
}

// ---------------------------------------------------------------------------
// Output parsers
// ---------------------------------------------------------------------------

/// Parse SLM output into a list of security tips.
///
/// Expected format: lines like `[INFO] tip text` or `[WARNING] tip text`.
fn parse_security_tips(raw: &str) -> Vec<SecurityTip> {
    let mut tips = Vec::new();
    let mut counter = 0u32;
    let now = Utc::now();

    // Map of recognized priority tokens -> normalized values
    let priority_map: HashMap<&str, &str> = [
        ("INFO", "info"),
        ("WARNING", "warning"),
        ("ACTION_NEEDED", "action_needed"),
    ]
    .into_iter()
    .collect();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Try to parse "[PRIORITY] tip text" format.
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(bracket_end) = rest.find(']') {
                let priority_raw = &rest[..bracket_end];
                let tip_text = rest[bracket_end + 1..].trim();

                if !tip_text.is_empty() {
                    let priority = priority_map
                        .get(priority_raw.trim().to_uppercase().as_str())
                        .copied()
                        .unwrap_or("info");

                    counter += 1;
                    tips.push(SecurityTip {
                        id: format!("tip-{counter}"),
                        tip: tip_text.to_string(),
                        priority: priority.to_string(),
                        generated_at: now,
                    });
                }
            }
        }
    }

    tips
}

/// Parse SLM output into a server risk assessment.
///
/// Expected format:
/// ```text
/// RISK: LOW|MEDIUM|HIGH
/// REASONING: one sentence
/// TRUST: trusted|verified|untrusted
/// ```
fn parse_server_assessment(server_name: &str, raw: &str) -> ServerRiskAssessment {
    let mut risk_level = "MEDIUM".to_string();
    let mut reasoning = String::new();
    let mut recommended_trust = "untrusted".to_string();

    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("RISK:") {
            let val = rest.trim().to_uppercase();
            if matches!(val.as_str(), "LOW" | "MEDIUM" | "HIGH") {
                risk_level = val;
            }
        } else if let Some(rest) = trimmed.strip_prefix("REASONING:") {
            reasoning = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("TRUST:") {
            let val = rest.trim().to_lowercase();
            if matches!(val.as_str(), "trusted" | "verified" | "untrusted") {
                recommended_trust = val;
            }
        }
    }

    if reasoning.is_empty() {
        reasoning = "Unable to determine reasoning from model output.".to_string();
    }

    ServerRiskAssessment {
        server_name: server_name.to_string(),
        risk_level,
        reasoning,
        recommended_trust,
        generated_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{MockSlmBackend, SlmConfig, SlmEngine};

    fn mock_engine_with_response(text: &str) -> SlmEngine {
        let backend = MockSlmBackend {
            response_text: text.to_string(),
            ..Default::default()
        };
        SlmEngine::new(Box::new(backend), SlmConfig::default())
    }

    // -- explain_anomaly tests --

    #[test]
    fn explain_anomaly_unknown_tool() {
        let engine = OfflineIntelEngine::new();
        let explanation = engine.explain_anomaly(
            "evt-1",
            &[("unknown_tool".to_string(), 0.85)],
            "server used execute_shell",
        );
        assert!(explanation.explanation.contains("unfamiliar tool"));
        assert!(explanation.explanation.contains("85%"));
        assert_eq!(explanation.anomaly_dimensions, vec!["unknown_tool"]);
    }

    #[test]
    fn explain_anomaly_sensitive_target() {
        let engine = OfflineIntelEngine::new();
        let explanation = engine.explain_anomaly(
            "evt-2",
            &[("sensitive_target".to_string(), 0.9)],
            "accessed ~/.ssh/id_rsa",
        );
        assert!(explanation.explanation.contains("sensitive location"));
    }

    #[test]
    fn explain_anomaly_abnormal_rate() {
        let engine = OfflineIntelEngine::new();
        let explanation = engine.explain_anomaly(
            "evt-3",
            &[("abnormal_rate".to_string(), 0.5)],
            "burst of requests",
        );
        assert!(explanation.explanation.contains("higher than"));
        assert!(explanation.explanation.contains("5x"));
    }

    #[test]
    fn explain_anomaly_unusual_hour() {
        let engine = OfflineIntelEngine::new();
        let explanation = engine.explain_anomaly(
            "evt-4",
            &[("unusual_hour".to_string(), 0.7)],
            "3am activity",
        );
        assert!(explanation.explanation.contains("outside"));
        assert!(explanation.explanation.contains("operating hours"));
    }

    #[test]
    fn explain_anomaly_network() {
        let engine = OfflineIntelEngine::new();
        let explanation = engine.explain_anomaly(
            "evt-5",
            &[("network_anomaly".to_string(), 0.6)],
            "connection to unknown host",
        );
        assert!(explanation.explanation.contains("unfamiliar or suspicious"));
    }

    #[test]
    fn explain_anomaly_first_time() {
        let engine = OfflineIntelEngine::new();
        let explanation = engine.explain_anomaly(
            "evt-6",
            &[("first_time_access".to_string(), 1.0)],
            "new resource accessed",
        );
        assert!(explanation.explanation.contains("first time"));
    }

    #[test]
    fn explain_anomaly_unknown_dimension() {
        let engine = OfflineIntelEngine::new();
        let explanation = engine.explain_anomaly(
            "evt-7",
            &[("custom_dimension".to_string(), 0.4)],
            "some event",
        );
        assert!(explanation.explanation.contains("custom_dimension"));
        assert!(explanation.explanation.contains("Unusual behavior"));
    }

    #[test]
    fn explain_anomaly_multiple_dimensions() {
        let engine = OfflineIntelEngine::new();
        let explanation = engine.explain_anomaly(
            "evt-8",
            &[
                ("unknown_tool".to_string(), 0.9),
                ("sensitive_target".to_string(), 0.8),
                ("unusual_hour".to_string(), 0.5),
            ],
            "suspicious activity",
        );
        assert!(explanation.explanation.contains("unfamiliar tool"));
        assert!(explanation.explanation.contains("sensitive location"));
        assert!(explanation.explanation.contains("operating hours"));
        assert_eq!(explanation.anomaly_dimensions.len(), 3);
    }

    #[test]
    fn explain_anomaly_empty_dimensions() {
        let engine = OfflineIntelEngine::new();
        let explanation = engine.explain_anomaly("evt-9", &[], "unknown event");
        assert!(explanation.explanation.contains("unknown event"));
        assert!(explanation.anomaly_dimensions.is_empty());
    }

    // -- OfflineIntelligence serialization --

    #[test]
    fn offline_intelligence_serialization_roundtrip() {
        let now = Utc::now();
        let intel = OfflineIntelligence {
            server_summaries: vec![ServerSummary {
                server_name: "test-server".to_string(),
                summary: "10 events, normal".to_string(),
                event_count: 10,
                anomaly_level: "normal".to_string(),
                generated_at: now,
            }],
            security_tips: vec![SecurityTip {
                id: "tip-1".to_string(),
                tip: "Wrap your servers.".to_string(),
                priority: "warning".to_string(),
                generated_at: now,
            }],
            anomaly_explanations: vec![AnomalyExplanation {
                event_id: "evt-1".to_string(),
                explanation: "Unfamiliar tool used.".to_string(),
                anomaly_dimensions: vec!["unknown_tool".to_string()],
                generated_at: now,
            }],
            server_assessments: vec![ServerRiskAssessment {
                server_name: "new-server".to_string(),
                risk_level: "MEDIUM".to_string(),
                reasoning: "Unknown command.".to_string(),
                recommended_trust: "untrusted".to_string(),
                generated_at: now,
            }],
            last_summary_update: Some(now),
            last_tips_update: Some(now),
        };

        let json = serde_json::to_string(&intel).expect("serialize");
        let parsed: OfflineIntelligence = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.server_summaries.len(), 1);
        assert_eq!(parsed.server_summaries[0].server_name, "test-server");
        assert_eq!(parsed.security_tips.len(), 1);
        assert_eq!(parsed.anomaly_explanations.len(), 1);
        assert_eq!(parsed.server_assessments.len(), 1);
        assert!(parsed.last_summary_update.is_some());
        assert!(parsed.last_tips_update.is_some());
    }

    // -- Cache tests --

    #[test]
    fn get_intelligence_returns_cached_data() {
        let engine = OfflineIntelEngine::new();

        // Generate an anomaly explanation to populate cache.
        let _ = engine.explain_anomaly(
            "evt-cache",
            &[("unknown_tool".to_string(), 0.5)],
            "test",
        );

        let intel = engine.get_intelligence();
        assert_eq!(intel.anomaly_explanations.len(), 1);
        assert_eq!(intel.anomaly_explanations[0].event_id, "evt-cache");
    }

    #[test]
    fn anomaly_explanations_cached_by_event_id() {
        let engine = OfflineIntelEngine::new();

        engine.explain_anomaly("evt-a", &[("unknown_tool".to_string(), 0.5)], "first");
        engine.explain_anomaly("evt-b", &[("sensitive_target".to_string(), 0.8)], "second");

        assert!(engine.get_anomaly_explanation("evt-a").is_some());
        assert!(engine.get_anomaly_explanation("evt-b").is_some());
        assert!(engine.get_anomaly_explanation("evt-nonexistent").is_none());

        // Verify correct content.
        let a = engine.get_anomaly_explanation("evt-a").unwrap();
        assert!(a.explanation.contains("unfamiliar tool"));

        let b = engine.get_anomaly_explanation("evt-b").unwrap();
        assert!(b.explanation.contains("sensitive location"));
    }

    #[test]
    fn anomaly_explanation_overwrites_same_event_id() {
        let engine = OfflineIntelEngine::new();

        engine.explain_anomaly("evt-dup", &[("unknown_tool".to_string(), 0.5)], "first");
        engine.explain_anomaly("evt-dup", &[("sensitive_target".to_string(), 0.9)], "updated");

        let intel = engine.get_intelligence();
        // Should have only 1 entry for evt-dup, the latest one.
        let matching: Vec<_> = intel
            .anomaly_explanations
            .iter()
            .filter(|e| e.event_id == "evt-dup")
            .collect();
        assert_eq!(matching.len(), 1);
        assert!(matching[0].explanation.contains("sensitive location"));
    }

    // -- parse_security_tips tests --

    #[test]
    fn parse_security_tips_valid() {
        let raw = "\
[INFO] Keep your model updated for best results.\n\
[WARNING] You have 2 unwrapped MCP servers.\n\
[ACTION_NEEDED] Configure a security policy for production use.";

        let tips = parse_security_tips(raw);
        assert_eq!(tips.len(), 3);

        assert_eq!(tips[0].priority, "info");
        assert!(tips[0].tip.contains("model updated"));

        assert_eq!(tips[1].priority, "warning");
        assert!(tips[1].tip.contains("unwrapped"));

        assert_eq!(tips[2].priority, "action_needed");
        assert!(tips[2].tip.contains("security policy"));
    }

    #[test]
    fn parse_security_tips_empty_input() {
        let tips = parse_security_tips("");
        assert!(tips.is_empty());
    }

    #[test]
    fn parse_security_tips_malformed_lines_skipped() {
        let raw = "Some preamble text\n\
                    [INFO] Valid tip here.\n\
                    Not a tip line\n\
                    [WARNING] Another valid tip.";
        let tips = parse_security_tips(raw);
        assert_eq!(tips.len(), 2);
    }

    #[test]
    fn parse_security_tips_unknown_priority_defaults_info() {
        let raw = "[BANANA] Some tip text.";
        let tips = parse_security_tips(raw);
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].priority, "info");
    }

    // -- parse_server_assessment tests --

    #[test]
    fn parse_server_assessment_valid() {
        let raw = "RISK: HIGH\nREASONING: Runs arbitrary shell commands.\nTRUST: untrusted";
        let assessment = parse_server_assessment("dangerous-server", raw);
        assert_eq!(assessment.server_name, "dangerous-server");
        assert_eq!(assessment.risk_level, "HIGH");
        assert!(assessment.reasoning.contains("shell commands"));
        assert_eq!(assessment.recommended_trust, "untrusted");
    }

    #[test]
    fn parse_server_assessment_low_risk() {
        let raw = "RISK: LOW\nREASONING: Read-only file server.\nTRUST: trusted";
        let assessment = parse_server_assessment("safe-server", raw);
        assert_eq!(assessment.risk_level, "LOW");
        assert_eq!(assessment.recommended_trust, "trusted");
    }

    #[test]
    fn parse_server_assessment_defaults_on_garbage() {
        let raw = "I don't understand the question.";
        let assessment = parse_server_assessment("unknown", raw);
        assert_eq!(assessment.risk_level, "MEDIUM");
        assert_eq!(assessment.recommended_trust, "untrusted");
        assert!(assessment.reasoning.contains("Unable to determine"));
    }

    #[test]
    fn parse_server_assessment_invalid_risk_ignored() {
        let raw = "RISK: BANANA\nREASONING: Weird server.\nTRUST: verified";
        let assessment = parse_server_assessment("weird-server", raw);
        // Invalid risk level should keep the default MEDIUM.
        assert_eq!(assessment.risk_level, "MEDIUM");
        assert_eq!(assessment.recommended_trust, "verified");
    }

    // -- Async SLM integration tests --

    #[tokio::test]
    async fn generate_server_summary_with_mock_slm() {
        let slm = mock_engine_with_response(
            "34 tool calls in the last hour, primarily file reads in ~/project/. Normal pattern.",
        );
        let engine = OfflineIntelEngine::new();

        let summary = engine
            .generate_server_summary(
                &slm,
                "filesystem-server",
                34,
                &["read_file".to_string(), "list_dir".to_string()],
                &["~/project/".to_string()],
                0.1,
            )
            .await
            .unwrap();

        assert_eq!(summary.server_name, "filesystem-server");
        assert_eq!(summary.event_count, 34);
        assert_eq!(summary.anomaly_level, "normal");
        assert!(!summary.summary.is_empty());

        // Verify it was cached.
        let summaries = engine.get_server_summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].server_name, "filesystem-server");
    }

    #[tokio::test]
    async fn generate_server_summary_elevated_anomaly() {
        let slm = mock_engine_with_response("Elevated activity detected.");
        let engine = OfflineIntelEngine::new();

        let summary = engine
            .generate_server_summary(&slm, "test-server", 100, &[], &[], 0.5)
            .await
            .unwrap();

        assert_eq!(summary.anomaly_level, "elevated");
    }

    #[tokio::test]
    async fn generate_server_summary_high_anomaly() {
        let slm = mock_engine_with_response("High anomaly detected.");
        let engine = OfflineIntelEngine::new();

        let summary = engine
            .generate_server_summary(&slm, "suspicious-server", 200, &[], &[], 0.8)
            .await
            .unwrap();

        assert_eq!(summary.anomaly_level, "high");
    }

    #[tokio::test]
    async fn assess_new_server_with_mock_slm() {
        let slm = mock_engine_with_response(
            "RISK: HIGH\nREASONING: Executes arbitrary commands.\nTRUST: untrusted",
        );
        let engine = OfflineIntelEngine::new();

        let assessment = engine
            .assess_new_server(
                &slm,
                "shell-server",
                "/bin/bash",
                &["-c".to_string(), "server.sh".to_string()],
                &["execute_command".to_string(), "read_file".to_string()],
            )
            .await
            .unwrap();

        assert_eq!(assessment.server_name, "shell-server");
        assert_eq!(assessment.risk_level, "HIGH");
        assert_eq!(assessment.recommended_trust, "untrusted");
        assert!(!assessment.reasoning.is_empty());

        // Verify it was cached.
        let intel = engine.get_intelligence();
        assert_eq!(intel.server_assessments.len(), 1);
    }

    #[tokio::test]
    async fn generate_security_tips_with_mock_slm() {
        let slm = mock_engine_with_response(
            "[INFO] Keep your model updated for best results.\n\
             [WARNING] You have 2 unwrapped MCP servers. Wrapping them adds proxy protection.\n\
             [ACTION_NEEDED] Configure a security policy before production use.",
        );
        let engine = OfflineIntelEngine::new();

        let tips = engine
            .generate_security_tips(&slm, 3, 5, true, "default policy")
            .await
            .unwrap();

        assert_eq!(tips.len(), 3);
        assert_eq!(tips[0].priority, "info");
        assert_eq!(tips[1].priority, "warning");
        assert_eq!(tips[2].priority, "action_needed");

        // Verify cached.
        let cached_tips = engine.get_security_tips();
        assert_eq!(cached_tips.len(), 3);
    }

    #[tokio::test]
    async fn server_summary_replaces_old_entry_for_same_server() {
        let slm = mock_engine_with_response("First summary.");
        let engine = OfflineIntelEngine::new();

        engine
            .generate_server_summary(&slm, "my-server", 10, &[], &[], 0.1)
            .await
            .unwrap();

        let slm2 = mock_engine_with_response("Updated summary.");
        engine
            .generate_server_summary(&slm2, "my-server", 20, &[], &[], 0.2)
            .await
            .unwrap();

        let summaries = engine.get_server_summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].event_count, 20);
    }

    #[tokio::test]
    async fn assess_new_server_replaces_old_entry_for_same_server() {
        let slm = mock_engine_with_response("RISK: LOW\nREASONING: Safe.\nTRUST: trusted");
        let engine = OfflineIntelEngine::new();

        engine
            .assess_new_server(&slm, "server-a", "node", &[], &[])
            .await
            .unwrap();
        engine
            .assess_new_server(&slm, "server-a", "node", &["--unsafe".to_string()], &[])
            .await
            .unwrap();

        let intel = engine.get_intelligence();
        let matching: Vec<_> = intel
            .server_assessments
            .iter()
            .filter(|a| a.server_name == "server-a")
            .collect();
        assert_eq!(matching.len(), 1);
    }

    #[tokio::test]
    async fn generate_server_summary_empty_slm_output_falls_back() {
        let slm = mock_engine_with_response("");
        let engine = OfflineIntelEngine::new();

        let summary = engine
            .generate_server_summary(
                &slm,
                "fallback-server",
                5,
                &["read_file".to_string()],
                &["/tmp".to_string()],
                0.1,
            )
            .await
            .unwrap();

        // Should produce a fallback summary instead of empty string.
        assert!(!summary.summary.is_empty());
        assert!(summary.summary.contains("5 events"));
    }
}
