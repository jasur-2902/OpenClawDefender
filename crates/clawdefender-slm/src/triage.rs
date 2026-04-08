//! Two-tier triage prompt system for fast event classification.
//!
//! Tier 1 (triage): A minimal prompt classifies events as ROUTINE, NOTABLE,
//! or SUSPICIOUS in under 1 second. Only SUSPICIOUS events proceed to Tier 2.
//!
//! Tier 2 (deep analysis): A full security analysis prompt produces structured
//! risk assessment with reasoning and recommended actions.

use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::analyzer::AnalysisRequest;
use crate::engine::{RiskLevel, SlmEngine};

// ── Types ────────────────────────────────────────────────────────────────

/// Triage classification level from the fast Tier-1 pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriageLevel {
    /// Known-safe pattern, skip further analysis.
    Routine,
    /// Unusual but not threatening, log only.
    Notable,
    /// Potential security threat, needs deep analysis.
    Suspicious,
}

impl std::fmt::Display for TriageLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriageLevel::Routine => write!(f, "ROUTINE"),
            TriageLevel::Notable => write!(f, "NOTABLE"),
            TriageLevel::Suspicious => write!(f, "SUSPICIOUS"),
        }
    }
}

/// Full deep-analysis result produced by Tier 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepAnalysis {
    pub risk_level: RiskLevel,
    pub confidence: f32,
    pub reasoning: String,
    pub recommended_action: String,
    pub context_used: bool,
}

/// Result of the two-tier triage pipeline.
#[derive(Debug)]
pub enum TriageResult {
    /// ROUTINE -- no further action needed.
    Skip,
    /// NOTABLE -- log with brief note but no alert.
    LogOnly(TriageLevel),
    /// SUSPICIOUS -- full analysis completed, alert recommended.
    Alert(Box<DeepAnalysis>),
}

/// Input data for the triage pipeline, derived from security events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageInput {
    pub server_name: String,
    pub tool_name: Option<String>,
    pub action_type: String,
    pub target: Option<String>,
    pub anomaly_score: f64,
    pub has_kill_chain: bool,
    /// Full event details used only for deep analysis (Tier 2).
    pub event_details: String,
}

// ── Conversions ──────────────────────────────────────────────────────────

impl From<&AnalysisRequest> for TriageInput {
    fn from(req: &AnalysisRequest) -> Self {
        use crate::analyzer::AnalysisEventType;

        let (tool_name, action_type, target, event_details) = match &req.event_type {
            AnalysisEventType::McpToolCall {
                tool_name,
                arguments,
            } => (
                Some(tool_name.clone()),
                "tool_call".to_string(),
                arguments.get("path").and_then(|v| v.as_str()).map(String::from)
                    .or_else(|| arguments.get("uri").and_then(|v| v.as_str()).map(String::from)),
                format!("Tool: {} Args: {}", tool_name, arguments),
            ),
            AnalysisEventType::McpResourceRead { uri } => (
                None,
                "resource_read".to_string(),
                Some(uri.clone()),
                format!("Resource read: {}", uri),
            ),
            AnalysisEventType::McpSampling { content } => (
                None,
                "sampling".to_string(),
                None,
                format!("Sampling: {}", content),
            ),
            AnalysisEventType::UncorrelatedOsActivity { description } => (
                None,
                "os_activity".to_string(),
                None,
                format!("OS activity: {}", description),
            ),
        };

        TriageInput {
            server_name: req.server_name.clone(),
            tool_name,
            action_type,
            target,
            anomaly_score: 0.0,
            has_kill_chain: false,
            event_details,
        }
    }
}

// ── Prompts ──────────────────────────────────────────────────────────────

/// Minimal system prompt for Tier-1 triage (~100 tokens). Hardcoded, never
/// constructed from user data.
pub const TRIAGE_SYSTEM_PROMPT: &str = "\
You are a security event classifier. Classify this event as exactly one word:
ROUTINE - Normal expected behavior, known-safe patterns
NOTABLE - Unusual but not threatening, worth logging
SUSPICIOUS - Potential security threat, needs investigation

Respond with only one word: ROUTINE, NOTABLE, or SUSPICIOUS";

/// System prompt for Tier-2 deep analysis. Hardcoded.
pub const DEEP_ANALYSIS_SYSTEM_PROMPT: &str = "\
You are a security analyst for ClawDefender. Analyze the event and respond in this exact format:
RISK: <LOW|MEDIUM|HIGH|CRITICAL>
CONFIDENCE: <0.0-1.0>
REASONING: <2-3 sentences explaining why>
ACTION: <allow|monitor|investigate|block>";

/// Build a compact triage prompt from event data (Tier 1).
///
/// Format: `server:{name} tool:{tool} action:{action} target:{target} anomaly:{score} killchain:{yes/no}`
pub fn build_triage_prompt(event: &TriageInput) -> String {
    format!(
        "{}\n\nserver:{} tool:{} action:{} target:{} anomaly:{:.2} killchain:{}",
        TRIAGE_SYSTEM_PROMPT,
        event.server_name,
        event.tool_name.as_deref().unwrap_or("none"),
        event.action_type,
        event.target.as_deref().unwrap_or("none"),
        event.anomaly_score,
        if event.has_kill_chain { "yes" } else { "no" },
    )
}

/// Build a full deep-analysis prompt from event data (Tier 2).
///
/// Includes the system prompt, full event details, and optional context.
pub fn build_deep_analysis_prompt(event: &TriageInput, context: Option<&str>) -> String {
    let mut prompt = String::with_capacity(1024);
    prompt.push_str(DEEP_ANALYSIS_SYSTEM_PROMPT);
    prompt.push_str("\n\n");
    prompt.push_str("Server: ");
    prompt.push_str(&event.server_name);
    prompt.push('\n');
    if let Some(tool) = &event.tool_name {
        prompt.push_str("Tool: ");
        prompt.push_str(tool);
        prompt.push('\n');
    }
    prompt.push_str("Action: ");
    prompt.push_str(&event.action_type);
    prompt.push('\n');
    if let Some(target) = &event.target {
        prompt.push_str("Target: ");
        prompt.push_str(target);
        prompt.push('\n');
    }
    prompt.push_str(&format!("Anomaly Score: {:.2}\n", event.anomaly_score));
    prompt.push_str(&format!(
        "Kill Chain Match: {}\n",
        if event.has_kill_chain { "yes" } else { "no" }
    ));
    prompt.push_str("\nEvent Details:\n");
    prompt.push_str(&event.event_details);

    if let Some(ctx) = context {
        prompt.push_str("\n\nContext Window:\n");
        prompt.push_str(ctx);
    }

    prompt
}

// ── Parsers ──────────────────────────────────────────────────────────────

/// Parse the model's triage output (one word) into a [`TriageLevel`].
///
/// Fail-closed: defaults to `Suspicious` on unrecognized output.
///
/// Also handles `RISK: LOW/MEDIUM/HIGH/CRITICAL` format from the heuristic
/// backend, mapping them to triage levels for compatibility.
pub fn parse_triage_output(raw: &str) -> TriageLevel {
    let upper = raw.trim().to_uppercase();

    // Primary: look for explicit triage keywords.
    if upper.contains("ROUTINE") {
        TriageLevel::Routine
    } else if upper.contains("NOTABLE") {
        TriageLevel::Notable
    } else if upper.contains("SUSPICIOUS") {
        TriageLevel::Suspicious
    }
    // Secondary: map RISK: levels (from heuristic backend).
    else if upper.contains("RISK: LOW") {
        TriageLevel::Routine
    } else if upper.contains("RISK: MEDIUM") {
        TriageLevel::Notable
    } else if upper.contains("RISK: HIGH") || upper.contains("RISK: CRITICAL") {
        TriageLevel::Suspicious
    } else {
        // Fail-closed: if we can't parse, treat as suspicious.
        TriageLevel::Suspicious
    }
}

/// Parse the model's deep-analysis output into a [`DeepAnalysis`].
///
/// Expected format:
/// ```text
/// RISK: HIGH
/// CONFIDENCE: 0.85
/// REASONING: Two to three sentences.
/// ACTION: investigate
/// ```
///
/// Fail-closed: defaults to High risk with 0.5 confidence on parse failure.
pub fn parse_deep_analysis_output(raw: &str) -> DeepAnalysis {
    let mut risk_level = RiskLevel::High;
    let mut confidence: f32 = 0.5;
    let mut reasoning = String::new();
    let mut recommended_action = String::from("investigate");

    for line in raw.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("RISK:") {
            risk_level = match rest.trim().to_uppercase().as_str() {
                "LOW" => RiskLevel::Low,
                "MEDIUM" => RiskLevel::Medium,
                "HIGH" => RiskLevel::High,
                "CRITICAL" => RiskLevel::Critical,
                _ => RiskLevel::High,
            };
        } else if let Some(rest) = line.strip_prefix("CONFIDENCE:") {
            confidence = rest
                .trim()
                .parse::<f32>()
                .unwrap_or(0.5)
                .clamp(0.0, 1.0);
        } else if let Some(rest) = line.strip_prefix("REASONING:") {
            reasoning = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("ACTION:") {
            let action = rest.trim().to_lowercase();
            recommended_action = match action.as_str() {
                "allow" | "monitor" | "investigate" | "block" => action,
                _ => "investigate".to_string(),
            };
        }
    }

    if reasoning.is_empty() {
        reasoning = "Unable to parse reasoning from model output.".to_string();
    }

    DeepAnalysis {
        risk_level,
        confidence,
        reasoning,
        recommended_action,
        context_used: false,
    }
}

// ── Triage engine ────────────────────────────────────────────────────────

/// Two-tier triage engine that routes events through fast classification
/// and optional deep analysis.
pub struct TriageEngine {
    slm: Arc<SlmEngine>,
}

impl TriageEngine {
    /// Create a new triage engine wrapping the given SLM engine.
    pub fn new(slm: Arc<SlmEngine>) -> Self {
        Self { slm }
    }

    /// Run the two-tier triage pipeline on an event.
    ///
    /// Tier 1: Fast triage classification (<1s target).
    /// Tier 2: Deep analysis for SUSPICIOUS events only (<5s target).
    pub async fn triage(&self, input: &TriageInput) -> Result<TriageResult> {
        let level = self.run_triage(input).await?;
        match level {
            TriageLevel::Routine => Ok(TriageResult::Skip),
            TriageLevel::Notable => Ok(TriageResult::LogOnly(level)),
            TriageLevel::Suspicious => {
                let analysis = self.run_deep_analysis(input, None).await?;
                Ok(TriageResult::Alert(Box::new(analysis)))
            }
        }
    }

    /// Run Tier-1 classification only, returning the triage level.
    ///
    /// Use this when you need to control the triage flow manually
    /// (e.g., in the pipeline where context enrichment happens between tiers).
    pub async fn classify(&self, input: &TriageInput) -> Result<TriageLevel> {
        self.run_triage(input).await
    }

    /// Run Tier-2 deep analysis with optional context enrichment.
    ///
    /// Call this after [`classify()`] returns [`TriageLevel::Suspicious`] to get
    /// a detailed risk assessment with reasoning.
    pub async fn deep_analyze(
        &self,
        input: &TriageInput,
        context: Option<&str>,
    ) -> Result<DeepAnalysis> {
        self.run_deep_analysis(input, context).await
    }

    /// Run Tier-1 fast triage classification.
    async fn run_triage(&self, input: &TriageInput) -> Result<TriageLevel> {
        let prompt = build_triage_prompt(input);
        let raw = self.slm.raw_infer(&prompt).await?;
        Ok(parse_triage_output(&raw))
    }

    /// Run Tier-2 deep analysis.
    async fn run_deep_analysis(
        &self,
        input: &TriageInput,
        context: Option<&str>,
    ) -> Result<DeepAnalysis> {
        let prompt = build_deep_analysis_prompt(input, context);
        let raw = self.slm.raw_infer(&prompt).await?;
        let mut analysis = parse_deep_analysis_output(&raw);
        analysis.context_used = context.is_some();
        Ok(analysis)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{
        AnalysisContext, AnalysisEventType, AnalysisRequest, ServerReputation,
    };
    use crate::engine::{MockSlmBackend, SlmConfig};

    // -- parse_triage_output tests --

    #[test]
    fn parse_triage_routine() {
        assert_eq!(parse_triage_output("ROUTINE"), TriageLevel::Routine);
    }

    #[test]
    fn parse_triage_notable() {
        assert_eq!(parse_triage_output("NOTABLE"), TriageLevel::Notable);
    }

    #[test]
    fn parse_triage_suspicious() {
        assert_eq!(parse_triage_output("SUSPICIOUS"), TriageLevel::Suspicious);
    }

    #[test]
    fn parse_triage_case_insensitive() {
        assert_eq!(parse_triage_output("routine"), TriageLevel::Routine);
        assert_eq!(parse_triage_output("Notable"), TriageLevel::Notable);
        assert_eq!(parse_triage_output("suspicious"), TriageLevel::Suspicious);
    }

    #[test]
    fn parse_triage_garbage_defaults_suspicious() {
        assert_eq!(
            parse_triage_output("I don't know what to say"),
            TriageLevel::Suspicious
        );
    }

    #[test]
    fn parse_triage_empty_defaults_suspicious() {
        assert_eq!(parse_triage_output(""), TriageLevel::Suspicious);
    }

    #[test]
    fn parse_triage_with_preamble() {
        assert_eq!(
            parse_triage_output("Let me think about this... ROUTINE"),
            TriageLevel::Routine
        );
        assert_eq!(
            parse_triage_output("Based on my analysis: NOTABLE"),
            TriageLevel::Notable
        );
    }

    #[test]
    fn parse_triage_with_extra_whitespace() {
        assert_eq!(parse_triage_output("  ROUTINE  \n"), TriageLevel::Routine);
    }

    // -- parse_deep_analysis_output tests --

    #[test]
    fn parse_deep_valid_output() {
        let raw = "RISK: HIGH\nCONFIDENCE: 0.85\nREASONING: This tool accesses sensitive files outside the project directory. The target path suggests credential harvesting.\nACTION: block";
        let analysis = parse_deep_analysis_output(raw);
        assert_eq!(analysis.risk_level, RiskLevel::High);
        assert!((analysis.confidence - 0.85).abs() < 0.01);
        assert!(analysis.reasoning.contains("sensitive files"));
        assert_eq!(analysis.recommended_action, "block");
    }

    #[test]
    fn parse_deep_low_risk() {
        let raw = "RISK: LOW\nCONFIDENCE: 0.92\nREASONING: Normal file read in project directory.\nACTION: allow";
        let analysis = parse_deep_analysis_output(raw);
        assert_eq!(analysis.risk_level, RiskLevel::Low);
        assert_eq!(analysis.recommended_action, "allow");
    }

    #[test]
    fn parse_deep_critical_risk() {
        let raw = "RISK: CRITICAL\nCONFIDENCE: 0.98\nREASONING: Data exfiltration attempt detected.\nACTION: block";
        let analysis = parse_deep_analysis_output(raw);
        assert_eq!(analysis.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn parse_deep_missing_fields_defaults() {
        let raw = "RISK: MEDIUM\nSome extra text here";
        let analysis = parse_deep_analysis_output(raw);
        assert_eq!(analysis.risk_level, RiskLevel::Medium);
        assert!((analysis.confidence - 0.5).abs() < 0.01);
        assert_eq!(analysis.recommended_action, "investigate");
        assert!(analysis.reasoning.contains("Unable to parse"));
    }

    #[test]
    fn parse_deep_empty_defaults_high() {
        let analysis = parse_deep_analysis_output("");
        assert_eq!(analysis.risk_level, RiskLevel::High);
        assert!((analysis.confidence - 0.5).abs() < 0.01);
    }

    #[test]
    fn parse_deep_unknown_action_defaults_investigate() {
        let raw = "RISK: LOW\nCONFIDENCE: 0.9\nREASONING: Looks fine.\nACTION: obliterate";
        let analysis = parse_deep_analysis_output(raw);
        assert_eq!(analysis.recommended_action, "investigate");
    }

    #[test]
    fn parse_deep_confidence_clamped() {
        let raw = "RISK: LOW\nCONFIDENCE: 5.0\nREASONING: Fine.\nACTION: allow";
        let analysis = parse_deep_analysis_output(raw);
        assert!((analysis.confidence - 1.0).abs() < 0.01);

        let raw2 = "RISK: LOW\nCONFIDENCE: -0.5\nREASONING: Fine.\nACTION: allow";
        let analysis2 = parse_deep_analysis_output(raw2);
        assert!((analysis2.confidence - 0.0).abs() < 0.01);
    }

    // -- build_triage_prompt tests --

    #[test]
    fn build_triage_prompt_compact_format() {
        let input = TriageInput {
            server_name: "fs-server".to_string(),
            tool_name: Some("read_file".to_string()),
            action_type: "tool_call".to_string(),
            target: Some("/etc/passwd".to_string()),
            anomaly_score: 0.87,
            has_kill_chain: true,
            event_details: "Full details here".to_string(),
        };
        let prompt = build_triage_prompt(&input);

        assert!(prompt.contains("server:fs-server"));
        assert!(prompt.contains("tool:read_file"));
        assert!(prompt.contains("action:tool_call"));
        assert!(prompt.contains("target:/etc/passwd"));
        assert!(prompt.contains("anomaly:0.87"));
        assert!(prompt.contains("killchain:yes"));
        // Should include the system prompt
        assert!(prompt.contains(TRIAGE_SYSTEM_PROMPT));
        // Should NOT include full event details (that's for deep analysis)
        assert!(!prompt.contains("Full details here"));
    }

    #[test]
    fn build_triage_prompt_none_fields() {
        let input = TriageInput {
            server_name: "test".to_string(),
            tool_name: None,
            action_type: "os_activity".to_string(),
            target: None,
            anomaly_score: 0.0,
            has_kill_chain: false,
            event_details: String::new(),
        };
        let prompt = build_triage_prompt(&input);
        assert!(prompt.contains("tool:none"));
        assert!(prompt.contains("target:none"));
        assert!(prompt.contains("killchain:no"));
    }

    // -- build_deep_analysis_prompt tests --

    #[test]
    fn build_deep_prompt_includes_details() {
        let input = TriageInput {
            server_name: "fs-server".to_string(),
            tool_name: Some("write_file".to_string()),
            action_type: "tool_call".to_string(),
            target: Some("/etc/hosts".to_string()),
            anomaly_score: 0.95,
            has_kill_chain: false,
            event_details: "Writing to system hosts file".to_string(),
        };
        let prompt = build_deep_analysis_prompt(&input, None);

        assert!(prompt.contains(DEEP_ANALYSIS_SYSTEM_PROMPT));
        assert!(prompt.contains("Server: fs-server"));
        assert!(prompt.contains("Tool: write_file"));
        assert!(prompt.contains("Target: /etc/hosts"));
        assert!(prompt.contains("Writing to system hosts file"));
        assert!(!prompt.contains("Context Window:"));
    }

    #[test]
    fn build_deep_prompt_with_context() {
        let input = TriageInput {
            server_name: "test".to_string(),
            tool_name: None,
            action_type: "os_activity".to_string(),
            target: None,
            anomaly_score: 0.5,
            has_kill_chain: false,
            event_details: "Process spawned".to_string(),
        };
        let prompt =
            build_deep_analysis_prompt(&input, Some("Previous: 3 file reads in /tmp"));

        assert!(prompt.contains("Context Window:"));
        assert!(prompt.contains("Previous: 3 file reads in /tmp"));
    }

    // -- From<&AnalysisRequest> for TriageInput tests --

    #[test]
    fn from_analysis_request_tool_call() {
        let req = AnalysisRequest {
            event_type: AnalysisEventType::McpToolCall {
                tool_name: "shell_exec".to_string(),
                arguments: serde_json::json!({"path": "/usr/bin/curl"}),
            },
            server_name: "code-server".to_string(),
            client_name: "cursor".to_string(),
            context: AnalysisContext {
                recent_events: vec![],
                server_reputation: ServerReputation::default(),
            },
        };
        let input = TriageInput::from(&req);
        assert_eq!(input.server_name, "code-server");
        assert_eq!(input.tool_name.as_deref(), Some("shell_exec"));
        assert_eq!(input.action_type, "tool_call");
        assert_eq!(input.target.as_deref(), Some("/usr/bin/curl"));
    }

    #[test]
    fn from_analysis_request_resource_read() {
        let req = AnalysisRequest {
            event_type: AnalysisEventType::McpResourceRead {
                uri: "file:///etc/shadow".to_string(),
            },
            server_name: "fs-server".to_string(),
            client_name: "claude".to_string(),
            context: AnalysisContext {
                recent_events: vec![],
                server_reputation: ServerReputation::default(),
            },
        };
        let input = TriageInput::from(&req);
        assert_eq!(input.action_type, "resource_read");
        assert_eq!(input.target.as_deref(), Some("file:///etc/shadow"));
        assert!(input.tool_name.is_none());
    }

    // -- TriageEngine routing tests --

    fn make_triage_input() -> TriageInput {
        TriageInput {
            server_name: "test-server".to_string(),
            tool_name: Some("test_tool".to_string()),
            action_type: "tool_call".to_string(),
            target: Some("/tmp/test".to_string()),
            anomaly_score: 0.5,
            has_kill_chain: false,
            event_details: "Test event".to_string(),
        }
    }

    #[tokio::test]
    async fn triage_engine_routine_returns_skip() {
        let backend = MockSlmBackend {
            response_text: "ROUTINE".to_string(),
            ..Default::default()
        };
        let engine = Arc::new(SlmEngine::new(Box::new(backend), SlmConfig::default()));
        let triage = TriageEngine::new(engine);
        let result = triage.triage(&make_triage_input()).await.unwrap();
        assert!(matches!(result, TriageResult::Skip));
    }

    #[tokio::test]
    async fn triage_engine_notable_returns_log_only() {
        let backend = MockSlmBackend {
            response_text: "NOTABLE".to_string(),
            ..Default::default()
        };
        let engine = Arc::new(SlmEngine::new(Box::new(backend), SlmConfig::default()));
        let triage = TriageEngine::new(engine);
        let result = triage.triage(&make_triage_input()).await.unwrap();
        assert!(matches!(result, TriageResult::LogOnly(TriageLevel::Notable)));
    }

    #[tokio::test]
    async fn triage_engine_suspicious_returns_alert() {
        // For SUSPICIOUS, the engine calls raw_infer twice: once for triage, once for deep analysis.
        // The MockSlmBackend returns the same text for both calls. The first call sees "SUSPICIOUS"
        // and the second call also gets "SUSPICIOUS", which parse_deep_analysis_output will treat
        // as an unparseable response, falling back to High/investigate defaults. That's correct
        // fail-closed behavior.
        let backend = MockSlmBackend {
            response_text: "SUSPICIOUS".to_string(),
            ..Default::default()
        };
        let engine = Arc::new(SlmEngine::new(Box::new(backend), SlmConfig::default()));
        let triage = TriageEngine::new(engine);
        let result = triage.triage(&make_triage_input()).await.unwrap();
        match result {
            TriageResult::Alert(analysis) => {
                // Fail-closed defaults since "SUSPICIOUS" isn't valid deep analysis output
                assert_eq!(analysis.risk_level, RiskLevel::High);
                assert_eq!(analysis.recommended_action, "investigate");
            }
            _ => panic!("Expected TriageResult::Alert"),
        }
    }

    #[tokio::test]
    async fn triage_engine_suspicious_with_deep_analysis() {
        // Use a backend that returns different content for the two phases.
        // Since MockSlmBackend always returns the same text, we test the deep analysis parser
        // with a proper deep analysis response format.
        let backend = MockSlmBackend {
            // This will be parsed by BOTH triage and deep analysis.
            // Triage: doesn't match ROUTINE or NOTABLE, so defaults to SUSPICIOUS. Good.
            // Deep analysis: parses RISK/CONFIDENCE/REASONING/ACTION fields.
            response_text: "RISK: CRITICAL\nCONFIDENCE: 0.95\nREASONING: Data exfiltration via curl.\nACTION: block".to_string(),
            ..Default::default()
        };
        let engine = Arc::new(SlmEngine::new(Box::new(backend), SlmConfig::default()));
        let triage = TriageEngine::new(engine);
        let result = triage.triage(&make_triage_input()).await.unwrap();
        match result {
            TriageResult::Alert(analysis) => {
                assert_eq!(analysis.risk_level, RiskLevel::Critical);
                assert!((analysis.confidence - 0.95).abs() < 0.01);
                assert!(analysis.reasoning.contains("exfiltration"));
                assert_eq!(analysis.recommended_action, "block");
            }
            _ => panic!("Expected TriageResult::Alert"),
        }
    }

    // -- TriageLevel display --

    #[test]
    fn triage_level_display() {
        assert_eq!(format!("{}", TriageLevel::Routine), "ROUTINE");
        assert_eq!(format!("{}", TriageLevel::Notable), "NOTABLE");
        assert_eq!(format!("{}", TriageLevel::Suspicious), "SUSPICIOUS");
    }

    // -- DeepAnalysis context_used --

    #[test]
    fn deep_analysis_context_used_default() {
        let analysis = parse_deep_analysis_output("RISK: LOW\nCONFIDENCE: 0.9\nREASONING: Safe.\nACTION: allow");
        assert!(!analysis.context_used);
    }
}
