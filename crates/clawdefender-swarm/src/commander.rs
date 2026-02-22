//! Swarm Commander: dispatches to specialist agents in parallel and synthesizes findings.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;

use crate::cost::{CostTracker, PricingTable, UsageRecord};
use crate::llm_client::{LlmClient, LlmRequest, LlmResponse};
use crate::prompts::{
    build_forensics_prompt, build_hawk_prompt, build_internal_affairs_prompt,
    parse_specialist_response, SpecialistPrompt, SpecialistReport, SwarmEventData,
};

use crate::keychain::Provider;

/// Overall timeout for all specialist calls (seconds).
const OVERALL_TIMEOUT_SECS: u64 = 10;

/// Default model used for specialist calls.
const DEFAULT_MODEL: &str = "claude-sonnet-4-20250514";

/// Final synthesized verdict from the swarm.
#[derive(Debug, Clone)]
pub struct SwarmVerdict {
    pub risk_level: String,
    pub explanation: String,
    pub recommended_action: String,
    pub confidence: f32,
    pub specialist_reports: Vec<SpecialistReport>,
    pub total_input_tokens: u32,
    pub total_output_tokens: u32,
    pub estimated_cost_usd: f64,
    pub total_latency_ms: u64,
}

/// The Commander dispatches to 3 specialist agents and synthesizes their findings.
pub struct Commander {
    client: Arc<dyn LlmClient>,
    cost_tracker: Option<Arc<Mutex<CostTracker>>>,
}

impl Commander {
    pub fn new(client: Arc<dyn LlmClient>, cost_tracker: Option<Arc<Mutex<CostTracker>>>) -> Self {
        Self {
            client,
            cost_tracker,
        }
    }

    /// Get a reference to the LLM client (for sharing with ChatManager).
    pub fn llm_client(&self) -> Arc<dyn LlmClient> {
        Arc::clone(&self.client)
    }

    /// Get a reference to the cost tracker (for sharing with ChatManager).
    pub fn cost_tracker(&self) -> Option<Arc<Mutex<CostTracker>>> {
        self.cost_tracker.clone()
    }

    /// Analyze an MCP event by dispatching to all 3 specialists in parallel.
    pub async fn analyze(&self, event: &SwarmEventData) -> Result<SwarmVerdict> {
        let start = Instant::now();

        // Build prompts for each specialist
        let hawk_prompt = build_hawk_prompt(event);
        let forensics_prompt = build_forensics_prompt(event);
        let ia_prompt = build_internal_affairs_prompt(event);

        // Dispatch all 3 in parallel with overall timeout
        let hawk_fut = self.call_specialist(hawk_prompt);
        let forensics_fut = self.call_specialist(forensics_prompt);
        let ia_fut = self.call_specialist(ia_prompt);

        let timeout_duration = std::time::Duration::from_secs(OVERALL_TIMEOUT_SECS);
        let results = tokio::time::timeout(timeout_duration, async {
            tokio::join!(hawk_fut, forensics_fut, ia_fut)
        })
        .await;

        let (hawk_resp, forensics_resp, ia_resp) = match results {
            Ok(r) => r,
            Err(_) => {
                // Overall timeout — all specialists get fallback
                let fallback = LlmResponse::fallback(DEFAULT_MODEL);
                (fallback.clone(), fallback.clone(), fallback)
            }
        };

        // Parse specialist responses
        let hawk_report = parse_specialist_response(&hawk_resp.content);
        let forensics_report = parse_specialist_response(&forensics_resp.content);
        let ia_report = parse_specialist_response(&ia_resp.content);

        let reports = vec![hawk_report, forensics_report, ia_report];
        let responses = [&hawk_resp, &forensics_resp, &ia_resp];
        let specialist_names = ["hawk", "forensics", "internal_affairs"];

        // Record cost for each specialist
        let pricing = PricingTable::default();
        let mut total_input_tokens: u32 = 0;
        let mut total_output_tokens: u32 = 0;
        let mut estimated_cost_usd: f64 = 0.0;

        for (i, resp) in responses.iter().enumerate() {
            total_input_tokens += resp.input_tokens;
            total_output_tokens += resp.output_tokens;
            let cost = pricing.estimate_cost(&resp.model, resp.input_tokens, resp.output_tokens);
            estimated_cost_usd += cost;

            if let Some(ref tracker) = self.cost_tracker {
                let record = UsageRecord {
                    timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
                    provider: "anthropic".to_string(),
                    model: resp.model.clone(),
                    input_tokens: resp.input_tokens,
                    output_tokens: resp.output_tokens,
                    estimated_cost_usd: cost,
                    event_id: None,
                    specialist: Some(specialist_names[i].to_string()),
                };
                let _ = tracker.lock().unwrap().record_usage(&record);
            }
        }

        // Synthesize verdict
        let (risk_level, explanation, recommended_action, confidence) = synthesize(&reports);
        let total_latency_ms = start.elapsed().as_millis() as u64;

        Ok(SwarmVerdict {
            risk_level,
            explanation,
            recommended_action,
            confidence,
            specialist_reports: reports,
            total_input_tokens,
            total_output_tokens,
            estimated_cost_usd,
            total_latency_ms,
        })
    }

    /// Call a single specialist, returning a fallback response on error.
    async fn call_specialist(&self, prompt: SpecialistPrompt) -> LlmResponse {
        let request = LlmRequest {
            provider: Provider::Anthropic,
            model: DEFAULT_MODEL.to_string(),
            system_prompt: prompt.system_prompt,
            user_prompt: prompt.user_prompt,
            max_tokens: 1024,
            temperature: 0.0,
        };

        match self.client.complete(&request).await {
            Ok(resp) => resp,
            Err(_) => LlmResponse::fallback(DEFAULT_MODEL),
        }
    }
}

// ---------------------------------------------------------------------------
// Rule-based synthesis
// ---------------------------------------------------------------------------

/// Synthesize findings from specialist reports.
/// Returns (risk_level, explanation, recommended_action, confidence).
fn synthesize(reports: &[SpecialistReport]) -> (String, String, String, f32) {
    let risk_levels: Vec<&str> = reports.iter().map(|r| r.risk_level.as_str()).collect();

    let risk_level = determine_risk_level(&risk_levels);

    let explanation = build_explanation(reports);

    let recommended_action = match risk_level.as_str() {
        "CRITICAL" => "block",
        "HIGH" => "investigate",
        "MEDIUM" => "investigate",
        _ => "allow",
    }
    .to_string();

    let confidence = compute_confidence(reports);

    (risk_level, explanation, recommended_action, confidence)
}

fn risk_to_num(risk: &str) -> u8 {
    match risk {
        "LOW" => 1,
        "MEDIUM" => 2,
        "HIGH" => 3,
        "CRITICAL" => 4,
        _ => 2,
    }
}

fn num_to_risk(n: u8) -> String {
    match n {
        1 => "LOW",
        2 => "MEDIUM",
        3 => "HIGH",
        4 => "CRITICAL",
        _ => "MEDIUM",
    }
    .to_string()
}

fn determine_risk_level(levels: &[&str]) -> String {
    // If ANY specialist says CRITICAL -> final = CRITICAL
    if levels.contains(&"CRITICAL") {
        return "CRITICAL".to_string();
    }

    let high_count = levels.iter().filter(|&&l| l == "HIGH").count();

    // If 2+ say HIGH -> final = HIGH
    if high_count >= 2 {
        return "HIGH".to_string();
    }

    // If 1 says HIGH, others LOW/MEDIUM -> final = MEDIUM (single dissent downgrades)
    if high_count == 1 {
        return "MEDIUM".to_string();
    }

    // Otherwise, take the median
    let mut nums: Vec<u8> = levels.iter().map(|l| risk_to_num(l)).collect();
    nums.sort();
    let median = nums[nums.len() / 2];
    num_to_risk(median)
}

fn build_explanation(reports: &[SpecialistReport]) -> String {
    let mut sentences: Vec<String> = Vec::new();
    for report in reports {
        if let Some(finding) = report.findings.first() {
            sentences.push(finding.clone());
            if sentences.len() >= 3 {
                break;
            }
        }
    }
    if sentences.is_empty() {
        "No findings available.".to_string()
    } else {
        sentences.join(". ") + "."
    }
}

fn compute_confidence(reports: &[SpecialistReport]) -> f32 {
    let mut total = 0.0f32;
    let mut count = 0;
    for report in reports {
        let conf = if report.verdict.contains("Unable to parse")
            || report.verdict == "analysis unavailable"
            || report
                .findings
                .first()
                .is_some_and(|f| f.contains("Unable to parse"))
        {
            0.5
        } else {
            0.85
        };
        total += conf;
        count += 1;
    }
    if count > 0 {
        total / count as f32
    } else {
        0.5
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm_client::{LlmResponse, MockLlmClient};
    use crate::prompts::SwarmEventData;
    use serde_json::json;
    use std::sync::Arc;

    fn sample_event() -> SwarmEventData {
        SwarmEventData {
            server_name: "test-server".to_string(),
            client_name: "test-client".to_string(),
            tool_name: Some("run_command".to_string()),
            arguments: Some(json!({"cmd": "ls -la /tmp"})),
            resource_uri: None,
            sampling_content: None,
            recent_events: vec![],
            slm_risk: "LOW".to_string(),
            slm_explanation: "Routine operation".to_string(),
        }
    }

    fn make_response(risk: &str, finding: &str, verdict: &str) -> String {
        format!("RISK: {risk}\nFINDINGS:\n- {finding}\nVERDICT: {verdict}")
    }

    fn mock_with_response(
        content: &str,
        input_tokens: u32,
        output_tokens: u32,
    ) -> Arc<MockLlmClient> {
        let mock = MockLlmClient::new();
        mock.add_response(
            DEFAULT_MODEL,
            LlmResponse {
                content: content.to_string(),
                input_tokens,
                output_tokens,
                model: DEFAULT_MODEL.to_string(),
                latency_ms: 100,
            },
        );
        Arc::new(mock)
    }

    // -- Synthesis unit tests --

    #[test]
    fn test_synthesis_three_lows() {
        let reports = vec![
            parse_specialist_response(&make_response("LOW", "No issues", "Safe")),
            parse_specialist_response(&make_response("LOW", "No issues", "Safe")),
            parse_specialist_response(&make_response("LOW", "No issues", "Safe")),
        ];
        let (risk, _explanation, action, _conf) = synthesize(&reports);
        assert_eq!(risk, "LOW");
        assert_eq!(action, "allow");
    }

    #[test]
    fn test_synthesis_three_highs() {
        let reports = vec![
            parse_specialist_response(&make_response("HIGH", "Suspicious", "Risky")),
            parse_specialist_response(&make_response("HIGH", "Suspicious", "Risky")),
            parse_specialist_response(&make_response("HIGH", "Suspicious", "Risky")),
        ];
        let (risk, _explanation, action, _conf) = synthesize(&reports);
        assert_eq!(risk, "HIGH");
        assert_eq!(action, "investigate");
    }

    #[test]
    fn test_synthesis_one_critical() {
        let reports = vec![
            parse_specialist_response(&make_response("LOW", "No issues", "Safe")),
            parse_specialist_response(&make_response("CRITICAL", "RCE detected", "Dangerous")),
            parse_specialist_response(&make_response("LOW", "No issues", "Safe")),
        ];
        let (risk, _explanation, action, _conf) = synthesize(&reports);
        assert_eq!(risk, "CRITICAL");
        assert_eq!(action, "block");
    }

    #[test]
    fn test_synthesis_mixed_high_low_medium() {
        let reports = vec![
            parse_specialist_response(&make_response("HIGH", "Suspicious connection", "Risky")),
            parse_specialist_response(&make_response("LOW", "No issues", "Safe")),
            parse_specialist_response(&make_response("MEDIUM", "Minor concern", "Moderate")),
        ];
        let (risk, _explanation, action, _conf) = synthesize(&reports);
        assert_eq!(risk, "MEDIUM");
        assert_eq!(action, "investigate");
    }

    #[test]
    fn test_synthesis_explanation_max_3_sentences() {
        let reports = vec![
            parse_specialist_response(&make_response("LOW", "Finding A", "Safe")),
            parse_specialist_response(&make_response("LOW", "Finding B", "Safe")),
            parse_specialist_response(&make_response("LOW", "Finding C", "Safe")),
        ];
        let (_risk, explanation, _action, _conf) = synthesize(&reports);
        assert!(explanation.contains("Finding A"));
        assert!(explanation.contains("Finding B"));
        assert!(explanation.contains("Finding C"));
        let sentence_count = explanation.matches(". ").count() + 1;
        assert!(sentence_count <= 3);
    }

    #[test]
    fn test_synthesis_all_timeouts_fallback() {
        let fallback = LlmResponse::fallback(DEFAULT_MODEL);
        let reports = vec![
            parse_specialist_response(&fallback.content),
            parse_specialist_response(&fallback.content),
            parse_specialist_response(&fallback.content),
        ];
        let (risk, _explanation, _action, conf) = synthesize(&reports);
        assert_eq!(risk, "MEDIUM");
        assert!((conf - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_synthesis_one_timeout_still_works() {
        let fallback = LlmResponse::fallback(DEFAULT_MODEL);
        let reports = vec![
            parse_specialist_response(&make_response("LOW", "No issues", "Safe")),
            parse_specialist_response(&fallback.content),
            parse_specialist_response(&make_response("LOW", "No issues", "Safe")),
        ];
        let (risk, _explanation, _action, _conf) = synthesize(&reports);
        // [LOW, MEDIUM(fallback), LOW] sorted=[1,1,2] median=1=LOW
        assert_eq!(risk, "LOW");
    }

    // -- Integration tests with Commander --

    #[tokio::test]
    async fn test_parallel_dispatch_all_3_calls() {
        let mock = mock_with_response(&make_response("LOW", "No issues", "Safe"), 100, 50);
        let commander = Commander::new(mock.clone(), None);
        let verdict = commander.analyze(&sample_event()).await.unwrap();

        assert_eq!(mock.calls().len(), 3);
        assert_eq!(verdict.risk_level, "LOW");
        assert_eq!(verdict.recommended_action, "allow");
        assert_eq!(verdict.specialist_reports.len(), 3);
    }

    #[tokio::test]
    async fn test_cost_aggregation() {
        let mock = mock_with_response(&make_response("LOW", "No issues", "Safe"), 100, 50);
        let commander = Commander::new(mock.clone(), None);
        let verdict = commander.analyze(&sample_event()).await.unwrap();

        assert_eq!(verdict.total_input_tokens, 300);
        assert_eq!(verdict.total_output_tokens, 150);
        assert!(verdict.estimated_cost_usd > 0.0);
    }

    #[tokio::test]
    async fn test_cost_tracker_records() {
        let mock = mock_with_response(&make_response("LOW", "No issues", "Safe"), 100, 50);

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let tracker = CostTracker::new(
            &db_path,
            PricingTable::default(),
            crate::cost::BudgetConfig::default(),
        )
        .unwrap();
        let tracker = Arc::new(Mutex::new(tracker));

        let commander = Commander::new(mock, Some(tracker.clone()));
        commander.analyze(&sample_event()).await.unwrap();

        let t = tracker.lock().unwrap();
        let recent = t.get_recent(10);
        assert_eq!(recent.len(), 3);
    }

    #[tokio::test]
    async fn test_verdict_with_all_high() {
        let mock = mock_with_response(
            &make_response("HIGH", "Suspicious activity", "Concerning"),
            200,
            100,
        );
        let commander = Commander::new(mock, None);
        let verdict = commander.analyze(&sample_event()).await.unwrap();

        assert_eq!(verdict.risk_level, "HIGH");
        assert_eq!(verdict.recommended_action, "investigate");
    }

    #[tokio::test]
    async fn test_fallback_on_no_registered_response() {
        let mock = Arc::new(MockLlmClient::new());
        let commander = Commander::new(mock, None);
        let verdict = commander.analyze(&sample_event()).await.unwrap();

        assert_eq!(verdict.risk_level, "MEDIUM");
    }

    #[tokio::test]
    async fn test_timeout_boundary() {
        // This test verifies the timeout mechanism exists by running with a fast mock.
        // The mock responds instantly, so we just confirm no timeout error occurs.
        let mock = mock_with_response(&make_response("LOW", "No issues", "Safe"), 50, 25);
        let commander = Commander::new(mock, None);
        let verdict = commander.analyze(&sample_event()).await.unwrap();

        assert_eq!(verdict.risk_level, "LOW");
        assert!(verdict.total_latency_ms < 10_000);
    }
}
