//! Autonomous blocking decision engine.
//!
//! Routes behavioral events through the decision pipeline:
//! policy evaluation → anomaly scoring → kill chain detection → decision.
//! Auto-blocking is opt-in and OFF by default.

use serde::{Deserialize, Serialize};

use super::anomaly::{AnomalyComponent, AnomalyScore};
use super::killchain::KillChainMatch;
use super::profile::ServerProfile;
use crate::policy::PolicyAction;

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// The outcome of the behavioral decision engine for a single event.
#[derive(Debug, Clone)]
pub enum BehavioralDecision {
    /// Normal prompt — anomaly score below threshold.
    NormalPrompt {
        anomaly_score: AnomalyScore,
        kill_chain: Option<KillChainMatch>,
    },
    /// Enriched prompt — high anomaly score, show warning to user.
    EnrichedPrompt {
        anomaly_score: AnomalyScore,
        kill_chain: Option<KillChainMatch>,
        explanation: String,
    },
    /// Auto-blocked — score above auto-block threshold.
    AutoBlock {
        anomaly_score: AnomalyScore,
        kill_chain: Option<KillChainMatch>,
        explanation: String,
    },
    /// Skip — event handled by an explicit policy rule (Allow/Block/Log).
    Skip,
    /// Learning — profile still in learning mode.
    Learning,
}

// ---------------------------------------------------------------------------
// Audit data
// ---------------------------------------------------------------------------

/// Structured audit data attached to every behavioral decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAuditData {
    pub anomaly_score: f64,
    pub anomaly_components: Vec<AuditAnomalyComponent>,
    pub kill_chain: Option<AuditKillChainData>,
    pub auto_blocked: bool,
    pub profile_status: String,
    pub observation_count: u64,
}

/// One dimension of the anomaly breakdown for audit records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAnomalyComponent {
    pub dimension: String,
    pub score: f64,
    pub explanation: String,
}

/// Kill chain data for audit records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditKillChainData {
    pub pattern: String,
    pub steps_matched: usize,
    pub steps_total: usize,
}

// ---------------------------------------------------------------------------
// Calibration
// ---------------------------------------------------------------------------

/// Result of a calibration run across historical data.
#[derive(Debug, Clone)]
pub struct CalibrationResult {
    pub total_events: usize,
    pub results_by_threshold: Vec<ThresholdResult>,
}

/// What would happen at a given threshold.
#[derive(Debug, Clone)]
pub struct ThresholdResult {
    pub threshold: f64,
    pub would_auto_block: usize,
    pub details: Vec<String>,
}

// ---------------------------------------------------------------------------
// Auto-block stats & feedback
// ---------------------------------------------------------------------------

/// Tracks accuracy of autonomous blocking decisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoBlockStats {
    pub total_auto_blocks: u64,
    pub total_overrides: u64,
    pub override_rate: f64,
}

impl AutoBlockStats {
    pub fn record_block(&mut self) {
        self.total_auto_blocks += 1;
        self.recompute_rate();
    }

    pub fn record_override(&mut self) {
        self.total_overrides += 1;
        self.recompute_rate();
    }

    fn recompute_rate(&mut self) {
        if self.total_auto_blocks > 0 {
            self.override_rate = self.total_overrides as f64 / self.total_auto_blocks as f64;
        } else {
            self.override_rate = 0.0;
        }
    }

    /// Returns true if the override rate exceeds 10%, suggesting the threshold
    /// should be raised.
    pub fn should_raise_threshold(&self) -> bool {
        self.total_auto_blocks >= 10 && self.override_rate > 0.1
    }
}

// ---------------------------------------------------------------------------
// Decision engine
// ---------------------------------------------------------------------------

/// The autonomous blocking decision engine.
///
/// Routes events through policy + behavioral analysis to produce a decision.
/// **Auto-block is opt-in and OFF by default.**
pub struct DecisionEngine {
    /// Anomaly score threshold for enriched prompts (default 0.7).
    pub anomaly_threshold: f64,
    /// Anomaly score threshold for auto-blocking (default 0.9).
    pub auto_block_threshold: f64,
    /// Whether auto-blocking is enabled. **OFF by default — opt-in only.**
    pub auto_block_enabled: bool,
    /// Tracks auto-block accuracy.
    pub stats: AutoBlockStats,
}

impl Default for DecisionEngine {
    fn default() -> Self {
        Self {
            anomaly_threshold: 0.7,
            auto_block_threshold: 0.9,
            auto_block_enabled: false,
            stats: AutoBlockStats::default(),
        }
    }
}

impl DecisionEngine {
    /// Create a new decision engine with default settings.
    /// Auto-block is OFF by default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a decision engine from configuration values.
    pub fn from_config(
        anomaly_threshold: f64,
        auto_block_threshold: f64,
        auto_block_enabled: bool,
    ) -> Self {
        Self {
            anomaly_threshold,
            auto_block_threshold,
            auto_block_enabled,
            stats: AutoBlockStats::default(),
        }
    }

    /// Evaluate an event and produce a behavioral decision.
    ///
    /// The `policy_action` is the result of the policy engine's evaluation.
    /// The `anomaly_score` and `kill_chain` come from the anomaly scorer and
    /// kill chain detector respectively.
    pub fn decide(
        &mut self,
        policy_action: &PolicyAction,
        profile: &ServerProfile,
        anomaly_score: Option<AnomalyScore>,
        kill_chain: Option<KillChainMatch>,
    ) -> BehavioralDecision {
        // Explicit policy rules take precedence — skip behavioral analysis.
        match policy_action {
            PolicyAction::Allow | PolicyAction::Block | PolicyAction::Log => {
                return BehavioralDecision::Skip;
            }
            PolicyAction::Prompt(_) => {
                // Fall through to behavioral evaluation.
            }
        }

        // If profile is still learning, pass through as normal.
        if profile.learning_mode {
            return BehavioralDecision::Learning;
        }

        // If we have no anomaly score (shouldn't happen outside learning), treat as normal.
        let score = match anomaly_score {
            Some(s) => s,
            None => return BehavioralDecision::Learning,
        };

        // Apply kill chain boost: add 0.3 to the anomaly score (capped at 1.0).
        let kill_chain_boost = kill_chain
            .as_ref()
            .map(|kc| kc.anomaly_boost())
            .unwrap_or(0.0);
        let effective_score = (score.total + kill_chain_boost).min(1.0);

        // Build a score with the boosted total for decision-making.
        let boosted_score = AnomalyScore {
            total: effective_score,
            components: score.components.clone(),
            explanation: if kill_chain_boost > 0.0 {
                format!(
                    "{} [Kill chain boost: +{:.1} -> {:.2}]",
                    score.explanation, kill_chain_boost, effective_score
                )
            } else {
                score.explanation.clone()
            },
        };

        // Decision routing based on effective score.
        if effective_score >= self.auto_block_threshold && self.auto_block_enabled {
            let explanation = self.build_block_explanation(&boosted_score, &kill_chain);
            self.stats.record_block();
            BehavioralDecision::AutoBlock {
                anomaly_score: boosted_score,
                kill_chain,
                explanation,
            }
        } else if effective_score >= self.anomaly_threshold {
            let explanation = self.build_warning_explanation(&boosted_score, &kill_chain);
            BehavioralDecision::EnrichedPrompt {
                anomaly_score: boosted_score,
                kill_chain,
                explanation,
            }
        } else {
            BehavioralDecision::NormalPrompt {
                anomaly_score: boosted_score,
                kill_chain,
            }
        }
    }

    /// Record that a user overrode an auto-block (trusted the action).
    pub fn record_override(&mut self) {
        self.stats.record_override();
    }

    /// Build audit data from a decision.
    pub fn build_audit_data(
        &self,
        decision: &BehavioralDecision,
        profile: &ServerProfile,
    ) -> BehavioralAuditData {
        match decision {
            BehavioralDecision::NormalPrompt {
                anomaly_score,
                kill_chain,
            }
            | BehavioralDecision::EnrichedPrompt {
                anomaly_score,
                kill_chain,
                ..
            }
            | BehavioralDecision::AutoBlock {
                anomaly_score,
                kill_chain,
                ..
            } => BehavioralAuditData {
                anomaly_score: anomaly_score.total,
                anomaly_components: anomaly_score
                    .components
                    .iter()
                    .map(|c| AuditAnomalyComponent {
                        dimension: format!("{:?}", c.dimension),
                        score: c.score,
                        explanation: c.explanation.clone(),
                    })
                    .collect(),
                kill_chain: kill_chain.as_ref().map(|kc| AuditKillChainData {
                    pattern: kc.pattern.name.clone(),
                    steps_matched: kc.matched_events.len(),
                    steps_total: kc.pattern.steps.len(),
                }),
                auto_blocked: matches!(decision, BehavioralDecision::AutoBlock { .. }),
                profile_status: if profile.learning_mode {
                    "learning".to_string()
                } else {
                    "active".to_string()
                },
                observation_count: profile.observation_count,
            },
            BehavioralDecision::Skip => BehavioralAuditData {
                anomaly_score: 0.0,
                anomaly_components: vec![],
                kill_chain: None,
                auto_blocked: false,
                profile_status: if profile.learning_mode {
                    "learning".to_string()
                } else {
                    "active".to_string()
                },
                observation_count: profile.observation_count,
            },
            BehavioralDecision::Learning => BehavioralAuditData {
                anomaly_score: 0.0,
                anomaly_components: vec![],
                kill_chain: None,
                auto_blocked: false,
                profile_status: "learning".to_string(),
                observation_count: profile.observation_count,
            },
        }
    }

    /// Run calibration against historical anomaly scores.
    /// Reports what would have happened at thresholds 0.7, 0.8, and 0.9.
    pub fn calibrate(scores: &[(f64, String)]) -> CalibrationResult {
        let thresholds = [0.7, 0.8, 0.9];
        let results_by_threshold = thresholds
            .iter()
            .map(|&threshold| {
                let mut would_auto_block = 0usize;
                let mut details = Vec::new();
                for (score, description) in scores {
                    if *score >= threshold {
                        would_auto_block += 1;
                        details.push(format!(
                            "score={:.2} threshold={:.1}: {}",
                            score, threshold, description
                        ));
                    }
                }
                ThresholdResult {
                    threshold,
                    would_auto_block,
                    details,
                }
            })
            .collect();

        CalibrationResult {
            total_events: scores.len(),
            results_by_threshold,
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn build_block_explanation(
        &self,
        score: &AnomalyScore,
        kill_chain: &Option<KillChainMatch>,
    ) -> String {
        let mut parts = vec![format!(
            "AUTO-BLOCKED: Anomaly score {:.2} exceeds auto-block threshold {:.1}.",
            score.total, self.auto_block_threshold
        )];
        if let Some(kc) = kill_chain {
            parts.push(format!("Kill chain detected: {}", kc.explanation));
        }
        // Top contributing dimensions.
        let mut top: Vec<&AnomalyComponent> =
            score.components.iter().filter(|c| c.score > 0.0).collect();
        top.sort_by(|a, b| {
            (b.score * b.weight)
                .partial_cmp(&(a.score * a.weight))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for c in top.iter().take(3) {
            parts.push(c.explanation.clone());
        }
        parts.join(" ")
    }

    fn build_warning_explanation(
        &self,
        score: &AnomalyScore,
        kill_chain: &Option<KillChainMatch>,
    ) -> String {
        let mut parts = vec![format!(
            "WARNING: Anomaly score {:.2} exceeds threshold {:.1}.",
            score.total, self.anomaly_threshold
        )];
        if let Some(kc) = kill_chain {
            parts.push(format!("Kill chain detected: {}", kc.explanation));
        }
        let mut top: Vec<&AnomalyComponent> =
            score.components.iter().filter(|c| c.score > 0.0).collect();
        top.sort_by(|a, b| {
            (b.score * b.weight)
                .partial_cmp(&(a.score * a.weight))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for c in top.iter().take(3) {
            parts.push(c.explanation.clone());
        }
        parts.join(" ")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavioral::anomaly::{AnomalyComponent, AnomalyDimension, AnomalyScore};
    use crate::behavioral::killchain::{AttackPattern, KillChainMatch, Severity};
    use crate::behavioral::profile::*;
    use crate::policy::PolicyAction;
    use chrono::Utc;

    // -- Helpers --

    fn make_profile(learning: bool) -> ServerProfile {
        ServerProfile {
            server_name: "test-server".to_string(),
            client_name: "test-client".to_string(),
            first_seen: Utc::now(),
            last_updated: Utc::now(),
            learning_mode: learning,
            observation_count: 500,
            tool_profile: ToolProfile::default(),
            file_profile: FileProfile::default(),
            network_profile: NetworkProfile::default(),
            temporal_profile: TemporalProfile::default(),
        }
    }

    fn make_score(total: f64) -> AnomalyScore {
        AnomalyScore {
            total,
            components: vec![AnomalyComponent {
                dimension: AnomalyDimension::UnknownTool,
                score: total,
                weight: 1.0,
                explanation: format!("Test component score={:.2}", total),
            }],
            explanation: format!("Test anomaly score {:.2}", total),
        }
    }

    fn make_kill_chain() -> KillChainMatch {
        KillChainMatch {
            pattern: AttackPattern {
                name: "test_pattern".to_string(),
                severity: Severity::High,
                window_seconds: 60,
                explanation: "Test kill chain pattern".to_string(),
                steps: vec![],
            },
            matched_events: vec![],
            explanation: "Test kill chain matched".to_string(),
            severity: Severity::High,
        }
    }

    // -- Test: score below anomaly threshold -> NormalPrompt --

    #[test]
    fn test_decision_below_threshold_normal_prompt() {
        let mut engine = DecisionEngine::new();
        let profile = make_profile(false);
        let score = make_score(0.3);
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            None,
        );
        assert!(matches!(decision, BehavioralDecision::NormalPrompt { .. }));
    }

    // -- Test: score between 0.7-0.9 -> EnrichedPrompt --

    #[test]
    fn test_decision_enriched_prompt_range() {
        let mut engine = DecisionEngine::new();
        let profile = make_profile(false);
        let score = make_score(0.75);
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            None,
        );
        assert!(matches!(
            decision,
            BehavioralDecision::EnrichedPrompt { .. }
        ));
    }

    // -- Test: score above 0.9 with auto-block enabled -> AutoBlock --

    #[test]
    fn test_decision_auto_block_enabled_high_score() {
        let mut engine = DecisionEngine::from_config(0.7, 0.9, true);
        let profile = make_profile(false);
        let score = make_score(0.95);
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            None,
        );
        assert!(matches!(decision, BehavioralDecision::AutoBlock { .. }));
    }

    // -- Test: auto-block is opt-in (disabled by default) --

    #[test]
    fn test_auto_block_disabled_by_default() {
        let engine = DecisionEngine::new();
        assert!(!engine.auto_block_enabled);
    }

    #[test]
    fn test_auto_block_disabled_high_score_enriched_not_blocked() {
        let mut engine = DecisionEngine::new(); // auto_block_enabled = false
        let profile = make_profile(false);
        let score = make_score(0.95);
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            None,
        );
        // Should be EnrichedPrompt, NOT AutoBlock, because auto-block is off.
        assert!(matches!(
            decision,
            BehavioralDecision::EnrichedPrompt { .. }
        ));
    }

    // -- Test: explicit Allow rule overrides behavioral (Skip) --

    #[test]
    fn test_explicit_allow_skips_behavioral() {
        let mut engine = DecisionEngine::from_config(0.7, 0.9, true);
        let profile = make_profile(false);
        let score = make_score(0.99);
        let decision = engine.decide(&PolicyAction::Allow, &profile, Some(score), None);
        assert!(matches!(decision, BehavioralDecision::Skip));
    }

    // -- Test: explicit Block rule -> Skip --

    #[test]
    fn test_explicit_block_skips_behavioral() {
        let mut engine = DecisionEngine::new();
        let profile = make_profile(false);
        let score = make_score(0.5);
        let decision = engine.decide(&PolicyAction::Block, &profile, Some(score), None);
        assert!(matches!(decision, BehavioralDecision::Skip));
    }

    // -- Test: Log rule -> Skip --

    #[test]
    fn test_log_action_skips_behavioral() {
        let mut engine = DecisionEngine::new();
        let profile = make_profile(false);
        let score = make_score(0.8);
        let decision = engine.decide(&PolicyAction::Log, &profile, Some(score), None);
        assert!(matches!(decision, BehavioralDecision::Skip));
    }

    // -- Test: learning mode -> Learning --

    #[test]
    fn test_learning_mode_returns_learning() {
        let mut engine = DecisionEngine::new();
        let profile = make_profile(true);
        let decision = engine.decide(&PolicyAction::Prompt("check".into()), &profile, None, None);
        assert!(matches!(decision, BehavioralDecision::Learning));
    }

    // -- Test: kill chain boost --

    #[test]
    fn test_kill_chain_boost_triggers_auto_block() {
        let mut engine = DecisionEngine::from_config(0.7, 0.9, true);
        let profile = make_profile(false);
        // Score of 0.75 alone would be EnrichedPrompt, but kill chain adds 0.3 -> 1.0 -> AutoBlock
        let score = make_score(0.75);
        let kc = make_kill_chain();
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            Some(kc),
        );
        assert!(matches!(decision, BehavioralDecision::AutoBlock { .. }));
        if let BehavioralDecision::AutoBlock { anomaly_score, .. } = &decision {
            assert!((anomaly_score.total - 1.0).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn test_kill_chain_boost_capped_at_one() {
        let mut engine = DecisionEngine::from_config(0.7, 0.9, true);
        let profile = make_profile(false);
        let score = make_score(0.85);
        let kc = make_kill_chain();
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            Some(kc),
        );
        if let BehavioralDecision::AutoBlock { anomaly_score, .. } = &decision {
            assert!(anomaly_score.total <= 1.0);
        } else {
            panic!("Expected AutoBlock");
        }
    }

    // -- Test: audit data for auto-block is complete --

    #[test]
    fn test_auto_block_audit_data_complete() {
        let mut engine = DecisionEngine::from_config(0.7, 0.9, true);
        let profile = make_profile(false);
        let score = make_score(0.95);
        let kc = make_kill_chain();
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            Some(kc),
        );
        let audit = engine.build_audit_data(&decision, &profile);
        assert!(audit.auto_blocked);
        assert!(audit.anomaly_score >= 0.95);
        assert!(!audit.anomaly_components.is_empty());
        assert!(audit.kill_chain.is_some());
        assert_eq!(audit.profile_status, "active");
        assert_eq!(audit.observation_count, 500);
    }

    // -- Test: calibration --

    #[test]
    fn test_calibration_with_synthetic_data() {
        let scores: Vec<(f64, String)> = vec![
            (0.3, "normal event".into()),
            (0.5, "slightly unusual".into()),
            (0.72, "suspicious file access".into()),
            (0.85, "unknown tool + sensitive path".into()),
            (0.95, "credential theft attempt".into()),
        ];

        let result = DecisionEngine::calibrate(&scores);
        assert_eq!(result.total_events, 5);
        assert_eq!(result.results_by_threshold.len(), 3);

        // At 0.7: events with score >= 0.7 -> 3 (0.72, 0.85, 0.95)
        let t07 = &result.results_by_threshold[0];
        assert!((t07.threshold - 0.7).abs() < f64::EPSILON);
        assert_eq!(t07.would_auto_block, 3);

        // At 0.8: events with score >= 0.8 -> 2 (0.85, 0.95)
        let t08 = &result.results_by_threshold[1];
        assert!((t08.threshold - 0.8).abs() < f64::EPSILON);
        assert_eq!(t08.would_auto_block, 2);

        // At 0.9: events with score >= 0.9 -> 1 (0.95)
        let t09 = &result.results_by_threshold[2];
        assert!((t09.threshold - 0.9).abs() < f64::EPSILON);
        assert_eq!(t09.would_auto_block, 1);
    }

    // -- Test: feedback loop / auto-block stats --

    #[test]
    fn test_auto_block_stats_tracking() {
        let mut stats = AutoBlockStats::default();
        assert_eq!(stats.total_auto_blocks, 0);
        assert_eq!(stats.total_overrides, 0);
        assert!((stats.override_rate - 0.0).abs() < f64::EPSILON);

        stats.record_block();
        stats.record_block();
        stats.record_block();
        assert_eq!(stats.total_auto_blocks, 3);
        assert!((stats.override_rate - 0.0).abs() < f64::EPSILON);

        stats.record_override();
        assert_eq!(stats.total_overrides, 1);
        // override_rate = 1/3 ≈ 0.333
        assert!((stats.override_rate - 1.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn test_should_raise_threshold_when_high_override_rate() {
        let mut stats = AutoBlockStats::default();
        // Need at least 10 blocks
        for _ in 0..10 {
            stats.record_block();
        }
        assert!(!stats.should_raise_threshold()); // 0% override

        // 2 overrides out of 10 = 20% > 10%
        stats.record_override();
        stats.record_override();
        assert!(stats.should_raise_threshold());
    }

    #[test]
    fn test_should_not_raise_threshold_few_samples() {
        let mut stats = AutoBlockStats::default();
        for _ in 0..5 {
            stats.record_block();
        }
        stats.record_override(); // 1/5 = 20%, but < 10 samples
        assert!(!stats.should_raise_threshold());
    }

    // -- Test: feedback loop integration --

    #[test]
    fn test_feedback_loop_override_updates_stats() {
        let mut engine = DecisionEngine::from_config(0.7, 0.9, true);
        let profile = make_profile(false);
        let score = make_score(0.95);
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            None,
        );
        assert!(matches!(decision, BehavioralDecision::AutoBlock { .. }));
        assert_eq!(engine.stats.total_auto_blocks, 1);

        // User trusts the action
        engine.record_override();
        assert_eq!(engine.stats.total_overrides, 1);
        assert!((engine.stats.override_rate - 1.0).abs() < f64::EPSILON);
    }

    // -- Test: score exactly at thresholds --

    #[test]
    fn test_score_exactly_at_anomaly_threshold() {
        let mut engine = DecisionEngine::new();
        let profile = make_profile(false);
        let score = make_score(0.7);
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            None,
        );
        assert!(matches!(
            decision,
            BehavioralDecision::EnrichedPrompt { .. }
        ));
    }

    #[test]
    fn test_score_exactly_at_auto_block_threshold() {
        let mut engine = DecisionEngine::from_config(0.7, 0.9, true);
        let profile = make_profile(false);
        let score = make_score(0.9);
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            None,
        );
        assert!(matches!(decision, BehavioralDecision::AutoBlock { .. }));
    }

    #[test]
    fn test_score_just_below_anomaly_threshold() {
        let mut engine = DecisionEngine::new();
        let profile = make_profile(false);
        let score = make_score(0.69);
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            None,
        );
        assert!(matches!(decision, BehavioralDecision::NormalPrompt { .. }));
    }

    // -- Test: kill chain without auto-block -> EnrichedPrompt --

    #[test]
    fn test_kill_chain_without_auto_block_enriched() {
        let mut engine = DecisionEngine::new(); // auto_block disabled
        let profile = make_profile(false);
        let score = make_score(0.75);
        let kc = make_kill_chain();
        let decision = engine.decide(
            &PolicyAction::Prompt("check".into()),
            &profile,
            Some(score),
            Some(kc),
        );
        // 0.75 + 0.3 = 1.05 -> capped at 1.0, but auto-block is OFF -> EnrichedPrompt
        assert!(matches!(
            decision,
            BehavioralDecision::EnrichedPrompt { .. }
        ));
    }

    // -- Test: audit data for learning mode --

    #[test]
    fn test_audit_data_learning_mode() {
        let mut engine = DecisionEngine::new();
        let profile = make_profile(true);
        let decision = engine.decide(&PolicyAction::Prompt("check".into()), &profile, None, None);
        let audit = engine.build_audit_data(&decision, &profile);
        assert!(!audit.auto_blocked);
        assert_eq!(audit.profile_status, "learning");
        assert!((audit.anomaly_score - 0.0).abs() < f64::EPSILON);
    }

    // -- Test: audit data for skip --

    #[test]
    fn test_audit_data_skip() {
        let mut engine = DecisionEngine::new();
        let profile = make_profile(false);
        let decision = engine.decide(&PolicyAction::Allow, &profile, Some(make_score(0.5)), None);
        let audit = engine.build_audit_data(&decision, &profile);
        assert!(!audit.auto_blocked);
        assert_eq!(audit.profile_status, "active");
    }
}
