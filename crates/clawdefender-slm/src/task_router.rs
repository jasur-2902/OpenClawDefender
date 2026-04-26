//! Intelligent task router for the dual AI backend architecture.
//!
//! The `TaskRouter` makes routing decisions based on:
//! - Task type (what kind of analysis is needed)
//! - Backend availability (which backends are online)
//! - User preferences (prefer local, cloud confirmation, etc.)
//! - Rate limiting (max cloud calls per hour)

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::backend_manager::TaskType;

// ---------------------------------------------------------------------------
// Feature routing types
// ---------------------------------------------------------------------------

/// High-level AI feature categories that users can configure routing for.
/// Each feature maps to one or more `TaskType` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiFeature {
    /// Triage, ContextUpdate
    EventTriage,
    /// AnomalyExplanation, EventNarrative
    EventExplanation,
    /// QuickRiskAssessment, SecurityTip
    QuickRiskCheck,
    /// DeepAnalysis, Investigation
    DeepAnalysis,
    /// ScanAnalysis
    ScanAnalysis,
    /// AskClaw
    AskClaw,
    /// ReportGeneration
    Reports,
    /// ThreatHunt
    ThreatHunting,
    /// AgentScan, PlaybookExecution
    AgentScan,
}

impl AiFeature {
    /// Return all feature variants.
    pub fn all() -> &'static [AiFeature] {
        &[
            AiFeature::EventTriage,
            AiFeature::EventExplanation,
            AiFeature::QuickRiskCheck,
            AiFeature::DeepAnalysis,
            AiFeature::ScanAnalysis,
            AiFeature::AskClaw,
            AiFeature::Reports,
            AiFeature::ThreatHunting,
            AiFeature::AgentScan,
        ]
    }

    /// Map a `TaskType` to the corresponding `AiFeature`.
    pub fn from_task_type(task_type: &TaskType) -> AiFeature {
        match task_type {
            TaskType::Triage | TaskType::ContextUpdate => AiFeature::EventTriage,
            TaskType::AnomalyExplanation | TaskType::EventNarrative => AiFeature::EventExplanation,
            TaskType::QuickRiskAssessment | TaskType::SecurityTip => AiFeature::QuickRiskCheck,
            TaskType::DeepAnalysis | TaskType::Investigation => AiFeature::DeepAnalysis,
            TaskType::ScanAnalysis => AiFeature::ScanAnalysis,
            TaskType::AskClaw => AiFeature::AskClaw,
            TaskType::ReportGeneration => AiFeature::Reports,
            TaskType::ThreatHunt => AiFeature::ThreatHunting,
            TaskType::AgentScan | TaskType::PlaybookExecution => AiFeature::AgentScan,
        }
    }

    /// Human-readable display name for the feature.
    pub fn display_name(&self) -> &'static str {
        match self {
            AiFeature::EventTriage => "Event Triage",
            AiFeature::EventExplanation => "Event Explanation",
            AiFeature::QuickRiskCheck => "Quick Risk Check",
            AiFeature::DeepAnalysis => "Deep Analysis",
            AiFeature::ScanAnalysis => "Scan Analysis",
            AiFeature::AskClaw => "Ask Rook",
            AiFeature::Reports => "Reports",
            AiFeature::ThreatHunting => "Threat Hunting",
            AiFeature::AgentScan => "Agent Scan",
        }
    }

    /// Short description of what the feature does.
    pub fn description(&self) -> &'static str {
        match self {
            AiFeature::EventTriage => "Real-time triage and context updates for security events",
            AiFeature::EventExplanation => "Anomaly explanations and event narrative generation",
            AiFeature::QuickRiskCheck => "Quick risk assessments and security tips",
            AiFeature::DeepAnalysis => "Deep analysis and investigations of suspicious activity",
            AiFeature::ScanAnalysis => "AI-powered security scan analysis",
            AiFeature::AskClaw => "Conversational AI security assistant",
            AiFeature::Reports => "AI-generated security reports",
            AiFeature::ThreatHunting => "Proactive threat hunting across your environment",
            AiFeature::AgentScan => "Autonomous agent scans and playbook execution",
        }
    }

    /// The default backend for this feature (what the hardcoded routing matrix uses).
    pub fn default_backend(&self) -> &'static str {
        match self {
            AiFeature::EventTriage | AiFeature::EventExplanation | AiFeature::QuickRiskCheck => {
                "local"
            }
            AiFeature::DeepAnalysis
            | AiFeature::ScanAnalysis
            | AiFeature::AskClaw
            | AiFeature::Reports
            | AiFeature::ThreatHunting
            | AiFeature::AgentScan => "cloud",
        }
    }
}

/// Per-feature backend preference: Auto (use default routing), Local, or Cloud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FeatureBackendPreference {
    /// Use the hardcoded routing matrix (current behavior).
    #[default]
    Auto,
    /// Force local SLM.
    Local,
    /// Force cloud API.
    Cloud,
}

/// Per-feature routing overrides. Only non-Auto entries are meaningful.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureRoutingConfig {
    pub overrides: HashMap<AiFeature, FeatureBackendPreference>,
}

impl FeatureRoutingConfig {
    /// Get the preference for a feature, defaulting to Auto.
    pub fn get(&self, feature: &AiFeature) -> FeatureBackendPreference {
        self.overrides.get(feature).copied().unwrap_or_default()
    }

    /// Returns true if any non-Auto overrides exist.
    pub fn has_overrides(&self) -> bool {
        self.overrides
            .values()
            .any(|p| *p != FeatureBackendPreference::Auto)
    }
}

/// Routing decision made by the TaskRouter.
#[derive(Debug, Clone, PartialEq)]
pub enum RoutingDecision {
    /// Use the local SLM backend.
    UseLocal,
    /// Use the cloud API backend.
    UseCloud,
    /// Try cloud first, fall back to local if cloud fails.
    UseCloudWithLocalFallback,
    /// Local handles it but with reduced quality (cloud unavailable).
    UseLocalReduced,
    /// Feature unavailable without cloud.
    RequiresCloud,
    /// Neither backend can handle this.
    Unavailable(String),
    /// User needs to confirm cloud usage before proceeding.
    AwaitConfirmation,
}

/// User-configurable routing preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPreferences {
    /// When both backends are available, prefer local inference. Default: true.
    pub prefer_local: bool,
    /// Automatically escalate to cloud for suspicious events. Default: true.
    pub cloud_auto_escalate: bool,
    /// Ask the user before each cloud API call. Default: false.
    pub cloud_confirmation: bool,
    /// Maximum cloud API calls per hour. Default: 10.
    pub max_cloud_calls_per_hour: u32,
}

impl Default for RoutingPreferences {
    fn default() -> Self {
        Self {
            prefer_local: true,
            cloud_auto_escalate: true,
            cloud_confirmation: false,
            max_cloud_calls_per_hour: 10,
        }
    }
}

/// Rate limit status for the cloud backend.
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitStatus {
    pub calls_this_hour: u32,
    pub max_per_hour: u32,
    pub remaining: u32,
}

/// The intelligent task router that decides which backend handles each request.
pub struct TaskRouter {
    preferences: RwLock<RoutingPreferences>,
    cloud_call_window: RwLock<VecDeque<Instant>>,
    cloud_calls_this_hour: AtomicU32,
    feature_routing: RwLock<FeatureRoutingConfig>,
}

impl TaskRouter {
    /// Create a new TaskRouter with the given preferences.
    pub fn new(prefs: RoutingPreferences) -> Self {
        Self {
            preferences: RwLock::new(prefs),
            cloud_call_window: RwLock::new(VecDeque::new()),
            cloud_calls_this_hour: AtomicU32::new(0),
            feature_routing: RwLock::new(FeatureRoutingConfig::default()),
        }
    }

    /// Make a routing decision based on task type and backend availability.
    ///
    /// Routing matrix:
    ///
    /// | Task Type            | Both Available  | Local Only     | Cloud Only   | Neither       |
    /// |----------------------|-----------------|----------------|--------------|---------------|
    /// | Triage               | Local           | Local          | Skip         | Skip          |
    /// | ContextUpdate        | Local           | Local          | Skip         | Skip          |
    /// | AnomalyExplanation   | Local           | Local          | Cloud        | Unavailable   |
    /// | EventNarrative       | Local           | Local          | Cloud        | Unavailable   |
    /// | QuickRiskAssessment  | Local           | Local          | Cloud        | Unavailable   |
    /// | SecurityTip          | Local           | Local          | Cloud        | Unavailable   |
    /// | DeepAnalysis         | Cloud           | LocalReduced   | Cloud        | Unavailable   |
    /// | Investigation        | Cloud           | RequiresCloud  | Cloud        | RequiresCloud |
    /// | ScanAnalysis         | Cloud           | LocalReduced   | Cloud        | Unavailable   |
    /// | AskClaw              | Cloud           | LocalReduced   | Cloud        | Unavailable   |
    /// | ReportGeneration     | Cloud           | LocalReduced   | Cloud        | Unavailable   |
    /// | ThreatHunt           | Cloud           | RequiresCloud  | Cloud        | RequiresCloud |
    /// | AgentScan            | Cloud           | RequiresCloud  | Cloud        | RequiresCloud |
    /// | PlaybookExecution    | Cloud           | RequiresCloud  | Cloud        | RequiresCloud |
    pub fn route(
        &self,
        task_type: &TaskType,
        local_available: bool,
        cloud_available: bool,
    ) -> RoutingDecision {
        let prefs = self.preferences.read().unwrap();

        // --- Feature routing overrides (before the hardcoded matrix) ---
        // ContextUpdate is always local regardless of override (internal background task).
        if *task_type != TaskType::ContextUpdate {
            let feature = AiFeature::from_task_type(task_type);
            let pref = self.feature_routing.read().unwrap().get(&feature);
            match pref {
                FeatureBackendPreference::Local => {
                    if local_available {
                        return RoutingDecision::UseLocal;
                    }
                    // Graceful degradation: forced local but unavailable
                    return RoutingDecision::Unavailable(
                        "Local model forced by routing config but unavailable".to_string(),
                    );
                }
                FeatureBackendPreference::Cloud => {
                    if cloud_available {
                        // Still apply rate limiting and confirmation
                        if !self.check_rate_limit_inner(&prefs) {
                            if local_available {
                                return RoutingDecision::UseLocalReduced;
                            }
                            return RoutingDecision::Unavailable(
                                "Cloud rate limit exceeded and no local model available"
                                    .to_string(),
                            );
                        }
                        if prefs.cloud_confirmation {
                            return RoutingDecision::AwaitConfirmation;
                        }
                        if local_available {
                            return RoutingDecision::UseCloudWithLocalFallback;
                        }
                        return RoutingDecision::UseCloud;
                    }
                    // Graceful degradation: forced cloud but unavailable, fall back to local
                    if local_available {
                        return RoutingDecision::UseLocalReduced;
                    }
                    return RoutingDecision::Unavailable(
                        "Cloud API forced by routing config but unavailable".to_string(),
                    );
                }
                FeatureBackendPreference::Auto => {
                    // Fall through to the hardcoded routing matrix
                }
            }
        }

        // Determine the raw decision from the routing matrix
        let decision = match task_type {
            // --- Local-first tasks: always prefer local when available ---
            TaskType::Triage | TaskType::ContextUpdate => {
                if local_available {
                    RoutingDecision::UseLocal
                } else {
                    // These are lightweight tasks; skip if local is unavailable
                    RoutingDecision::Unavailable(
                        "Local model required for fast triage tasks".to_string(),
                    )
                }
            }

            // --- Local-preferred tasks: local when available, cloud fallback ---
            TaskType::AnomalyExplanation
            | TaskType::EventNarrative
            | TaskType::QuickRiskAssessment
            | TaskType::SecurityTip => {
                if local_available {
                    RoutingDecision::UseLocal
                } else if cloud_available {
                    RoutingDecision::UseCloud
                } else {
                    RoutingDecision::Unavailable("No AI backend available for analysis".to_string())
                }
            }

            // --- Cloud-preferred tasks: cloud when available, local reduced fallback ---
            TaskType::DeepAnalysis
            | TaskType::ScanAnalysis
            | TaskType::AskClaw
            | TaskType::ReportGeneration => {
                if cloud_available {
                    if local_available {
                        RoutingDecision::UseCloudWithLocalFallback
                    } else {
                        RoutingDecision::UseCloud
                    }
                } else if local_available {
                    RoutingDecision::UseLocalReduced
                } else {
                    RoutingDecision::Unavailable(
                        "No AI backend available for deep analysis".to_string(),
                    )
                }
            }

            // --- Cloud-required tasks: no local fallback ---
            TaskType::Investigation
            | TaskType::ThreatHunt
            | TaskType::AgentScan
            | TaskType::PlaybookExecution => {
                if cloud_available {
                    if local_available {
                        RoutingDecision::UseCloudWithLocalFallback
                    } else {
                        RoutingDecision::UseCloud
                    }
                } else {
                    RoutingDecision::RequiresCloud
                }
            }
        };

        // Apply preference overrides and rate limiting for cloud decisions
        match &decision {
            RoutingDecision::UseCloud | RoutingDecision::UseCloudWithLocalFallback => {
                // Check rate limit
                if !self.check_rate_limit_inner(&prefs) {
                    // Rate limited: fall back to local if available
                    if local_available {
                        return RoutingDecision::UseLocalReduced;
                    } else {
                        return RoutingDecision::Unavailable(
                            "Cloud rate limit exceeded and no local model available".to_string(),
                        );
                    }
                }

                // Check if user confirmation is required
                if prefs.cloud_confirmation {
                    return RoutingDecision::AwaitConfirmation;
                }

                decision
            }
            _ => decision,
        }
    }

    /// Check if a cloud call is within the rate limit.
    fn check_rate_limit_inner(&self, prefs: &RoutingPreferences) -> bool {
        let mut window = self.cloud_call_window.write().unwrap();
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(3600);

        // Evict old entries
        while window.front().is_some_and(|t| *t < cutoff) {
            window.pop_front();
        }

        (window.len() as u32) < prefs.max_cloud_calls_per_hour
    }

    /// Check if a cloud call is within the rate limit (public API).
    pub fn check_rate_limit(&self) -> bool {
        let prefs = self.preferences.read().unwrap();
        self.check_rate_limit_inner(&prefs)
    }

    /// Record a cloud call for rate limiting.
    pub fn record_cloud_call(&self) {
        let mut window = self.cloud_call_window.write().unwrap();
        window.push_back(Instant::now());
        self.cloud_calls_this_hour.fetch_add(1, Ordering::Relaxed);
    }

    /// Update routing preferences.
    pub fn update_preferences(&self, prefs: RoutingPreferences) {
        *self.preferences.write().unwrap() = prefs;
    }

    /// Get current preferences.
    pub fn get_preferences(&self) -> RoutingPreferences {
        self.preferences.read().unwrap().clone()
    }

    /// Update per-feature routing configuration.
    pub fn update_feature_routing(&self, config: FeatureRoutingConfig) {
        *self.feature_routing.write().unwrap() = config;
    }

    /// Get current per-feature routing configuration.
    pub fn get_feature_routing(&self) -> FeatureRoutingConfig {
        self.feature_routing.read().unwrap().clone()
    }

    /// Get rate limit status.
    pub fn rate_limit_status(&self) -> RateLimitStatus {
        let mut window = self.cloud_call_window.write().unwrap();
        let prefs = self.preferences.read().unwrap();

        // Evict stale entries before reporting
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(3600);
        while window.front().is_some_and(|t| *t < cutoff) {
            window.pop_front();
        }

        let calls = window.len() as u32;
        RateLimitStatus {
            calls_this_hour: calls,
            max_per_hour: prefs.max_cloud_calls_per_hour,
            remaining: prefs.max_cloud_calls_per_hour.saturating_sub(calls),
        }
    }
}

impl Default for TaskRouter {
    fn default() -> Self {
        Self::new(RoutingPreferences::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Routing with both backends available ---

    #[test]
    fn route_triage_both_available() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::Triage, true, true);
        assert_eq!(decision, RoutingDecision::UseLocal);
    }

    #[test]
    fn route_context_update_both_available() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::ContextUpdate, true, true);
        assert_eq!(decision, RoutingDecision::UseLocal);
    }

    #[test]
    fn route_anomaly_both_available() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::AnomalyExplanation, true, true);
        assert_eq!(decision, RoutingDecision::UseLocal);
    }

    #[test]
    fn route_deep_analysis_both_available() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::DeepAnalysis, true, true);
        assert_eq!(decision, RoutingDecision::UseCloudWithLocalFallback);
    }

    #[test]
    fn route_investigation_both_available() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::Investigation, true, true);
        assert_eq!(decision, RoutingDecision::UseCloudWithLocalFallback);
    }

    #[test]
    fn route_agent_scan_both_available() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::AgentScan, true, true);
        assert_eq!(decision, RoutingDecision::UseCloudWithLocalFallback);
    }

    // --- Routing with local only ---

    #[test]
    fn route_triage_local_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::Triage, true, false);
        assert_eq!(decision, RoutingDecision::UseLocal);
    }

    #[test]
    fn route_anomaly_local_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::AnomalyExplanation, true, false);
        assert_eq!(decision, RoutingDecision::UseLocal);
    }

    #[test]
    fn route_deep_analysis_local_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::DeepAnalysis, true, false);
        assert_eq!(decision, RoutingDecision::UseLocalReduced);
    }

    #[test]
    fn route_investigation_local_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::Investigation, true, false);
        assert_eq!(decision, RoutingDecision::RequiresCloud);
    }

    #[test]
    fn route_agent_scan_local_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::AgentScan, true, false);
        assert_eq!(decision, RoutingDecision::RequiresCloud);
    }

    #[test]
    fn route_playbook_local_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::PlaybookExecution, true, false);
        assert_eq!(decision, RoutingDecision::RequiresCloud);
    }

    #[test]
    fn route_ask_claw_local_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::AskClaw, true, false);
        assert_eq!(decision, RoutingDecision::UseLocalReduced);
    }

    #[test]
    fn route_report_local_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::ReportGeneration, true, false);
        assert_eq!(decision, RoutingDecision::UseLocalReduced);
    }

    // --- Routing with cloud only ---

    #[test]
    fn route_triage_cloud_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::Triage, false, true);
        // Triage/ContextUpdate are local-only fast tasks — skip if no local
        assert!(matches!(decision, RoutingDecision::Unavailable(_)));
    }

    #[test]
    fn route_anomaly_cloud_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::AnomalyExplanation, false, true);
        assert_eq!(decision, RoutingDecision::UseCloud);
    }

    #[test]
    fn route_deep_analysis_cloud_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::DeepAnalysis, false, true);
        assert_eq!(decision, RoutingDecision::UseCloud);
    }

    #[test]
    fn route_investigation_cloud_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::Investigation, false, true);
        assert_eq!(decision, RoutingDecision::UseCloud);
    }

    // --- Routing with neither ---

    #[test]
    fn route_triage_neither() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::Triage, false, false);
        assert!(matches!(decision, RoutingDecision::Unavailable(_)));
    }

    #[test]
    fn route_anomaly_neither() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::AnomalyExplanation, false, false);
        assert!(matches!(decision, RoutingDecision::Unavailable(_)));
    }

    #[test]
    fn route_deep_analysis_neither() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::DeepAnalysis, false, false);
        assert!(matches!(decision, RoutingDecision::Unavailable(_)));
    }

    #[test]
    fn route_investigation_neither() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::Investigation, false, false);
        assert_eq!(decision, RoutingDecision::RequiresCloud);
    }

    #[test]
    fn route_agent_scan_neither() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::AgentScan, false, false);
        assert_eq!(decision, RoutingDecision::RequiresCloud);
    }

    // --- Rate limiting ---

    #[test]
    fn rate_limit_within_limit() {
        let router = TaskRouter::new(RoutingPreferences {
            max_cloud_calls_per_hour: 5,
            ..Default::default()
        });

        // Record 4 calls (under limit of 5)
        for _ in 0..4 {
            router.record_cloud_call();
        }

        assert!(router.check_rate_limit());

        // Cloud tasks should still route to cloud
        let decision = router.route(&TaskType::DeepAnalysis, true, true);
        assert_eq!(decision, RoutingDecision::UseCloudWithLocalFallback);
    }

    #[test]
    fn rate_limit_at_limit() {
        let router = TaskRouter::new(RoutingPreferences {
            max_cloud_calls_per_hour: 3,
            ..Default::default()
        });

        // Fill to limit
        for _ in 0..3 {
            router.record_cloud_call();
        }

        assert!(!router.check_rate_limit());

        // Cloud task should fall back to local reduced
        let decision = router.route(&TaskType::DeepAnalysis, true, true);
        assert_eq!(decision, RoutingDecision::UseLocalReduced);
    }

    #[test]
    fn rate_limit_over_limit_no_local() {
        let router = TaskRouter::new(RoutingPreferences {
            max_cloud_calls_per_hour: 2,
            ..Default::default()
        });

        for _ in 0..3 {
            router.record_cloud_call();
        }

        // Cloud task with no local should be unavailable
        let decision = router.route(&TaskType::DeepAnalysis, false, true);
        assert!(matches!(decision, RoutingDecision::Unavailable(_)));
    }

    #[test]
    fn rate_limit_does_not_affect_local_tasks() {
        let router = TaskRouter::new(RoutingPreferences {
            max_cloud_calls_per_hour: 1,
            ..Default::default()
        });

        // Exhaust rate limit
        for _ in 0..5 {
            router.record_cloud_call();
        }

        // Local tasks should still work
        let decision = router.route(&TaskType::Triage, true, true);
        assert_eq!(decision, RoutingDecision::UseLocal);
    }

    #[test]
    fn rate_limit_status_reports_correctly() {
        let router = TaskRouter::new(RoutingPreferences {
            max_cloud_calls_per_hour: 10,
            ..Default::default()
        });

        router.record_cloud_call();
        router.record_cloud_call();
        router.record_cloud_call();

        let status = router.rate_limit_status();
        assert_eq!(status.calls_this_hour, 3);
        assert_eq!(status.max_per_hour, 10);
        assert_eq!(status.remaining, 7);
    }

    // --- Preference updates ---

    #[test]
    fn update_preferences() {
        let router = TaskRouter::default();
        let prefs = router.get_preferences();
        assert!(prefs.prefer_local);
        assert_eq!(prefs.max_cloud_calls_per_hour, 10);

        router.update_preferences(RoutingPreferences {
            prefer_local: false,
            cloud_auto_escalate: false,
            cloud_confirmation: true,
            max_cloud_calls_per_hour: 50,
        });

        let updated = router.get_preferences();
        assert!(!updated.prefer_local);
        assert!(!updated.cloud_auto_escalate);
        assert!(updated.cloud_confirmation);
        assert_eq!(updated.max_cloud_calls_per_hour, 50);
    }

    // --- Confirmation mode ---

    #[test]
    fn confirmation_mode_for_cloud_tasks() {
        let router = TaskRouter::new(RoutingPreferences {
            cloud_confirmation: true,
            ..Default::default()
        });

        // Cloud-preferred task should require confirmation
        let decision = router.route(&TaskType::DeepAnalysis, true, true);
        assert_eq!(decision, RoutingDecision::AwaitConfirmation);
    }

    #[test]
    fn confirmation_mode_not_for_local_tasks() {
        let router = TaskRouter::new(RoutingPreferences {
            cloud_confirmation: true,
            ..Default::default()
        });

        // Local tasks should not be affected by confirmation mode
        let decision = router.route(&TaskType::Triage, true, true);
        assert_eq!(decision, RoutingDecision::UseLocal);
    }

    #[test]
    fn confirmation_mode_cloud_required_tasks() {
        let router = TaskRouter::new(RoutingPreferences {
            cloud_confirmation: true,
            ..Default::default()
        });

        // Cloud-required task should also require confirmation
        let decision = router.route(&TaskType::Investigation, true, true);
        assert_eq!(decision, RoutingDecision::AwaitConfirmation);
    }

    // --- Default preferences ---

    #[test]
    fn default_preferences() {
        let prefs = RoutingPreferences::default();
        assert!(prefs.prefer_local);
        assert!(prefs.cloud_auto_escalate);
        assert!(!prefs.cloud_confirmation);
        assert_eq!(prefs.max_cloud_calls_per_hour, 10);
    }

    // --- All task types covered ---

    #[test]
    fn all_task_types_produce_decisions() {
        let router = TaskRouter::default();
        let task_types = vec![
            TaskType::Triage,
            TaskType::ContextUpdate,
            TaskType::AnomalyExplanation,
            TaskType::EventNarrative,
            TaskType::QuickRiskAssessment,
            TaskType::SecurityTip,
            TaskType::DeepAnalysis,
            TaskType::Investigation,
            TaskType::ScanAnalysis,
            TaskType::AskClaw,
            TaskType::ReportGeneration,
            TaskType::ThreatHunt,
            TaskType::AgentScan,
            TaskType::PlaybookExecution,
        ];

        for task in &task_types {
            // Should never panic for any combination
            let _ = router.route(task, true, true);
            let _ = router.route(task, true, false);
            let _ = router.route(task, false, true);
            let _ = router.route(task, false, false);
        }
    }

    #[test]
    fn scan_analysis_cloud_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::ScanAnalysis, false, true);
        assert_eq!(decision, RoutingDecision::UseCloud);
    }

    #[test]
    fn threat_hunt_local_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::ThreatHunt, true, false);
        assert_eq!(decision, RoutingDecision::RequiresCloud);
    }

    #[test]
    fn security_tip_cloud_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::SecurityTip, false, true);
        assert_eq!(decision, RoutingDecision::UseCloud);
    }

    #[test]
    fn event_narrative_local_only() {
        let router = TaskRouter::default();
        let decision = router.route(&TaskType::EventNarrative, true, false);
        assert_eq!(decision, RoutingDecision::UseLocal);
    }

    // --- Feature routing override tests ---

    #[test]
    fn feature_override_force_local() {
        let router = TaskRouter::default();
        let mut config = FeatureRoutingConfig::default();
        config
            .overrides
            .insert(AiFeature::DeepAnalysis, FeatureBackendPreference::Local);
        router.update_feature_routing(config);

        // DeepAnalysis normally uses cloud; override forces local
        let decision = router.route(&TaskType::DeepAnalysis, true, true);
        assert_eq!(decision, RoutingDecision::UseLocal);
    }

    #[test]
    fn feature_override_force_cloud() {
        let router = TaskRouter::default();
        let mut config = FeatureRoutingConfig::default();
        config
            .overrides
            .insert(AiFeature::EventTriage, FeatureBackendPreference::Cloud);
        router.update_feature_routing(config);

        // Triage normally uses local; override forces cloud
        let decision = router.route(&TaskType::Triage, true, true);
        assert_eq!(decision, RoutingDecision::UseCloudWithLocalFallback);
    }

    #[test]
    fn feature_override_cloud_unavailable_falls_back_to_local() {
        let router = TaskRouter::default();
        let mut config = FeatureRoutingConfig::default();
        config
            .overrides
            .insert(AiFeature::EventExplanation, FeatureBackendPreference::Cloud);
        router.update_feature_routing(config);

        // Cloud forced but unavailable — should fall back to local reduced
        let decision = router.route(&TaskType::AnomalyExplanation, true, false);
        assert_eq!(decision, RoutingDecision::UseLocalReduced);
    }

    #[test]
    fn feature_override_local_unavailable() {
        let router = TaskRouter::default();
        let mut config = FeatureRoutingConfig::default();
        config
            .overrides
            .insert(AiFeature::DeepAnalysis, FeatureBackendPreference::Local);
        router.update_feature_routing(config);

        let decision = router.route(&TaskType::DeepAnalysis, false, true);
        assert!(matches!(decision, RoutingDecision::Unavailable(_)));
    }

    #[test]
    fn feature_override_auto_uses_default_matrix() {
        let router = TaskRouter::default();
        let mut config = FeatureRoutingConfig::default();
        config
            .overrides
            .insert(AiFeature::DeepAnalysis, FeatureBackendPreference::Auto);
        router.update_feature_routing(config);

        // Auto should use the default routing matrix
        let decision = router.route(&TaskType::DeepAnalysis, true, true);
        assert_eq!(decision, RoutingDecision::UseCloudWithLocalFallback);
    }

    #[test]
    fn context_update_always_uses_matrix_despite_override() {
        let router = TaskRouter::default();
        let mut config = FeatureRoutingConfig::default();
        config
            .overrides
            .insert(AiFeature::EventTriage, FeatureBackendPreference::Cloud);
        router.update_feature_routing(config);

        // ContextUpdate should always use the matrix (local), ignoring the cloud override
        let decision = router.route(&TaskType::ContextUpdate, true, true);
        assert_eq!(decision, RoutingDecision::UseLocal);
    }

    #[test]
    fn feature_routing_config_has_overrides() {
        let config = FeatureRoutingConfig::default();
        assert!(!config.has_overrides());

        let mut config = FeatureRoutingConfig::default();
        config
            .overrides
            .insert(AiFeature::AskClaw, FeatureBackendPreference::Local);
        assert!(config.has_overrides());

        let mut config = FeatureRoutingConfig::default();
        config
            .overrides
            .insert(AiFeature::AskClaw, FeatureBackendPreference::Auto);
        assert!(!config.has_overrides());
    }

    #[test]
    fn ai_feature_from_task_type_coverage() {
        // Verify all task types map to a feature
        assert_eq!(
            AiFeature::from_task_type(&TaskType::Triage),
            AiFeature::EventTriage
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::ContextUpdate),
            AiFeature::EventTriage
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::AnomalyExplanation),
            AiFeature::EventExplanation
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::EventNarrative),
            AiFeature::EventExplanation
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::QuickRiskAssessment),
            AiFeature::QuickRiskCheck
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::SecurityTip),
            AiFeature::QuickRiskCheck
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::DeepAnalysis),
            AiFeature::DeepAnalysis
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::Investigation),
            AiFeature::DeepAnalysis
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::ScanAnalysis),
            AiFeature::ScanAnalysis
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::AskClaw),
            AiFeature::AskClaw
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::ReportGeneration),
            AiFeature::Reports
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::ThreatHunt),
            AiFeature::ThreatHunting
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::AgentScan),
            AiFeature::AgentScan
        );
        assert_eq!(
            AiFeature::from_task_type(&TaskType::PlaybookExecution),
            AiFeature::AgentScan
        );
    }

    #[test]
    fn ai_feature_all_returns_nine() {
        assert_eq!(AiFeature::all().len(), 9);
    }
}
