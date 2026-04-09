//! Adaptive Threat Posture System
//!
//! Dynamically adjusts security monitoring intensity based on threat landscape,
//! power state, and user preferences.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Threat posture level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureLevel {
    Low,
    Normal,
    Elevated,
    High,
    Critical,
}

impl PostureLevel {
    /// Get default parameters for this posture level
    pub fn parameters(&self) -> PostureParameters {
        match self {
            PostureLevel::Low => PostureParameters {
                slm_triage_enabled: false,
                slm_triage_threshold: 999.0,
                anomaly_alert_threshold: 0.85,
                event_clustering_window_secs: 120,
                cloud_escalation_enabled: false,
                cloud_escalation_min_severity: "high".to_string(),
                auto_block_enabled: false,
                auto_block_min_kill_chain_stage: 5,
                sensor_noise_filter_percent: 90,
                scheduled_analyses: vec!["hourly_sweep".to_string()],
            },
            PostureLevel::Normal => PostureParameters {
                slm_triage_enabled: true,
                slm_triage_threshold: 0.5,
                anomaly_alert_threshold: 0.65,
                event_clustering_window_secs: 30,
                cloud_escalation_enabled: false,
                cloud_escalation_min_severity: "high".to_string(),
                auto_block_enabled: false,
                auto_block_min_kill_chain_stage: 5,
                sensor_noise_filter_percent: 70,
                scheduled_analyses: vec!["hourly_sweep".to_string(), "daily_review".to_string()],
            },
            PostureLevel::Elevated => PostureParameters {
                slm_triage_enabled: true,
                slm_triage_threshold: 0.3,
                anomaly_alert_threshold: 0.45,
                event_clustering_window_secs: 15,
                cloud_escalation_enabled: true,
                cloud_escalation_min_severity: "high".to_string(),
                auto_block_enabled: false,
                auto_block_min_kill_chain_stage: 5,
                sensor_noise_filter_percent: 40,
                scheduled_analyses: vec!["hourly_sweep".to_string(), "daily_review".to_string()],
            },
            PostureLevel::High => PostureParameters {
                slm_triage_enabled: true,
                slm_triage_threshold: 0.0,
                anomaly_alert_threshold: 0.3,
                event_clustering_window_secs: 10,
                cloud_escalation_enabled: true,
                cloud_escalation_min_severity: "medium".to_string(),
                auto_block_enabled: true,
                auto_block_min_kill_chain_stage: 4,
                sensor_noise_filter_percent: 10,
                scheduled_analyses: vec![
                    "hourly_sweep".to_string(),
                    "daily_review".to_string(),
                    "weekly_report".to_string(),
                ],
            },
            PostureLevel::Critical => PostureParameters {
                slm_triage_enabled: true,
                slm_triage_threshold: 0.0,
                anomaly_alert_threshold: 0.2,
                event_clustering_window_secs: 5,
                cloud_escalation_enabled: true,
                cloud_escalation_min_severity: "low".to_string(),
                auto_block_enabled: true,
                auto_block_min_kill_chain_stage: 2,
                sensor_noise_filter_percent: 0,
                scheduled_analyses: vec![
                    "hourly_sweep".to_string(),
                    "daily_review".to_string(),
                    "weekly_report".to_string(),
                ],
            },
        }
    }

    /// Get display name for UI
    pub fn display_name(&self) -> &str {
        match self {
            PostureLevel::Low => "Low",
            PostureLevel::Normal => "Normal",
            PostureLevel::Elevated => "Elevated",
            PostureLevel::High => "High",
            PostureLevel::Critical => "Critical",
        }
    }

    /// Get color code for UI
    pub fn color(&self) -> &str {
        match self {
            PostureLevel::Low => "green",
            PostureLevel::Normal => "green",
            PostureLevel::Elevated => "yellow",
            PostureLevel::High => "orange",
            PostureLevel::Critical => "red",
        }
    }

    /// Get next higher level
    pub fn escalate(&self) -> Option<PostureLevel> {
        match self {
            PostureLevel::Low => Some(PostureLevel::Normal),
            PostureLevel::Normal => Some(PostureLevel::Elevated),
            PostureLevel::Elevated => Some(PostureLevel::High),
            PostureLevel::High => Some(PostureLevel::Critical),
            PostureLevel::Critical => None,
        }
    }

    /// Get next lower level
    pub fn deescalate(&self) -> Option<PostureLevel> {
        match self {
            PostureLevel::Low => None,
            PostureLevel::Normal => Some(PostureLevel::Low),
            PostureLevel::Elevated => Some(PostureLevel::Normal),
            PostureLevel::High => Some(PostureLevel::Elevated),
            PostureLevel::Critical => Some(PostureLevel::High),
        }
    }
}

/// Posture-driven monitoring parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureParameters {
    pub slm_triage_enabled: bool,
    pub slm_triage_threshold: f64,
    pub anomaly_alert_threshold: f64,
    pub event_clustering_window_secs: u32,
    pub cloud_escalation_enabled: bool,
    pub cloud_escalation_min_severity: String,
    pub auto_block_enabled: bool,
    pub auto_block_min_kill_chain_stage: u32,
    pub sensor_noise_filter_percent: u32,
    pub scheduled_analyses: Vec<String>,
}

/// A single parameter adjustment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureAdjustment {
    pub parameter: String,
    pub old_value: String,
    pub new_value: String,
    pub reason: String,
}

/// Historical posture change record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureChange {
    pub id: Uuid,
    pub from: PostureLevel,
    pub to: PostureLevel,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
    pub trigger: PostureTrigger,
    pub auto: bool,
}

/// What triggered a posture change
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureTrigger {
    KillChainDetected { stage: u32 },
    SuspiciousEventBurst { count: u32, window_minutes: u32 },
    ThreatFeedMatch { server: String },
    InvestigationVerdict { verdict: String },
    DataExfiltrationDetected,
    NoSuspiciousEvents { hours: u32 },
    FalsePositiveVerdict,
    AllAlertsResolved,
    SystemIdle { hours: u32 },
    UserManual,
    BatteryLow,
    PowerSourceChange,
}

/// Posture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureConfig {
    pub auto_adjust_enabled: bool,
    pub battery_cap_enabled: bool,
    pub battery_force_low_threshold: u8,
    pub escalation_cooldown: Duration,
    pub deescalation_cooldown: Duration,
    pub max_auto_level: PostureLevel,
}

impl Default for PostureConfig {
    fn default() -> Self {
        Self {
            auto_adjust_enabled: true,
            battery_cap_enabled: true,
            battery_force_low_threshold: 20,
            escalation_cooldown: Duration::minutes(5),
            deescalation_cooldown: Duration::hours(1),
            max_auto_level: PostureLevel::Critical,
        }
    }
}

/// Power state tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerState {
    pub on_battery: bool,
    pub battery_percent: Option<u8>,
    pub last_checked: DateTime<Utc>,
}

impl Default for PowerState {
    fn default() -> Self {
        Self {
            on_battery: false,
            battery_percent: None,
            last_checked: Utc::now(),
        }
    }
}

/// Main threat posture state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPosture {
    pub current_level: PostureLevel,
    pub level_since: DateTime<Utc>,
    pub reason: String,
    pub auto_adjustments: Vec<PostureAdjustment>,
    pub manual_override: Option<PostureLevel>,
    pub history: Vec<PostureChange>,
    pub power_state: PowerState,
    pub config: PostureConfig,
}

impl Default for ThreatPosture {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatPosture {
    /// Create new posture at Normal level
    pub fn new() -> Self {
        Self {
            current_level: PostureLevel::Normal,
            level_since: Utc::now(),
            reason: "Initial state".to_string(),
            auto_adjustments: Vec::new(),
            manual_override: None,
            history: Vec::new(),
            power_state: PowerState::default(),
            config: PostureConfig::default(),
        }
    }

    /// Escalate by one level
    pub fn escalate(&mut self, trigger: PostureTrigger) -> Option<PostureChange> {
        let target = self.current_level.escalate()?;
        self.try_escalate_to(target, trigger)
    }

    /// Try to escalate to specific level
    pub fn try_escalate_to(
        &mut self,
        target: PostureLevel,
        trigger: PostureTrigger,
    ) -> Option<PostureChange> {
        // Check if already at or above target
        if self.current_level >= target {
            debug!("Already at or above target level {:?}", target);
            return None;
        }

        // Check cooldown
        let elapsed = Utc::now() - self.level_since;
        if elapsed < self.config.escalation_cooldown {
            debug!("Escalation cooldown not met");
            return None;
        }

        // Check max auto level
        if !self.has_override() && target > self.config.max_auto_level {
            warn!("Auto escalation blocked by max_auto_level config");
            return None;
        }

        let from = self.current_level;
        let reason = format!("Escalated due to {:?}", trigger);

        let change = PostureChange {
            id: Uuid::new_v4(),
            from,
            to: target,
            reason: reason.clone(),
            timestamp: Utc::now(),
            trigger,
            auto: true,
        };

        self.current_level = target;
        self.level_since = Utc::now();
        self.reason = reason;
        self.history.push(change.clone());

        info!("Posture escalated from {:?} to {:?}", from, target);

        Some(change)
    }

    /// Try to de-escalate by one level
    pub fn try_deescalate(&mut self, trigger: PostureTrigger) -> Option<PostureChange> {
        let target = self.current_level.deescalate()?;

        // Check cooldown
        let elapsed = Utc::now() - self.level_since;
        if elapsed < self.config.deescalation_cooldown {
            debug!("De-escalation cooldown not met");
            return None;
        }

        let from = self.current_level;
        let reason = format!("De-escalated due to {:?}", trigger);

        let change = PostureChange {
            id: Uuid::new_v4(),
            from,
            to: target,
            reason: reason.clone(),
            timestamp: Utc::now(),
            trigger,
            auto: true,
        };

        self.current_level = target;
        self.level_since = Utc::now();
        self.reason = reason;
        self.history.push(change.clone());

        info!("Posture de-escalated from {:?} to {:?}", from, target);

        Some(change)
    }

    /// Try to de-escalate to a specific level
    pub fn try_deescalate_to(
        &mut self,
        target: PostureLevel,
        trigger: PostureTrigger,
    ) -> Option<PostureChange> {
        // Check if already at or below target
        if self.current_level <= target {
            debug!("Already at or below target level {:?}", target);
            return None;
        }

        // Check cooldown
        let elapsed = Utc::now() - self.level_since;
        if elapsed < self.config.deescalation_cooldown {
            debug!("De-escalation cooldown not met");
            return None;
        }

        let from = self.current_level;
        let reason = format!("De-escalated due to {:?}", trigger);

        let change = PostureChange {
            id: Uuid::new_v4(),
            from,
            to: target,
            reason: reason.clone(),
            timestamp: Utc::now(),
            trigger,
            auto: true,
        };

        self.current_level = target;
        self.level_since = Utc::now();
        self.reason = reason;
        self.history.push(change.clone());

        info!("Posture de-escalated from {:?} to {:?}", from, target);

        Some(change)
    }

    /// Set manual override
    pub fn set_override(&mut self, level: PostureLevel) -> PostureChange {
        let from = self.current_level;
        let reason = format!("Manual override to {:?}", level);

        let change = PostureChange {
            id: Uuid::new_v4(),
            from,
            to: level,
            reason: reason.clone(),
            timestamp: Utc::now(),
            trigger: PostureTrigger::UserManual,
            auto: false,
        };

        self.manual_override = Some(level);
        self.current_level = level;
        self.level_since = Utc::now();
        self.reason = reason;
        self.history.push(change.clone());

        info!("Manual override set to {:?}", level);

        change
    }

    /// Clear manual override
    pub fn clear_override(&mut self) -> PostureChange {
        let from = self.current_level;
        let to = self.current_level; // Stay at current level when clearing
        let reason = "Manual override cleared".to_string();

        let change = PostureChange {
            id: Uuid::new_v4(),
            from,
            to,
            reason: reason.clone(),
            timestamp: Utc::now(),
            trigger: PostureTrigger::UserManual,
            auto: false,
        };

        self.manual_override = None;
        self.reason = reason;
        self.history.push(change.clone());

        info!("Manual override cleared");

        change
    }

    /// Check if manual override is active
    pub fn has_override(&self) -> bool {
        self.manual_override.is_some()
    }

    /// Get effective level (considering override and battery)
    pub fn effective_level(&self) -> PostureLevel {
        let mut level = if let Some(override_level) = self.manual_override {
            override_level
        } else {
            self.current_level
        };

        // Apply battery constraints
        if self.config.battery_cap_enabled && self.power_state.on_battery {
            if let Some(pct) = self.power_state.battery_percent {
                if pct < self.config.battery_force_low_threshold {
                    level = PostureLevel::Low;
                } else if level > PostureLevel::Normal && !self.has_override() {
                    level = PostureLevel::Normal;
                }
            } else if level > PostureLevel::Normal && !self.has_override() {
                level = PostureLevel::Normal;
            }
        }

        level
    }

    /// Get current parameters
    pub fn get_parameters(&self) -> PostureParameters {
        self.effective_level().parameters()
    }

    /// Update power state
    pub fn update_power_state(
        &mut self,
        on_battery: bool,
        battery_percent: Option<u8>,
    ) -> Option<PostureChange> {
        let was_on_battery = self.power_state.on_battery;
        let old_effective = self.effective_level();

        self.power_state = PowerState {
            on_battery,
            battery_percent,
            last_checked: Utc::now(),
        };

        let new_effective = self.effective_level();

        // Create change record if effective level changed
        if old_effective != new_effective {
            let trigger = if on_battery && !was_on_battery {
                if let Some(pct) = battery_percent {
                    if pct < self.config.battery_force_low_threshold {
                        PostureTrigger::BatteryLow
                    } else {
                        PostureTrigger::PowerSourceChange
                    }
                } else {
                    PostureTrigger::PowerSourceChange
                }
            } else {
                PostureTrigger::PowerSourceChange
            };

            let reason = format!("Power state change: {:?}", trigger);

            let change = PostureChange {
                id: Uuid::new_v4(),
                from: old_effective,
                to: new_effective,
                reason: reason.clone(),
                timestamp: Utc::now(),
                trigger,
                auto: true,
            };

            self.history.push(change.clone());

            info!(
                "Power state change caused effective level change: {:?} -> {:?}",
                old_effective, new_effective
            );

            Some(change)
        } else {
            None
        }
    }

    /// Evaluate if event should trigger escalation
    pub fn evaluate_escalation(&mut self, event: &PostureEvent) -> Option<PostureChange> {
        if !self.config.auto_adjust_enabled {
            return None;
        }

        let target_trigger = match &event.event_type {
            PostureEventType::KillChainProgression { stage } => {
                let target = if *stage >= 3 {
                    PostureLevel::High
                } else {
                    PostureLevel::Elevated
                };
                return self.try_escalate_to(
                    target,
                    PostureTrigger::KillChainDetected { stage: *stage },
                );
            }
            PostureEventType::SuspiciousBurst {
                count,
                window_minutes,
            } => {
                let target = if *count >= 10 {
                    PostureLevel::High
                } else if *count >= 3 {
                    PostureLevel::Elevated
                } else {
                    return None;
                };
                return self.try_escalate_to(
                    target,
                    PostureTrigger::SuspiciousEventBurst {
                        count: *count,
                        window_minutes: *window_minutes,
                    },
                );
            }
            PostureEventType::ThreatFeedMatch { server } => {
                return self.try_escalate_to(
                    PostureLevel::Elevated,
                    PostureTrigger::ThreatFeedMatch {
                        server: server.clone(),
                    },
                );
            }
            PostureEventType::InvestigationComplete { verdict } => {
                if verdict == "confirmed_threat" {
                    return self.try_escalate_to(
                        PostureLevel::High,
                        PostureTrigger::InvestigationVerdict {
                            verdict: verdict.clone(),
                        },
                    );
                }
                return None;
            }
            PostureEventType::DataExfiltration => {
                return self.try_escalate_to(
                    PostureLevel::Critical,
                    PostureTrigger::DataExfiltrationDetected,
                );
            }
            PostureEventType::SimulationGap { gap_count } => {
                if *gap_count > 3 {
                    return self.try_escalate_to(
                        PostureLevel::Elevated,
                        PostureTrigger::NoSuspiciousEvents { hours: 0 },
                    );
                }
                return None;
            }
        };

        None
    }

    /// Evaluate if context should trigger de-escalation
    pub fn evaluate_deescalation(
        &mut self,
        context: &DeescalationContext,
    ) -> Option<PostureChange> {
        if !self.config.auto_adjust_enabled {
            return None;
        }

        // All alerts resolved -> go to Normal
        if context.all_alerts_resolved && self.current_level > PostureLevel::Normal {
            return self.try_deescalate_to(
                PostureLevel::Normal,
                PostureTrigger::AllAlertsResolved,
            );
        }

        // False positive verdict -> step down one
        if let Some(verdict) = &context.investigation_verdict {
            if verdict == "false_positive" {
                return self.try_deescalate(PostureTrigger::FalsePositiveVerdict);
            }
        }

        // No suspicious events for 4 hours -> step down to Low
        if context.hours_since_last_suspicious >= 4 && self.current_level > PostureLevel::Low {
            return self.try_deescalate_to(
                PostureLevel::Low,
                PostureTrigger::SystemIdle {
                    hours: context.hours_since_last_suspicious,
                },
            );
        }

        // No suspicious events for 1 hour -> step down one
        if context.hours_since_last_suspicious >= 1 {
            return self.try_deescalate(PostureTrigger::NoSuspiciousEvents {
                hours: context.hours_since_last_suspicious,
            });
        }

        None
    }

    /// Get recent history
    pub fn get_history(&self, count: usize) -> Vec<&PostureChange> {
        self.history.iter().rev().take(count).collect()
    }

    /// Get posture info for UI
    pub fn get_posture_info(&self) -> PostureInfo {
        let effective = self.effective_level();
        PostureInfo {
            level: effective,
            level_name: effective.display_name().to_string(),
            color: effective.color().to_string(),
            reason: self.reason.clone(),
            duration_minutes: self.current_duration().num_minutes(),
            auto_adjust_enabled: self.config.auto_adjust_enabled,
            has_override: self.has_override(),
            on_battery: self.power_state.on_battery,
            active_adjustments: self.auto_adjustments.clone(),
        }
    }

    /// Get duration at current level
    pub fn current_duration(&self) -> Duration {
        Utc::now() - self.level_since
    }

    /// Update configuration
    pub fn update_config(&mut self, config: PostureConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &PostureConfig {
        &self.config
    }
}

/// Input for automatic escalation evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureEvent {
    pub event_type: PostureEventType,
    pub timestamp: DateTime<Utc>,
}

/// Type of posture event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureEventType {
    KillChainProgression { stage: u32 },
    SuspiciousBurst { count: u32, window_minutes: u32 },
    ThreatFeedMatch { server: String },
    InvestigationComplete { verdict: String },
    DataExfiltration,
    SimulationGap { gap_count: u32 },
}

/// Context for de-escalation evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeescalationContext {
    pub hours_since_last_suspicious: u32,
    pub all_alerts_resolved: bool,
    pub last_event_time: Option<DateTime<Utc>>,
    pub investigation_verdict: Option<String>,
}

/// Posture information for UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureInfo {
    pub level: PostureLevel,
    pub level_name: String,
    pub color: String,
    pub reason: String,
    pub duration_minutes: i64,
    pub auto_adjust_enabled: bool,
    pub has_override: bool,
    pub on_battery: bool,
    pub active_adjustments: Vec<PostureAdjustment>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_construction() {
        let posture = ThreatPosture::new();
        assert_eq!(posture.current_level, PostureLevel::Normal);
        assert_eq!(posture.reason, "Initial state");
        assert!(!posture.has_override());
        assert!(posture.config.auto_adjust_enabled);
    }

    #[test]
    fn test_posture_level_ordering() {
        assert!(PostureLevel::Low < PostureLevel::Normal);
        assert!(PostureLevel::Normal < PostureLevel::Elevated);
        assert!(PostureLevel::Elevated < PostureLevel::High);
        assert!(PostureLevel::High < PostureLevel::Critical);
    }

    #[test]
    fn test_posture_level_escalate() {
        assert_eq!(PostureLevel::Low.escalate(), Some(PostureLevel::Normal));
        assert_eq!(
            PostureLevel::Normal.escalate(),
            Some(PostureLevel::Elevated)
        );
        assert_eq!(PostureLevel::Elevated.escalate(), Some(PostureLevel::High));
        assert_eq!(PostureLevel::High.escalate(), Some(PostureLevel::Critical));
        assert_eq!(PostureLevel::Critical.escalate(), None);
    }

    #[test]
    fn test_posture_level_deescalate() {
        assert_eq!(PostureLevel::Low.deescalate(), None);
        assert_eq!(PostureLevel::Normal.deescalate(), Some(PostureLevel::Low));
        assert_eq!(
            PostureLevel::Elevated.deescalate(),
            Some(PostureLevel::Normal)
        );
        assert_eq!(
            PostureLevel::High.deescalate(),
            Some(PostureLevel::Elevated)
        );
        assert_eq!(
            PostureLevel::Critical.deescalate(),
            Some(PostureLevel::High)
        );
    }

    #[test]
    fn test_escalate_by_one() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let change = posture.escalate(PostureTrigger::UserManual);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Elevated);
    }

    #[test]
    fn test_escalate_kill_chain_high_stage() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::KillChainProgression { stage: 4 },
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::High);
    }

    #[test]
    fn test_escalate_kill_chain_low_stage() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::KillChainProgression { stage: 2 },
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Elevated);
    }

    #[test]
    fn test_escalate_suspicious_burst_moderate() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::SuspiciousBurst {
                count: 5,
                window_minutes: 10,
            },
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Elevated);
    }

    #[test]
    fn test_escalate_suspicious_burst_high() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::SuspiciousBurst {
                count: 12,
                window_minutes: 10,
            },
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::High);
    }

    #[test]
    fn test_escalate_threat_feed_match() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::ThreatFeedMatch {
                server: "malicious.com".to_string(),
            },
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Elevated);
    }

    #[test]
    fn test_escalate_investigation_confirmed() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::InvestigationComplete {
                verdict: "confirmed_threat".to_string(),
            },
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::High);
    }

    #[test]
    fn test_escalate_data_exfiltration() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::DataExfiltration,
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Critical);
    }

    #[test]
    fn test_escalate_simulation_gap() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::SimulationGap { gap_count: 5 },
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Elevated);
    }

    #[test]
    fn test_deescalate_by_one() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;
        posture.config.deescalation_cooldown = Duration::zero();

        let change = posture.try_deescalate(PostureTrigger::UserManual);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Elevated);
    }

    #[test]
    fn test_deescalate_no_suspicious_events_one_hour() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::Elevated;
        posture.config.deescalation_cooldown = Duration::zero();

        let context = DeescalationContext {
            hours_since_last_suspicious: 1,
            all_alerts_resolved: false,
            last_event_time: None,
            investigation_verdict: None,
        };

        let change = posture.evaluate_deescalation(&context);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Normal);
    }

    #[test]
    fn test_deescalate_false_positive() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;
        posture.config.deescalation_cooldown = Duration::zero();

        let context = DeescalationContext {
            hours_since_last_suspicious: 0,
            all_alerts_resolved: false,
            last_event_time: None,
            investigation_verdict: Some("false_positive".to_string()),
        };

        let change = posture.evaluate_deescalation(&context);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Elevated);
    }

    #[test]
    fn test_deescalate_all_alerts_resolved() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::Critical;
        posture.config.deescalation_cooldown = Duration::zero();

        let context = DeescalationContext {
            hours_since_last_suspicious: 0,
            all_alerts_resolved: true,
            last_event_time: None,
            investigation_verdict: None,
        };

        let change = posture.evaluate_deescalation(&context);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Normal);
    }

    #[test]
    fn test_deescalate_system_idle_four_hours() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;
        posture.config.deescalation_cooldown = Duration::zero();

        let context = DeescalationContext {
            hours_since_last_suspicious: 4,
            all_alerts_resolved: false,
            last_event_time: None,
            investigation_verdict: None,
        };

        let change = posture.evaluate_deescalation(&context);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Low);
    }

    #[test]
    fn test_deescalation_cooldown_enforcement() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;
        posture.config.deescalation_cooldown = Duration::hours(1);
        posture.level_since = Utc::now();

        let change = posture.try_deescalate(PostureTrigger::UserManual);
        assert!(change.is_none());
    }

    #[test]
    fn test_escalation_cooldown_enforcement() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::minutes(5);
        posture.level_since = Utc::now();

        let change = posture.escalate(PostureTrigger::UserManual);
        assert!(change.is_none());
    }

    #[test]
    fn test_gradual_deescalation() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::Critical;
        posture.config.deescalation_cooldown = Duration::zero();

        // Should step down one level at a time
        let change = posture.try_deescalate(PostureTrigger::UserManual);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::High);

        let change = posture.try_deescalate(PostureTrigger::UserManual);
        assert!(change.is_some());
        assert_eq!(posture.current_level, PostureLevel::Elevated);
    }

    #[test]
    fn test_manual_override_set() {
        let mut posture = ThreatPosture::new();
        let change = posture.set_override(PostureLevel::Critical);

        assert_eq!(posture.current_level, PostureLevel::Critical);
        assert_eq!(posture.manual_override, Some(PostureLevel::Critical));
        assert!(posture.has_override());
        assert!(!change.auto);
    }

    #[test]
    fn test_manual_override_clear() {
        let mut posture = ThreatPosture::new();
        posture.set_override(PostureLevel::High);

        let change = posture.clear_override();
        assert!(!posture.has_override());
        assert_eq!(posture.manual_override, None);
        assert!(!change.auto);
    }

    #[test]
    fn test_effective_level_with_override() {
        let mut posture = ThreatPosture::new();
        posture.set_override(PostureLevel::Low);

        assert_eq!(posture.effective_level(), PostureLevel::Low);
    }

    #[test]
    fn test_battery_cap_at_normal() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;
        posture.config.battery_cap_enabled = true;
        posture.config.escalation_cooldown = Duration::zero();

        posture.update_power_state(true, Some(50));

        assert_eq!(posture.effective_level(), PostureLevel::Normal);
    }

    #[test]
    fn test_battery_force_low_below_threshold() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;
        posture.config.battery_cap_enabled = true;
        posture.config.battery_force_low_threshold = 20;

        posture.update_power_state(true, Some(15));

        assert_eq!(posture.effective_level(), PostureLevel::Low);
    }

    #[test]
    fn test_power_restore_removes_cap() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;
        posture.config.battery_cap_enabled = true;

        posture.update_power_state(true, Some(50));
        assert_eq!(posture.effective_level(), PostureLevel::Normal);

        posture.update_power_state(false, None);
        assert_eq!(posture.effective_level(), PostureLevel::High);
    }

    #[test]
    fn test_battery_override_bypasses_cap() {
        let mut posture = ThreatPosture::new();
        posture.set_override(PostureLevel::Critical);
        posture.config.battery_cap_enabled = true;

        posture.update_power_state(true, Some(50));

        // Override should take precedence even on battery
        assert_eq!(posture.effective_level(), PostureLevel::Critical);
    }

    #[test]
    fn test_parameters_low() {
        let params = PostureLevel::Low.parameters();
        assert!(!params.slm_triage_enabled);
        assert_eq!(params.slm_triage_threshold, 999.0);
        assert_eq!(params.anomaly_alert_threshold, 0.85);
        assert_eq!(params.event_clustering_window_secs, 120);
        assert!(!params.cloud_escalation_enabled);
        assert!(!params.auto_block_enabled);
        assert_eq!(params.sensor_noise_filter_percent, 90);
        assert_eq!(params.scheduled_analyses.len(), 1);
    }

    #[test]
    fn test_parameters_normal() {
        let params = PostureLevel::Normal.parameters();
        assert!(params.slm_triage_enabled);
        assert_eq!(params.slm_triage_threshold, 0.5);
        assert_eq!(params.anomaly_alert_threshold, 0.65);
        assert_eq!(params.event_clustering_window_secs, 30);
        assert!(!params.cloud_escalation_enabled);
        assert!(!params.auto_block_enabled);
        assert_eq!(params.sensor_noise_filter_percent, 70);
        assert_eq!(params.scheduled_analyses.len(), 2);
    }

    #[test]
    fn test_parameters_elevated() {
        let params = PostureLevel::Elevated.parameters();
        assert!(params.slm_triage_enabled);
        assert_eq!(params.slm_triage_threshold, 0.3);
        assert_eq!(params.anomaly_alert_threshold, 0.45);
        assert_eq!(params.event_clustering_window_secs, 15);
        assert!(params.cloud_escalation_enabled);
        assert_eq!(params.cloud_escalation_min_severity, "high");
        assert!(!params.auto_block_enabled);
        assert_eq!(params.sensor_noise_filter_percent, 40);
    }

    #[test]
    fn test_parameters_high() {
        let params = PostureLevel::High.parameters();
        assert!(params.slm_triage_enabled);
        assert_eq!(params.slm_triage_threshold, 0.0);
        assert_eq!(params.anomaly_alert_threshold, 0.3);
        assert_eq!(params.event_clustering_window_secs, 10);
        assert!(params.cloud_escalation_enabled);
        assert_eq!(params.cloud_escalation_min_severity, "medium");
        assert!(params.auto_block_enabled);
        assert_eq!(params.auto_block_min_kill_chain_stage, 4);
        assert_eq!(params.sensor_noise_filter_percent, 10);
        assert_eq!(params.scheduled_analyses.len(), 3);
    }

    #[test]
    fn test_parameters_critical() {
        let params = PostureLevel::Critical.parameters();
        assert!(params.slm_triage_enabled);
        assert_eq!(params.slm_triage_threshold, 0.0);
        assert_eq!(params.anomaly_alert_threshold, 0.2);
        assert_eq!(params.event_clustering_window_secs, 5);
        assert!(params.cloud_escalation_enabled);
        assert_eq!(params.cloud_escalation_min_severity, "low");
        assert!(params.auto_block_enabled);
        assert_eq!(params.auto_block_min_kill_chain_stage, 2);
        assert_eq!(params.sensor_noise_filter_percent, 0);
        assert_eq!(params.scheduled_analyses.len(), 3);
    }

    #[test]
    fn test_posture_info_generation() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;

        let info = posture.get_posture_info();
        assert_eq!(info.level, PostureLevel::High);
        assert_eq!(info.level_name, "High");
        assert_eq!(info.color, "orange");
        assert!(info.auto_adjust_enabled);
        assert!(!info.has_override);
    }

    #[test]
    fn test_history_tracking() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        posture.escalate(PostureTrigger::UserManual);
        posture.escalate(PostureTrigger::UserManual);

        assert_eq!(posture.history.len(), 2);
        let recent = posture.get_history(1);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_config_update() {
        let mut posture = ThreatPosture::new();
        let mut config = PostureConfig::default();
        config.auto_adjust_enabled = false;

        posture.update_config(config);
        assert!(!posture.get_config().auto_adjust_enabled);
    }

    #[test]
    fn test_auto_adjust_disabled_prevents_escalation() {
        let mut posture = ThreatPosture::new();
        posture.config.auto_adjust_enabled = false;

        let event = PostureEvent {
            event_type: PostureEventType::DataExfiltration,
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_none());
    }

    #[test]
    fn test_auto_adjust_disabled_prevents_deescalation() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;
        posture.config.auto_adjust_enabled = false;

        let context = DeescalationContext {
            hours_since_last_suspicious: 5,
            all_alerts_resolved: true,
            last_event_time: None,
            investigation_verdict: None,
        };

        let change = posture.evaluate_deescalation(&context);
        assert!(change.is_none());
    }

    #[test]
    fn test_posture_change_includes_trigger() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let change = posture.escalate(PostureTrigger::BatteryLow);
        assert!(change.is_some());

        let change = change.unwrap();
        matches!(change.trigger, PostureTrigger::BatteryLow);
    }

    #[test]
    fn test_display_names() {
        assert_eq!(PostureLevel::Low.display_name(), "Low");
        assert_eq!(PostureLevel::Normal.display_name(), "Normal");
        assert_eq!(PostureLevel::Elevated.display_name(), "Elevated");
        assert_eq!(PostureLevel::High.display_name(), "High");
        assert_eq!(PostureLevel::Critical.display_name(), "Critical");
    }

    #[test]
    fn test_colors() {
        assert_eq!(PostureLevel::Low.color(), "green");
        assert_eq!(PostureLevel::Normal.color(), "green");
        assert_eq!(PostureLevel::Elevated.color(), "yellow");
        assert_eq!(PostureLevel::High.color(), "orange");
        assert_eq!(PostureLevel::Critical.color(), "red");
    }

    #[test]
    fn test_duration_tracking() {
        let posture = ThreatPosture::new();
        let duration = posture.current_duration();
        assert!(duration >= Duration::zero());
    }

    #[test]
    fn test_combined_battery_and_override() {
        let mut posture = ThreatPosture::new();
        posture.set_override(PostureLevel::High);
        posture.config.battery_cap_enabled = true;

        // With override, battery cap should not apply
        posture.update_power_state(true, Some(50));
        assert_eq!(posture.effective_level(), PostureLevel::High);

        // But force-low threshold should still apply
        posture.update_power_state(true, Some(15));
        assert_eq!(posture.effective_level(), PostureLevel::Low);
    }

    #[test]
    fn test_edge_escalate_at_target_level() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;
        posture.config.escalation_cooldown = Duration::zero();

        let change = posture.try_escalate_to(PostureLevel::High, PostureTrigger::UserManual);
        assert!(change.is_none());
    }

    #[test]
    fn test_edge_deescalate_at_low() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::Low;
        posture.config.deescalation_cooldown = Duration::zero();

        let change = posture.try_deescalate(PostureTrigger::UserManual);
        assert!(change.is_none());
    }

    #[test]
    fn test_max_auto_level_enforcement() {
        let mut posture = ThreatPosture::new();
        posture.config.max_auto_level = PostureLevel::Elevated;
        posture.config.escalation_cooldown = Duration::zero();

        let change = posture.try_escalate_to(PostureLevel::High, PostureTrigger::UserManual);
        assert!(change.is_none());
    }

    #[test]
    fn test_power_state_change_creates_history() {
        let mut posture = ThreatPosture::new();
        posture.current_level = PostureLevel::High;
        posture.config.battery_cap_enabled = true;

        let change = posture.update_power_state(true, Some(50));
        assert!(change.is_some());
        assert_eq!(posture.history.len(), 1);
    }

    #[test]
    fn test_investigation_non_threat_verdict_no_escalation() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::InvestigationComplete {
                verdict: "benign".to_string(),
            },
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_none());
    }

    #[test]
    fn test_simulation_gap_below_threshold() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::SimulationGap { gap_count: 2 },
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_none());
    }

    #[test]
    fn test_suspicious_burst_below_threshold() {
        let mut posture = ThreatPosture::new();
        posture.config.escalation_cooldown = Duration::zero();

        let event = PostureEvent {
            event_type: PostureEventType::SuspiciousBurst {
                count: 2,
                window_minutes: 10,
            },
            timestamp: Utc::now(),
        };

        let change = posture.evaluate_escalation(&event);
        assert!(change.is_none());
    }
}
