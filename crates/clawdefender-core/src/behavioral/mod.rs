//! Behavioral baseline engine for ClawDefender.
//!
//! Builds per-server behavioral profiles by observing MCP and OS events during
//! a learning phase. After learning, profiles are updated incrementally using
//! exponential moving averages and conservative set expansion.

pub mod anomaly;
pub mod decision;
pub mod injection_detector;
pub mod killchain;
pub mod learning;
pub mod persistence;
pub mod profile;
pub mod update;

pub use anomaly::{
    AnomalyComponent, AnomalyDimension, AnomalyScore, AnomalyScorer, BehavioralEvent,
    BehavioralEventType,
};
pub use decision::{
    AutoBlockStats, BehavioralAuditData, BehavioralDecision, CalibrationResult, DecisionEngine,
    ThresholdResult,
};
pub use injection_detector::{
    InjectionDetector, InjectionDetectorConfig, InjectionScore, MessageDirection,
};
pub use killchain::{AttackPattern, KillChainDetector, KillChainEvent, KillChainMatch};
pub use learning::LearningEngine;
pub use persistence::ProfileStore;
pub use profile::{FileProfile, NetworkProfile, ServerProfile, TemporalProfile, ToolProfile};
pub use update::ProfileUpdater;
