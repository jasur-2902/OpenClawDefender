//! Telemetry data aggregator.
//!
//! Collects data points in memory throughout the day and produces
//! aggregate reports. All data is lost on restart, which is acceptable
//! since reports are submitted daily.
//!
//! **Privacy**: method signatures enforce that no PII can enter the
//! aggregator — only entry IDs, category strings, scores, and counts.

use std::collections::HashMap;

use chrono::Utc;

use super::types::{
    AnomalyAggregate, BlocklistMatchReport, IoCMatchRates, KillchainTriggerReport, ScannerSummary,
    TelemetryReport, REPORT_SCHEMA_VERSION,
};

/// Collects telemetry data points and produces aggregate reports.
#[derive(Debug, Default)]
pub struct TelemetryAggregator {
    blocklist_matches: Vec<BlocklistMatchReport>,
    anomaly_events: Vec<AnomalyEvent>,
    auto_blocks: u64,
    killchain_triggers: Vec<KillchainTriggerReport>,
    ioc_network: u64,
    ioc_file: u64,
    ioc_behavioral: u64,
    scan_categories: HashMap<String, bool>,
    scan_severity_counts: HashMap<String, u64>,
}

/// Internal anomaly event for aggregation.
#[derive(Debug)]
struct AnomalyEvent {
    _score: f64,
    dimension: String,
}

impl TelemetryAggregator {
    /// Create a new empty aggregator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a blocklist match. Only the entry ID is recorded, not the server name.
    pub fn record_blocklist_match(&mut self, entry_id: &str) {
        self.blocklist_matches.push(BlocklistMatchReport {
            entry_id: entry_id.to_string(),
            matched: true,
            date: Utc::now().format("%Y-%m-%d").to_string(),
        });
    }

    /// Record an anomaly event with its score and top contributing dimension.
    pub fn record_anomaly_event(&mut self, score: f64, top_dimension: &str) {
        self.anomaly_events.push(AnomalyEvent {
            _score: score,
            dimension: top_dimension.to_string(),
        });
    }

    /// Record an automatic block triggered by anomaly detection.
    pub fn record_auto_block(&mut self) {
        self.auto_blocks += 1;
    }

    /// Record a kill chain pattern trigger.
    pub fn record_killchain_trigger(&mut self, pattern_id: &str, steps: u32, decision: &str) {
        self.killchain_triggers.push(KillchainTriggerReport {
            pattern_id: pattern_id.to_string(),
            steps_matched: steps,
            user_decision: decision.to_string(),
        });
    }

    /// Record an IoC match by indicator type ("network", "file", or "behavioral").
    pub fn record_ioc_match(&mut self, indicator_type: &str) {
        match indicator_type {
            "network" => self.ioc_network += 1,
            "file" => self.ioc_file += 1,
            "behavioral" => self.ioc_behavioral += 1,
            _ => {
                tracing::warn!(
                    indicator_type,
                    "unknown IoC indicator type, counting as behavioral"
                );
                self.ioc_behavioral += 1;
            }
        }
    }

    /// Record a scanner finding. Only categories and severity are recorded.
    pub fn record_scan_finding(&mut self, category: &str, severity: &str) {
        self.scan_categories.insert(category.to_string(), true);
        *self
            .scan_severity_counts
            .entry(severity.to_string())
            .or_insert(0) += 1;
    }

    /// Build a complete telemetry report from accumulated data.
    pub fn build_report(&self, installation_id: &str) -> TelemetryReport {
        let anomaly_aggregate = self.aggregate_anomalies();

        let ioc_match_rates = IoCMatchRates {
            total_matches: self.ioc_network + self.ioc_file + self.ioc_behavioral,
            network_matches: self.ioc_network,
            file_matches: self.ioc_file,
            behavioral_matches: self.ioc_behavioral,
        };

        let scanner_summary =
            if self.scan_categories.is_empty() && self.scan_severity_counts.is_empty() {
                None
            } else {
                Some(ScannerSummary {
                    finding_categories: self.scan_categories.keys().cloned().collect(),
                    severity_counts: self.scan_severity_counts.clone(),
                })
            };

        TelemetryReport {
            installation_id: installation_id.to_string(),
            report_date: Utc::now().format("%Y-%m-%d").to_string(),
            report_version: REPORT_SCHEMA_VERSION,
            blocklist_matches: self.blocklist_matches.clone(),
            anomaly_aggregate,
            killchain_triggers: self.killchain_triggers.clone(),
            ioc_match_rates,
            scanner_summary,
        }
    }

    /// Preview the report that would be sent (same as `build_report` but with a placeholder ID).
    pub fn preview(&self) -> TelemetryReport {
        self.build_report("preview")
    }

    /// Reset all accumulated data after a successful report submission.
    pub fn reset(&mut self) {
        self.blocklist_matches.clear();
        self.anomaly_events.clear();
        self.auto_blocks = 0;
        self.killchain_triggers.clear();
        self.ioc_network = 0;
        self.ioc_file = 0;
        self.ioc_behavioral = 0;
        self.scan_categories.clear();
        self.scan_severity_counts.clear();
    }

    /// Aggregate anomaly events into a summary.
    fn aggregate_anomalies(&self) -> AnomalyAggregate {
        if self.anomaly_events.is_empty() {
            return AnomalyAggregate {
                events_above_threshold: 0,
                top_dimension: String::new(),
                top_dimension_percentage: 0.0,
                auto_blocks: self.auto_blocks,
            };
        }

        // Count occurrences of each dimension
        let mut dimension_counts: HashMap<&str, u64> = HashMap::new();
        for event in &self.anomaly_events {
            *dimension_counts.entry(&event.dimension).or_insert(0) += 1;
        }

        // Find the top dimension
        let total = self.anomaly_events.len() as f64;
        let (top_dim, top_count) = dimension_counts
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|(dim, count)| (dim.to_string(), *count))
            .unwrap_or_default();

        let percentage = if total > 0.0 {
            (top_count as f64 / total) * 100.0
        } else {
            0.0
        };

        AnomalyAggregate {
            events_above_threshold: self.anomaly_events.len() as u64,
            top_dimension: top_dim,
            top_dimension_percentage: percentage,
            auto_blocks: self.auto_blocks,
        }
    }
}
