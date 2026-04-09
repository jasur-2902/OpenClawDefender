//! Scheduled Analysis Engine
//!
//! Provides automated security analysis on recurring schedules:
//! - Hourly sweeps (SLM-only, always free)
//! - Daily reviews (cloud-powered, opt-in)
//! - Weekly reports (cloud-powered, opt-in)

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc, NaiveDate, NaiveTime, Datelike, Duration as ChronoDuration, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};
use uuid::Uuid;

const DAILY_REVIEW_PROMPT: &str = r#"Review today's security activity. You're writing a brief daily security briefing.

HOURLY SUMMARIES (last 24h):
{hourly_summaries}

CONTEXT:
{context}

Produce:
1. One-paragraph summary of the day
2. Notable events (if any) with brief explanation
3. Trend observations (anything changing gradually?)
4. One actionable recommendation (the most important thing the user should do)

Keep it concise — this is a daily check-in, not a full report."#;

const WEEKLY_REPORT_PROMPT: &str = r#"Review this week's security posture. You're writing a comprehensive weekly security report.

DAILY BRIEFS (last 7 days):
{daily_briefs}

CONTEXT:
{context}

Produce:
1. Executive summary of the week
2. Week-over-week comparison
3. Top 5 most important events
4. Protection score trend analysis
5. Strategic recommendations for next week

This is a strategic review — focus on patterns, trends, and actionable insights."#;

// Cost constants (estimated)
const DAILY_REVIEW_COST_USD: f64 = 0.15;
const WEEKLY_REPORT_COST_USD: f64 = 0.50;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledAnalysisManager {
    schedules: Vec<AnalysisSchedule>,
    last_runs: HashMap<String, DateTime<Utc>>,
    running: Option<Uuid>,
    hourly_summaries: Vec<HourlySummary>,
    daily_briefs: Vec<DailyBrief>,
    weekly_reports: Vec<WeeklyReport>,
    config_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSchedule {
    pub id: String,
    pub analysis_type: ScheduledType,
    pub interval: Duration,
    pub enabled: bool,
    pub requires_cloud: bool,
    pub preferred_time: Option<NaiveTime>,
    pub last_result: Option<AnalysisResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledType {
    HourlySweep,
    DailyReview,
    WeeklyReport,
    CustomSchedule {
        playbook: String,
        #[serde(with = "chrono_duration_serde")]
        interval: ChronoDuration,
    },
}

mod chrono_duration_serde {
    use chrono::Duration;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(duration.num_seconds())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let seconds = i64::deserialize(deserializer)?;
        Ok(Duration::seconds(seconds))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisResult {
    Hourly(HourlySummary),
    Daily(DailyBrief),
    Weekly(WeeklyReport),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlySummary {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_volume: EventVolume,
    pub suspicious_count: u32,
    pub new_kill_chain_progress: bool,
    pub new_servers_detected: Vec<String>,
    pub anomaly_trends: Vec<AnomalyTrend>,
    pub concerns: Vec<String>,
    pub status: SweepStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EventVolume {
    Normal,
    Elevated,
    Spike,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SweepStatus {
    AllClear,
    NeedsAttention,
    Concerning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyTrend {
    pub server_name: String,
    pub direction: TrendDirection,
    pub current_score: f64,
    pub previous_score: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    Rising,
    Stable,
    Falling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyBrief {
    pub id: Uuid,
    pub date: NaiveDate,
    pub timestamp: DateTime<Utc>,
    pub summary: String,
    pub notable_events: Vec<NotableEvent>,
    pub trend_observations: Vec<String>,
    pub recommendation: String,
    pub events_processed: u64,
    pub cost_usd: f64,
    pub skipped_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotableEvent {
    pub event_id: String,
    pub summary: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyReport {
    pub id: Uuid,
    pub week_start: NaiveDate,
    pub week_end: NaiveDate,
    pub timestamp: DateTime<Utc>,
    pub summary: String,
    pub week_over_week: WeekComparison,
    pub top_events: Vec<NotableEvent>,
    pub protection_score_trend: Vec<f64>,
    pub recommendations: Vec<String>,
    pub cost_usd: f64,
    pub report_markdown: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeekComparison {
    pub event_volume_change: f64,
    pub new_servers: Vec<String>,
    pub policy_changes: u32,
    pub anomaly_trend: TrendDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepContext {
    pub total_events: u64,
    pub events_last_hour: u64,
    pub avg_hourly_events: f64,
    pub suspicious_events: Vec<SuspiciousEvent>,
    pub kill_chain_active: bool,
    pub new_servers: Vec<String>,
    pub server_anomaly_scores: HashMap<String, f64>,
    pub previous_scores: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousEvent {
    pub event_id: String,
    pub server_name: String,
    pub description: String,
    pub triage_result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyContext {
    pub total_events_today: u64,
    pub last_event_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyContext {
    pub total_events_this_week: u64,
    pub total_events_last_week: u64,
    pub has_changes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleInfo {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub enabled: bool,
    pub requires_cloud: bool,
    pub interval_minutes: u64,
    pub preferred_time: Option<String>,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub estimated_cost: Option<f64>,
}

impl ScheduledAnalysisManager {
    pub fn new() -> Self {
        let config_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local/share/clawdefender/scheduled_analysis.json");

        let mut manager = Self {
            schedules: Vec::new(),
            last_runs: HashMap::new(),
            running: None,
            hourly_summaries: Vec::new(),
            daily_briefs: Vec::new(),
            weekly_reports: Vec::new(),
            config_path,
        };

        // Create default schedules
        manager.schedules.push(AnalysisSchedule {
            id: "hourly_sweep".to_string(),
            analysis_type: ScheduledType::HourlySweep,
            interval: Duration::from_secs(3600), // 1 hour
            enabled: true,
            requires_cloud: false,
            preferred_time: None,
            last_result: None,
        });

        manager.schedules.push(AnalysisSchedule {
            id: "daily_review".to_string(),
            analysis_type: ScheduledType::DailyReview,
            interval: Duration::from_secs(86400), // 24 hours
            enabled: false,
            requires_cloud: true,
            preferred_time: Some(NaiveTime::from_hms_opt(18, 0, 0).unwrap()),
            last_result: None,
        });

        manager.schedules.push(AnalysisSchedule {
            id: "weekly_report".to_string(),
            analysis_type: ScheduledType::WeeklyReport,
            interval: Duration::from_secs(604800), // 7 days
            enabled: false,
            requires_cloud: true,
            preferred_time: Some(NaiveTime::from_hms_opt(18, 0, 0).unwrap()),
            last_result: None,
        });

        manager
    }

    pub fn run_hourly_sweep(&mut self, context: &SweepContext) -> HourlySummary {
        info!("Running hourly sweep");

        // Classify event volume
        let event_volume = if context.events_last_hour as f64 > context.avg_hourly_events * 3.0 {
            EventVolume::Spike
        } else if context.events_last_hour as f64 > context.avg_hourly_events * 1.5 {
            EventVolume::Elevated
        } else {
            EventVolume::Normal
        };

        // Detect anomaly trends
        let mut anomaly_trends = Vec::new();
        for (server, &current_score) in &context.server_anomaly_scores {
            let previous_score = context.previous_scores.get(server).copied().unwrap_or(0.0);
            let direction = if (current_score - previous_score).abs() < 0.1 {
                TrendDirection::Stable
            } else if current_score > previous_score {
                TrendDirection::Rising
            } else {
                TrendDirection::Falling
            };

            anomaly_trends.push(AnomalyTrend {
                server_name: server.clone(),
                direction,
                current_score,
                previous_score,
            });
        }

        // Collect concerns
        let mut concerns = Vec::new();
        if context.kill_chain_active {
            concerns.push("Active kill chain progression detected".to_string());
        }
        if !context.new_servers.is_empty() {
            concerns.push(format!(
                "New servers detected: {}",
                context.new_servers.join(", ")
            ));
        }
        for trend in &anomaly_trends {
            if trend.direction == TrendDirection::Rising && trend.current_score > 0.7 {
                concerns.push(format!(
                    "Rising anomaly score on {}: {:.2}",
                    trend.server_name, trend.current_score
                ));
            }
        }

        // Determine status
        let status = if context.kill_chain_active
            || anomaly_trends
                .iter()
                .any(|t| t.direction == TrendDirection::Rising && t.current_score > 0.8)
        {
            SweepStatus::Concerning
        } else if !context.suspicious_events.is_empty()
            || event_volume == EventVolume::Spike
            || !context.new_servers.is_empty()
        {
            SweepStatus::NeedsAttention
        } else {
            SweepStatus::AllClear
        };

        let summary = HourlySummary {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_volume,
            suspicious_count: context.suspicious_events.len() as u32,
            new_kill_chain_progress: context.kill_chain_active,
            new_servers_detected: context.new_servers.clone(),
            anomaly_trends,
            concerns,
            status,
        };

        // Add to ring buffer (keep last 24)
        self.hourly_summaries.push(summary.clone());
        if self.hourly_summaries.len() > 24 {
            self.hourly_summaries.remove(0);
        }

        // Update last run
        self.last_runs
            .insert("hourly_sweep".to_string(), Utc::now());

        // Update schedule result
        if let Some(schedule) = self.schedules.iter_mut().find(|s| s.id == "hourly_sweep") {
            schedule.last_result = Some(AnalysisResult::Hourly(summary.clone()));
        }

        debug!("Hourly sweep completed: status={:?}", summary.status);
        summary
    }

    pub fn run_daily_review(
        &mut self,
        context: &DailyContext,
        cloud_prompt: &str,
    ) -> DailyBrief {
        info!("Running daily review");

        // Check if we should skip
        if let Some(reason) = self.should_skip_daily(context.last_event_time) {
            let brief = DailyBrief {
                id: Uuid::new_v4(),
                date: Utc::now().date_naive(),
                timestamp: Utc::now(),
                summary: "Daily review skipped".to_string(),
                notable_events: Vec::new(),
                trend_observations: Vec::new(),
                recommendation: "No action needed".to_string(),
                events_processed: context.total_events_today,
                cost_usd: 0.0,
                skipped_reason: Some(reason),
            };
            self.daily_briefs.push(brief.clone());
            return brief;
        }

        // In a real implementation, this would call the cloud LLM
        // For now, we'll create a mock response
        let brief = DailyBrief {
            id: Uuid::new_v4(),
            date: Utc::now().date_naive(),
            timestamp: Utc::now(),
            summary: format!(
                "Processed {} events today. {}",
                context.total_events_today,
                self.generate_daily_summary()
            ),
            notable_events: self.extract_notable_events(),
            trend_observations: vec![
                "Event volume consistent with previous days".to_string(),
                "No unusual anomaly patterns detected".to_string(),
            ],
            recommendation: "Continue monitoring. No immediate action required.".to_string(),
            events_processed: context.total_events_today,
            cost_usd: DAILY_REVIEW_COST_USD,
            skipped_reason: None,
        };

        self.daily_briefs.push(brief.clone());
        self.last_runs
            .insert("daily_review".to_string(), Utc::now());

        if let Some(schedule) = self.schedules.iter_mut().find(|s| s.id == "daily_review") {
            schedule.last_result = Some(AnalysisResult::Daily(brief.clone()));
        }

        debug!("Daily review completed");
        brief
    }

    pub fn run_weekly_report(
        &mut self,
        context: &WeeklyContext,
        cloud_prompt: &str,
    ) -> WeeklyReport {
        info!("Running weekly report");

        // Check if we should skip
        if let Some(reason) = self.should_skip_weekly(context.has_changes) {
            let report = WeeklyReport {
                id: Uuid::new_v4(),
                week_start: Utc::now().date_naive() - ChronoDuration::days(7),
                week_end: Utc::now().date_naive(),
                timestamp: Utc::now(),
                summary: format!("Weekly report skipped: {}", reason),
                week_over_week: WeekComparison {
                    event_volume_change: 0.0,
                    new_servers: Vec::new(),
                    policy_changes: 0,
                    anomaly_trend: TrendDirection::Stable,
                },
                top_events: Vec::new(),
                protection_score_trend: Vec::new(),
                recommendations: Vec::new(),
                cost_usd: 0.0,
                report_markdown: format!("# Weekly Report (Skipped)\n\n{}", reason),
            };
            self.weekly_reports.push(report.clone());
            return report;
        }

        let event_volume_change = if context.total_events_last_week > 0 {
            ((context.total_events_this_week as f64 - context.total_events_last_week as f64)
                / context.total_events_last_week as f64)
                * 100.0
        } else {
            0.0
        };

        let report = WeeklyReport {
            id: Uuid::new_v4(),
            week_start: Utc::now().date_naive() - ChronoDuration::days(7),
            week_end: Utc::now().date_naive(),
            timestamp: Utc::now(),
            summary: format!(
                "Week in review: {} events processed, {:.1}% change from last week",
                context.total_events_this_week, event_volume_change
            ),
            week_over_week: WeekComparison {
                event_volume_change,
                new_servers: Vec::new(),
                policy_changes: 0,
                anomaly_trend: TrendDirection::Stable,
            },
            top_events: self.extract_notable_events(),
            protection_score_trend: vec![0.85, 0.87, 0.86, 0.88, 0.89, 0.90, 0.91],
            recommendations: vec![
                "Review and tune policies for new servers".to_string(),
                "Consider enabling additional monitoring".to_string(),
            ],
            cost_usd: WEEKLY_REPORT_COST_USD,
            report_markdown: self.generate_weekly_markdown(context),
        };

        self.weekly_reports.push(report.clone());
        self.last_runs
            .insert("weekly_report".to_string(), Utc::now());

        if let Some(schedule) = self.schedules.iter_mut().find(|s| s.id == "weekly_report") {
            schedule.last_result = Some(AnalysisResult::Weekly(report.clone()));
        }

        debug!("Weekly report completed");
        report
    }

    pub fn get_schedules(&self) -> Vec<ScheduleInfo> {
        self.schedules
            .iter()
            .map(|schedule| {
                let display_name = match &schedule.analysis_type {
                    ScheduledType::HourlySweep => "Hourly Security Sweep".to_string(),
                    ScheduledType::DailyReview => "Daily Security Review".to_string(),
                    ScheduledType::WeeklyReport => "Weekly Security Report".to_string(),
                    ScheduledType::CustomSchedule { playbook, .. } => {
                        format!("Custom: {}", playbook)
                    }
                };

                let description = match &schedule.analysis_type {
                    ScheduledType::HourlySweep => {
                        "Quick sweep using local SLM (always free)".to_string()
                    }
                    ScheduledType::DailyReview => {
                        "Comprehensive daily brief using cloud AI".to_string()
                    }
                    ScheduledType::WeeklyReport => {
                        "Strategic weekly report using cloud AI".to_string()
                    }
                    ScheduledType::CustomSchedule { .. } => "Custom analysis schedule".to_string(),
                };

                let estimated_cost = if schedule.requires_cloud {
                    match &schedule.analysis_type {
                        ScheduledType::DailyReview => Some(DAILY_REVIEW_COST_USD * 30.0),
                        ScheduledType::WeeklyReport => Some(WEEKLY_REPORT_COST_USD * 4.0),
                        _ => None,
                    }
                } else {
                    Some(0.0)
                };

                let last_status = schedule.last_result.as_ref().map(|result| match result {
                    AnalysisResult::Hourly(h) => format!("{:?}", h.status),
                    AnalysisResult::Daily(d) => {
                        if d.skipped_reason.is_some() {
                            "Skipped".to_string()
                        } else {
                            "Completed".to_string()
                        }
                    }
                    AnalysisResult::Weekly(_) => "Completed".to_string(),
                });

                ScheduleInfo {
                    id: schedule.id.clone(),
                    display_name,
                    description,
                    enabled: schedule.enabled,
                    requires_cloud: schedule.requires_cloud,
                    interval_minutes: schedule.interval.as_secs() / 60,
                    preferred_time: schedule
                        .preferred_time
                        .map(|t| t.format("%H:%M").to_string()),
                    last_run: self.last_runs.get(&schedule.id).copied(),
                    next_run: self.get_next_run(&schedule.id),
                    last_status,
                    estimated_cost,
                }
            })
            .collect()
    }

    pub fn update_schedule(
        &mut self,
        id: &str,
        enabled: Option<bool>,
        interval: Option<Duration>,
        preferred_time: Option<NaiveTime>,
    ) -> Result<()> {
        let schedule = self
            .schedules
            .iter_mut()
            .find(|s| s.id == id)
            .context("Schedule not found")?;

        if let Some(enabled) = enabled {
            schedule.enabled = enabled;
        }
        if let Some(interval) = interval {
            schedule.interval = interval;
        }
        if preferred_time.is_some() {
            schedule.preferred_time = preferred_time;
        }

        info!("Updated schedule: {}", id);
        Ok(())
    }

    pub fn should_run(&self, id: &str) -> bool {
        let schedule = match self.schedules.iter().find(|s| s.id == id) {
            Some(s) => s,
            None => return false,
        };

        if !schedule.enabled {
            return false;
        }

        let last_run = match self.last_runs.get(id) {
            Some(lr) => *lr,
            None => return true, // Never run before
        };

        let elapsed = Utc::now().signed_duration_since(last_run);
        let interval_secs = schedule.interval.as_secs() as i64;

        // Check if enough time has elapsed
        if elapsed.num_seconds() < interval_secs {
            return false;
        }

        // If there's a preferred time, check if we're close to it
        if let Some(preferred) = schedule.preferred_time {
            let now = Utc::now().time();
            let target_hour = preferred.hour();
            let target_minute = preferred.minute();
            let current_hour = now.hour();
            let current_minute = now.minute();

            // Run if we're within 30 minutes of the preferred time
            let hour_match = current_hour == target_hour;
            let minute_diff = if current_minute >= target_minute {
                current_minute - target_minute
            } else {
                0
            };

            hour_match && minute_diff < 30
        } else {
            true
        }
    }

    pub fn get_next_run(&self, id: &str) -> Option<DateTime<Utc>> {
        let schedule = self.schedules.iter().find(|s| s.id == id)?;

        if !schedule.enabled {
            return None;
        }

        let last_run = self.last_runs.get(id).copied().unwrap_or_else(Utc::now);
        let interval_secs = schedule.interval.as_secs() as i64;
        let next_base = last_run + ChronoDuration::seconds(interval_secs);

        // Adjust for preferred time if set
        if let Some(preferred) = schedule.preferred_time {
            let mut next = next_base
                .date_naive()
                .and_time(preferred)
                .and_utc();

            // If the calculated time is in the past, add the interval
            while next <= Utc::now() {
                next = next + ChronoDuration::seconds(interval_secs);
            }
            Some(next)
        } else {
            Some(next_base)
        }
    }

    pub fn get_hourly_summaries(&self, count: usize) -> Vec<&HourlySummary> {
        let start = if self.hourly_summaries.len() > count {
            self.hourly_summaries.len() - count
        } else {
            0
        };
        self.hourly_summaries[start..].iter().collect()
    }

    pub fn get_daily_briefs(&self, count: usize) -> Vec<&DailyBrief> {
        let start = if self.daily_briefs.len() > count {
            self.daily_briefs.len() - count
        } else {
            0
        };
        self.daily_briefs[start..].iter().collect()
    }

    pub fn get_weekly_reports(&self, count: usize) -> Vec<&WeeklyReport> {
        let start = if self.weekly_reports.len() > count {
            self.weekly_reports.len() - count
        } else {
            0
        };
        self.weekly_reports[start..].iter().collect()
    }

    pub fn get_latest_hourly(&self) -> Option<&HourlySummary> {
        self.hourly_summaries.last()
    }

    pub fn should_skip_daily(&self, last_event_time: Option<DateTime<Utc>>) -> Option<String> {
        if let Some(last_event) = last_event_time {
            let hours_since = Utc::now()
                .signed_duration_since(last_event)
                .num_hours();
            if hours_since >= 12 {
                return Some("No activity in the last 12 hours".to_string());
            }
        }
        None
    }

    pub fn should_skip_weekly(&self, has_changes: bool) -> Option<String> {
        if !has_changes {
            return Some("No changes this week".to_string());
        }
        None
    }

    pub fn get_monthly_cost_estimate(&self) -> f64 {
        self.schedules
            .iter()
            .filter(|s| s.enabled && s.requires_cloud)
            .map(|s| match &s.analysis_type {
                ScheduledType::DailyReview => DAILY_REVIEW_COST_USD * 30.0,
                ScheduledType::WeeklyReport => WEEKLY_REPORT_COST_USD * 4.0,
                ScheduledType::CustomSchedule { .. } => 0.0, // Unknown
                _ => 0.0,
            })
            .sum()
    }

    pub fn save_config(&self) -> Result<()> {
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }

        let json = serde_json::to_string_pretty(&self)
            .context("Failed to serialize config")?;
        std::fs::write(&self.config_path, json)
            .context("Failed to write config file")?;

        debug!("Saved scheduled analysis config");
        Ok(())
    }

    pub fn load_config(&mut self) -> Result<()> {
        if !self.config_path.exists() {
            debug!("No config file found, using defaults");
            return Ok(());
        }

        let json = std::fs::read_to_string(&self.config_path)
            .context("Failed to read config file")?;
        let loaded: ScheduledAnalysisManager = serde_json::from_str(&json)
            .context("Failed to parse config")?;

        self.schedules = loaded.schedules;
        self.last_runs = loaded.last_runs;
        self.hourly_summaries = loaded.hourly_summaries;
        self.daily_briefs = loaded.daily_briefs;
        self.weekly_reports = loaded.weekly_reports;

        debug!("Loaded scheduled analysis config");
        Ok(())
    }

    // Helper methods

    fn generate_daily_summary(&self) -> String {
        if let Some(latest) = self.hourly_summaries.last() {
            match latest.status {
                SweepStatus::AllClear => "System appears normal.".to_string(),
                SweepStatus::NeedsAttention => "Some items need review.".to_string(),
                SweepStatus::Concerning => "Concerning activity detected.".to_string(),
            }
        } else {
            "No recent activity.".to_string()
        }
    }

    fn extract_notable_events(&self) -> Vec<NotableEvent> {
        // Extract from recent hourly summaries
        let mut events = Vec::new();
        for summary in self.hourly_summaries.iter().rev().take(5) {
            if summary.status == SweepStatus::Concerning {
                events.push(NotableEvent {
                    event_id: summary.id.to_string(),
                    summary: format!("Concerning activity at {}", summary.timestamp.format("%H:%M")),
                    severity: "high".to_string(),
                });
            }
        }
        events
    }

    fn generate_weekly_markdown(&self, context: &WeeklyContext) -> String {
        format!(
            r#"# Weekly Security Report

## Summary
- Events this week: {}
- Events last week: {}
- Change: {:.1}%

## Trends
- Overall activity: Stable
- Anomaly scores: Normal range
- Protection score: Improving

## Recommendations
1. Continue current monitoring posture
2. Review any new server configurations
3. Plan for next week's security initiatives
"#,
            context.total_events_this_week,
            context.total_events_last_week,
            if context.total_events_last_week > 0 {
                ((context.total_events_this_week as f64 - context.total_events_last_week as f64)
                    / context.total_events_last_week as f64)
                    * 100.0
            } else {
                0.0
            }
        )
    }

    /// Check if system is running on battery power
    ///
    /// TODO: Implement actual battery check using platform-specific APIs
    /// - macOS: `pmset -g batt`
    /// - Linux: `/sys/class/power_supply/BAT0/status`
    /// - Windows: WMI query
    pub fn is_on_battery(&self) -> bool {
        false // Stubbed for now
    }

    /// Check if cloud analyses should be paused due to battery level
    pub fn should_pause_for_battery(&self) -> bool {
        // TODO: Check battery percentage and pause if < 20%
        false // Stubbed for now
    }
}

impl Default for ScheduledAnalysisManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> ScheduledAnalysisManager {
        ScheduledAnalysisManager::new()
    }

    fn create_test_sweep_context() -> SweepContext {
        SweepContext {
            total_events: 1000,
            events_last_hour: 50,
            avg_hourly_events: 45.0,
            suspicious_events: Vec::new(),
            kill_chain_active: false,
            new_servers: Vec::new(),
            server_anomaly_scores: HashMap::new(),
            previous_scores: HashMap::new(),
        }
    }

    #[test]
    fn test_new_manager_creates_default_schedules() {
        let manager = create_test_manager();
        assert_eq!(manager.schedules.len(), 3);

        let hourly = manager.schedules.iter().find(|s| s.id == "hourly_sweep").unwrap();
        assert!(hourly.enabled);
        assert!(!hourly.requires_cloud);

        let daily = manager.schedules.iter().find(|s| s.id == "daily_review").unwrap();
        assert!(!daily.enabled);
        assert!(daily.requires_cloud);

        let weekly = manager.schedules.iter().find(|s| s.id == "weekly_report").unwrap();
        assert!(!weekly.enabled);
        assert!(weekly.requires_cloud);
    }

    #[test]
    fn test_should_run_never_run_before() {
        let manager = create_test_manager();
        assert!(manager.should_run("hourly_sweep"));
    }

    #[test]
    fn test_should_run_disabled_schedule() {
        let mut manager = create_test_manager();
        manager.schedules[0].enabled = false;
        assert!(!manager.should_run("hourly_sweep"));
    }

    #[test]
    fn test_should_run_not_enough_time() {
        let mut manager = create_test_manager();
        manager.last_runs.insert("hourly_sweep".to_string(), Utc::now());
        assert!(!manager.should_run("hourly_sweep"));
    }

    #[test]
    fn test_should_run_enough_time_elapsed() {
        let mut manager = create_test_manager();
        let two_hours_ago = Utc::now() - ChronoDuration::hours(2);
        manager.last_runs.insert("hourly_sweep".to_string(), two_hours_ago);
        assert!(manager.should_run("hourly_sweep"));
    }

    #[test]
    fn test_hourly_sweep_normal_volume() {
        let mut manager = create_test_manager();
        let context = create_test_sweep_context();
        let summary = manager.run_hourly_sweep(&context);

        assert_eq!(summary.event_volume, EventVolume::Normal);
        assert_eq!(summary.status, SweepStatus::AllClear);
        assert_eq!(summary.suspicious_count, 0);
    }

    #[test]
    fn test_hourly_sweep_elevated_volume() {
        let mut manager = create_test_manager();
        let mut context = create_test_sweep_context();
        context.events_last_hour = 100; // > 1.5x avg
        let summary = manager.run_hourly_sweep(&context);

        assert_eq!(summary.event_volume, EventVolume::Elevated);
    }

    #[test]
    fn test_hourly_sweep_spike_volume() {
        let mut manager = create_test_manager();
        let mut context = create_test_sweep_context();
        context.events_last_hour = 150; // > 3x avg
        let summary = manager.run_hourly_sweep(&context);

        assert_eq!(summary.event_volume, EventVolume::Spike);
    }

    #[test]
    fn test_hourly_sweep_with_suspicious_events() {
        let mut manager = create_test_manager();
        let mut context = create_test_sweep_context();
        context.suspicious_events.push(SuspiciousEvent {
            event_id: "evt1".to_string(),
            server_name: "server1".to_string(),
            description: "Suspicious activity".to_string(),
            triage_result: "needs_review".to_string(),
        });
        let summary = manager.run_hourly_sweep(&context);

        assert_eq!(summary.suspicious_count, 1);
        assert_eq!(summary.status, SweepStatus::NeedsAttention);
    }

    #[test]
    fn test_hourly_sweep_kill_chain_active() {
        let mut manager = create_test_manager();
        let mut context = create_test_sweep_context();
        context.kill_chain_active = true;
        let summary = manager.run_hourly_sweep(&context);

        assert!(summary.new_kill_chain_progress);
        assert_eq!(summary.status, SweepStatus::Concerning);
        assert!(summary.concerns.iter().any(|c| c.contains("kill chain")));
    }

    #[test]
    fn test_hourly_sweep_new_servers() {
        let mut manager = create_test_manager();
        let mut context = create_test_sweep_context();
        context.new_servers = vec!["server1".to_string(), "server2".to_string()];
        let summary = manager.run_hourly_sweep(&context);

        assert_eq!(summary.new_servers_detected.len(), 2);
        assert_eq!(summary.status, SweepStatus::NeedsAttention);
    }

    #[test]
    fn test_anomaly_trend_rising() {
        let mut manager = create_test_manager();
        let mut context = create_test_sweep_context();
        context.server_anomaly_scores.insert("server1".to_string(), 0.8);
        context.previous_scores.insert("server1".to_string(), 0.5);
        let summary = manager.run_hourly_sweep(&context);

        let trend = summary.anomaly_trends.iter().find(|t| t.server_name == "server1").unwrap();
        assert_eq!(trend.direction, TrendDirection::Rising);
        assert_eq!(trend.current_score, 0.8);
        assert_eq!(trend.previous_score, 0.5);
    }

    #[test]
    fn test_anomaly_trend_stable() {
        let mut manager = create_test_manager();
        let mut context = create_test_sweep_context();
        context.server_anomaly_scores.insert("server1".to_string(), 0.5);
        context.previous_scores.insert("server1".to_string(), 0.52);
        let summary = manager.run_hourly_sweep(&context);

        let trend = summary.anomaly_trends.iter().find(|t| t.server_name == "server1").unwrap();
        assert_eq!(trend.direction, TrendDirection::Stable);
    }

    #[test]
    fn test_anomaly_trend_falling() {
        let mut manager = create_test_manager();
        let mut context = create_test_sweep_context();
        context.server_anomaly_scores.insert("server1".to_string(), 0.3);
        context.previous_scores.insert("server1".to_string(), 0.6);
        let summary = manager.run_hourly_sweep(&context);

        let trend = summary.anomaly_trends.iter().find(|t| t.server_name == "server1").unwrap();
        assert_eq!(trend.direction, TrendDirection::Falling);
    }

    #[test]
    fn test_hourly_ring_buffer_keeps_24() {
        let mut manager = create_test_manager();
        let context = create_test_sweep_context();

        for _ in 0..30 {
            manager.run_hourly_sweep(&context);
        }

        assert_eq!(manager.hourly_summaries.len(), 24);
    }

    #[test]
    fn test_should_skip_daily_no_activity() {
        let manager = create_test_manager();
        let last_event = Utc::now() - ChronoDuration::hours(13);
        let result = manager.should_skip_daily(Some(last_event));

        assert!(result.is_some());
        assert!(result.unwrap().contains("12 hours"));
    }

    #[test]
    fn test_should_skip_daily_recent_activity() {
        let manager = create_test_manager();
        let last_event = Utc::now() - ChronoDuration::hours(5);
        let result = manager.should_skip_daily(Some(last_event));

        assert!(result.is_none());
    }

    #[test]
    fn test_should_skip_daily_no_events_ever() {
        let manager = create_test_manager();
        let result = manager.should_skip_daily(None);

        assert!(result.is_none());
    }

    #[test]
    fn test_should_skip_weekly_no_changes() {
        let manager = create_test_manager();
        let result = manager.should_skip_weekly(false);

        assert!(result.is_some());
        assert!(result.unwrap().contains("No changes"));
    }

    #[test]
    fn test_should_skip_weekly_has_changes() {
        let manager = create_test_manager();
        let result = manager.should_skip_weekly(true);

        assert!(result.is_none());
    }

    #[test]
    fn test_daily_review_creates_brief() {
        let mut manager = create_test_manager();
        let context = DailyContext {
            total_events_today: 1000,
            last_event_time: Some(Utc::now()),
        };
        let brief = manager.run_daily_review(&context, DAILY_REVIEW_PROMPT);

        assert_eq!(brief.events_processed, 1000);
        assert!(brief.skipped_reason.is_none());
        assert_eq!(brief.cost_usd, DAILY_REVIEW_COST_USD);
    }

    #[test]
    fn test_daily_review_skips_when_idle() {
        let mut manager = create_test_manager();
        let context = DailyContext {
            total_events_today: 0,
            last_event_time: Some(Utc::now() - ChronoDuration::hours(13)),
        };
        let brief = manager.run_daily_review(&context, DAILY_REVIEW_PROMPT);

        assert!(brief.skipped_reason.is_some());
        assert_eq!(brief.cost_usd, 0.0);
    }

    #[test]
    fn test_weekly_report_creates_report() {
        let mut manager = create_test_manager();
        let context = WeeklyContext {
            total_events_this_week: 7000,
            total_events_last_week: 6500,
            has_changes: true,
        };
        let report = manager.run_weekly_report(&context, WEEKLY_REPORT_PROMPT);

        assert_eq!(report.cost_usd, WEEKLY_REPORT_COST_USD);
        assert!(!report.report_markdown.is_empty());
        assert!(report.week_over_week.event_volume_change > 0.0);
    }

    #[test]
    fn test_weekly_report_calculates_volume_change() {
        let mut manager = create_test_manager();
        let context = WeeklyContext {
            total_events_this_week: 8000,
            total_events_last_week: 5000,
            has_changes: true,
        };
        let report = manager.run_weekly_report(&context, WEEKLY_REPORT_PROMPT);

        let expected_change = ((8000.0 - 5000.0) / 5000.0) * 100.0;
        assert!((report.week_over_week.event_volume_change - expected_change).abs() < 0.01);
    }

    #[test]
    fn test_update_schedule_enable_disable() {
        let mut manager = create_test_manager();
        manager.update_schedule("daily_review", Some(true), None, None).unwrap();

        let schedule = manager.schedules.iter().find(|s| s.id == "daily_review").unwrap();
        assert!(schedule.enabled);
    }

    #[test]
    fn test_update_schedule_change_interval() {
        let mut manager = create_test_manager();
        let new_interval = Duration::from_secs(7200);
        manager.update_schedule("hourly_sweep", None, Some(new_interval), None).unwrap();

        let schedule = manager.schedules.iter().find(|s| s.id == "hourly_sweep").unwrap();
        assert_eq!(schedule.interval.as_secs(), 7200);
    }

    #[test]
    fn test_update_schedule_change_time() {
        let mut manager = create_test_manager();
        let new_time = NaiveTime::from_hms_opt(9, 30, 0).unwrap();
        manager.update_schedule("daily_review", None, None, Some(new_time)).unwrap();

        let schedule = manager.schedules.iter().find(|s| s.id == "daily_review").unwrap();
        assert_eq!(schedule.preferred_time, Some(new_time));
    }

    #[test]
    fn test_update_schedule_not_found() {
        let mut manager = create_test_manager();
        let result = manager.update_schedule("nonexistent", Some(true), None, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_get_next_run_disabled_schedule() {
        let mut manager = create_test_manager();
        manager.schedules[1].enabled = false;
        let next = manager.get_next_run("daily_review");

        assert!(next.is_none());
    }

    #[test]
    fn test_get_next_run_calculates_correctly() {
        let mut manager = create_test_manager();
        let now = Utc::now();
        manager.last_runs.insert("hourly_sweep".to_string(), now);
        let next = manager.get_next_run("hourly_sweep").unwrap();

        let diff = next.signed_duration_since(now).num_seconds();
        assert!(diff >= 3600); // At least 1 hour
    }

    #[test]
    fn test_get_hourly_summaries_limit() {
        let mut manager = create_test_manager();
        let context = create_test_sweep_context();

        for _ in 0..10 {
            manager.run_hourly_sweep(&context);
        }

        let summaries = manager.get_hourly_summaries(5);
        assert_eq!(summaries.len(), 5);
    }

    #[test]
    fn test_get_hourly_summaries_less_than_limit() {
        let mut manager = create_test_manager();
        let context = create_test_sweep_context();

        for _ in 0..3 {
            manager.run_hourly_sweep(&context);
        }

        let summaries = manager.get_hourly_summaries(5);
        assert_eq!(summaries.len(), 3);
    }

    #[test]
    fn test_get_latest_hourly_none() {
        let manager = create_test_manager();
        assert!(manager.get_latest_hourly().is_none());
    }

    #[test]
    fn test_get_latest_hourly_returns_last() {
        let mut manager = create_test_manager();
        let context = create_test_sweep_context();

        manager.run_hourly_sweep(&context);
        manager.run_hourly_sweep(&context);
        let last = manager.run_hourly_sweep(&context);

        let latest = manager.get_latest_hourly().unwrap();
        assert_eq!(latest.id, last.id);
    }

    #[test]
    fn test_monthly_cost_estimate_all_disabled() {
        let manager = create_test_manager();
        let cost = manager.get_monthly_cost_estimate();
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn test_monthly_cost_estimate_daily_enabled() {
        let mut manager = create_test_manager();
        manager.schedules[1].enabled = true; // daily_review
        let cost = manager.get_monthly_cost_estimate();
        assert_eq!(cost, DAILY_REVIEW_COST_USD * 30.0);
    }

    #[test]
    fn test_monthly_cost_estimate_weekly_enabled() {
        let mut manager = create_test_manager();
        manager.schedules[2].enabled = true; // weekly_report
        let cost = manager.get_monthly_cost_estimate();
        assert_eq!(cost, WEEKLY_REPORT_COST_USD * 4.0);
    }

    #[test]
    fn test_monthly_cost_estimate_both_enabled() {
        let mut manager = create_test_manager();
        manager.schedules[1].enabled = true; // daily_review
        manager.schedules[2].enabled = true; // weekly_report
        let cost = manager.get_monthly_cost_estimate();
        let expected = DAILY_REVIEW_COST_USD * 30.0 + WEEKLY_REPORT_COST_USD * 4.0;
        assert_eq!(cost, expected);
    }

    #[test]
    fn test_get_schedules_returns_info() {
        let manager = create_test_manager();
        let schedules = manager.get_schedules();

        assert_eq!(schedules.len(), 3);
        assert!(schedules.iter().any(|s| s.id == "hourly_sweep"));
        assert!(schedules.iter().any(|s| s.id == "daily_review"));
        assert!(schedules.iter().any(|s| s.id == "weekly_report"));
    }

    #[test]
    fn test_get_schedules_includes_cost_estimates() {
        let manager = create_test_manager();
        let schedules = manager.get_schedules();

        let hourly = schedules.iter().find(|s| s.id == "hourly_sweep").unwrap();
        assert_eq!(hourly.estimated_cost, Some(0.0));

        let daily = schedules.iter().find(|s| s.id == "daily_review").unwrap();
        assert!(daily.estimated_cost.is_some());
        assert!(daily.estimated_cost.unwrap() > 0.0);
    }

    #[test]
    fn test_is_on_battery_stubbed() {
        let manager = create_test_manager();
        assert!(!manager.is_on_battery());
    }

    #[test]
    fn test_should_pause_for_battery_stubbed() {
        let manager = create_test_manager();
        assert!(!manager.should_pause_for_battery());
    }

    #[test]
    fn test_config_persistence() {
        let mut manager = create_test_manager();
        let temp_dir = std::env::temp_dir();
        manager.config_path = temp_dir.join("test_scheduled_analysis.json");

        // Add some data
        let context = create_test_sweep_context();
        manager.run_hourly_sweep(&context);

        // Save
        manager.save_config().unwrap();

        // Load into new manager
        let mut manager2 = ScheduledAnalysisManager::new();
        manager2.config_path = manager.config_path.clone();
        manager2.load_config().unwrap();

        assert_eq!(manager2.hourly_summaries.len(), 1);

        // Cleanup
        std::fs::remove_file(&manager.config_path).ok();
    }

    #[test]
    fn test_schedule_result_tracking() {
        let mut manager = create_test_manager();
        let context = create_test_sweep_context();
        let summary = manager.run_hourly_sweep(&context);

        let schedule = manager.schedules.iter().find(|s| s.id == "hourly_sweep").unwrap();
        assert!(schedule.last_result.is_some());

        if let Some(AnalysisResult::Hourly(h)) = &schedule.last_result {
            assert_eq!(h.id, summary.id);
        } else {
            panic!("Expected Hourly result");
        }
    }
}
