//! Token tracking, budgeting, and usage reporting for cloud swarm calls.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// Tracks token usage and estimated costs across providers.
pub struct CostTracker {
    db: Connection,
    pricing: PricingTable,
    budget: BudgetConfig,
    session_used: f64,
}

/// Maps model names to their per-token pricing.
pub struct PricingTable {
    pub models: HashMap<String, ModelPricing>,
}

/// Per-million-token pricing for a single model.
pub struct ModelPricing {
    pub input_per_million: f64,
    pub output_per_million: f64,
}

/// A single recorded API call with token counts and cost.
#[derive(Debug, Clone)]
pub struct UsageRecord {
    pub timestamp: String,
    pub provider: String,
    pub model: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub estimated_cost_usd: f64,
    pub event_id: Option<String>,
    pub specialist: Option<String>,
}

/// Aggregate usage statistics.
#[derive(Debug)]
pub struct UsageSummary {
    pub today_cost: f64,
    pub month_cost: f64,
    pub total_cost: f64,
    pub total_calls: u64,
    pub avg_cost_per_call: f64,
    pub by_provider: HashMap<String, f64>,
}

/// Budget limits for session, daily, and monthly spend.
#[derive(Debug, Clone)]
pub struct BudgetConfig {
    pub session_limit_usd: f64,
    pub daily_limit_usd: f64,
    pub monthly_limit_usd: f64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            session_limit_usd: 0.50,
            daily_limit_usd: 1.00,
            monthly_limit_usd: 20.00,
        }
    }
}

/// Result of a budget check.
#[derive(Debug, PartialEq)]
pub enum BudgetStatus {
    WithinBudget,
    Exceeded {
        daily_used: f64,
        monthly_used: f64,
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// New types for pre-flight estimation, cost guards, and reporting
// ---------------------------------------------------------------------------

/// Pre-flight cost estimate for a session before it runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreFlightEstimate {
    pub estimated_input_tokens: u64,
    pub estimated_output_tokens: u64,
    pub estimated_cost_usd: f64,
    pub session_budget_remaining: f64,
    pub daily_budget_remaining: f64,
    pub monthly_budget_remaining: f64,
    pub will_exceed_budget: bool,
    pub display_message: String,
}

/// Type of session, used for token estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionCostType {
    /// Full security scan (~20-40K tokens).
    Scan,
    /// Investigation of a specific event (~10-20K tokens).
    Investigation,
    /// Single chat message turn (~1-3K tokens).
    ChatMessage,
    /// Full report generation (~30-50K tokens).
    Report,
}

impl SessionCostType {
    /// Returns conservative (high-end) token estimates as `(input, output)`.
    fn estimated_tokens(&self) -> (u64, u64) {
        match self {
            SessionCostType::Scan => (40_000, 10_000),
            SessionCostType::Investigation => (20_000, 5_000),
            SessionCostType::ChatMessage => (3_000, 1_000),
            SessionCostType::Report => (50_000, 15_000),
        }
    }
}

/// Daily cost aggregate for history reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyCost {
    pub date: String,
    pub total_cost: f64,
    pub total_calls: u32,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
}

/// Full budget status report with all tiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetStatusReport {
    pub session_budget: f64,
    pub session_used: f64,
    pub session_remaining: f64,
    pub session_percent: f64,
    pub daily_budget: f64,
    pub daily_used: f64,
    pub daily_remaining: f64,
    pub daily_percent: f64,
    pub monthly_budget: f64,
    pub monthly_used: f64,
    pub monthly_remaining: f64,
    pub monthly_percent: f64,
    pub warning_threshold_percent: f64,
    pub any_warning: bool,
}

/// Error returned when a budget limit has been exceeded.
#[derive(Debug, thiserror::Error)]
pub enum BudgetExceededError {
    #[error("Session budget exceeded: ${used:.4} of ${limit:.4} used")]
    SessionBudget { used: f64, limit: f64 },
    #[error("Daily budget exceeded: ${used:.4} of ${limit:.4} used")]
    DailyBudget { used: f64, limit: f64 },
    #[error("Monthly budget exceeded: ${used:.4} of ${limit:.4} used")]
    MonthlyBudget { used: f64, limit: f64 },
}

/// Guard that checks budgets before API calls and records usage after.
pub struct CostGuard {
    tracker: Arc<Mutex<CostTracker>>,
}

impl CostGuard {
    pub fn new(tracker: Arc<Mutex<CostTracker>>) -> Self {
        Self { tracker }
    }

    /// Called BEFORE every API call. Returns `Err` if any budget is exceeded.
    pub async fn check_budget(&self) -> std::result::Result<(), BudgetExceededError> {
        let tracker = self.tracker.lock().unwrap();

        // Session budget
        if tracker.session_used >= tracker.budget.session_limit_usd {
            return Err(BudgetExceededError::SessionBudget {
                used: tracker.session_used,
                limit: tracker.budget.session_limit_usd,
            });
        }

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let month_prefix = &today[..7];

        let daily_used: f64 = tracker
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage WHERE timestamp LIKE ?1",
                rusqlite::params![format!("{today}%")],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        if daily_used >= tracker.budget.daily_limit_usd {
            return Err(BudgetExceededError::DailyBudget {
                used: daily_used,
                limit: tracker.budget.daily_limit_usd,
            });
        }

        let monthly_used: f64 = tracker
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage WHERE timestamp LIKE ?1",
                rusqlite::params![format!("{month_prefix}%")],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        if monthly_used >= tracker.budget.monthly_limit_usd {
            return Err(BudgetExceededError::MonthlyBudget {
                used: monthly_used,
                limit: tracker.budget.monthly_limit_usd,
            });
        }

        Ok(())
    }

    /// Called AFTER every API call to record actual usage.
    pub async fn record_usage(&self, record: UsageRecord) -> Result<()> {
        let mut tracker = self.tracker.lock().unwrap();
        tracker.session_used += record.estimated_cost_usd;
        tracker.record_usage(&record)?;
        Ok(())
    }
}

impl Default for PricingTable {
    fn default() -> Self {
        let entries: &[(&str, f64, f64)] = &[
            // Anthropic
            ("claude-sonnet-4-20250514", 3.0, 15.0),
            ("claude-haiku-4-5-20251001", 1.0, 5.0),
            // OpenAI
            ("gpt-4o-mini", 0.15, 0.60),
            ("gpt-4o", 2.50, 10.0),
            // Google
            ("gemini-2.0-flash", 0.10, 0.40),
        ];

        let mut models = HashMap::new();
        for &(name, input, output) in entries {
            models.insert(
                name.to_string(),
                ModelPricing {
                    input_per_million: input,
                    output_per_million: output,
                },
            );
        }
        Self { models }
    }
}

impl PricingTable {
    /// Estimate cost for the given token counts. Returns 0.0 for unknown models.
    pub fn estimate_cost(&self, model: &str, input_tokens: u32, output_tokens: u32) -> f64 {
        match self.models.get(model) {
            Some(pricing) => {
                let input_cost = (input_tokens as f64 / 1_000_000.0) * pricing.input_per_million;
                let output_cost = (output_tokens as f64 / 1_000_000.0) * pricing.output_per_million;
                input_cost + output_cost
            }
            None => 0.0,
        }
    }
}

impl CostTracker {
    /// Open (or create) the usage database at `db_path`.
    pub fn new(db_path: &Path, pricing: PricingTable, budget: BudgetConfig) -> Result<Self> {
        let db = Connection::open(db_path)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                estimated_cost_usd REAL NOT NULL,
                event_id TEXT,
                specialist TEXT
            );",
        )?;
        Ok(Self {
            db,
            pricing,
            budget,
            session_used: 0.0,
        })
    }

    /// Record a single API call.
    pub fn record_usage(&self, record: &UsageRecord) -> Result<()> {
        self.db.execute(
            "INSERT INTO usage (timestamp, provider, model, input_tokens, output_tokens, estimated_cost_usd, event_id, specialist)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                record.timestamp,
                record.provider,
                record.model,
                record.input_tokens,
                record.output_tokens,
                record.estimated_cost_usd,
                record.event_id,
                record.specialist,
            ],
        )?;
        Ok(())
    }

    /// Check whether the current spend is within budget.
    pub fn check_budget(&self) -> BudgetStatus {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let month_prefix = &today[..7]; // "YYYY-MM"

        let daily_used: f64 = self
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage WHERE timestamp LIKE ?1",
                rusqlite::params![format!("{today}%")],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        let monthly_used: f64 = self
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage WHERE timestamp LIKE ?1",
                rusqlite::params![format!("{month_prefix}%")],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        if daily_used >= self.budget.daily_limit_usd {
            return BudgetStatus::Exceeded {
                daily_used,
                monthly_used,
                reason: format!(
                    "Daily limit exceeded: ${:.4} / ${:.2}",
                    daily_used, self.budget.daily_limit_usd
                ),
            };
        }

        if monthly_used >= self.budget.monthly_limit_usd {
            return BudgetStatus::Exceeded {
                daily_used,
                monthly_used,
                reason: format!(
                    "Monthly limit exceeded: ${:.4} / ${:.2}",
                    monthly_used, self.budget.monthly_limit_usd
                ),
            };
        }

        BudgetStatus::WithinBudget
    }

    /// Return aggregate usage statistics.
    pub fn get_summary(&self) -> UsageSummary {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let month_prefix = &today[..7];

        let today_cost: f64 = self
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage WHERE timestamp LIKE ?1",
                rusqlite::params![format!("{today}%")],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        let month_cost: f64 = self
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage WHERE timestamp LIKE ?1",
                rusqlite::params![format!("{month_prefix}%")],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        let total_cost: f64 = self
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        let total_calls: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM usage", [], |row| row.get(0))
            .unwrap_or(0);

        let avg_cost_per_call = if total_calls > 0 {
            total_cost / total_calls as f64
        } else {
            0.0
        };

        let mut by_provider: HashMap<String, f64> = HashMap::new();
        if let Ok(mut stmt) = self
            .db
            .prepare("SELECT provider, SUM(estimated_cost_usd) FROM usage GROUP BY provider")
        {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
            }) {
                for row in rows.flatten() {
                    by_provider.insert(row.0, row.1);
                }
            }
        }

        UsageSummary {
            today_cost,
            month_cost,
            total_cost,
            total_calls,
            avg_cost_per_call,
            by_provider,
        }
    }

    /// Return the `n` most recent usage records.
    pub fn get_recent(&self, n: usize) -> Vec<UsageRecord> {
        let mut stmt = match self.db.prepare(
            "SELECT timestamp, provider, model, input_tokens, output_tokens, estimated_cost_usd, event_id, specialist
             FROM usage ORDER BY id DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map(rusqlite::params![n as u32], |row| {
            Ok(UsageRecord {
                timestamp: row.get(0)?,
                provider: row.get(1)?,
                model: row.get(2)?,
                input_tokens: row.get(3)?,
                output_tokens: row.get(4)?,
                estimated_cost_usd: row.get(5)?,
                event_id: row.get(6)?,
                specialist: row.get(7)?,
            })
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.flatten().collect()
    }

    /// Delete all usage data.
    pub fn reset(&self) -> Result<()> {
        self.db.execute("DELETE FROM usage", [])?;
        Ok(())
    }

    /// Reference to the pricing table.
    pub fn pricing(&self) -> &PricingTable {
        &self.pricing
    }

    /// Reference to the budget config.
    pub fn budget(&self) -> &BudgetConfig {
        &self.budget
    }

    /// Current session cost accumulated since tracker creation.
    pub fn session_used(&self) -> f64 {
        self.session_used
    }

    /// Estimate cost for a session type before it runs.
    pub fn estimate_session_cost(
        &self,
        session_type: SessionCostType,
        _provider: &str,
        model: &str,
    ) -> PreFlightEstimate {
        let (est_input, est_output) = session_type.estimated_tokens();
        let estimated_cost = self
            .pricing
            .estimate_cost(model, est_input as u32, est_output as u32);

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let month_prefix = &today[..7];

        let daily_used: f64 = self
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage WHERE timestamp LIKE ?1",
                rusqlite::params![format!("{today}%")],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        let monthly_used: f64 = self
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage WHERE timestamp LIKE ?1",
                rusqlite::params![format!("{month_prefix}%")],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        let session_remaining = (self.budget.session_limit_usd - self.session_used).max(0.0);
        let daily_remaining = (self.budget.daily_limit_usd - daily_used).max(0.0);
        let monthly_remaining = (self.budget.monthly_limit_usd - monthly_used).max(0.0);

        let will_exceed_budget = estimated_cost > session_remaining
            || estimated_cost > daily_remaining
            || estimated_cost > monthly_remaining;

        let display_message = format!(
            "This will use ~{}K tokens (~${:.2}). Daily budget: ${:.2} remaining.",
            (est_input + est_output) / 1000,
            estimated_cost,
            daily_remaining,
        );

        PreFlightEstimate {
            estimated_input_tokens: est_input,
            estimated_output_tokens: est_output,
            estimated_cost_usd: estimated_cost,
            session_budget_remaining: session_remaining,
            daily_budget_remaining: daily_remaining,
            monthly_budget_remaining: monthly_remaining,
            will_exceed_budget,
            display_message,
        }
    }

    /// Return cost history aggregated by day for the last `days` days.
    pub fn get_cost_history(&self, days: u32) -> Result<Vec<DailyCost>> {
        let mut stmt = self.db.prepare(
            "SELECT
                 substr(timestamp, 1, 10) AS day,
                 COALESCE(SUM(estimated_cost_usd), 0.0),
                 COUNT(*),
                 COALESCE(SUM(input_tokens), 0),
                 COALESCE(SUM(output_tokens), 0)
             FROM usage
             WHERE date(substr(timestamp, 1, 10)) >= date('now', ?1)
             GROUP BY day
             ORDER BY day DESC",
        )?;

        let offset = format!("-{days} days");
        let rows = stmt.query_map(rusqlite::params![offset], |row| {
            Ok(DailyCost {
                date: row.get(0)?,
                total_cost: row.get(1)?,
                total_calls: row.get(2)?,
                total_input_tokens: row.get(3)?,
                total_output_tokens: row.get(4)?,
            })
        })?;

        Ok(rows.flatten().collect())
    }

    /// Build a full budget status report across all tiers.
    pub fn get_budget_status(&self) -> Result<BudgetStatusReport> {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let month_prefix = &today[..7];

        let daily_used: f64 = self
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage WHERE timestamp LIKE ?1",
                rusqlite::params![format!("{today}%")],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        let monthly_used: f64 = self
            .db
            .query_row(
                "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage WHERE timestamp LIKE ?1",
                rusqlite::params![format!("{month_prefix}%")],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        let session_remaining = (self.budget.session_limit_usd - self.session_used).max(0.0);
        let daily_remaining = (self.budget.daily_limit_usd - daily_used).max(0.0);
        let monthly_remaining = (self.budget.monthly_limit_usd - monthly_used).max(0.0);

        let session_pct = if self.budget.session_limit_usd > 0.0 {
            (self.session_used / self.budget.session_limit_usd) * 100.0
        } else {
            0.0
        };
        let daily_pct = if self.budget.daily_limit_usd > 0.0 {
            (daily_used / self.budget.daily_limit_usd) * 100.0
        } else {
            0.0
        };
        let monthly_pct = if self.budget.monthly_limit_usd > 0.0 {
            (monthly_used / self.budget.monthly_limit_usd) * 100.0
        } else {
            0.0
        };

        let warning_threshold = 80.0;
        let any_warning =
            session_pct >= warning_threshold
            || daily_pct >= warning_threshold
            || monthly_pct >= warning_threshold;

        Ok(BudgetStatusReport {
            session_budget: self.budget.session_limit_usd,
            session_used: self.session_used,
            session_remaining,
            session_percent: session_pct,
            daily_budget: self.budget.daily_limit_usd,
            daily_used,
            daily_remaining,
            daily_percent: daily_pct,
            monthly_budget: self.budget.monthly_limit_usd,
            monthly_used,
            monthly_remaining,
            monthly_percent: monthly_pct,
            warning_threshold_percent: warning_threshold,
            any_warning,
        })
    }

    /// Update budget limits. Only provided values are changed.
    pub fn update_budgets(
        &mut self,
        session: Option<f64>,
        daily: Option<f64>,
        monthly: Option<f64>,
    ) -> Result<()> {
        if let Some(s) = session {
            self.budget.session_limit_usd = s;
        }
        if let Some(d) = daily {
            self.budget.daily_limit_usd = d;
        }
        if let Some(m) = monthly {
            self.budget.monthly_limit_usd = m;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_db() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_usage.db");
        (dir, path)
    }

    fn make_tracker(db_path: &Path) -> CostTracker {
        CostTracker::new(db_path, PricingTable::default(), BudgetConfig::default()).unwrap()
    }

    fn today_timestamp() -> String {
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string()
    }

    #[test]
    fn test_cost_calculation_claude_sonnet() {
        let pricing = PricingTable::default();
        // 1000 input tokens, 500 output tokens for claude-sonnet-4-20250514
        // input: 1000/1M * 3.00 = 0.003
        // output: 500/1M * 15.00 = 0.0075
        // total: 0.0105
        let cost = pricing.estimate_cost("claude-sonnet-4-20250514", 1000, 500);
        assert!((cost - 0.0105).abs() < 1e-10);
    }

    #[test]
    fn test_cost_calculation_gpt4o_mini() {
        let pricing = PricingTable::default();
        // 1_000_000 input, 1_000_000 output
        // input: 0.15, output: 0.60, total: 0.75
        let cost = pricing.estimate_cost("gpt-4o-mini", 1_000_000, 1_000_000);
        assert!((cost - 0.75).abs() < 1e-10);
    }

    #[test]
    fn test_zero_cost_unknown_model() {
        let pricing = PricingTable::default();
        let cost = pricing.estimate_cost("custom-local-model", 10000, 5000);
        assert!((cost - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_zero_cost_custom_provider() {
        let mut models = HashMap::new();
        models.insert(
            "my-custom".to_string(),
            ModelPricing {
                input_per_million: 0.0,
                output_per_million: 0.0,
            },
        );
        let pricing = PricingTable { models };
        let cost = pricing.estimate_cost("my-custom", 999_999, 999_999);
        assert!((cost - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_budget_config_defaults() {
        let config = BudgetConfig::default();
        assert!((config.daily_limit_usd - 1.00).abs() < 1e-10);
        assert!((config.monthly_limit_usd - 20.00).abs() < 1e-10);
    }

    #[test]
    fn test_record_and_summary() {
        let (_dir, db_path) = temp_db();
        let tracker = make_tracker(&db_path);

        let ts = today_timestamp();
        tracker
            .record_usage(&UsageRecord {
                timestamp: ts.clone(),
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                input_tokens: 1000,
                output_tokens: 500,
                estimated_cost_usd: 0.0105,
                event_id: Some("evt-1".to_string()),
                specialist: Some("hawk".to_string()),
            })
            .unwrap();

        tracker
            .record_usage(&UsageRecord {
                timestamp: ts,
                provider: "openai".to_string(),
                model: "gpt-4o-mini".to_string(),
                input_tokens: 2000,
                output_tokens: 1000,
                estimated_cost_usd: 0.0009,
                event_id: None,
                specialist: None,
            })
            .unwrap();

        let summary = tracker.get_summary();
        assert_eq!(summary.total_calls, 2);
        assert!((summary.total_cost - 0.0114).abs() < 1e-10);
        assert!((summary.avg_cost_per_call - 0.0057).abs() < 1e-10);
        assert!(summary.by_provider.contains_key("anthropic"));
        assert!(summary.by_provider.contains_key("openai"));
    }

    #[test]
    fn test_get_recent() {
        let (_dir, db_path) = temp_db();
        let tracker = make_tracker(&db_path);

        for i in 0..5 {
            tracker
                .record_usage(&UsageRecord {
                    timestamp: format!("2025-01-01T00:00:0{i}"),
                    provider: "anthropic".to_string(),
                    model: "claude-sonnet-4-20250514".to_string(),
                    input_tokens: 100,
                    output_tokens: 50,
                    estimated_cost_usd: 0.001,
                    event_id: Some(format!("evt-{i}")),
                    specialist: None,
                })
                .unwrap();
        }

        let recent = tracker.get_recent(3);
        assert_eq!(recent.len(), 3);
        // Most recent first
        assert_eq!(recent[0].event_id, Some("evt-4".to_string()));
    }

    #[test]
    fn test_daily_budget_exceeded() {
        let (_dir, db_path) = temp_db();
        let tracker = CostTracker::new(
            &db_path,
            PricingTable::default(),
            BudgetConfig {
                session_limit_usd: 100.00,
                daily_limit_usd: 0.01,
                monthly_limit_usd: 20.00,
            },
        )
        .unwrap();

        let ts = today_timestamp();
        // Record usage that exceeds the daily limit
        tracker
            .record_usage(&UsageRecord {
                timestamp: ts,
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                input_tokens: 10000,
                output_tokens: 5000,
                estimated_cost_usd: 0.105,
                event_id: None,
                specialist: None,
            })
            .unwrap();

        match tracker.check_budget() {
            BudgetStatus::Exceeded { daily_used, .. } => {
                assert!(daily_used >= 0.01);
            }
            BudgetStatus::WithinBudget => panic!("Expected budget exceeded"),
        }
    }

    #[test]
    fn test_monthly_budget_accumulates() {
        let (_dir, db_path) = temp_db();
        let tracker = CostTracker::new(
            &db_path,
            PricingTable::default(),
            BudgetConfig {
                session_limit_usd: 100.00,
                daily_limit_usd: 100.00, // high daily so we only trigger monthly
                monthly_limit_usd: 0.05,
            },
        )
        .unwrap();

        let now = chrono::Utc::now();
        // Record usage on different days within this month
        for day in 1..=3 {
            let ts = format!(
                "{}-{:02}-{:02}T12:00:00",
                now.format("%Y"),
                now.format("%m"),
                day
            );
            tracker
                .record_usage(&UsageRecord {
                    timestamp: ts,
                    provider: "openai".to_string(),
                    model: "gpt-4o-mini".to_string(),
                    input_tokens: 100000,
                    output_tokens: 50000,
                    estimated_cost_usd: 0.02,
                    event_id: None,
                    specialist: None,
                })
                .unwrap();
        }

        match tracker.check_budget() {
            BudgetStatus::Exceeded { monthly_used, .. } => {
                assert!(monthly_used >= 0.05);
            }
            BudgetStatus::WithinBudget => panic!("Expected monthly budget exceeded"),
        }
    }

    #[test]
    fn test_within_budget() {
        let (_dir, db_path) = temp_db();
        let tracker = make_tracker(&db_path);

        let ts = today_timestamp();
        tracker
            .record_usage(&UsageRecord {
                timestamp: ts,
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                input_tokens: 100,
                output_tokens: 50,
                estimated_cost_usd: 0.001,
                event_id: None,
                specialist: None,
            })
            .unwrap();

        assert_eq!(tracker.check_budget(), BudgetStatus::WithinBudget);
    }

    #[test]
    fn test_sqlite_persistence() {
        let (_dir, db_path) = temp_db();

        // Write data with one tracker instance
        {
            let tracker = make_tracker(&db_path);
            tracker
                .record_usage(&UsageRecord {
                    timestamp: "2025-06-01T10:00:00".to_string(),
                    provider: "anthropic".to_string(),
                    model: "claude-sonnet-4-20250514".to_string(),
                    input_tokens: 500,
                    output_tokens: 200,
                    estimated_cost_usd: 0.0045,
                    event_id: Some("persist-test".to_string()),
                    specialist: Some("forensics".to_string()),
                })
                .unwrap();
        }

        // Reopen and verify data persists
        {
            let tracker = make_tracker(&db_path);
            let recent = tracker.get_recent(10);
            assert_eq!(recent.len(), 1);
            assert_eq!(recent[0].event_id, Some("persist-test".to_string()));
            assert_eq!(recent[0].specialist, Some("forensics".to_string()));
            assert!((recent[0].estimated_cost_usd - 0.0045).abs() < 1e-10);

            let summary = tracker.get_summary();
            assert_eq!(summary.total_calls, 1);
        }
    }

    #[test]
    fn test_reset() {
        let (_dir, db_path) = temp_db();
        let tracker = make_tracker(&db_path);

        tracker
            .record_usage(&UsageRecord {
                timestamp: today_timestamp(),
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                input_tokens: 100,
                output_tokens: 50,
                estimated_cost_usd: 0.001,
                event_id: None,
                specialist: None,
            })
            .unwrap();

        assert_eq!(tracker.get_summary().total_calls, 1);

        tracker.reset().unwrap();

        let summary = tracker.get_summary();
        assert_eq!(summary.total_calls, 0);
        assert!((summary.total_cost - 0.0).abs() < 1e-10);
    }

    // -----------------------------------------------------------------------
    // New tests for pre-flight estimates, cost guard, and budget reporting
    // -----------------------------------------------------------------------

    #[test]
    fn test_pre_flight_estimate_scan() {
        let (_dir, db_path) = temp_db();
        let tracker = make_tracker(&db_path);

        let estimate = tracker.estimate_session_cost(
            SessionCostType::Scan,
            "anthropic",
            "claude-sonnet-4-20250514",
        );

        // Scan: 40K input + 10K output for claude-sonnet
        // input: 40000/1M * 3.00 = 0.12
        // output: 10000/1M * 15.00 = 0.15
        // total: 0.27
        assert!(
            estimate.estimated_cost_usd >= 0.01 && estimate.estimated_cost_usd <= 0.50,
            "Scan estimate ${:.4} should be in $0.01-$0.50 range",
            estimate.estimated_cost_usd,
        );
        assert_eq!(estimate.estimated_input_tokens, 40_000);
        assert_eq!(estimate.estimated_output_tokens, 10_000);
        assert!(!estimate.will_exceed_budget);
        assert!(!estimate.display_message.is_empty());
    }

    #[test]
    fn test_pre_flight_estimate_chat() {
        let (_dir, db_path) = temp_db();
        let tracker = make_tracker(&db_path);

        let chat_est = tracker.estimate_session_cost(
            SessionCostType::ChatMessage,
            "anthropic",
            "claude-sonnet-4-20250514",
        );
        let scan_est = tracker.estimate_session_cost(
            SessionCostType::Scan,
            "anthropic",
            "claude-sonnet-4-20250514",
        );

        // Chat should be cheapest compared to scan
        assert!(
            chat_est.estimated_cost_usd < scan_est.estimated_cost_usd,
            "Chat ${:.4} should be cheaper than scan ${:.4}",
            chat_est.estimated_cost_usd,
            scan_est.estimated_cost_usd,
        );
        assert_eq!(chat_est.estimated_input_tokens, 3_000);
        assert_eq!(chat_est.estimated_output_tokens, 1_000);
    }

    #[tokio::test]
    async fn test_budget_enforcement_blocks_over_limit() {
        let (_dir, db_path) = temp_db();
        let tracker = CostTracker::new(
            &db_path,
            PricingTable::default(),
            BudgetConfig {
                session_limit_usd: 0.001,
                daily_limit_usd: 0.001,
                monthly_limit_usd: 0.001,
            },
        )
        .unwrap();

        // Record usage that exceeds budgets
        tracker
            .record_usage(&UsageRecord {
                timestamp: today_timestamp(),
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                input_tokens: 10000,
                output_tokens: 5000,
                estimated_cost_usd: 0.105,
                event_id: None,
                specialist: None,
            })
            .unwrap();

        let tracker = Arc::new(Mutex::new(tracker));
        let guard = CostGuard::new(tracker);

        let result = guard.check_budget().await;
        assert!(result.is_err(), "Should fail when budget is exceeded");
    }

    #[tokio::test]
    async fn test_budget_enforcement_allows_within_limit() {
        let (_dir, db_path) = temp_db();
        let tracker = CostTracker::new(
            &db_path,
            PricingTable::default(),
            BudgetConfig {
                session_limit_usd: 100.0,
                daily_limit_usd: 100.0,
                monthly_limit_usd: 100.0,
            },
        )
        .unwrap();

        let tracker = Arc::new(Mutex::new(tracker));
        let guard = CostGuard::new(tracker);

        let result = guard.check_budget().await;
        assert!(result.is_ok(), "Should succeed when within budget");
    }

    #[test]
    fn test_cost_calculation_accuracy() {
        let pricing = PricingTable::default();
        // 1000 input tokens + 500 output tokens with claude-sonnet pricing
        // input: 1000/1M * 3.00 = 0.003
        // output: 500/1M * 15.00 = 0.0075
        // total: 0.0105
        let cost = pricing.estimate_cost("claude-sonnet-4-20250514", 1000, 500);
        let expected = (1000.0 / 1_000_000.0) * 3.0 + (500.0 / 1_000_000.0) * 15.0;
        assert!(
            (cost - expected).abs() < 1e-10,
            "Cost {cost} should equal expected {expected}",
        );
    }

    #[test]
    fn test_budget_status_report() {
        let (_dir, db_path) = temp_db();
        let mut tracker = CostTracker::new(
            &db_path,
            PricingTable::default(),
            BudgetConfig {
                session_limit_usd: 1.00,
                daily_limit_usd: 2.00,
                monthly_limit_usd: 10.00,
            },
        )
        .unwrap();

        // Simulate session usage
        tracker.session_used = 0.85;

        // Record daily/monthly usage
        tracker
            .record_usage(&UsageRecord {
                timestamp: today_timestamp(),
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                input_tokens: 10000,
                output_tokens: 5000,
                estimated_cost_usd: 1.70,
                event_id: None,
                specialist: None,
            })
            .unwrap();

        let report = tracker.get_budget_status().unwrap();

        // Session: 0.85/1.00 = 85%
        assert!((report.session_percent - 85.0).abs() < 1e-6);
        assert!((report.session_remaining - 0.15).abs() < 1e-6);

        // Daily: 1.70/2.00 = 85%
        assert!((report.daily_percent - 85.0).abs() < 1e-6);

        // Warning threshold is 80%
        assert!((report.warning_threshold_percent - 80.0).abs() < 1e-6);
        assert!(report.any_warning, "Should trigger warning at 85% usage");
    }

    #[test]
    fn test_pricing_table_has_all_models() {
        let pricing = PricingTable::default();
        let expected_models = [
            "claude-sonnet-4-20250514",
            "claude-haiku-4-5-20251001",
            "gpt-4o-mini",
            "gpt-4o",
            "gemini-2.0-flash",
        ];

        for model in &expected_models {
            assert!(
                pricing.models.contains_key(*model),
                "Pricing table should contain model: {model}",
            );
        }
    }

    #[test]
    fn test_update_budgets() {
        let (_dir, db_path) = temp_db();
        let mut tracker = make_tracker(&db_path);

        tracker.update_budgets(Some(2.0), Some(5.0), None).unwrap();
        assert!((tracker.budget().session_limit_usd - 2.0).abs() < 1e-10);
        assert!((tracker.budget().daily_limit_usd - 5.0).abs() < 1e-10);
        // Monthly should remain at default
        assert!((tracker.budget().monthly_limit_usd - 20.0).abs() < 1e-10);
    }

    #[tokio::test]
    async fn test_cost_guard_record_updates_session() {
        let (_dir, db_path) = temp_db();
        let tracker = CostTracker::new(
            &db_path,
            PricingTable::default(),
            BudgetConfig {
                session_limit_usd: 10.0,
                daily_limit_usd: 100.0,
                monthly_limit_usd: 100.0,
            },
        )
        .unwrap();

        let tracker = Arc::new(Mutex::new(tracker));
        let guard = CostGuard::new(Arc::clone(&tracker));

        guard
            .record_usage(UsageRecord {
                timestamp: today_timestamp(),
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                input_tokens: 1000,
                output_tokens: 500,
                estimated_cost_usd: 0.05,
                event_id: None,
                specialist: None,
            })
            .await
            .unwrap();

        let t = tracker.lock().unwrap();
        assert!(
            (t.session_used() - 0.05).abs() < 1e-10,
            "Session used should be 0.05 after recording",
        );
    }
}
