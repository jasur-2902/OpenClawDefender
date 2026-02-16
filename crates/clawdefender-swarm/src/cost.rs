//! Token tracking, budgeting, and usage reporting for cloud swarm calls.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;

/// Tracks token usage and estimated costs across providers.
pub struct CostTracker {
    db: Connection,
    pricing: PricingTable,
    budget: BudgetConfig,
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

/// Budget limits for daily and monthly spend.
#[derive(Debug, Clone)]
pub struct BudgetConfig {
    pub daily_limit_usd: f64,
    pub monthly_limit_usd: f64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
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

impl Default for PricingTable {
    fn default() -> Self {
        let mut models = HashMap::new();
        models.insert(
            "claude-sonnet-4-20250514".to_string(),
            ModelPricing {
                input_per_million: 3.00,
                output_per_million: 15.00,
            },
        );
        models.insert(
            "gpt-4o-mini".to_string(),
            ModelPricing {
                input_per_million: 0.15,
                output_per_million: 0.60,
            },
        );
        Self { models }
    }
}

impl PricingTable {
    /// Estimate cost for the given token counts. Returns 0.0 for unknown models.
    pub fn estimate_cost(&self, model: &str, input_tokens: u32, output_tokens: u32) -> f64 {
        match self.models.get(model) {
            Some(pricing) => {
                let input_cost = (input_tokens as f64 / 1_000_000.0) * pricing.input_per_million;
                let output_cost =
                    (output_tokens as f64 / 1_000_000.0) * pricing.output_per_million;
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
                daily_limit_usd: 100.00, // high daily so we only trigger monthly
                monthly_limit_usd: 0.05,
            },
        )
        .unwrap();

        let now = chrono::Utc::now();
        // Record usage on different days within this month
        for day in 1..=3 {
            let ts = format!("{}-{:02}-{:02}T12:00:00", now.format("%Y"), now.format("%m"), day);
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
}
