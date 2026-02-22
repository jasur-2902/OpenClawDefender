//! `clawdefender usage` — display cloud swarm token usage and costs.

use std::io::{self, Write};
use std::path::PathBuf;

use clawdefender_swarm::cost::{BudgetConfig, CostTracker, PricingTable};

/// Default database path: ~/.local/share/clawdefender/usage.db
fn default_db_path() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME not set");
    PathBuf::from(home)
        .join(".local/share/clawdefender")
        .join("usage.db")
}

/// Open a CostTracker with defaults, creating the parent directory if needed.
fn open_tracker() -> anyhow::Result<CostTracker> {
    let db_path = default_db_path();
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    CostTracker::new(&db_path, PricingTable::default(), BudgetConfig::default())
}

pub fn run(detail: bool, reset: bool) -> anyhow::Result<()> {
    let tracker = open_tracker()?;

    if reset {
        print!("This will permanently delete all usage data. Continue? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().eq_ignore_ascii_case("y") {
            tracker.reset()?;
            println!("Usage data cleared.");
        } else {
            println!("Cancelled.");
        }
        return Ok(());
    }

    if detail {
        let records = tracker.get_recent(50);
        if records.is_empty() {
            println!("No usage records yet.");
            return Ok(());
        }
        println!(
            "{:<22} {:<12} {:<30} {:>8} {:>8} {:>10}",
            "Timestamp", "Provider", "Model", "In Tok", "Out Tok", "Cost"
        );
        println!("{}", "-".repeat(94));
        for r in &records {
            println!(
                "{:<22} {:<12} {:<30} {:>8} {:>8} ${:>9.6}",
                r.timestamp,
                r.provider,
                r.model,
                r.input_tokens,
                r.output_tokens,
                r.estimated_cost_usd
            );
        }
        return Ok(());
    }

    // Default: show summary
    let summary = tracker.get_summary();
    let budget = tracker.budget();

    println!("ClawDefender Cloud Swarm Usage");
    println!("{}", "=".repeat(40));
    println!("Today:       ${:.6}", summary.today_cost);
    println!("This month:  ${:.6}", summary.month_cost);
    println!("All time:    ${:.6}", summary.total_cost);
    println!("Total calls: {}", summary.total_calls);
    if summary.total_calls > 0 {
        println!("Avg/call:    ${:.6}", summary.avg_cost_per_call);
    }

    if !summary.by_provider.is_empty() {
        println!();
        println!("By provider:");
        let mut providers: Vec<_> = summary.by_provider.iter().collect();
        providers.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());
        for (provider, cost) in providers {
            println!("  {:<16} ${:.6}", provider, cost);
        }
    }

    println!();
    println!("Budget:");
    println!(
        "  Daily:   ${:.6} / ${:.2}",
        summary.today_cost, budget.daily_limit_usd
    );
    println!(
        "  Monthly: ${:.6} / ${:.2}",
        summary.month_cost, budget.monthly_limit_usd
    );

    let status = tracker.check_budget();
    match status {
        clawdefender_swarm::cost::BudgetStatus::WithinBudget => {
            println!("  Status:  OK");
        }
        clawdefender_swarm::cost::BudgetStatus::Exceeded { reason, .. } => {
            println!("  Status:  EXCEEDED - {}", reason);
        }
    }

    Ok(())
}
