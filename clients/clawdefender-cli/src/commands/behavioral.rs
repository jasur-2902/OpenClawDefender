//! CLI commands for the behavioral baseline engine.

use anyhow::Result;
use clawdefender_core::audit::AuditLogger;
use clawdefender_core::behavioral::{DecisionEngine, ProfileStore};
use clawdefender_core::config::settings::ClawConfig;

/// Show behavioral engine status.
pub fn status(config: &ClawConfig) -> Result<()> {
    println!("Behavioral Engine Status");
    println!("========================");
    println!();
    println!("  Enabled:             {}", config.behavioral.enabled);
    println!(
        "  Anomaly threshold:   {:.2}",
        config.behavioral.anomaly_threshold
    );
    println!(
        "  Auto-block threshold: {:.2}",
        config.behavioral.auto_block_threshold
    );
    println!(
        "  Auto-block enabled:  {}",
        config.behavioral.auto_block_enabled
    );
    println!(
        "  Learning events:     {}",
        config.behavioral.learning_event_threshold
    );
    println!(
        "  Learning time (min): {}",
        config.behavioral.learning_time_minutes
    );
    println!();

    if !config.behavioral.enabled {
        println!("  Engine is DISABLED. Enable in config with [behavioral] enabled = true");
        return Ok(());
    }

    // Load profiles from store
    let store = open_store()?;
    let profiles = store.load_all_profiles()?;
    let total = profiles.len();
    let learning = profiles.iter().filter(|p| p.learning_mode).count();
    let active = total - learning;

    println!("  Profiles:            {}", total);
    println!("    Learning:          {}", learning);
    println!("    Active:            {}", active);

    println!();
    println!("Injection Detector");
    println!("------------------");
    println!(
        "  Enabled:             {}",
        config.injection_detector.enabled
    );
    println!(
        "  Threshold:           {:.2}",
        config.injection_detector.threshold
    );
    println!(
        "  Auto-block:          {}",
        config.injection_detector.auto_block
    );
    if let Some(ref path) = config.injection_detector.patterns_path {
        println!("  Custom patterns:     {}", path.display());
    }

    Ok(())
}

/// Run calibration analysis against historical audit data.
pub fn calibrate(config: &ClawConfig) -> Result<()> {
    if !config.behavioral.enabled {
        anyhow::bail!("Behavioral engine is disabled in config.");
    }

    // Load audit log to find events with behavioral data
    let logger = clawdefender_core::audit::logger::FileAuditLogger::new(
        config.audit_log_path.clone(),
        config.log_rotation.clone(),
    )?;

    let filter = clawdefender_core::audit::AuditFilter {
        limit: 10000,
        ..Default::default()
    };

    let records = logger.query(&filter)?;
    let scores: Vec<(f64, String)> = records
        .iter()
        .filter_map(|r| {
            r.behavioral
                .as_ref()
                .map(|b| (b.anomaly_score, r.event_summary.clone()))
        })
        .filter(|(score, _)| *score > 0.0)
        .collect();

    if scores.is_empty() {
        println!("No behavioral scores found in audit log.");
        println!(
            "The behavioral engine may still be in learning mode or has not yet processed events."
        );
        return Ok(());
    }

    let result = DecisionEngine::calibrate(&scores);
    println!("Calibration Analysis");
    println!("====================");
    println!(
        "  Total events with behavioral scores: {}",
        result.total_events
    );
    println!();

    for tr in &result.results_by_threshold {
        println!(
            "  Threshold {:.1}: {} events would be auto-blocked ({:.1}%)",
            tr.threshold,
            tr.would_auto_block,
            if result.total_events > 0 {
                tr.would_auto_block as f64 / result.total_events as f64 * 100.0
            } else {
                0.0
            }
        );
        for detail in tr.details.iter().take(5) {
            println!("    - {}", detail);
        }
    }

    Ok(())
}

/// Show auto-block statistics.
pub fn stats(config: &ClawConfig) -> Result<()> {
    if !config.behavioral.enabled {
        anyhow::bail!("Behavioral engine is disabled in config.");
    }

    // Load audit log and compute stats from behavioral data
    let logger = clawdefender_core::audit::logger::FileAuditLogger::new(
        config.audit_log_path.clone(),
        config.log_rotation.clone(),
    )?;

    let filter = clawdefender_core::audit::AuditFilter {
        limit: 10000,
        ..Default::default()
    };

    let records = logger.query(&filter)?;
    let mut total_auto_blocks: u64 = 0;
    let mut total_with_behavioral: u64 = 0;
    let mut high_score_count: u64 = 0;
    let mut dimension_counts: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();

    for record in &records {
        if let Some(ref b) = record.behavioral {
            total_with_behavioral += 1;
            if b.auto_blocked {
                total_auto_blocks += 1;
            }
            if b.anomaly_score >= config.behavioral.anomaly_threshold {
                high_score_count += 1;
            }
            for comp in &b.anomaly_components {
                if comp.score > 0.0 {
                    *dimension_counts.entry(comp.dimension.clone()).or_insert(0) += 1;
                }
            }
        }
    }

    println!("Behavioral Auto-Block Statistics");
    println!("================================");
    println!();
    println!("  Events with behavioral data: {}", total_with_behavioral);
    println!("  Auto-blocked events:         {}", total_auto_blocks);
    println!(
        "  High anomaly events:         {} (score >= {:.2})",
        high_score_count, config.behavioral.anomaly_threshold
    );
    println!();

    if !dimension_counts.is_empty() {
        println!("  Top Anomaly Triggers:");
        let mut sorted: Vec<_> = dimension_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (dim, count) in sorted.iter().take(10) {
            println!("    {}: {} events", dim, count);
        }
    }

    Ok(())
}

fn open_store() -> Result<ProfileStore> {
    ProfileStore::open(&ProfileStore::default_path())
}
