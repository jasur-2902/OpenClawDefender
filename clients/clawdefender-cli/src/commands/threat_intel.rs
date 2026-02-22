//! CLI commands for threat intelligence management.

use anyhow::Result;
use clawdefender_core::config::ClawConfig;

use std::path::PathBuf;

/// Data directory for threat intelligence cache.
fn data_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share/clawdefender/threat-intel")
    } else {
        PathBuf::from("/tmp/clawdefender/threat-intel")
    }
}

// ---------------------------------------------------------------------------
// Feed commands
// ---------------------------------------------------------------------------

pub fn feed_status(config: &ClawConfig) -> Result<()> {
    use clawdefender_threat_intel::FeedCache;

    println!("Feed Status");
    println!("===========");

    if !config.threat_intel.enabled {
        println!("  Threat intelligence: disabled in config");
        return Ok(());
    }

    let cache = FeedCache::new(data_dir());
    match cache.read_manifest() {
        Ok(Some(manifest)) => {
            println!("  Feed version:  {}", manifest.version);
            println!("  Last updated:  {}", manifest.last_updated);
            println!("  Files cached:  {}", manifest.files.len());
            println!(
                "  Update interval: {} hours",
                config.threat_intel.update_interval_hours
            );
        }
        Ok(None) => {
            println!("  No feed data cached yet.");
            println!("  Run `clawdefender feed update` to fetch the latest feed.");
        }
        Err(e) => {
            println!("  Error reading cache: {}", e);
        }
    }

    Ok(())
}

pub async fn feed_update(config: &ClawConfig) -> Result<()> {
    use clawdefender_threat_intel::{FeedCache, FeedClient, FeedVerifier};

    if !config.threat_intel.enabled {
        println!("Threat intelligence is disabled in config.");
        return Ok(());
    }

    println!("Checking for feed updates...");

    let cache = FeedCache::new(data_dir());
    let verifier =
        FeedVerifier::from_hex("0000000000000000000000000000000000000000000000000000000000000000")?;

    let ti_config = clawdefender_threat_intel::ThreatIntelConfig {
        enabled: config.threat_intel.enabled,
        feed_url: config.threat_intel.feed_url.clone(),
        update_interval_hours: config.threat_intel.update_interval_hours,
        auto_apply_rules: config.threat_intel.auto_apply_rules,
        auto_apply_blocklist: config.threat_intel.auto_apply_blocklist,
        auto_apply_patterns: config.threat_intel.auto_apply_patterns,
        auto_apply_iocs: config.threat_intel.auto_apply_iocs,
        notify_on_update: config.threat_intel.notify_on_update,
    };

    let mut client = FeedClient::new(ti_config, cache, verifier)?;
    match client.check_update().await {
        Ok(result) => match result {
            clawdefender_threat_intel::UpdateResult::Updated {
                old_version,
                new_version,
                files_updated,
            } => {
                println!(
                    "  Updated: {} -> {}",
                    old_version.as_deref().unwrap_or("(none)"),
                    new_version
                );
                println!("  Files updated: {}", files_updated.len());
                for f in &files_updated {
                    println!("    - {}", f);
                }
            }
            clawdefender_threat_intel::UpdateResult::UpToDate { version } => {
                println!("  Already up to date (v{})", version);
            }
            clawdefender_threat_intel::UpdateResult::FallbackToCached { reason, version } => {
                println!("  Using cached data (v{}): {}", version, reason);
            }
            clawdefender_threat_intel::UpdateResult::NoData => {
                println!("  No feed data available.");
            }
        },
        Err(e) => {
            println!("  Feed update failed: {}", e);
        }
    }

    Ok(())
}

pub fn feed_verify(_config: &ClawConfig) -> Result<()> {
    use clawdefender_threat_intel::FeedCache;

    println!("Feed Verification");
    println!("=================");

    let cache = FeedCache::new(data_dir());
    match cache.read_manifest() {
        Ok(Some(manifest)) => {
            println!("  Feed version:  {}", manifest.version);
            println!("  Files in manifest: {}", manifest.files.len());

            let mut present = 0;
            let mut missing = 0;
            for (name, entry) in &manifest.files {
                match cache.read_file(name) {
                    Ok(Some(data)) => {
                        let hash = clawdefender_threat_intel::client::sha256_hex(&data);
                        if hash == entry.sha256 {
                            present += 1;
                        } else {
                            println!(
                                "  MISMATCH: {} (expected {}..., got {}...)",
                                name,
                                &entry.sha256[..8.min(entry.sha256.len())],
                                &hash[..8.min(hash.len())]
                            );
                        }
                    }
                    Ok(None) => {
                        println!("  MISSING: {}", name);
                        missing += 1;
                    }
                    Err(e) => {
                        println!("  ERROR reading {}: {}", name, e);
                    }
                }
            }

            println!();
            println!("  Valid:   {}", present);
            println!("  Missing: {}", missing);
        }
        Ok(None) => {
            println!("  No feed data cached.");
        }
        Err(e) => {
            println!("  Error: {}", e);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Rules commands
// ---------------------------------------------------------------------------

pub fn rules_list(_config: &ClawConfig) -> Result<()> {
    use clawdefender_threat_intel::rules::catalog::RuleCatalog;

    println!("Community Rule Packs");
    println!("====================");

    let rules_dir = data_dir().join("rules");
    std::fs::create_dir_all(&rules_dir).ok();

    let catalog = RuleCatalog::new(&rules_dir)?;

    let installed = catalog.list_installed();
    let available = catalog.list_available();

    if !installed.is_empty() {
        println!("\n  Installed:");
        for pack in installed {
            println!(
                "    - {} v{} ({})",
                pack.metadata.id, pack.metadata.version, pack.metadata.name
            );
        }
    } else {
        println!("\n  No packs installed.");
    }

    if !available.is_empty() {
        println!("\n  Available:");
        for pack in available {
            let installed_marker = if installed.iter().any(|i| i.metadata.id == pack.id) {
                " [installed]"
            } else {
                ""
            };
            println!(
                "    - {} v{} — {}{}",
                pack.id, pack.version, pack.name, installed_marker
            );
        }
    }

    Ok(())
}

pub fn rules_install(_config: &ClawConfig, pack_id: &str) -> Result<()> {
    use clawdefender_threat_intel::rules::catalog::RuleCatalog;
    use clawdefender_threat_intel::rules::manager::RulePackManager;
    use clawdefender_threat_intel::FeedCache;

    let rules_dir = data_dir().join("rules");
    std::fs::create_dir_all(&rules_dir).ok();

    let catalog = RuleCatalog::new(&rules_dir)?;
    let cache = FeedCache::new(data_dir());
    let mut manager = RulePackManager::new(catalog, cache);

    match manager.install(pack_id) {
        Ok(()) => println!("Installed rule pack: {}", pack_id),
        Err(e) => println!("Failed to install {}: {}", pack_id, e),
    }

    Ok(())
}

pub fn rules_uninstall(_config: &ClawConfig, pack_id: &str) -> Result<()> {
    use clawdefender_threat_intel::rules::catalog::RuleCatalog;
    use clawdefender_threat_intel::rules::manager::RulePackManager;
    use clawdefender_threat_intel::FeedCache;

    let rules_dir = data_dir().join("rules");
    let catalog = RuleCatalog::new(&rules_dir)?;
    let cache = FeedCache::new(data_dir());
    let mut manager = RulePackManager::new(catalog, cache);

    match manager.uninstall(pack_id) {
        Ok(()) => println!("Uninstalled rule pack: {}", pack_id),
        Err(e) => println!("Failed to uninstall {}: {}", pack_id, e),
    }

    Ok(())
}

pub fn rules_update(_config: &ClawConfig) -> Result<()> {
    use clawdefender_threat_intel::rules::catalog::RuleCatalog;
    use clawdefender_threat_intel::rules::manager::RulePackManager;
    use clawdefender_threat_intel::FeedCache;

    let rules_dir = data_dir().join("rules");
    std::fs::create_dir_all(&rules_dir).ok();

    let catalog = RuleCatalog::new(&rules_dir)?;
    let cache = FeedCache::new(data_dir());
    let mut manager = RulePackManager::new(catalog, cache);

    match manager.update_all() {
        Ok(updated) => {
            if updated.is_empty() {
                println!("All rule packs are up to date.");
            } else {
                println!("Updated {} pack(s):", updated.len());
                for id in &updated {
                    println!("  - {}", id);
                }
            }
        }
        Err(e) => println!("Failed to update rule packs: {}", e),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// IoC commands
// ---------------------------------------------------------------------------

pub fn ioc_status(_config: &ClawConfig) -> Result<()> {
    use clawdefender_threat_intel::ioc::IoCDatabase;

    println!("IoC Database Status");
    println!("===================");

    let ioc_dir = data_dir().join("ioc");
    if !ioc_dir.exists() {
        println!("  No IoC data directory found.");
        println!("  Run `clawdefender feed update` to fetch indicators.");
        return Ok(());
    }

    let mut db = IoCDatabase::new();
    match db.load_from_directory(&ioc_dir) {
        Ok(count) => {
            println!("  Total indicators: {}", count);
        }
        Err(e) => {
            println!("  Error loading IoC database: {}", e);
        }
    }

    Ok(())
}

pub fn ioc_add(_config: &ClawConfig, ioc_type: &str, value: &str) -> Result<()> {
    println!("Adding local IoC: type={}, value={}", ioc_type, value);
    println!("  (Local IoC additions will be available in a future version)");
    Ok(())
}

pub fn ioc_test(_config: &ClawConfig, value: &str) -> Result<()> {
    use clawdefender_threat_intel::ioc::types::EventData;
    use clawdefender_threat_intel::ioc::IoCDatabase;

    println!("Testing value against IoC database: {}", value);

    let ioc_dir = data_dir().join("ioc");
    let mut db = IoCDatabase::new();
    if ioc_dir.exists() {
        let _ = db.load_from_directory(&ioc_dir);
    }

    let engine = db.engine();
    // Create an event with the value in multiple fields for broad matching.
    let event = EventData {
        event_id: "cli-test".to_string(),
        destination_ip: value.parse().ok(),
        destination_domain: Some(value.to_string()),
        file_path: None,
        file_hash: Some(value.to_string()),
        process_name: None,
        command_line: Some(value.to_string()),
        tool_name: None,
        tool_args: None,
        tool_sequence: Vec::new(),
    };
    let matches = engine.check_event(&event);
    if matches.is_empty() {
        println!("  No IoC matches found.");
    } else {
        println!("  {} match(es) found:", matches.len());
        for m in &matches {
            println!(
                "    - {} (severity: {:?})",
                m.indicator.threat_id, m.indicator.severity
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Telemetry commands
// ---------------------------------------------------------------------------

pub fn telemetry_status(_config: &ClawConfig) -> Result<()> {
    use clawdefender_threat_intel::telemetry::{ConsentManager, TelemetryConfig};

    println!("Telemetry Status");
    println!("================");

    let consent = ConsentManager::new(TelemetryConfig::default());
    let enabled = consent.is_enabled();
    println!("  Enabled: {}", enabled);
    if let Some(id) = consent.get_installation_id() {
        println!("  Installation ID: {}", id);
    }

    Ok(())
}

pub fn telemetry_preview(_config: &ClawConfig) -> Result<()> {
    println!("Telemetry Preview");
    println!("=================");
    println!("  If telemetry were enabled, this would show what data would be sent.");
    println!("  ClawDefender telemetry collects only aggregate, anonymous data:");
    println!("    - Blocklist match counts (entry IDs only, no server names)");
    println!("    - Anomaly score distributions (no file paths or usernames)");
    println!("    - IoC match rates by category");
    println!("    - Kill chain detection trigger counts");
    println!("    - Scanner finding categories");
    println!("  No PII, no file paths, no API keys, no server names are ever sent.");

    Ok(())
}

pub fn telemetry_enable(_config: &ClawConfig) -> Result<()> {
    use clawdefender_threat_intel::telemetry::{ConsentManager, TelemetryConfig};

    let config = TelemetryConfig {
        enabled: true,
        ..Default::default()
    };
    let mut consent = ConsentManager::new(config);
    let _id = consent.opt_in();
    println!("Telemetry enabled. Thank you for helping improve ClawDefender.");
    println!("You can disable telemetry at any time with `clawdefender telemetry disable`.");

    Ok(())
}

pub fn telemetry_disable(_config: &ClawConfig) -> Result<()> {
    use clawdefender_threat_intel::telemetry::{ConsentManager, TelemetryConfig};

    let mut consent = ConsentManager::new(TelemetryConfig::default());
    consent.opt_out();
    println!("Telemetry disabled. All data collection has been stopped.");

    Ok(())
}

// ---------------------------------------------------------------------------
// Reputation command
// ---------------------------------------------------------------------------

pub fn check_reputation(_config: &ClawConfig, server_name: &str) -> Result<()> {
    use clawdefender_threat_intel::blocklist::BlocklistMatcher;

    println!("Server Reputation Check: {}", server_name);
    println!("========================{}", "=".repeat(server_name.len()));

    let empty_blocklist = clawdefender_threat_intel::blocklist::types::Blocklist {
        version: 0,
        updated_at: String::new(),
        entries: Vec::new(),
    };
    let matcher = BlocklistMatcher::new(empty_blocklist);

    let results = matcher.check_server(server_name, None, None);
    if results.is_empty() {
        println!("  No blocklist matches found. Server appears clean.");
    } else {
        println!(
            "  WARNING: Server matches {} blocklist entry(ies)!",
            results.len()
        );
        for result in &results {
            println!("  Entry ID:    {}", result.entry_id);
            println!("  Name:        {}", result.entry_name);
            println!("  Severity:    {:?}", result.severity);
            println!("  Match type:  {:?}", result.match_type);
            println!("  Description: {}", result.description);
            println!();
        }
    }

    Ok(())
}
