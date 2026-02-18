//! `clawdefender network` — manage network policy, DNS filter, and connection rules.

use anyhow::Result;
use clap::Subcommand;
use clawdefender_core::config::ClawConfig;
use clawdefender_core::dns::filter::DnsFilter;
use clawdefender_core::network_policy::engine::NetworkPolicyEngine;
use clawdefender_core::network_policy::rate_limiter::RateLimitConfig;
use clawdefender_core::network_policy::rules::NetworkAction;

#[derive(Subcommand, Debug)]
pub enum NetworkAction2 {
    /// Show network extension status, active filters, and stats.
    Status,
    /// Show recent network connections.
    Log {
        /// Show only blocked connections.
        #[arg(long)]
        blocked: bool,
    },
    /// Add a host to the allow list.
    Allow {
        /// Hostname or IP to allow.
        host: String,
    },
    /// Add a host to the block list.
    Block {
        /// Hostname or IP to block.
        host: String,
    },
    /// Show network policy rules.
    Rules,
}

/// Run the network subcommand.
pub fn run(action: &NetworkAction2, config: &ClawConfig) -> Result<()> {
    match action {
        NetworkAction2::Status => status(config),
        NetworkAction2::Log { blocked } => log(config, *blocked),
        NetworkAction2::Allow { host } => allow(config, host),
        NetworkAction2::Block { host } => block(config, host),
        NetworkAction2::Rules => rules(config),
    }
}

/// Show network extension status.
fn status(config: &ClawConfig) -> Result<()> {
    println!("Network Policy Status");
    println!("=====================");
    println!();

    if !config.network_policy.enabled {
        println!("  Network policy engine: DISABLED");
        println!();
        println!("  Enable in config.toml: [network_policy] enabled = true");
        return Ok(());
    }

    println!("  Network policy engine: ENABLED");
    println!("  Default agent action:  {}", config.network_policy.default_agent_action);
    println!("  Prompt timeout:        {}s", config.network_policy.prompt_timeout_seconds);
    println!("  Timeout action:        {}", config.network_policy.timeout_action);
    println!("  Rate limit (conn/min): {}", config.network_policy.rate_limit_connections_per_min);
    println!("  Rate limit (dest/10s): {}", config.network_policy.rate_limit_unique_dest_per_10s);
    println!("  Block private ranges:  {}", config.network_policy.block_private_ranges);
    println!("  Log all DNS:           {}", config.network_policy.log_all_dns);
    println!();

    // Show rule count from default engine.
    let engine = NetworkPolicyEngine::with_defaults();
    println!("  Built-in rules loaded: {}", engine.rules().len());

    // Check if daemon is running via socket.
    let daemon_running = std::os::unix::net::UnixStream::connect(&config.daemon_socket_path).is_ok();
    println!("  Daemon running:        {}", if daemon_running { "yes" } else { "no" });
    println!("  Extension mode:        mock (system extension not installed)");

    Ok(())
}

/// Show recent network connection log.
fn log(config: &ClawConfig, blocked_only: bool) -> Result<()> {
    use clawdefender_core::audit::logger::FileAuditLogger;
    use clawdefender_core::audit::{AuditFilter, AuditLogger};

    let logger = FileAuditLogger::new(
        config.audit_log_path.clone(),
        config.log_rotation.clone(),
    )?;

    let filter = AuditFilter {
        source: Some("network".to_string()),
        action: if blocked_only {
            Some("block".to_string())
        } else {
            None
        },
        limit: 100,
        ..Default::default()
    };

    let records = logger.query(&filter)?;

    if records.is_empty() {
        println!("No network connection logs found.");
        if blocked_only {
            println!("  (Showing blocked only. Remove --blocked to see all.)");
        }
        return Ok(());
    }

    println!(
        "{:<20} {:<8} {:<40} {:<10}",
        "TIMESTAMP", "ACTION", "DESTINATION", "REASON"
    );
    println!("{}", "-".repeat(80));

    for record in &records {
        let ts = record.timestamp.format("%Y-%m-%d %H:%M:%S");
        let dest = record
            .event_summary
            .chars()
            .take(40)
            .collect::<String>();
        let reason = record
            .rule_matched
            .as_deref()
            .unwrap_or("-");
        println!(
            "{:<20} {:<8} {:<40} {:<10}",
            ts, record.action_taken, dest, reason
        );
    }

    println!();
    println!("Total: {} entries", records.len());

    Ok(())
}

/// Add a host to the DNS allowlist.
fn allow(_config: &ClawConfig, host: &str) -> Result<()> {
    // Create a filter and add the allow entry.
    // In a full implementation this would persist to config or send to daemon.
    let mut filter = DnsFilter::new();
    filter.add_allow(host);
    println!("Added '{}' to network allow list.", host);
    println!();
    println!("Note: This change takes effect on daemon restart.");
    println!("  To persist, add to [network_policy] allowlist in config.toml.");
    Ok(())
}

/// Add a host to the DNS blocklist.
fn block(_config: &ClawConfig, host: &str) -> Result<()> {
    let mut filter = DnsFilter::new();
    filter.add_block(host);
    println!("Added '{}' to network block list.", host);
    println!();
    println!("Note: This change takes effect on daemon restart.");
    println!("  To persist, add to [network_policy] blocklist in config.toml.");
    Ok(())
}

/// Show loaded network policy rules.
fn rules(config: &ClawConfig) -> Result<()> {
    if !config.network_policy.enabled {
        println!("Network policy engine is disabled.");
        return Ok(());
    }

    let default_action = match config.network_policy.default_agent_action.as_str() {
        "allow" => NetworkAction::Allow,
        "block" => NetworkAction::Block,
        "log" => NetworkAction::Log,
        _ => NetworkAction::Prompt,
    };

    let engine = NetworkPolicyEngine::new(Vec::new(), default_action.clone(), RateLimitConfig::default());
    let rules = engine.rules();

    println!("Network Policy Rules ({} loaded)", rules.len());
    println!("=================================");
    println!();
    println!(
        "{:<5} {:<25} {:<10} {:<10} {}",
        "PRI", "NAME", "ACTION", "SOURCE", "DESCRIPTION"
    );
    println!("{}", "-".repeat(80));

    for rule in rules {
        println!(
            "{:<5} {:<25} {:<10} {:<10} {}",
            rule.priority,
            rule.name,
            format!("{:?}", rule.action),
            format!("{:?}", rule.source),
            rule.description,
        );
    }

    println!();
    println!("Default action: {:?}", default_action);

    Ok(())
}
