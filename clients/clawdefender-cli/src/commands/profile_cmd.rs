//! CLI commands for managing behavioral profiles.

use std::path::PathBuf;

use anyhow::Result;
use clawdefender_core::behavioral::ProfileStore;
use clawdefender_core::config::settings::ClawConfig;

/// List all behavioral profiles.
pub fn list(_config: &ClawConfig) -> Result<()> {
    let store = open_store()?;
    let profiles = store.load_all_profiles()?;

    if profiles.is_empty() {
        println!("No behavioral profiles found.");
        println!("Profiles are created automatically when MCP servers are observed.");
        return Ok(());
    }

    println!(
        "{:<30} {:<10} {:>8} {:>6} {:>6} {:>6}",
        "SERVER", "STATUS", "EVENTS", "TOOLS", "DIRS", "HOSTS"
    );
    println!("{}", "-".repeat(80));

    for p in &profiles {
        let status = if p.learning_mode { "learning" } else { "active" };
        println!(
            "{:<30} {:<10} {:>8} {:>6} {:>6} {:>6}",
            p.server_name,
            status,
            p.observation_count,
            p.tool_profile.tool_counts.len(),
            p.file_profile.directory_prefixes.len(),
            p.network_profile.observed_hosts.len(),
        );
    }

    println!();
    println!("{} profile(s) total", profiles.len());
    Ok(())
}

/// Show full details of a profile.
pub fn show(server: &str) -> Result<()> {
    let store = open_store()?;
    let profiles = store.load_all_profiles()?;
    let profile = profiles.iter().find(|p| p.server_name == server);

    let profile = match profile {
        Some(p) => p,
        None => {
            anyhow::bail!("Profile not found for server: {}", server);
        }
    };

    println!("Profile: {}", profile.server_name);
    println!("========{}", "=".repeat(profile.server_name.len()));
    println!();
    println!("  Client:       {}", profile.client_name);
    println!("  Status:       {}", if profile.learning_mode { "learning" } else { "active" });
    println!("  First seen:   {}", profile.first_seen.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Last updated: {}", profile.last_updated.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Observations: {}", profile.observation_count);

    // Tool profile
    println!();
    println!("  Tool Profile:");
    if profile.tool_profile.tool_counts.is_empty() {
        println!("    (no tools observed)");
    } else {
        let mut tools: Vec<_> = profile.tool_profile.tool_counts.iter().collect();
        tools.sort_by(|a, b| b.1.cmp(a.1));
        for (name, count) in tools.iter().take(20) {
            println!("    {:<30} {} calls", name, count);
        }
    }

    // File profile
    println!();
    println!("  File Profile:");
    println!("    Read ops:   {}", profile.file_profile.read_count);
    println!("    Write ops:  {}", profile.file_profile.write_count);
    if !profile.file_profile.directory_prefixes.is_empty() {
        println!("    Territory:");
        let mut dirs: Vec<_> = profile.file_profile.directory_prefixes.iter().collect();
        dirs.sort();
        for dir in dirs.iter().take(20) {
            println!("      {}", dir);
        }
        if dirs.len() > 20 {
            println!("      ... and {} more", dirs.len() - 20);
        }
    }
    if !profile.file_profile.extension_counts.is_empty() {
        println!("    Extensions:");
        let mut exts: Vec<_> = profile.file_profile.extension_counts.iter().collect();
        exts.sort_by(|a, b| b.1.cmp(a.1));
        for (ext, count) in exts.iter().take(10) {
            println!("      .{:<10} {} files", ext, count);
        }
    }

    // Network profile
    println!();
    println!("  Network Profile:");
    println!("    Has networked: {}", profile.network_profile.has_networked);
    if !profile.network_profile.observed_hosts.is_empty() {
        println!("    Known hosts:");
        for host in &profile.network_profile.observed_hosts {
            println!("      {}", host);
        }
    }
    if !profile.network_profile.observed_ports.is_empty() {
        let ports: Vec<String> = profile.network_profile.observed_ports.iter().map(|p| p.to_string()).collect();
        println!("    Known ports: {}", ports.join(", "));
    }

    // Temporal profile
    println!();
    println!("  Temporal Profile:");
    println!(
        "    Mean inter-request gap: {:.0}ms",
        profile.temporal_profile.inter_request_gap_mean_ms
    );
    println!(
        "    Gap stddev:             {:.0}ms",
        profile.temporal_profile.inter_request_gap_stddev_ms
    );
    println!("    Gap samples:            {}", profile.temporal_profile.gap_count);

    Ok(())
}

/// Reset a profile back to learning mode.
pub fn reset(server: &str) -> Result<()> {
    let store = open_store()?;

    // Check the profile exists
    let profiles = store.load_all_profiles()?;
    if !profiles.iter().any(|p| p.server_name == server) {
        anyhow::bail!("Profile not found for server: {}", server);
    }

    store.reset_profile(server)?;
    println!("Profile for '{}' has been reset to learning mode.", server);
    println!("The server will re-enter the learning phase on next observation.");
    Ok(())
}

/// Export a profile as JSON.
pub fn export(server: &str, file: &PathBuf) -> Result<()> {
    let store = open_store()?;
    let value = store.export_profile(server)?;

    match value {
        Some(json) => {
            let content = serde_json::to_string_pretty(&json)?;
            std::fs::write(file, &content)?;
            println!("Profile for '{}' exported to {}", server, file.display());
            Ok(())
        }
        None => {
            anyhow::bail!("Profile not found for server: {}", server);
        }
    }
}

fn open_store() -> Result<ProfileStore> {
    ProfileStore::open(&ProfileStore::default_path())
}
