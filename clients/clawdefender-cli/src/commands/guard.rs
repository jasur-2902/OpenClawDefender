//! `clawdefender guard` — manage agent guards.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result};
use clawdefender_core::config::ClawConfig;

/// List active guards.
pub fn list(config: &ClawConfig) -> Result<()> {
    let port = config.guard_api.port;
    let url = format!("http://127.0.0.1:{}/api/v1/guards", port);

    match ureq_get_json(&url) {
        Ok(json) => {
            if let Some(guards) = json.get("guards").and_then(|v| v.as_array()) {
                if guards.is_empty() {
                    println!("No active guards.");
                    return Ok(());
                }

                println!(
                    "  {:<36} {:<20} {:<8} {:<10} {:<8}",
                    "GUARD ID", "AGENT", "PID", "MODE", "CHECKS"
                );
                println!("  {}", "-".repeat(86));

                for guard in guards {
                    let id = guard.get("guard_id").and_then(|v| v.as_str()).unwrap_or("-");
                    let name = guard.get("agent_name").and_then(|v| v.as_str()).unwrap_or("-");
                    let pid = guard
                        .get("pid")
                        .and_then(|v| v.as_u64())
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let mode = guard.get("mode").and_then(|v| v.as_str()).unwrap_or("-");
                    let checks = guard
                        .get("checks_total")
                        .and_then(|v| v.as_u64())
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "0".to_string());

                    println!("  {:<36} {:<20} {:<8} {:<10} {:<8}", id, name, pid, mode, checks);
                }
                println!();
                println!("  {} guard(s) active", guards.len());
            } else {
                println!("No active guards.");
            }
        }
        Err(_) => {
            // Fall back to IPC health check
            println!("Guard API not reachable. Is the daemon running?");
            println!("  -> Start it with: clawdefender daemon start");
        }
    }

    Ok(())
}

/// Show details of a specific guard.
pub fn show(config: &ClawConfig, guard_id: &str) -> Result<()> {
    let port = config.guard_api.port;
    let url = format!("http://127.0.0.1:{}/api/v1/guard/{}", port, guard_id);

    match ureq_get_json(&url) {
        Ok(json) => {
            println!("Guard Details:");
            println!("  ID:          {}", json.get("guard_id").and_then(|v| v.as_str()).unwrap_or("-"));
            println!("  Agent:       {}", json.get("agent_name").and_then(|v| v.as_str()).unwrap_or("-"));
            println!("  PID:         {}", json.get("pid").and_then(|v| v.as_u64()).unwrap_or(0));
            println!("  Mode:        {}", json.get("mode").and_then(|v| v.as_str()).unwrap_or("-"));
            println!("  Status:      {}", json.get("status").and_then(|v| v.as_str()).unwrap_or("-"));
            println!("  Created:     {}", json.get("created_at").and_then(|v| v.as_str()).unwrap_or("-"));
            println!();
            println!("Statistics:");
            println!("  Total checks:   {}", json.get("checks_total").and_then(|v| v.as_u64()).unwrap_or(0));
            println!("  Allowed:        {}", json.get("checks_allowed").and_then(|v| v.as_u64()).unwrap_or(0));
            println!("  Blocked:        {}", json.get("checks_blocked").and_then(|v| v.as_u64()).unwrap_or(0));

            // Show stats details
            let stats_url = format!("http://127.0.0.1:{}/api/v1/guard/{}/stats", port, guard_id);
            if let Ok(stats) = ureq_get_json(&stats_url) {
                if let Some(rules) = stats.get("policy_rules").and_then(|v| v.as_array()) {
                    println!();
                    println!("Policy Rules:");
                    for rule in rules {
                        if let Some(r) = rule.as_str() {
                            println!("  - {}", r);
                        }
                    }
                }
                if let Some(blocked) = stats.get("blocked_operations").and_then(|v| v.as_array()) {
                    if !blocked.is_empty() {
                        println!();
                        println!("Recent Blocked Operations:");
                        for op in blocked.iter().take(10) {
                            let action = op.get("action").and_then(|v| v.as_str()).unwrap_or("-");
                            let target = op.get("target").and_then(|v| v.as_str()).unwrap_or("-");
                            let reason = op.get("reason").and_then(|v| v.as_str()).unwrap_or("-");
                            println!("  {} {} -> {}", action, target, reason);
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to get guard details: {}", e);
            eprintln!("Is the daemon running with the guard API enabled?");
        }
    }

    Ok(())
}

/// Forcefully remove a guard.
pub fn kill(config: &ClawConfig, guard_id: &str) -> Result<()> {
    let port = config.guard_api.port;
    let url = format!("http://127.0.0.1:{}/api/v1/guard/{}", port, guard_id);

    match ureq_delete_json(&url) {
        Ok(json) => {
            let status = json.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
            println!("Guard {}: {}", guard_id, status);
        }
        Err(e) => {
            eprintln!("Failed to kill guard: {}", e);
            eprintln!("Is the daemon running with the guard API enabled?");
        }
    }

    Ok(())
}

/// Test a guard permissions config file.
pub fn test(_config: &ClawConfig, file: &str) -> Result<()> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("reading permissions file: {}", file))?;

    // Try to parse as TOML guard config.
    let parsed: serde_json::Value = if file.ends_with(".toml") {
        let toml_val: toml::Value =
            toml::from_str(&content).with_context(|| "parsing TOML permissions file")?;
        // Convert TOML to JSON for display.
        serde_json::to_value(toml_val)?
    } else {
        serde_json::from_str(&content).with_context(|| "parsing JSON permissions file")?
    };

    println!("Permissions Config Test");
    println!("  File: {}", file);
    println!();

    // Display parsed permissions.
    if let Some(perms) = parsed.get("permissions") {
        println!("Parsed Permissions:");
        println!(
            "{}",
            serde_json::to_string_pretty(perms).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Parsed Config:");
        println!(
            "{}",
            serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| "{}".to_string())
        );
    }

    println!();
    println!("Config is valid.");

    Ok(())
}

/// Send a JSON message to the daemon via IPC and return the response.
#[allow(dead_code)]
fn send_guard_ipc(socket_path: &Path, request: &serde_json::Value) -> Result<serde_json::Value> {
    let mut stream =
        UnixStream::connect(socket_path).context("connecting to daemon IPC socket")?;

    let msg = serde_json::to_string(request)? + "\n";
    stream.write_all(msg.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;

    let value: serde_json::Value =
        serde_json::from_str(response.trim()).context("parsing IPC response")?;
    Ok(value)
}

/// Simple HTTP GET that returns JSON (no external deps needed for localhost).
fn ureq_get_json(url: &str) -> Result<serde_json::Value> {
    use std::io::Read;
    use std::net::TcpStream;

    let url_parsed: Vec<&str> = url
        .strip_prefix("http://")
        .unwrap_or(url)
        .splitn(2, '/')
        .collect();

    let host = url_parsed[0];
    let path = if url_parsed.len() > 1 {
        format!("/{}", url_parsed[1])
    } else {
        "/".to_string()
    };

    let mut stream = TcpStream::connect(host).context("connecting to guard API")?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    // Parse HTTP response body (after headers).
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("");

    serde_json::from_str(body).context("parsing guard API response")
}

/// Simple HTTP DELETE that returns JSON.
fn ureq_delete_json(url: &str) -> Result<serde_json::Value> {
    use std::io::Read;
    use std::net::TcpStream;

    let url_parsed: Vec<&str> = url
        .strip_prefix("http://")
        .unwrap_or(url)
        .splitn(2, '/')
        .collect();

    let host = url_parsed[0];
    let path = if url_parsed.len() > 1 {
        format!("/{}", url_parsed[1])
    } else {
        "/".to_string()
    };

    let mut stream = TcpStream::connect(host).context("connecting to guard API")?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    let request = format!(
        "DELETE {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("");

    serde_json::from_str(body).context("parsing guard API response")
}
