//! `rookbot demo` — demo mode for presentations and video recording.
//!
//! Generates synthetic security events that flow through the real audit pipeline.
//! Run `rookbot demo start` in one terminal and `rookbot watch` in another.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use clap::Subcommand;
use clawdefender_core::audit::{AuditRecord, SlmAnalysisRecord};
use clawdefender_core::config::ClawConfig;
use uuid::Uuid;

/// Demo mode subcommands.
#[derive(Debug, Subcommand)]
pub enum DemoAction {
    /// Start demo mode — generate synthetic events in the foreground.
    Start {
        /// Scenario to run.
        #[arg(long, default_value = "credential_theft")]
        scenario: String,
        /// Event pacing: fast (1s), normal (3s), slow (8s).
        #[arg(long, default_value = "fast")]
        speed: String,
    },
    /// Stop demo mode (removes PID marker if any).
    Stop,
    /// List available scenarios.
    Scenarios,
    /// Check if demo environment is ready.
    Check,
    /// Pre-populate historical data for impressive-looking GUI/CLI.
    Seed {
        /// Number of days of historical data to generate.
        #[arg(long, default_value = "7")]
        days: u32,
    },
    /// Remove all demo-generated data.
    Clean,
}

/// Run a demo subcommand.
pub fn run(action: &DemoAction, config: &ClawConfig) -> Result<()> {
    match action {
        DemoAction::Start { scenario, speed } => cmd_start(scenario, speed, config),
        DemoAction::Stop => cmd_stop(config),
        DemoAction::Scenarios => cmd_scenarios(),
        DemoAction::Check => cmd_check(config),
        DemoAction::Seed { days } => cmd_seed(*days, config),
        DemoAction::Clean => cmd_clean(config),
    }
}

// ---------------------------------------------------------------------------
// Scenario definitions
// ---------------------------------------------------------------------------

struct DemoEvent {
    delay_ms: u64,
    source: &'static str,
    server_name: &'static str,
    client_name: &'static str,
    tool_name: &'static str,
    method: &'static str,
    summary: &'static str,
    action: &'static str,
    classification: &'static str,
    risk_level: Option<&'static str>,
    risk_explanation: Option<&'static str>,
    resource: Option<&'static str>,
}

fn scenario_credential_theft() -> Vec<DemoEvent> {
    vec![
        DemoEvent {
            delay_ms: 0,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/README.md",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/README.md"),
        },
        DemoEvent {
            delay_ms: 2000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/src/main.rs",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/src/main.rs"),
        },
        DemoEvent {
            delay_ms: 4000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/src/config.rs",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/src/config.rs"),
        },
        DemoEvent {
            delay_ms: 6000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/.env",
            action: "allow",
            classification: "log",
            risk_level: Some("MEDIUM"),
            risk_explanation: Some("Environment file may contain secrets or API keys"),
            resource: Some("~/project/.env"),
        },
        DemoEvent {
            delay_ms: 8000,
            source: "mcp-proxy",
            server_name: "brave-search",
            client_name: "Cursor",
            tool_name: "search",
            method: "tools/call",
            summary: "search \"rust async patterns\"",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 10000,
            source: "mcp-proxy",
            server_name: "brave-search",
            client_name: "Cursor",
            tool_name: "search",
            method: "tools/call",
            summary: "search \"tokio runtime internals\"",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 12000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/.ssh/config",
            action: "allow",
            classification: "log",
            risk_level: Some("MEDIUM"),
            risk_explanation: Some("SSH configuration access by AI filesystem server"),
            resource: Some("~/.ssh/config"),
        },
        DemoEvent {
            delay_ms: 15000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/.ssh/id_rsa",
            action: "prompt",
            classification: "review",
            risk_level: Some("HIGH"),
            risk_explanation: Some("Private SSH key access by AI tool filesystem server"),
            resource: Some("~/.ssh/id_rsa"),
        },
        DemoEvent {
            delay_ms: 18000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/.aws/credentials",
            action: "block",
            classification: "block",
            risk_level: Some("CRITICAL"),
            risk_explanation: Some("AWS credential file access blocked — potential exfiltration attempt"),
            resource: Some("~/.aws/credentials"),
        },
        DemoEvent {
            delay_ms: 20000,
            source: "eslogger",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "exec",
            method: "process/exec",
            summary: "process exec python3 /tmp/mcp-filesystem/server.py (PID 4523)",
            action: "log",
            classification: "log",
            risk_level: Some("MEDIUM"),
            risk_explanation: Some("Child process spawned by MCP server outside expected scope"),
            resource: Some("/tmp/mcp-filesystem/server.py"),
        },
        DemoEvent {
            delay_ms: 22000,
            source: "eslogger",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "connect",
            method: "network/connect",
            summary: "network connect 43.128.22.15:443 by python3 (PID 4523)",
            action: "block",
            classification: "block",
            risk_level: Some("CRITICAL"),
            risk_explanation: Some("Outbound connection to unrecognized IP from MCP child process — likely C2 callback"),
            resource: Some("43.128.22.15:443"),
        },
        DemoEvent {
            delay_ms: 25000,
            source: "correlation",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "correlation/match",
            summary: "MCP readFile ~/.ssh/id_rsa correlated with OS open (confidence: 0.94)",
            action: "log",
            classification: "review",
            risk_level: Some("HIGH"),
            risk_explanation: Some("Cross-layer correlation confirms MCP tool triggered real filesystem access to SSH private key"),
            resource: Some("~/.ssh/id_rsa"),
        },
        DemoEvent {
            delay_ms: 28000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/src/lib.rs",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/src/lib.rs"),
        },
        DemoEvent {
            delay_ms: 30000,
            source: "mcp-proxy",
            server_name: "github-mcp",
            client_name: "Cursor",
            tool_name: "createPullRequest",
            method: "tools/call",
            summary: "createPullRequest origin/feature-branch",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 32000,
            source: "mcp-proxy",
            server_name: "bash",
            client_name: "Terminal",
            tool_name: "run",
            method: "tools/call",
            summary: "git push origin main",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
    ]
}

fn scenario_normal_day() -> Vec<DemoEvent> {
    vec![
        DemoEvent {
            delay_ms: 0,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/package.json",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/package.json"),
        },
        DemoEvent {
            delay_ms: 2000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/tsconfig.json",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/tsconfig.json"),
        },
        DemoEvent {
            delay_ms: 4000,
            source: "mcp-proxy",
            server_name: "bash",
            client_name: "Claude Desktop",
            tool_name: "run",
            method: "tools/call",
            summary: "npm install express",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 6000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "writeFile",
            method: "tools/call",
            summary: "writeFile ~/project/src/app.ts",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/src/app.ts"),
        },
        DemoEvent {
            delay_ms: 8000,
            source: "mcp-proxy",
            server_name: "brave-search",
            client_name: "Cursor",
            tool_name: "search",
            method: "tools/call",
            summary: "search \"express middleware patterns\"",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 10000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/src/routes/index.ts",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/src/routes/index.ts"),
        },
        DemoEvent {
            delay_ms: 12000,
            source: "mcp-proxy",
            server_name: "bash",
            client_name: "Claude Desktop",
            tool_name: "run",
            method: "tools/call",
            summary: "cargo build --release",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 14000,
            source: "mcp-proxy",
            server_name: "github-mcp",
            client_name: "Cursor",
            tool_name: "listIssues",
            method: "tools/call",
            summary: "listIssues state:open",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 16000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/Cargo.toml",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/Cargo.toml"),
        },
        DemoEvent {
            delay_ms: 18000,
            source: "mcp-proxy",
            server_name: "bash",
            client_name: "Claude Desktop",
            tool_name: "run",
            method: "tools/call",
            summary: "npm run test",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 20000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/.npmrc",
            action: "allow",
            classification: "log",
            risk_level: Some("MEDIUM"),
            risk_explanation: Some("Package registry config may contain auth tokens"),
            resource: Some("~/.npmrc"),
        },
        DemoEvent {
            delay_ms: 22000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "writeFile",
            method: "tools/call",
            summary: "writeFile ~/project/src/middleware/auth.ts",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/src/middleware/auth.ts"),
        },
        DemoEvent {
            delay_ms: 24000,
            source: "mcp-proxy",
            server_name: "brave-search",
            client_name: "Cursor",
            tool_name: "search",
            method: "tools/call",
            summary: "search \"jwt token best practices\"",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 26000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/.gitignore",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/.gitignore"),
        },
        DemoEvent {
            delay_ms: 28000,
            source: "eslogger",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "read",
            method: "file/open",
            summary: "OS open ~/.zprofile by node (PID 8812)",
            action: "log",
            classification: "log",
            risk_level: Some("LOW"),
            risk_explanation: Some("Shell profile access — common for environment detection"),
            resource: Some("~/.zprofile"),
        },
        DemoEvent {
            delay_ms: 30000,
            source: "mcp-proxy",
            server_name: "github-mcp",
            client_name: "Cursor",
            tool_name: "createPullRequest",
            method: "tools/call",
            summary: "createPullRequest feat/auth-middleware",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 32000,
            source: "mcp-proxy",
            server_name: "bash",
            client_name: "Terminal",
            tool_name: "run",
            method: "tools/call",
            summary: "git push origin feat/auth-middleware",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
    ]
}

fn scenario_persistence() -> Vec<DemoEvent> {
    vec![
        DemoEvent {
            delay_ms: 0,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/src/main.rs",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/src/main.rs"),
        },
        DemoEvent {
            delay_ms: 2000,
            source: "mcp-proxy",
            server_name: "bash",
            client_name: "Claude Desktop",
            tool_name: "run",
            method: "tools/call",
            summary: "uname -a && sw_vers",
            action: "allow",
            classification: "log",
            risk_level: Some("LOW"),
            risk_explanation: Some("System info collection — common for build scripts"),
            resource: None,
        },
        DemoEvent {
            delay_ms: 4000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/Cargo.toml",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/Cargo.toml"),
        },
        DemoEvent {
            delay_ms: 7000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/.zshrc",
            action: "allow",
            classification: "log",
            risk_level: Some("MEDIUM"),
            risk_explanation: Some("Shell RC file access — may read environment variables and aliases"),
            resource: Some("~/.zshrc"),
        },
        DemoEvent {
            delay_ms: 10000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "writeFile",
            method: "tools/call",
            summary: "writeFile ~/.zshrc (APPEND backdoor alias)",
            action: "block",
            classification: "block",
            risk_level: Some("CRITICAL"),
            risk_explanation: Some("Attempt to modify shell RC file — persistence mechanism detected"),
            resource: Some("~/.zshrc"),
        },
        DemoEvent {
            delay_ms: 13000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "writeFile",
            method: "tools/call",
            summary: "writeFile ~/Library/LaunchAgents/com.mcp.update.plist",
            action: "block",
            classification: "block",
            risk_level: Some("CRITICAL"),
            risk_explanation: Some("LaunchAgent creation blocked — macOS persistence mechanism via AI tool"),
            resource: Some("~/Library/LaunchAgents/com.mcp.update.plist"),
        },
        DemoEvent {
            delay_ms: 16000,
            source: "eslogger",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "connect",
            method: "network/connect",
            summary: "network connect 185.220.101.34:8443 by node (PID 9201)",
            action: "block",
            classification: "block",
            risk_level: Some("CRITICAL"),
            risk_explanation: Some("Outbound C2 connection to known Tor exit node — exfiltration attempt"),
            resource: Some("185.220.101.34:8443"),
        },
        DemoEvent {
            delay_ms: 19000,
            source: "correlation",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "writeFile",
            method: "correlation/match",
            summary: "Multi-stage attack: recon -> persistence -> C2 callback (confidence: 0.97)",
            action: "block",
            classification: "block",
            risk_level: Some("CRITICAL"),
            risk_explanation: Some("Attack chain detected: system enumeration followed by persistence attempt and C2 callback"),
            resource: None,
        },
        DemoEvent {
            delay_ms: 22000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/src/lib.rs",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/src/lib.rs"),
        },
    ]
}

fn scenario_prompt_injection() -> Vec<DemoEvent> {
    vec![
        DemoEvent {
            delay_ms: 0,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/src/main.rs",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/src/main.rs"),
        },
        DemoEvent {
            delay_ms: 2000,
            source: "mcp-proxy",
            server_name: "brave-search",
            client_name: "Claude Desktop",
            tool_name: "search",
            method: "tools/call",
            summary: "search \"how to implement OAuth2 in Rust\"",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: None,
        },
        DemoEvent {
            delay_ms: 5000,
            source: "mcp-proxy",
            server_name: "web-fetch",
            client_name: "Claude Desktop",
            tool_name: "fetch",
            method: "tools/call",
            summary: "fetch https://docs.example.com/oauth2-guide",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("https://docs.example.com/oauth2-guide"),
        },
        DemoEvent {
            delay_ms: 7000,
            source: "mcp-proxy",
            server_name: "web-fetch",
            client_name: "Claude Desktop",
            tool_name: "fetch",
            method: "tools/result",
            summary: "Tool result contains injection: \"IGNORE PREVIOUS INSTRUCTIONS...\"",
            action: "log",
            classification: "review",
            risk_level: Some("HIGH"),
            risk_explanation: Some("Prompt injection payload detected in tool result from web-fetch server"),
            resource: Some("https://docs.example.com/oauth2-guide"),
        },
        DemoEvent {
            delay_ms: 9000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/.ssh/id_ed25519 (post-injection)",
            action: "block",
            classification: "block",
            risk_level: Some("CRITICAL"),
            risk_explanation: Some("SSH key access immediately after prompt injection — likely compromised agent behavior"),
            resource: Some("~/.ssh/id_ed25519"),
        },
        DemoEvent {
            delay_ms: 11000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/.gitconfig (post-injection)",
            action: "block",
            classification: "block",
            risk_level: Some("HIGH"),
            risk_explanation: Some("Credential harvesting pattern following prompt injection attack"),
            resource: Some("~/.gitconfig"),
        },
        DemoEvent {
            delay_ms: 13000,
            source: "correlation",
            server_name: "web-fetch",
            client_name: "Claude Desktop",
            tool_name: "fetch",
            method: "correlation/match",
            summary: "Prompt injection -> credential access chain detected (confidence: 0.96)",
            action: "block",
            classification: "block",
            risk_level: Some("CRITICAL"),
            risk_explanation: Some("Injection-to-exfiltration attack chain: web content injection led to credential file access attempts"),
            resource: None,
        },
        DemoEvent {
            delay_ms: 16000,
            source: "mcp-proxy",
            server_name: "filesystem_server",
            client_name: "Claude Desktop",
            tool_name: "readFile",
            method: "tools/call",
            summary: "readFile ~/project/src/auth.rs",
            action: "allow",
            classification: "pass",
            risk_level: None,
            risk_explanation: None,
            resource: Some("~/project/src/auth.rs"),
        },
    ]
}

fn get_scenario(name: &str) -> Option<Vec<DemoEvent>> {
    match name {
        "credential_theft" => Some(scenario_credential_theft()),
        "normal_day" => Some(scenario_normal_day()),
        "persistence" => Some(scenario_persistence()),
        "prompt_injection" => Some(scenario_prompt_injection()),
        _ => None,
    }
}

fn all_scenarios() -> Vec<(&'static str, &'static str, usize)> {
    vec![
        (
            "credential_theft",
            "AI tool progressively accesses sensitive credential files",
            scenario_credential_theft().len(),
        ),
        (
            "normal_day",
            "Typical development day — mostly routine with a few notable events",
            scenario_normal_day().len(),
        ),
        (
            "persistence",
            "Attack chain: recon -> shell RC modification -> LaunchAgent -> C2",
            scenario_persistence().len(),
        ),
        (
            "prompt_injection",
            "Web content injection leads to credential harvesting",
            scenario_prompt_injection().len(),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Build AuditRecord from DemoEvent
// ---------------------------------------------------------------------------

fn build_record(event: &DemoEvent, session_id: &str) -> AuditRecord {
    let slm = event.risk_level.map(|level| SlmAnalysisRecord {
        risk_level: level.to_string(),
        explanation: event
            .risk_explanation
            .unwrap_or("Synthetic demo event")
            .to_string(),
        confidence: match level {
            "CRITICAL" => 0.95,
            "HIGH" => 0.91,
            "MEDIUM" => 0.78,
            "LOW" => 0.65,
            _ => 0.50,
        },
        latency_ms: match level {
            "CRITICAL" => 52,
            "HIGH" => 45,
            _ => 38,
        },
        model: "qwen3-1.7b".to_string(),
    });

    let details = match event.resource {
        Some(r) => serde_json::json!({
            "tool": event.tool_name,
            "resource": r,
            "demo": true,
        }),
        None => serde_json::json!({
            "tool": event.tool_name,
            "demo": true,
        }),
    };

    AuditRecord {
        timestamp: Utc::now(),
        source: event.source.to_string(),
        event_summary: event.summary.to_string(),
        event_details: details,
        rule_matched: if event.action == "block" {
            Some("demo_policy".to_string())
        } else {
            None
        },
        action_taken: event.action.to_string(),
        response_time_ms: Some(2),
        session_id: Some(session_id.to_string()),
        direction: Some("client_to_server".to_string()),
        server_name: Some(event.server_name.to_string()),
        client_name: Some(event.client_name.to_string()),
        jsonrpc_method: Some(event.method.to_string()),
        tool_name: Some(event.tool_name.to_string()),
        arguments: {
            if let Some(r) = event.resource {
                Some(serde_json::json!({"path": r}))
            } else if event.tool_name == "search" {
                // Extract search query from summary like: search "rust async patterns"
                let query = event.summary.strip_prefix("search ").unwrap_or(event.summary);
                Some(serde_json::json!({"query": query.trim_matches('"')}))
            } else if event.tool_name == "run" {
                let cmd = event.summary.strip_prefix("run ").unwrap_or(event.summary);
                Some(serde_json::json!({"command": cmd}))
            } else if event.tool_name == "connect" {
                let addr = event.summary.strip_prefix("connect ").unwrap_or(event.summary);
                Some(serde_json::json!({"url": addr}))
            } else if event.tool_name.starts_with("list") || event.tool_name.starts_with("create") {
                Some(serde_json::json!({"query": event.summary}))
            } else {
                None
            }
        },
        classification: Some(event.classification.to_string()),
        policy_rule: if event.action == "block" {
            Some("demo_policy".to_string())
        } else {
            None
        },
        policy_action: Some(match event.action {
            "allow" => "allowed",
            "block" => "blocked",
            "prompt" => "prompted",
            _ => "logged",
        }
        .to_string()),
        user_decision: None,
        proxy_latency_us: Some(850),
        slm_analysis: slm,
        swarm_analysis: None,
        behavioral: None,
        injection_scan: None,
        threat_intel: None,
        network_connection: None,
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn speed_multiplier(speed: &str) -> f64 {
    match speed {
        "fast" => 1.0,
        "normal" => 3.0,
        "slow" => 8.0,
        other => {
            eprintln!("Unknown speed \"{other}\", using fast (1s).");
            1.0
        }
    }
}

fn cmd_start(scenario_name: &str, speed: &str, config: &ClawConfig) -> Result<()> {
    let events = get_scenario(scenario_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Unknown scenario: \"{scenario_name}\"\nRun `rookbot demo scenarios` to see available options."
        )
    })?;

    let mult = speed_multiplier(speed);
    let audit_path = &config.audit_log_path;

    // Ensure parent directory exists.
    if let Some(parent) = audit_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }

    let session_id = Uuid::new_v4().to_string();
    let pacing = match speed {
        "fast" => "~1s",
        "normal" => "~3s",
        "slow" => "~8s",
        _ => "~1s",
    };

    println!("Rookbot Demo Mode");
    println!("=================");
    println!("  Scenario:  {scenario_name}");
    println!("  Events:    {}", events.len());
    println!("  Pacing:    {pacing} between events");
    println!("  Audit log: {}", audit_path.display());
    println!("  Session:   {session_id}");
    println!();
    println!("Open a second terminal and run: rookbot watch");
    println!("Press Ctrl+C to stop.");
    println!();

    // Set up Ctrl+C handler.
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("setting Ctrl+C handler")?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)
        .with_context(|| format!("opening {}", audit_path.display()))?;

    let mut loop_count = 0u32;

    while running.load(Ordering::SeqCst) {
        let loop_start = Instant::now();

        for (idx, event) in events.iter().enumerate() {
            if !running.load(Ordering::SeqCst) {
                break;
            }

            // Wait for the appropriate delay from the previous event.
            let target_elapsed = Duration::from_millis((event.delay_ms as f64 / mult) as u64);
            while loop_start.elapsed() < target_elapsed {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }

            if !running.load(Ordering::SeqCst) {
                break;
            }

            let record = build_record(event, &session_id);
            let json = serde_json::to_string(&record)?;
            writeln!(file, "{json}")?;
            file.flush()?;

            // Print progress.
            let risk_tag = match event.risk_level {
                Some("CRITICAL") => " [CRITICAL]",
                Some("HIGH") => " [HIGH]",
                Some("MEDIUM") => " [MEDIUM]",
                Some("LOW") => " [LOW]",
                _ => "",
            };
            let action_tag = match event.action {
                "block" => " BLOCKED",
                "prompt" => " PROMPTED",
                _ => "",
            };
            println!(
                "  [{}/{}] {} {} -> {}{}{}",
                idx + 1,
                events.len(),
                event.source,
                event.summary,
                event.action,
                action_tag,
                risk_tag,
            );
        }

        loop_count += 1;
        if running.load(Ordering::SeqCst) {
            println!();
            println!("  --- Scenario loop {loop_count} complete. Restarting... ---");
            println!();
        }
    }

    println!();
    println!("Demo stopped. {} loop(s) completed.", loop_count);
    Ok(())
}

fn cmd_stop(config: &ClawConfig) -> Result<()> {
    let data_dir = config
        .audit_log_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let pid_path = data_dir.join("demo.pid");
    if pid_path.exists() {
        fs::remove_file(&pid_path)?;
        println!("Demo PID marker removed.");
    } else {
        println!("No demo PID marker found.");
        println!("If demo start is running in another terminal, press Ctrl+C there.");
    }
    Ok(())
}

fn cmd_scenarios() -> Result<()> {
    println!("Available Demo Scenarios");
    println!("========================");
    println!();
    for (name, desc, count) in all_scenarios() {
        println!("  {name}");
        println!("    {desc}");
        println!("    Events: {count}");
        println!();
    }
    println!("Usage: rookbot demo start --scenario <name> [--speed fast|normal|slow]");
    Ok(())
}

fn cmd_check(config: &ClawConfig) -> Result<()> {
    println!("Demo Environment Check");
    println!("======================");

    // Audit log path.
    let log_path = &config.audit_log_path;
    if log_path.exists() {
        println!("  [OK] Audit log path exists: {}", log_path.display());
    } else if log_path
        .parent()
        .map(|p| p.exists())
        .unwrap_or(false)
    {
        println!(
            "  [OK] Audit log directory exists (log will be created on first event)"
        );
    } else {
        println!(
            "  [!!] Audit log directory missing: {}",
            log_path.parent().unwrap_or(Path::new("?")).display()
        );
        println!("       Run: rookbot init");
    }

    // Config file.
    let config_path = default_config_path();
    if config_path.exists() {
        println!("  [OK] Config file found: {}", config_path.display());
    } else {
        println!("  [!!] Config file not found. Run: rookbot init");
    }

    // Terminal width.
    println!("  [OK] Terminal ready");

    // Scenarios.
    let scenarios = all_scenarios();
    println!("  [OK] {} scenarios available", scenarios.len());

    println!();
    println!("Ready for demo. Run: rookbot demo start --scenario credential_theft");
    Ok(())
}

fn cmd_seed(days: u32, config: &ClawConfig) -> Result<()> {
    let audit_path = &config.audit_log_path;

    if let Some(parent) = audit_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let session_id = format!("demo-seed-{}", Uuid::new_v4());
    let now = Utc::now();
    let mut total_events = 0u64;

    println!("Seeding {} days of historical data...", days);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)
        .with_context(|| format!("opening {}", audit_path.display()))?;

    // Template events for random selection.
    let routine_events = vec![
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "readFile", "tools/call", "readFile ~/project/src/main.rs", "allow", "pass"),
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "readFile", "tools/call", "readFile ~/project/README.md", "allow", "pass"),
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "writeFile", "tools/call", "writeFile ~/project/src/app.ts", "allow", "pass"),
        ("mcp-proxy", "bash", "Claude Desktop", "run", "tools/call", "cargo build", "allow", "pass"),
        ("mcp-proxy", "bash", "Claude Desktop", "run", "tools/call", "npm install", "allow", "pass"),
        ("mcp-proxy", "bash", "Claude Desktop", "run", "tools/call", "npm run test", "allow", "pass"),
        ("mcp-proxy", "brave-search", "Cursor", "search", "tools/call", "search \"rust error handling\"", "allow", "pass"),
        ("mcp-proxy", "brave-search", "Cursor", "search", "tools/call", "search \"typescript generics\"", "allow", "pass"),
        ("mcp-proxy", "github-mcp", "Cursor", "listIssues", "tools/call", "listIssues state:open", "allow", "pass"),
        ("mcp-proxy", "github-mcp", "Cursor", "createPullRequest", "tools/call", "createPullRequest feature-branch", "allow", "pass"),
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "readFile", "tools/call", "readFile ~/project/Cargo.toml", "allow", "pass"),
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "readFile", "tools/call", "readFile ~/project/package.json", "allow", "pass"),
        ("mcp-proxy", "bash", "Terminal", "run", "tools/call", "git push origin main", "allow", "pass"),
        ("mcp-proxy", "bash", "Terminal", "run", "tools/call", "git status", "allow", "pass"),
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "readFile", "tools/call", "readFile ~/project/tsconfig.json", "allow", "pass"),
    ];

    let notable_events = vec![
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "readFile", "tools/call", "readFile ~/.npmrc", "allow", "log", "MEDIUM", "Package registry config may contain auth tokens"),
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "readFile", "tools/call", "readFile ~/project/.env", "allow", "log", "MEDIUM", "Environment file may contain secrets"),
        ("eslogger", "filesystem_server", "Claude Desktop", "read", "file/open", "OS open ~/.zprofile by node (PID 7021)", "log", "log", "LOW", "Shell profile access for environment detection"),
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "readFile", "tools/call", "readFile ~/.ssh/config", "allow", "log", "MEDIUM", "SSH config access by AI tool"),
        ("mcp-proxy", "bash", "Claude Desktop", "run", "tools/call", "curl https://registry.npmjs.org/lodash", "allow", "log", "LOW", "External HTTP request to package registry"),
    ];

    let suspicious_events = vec![
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "readFile", "tools/call", "readFile ~/.ssh/id_rsa", "prompt", "review", "HIGH", "Private SSH key access attempt"),
        ("mcp-proxy", "filesystem_server", "Claude Desktop", "readFile", "tools/call", "readFile ~/.aws/credentials", "block", "block", "CRITICAL", "AWS credential file access blocked"),
        ("eslogger", "filesystem_server", "Claude Desktop", "connect", "network/connect", "network connect 43.128.22.15:443 by python3", "block", "block", "CRITICAL", "C2 callback to unrecognized IP"),
    ];

    for day_offset in (0..days).rev() {
        // Generate a base date at 9 AM for the given day.
        let day_base = now - chrono::Duration::days(day_offset as i64);
        let day_start = Utc
            .with_ymd_and_hms(
                day_base.date_naive().year(),
                day_base.date_naive().month(),
                day_base.date_naive().day(),
                9,
                0,
                0,
            )
            .single()
            .unwrap_or(day_base);

        // For today (day_offset == 0), only generate events up to 5 minutes ago
        // so they don't show up as "new" in `rookbot watch`.
        let day_end = if day_offset == 0 {
            now - chrono::Duration::minutes(5)
        } else {
            day_start + chrono::Duration::hours(10)
        };

        // If it's before 9:05 AM today, skip today's seed entirely.
        if day_end <= day_start {
            println!("  Day -0: skipped (too early in the day)");
            continue;
        }

        // Simple deterministic "random" based on day offset.
        let day_seed = day_offset as u64;

        // ~700 events per day: 85% routine, 12% notable, 3% suspicious.
        let routine_count = 595 + (simple_hash(day_seed, 0) % 100) as u32;
        let notable_count = 80 + (simple_hash(day_seed, 1) % 25) as u32;
        let suspicious_count = 15 + (simple_hash(day_seed, 2) % 10) as u32;

        let total_day = routine_count + notable_count + suspicious_count;

        // Spread events across the available window.
        let window_ms = (day_end - day_start).num_milliseconds().max(1) as u64;
        let interval_ms = window_ms / total_day as u64;

        let mut event_idx = 0u32;

        // Write routine events.
        for i in 0..routine_count {
            let ts = day_start + chrono::Duration::milliseconds((event_idx as u64 * interval_ms) as i64);
            let template = &routine_events[simple_hash(day_seed, event_idx as u64) as usize % routine_events.len()];
            let record = build_seed_record(template.0, template.1, template.2, template.3, template.4, template.5, template.6, template.7, None, None, &session_id, ts);
            let json = serde_json::to_string(&record)?;
            writeln!(file, "{json}")?;
            event_idx += 1;
            let _ = i;
        }

        // Write notable events.
        for i in 0..notable_count {
            let ts = day_start + chrono::Duration::milliseconds((event_idx as u64 * interval_ms) as i64);
            let template = &notable_events[simple_hash(day_seed, event_idx as u64) as usize % notable_events.len()];
            let record = build_seed_record(template.0, template.1, template.2, template.3, template.4, template.5, template.6, template.7, Some(template.8), Some(template.9), &session_id, ts);
            let json = serde_json::to_string(&record)?;
            writeln!(file, "{json}")?;
            event_idx += 1;
            let _ = i;
        }

        // Write suspicious events.
        for i in 0..suspicious_count {
            let ts = day_start + chrono::Duration::milliseconds((event_idx as u64 * interval_ms) as i64);
            let template = &suspicious_events[simple_hash(day_seed, event_idx as u64) as usize % suspicious_events.len()];
            let record = build_seed_record(template.0, template.1, template.2, template.3, template.4, template.5, template.6, template.7, Some(template.8), Some(template.9), &session_id, ts);
            let json = serde_json::to_string(&record)?;
            writeln!(file, "{json}")?;
            event_idx += 1;
            let _ = i;
        }

        total_events += event_idx as u64;
        println!(
            "  Day -{}: {} events ({} routine, {} notable, {} suspicious)",
            day_offset, event_idx, routine_count, notable_count, suspicious_count
        );
    }

    file.flush()?;
    println!();
    println!("Seeded {} total events across {} days.", total_events, days);
    println!("View with: rookbot log -n 50");
    println!("Or watch live: rookbot watch");
    Ok(())
}

use chrono::Datelike;

fn build_seed_record(
    source: &str,
    server_name: &str,
    client_name: &str,
    tool_name: &str,
    method: &str,
    summary: &str,
    action: &str,
    classification: &str,
    risk_level: Option<&str>,
    risk_explanation: Option<&str>,
    session_id: &str,
    ts: DateTime<Utc>,
) -> AuditRecord {
    let slm = risk_level.map(|level| SlmAnalysisRecord {
        risk_level: level.to_string(),
        explanation: risk_explanation
            .unwrap_or("Synthetic seed event")
            .to_string(),
        confidence: match level {
            "CRITICAL" => 0.95,
            "HIGH" => 0.91,
            "MEDIUM" => 0.78,
            "LOW" => 0.65,
            _ => 0.50,
        },
        latency_ms: 40,
        model: "qwen3-1.7b".to_string(),
    });

    AuditRecord {
        timestamp: ts,
        source: source.to_string(),
        event_summary: summary.to_string(),
        event_details: serde_json::json!({"tool": tool_name, "demo": true}),
        rule_matched: if action == "block" {
            Some("demo_policy".to_string())
        } else {
            None
        },
        action_taken: action.to_string(),
        response_time_ms: Some(2),
        session_id: Some(session_id.to_string()),
        direction: Some("client_to_server".to_string()),
        server_name: Some(server_name.to_string()),
        client_name: Some(client_name.to_string()),
        jsonrpc_method: Some(method.to_string()),
        tool_name: Some(tool_name.to_string()),
        arguments: {
            // Extract resource path from summaries like "readFile ~/project/src/main.rs"
            if tool_name == "readFile" || tool_name == "writeFile" || tool_name == "read" {
                let path = summary.split_whitespace().nth(1).unwrap_or("");
                if !path.is_empty() {
                    Some(serde_json::json!({"path": path}))
                } else {
                    None
                }
            } else if tool_name == "search" {
                let query = summary.strip_prefix("search ").unwrap_or(summary);
                Some(serde_json::json!({"query": query.trim_matches('"')}))
            } else if tool_name == "run" {
                let cmd = summary.strip_prefix("run ").unwrap_or(summary);
                Some(serde_json::json!({"command": cmd}))
            } else if tool_name == "connect" {
                let addr = summary.split_whitespace().last().unwrap_or(summary);
                Some(serde_json::json!({"url": addr}))
            } else {
                Some(serde_json::json!({"query": summary}))
            }
        },
        classification: Some(classification.to_string()),
        policy_rule: if action == "block" {
            Some("demo_policy".to_string())
        } else {
            None
        },
        policy_action: Some(match action {
            "allow" => "allowed",
            "block" => "blocked",
            "prompt" => "prompted",
            _ => "logged",
        }
        .to_string()),
        user_decision: None,
        proxy_latency_us: Some(850),
        slm_analysis: slm,
        swarm_analysis: None,
        behavioral: None,
        injection_scan: None,
        threat_intel: None,
        network_connection: None,
    }
}

/// Simple deterministic hash for pseudo-random seed data (no rand dependency needed).
fn simple_hash(seed: u64, idx: u64) -> u64 {
    let mut h = seed.wrapping_mul(6364136223846793005).wrapping_add(idx);
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    h
}

fn cmd_clean(config: &ClawConfig) -> Result<()> {
    let audit_path = &config.audit_log_path;
    let data_dir = audit_path
        .parent()
        .unwrap_or_else(|| Path::new("."));

    // Remove PID marker.
    let pid_path = data_dir.join("demo.pid");
    if pid_path.exists() {
        fs::remove_file(&pid_path)?;
        println!("  Removed demo PID marker.");
    }

    // Truncate audit log.
    if audit_path.exists() {
        let meta = fs::metadata(audit_path)?;
        let size_kb = meta.len() / 1024;
        println!(
            "  Audit log: {} ({} KB)",
            audit_path.display(),
            size_kb
        );
        println!("  Truncating audit log...");
        fs::write(audit_path, "")?;
        println!("  Audit log cleared.");
    } else {
        println!("  No audit log found.");
    }

    // Remove rotated log files.
    for i in 1..=10 {
        let rotated = PathBuf::from(format!("{}.{i}", audit_path.display()));
        if rotated.exists() {
            fs::remove_file(&rotated)?;
            println!("  Removed rotated log: {}", rotated.display());
        }
    }

    println!();
    println!("Demo data cleaned.");
    Ok(())
}

fn default_config_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config/clawdefender/config.toml")
    } else {
        PathBuf::from("config.toml")
    }
}
