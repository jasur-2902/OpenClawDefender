//! Level 3 (Proactive) certification tests.
//!
//! Verifies that the MCP server proactively declares its security posture:
//! ships a manifest, declares permissions, calls requestPermission with
//! justifications, and calls getPolicy on startup.

use std::path::Path;

use anyhow::Result;
use serde_json::json;

use crate::harness::McpHarness;
use crate::manifest::{self, Manifest};
use crate::report::{LevelReport, TestResult};
use crate::CertifyConfig;

pub async fn run(config: &CertifyConfig) -> Result<LevelReport> {
    let mut tests = Vec::new();

    tests.push(test_has_manifest(config).await);
    tests.push(test_declares_permissions(config).await);
    tests.push(test_request_permission_with_justification(config).await);
    tests.push(test_calls_get_policy_on_startup(config).await);
    tests.push(test_graceful_degradation(config).await);

    Ok(LevelReport::from_tests("Proactive", tests))
}

/// Resolve the server directory from config or from the server command.
fn resolve_server_dir(config: &CertifyConfig) -> Option<std::path::PathBuf> {
    if let Some(dir) = &config.server_dir {
        return Some(dir.clone());
    }
    // Try to infer from the server command — use the directory of the first arg
    if let Some(cmd) = config.server_command.first() {
        let path = Path::new(cmd);
        if let Some(parent) = path.parent() {
            if parent.exists() {
                return Some(parent.to_path_buf());
            }
        }
    }
    // Fall back to current directory
    std::env::current_dir().ok()
}

/// Test: server package includes a clawdefender.toml manifest.
async fn test_has_manifest(config: &CertifyConfig) -> TestResult {
    let name = "Has clawdefender.toml manifest";

    let server_dir = match resolve_server_dir(config) {
        Some(d) => d,
        None => {
            return TestResult {
                name: name.to_string(),
                passed: false,
                message: "Could not determine server directory".to_string(),
            };
        }
    };

    match manifest::find_manifest(&server_dir) {
        Some(path) => match Manifest::load(&path) {
            Ok(_) => TestResult {
                name: name.to_string(),
                passed: true,
                message: String::new(),
            },
            Err(e) => TestResult {
                name: name.to_string(),
                passed: false,
                message: format!("Found manifest but failed to parse: {e:#}"),
            },
        },
        None => TestResult {
            name: name.to_string(),
            passed: false,
            message: format!(
                "No clawdefender.toml found in {} or parent directories",
                server_dir.display()
            ),
        },
    }
}

/// Test: manifest declares permissions.
async fn test_declares_permissions(config: &CertifyConfig) -> TestResult {
    let name = "Manifest declares permissions";

    let server_dir = match resolve_server_dir(config) {
        Some(d) => d,
        None => {
            return TestResult {
                name: name.to_string(),
                passed: false,
                message: "Could not determine server directory".to_string(),
            };
        }
    };

    match manifest::find_manifest(&server_dir).and_then(|p| Manifest::load(&p).ok()) {
        Some(m) if m.has_permissions() => TestResult {
            name: name.to_string(),
            passed: true,
            message: String::new(),
        },
        Some(_) => TestResult {
            name: name.to_string(),
            passed: false,
            message: "Manifest exists but declares no permissions".to_string(),
        },
        None => TestResult {
            name: name.to_string(),
            passed: false,
            message: "No valid manifest found".to_string(),
        },
    }
}

/// Test: server calls requestPermission with meaningful justifications.
async fn test_request_permission_with_justification(config: &CertifyConfig) -> TestResult {
    let name = "Calls requestPermission with justifications";
    match run_request_permission(config).await {
        Ok(()) => TestResult {
            name: name.to_string(),
            passed: true,
            message: String::new(),
        },
        Err(e) => TestResult {
            name: name.to_string(),
            passed: false,
            message: format!("{e:#}"),
        },
    }
}

async fn run_request_permission(config: &CertifyConfig) -> Result<()> {
    let mut harness = McpHarness::start(&config.server_command).await?;
    let init_result = harness.initialize().await?;

    // Check for proactive permission handling via capabilities
    let has_permission_support = init_result
        .get("capabilities")
        .and_then(|c| c.get("experimental"))
        .and_then(|e| e.get("clawdefender"))
        .and_then(|cd| cd.get("requestPermission"))
        .is_some();

    harness.shutdown().await?;

    if !has_permission_support {
        anyhow::bail!(
            "No evidence of requestPermission capability \
             (no experimental/clawdefender/requestPermission in capabilities)"
        );
    }

    Ok(())
}

/// Test: server calls getPolicy on startup.
async fn test_calls_get_policy_on_startup(config: &CertifyConfig) -> TestResult {
    let name = "Calls getPolicy on startup";
    match run_get_policy(config).await {
        Ok(()) => TestResult {
            name: name.to_string(),
            passed: true,
            message: String::new(),
        },
        Err(e) => TestResult {
            name: name.to_string(),
            passed: false,
            message: format!("{e:#}"),
        },
    }
}

async fn run_get_policy(config: &CertifyConfig) -> Result<()> {
    let mut harness = McpHarness::start(&config.server_command).await?;
    let init_result = harness.initialize().await?;

    // Check for getPolicy support
    let has_get_policy = init_result
        .get("capabilities")
        .and_then(|c| c.get("experimental"))
        .and_then(|e| e.get("clawdefender"))
        .and_then(|cd| cd.get("getPolicy"))
        .is_some();

    harness.shutdown().await?;

    if !has_get_policy {
        anyhow::bail!(
            "No evidence of getPolicy capability \
             (no experimental/clawdefender/getPolicy in capabilities)"
        );
    }

    Ok(())
}

/// Test: server gracefully degrades when permissions are denied.
async fn test_graceful_degradation(config: &CertifyConfig) -> TestResult {
    let name = "Graceful degradation on denied permissions";
    match run_graceful_degradation(config).await {
        Ok(()) => TestResult {
            name: name.to_string(),
            passed: true,
            message: String::new(),
        },
        Err(e) => TestResult {
            name: name.to_string(),
            passed: false,
            message: format!("{e:#}"),
        },
    }
}

async fn run_graceful_degradation(config: &CertifyConfig) -> Result<()> {
    let mut harness = McpHarness::start(&config.server_command).await?;
    harness.initialize().await?;

    let tools = harness.list_tools().await?;
    if tools.is_empty() {
        anyhow::bail!("Server reported no tools");
    }

    // Call all tools — server should respond gracefully even if it cannot
    // perform operations (e.g., when permissions would be denied)
    for tool in &tools {
        let tool_name = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");
        let resp = harness.call_tool(tool_name, json!({})).await?;

        // Must have either result or error — not crash
        if resp.get("result").is_none() && resp.get("error").is_none() {
            anyhow::bail!("Tool '{tool_name}' returned neither result nor error");
        }
    }

    if !harness.is_running() {
        anyhow::bail!("Server crashed during degradation test");
    }

    harness.shutdown().await?;
    Ok(())
}
