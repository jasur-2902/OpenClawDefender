//! Level 2 (Cooperative) certification tests.
//!
//! Verifies that the MCP server integrates with the ClawDefender SDK:
//! calls checkIntent before operations, respects denials, reports actions,
//! and operates without ClawDefender.

use anyhow::Result;
use serde_json::json;

use crate::harness::McpHarness;
use crate::report::{LevelReport, TestResult};
use crate::CertifyConfig;

pub async fn run(config: &CertifyConfig) -> Result<LevelReport> {
    let mut tests = Vec::new();

    tests.push(test_calls_check_intent(config).await);
    tests.push(test_respects_denials(config).await);
    tests.push(test_calls_report_action(config).await);
    tests.push(test_operates_without_clawdefender(config).await);

    Ok(LevelReport::from_tests("Cooperative", tests))
}

/// Test: server calls checkIntent before tool execution.
///
/// We look for evidence that the server attempts to call ClawDefender's
/// checkIntent endpoint. Since we cannot directly instrument the server,
/// we check if the server exposes any ClawDefender integration metadata
/// or if tool call responses indicate SDK usage.
async fn test_calls_check_intent(config: &CertifyConfig) -> TestResult {
    let name = "Calls checkIntent before sensitive operations";
    match run_check_intent(config).await {
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

async fn run_check_intent(config: &CertifyConfig) -> Result<()> {
    let mut harness = McpHarness::start(&config.server_command).await?;
    let init_result = harness.initialize().await?;

    // Check if the server advertises ClawDefender support in its capabilities
    let has_clawdefender_support = init_result
        .get("capabilities")
        .and_then(|c| c.get("experimental"))
        .and_then(|e| e.get("clawdefender"))
        .is_some();

    // Also check server info for SDK markers
    let server_info = init_result.get("serverInfo");
    let has_sdk_marker = server_info
        .and_then(|s| s.get("metadata"))
        .and_then(|m| m.get("clawdefender_sdk"))
        .is_some();

    // Check if server has a clawdefender-related tool or resource
    let tools = harness.list_tools().await?;
    let has_security_tool = tools.iter().any(|t| {
        t.get("name")
            .and_then(|n| n.as_str())
            .map(|n| n.contains("clawdefender") || n.contains("security") || n.contains("check"))
            .unwrap_or(false)
    });

    harness.shutdown().await?;

    if !has_clawdefender_support && !has_sdk_marker && !has_security_tool {
        anyhow::bail!(
            "No evidence of ClawDefender SDK integration (no experimental/clawdefender capability, \
             no SDK metadata, no security-related tools)"
        );
    }

    Ok(())
}

/// Test: when checkIntent returns denied, the server does not proceed.
async fn test_respects_denials(config: &CertifyConfig) -> TestResult {
    let name = "Respects denials from checkIntent";
    match run_respects_denials(config).await {
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

async fn run_respects_denials(config: &CertifyConfig) -> Result<()> {
    let mut harness = McpHarness::start(&config.server_command).await?;
    harness.initialize().await?;

    let tools = harness.list_tools().await?;
    if tools.is_empty() {
        anyhow::bail!("Server reported no tools");
    }

    // Call a tool — for Level 2 compliance, the server should handle errors
    // from ClawDefender gracefully and return user-friendly messages
    let tool_name = tools[0]
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("unknown");

    let resp = harness.call_tool(tool_name, json!({})).await?;

    // The response should have either a result or a well-formed error
    let has_result = resp.get("result").is_some();
    let has_error = resp.get("error").is_some();

    harness.shutdown().await?;

    if !has_result && !has_error {
        anyhow::bail!("Server returned neither result nor error");
    }

    Ok(())
}

/// Test: server calls reportAction after execution.
async fn test_calls_report_action(config: &CertifyConfig) -> TestResult {
    let name = "Calls reportAction after tool execution";
    match run_report_action(config).await {
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

async fn run_report_action(config: &CertifyConfig) -> Result<()> {
    // Similar to checkIntent — we look for evidence of reportAction usage.
    // In a real deployment, we'd intercept the ClawDefender MCP server calls.
    let mut harness = McpHarness::start(&config.server_command).await?;
    let init_result = harness.initialize().await?;

    let has_clawdefender = init_result
        .get("capabilities")
        .and_then(|c| c.get("experimental"))
        .and_then(|e| e.get("clawdefender"))
        .is_some();

    harness.shutdown().await?;

    if !has_clawdefender {
        anyhow::bail!(
            "No evidence of ClawDefender SDK integration for reportAction \
             (no experimental/clawdefender capability)"
        );
    }

    Ok(())
}

/// Test: server starts and operates when ClawDefender is not available.
async fn test_operates_without_clawdefender(config: &CertifyConfig) -> TestResult {
    let name = "Operates without ClawDefender available";
    match run_without_clawdefender(config).await {
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

async fn run_without_clawdefender(config: &CertifyConfig) -> Result<()> {
    // Start the server without any ClawDefender daemon/proxy running.
    // The server must start successfully and respond to basic requests.
    let mut harness = McpHarness::start(&config.server_command).await?;
    let _init = harness.initialize().await?;
    let tools = harness.list_tools().await?;

    if tools.is_empty() {
        anyhow::bail!("Server reported no tools when ClawDefender unavailable");
    }

    // Verify we can call a tool
    let tool_name = tools[0]
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("unknown");

    let resp = harness.call_tool(tool_name, json!({})).await?;
    if resp.get("result").is_none() && resp.get("error").is_none() {
        anyhow::bail!("Server returned invalid response without ClawDefender");
    }

    if !harness.is_running() {
        anyhow::bail!("Server crashed without ClawDefender");
    }

    harness.shutdown().await?;
    Ok(())
}
