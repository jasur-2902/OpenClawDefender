//! `clawai policy list` and `clawai policy test` commands.

use std::path::Path;

use anyhow::{bail, Context, Result};
use claw_core::event::mcp::{McpEvent, McpEventKind, ResourceRead, SamplingRequest, ToolCall};
use claw_core::policy::engine::DefaultPolicyEngine;
use claw_core::policy::PolicyEngine;
use chrono::Utc;
use serde_json::Value;

/// Print all rules loaded from the policy file.
pub fn list(policy_path: &Path) -> Result<()> {
    if !policy_path.exists() {
        bail!(
            "Policy file not found: {}\nRun `clawai init` to create defaults.",
            policy_path.display()
        );
    }

    let content = std::fs::read_to_string(policy_path)
        .with_context(|| format!("reading {}", policy_path.display()))?;
    let rules = claw_core::policy::rule::parse_policy_toml(&content)?;

    if rules.is_empty() {
        println!("No rules defined in {}", policy_path.display());
        return Ok(());
    }

    println!("Policy rules from {}:", policy_path.display());
    println!();
    println!(
        "  {:<4} {:<24} {:<8} DESCRIPTION",
        "PRI", "NAME", "ACTION"
    );
    println!("  {}", "-".repeat(72));

    for rule in &rules {
        let action = match &rule.action {
            claw_core::policy::PolicyAction::Allow => "allow",
            claw_core::policy::PolicyAction::Block => "block",
            claw_core::policy::PolicyAction::Prompt(_) => "prompt",
            claw_core::policy::PolicyAction::Log => "log",
        };
        println!(
            "  {:<4} {:<24} {:<8} {}",
            rule.priority, rule.name, action, rule.description
        );
    }

    println!();
    println!("  {} rule(s) loaded", rules.len());

    Ok(())
}

/// Test a JSON fixture against the policy and show the result.
pub fn test_fixture(fixture_path: &Path, policy_path: &Path) -> Result<()> {
    if !policy_path.exists() {
        bail!(
            "Policy file not found: {}\nRun `clawai init` to create defaults.",
            policy_path.display()
        );
    }
    if !fixture_path.exists() {
        bail!("Fixture file not found: {}", fixture_path.display());
    }

    let engine = DefaultPolicyEngine::load(policy_path)?;

    let fixture_content = std::fs::read_to_string(fixture_path)
        .with_context(|| format!("reading fixture {}", fixture_path.display()))?;
    let fixture: Value = serde_json::from_str(&fixture_content)
        .with_context(|| format!("parsing fixture as JSON: {}", fixture_path.display()))?;

    // Try to interpret the fixture as a JSON-RPC message and build an McpEvent.
    let event = fixture_to_event(&fixture)
        .with_context(|| "could not interpret fixture as an MCP event")?;

    let action = engine.evaluate(&event);

    let summary = match &event.kind {
        McpEventKind::ToolCall(tc) => format!("tool_call: {}", tc.tool_name),
        McpEventKind::ResourceRead(rr) => format!("resource_read: {}", rr.uri),
        McpEventKind::SamplingRequest(_) => "sampling_request".to_string(),
        McpEventKind::ListRequest => "list_request".to_string(),
        McpEventKind::Notification(n) => format!("notification: {n}"),
        McpEventKind::Other(m) => format!("other: {m}"),
    };

    let action_str = match &action {
        claw_core::policy::PolicyAction::Allow => "ALLOW",
        claw_core::policy::PolicyAction::Block => "BLOCK",
        claw_core::policy::PolicyAction::Prompt(msg) => {
            println!("Result: PROMPT");
            println!("  Message: {msg}");
            println!("  Event:   {summary}");
            return Ok(());
        }
        claw_core::policy::PolicyAction::Log => "LOG",
    };

    println!("Result: {action_str}");
    println!("  Event: {summary}");

    Ok(())
}

/// Convert a JSON fixture value into an McpEvent for policy evaluation.
fn fixture_to_event(v: &Value) -> Result<McpEvent> {
    let method = v
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");

    let params = v.get("params").cloned().unwrap_or(Value::Object(Default::default()));
    let id = v.get("id").cloned().unwrap_or(Value::Number(0.into()));

    let kind = match method {
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unknown")
                .to_string();
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));
            McpEventKind::ToolCall(ToolCall {
                tool_name: name,
                arguments,
                request_id: id,
            })
        }
        "resources/read" => {
            let uri = params
                .get("uri")
                .and_then(|u| u.as_str())
                .unwrap_or("unknown")
                .to_string();
            McpEventKind::ResourceRead(ResourceRead {
                uri,
                request_id: id,
            })
        }
        "sampling/createMessage" => {
            let messages = params
                .get("messages")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let model_preferences = params.get("modelPreferences").cloned();
            McpEventKind::SamplingRequest(SamplingRequest {
                messages,
                model_preferences,
                request_id: id,
            })
        }
        "tools/list" | "resources/list" | "prompts/list" => McpEventKind::ListRequest,
        m if m.starts_with("notifications/") => McpEventKind::Notification(m.to_string()),
        other => McpEventKind::Other(other.to_string()),
    };

    Ok(McpEvent {
        timestamp: Utc::now(),
        source: "cli-test".to_string(),
        kind,
        raw_message: v.clone(),
    })
}
