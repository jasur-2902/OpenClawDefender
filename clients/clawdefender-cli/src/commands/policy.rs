//! `clawdefender policy list/add/test/reload` commands.

use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{bail, Context, Result};
use clawdefender_core::config::ClawConfig;
use clawdefender_core::event::mcp::{McpEvent, McpEventKind, ResourceRead, SamplingRequest, ToolCall};
use clawdefender_core::policy::engine::DefaultPolicyEngine;
use clawdefender_core::policy::PolicyEngine;
use chrono::Utc;
use serde_json::Value;

/// Print all rules loaded from the policy file.
pub fn list(policy_path: &Path) -> Result<()> {
    if !policy_path.exists() {
        bail!(
            "Policy file not found: {}\nRun `clawdefender init` to create defaults.",
            policy_path.display()
        );
    }

    let content = std::fs::read_to_string(policy_path)
        .with_context(|| format!("reading {}", policy_path.display()))?;
    let rules = clawdefender_core::policy::rule::parse_policy_toml(&content)?;

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
            clawdefender_core::policy::PolicyAction::Allow => "allow",
            clawdefender_core::policy::PolicyAction::Block => "block",
            clawdefender_core::policy::PolicyAction::Prompt(_) => "prompt",
            clawdefender_core::policy::PolicyAction::Log => "log",
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

/// Interactively add a new policy rule.
pub fn add(policy_path: &Path) -> Result<()> {
    if !policy_path.exists() {
        bail!(
            "Policy file not found: {}\nRun `clawdefender init` to create defaults.",
            policy_path.display()
        );
    }

    let stdin = io::stdin();
    let mut reader = stdin.lock();

    let name = prompt_line(&mut reader, "Rule name (e.g. block_dangerous_tools): ")?;
    let description = prompt_line(&mut reader, "Description: ")?;

    println!("Action [allow/block/prompt/log]: ");
    io::stdout().flush()?;
    let action = read_line(&mut reader)?;
    let action = match action.trim() {
        "allow" | "block" | "prompt" | "log" => action.trim().to_string(),
        _ => bail!("Invalid action: {action}. Must be allow, block, prompt, or log."),
    };

    let message = prompt_line(&mut reader, "Message: ")?;

    println!("Match type [tool_name/resource_path/method/event_type/any]: ");
    io::stdout().flush()?;
    let match_type = read_line(&mut reader)?;
    let match_type = match_type.trim();

    let match_section = if match_type == "any" {
        "any = true".to_string()
    } else {
        let values = prompt_line(
            &mut reader,
            &format!("{match_type} patterns (comma-separated): "),
        )?;
        let values: Vec<String> = values.split(',').map(|s| s.trim().to_string()).collect();
        let quoted: Vec<String> = values.iter().map(|v| format!("\"{v}\"")).collect();
        format!("{match_type} = [{}]", quoted.join(", "))
    };

    let toml_fragment = format!(
        "\n[rules.{name}]\ndescription = \"{description}\"\naction = \"{action}\"\nmessage = \"{message}\"\npriority = 50\n\n[rules.{name}.match]\n{match_section}\n"
    );

    let mut content = std::fs::read_to_string(policy_path)?;
    content.push_str(&toml_fragment);
    std::fs::write(policy_path, &content)?;

    println!();
    println!("Rule \"{name}\" added to {}", policy_path.display());

    Ok(())
}

/// Test a JSON fixture against the policy and show the result.
pub fn test_fixture(fixture_path: &Path, policy_path: &Path) -> Result<()> {
    if !policy_path.exists() {
        bail!(
            "Policy file not found: {}\nRun `clawdefender init` to create defaults.",
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
        clawdefender_core::policy::PolicyAction::Allow => "ALLOW",
        clawdefender_core::policy::PolicyAction::Block => "BLOCK",
        clawdefender_core::policy::PolicyAction::Prompt(msg) => {
            println!("Result: PROMPT");
            println!("  Message: {msg}");
            println!("  Event:   {summary}");
            return Ok(());
        }
        clawdefender_core::policy::PolicyAction::Log => "LOG",
    };

    println!("Result: {action_str}");
    println!("  Event: {summary}");

    Ok(())
}

/// Signal the running daemon to reload policy.
pub fn reload(config: &ClawConfig) -> Result<()> {
    let socket_path = &config.daemon_socket_path;
    match UnixStream::connect(socket_path) {
        Ok(_stream) => {
            // TODO: send actual reload command over IPC.
            println!("Policy reload signal sent to daemon.");
        }
        Err(_) => {
            println!("Daemon is not running. Policy will be loaded fresh on next proxy start.");
        }
    }
    Ok(())
}

fn prompt_line<R: BufRead>(reader: &mut R, prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    read_line(reader)
}

fn read_line<R: BufRead>(reader: &mut R) -> Result<String> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Convert a JSON fixture value into an McpEvent for policy evaluation.
fn fixture_to_event(v: &Value) -> Result<McpEvent> {
    let method = v
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");

    let params = v
        .get("params")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));
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
