use std::collections::HashMap;

use crate::state::{AuditEvent, ServerProfileSummary};

use super::context::*;
use super::display_names::*;
use super::humanizer::*;
use super::templates::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_event(
    server: &str,
    tool: Option<&str>,
    action: &str,
    decision: &str,
    resource: Option<&str>,
    details: &str,
    event_type: &str,
) -> AuditEvent {
    AuditEvent {
        id: "evt-1".to_string(),
        timestamp: "2026-02-25T10:00:00Z".to_string(),
        event_type: event_type.to_string(),
        server_name: server.to_string(),
        tool_name: tool.map(|s| s.to_string()),
        action: action.to_string(),
        decision: decision.to_string(),
        risk_level: "low".to_string(),
        details: details.to_string(),
        resource: resource.map(|s| s.to_string()),
    }
}

fn make_profile(server: &str, total_calls: u64, status: &str, anomaly_score: f64) -> ServerProfileSummary {
    ServerProfileSummary {
        server_name: server.to_string(),
        tools_count: 5,
        total_calls,
        anomaly_score,
        status: status.to_string(),
        last_activity: "2026-02-25T10:00:00Z".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Template classification tests
// ---------------------------------------------------------------------------

#[test]
fn test_classify_ssh_key_access() {
    let event = make_event(
        "filesystem", Some("read_file"), "read", "prompted",
        Some("/home/user/.ssh/id_rsa"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::SshKeyAccess);
}

#[test]
fn test_classify_ssh_ed25519() {
    let event = make_event(
        "filesystem", Some("read_file"), "read", "prompted",
        Some("/home/user/.ssh/id_ed25519"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::SshKeyAccess);
}

#[test]
fn test_classify_aws_credentials() {
    let event = make_event(
        "filesystem", Some("read_file"), "read", "prompted",
        Some("/home/user/.aws/credentials"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::AwsCredentials);
}

#[test]
fn test_classify_env_file() {
    let event = make_event(
        "filesystem", Some("read_file"), "read", "allow",
        Some("/home/user/project/.env"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::EnvFileAccess);
}

#[test]
fn test_classify_env_file_with_suffix() {
    let event = make_event(
        "filesystem", Some("read_file"), "read", "allow",
        Some("/home/user/project/.env.production"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::EnvFileAccess);
}

#[test]
fn test_classify_browser_data() {
    let event = make_event(
        "filesystem", Some("read_file"), "read", "blocked",
        Some("/home/user/Library/Application Support/Google/Chrome/Default/Login Data"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::BrowserData);
}

#[test]
fn test_classify_high_risk_shell() {
    let event = make_event(
        "filesystem", Some("execute_command"), "Shell Command", "prompted",
        Some("curl | bash"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::HighRiskShellCommand);
}

#[test]
fn test_classify_rm_rf() {
    let event = make_event(
        "filesystem", Some("execute_command"), "Shell Command", "prompted",
        Some("rm -rf /"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::HighRiskShellCommand);
}

#[test]
fn test_classify_safe_shell() {
    let event = make_event(
        "filesystem", Some("execute_command"), "Shell Command", "allow",
        Some("ls -la"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::SafeShellCommand);
}

#[test]
fn test_classify_safe_shell_git() {
    let event = make_event(
        "filesystem", Some("execute_command"), "Shell Command", "allow",
        Some("git status"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::SafeShellCommand);
}

#[test]
fn test_classify_network_known_api() {
    let event = make_event(
        "server-fetch", None, "connect", "allow",
        Some("api.openai.com"), "", "connect",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::NetworkKnownApi);
}

#[test]
fn test_classify_network_malicious() {
    let event = make_event(
        "server-fetch", None, "connect", "blocked",
        Some("evil.example.com"), "ioc match found", "connect",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::NetworkMalicious);
}

#[test]
fn test_classify_network_unknown() {
    let event = make_event(
        "server-fetch", None, "connect", "allow",
        Some("unknown-host.example.com"), "", "connect",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::NetworkUnknown);
}

#[test]
fn test_classify_sampling_request() {
    let event = make_event(
        "filesystem", None, "sampling/createMessage", "allow",
        None, "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::SamplingRequest);
}

#[test]
fn test_classify_prompt_injection() {
    let event = make_event(
        "filesystem", None, "sampling", "blocked",
        None, "prompt injection detected", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::PromptInjection);
}

#[test]
fn test_classify_kill_chain() {
    let event = make_event(
        "filesystem", None, "read", "blocked",
        None, "kill chain pattern detected", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::KillChainStep);
}

#[test]
fn test_classify_discovery() {
    let event = make_event(
        "filesystem", None, "tools/list", "allow",
        None, "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::DiscoveryRequest);
}

#[test]
fn test_classify_session_start() {
    let event = make_event(
        "filesystem", None, "Session Started", "allow",
        None, "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::SessionStart);
}

#[test]
fn test_classify_session_end() {
    let event = make_event(
        "filesystem", None, "Session Ended", "allow",
        None, "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::SessionEnd);
}

#[test]
fn test_classify_file_read_project() {
    let event = make_event(
        "filesystem", Some("read_file"), "File Read", "allow",
        Some("/home/user/workspace/project/src/main.rs"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::FileReadProject);
}

#[test]
fn test_classify_file_read_sensitive() {
    let event = make_event(
        "filesystem", Some("read_file"), "File Read", "allow",
        Some("/etc/passwd"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::FileReadSensitive);
}

#[test]
fn test_classify_file_write() {
    let event = make_event(
        "filesystem", Some("write_file"), "File Write", "allow",
        Some("/home/user/project/output.txt"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::FileWrite);
}

#[test]
fn test_classify_auto_block() {
    let event = make_event(
        "filesystem", Some("read_file"), "read", "blocked",
        Some("/sensitive/file"), "auto-blocked by policy", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::AutoBlock);
}

#[test]
fn test_classify_policy_prompt() {
    let event = make_event(
        "filesystem", Some("write_file"), "write", "prompted",
        Some("/home/user/project/config.json"), "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::PolicyPrompt);
}

#[test]
fn test_classify_first_time_action() {
    let event = make_event(
        "filesystem", Some("new_tool"), "call", "allow",
        None, "", "proxy",
    );
    assert_eq!(classify_event(&event, true, false), EventPattern::FirstTimeAction);
}

#[test]
fn test_classify_uncorrelated() {
    let event = make_event(
        "system", None, "file_create", "allow",
        Some("/tmp/suspicious"), "uncorrelated system activity", "system",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::UncorrelatedActivity);
}

#[test]
fn test_classify_generic_fallback() {
    let event = make_event(
        "filesystem", Some("custom_tool"), "custom_action", "allow",
        None, "", "proxy",
    );
    assert_eq!(classify_event(&event, false, false), EventPattern::GenericFallback);
}

// ---------------------------------------------------------------------------
// Display name tests
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_server_known() {
    let registry = DisplayNameRegistry::new();
    assert_eq!(
        registry.resolve_server("filesystem-server", Some("Cursor")),
        "Cursor's file access tool"
    );
    assert_eq!(
        registry.resolve_server("server-git", Some("Claude Desktop")),
        "Claude Desktop's Git tool"
    );
    assert_eq!(
        registry.resolve_server("server-postgres", None),
        "Your AI tool's database tool"
    );
}

#[test]
fn test_resolve_server_unknown() {
    let registry = DisplayNameRegistry::new();
    let result = registry.resolve_server("my-custom-server", Some("Cursor"));
    assert!(result.contains("my-custom-server"));
    assert!(result.contains("Cursor"));
}

#[test]
fn test_resolve_server_strips_prefix() {
    let registry = DisplayNameRegistry::new();
    let result = registry.resolve_server("mcp-server-custom", Some("Cursor"));
    assert!(result.contains("custom"));
    assert!(result.contains("Cursor"));
}

#[test]
fn test_resolve_tool_known() {
    let registry = DisplayNameRegistry::new();
    assert_eq!(registry.resolve_tool("read_file"), "read a file");
    assert_eq!(registry.resolve_tool("execute_command"), "run a command");
    assert_eq!(registry.resolve_tool("list_directory"), "browse a folder");
}

#[test]
fn test_resolve_tool_unknown() {
    let registry = DisplayNameRegistry::new();
    assert_eq!(registry.resolve_tool("my_custom_tool"), "my custom tool");
}

#[test]
fn test_resolve_resource_ssh() {
    let registry = DisplayNameRegistry::new();
    assert_eq!(
        registry.resolve_resource("/home/user/.ssh/id_rsa"),
        "your SSH keys"
    );
}

#[test]
fn test_resolve_resource_aws() {
    let registry = DisplayNameRegistry::new();
    assert_eq!(
        registry.resolve_resource("/home/user/.aws/credentials"),
        "your AWS credentials"
    );
}

#[test]
fn test_resolve_resource_browser() {
    let registry = DisplayNameRegistry::new();
    assert_eq!(
        registry.resolve_resource("/home/user/Library/Cookies"),
        "your browser credentials"
    );
}

#[test]
fn test_resolve_resource_system() {
    let registry = DisplayNameRegistry::new();
    assert_eq!(
        registry.resolve_resource("/etc/passwd"),
        "a system file"
    );
}

// ---------------------------------------------------------------------------
// Behavioral context tests
// ---------------------------------------------------------------------------

#[test]
fn test_context_no_profile() {
    let ctx = generate_behavioral_context(None);
    assert!(ctx.contains("do not have behavioral data"));
}

#[test]
fn test_context_learning() {
    let profile = make_profile("fs", 30, "learning", 0.0);
    let ctx = generate_behavioral_context(Some(&profile));
    assert!(ctx.contains("still learning"));
    assert!(ctx.contains("70"));
}

#[test]
fn test_context_high_anomaly() {
    let profile = make_profile("fs", 200, "active", 0.8);
    let ctx = generate_behavioral_context(Some(&profile));
    assert!(ctx.contains("unusual"));
}

#[test]
fn test_context_consistent() {
    let profile = make_profile("fs", 200, "active", 0.05);
    let ctx = generate_behavioral_context(Some(&profile));
    assert!(ctx.contains("completely consistent"));
}

#[test]
fn test_context_low_count() {
    let profile = make_profile("fs", 3, "active", 0.0);
    let ctx = generate_behavioral_context(Some(&profile));
    assert!(ctx.contains("3 time(s) before"));
}

#[test]
fn test_context_routine() {
    let profile = make_profile("fs", 70, "active", 0.2);
    let ctx = generate_behavioral_context(Some(&profile));
    assert!(ctx.contains("routine"));
}

// ---------------------------------------------------------------------------
// Risk level mapping tests
// ---------------------------------------------------------------------------

#[test]
fn test_threat_level_dangerous() {
    assert_eq!(threat_level_from_anomaly(0.95), "dangerous");
}

#[test]
fn test_threat_level_suspicious() {
    assert_eq!(threat_level_from_anomaly(0.75), "suspicious");
}

#[test]
fn test_threat_level_unusual() {
    assert_eq!(threat_level_from_anomaly(0.5), "unusual");
}

#[test]
fn test_threat_level_normal() {
    assert_eq!(threat_level_from_anomaly(0.1), "normal");
}

#[test]
fn test_risk_explanation_dangerous() {
    let explanation = risk_explanation_from_anomaly(0.95);
    assert!(explanation.contains("dangerous"));
}

#[test]
fn test_risk_explanation_normal() {
    let explanation = risk_explanation_from_anomaly(0.1);
    assert!(explanation.contains("normal"));
}

// ---------------------------------------------------------------------------
// Full humanization tests
// ---------------------------------------------------------------------------

#[test]
fn test_humanize_ssh_event() {
    let event = make_event(
        "filesystem-server", Some("read_file"), "read", "prompted",
        Some("/home/user/.ssh/id_rsa"), "", "proxy",
    );
    let ctx = HumanizationContext::default();
    let result = humanize_event(&event, None, &ctx);

    assert_eq!(result.event_id, "evt-1");
    assert!(result.one_liner.contains("SSH private key"));
    assert!(result.is_notable);
    assert_eq!(result.risk_level, "dangerous");
    assert_eq!(result.action_taken, "Prompted");
    assert!(result.educational_aside.is_some());
    // Server name should NOT be raw MCP identifier
    assert!(!result.server_display_name.contains("filesystem-server"));
}

#[test]
fn test_humanize_safe_command() {
    let event = make_event(
        "filesystem", Some("execute_command"), "Shell Command", "allow",
        Some("ls -la"), "", "proxy",
    );
    let ctx = HumanizationContext::default();
    let result = humanize_event(&event, None, &ctx);

    assert!(result.one_liner.contains("ls -la") || result.one_liner.contains("shell command"));
    assert!(!result.is_notable);
    assert_eq!(result.risk_level, "normal");
    assert_eq!(result.action_taken, "Allowed");
}

#[test]
fn test_humanize_blocked_event() {
    let event = make_event(
        "filesystem", Some("read_file"), "read", "blocked",
        Some("/etc/passwd"), "auto-blocked by policy", "proxy",
    );
    let ctx = HumanizationContext::default();
    let result = humanize_event(&event, None, &ctx);

    assert_eq!(result.action_taken, "AutoBlocked");
    assert!(result.is_notable);
}

#[test]
fn test_humanize_with_profile() {
    let event = make_event(
        "filesystem", Some("read_file"), "read", "allow",
        Some("/home/user/workspace/project/main.rs"), "", "proxy",
    );
    let profile = make_profile("filesystem", 200, "active", 0.05);
    let ctx = HumanizationContext::default();
    let result = humanize_event(&event, Some(&profile), &ctx);

    assert!(result.behavioral_context.contains("consistent"));
}

#[test]
fn test_humanize_with_anomalous_profile() {
    let event = make_event(
        "filesystem", Some("read_file"), "read", "allow",
        Some("/home/user/workspace/project/main.rs"), "", "proxy",
    );
    let profile = make_profile("filesystem", 200, "active", 0.8);
    let ctx = HumanizationContext::default();
    let result = humanize_event(&event, Some(&profile), &ctx);

    assert!(result.behavioral_context.contains("unusual"));
    assert!(result.is_notable);
    // Risk should be elevated due to anomaly
    assert!(result.risk_level == "suspicious" || result.risk_level == "unusual");
}

// ---------------------------------------------------------------------------
// Batch humanization tests
// ---------------------------------------------------------------------------

#[test]
fn test_batch_humanization() {
    let events = vec![
        make_event("fs", Some("read_file"), "read", "allow", Some("/home/user/workspace/project/main.rs"), "", "proxy"),
        make_event("fs", Some("write_file"), "write", "allow", Some("/home/user/workspace/project/out.txt"), "", "proxy"),
        make_event("net", None, "connect", "allow", Some("api.openai.com"), "", "connect"),
    ];
    let mut profiles = HashMap::new();
    profiles.insert("fs".to_string(), make_profile("fs", 100, "active", 0.1));

    let results = humanize_events(&events, &profiles);
    assert_eq!(results.len(), 3);

    // First two should have profile context, third should not
    assert!(!results[0].behavioral_context.contains("do not have"));
    assert!(!results[1].behavioral_context.contains("do not have"));
    assert!(results[2].behavioral_context.contains("do not have"));
}

#[test]
fn test_batch_empty() {
    let results = humanize_events(&[], &HashMap::new());
    assert!(results.is_empty());
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

#[test]
fn test_event_missing_resource() {
    let event = make_event("filesystem", Some("read_file"), "read", "allow", None, "", "proxy");
    let ctx = HumanizationContext::default();
    let result = humanize_event(&event, None, &ctx);
    // Should not panic and should produce valid output
    assert!(!result.one_liner.is_empty());
}

#[test]
fn test_event_missing_tool() {
    let event = make_event("filesystem", None, "unknown_action", "allow", None, "", "proxy");
    let ctx = HumanizationContext::default();
    let result = humanize_event(&event, None, &ctx);
    assert!(!result.one_liner.is_empty());
    assert_eq!(result.raw_event.id, "evt-1");
}

#[test]
fn test_event_unknown_server() {
    let event = make_event("totally-unknown-server", Some("read_file"), "read", "allow", None, "", "proxy");
    let ctx = HumanizationContext::default();
    let result = humanize_event(&event, None, &ctx);
    // Should use fallback display name
    assert!(result.server_display_name.contains("totally-unknown-server"));
}

#[test]
fn test_kill_chain_id_detection() {
    let event = make_event(
        "filesystem", None, "read", "blocked",
        None, "kill chain pattern: credential exfiltration", "proxy",
    );
    let ctx = HumanizationContext::default();
    let result = humanize_event(&event, None, &ctx);
    assert!(result.kill_chain_id.is_some());
}

#[test]
fn test_action_taken_variants() {
    assert_eq!(ActionTaken::from_decision("allow", "").label(), "Allowed");
    assert_eq!(ActionTaken::from_decision("prompted", "").label(), "Prompted");
    assert_eq!(ActionTaken::from_decision("blocked", "").label(), "Blocked");
    assert_eq!(ActionTaken::from_decision("blocked", "auto-blocked").label(), "AutoBlocked");
    assert_eq!(ActionTaken::from_decision("denied", "auto policy").label(), "AutoBlocked");
}
