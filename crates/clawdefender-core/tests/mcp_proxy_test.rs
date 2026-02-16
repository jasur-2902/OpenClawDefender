//! Integration tests for the MCP proxy policy enforcement pipeline.
//!
//! These tests load JSON fixtures representing MCP JSON-RPC messages, evaluate
//! them against the default policy (policies/default.toml), and assert that the
//! correct policy action is produced.
//!
//! All tests are marked `#[ignore]` because the full proxy pipeline is not yet
//! implemented. Run with `cargo test -- --ignored` once the proxy is available.

use std::path::PathBuf;

use clawdefender_core::policy::rule::{parse_policy_toml, EventContext};
use clawdefender_core::policy::{PolicyAction, PolicyRule};

/// Root of the workspace (two levels up from crates/clawdefender-core/).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Load the default policy rules from policies/default.toml.
fn load_default_policy() -> Vec<PolicyRule> {
    let policy_path = workspace_root().join("policies/default.toml");
    let content = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", policy_path.display()));
    parse_policy_toml(&content).expect("failed to parse default policy TOML")
}

/// Load a JSON fixture from tests/fixtures/.
fn load_fixture(name: &str) -> serde_json::Value {
    let path = workspace_root().join("tests/fixtures").join(name);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("invalid JSON in fixture {}: {e}", path.display()))
}

/// Load the expected action from a .expected file.
fn load_expected_action(name: &str) -> String {
    let path = workspace_root().join("tests/fixtures").join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read expected file {}: {e}", path.display()))
        .trim()
        .to_string()
}

/// Build an EventContext from a JSON-RPC fixture.
fn context_from_fixture(fixture: &serde_json::Value) -> EventContext {
    let method = fixture["method"].as_str().map(|s| s.to_string());
    let params = &fixture["params"];

    let tool_name = params["name"].as_str().map(|s| s.to_string());

    let resource_path = params["arguments"]["path"]
        .as_str()
        .or_else(|| params["uri"].as_str())
        .map(|s| s.to_string());

    let event_type = match method.as_deref() {
        Some("tools/call") => Some("tool_call".to_string()),
        Some("resources/list") => Some("list".to_string()),
        Some("resources/read") => Some("resource_read".to_string()),
        Some("sampling/createMessage") => Some("sampling".to_string()),
        Some(m) => Some(m.to_string()),
        None => None,
    };

    EventContext {
        tool_name,
        resource_path,
        method,
        event_type,
    }
}

/// Evaluate an event context against the policy rules (first match wins, sorted by priority).
fn evaluate(rules: &[PolicyRule], ctx: &EventContext) -> PolicyAction {
    for rule in rules {
        if rule.matches(ctx) {
            return rule.action.clone();
        }
    }
    PolicyAction::Log
}

/// Assert that a fixture produces the expected action string.
fn assert_fixture_action(fixture_name: &str, expected_name: &str) {
    let rules = load_default_policy();
    let fixture = load_fixture(fixture_name);
    let expected_str = load_expected_action(expected_name);

    let ctx = context_from_fixture(&fixture);
    let action = evaluate(&rules, &ctx);

    let action_str = match &action {
        PolicyAction::Allow => "allow",
        PolicyAction::Block => "block",
        PolicyAction::Prompt(_) => "prompt",
        PolicyAction::Log => "log",
    };

    assert_eq!(
        action_str, expected_str,
        "fixture {fixture_name}: expected {expected_str}, got {action_str} (context: {ctx:?})"
    );
}

#[test]
#[ignore = "full proxy pipeline not yet implemented"]
fn blocked_ssh_read() {
    assert_fixture_action("malicious_ssh_read.json", "malicious_ssh_read.expected");
}

#[test]
#[ignore = "full proxy pipeline not yet implemented"]
fn blocked_shell_exec() {
    assert_fixture_action("malicious_shell_exec.json", "malicious_shell_exec.expected");
}

#[test]
#[ignore = "full proxy pipeline not yet implemented"]
fn prompt_injection() {
    assert_fixture_action(
        "malicious_prompt_injection.json",
        "malicious_prompt_injection.expected",
    );
}

#[test]
#[ignore = "full proxy pipeline not yet implemented"]
fn benign_listing() {
    assert_fixture_action("benign_file_list.json", "benign_file_list.expected");
}

#[test]
#[ignore = "full proxy pipeline not yet implemented"]
fn benign_project_read() {
    assert_fixture_action("benign_tool_call.json", "benign_tool_call.expected");
}

/// Verify that the default policy TOML can be loaded and parsed without error.
#[test]
fn default_policy_loads() {
    let rules = load_default_policy();
    assert!(!rules.is_empty(), "default policy should have rules");
    // Verify rules are sorted by priority.
    for window in rules.windows(2) {
        assert!(
            window[0].priority <= window[1].priority,
            "rules should be sorted by priority: {} (pri={}) should come before {} (pri={})",
            window[0].name,
            window[0].priority,
            window[1].name,
            window[1].priority,
        );
    }
}

/// Verify that all fixture JSON files are valid JSON.
#[test]
fn all_fixtures_valid_json() {
    let fixtures_dir = workspace_root().join("tests/fixtures");
    for entry in std::fs::read_dir(&fixtures_dir).expect("failed to read fixtures dir") {
        let entry = entry.expect("failed to read dir entry");
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "json") {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            let _: serde_json::Value = serde_json::from_str(&content)
                .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()));
        }
    }
}

/// Verify that all .expected files contain a valid action string.
#[test]
fn all_expected_files_valid() {
    let fixtures_dir = workspace_root().join("tests/fixtures");
    let valid_actions = ["allow", "block", "prompt", "log"];
    for entry in std::fs::read_dir(&fixtures_dir).expect("failed to read fixtures dir") {
        let entry = entry.expect("failed to read dir entry");
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "expected") {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
                .trim()
                .to_string();
            assert!(
                valid_actions.contains(&content.as_str()),
                "{}: expected one of {:?}, got {:?}",
                path.display(),
                valid_actions,
                content
            );
        }
    }
}
