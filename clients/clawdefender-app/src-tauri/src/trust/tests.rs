use super::generator::*;
use super::levels::*;
use super::permissions::*;
use super::reader::*;
use crate::state::PolicyRule;

// --- Rule Generation Tests ---

#[test]
fn test_generate_trusted_rules() {
    let rules = generate_trust_rules("filesystem-server", TrustLevel::Trusted);
    // 7 permissions: tool-call, file-read-project, file-read-external, file-write, shell-exec, network-access, sensitive-paths
    assert_eq!(rules.len(), 7, "Trusted should have 7 rules");

    let tool_call = rules.iter().find(|r| r.name.ends_with(".tool-call")).unwrap();
    assert_eq!(tool_call.action, "allow");
    assert!(tool_call.priority >= 200 && tool_call.priority < 300);

    let file_write = rules.iter().find(|r| r.name.ends_with(".file-write")).unwrap();
    assert_eq!(file_write.action, "allow");

    let shell = rules.iter().find(|r| r.name.ends_with(".shell-exec")).unwrap();
    assert_eq!(shell.action, "prompt");

    let network = rules.iter().find(|r| r.name.ends_with(".network-access")).unwrap();
    assert_eq!(network.action, "allow");

    let sensitive = rules.iter().find(|r| r.name.ends_with(".sensitive-paths")).unwrap();
    assert_eq!(sensitive.action, "block");
    assert_eq!(sensitive.priority, 999);
}

#[test]
fn test_generate_standard_rules() {
    let rules = generate_trust_rules("my-server", TrustLevel::Standard);
    assert_eq!(rules.len(), 7);

    let tool_call = rules.iter().find(|r| r.name.ends_with(".tool-call")).unwrap();
    assert_eq!(tool_call.action, "prompt");
    assert!(tool_call.priority >= 300 && tool_call.priority < 400);

    let read_project = rules.iter().find(|r| r.name.ends_with(".file-read-project")).unwrap();
    assert_eq!(read_project.action, "allow");

    let read_ext = rules.iter().find(|r| r.name.ends_with(".file-read-external")).unwrap();
    assert_eq!(read_ext.action, "prompt");

    let write = rules.iter().find(|r| r.name.ends_with(".file-write")).unwrap();
    assert_eq!(write.action, "prompt");

    let shell = rules.iter().find(|r| r.name.ends_with(".shell-exec")).unwrap();
    assert_eq!(shell.action, "prompt");

    let net = rules.iter().find(|r| r.name.ends_with(".network-access")).unwrap();
    assert_eq!(net.action, "prompt");
}

#[test]
fn test_generate_cautious_rules() {
    let rules = generate_trust_rules("my-server", TrustLevel::Cautious);
    assert_eq!(rules.len(), 7);

    let write = rules.iter().find(|r| r.name.ends_with(".file-write")).unwrap();
    assert_eq!(write.action, "block");

    let shell = rules.iter().find(|r| r.name.ends_with(".shell-exec")).unwrap();
    assert_eq!(shell.action, "block");

    let net = rules.iter().find(|r| r.name.ends_with(".network-access")).unwrap();
    assert_eq!(net.action, "prompt");

    let read_project = rules.iter().find(|r| r.name.ends_with(".file-read-project")).unwrap();
    assert_eq!(read_project.action, "allow");
}

#[test]
fn test_generate_restricted_rules() {
    let rules = generate_trust_rules("my-server", TrustLevel::Restricted);
    // Restricted has 8 rules: 7 standard + tool-call-list-only companion
    assert_eq!(rules.len(), 8, "Restricted should have 8 rules (includes list-only)");

    let tool_call = rules.iter().find(|r| r.name.ends_with(".tool-call") && !r.name.contains("list-only")).unwrap();
    assert_eq!(tool_call.action, "block");

    let list_only = rules.iter().find(|r| r.name.ends_with(".tool-call-list-only")).unwrap();
    assert_eq!(list_only.action, "allow");
    assert!(list_only.priority > tool_call.priority);

    let read_project = rules.iter().find(|r| r.name.ends_with(".file-read-project")).unwrap();
    assert_eq!(read_project.action, "prompt");

    let read_ext = rules.iter().find(|r| r.name.ends_with(".file-read-external")).unwrap();
    assert_eq!(read_ext.action, "block");

    let write = rules.iter().find(|r| r.name.ends_with(".file-write")).unwrap();
    assert_eq!(write.action, "block");

    let shell = rules.iter().find(|r| r.name.ends_with(".shell-exec")).unwrap();
    assert_eq!(shell.action, "block");

    let net = rules.iter().find(|r| r.name.ends_with(".network-access")).unwrap();
    assert_eq!(net.action, "block");
}

#[test]
fn test_sensitive_paths_always_block() {
    for level in &[TrustLevel::Trusted, TrustLevel::Standard, TrustLevel::Cautious, TrustLevel::Restricted] {
        let rules = generate_trust_rules("test-server", *level);
        let sensitive = rules.iter().find(|r| r.name.ends_with(".sensitive-paths")).unwrap();
        assert_eq!(sensitive.action, "block", "Sensitive paths must always be block for {:?}", level);
        assert_eq!(sensitive.priority, 999);
    }
}

#[test]
fn test_custom_level_generates_standard() {
    let custom_rules = generate_trust_rules("server", TrustLevel::Custom);
    let standard_rules = generate_trust_rules("server", TrustLevel::Standard);
    assert_eq!(custom_rules.len(), standard_rules.len());
    for (c, s) in custom_rules.iter().zip(standard_rules.iter()) {
        assert_eq!(c.name, s.name);
        assert_eq!(c.action, s.action);
    }
}

// --- Rule Key Tests ---

#[test]
fn test_trust_rule_key() {
    assert_eq!(
        trust_rule_key("filesystem-server", "tool-call"),
        "trust.filesystem-server.tool-call"
    );
}

#[test]
fn test_sanitize_server_name() {
    assert_eq!(sanitize_server_name("My Server"), "my-server");
    assert_eq!(sanitize_server_name("  Filesystem Server  "), "filesystem-server");
    assert_eq!(sanitize_server_name("test@server!"), "testserver");
    assert_eq!(sanitize_server_name("under_score"), "under_score");
}

#[test]
fn test_rule_names_are_namespaced() {
    let rules = generate_trust_rules("my-tool", TrustLevel::Standard);
    for rule in &rules {
        assert!(
            rule.name.starts_with("trust.my-tool."),
            "Rule '{}' should start with 'trust.my-tool.'",
            rule.name
        );
    }
}

// --- Trust Level Inference Tests ---

#[test]
fn test_infer_no_rules_returns_standard() {
    let (level, customized) = infer_trust_level("unknown-server", &[]);
    assert_eq!(level, TrustLevel::Standard);
    assert!(!customized);
}

#[test]
fn test_infer_trusted() {
    let rules = generate_trust_rules("my-server", TrustLevel::Trusted);
    let (level, customized) = infer_trust_level("my-server", &rules);
    assert_eq!(level, TrustLevel::Trusted);
    assert!(!customized);
}

#[test]
fn test_infer_standard() {
    let rules = generate_trust_rules("my-server", TrustLevel::Standard);
    let (level, customized) = infer_trust_level("my-server", &rules);
    assert_eq!(level, TrustLevel::Standard);
    assert!(!customized);
}

#[test]
fn test_infer_cautious() {
    let rules = generate_trust_rules("my-server", TrustLevel::Cautious);
    let (level, customized) = infer_trust_level("my-server", &rules);
    assert_eq!(level, TrustLevel::Cautious);
    assert!(!customized);
}

#[test]
fn test_infer_restricted() {
    let rules = generate_trust_rules("my-server", TrustLevel::Restricted);
    let (level, customized) = infer_trust_level("my-server", &rules);
    assert_eq!(level, TrustLevel::Restricted);
    assert!(!customized);
}

#[test]
fn test_infer_customized_when_action_modified() {
    let mut rules = generate_trust_rules("my-server", TrustLevel::Standard);
    // Modify one rule's action
    if let Some(r) = rules.iter_mut().find(|r| r.name.ends_with(".file-write")) {
        r.action = "allow".to_string(); // Changed from prompt to allow
    }
    let (level, customized) = infer_trust_level("my-server", &rules);
    assert_eq!(level, TrustLevel::Standard);
    assert!(customized, "Should detect customization when action differs");
}

#[test]
fn test_infer_ignores_other_server_rules() {
    let rules_a = generate_trust_rules("server-a", TrustLevel::Trusted);
    let rules_b = generate_trust_rules("server-b", TrustLevel::Restricted);
    let all_rules: Vec<PolicyRule> = rules_a.into_iter().chain(rules_b.into_iter()).collect();

    let (level_a, _) = infer_trust_level("server-a", &all_rules);
    let (level_b, _) = infer_trust_level("server-b", &all_rules);

    assert_eq!(level_a, TrustLevel::Trusted);
    assert_eq!(level_b, TrustLevel::Restricted);
}

// --- TrustLevelInfo Builder Tests ---

#[test]
fn test_build_trust_level_info_standard() {
    let rules = generate_trust_rules("test-server", TrustLevel::Standard);
    let info = build_trust_level_info("test-server", &rules);
    assert_eq!(info.level, "standard");
    assert!(!info.customized);
    assert_eq!(info.permissions.len(), 7);

    let sensitive = info.permissions.iter().find(|p| p.id == "sensitive_paths").unwrap();
    assert!(sensitive.locked);
    assert_eq!(sensitive.action, "block");
    assert!(!sensitive.overridden);
}

#[test]
fn test_build_trust_level_info_with_override() {
    let mut rules = generate_trust_rules("test-server", TrustLevel::Standard);
    if let Some(r) = rules.iter_mut().find(|r| r.name.ends_with(".file-write")) {
        r.action = "block".to_string();
    }
    let info = build_trust_level_info("test-server", &rules);
    assert_eq!(info.level, "standard");
    assert!(info.customized);

    let fw = info.permissions.iter().find(|p| p.id == "file_write").unwrap();
    assert_eq!(fw.action, "block");
    assert!(fw.overridden);
}

// --- Preview Trust Change Tests ---

#[test]
fn test_preview_standard_to_trusted() {
    let rules = generate_trust_rules("srv", TrustLevel::Standard);
    let changes = preview_trust_change("srv", &rules, TrustLevel::Trusted);

    // Standard -> Trusted changes: tool-call (prompt->allow), file-read-external (prompt->allow),
    // file-write (prompt->allow), network-access (prompt->allow)
    // shell-exec stays prompt, file-read-project stays allow
    assert!(!changes.is_empty());
    assert!(changes.iter().any(|c| c.permission == "tool_call" && c.to_action == "allow"));
    assert!(changes.iter().any(|c| c.permission == "file_write" && c.to_action == "allow"));
    assert!(changes.iter().any(|c| c.permission == "network_access" && c.to_action == "allow"));

    // Shell exec is prompt in both, should NOT appear
    assert!(!changes.iter().any(|c| c.permission == "shell_exec"));
}

#[test]
fn test_preview_standard_to_restricted() {
    let rules = generate_trust_rules("srv", TrustLevel::Standard);
    let changes = preview_trust_change("srv", &rules, TrustLevel::Restricted);

    assert!(changes.iter().any(|c| c.permission == "tool_call" && c.from_action == "prompt" && c.to_action == "block"));
    assert!(changes.iter().any(|c| c.permission == "file_read_project" && c.from_action == "allow" && c.to_action == "prompt"));
    assert!(changes.iter().any(|c| c.permission == "file_write" && c.from_action == "prompt" && c.to_action == "block"));
}

#[test]
fn test_preview_same_level_no_changes() {
    let rules = generate_trust_rules("srv", TrustLevel::Cautious);
    let changes = preview_trust_change("srv", &rules, TrustLevel::Cautious);
    assert!(changes.is_empty(), "Same level should produce no changes");
}

#[test]
fn test_preview_never_includes_sensitive_paths() {
    let rules = generate_trust_rules("srv", TrustLevel::Trusted);
    let changes = preview_trust_change("srv", &rules, TrustLevel::Restricted);
    assert!(
        !changes.iter().any(|c| c.permission == "sensitive_paths"),
        "Sensitive paths should never appear in change preview"
    );
}

// --- Multiple Server Isolation ---

#[test]
fn test_multiple_servers_independent() {
    let rules_a = generate_trust_rules("alpha", TrustLevel::Trusted);
    let rules_b = generate_trust_rules("beta", TrustLevel::Restricted);

    let combined: Vec<PolicyRule> = rules_a.into_iter().chain(rules_b).collect();

    let info_a = build_trust_level_info("alpha", &combined);
    let info_b = build_trust_level_info("beta", &combined);

    assert_eq!(info_a.level, "trusted");
    assert_eq!(info_b.level, "restricted");
    assert!(!info_a.customized);
    assert!(!info_b.customized);
}

// --- Permission Tests ---

#[test]
fn test_permission_category_round_trip() {
    for perm in Permission::all() {
        let category = perm.category();
        let parsed = Permission::from_category(category).unwrap();
        assert_eq!(*perm, parsed);
    }
}

#[test]
fn test_permission_frontend_id_round_trip() {
    for perm in Permission::all() {
        let id = perm.frontend_id();
        let parsed = Permission::from_frontend_id(id).unwrap();
        assert_eq!(*perm, parsed);
    }
}

#[test]
fn test_sensitive_paths_is_locked() {
    assert!(Permission::SensitivePaths.is_locked());
    for perm in Permission::configurable() {
        assert!(!perm.is_locked());
    }
}

// --- Trust Level Parsing ---

#[test]
fn test_trust_level_from_str() {
    assert_eq!(TrustLevel::from_str_loose("trusted"), Some(TrustLevel::Trusted));
    assert_eq!(TrustLevel::from_str_loose("STANDARD"), Some(TrustLevel::Standard));
    assert_eq!(TrustLevel::from_str_loose("Cautious"), Some(TrustLevel::Cautious));
    assert_eq!(TrustLevel::from_str_loose("restricted"), Some(TrustLevel::Restricted));
    assert_eq!(TrustLevel::from_str_loose("custom"), Some(TrustLevel::Custom));
    assert_eq!(TrustLevel::from_str_loose("invalid"), None);
}

// --- TOML Generation Tests ---

#[test]
fn test_trust_rule_to_toml_has_match_section() {
    let rules = generate_trust_rules("test-srv", TrustLevel::Standard);
    let tool_call = rules.iter().find(|r| r.name.ends_with(".tool-call")).unwrap();
    let toml_val = trust_rule_to_toml(tool_call, "test-srv", Permission::ToolCall);

    let table = toml_val.as_table().unwrap();
    assert!(table.contains_key("match"));
    assert!(table.contains_key("action"));
    assert!(table.contains_key("priority"));
    assert!(table.contains_key("description"));
    assert!(table.contains_key("enabled"));

    let match_section = table.get("match").unwrap().as_table().unwrap();
    assert!(match_section.contains_key("server_name"));
    assert!(match_section.contains_key("event_type"));
}

#[test]
fn test_restricted_list_only_toml() {
    let toml_val = restricted_list_only_toml("my-srv", 501);
    let table = toml_val.as_table().unwrap();
    assert_eq!(table.get("action").unwrap().as_str().unwrap(), "allow");

    let match_section = table.get("match").unwrap().as_table().unwrap();
    assert!(match_section.contains_key("tool_name"));
    let tool_names = match_section.get("tool_name").unwrap().as_array().unwrap();
    assert_eq!(tool_names[0].as_str().unwrap(), "list_*");
}
