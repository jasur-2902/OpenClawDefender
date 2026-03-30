use crate::state::PolicyRule;
use super::levels::TrustLevel;
use super::permissions::{Permission, canonical_action};

/// Sensitive path globs that are always blocked regardless of trust level.
const SENSITIVE_PATHS: &[&str] = &[
    "**/.ssh/**",
    "**/.aws/credentials",
    "**/.env*",
    "**/.gnupg/**",
    "**/id_rsa",
    "**/id_ed25519",
];

/// Sanitize a server name for use in rule keys.
/// Lowercase, spaces to hyphens, only alphanumeric + hyphens + underscores.
pub fn sanitize_server_name(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .replace(' ', "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// Build a trust rule key: `trust.{server_name}.{category}`.
/// Dots are preserved (unlike the existing sanitize_rule_key which strips them).
pub fn trust_rule_key(server_name: &str, category: &str) -> String {
    let sanitized = sanitize_server_name(server_name);
    format!("trust.{}.{}", sanitized, category)
}

/// Generate all trust-level policy rules for a server.
/// The `Custom` level cannot be generated — it represents rules that were manually modified.
pub fn generate_trust_rules(server_name: &str, level: TrustLevel) -> Vec<PolicyRule> {
    let level = if level == TrustLevel::Custom {
        TrustLevel::Standard
    } else {
        level
    };

    let base = level.base_priority();
    let sanitized = sanitize_server_name(server_name);
    let mut rules = Vec::new();

    // Tool call rule
    rules.push(make_rule(
        &sanitized,
        Permission::ToolCall,
        canonical_action(level, Permission::ToolCall),
        base,
        &description_for(level, Permission::ToolCall),
        &message_for(level, Permission::ToolCall),
        server_name,
    ));

    // For restricted level, add the companion list_* allow rule
    if level == TrustLevel::Restricted {
        rules.push(PolicyRule {
            name: trust_rule_key(server_name, "tool-call-list-only"),
            description: "Trust level: allow list_* tools in restricted mode".to_string(),
            action: "allow".to_string(),
            resource: "*".to_string(),
            pattern: format!("server_name={},event_type=tools/call,tool_name=list_*", sanitized),
            priority: base + 1,
            enabled: true,
        });
    }

    // File read project
    let offset = if level == TrustLevel::Restricted { 2 } else { 1 };
    rules.push(make_rule(
        &sanitized,
        Permission::FileReadProject,
        canonical_action(level, Permission::FileReadProject),
        base + offset,
        &description_for(level, Permission::FileReadProject),
        &message_for(level, Permission::FileReadProject),
        server_name,
    ));

    // File read external
    rules.push(make_rule(
        &sanitized,
        Permission::FileReadExternal,
        canonical_action(level, Permission::FileReadExternal),
        base + offset + 1,
        &description_for(level, Permission::FileReadExternal),
        &message_for(level, Permission::FileReadExternal),
        server_name,
    ));

    // File write
    rules.push(make_rule(
        &sanitized,
        Permission::FileWrite,
        canonical_action(level, Permission::FileWrite),
        base + offset + 2,
        &description_for(level, Permission::FileWrite),
        &message_for(level, Permission::FileWrite),
        server_name,
    ));

    // Shell exec
    rules.push(make_rule(
        &sanitized,
        Permission::ShellExec,
        canonical_action(level, Permission::ShellExec),
        base + offset + 3,
        &description_for(level, Permission::ShellExec),
        &message_for(level, Permission::ShellExec),
        server_name,
    ));

    // Network access
    rules.push(make_rule(
        &sanitized,
        Permission::NetworkAccess,
        canonical_action(level, Permission::NetworkAccess),
        base + offset + 4,
        &description_for(level, Permission::NetworkAccess),
        &message_for(level, Permission::NetworkAccess),
        server_name,
    ));

    // Sensitive paths — always block at priority 999
    rules.push(PolicyRule {
        name: trust_rule_key(server_name, "sensitive-paths"),
        description: "Block access to sensitive paths (always enforced)".to_string(),
        action: "block".to_string(),
        resource: "file".to_string(),
        pattern: SENSITIVE_PATHS.join(","),
        priority: 999,
        enabled: true,
    });

    rules
}

fn make_rule(
    sanitized_server: &str,
    perm: Permission,
    action: &str,
    priority: i32,
    description: &str,
    message: &str,
    raw_server_name: &str,
) -> PolicyRule {
    let (resource, pattern) = match perm {
        Permission::ToolCall => (
            "*".to_string(),
            format!("server_name={},event_type=tools/call", sanitized_server),
        ),
        Permission::FileReadProject => (
            "file".to_string(),
            format!("server_name={},resource_path={{project_dir}}/**", sanitized_server),
        ),
        Permission::FileReadExternal => (
            "file".to_string(),
            format!("server_name={},resource_path=**", sanitized_server),
        ),
        Permission::FileWrite => (
            "file".to_string(),
            format!("server_name={},event_type=file_write,file_create", sanitized_server),
        ),
        Permission::ShellExec => (
            "*".to_string(),
            format!("server_name={},event_type=exec", sanitized_server),
        ),
        Permission::NetworkAccess => (
            "network".to_string(),
            format!("server_name={},event_type=connect", sanitized_server),
        ),
        Permission::SensitivePaths => (
            "file".to_string(),
            SENSITIVE_PATHS.join(","),
        ),
    };

    let mut desc = description.to_string();
    if !message.is_empty() && action == "prompt" {
        // Prompt messages are stored in the pattern metadata, not the description
    }
    let _ = &mut desc; // suppress unused

    PolicyRule {
        name: trust_rule_key(raw_server_name, perm.category()),
        description: description.to_string(),
        action: action.to_string(),
        resource,
        pattern,
        priority,
        enabled: true,
    }
}

fn description_for(level: TrustLevel, perm: Permission) -> String {
    let action = canonical_action(level, perm);
    match perm {
        Permission::ToolCall => match level {
            TrustLevel::Trusted => "Trust level: allow all tool calls".to_string(),
            TrustLevel::Standard => "Trust level: allow known tools, prompt unknown".to_string(),
            TrustLevel::Cautious => "Trust level: prompt before most tool calls".to_string(),
            TrustLevel::Restricted => "Trust level: block most tool calls, allow list_* only".to_string(),
            _ => format!("Trust level: {} tool calls", action),
        },
        Permission::FileReadProject => match action {
            "allow" => "Trust level: allow reading files in project directory".to_string(),
            "prompt" => "Trust level: prompt before reading project files".to_string(),
            _ => format!("Trust level: {} reading project files", action),
        },
        Permission::FileReadExternal => match action {
            "allow" => "Trust level: allow reading files outside project".to_string(),
            "prompt" => "Trust level: prompt before reading files outside project".to_string(),
            "block" => "Trust level: block reading files outside project".to_string(),
            _ => format!("Trust level: {} reading external files", action),
        },
        Permission::FileWrite => match action {
            "allow" => "Trust level: allow writing files".to_string(),
            "prompt" => "Trust level: prompt before writing files".to_string(),
            "block" => "Trust level: block file writes".to_string(),
            _ => format!("Trust level: {} file writes", action),
        },
        Permission::ShellExec => match action {
            "prompt" => "Trust level: prompt before shell execution".to_string(),
            "block" => "Trust level: block shell execution".to_string(),
            _ => format!("Trust level: {} shell execution", action),
        },
        Permission::NetworkAccess => match action {
            "allow" => "Trust level: allow network access".to_string(),
            "prompt" => "Trust level: prompt before network access".to_string(),
            "block" => "Trust level: block network access".to_string(),
            _ => format!("Trust level: {} network access", action),
        },
        Permission::SensitivePaths => "Block access to sensitive paths (always enforced)".to_string(),
    }
}

fn message_for(level: TrustLevel, perm: Permission) -> String {
    let action = canonical_action(level, perm);
    if action != "prompt" {
        return String::new();
    }
    match perm {
        Permission::ToolCall => match level {
            TrustLevel::Standard => "This tool wants to perform an action. Allow?".to_string(),
            TrustLevel::Cautious => "This tool is trying to perform an action. Review carefully.".to_string(),
            _ => "Allow this tool call?".to_string(),
        },
        Permission::FileReadProject => "This restricted tool wants to read a project file. Allow?".to_string(),
        Permission::FileReadExternal => match level {
            TrustLevel::Cautious => "This tool wants to read a file outside your project. It is in cautious mode.".to_string(),
            _ => "This tool wants to read a file outside your project. Allow?".to_string(),
        },
        Permission::FileWrite => "This tool wants to write a file. Allow?".to_string(),
        Permission::ShellExec => match level {
            TrustLevel::Trusted => "This trusted tool wants to run a command. Allow?".to_string(),
            _ => "This tool wants to run a command. Allow?".to_string(),
        },
        Permission::NetworkAccess => match level {
            TrustLevel::Cautious => "This cautious-mode tool wants to access the network. Allow?".to_string(),
            _ => "This tool wants to access the network. Allow?".to_string(),
        },
        _ => String::new(),
    }
}

/// Build a TOML table for a trust rule, with full match section.
/// This produces the rich TOML structure that the daemon expects,
/// unlike the simpler policy_rule_to_toml_table used for user-created rules.
pub fn trust_rule_to_toml(rule: &PolicyRule, server_name: &str, perm: Permission) -> toml::Value {
    let sanitized = sanitize_server_name(server_name);
    let mut table = toml::map::Map::new();

    table.insert("description".to_string(), toml::Value::String(rule.description.clone()));
    table.insert("action".to_string(), toml::Value::String(rule.action.clone()));
    table.insert("priority".to_string(), toml::Value::Integer(rule.priority as i64));
    table.insert("enabled".to_string(), toml::Value::Boolean(rule.enabled));

    // Add prompt message if action is prompt
    if rule.action == "prompt" {
        let msg = message_for(
            TrustLevel::Standard, // message varies, but we use the rule desc context
            perm,
        );
        if !msg.is_empty() {
            table.insert("message".to_string(), toml::Value::String(msg));
        }
    }

    let mut match_table = toml::map::Map::new();
    match_table.insert(
        "server_name".to_string(),
        toml::Value::Array(vec![toml::Value::String(sanitized.clone())]),
    );

    match perm {
        Permission::ToolCall => {
            match_table.insert(
                "event_type".to_string(),
                toml::Value::Array(vec![toml::Value::String("tools/call".to_string())]),
            );
        }
        Permission::FileReadProject => {
            match_table.insert(
                "resource_path".to_string(),
                toml::Value::Array(vec![toml::Value::String("{project_dir}/**".to_string())]),
            );
        }
        Permission::FileReadExternal => {
            match_table.insert(
                "resource_path".to_string(),
                toml::Value::Array(vec![toml::Value::String("**".to_string())]),
            );
        }
        Permission::FileWrite => {
            match_table.insert(
                "event_type".to_string(),
                toml::Value::Array(vec![
                    toml::Value::String("file_write".to_string()),
                    toml::Value::String("file_create".to_string()),
                ]),
            );
        }
        Permission::ShellExec => {
            match_table.insert(
                "event_type".to_string(),
                toml::Value::Array(vec![toml::Value::String("exec".to_string())]),
            );
        }
        Permission::NetworkAccess => {
            match_table.insert(
                "event_type".to_string(),
                toml::Value::Array(vec![toml::Value::String("connect".to_string())]),
            );
        }
        Permission::SensitivePaths => {
            match_table.insert(
                "resource_path".to_string(),
                toml::Value::Array(
                    SENSITIVE_PATHS.iter().map(|p| toml::Value::String(p.to_string())).collect(),
                ),
            );
        }
    }

    table.insert("match".to_string(), toml::Value::Table(match_table));
    toml::Value::Table(table)
}

/// Build a TOML table for the restricted-mode list-only companion rule.
pub fn restricted_list_only_toml(server_name: &str, priority: i32) -> toml::Value {
    let sanitized = sanitize_server_name(server_name);
    let mut table = toml::map::Map::new();

    table.insert("description".to_string(), toml::Value::String(
        "Trust level: allow list_* tools in restricted mode".to_string(),
    ));
    table.insert("action".to_string(), toml::Value::String("allow".to_string()));
    table.insert("priority".to_string(), toml::Value::Integer(priority as i64));
    table.insert("enabled".to_string(), toml::Value::Boolean(true));

    let mut match_table = toml::map::Map::new();
    match_table.insert(
        "server_name".to_string(),
        toml::Value::Array(vec![toml::Value::String(sanitized)]),
    );
    match_table.insert(
        "event_type".to_string(),
        toml::Value::Array(vec![toml::Value::String("tools/call".to_string())]),
    );
    match_table.insert(
        "tool_name".to_string(),
        toml::Value::Array(vec![toml::Value::String("list_*".to_string())]),
    );

    table.insert("match".to_string(), toml::Value::Table(match_table));
    toml::Value::Table(table)
}
