//! Policy rule definitions, TOML deserialization, and matching helpers.

pub use super::{MatchCriteria, PolicyAction, PolicyRule};

use super::matcher::{canonicalize_path, GlobMatcher};
use anyhow::{bail, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use tracing::warn;

/// Context extracted from an event for matching against policy rules.
/// This is the bridge between concrete event types and the generic matching logic.
#[derive(Debug, Clone, Default)]
pub struct EventContext {
    /// Tool name (for MCP tool calls).
    pub tool_name: Option<String>,
    /// Resource path or file path involved.
    pub resource_path: Option<String>,
    /// MCP method or OS event type string.
    pub method: Option<String>,
    /// Event type classification (e.g. "exec", "connect", "tool_call", "resource_read").
    pub event_type: Option<String>,
}

impl PolicyRule {
    /// Check if this rule matches the given event context.
    pub fn matches(&self, ctx: &EventContext) -> bool {
        let criteria = &self.match_criteria;

        // Catch-all rule.
        if criteria.any {
            return true;
        }

        // All specified criteria must match (AND logic).
        // If a criterion is None in the rule, it doesn't constrain.
        let mut has_any_criterion = false;

        if let Some(ref tool_names) = criteria.tool_names {
            has_any_criterion = true;
            if let Some(ref event_tool) = ctx.tool_name {
                if !tool_names.iter().any(|pat| pattern_matches(pat, event_tool)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(ref resource_paths) = criteria.resource_paths {
            has_any_criterion = true;
            if let Some(ref event_path) = ctx.resource_path {
                // Canonicalize the event path before matching to prevent
                // path traversal attacks (e.g., /project/../etc/passwd).
                let canonical = match canonicalize_path(event_path) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("path canonicalization failed for '{}': {e}, rejecting match", event_path);
                        return false;
                    }
                };
                if !resource_paths.iter().any(|pat| glob_matches(pat, &canonical)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(ref methods) = criteria.methods {
            has_any_criterion = true;
            if let Some(ref event_method) = ctx.method {
                if !methods.iter().any(|m| pattern_matches(m, event_method)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(ref event_types) = criteria.event_types {
            has_any_criterion = true;
            if let Some(ref event_type) = ctx.event_type {
                if !event_types.iter().any(|t| pattern_matches(t, event_type)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // If no criteria were specified at all, don't match.
        has_any_criterion
    }
}

/// Thread-local cache for compiled glob patterns to avoid recompilation on every evaluation.
mod glob_cache {
    use super::GlobMatcher;
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static CACHE: RefCell<HashMap<String, Option<GlobMatcher>>> = RefCell::new(HashMap::new());
    }

    /// Check if `value` matches the glob `pattern`, using a thread-local cache for
    /// compiled patterns.
    pub fn glob_matches_cached(pattern: &str, value: &str) -> bool {
        CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            let entry = cache.entry(pattern.to_string()).or_insert_with(|| {
                GlobMatcher::new(pattern).ok()
            });
            match entry {
                Some(matcher) => matcher.is_match(value),
                None => false,
            }
        })
    }
}

/// Simple pattern match: either glob or exact.
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
        glob_cache::glob_matches_cached(pattern, value)
    } else {
        pattern == value
    }
}

/// Glob match with tilde expansion for paths.
fn glob_matches(pattern: &str, value: &str) -> bool {
    glob_cache::glob_matches_cached(pattern, value)
}

// --- TOML deserialization support ---

/// Top-level TOML structure: `[rules.name]` sections.
#[derive(Debug, Deserialize)]
pub(crate) struct PolicyFile {
    #[serde(default)]
    pub rules: BTreeMap<String, RawRule>,
}

/// A single rule as it appears in the TOML file.
#[derive(Debug, Deserialize)]
pub(crate) struct RawRule {
    #[serde(default)]
    pub description: String,
    #[serde(rename = "match", default)]
    pub match_criteria: RawMatch,
    pub action: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub priority: Option<u32>,
}

/// The `[rules.name.match]` table in TOML.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawMatch {
    pub tool_name: Option<Vec<String>>,
    pub resource_path: Option<Vec<String>>,
    pub method: Option<Vec<String>>,
    pub event_type: Option<Vec<String>>,
    #[serde(default)]
    pub any: bool,
}

/// Parse a TOML string into a list of policy rules.
pub fn parse_policy_toml(content: &str) -> Result<Vec<PolicyRule>> {
    let file: PolicyFile = toml::from_str(content)
        .map_err(|e| anyhow::anyhow!("failed to parse policy TOML: {e}"))?;

    let mut rules = Vec::new();
    for (idx, (name, raw)) in file.rules.into_iter().enumerate() {
        let action = parse_action(&raw.action, &raw.message)
            .map_err(|e| anyhow::anyhow!("rule '{name}': {e}"))?;

        // Validate glob/regex patterns upfront.
        if let Some(ref paths) = raw.match_criteria.resource_path {
            for p in paths {
                GlobMatcher::new(p)?;
            }
        }

        let rule = PolicyRule {
            name,
            description: raw.description,
            match_criteria: MatchCriteria {
                tool_names: raw.match_criteria.tool_name,
                resource_paths: raw.match_criteria.resource_path,
                methods: raw.match_criteria.method,
                event_types: raw.match_criteria.event_type,
                any: raw.match_criteria.any,
            },
            action,
            message: raw.message,
            priority: raw.priority.unwrap_or(idx as u32),
        };
        rules.push(rule);
    }

    // Sort by priority (lower first).
    rules.sort_by_key(|r| r.priority);
    Ok(rules)
}

fn parse_action(action_str: &str, message: &str) -> Result<PolicyAction> {
    match action_str {
        "allow" => Ok(PolicyAction::Allow),
        "block" => Ok(PolicyAction::Block),
        "prompt" => Ok(PolicyAction::Prompt(message.to_string())),
        "log" => Ok(PolicyAction::Log),
        other => bail!("unknown action '{other}', expected allow/block/prompt/log"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(criteria: MatchCriteria, action: PolicyAction) -> PolicyRule {
        PolicyRule {
            name: "test".to_string(),
            description: "test rule".to_string(),
            match_criteria: criteria,
            action,
            message: "test message".to_string(),
            priority: 0,
        }
    }

    #[test]
    fn any_matches_everything() {
        let rule = make_rule(
            MatchCriteria { any: true, ..Default::default() },
            PolicyAction::Log,
        );
        let ctx = EventContext::default();
        assert!(rule.matches(&ctx));
    }

    #[test]
    fn tool_name_exact_match() {
        let rule = make_rule(
            MatchCriteria {
                tool_names: Some(vec!["shell_exec".to_string()]),
                ..Default::default()
            },
            PolicyAction::Block,
        );
        let ctx = EventContext {
            tool_name: Some("shell_exec".to_string()),
            ..Default::default()
        };
        assert!(rule.matches(&ctx));

        let ctx2 = EventContext {
            tool_name: Some("file_read".to_string()),
            ..Default::default()
        };
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn resource_path_glob_match() {
        std::env::set_var("HOME", "/Users/testuser");
        let rule = make_rule(
            MatchCriteria {
                resource_paths: Some(vec!["~/.ssh/id_*".to_string()]),
                ..Default::default()
            },
            PolicyAction::Block,
        );
        let ctx = EventContext {
            resource_path: Some("/Users/testuser/.ssh/id_rsa".to_string()),
            ..Default::default()
        };
        assert!(rule.matches(&ctx));

        let ctx2 = EventContext {
            resource_path: Some("/Users/testuser/.ssh/config".to_string()),
            ..Default::default()
        };
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn no_criteria_does_not_match() {
        let rule = make_rule(MatchCriteria::default(), PolicyAction::Log);
        let ctx = EventContext {
            tool_name: Some("anything".to_string()),
            ..Default::default()
        };
        assert!(!rule.matches(&ctx));
    }

    #[test]
    fn parse_valid_toml() {
        let toml = r#"
[rules.block_ssh]
description = "Block SSH key access"
action = "block"
message = "SSH key access is blocked"
priority = 0

[rules.block_ssh.match]
resource_path = ["~/.ssh/id_*"]

[rules.allow_project]
description = "Allow project reads"
action = "allow"
message = "Allowed"
priority = 1

[rules.allow_project.match]
resource_path = ["/project/**"]
"#;
        let rules = parse_policy_toml(toml).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "block_ssh");
        assert_eq!(rules[0].action, PolicyAction::Block);
        assert_eq!(rules[1].name, "allow_project");
        assert_eq!(rules[1].action, PolicyAction::Allow);
    }

    #[test]
    fn parse_invalid_action() {
        let toml = r#"
[rules.bad]
description = "Bad rule"
action = "explode"
message = "boom"

[rules.bad.match]
any = true
"#;
        let result = parse_policy_toml(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown action"));
    }

    #[test]
    fn parse_invalid_glob() {
        let toml = r#"
[rules.bad_glob]
description = "Bad glob"
action = "block"
message = "bad"

[rules.bad_glob.match]
resource_path = ["[invalid"]
"#;
        let result = parse_policy_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_malformed_toml() {
        let result = parse_policy_toml("this is not valid toml {{{{");
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_policy() {
        let rules = parse_policy_toml("").unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_prompt_action() {
        let toml = r#"
[rules.prompt_exec]
description = "Prompt on exec"
action = "prompt"
message = "Allow execution?"

[rules.prompt_exec.match]
event_type = ["exec"]
"#;
        let rules = parse_policy_toml(toml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].action,
            PolicyAction::Prompt("Allow execution?".to_string())
        );
    }
}
