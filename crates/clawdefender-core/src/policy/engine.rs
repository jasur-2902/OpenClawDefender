//! Policy evaluation engine.
//!
//! The [`DefaultPolicyEngine`] loads rules from a TOML file and evaluates
//! incoming events against them. First match wins; if nothing matches, the
//! default action is [`PolicyAction::Log`].

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{debug, warn};

use super::rule::{parse_policy_toml, EventContext};
use super::{PolicyAction, PolicyEngine, PolicyRule};
use crate::event::mcp::{McpEvent, McpEventKind};
use crate::event::os::{OsEvent, OsEventKind};
use crate::event::Event;

/// Default policy engine implementation that loads rules from TOML.
pub struct DefaultPolicyEngine {
    /// Path to the on-disk TOML policy file.
    policy_path: PathBuf,
    /// Session-only rules (prepended, highest priority).
    session_rules: Vec<PolicyRule>,
    /// Persistent rules loaded from the TOML file.
    file_rules: Vec<PolicyRule>,
}

impl DefaultPolicyEngine {
    /// Load a policy engine from a TOML file at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path.display()))?;
        let file_rules = parse_policy_toml(&content)?;
        debug!("loaded {} policy rules from {}", file_rules.len(), path.display());
        Ok(Self {
            policy_path: path.to_path_buf(),
            session_rules: Vec::new(),
            file_rules,
        })
    }

    /// Create an empty policy engine with no rules (useful for testing).
    pub fn empty() -> Self {
        Self {
            policy_path: PathBuf::new(),
            session_rules: Vec::new(),
            file_rules: Vec::new(),
        }
    }

    /// Extract an [`EventContext`] from a concrete event for matching.
    fn extract_context(event: &dyn Event) -> EventContext {
        let any = event.as_any();

        if let Some(mcp) = any.downcast_ref::<McpEvent>() {
            return Self::mcp_context(mcp);
        }
        if let Some(os) = any.downcast_ref::<OsEvent>() {
            return Self::os_context(os);
        }

        // Fallback: no specific context extractable.
        warn!("unknown event type from source '{}', no context extracted", event.source());
        EventContext::default()
    }

    fn mcp_context(event: &McpEvent) -> EventContext {
        match &event.kind {
            McpEventKind::ToolCall(tc) => EventContext {
                tool_name: Some(tc.tool_name.clone()),
                resource_path: Self::extract_path_from_arguments(&tc.arguments),
                method: Some("tools/call".to_string()),
                event_type: Some("tool_call".to_string()),
            },
            McpEventKind::ResourceRead(rr) => EventContext {
                tool_name: None,
                resource_path: Some(rr.uri.clone()),
                method: Some("resources/read".to_string()),
                event_type: Some("resource_read".to_string()),
            },
            McpEventKind::SamplingRequest(_) => EventContext {
                tool_name: None,
                resource_path: None,
                method: Some("sampling/createMessage".to_string()),
                event_type: Some("sampling".to_string()),
            },
            McpEventKind::ListRequest => EventContext {
                tool_name: None,
                resource_path: None,
                method: None,
                event_type: Some("list".to_string()),
            },
            McpEventKind::Notification(n) => EventContext {
                tool_name: None,
                resource_path: None,
                method: Some(n.clone()),
                event_type: Some("notification".to_string()),
            },
            McpEventKind::Other(m) => EventContext {
                tool_name: None,
                resource_path: None,
                method: Some(m.clone()),
                event_type: Some("other".to_string()),
            },
        }
    }

    /// Extract a file path from tool call arguments.
    ///
    /// MCP filesystem tools (read_file, write_file, etc.) pass paths in
    /// arguments like `path`, `file_path`, `filename`, `file`, or `directory`.
    /// We extract the first match so `resource_path` policy rules work for
    /// tool calls, not just `resources/read` events.
    fn extract_path_from_arguments(arguments: &serde_json::Value) -> Option<String> {
        const PATH_KEYS: &[&str] = &["path", "file_path", "filepath", "filename", "file", "directory"];
        let obj = arguments.as_object()?;
        for key in PATH_KEYS {
            if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
        None
    }

    fn os_context(event: &OsEvent) -> EventContext {
        match &event.kind {
            OsEventKind::Exec { target_path, .. } => EventContext {
                tool_name: None,
                resource_path: Some(target_path.clone()),
                method: None,
                event_type: Some("exec".to_string()),
            },
            OsEventKind::Open { path, .. } => EventContext {
                tool_name: None,
                resource_path: Some(path.clone()),
                method: None,
                event_type: Some("open".to_string()),
            },
            OsEventKind::Close { path } => EventContext {
                tool_name: None,
                resource_path: Some(path.clone()),
                method: None,
                event_type: Some("close".to_string()),
            },
            OsEventKind::Rename { source, .. } => EventContext {
                tool_name: None,
                resource_path: Some(source.clone()),
                method: None,
                event_type: Some("rename".to_string()),
            },
            OsEventKind::Unlink { path } => EventContext {
                tool_name: None,
                resource_path: Some(path.clone()),
                method: None,
                event_type: Some("unlink".to_string()),
            },
            OsEventKind::Connect { address, port, protocol } => EventContext {
                tool_name: None,
                resource_path: Some(format!("{protocol}://{address}:{port}")),
                method: None,
                event_type: Some("connect".to_string()),
            },
            OsEventKind::Fork { .. } => EventContext {
                tool_name: None,
                resource_path: None,
                method: None,
                event_type: Some("fork".to_string()),
            },
            OsEventKind::Exit { .. } => EventContext {
                tool_name: None,
                resource_path: None,
                method: None,
                event_type: Some("exit".to_string()),
            },
            OsEventKind::PtyGrant { path } => EventContext {
                tool_name: None,
                resource_path: Some(path.clone()),
                method: None,
                event_type: Some("pty_grant".to_string()),
            },
            OsEventKind::SetMode { path, .. } => EventContext {
                tool_name: None,
                resource_path: Some(path.clone()),
                method: None,
                event_type: Some("setmode".to_string()),
            },
        }
    }
}

impl PolicyEngine for DefaultPolicyEngine {
    fn evaluate(&self, event: &dyn Event) -> PolicyAction {
        let ctx = Self::extract_context(event);

        // Session rules first (highest priority), then file rules.
        for rule in self.session_rules.iter().chain(self.file_rules.iter()) {
            if rule.matches(&ctx) {
                debug!("rule '{}' matched, action: {:?}", rule.name, rule.action);
                return rule.action.clone();
            }
        }

        // Default: log.
        PolicyAction::Log
    }

    fn reload(&mut self) -> Result<()> {
        let content = fs::read_to_string(&self.policy_path)
            .with_context(|| format!("failed to read policy file: {}", self.policy_path.display()))?;
        self.file_rules = parse_policy_toml(&content)?;
        debug!("reloaded {} policy rules", self.file_rules.len());
        Ok(())
    }

    fn add_session_rule(&mut self, rule: PolicyRule) {
        debug!("adding session rule: {}", rule.name);
        self.session_rules.insert(0, rule);
    }

    fn add_permanent_rule(&mut self, rule: PolicyRule) -> Result<()> {
        // Append to the TOML file on disk.
        let toml_fragment = serialize_rule_toml(&rule);
        let mut content = fs::read_to_string(&self.policy_path).unwrap_or_default();
        content.push('\n');
        content.push_str(&toml_fragment);
        fs::write(&self.policy_path, &content)
            .with_context(|| format!("failed to write policy file: {}", self.policy_path.display()))?;

        // Also add to in-memory list.
        self.file_rules.push(rule);
        Ok(())
    }
}

/// Serialize a single PolicyRule into TOML fragment for appending to a file.
fn serialize_rule_toml(rule: &PolicyRule) -> String {
    let mut s = format!("[rules.{}]\n", rule.name);
    s.push_str(&format!("description = {:?}\n", rule.description));
    let action_str = match &rule.action {
        PolicyAction::Allow => "allow",
        PolicyAction::Block => "block",
        PolicyAction::Prompt(_) => "prompt",
        PolicyAction::Log => "log",
    };
    s.push_str(&format!("action = {:?}\n", action_str));
    s.push_str(&format!("message = {:?}\n", rule.message));
    s.push_str(&format!("priority = {}\n", rule.priority));

    s.push_str(&format!("\n[rules.{}.match]\n", rule.name));
    let mc = &rule.match_criteria;
    if mc.any {
        s.push_str("any = true\n");
    }
    if let Some(ref names) = mc.tool_names {
        s.push_str(&format!("tool_name = {:?}\n", names));
    }
    if let Some(ref paths) = mc.resource_paths {
        s.push_str(&format!("resource_path = {:?}\n", paths));
    }
    if let Some(ref methods) = mc.methods {
        s.push_str(&format!("method = {:?}\n", methods));
    }
    if let Some(ref types) = mc.event_types {
        s.push_str(&format!("event_type = {:?}\n", types));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::mcp::{McpEvent, McpEventKind, ResourceRead, ToolCall};
    use crate::event::os::{OsEvent, OsEventKind};
    use chrono::Utc;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn policy_toml() -> &'static str {
        r#"
[rules.block_ssh]
description = "Block SSH key access"
action = "block"
message = "SSH key access is not allowed"
priority = 0

[rules.block_ssh.match]
resource_path = ["/home/user/.ssh/id_*"]

[rules.allow_project]
description = "Allow project file reads"
action = "allow"
message = "Project file access allowed"
priority = 1

[rules.allow_project.match]
resource_path = ["/project/**"]

[rules.prompt_exec]
description = "Prompt on shell execution"
action = "prompt"
message = "Allow shell execution?"
priority = 2

[rules.prompt_exec.match]
event_type = ["exec"]

[rules.catch_all]
description = "Log everything else"
action = "log"
message = "Logged"
priority = 100

[rules.catch_all.match]
any = true
"#
    }

    fn write_temp_policy(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn make_tool_call_event(tool_name: &str) -> McpEvent {
        McpEvent {
            timestamp: Utc::now(),
            source: "mcp-proxy".to_string(),
            kind: McpEventKind::ToolCall(ToolCall {
                tool_name: tool_name.to_string(),
                arguments: json!({}),
                request_id: json!(1),
            }),
            raw_message: json!({}),
        }
    }

    fn make_resource_read_event(uri: &str) -> McpEvent {
        McpEvent {
            timestamp: Utc::now(),
            source: "mcp-proxy".to_string(),
            kind: McpEventKind::ResourceRead(ResourceRead {
                uri: uri.to_string(),
                request_id: json!(1),
            }),
            raw_message: json!({}),
        }
    }

    fn make_exec_event(target: &str) -> OsEvent {
        OsEvent {
            timestamp: Utc::now(),
            pid: 1234,
            ppid: 1,
            process_path: "/bin/sh".to_string(),
            kind: OsEventKind::Exec {
                target_path: target.to_string(),
                args: vec![],
            },
            signing_id: None,
            team_id: None,
        }
    }

    fn make_open_event(path: &str) -> OsEvent {
        OsEvent {
            timestamp: Utc::now(),
            pid: 1234,
            ppid: 1,
            process_path: "/bin/cat".to_string(),
            kind: OsEventKind::Open {
                path: path.to_string(),
                flags: 0,
            },
            signing_id: None,
            team_id: None,
        }
    }

    #[test]
    fn load_valid_policy() {
        let f = write_temp_policy(policy_toml());
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();
        assert_eq!(engine.file_rules.len(), 4);
        assert_eq!(engine.file_rules[0].name, "block_ssh");
        assert_eq!(engine.file_rules[3].name, "catch_all");
    }

    #[test]
    fn evaluate_block_ssh_key_access() {
        let f = write_temp_policy(policy_toml());
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();

        let event = make_resource_read_event("/home/user/.ssh/id_rsa");
        assert_eq!(engine.evaluate(&event), PolicyAction::Block);
    }

    #[test]
    fn evaluate_allow_project_reads() {
        let f = write_temp_policy(policy_toml());
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();

        let event = make_resource_read_event("/project/src/main.rs");
        assert_eq!(engine.evaluate(&event), PolicyAction::Allow);
    }

    #[test]
    fn evaluate_prompt_shell_execution() {
        let f = write_temp_policy(policy_toml());
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();

        let event = make_exec_event("/usr/bin/bash");
        assert_eq!(
            engine.evaluate(&event),
            PolicyAction::Prompt("Allow shell execution?".to_string())
        );
    }

    #[test]
    fn evaluate_catch_all_log() {
        let f = write_temp_policy(policy_toml());
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();

        // A tool call that doesn't match specific rules falls through to catch-all.
        let event = make_tool_call_event("some_random_tool");
        assert_eq!(engine.evaluate(&event), PolicyAction::Log);
    }

    #[test]
    fn first_match_wins_precedence() {
        // SSH key access via resource_read: block_ssh should win over catch_all.
        let f = write_temp_policy(policy_toml());
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();

        let event = make_resource_read_event("/home/user/.ssh/id_ed25519");
        assert_eq!(engine.evaluate(&event), PolicyAction::Block);
    }

    #[test]
    fn default_action_when_no_rules() {
        let engine = DefaultPolicyEngine::empty();
        let event = make_tool_call_event("anything");
        assert_eq!(engine.evaluate(&event), PolicyAction::Log);
    }

    #[test]
    fn reload_policy() {
        let f = write_temp_policy(policy_toml());
        let mut engine = DefaultPolicyEngine::load(f.path()).unwrap();
        assert_eq!(engine.file_rules.len(), 4);

        // Overwrite with a smaller policy.
        fs::write(f.path(), r#"
[rules.only_one]
description = "Only rule"
action = "allow"
message = "allowed"
priority = 0

[rules.only_one.match]
any = true
"#).unwrap();

        engine.reload().unwrap();
        assert_eq!(engine.file_rules.len(), 1);
        assert_eq!(engine.file_rules[0].name, "only_one");

        // Verify the new rule is applied.
        let event = make_tool_call_event("anything");
        assert_eq!(engine.evaluate(&event), PolicyAction::Allow);
    }

    #[test]
    fn session_rules_take_precedence() {
        let f = write_temp_policy(policy_toml());
        let mut engine = DefaultPolicyEngine::load(f.path()).unwrap();

        // Normally, exec events trigger a prompt.
        let event = make_exec_event("/usr/bin/bash");
        assert_eq!(
            engine.evaluate(&event),
            PolicyAction::Prompt("Allow shell execution?".to_string())
        );

        // Add a session rule that allows exec.
        engine.add_session_rule(PolicyRule {
            name: "allow_exec_session".to_string(),
            description: "Temporarily allow exec".to_string(),
            match_criteria: super::super::MatchCriteria {
                event_types: Some(vec!["exec".to_string()]),
                ..Default::default()
            },
            action: PolicyAction::Allow,
            message: "Session override".to_string(),
            priority: 0,
        });

        assert_eq!(engine.evaluate(&event), PolicyAction::Allow);
    }

    #[test]
    fn add_permanent_rule() {
        let f = write_temp_policy("");
        let mut engine = DefaultPolicyEngine::load(f.path()).unwrap();
        assert_eq!(engine.file_rules.len(), 0);

        engine.add_permanent_rule(PolicyRule {
            name: "block_network".to_string(),
            description: "Block network".to_string(),
            match_criteria: super::super::MatchCriteria {
                event_types: Some(vec!["connect".to_string()]),
                ..Default::default()
            },
            action: PolicyAction::Block,
            message: "Network blocked".to_string(),
            priority: 0,
        }).unwrap();

        assert_eq!(engine.file_rules.len(), 1);

        // Verify it was written to disk by reloading.
        engine.reload().unwrap();
        assert_eq!(engine.file_rules.len(), 1);
        assert_eq!(engine.file_rules[0].name, "block_network");
    }

    #[test]
    fn empty_policy_file_default_log() {
        let f = write_temp_policy("");
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();
        let event = make_tool_call_event("anything");
        assert_eq!(engine.evaluate(&event), PolicyAction::Log);
    }

    #[test]
    fn os_connect_event_context() {
        let event = OsEvent {
            timestamp: Utc::now(),
            pid: 100,
            ppid: 1,
            process_path: "/usr/bin/curl".to_string(),
            kind: OsEventKind::Connect {
                address: "10.0.0.1".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
            },
            signing_id: None,
            team_id: None,
        };
        let ctx = DefaultPolicyEngine::extract_context(&event);
        assert_eq!(ctx.event_type.as_deref(), Some("connect"));
        assert_eq!(ctx.resource_path.as_deref(), Some("tcp://10.0.0.1:443"));
    }

    #[test]
    fn os_open_event_falls_through_to_catch_all() {
        let f = write_temp_policy(policy_toml());
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();

        let event = make_open_event("/tmp/some_file.txt");
        // open event type doesn't match block_ssh, allow_project, or prompt_exec,
        // so it falls through to the catch_all log rule.
        assert_eq!(engine.evaluate(&event), PolicyAction::Log);
    }

    // -----------------------------------------------------------------------
    // Performance benchmarks
    // -----------------------------------------------------------------------

    #[test]
    fn bench_policy_evaluation_4_rules_first_match() {
        let f = write_temp_policy(policy_toml());
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();
        let event = make_resource_read_event("/home/user/.ssh/id_rsa");

        let iterations = 10_000u32;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = engine.evaluate(&event);
        }
        let elapsed = start.elapsed();
        let per_eval_us = elapsed.as_micros() / iterations as u128;
        // Release target is < 100us. Debug builds are ~50-100x slower due to
        // unoptimized canonicalize_path + glob matching, so we use a relaxed
        // threshold here. Run `cargo test --release` to verify the real target.
        let threshold = if cfg!(debug_assertions) { 20_000 } else { 100 };
        assert!(
            per_eval_us < threshold,
            "policy evaluation (first match) {per_eval_us}us exceeds {threshold}us target"
        );
    }

    #[test]
    fn bench_policy_evaluation_4_rules_catch_all() {
        let f = write_temp_policy(policy_toml());
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();
        // Worst case: falls through to catch-all
        let event = make_tool_call_event("random_tool");

        let iterations = 10_000u32;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = engine.evaluate(&event);
        }
        let elapsed = start.elapsed();
        let per_eval_us = elapsed.as_micros() / iterations as u128;
        assert!(
            per_eval_us < 100,
            "policy evaluation (catch-all) {per_eval_us}us exceeds 100us target"
        );
    }

    #[test]
    fn bench_policy_evaluation_50_rules_worst_case() {
        // Build a policy with 50 rules (49 specific + 1 catch-all)
        let mut toml = String::new();
        for i in 0..49 {
            toml.push_str(&format!(
                "[rules.rule_{i}]\ndescription = \"Rule {i}\"\naction = \"allow\"\n\
                 message = \"ok\"\npriority = {i}\n\n\
                 [rules.rule_{i}.match]\ntool_name = [\"specific_tool_{i}\"]\n\n"
            ));
        }
        toml.push_str(
            "[rules.catch_all]\ndescription = \"Catch all\"\naction = \"log\"\n\
             message = \"logged\"\npriority = 100\n\n[rules.catch_all.match]\nany = true\n",
        );

        let f = write_temp_policy(&toml);
        let engine = DefaultPolicyEngine::load(f.path()).unwrap();
        assert_eq!(engine.file_rules.len(), 50);

        // Worst case: tool name doesn't match any specific rule
        let event = make_tool_call_event("unknown_tool");

        let iterations = 10_000u32;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = engine.evaluate(&event);
        }
        let elapsed = start.elapsed();
        let per_eval_us = elapsed.as_micros() / iterations as u128;
        assert!(
            per_eval_us < 100,
            "50-rule policy evaluation (worst case) {per_eval_us}us exceeds 100us target"
        );
    }
}
