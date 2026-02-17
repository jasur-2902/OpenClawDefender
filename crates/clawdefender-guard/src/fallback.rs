//! Embedded fallback policy engine for when the daemon is unavailable.

use glob::Pattern;
use tracing::info;

use crate::types::{ActionResult, PermissionSet, ShellPolicy};

/// Sensitive paths that are always blocked.
const SENSITIVE_PATHS: &[&str] = &[
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "~/.config/gcloud/**",
];

/// Shell-related tool names.
const SHELL_TOOLS: &[&str] = &[
    "run_command", "execute", "shell", "bash", "exec", "terminal", "sh",
];

/// Network-related tool names.
const NETWORK_TOOLS: &[&str] = &[
    "fetch", "http_request", "curl", "wget", "http", "request",
];

/// File-read tool names.
const READ_TOOLS: &[&str] = &["read_file", "file_read", "Read"];

/// File-write tool names.
const WRITE_TOOLS: &[&str] = &["write_file", "file_write", "Write", "Edit"];

/// File-delete tool names.
const DELETE_TOOLS: &[&str] = &["delete_file", "file_delete", "remove"];

/// Lightweight in-process policy engine for checking permissions without the daemon.
pub struct FallbackEngine {
    permissions: PermissionSet,
}

impl FallbackEngine {
    /// Create a new fallback engine with the given permissions.
    pub fn new(permissions: PermissionSet) -> Self {
        info!("AgentGuard running in embedded mode — daemon unavailable, using in-process policy enforcement");
        Self { permissions }
    }

    /// Check whether an action is allowed.
    pub fn check_action(&self, tool: &str, target: &str) -> ActionResult {
        // 1. Always block sensitive paths.
        if is_sensitive_path(target) {
            return ActionResult::Block(
                "Access to sensitive paths is always blocked".to_string(),
            );
        }

        // 2. Check tool-specific permissions.
        if is_tool_in_list(tool, READ_TOOLS) {
            return self.check_file_read(target);
        }
        if is_tool_in_list(tool, WRITE_TOOLS) {
            return self.check_file_write(target);
        }
        if is_tool_in_list(tool, DELETE_TOOLS) {
            return self.check_file_delete(target);
        }
        if is_tool_in_list(tool, SHELL_TOOLS) {
            return self.check_shell(tool);
        }
        if is_tool_in_list(tool, NETWORK_TOOLS) {
            return self.check_network(target);
        }

        // 3. Check declared tools list.
        if self.permissions.tools.contains(&tool.to_string()) {
            return ActionResult::Allow;
        }

        // 4. Catch-all: block.
        ActionResult::Block("Operation not permitted by guard policy".to_string())
    }

    fn check_file_read(&self, target: &str) -> ActionResult {
        if path_matches_any(target, &self.permissions.file_read) {
            ActionResult::Allow
        } else {
            ActionResult::Block(format!(
                "File read not allowed: {target} not in declared read paths"
            ))
        }
    }

    fn check_file_write(&self, target: &str) -> ActionResult {
        if path_matches_any(target, &self.permissions.file_write) {
            ActionResult::Allow
        } else {
            ActionResult::Block(format!(
                "File write not allowed: {target} not in declared write paths"
            ))
        }
    }

    fn check_file_delete(&self, target: &str) -> ActionResult {
        if path_matches_any(target, &self.permissions.file_delete) {
            ActionResult::Allow
        } else {
            ActionResult::Block(format!(
                "File delete not allowed: {target} not in declared delete paths"
            ))
        }
    }

    fn check_shell(&self, _tool: &str) -> ActionResult {
        match &self.permissions.shell_execute {
            ShellPolicy::Deny => {
                ActionResult::Block("Shell execution is denied by guard policy".to_string())
            }
            ShellPolicy::AllowList(commands) => {
                if commands.iter().any(|c| c == "*" || c == _tool) {
                    ActionResult::Allow
                } else {
                    ActionResult::Block(
                        "Shell command not in allow list".to_string(),
                    )
                }
            }
            ShellPolicy::AllowWithApproval => {
                // In fallback mode, we block (no way to prompt user).
                ActionResult::Block(
                    "Shell execution requires approval (unavailable in embedded mode)".to_string(),
                )
            }
        }
    }

    fn check_network(&self, target: &str) -> ActionResult {
        if self.permissions.network.deny_all {
            return ActionResult::Block(
                "Network access is denied by guard policy".to_string(),
            );
        }

        if self.permissions.network.allowed_hosts.is_empty() {
            return ActionResult::Block(
                "No network hosts declared in guard policy".to_string(),
            );
        }

        if host_matches_any(target, &self.permissions.network.allowed_hosts) {
            ActionResult::Allow
        } else {
            ActionResult::Block(format!(
                "Network access to {target} not in declared hosts"
            ))
        }
    }
}

/// Expand tilde to the user's home directory.
fn expand_tilde(pattern: &str) -> String {
    if let Some(rest) = pattern.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    pattern.to_string()
}

/// Check if a path matches any sensitive path patterns.
fn is_sensitive_path(path: &str) -> bool {
    for pat in SENSITIVE_PATHS {
        let expanded = expand_tilde(pat);
        if let Ok(glob) = Pattern::new(&expanded) {
            if glob.matches(path) {
                return true;
            }
        }
    }
    false
}

/// Check if a tool name is in a list.
fn is_tool_in_list(tool: &str, list: &[&str]) -> bool {
    list.contains(&tool)
}

/// Check if a path matches any of the given patterns.
fn path_matches_any(path: &str, patterns: &[String]) -> bool {
    for pat in patterns {
        let expanded = expand_tilde(pat);
        if let Ok(glob) = Pattern::new(&expanded) {
            if glob.matches(path) {
                return true;
            }
        }
    }
    false
}

/// Check if a host/target matches any of the given host patterns.
fn host_matches_any(target: &str, patterns: &[String]) -> bool {
    for pat in patterns {
        if let Ok(glob) = Pattern::new(pat) {
            if glob.matches(target) {
                return true;
            }
        }
        // Also check for exact match.
        if target.contains(pat.as_str()) {
            return true;
        }
    }
    false
}
