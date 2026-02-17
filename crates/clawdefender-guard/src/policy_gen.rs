//! Policy generation from PermissionSet to TOML format.

use chrono::Utc;

use crate::types::{PermissionSet, ShellPolicy};

/// Sensitive paths that should always be blocked.
const SENSITIVE_PATHS: &[&str] = &[
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "~/.config/gcloud/**",
];

/// Shell tool names to block.
const SHELL_TOOLS: &[&str] = &[
    "run_command",
    "execute",
    "shell",
    "bash",
    "exec",
    "terminal",
    "sh",
];

/// Network tool names to block.
const NETWORK_TOOLS: &[&str] = &[
    "fetch",
    "http_request",
    "curl",
    "wget",
    "http",
    "request",
];

/// Generate a complete TOML policy string from an agent name and permission set.
pub fn generate_policy_toml(agent_name: &str, permissions: &PermissionSet) -> String {
    let timestamp = Utc::now().to_rfc3339();
    let mut toml = format!(
        "# Auto-generated policy for agent: {agent_name}\n\
         # Generated at: {timestamp}\n\n"
    );

    let mut priority: u32 = 0;

    // 1. Always block sensitive paths first (highest priority).
    toml.push_str(&format!(
        "[rules.guard_block_sensitive_paths]\n\
         description = \"Block access to sensitive paths for agent {agent_name}\"\n\
         action = \"block\"\n\
         message = \"Access to sensitive paths is always blocked\"\n\
         priority = {priority}\n\n\
         [rules.guard_block_sensitive_paths.match]\n\
         resource_path = {paths}\n\n",
        paths = format_string_array(SENSITIVE_PATHS),
    ));
    priority += 1;

    // 2. Allow declared read paths.
    if !permissions.file_read.is_empty() {
        toml.push_str(&format!(
            "[rules.guard_allow_project_read]\n\
             description = \"Allow reading declared paths for agent {agent_name}\"\n\
             action = \"allow\"\n\
             message = \"File read allowed by guard policy\"\n\
             priority = {priority}\n\n\
             [rules.guard_allow_project_read.match]\n\
             tool_name = [\"read_file\", \"file_read\", \"Read\"]\n\
             resource_path = {paths}\n\n",
            paths = format_string_array_owned(&permissions.file_read),
        ));
        priority += 1;
    }

    // 3. Allow declared write paths.
    if !permissions.file_write.is_empty() {
        toml.push_str(&format!(
            "[rules.guard_allow_project_write]\n\
             description = \"Allow writing to declared paths for agent {agent_name}\"\n\
             action = \"allow\"\n\
             message = \"File write allowed by guard policy\"\n\
             priority = {priority}\n\n\
             [rules.guard_allow_project_write.match]\n\
             tool_name = [\"write_file\", \"file_write\", \"Write\", \"Edit\"]\n\
             resource_path = {paths}\n\n",
            paths = format_string_array_owned(&permissions.file_write),
        ));
        priority += 1;
    }

    // 4. Allow declared delete paths.
    if !permissions.file_delete.is_empty() {
        toml.push_str(&format!(
            "[rules.guard_allow_project_delete]\n\
             description = \"Allow deleting at declared paths for agent {agent_name}\"\n\
             action = \"allow\"\n\
             message = \"File delete allowed by guard policy\"\n\
             priority = {priority}\n\n\
             [rules.guard_allow_project_delete.match]\n\
             tool_name = [\"delete_file\", \"file_delete\", \"remove\"]\n\
             resource_path = {paths}\n\n",
            paths = format_string_array_owned(&permissions.file_delete),
        ));
        priority += 1;
    }

    // 5. Shell policy.
    match &permissions.shell_execute {
        ShellPolicy::Deny => {
            toml.push_str(&format!(
                "[rules.guard_block_all_shell]\n\
                 description = \"Block all shell execution for agent {agent_name}\"\n\
                 action = \"block\"\n\
                 message = \"Shell execution is denied by guard policy\"\n\
                 priority = {priority}\n\n\
                 [rules.guard_block_all_shell.match]\n\
                 tool_name = {tools}\n\n",
                tools = format_string_array(SHELL_TOOLS),
            ));
            priority += 1;
        }
        ShellPolicy::AllowList(commands) => {
            // Allow specific commands via tool_name patterns.
            toml.push_str(&format!(
                "[rules.guard_allow_shell]\n\
                 description = \"Allow declared shell commands for agent {agent_name}\"\n\
                 action = \"allow\"\n\
                 message = \"Shell command allowed by guard policy\"\n\
                 priority = {priority}\n\n\
                 [rules.guard_allow_shell.match]\n\
                 tool_name = {tools}\n\n",
                tools = format_string_array_owned(commands),
            ));
            priority += 1;
        }
        ShellPolicy::AllowWithApproval => {
            toml.push_str(&format!(
                "[rules.guard_prompt_shell]\n\
                 description = \"Prompt for shell execution for agent {agent_name}\"\n\
                 action = \"prompt\"\n\
                 message = \"Shell execution requires approval\"\n\
                 priority = {priority}\n\n\
                 [rules.guard_prompt_shell.match]\n\
                 tool_name = {tools}\n\n",
                tools = format_string_array(SHELL_TOOLS),
            ));
            priority += 1;
        }
    }

    // 6. Network policy.
    if permissions.network.deny_all {
        toml.push_str(&format!(
            "[rules.guard_block_all_network]\n\
             description = \"Block all network access for agent {agent_name}\"\n\
             action = \"block\"\n\
             message = \"Network access is denied by guard policy\"\n\
             priority = {priority}\n\n\
             [rules.guard_block_all_network.match]\n\
             tool_name = {tools}\n\n",
            tools = format_string_array(NETWORK_TOOLS),
        ));
        priority += 1;
    } else if !permissions.network.allowed_hosts.is_empty() {
        toml.push_str(&format!(
            "[rules.guard_allow_network]\n\
             description = \"Allow network access to declared hosts for agent {agent_name}\"\n\
             action = \"allow\"\n\
             message = \"Network access allowed by guard policy\"\n\
             priority = {priority}\n\n\
             [rules.guard_allow_network.match]\n\
             tool_name = {net_tools}\n\
             resource_path = {hosts}\n\n",
            net_tools = format_string_array(NETWORK_TOOLS),
            hosts = format_string_array_owned(&permissions.network.allowed_hosts),
        ));
        priority += 1;

        // Block undeclared network access.
        toml.push_str(&format!(
            "[rules.guard_block_undeclared_network]\n\
             description = \"Block network access to undeclared hosts for agent {agent_name}\"\n\
             action = \"block\"\n\
             message = \"Network access to this host is not declared in guard policy\"\n\
             priority = {priority}\n\n\
             [rules.guard_block_undeclared_network.match]\n\
             tool_name = {tools}\n\n",
            tools = format_string_array(NETWORK_TOOLS),
        ));
        priority += 1;
    }

    // 7. Allow declared tools.
    if !permissions.tools.is_empty() {
        toml.push_str(&format!(
            "[rules.guard_allow_declared_tools]\n\
             description = \"Allow declared tools for agent {agent_name}\"\n\
             action = \"allow\"\n\
             message = \"Tool allowed by guard policy\"\n\
             priority = {priority}\n\n\
             [rules.guard_allow_declared_tools.match]\n\
             tool_name = {tools}\n\n",
            tools = format_string_array_owned(&permissions.tools),
        ));
        priority += 1;
    }

    // 8. Catch-all block.
    toml.push_str(&format!(
        "[rules.guard_block_everything_else]\n\
         description = \"Block undeclared operations for agent {agent_name}\"\n\
         action = \"block\"\n\
         message = \"Operation not permitted by guard policy\"\n\
         priority = {priority}\n\n\
         [rules.guard_block_everything_else.match]\n\
         any = true\n"
    ));

    toml
}

fn format_string_array(items: &[&str]) -> String {
    let formatted: Vec<String> = items.iter().map(|s| format!("{s:?}")).collect();
    format!("[{}]", formatted.join(", "))
}

fn format_string_array_owned(items: &[String]) -> String {
    let formatted: Vec<String> = items.iter().map(|s| format!("{s:?}")).collect();
    format!("[{}]", formatted.join(", "))
}

/// Verify that generated TOML is valid by parsing it.
pub fn validate_policy_toml(toml_content: &str) -> anyhow::Result<()> {
    let _: toml::Value = toml::from_str(toml_content)
        .map_err(|e| anyhow::anyhow!("invalid generated TOML: {e}"))?;
    Ok(())
}
