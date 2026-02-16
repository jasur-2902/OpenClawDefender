//! `clawdefender init` — create the ClawDefender configuration directory with defaults.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clawdefender_core::config::ClawConfig;

use super::known_clients;

/// Default policy TOML written during init.
const DEFAULT_POLICY: &str = r#"# ClawDefender Policy Rules
# Rules are evaluated top-to-bottom; first match wins.
# Actions: allow, block, prompt, log
# Match criteria: tool_name, resource_path, method, event_type, any

[rules.block_ssh_keys]
description = "Block access to SSH private keys"
action = "block"
message = "SSH key access is not allowed"
priority = 0

[rules.block_ssh_keys.match]
resource_path = ["~/.ssh/id_*", "~/.ssh/*.pem"]

[rules.prompt_shell]
description = "Prompt before executing shell commands"
action = "prompt"
message = "An AI agent wants to execute a shell command. Allow?"
priority = 10

[rules.prompt_shell.match]
tool_name = ["exec*", "shell*", "run_command*", "bash*"]

[rules.log_all]
description = "Log all other operations"
action = "log"
message = "Logged"
priority = 100

[rules.log_all.match]
any = true
"#;

/// Default config TOML written during init.
const DEFAULT_CONFIG: &str = r#"# ClawDefender Configuration
# See https://github.com/clawdefender/clawdefender for documentation.

# Path to the policy rules file.
# policy_path = "~/.config/clawdefender/policy.toml"

# Path to the audit log.
# audit_log_path = "~/.local/share/clawdefender/audit.jsonl"

# Log rotation settings.
[log_rotation]
max_size_mb = 50
max_files = 10

# eslogger / Endpoint Security settings.
[eslogger]
enabled = true
events = ["exec", "open", "close", "rename", "unlink", "connect", "fork", "exit"]

# UI settings.
[ui]
theme = "dark"
notifications = true
"#;

pub fn run(config: &ClawConfig) -> Result<()> {
    let config_dir = config_dir()?;
    let data_dir = data_dir()?;

    // Create directories.
    fs::create_dir_all(&config_dir)
        .with_context(|| format!("creating config dir: {}", config_dir.display()))?;
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir: {}", data_dir.display()))?;

    // Write config.toml.
    let config_path = config_dir.join("config.toml");
    write_if_not_exists(&config_path, DEFAULT_CONFIG)?;

    // Write policy.toml.
    let policy_path = config_dir.join("policy.toml");
    write_if_not_exists(&policy_path, DEFAULT_POLICY)?;

    // Ensure the audit log directory exists.
    if let Some(parent) = config.audit_log_path.parent() {
        fs::create_dir_all(parent).ok();
    }

    println!("ClawDefender initialized successfully!");
    println!("  Config:  {}", config_path.display());
    println!("  Policy:  {}", policy_path.display());
    println!("  Data:    {}", data_dir.display());
    println!("  Audit:   {}", config.audit_log_path.display());

    // Detect installed MCP clients.
    println!();
    println!("Detected MCP clients:");
    let clients = known_clients();
    let mut found = false;
    for client in &clients {
        if client.config_path.exists() {
            println!("  - {} ({})", client.display_name, client.config_path.display());
            found = true;
        }
    }
    if !found {
        println!("  (none detected)");
    }

    println!();
    println!("Next steps:");
    println!("  1. Edit policy rules:     clawdefender policy list");
    println!("  2. Wrap an MCP server:    clawdefender wrap <server-name>");
    println!("  3. Check installation:    clawdefender doctor");

    Ok(())
}

fn write_if_not_exists(path: &PathBuf, content: &str) -> Result<()> {
    if path.exists() {
        println!("  [skip] {} already exists", path.display());
    } else {
        fs::write(path, content)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("  [create] {}", path.display());
    }
    Ok(())
}

fn config_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".config/clawdefender"))
}

fn data_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".local/share/clawdefender"))
}

#[cfg(test)]
mod tests {
    /// Verify the default policy is valid TOML that parses correctly.
    #[test]
    fn test_default_policy_parses() {
        let rules = clawdefender_core::policy::rule::parse_policy_toml(super::DEFAULT_POLICY).unwrap();
        assert!(rules.len() >= 3);
    }

    /// Verify the default config is valid TOML.
    #[test]
    fn test_default_config_parses() {
        let _config: toml::Value = toml::from_str(super::DEFAULT_CONFIG).unwrap();
    }

    /// Init in a temp dir should create files.
    #[test]
    fn test_init_creates_files_in_temp_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        let policy_path = dir.path().join("policy.toml");

        super::write_if_not_exists(&config_path, super::DEFAULT_CONFIG).unwrap();
        super::write_if_not_exists(&policy_path, super::DEFAULT_POLICY).unwrap();

        assert!(config_path.exists());
        assert!(policy_path.exists());

        // Calling again should skip (not overwrite).
        std::fs::write(&config_path, "custom content").unwrap();
        super::write_if_not_exists(&config_path, super::DEFAULT_CONFIG).unwrap();
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), "custom content");
    }
}
