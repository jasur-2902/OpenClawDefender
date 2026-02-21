//! `clawdefender init` — create the ClawDefender configuration directory with defaults.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clawdefender_core::config::ClawConfig;

use super::{honeypot_dir, known_clients};

/// Default policy TOML written during init.
const DEFAULT_POLICY: &str = r#"# ClawDefender Policy Rules
# Rules are evaluated top-to-bottom; first match wins.
# Actions: allow, block, prompt, log
# Match criteria: tool_name, resource_path, method, event_type, any

[rules.block_honeypot]
description = "Block access to ClawDefender honeypot canary files"
action = "block"
message = "Honeypot canary file access detected — possible credential theft attempt"
priority = 0

[rules.block_honeypot.match]
resource_path = ["~/.config/clawdefender/honeypot/**"]

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

    // Create honeypot canary files.
    let honeypot_path = create_honeypot()?;

    // Ensure the audit log directory exists.
    if let Some(parent) = config.audit_log_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!(
                "  [warn] Could not create audit log directory {}: {}",
                parent.display(),
                e
            );
            eprintln!("  Audit logging may not work. Check permissions and try again.");
        }
    }

    println!();
    println!("ClawDefender initialized successfully!");
    println!();
    println!("  Config:   {}", config_path.display());
    println!("  Policy:   {}", policy_path.display());
    println!("  Data:     {}", data_dir.display());
    println!("  Audit:    {}", config.audit_log_path.display());
    println!("  Honeypot: {}", honeypot_path.display());

    // Detect installed MCP clients.
    println!();
    println!("Detected MCP clients:");
    let clients = known_clients();
    let mut found = false;
    for client in &clients {
        if client.config_path.exists() {
            println!("  Found {} \u{2713}", client.display_name);
            found = true;
        }
    }
    if !found {
        println!("  (none detected)");
        println!("  Install Claude Desktop, Cursor, or VS Code to get started.");
    }

    println!();
    println!("Next steps:");
    if found {
        println!("  1. Wrap an MCP server:    clawdefender wrap <server-name>");
        println!("  2. Check installation:    clawdefender doctor");
        println!("  3. Edit policy rules:     clawdefender policy list");
        println!("  4. Apply a template:      clawdefender policy template-list");
    } else {
        println!("  1. Install an MCP client (Claude Desktop, Cursor, or VS Code)");
        println!("  2. Wrap an MCP server:    clawdefender wrap <server-name>");
        println!("  3. Check installation:    clawdefender doctor");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Honeypot canary files
// ---------------------------------------------------------------------------

const HONEYPOT_SSH_RSA: &str = "\
-----BEGIN RSA PRIVATE KEY-----
# CLAWDEFENDER HONEYPOT — This is a dummy key for canary detection.
# Any access to this file triggers a credential theft alert.
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU4yqlSMnDjEBBHKblINhFOkyGCAoA1KQpMigM3kDgbCzTi3TOmOLFq
UPHAkdPmEgL0JmDRDJVBbUBqR1YVv0cQ1jiYNCjP3DaBRbkCtLkHKbpPJElNQoSc
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
-----END RSA PRIVATE KEY-----
";

const HONEYPOT_SSH_ED25519: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
# CLAWDEFENDER HONEYPOT — This is a dummy key for canary detection.
# Any access to this file triggers a credential theft alert.
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
-----END OPENSSH PRIVATE KEY-----
";

const HONEYPOT_AWS_CREDENTIALS: &str = "\
# CLAWDEFENDER HONEYPOT — These are dummy credentials for canary detection.
# Any access to this file triggers a credential theft alert.
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
";

const HONEYPOT_DOTENV: &str = "\
# CLAWDEFENDER HONEYPOT — These are dummy secrets for canary detection.
# Any access to this file triggers a credential theft alert.
DATABASE_URL=postgresql://admin:hunter2@db.example.com:5432/production
API_KEY=sk-clawdefender-honeypot-0000000000000000000000000000
SECRET_KEY=clawdefender-honeypot-secret-key-do-not-use
STRIPE_SECRET_KEY=sk_live_clawdefender_honeypot_000000000000
";

/// Create the honeypot canary directory with realistic dummy credential files.
/// Returns the honeypot directory path.
fn create_honeypot() -> Result<PathBuf> {
    let dir = honeypot_dir().context("could not determine honeypot directory (HOME not set)")?;
    create_honeypot_in(&dir)?;
    Ok(dir)
}

/// Create honeypot files inside `base_dir`. Extracted for testability.
fn create_honeypot_in(base_dir: &Path) -> Result<()> {
    let ssh_dir = base_dir.join("ssh");
    let aws_dir = base_dir.join("aws");

    fs::create_dir_all(&ssh_dir)
        .with_context(|| format!("creating honeypot ssh dir: {}", ssh_dir.display()))?;
    fs::create_dir_all(&aws_dir)
        .with_context(|| format!("creating honeypot aws dir: {}", aws_dir.display()))?;

    write_if_not_exists(&ssh_dir.join("id_rsa"), HONEYPOT_SSH_RSA)?;
    write_if_not_exists(&ssh_dir.join("id_ed25519"), HONEYPOT_SSH_ED25519)?;
    write_if_not_exists(&aws_dir.join("credentials"), HONEYPOT_AWS_CREDENTIALS)?;
    write_if_not_exists(&base_dir.join("env"), HONEYPOT_DOTENV)?;

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
    let home = PathBuf::from(home);
    let dot_config = home.join(".config");

    // If ~/.config exists but isn't writable (e.g. owned by root on macOS),
    // provide a clear message instead of a confusing "Permission denied".
    if dot_config.exists() && fs::metadata(&dot_config).is_ok() {
        // Try creating a temp probe to check writability
        let probe = dot_config.join(".clawdefender_probe");
        if fs::create_dir(&probe).is_err() {
            anyhow::bail!(
                "~/.config exists but is not writable by your user.\n\
                 Fix with: sudo chown $(whoami) ~/.config\n\
                 Or manually create: mkdir -p ~/.config/clawdefender"
            );
        }
        let _ = fs::remove_dir(&probe);
    }

    Ok(dot_config.join("clawdefender"))
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
        assert!(rules.len() >= 4);
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

    #[test]
    fn test_create_honeypot_creates_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("honeypot");
        super::create_honeypot_in(&base).unwrap();

        assert!(base.join("ssh/id_rsa").exists());
        assert!(base.join("ssh/id_ed25519").exists());
        assert!(base.join("aws/credentials").exists());
        assert!(base.join("env").exists());

        // Verify content has honeypot marker.
        let rsa = std::fs::read_to_string(base.join("ssh/id_rsa")).unwrap();
        assert!(rsa.contains("CLAWDEFENDER HONEYPOT"));
        assert!(rsa.contains("BEGIN RSA PRIVATE KEY"));

        let aws = std::fs::read_to_string(base.join("aws/credentials")).unwrap();
        assert!(aws.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_honeypot_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("honeypot");
        super::create_honeypot_in(&base).unwrap();

        // Overwrite one file with custom content.
        let rsa_path = base.join("ssh/id_rsa");
        std::fs::write(&rsa_path, "custom key").unwrap();

        // Second call should not overwrite.
        super::create_honeypot_in(&base).unwrap();
        assert_eq!(std::fs::read_to_string(&rsa_path).unwrap(), "custom key");
    }
}
