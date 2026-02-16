//! Built-in activity profiles and custom rule loading for noise filtering.

use crate::noise_filter::{ActivityProfile, NoiseRule};
use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

/// Returns all built-in activity profiles.
pub fn builtin_profiles() -> Vec<ActivityProfile> {
    vec![
        compiler_profile(),
        package_manager_profile(),
        ide_profile(),
        git_profile(),
        test_runner_profile(),
    ]
}

fn compiler_profile() -> ActivityProfile {
    ActivityProfile {
        name: "compiler".into(),
        description: "Compiler and build tool invocations".into(),
        rules: vec![
            NoiseRule {
                tool_pattern: Some(r"^(gcc|g\+\+|clang|clang\+\+|rustc|swiftc|javac|make|cmake|ninja)$".into()),
                argument_pattern: None,
                server_pattern: None,
                max_frequency: None,
            },
            NoiseRule {
                tool_pattern: Some(r"^cargo$".into()),
                argument_pattern: Some(r"^(build|test|check|clippy)\b".into()),
                server_pattern: None,
                max_frequency: None,
            },
            NoiseRule {
                tool_pattern: Some(r"^go$".into()),
                argument_pattern: Some(r"^build\b".into()),
                server_pattern: None,
                max_frequency: None,
            },
            // File operations in build output directories
            NoiseRule {
                tool_pattern: None,
                argument_pattern: Some(r"(^|[\s/])(target|build|dist|node_modules|\.build)/".into()),
                server_pattern: None,
                max_frequency: None,
            },
        ],
    }
}

fn package_manager_profile() -> ActivityProfile {
    ActivityProfile {
        name: "package_manager".into(),
        description: "Package manager operations".into(),
        rules: vec![
            NoiseRule {
                tool_pattern: Some(r"^(npm|yarn|pnpm|pip|pip3|brew|gem|pod|composer)$".into()),
                argument_pattern: None,
                server_pattern: None,
                max_frequency: None,
            },
            NoiseRule {
                tool_pattern: Some(r"^cargo$".into()),
                argument_pattern: Some(r"^install\b".into()),
                server_pattern: None,
                max_frequency: None,
            },
            // Lock file reads
            NoiseRule {
                tool_pattern: None,
                argument_pattern: Some(r"(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|Pipfile\.lock|Gemfile\.lock|composer\.lock|Podfile\.lock)".into()),
                server_pattern: None,
                max_frequency: None,
            },
        ],
    }
}

fn ide_profile() -> ActivityProfile {
    ActivityProfile {
        name: "ide".into(),
        description: "IDE and language server operations".into(),
        rules: vec![
            NoiseRule {
                tool_pattern: None,
                argument_pattern: None,
                server_pattern: Some("*language-server*".into()),
                max_frequency: None,
            },
            NoiseRule {
                tool_pattern: None,
                argument_pattern: None,
                server_pattern: Some("*lsp*".into()),
                max_frequency: None,
            },
            NoiseRule {
                tool_pattern: None,
                argument_pattern: None,
                server_pattern: Some("*intellisense*".into()),
                max_frequency: None,
            },
            NoiseRule {
                tool_pattern: None,
                argument_pattern: None,
                server_pattern: Some("*copilot*".into()),
                max_frequency: None,
            },
            NoiseRule {
                tool_pattern: Some(r"^(rust-analyzer|typescript-language-server|pylsp|gopls|clangd|sourcekit-lsp)$".into()),
                argument_pattern: None,
                server_pattern: None,
                max_frequency: None,
            },
        ],
    }
}

fn git_profile() -> ActivityProfile {
    ActivityProfile {
        name: "git".into(),
        description: "Git version control operations".into(),
        rules: vec![
            NoiseRule {
                tool_pattern: Some(r"^git$".into()),
                argument_pattern: Some(r"^(status|log|diff|add|commit|push|pull|fetch|checkout|branch|stash|rebase|merge)\b".into()),
                server_pattern: None,
                max_frequency: None,
            },
            // File reads in .git/
            NoiseRule {
                tool_pattern: None,
                argument_pattern: Some(r"(^|[\s/])\.git/".into()),
                server_pattern: None,
                max_frequency: None,
            },
        ],
    }
}

fn test_runner_profile() -> ActivityProfile {
    ActivityProfile {
        name: "test_runner".into(),
        description: "Test runner invocations".into(),
        rules: vec![
            NoiseRule {
                tool_pattern: Some(r"^(pytest|jest|mocha|rspec)$".into()),
                argument_pattern: None,
                server_pattern: None,
                max_frequency: None,
            },
            NoiseRule {
                tool_pattern: Some(r"^cargo$".into()),
                argument_pattern: Some(r"^test\b".into()),
                server_pattern: None,
                max_frequency: None,
            },
            NoiseRule {
                tool_pattern: Some(r"^go$".into()),
                argument_pattern: Some(r"^test\b".into()),
                server_pattern: None,
                max_frequency: None,
            },
            NoiseRule {
                tool_pattern: Some(r"^npm$".into()),
                argument_pattern: Some(r"^test\b".into()),
                server_pattern: None,
                max_frequency: None,
            },
        ],
    }
}

/// TOML config file structure.
#[derive(Deserialize)]
struct NoiseConfig {
    #[serde(default)]
    rules: Vec<TomlRule>,
}

#[derive(Deserialize)]
struct TomlRule {
    #[allow(dead_code)]
    description: Option<String>,
    tool_pattern: Option<String>,
    argument_pattern: Option<String>,
    server_pattern: Option<String>,
    max_frequency: Option<u32>,
}

/// Load custom noise rules from a TOML file.
pub fn load_custom_rules(path: &Path) -> Result<Vec<NoiseRule>> {
    let content = std::fs::read_to_string(path)?;
    parse_custom_rules(&content)
}

/// Parse custom noise rules from TOML content.
pub fn parse_custom_rules(content: &str) -> Result<Vec<NoiseRule>> {
    let config: NoiseConfig = toml::from_str(content)?;
    Ok(config
        .rules
        .into_iter()
        .map(|r| NoiseRule {
            tool_pattern: r.tool_pattern,
            argument_pattern: r.argument_pattern,
            server_pattern: r.server_pattern,
            max_frequency: r.max_frequency,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_profiles_count() {
        assert_eq!(builtin_profiles().len(), 5);
    }

    #[test]
    fn test_parse_custom_rules() {
        let toml = r#"
[[rules]]
description = "My custom build tool"
tool_pattern = "run_command"
argument_pattern = "bazel build.*"

[[rules]]
description = "Another rule"
server_pattern = "*custom-server*"
"#;
        let rules = parse_custom_rules(toml).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].tool_pattern.as_deref(), Some("run_command"));
        assert_eq!(rules[0].argument_pattern.as_deref(), Some("bazel build.*"));
        assert!(rules[0].server_pattern.is_none());
        assert_eq!(rules[1].server_pattern.as_deref(), Some("*custom-server*"));
    }
}
