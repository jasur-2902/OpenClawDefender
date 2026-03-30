use serde::{Deserialize, Serialize};

/// Describes what a given MCP server can do (filesystem, shell, network, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    pub can_read_files: bool,
    pub can_write_files: bool,
    pub can_execute_commands: bool,
    pub can_access_network: bool,
    pub can_sample_llm: bool,
    pub tools: Vec<ToolInfo>,
    /// How capabilities were determined: "known_database", "inferred", "observed".
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub category: String,
    pub risk_level: String,
}

impl Default for ServerCapabilities {
    fn default() -> Self {
        Self {
            can_read_files: false,
            can_write_files: false,
            can_execute_commands: false,
            can_access_network: false,
            can_sample_llm: false,
            tools: Vec::new(),
            source: "inferred".to_string(),
        }
    }
}

struct KnownServer {
    can_read_files: bool,
    can_write_files: bool,
    can_execute_commands: bool,
    can_access_network: bool,
    can_sample_llm: bool,
    tools: &'static [(&'static str, &'static str, &'static str)],
}

/// Returns the known capabilities database as a static map.
fn known_servers() -> Vec<(&'static str, KnownServer)> {
    vec![
        (
            "@modelcontextprotocol/server-filesystem",
            KnownServer {
                can_read_files: true,
                can_write_files: true,
                can_execute_commands: false,
                can_access_network: false,
                can_sample_llm: false,
                tools: &[
                    ("read_file", "filesystem", "low"),
                    ("write_file", "filesystem", "medium"),
                    ("list_directory", "filesystem", "low"),
                    ("create_directory", "filesystem", "medium"),
                    ("move_file", "filesystem", "medium"),
                    ("search_files", "filesystem", "low"),
                ],
            },
        ),
        (
            "@modelcontextprotocol/server-fetch",
            KnownServer {
                can_read_files: false,
                can_write_files: false,
                can_execute_commands: false,
                can_access_network: true,
                can_sample_llm: false,
                tools: &[("fetch", "network", "medium")],
            },
        ),
        (
            "@modelcontextprotocol/server-git",
            KnownServer {
                can_read_files: true,
                can_write_files: true,
                can_execute_commands: true,
                can_access_network: true,
                can_sample_llm: false,
                tools: &[
                    ("git_clone", "execution", "high"),
                    ("git_commit", "filesystem", "medium"),
                    ("git_push", "network", "high"),
                    ("git_status", "filesystem", "low"),
                    ("git_diff", "filesystem", "low"),
                ],
            },
        ),
        (
            "@modelcontextprotocol/server-postgres",
            KnownServer {
                can_read_files: false,
                can_write_files: false,
                can_execute_commands: false,
                can_access_network: true,
                can_sample_llm: false,
                tools: &[("query", "network", "high")],
            },
        ),
        (
            "@modelcontextprotocol/server-brave-search",
            KnownServer {
                can_read_files: false,
                can_write_files: false,
                can_execute_commands: false,
                can_access_network: true,
                can_sample_llm: false,
                tools: &[("brave_web_search", "network", "low")],
            },
        ),
        (
            "@modelcontextprotocol/server-github",
            KnownServer {
                can_read_files: false,
                can_write_files: false,
                can_execute_commands: false,
                can_access_network: true,
                can_sample_llm: false,
                tools: &[
                    ("create_issue", "network", "medium"),
                    ("list_issues", "network", "low"),
                    ("create_pull_request", "network", "medium"),
                    ("search_repositories", "network", "low"),
                ],
            },
        ),
        (
            "@modelcontextprotocol/server-memory",
            KnownServer {
                can_read_files: false,
                can_write_files: false,
                can_execute_commands: false,
                can_access_network: false,
                can_sample_llm: false,
                tools: &[
                    ("store", "other", "low"),
                    ("retrieve", "other", "low"),
                ],
            },
        ),
        (
            "@modelcontextprotocol/server-puppeteer",
            KnownServer {
                can_read_files: false,
                can_write_files: false,
                can_execute_commands: true,
                can_access_network: true,
                can_sample_llm: false,
                tools: &[
                    ("navigate", "network", "medium"),
                    ("screenshot", "network", "low"),
                    ("click", "execution", "medium"),
                    ("evaluate", "execution", "high"),
                ],
            },
        ),
        (
            "@modelcontextprotocol/server-sqlite",
            KnownServer {
                can_read_files: true,
                can_write_files: true,
                can_execute_commands: false,
                can_access_network: false,
                can_sample_llm: false,
                tools: &[
                    ("read_query", "filesystem", "low"),
                    ("write_query", "filesystem", "medium"),
                ],
            },
        ),
        (
            "@modelcontextprotocol/server-slack",
            KnownServer {
                can_read_files: false,
                can_write_files: false,
                can_execute_commands: false,
                can_access_network: true,
                can_sample_llm: false,
                tools: &[
                    ("send_message", "network", "medium"),
                    ("list_channels", "network", "low"),
                ],
            },
        ),
        (
            "@modelcontextprotocol/server-sequential-thinking",
            KnownServer {
                can_read_files: false,
                can_write_files: false,
                can_execute_commands: false,
                can_access_network: false,
                can_sample_llm: false,
                tools: &[("think", "other", "low")],
            },
        ),
        (
            "@modelcontextprotocol/server-everything",
            KnownServer {
                can_read_files: true,
                can_write_files: true,
                can_execute_commands: true,
                can_access_network: true,
                can_sample_llm: false,
                tools: &[
                    ("read_file", "filesystem", "low"),
                    ("write_file", "filesystem", "medium"),
                    ("execute", "execution", "high"),
                    ("fetch", "network", "medium"),
                ],
            },
        ),
        (
            "@anthropic/mcp-server-claude-code",
            KnownServer {
                can_read_files: true,
                can_write_files: true,
                can_execute_commands: true,
                can_access_network: true,
                can_sample_llm: true,
                tools: &[
                    ("read_file", "filesystem", "low"),
                    ("write_file", "filesystem", "medium"),
                    ("execute_command", "execution", "high"),
                    ("web_search", "network", "medium"),
                ],
            },
        ),
        (
            "mcp-server-kubernetes",
            KnownServer {
                can_read_files: false,
                can_write_files: false,
                can_execute_commands: true,
                can_access_network: true,
                can_sample_llm: false,
                tools: &[
                    ("kubectl", "execution", "high"),
                    ("get_pods", "network", "low"),
                    ("apply_manifest", "network", "high"),
                ],
            },
        ),
        (
            "mcp-server-docker",
            KnownServer {
                can_read_files: true,
                can_write_files: true,
                can_execute_commands: true,
                can_access_network: true,
                can_sample_llm: false,
                tools: &[
                    ("docker_run", "execution", "high"),
                    ("docker_build", "execution", "high"),
                    ("docker_ps", "execution", "low"),
                    ("docker_logs", "filesystem", "low"),
                ],
            },
        ),
    ]
}

/// Try to extract a known server package name from an MCP server command line.
/// For example: `["npx", "-y", "@modelcontextprotocol/server-filesystem", "/path"]`
/// returns `Some("@modelcontextprotocol/server-filesystem")`.
fn extract_package_from_command(command: &[String]) -> Option<String> {
    for arg in command {
        // Check for known prefixes
        if arg.starts_with("@modelcontextprotocol/server-")
            || arg.starts_with("@anthropic/mcp-server-")
            || arg.starts_with("mcp-server-")
        {
            // Strip any version suffix like @1.0.0
            let pkg = if let Some(idx) = arg.rfind('@') {
                if idx > 0 {
                    &arg[..idx]
                } else {
                    arg.as_str()
                }
            } else {
                arg.as_str()
            };
            return Some(pkg.to_string());
        }
    }
    None
}

/// Infer server capabilities from the server command line.
/// Looks up the known server database first, then falls back to heuristics.
pub fn infer_capabilities(server_name: &str, command: &[String]) -> ServerCapabilities {
    // Try to extract package name from command and look up in known database
    if let Some(pkg) = extract_package_from_command(command) {
        for (known_name, known) in known_servers() {
            if pkg == known_name || pkg.ends_with(known_name) {
                return ServerCapabilities {
                    can_read_files: known.can_read_files,
                    can_write_files: known.can_write_files,
                    can_execute_commands: known.can_execute_commands,
                    can_access_network: known.can_access_network,
                    can_sample_llm: known.can_sample_llm,
                    tools: known
                        .tools
                        .iter()
                        .map(|(name, cat, risk)| ToolInfo {
                            name: name.to_string(),
                            category: cat.to_string(),
                            risk_level: risk.to_string(),
                        })
                        .collect(),
                    source: "known_database".to_string(),
                };
            }
        }
    }

    // Try matching by server_name against known server suffixes
    let name_lower = server_name.to_lowercase();
    for (known_name, known) in known_servers() {
        let suffix = known_name
            .rsplit('/')
            .next()
            .unwrap_or(known_name)
            .trim_start_matches("server-")
            .trim_start_matches("mcp-server-");
        if name_lower == suffix || name_lower.contains(suffix) {
            return ServerCapabilities {
                can_read_files: known.can_read_files,
                can_write_files: known.can_write_files,
                can_execute_commands: known.can_execute_commands,
                can_access_network: known.can_access_network,
                can_sample_llm: known.can_sample_llm,
                tools: known
                    .tools
                    .iter()
                    .map(|(name, cat, risk)| ToolInfo {
                        name: name.to_string(),
                        category: cat.to_string(),
                        risk_level: risk.to_string(),
                    })
                    .collect(),
                source: "known_database".to_string(),
            };
        }
    }

    // Heuristic fallback: unknown server
    ServerCapabilities {
        can_read_files: false,
        can_write_files: false,
        can_execute_commands: false,
        can_access_network: false,
        can_sample_llm: false,
        tools: Vec::new(),
        source: "inferred".to_string(),
    }
}

/// Suggest a trust level for a server based on its capabilities.
pub fn suggest_trust_level(caps: &ServerCapabilities) -> String {
    if caps.can_execute_commands || (caps.can_access_network && caps.can_write_files) {
        "cautious".to_string()
    } else if caps.can_access_network {
        "standard".to_string()
    } else {
        "standard".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_filesystem_server() {
        let caps = infer_capabilities(
            "filesystem",
            &[
                "npx".to_string(),
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem".to_string(),
                "/tmp".to_string(),
            ],
        );
        assert!(caps.can_read_files);
        assert!(caps.can_write_files);
        assert!(!caps.can_execute_commands);
        assert!(!caps.can_access_network);
        assert_eq!(caps.source, "known_database");
        assert!(!caps.tools.is_empty());
    }

    #[test]
    fn test_infer_fetch_server() {
        let caps = infer_capabilities(
            "fetch",
            &[
                "npx".to_string(),
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ],
        );
        assert!(!caps.can_read_files);
        assert!(caps.can_access_network);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_git_server() {
        let caps = infer_capabilities(
            "git",
            &[
                "npx".to_string(),
                "-y".to_string(),
                "@modelcontextprotocol/server-git".to_string(),
            ],
        );
        assert!(caps.can_read_files);
        assert!(caps.can_execute_commands);
        assert!(caps.can_access_network);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_brave_search() {
        let caps = infer_capabilities(
            "brave-search",
            &[
                "npx".to_string(),
                "-y".to_string(),
                "@modelcontextprotocol/server-brave-search".to_string(),
            ],
        );
        assert!(!caps.can_read_files);
        assert!(caps.can_access_network);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_memory_server() {
        let caps = infer_capabilities(
            "memory",
            &[
                "npx".to_string(),
                "-y".to_string(),
                "@modelcontextprotocol/server-memory".to_string(),
            ],
        );
        assert!(!caps.can_read_files);
        assert!(!caps.can_access_network);
        assert!(!caps.can_execute_commands);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_claude_code() {
        let caps = infer_capabilities(
            "claude-code",
            &[
                "npx".to_string(),
                "-y".to_string(),
                "@anthropic/mcp-server-claude-code".to_string(),
            ],
        );
        assert!(caps.can_read_files);
        assert!(caps.can_write_files);
        assert!(caps.can_execute_commands);
        assert!(caps.can_access_network);
        assert!(caps.can_sample_llm);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_kubernetes() {
        let caps = infer_capabilities(
            "kubernetes",
            &["npx".to_string(), "mcp-server-kubernetes".to_string()],
        );
        assert!(caps.can_execute_commands);
        assert!(caps.can_access_network);
        assert!(!caps.can_read_files);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_docker() {
        let caps = infer_capabilities(
            "docker",
            &["npx".to_string(), "mcp-server-docker".to_string()],
        );
        assert!(caps.can_read_files);
        assert!(caps.can_execute_commands);
        assert!(caps.can_access_network);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_unknown_server() {
        let caps = infer_capabilities(
            "my-custom-server",
            &["node".to_string(), "server.js".to_string()],
        );
        assert!(!caps.can_read_files);
        assert!(!caps.can_access_network);
        assert_eq!(caps.source, "inferred");
        assert!(caps.tools.is_empty());
    }

    #[test]
    fn test_infer_by_server_name_fallback() {
        // Even without package in command, should match by name
        let caps = infer_capabilities(
            "filesystem",
            &["node".to_string(), "custom-path.js".to_string()],
        );
        assert!(caps.can_read_files);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_postgres() {
        let caps = infer_capabilities(
            "postgres",
            &[
                "npx".to_string(),
                "@modelcontextprotocol/server-postgres".to_string(),
            ],
        );
        assert!(!caps.can_read_files);
        assert!(caps.can_access_network);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_sqlite() {
        let caps = infer_capabilities(
            "sqlite",
            &[
                "npx".to_string(),
                "@modelcontextprotocol/server-sqlite".to_string(),
            ],
        );
        assert!(caps.can_read_files);
        assert!(caps.can_write_files);
        assert!(!caps.can_access_network);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_slack() {
        let caps = infer_capabilities(
            "slack",
            &[
                "npx".to_string(),
                "@modelcontextprotocol/server-slack".to_string(),
            ],
        );
        assert!(caps.can_access_network);
        assert!(!caps.can_read_files);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_sequential_thinking() {
        let caps = infer_capabilities(
            "sequential-thinking",
            &[
                "npx".to_string(),
                "@modelcontextprotocol/server-sequential-thinking".to_string(),
            ],
        );
        assert!(!caps.can_read_files);
        assert!(!caps.can_access_network);
        assert!(!caps.can_execute_commands);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_infer_everything_server() {
        let caps = infer_capabilities(
            "everything",
            &[
                "npx".to_string(),
                "@modelcontextprotocol/server-everything".to_string(),
            ],
        );
        assert!(caps.can_read_files);
        assert!(caps.can_write_files);
        assert!(caps.can_execute_commands);
        assert!(caps.can_access_network);
        assert_eq!(caps.source, "known_database");
    }

    #[test]
    fn test_suggest_trust_level_cautious_for_shell() {
        let caps = ServerCapabilities {
            can_execute_commands: true,
            ..Default::default()
        };
        assert_eq!(suggest_trust_level(&caps), "cautious");
    }

    #[test]
    fn test_suggest_trust_level_standard_for_safe() {
        let caps = ServerCapabilities::default();
        assert_eq!(suggest_trust_level(&caps), "standard");
    }

    #[test]
    fn test_suggest_trust_level_cautious_for_net_and_write() {
        let caps = ServerCapabilities {
            can_access_network: true,
            can_write_files: true,
            ..Default::default()
        };
        assert_eq!(suggest_trust_level(&caps), "cautious");
    }

    #[test]
    fn test_extract_package_from_command() {
        assert_eq!(
            extract_package_from_command(&[
                "npx".to_string(),
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ]),
            Some("@modelcontextprotocol/server-fetch".to_string())
        );
    }

    #[test]
    fn test_extract_package_no_match() {
        assert_eq!(
            extract_package_from_command(&["node".to_string(), "server.js".to_string()]),
            None
        );
    }
}
