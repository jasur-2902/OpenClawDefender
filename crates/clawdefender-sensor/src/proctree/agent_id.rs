//! Agent process identification heuristics.
//!
//! Detects whether a process belongs to or was spawned by a known AI coding
//! agent using a 4-layer identification strategy:
//!
//! 1. **Tagged** — explicitly registered by MCP proxy via `register_agent()`
//! 2. **Known** — executable name or path matches a known MCP client
//! 3. **Heuristic** — runtime process with MCP-related command-line arguments
//! 4. **Transitive** — parent is an identified agent, child inherits

use super::{ProcessInfo, ProcessTree};

/// Well-known MCP client application names.
pub const KNOWN_MCP_CLIENTS: &[&str] = &["Claude", "Cursor", "Code", "Windsurf", "Zed"];

/// Extended client signatures: (display_name, name_patterns, path_patterns).
const CLIENT_SIGNATURES: &[(&str, &[&str], &[&str])] = &[
    (
        "Claude",
        &["Claude"],
        &["Claude.app/Contents/MacOS/"],
    ),
    (
        "Cursor",
        &["Cursor", "Cursor Helper"],
        &["Cursor.app/"],
    ),
    (
        "VS Code",
        &["Code", "Code Helper"],
        &["Code.app/"],
    ),
    (
        "Windsurf",
        &["Windsurf"],
        &["Windsurf.app/"],
    ),
    (
        "Zed",
        &["Zed"],
        &["Zed.app/"],
    ),
];

/// Well-known runtimes commonly used by AI agent tool-call subprocesses.
pub const KNOWN_AGENT_RUNTIMES: &[&str] = &["node", "python", "python3", "ruby", "deno", "bun"];

/// MCP-related keywords to look for in command-line arguments.
const MCP_ARG_KEYWORDS: &[&str] = &["mcp", "model-context-protocol", "@modelcontextprotocol"];

/// Confidence level for agent identification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    /// Process name directly matches a known MCP client.
    Known,
    /// Identified via heuristic rules (ancestry, runtime patterns).
    Heuristic,
    /// Explicitly tagged by the agent itself (e.g. via MCP registration).
    Tagged,
}

/// Identified agent information.
#[derive(Debug, Clone)]
pub struct AgentInfo {
    pub agent_name: String,
    pub client_name: String,
    pub confidence: Confidence,
}

/// Attempt to identify a process as a known AI agent using 4-layer detection.
///
/// Layers are checked in priority order:
/// 1. Tagged agents (registered via MCP proxy)
/// 2. Known MCP client by name or path
/// 3. Runtime heuristic (node/python with MCP args)
/// 4. Transitive (parent identified → child inherits)
pub fn identify_agent(process: &ProcessInfo, tree: &ProcessTree) -> Option<AgentInfo> {
    // Layer 1: Tagged — check registered agents
    if let Some(info) = tree.get_tagged_agent(process.pid) {
        return Some(info);
    }

    // Layer 2: Known MCP client — check process name and path
    if let Some(info) = check_known_client(process) {
        return Some(info);
    }

    // Layer 3: Runtime heuristic — runtime + MCP args
    if let Some(info) = check_runtime_heuristic(process) {
        return Some(info);
    }

    // Layer 4: Transitive — walk ancestry for identified agents
    check_transitive(process, tree)
}

/// Layer 2: Check if the process itself is a known MCP client.
fn check_known_client(process: &ProcessInfo) -> Option<AgentInfo> {
    let proc_name = process
        .path
        .rsplit('/')
        .next()
        .unwrap_or(&process.name);

    for &(display_name, name_patterns, path_patterns) in CLIENT_SIGNATURES {
        // Check executable name
        for &name_pat in name_patterns {
            if proc_name.eq_ignore_ascii_case(name_pat) {
                return Some(AgentInfo {
                    agent_name: proc_name.to_string(),
                    client_name: display_name.to_string(),
                    confidence: Confidence::Known,
                });
            }
        }

        // Check path patterns
        for &path_pat in path_patterns {
            if process.path.contains(path_pat) {
                return Some(AgentInfo {
                    agent_name: proc_name.to_string(),
                    client_name: display_name.to_string(),
                    confidence: Confidence::Known,
                });
            }
        }
    }

    // Backwards compat: also check the flat KNOWN_MCP_CLIENTS list (case insensitive)
    for &client in KNOWN_MCP_CLIENTS {
        if proc_name.eq_ignore_ascii_case(client) {
            return Some(AgentInfo {
                agent_name: proc_name.to_string(),
                client_name: client.to_string(),
                confidence: Confidence::Known,
            });
        }

        // Path contains client name as directory component
        let lower_path = process.path.to_ascii_lowercase();
        let pattern = format!("/{}/", client.to_ascii_lowercase());
        if lower_path.contains(&pattern) {
            return Some(AgentInfo {
                agent_name: proc_name.to_string(),
                client_name: client.to_string(),
                confidence: Confidence::Known,
            });
        }
    }

    None
}

/// Layer 3: Check if process is a known runtime with MCP-related args.
fn check_runtime_heuristic(process: &ProcessInfo) -> Option<AgentInfo> {
    let proc_name = process
        .path
        .rsplit('/')
        .next()
        .unwrap_or(&process.name);

    let is_runtime = KNOWN_AGENT_RUNTIMES
        .iter()
        .any(|r| proc_name.eq_ignore_ascii_case(r));

    if !is_runtime {
        return None;
    }

    // Check command-line args for MCP keywords
    let args_joined = process.args.join(" ").to_ascii_lowercase();
    for &keyword in MCP_ARG_KEYWORDS {
        if args_joined.contains(keyword) {
            return Some(AgentInfo {
                agent_name: proc_name.to_string(),
                client_name: "unknown".to_string(),
                confidence: Confidence::Heuristic,
            });
        }
    }

    None
}

/// Layer 4: Transitive identification — walk ancestry, if parent is an agent, child inherits.
/// Known parent → Heuristic child. Heuristic parent → Heuristic child.
fn check_transitive(process: &ProcessInfo, tree: &ProcessTree) -> Option<AgentInfo> {
    let proc_name = process
        .path
        .rsplit('/')
        .next()
        .unwrap_or(&process.name);

    let ancestry = tree.get_ancestry(process.pid);
    // Skip the first entry (the process itself)
    for ancestor in ancestry.iter().skip(1) {
        // Check if ancestor is a tagged agent
        if let Some(info) = tree.get_tagged_agent(ancestor.pid) {
            return Some(AgentInfo {
                agent_name: proc_name.to_string(),
                client_name: info.client_name,
                confidence: Confidence::Heuristic,
            });
        }

        // Check if ancestor is a known client
        if let Some(info) = check_known_client(ancestor) {
            return Some(AgentInfo {
                agent_name: proc_name.to_string(),
                client_name: info.client_name,
                confidence: Confidence::Heuristic,
            });
        }

        // Check if ancestor has MCP runtime heuristic
        if let Some(info) = check_runtime_heuristic(ancestor) {
            return Some(AgentInfo {
                agent_name: proc_name.to_string(),
                client_name: info.client_name,
                confidence: Confidence::Heuristic,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: u32, ppid: u32, name: &str, path: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.to_string(),
            path: path.to_string(),
            args: Vec::new(),
            start_time: None,
        }
    }

    fn make_proc_with_args(
        pid: u32,
        ppid: u32,
        name: &str,
        path: &str,
        args: Vec<&str>,
    ) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.to_string(),
            path: path.to_string(),
            args: args.into_iter().map(|s| s.to_string()).collect(),
            start_time: None,
        }
    }

    // --- Existing tests (preserved) ---

    #[test]
    fn identify_known_client_by_name() {
        let tree = ProcessTree::new();
        let proc_info =
            make_proc(1, 0, "Claude", "/Applications/Claude.app/Contents/MacOS/Claude");
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.confidence, Confidence::Known);
        assert!(
            info.client_name == "Claude",
            "expected Claude, got {}",
            info.client_name
        );
    }

    #[test]
    fn identify_known_client_case_insensitive() {
        let tree = ProcessTree::new();
        let proc_info = make_proc(1, 0, "cursor", "/usr/bin/cursor");
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_some());
        assert_eq!(result.unwrap().client_name, "Cursor");
    }

    #[test]
    fn unknown_process_returns_none() {
        let tree = ProcessTree::new();
        let proc_info = make_proc(1, 0, "vim", "/usr/bin/vim");
        assert!(identify_agent(&proc_info, &tree).is_none());
    }

    #[test]
    fn identify_via_ancestry() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(
            1,
            0,
            "Claude",
            "/Applications/Claude.app/Contents/MacOS/Claude",
        ));
        tree.insert(make_proc(100, 1, "node", "/usr/local/bin/node"));

        let proc_info = tree.get(100).unwrap();
        let result = identify_agent(proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.confidence, Confidence::Heuristic);
        assert_eq!(info.client_name, "Claude");
    }

    #[test]
    fn identify_via_path_pattern() {
        let tree = ProcessTree::new();
        let proc_info = make_proc(1, 0, "node", "/Applications/cursor/resources/node");
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        // Now detected as Known via path pattern in KNOWN_MCP_CLIENTS fallback
        assert_eq!(info.client_name, "Cursor");
    }

    // --- New 4-layer tests ---

    #[test]
    fn layer1_tagged_agent_highest_priority() {
        let mut tree = ProcessTree::new();
        // Insert a process that is also a known client name, but tagged should win
        tree.insert(make_proc(42, 1, "node", "/usr/bin/node"));
        tree.register_agent(42, "my-agent".to_string(), "Claude".to_string());

        let proc_info = tree.get(42).unwrap();
        let result = identify_agent(proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.confidence, Confidence::Tagged);
        assert_eq!(info.agent_name, "my-agent");
        assert_eq!(info.client_name, "Claude");
    }

    #[test]
    fn layer2_known_client_by_path() {
        let tree = ProcessTree::new();
        let proc_info = make_proc(
            1,
            0,
            "Cursor Helper",
            "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper",
        );
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.confidence, Confidence::Known);
        assert_eq!(info.client_name, "Cursor");
    }

    #[test]
    fn layer2_vscode_detection() {
        let tree = ProcessTree::new();
        let proc_info = make_proc(
            1,
            0,
            "Code Helper",
            "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper",
        );
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.client_name, "VS Code");
    }

    #[test]
    fn layer3_runtime_with_mcp_args() {
        let tree = ProcessTree::new();
        let proc_info = make_proc_with_args(
            1,
            0,
            "node",
            "/usr/local/bin/node",
            vec!["/usr/local/bin/node", "server.js", "--mcp"],
        );
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.confidence, Confidence::Heuristic);
    }

    #[test]
    fn layer3_python_with_modelcontextprotocol_arg() {
        let tree = ProcessTree::new();
        let proc_info = make_proc_with_args(
            1,
            0,
            "python3",
            "/usr/bin/python3",
            vec!["python3", "-m", "@modelcontextprotocol/server"],
        );
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.confidence, Confidence::Heuristic);
    }

    #[test]
    fn layer3_runtime_without_mcp_args_returns_none() {
        let tree = ProcessTree::new();
        let proc_info = make_proc_with_args(
            1,
            0,
            "node",
            "/usr/local/bin/node",
            vec!["node", "index.js"],
        );
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_none());
    }

    #[test]
    fn layer4_transitive_from_known_parent() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(
            1,
            0,
            "Claude",
            "/Applications/Claude.app/Contents/MacOS/Claude",
        ));
        tree.insert(make_proc(100, 1, "node", "/usr/local/bin/node"));
        tree.insert(make_proc(200, 100, "npm", "/usr/local/bin/npm"));

        // Grandchild should inherit via transitive layer
        let proc_info = tree.get(200).unwrap();
        let result = identify_agent(proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.confidence, Confidence::Heuristic);
        assert_eq!(info.client_name, "Claude");
    }

    #[test]
    fn layer4_transitive_from_tagged_parent() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(10, 0, "node", "/usr/bin/node"));
        tree.insert(make_proc(20, 10, "bash", "/bin/bash"));
        tree.register_agent(10, "mcp-server".to_string(), "Claude".to_string());

        let proc_info = tree.get(20).unwrap();
        let result = identify_agent(proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.confidence, Confidence::Heuristic);
        assert_eq!(info.client_name, "Claude");
    }

    #[test]
    fn windsurf_detection() {
        let tree = ProcessTree::new();
        let proc_info = make_proc(
            1,
            0,
            "Windsurf",
            "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
        );
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_some());
        assert_eq!(result.unwrap().client_name, "Windsurf");
    }

    #[test]
    fn zed_detection() {
        let tree = ProcessTree::new();
        let proc_info =
            make_proc(1, 0, "Zed", "/Applications/Zed.app/Contents/MacOS/Zed");
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_some());
        assert_eq!(result.unwrap().client_name, "Zed");
    }
}
