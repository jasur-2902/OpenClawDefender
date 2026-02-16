//! Agent process identification heuristics.
//!
//! Detects whether a process belongs to or was spawned by a known AI coding
//! agent by checking executable names and ancestry against known signatures.

use super::{ProcessInfo, ProcessTree};

/// Well-known MCP client application names.
pub const KNOWN_MCP_CLIENTS: &[&str] = &["Claude", "Cursor", "Code", "Windsurf", "Zed"];

/// Well-known runtimes commonly used by AI agent tool-call subprocesses.
pub const KNOWN_AGENT_RUNTIMES: &[&str] = &["node", "python", "deno", "bun"];

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

/// Attempt to identify a process as a known AI agent.
///
/// Checks the process name against [`KNOWN_MCP_CLIENTS`] (case-insensitive).
/// If no direct match, checks the process path for known agent runtime patterns.
/// Finally, walks the ancestry to see if any ancestor is a known MCP client.
pub fn identify_agent(process: &ProcessInfo, tree: &ProcessTree) -> Option<AgentInfo> {
    let proc_name = process
        .path
        .rsplit('/')
        .next()
        .unwrap_or(&process.name);

    // Direct match against known MCP clients
    for &client in KNOWN_MCP_CLIENTS {
        if proc_name.eq_ignore_ascii_case(client) {
            return Some(AgentInfo {
                agent_name: proc_name.to_string(),
                client_name: client.to_string(),
                confidence: Confidence::Known,
            });
        }
    }

    // Check if the process name matches a known MCP client name pattern in path
    let lower_path = process.path.to_ascii_lowercase();
    for &client in KNOWN_MCP_CLIENTS {
        let pattern = format!("/{}/", client.to_ascii_lowercase());
        if lower_path.contains(&pattern) {
            return Some(AgentInfo {
                agent_name: proc_name.to_string(),
                client_name: client.to_string(),
                confidence: Confidence::Heuristic,
            });
        }
    }

    // Walk ancestry: if any ancestor is a known MCP client, tag as Heuristic
    let ancestry = tree.get_ancestry(process.pid);
    // Skip the first entry (the process itself) since we already checked it
    for ancestor in ancestry.iter().skip(1) {
        let ancestor_name = ancestor
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&ancestor.name);

        for &client in KNOWN_MCP_CLIENTS {
            if ancestor_name.eq_ignore_ascii_case(client) {
                return Some(AgentInfo {
                    agent_name: proc_name.to_string(),
                    client_name: client.to_string(),
                    confidence: Confidence::Heuristic,
                });
            }
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

    #[test]
    fn identify_known_client_by_name() {
        let tree = ProcessTree::new();
        let proc_info = make_proc(1, 0, "Claude", "/Applications/Claude.app/Contents/MacOS/Claude");
        let result = identify_agent(&proc_info, &tree);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.confidence, Confidence::Known);
        assert_eq!(info.client_name, "Claude");
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
        tree.insert(make_proc(1, 0, "Claude", "/Applications/Claude.app/Contents/MacOS/Claude"));
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
        assert_eq!(info.confidence, Confidence::Heuristic);
        assert_eq!(info.client_name, "Cursor");
    }
}
