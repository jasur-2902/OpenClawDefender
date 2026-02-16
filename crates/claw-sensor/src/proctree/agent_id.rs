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
/// Checks the process name against [`KNOWN_MCP_CLIENTS`]. Returns `Some` with
/// [`Confidence::Known`] if a match is found, otherwise `None`.
// TODO: Phase 2 — heuristic detection via ancestry walking, runtime detection
pub fn identify_agent(process: &ProcessInfo, _tree: &ProcessTree) -> Option<AgentInfo> {
    let proc_name = process
        .path
        .rsplit('/')
        .next()
        .unwrap_or(&process.name);

    for &client in KNOWN_MCP_CLIENTS {
        if proc_name.eq_ignore_ascii_case(client) {
            return Some(AgentInfo {
                agent_name: proc_name.to_string(),
                client_name: client.to_string(),
                confidence: Confidence::Known,
            });
        }
    }

    None
}
