//! Process tree tracking and agent identification.
//!
//! Maintains an in-memory snapshot of the process tree so that events from
//! eslogger can be attributed to a specific AI agent session.

pub mod agent_id;

use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};

pub use agent_id::{identify_agent, AgentInfo, Confidence};

/// Information about a single process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub args: Vec<String>,
    pub start_time: Option<DateTime<Utc>>,
}

/// In-memory process tree built from OS data.
pub struct ProcessTree {
    processes: HashMap<u32, ProcessInfo>,
    /// Registered AI agent processes.
    agents: HashMap<u32, (String, String)>, // pid -> (agent_name, client)
}

impl ProcessTree {
    /// Create an empty process tree.
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            agents: HashMap::new(),
        }
    }

    /// Refresh the process tree from the OS.
    ///
    /// In production this will use `libc::proc_listallpids` and `proc_pidpath`
    /// via FFI to enumerate all running processes.
    // TODO: Phase 2 — implement FFI calls to libproc
    pub fn refresh(&mut self) -> Result<()> {
        self.processes.clear();
        Ok(())
    }

    /// Check whether the given PID belongs to a registered AI agent.
    // TODO: Phase 2 — walk ancestry to detect agent lineage
    pub fn is_agent(&self, pid: u32) -> bool {
        self.agents.contains_key(&pid)
    }

    /// Walk up the parent chain from the given PID, returning ancestors
    /// in order from the process itself up to the root (or until the chain
    /// breaks).
    pub fn get_ancestry(&self, pid: u32) -> Vec<&ProcessInfo> {
        let mut result = Vec::new();
        let mut current = pid;
        // Guard against cycles with a reasonable depth limit.
        let max_depth = 128;
        for _ in 0..max_depth {
            match self.processes.get(&current) {
                Some(info) => {
                    result.push(info);
                    if info.ppid == 0 || info.ppid == current {
                        break;
                    }
                    current = info.ppid;
                }
                None => break,
            }
        }
        result
    }

    /// Register a process as a known AI agent.
    pub fn register_agent(&mut self, pid: u32, name: String, client: String) {
        self.agents.insert(pid, (name, client));
    }

    /// Look up a process by PID.
    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.processes.get(&pid)
    }

    /// Insert or update a process entry (used by event handlers).
    pub fn insert(&mut self, info: ProcessInfo) {
        self.processes.insert(info.pid, info);
    }
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self::new()
    }
}
