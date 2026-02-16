//! Process tree tracking and agent identification.
//!
//! Maintains an in-memory snapshot of the process tree so that events from
//! eslogger can be attributed to a specific AI agent session.

pub mod agent_id;

use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use sysinfo::{ProcessesToUpdate, System};

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

    /// Refresh the process tree from the OS using sysinfo.
    pub fn refresh(&mut self) -> Result<()> {
        self.processes.clear();

        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        for (raw_pid, process) in sys.processes() {
            let pid = raw_pid.as_u32();
            let ppid = process
                .parent()
                .map(|p| p.as_u32())
                .unwrap_or(0);

            let exe_path = process
                .exe()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();

            let start_time = {
                let secs = process.start_time();
                if secs > 0 {
                    DateTime::from_timestamp(secs as i64, 0)
                } else {
                    None
                }
            };

            let info = ProcessInfo {
                pid,
                ppid,
                name: process.name().to_string_lossy().into_owned(),
                path: exe_path,
                args: process.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect(),
                start_time,
            };
            self.processes.insert(pid, info);
        }

        Ok(())
    }

    /// Check whether the given PID belongs to a registered AI agent,
    /// or is detected as one via heuristics.
    pub fn is_agent(&self, pid: u32) -> bool {
        if self.agents.contains_key(&pid) {
            return true;
        }
        if let Some(proc_info) = self.processes.get(&pid) {
            if identify_agent(proc_info, self).is_some() {
                return true;
            }
        }
        false
    }

    /// Walk up the parent chain from the given PID, returning ancestors
    /// in order from the process itself up to the root (or until the chain
    /// breaks).
    pub fn get_ancestry(&self, pid: u32) -> Vec<&ProcessInfo> {
        let mut result = Vec::new();
        let mut current = pid;
        let max_depth = 100;
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

    /// Return the number of tracked processes.
    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self::new()
    }
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
    fn get_ancestry_returns_chain() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(1, 0, "launchd", "/sbin/launchd"));
        tree.insert(make_proc(100, 1, "zsh", "/bin/zsh"));
        tree.insert(make_proc(200, 100, "node", "/usr/local/bin/node"));
        tree.insert(make_proc(300, 200, "npm", "/usr/local/bin/npm"));

        let ancestry = tree.get_ancestry(300);
        assert_eq!(ancestry.len(), 4);
        assert_eq!(ancestry[0].pid, 300);
        assert_eq!(ancestry[1].pid, 200);
        assert_eq!(ancestry[2].pid, 100);
        assert_eq!(ancestry[3].pid, 1);
    }

    #[test]
    fn get_ancestry_handles_missing_parent() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(500, 999, "orphan", "/bin/orphan"));

        let ancestry = tree.get_ancestry(500);
        assert_eq!(ancestry.len(), 1);
        assert_eq!(ancestry[0].pid, 500);
    }

    #[test]
    fn get_ancestry_handles_cycle() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(10, 10, "self-parent", "/bin/self"));

        let ancestry = tree.get_ancestry(10);
        assert_eq!(ancestry.len(), 1);
    }

    #[test]
    fn is_agent_with_registered() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(42, 1, "node", "/usr/bin/node"));
        tree.register_agent(42, "claude".to_string(), "Claude".to_string());
        assert!(tree.is_agent(42));
        assert!(!tree.is_agent(99));
    }

    #[test]
    fn is_agent_detects_known_client() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(50, 1, "Cursor", "/Applications/Cursor.app/Contents/MacOS/Cursor"));
        assert!(tree.is_agent(50));
    }

    #[test]
    fn refresh_populates_processes() {
        let mut tree = ProcessTree::new();
        tree.refresh().expect("refresh should succeed");
        // We should have at least our own process
        assert!(!tree.is_empty());
    }
}
