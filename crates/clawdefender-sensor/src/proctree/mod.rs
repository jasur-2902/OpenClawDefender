//! Process tree tracking and agent identification.
//!
//! Maintains an in-memory snapshot of the process tree so that events from
//! eslogger can be attributed to a specific AI agent session.

pub mod agent_id;

use std::collections::HashMap;
use std::time::Instant;

use anyhow::Result;
use chrono::{DateTime, Utc};
use sysinfo::{ProcessesToUpdate, System};
use tracing::warn;

pub use agent_id::{identify_agent, AgentInfo, Confidence};

/// Default TTL for ancestry cache entries (5 seconds).
const ANCESTRY_CACHE_TTL_SECS: u64 = 5;

/// Maximum number of processes tracked in the tree before warning.
const MAX_PROCESS_TREE_SIZE: usize = 10_000;

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

/// Cached ancestry entry.
struct AncestryCache {
    ancestry: Vec<ProcessInfo>,
    cached_at: Instant,
}

/// Registered tagged agent entry.
#[derive(Debug, Clone)]
struct TaggedAgent {
    agent_name: String,
    client_name: String,
    start_time: Option<DateTime<Utc>>,
}

/// In-memory process tree built from OS data.
pub struct ProcessTree {
    processes: HashMap<u32, ProcessInfo>,
    /// Registered AI agent processes (tagged via MCP proxy).
    agents: HashMap<u32, TaggedAgent>,
    /// Ancestry cache with TTL.
    ancestry_cache: HashMap<u32, AncestryCache>,
}

impl ProcessTree {
    /// Create an empty process tree.
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            agents: HashMap::new(),
            ancestry_cache: HashMap::new(),
        }
    }

    /// Refresh the process tree from the OS using sysinfo.
    pub fn refresh(&mut self) -> Result<()> {
        self.processes.clear();
        self.ancestry_cache.clear();

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

        if self.processes.len() > MAX_PROCESS_TREE_SIZE {
            warn!(
                count = self.processes.len(),
                max = MAX_PROCESS_TREE_SIZE,
                "process tree exceeds size limit after refresh"
            );
        }

        Ok(())
    }

    /// Check whether the given PID belongs to a registered AI agent,
    /// or is detected as one via heuristics.
    ///
    /// Also verifies start_time matches for tagged agents to prevent
    /// false identification after PID recycling.
    pub fn is_agent(&self, pid: u32) -> bool {
        // Check tagged agents with start_time verification
        if let Some(tagged) = self.agents.get(&pid) {
            // If we have both start times, verify they match
            if let (Some(tagged_st), Some(proc)) = (tagged.start_time, self.processes.get(&pid)) {
                if let Some(proc_st) = proc.start_time {
                    if tagged_st != proc_st {
                        // PID was recycled — this is a different process
                        return false;
                    }
                }
            }
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
    /// breaks). Results are cached for 5 seconds.
    pub fn get_ancestry(&self, pid: u32) -> Vec<&ProcessInfo> {
        // Check cache (we need to use unsafe-free approach: compute directly
        // since returning references to cache would require &mut self or RefCell)
        // The cache stores owned ProcessInfo, but callers need &ProcessInfo from
        // self.processes. We cache the PIDs instead.
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

    /// Get cached ancestry as owned ProcessInfo vec, using TTL cache.
    pub fn get_ancestry_cached(&mut self, pid: u32) -> Vec<ProcessInfo> {
        // Check cache
        if let Some(entry) = self.ancestry_cache.get(&pid) {
            if entry.cached_at.elapsed().as_secs() < ANCESTRY_CACHE_TTL_SECS {
                return entry.ancestry.clone();
            }
        }

        // Compute and cache
        let ancestry: Vec<ProcessInfo> = self.get_ancestry(pid).into_iter().cloned().collect();
        self.ancestry_cache.insert(pid, AncestryCache {
            ancestry: ancestry.clone(),
            cached_at: Instant::now(),
        });
        ancestry
    }

    /// Register a process as a known AI agent (Layer 1: Tagged).
    ///
    /// Records the process start_time (if available) to guard against
    /// PID recycling.
    pub fn register_agent(&mut self, pid: u32, name: String, client: String) {
        let start_time = self.processes.get(&pid).and_then(|p| p.start_time);
        self.agents.insert(pid, TaggedAgent {
            agent_name: name,
            client_name: client,
            start_time,
        });
    }

    /// Get tagged agent info for a PID (used by identify_agent Layer 1).
    pub fn get_tagged_agent(&self, pid: u32) -> Option<AgentInfo> {
        let tagged = self.agents.get(&pid)?;

        // Verify start_time if we can
        if let Some(tagged_st) = tagged.start_time {
            if let Some(proc) = self.processes.get(&pid) {
                if let Some(proc_st) = proc.start_time {
                    if tagged_st != proc_st {
                        return None; // PID recycled
                    }
                }
            }
        }

        Some(AgentInfo {
            agent_name: tagged.agent_name.clone(),
            client_name: tagged.client_name.clone(),
            confidence: Confidence::Tagged,
        })
    }

    /// Handle process exit: remove from agents and processes maps.
    ///
    /// Prevents stale PID reuse by cleaning up all state for the exited process.
    pub fn handle_exit(&mut self, pid: u32) {
        self.agents.remove(&pid);
        self.processes.remove(&pid);
        self.ancestry_cache.remove(&pid);
    }

    /// Look up a process by PID.
    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.processes.get(&pid)
    }

    /// Insert or update a process entry (used by event handlers).
    ///
    /// If the tree has reached [`MAX_PROCESS_TREE_SIZE`] and this is a new PID
    /// (not an update), the insert is skipped and a warning is logged.
    pub fn insert(&mut self, info: ProcessInfo) {
        let is_update = self.processes.contains_key(&info.pid);
        if !is_update && self.processes.len() >= MAX_PROCESS_TREE_SIZE {
            warn!(
                pid = info.pid,
                max = MAX_PROCESS_TREE_SIZE,
                "process tree at capacity, dropping new entry"
            );
            return;
        }
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

    fn make_proc_with_start(
        pid: u32,
        ppid: u32,
        name: &str,
        path: &str,
        start_time: Option<DateTime<Utc>>,
    ) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.to_string(),
            path: path.to_string(),
            args: Vec::new(),
            start_time,
        }
    }

    // --- Existing tests (preserved) ---

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
        assert!(!tree.is_empty());
    }

    // --- New tests ---

    #[test]
    fn handle_exit_removes_agent_and_process() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(42, 1, "node", "/usr/bin/node"));
        tree.register_agent(42, "claude".to_string(), "Claude".to_string());
        assert!(tree.is_agent(42));

        tree.handle_exit(42);
        assert!(!tree.is_agent(42));
        assert!(tree.get(42).is_none());
    }

    #[test]
    fn pid_recycling_detection() {
        let mut tree = ProcessTree::new();
        let t1 = DateTime::from_timestamp(1000, 0);
        let t2 = DateTime::from_timestamp(2000, 0);

        // Register agent with start_time t1
        tree.insert(make_proc_with_start(42, 1, "node", "/usr/bin/node", t1));
        tree.register_agent(42, "claude".to_string(), "Claude".to_string());
        assert!(tree.is_agent(42));

        // Simulate PID recycling: new process with same PID but different start_time
        tree.insert(make_proc_with_start(42, 1, "vim", "/usr/bin/vim", t2));
        assert!(!tree.is_agent(42));
    }

    #[test]
    fn pid_recycling_handle_exit_then_new_process() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(42, 1, "node", "/usr/bin/node"));
        tree.register_agent(42, "claude".to_string(), "Claude".to_string());
        assert!(tree.is_agent(42));

        // Process exits
        tree.handle_exit(42);
        assert!(!tree.is_agent(42));

        // New process reuses PID 42
        tree.insert(make_proc(42, 1, "vim", "/usr/bin/vim"));
        assert!(!tree.is_agent(42));
    }

    #[test]
    fn ancestry_cache_works() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(1, 0, "launchd", "/sbin/launchd"));
        tree.insert(make_proc(100, 1, "zsh", "/bin/zsh"));

        // First call computes and caches
        let a1 = tree.get_ancestry_cached(100);
        assert_eq!(a1.len(), 2);

        // Second call within TTL should return cached result
        let a2 = tree.get_ancestry_cached(100);
        assert_eq!(a2.len(), 2);
        assert_eq!(a1[0].pid, a2[0].pid);
    }

    #[test]
    fn ancestry_cache_invalidated_on_refresh() {
        let mut tree = ProcessTree::new();
        tree.insert(make_proc(1, 0, "launchd", "/sbin/launchd"));
        tree.insert(make_proc(100, 1, "zsh", "/bin/zsh"));

        // Populate cache
        let _ = tree.get_ancestry_cached(100);
        assert!(tree.ancestry_cache.contains_key(&100));

        // Refresh clears cache
        tree.refresh().expect("refresh should succeed");
        assert!(!tree.ancestry_cache.contains_key(&100));
    }

    #[test]
    fn get_tagged_agent_returns_none_for_recycled_pid() {
        let mut tree = ProcessTree::new();
        let t1 = DateTime::from_timestamp(1000, 0);
        let t2 = DateTime::from_timestamp(2000, 0);

        tree.insert(make_proc_with_start(42, 1, "node", "/usr/bin/node", t1));
        tree.register_agent(42, "claude".to_string(), "Claude".to_string());

        // Verify it works normally
        assert!(tree.get_tagged_agent(42).is_some());

        // Simulate PID recycling
        tree.insert(make_proc_with_start(42, 1, "vim", "/usr/bin/vim", t2));
        assert!(tree.get_tagged_agent(42).is_none());
    }

    #[test]
    fn handle_exit_idempotent() {
        let mut tree = ProcessTree::new();
        // Calling handle_exit on non-existent PID should not panic
        tree.handle_exit(999);
        tree.handle_exit(999);
    }
}
