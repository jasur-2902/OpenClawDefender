//! SLM-to-Cloud context bridge.
//!
//! Builds a "briefing document" that gives Claude full system awareness on every
//! interaction. The bridge is self-contained — it defines its own simplified
//! snapshot types rather than importing from `clawdefender-slm`, keeping the
//! dependency graph clean.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Hardware and OS profile of the host machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemProfile {
    pub os_version: String,
    pub cpu_architecture: String,
    pub cpu_name: String,
    pub ram_gb: u32,
    pub gpu: Option<String>,
}

impl Default for SystemProfile {
    fn default() -> Self {
        Self {
            os_version: "unknown".into(),
            cpu_architecture: "unknown".into(),
            cpu_name: "unknown".into(),
            ram_gb: 0,
            gpu: None,
        }
    }
}

impl fmt::Display for SystemProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, {}", self.os_version, self.cpu_name)?;
        if self.ram_gb > 0 {
            write!(f, ", {}GB RAM", self.ram_gb)?;
        }
        if let Some(gpu) = &self.gpu {
            write!(f, ", GPU: {}", gpu)?;
        }
        Ok(())
    }
}

/// Status of a single MCP server as seen by the bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerInfo {
    pub name: String,
    pub wrapped: bool,
    pub trust_level: String,
    pub anomaly_score: f64,
    pub events_per_hour: f64,
    pub status: String,
}

/// Summary of the active policy ruleset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    pub rule_count: u32,
    pub default_action: String,
    pub coverage_gaps: Vec<String>,
}

impl Default for PolicySummary {
    fn default() -> Self {
        Self {
            rule_count: 0,
            default_action: "Allow".into(),
            coverage_gaps: Vec::new(),
        }
    }
}

/// Summary of threat-intelligence feed state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelSummary {
    pub feed_age_hours: f64,
    pub ioc_count: u32,
    pub blocklist_matches: u32,
}

impl Default for ThreatIntelSummary {
    fn default() -> Self {
        Self {
            feed_age_hours: 0.0,
            ioc_count: 0,
            blocklist_matches: 0,
        }
    }
}

/// The purpose of this cloud interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionType {
    Scan { playbook: String },
    Investigate { event_id: String },
    Chat,
    Report { report_type: String },
}

impl fmt::Display for SessionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scan { playbook } => write!(f, "Scan({})", playbook),
            Self::Investigate { event_id } => write!(f, "Investigate({})", event_id),
            Self::Chat => write!(f, "Chat"),
            Self::Report { report_type } => write!(f, "Report({})", report_type),
        }
    }
}

// -- Bridge-local snapshot types (simplified, no SLM dependency) -------------

/// Simplified per-server snapshot for the cloud briefing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSnapshotBrief {
    pub name: String,
    pub trust_level: String,
    pub anomaly_score: f64,
    pub event_count: u64,
}

/// Brief description of a suspicious event (bridge-local copy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousEventBrief {
    pub timestamp: String,
    pub server: String,
    pub description: String,
}

/// Brief description of an active kill-chain pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainBrief {
    pub server: String,
    pub pattern: String,
    pub stage: String,
    pub confidence: f64,
}

// ---------------------------------------------------------------------------
// CloudBriefing — the full context document sent to Claude
// ---------------------------------------------------------------------------

/// The complete "briefing document" assembled for every cloud turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudBriefing {
    pub event_summary: String,
    pub server_snapshots: Vec<ServerSnapshotBrief>,
    pub recent_suspicious: Vec<SuspiciousEventBrief>,
    pub active_kill_chains: Vec<KillChainBrief>,
    pub system_profile: SystemProfile,
    pub mcp_inventory: Vec<McpServerInfo>,
    pub policy_summary: PolicySummary,
    pub threat_intel_summary: ThreatIntelSummary,
    pub session_type: SessionType,
    pub user_query: Option<String>,
    pub target_event: Option<serde_json::Value>,
    pub slm_triage_summary: Option<String>,
}

impl CloudBriefing {
    /// Render the briefing as a system-prompt string for Claude.
    ///
    /// Target length: 800-1500 tokens (roughly word_count * 1.3).
    pub fn to_system_prompt(&self) -> String {
        let mut out = String::with_capacity(2048);

        out.push_str(
            "You are RookBot's security agent running on the user's machine.\n\n",
        );

        // System profile
        out.push_str(&format!("SYSTEM: {}\n", self.system_profile));

        // MCP server inventory
        let wrapped = self.mcp_inventory.iter().filter(|s| s.wrapped).count();
        out.push_str(&format!(
            "MCP SERVERS ({} installed, {} wrapped):\n",
            self.mcp_inventory.len(),
            wrapped,
        ));
        for srv in &self.mcp_inventory {
            let wrap_label = if srv.wrapped { "wrapped" } else { "unwrapped" };
            let alert = if srv.anomaly_score >= 0.6 { " !!!" } else { "" };
            out.push_str(&format!(
                "  - {} [{}, {}, anomaly={:.2}, {:.0} events/hr]{}\n",
                srv.name, wrap_label, srv.trust_level, srv.anomaly_score,
                srv.events_per_hour, alert,
            ));
        }

        // Policy
        let gaps = if self.policy_summary.coverage_gaps.is_empty() {
            "none".to_string()
        } else {
            self.policy_summary.coverage_gaps.join(", ")
        };
        out.push_str(&format!(
            "POLICY: {} rules, default={}, gaps=[{}]\n",
            self.policy_summary.rule_count,
            self.policy_summary.default_action,
            gaps,
        ));

        // Threat intel
        out.push_str(&format!(
            "THREAT INTEL: feed {:.0}h old, {} IoCs loaded, {} blocklist matches\n",
            self.threat_intel_summary.feed_age_hours,
            self.threat_intel_summary.ioc_count,
            self.threat_intel_summary.blocklist_matches,
        ));

        // Event summary
        out.push_str(&format!("RECENT: {}\n", self.event_summary));

        // Suspicious events
        if !self.recent_suspicious.is_empty() {
            let parts: Vec<String> = self
                .recent_suspicious
                .iter()
                .map(|e| format!("[{} {}->{}]", e.timestamp, e.server, e.description))
                .collect();
            out.push_str(&format!("SUSPICIOUS: {}\n", parts.join(" ")));
        }

        // Kill chains
        if !self.active_kill_chains.is_empty() {
            let parts: Vec<String> = self
                .active_kill_chains
                .iter()
                .map(|kc| {
                    format!(
                        "{} -- {} ({}, confidence={:.2})",
                        kc.server, kc.pattern, kc.stage, kc.confidence,
                    )
                })
                .collect();
            out.push_str(&format!("KILL CHAINS: {}\n", parts.join("; ")));
        }

        // SLM triage summary
        if let Some(triage) = &self.slm_triage_summary {
            out.push_str(&format!("SLM TRIAGE: {}\n", triage));
        }

        // Session type
        out.push_str(&format!("\nSESSION: {}\n", self.session_type));

        // User query
        if let Some(query) = &self.user_query {
            out.push_str(&format!("USER QUERY: {}\n", query));
        }

        // Target event
        if let Some(event) = &self.target_event {
            if let Ok(pretty) = serde_json::to_string(event) {
                // Truncate to avoid blowing up token budget.
                let truncated = if pretty.len() > 500 {
                    format!("{}...(truncated)", &pretty[..500])
                } else {
                    pretty
                };
                out.push_str(&format!("TARGET EVENT: {}\n", truncated));
            }
        }

        out.push_str(
            "\nYou have tools to investigate this system. \
             Use them to answer the user's question or complete the requested task.\n",
        );

        out
    }
}

// ---------------------------------------------------------------------------
// BriefingDiff — compact delta between two briefings
// ---------------------------------------------------------------------------

/// Compact diff between two consecutive briefings, used for multi-turn context
/// updates so we don't re-send the full briefing every turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BriefingDiff {
    pub new_events_count: u32,
    pub changed_servers: Vec<(String, String)>,
    pub new_suspicious: Vec<SuspiciousEventBrief>,
    pub kill_chain_updates: Vec<String>,
}

impl BriefingDiff {
    /// Render as a compact context-update string for injection into the conversation.
    pub fn to_context_update(&self) -> String {
        let mut parts: Vec<String> = Vec::new();

        if self.new_events_count > 0 {
            parts.push(format!("+{} events since last turn", self.new_events_count));
        }

        for (server, change) in &self.changed_servers {
            parts.push(format!("{} {}", server, change));
        }

        for s in &self.new_suspicious {
            parts.push(format!("NEW SUSPICIOUS: {} {}->{}",
                s.timestamp, s.server, s.description));
        }

        for update in &self.kill_chain_updates {
            parts.push(update.clone());
        }

        if parts.is_empty() {
            "CONTEXT UPDATE: no changes since last turn".to_string()
        } else {
            format!("CONTEXT UPDATE: {}", parts.join(", "))
        }
    }
}

/// Compute a diff between two briefings.
pub fn diff_briefings(old: &CloudBriefing, new: &CloudBriefing) -> BriefingDiff {
    // Estimate new events from server snapshot totals.
    let old_total: u64 = old.server_snapshots.iter().map(|s| s.event_count).sum();
    let new_total: u64 = new.server_snapshots.iter().map(|s| s.event_count).sum();
    let new_events_count = new_total.saturating_sub(old_total) as u32;

    // Find servers whose anomaly score changed significantly.
    let old_scores: HashMap<&str, f64> = old
        .server_snapshots
        .iter()
        .map(|s| (s.name.as_str(), s.anomaly_score))
        .collect();

    let mut changed_servers = Vec::new();
    for snap in &new.server_snapshots {
        if let Some(&old_score) = old_scores.get(snap.name.as_str()) {
            let delta = (snap.anomaly_score - old_score).abs();
            if delta >= 0.05 {
                changed_servers.push((
                    snap.name.clone(),
                    format!("anomaly now {:.2}", snap.anomaly_score),
                ));
            }
        } else {
            // New server appeared.
            changed_servers.push((snap.name.clone(), "newly appeared".into()));
        }
    }

    // Find new suspicious events not present in the old briefing.
    let old_suspicious: std::collections::HashSet<String> = old
        .recent_suspicious
        .iter()
        .map(|e| format!("{}:{}:{}", e.timestamp, e.server, e.description))
        .collect();

    let new_suspicious: Vec<SuspiciousEventBrief> = new
        .recent_suspicious
        .iter()
        .filter(|e| {
            let key = format!("{}:{}:{}", e.timestamp, e.server, e.description);
            !old_suspicious.contains(&key)
        })
        .cloned()
        .collect();

    // Kill chain changes.
    let old_chains: HashMap<&str, &KillChainBrief> = old
        .active_kill_chains
        .iter()
        .map(|kc| (kc.server.as_str(), kc))
        .collect();

    let mut kill_chain_updates = Vec::new();
    for kc in &new.active_kill_chains {
        if let Some(old_kc) = old_chains.get(kc.server.as_str()) {
            if kc.stage != old_kc.stage || (kc.confidence - old_kc.confidence).abs() >= 0.05 {
                kill_chain_updates.push(format!(
                    "kill chain {} advanced to {} (confidence={:.2})",
                    kc.server, kc.stage, kc.confidence,
                ));
            }
        } else {
            kill_chain_updates.push(format!(
                "new kill chain detected: {} -- {} ({})",
                kc.server, kc.pattern, kc.stage,
            ));
        }
    }

    BriefingDiff {
        new_events_count,
        changed_servers,
        new_suspicious,
        kill_chain_updates,
    }
}

// ---------------------------------------------------------------------------
// CloudBriefingBuilder
// ---------------------------------------------------------------------------

/// Builder for assembling a [`CloudBriefing`] step by step.
pub struct CloudBriefingBuilder {
    session_type: SessionType,
    system_profile: SystemProfile,
    mcp_inventory: Vec<McpServerInfo>,
    event_summary: String,
    server_snapshots: Vec<ServerSnapshotBrief>,
    recent_suspicious: Vec<SuspiciousEventBrief>,
    active_kill_chains: Vec<KillChainBrief>,
    policy_summary: PolicySummary,
    threat_intel_summary: ThreatIntelSummary,
    user_query: Option<String>,
    target_event: Option<serde_json::Value>,
    slm_triage_summary: Option<String>,
}

impl CloudBriefingBuilder {
    pub fn new(session_type: SessionType) -> Self {
        Self {
            session_type,
            system_profile: SystemProfile::default(),
            mcp_inventory: Vec::new(),
            event_summary: String::new(),
            server_snapshots: Vec::new(),
            recent_suspicious: Vec::new(),
            active_kill_chains: Vec::new(),
            policy_summary: PolicySummary::default(),
            threat_intel_summary: ThreatIntelSummary::default(),
            user_query: None,
            target_event: None,
            slm_triage_summary: None,
        }
    }

    pub fn with_system_profile(mut self, profile: SystemProfile) -> Self {
        self.system_profile = profile;
        self
    }

    pub fn with_servers(mut self, servers: Vec<McpServerInfo>) -> Self {
        self.mcp_inventory = servers;
        self
    }

    pub fn with_server_snapshots(mut self, snapshots: Vec<ServerSnapshotBrief>) -> Self {
        self.server_snapshots = snapshots;
        self
    }

    pub fn with_event_summary(mut self, summary: String) -> Self {
        self.event_summary = summary;
        self
    }

    pub fn with_suspicious_events(mut self, events: Vec<SuspiciousEventBrief>) -> Self {
        self.recent_suspicious = events;
        self
    }

    pub fn with_kill_chains(mut self, chains: Vec<KillChainBrief>) -> Self {
        self.active_kill_chains = chains;
        self
    }

    pub fn with_policy(mut self, summary: PolicySummary) -> Self {
        self.policy_summary = summary;
        self
    }

    pub fn with_threat_intel(mut self, summary: ThreatIntelSummary) -> Self {
        self.threat_intel_summary = summary;
        self
    }

    pub fn with_user_query(mut self, query: String) -> Self {
        self.user_query = Some(query);
        self
    }

    pub fn with_target_event(mut self, event: serde_json::Value) -> Self {
        self.target_event = Some(event);
        self
    }

    pub fn with_slm_triage(mut self, summary: String) -> Self {
        self.slm_triage_summary = Some(summary);
        self
    }

    pub fn build(self) -> CloudBriefing {
        CloudBriefing {
            event_summary: self.event_summary,
            server_snapshots: self.server_snapshots,
            recent_suspicious: self.recent_suspicious,
            active_kill_chains: self.active_kill_chains,
            system_profile: self.system_profile,
            mcp_inventory: self.mcp_inventory,
            policy_summary: self.policy_summary,
            threat_intel_summary: self.threat_intel_summary,
            session_type: self.session_type,
            user_query: self.user_query,
            target_event: self.target_event,
            slm_triage_summary: self.slm_triage_summary,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_briefing() -> CloudBriefing {
        CloudBriefingBuilder::new(SessionType::Chat)
            .with_system_profile(SystemProfile {
                os_version: "macOS 15.2".into(),
                cpu_architecture: "arm64".into(),
                cpu_name: "Apple M3 Pro".into(),
                ram_gb: 18,
                gpu: None,
            })
            .with_servers(vec![
                McpServerInfo {
                    name: "ProjectHelper".into(),
                    wrapped: true,
                    trust_level: "trusted".into(),
                    anomaly_score: 0.12,
                    events_per_hour: 89.0,
                    status: "active".into(),
                },
                McpServerInfo {
                    name: "FileManager".into(),
                    wrapped: true,
                    trust_level: "new".into(),
                    anomaly_score: 0.71,
                    events_per_hour: 127.0,
                    status: "active".into(),
                },
                McpServerInfo {
                    name: "WebSearch".into(),
                    wrapped: false,
                    trust_level: "unknown".into(),
                    anomaly_score: 0.0,
                    events_per_hour: 5.0,
                    status: "active".into(),
                },
            ])
            .with_server_snapshots(vec![
                ServerSnapshotBrief {
                    name: "ProjectHelper".into(),
                    trust_level: "trusted".into(),
                    anomaly_score: 0.12,
                    event_count: 200,
                },
                ServerSnapshotBrief {
                    name: "FileManager".into(),
                    trust_level: "new".into(),
                    anomaly_score: 0.71,
                    event_count: 58,
                },
            ])
            .with_event_summary(
                "258 events in last hour: 241 routine, 14 notable, 3 suspicious".into(),
            )
            .with_suspicious_events(vec![
                SuspiciousEventBrief {
                    timestamp: "14:23".into(),
                    server: "FileManager".into(),
                    description: "~/.ssh/id_rsa".into(),
                },
                SuspiciousEventBrief {
                    timestamp: "14:31".into(),
                    server: "FileManager".into(),
                    description: "43.128.x.x:443".into(),
                },
            ])
            .with_kill_chains(vec![KillChainBrief {
                server: "FileManager".into(),
                pattern: "credential_access".into(),
                stage: "3/6 stages".into(),
                confidence: 0.82,
            }])
            .with_policy(PolicySummary {
                rule_count: 12,
                default_action: "Prompt".into(),
                coverage_gaps: vec!["no network rules for FileManager".into()],
            })
            .with_threat_intel(ThreatIntelSummary {
                feed_age_hours: 2.0,
                ioc_count: 1247,
                blocklist_matches: 0,
            })
            .build()
    }

    #[test]
    fn test_briefing_serialization() {
        let briefing = sample_briefing();
        let prompt = briefing.to_system_prompt();

        assert!(prompt.contains("RookBot's security agent"));
        assert!(prompt.contains("macOS 15.2"));
        assert!(prompt.contains("Apple M3 Pro"));
        assert!(prompt.contains("18GB RAM"));
        assert!(prompt.contains("MCP SERVERS (3 installed, 2 wrapped)"));
        assert!(prompt.contains("ProjectHelper"));
        assert!(prompt.contains("FileManager"));
        assert!(prompt.contains("WebSearch"));
        assert!(prompt.contains("anomaly=0.71"));
        assert!(prompt.contains("!!!"));
        assert!(prompt.contains("POLICY: 12 rules"));
        assert!(prompt.contains("default=Prompt"));
        assert!(prompt.contains("no network rules for FileManager"));
        assert!(prompt.contains("THREAT INTEL: feed 2h old"));
        assert!(prompt.contains("1247 IoCs loaded"));
        assert!(prompt.contains("SUSPICIOUS:"));
        assert!(prompt.contains("~/.ssh/id_rsa"));
        assert!(prompt.contains("KILL CHAINS:"));
        assert!(prompt.contains("credential_access"));
        assert!(prompt.contains("confidence=0.82"));
        assert!(prompt.contains("SESSION: Chat"));
    }

    #[test]
    fn test_briefing_token_estimate() {
        let briefing = sample_briefing();
        let prompt = briefing.to_system_prompt();
        let word_count = prompt.split_whitespace().count();
        let token_estimate = (word_count as f64 * 1.3) as usize;
        assert!(
            token_estimate < 1500,
            "briefing too long: ~{} tokens ({} words)",
            token_estimate,
            word_count,
        );
    }

    #[test]
    fn test_diff_is_compact() {
        let old = sample_briefing();
        let mut new = sample_briefing();
        // Advance the kill chain
        new.active_kill_chains[0].stage = "4/6 stages".into();
        new.active_kill_chains[0].confidence = 0.88;
        // Bump server anomaly
        new.server_snapshots[1].anomaly_score = 0.78;
        new.server_snapshots[1].event_count = 70;

        let diff = diff_briefings(&old, &new);
        let update_str = diff.to_context_update();
        let full_prompt = new.to_system_prompt();

        assert!(
            update_str.len() < full_prompt.len() / 2,
            "diff ({} chars) should be much shorter than full briefing ({} chars)",
            update_str.len(),
            full_prompt.len(),
        );
        assert!(update_str.contains("CONTEXT UPDATE"));
        assert!(update_str.contains("kill chain"));
    }

    #[test]
    fn test_builder_pattern() {
        let briefing = CloudBriefingBuilder::new(SessionType::Investigate {
            event_id: "evt-42".into(),
        })
        .with_system_profile(SystemProfile {
            os_version: "Ubuntu 24.04".into(),
            cpu_architecture: "x86_64".into(),
            cpu_name: "Intel i9".into(),
            ram_gb: 64,
            gpu: Some("RTX 4090".into()),
        })
        .with_event_summary("100 events".into())
        .with_user_query("What is FileManager doing?".into())
        .with_target_event(serde_json::json!({"type": "file_read", "path": "/etc/passwd"}))
        .with_slm_triage("SLM flagged as suspicious credential access attempt".into())
        .build();

        let prompt = briefing.to_system_prompt();
        assert!(prompt.contains("Ubuntu 24.04"));
        assert!(prompt.contains("64GB RAM"));
        assert!(prompt.contains("GPU: RTX 4090"));
        assert!(prompt.contains("Investigate(evt-42)"));
        assert!(prompt.contains("What is FileManager doing?"));
        assert!(prompt.contains("/etc/passwd"));
        assert!(prompt.contains("SLM flagged"));
    }

    #[test]
    fn test_empty_briefing() {
        let briefing = CloudBriefingBuilder::new(SessionType::Chat).build();
        let prompt = briefing.to_system_prompt();

        // Should not panic and should produce valid output.
        assert!(prompt.contains("RookBot's security agent"));
        assert!(prompt.contains("SYSTEM:"));
        assert!(prompt.contains("MCP SERVERS (0 installed, 0 wrapped)"));
        assert!(prompt.contains("SESSION: Chat"));
        // No suspicious or kill chain sections when empty.
        assert!(!prompt.contains("SUSPICIOUS:"));
        assert!(!prompt.contains("KILL CHAINS:"));
        assert!(!prompt.contains("SLM TRIAGE:"));
        assert!(!prompt.contains("USER QUERY:"));
        assert!(!prompt.contains("TARGET EVENT:"));
    }

    #[test]
    fn test_diff_no_changes() {
        let a = sample_briefing();
        let b = a.clone();
        let diff = diff_briefings(&a, &b);
        let update = diff.to_context_update();
        assert_eq!(update, "CONTEXT UPDATE: no changes since last turn");
    }

    #[test]
    fn test_diff_new_suspicious() {
        let old = sample_briefing();
        let mut new = sample_briefing();
        new.recent_suspicious.push(SuspiciousEventBrief {
            timestamp: "14:45".into(),
            server: "FileManager".into(),
            description: "POST to external API".into(),
        });

        let diff = diff_briefings(&old, &new);
        assert_eq!(diff.new_suspicious.len(), 1);
        assert!(diff.new_suspicious[0].description.contains("POST"));
    }

    #[test]
    fn test_diff_new_server() {
        let old = sample_briefing();
        let mut new = sample_briefing();
        new.server_snapshots.push(ServerSnapshotBrief {
            name: "NewServer".into(),
            trust_level: "unknown".into(),
            anomaly_score: 0.5,
            event_count: 10,
        });

        let diff = diff_briefings(&old, &new);
        assert!(
            diff.changed_servers
                .iter()
                .any(|(name, _)| name == "NewServer"),
        );
    }

    #[test]
    fn test_system_profile_display() {
        let profile = SystemProfile {
            os_version: "macOS 15.2".into(),
            cpu_architecture: "arm64".into(),
            cpu_name: "Apple M3 Pro".into(),
            ram_gb: 18,
            gpu: None,
        };
        let s = format!("{}", profile);
        assert_eq!(s, "macOS 15.2, Apple M3 Pro, 18GB RAM");
    }

    #[test]
    fn test_session_type_display() {
        assert_eq!(format!("{}", SessionType::Chat), "Chat");
        assert_eq!(
            format!("{}", SessionType::Scan { playbook: "full".into() }),
            "Scan(full)",
        );
        assert_eq!(
            format!("{}", SessionType::Investigate { event_id: "e1".into() }),
            "Investigate(e1)",
        );
        assert_eq!(
            format!("{}", SessionType::Report { report_type: "weekly".into() }),
            "Report(weekly)",
        );
    }

    #[test]
    fn test_briefing_json_roundtrip() {
        let briefing = sample_briefing();
        let json = serde_json::to_string(&briefing).expect("serialize");
        let restored: CloudBriefing = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.event_summary, briefing.event_summary);
        assert_eq!(restored.mcp_inventory.len(), briefing.mcp_inventory.len());
        assert_eq!(
            restored.active_kill_chains.len(),
            briefing.active_kill_chains.len(),
        );
    }
}
