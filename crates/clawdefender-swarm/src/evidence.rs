//! Evidence collection and linking for AI security scans.
//!
//! Records every tool call made during an investigation, links evidence to
//! findings, and supports automatic cross-referencing by shared resources
//! (servers, files, events).

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single piece of evidence collected from a tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: String,
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,

    // What was checked
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub tool_result_hash: String,
    pub tool_result_summary: String,

    // Classification
    pub stage: String,
    pub relevance: Relevance,

    // Links
    pub related_findings: Vec<String>,
    pub related_evidence: Vec<String>,
    pub related_events: Vec<String>,
}

/// How relevant a piece of evidence is to an active investigation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Relevance {
    Relevant,
    PossiblyRelevant,
    Background,
}

/// An ordered chain of evidence items that support a specific finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    pub finding_id: String,
    pub items: Vec<EvidenceItem>,
    pub summary: String,
}

/// Summary statistics for the evidence store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStats {
    pub total_items: usize,
    pub relevant_count: usize,
    pub possibly_relevant_count: usize,
    pub background_count: usize,
    pub stages_covered: Vec<String>,
    pub tools_used: HashMap<String, usize>,
}

// ---------------------------------------------------------------------------
// EvidenceStore
// ---------------------------------------------------------------------------

/// Collects, links, and queries evidence items from a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStore {
    pub scan_id: String,
    items: Vec<EvidenceItem>,
    finding_links: HashMap<String, Vec<String>>,
    auto_links: HashMap<String, Vec<String>>,
    next_seq: u64,
}

impl EvidenceStore {
    /// Create a new, empty evidence store for a scan.
    pub fn new(scan_id: String) -> Self {
        Self {
            scan_id,
            items: Vec::new(),
            finding_links: HashMap::new(),
            auto_links: HashMap::new(),
            next_seq: 1,
        }
    }

    /// Record a new evidence item from a tool call. Returns the evidence ID.
    pub fn record_tool_call(
        &mut self,
        tool_name: &str,
        tool_input: serde_json::Value,
        tool_result: &str,
        stage: &str,
    ) -> String {
        let id = format!("ev-{}-{}", self.scan_id, self.next_seq);
        self.next_seq += 1;

        let result_hash = hash_content(tool_result);
        let result_summary = summarize_result(tool_result);

        let item = EvidenceItem {
            id: id.clone(),
            scan_id: self.scan_id.clone(),
            timestamp: Utc::now(),
            tool_name: tool_name.to_string(),
            tool_input: tool_input.clone(),
            tool_result_hash: result_hash,
            tool_result_summary: result_summary,
            stage: stage.to_string(),
            relevance: Relevance::Background,
            related_findings: Vec::new(),
            related_evidence: Vec::new(),
            related_events: Vec::new(),
        };

        // Extract resource keys and register auto-links
        for key in extract_resource_keys(tool_name, &tool_input) {
            self.auto_links.entry(key).or_default().push(id.clone());
        }

        self.items.push(item);
        id
    }

    /// Link an evidence item to a finding.
    pub fn link_to_finding(&mut self, evidence_id: &str, finding_id: &str) {
        self.finding_links
            .entry(finding_id.to_string())
            .or_default()
            .push(evidence_id.to_string());

        if let Some(item) = self.items.iter_mut().find(|i| i.id == evidence_id) {
            if !item.related_findings.contains(&finding_id.to_string()) {
                item.related_findings.push(finding_id.to_string());
            }
        }
    }

    /// Update the relevance classification of an evidence item.
    pub fn mark_relevant(&mut self, evidence_id: &str, relevance: Relevance) {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == evidence_id) {
            item.relevance = relevance;
        }
    }

    /// Populate `related_evidence` on each item based on shared resource keys.
    pub fn auto_link_evidence(&mut self) {
        // Build a map from evidence_id -> set of sibling ids
        let mut siblings: HashMap<String, Vec<String>> = HashMap::new();

        for ids in self.auto_links.values() {
            if ids.len() < 2 {
                continue;
            }
            for id in ids {
                for other in ids {
                    if id != other {
                        siblings.entry(id.clone()).or_default().push(other.clone());
                    }
                }
            }
        }

        // Deduplicate and apply
        for item in &mut self.items {
            if let Some(sibs) = siblings.get(&item.id) {
                for sib in sibs {
                    if !item.related_evidence.contains(sib) {
                        item.related_evidence.push(sib.clone());
                    }
                }
            }
        }
    }

    /// Build the evidence chain for a specific finding.
    pub fn get_evidence_chain(&self, finding_id: &str) -> EvidenceChain {
        let evidence_ids = self
            .finding_links
            .get(finding_id)
            .cloned()
            .unwrap_or_default();

        let mut items: Vec<EvidenceItem> = self
            .items
            .iter()
            .filter(|i| evidence_ids.contains(&i.id))
            .cloned()
            .collect();

        items.sort_by_key(|i| i.timestamp);

        let summary = if items.is_empty() {
            "No evidence collected for this finding.".to_string()
        } else {
            let tool_names: Vec<&str> = items.iter().map(|i| i.tool_name.as_str()).collect();
            format!(
                "{} evidence item(s) collected via: {}",
                items.len(),
                tool_names.join(", ")
            )
        };

        EvidenceChain {
            finding_id: finding_id.to_string(),
            items,
            summary,
        }
    }

    /// Return all evidence items.
    pub fn get_all_evidence(&self) -> &[EvidenceItem] {
        &self.items
    }

    /// Return evidence items belonging to a specific playbook stage.
    pub fn get_evidence_by_stage(&self, stage: &str) -> Vec<&EvidenceItem> {
        self.items.iter().filter(|i| i.stage == stage).collect()
    }

    /// Export the full evidence store as a JSON value for inclusion in reports.
    pub fn export_for_report(&self) -> serde_json::Value {
        let chains: Vec<serde_json::Value> = self
            .finding_links
            .keys()
            .map(|fid| serde_json::to_value(self.get_evidence_chain(fid)).unwrap())
            .collect();

        serde_json::json!({
            "scan_id": self.scan_id,
            "total_evidence_items": self.items.len(),
            "items": self.items,
            "finding_chains": chains,
            "stats": self.get_stats(),
        })
    }

    /// Compute summary statistics for the evidence store.
    pub fn get_stats(&self) -> EvidenceStats {
        let mut tools_used: HashMap<String, usize> = HashMap::new();
        let mut stages_set: Vec<String> = Vec::new();
        let mut relevant = 0usize;
        let mut possibly = 0usize;
        let mut background = 0usize;

        for item in &self.items {
            *tools_used.entry(item.tool_name.clone()).or_insert(0) += 1;

            if !stages_set.contains(&item.stage) {
                stages_set.push(item.stage.clone());
            }

            match item.relevance {
                Relevance::Relevant => relevant += 1,
                Relevance::PossiblyRelevant => possibly += 1,
                Relevance::Background => background += 1,
            }
        }

        EvidenceStats {
            total_items: self.items.len(),
            relevant_count: relevant,
            possibly_relevant_count: possibly,
            background_count: background,
            stages_covered: stages_set,
            tools_used,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute SHA-256 hex digest of content.
fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Produce a 1-sentence summary of a tool result (first 120 chars).
fn summarize_result(result: &str) -> String {
    let trimmed = result.trim();
    if trimmed.len() <= 120 {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..120])
    }
}

/// Extract resource keys from tool input for auto-linking.
fn extract_resource_keys(tool_name: &str, input: &serde_json::Value) -> Vec<String> {
    let mut keys = Vec::new();

    match tool_name {
        "query_events" => {
            if let Some(server) = input.get("server").and_then(|v| v.as_str()) {
                keys.push(format!("server:{}", server));
            }
        }
        "get_server_profile" => {
            if let Some(name) = input.get("server_name").and_then(|v| v.as_str()) {
                keys.push(format!("server:{}", name));
            }
        }
        "read_file" => {
            if let Some(path) = input.get("path").and_then(|v| v.as_str()) {
                keys.push(format!("file:{}", path));
            }
        }
        "check_reputation" => {
            if let Some(target) = input.get("target").and_then(|v| v.as_str()) {
                keys.push(format!("target:{}", target));
            }
        }
        "get_event_detail" => {
            if let Some(eid) = input.get("event_id").and_then(|v| v.as_str()) {
                keys.push(format!("event:{}", eid));
            }
        }
        _ => {}
    }

    keys
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_store() -> EvidenceStore {
        EvidenceStore::new("scan-001".to_string())
    }

    #[test]
    fn test_record_tool_call() {
        let mut store = make_store();
        let id = store.record_tool_call(
            "query_events",
            json!({"time_range": "last_hour", "server": "evil-srv"}),
            r#"{"events": [{"id": "e1"}]}"#,
            "reconnaissance",
        );

        assert!(id.starts_with("ev-scan-001-"));
        assert_eq!(store.items.len(), 1);
        assert_eq!(store.items[0].tool_name, "query_events");
        assert_eq!(store.items[0].stage, "reconnaissance");
        assert_eq!(store.items[0].relevance, Relevance::Background);
        assert_eq!(store.items[0].tool_result_hash.len(), 64);
    }

    #[test]
    fn test_sequential_ids() {
        let mut store = make_store();
        let id1 = store.record_tool_call("t1", json!({}), "r1", "s1");
        let id2 = store.record_tool_call("t2", json!({}), "r2", "s1");
        assert_ne!(id1, id2);
        assert!(id1.ends_with("-1"));
        assert!(id2.ends_with("-2"));
    }

    #[test]
    fn test_link_to_finding() {
        let mut store = make_store();
        let eid = store.record_tool_call("query_events", json!({}), "result", "recon");

        store.link_to_finding(&eid, "finding-42");

        assert_eq!(
            store.finding_links.get("finding-42").unwrap(),
            &vec![eid.clone()]
        );
        assert_eq!(store.items[0].related_findings, vec!["finding-42"]);
    }

    #[test]
    fn test_link_to_finding_idempotent() {
        let mut store = make_store();
        let eid = store.record_tool_call("query_events", json!({}), "result", "recon");

        store.link_to_finding(&eid, "finding-42");
        store.link_to_finding(&eid, "finding-42");

        // related_findings should not have duplicates
        assert_eq!(store.items[0].related_findings.len(), 1);
    }

    #[test]
    fn test_mark_relevant() {
        let mut store = make_store();
        let eid = store.record_tool_call("query_events", json!({}), "result", "recon");

        assert_eq!(store.items[0].relevance, Relevance::Background);

        store.mark_relevant(&eid, Relevance::Relevant);
        assert_eq!(store.items[0].relevance, Relevance::Relevant);

        store.mark_relevant(&eid, Relevance::PossiblyRelevant);
        assert_eq!(store.items[0].relevance, Relevance::PossiblyRelevant);
    }

    #[test]
    fn test_auto_link_evidence_by_server() {
        let mut store = make_store();
        let e1 = store.record_tool_call(
            "query_events",
            json!({"time_range": "last_hour", "server": "web-01"}),
            "events from web-01",
            "recon",
        );
        let e2 = store.record_tool_call(
            "get_server_profile",
            json!({"server_name": "web-01"}),
            "profile of web-01",
            "analysis",
        );
        // Different server -- should NOT be linked
        let _e3 = store.record_tool_call(
            "query_events",
            json!({"time_range": "last_hour", "server": "db-01"}),
            "events from db-01",
            "recon",
        );

        store.auto_link_evidence();

        let item1 = store.items.iter().find(|i| i.id == e1).unwrap();
        assert!(item1.related_evidence.contains(&e2));

        let item2 = store.items.iter().find(|i| i.id == e2).unwrap();
        assert!(item2.related_evidence.contains(&e1));

        // e3 should have no related evidence
        let item3 = &store.items[2];
        assert!(item3.related_evidence.is_empty());
    }

    #[test]
    fn test_auto_link_evidence_by_file() {
        let mut store = make_store();
        let e1 = store.record_tool_call(
            "read_file",
            json!({"path": "/etc/hosts"}),
            "contents",
            "inspection",
        );
        let e2 = store.record_tool_call(
            "read_file",
            json!({"path": "/etc/hosts"}),
            "updated contents",
            "verification",
        );

        store.auto_link_evidence();

        let item1 = store.items.iter().find(|i| i.id == e1).unwrap();
        assert!(item1.related_evidence.contains(&e2));
    }

    #[test]
    fn test_get_evidence_chain() {
        let mut store = make_store();
        let e1 = store.record_tool_call("query_events", json!({}), "result1", "recon");
        let e2 = store.record_tool_call("get_server_profile", json!({}), "result2", "analysis");
        let _e3 = store.record_tool_call("get_policy", json!({}), "result3", "baseline");

        store.link_to_finding(&e1, "f-1");
        store.link_to_finding(&e2, "f-1");

        let chain = store.get_evidence_chain("f-1");
        assert_eq!(chain.finding_id, "f-1");
        assert_eq!(chain.items.len(), 2);
        assert!(chain.summary.contains("2 evidence item(s)"));
        assert!(chain.summary.contains("query_events"));
        assert!(chain.summary.contains("get_server_profile"));
    }

    #[test]
    fn test_get_evidence_chain_empty() {
        let store = make_store();
        let chain = store.get_evidence_chain("nonexistent");
        assert!(chain.items.is_empty());
        assert!(chain.summary.contains("No evidence"));
    }

    #[test]
    fn test_get_all_evidence() {
        let mut store = make_store();
        store.record_tool_call("t1", json!({}), "r1", "s1");
        store.record_tool_call("t2", json!({}), "r2", "s2");
        assert_eq!(store.get_all_evidence().len(), 2);
    }

    #[test]
    fn test_get_evidence_by_stage() {
        let mut store = make_store();
        store.record_tool_call("t1", json!({}), "r1", "recon");
        store.record_tool_call("t2", json!({}), "r2", "analysis");
        store.record_tool_call("t3", json!({}), "r3", "recon");

        let recon = store.get_evidence_by_stage("recon");
        assert_eq!(recon.len(), 2);

        let analysis = store.get_evidence_by_stage("analysis");
        assert_eq!(analysis.len(), 1);

        let empty = store.get_evidence_by_stage("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_get_stats() {
        let mut store = make_store();
        let e1 = store.record_tool_call("query_events", json!({}), "r1", "recon");
        let e2 = store.record_tool_call("query_events", json!({}), "r2", "recon");
        let e3 = store.record_tool_call("get_server_profile", json!({}), "r3", "analysis");
        store.record_tool_call("read_file", json!({}), "r4", "inspection");

        store.mark_relevant(&e1, Relevance::Relevant);
        store.mark_relevant(&e2, Relevance::Relevant);
        store.mark_relevant(&e3, Relevance::PossiblyRelevant);

        let stats = store.get_stats();
        assert_eq!(stats.total_items, 4);
        assert_eq!(stats.relevant_count, 2);
        assert_eq!(stats.possibly_relevant_count, 1);
        assert_eq!(stats.background_count, 1);
        assert_eq!(stats.stages_covered.len(), 3);
        assert!(stats.stages_covered.contains(&"recon".to_string()));
        assert!(stats.stages_covered.contains(&"analysis".to_string()));
        assert!(stats.stages_covered.contains(&"inspection".to_string()));
        assert_eq!(*stats.tools_used.get("query_events").unwrap(), 2);
        assert_eq!(*stats.tools_used.get("get_server_profile").unwrap(), 1);
        assert_eq!(*stats.tools_used.get("read_file").unwrap(), 1);
    }

    #[test]
    fn test_export_for_report() {
        let mut store = make_store();
        let e1 = store.record_tool_call("query_events", json!({}), "r1", "recon");
        store.link_to_finding(&e1, "f-1");

        let report = store.export_for_report();
        assert_eq!(report["scan_id"], "scan-001");
        assert_eq!(report["total_evidence_items"], 1);
        assert!(report["items"].is_array());
        assert!(report["finding_chains"].is_array());
        assert!(report["stats"].is_object());
    }

    #[test]
    fn test_hash_content_deterministic() {
        let h1 = hash_content("test data");
        let h2 = hash_content("test data");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_hash_content_different_inputs() {
        let h1 = hash_content("input A");
        let h2 = hash_content("input B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_summarize_short_result() {
        let summary = summarize_result("short result");
        assert_eq!(summary, "short result");
    }

    #[test]
    fn test_summarize_long_result() {
        let long = "x".repeat(200);
        let summary = summarize_result(&long);
        assert!(summary.ends_with("..."));
        assert!(summary.len() <= 124); // 120 + "..."
    }

    #[test]
    fn test_extract_resource_keys() {
        assert_eq!(
            extract_resource_keys("query_events", &json!({"server": "web-01"})),
            vec!["server:web-01"]
        );
        assert_eq!(
            extract_resource_keys("get_server_profile", &json!({"server_name": "web-01"})),
            vec!["server:web-01"]
        );
        assert_eq!(
            extract_resource_keys("read_file", &json!({"path": "/etc/hosts"})),
            vec!["file:/etc/hosts"]
        );
        assert_eq!(
            extract_resource_keys("check_reputation", &json!({"target": "evil.com"})),
            vec!["target:evil.com"]
        );
        assert_eq!(
            extract_resource_keys("get_event_detail", &json!({"event_id": "evt-99"})),
            vec!["event:evt-99"]
        );
        assert!(extract_resource_keys("get_policy", &json!({})).is_empty());
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut store = make_store();
        let eid = store.record_tool_call(
            "query_events",
            json!({"time_range": "last_hour"}),
            "some events",
            "recon",
        );
        store.mark_relevant(&eid, Relevance::Relevant);
        store.link_to_finding(&eid, "f-1");

        let json_str = serde_json::to_string(&store).unwrap();
        let deserialized: EvidenceStore = serde_json::from_str(&json_str).unwrap();

        assert_eq!(deserialized.scan_id, store.scan_id);
        assert_eq!(deserialized.items.len(), 1);
        assert_eq!(deserialized.items[0].relevance, Relevance::Relevant);
        assert_eq!(deserialized.finding_links.get("f-1").unwrap(), &vec![eid]);
    }
}
