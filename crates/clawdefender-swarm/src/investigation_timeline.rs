//! Investigation timeline reconstruction and threat story visualization.
//!
//! Turns raw audit events, evidence items, and Claude's analysis into a visual
//! narrative timeline that users can follow to understand security incidents.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A complete investigation timeline with entries and narrative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationTimeline {
    pub investigation_id: String,
    pub entries: Vec<TimelineEntry>,
    pub servers_involved: Vec<String>,
    pub time_span: TimeSpan,
    pub narrative_summary: String,
}

/// Start and end timestamps for a timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSpan {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// A single entry in the investigation timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub entry_type: TimelineEntryType,
    pub server: String,
    pub description: String,
    pub severity: String,
    pub event_id: Option<String>,
    pub is_key_moment: bool,
    pub connects_to: Option<String>,
    pub stage: Option<String>,
}

/// Classification of timeline entry types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TimelineEntryType {
    McpToolCall,
    FileAccess,
    NetworkConnection,
    ProcessExecution,
    PolicyDecision,
    UserAction,
    AiAssessment,
    InvestigatorNote,
}

impl TimelineEntryType {
    /// Determine entry type from event data fields.
    pub fn from_event(event: &serde_json::Value) -> Self {
        // Check explicit type field
        if let Some(t) = event.get("entry_type").and_then(|v| v.as_str()) {
            return Self::from_str_label(t);
        }

        // Check event_type field
        if let Some(event_type) = event.get("event_type").and_then(|v| v.as_str()) {
            match event_type {
                "proxy" | "tool_call" | "mcp_call" => return Self::McpToolCall,
                "file_access" | "file_read" | "file_write" => return Self::FileAccess,
                "network" | "connection" | "dns" => return Self::NetworkConnection,
                "process" | "exec" | "spawn" => return Self::ProcessExecution,
                "policy" | "decision" | "rule_match" => return Self::PolicyDecision,
                "user" | "user_action" | "prompt_response" => return Self::UserAction,
                "ai" | "analysis" | "assessment" => return Self::AiAssessment,
                _ => {}
            }
        }

        // Check for tool_name field (likely MCP tool call)
        if event.get("tool_name").is_some() {
            return Self::McpToolCall;
        }

        // Check for decision field (policy decision)
        if let Some(decision) = event.get("decision").and_then(|v| v.as_str()) {
            if ["allow", "deny", "block", "prompt"].contains(&decision) {
                return Self::PolicyDecision;
            }
        }

        // Check action field for hints
        if let Some(action) = event.get("action").and_then(|v| v.as_str()) {
            let action_lower = action.to_lowercase();
            if action_lower.contains("file") || action_lower.contains("read") || action_lower.contains("write") {
                return Self::FileAccess;
            }
            if action_lower.contains("network") || action_lower.contains("connect") || action_lower.contains("dns") {
                return Self::NetworkConnection;
            }
            if action_lower.contains("exec") || action_lower.contains("process") || action_lower.contains("spawn") {
                return Self::ProcessExecution;
            }
            if action_lower.contains("tools/call") || action_lower.contains("mcp") {
                return Self::McpToolCall;
            }
        }

        // Default
        Self::McpToolCall
    }

    /// Parse from a string label (used in [TIMELINE_ENTRY] tags).
    fn from_str_label(s: &str) -> Self {
        match s {
            "McpToolCall" | "mcp_tool_call" | "tool_call" => Self::McpToolCall,
            "FileAccess" | "file_access" | "file" => Self::FileAccess,
            "NetworkConnection" | "network_connection" | "network" => Self::NetworkConnection,
            "ProcessExecution" | "process_execution" | "process" => Self::ProcessExecution,
            "PolicyDecision" | "policy_decision" | "policy" => Self::PolicyDecision,
            "UserAction" | "user_action" | "user" => Self::UserAction,
            "AiAssessment" | "ai_assessment" | "ai" => Self::AiAssessment,
            "InvestigatorNote" | "investigator_note" | "note" => Self::InvestigatorNote,
            _ => Self::McpToolCall,
        }
    }

    /// Get icon hint for the frontend.
    pub fn icon_hint(&self) -> &str {
        match self {
            Self::McpToolCall => "terminal",
            Self::FileAccess => "file",
            Self::NetworkConnection => "globe",
            Self::ProcessExecution => "cpu",
            Self::PolicyDecision => "shield",
            Self::UserAction => "user",
            Self::AiAssessment => "brain",
            Self::InvestigatorNote => "search",
        }
    }
}

// ---------------------------------------------------------------------------
// TimelineBuilder
// ---------------------------------------------------------------------------

/// Builds investigation timelines from various data sources.
pub struct TimelineBuilder;

impl TimelineBuilder {
    /// Build a timeline from investigation evidence and findings.
    pub fn from_investigation(
        investigation_id: &str,
        events: &[serde_json::Value],
        evidence: &[serde_json::Value],
        findings: &[serde_json::Value],
        narrative: &str,
    ) -> InvestigationTimeline {
        let mut entries = Vec::new();
        let mut seq = 1u64;

        // Convert raw events to timeline entries
        for event in events {
            let timestamp = parse_event_timestamp(event);
            let server = event
                .get("server_name")
                .or_else(|| event.get("server"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let description = event
                .get("description")
                .or_else(|| event.get("details"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let severity = event
                .get("severity")
                .or_else(|| event.get("risk_level"))
                .and_then(|v| v.as_str())
                .unwrap_or("info")
                .to_string();
            let event_id = event
                .get("id")
                .or_else(|| event.get("event_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let entry_type = TimelineEntryType::from_event(event);

            // Build a meaningful description if the raw one is empty
            let desc = if description.is_empty() {
                build_event_description(event)
            } else {
                description
            };

            entries.push(TimelineEntry {
                id: format!("tl-{}-{}", investigation_id, seq),
                timestamp,
                entry_type,
                server,
                description: desc,
                severity,
                event_id,
                is_key_moment: false,
                connects_to: None,
                stage: event
                    .get("stage")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
            seq += 1;
        }

        // Add evidence items as timeline entries
        for ev_item in evidence {
            let timestamp = parse_event_timestamp(ev_item);
            let server = ev_item
                .get("server")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let description = ev_item
                .get("tool_result_summary")
                .or_else(|| ev_item.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("Evidence collected")
                .to_string();

            entries.push(TimelineEntry {
                id: format!("tl-{}-{}", investigation_id, seq),
                timestamp,
                entry_type: TimelineEntryType::AiAssessment,
                server,
                description,
                severity: "info".to_string(),
                event_id: ev_item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                is_key_moment: false,
                connects_to: None,
                stage: ev_item
                    .get("stage")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
            seq += 1;
        }

        // Add findings as key timeline entries
        for finding in findings {
            let timestamp = parse_event_timestamp(finding);
            let server = finding
                .get("server")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let severity = finding
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("medium")
                .to_string();
            let title = finding
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Finding");
            let description_text = finding
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let desc = if description_text.is_empty() {
                title.to_string()
            } else {
                format!("{}: {}", title, description_text)
            };

            entries.push(TimelineEntry {
                id: format!("tl-{}-{}", investigation_id, seq),
                timestamp,
                entry_type: TimelineEntryType::AiAssessment,
                server,
                description: desc,
                severity,
                event_id: None,
                is_key_moment: true,
                connects_to: None,
                stage: finding
                    .get("stage")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
            seq += 1;
        }

        // Extract any [TIMELINE_ENTRY] tags from the narrative
        let parsed_entries = Self::extract_timeline_entries(narrative);
        for mut entry in parsed_entries {
            entry.id = format!("tl-{}-{}", investigation_id, seq);
            entries.push(entry);
            seq += 1;
        }

        // Sort chronologically
        entries.sort_by_key(|e| e.timestamp);

        // Mark key moments and link related entries
        Self::mark_key_moments(&mut entries);
        Self::link_related_entries(&mut entries);

        // Collect servers
        let mut servers_involved: Vec<String> = entries
            .iter()
            .map(|e| e.server.clone())
            .filter(|s| s != "unknown")
            .collect();
        servers_involved.sort();
        servers_involved.dedup();

        // Compute time span
        let time_span = if entries.is_empty() {
            let now = Utc::now();
            TimeSpan {
                start: now,
                end: now,
            }
        } else {
            TimeSpan {
                start: entries.first().unwrap().timestamp,
                end: entries.last().unwrap().timestamp,
            }
        };

        // Build narrative
        let narrative_summary = if narrative.is_empty() {
            NarrativeGenerator::generate_summary(&entries)
        } else {
            // Strip [TIMELINE_ENTRY] tags from the narrative for the summary
            strip_timeline_tags(narrative)
        };

        InvestigationTimeline {
            investigation_id: investigation_id.to_string(),
            entries,
            servers_involved,
            time_span,
            narrative_summary,
        }
    }

    /// Build a timeline for a single event with surrounding context.
    pub fn from_event_context(
        event_id: &str,
        target_event: &serde_json::Value,
        surrounding_events: &[serde_json::Value],
    ) -> InvestigationTimeline {
        let investigation_id = format!("evt-{}", event_id);
        let mut all_events: Vec<serde_json::Value> = surrounding_events.to_vec();

        // Make sure the target event is included
        let target_id = target_event
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !all_events
            .iter()
            .any(|e| e.get("id").and_then(|v| v.as_str()).unwrap_or("") == target_id)
        {
            all_events.push(target_event.clone());
        }

        let narrative =
            NarrativeGenerator::generate_event_story(target_event, surrounding_events);

        Self::from_investigation(&investigation_id, &all_events, &[], &[], &narrative)
    }

    /// Parse `[TIMELINE_ENTRY ...]...[/TIMELINE_ENTRY]` tags from text.
    pub fn extract_timeline_entries(text: &str) -> Vec<TimelineEntry> {
        let mut entries = Vec::new();
        let re = Regex::new(
            r#"\[TIMELINE_ENTRY\s+([^\]]*)\]([\s\S]*?)\[/TIMELINE_ENTRY\]"#,
        )
        .expect("regex must compile");

        for (idx, cap) in re.captures_iter(text).enumerate() {
            let attrs_str = &cap[1];
            let body = cap[2].trim();

            let time_str = parse_tag_attr_value(attrs_str, "time")
                .unwrap_or_default();
            let timestamp = DateTime::parse_from_rfc3339(&time_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            let server = parse_tag_attr_value(attrs_str, "server")
                .unwrap_or_else(|| "unknown".to_string());
            let type_str = parse_tag_attr_value(attrs_str, "type")
                .unwrap_or_else(|| "McpToolCall".to_string());
            let severity = parse_tag_attr_value(attrs_str, "severity")
                .unwrap_or_else(|| "info".to_string());
            let key_str = parse_tag_attr_value(attrs_str, "key")
                .unwrap_or_else(|| "false".to_string());
            let is_key = key_str == "true" || key_str == "yes" || key_str == "1";

            let stage = parse_tag_attr_value(attrs_str, "stage");

            entries.push(TimelineEntry {
                id: format!("parsed-{}", idx),
                timestamp,
                entry_type: TimelineEntryType::from_str_label(&type_str),
                server,
                description: body.to_string(),
                severity,
                event_id: None,
                is_key_moment: is_key,
                connects_to: None,
                stage,
            });
        }

        entries
    }

    /// Insert investigator notes at appropriate timeline positions.
    fn insert_investigator_notes(
        timeline: &mut Vec<TimelineEntry>,
        notes: &[(DateTime<Utc>, String)],
    ) {
        for (timestamp, note_text) in notes {
            let entry = TimelineEntry {
                id: format!("note-{}", timeline.len()),
                timestamp: *timestamp,
                entry_type: TimelineEntryType::InvestigatorNote,
                server: "investigator".to_string(),
                description: note_text.clone(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            };
            timeline.push(entry);
        }
        timeline.sort_by_key(|e| e.timestamp);
    }

    /// Identify key moments: critical/high severity, policy blocks, pivots.
    fn mark_key_moments(entries: &mut Vec<TimelineEntry>) {
        for entry in entries.iter_mut() {
            if entry.is_key_moment {
                continue;
            }
            let sev = entry.severity.to_lowercase();
            if sev == "critical" || sev == "high" {
                entry.is_key_moment = true;
                continue;
            }
            if entry.entry_type == TimelineEntryType::PolicyDecision {
                let desc_lower = entry.description.to_lowercase();
                if desc_lower.contains("block") || desc_lower.contains("deny") {
                    entry.is_key_moment = true;
                    continue;
                }
            }
            // Mark file access to sensitive paths
            if entry.entry_type == TimelineEntryType::FileAccess {
                let desc_lower = entry.description.to_lowercase();
                if desc_lower.contains("ssh")
                    || desc_lower.contains("passwd")
                    || desc_lower.contains("shadow")
                    || desc_lower.contains("private")
                    || desc_lower.contains("secret")
                    || desc_lower.contains("token")
                    || desc_lower.contains("credential")
                {
                    entry.is_key_moment = true;
                }
            }
        }
    }

    /// Link related entries: consecutive events from the same server, or
    /// tool calls followed by file access.
    fn link_related_entries(entries: &mut Vec<TimelineEntry>) {
        if entries.len() < 2 {
            return;
        }

        // Link consecutive entries from the same server
        let ids: Vec<(String, String)> = entries
            .iter()
            .map(|e| (e.id.clone(), e.server.clone()))
            .collect();

        for i in 1..ids.len() {
            if ids[i].1 == ids[i - 1].1 && ids[i].1 != "unknown" {
                entries[i].connects_to = Some(ids[i - 1].0.clone());
            }
        }
    }

    /// Find related past investigations and compare.
    pub fn compare_with_past(
        current: &InvestigationTimeline,
        past_timelines: &[InvestigationTimeline],
    ) -> Vec<StoryComparison> {
        let mut comparisons = Vec::new();

        for past in past_timelines {
            if past.investigation_id == current.investigation_id {
                continue;
            }

            let common_servers: Vec<String> = current
                .servers_involved
                .iter()
                .filter(|s| past.servers_involved.contains(s))
                .cloned()
                .collect();

            // Find common patterns (entry type sequences)
            let current_types: Vec<&str> = current
                .entries
                .iter()
                .map(|e| e.entry_type.icon_hint())
                .collect();
            let past_types: Vec<&str> = past
                .entries
                .iter()
                .map(|e| e.entry_type.icon_hint())
                .collect();

            let mut common_patterns = Vec::new();
            // Look for common 2-entry subsequences
            for window in current_types.windows(2) {
                let pattern = format!("{} -> {}", window[0], window[1]);
                if past_types
                    .windows(2)
                    .any(|w| w[0] == window[0] && w[1] == window[1])
                    && !common_patterns.contains(&pattern)
                {
                    common_patterns.push(pattern);
                }
            }

            // Find differences
            let mut differences = Vec::new();
            let current_server_set: std::collections::HashSet<&str> =
                current.servers_involved.iter().map(|s| s.as_str()).collect();
            let past_server_set: std::collections::HashSet<&str> =
                past.servers_involved.iter().map(|s| s.as_str()).collect();

            for s in &current_server_set {
                if !past_server_set.contains(s) {
                    differences.push(format!(
                        "Server '{}' only in current investigation",
                        s
                    ));
                }
            }
            for s in &past_server_set {
                if !current_server_set.contains(s) {
                    differences.push(format!(
                        "Server '{}' only in past investigation",
                        s
                    ));
                }
            }

            if current.entries.len() != past.entries.len() {
                differences.push(format!(
                    "Different number of events ({} vs {})",
                    current.entries.len(),
                    past.entries.len()
                ));
            }

            // Compute similarity score
            let server_sim = if current.servers_involved.is_empty()
                && past.servers_involved.is_empty()
            {
                1.0
            } else {
                let union_size = current_server_set.union(&past_server_set).count();
                if union_size == 0 {
                    0.0
                } else {
                    common_servers.len() as f64 / union_size as f64
                }
            };

            let pattern_sim = if common_patterns.is_empty() {
                0.0
            } else {
                let max_windows = current_types
                    .windows(2)
                    .count()
                    .max(past_types.windows(2).count());
                if max_windows == 0 {
                    0.0
                } else {
                    common_patterns.len() as f64 / max_windows as f64
                }
            };

            let similarity_score =
                ((server_sim * 0.5 + pattern_sim * 0.5) * 100.0).round() / 100.0;

            let comparison_narrative = format!(
                "Investigation {} shares {} server(s) and {} pattern(s) with the current investigation. Similarity: {:.0}%.",
                past.investigation_id,
                common_servers.len(),
                common_patterns.len(),
                similarity_score * 100.0,
            );

            comparisons.push(StoryComparison {
                current_investigation_id: current.investigation_id.clone(),
                related_investigation_id: past.investigation_id.clone(),
                similarity_score,
                common_servers,
                common_patterns,
                differences,
                comparison_narrative,
            });
        }

        // Sort by similarity (highest first)
        comparisons.sort_by(|a, b| {
            b.similarity_score
                .partial_cmp(&a.similarity_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        comparisons
    }
}

// ---------------------------------------------------------------------------
// NarrativeGenerator
// ---------------------------------------------------------------------------

/// Generates human-readable narratives from timeline data.
pub struct NarrativeGenerator;

impl NarrativeGenerator {
    /// Generate a short narrative summary from timeline entries.
    pub fn generate_summary(entries: &[TimelineEntry]) -> String {
        if entries.is_empty() {
            return "No events recorded in this timeline.".to_string();
        }

        let key_moments: Vec<&TimelineEntry> =
            entries.iter().filter(|e| e.is_key_moment).collect();
        let servers: Vec<String> = {
            let mut s: Vec<String> = entries
                .iter()
                .map(|e| e.server.clone())
                .filter(|s| s != "unknown")
                .collect();
            s.sort();
            s.dedup();
            s
        };

        let mut parts = Vec::new();

        // Opening: time span and scope
        let first = &entries[0];
        let last = &entries[entries.len() - 1];
        parts.push(format!(
            "Timeline spans {} event(s) across {} server(s).",
            entries.len(),
            servers.len().max(1),
        ));

        if first.timestamp != last.timestamp {
            let duration = last.timestamp - first.timestamp;
            let duration_desc = format_duration(duration);
            parts.push(format!("Duration: {}.", duration_desc));
        }

        // Key moments
        if !key_moments.is_empty() {
            parts.push(format!(
                "{} key moment(s) identified.",
                key_moments.len()
            ));
            for km in key_moments.iter().take(3) {
                parts.push(format!(
                    "- [{}] {}: {}",
                    km.severity.to_uppercase(),
                    km.server,
                    km.description
                ));
            }
            if key_moments.len() > 3 {
                parts.push(format!(
                    "  ...and {} more.",
                    key_moments.len() - 3
                ));
            }
        }

        // Severity breakdown
        let critical_count = entries.iter().filter(|e| e.severity == "critical").count();
        let high_count = entries.iter().filter(|e| e.severity == "high").count();
        if critical_count > 0 || high_count > 0 {
            parts.push(format!(
                "Severity: {} critical, {} high.",
                critical_count, high_count
            ));
        }

        parts.join(" ")
    }

    /// Generate a quick event story from event data (no Claude needed).
    pub fn generate_event_story(
        event: &serde_json::Value,
        surrounding: &[serde_json::Value],
    ) -> String {
        let server = event
            .get("server_name")
            .or_else(|| event.get("server"))
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown server");
        let action = event
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("performed an action");
        let decision = event
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let tool = event
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let risk = event
            .get("risk_level")
            .or_else(|| event.get("severity"))
            .and_then(|v| v.as_str())
            .unwrap_or("info");
        let timestamp = parse_event_timestamp(event);

        let mut story_parts = Vec::new();

        // Main event description
        let time_str = timestamp.format("%H:%M:%S UTC").to_string();
        if !tool.is_empty() {
            story_parts.push(format!(
                "At {}, {} called tool '{}' ({}).",
                time_str, server, tool, action
            ));
        } else {
            story_parts.push(format!(
                "At {}, {} {}.",
                time_str, server, action
            ));
        }

        // Decision
        if !decision.is_empty() {
            let decision_desc = match decision {
                "allow" => "The action was allowed by policy.",
                "deny" | "block" => "The action was blocked by policy.",
                "prompt" => "The user was prompted for a decision.",
                _ => "",
            };
            if !decision_desc.is_empty() {
                story_parts.push(decision_desc.to_string());
            }
        }

        // Risk assessment
        match risk {
            "critical" => story_parts.push(
                "This event is rated CRITICAL and requires immediate attention.".to_string(),
            ),
            "high" => story_parts.push(
                "This event is rated HIGH risk and should be investigated.".to_string(),
            ),
            "medium" => story_parts.push(
                "This event is rated MEDIUM risk.".to_string(),
            ),
            _ => {}
        }

        // Context from surrounding events
        if !surrounding.is_empty() {
            let same_server: Vec<&serde_json::Value> = surrounding
                .iter()
                .filter(|e| {
                    e.get("server_name")
                        .or_else(|| e.get("server"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        == server
                })
                .collect();
            if !same_server.is_empty() {
                story_parts.push(format!(
                    "{} other event(s) from the same server were observed in the surrounding window.",
                    same_server.len()
                ));
            }

            let other_servers: Vec<&str> = surrounding
                .iter()
                .filter_map(|e| {
                    let s = e
                        .get("server_name")
                        .or_else(|| e.get("server"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if s != server && !s.is_empty() {
                        Some(s)
                    } else {
                        None
                    }
                })
                .collect();
            if !other_servers.is_empty() {
                let mut unique: Vec<&str> = other_servers;
                unique.sort();
                unique.dedup();
                story_parts.push(format!(
                    "Other servers active in this window: {}.",
                    unique.join(", ")
                ));
            }
        }

        story_parts.join(" ")
    }
}

// ---------------------------------------------------------------------------
// StoryComparison
// ---------------------------------------------------------------------------

/// Comparison between two investigation timelines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoryComparison {
    pub current_investigation_id: String,
    pub related_investigation_id: String,
    pub similarity_score: f64,
    pub common_servers: Vec<String>,
    pub common_patterns: Vec<String>,
    pub differences: Vec<String>,
    pub comparison_narrative: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a timestamp from an event's various possible timestamp fields.
fn parse_event_timestamp(event: &serde_json::Value) -> DateTime<Utc> {
    let ts_str = event
        .get("timestamp")
        .or_else(|| event.get("time"))
        .or_else(|| event.get("created_at"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    DateTime::parse_from_rfc3339(ts_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

/// Build a description from event fields when no explicit description exists.
fn build_event_description(event: &serde_json::Value) -> String {
    let mut parts = Vec::new();

    if let Some(action) = event.get("action").and_then(|v| v.as_str()) {
        parts.push(action.to_string());
    }
    if let Some(tool) = event.get("tool_name").and_then(|v| v.as_str()) {
        parts.push(format!("tool: {}", tool));
    }
    if let Some(decision) = event.get("decision").and_then(|v| v.as_str()) {
        parts.push(format!("decision: {}", decision));
    }
    if let Some(resource) = event.get("resource").and_then(|v| v.as_str()) {
        parts.push(format!("resource: {}", resource));
    }
    if let Some(details) = event.get("details").and_then(|v| v.as_str()) {
        if !details.is_empty() {
            let summary = if details.len() > 120 {
                format!("{}...", &details[..120])
            } else {
                details.to_string()
            };
            parts.push(summary);
        }
    }

    if parts.is_empty() {
        "Event recorded".to_string()
    } else {
        parts.join("; ")
    }
}

/// Parse a `key="value"` or `key=value` attribute from a tag attribute string.
fn parse_tag_attr_value(attrs: &str, key: &str) -> Option<String> {
    // Try quoted: key="value"
    let quoted_pattern = format!(r#"{}="([^"]*)""#, regex::escape(key));
    if let Ok(re) = Regex::new(&quoted_pattern) {
        if let Some(cap) = re.captures(attrs) {
            return Some(cap[1].to_string());
        }
    }

    // Try unquoted: key=value
    let unquoted_pattern = format!(r#"{}=(\S+)"#, regex::escape(key));
    if let Ok(re) = Regex::new(&unquoted_pattern) {
        if let Some(cap) = re.captures(attrs) {
            return Some(cap[1].to_string());
        }
    }

    None
}

/// Strip [TIMELINE_ENTRY]...[/TIMELINE_ENTRY] tags from text, keeping surrounding text.
fn strip_timeline_tags(text: &str) -> String {
    let re = Regex::new(r#"\[TIMELINE_ENTRY\s+[^\]]*\][\s\S]*?\[/TIMELINE_ENTRY\]"#)
        .expect("regex must compile");
    let result = re.replace_all(text, "").to_string();
    // Clean up extra whitespace
    let cleaned: Vec<&str> = result.lines().filter(|l| !l.trim().is_empty()).collect();
    cleaned.join("\n")
}

/// Format a chrono Duration for human display.
fn format_duration(duration: chrono::Duration) -> String {
    let total_secs = duration.num_seconds().unsigned_abs();
    if total_secs < 60 {
        format!("{} second(s)", total_secs)
    } else if total_secs < 3600 {
        format!("{} minute(s)", total_secs / 60)
    } else if total_secs < 86400 {
        format!("{} hour(s)", total_secs / 3600)
    } else {
        format!("{} day(s)", total_secs / 86400)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_event(id: &str, server: &str, timestamp: &str) -> serde_json::Value {
        json!({
            "id": id,
            "timestamp": timestamp,
            "server_name": server,
            "event_type": "proxy",
            "tool_name": "read_file",
            "action": "tools/call",
            "decision": "allow",
            "risk_level": "info",
            "details": format!("Event {} from {}", id, server),
        })
    }

    fn make_critical_event(id: &str, server: &str, timestamp: &str) -> serde_json::Value {
        json!({
            "id": id,
            "timestamp": timestamp,
            "server_name": server,
            "event_type": "proxy",
            "tool_name": "read_file",
            "action": "tools/call",
            "decision": "allow",
            "risk_level": "critical",
            "details": "Read SSH private key at ~/.ssh/id_rsa",
        })
    }

    fn make_evidence(id: &str, server: &str, timestamp: &str) -> serde_json::Value {
        json!({
            "id": id,
            "timestamp": timestamp,
            "server": server,
            "tool_result_summary": "Evidence collected",
            "stage": "reconnaissance",
        })
    }

    fn make_finding(title: &str, severity: &str, server: &str) -> serde_json::Value {
        json!({
            "title": title,
            "severity": severity,
            "server": server,
            "description": format!("Finding: {}", title),
            "timestamp": "2024-01-15T14:30:00Z",
        })
    }

    // -- Timeline construction tests --

    #[test]
    fn test_from_investigation_basic() {
        let events = vec![
            make_event("e1", "file-manager", "2024-01-15T14:20:00Z"),
            make_event("e2", "file-manager", "2024-01-15T14:21:00Z"),
            make_event("e3", "web-browser", "2024-01-15T14:22:00Z"),
        ];
        let evidence = vec![
            make_evidence("ev1", "file-manager", "2024-01-15T14:20:30Z"),
        ];
        let findings = vec![
            make_finding("SSH Key Exposed", "high", "file-manager"),
        ];

        let timeline = TimelineBuilder::from_investigation(
            "inv-001",
            &events,
            &evidence,
            &findings,
            "",
        );

        assert_eq!(timeline.investigation_id, "inv-001");
        // 3 events + 1 evidence + 1 finding = 5 entries
        assert_eq!(timeline.entries.len(), 5);
        assert!(timeline.servers_involved.contains(&"file-manager".to_string()));
        assert!(timeline.servers_involved.contains(&"web-browser".to_string()));
        assert!(!timeline.narrative_summary.is_empty());
    }

    #[test]
    fn test_from_investigation_empty() {
        let timeline = TimelineBuilder::from_investigation(
            "inv-empty",
            &[],
            &[],
            &[],
            "",
        );

        assert_eq!(timeline.entries.len(), 0);
        assert!(timeline.servers_involved.is_empty());
        assert!(timeline.narrative_summary.contains("No events"));
    }

    #[test]
    fn test_from_investigation_with_narrative() {
        let events = vec![
            make_event("e1", "srv", "2024-01-15T14:20:00Z"),
        ];
        let narrative = "The server performed a suspicious action.";

        let timeline = TimelineBuilder::from_investigation(
            "inv-002",
            &events,
            &[],
            &[],
            narrative,
        );

        assert_eq!(timeline.narrative_summary, narrative);
    }

    #[test]
    fn test_timeline_sorted_chronologically() {
        let events = vec![
            make_event("e3", "srv", "2024-01-15T14:30:00Z"),
            make_event("e1", "srv", "2024-01-15T14:10:00Z"),
            make_event("e2", "srv", "2024-01-15T14:20:00Z"),
        ];

        let timeline = TimelineBuilder::from_investigation(
            "inv-sort",
            &events,
            &[],
            &[],
            "",
        );

        assert_eq!(timeline.entries[0].event_id, Some("e1".to_string()));
        assert_eq!(timeline.entries[1].event_id, Some("e2".to_string()));
        assert_eq!(timeline.entries[2].event_id, Some("e3".to_string()));
    }

    #[test]
    fn test_time_span_calculated() {
        let events = vec![
            make_event("e1", "srv", "2024-01-15T14:00:00Z"),
            make_event("e2", "srv", "2024-01-15T15:30:00Z"),
        ];

        let timeline = TimelineBuilder::from_investigation(
            "inv-span",
            &events,
            &[],
            &[],
            "",
        );

        assert!(timeline.time_span.start < timeline.time_span.end);
        let duration = timeline.time_span.end - timeline.time_span.start;
        assert_eq!(duration.num_minutes(), 90);
    }

    // -- [TIMELINE_ENTRY] tag parsing tests --

    #[test]
    fn test_extract_timeline_entries_basic() {
        let text = r#"
Some analysis.

[TIMELINE_ENTRY time="2024-01-15T14:23:00Z" server="file-manager" type="FileAccess" severity="high" key=true]
FileManager read the SSH private key at ~/.ssh/id_rsa
[/TIMELINE_ENTRY]

More text.
"#;
        let entries = TimelineBuilder::extract_timeline_entries(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].server, "file-manager");
        assert_eq!(entries[0].entry_type, TimelineEntryType::FileAccess);
        assert_eq!(entries[0].severity, "high");
        assert!(entries[0].is_key_moment);
        assert!(entries[0].description.contains("SSH private key"));
    }

    #[test]
    fn test_extract_timeline_entries_multiple() {
        let text = r#"
[TIMELINE_ENTRY time="2024-01-15T14:20:00Z" server="srv-a" type="McpToolCall" severity="info" key=false]
First event
[/TIMELINE_ENTRY]

[TIMELINE_ENTRY time="2024-01-15T14:21:00Z" server="srv-b" type="NetworkConnection" severity="medium" key=false]
Second event
[/TIMELINE_ENTRY]

[TIMELINE_ENTRY time="2024-01-15T14:22:00Z" server="srv-a" type="PolicyDecision" severity="high" key=true]
Third event - blocked
[/TIMELINE_ENTRY]
"#;
        let entries = TimelineBuilder::extract_timeline_entries(text);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].server, "srv-a");
        assert_eq!(entries[0].entry_type, TimelineEntryType::McpToolCall);
        assert_eq!(entries[1].entry_type, TimelineEntryType::NetworkConnection);
        assert_eq!(entries[2].entry_type, TimelineEntryType::PolicyDecision);
        assert!(entries[2].is_key_moment);
    }

    #[test]
    fn test_extract_timeline_entries_no_tags() {
        let text = "Just some regular text without any timeline entries.";
        let entries = TimelineBuilder::extract_timeline_entries(text);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_extract_timeline_entries_unquoted_attrs() {
        let text = r#"[TIMELINE_ENTRY time=2024-01-15T14:23:00Z server=test-srv type=FileAccess severity=low key=false]
Some event
[/TIMELINE_ENTRY]"#;
        let entries = TimelineBuilder::extract_timeline_entries(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].server, "test-srv");
        assert_eq!(entries[0].severity, "low");
        assert!(!entries[0].is_key_moment);
    }

    #[test]
    fn test_extract_timeline_entries_missing_attrs() {
        let text = r#"[TIMELINE_ENTRY time="2024-01-15T14:23:00Z"]
Minimal entry
[/TIMELINE_ENTRY]"#;
        let entries = TimelineBuilder::extract_timeline_entries(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].server, "unknown");
        assert_eq!(entries[0].severity, "info");
        assert_eq!(entries[0].entry_type, TimelineEntryType::McpToolCall);
    }

    // -- Entry type detection tests --

    #[test]
    fn test_entry_type_from_event_proxy() {
        let event = json!({"event_type": "proxy", "tool_name": "read_file"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::McpToolCall);
    }

    #[test]
    fn test_entry_type_from_event_file_access() {
        let event = json!({"event_type": "file_access"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::FileAccess);
    }

    #[test]
    fn test_entry_type_from_event_network() {
        let event = json!({"event_type": "network"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::NetworkConnection);
    }

    #[test]
    fn test_entry_type_from_event_process() {
        let event = json!({"event_type": "process"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::ProcessExecution);
    }

    #[test]
    fn test_entry_type_from_event_policy() {
        let event = json!({"event_type": "policy"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::PolicyDecision);
    }

    #[test]
    fn test_entry_type_from_event_user_action() {
        let event = json!({"event_type": "user_action"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::UserAction);
    }

    #[test]
    fn test_entry_type_from_event_by_tool_name() {
        let event = json!({"tool_name": "search_code"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::McpToolCall);
    }

    #[test]
    fn test_entry_type_from_event_by_decision() {
        let event = json!({"decision": "deny"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::PolicyDecision);
    }

    #[test]
    fn test_entry_type_from_event_by_action_file() {
        let event = json!({"action": "file_read_operation"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::FileAccess);
    }

    #[test]
    fn test_entry_type_from_event_by_action_network() {
        let event = json!({"action": "network_connect"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::NetworkConnection);
    }

    #[test]
    fn test_entry_type_from_event_default() {
        let event = json!({"some_field": "some_value"});
        assert_eq!(TimelineEntryType::from_event(&event), TimelineEntryType::McpToolCall);
    }

    #[test]
    fn test_entry_type_from_str_label() {
        assert_eq!(TimelineEntryType::from_str_label("McpToolCall"), TimelineEntryType::McpToolCall);
        assert_eq!(TimelineEntryType::from_str_label("file_access"), TimelineEntryType::FileAccess);
        assert_eq!(TimelineEntryType::from_str_label("network"), TimelineEntryType::NetworkConnection);
        assert_eq!(TimelineEntryType::from_str_label("process"), TimelineEntryType::ProcessExecution);
        assert_eq!(TimelineEntryType::from_str_label("policy"), TimelineEntryType::PolicyDecision);
        assert_eq!(TimelineEntryType::from_str_label("user"), TimelineEntryType::UserAction);
        assert_eq!(TimelineEntryType::from_str_label("ai"), TimelineEntryType::AiAssessment);
        assert_eq!(TimelineEntryType::from_str_label("note"), TimelineEntryType::InvestigatorNote);
        assert_eq!(TimelineEntryType::from_str_label("unknown"), TimelineEntryType::McpToolCall);
    }

    // -- Icon hint tests --

    #[test]
    fn test_icon_hints() {
        assert_eq!(TimelineEntryType::McpToolCall.icon_hint(), "terminal");
        assert_eq!(TimelineEntryType::FileAccess.icon_hint(), "file");
        assert_eq!(TimelineEntryType::NetworkConnection.icon_hint(), "globe");
        assert_eq!(TimelineEntryType::ProcessExecution.icon_hint(), "cpu");
        assert_eq!(TimelineEntryType::PolicyDecision.icon_hint(), "shield");
        assert_eq!(TimelineEntryType::UserAction.icon_hint(), "user");
        assert_eq!(TimelineEntryType::AiAssessment.icon_hint(), "brain");
        assert_eq!(TimelineEntryType::InvestigatorNote.icon_hint(), "search");
    }

    // -- Key moment detection tests --

    #[test]
    fn test_mark_key_moments_critical() {
        let mut entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: Utc::now(),
                entry_type: TimelineEntryType::McpToolCall,
                server: "srv".to_string(),
                description: "Normal call".to_string(),
                severity: "critical".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];
        TimelineBuilder::mark_key_moments(&mut entries);
        assert!(entries[0].is_key_moment);
    }

    #[test]
    fn test_mark_key_moments_high() {
        let mut entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: Utc::now(),
                entry_type: TimelineEntryType::McpToolCall,
                server: "srv".to_string(),
                description: "High risk call".to_string(),
                severity: "high".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];
        TimelineBuilder::mark_key_moments(&mut entries);
        assert!(entries[0].is_key_moment);
    }

    #[test]
    fn test_mark_key_moments_policy_block() {
        let mut entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: Utc::now(),
                entry_type: TimelineEntryType::PolicyDecision,
                server: "srv".to_string(),
                description: "Request blocked by firewall rule".to_string(),
                severity: "medium".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];
        TimelineBuilder::mark_key_moments(&mut entries);
        assert!(entries[0].is_key_moment);
    }

    #[test]
    fn test_mark_key_moments_sensitive_file() {
        let mut entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: Utc::now(),
                entry_type: TimelineEntryType::FileAccess,
                server: "srv".to_string(),
                description: "Read SSH private key".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];
        TimelineBuilder::mark_key_moments(&mut entries);
        assert!(entries[0].is_key_moment);
    }

    #[test]
    fn test_mark_key_moments_info_not_key() {
        let mut entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: Utc::now(),
                entry_type: TimelineEntryType::McpToolCall,
                server: "srv".to_string(),
                description: "Normal operation".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];
        TimelineBuilder::mark_key_moments(&mut entries);
        assert!(!entries[0].is_key_moment);
    }

    // -- Entry linking tests --

    #[test]
    fn test_link_related_entries_same_server() {
        let now = Utc::now();
        let mut entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: now,
                entry_type: TimelineEntryType::McpToolCall,
                server: "file-manager".to_string(),
                description: "First".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
            TimelineEntry {
                id: "e2".to_string(),
                timestamp: now,
                entry_type: TimelineEntryType::FileAccess,
                server: "file-manager".to_string(),
                description: "Second".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];

        TimelineBuilder::link_related_entries(&mut entries);
        assert_eq!(entries[0].connects_to, None);
        assert_eq!(entries[1].connects_to, Some("e1".to_string()));
    }

    #[test]
    fn test_link_related_entries_different_servers() {
        let now = Utc::now();
        let mut entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: now,
                entry_type: TimelineEntryType::McpToolCall,
                server: "server-a".to_string(),
                description: "First".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
            TimelineEntry {
                id: "e2".to_string(),
                timestamp: now,
                entry_type: TimelineEntryType::McpToolCall,
                server: "server-b".to_string(),
                description: "Second".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];

        TimelineBuilder::link_related_entries(&mut entries);
        assert_eq!(entries[0].connects_to, None);
        assert_eq!(entries[1].connects_to, None);
    }

    #[test]
    fn test_link_related_entries_empty() {
        let mut entries: Vec<TimelineEntry> = Vec::new();
        TimelineBuilder::link_related_entries(&mut entries);
        // Should not panic
        assert!(entries.is_empty());
    }

    #[test]
    fn test_link_related_entries_single() {
        let mut entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: Utc::now(),
                entry_type: TimelineEntryType::McpToolCall,
                server: "srv".to_string(),
                description: "Only entry".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];
        TimelineBuilder::link_related_entries(&mut entries);
        assert_eq!(entries[0].connects_to, None);
    }

    // -- Narrative generation tests --

    #[test]
    fn test_narrative_empty_entries() {
        let summary = NarrativeGenerator::generate_summary(&[]);
        assert!(summary.contains("No events"));
    }

    #[test]
    fn test_narrative_with_key_moments() {
        let now = Utc::now();
        let entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: now,
                entry_type: TimelineEntryType::McpToolCall,
                server: "srv-a".to_string(),
                description: "SSH key read".to_string(),
                severity: "critical".to_string(),
                event_id: None,
                is_key_moment: true,
                connects_to: None,
                stage: None,
            },
            TimelineEntry {
                id: "e2".to_string(),
                timestamp: now,
                entry_type: TimelineEntryType::McpToolCall,
                server: "srv-b".to_string(),
                description: "Normal call".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];

        let summary = NarrativeGenerator::generate_summary(&entries);
        assert!(summary.contains("2 event(s)"));
        assert!(summary.contains("2 server(s)"));
        assert!(summary.contains("1 key moment"));
        assert!(summary.contains("CRITICAL"));
        assert!(summary.contains("SSH key read"));
    }

    #[test]
    fn test_event_story_generation() {
        let event = json!({
            "server_name": "file-manager",
            "action": "tools/call",
            "tool_name": "read_file",
            "decision": "allow",
            "risk_level": "high",
            "timestamp": "2024-01-15T14:23:00Z",
        });

        let surrounding = vec![
            json!({
                "server_name": "file-manager",
                "action": "tools/call",
                "tool_name": "list_files",
                "timestamp": "2024-01-15T14:22:00Z",
            }),
            json!({
                "server_name": "web-browser",
                "action": "tools/call",
                "tool_name": "fetch_url",
                "timestamp": "2024-01-15T14:23:30Z",
            }),
        ];

        let story = NarrativeGenerator::generate_event_story(&event, &surrounding);
        assert!(story.contains("file-manager"));
        assert!(story.contains("read_file"));
        assert!(story.contains("allowed by policy"));
        assert!(story.contains("HIGH risk"));
        assert!(story.contains("1 other event(s) from the same server"));
        assert!(story.contains("web-browser"));
    }

    #[test]
    fn test_event_story_no_surrounding() {
        let event = json!({
            "server_name": "test-srv",
            "action": "ping",
            "decision": "allow",
            "risk_level": "info",
            "timestamp": "2024-01-15T14:00:00Z",
        });

        let story = NarrativeGenerator::generate_event_story(&event, &[]);
        assert!(story.contains("test-srv"));
        assert!(story.contains("ping"));
    }

    #[test]
    fn test_event_story_blocked() {
        let event = json!({
            "server_name": "evil-server",
            "action": "tools/call",
            "tool_name": "exec_command",
            "decision": "block",
            "risk_level": "critical",
            "timestamp": "2024-01-15T14:00:00Z",
        });

        let story = NarrativeGenerator::generate_event_story(&event, &[]);
        assert!(story.contains("blocked by policy"));
        assert!(story.contains("CRITICAL"));
    }

    // -- Story comparison tests --

    #[test]
    fn test_compare_identical_timelines() {
        let now = Utc::now();
        let entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: now,
                entry_type: TimelineEntryType::McpToolCall,
                server: "srv-a".to_string(),
                description: "Call".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
            TimelineEntry {
                id: "e2".to_string(),
                timestamp: now,
                entry_type: TimelineEntryType::FileAccess,
                server: "srv-a".to_string(),
                description: "Read".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];

        let current = InvestigationTimeline {
            investigation_id: "inv-1".to_string(),
            entries: entries.clone(),
            servers_involved: vec!["srv-a".to_string()],
            time_span: TimeSpan { start: now, end: now },
            narrative_summary: "Test".to_string(),
        };

        let past = InvestigationTimeline {
            investigation_id: "inv-2".to_string(),
            entries,
            servers_involved: vec!["srv-a".to_string()],
            time_span: TimeSpan { start: now, end: now },
            narrative_summary: "Test".to_string(),
        };

        let comparisons = TimelineBuilder::compare_with_past(&current, &[past]);
        assert_eq!(comparisons.len(), 1);
        assert!(comparisons[0].similarity_score > 0.5);
        assert_eq!(comparisons[0].common_servers, vec!["srv-a"]);
        assert!(!comparisons[0].common_patterns.is_empty());
    }

    #[test]
    fn test_compare_different_timelines() {
        let now = Utc::now();

        let current = InvestigationTimeline {
            investigation_id: "inv-1".to_string(),
            entries: vec![
                TimelineEntry {
                    id: "e1".to_string(),
                    timestamp: now,
                    entry_type: TimelineEntryType::McpToolCall,
                    server: "srv-a".to_string(),
                    description: "Call".to_string(),
                    severity: "info".to_string(),
                    event_id: None,
                    is_key_moment: false,
                    connects_to: None,
                    stage: None,
                },
            ],
            servers_involved: vec!["srv-a".to_string()],
            time_span: TimeSpan { start: now, end: now },
            narrative_summary: "Test".to_string(),
        };

        let past = InvestigationTimeline {
            investigation_id: "inv-2".to_string(),
            entries: vec![
                TimelineEntry {
                    id: "e1".to_string(),
                    timestamp: now,
                    entry_type: TimelineEntryType::NetworkConnection,
                    server: "srv-b".to_string(),
                    description: "Connect".to_string(),
                    severity: "high".to_string(),
                    event_id: None,
                    is_key_moment: false,
                    connects_to: None,
                    stage: None,
                },
            ],
            servers_involved: vec!["srv-b".to_string()],
            time_span: TimeSpan { start: now, end: now },
            narrative_summary: "Test".to_string(),
        };

        let comparisons = TimelineBuilder::compare_with_past(&current, &[past]);
        assert_eq!(comparisons.len(), 1);
        assert_eq!(comparisons[0].similarity_score, 0.0);
        assert!(comparisons[0].common_servers.is_empty());
        assert!(!comparisons[0].differences.is_empty());
    }

    #[test]
    fn test_compare_skips_self() {
        let now = Utc::now();
        let timeline = InvestigationTimeline {
            investigation_id: "inv-1".to_string(),
            entries: Vec::new(),
            servers_involved: Vec::new(),
            time_span: TimeSpan { start: now, end: now },
            narrative_summary: "Test".to_string(),
        };

        let comparisons = TimelineBuilder::compare_with_past(&timeline, &[timeline.clone()]);
        assert!(comparisons.is_empty());
    }

    #[test]
    fn test_compare_sorted_by_similarity() {
        let now = Utc::now();
        let entry_a = TimelineEntry {
            id: "e1".to_string(),
            timestamp: now,
            entry_type: TimelineEntryType::McpToolCall,
            server: "srv-a".to_string(),
            description: "Call".to_string(),
            severity: "info".to_string(),
            event_id: None,
            is_key_moment: false,
            connects_to: None,
            stage: None,
        };

        let current = InvestigationTimeline {
            investigation_id: "inv-0".to_string(),
            entries: vec![entry_a.clone()],
            servers_involved: vec!["srv-a".to_string()],
            time_span: TimeSpan { start: now, end: now },
            narrative_summary: "".to_string(),
        };

        // Similar (same server)
        let past_similar = InvestigationTimeline {
            investigation_id: "inv-1".to_string(),
            entries: vec![entry_a.clone()],
            servers_involved: vec!["srv-a".to_string()],
            time_span: TimeSpan { start: now, end: now },
            narrative_summary: "".to_string(),
        };

        // Different (different server)
        let past_different = InvestigationTimeline {
            investigation_id: "inv-2".to_string(),
            entries: vec![TimelineEntry {
                server: "srv-z".to_string(),
                ..entry_a
            }],
            servers_involved: vec!["srv-z".to_string()],
            time_span: TimeSpan { start: now, end: now },
            narrative_summary: "".to_string(),
        };

        let comparisons = TimelineBuilder::compare_with_past(
            &current,
            &[past_different, past_similar],
        );
        assert_eq!(comparisons.len(), 2);
        assert!(comparisons[0].similarity_score >= comparisons[1].similarity_score);
        assert_eq!(comparisons[0].related_investigation_id, "inv-1");
    }

    // -- From event context tests --

    #[test]
    fn test_from_event_context() {
        let target = make_event("evt-target", "web-srv", "2024-01-15T14:25:00Z");
        let surrounding = vec![
            make_event("evt-1", "web-srv", "2024-01-15T14:24:00Z"),
            make_event("evt-2", "other-srv", "2024-01-15T14:26:00Z"),
        ];

        let timeline = TimelineBuilder::from_event_context(
            "evt-target",
            &target,
            &surrounding,
        );

        assert_eq!(timeline.investigation_id, "evt-evt-target");
        assert_eq!(timeline.entries.len(), 3); // target + 2 surrounding
        assert!(!timeline.narrative_summary.is_empty());
    }

    #[test]
    fn test_from_event_context_deduplicates_target() {
        let target = make_event("evt-1", "srv", "2024-01-15T14:25:00Z");
        let surrounding = vec![
            make_event("evt-1", "srv", "2024-01-15T14:25:00Z"),
            make_event("evt-2", "srv", "2024-01-15T14:26:00Z"),
        ];

        let timeline = TimelineBuilder::from_event_context("evt-1", &target, &surrounding);
        // Should not duplicate evt-1
        assert_eq!(timeline.entries.len(), 2);
    }

    // -- Investigator notes insertion test --

    #[test]
    fn test_insert_investigator_notes() {
        let now = Utc::now();
        let later = now + chrono::Duration::seconds(30);
        let mut entries = vec![
            TimelineEntry {
                id: "e1".to_string(),
                timestamp: now,
                entry_type: TimelineEntryType::McpToolCall,
                server: "srv".to_string(),
                description: "Original".to_string(),
                severity: "info".to_string(),
                event_id: None,
                is_key_moment: false,
                connects_to: None,
                stage: None,
            },
        ];

        let notes = vec![
            (later, "This is suspicious.".to_string()),
        ];

        TimelineBuilder::insert_investigator_notes(&mut entries, &notes);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].entry_type, TimelineEntryType::InvestigatorNote);
        assert_eq!(entries[1].description, "This is suspicious.");
        // Should be sorted: original first, then note
        assert!(entries[0].timestamp <= entries[1].timestamp);
    }

    // -- Helper function tests --

    #[test]
    fn test_parse_tag_attr_value_quoted() {
        let attrs = r#"time="2024-01-15T14:23:00Z" server="file-manager" type="FileAccess""#;
        assert_eq!(
            parse_tag_attr_value(attrs, "time"),
            Some("2024-01-15T14:23:00Z".to_string())
        );
        assert_eq!(
            parse_tag_attr_value(attrs, "server"),
            Some("file-manager".to_string())
        );
        assert_eq!(
            parse_tag_attr_value(attrs, "type"),
            Some("FileAccess".to_string())
        );
        assert_eq!(parse_tag_attr_value(attrs, "missing"), None);
    }

    #[test]
    fn test_parse_tag_attr_value_unquoted() {
        let attrs = "time=2024-01-15T14:23:00Z server=srv type=FileAccess";
        assert_eq!(
            parse_tag_attr_value(attrs, "server"),
            Some("srv".to_string())
        );
    }

    #[test]
    fn test_strip_timeline_tags() {
        let text = r#"Some text.
[TIMELINE_ENTRY time="2024-01-15T14:23:00Z" server="srv"]
Event description
[/TIMELINE_ENTRY]
More text."#;
        let stripped = strip_timeline_tags(text);
        assert!(stripped.contains("Some text."));
        assert!(stripped.contains("More text."));
        assert!(!stripped.contains("[TIMELINE_ENTRY"));
        assert!(!stripped.contains("Event description"));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(chrono::Duration::seconds(30)), "30 second(s)");
        assert_eq!(format_duration(chrono::Duration::seconds(120)), "2 minute(s)");
        assert_eq!(format_duration(chrono::Duration::seconds(7200)), "2 hour(s)");
        assert_eq!(format_duration(chrono::Duration::seconds(172800)), "2 day(s)");
    }

    #[test]
    fn test_build_event_description() {
        let event = json!({
            "action": "tools/call",
            "tool_name": "read_file",
            "decision": "allow",
            "resource": "/etc/passwd",
        });
        let desc = build_event_description(&event);
        assert!(desc.contains("tools/call"));
        assert!(desc.contains("read_file"));
        assert!(desc.contains("allow"));
        assert!(desc.contains("/etc/passwd"));
    }

    #[test]
    fn test_build_event_description_empty() {
        let event = json!({});
        let desc = build_event_description(&event);
        assert_eq!(desc, "Event recorded");
    }

    // -- Serde roundtrip tests --

    #[test]
    fn test_timeline_serde_roundtrip() {
        let now = Utc::now();
        let timeline = InvestigationTimeline {
            investigation_id: "inv-test".to_string(),
            entries: vec![
                TimelineEntry {
                    id: "e1".to_string(),
                    timestamp: now,
                    entry_type: TimelineEntryType::McpToolCall,
                    server: "srv".to_string(),
                    description: "Test".to_string(),
                    severity: "info".to_string(),
                    event_id: Some("evt-1".to_string()),
                    is_key_moment: true,
                    connects_to: None,
                    stage: Some("recon".to_string()),
                },
            ],
            servers_involved: vec!["srv".to_string()],
            time_span: TimeSpan { start: now, end: now },
            narrative_summary: "Test narrative".to_string(),
        };

        let json = serde_json::to_string(&timeline).unwrap();
        let parsed: InvestigationTimeline = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.investigation_id, "inv-test");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].entry_type, TimelineEntryType::McpToolCall);
        assert_eq!(parsed.entries[0].is_key_moment, true);
    }

    #[test]
    fn test_story_comparison_serde() {
        let comp = StoryComparison {
            current_investigation_id: "inv-1".to_string(),
            related_investigation_id: "inv-2".to_string(),
            similarity_score: 0.75,
            common_servers: vec!["srv-a".to_string()],
            common_patterns: vec!["terminal -> file".to_string()],
            differences: vec!["Different event counts".to_string()],
            comparison_narrative: "75% similar".to_string(),
        };

        let json = serde_json::to_string(&comp).unwrap();
        let parsed: StoryComparison = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.similarity_score, 0.75);
        assert_eq!(parsed.common_servers.len(), 1);
    }

    #[test]
    fn test_entry_type_serde() {
        let types = vec![
            TimelineEntryType::McpToolCall,
            TimelineEntryType::FileAccess,
            TimelineEntryType::NetworkConnection,
            TimelineEntryType::ProcessExecution,
            TimelineEntryType::PolicyDecision,
            TimelineEntryType::UserAction,
            TimelineEntryType::AiAssessment,
            TimelineEntryType::InvestigatorNote,
        ];
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let parsed: TimelineEntryType = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, t);
        }
    }
}
