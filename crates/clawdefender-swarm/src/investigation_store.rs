//! Investigation persistence, search, and retrieval system.
//!
//! Stores investigation results as JSON files with a lightweight index for
//! fast listing and filtering. Supports full-text search, expiry, pinning,
//! and export to markdown.

use std::path::PathBuf;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core result types
// ---------------------------------------------------------------------------

/// Verdict of an investigation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict {
    FalsePositive,
    Benign,
    Suspicious,
    ConfirmedThreat,
}

/// Assessment of an incident's impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    pub data_accessed: Vec<String>,
    pub data_modified: Vec<String>,
    pub data_exfiltrated: bool,
    pub blast_radius: String,
    pub severity: String,
}

/// Complete result of a finished investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationResult {
    pub investigation_id: String,
    pub target_type: String,
    pub target_id: String,
    pub target_summary: String,

    // The 5 answers
    pub what_happened: String,
    pub why_it_happened: String,
    pub part_of_larger: Option<String>,
    pub impact: ImpactAssessment,
    pub recommendations: Vec<String>,

    // Supporting data
    pub related_events: Vec<String>,
    pub evidence_ids: Vec<String>,

    // Verdict
    pub verdict: Verdict,
    pub confidence: f64,
    pub narrative: String,

    // Metadata
    pub depth: String,
    pub total_tool_calls: usize,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub estimated_cost_usd: f64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub pinned: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Index types
// ---------------------------------------------------------------------------

/// Lightweight index entry for fast listing without loading full results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationIndexEntry {
    pub id: String,
    pub target_type: String,
    pub target_id: String,
    pub target_summary: String,
    pub verdict: Verdict,
    pub confidence: f64,
    pub severity: String,
    pub servers_involved: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub narrative_preview: String,
    pub pinned: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

/// In-memory index of all investigations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationIndex {
    pub entries: Vec<InvestigationIndexEntry>,
    pub last_updated: DateTime<Utc>,
    pub total_size_bytes: u64,
}

// ---------------------------------------------------------------------------
// Search types
// ---------------------------------------------------------------------------

/// Query for filtering and searching investigations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvestigationSearchQuery {
    pub text: Option<String>,
    pub server: Option<String>,
    pub verdict: Option<String>,
    pub severity: Option<String>,
    pub date_start: Option<DateTime<Utc>>,
    pub date_end: Option<DateTime<Utc>>,
    pub has_remediation: Option<bool>,
    pub pinned_only: Option<bool>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Compact summary for injecting into Claude's context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationSummary {
    pub id: String,
    pub date: DateTime<Utc>,
    pub target: String,
    pub verdict: String,
    pub severity: String,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// InvestigationStore
// ---------------------------------------------------------------------------

/// Storage warning threshold in bytes (100 MB).
const STORAGE_WARNING_BYTES: u64 = 100 * 1024 * 1024;

/// Default expiry for unpinned investigations (90 days).
#[allow(dead_code)]
const DEFAULT_EXPIRY_DAYS: i64 = 90;

/// Manages on-disk persistence and in-memory index of investigation results.
pub struct InvestigationStore {
    base_dir: PathBuf,
    index: InvestigationIndex,
}

impl InvestigationStore {
    /// Create a new store, loading or creating the index.
    pub fn new() -> Result<Self> {
        let base_dir = investigations_directory();
        std::fs::create_dir_all(&base_dir)?;

        let index = load_or_create_index(&base_dir)?;
        Ok(Self { base_dir, index })
    }

    /// Create a store with a custom base directory (for testing).
    pub fn with_dir(base_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&base_dir)?;
        let index = load_or_create_index(&base_dir)?;
        Ok(Self { base_dir, index })
    }

    /// Save an investigation result to disk and update the index.
    pub fn save(&mut self, result: &InvestigationResult) -> Result<()> {
        let path = self
            .base_dir
            .join(format!("{}.json", result.investigation_id));
        let data = serde_json::to_string_pretty(result)?;
        let size = data.len() as u64;
        std::fs::write(&path, &data)?;

        // Update or insert index entry
        let entry = build_index_entry(result);
        if let Some(existing) = self
            .index
            .entries
            .iter_mut()
            .find(|e| e.id == result.investigation_id)
        {
            *existing = entry;
        } else {
            self.index.entries.push(entry);
        }
        self.index.last_updated = Utc::now();
        self.index.total_size_bytes += size;

        self.save_index()?;
        Ok(())
    }

    /// Load a full investigation result from disk.
    pub fn load(&self, id: &str) -> Result<InvestigationResult> {
        let path = self.base_dir.join(format!("{}.json", id));
        let data = std::fs::read_to_string(&path)
            .map_err(|_| anyhow::anyhow!("Investigation not found: {}", id))?;
        let result: InvestigationResult = serde_json::from_str(&data)?;
        Ok(result)
    }

    /// List investigations from the index, optionally filtered.
    pub fn list(&self, filter: Option<&InvestigationSearchQuery>) -> Vec<InvestigationIndexEntry> {
        let mut results: Vec<InvestigationIndexEntry> = self
            .index
            .entries
            .iter()
            .filter(|e| match_index_entry(e, filter))
            .cloned()
            .collect();

        // Sort by started_at descending (newest first)
        results.sort_by(|a, b| b.started_at.cmp(&a.started_at));

        // Apply offset and limit
        if let Some(query) = filter {
            let offset = query.offset.unwrap_or(0);
            let limit = query.limit.unwrap_or(usize::MAX);
            results = results.into_iter().skip(offset).take(limit).collect();
        }

        results
    }

    /// Search investigations with full-text matching across narratives and answers.
    pub fn search(&self, query: &InvestigationSearchQuery) -> Result<Vec<InvestigationIndexEntry>> {
        let search_text = match &query.text {
            Some(t) if !t.is_empty() => t.to_lowercase(),
            _ => return Ok(self.list(Some(query))),
        };

        // First filter by index-level fields
        let candidates: Vec<&InvestigationIndexEntry> = self
            .index
            .entries
            .iter()
            .filter(|e| match_index_entry(e, Some(query)))
            .collect();

        // For each candidate, load the full result and search
        let mut matches = Vec::new();
        for entry in candidates {
            if let Ok(result) = self.load(&entry.id) {
                if text_matches_investigation(&result, &search_text) {
                    matches.push(entry.clone());
                }
            }
        }

        matches.sort_by(|a, b| b.started_at.cmp(&a.started_at));

        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(usize::MAX);
        Ok(matches.into_iter().skip(offset).take(limit).collect())
    }

    /// Find investigations related to a server or target.
    pub fn find_related(
        &self,
        server: Option<&str>,
        target_id: Option<&str>,
    ) -> Vec<InvestigationIndexEntry> {
        self.index
            .entries
            .iter()
            .filter(|e| {
                if let Some(srv) = server {
                    if e.servers_involved
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(srv))
                    {
                        return true;
                    }
                }
                if let Some(tid) = target_id {
                    if e.target_id == tid {
                        return true;
                    }
                }
                false
            })
            .cloned()
            .collect()
    }

    /// Pin or unpin an investigation.
    pub fn pin(&mut self, id: &str, pinned: bool) -> Result<()> {
        // Update in-memory index
        if let Some(entry) = self.index.entries.iter_mut().find(|e| e.id == id) {
            entry.pinned = pinned;
            if pinned {
                entry.expires_at = None;
            }
        } else {
            anyhow::bail!("Investigation not found: {}", id);
        }

        // Update the on-disk investigation file
        let mut result = self.load(id)?;
        result.pinned = pinned;
        if pinned {
            result.expires_at = None;
        }
        let path = self.base_dir.join(format!("{}.json", id));
        let data = serde_json::to_string_pretty(&result)?;
        std::fs::write(path, data)?;

        self.save_index()?;
        Ok(())
    }

    /// Delete an investigation from disk and the index.
    pub fn delete(&mut self, id: &str) -> Result<()> {
        let path = self.base_dir.join(format!("{}.json", id));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        self.index.entries.retain(|e| e.id != id);
        self.index.last_updated = Utc::now();
        self.save_index()?;
        Ok(())
    }

    /// Remove expired, unpinned investigations. Returns IDs of removed items.
    pub fn expire_old(&mut self) -> Result<Vec<String>> {
        let now = Utc::now();
        let mut expired_ids = Vec::new();

        for entry in &self.index.entries {
            if entry.pinned {
                continue;
            }
            if let Some(expires) = entry.expires_at {
                if now > expires {
                    expired_ids.push(entry.id.clone());
                }
            }
        }

        for id in &expired_ids {
            let path = self.base_dir.join(format!("{}.json", id));
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
        }

        self.index.entries.retain(|e| !expired_ids.contains(&e.id));
        if !expired_ids.is_empty() {
            self.index.last_updated = Utc::now();
            self.save_index()?;
        }

        Ok(expired_ids)
    }

    /// Compute total storage size of investigation files on disk.
    pub fn storage_size(&self) -> Result<u64> {
        let mut total = 0u64;
        if self.base_dir.exists() {
            for entry in std::fs::read_dir(&self.base_dir)? {
                let entry = entry?;
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
            }
        }
        Ok(total)
    }

    /// Check if storage exceeds the warning threshold (100 MB).
    pub fn storage_warning(&self) -> bool {
        self.storage_size().unwrap_or(0) > STORAGE_WARNING_BYTES
    }

    /// Export an investigation in the given format ("json" or "markdown").
    pub fn export(&self, id: &str, format: &str) -> Result<String> {
        let result = self.load(id)?;
        match format {
            "json" => Ok(serde_json::to_string_pretty(&result)?),
            "markdown" | _ => Ok(render_investigation_markdown(&result)),
        }
    }

    /// Get compact summaries of investigations for a specific server,
    /// suitable for injecting into Claude's context.
    pub fn get_summaries_for_server(&self, server: &str) -> Vec<InvestigationSummary> {
        self.index
            .entries
            .iter()
            .filter(|e| {
                e.servers_involved
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(server))
            })
            .map(|e| InvestigationSummary {
                id: e.id.clone(),
                date: e.started_at,
                target: e.target_summary.clone(),
                verdict: format!("{:?}", e.verdict),
                severity: e.severity.clone(),
                summary: e.narrative_preview.clone(),
            })
            .collect()
    }

    // -- Internal -----------------------------------------------------------

    fn save_index(&self) -> Result<()> {
        let path = self.base_dir.join("_index.json");
        let data = serde_json::to_string_pretty(&self.index)?;
        std::fs::write(path, data)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InvestigationParser — extract structured data from Claude's output
// ---------------------------------------------------------------------------

/// Parses structured investigation data from Claude's free-text output.
pub struct InvestigationParser;

/// Extracted answers from Claude's investigation narrative.
#[derive(Debug, Clone, Default)]
pub struct InvestigationAnswers {
    pub what_happened: String,
    pub why_it_happened: String,
    pub part_of_larger: Option<String>,
    pub impact_description: String,
    pub recommendations: Vec<String>,
}

impl InvestigationParser {
    /// Extract verdict from `[VERDICT type="..." confidence=0.85]...[/VERDICT]`.
    pub fn extract_verdict(text: &str) -> Option<(Verdict, f64)> {
        let start = text.find("[VERDICT ")?;
        let after = &text[start..];
        let tag_end = after.find(']')?;
        let tag = &after[..tag_end];

        let verdict_type =
            parse_tag_quoted_attr(tag, "type").or_else(|| parse_tag_attr_simple(tag, "type"))?;
        let confidence_str = parse_tag_attr_simple(tag, "confidence").unwrap_or_default();
        let confidence: f64 = confidence_str.parse().unwrap_or(0.5);

        let verdict = match verdict_type.to_lowercase().as_str() {
            "falsepositive" | "false_positive" | "false positive" => Verdict::FalsePositive,
            "benign" => Verdict::Benign,
            "suspicious" => Verdict::Suspicious,
            "confirmedthreat" | "confirmed_threat" | "confirmed threat" => Verdict::ConfirmedThreat,
            _ => return None,
        };

        Some((verdict, confidence))
    }

    /// Extract impact assessment from `[IMPACT]...[/IMPACT]` tags.
    pub fn extract_impact(text: &str) -> Option<ImpactAssessment> {
        let start = text.find("[IMPACT]")?;
        let after = &text[start + 8..];
        let end = after.find("[/IMPACT]")?;
        let body = after[..end].trim();

        let data_accessed = parse_list_field(body, "data_accessed");
        let data_modified = parse_list_field(body, "data_modified");
        let data_exfiltrated = parse_body_field(body, "data_exfiltrated")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "yes")
            .unwrap_or(false);
        let blast_radius =
            parse_body_field(body, "blast_radius").unwrap_or_else(|| "unknown".to_string());
        let severity = parse_body_field(body, "severity").unwrap_or_else(|| "unknown".to_string());

        Some(ImpactAssessment {
            data_accessed,
            data_modified,
            data_exfiltrated,
            blast_radius,
            severity,
        })
    }

    /// Extract the 5 investigation answers from Claude's narrative.
    pub fn extract_answers(text: &str) -> InvestigationAnswers {
        let mut answers = InvestigationAnswers::default();

        // Try section headers first
        let sections = [
            ("WHAT HAPPENED:", "what_happened"),
            ("WHY:", "why"),
            ("PART OF SOMETHING LARGER:", "part_of_larger"),
            ("IMPACT:", "impact"),
            ("RECOMMENDATIONS:", "recommendations"),
        ];

        let text_upper = text.to_uppercase();
        let mut section_positions: Vec<(usize, &str)> = Vec::new();

        for (header, key) in &sections {
            if let Some(pos) = text_upper.find(header) {
                section_positions.push((pos, key));
            }
        }

        section_positions.sort_by_key(|(pos, _)| *pos);

        for (i, (pos, key)) in section_positions.iter().enumerate() {
            let header_len = sections
                .iter()
                .find(|(_, k)| k == key)
                .map(|(h, _)| h.len())
                .unwrap_or(0);
            let start = pos + header_len;
            let end = if i + 1 < section_positions.len() {
                section_positions[i + 1].0
            } else {
                text.len()
            };

            let content = text[start..end].trim().to_string();

            match *key {
                "what_happened" => answers.what_happened = content,
                "why" => answers.why_it_happened = content,
                "part_of_larger" => {
                    if !content.is_empty()
                        && !content.to_lowercase().starts_with("no")
                        && !content.to_lowercase().starts_with("n/a")
                    {
                        answers.part_of_larger = Some(content);
                    }
                }
                "impact" => answers.impact_description = content,
                "recommendations" => {
                    answers.recommendations = Self::extract_recommendations_from_text(&content);
                }
                _ => {}
            }
        }

        answers
    }

    /// Extract recommendations as a list of strings from text.
    pub fn extract_recommendations(text: &str) -> Vec<String> {
        Self::extract_recommendations_from_text(text)
    }

    fn extract_recommendations_from_text(text: &str) -> Vec<String> {
        text.lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .filter(|line| {
                line.starts_with('-')
                    || line.starts_with('*')
                    || line.starts_with("1.")
                    || line.starts_with("2.")
                    || line.starts_with("3.")
                    || line.starts_with("4.")
                    || line.starts_with("5.")
                    || line.starts_with("6.")
                    || line.starts_with("7.")
                    || line.starts_with("8.")
                    || line.starts_with("9.")
            })
            .map(|line| {
                line.trim_start_matches(|c: char| {
                    c == '-' || c == '*' || c == '.' || c.is_ascii_digit()
                })
                .trim()
                .to_string()
            })
            .filter(|s| !s.is_empty())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Get the investigations storage directory.
fn investigations_directory() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".local/share")
    });
    base.join("clawdefender").join("investigations")
}

/// Load existing index from disk or create a fresh one.
fn load_or_create_index(base_dir: &PathBuf) -> Result<InvestigationIndex> {
    let path = base_dir.join("_index.json");
    if path.exists() {
        let data = std::fs::read_to_string(&path)?;
        let index: InvestigationIndex = serde_json::from_str(&data)?;
        Ok(index)
    } else {
        Ok(InvestigationIndex {
            entries: Vec::new(),
            last_updated: Utc::now(),
            total_size_bytes: 0,
        })
    }
}

/// Build an index entry from a full investigation result.
fn build_index_entry(result: &InvestigationResult) -> InvestigationIndexEntry {
    let narrative_preview = if result.narrative.len() > 200 {
        format!("{}...", &result.narrative[..200])
    } else {
        result.narrative.clone()
    };

    InvestigationIndexEntry {
        id: result.investigation_id.clone(),
        target_type: result.target_type.clone(),
        target_id: result.target_id.clone(),
        target_summary: result.target_summary.clone(),
        verdict: result.verdict.clone(),
        confidence: result.confidence,
        severity: result.impact.severity.clone(),
        servers_involved: Vec::new(), // Populated by caller if needed
        started_at: result.started_at,
        completed_at: result.completed_at,
        narrative_preview,
        pinned: result.pinned,
        expires_at: result.expires_at,
    }
}

/// Check if an index entry matches a search query (index-level fields only).
fn match_index_entry(
    entry: &InvestigationIndexEntry,
    filter: Option<&InvestigationSearchQuery>,
) -> bool {
    let query = match filter {
        Some(q) => q,
        None => return true,
    };

    if let Some(ref verdict) = query.verdict {
        let entry_verdict = format!("{:?}", entry.verdict).to_lowercase();
        if entry_verdict != verdict.to_lowercase() {
            return false;
        }
    }

    if let Some(ref severity) = query.severity {
        if !entry.severity.eq_ignore_ascii_case(severity) {
            return false;
        }
    }

    if let Some(ref server) = query.server {
        if !entry
            .servers_involved
            .iter()
            .any(|s| s.eq_ignore_ascii_case(server))
        {
            return false;
        }
    }

    if let Some(start) = query.date_start {
        if entry.started_at < start {
            return false;
        }
    }

    if let Some(end) = query.date_end {
        if entry.started_at > end {
            return false;
        }
    }

    if let Some(true) = query.pinned_only {
        if !entry.pinned {
            return false;
        }
    }

    true
}

/// Check if full-text search matches any searchable field of an investigation.
fn text_matches_investigation(result: &InvestigationResult, search: &str) -> bool {
    result.narrative.to_lowercase().contains(search)
        || result.what_happened.to_lowercase().contains(search)
        || result.why_it_happened.to_lowercase().contains(search)
        || result.target_summary.to_lowercase().contains(search)
        || result
            .recommendations
            .iter()
            .any(|r| r.to_lowercase().contains(search))
        || result
            .part_of_larger
            .as_ref()
            .map(|p| p.to_lowercase().contains(search))
            .unwrap_or(false)
}

/// Parse a `key=value` attribute from a tag (unquoted value).
fn parse_tag_attr_simple(tag: &str, key: &str) -> Option<String> {
    let search = format!("{key}=");
    let idx = tag.find(&search)?;
    let after = &tag[idx + search.len()..];
    // Skip leading quote if present
    let after = after.strip_prefix('"').unwrap_or(after);
    let value = after
        .split(|c: char| c.is_whitespace() || c == ']' || c == '"')
        .next()
        .unwrap_or("")
        .to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Parse a `key="value"` attribute from a tag (quoted value).
fn parse_tag_quoted_attr(tag: &str, key: &str) -> Option<String> {
    let search = format!("{key}=\"");
    let idx = tag.find(&search)?;
    let after = &tag[idx + search.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

/// Extract a `key: value` field from body text.
fn parse_body_field(body: &str, key: &str) -> Option<String> {
    let prefix_eq = format!("{}=", key);
    let prefix_colon = format!("{}:", key);
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix_eq) {
            let value = rest.trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        if let Some(rest) = trimmed.strip_prefix(&prefix_colon) {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Parse a comma-separated list field from body text.
fn parse_list_field(body: &str, key: &str) -> Vec<String> {
    parse_body_field(body, key)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Render an investigation result as markdown.
fn render_investigation_markdown(result: &InvestigationResult) -> String {
    let mut md = String::new();

    md.push_str("# CLAWDEFENDER INVESTIGATION REPORT\n\n");
    md.push_str(&format!(
        "**Investigation ID:** {}  \n",
        result.investigation_id
    ));
    md.push_str(&format!(
        "**Date:** {}  \n",
        result.started_at.format("%B %d, %Y %H:%M UTC")
    ));
    md.push_str(&format!(
        "**Target:** {} ({})  \n",
        result.target_summary, result.target_type
    ));
    md.push_str(&format!(
        "**Verdict:** {:?} (confidence: {:.0}%)  \n",
        result.verdict,
        result.confidence * 100.0
    ));
    md.push_str(&format!("**Depth:** {}  \n", result.depth));
    md.push_str(&format!(
        "**Cost:** ${:.4} ({} tool calls)\n\n",
        result.estimated_cost_usd, result.total_tool_calls
    ));
    md.push_str("---\n\n");

    md.push_str("## What Happened\n\n");
    md.push_str(&result.what_happened);
    md.push_str("\n\n");

    md.push_str("## Why It Happened\n\n");
    md.push_str(&result.why_it_happened);
    md.push_str("\n\n");

    if let Some(ref larger) = result.part_of_larger {
        md.push_str("## Part of Something Larger?\n\n");
        md.push_str(larger);
        md.push_str("\n\n");
    }

    md.push_str("## Impact Assessment\n\n");
    md.push_str(&format!("**Severity:** {}  \n", result.impact.severity));
    md.push_str(&format!(
        "**Blast Radius:** {}  \n",
        result.impact.blast_radius
    ));
    md.push_str(&format!(
        "**Data Exfiltrated:** {}  \n",
        if result.impact.data_exfiltrated {
            "Yes"
        } else {
            "No"
        }
    ));
    if !result.impact.data_accessed.is_empty() {
        md.push_str(&format!(
            "**Data Accessed:** {}  \n",
            result.impact.data_accessed.join(", ")
        ));
    }
    if !result.impact.data_modified.is_empty() {
        md.push_str(&format!(
            "**Data Modified:** {}  \n",
            result.impact.data_modified.join(", ")
        ));
    }
    md.push('\n');

    if !result.recommendations.is_empty() {
        md.push_str("## Recommendations\n\n");
        for rec in &result.recommendations {
            md.push_str(&format!("- {}\n", rec));
        }
        md.push('\n');
    }

    md.push_str("## Narrative\n\n");
    md.push_str(&result.narrative);
    md.push_str("\n\n");

    md.push_str("---\n\n");
    md.push_str("*Generated by RookBot Investigation Engine*\n");

    md
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_test_result(id: &str) -> InvestigationResult {
        InvestigationResult {
            investigation_id: id.to_string(),
            target_type: "event".to_string(),
            target_id: "evt-001".to_string(),
            target_summary: "Suspicious file access on web-server".to_string(),
            what_happened: "The MCP server accessed /etc/passwd unexpectedly.".to_string(),
            why_it_happened: "A prompt injection in the user query caused the tool call."
                .to_string(),
            part_of_larger: Some("Part of a reconnaissance pattern.".to_string()),
            impact: ImpactAssessment {
                data_accessed: vec!["/etc/passwd".to_string()],
                data_modified: vec![],
                data_exfiltrated: false,
                blast_radius: "single server".to_string(),
                severity: "high".to_string(),
            },
            recommendations: vec![
                "Block access to /etc/passwd".to_string(),
                "Enable file access monitoring".to_string(),
            ],
            related_events: vec!["evt-001".to_string(), "evt-002".to_string()],
            evidence_ids: vec!["ev-1".to_string()],
            verdict: Verdict::Suspicious,
            confidence: 0.85,
            narrative: "Investigation revealed a prompt injection attack targeting sensitive system files. The attacker used a crafted prompt to bypass safety measures.".to_string(),
            depth: "standard".to_string(),
            total_tool_calls: 12,
            total_input_tokens: 50000,
            total_output_tokens: 20000,
            estimated_cost_usd: 0.45,
            started_at: Utc::now() - Duration::hours(1),
            completed_at: Some(Utc::now()),
            pinned: false,
            expires_at: Some(Utc::now() + Duration::days(DEFAULT_EXPIRY_DAYS)),
        }
    }

    #[allow(dead_code)]
    fn make_test_result_with_server(id: &str, server: &str) -> InvestigationResult {
        let mut result = make_test_result(id);
        result.target_summary = format!("Activity on {}", server);
        result
    }

    // -- Save and load round-trip --

    #[test]
    fn test_save_and_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        let result = make_test_result("inv-001");
        store.save(&result).unwrap();

        let loaded = store.load("inv-001").unwrap();
        assert_eq!(loaded.investigation_id, "inv-001");
        assert_eq!(loaded.target_type, "event");
        assert_eq!(loaded.what_happened, result.what_happened);
        assert_eq!(loaded.verdict, Verdict::Suspicious);
        assert!((loaded.confidence - 0.85).abs() < 0.001);
        assert_eq!(loaded.recommendations.len(), 2);
    }

    // -- Index creation and update --

    #[test]
    fn test_index_creation_and_update() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        assert_eq!(store.index.entries.len(), 0);

        let r1 = make_test_result("inv-001");
        store.save(&r1).unwrap();
        assert_eq!(store.index.entries.len(), 1);
        assert_eq!(store.index.entries[0].id, "inv-001");

        let r2 = make_test_result("inv-002");
        store.save(&r2).unwrap();
        assert_eq!(store.index.entries.len(), 2);

        // Update existing
        let mut r1_updated = r1.clone();
        r1_updated.verdict = Verdict::ConfirmedThreat;
        store.save(&r1_updated).unwrap();
        assert_eq!(store.index.entries.len(), 2); // No duplicate
        let entry = store
            .index
            .entries
            .iter()
            .find(|e| e.id == "inv-001")
            .unwrap();
        assert_eq!(entry.verdict, Verdict::ConfirmedThreat);
    }

    // -- Index persistence across store instances --

    #[test]
    fn test_index_persistence() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();

        {
            let mut store = InvestigationStore::with_dir(base.clone()).unwrap();
            store.save(&make_test_result("inv-001")).unwrap();
            store.save(&make_test_result("inv-002")).unwrap();
        }

        // Reload from disk
        let store2 = InvestigationStore::with_dir(base).unwrap();
        assert_eq!(store2.index.entries.len(), 2);
    }

    // -- Search tests --

    #[test]
    fn test_search_by_text() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        let mut r1 = make_test_result("inv-001");
        r1.narrative = "This was a prompt injection attack.".to_string();
        store.save(&r1).unwrap();

        let mut r2 = make_test_result("inv-002");
        r2.narrative = "Normal server operation, no issues.".to_string();
        r2.what_happened = "Nothing unusual happened.".to_string();
        r2.why_it_happened = "Routine check.".to_string();
        r2.part_of_larger = None;
        r2.recommendations = vec!["No action needed.".to_string()];
        store.save(&r2).unwrap();

        let query = InvestigationSearchQuery {
            text: Some("prompt injection".to_string()),
            ..Default::default()
        };
        let results = store.search(&query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "inv-001");
    }

    #[test]
    fn test_search_by_verdict() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        let mut r1 = make_test_result("inv-001");
        r1.verdict = Verdict::Suspicious;
        store.save(&r1).unwrap();

        let mut r2 = make_test_result("inv-002");
        r2.verdict = Verdict::Benign;
        store.save(&r2).unwrap();

        let query = InvestigationSearchQuery {
            verdict: Some("Suspicious".to_string()),
            ..Default::default()
        };
        let results = store.list(Some(&query));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "inv-001");
    }

    #[test]
    fn test_search_by_severity() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        store.save(&make_test_result("inv-001")).unwrap(); // severity = "high"

        let mut r2 = make_test_result("inv-002");
        r2.impact.severity = "low".to_string();
        store.save(&r2).unwrap();

        let query = InvestigationSearchQuery {
            severity: Some("high".to_string()),
            ..Default::default()
        };
        let results = store.list(Some(&query));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "inv-001");
    }

    #[test]
    fn test_search_by_date_range() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        let mut r1 = make_test_result("inv-old");
        r1.started_at = Utc::now() - Duration::days(30);
        store.save(&r1).unwrap();

        let mut r2 = make_test_result("inv-new");
        r2.started_at = Utc::now() - Duration::hours(1);
        store.save(&r2).unwrap();

        let query = InvestigationSearchQuery {
            date_start: Some(Utc::now() - Duration::days(1)),
            ..Default::default()
        };
        let results = store.list(Some(&query));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "inv-new");
    }

    // -- Find related --

    #[test]
    fn test_find_related_by_server() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        let r1 = make_test_result("inv-001");
        store.save(&r1).unwrap();
        // Manually set servers_involved in index
        store.index.entries[0].servers_involved = vec!["web-server".to_string()];

        let r2 = make_test_result("inv-002");
        store.save(&r2).unwrap();
        store.index.entries[1].servers_involved = vec!["db-server".to_string()];

        let related = store.find_related(Some("web-server"), None);
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].id, "inv-001");
    }

    #[test]
    fn test_find_related_by_target_id() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        store.save(&make_test_result("inv-001")).unwrap();

        let mut r2 = make_test_result("inv-002");
        r2.target_id = "evt-999".to_string();
        store.save(&r2).unwrap();

        let related = store.find_related(None, Some("evt-001"));
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].id, "inv-001");
    }

    // -- Pin/unpin --

    #[test]
    fn test_pin_unpin() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        store.save(&make_test_result("inv-001")).unwrap();
        assert!(!store.index.entries[0].pinned);

        store.pin("inv-001", true).unwrap();
        assert!(store.index.entries[0].pinned);
        assert!(store.index.entries[0].expires_at.is_none());

        // Verify persisted on disk
        let loaded = store.load("inv-001").unwrap();
        assert!(loaded.pinned);
        assert!(loaded.expires_at.is_none());

        store.pin("inv-001", false).unwrap();
        assert!(!store.index.entries[0].pinned);
    }

    #[test]
    fn test_pin_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        let result = store.pin("nonexistent", true);
        assert!(result.is_err());
    }

    // -- Delete --

    #[test]
    fn test_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        store.save(&make_test_result("inv-001")).unwrap();
        store.save(&make_test_result("inv-002")).unwrap();
        assert_eq!(store.index.entries.len(), 2);

        store.delete("inv-001").unwrap();
        assert_eq!(store.index.entries.len(), 1);
        assert_eq!(store.index.entries[0].id, "inv-002");

        // Loading should fail
        assert!(store.load("inv-001").is_err());
    }

    // -- Expiry --

    #[test]
    fn test_expire_old() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        // Expired investigation
        let mut r1 = make_test_result("inv-expired");
        r1.expires_at = Some(Utc::now() - Duration::days(1));
        store.save(&r1).unwrap();

        // Non-expired investigation
        let mut r2 = make_test_result("inv-fresh");
        r2.expires_at = Some(Utc::now() + Duration::days(30));
        store.save(&r2).unwrap();

        // Pinned but with past expiry — should NOT be expired
        let mut r3 = make_test_result("inv-pinned");
        r3.pinned = true;
        r3.expires_at = Some(Utc::now() - Duration::days(1));
        store.save(&r3).unwrap();

        let expired = store.expire_old().unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "inv-expired");
        assert_eq!(store.index.entries.len(), 2);
    }

    // -- Storage size --

    #[test]
    fn test_storage_size() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        store.save(&make_test_result("inv-001")).unwrap();

        let size = store.storage_size().unwrap();
        assert!(size > 0);
    }

    #[test]
    fn test_storage_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();
        // Fresh store should not trigger warning
        assert!(!store.storage_warning());
    }

    // -- Verdict parsing --

    #[test]
    fn test_extract_verdict_suspicious() {
        let text = r#"Based on analysis:
[VERDICT type="Suspicious" confidence=0.85]The server exhibited unusual behavior[/VERDICT]
End of report."#;
        let (verdict, confidence) = InvestigationParser::extract_verdict(text).unwrap();
        assert_eq!(verdict, Verdict::Suspicious);
        assert!((confidence - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_extract_verdict_confirmed_threat() {
        let text = r#"[VERDICT type="ConfirmedThreat" confidence=0.95]Malicious[/VERDICT]"#;
        let (verdict, confidence) = InvestigationParser::extract_verdict(text).unwrap();
        assert_eq!(verdict, Verdict::ConfirmedThreat);
        assert!((confidence - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_extract_verdict_false_positive() {
        let text = r#"[VERDICT type="FalsePositive" confidence=0.90]Not a real threat[/VERDICT]"#;
        let (verdict, _) = InvestigationParser::extract_verdict(text).unwrap();
        assert_eq!(verdict, Verdict::FalsePositive);
    }

    #[test]
    fn test_extract_verdict_benign() {
        let text = r#"[VERDICT type="Benign" confidence=0.75]Normal behavior[/VERDICT]"#;
        let (verdict, _) = InvestigationParser::extract_verdict(text).unwrap();
        assert_eq!(verdict, Verdict::Benign);
    }

    #[test]
    fn test_extract_verdict_missing() {
        let text = "No verdict here.";
        assert!(InvestigationParser::extract_verdict(text).is_none());
    }

    // -- Impact parsing --

    #[test]
    fn test_extract_impact() {
        let text = r#"Some text.
[IMPACT]
data_accessed=/etc/passwd, /etc/shadow
data_modified=/tmp/output.txt
data_exfiltrated=true
blast_radius=single server
severity=critical
[/IMPACT]
More text."#;
        let impact = InvestigationParser::extract_impact(text).unwrap();
        assert_eq!(impact.data_accessed, vec!["/etc/passwd", "/etc/shadow"]);
        assert_eq!(impact.data_modified, vec!["/tmp/output.txt"]);
        assert!(impact.data_exfiltrated);
        assert_eq!(impact.blast_radius, "single server");
        assert_eq!(impact.severity, "critical");
    }

    #[test]
    fn test_extract_impact_missing() {
        let text = "No impact tags here.";
        assert!(InvestigationParser::extract_impact(text).is_none());
    }

    // -- Answer extraction --

    #[test]
    fn test_extract_answers() {
        let text = r#"
WHAT HAPPENED:
The MCP server accessed sensitive files on the host.

WHY:
A prompt injection bypassed the safety filters.

PART OF SOMETHING LARGER:
This appears to be part of a coordinated reconnaissance campaign.

IMPACT:
Sensitive system files were read, potentially exposing user data.

RECOMMENDATIONS:
- Block access to /etc/passwd
- Enable file monitoring
- Review MCP server permissions
"#;
        let answers = InvestigationParser::extract_answers(text);
        assert!(answers.what_happened.contains("accessed sensitive files"));
        assert!(answers.why_it_happened.contains("prompt injection"));
        assert!(answers.part_of_larger.is_some());
        assert!(answers.part_of_larger.unwrap().contains("reconnaissance"));
        assert!(answers.impact_description.contains("system files"));
        assert_eq!(answers.recommendations.len(), 3);
        assert!(answers.recommendations[0].contains("Block access"));
    }

    #[test]
    fn test_extract_answers_no_larger_pattern() {
        let text = r#"
WHAT HAPPENED:
Something happened.

WHY:
Because reasons.

PART OF SOMETHING LARGER:
No, this is an isolated event.

IMPACT:
Minimal impact.

RECOMMENDATIONS:
- Fix it
"#;
        let answers = InvestigationParser::extract_answers(text);
        // "No" at start => None
        assert!(answers.part_of_larger.is_none());
    }

    // -- Recommendations extraction --

    #[test]
    fn test_extract_recommendations() {
        let text = r#"
- Block the IP address
- Update firewall rules
- Monitor for similar patterns
"#;
        let recs = InvestigationParser::extract_recommendations(text);
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0], "Block the IP address");
    }

    #[test]
    fn test_extract_recommendations_numbered() {
        let text = r#"
1. First action
2. Second action
3. Third action
"#;
        let recs = InvestigationParser::extract_recommendations(text);
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0], "First action");
    }

    // -- Export to markdown --

    #[test]
    fn test_export_markdown() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        store.save(&make_test_result("inv-001")).unwrap();

        let md = store.export("inv-001", "markdown").unwrap();
        assert!(md.contains("# CLAWDEFENDER INVESTIGATION REPORT"));
        assert!(md.contains("inv-001"));
        assert!(md.contains("What Happened"));
        assert!(md.contains("Why It Happened"));
        assert!(md.contains("Impact Assessment"));
        assert!(md.contains("Recommendations"));
        assert!(md.contains("Narrative"));
    }

    #[test]
    fn test_export_json() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        store.save(&make_test_result("inv-001")).unwrap();

        let json = store.export("inv-001", "json").unwrap();
        let parsed: InvestigationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.investigation_id, "inv-001");
    }

    // -- Summaries for server --

    #[test]
    fn test_get_summaries_for_server() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        store.save(&make_test_result("inv-001")).unwrap();
        store.index.entries[0].servers_involved = vec!["web-server".to_string()];

        store.save(&make_test_result("inv-002")).unwrap();
        store.index.entries[1].servers_involved = vec!["db-server".to_string()];

        let summaries = store.get_summaries_for_server("web-server");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].id, "inv-001");
    }

    // -- Offset and limit --

    #[test]
    fn test_list_with_offset_and_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        for i in 0..10 {
            let mut r = make_test_result(&format!("inv-{:03}", i));
            r.started_at = Utc::now() - Duration::hours(10 - i as i64);
            store.save(&r).unwrap();
        }

        let query = InvestigationSearchQuery {
            offset: Some(2),
            limit: Some(3),
            ..Default::default()
        };
        let results = store.list(Some(&query));
        assert_eq!(results.len(), 3);
    }

    // -- Pinned-only filter --

    #[test]
    fn test_list_pinned_only() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = InvestigationStore::with_dir(tmp.path().to_path_buf()).unwrap();

        let mut r1 = make_test_result("inv-001");
        r1.pinned = true;
        store.save(&r1).unwrap();

        store.save(&make_test_result("inv-002")).unwrap();

        let query = InvestigationSearchQuery {
            pinned_only: Some(true),
            ..Default::default()
        };
        let results = store.list(Some(&query));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "inv-001");
    }

    // -- Serde roundtrip --

    #[test]
    fn test_investigation_result_serde() {
        let result = make_test_result("inv-001");
        let json = serde_json::to_string(&result).unwrap();
        let parsed: InvestigationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.investigation_id, "inv-001");
        assert_eq!(parsed.verdict, Verdict::Suspicious);
        assert_eq!(parsed.recommendations.len(), 2);
    }

    #[test]
    fn test_verdict_serde() {
        let verdicts = vec![
            Verdict::FalsePositive,
            Verdict::Benign,
            Verdict::Suspicious,
            Verdict::ConfirmedThreat,
        ];
        for v in &verdicts {
            let json = serde_json::to_string(v).unwrap();
            let parsed: Verdict = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, v);
        }
    }

    #[test]
    fn test_index_entry_serde() {
        let result = make_test_result("inv-001");
        let entry = build_index_entry(&result);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: InvestigationIndexEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "inv-001");
        assert_eq!(parsed.verdict, Verdict::Suspicious);
    }
}
