//! Query and aggregation functions for audit log files.
//!
//! Provides standalone functions to query and aggregate audit logs
//! without needing a running `FileAuditLogger` instance.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};

use super::logger::rotated_path;
use super::{AuditRecord, AuditStats};

/// Filter for querying audit log files directly.
pub struct LogFilter {
    /// Only include records after this time.
    pub since: Option<DateTime<Utc>>,
    /// Only include records before this time.
    pub until: Option<DateTime<Utc>>,
    /// Only include records from this server.
    pub server_name: Option<String>,
    /// Only include records with this action (e.g. "blocked", "allowed", "prompted").
    pub action: Option<String>,
    /// Only include records with this JSON-RPC method.
    pub method: Option<String>,
    /// Maximum number of records to return. 0 means no limit.
    pub limit: usize,
}

impl Default for LogFilter {
    fn default() -> Self {
        Self {
            since: None,
            until: None,
            server_name: None,
            action: None,
            method: None,
            limit: 100,
        }
    }
}

/// Query audit log files, returning matching records newest-first.
///
/// Searches the current log file and rotated files (.1, .2, etc.)
/// if the time range may span them.
pub fn query_logs(path: &Path, filter: &LogFilter) -> Result<Vec<AuditRecord>> {
    let mut all_records = Vec::new();

    // Collect all file paths to search: rotated files first (oldest), then current.
    let mut files_to_search = Vec::new();

    // Search rotated files if time range might span them.
    for i in (1..=20).rev() {
        let rotated = rotated_path(path, i);
        if rotated.exists() {
            files_to_search.push(rotated);
        }
    }

    // Current log file.
    if path.exists() {
        files_to_search.push(path.to_path_buf());
    }

    for file_path in &files_to_search {
        read_and_filter(file_path, filter, &mut all_records);
    }

    // Newest first.
    all_records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    if filter.limit > 0 && all_records.len() > filter.limit {
        all_records.truncate(filter.limit);
    }

    Ok(all_records)
}

/// Read records from a file and apply filters, appending matches to `out`.
fn read_and_filter(path: &Path, filter: &LogFilter, out: &mut Vec<AuditRecord>) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let record: AuditRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue, // Skip corrupt lines.
        };

        if let Some(ref since) = filter.since {
            if record.timestamp < *since {
                continue;
            }
        }
        if let Some(ref until) = filter.until {
            if record.timestamp > *until {
                continue;
            }
        }
        if let Some(ref server) = filter.server_name {
            match &record.server_name {
                Some(s) if s == server => {}
                _ => continue,
            }
        }
        if let Some(ref action) = filter.action {
            if record.action_taken != *action {
                // Also check policy_action for "blocked"/"allowed"/"prompted" variants.
                match &record.policy_action {
                    Some(pa) if pa == action => {}
                    _ => continue,
                }
            }
        }
        if let Some(ref method) = filter.method {
            match &record.jsonrpc_method {
                Some(m) if m == method => {}
                _ => continue,
            }
        }

        out.push(record);
    }
}

/// Compute aggregate statistics from audit log files.
///
/// Searches the current log file and all rotated files.
pub fn aggregate_stats(path: &Path, since: Option<DateTime<Utc>>) -> Result<AuditStats> {
    let mut all_records = Vec::new();

    // Collect from all files.
    for i in (1..=20).rev() {
        let rotated = rotated_path(path, i);
        if rotated.exists() {
            read_records_from_file(&rotated, &mut all_records);
        }
    }
    if path.exists() {
        read_records_from_file(path, &mut all_records);
    }

    // Filter by since if provided.
    if let Some(ref cutoff) = since {
        all_records.retain(|r| r.timestamp >= *cutoff);
    }

    Ok(compute_audit_stats(&all_records))
}

/// Read all records from a file, skipping corrupt lines.
fn read_records_from_file(path: &Path, records: &mut Vec<AuditRecord>) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<AuditRecord>(&line) {
            records.push(record);
        }
    }
}

fn compute_audit_stats(records: &[AuditRecord]) -> AuditStats {
    let mut stats = AuditStats {
        total_events: records.len() as u64,
        ..Default::default()
    };

    let mut servers = HashSet::new();
    let mut tools = HashSet::new();
    let mut blocked_tools: HashMap<String, u64> = HashMap::new();
    let mut blocked_paths: HashMap<String, u64> = HashMap::new();

    for r in records {
        match r.action_taken.as_str() {
            "block" => {
                stats.blocked += 1;
                if let Some(ref tool) = r.tool_name {
                    *blocked_tools.entry(tool.clone()).or_insert(0) += 1;
                }
                if let Some(path) = r.event_details.get("process_path").and_then(|v| v.as_str()) {
                    *blocked_paths.entry(path.to_string()).or_insert(0) += 1;
                }
            }
            "allow" => stats.allowed += 1,
            "prompt" => stats.prompted += 1,
            "log" => stats.logged += 1,
            _ => {}
        }
        *stats.by_source.entry(r.source.clone()).or_insert(0) += 1;

        if let Some(ref s) = r.server_name {
            servers.insert(s.clone());
        }
        if let Some(ref t) = r.tool_name {
            tools.insert(t.clone());
        }
    }

    stats.unique_servers = servers.into_iter().collect();
    stats.unique_servers.sort();
    stats.unique_tools = tools.into_iter().collect();
    stats.unique_tools.sort();

    let mut bt: Vec<_> = blocked_tools.into_iter().collect();
    bt.sort_by(|a, b| b.1.cmp(&a.1));
    bt.truncate(10);
    stats.top_blocked_tools = bt;

    let mut bp: Vec<_> = blocked_paths.into_iter().collect();
    bp.sort_by(|a, b| b.1.cmp(&a.1));
    bp.truncate(10);
    stats.top_blocked_paths = bp;

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::io::Write;
    use tempfile::TempDir;

    fn make_record(source: &str, action: &str) -> AuditRecord {
        AuditRecord {
            timestamp: Utc::now(),
            source: source.to_string(),
            event_summary: format!("{source} event"),
            event_details: serde_json::json!({"key": "value"}),
            rule_matched: None,
            action_taken: action.to_string(),
            response_time_ms: Some(1),
            session_id: None,
            direction: None,
            server_name: None,
            client_name: None,
            jsonrpc_method: None,
            tool_name: None,
            arguments: None,
            classification: None,
            policy_rule: None,
            policy_action: None,
            user_decision: None,
            proxy_latency_us: None,
            slm_analysis: None,
            swarm_analysis: None,
            behavioral: None,
            injection_scan: None,
        }
    }

    fn write_records_to_file(path: &Path, records: &[AuditRecord]) {
        let mut file = File::create(path).unwrap();
        for r in records {
            let json = serde_json::to_string(r).unwrap();
            writeln!(file, "{json}").unwrap();
        }
    }

    #[test]
    fn test_query_logs_basic() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let records: Vec<AuditRecord> = (0..10)
            .map(|i| {
                let mut r = make_record(&format!("src-{}", i % 3), "allow");
                r.event_summary = format!("event-{i}");
                r
            })
            .collect();
        write_records_to_file(&path, &records);

        let filter = LogFilter {
            limit: 5,
            ..Default::default()
        };
        let results = query_logs(&path, &filter).unwrap();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_query_logs_filter_by_since() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let now = Utc::now();
        let mut records = Vec::new();
        for i in 0..5 {
            let mut r = make_record("s", "allow");
            r.timestamp = now - Duration::hours(5 - i);
            records.push(r);
        }
        write_records_to_file(&path, &records);

        let filter = LogFilter {
            since: Some(now - Duration::hours(3)),
            limit: 0,
            ..Default::default()
        };
        let results = query_logs(&path, &filter).unwrap();
        assert_eq!(results.len(), 3); // hours -3, -2, and -1
    }

    #[test]
    fn test_query_logs_filter_by_until() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let now = Utc::now();
        let mut records = Vec::new();
        for i in 0..5 {
            let mut r = make_record("s", "allow");
            r.timestamp = now - Duration::hours(5 - i);
            records.push(r);
        }
        write_records_to_file(&path, &records);

        let filter = LogFilter {
            until: Some(now - Duration::hours(3)),
            limit: 0,
            ..Default::default()
        };
        let results = query_logs(&path, &filter).unwrap();
        assert_eq!(results.len(), 3); // hours -5, -4, -3
    }

    #[test]
    fn test_query_logs_filter_by_server() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut records = Vec::new();
        for i in 0..6 {
            let mut r = make_record("mcp-proxy", "allow");
            r.server_name = Some(format!("server-{}", i % 2));
            records.push(r);
        }
        write_records_to_file(&path, &records);

        let filter = LogFilter {
            server_name: Some("server-0".to_string()),
            limit: 0,
            ..Default::default()
        };
        let results = query_logs(&path, &filter).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_query_logs_filter_by_action() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let records = vec![
            make_record("s", "allow"),
            make_record("s", "block"),
            make_record("s", "allow"),
            make_record("s", "prompt"),
            make_record("s", "block"),
        ];
        write_records_to_file(&path, &records);

        let filter = LogFilter {
            action: Some("block".to_string()),
            limit: 0,
            ..Default::default()
        };
        let results = query_logs(&path, &filter).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_logs_filter_by_method() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut records = Vec::new();
        for method in &["tools/call", "tools/list", "tools/call", "resources/read"] {
            let mut r = make_record("mcp-proxy", "allow");
            r.jsonrpc_method = Some(method.to_string());
            records.push(r);
        }
        write_records_to_file(&path, &records);

        let filter = LogFilter {
            method: Some("tools/call".to_string()),
            limit: 0,
            ..Default::default()
        };
        let results = query_logs(&path, &filter).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_logs_searches_rotated_files() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Write records to rotated file .1
        let rotated = rotated_path(&path, 1);
        let old_records = vec![
            make_record("old", "allow"),
            make_record("old", "block"),
        ];
        write_records_to_file(&rotated, &old_records);

        // Write records to current file
        let current_records = vec![
            make_record("new", "allow"),
        ];
        write_records_to_file(&path, &current_records);

        let filter = LogFilter {
            limit: 0,
            ..Default::default()
        };
        let results = query_logs(&path, &filter).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_aggregate_stats_basic() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut records = Vec::new();
        for _ in 0..3 {
            records.push(make_record("s", "allow"));
        }
        for _ in 0..2 {
            let mut r = make_record("s", "block");
            r.tool_name = Some("dangerous_tool".to_string());
            records.push(r);
        }
        records.push(make_record("s", "prompt"));
        records.push(make_record("s", "log"));
        write_records_to_file(&path, &records);

        let stats = aggregate_stats(&path, None).unwrap();
        assert_eq!(stats.total_events, 7);
        assert_eq!(stats.allowed, 3);
        assert_eq!(stats.blocked, 2);
        assert_eq!(stats.prompted, 1);
        assert_eq!(stats.logged, 1);
        assert_eq!(stats.top_blocked_tools.len(), 1);
        assert_eq!(stats.top_blocked_tools[0].0, "dangerous_tool");
        assert_eq!(stats.top_blocked_tools[0].1, 2);
    }

    #[test]
    fn test_aggregate_stats_with_since() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let now = Utc::now();
        let mut records = Vec::new();
        // Old record
        let mut r = make_record("s", "allow");
        r.timestamp = now - Duration::hours(10);
        records.push(r);
        // Recent records
        let mut r = make_record("s", "block");
        r.timestamp = now - Duration::hours(1);
        records.push(r);
        let mut r = make_record("s", "allow");
        r.timestamp = now - Duration::minutes(30);
        records.push(r);
        write_records_to_file(&path, &records);

        let stats = aggregate_stats(&path, Some(now - Duration::hours(2))).unwrap();
        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.blocked, 1);
    }

    #[test]
    fn test_aggregate_stats_includes_rotated() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Rotated file
        let rotated = rotated_path(&path, 1);
        write_records_to_file(&rotated, &[make_record("s", "block")]);

        // Current file
        write_records_to_file(&path, &[make_record("s", "allow")]);

        let stats = aggregate_stats(&path, None).unwrap();
        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.blocked, 1);
    }

    #[test]
    fn test_query_corrupt_lines_skipped() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Write a mix of valid and corrupt lines.
        {
            let mut file = File::create(&path).unwrap();
            let r = make_record("s", "allow");
            writeln!(file, "{}", serde_json::to_string(&r).unwrap()).unwrap();
            writeln!(file, "NOT VALID JSON").unwrap();
            writeln!(file, "{{}}").unwrap(); // valid JSON but not a valid AuditRecord
            let r2 = make_record("s", "block");
            writeln!(file, "{}", serde_json::to_string(&r2).unwrap()).unwrap();
        }

        let filter = LogFilter {
            limit: 0,
            ..Default::default()
        };
        let results = query_logs(&path, &filter).unwrap();
        assert_eq!(results.len(), 2); // Only the two valid records
    }

    #[test]
    fn test_stats_unique_servers_and_tools() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut records = Vec::new();
        for (server, tool) in &[
            ("srv-a", "tool-1"),
            ("srv-b", "tool-2"),
            ("srv-a", "tool-1"),
            ("srv-c", "tool-3"),
        ] {
            let mut r = make_record("mcp", "allow");
            r.server_name = Some(server.to_string());
            r.tool_name = Some(tool.to_string());
            records.push(r);
        }
        write_records_to_file(&path, &records);

        let stats = aggregate_stats(&path, None).unwrap();
        assert_eq!(stats.unique_servers.len(), 3);
        assert_eq!(stats.unique_tools.len(), 3);
    }
}
