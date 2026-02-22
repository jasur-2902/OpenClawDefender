//! Structured audit log writer.
//!
//! Implements a JSON-lines audit logger with channel-based async writes,
//! buffered I/O, log rotation, and retention cleanup.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use tracing::warn;
use uuid::Uuid;

use super::{AuditFilter, AuditLogger, AuditRecord, AuditStats};
use crate::config::settings::LogRotation;

/// Maximum file size in bytes before rotation (50 MB).
const DEFAULT_MAX_SIZE_BYTES: u64 = 50 * 1024 * 1024;
/// Flush interval for the buffered writer.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
/// Flush after this many records.
const FLUSH_RECORD_COUNT: usize = 100;
/// Retention: delete rotated files older than 30 days.
const RETENTION_DAYS: i64 = 30;

/// Internal command sent to the writer thread.
enum WriterCommand {
    Write(Box<AuditRecord>),
    Flush,
    Shutdown,
}

/// Shared state for the writer thread.
struct WriterState {
    writer: BufWriter<File>,
    log_path: PathBuf,
    rotation: LogRotation,
    records_since_flush: usize,
    last_flush: Instant,
}

impl WriterState {
    fn write_record(&mut self, record: &AuditRecord) -> Result<()> {
        let json = serde_json::to_string(record)?;
        writeln!(self.writer, "{json}")?;
        self.records_since_flush += 1;

        if self.records_since_flush >= FLUSH_RECORD_COUNT
            || self.last_flush.elapsed() >= FLUSH_INTERVAL
        {
            self.flush()?;
        }

        // Check rotation after writing.
        let max_bytes = if self.rotation.max_size_mb > 0 {
            self.rotation.max_size_mb * 1024 * 1024
        } else {
            DEFAULT_MAX_SIZE_BYTES
        };

        if let Ok(meta) = fs::metadata(&self.log_path) {
            if meta.len() >= max_bytes {
                self.flush()?;
                self.rotate()?;
            }
        }

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.records_since_flush = 0;
        self.last_flush = Instant::now();
        Ok(())
    }

    fn rotate(&mut self) -> Result<()> {
        let max = self.rotation.max_files;
        if max == 0 {
            return Ok(());
        }

        // Delete the oldest rotated file if it exists.
        let oldest = rotated_path(&self.log_path, max);
        if oldest.exists() {
            fs::remove_file(&oldest)?;
        }

        // Shift .N -> .N+1, starting from the highest to avoid overwrites.
        for i in (1..max).rev() {
            let from = rotated_path(&self.log_path, i);
            let to = rotated_path(&self.log_path, i + 1);
            if from.exists() {
                fs::rename(&from, &to)?;
            }
        }

        // Rename current log to .1
        if self.log_path.exists() {
            fs::rename(&self.log_path, rotated_path(&self.log_path, 1))?;
        }

        // Open a fresh log file.
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        self.writer = BufWriter::new(new_file);

        Ok(())
    }
}

/// A file-backed audit logger that writes JSON Lines with channel-based async writes,
/// buffered I/O, log rotation, session tracking, and retention cleanup.
pub struct FileAuditLogger {
    log_path: PathBuf,
    rotation: LogRotation,
    session_id: String,
    /// Channel sender for async writes.
    sender: mpsc::Sender<WriterCommand>,
    /// Writer thread handle. Wrapped in Option for Drop.
    writer_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Counters for session-end summary.
    total_logged: AtomicU64,
    blocked_count: AtomicU64,
    allowed_count: AtomicU64,
    prompted_count: AtomicU64,
    /// Direct file access for reads (query/stats). Separate from writer.
    file_for_read: Mutex<()>,
}

impl FileAuditLogger {
    /// Create a new logger, creating parent directories and the log file as needed.
    ///
    /// Spawns a dedicated writer thread that drains records from a channel.
    /// On startup, logs a session-start record and cleans up old rotated files.
    pub fn new(log_path: PathBuf, rotation: LogRotation) -> Result<Self> {
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dirs for {}", log_path.display()))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("opening audit log {}", log_path.display()))?;

        let session_id = Uuid::new_v4().to_string();

        // Clean up old rotated files.
        cleanup_old_files(&log_path, &rotation);

        // Set up channel and writer thread.
        let (sender, receiver) = mpsc::channel::<WriterCommand>();

        let mut state = WriterState {
            writer: BufWriter::new(file),
            log_path: log_path.clone(),
            rotation: rotation.clone(),
            records_since_flush: 0,
            last_flush: Instant::now(),
        };

        let writer_handle = std::thread::spawn(move || {
            while let Ok(cmd) = receiver.recv() {
                match cmd {
                    WriterCommand::Write(record) => {
                        if let Err(e) = state.write_record(&record) {
                            warn!(error = %e, "failed to write audit record");
                        }
                    }
                    WriterCommand::Flush => {
                        if let Err(e) = state.flush() {
                            warn!(error = %e, "failed to flush audit log");
                        }
                    }
                    WriterCommand::Shutdown => {
                        let _ = state.flush();
                        break;
                    }
                }
            }
            // Final flush on channel close.
            let _ = state.flush();
        });

        let logger = Self {
            log_path,
            rotation,
            session_id: session_id.clone(),
            sender,
            writer_handle: Mutex::new(Some(writer_handle)),
            total_logged: AtomicU64::new(0),
            blocked_count: AtomicU64::new(0),
            allowed_count: AtomicU64::new(0),
            prompted_count: AtomicU64::new(0),
            file_for_read: Mutex::new(()),
        };

        // Log session-start record.
        let start_record = AuditRecord {
            timestamp: Utc::now(),
            source: "system".to_string(),
            event_summary: "session-start".to_string(),
            event_details: serde_json::json!({
                "session_id": session_id,
            }),
            rule_matched: None,
            action_taken: "log".to_string(),
            response_time_ms: None,
            session_id: Some(session_id),
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
            threat_intel: None,
            network_connection: None,
        };
        // Use the channel to write session-start.
        let _ = logger
            .sender
            .send(WriterCommand::Write(Box::new(start_record)));
        // Flush to ensure session-start is persisted.
        let _ = logger.sender.send(WriterCommand::Flush);

        Ok(logger)
    }

    /// Get the session ID for this logger instance.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Explicitly flush and shut down the writer thread, logging a session-end record.
    pub fn shutdown(&self) {
        let end_record = AuditRecord {
            timestamp: Utc::now(),
            source: "system".to_string(),
            event_summary: "session-end".to_string(),
            event_details: serde_json::json!({
                "session_id": self.session_id,
                "total_logged": self.total_logged.load(Ordering::Relaxed),
                "blocked": self.blocked_count.load(Ordering::Relaxed),
                "allowed": self.allowed_count.load(Ordering::Relaxed),
                "prompted": self.prompted_count.load(Ordering::Relaxed),
            }),
            rule_matched: None,
            action_taken: "log".to_string(),
            response_time_ms: None,
            session_id: Some(self.session_id.clone()),
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
            threat_intel: None,
            network_connection: None,
        };
        let _ = self.sender.send(WriterCommand::Write(Box::new(end_record)));
        let _ = self.sender.send(WriterCommand::Shutdown);

        if let Ok(mut guard) = self.writer_handle.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }

    /// Rotate log files manually (exposed for testing).
    #[cfg(test)]
    fn rotate_sync(&self) -> Result<()> {
        let max = self.rotation.max_files;
        if max == 0 {
            return Ok(());
        }

        // Flush first.
        let _ = self.sender.send(WriterCommand::Flush);
        // Give writer thread a moment to flush.
        std::thread::sleep(Duration::from_millis(50));

        let oldest = rotated_path(&self.log_path, max);
        if oldest.exists() {
            fs::remove_file(&oldest)?;
        }

        for i in (1..max).rev() {
            let from = rotated_path(&self.log_path, i);
            let to = rotated_path(&self.log_path, i + 1);
            if from.exists() {
                fs::rename(&from, &to)?;
            }
        }

        if self.log_path.exists() {
            fs::rename(&self.log_path, rotated_path(&self.log_path, 1))?;
        }

        // Tell writer to re-open via a flush (the writer state handles its own file).
        // We need to create the file so the writer can continue.
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        Ok(())
    }

    /// Read all records from the current log file (and optionally rotated files).
    fn read_all_files(&self) -> Result<Vec<AuditRecord>> {
        let _guard = self.file_for_read.lock().unwrap();
        // Flush writer first so we read the latest data.
        let _ = self.sender.send(WriterCommand::Flush);
        std::thread::sleep(Duration::from_millis(20));

        let mut records = Vec::new();

        // Read rotated files first (oldest to newest).
        let max = self.rotation.max_files;
        for i in (1..=max).rev() {
            let path = rotated_path(&self.log_path, i);
            if path.exists() {
                read_records_from_file(&path, &mut records);
            }
        }

        // Read current file.
        if self.log_path.exists() {
            read_records_from_file(&self.log_path, &mut records);
        }

        Ok(records)
    }
}

impl Drop for FileAuditLogger {
    fn drop(&mut self) {
        // Log session-end and shut down writer thread.
        let end_record = AuditRecord {
            timestamp: Utc::now(),
            source: "system".to_string(),
            event_summary: "session-end".to_string(),
            event_details: serde_json::json!({
                "session_id": self.session_id,
                "total_logged": self.total_logged.load(Ordering::Relaxed),
                "blocked": self.blocked_count.load(Ordering::Relaxed),
                "allowed": self.allowed_count.load(Ordering::Relaxed),
                "prompted": self.prompted_count.load(Ordering::Relaxed),
            }),
            rule_matched: None,
            action_taken: "log".to_string(),
            response_time_ms: None,
            session_id: Some(self.session_id.clone()),
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
            threat_intel: None,
            network_connection: None,
        };
        let _ = self.sender.send(WriterCommand::Write(Box::new(end_record)));
        let _ = self.sender.send(WriterCommand::Shutdown);

        if let Ok(mut guard) = self.writer_handle.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

/// Read records from a single file, skipping corrupt lines.
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
        match serde_json::from_str::<AuditRecord>(&line) {
            Ok(record) => records.push(record),
            Err(_) => {
                // Skip corrupt lines gracefully.
                continue;
            }
        }
    }
}

pub(crate) fn rotated_path(base: &Path, n: u32) -> PathBuf {
    let mut s = base.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// Delete rotated files older than RETENTION_DAYS.
fn cleanup_old_files(log_path: &Path, rotation: &LogRotation) {
    let cutoff = Utc::now() - chrono::Duration::days(RETENTION_DAYS);

    for i in 1..=rotation.max_files {
        let path = rotated_path(log_path, i);
        if !path.exists() {
            continue;
        }
        if let Ok(meta) = fs::metadata(&path) {
            if let Ok(modified) = meta.modified() {
                let modified_dt: chrono::DateTime<Utc> = modified.into();
                if modified_dt < cutoff {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }
}

fn compute_stats(records: &[AuditRecord]) -> AuditStats {
    let mut stats = AuditStats {
        total_events: records.len() as u64,
        ..Default::default()
    };

    let mut servers = std::collections::HashSet::new();
    let mut tools = std::collections::HashSet::new();
    let mut blocked_tools: HashMap<String, u64> = HashMap::new();
    let mut blocked_paths: HashMap<String, u64> = HashMap::new();

    for r in records {
        match r.action_taken.as_str() {
            "block" => {
                stats.blocked += 1;
                if let Some(ref tool) = r.tool_name {
                    *blocked_tools.entry(tool.clone()).or_insert(0) += 1;
                }
                // Use process path from event_details if available.
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

impl AuditLogger for FileAuditLogger {
    fn log(&self, record: &AuditRecord) -> Result<()> {
        self.sender
            .send(WriterCommand::Write(Box::new(record.clone())))
            .map_err(|e| anyhow::anyhow!("audit writer channel closed: {e}"))?;

        self.total_logged.fetch_add(1, Ordering::Relaxed);
        match record.action_taken.as_str() {
            "block" => {
                self.blocked_count.fetch_add(1, Ordering::Relaxed);
            }
            "allow" => {
                self.allowed_count.fetch_add(1, Ordering::Relaxed);
            }
            "prompt" => {
                self.prompted_count.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        Ok(())
    }

    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditRecord>> {
        // Flush to ensure we read latest data.
        let _ = self.sender.send(WriterCommand::Flush);
        std::thread::sleep(Duration::from_millis(20));

        let file = File::open(&self.log_path);
        let file = match file {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            let record: AuditRecord = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => continue, // Skip corrupt lines.
            };

            if let Some(ref from) = filter.from {
                if record.timestamp < *from {
                    continue;
                }
            }
            if let Some(ref to) = filter.to {
                if record.timestamp > *to {
                    continue;
                }
            }
            if let Some(ref source) = filter.source {
                if record.source != *source {
                    continue;
                }
            }
            if let Some(ref action) = filter.action {
                if record.action_taken != *action {
                    continue;
                }
            }
            records.push(record);
        }

        // Most recent first.
        records.reverse();

        if filter.limit > 0 && records.len() > filter.limit {
            records.truncate(filter.limit);
        }

        Ok(records)
    }

    fn stats(&self) -> Result<AuditStats> {
        let records = self.read_all_files()?;
        Ok(compute_stats(&records))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
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
            threat_intel: None,
            network_connection: None,
        }
    }

    fn make_record_at(source: &str, action: &str, ts: chrono::DateTime<Utc>) -> AuditRecord {
        AuditRecord {
            timestamp: ts,
            source: source.to_string(),
            event_summary: format!("{source} event"),
            event_details: serde_json::json!({}),
            rule_matched: None,
            action_taken: action.to_string(),
            response_time_ms: None,
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
            threat_intel: None,
            network_connection: None,
        }
    }

    fn default_rotation() -> LogRotation {
        LogRotation {
            max_size_mb: 50,
            max_files: 5,
        }
    }

    /// Helper: flush writer and wait briefly for it to complete.
    fn flush_and_wait(logger: &FileAuditLogger) {
        let _ = logger.sender.send(WriterCommand::Flush);
        std::thread::sleep(Duration::from_millis(50));
    }

    #[test]
    fn test_log_writes_valid_jsonl() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path.clone(), default_rotation()).unwrap();

        let record = make_record("mcp-proxy", "allow");
        logger.log(&record).unwrap();
        flush_and_wait(&logger);

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        // First line is session-start, second is our record.
        assert!(lines.len() >= 2);
        let parsed: AuditRecord = serde_json::from_str(lines[lines.len() - 1]).unwrap();
        assert_eq!(parsed.source, "mcp-proxy");
        assert_eq!(parsed.action_taken, "allow");
    }

    #[test]
    fn test_log_query_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();

        for i in 0..5 {
            let r = make_record(&format!("src-{i}"), "allow");
            logger.log(&r).unwrap();
        }
        flush_and_wait(&logger);

        let filter = AuditFilter {
            source: Some("src-0".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source, "src-0");
    }

    #[test]
    fn test_query_filter_by_source() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();

        logger.log(&make_record("mcp-proxy", "allow")).unwrap();
        logger.log(&make_record("eslogger", "block")).unwrap();
        logger.log(&make_record("mcp-proxy", "block")).unwrap();
        flush_and_wait(&logger);

        let filter = AuditFilter {
            source: Some("mcp-proxy".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.source == "mcp-proxy"));
    }

    #[test]
    fn test_query_filter_by_action() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();

        logger.log(&make_record("src", "allow")).unwrap();
        logger.log(&make_record("src", "block")).unwrap();
        logger.log(&make_record("src", "allow")).unwrap();
        flush_and_wait(&logger);

        let filter = AuditFilter {
            action: Some("block".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action_taken, "block");
    }

    #[test]
    fn test_query_filter_by_timestamp_range() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();

        let now = Utc::now();
        let t1 = now - ChronoDuration::hours(3);
        let t2 = now - ChronoDuration::hours(2);
        let t3 = now - ChronoDuration::hours(1);

        logger.log(&make_record_at("s", "allow", t1)).unwrap();
        logger.log(&make_record_at("s", "allow", t2)).unwrap();
        logger.log(&make_record_at("s", "allow", t3)).unwrap();
        flush_and_wait(&logger);

        let filter = AuditFilter {
            from: Some(now - ChronoDuration::minutes(150)),
            to: Some(now - ChronoDuration::minutes(30)),
            source: Some("s".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_with_limit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();

        for _ in 0..10 {
            logger.log(&make_record("s", "allow")).unwrap();
        }
        flush_and_wait(&logger);

        let filter = AuditFilter {
            limit: 3,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        // We asked for limit 3, but there's also a session-start record.
        // The limit applies after filtering, so we get 3 most recent.
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_rotation_triggers_and_renames() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let rotation = LogRotation {
            max_size_mb: 0,
            max_files: 3,
        };
        let logger = FileAuditLogger::new(path.clone(), rotation).unwrap();

        logger.log(&make_record("s", "allow")).unwrap();
        flush_and_wait(&logger);
        logger.rotate_sync().unwrap();

        assert!(path.exists(), "fresh log file should exist");
        assert!(
            rotated_path(&path, 1).exists(),
            "rotated .1 file should exist"
        );

        // Second rotation.
        logger.log(&make_record("s", "block")).unwrap();
        flush_and_wait(&logger);
        logger.rotate_sync().unwrap();

        assert!(rotated_path(&path, 2).exists());
    }

    #[test]
    fn test_rotation_respects_max_files() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let rotation = LogRotation {
            max_size_mb: 0,
            max_files: 2,
        };
        let logger = FileAuditLogger::new(path.clone(), rotation).unwrap();

        for _ in 0..3 {
            logger.log(&make_record("s", "allow")).unwrap();
            flush_and_wait(&logger);
            logger.rotate_sync().unwrap();
        }

        assert!(rotated_path(&path, 1).exists());
        assert!(rotated_path(&path, 2).exists());
        assert!(
            !rotated_path(&path, 3).exists(),
            "oldest file beyond max_files should be deleted"
        );
    }

    #[test]
    fn test_log_rotation_by_size() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let rotation = LogRotation {
            max_size_mb: 1,
            max_files: 3,
        };
        let logger = FileAuditLogger::new(path.clone(), rotation).unwrap();

        logger.log(&make_record("s", "allow")).unwrap();
        flush_and_wait(&logger);
        assert!(path.exists());
    }

    #[test]
    fn test_stats() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();

        logger.log(&make_record("mcp-proxy", "allow")).unwrap();
        logger.log(&make_record("mcp-proxy", "block")).unwrap();
        logger.log(&make_record("eslogger", "allow")).unwrap();
        logger.log(&make_record("eslogger", "prompt")).unwrap();
        logger.log(&make_record("eslogger", "block")).unwrap();
        flush_and_wait(&logger);

        let stats = logger.stats().unwrap();
        // +1 for session-start which has action "log"
        assert_eq!(stats.total_events, 6);
        assert_eq!(stats.allowed, 2);
        assert_eq!(stats.blocked, 2);
        assert_eq!(stats.prompted, 1);
        assert_eq!(stats.by_source["mcp-proxy"], 2);
        assert_eq!(stats.by_source["eslogger"], 3);
    }

    #[test]
    fn test_empty_log_query_and_stats() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();
        flush_and_wait(&logger);

        let filter = AuditFilter {
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        // Session-start record is always present.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_summary, "session-start");

        let stats = logger.stats().unwrap();
        assert_eq!(stats.total_events, 1); // session-start
        assert_eq!(stats.blocked, 0);
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.prompted, 0);
    }

    #[test]
    fn test_concurrent_writes() {
        use std::sync::Arc;
        use std::thread;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = Arc::new(FileAuditLogger::new(path.clone(), default_rotation()).unwrap());

        let mut handles = Vec::new();
        for i in 0..10 {
            let logger = Arc::clone(&logger);
            handles.push(thread::spawn(move || {
                logger
                    .log(&make_record(&format!("thread-{i}"), "allow"))
                    .unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        flush_and_wait(&logger);

        let filter = AuditFilter {
            source: None,
            action: Some("allow".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert_eq!(results.len(), 10);
    }

    #[test]
    fn test_session_start_and_end_records() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let session_id;
        {
            let logger = FileAuditLogger::new(path.clone(), default_rotation()).unwrap();
            session_id = logger.session_id().to_string();
            logger.log(&make_record("s", "allow")).unwrap();
            // Drop triggers session-end
        }

        // Wait for drop/shutdown.
        std::thread::sleep(Duration::from_millis(100));

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();

        // Should have: session-start, our record, session-end
        assert!(
            lines.len() >= 3,
            "expected at least 3 lines, got {}",
            lines.len()
        );

        let first: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.event_summary, "session-start");
        assert_eq!(first.session_id.as_deref(), Some(session_id.as_str()));

        let last: AuditRecord = serde_json::from_str(lines[lines.len() - 1]).unwrap();
        assert_eq!(last.event_summary, "session-end");
        assert_eq!(last.session_id.as_deref(), Some(session_id.as_str()));
    }

    #[test]
    fn test_write_1000_records_and_read_back() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();

        for i in 0..1000 {
            let mut r = make_record(&format!("src-{}", i % 10), "allow");
            r.event_summary = format!("event-{i}");
            logger.log(&r).unwrap();
        }
        flush_and_wait(&logger);

        let filter = AuditFilter {
            action: Some("allow".to_string()),
            limit: 0, // no limit
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert_eq!(results.len(), 1000);
    }

    #[test]
    fn test_corrupt_log_lines_handled_gracefully() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Write some valid records and some corrupt lines.
        {
            let logger = FileAuditLogger::new(path.clone(), default_rotation()).unwrap();
            logger.log(&make_record("s", "allow")).unwrap();
            flush_and_wait(&logger);
        }
        std::thread::sleep(Duration::from_millis(100));

        // Append a corrupt line directly.
        {
            use std::io::Write;
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(file, "THIS IS NOT VALID JSON").unwrap();
            writeln!(file, "{{\"also\": \"not a valid AuditRecord\"}}").unwrap();
        }

        // Now read with a new logger.
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();
        flush_and_wait(&logger);

        let filter = AuditFilter {
            limit: 100,
            ..Default::default()
        };
        // Should not error, just skip bad lines.
        let results = logger.query(&filter).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_channel_writer_no_lost_records() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path.clone(), default_rotation()).unwrap();

        // Fire off many records quickly.
        for i in 0..500 {
            let mut r = make_record("fast", "allow");
            r.event_summary = format!("fast-{i}");
            logger.log(&r).unwrap();
        }

        // Explicit shutdown to ensure all records are flushed.
        logger.shutdown();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
        // session-start + 500 records + session-end (from shutdown) + session-end (from drop, but writer already stopped so this one won't be written)
        // Actually drop's send will fail since channel is closed after shutdown. So: session-start + 500 + session-end = 502
        assert!(
            lines.len() >= 502,
            "expected at least 502 lines (start + 500 + end), got {}",
            lines.len()
        );
    }

    #[test]
    fn test_enhanced_fields_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();

        let mut record = make_record("mcp-proxy", "block");
        record.session_id = Some("test-session".to_string());
        record.direction = Some("client_to_server".to_string());
        record.server_name = Some("my-server".to_string());
        record.tool_name = Some("read_file".to_string());
        record.classification = Some("block".to_string());
        record.policy_action = Some("blocked".to_string());
        record.proxy_latency_us = Some(1234);

        logger.log(&record).unwrap();
        flush_and_wait(&logger);

        let filter = AuditFilter {
            action: Some("block".to_string()),
            limit: 1,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server_name.as_deref(), Some("my-server"));
        assert_eq!(results[0].tool_name.as_deref(), Some("read_file"));
        assert_eq!(results[0].proxy_latency_us, Some(1234));
    }

    #[test]
    fn test_stats_with_enhanced_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = FileAuditLogger::new(path, default_rotation()).unwrap();

        let mut r1 = make_record("mcp-proxy", "block");
        r1.server_name = Some("server-a".to_string());
        r1.tool_name = Some("run_command".to_string());

        let mut r2 = make_record("mcp-proxy", "allow");
        r2.server_name = Some("server-b".to_string());
        r2.tool_name = Some("read_file".to_string());

        let mut r3 = make_record("mcp-proxy", "block");
        r3.server_name = Some("server-a".to_string());
        r3.tool_name = Some("run_command".to_string());

        logger.log(&r1).unwrap();
        logger.log(&r2).unwrap();
        logger.log(&r3).unwrap();
        flush_and_wait(&logger);

        let stats = logger.stats().unwrap();
        assert_eq!(stats.blocked, 2);
        assert_eq!(stats.allowed, 1);
        assert!(stats.unique_servers.contains(&"server-a".to_string()));
        assert!(stats.unique_servers.contains(&"server-b".to_string()));
        assert!(stats.unique_tools.contains(&"run_command".to_string()));
        assert!(stats.unique_tools.contains(&"read_file".to_string()));
        assert_eq!(stats.top_blocked_tools.len(), 1);
        assert_eq!(stats.top_blocked_tools[0], ("run_command".to_string(), 2));
    }
}
