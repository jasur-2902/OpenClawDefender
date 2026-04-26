//! Audit log integrity checks run at startup.
//!
//! Detects and repairs truncated entries at the end of audit.jsonl that may
//! have been caused by a crash mid-write in the previous session.

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use tracing::{info, warn};

/// Path to the audit.jsonl file.
fn audit_log_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/share/rookbot/audit.jsonl")
}

/// Check the last line of audit.jsonl and remove it if truncated/invalid.
///
/// When the daemon or proxy crashes mid-write, the last line of audit.jsonl
/// may be an incomplete JSON object. This function detects that case and
/// removes the truncated line to prevent downstream parse errors.
pub fn check_and_repair_audit_log() {
    let path = audit_log_path();
    if !path.exists() {
        return;
    }

    // Read the file contents
    let mut file = match std::fs::OpenOptions::new().read(true).write(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, "Failed to open audit.jsonl for integrity check");
            return;
        }
    };

    let file_len = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return,
    };

    if file_len == 0 {
        return;
    }

    // Read the last portion of the file to find the last line.
    // We read up to 64KB from the end — more than enough for a single JSON line.
    let read_size = std::cmp::min(file_len, 65536);
    let start_pos = file_len - read_size;

    if file.seek(SeekFrom::Start(start_pos)).is_err() {
        return;
    }

    let mut buf = vec![0u8; read_size as usize];
    if file.read_exact(&mut buf).is_err() {
        return;
    }

    let content = String::from_utf8_lossy(&buf);

    // Find the last non-empty line
    let lines: Vec<&str> = content.lines().collect();
    let last_line = match lines.iter().rev().find(|l| !l.trim().is_empty()) {
        Some(l) => *l,
        None => return,
    };

    // Try to parse the last line as JSON
    if serde_json::from_str::<serde_json::Value>(last_line).is_ok() {
        // Last line is valid JSON — no repair needed
        return;
    }

    // Last line is truncated/invalid — remove it
    info!("Removed truncated audit log entry from last session");

    // Find the byte position of the last valid newline before the truncated line
    // by finding where the last line starts in the buffer
    if let Some(last_newline_pos) = content.rfind('\n') {
        // Check if there's content before this newline
        let before_last = &content[..last_newline_pos];
        if let Some(second_last_newline) = before_last.rfind('\n') {
            // Truncate to the end of the second-to-last line
            let truncate_to = start_pos + (second_last_newline as u64) + 1;
            if file.set_len(truncate_to).is_err() {
                warn!("Failed to truncate audit.jsonl during repair");
            }
        } else {
            // Only one line in our read buffer — truncate to just before it
            let truncate_to = start_pos;
            if truncate_to == 0 {
                // The entire file is one bad line — truncate to empty
                let _ = file.set_len(0);
            } else {
                let _ = file.set_len(truncate_to);
            }
        }
    }
}
