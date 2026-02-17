use serde_json::Value;

use crate::client::Direction;
use crate::finding::Evidence;

#[derive(Debug)]
pub struct EvidenceCollector {
    messages: Vec<(Direction, Value, usize)>,
    os_events: Vec<String>,
    file_changes: Vec<String>,
    network_connections: Vec<String>,
    stderr_output: Vec<String>,
    canary_detections: Vec<String>,
}

impl EvidenceCollector {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            os_events: Vec::new(),
            file_changes: Vec::new(),
            network_connections: Vec::new(),
            stderr_output: Vec::new(),
            canary_detections: Vec::new(),
        }
    }

    pub fn record_message(&mut self, direction: Direction, msg: Value, index: usize) {
        self.messages.push((direction, msg, index));
    }

    pub fn record_os_event(&mut self, event: String) {
        self.os_events.push(event);
    }

    pub fn record_file_change(&mut self, path: String) {
        self.file_changes.push(path);
    }

    pub fn record_network(&mut self, connection: String) {
        self.network_connections.push(connection);
    }

    pub fn record_stderr(&mut self, output: String) {
        self.stderr_output.push(output);
    }

    pub fn check_canary_in_message(&self, msg: &Value, canaries: &[&str]) -> Vec<String> {
        let text = msg.to_string();
        canaries
            .iter()
            .filter(|c| text.contains(**c))
            .map(|c| c.to_string())
            .collect()
    }

    pub fn record_canary_detection(&mut self, canary: String) {
        self.canary_detections.push(canary);
    }

    pub fn network_connections(&self) -> &[String] {
        &self.network_connections
    }

    pub fn build_evidence(&self, message_indices: Vec<usize>) -> Evidence {
        let canary_detected = !self.canary_detections.is_empty();
        let stderr = if self.stderr_output.is_empty() {
            None
        } else {
            Some(self.stderr_output.join("\n"))
        };

        Evidence {
            messages: message_indices,
            audit_record: None,
            canary_detected,
            os_events: self.os_events.clone(),
            files_modified: self.file_changes.clone(),
            network_connections: self.network_connections.clone(),
            stderr_output: stderr,
        }
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}
