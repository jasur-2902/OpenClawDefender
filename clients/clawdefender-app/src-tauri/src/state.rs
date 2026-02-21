use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::ipc_client::DaemonIpcClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub server_name: String,
    pub tool_name: Option<String>,
    pub action: String,
    pub decision: String,
    pub risk_level: String,
    pub details: String,
    pub resource: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPrompt {
    pub id: String,
    pub timestamp: String,
    pub server_name: String,
    pub tool_name: String,
    pub action: String,
    pub resource: String,
    pub risk_level: String,
    pub context: String,
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime_seconds: Option<u64>,
    pub version: Option<String>,
    pub socket_path: String,
    pub servers_proxied: u32,
    pub events_processed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpClient {
    pub name: String,
    pub display_name: String,
    pub config_path: String,
    pub detected: bool,
    pub servers_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    pub name: String,
    pub command: Vec<String>,
    pub wrapped: bool,
    pub status: String,
    pub events_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub version: String,
    pub rules: Vec<PolicyRule>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub description: String,
    pub action: String,
    pub resource: String,
    pub pattern: String,
    pub priority: i32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplate {
    pub name: String,
    pub description: String,
    pub rules_count: u32,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerProfileSummary {
    pub server_name: String,
    pub tools_count: u32,
    pub total_calls: u64,
    pub anomaly_score: f64,
    pub status: String,
    pub last_activity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralStatus {
    pub enabled: bool,
    pub profiles_count: u32,
    pub total_anomalies: u32,
    pub learning_servers: u32,
    pub monitoring_servers: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardSummary {
    pub name: String,
    pub guard_type: String,
    pub enabled: bool,
    pub triggers_count: u32,
    pub last_triggered: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub status: String,
    pub progress_percent: f64,
    pub modules_completed: u32,
    pub modules_total: u32,
    pub findings_count: u32,
    pub current_module: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: String,
    pub message: String,
    pub fix_suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub daemon_version: Option<String>,
    pub app_version: String,
    pub config_dir: String,
    pub log_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme: String,
    pub notifications_enabled: bool,
    pub auto_start_daemon: bool,
    pub minimize_to_tray: bool,
    pub log_level: String,
    pub prompt_timeout_seconds: u32,
    pub event_retention_days: u32,
}

// --- Threat Intelligence types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedStatus {
    pub version: String,
    pub last_updated: String,
    pub next_check: String,
    pub entries_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistAlert {
    pub entry_id: String,
    pub server_name: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePackInfo {
    pub id: String,
    pub name: String,
    pub installed: bool,
    pub version: String,
    pub rule_count: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoCStats {
    pub network: u32,
    pub file: u32,
    pub behavioral: u32,
    pub total: u32,
    pub last_updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryStatus {
    pub enabled: bool,
    pub last_report: Option<String>,
    pub installation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPreview {
    pub categories: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationResult {
    pub server_name: String,
    pub clean: bool,
    pub matches: Vec<ReputationMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationMatch {
    pub entry_id: String,
    pub severity: String,
    pub description: String,
}

// --- Network Connection Log types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionEvent {
    pub id: String,
    pub timestamp: String,
    pub pid: u32,
    pub process_name: String,
    pub server_name: Option<String>,
    pub destination_ip: String,
    pub destination_port: u16,
    pub destination_domain: Option<String>,
    pub protocol: String,
    pub tls: bool,
    pub action: String,
    pub reason: String,
    pub rule: Option<String>,
    pub ioc_match: bool,
    pub anomaly_score: Option<f64>,
    pub behavioral: Option<String>,
    pub kill_chain: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummaryData {
    pub total_allowed: u64,
    pub total_blocked: u64,
    pub total_prompted: u64,
    pub top_destinations: Vec<DestinationCount>,
    pub period: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationCount {
    pub destination: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTrafficData {
    pub server_name: String,
    pub total_connections: u64,
    pub connections_allowed: u64,
    pub connections_blocked: u64,
    pub connections_prompted: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub unique_destinations: u32,
    pub period: String,
}

// --- Network Extension types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkExtensionStatus {
    pub loaded: bool,
    pub filter_active: bool,
    pub dns_active: bool,
    pub filtering_count: u64,
    pub mock_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    pub filter_enabled: bool,
    pub dns_enabled: bool,
    pub filter_all_processes: bool,
    pub default_action: String,
    pub prompt_timeout: u32,
    pub block_private_ranges: bool,
    pub block_doh: bool,
    pub log_dns: bool,
}

/// Maximum number of events to keep in the buffer to prevent unbounded memory growth.
const MAX_EVENT_BUFFER: usize = 10_000;

/// Maximum number of pending prompts to keep.
const MAX_PENDING_PROMPTS: usize = 100;

pub struct AppState {
    /// Whether the daemon is currently connected (updated by the connection monitor).
    pub daemon_connected: Mutex<bool>,
    /// Cached daemon status from the last successful status query.
    pub cached_status: Mutex<Option<DaemonStatus>>,
    /// Buffer of recent audit events received from the daemon.
    pub event_buffer: Mutex<Vec<AuditEvent>>,
    /// Pending prompts from the daemon awaiting user response.
    pub pending_prompts: Mutex<Vec<PendingPrompt>>,
    /// Whether onboarding has been completed (persisted to disk).
    pub onboarding_complete: Mutex<bool>,
    /// IPC client for communicating with the daemon.
    pub ipc_client: DaemonIpcClient,
    /// Whether the daemon was started by this GUI instance (for clean shutdown).
    pub daemon_started_by_gui: Mutex<bool>,
}

impl AppState {
    /// Path to the onboarding flag file.
    pub fn onboarding_flag_path() -> std::path::PathBuf {
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        home.join(".clawdefender").join("onboarding_complete")
    }

    /// Check if onboarding was previously completed (persisted to disk).
    fn load_onboarding_state() -> bool {
        Self::onboarding_flag_path().exists()
    }

    /// Add an audit event to the buffer, enforcing the size limit.
    pub fn push_event(&self, event: AuditEvent) {
        if let Ok(mut buffer) = self.event_buffer.lock() {
            buffer.push(event);
            if buffer.len() > MAX_EVENT_BUFFER {
                // Remove oldest events (front of the vec)
                let excess = buffer.len() - MAX_EVENT_BUFFER;
                buffer.drain(..excess);
            }
        }
    }

    /// Add a pending prompt, enforcing the size limit.
    pub fn push_prompt(&self, prompt: PendingPrompt) {
        if let Ok(mut prompts) = self.pending_prompts.lock() {
            prompts.push(prompt);
            if prompts.len() > MAX_PENDING_PROMPTS {
                prompts.drain(..1);
            }
        }
    }

    /// Update the cached daemon status and connection state.
    pub fn update_daemon_status(&self, connected: bool, status: Option<DaemonStatus>) {
        if let Ok(mut conn) = self.daemon_connected.lock() {
            *conn = connected;
        }
        if let Ok(mut cached) = self.cached_status.lock() {
            *cached = status;
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            daemon_connected: Mutex::new(false),
            cached_status: Mutex::new(None),
            event_buffer: Mutex::new(Vec::new()),
            pending_prompts: Mutex::new(Vec::new()),
            onboarding_complete: Mutex::new(Self::load_onboarding_state()),
            ipc_client: DaemonIpcClient::new(),
            daemon_started_by_gui: Mutex::new(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(id: &str) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            timestamp: "2025-01-15T10:30:00Z".to_string(),
            event_type: "proxy".to_string(),
            server_name: "test".to_string(),
            tool_name: None,
            action: "test".to_string(),
            decision: "allow".to_string(),
            risk_level: "info".to_string(),
            details: String::new(),
            resource: None,
        }
    }

    fn make_prompt(id: &str) -> PendingPrompt {
        PendingPrompt {
            id: id.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            server_name: "test".to_string(),
            tool_name: "tool".to_string(),
            action: "call".to_string(),
            resource: "/path".to_string(),
            risk_level: "info".to_string(),
            context: String::new(),
            timeout_seconds: 30,
        }
    }

    #[test]
    fn test_event_buffer_bounded_at_10000() {
        let state = AppState::default();
        for i in 0..10_050 {
            state.push_event(make_event(&format!("evt-{}", i)));
        }
        let buffer = state.event_buffer.lock().unwrap();
        assert_eq!(buffer.len(), MAX_EVENT_BUFFER);
        // Oldest events should have been drained; first event should be evt-50
        assert_eq!(buffer[0].id, "evt-50");
    }

    #[test]
    fn test_pending_prompts_bounded_at_100() {
        let state = AppState::default();
        for i in 0..110 {
            state.push_prompt(make_prompt(&format!("prompt-{}", i)));
        }
        let prompts = state.pending_prompts.lock().unwrap();
        assert_eq!(prompts.len(), MAX_PENDING_PROMPTS);
    }

    #[test]
    fn test_push_event_basic() {
        let state = AppState::default();
        state.push_event(make_event("evt-1"));
        state.push_event(make_event("evt-2"));
        let buffer = state.event_buffer.lock().unwrap();
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer[0].id, "evt-1");
        assert_eq!(buffer[1].id, "evt-2");
    }

    #[test]
    fn test_update_daemon_status() {
        let state = AppState::default();
        assert!(!*state.daemon_connected.lock().unwrap());

        state.update_daemon_status(true, Some(DaemonStatus {
            running: true,
            pid: Some(1234),
            uptime_seconds: Some(60),
            version: Some("1.0".into()),
            socket_path: "/tmp/test.sock".into(),
            servers_proxied: 2,
            events_processed: 100,
        }));

        assert!(*state.daemon_connected.lock().unwrap());
        let cached = state.cached_status.lock().unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.as_ref().unwrap().pid, Some(1234));
    }
}
