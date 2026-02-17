use serde::{Deserialize, Serialize};
use std::sync::Mutex;

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

pub struct AppState {
    pub daemon_connected: Mutex<bool>,
    pub event_buffer: Mutex<Vec<AuditEvent>>,
    pub pending_prompts: Mutex<Vec<PendingPrompt>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            daemon_connected: Mutex::new(false),
            event_buffer: Mutex::new(Vec::new()),
            pending_prompts: Mutex::new(Vec::new()),
        }
    }
}
