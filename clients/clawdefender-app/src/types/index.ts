export interface DaemonStatus {
  running: boolean;
  pid: number | null;
  uptime_seconds: number | null;
  version: string | null;
  socket_path: string;
  servers_proxied: number;
  events_processed: number;
}

export interface McpClient {
  name: string;
  display_name: string;
  config_path: string;
  detected: boolean;
  servers_count: number;
}

export interface McpServer {
  name: string;
  command: string[];
  wrapped: boolean;
  status: "running" | "stopped" | "error";
  events_count: number;
}

export interface Policy {
  name: string;
  version: string;
  rules: PolicyRule[];
  created_at: string;
  updated_at: string;
}

export interface PolicyRule {
  name: string;
  description: string;
  action: "allow" | "deny" | "prompt" | "audit";
  resource: string;
  pattern: string;
  priority: number;
  enabled: boolean;
}

export interface PolicyTemplate {
  name: string;
  description: string;
  rules_count: number;
  category: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  event_type: string;
  server_name: string;
  tool_name: string | null;
  action: string;
  decision: string;
  risk_level: "low" | "medium" | "high" | "critical";
  details: string;
  resource: string | null;
}

export interface PendingPrompt {
  id: string;
  timestamp: string;
  server_name: string;
  tool_name: string;
  action: string;
  resource: string;
  risk_level: "low" | "medium" | "high" | "critical";
  context: string;
  timeout_seconds: number;
}

export interface ServerProfileSummary {
  server_name: string;
  tools_count: number;
  total_calls: number;
  anomaly_score: number;
  status: "normal" | "learning" | "anomalous";
  last_activity: string;
}

export interface BehavioralStatus {
  enabled: boolean;
  profiles_count: number;
  total_anomalies: number;
  learning_servers: number;
  monitoring_servers: number;
}

export interface GuardSummary {
  name: string;
  guard_type: string;
  enabled: boolean;
  triggers_count: number;
  last_triggered: string | null;
  description: string;
}

export interface ScanProgress {
  scan_id: string;
  status: "running" | "completed" | "failed";
  progress_percent: number;
  modules_completed: number;
  modules_total: number;
  findings_count: number;
  current_module: string | null;
}

export interface DoctorCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
  fix_suggestion: string | null;
}

export interface SystemInfo {
  os: string;
  os_version: string;
  arch: string;
  daemon_version: string | null;
  app_version: string;
  config_dir: string;
  log_dir: string;
}

export interface AppSettings {
  theme: "dark" | "light" | "system";
  notifications_enabled: boolean;
  auto_start_daemon: boolean;
  minimize_to_tray: boolean;
  log_level: "trace" | "debug" | "info" | "warn" | "error";
  prompt_timeout_seconds: number;
  event_retention_days: number;
}

// --- Threat Intelligence types ---

export interface FeedStatus {
  version: string;
  last_updated: string;
  next_check: string;
  entries_count: number;
}

export interface BlocklistAlert {
  entry_id: string;
  server_name: string;
  severity: string;
  description: string;
}

export interface RulePackInfo {
  id: string;
  name: string;
  installed: boolean;
  version: string;
  rule_count: number;
  description: string;
}

export interface IoCStats {
  network: number;
  file: number;
  behavioral: number;
  total: number;
  last_updated: string;
}

export interface TelemetryStatus {
  enabled: boolean;
  last_report: string | null;
  installation_id: string | null;
}

export interface TelemetryPreview {
  categories: string[];
  description: string;
}

export interface ReputationResult {
  server_name: string;
  clean: boolean;
  matches: ReputationMatch[];
}

export interface ReputationMatch {
  entry_id: string;
  severity: string;
  description: string;
}

// --- Network Extension types ---

export interface NetworkExtensionStatus {
  loaded: boolean;
  filter_active: boolean;
  dns_active: boolean;
  filtering_count: number;
  mock_mode: boolean;
}

export interface NetworkSettings {
  filter_enabled: boolean;
  dns_enabled: boolean;
  filter_all_processes: boolean;
  default_action: "prompt" | "block" | "allow";
  prompt_timeout: number;
  block_private_ranges: boolean;
  block_doh: boolean;
  log_dns: boolean;
}

// --- Network Connection Log types ---

export interface NetworkConnectionEvent {
  id: string;
  timestamp: string;
  pid: number;
  process_name: string;
  server_name: string | null;
  destination_ip: string;
  destination_port: number;
  destination_domain: string | null;
  protocol: string;
  tls: boolean;
  action: "allowed" | "blocked" | "prompted";
  reason: string;
  rule: string | null;
  ioc_match: boolean;
  anomaly_score: number | null;
  behavioral: string | null;
  kill_chain: string | null;
  bytes_sent: number;
  bytes_received: number;
  duration_ms: number;
}

export interface NetworkSummaryData {
  total_allowed: number;
  total_blocked: number;
  total_prompted: number;
  top_destinations: DestinationCount[];
  period: string;
}

export interface DestinationCount {
  destination: string;
  count: number;
}

export interface ServerTrafficData {
  server_name: string;
  total_connections: number;
  connections_allowed: number;
  connections_blocked: number;
  connections_prompted: number;
  bytes_sent: number;
  bytes_received: number;
  unique_destinations: number;
  period: string;
}

export type TauriEvent =
  | { type: "event"; payload: AuditEvent }
  | { type: "prompt"; payload: PendingPrompt }
  | { type: "alert"; payload: { level: string; message: string; details: string } }
  | { type: "status-change"; payload: { daemon_running: boolean } };
