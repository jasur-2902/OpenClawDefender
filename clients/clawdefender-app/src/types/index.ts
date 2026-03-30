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
  slm_analysis?: string;
  slm_recommendation?: string;
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
  behavioral_auto_block: boolean;
  behavioral_threshold: number;
  analysis_frequency: string;
  security_level: string;
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

// --- Alert types ---

export interface AlertAction {
  id: string;
  label: string;
  action_type: string;
  params?: Record<string, unknown>;
}

export interface KillChainStep {
  step_number: number;
  timestamp: string;
  description: string;
  severity: string;
  was_blocked: boolean;
  event_id: string;
}

export interface KillChainNarrative {
  pattern_name: string;
  summary: string;
  steps: KillChainStep[];
  verdict: string;
  outcome: string;
  confidence: number;
}

export interface IntelligentAlert {
  id: string;
  alert_type: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  recommendation: string;
  source_events: string[];
  server_name: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
  dedup_key: string;
  dedup_count: number;
  actions: AlertAction[];
  kill_chain: KillChainNarrative | null;
  ai_summary?: string;
  ai_risk_level?: string;
  ai_confidence?: number;
  ai_recommendation?: string;
}

export interface AlertStats {
  total_active: number;
  dangerous_count: number;
  suspicious_count: number;
  unusual_count: number;
  info_count: number;
  resolved_this_week: number;
  blocked_this_week: number;
  avg_resolution_minutes: number;
}

export interface Recommendation {
  id: string;
  rec_type: string;
  description: string;
  action_label: string;
  action_type: string;
  action_params?: Record<string, unknown>;
  priority: number;
  dismissed: boolean;
}

// --- Humanized Event (from Rust backend humanizer) ---

export interface HumanizedEvent {
  event_id: string;
  timestamp: string;
  server_display_name: string;
  client_name: string | null;
  one_liner: string;
  expanded_explanation: string;
  educational_aside: string | null;
  behavioral_context: string;
  risk_level: string;
  risk_explanation: string;
  action_taken: "Allowed" | "Blocked" | "Prompted" | "AutoBlocked";
  action_reason: string;
  is_notable: boolean;
  correlation_id: string | null;
  kill_chain_id: string | null;
  raw_event: AuditEvent;
}

// --- Correlation types ---

export interface CorrelatedEvent {
  event_id: string;
  timestamp: string;
  description: string;
  match_confidence: number;
  match_reason: string;
}

export interface UncorrelatedEvent {
  event_id: string;
  timestamp: string;
  description: string;
  concern_level: string;
  explanation: string;
}

export interface CoverageAssessment {
  mcp_events_with_match: number;
  mcp_events_without_match: number;
  uncorrelated_count: number;
  coverage_percent: number;
  assessment: string;
}

export interface CorrelationResult {
  mcp_event_id: string;
  correlated_events: CorrelatedEvent[];
  correlation_confidence: number;
  uncorrelated_events: UncorrelatedEvent[];
  coverage: CoverageAssessment;
}

// --- Protection Score types ---

export interface FixAction {
  label: string;
  action_type: string;
  target: string;
  params?: unknown;
}

export interface ScoreFactor {
  id: string;
  name: string;
  description: string;
  max_points: number;
  current_points: number;
  status: string;
  details: string;
  fix_actions: FixAction[];
}

/** Alias used by ScoreBreakdown component. */
export type BackendScoreFactor = ScoreFactor;

export interface ProtectionScore {
  total: number;
  label: string;
  color: string;
  factors: ScoreFactor[];
  computed_at: string;
  change_from_last: number | null;
}

export interface ScoreSnapshot {
  id: number;
  score: number;
  factors_json: string;
  computed_at: string;
}

// --- Tool types (for My Tools / Tool Detail pages) ---

export type TrustLevel = "trusted" | "default" | "untrusted" | "blocked";

export type PermissionAction = "allow" | "deny" | "prompt" | "inherit" | "block";

export interface ServerCapabilities {
  read_files: boolean;
  write_files: boolean;
  execute_commands: boolean;
  network_access: boolean;
  browser_access: boolean;
  can_read_files?: boolean;
  can_write_files?: boolean;
  can_execute?: boolean;
  can_network?: boolean;
}

export interface PermissionState {
  permission: string;
  action: PermissionAction;
  inherited: boolean;
}

export interface PermissionChange {
  permission: string;
  old_action: PermissionAction;
  new_action: PermissionAction;
}

export interface TrustLevelInfo {
  server_name: string;
  trust_level: TrustLevel;
  permissions: PermissionState[];
}

export interface ToolCardData {
  server_name: string;
  client_name: string;
  display_name: string;
  wrapped: boolean;
  status: string;
  trust_level: TrustLevel;
  event_count: number;
  anomaly_score: number;
  capabilities: ServerCapabilities;
  last_activity: string | null;
}

export interface NewToolInfo {
  server_name: string;
  client_name: string;
  client_display_name?: string;
  display_name: string;
  detected_at: string;
  capabilities?: ServerCapabilities;
}

export interface NetworkSummary {
  destinations: string[];
  total_connections: number;
  blocked_connections: number;
}

export interface ActivityPattern {
  peak_hour: number;
  avg_daily_events: number;
  trend: string;
}

export interface ServerSummary {
  server_name: string;
  display_name: string;
  client_name: string;
  trust_level: TrustLevel;
  status: string;
  event_count: number;
  anomaly_score: number;
  tools_count: number;
  total_calls: number;
  last_activity: string | null;
  capabilities: ServerCapabilities;
  permissions: PermissionState[];
  learning_status?: string;
  territory?: string[];
  common_tools?: string[];
  network_summary?: NetworkSummary;
  activity_pattern?: ActivityPattern;
  notable_observations?: string[];
  trust_recommendation?: string;
}

// --- Tauri Event Union ---

export type TauriEvent =
  | { type: "event"; payload: AuditEvent }
  | { type: "prompt"; payload: PendingPrompt }
  | { type: "alert"; payload: { level: string; message: string; details: string } }
  | { type: "status-change"; payload: { daemon_running: boolean } };
