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
  source_type?: "os" | "mcp";
  // Fields mirrored from raw_event for direct access
  id: string;
  server_name: string;
  event_type: string;
  tool_name: string | null;
  action: string;
  decision: string;
  resource: string | null;
  details: string;
}

export interface SensorHealth {
  fda_granted: boolean;
  eslogger_available: boolean;
  os_version_ok: boolean;
  daemon_running: boolean;
  events_flowing: boolean;
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
  client_app?: string;
  display_name: string;
  wrapped: boolean;
  is_wrapped?: boolean;
  status: string;
  trust_level: TrustLevel;
  trust_customized?: boolean;
  event_count: number;
  anomaly_score: number;
  capabilities: ServerCapabilities;
  last_activity: string | null;
  scan_findings_count?: number;
  scan_status?: string;
  behavioral_status?: string;
  learning_progress?: number;
  health_warnings?: any[];
  guard_name?: string;
  guard_enabled?: boolean;
  event_count_today?: number;
  blocked_count_today?: number;
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

// --- AI Scan types ---

export interface AiScanProgress {
  scan_id: string;
  status: string;
  playbook_id: string;
  playbook_name: string;
  current_stage: string | null;
  stages_completed: string[];
  stages_total: number;
  findings_count: number;
  tool_calls_used: number;
  elapsed_secs: number;
  estimated_total_secs: number;
  progress_percent: number;
}

export interface AiScanResult {
  scan_id: string;
  playbook_id: string;
  playbook_name: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  duration_secs: number;
  findings: AiScanFinding[];
  evidence_count: number;
  stages_completed: string[];
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  tool_calls_used: number;
  estimated_cost: number;
  summary: string;
}

export interface AiScanFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  evidence_ids: string[];
  remediation_hint: string | null;
  stage: string;
  discovered_at: string;
}

export interface PlaybookSummary {
  id: string;
  name: string;
  description: string;
  stage_count: number;
  estimated_duration_secs: number;
  estimated_cost_usd: number;
}

export interface ScanUserRequest {
  id: string;
  request_id: string;
  question: string;
  scan_id: string;
  context: string;
}

export interface ScanFindingEvent {
  scan_id: string;
  finding_id: string;
  severity: string;
  title: string;
  stage: string;
}

export interface ScanStageCompleteEvent {
  scan_id: string;
  stage_name: string;
  stages_completed: number;
  stages_total: number;
}

export interface ScanCompleteEvent {
  scan_id: string;
  status: string;
  findings_count: number;
  summary: string;
}

export interface ScanRemediation {
  id: string;
  finding_id: string;
  title: string;
  description: string;
  risk_level: string;
  auto_executable: boolean;
  status: string;
  executed_at: string | null;
  reverted_at: string | null;
}

export interface ScanEvidenceItem {
  id: string;
  evidence_type: string;
  source: string;
  content: string;
  collected_at: string;
  tool_call_id: string | null;
}

// --- Investigation types ---

export interface InvestigationProgress {
  investigation_id: string;
  status: string;
  target_summary: string;
  depth: string;
  questions_answered: number;
  questions_total: number;
  tool_calls_count: number;
  max_tool_calls: number;
  elapsed_secs: number;
  findings_count: number;
  current_activity: string;
}

export interface ImpactAssessment {
  data_accessed: string[];
  data_modified: string[];
  data_exfiltrated: boolean;
  blast_radius: string;
  severity: string;
}

export interface InvestigationResult {
  investigation_id: string;
  target_type: string;
  target_id: string;
  target_summary: string;
  what_happened: string;
  why_it_happened: string;
  part_of_larger: string | null;
  impact: ImpactAssessment;
  recommendations: string[];
  related_events: string[];
  evidence_ids: string[];
  verdict: string;
  confidence: number;
  narrative: string;
  total_tool_calls: number;
  estimated_cost_usd: number;
  started_at: string;
  completed_at: string | null;
}

export interface InvestigationIndexEntry {
  id: string;
  target_type: string;
  target_id: string;
  target_summary: string;
  verdict: string;
  confidence: number;
  severity: string;
  servers_involved: string[];
  started_at: string;
  completed_at: string | null;
  narrative_preview: string;
  pinned: boolean;
}

export interface HuntProgress {
  hunt_id: string;
  hunt_type: string;
  status: string;
  patterns_checked: string[];
  findings_count: number;
  tool_calls_count: number;
  elapsed_secs: number;
}

export interface HuntFinding {
  id: string;
  pattern_name: string;
  description: string;
  involved_servers: string[];
  involved_events: string[];
  confidence: number;
  severity: string;
  recommended_investigation: string;
}

export interface HuntResult {
  hunt_id: string;
  hunt_type: string;
  status: string;
  findings: HuntFinding[];
  patterns_checked: string[];
  summary: string;
  estimated_cost_usd: number;
}

export interface TimelineEntry {
  id: string;
  timestamp: string;
  entry_type: string;
  server: string;
  description: string;
  severity: string;
  event_id: string | null;
  is_key_moment: boolean;
  connects_to: string | null;
  stage: string | null;
}

export interface InvestigationTimeline {
  investigation_id: string;
  entries: TimelineEntry[];
  servers_involved: string[];
  narrative_summary: string;
}

export interface SuggestedAction {
  id: string;
  action_type: string;
  description: string;
  preview: string | null;
  requires_approval: boolean;
}

export interface ContextReference {
  ref_type: string;
  ref_id: string;
  label: string;
}

export interface ToolCallInfo {
  tool_name: string;
  description: string;
  success: boolean;
}

export interface AskClawAIResponse {
  mode: string;
  response_text: string;
  conversation_id: string;
  suggested_actions: SuggestedAction[];
  context_references: ContextReference[];
  tool_calls_made: ToolCallInfo[];
}

// --- Phase 5: Proactive Security Agent types ---

export interface ScheduleInfo {
  id: string;
  display_name: string;
  description: string;
  enabled: boolean;
  requires_cloud: boolean;
  interval_minutes: number;
  preferred_time: string | null;
  last_run: string | null;
  next_run: string | null;
  last_status: string | null;
  estimated_cost: number | null;
}

export interface HourlySummary {
  id: string;
  timestamp: string;
  event_volume: string;
  suspicious_count: number;
  new_kill_chain_progress: boolean;
  new_servers_detected: string[];
  anomaly_trends: AnomalyTrend[];
  concerns: string[];
  status: string;
}

export interface AnomalyTrend {
  server_name: string;
  direction: string;
  current_score: number;
  previous_score: number;
}

export interface DailyBrief {
  id: string;
  date: string;
  timestamp: string;
  summary: string;
  notable_events: NotableEvent[];
  trend_observations: string[];
  recommendation: string;
  events_processed: number;
  cost_usd: number;
  skipped_reason: string | null;
}

export interface NotableEvent {
  event_id: string;
  summary: string;
  severity: string;
}

export interface DriftReport {
  id: string;
  server_name: string;
  timestamp: string;
  overall_drift_score: number;
  dimensions: DriftDimension[];
  narrative: string;
  recommended_action: string;
}

export interface DriftDimension {
  drift_type: string;
  score: number;
  description: string;
}

export interface BaselineSummary {
  server_name: string;
  established_at: string;
  last_updated: string;
  tool_count: number;
  path_count: number;
  host_count: number;
  current_drift_score: number | null;
}

export interface AlertGroup {
  id: string;
  primary_alert_id: string;
  primary_summary: string;
  primary_severity: string;
  related_alert_ids: string[];
  count: number;
  first_seen: string;
  last_seen: string;
  group_reason: string;
  narrative: string;
  escalating: boolean;
  status: string;
}

export interface FatigueSuggestion {
  pattern: string;
  dismiss_count: number;
  suggestion_type: string;
  description: string;
  created_at: string;
}

export interface PostureInfo {
  level: string;
  level_name: string;
  color: string;
  reason: string;
  duration_minutes: number;
  auto_adjust_enabled: boolean;
  has_override: boolean;
  on_battery: boolean;
  active_adjustments: PostureAdjustment[];
}

export interface PostureAdjustment {
  parameter: string;
  old_value: string;
  new_value: string;
  reason: string;
}

export interface PostureChange {
  id: string;
  from: string;
  to: string;
  reason: string;
  timestamp: string;
  auto: boolean;
}

export interface SimulationRun {
  id: string;
  timestamp: string;
  results: SimulationResult[];
  overall_score: number;
  gaps: DefenseGap[];
  execution_time_ms: number;
}

export interface SimulationResult {
  scenario_id: string;
  scenario_name: string;
  caught: boolean;
  caught_at_step: number | null;
  total_steps: number;
  detection_method: string | null;
}

export interface DefenseGap {
  scenario_id: string;
  gap_description: string;
  severity: string;
  remediation: string;
  failed_at_step: number;
}

export interface KnowledgeStats {
  total_entries: number;
  server_count: number;
  false_positive_count: number;
  learned_pattern_count: number;
  resolved_incident_count: number;
  storage_size_bytes: number;
  oldest_entry: string | null;
  newest_entry: string | null;
}

export interface ServerKnowledgeSummary {
  server_name: string;
  trust_level: string;
  trust_assessment: string;
  known_behaviors: string[];
  false_positive_count: number;
  investigation_count: number;
  incident_count: number;
  user_trust_signal_count: number;
  first_seen: string;
  last_seen: string;
}

// --- Phase 6: Agent Autonomy & Reporting types ---

export interface AutonomyInfo {
  global_level: string;
  is_locked_down: boolean;
  server_overrides: Record<string, string>;
  stats: AutonomyStats;
}

export interface AutonomyStats {
  global_level: string;
  total_actions: number;
  approved_actions: number;
  denied_actions: number;
  auto_executed: number;
  approval_rate: number;
  days_at_current_level: number;
  countdown_cancellations: number;
}

export interface AgentActionLog {
  id: string;
  timestamp: string;
  action_category: string;
  description: string;
  server_name: string | null;
  risk_level: string;
  permission_result: string;
  user_response: string | null;
  outcome: string | null;
}

export interface ResponsePlaybook {
  id: string;
  name: string;
  description: string;
  trigger: unknown;
  actions: PlaybookAction[];
  enabled: boolean;
  autonomy_required: string;
  is_builtin: boolean;
}

export interface PlaybookAction {
  action_type: string;
  description: string;
  parameters: unknown;
  delay_after_secs: number;
  continue_on_failure: boolean;
  risk_level: string;
}

export interface PlaybookExecution {
  id: string;
  playbook_id: string;
  playbook_name: string;
  triggered_at: string;
  completed_at: string | null;
  trigger_context: string;
  actions_attempted: number;
  actions_executed: number;
  actions_blocked: number;
  status: string;
}

export interface GeneratedReport {
  id: string;
  report_type: string;
  generated_at: string;
  period_start: string | null;
  period_end: string | null;
  format: string;
  file_path: string;
  summary: string;
  size_bytes: number;
}

export interface FeedbackStats {
  triage_override_count: number;
  alert_dismissal_count: number;
  suggestion_approval_rate: number;
  calibration_events: number;
  last_calibration: string | null;
}

export interface SelfAssessment {
  triage_accuracy: number;
  alert_relevance: number;
  suggestion_acceptance: number;
  overall_accuracy: number;
  trend: string;
  areas_for_improvement: string[];
}

export interface DashboardSummary {
  activity_summary: ActivitySummary;
  cost_summary: CostSummaryData;
  accuracy_metrics: AccuracyMetricsData;
  pattern_stats: PatternStatsData;
  audit_summary: AuditSummaryData;
  recent_decisions: DecisionExplanation[];
  generated_at: string;
}

export interface ActivitySummary {
  total: number;
  by_type: Record<string, number>;
  by_server: Record<string, number>;
  last_24h: number;
  last_7d: number;
}

export interface CostSummaryData {
  total_operations: number;
  total_duration_ms: number;
  by_type: Record<string, { count: number; total_duration_ms: number; avg_duration_ms: number }>;
  last_24h_operations: number;
  last_7d_operations: number;
  avg_duration_ms: number;
}

export interface AccuracyMetricsData {
  total_assessments: number;
  correct: number;
  incorrect: number;
  accuracy_rate: number;
  by_type: Record<string, { total: number; correct: number; accuracy_rate: number }>;
  trend: string;
}

export interface PatternStatsData {
  total_learned: number;
  safe_count: number;
  risk_count: number;
  by_category: Record<string, number>;
  by_server: Record<string, number>;
}

export interface AuditSummaryData {
  total_entries: number;
  permissions_requested: number;
  permissions_granted: number;
  permissions_denied: number;
  actions_executed: number;
  actions_blocked: number;
  lockdowns_activated: number;
  level_changes: number;
}

export interface DecisionExplanation {
  id: string;
  timestamp: string;
  decision_type: string;
  input_summary: string;
  reasoning: string[];
  conclusion: string;
  confidence: number;
  factors: DecisionFactorData[];
  server_name: string | null;
}

export interface DecisionFactorData {
  name: string;
  value: string;
  weight: number;
  direction: string;
}

export interface AgentActivity {
  id: string;
  timestamp: string;
  activity_type: string;
  description: string;
  server_name: string | null;
  autonomy_level: string;
  risk_level: string | null;
  outcome: string | null;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  entry_type: string;
  autonomy_level: string;
  action_category: string | null;
  server_name: string | null;
  description: string;
  user_response: string | null;
  result: string | null;
}

export interface ExportResult {
  export_id: string;
  file_path: string;
  size_bytes: number;
  components_included: string[];
  exported_at: string;
}

export interface ImportPreview {
  version: string;
  exported_at: string;
  components: string[];
  warnings: string[];
}

// --- Dual AI Backend Status ---

export interface AiStatus {
  local: LocalStatusInfo;
  cloud: CloudStatusInfo;
  routing: TaskRoutingInfo;
}

export interface LocalStatusInfo {
  active: boolean;
  model_name: string | null;
  model_size: number | null;
  gpu_enabled: boolean;
  status: string | null;
  total_inferences: number;
  avg_latency_ms: number;
}

export interface CloudStatusInfo {
  active: boolean;
  provider: string | null;
  model: string | null;
  key_configured: boolean;
  status: string | null;
}

export interface TaskRoutingInfo {
  fast_tasks: string;
  deep_tasks: string;
}

// --- Routing Preferences ---

export interface RoutingPreferences {
  prefer_local: boolean;
  cloud_auto_escalate: boolean;
  cloud_confirmation: boolean;
  max_cloud_calls_per_hour: number;
}

export interface RateLimitStatus {
  calls_this_hour: number;
  max_per_hour: number;
  remaining: number;
}

// --- Tauri Event Union ---

export type TauriEvent =
  | { type: "event"; payload: AuditEvent }
  | { type: "prompt"; payload: PendingPrompt }
  | { type: "alert"; payload: { level: string; message: string; details: string } }
  | { type: "status-change"; payload: { daemon_running: boolean } };
