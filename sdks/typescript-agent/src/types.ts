export interface GuardOptions {
  name: string;
  allowedPaths?: string[];
  allowedTools?: string[];
  blockedPaths?: string[];
  networkAllowlist?: string[];
  shellPolicy?: 'deny' | 'allowlist' | 'approve';
  allowedCommands?: string[];
  maxFileSize?: number;
  maxFilesPerMinute?: number;
  maxNetworkRequestsPerMinute?: number;
  mode?: 'enforce' | 'monitor';
}

export interface GuardStats {
  activatedAt: Date | null;
  operationsAllowed: number;
  operationsBlocked: number;
  blockedDetails: BlockedOperation[];
  anomalyAlerts: number;
  status: GuardStatus;
}

export interface BlockedOperation {
  timestamp: Date;
  tool: string;
  target: string;
  reason: string;
}

export type GuardStatus =
  | 'inactive'
  | 'active'
  | { degraded: string }
  | { failed: string };

export interface CheckResult {
  allowed: boolean;
  reason?: string;
  rule?: string;
}

export interface SuggestedPermissions {
  allowedPaths: string[];
  allowedTools: string[];
  networkAllowlist: string[];
  shellCommands: string[];
}

export interface MonitorRecord {
  timestamp: Date;
  action: string;
  target: string;
  allowed: boolean;
  reason?: string;
}

export interface DaemonGuardResponse {
  guard_id: string;
  status: string;
}

export interface DaemonCheckResponse {
  allowed: boolean;
  reason?: string;
  rule?: string;
}

export interface DaemonStatsResponse {
  operations_allowed: number;
  operations_blocked: number;
  anomaly_alerts: number;
  blocked_details: Array<{
    timestamp: string;
    tool: string;
    target: string;
    reason: string;
  }>;
}
