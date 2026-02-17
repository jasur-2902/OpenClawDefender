/** Action types that ClawDefender can evaluate. */
export type ActionType =
  | 'file_read'
  | 'file_write'
  | 'file_delete'
  | 'shell_execute'
  | 'network_request'
  | 'resource_access'
  | 'other';

/** Risk level assigned to an intent check. */
export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';

/** Operation type for permission requests. */
export type Operation = 'read' | 'write' | 'execute' | 'delete' | 'connect';

/** Scope of a granted permission. */
export type PermissionScope = 'once' | 'session' | 'permanent';

/** Result of a reported action. */
export type ActionResult = 'success' | 'failure' | 'partial';

// ── Check Intent ──

export interface CheckIntentRequest {
  description: string;
  actionType: ActionType;
  target: string;
  reason?: string;
}

export interface CheckIntentResponse {
  allowed: boolean;
  riskLevel: RiskLevel;
  explanation: string;
  policyRule: string;
  suggestions?: string[];
}

// ── Request Permission ──

export interface RequestPermissionRequest {
  resource: string;
  operation: Operation;
  justification: string;
  timeoutSeconds?: number;
}

export interface RequestPermissionResponse {
  granted: boolean;
  scope: PermissionScope;
  expiresAt?: string;
}

// ── Report Action ──

export interface ReportActionRequest {
  description: string;
  actionType: ActionType;
  target: string;
  result: ActionResult;
  details?: Record<string, unknown>;
}

export interface ReportActionResponse {
  recorded: boolean;
  eventId: string;
}

// ── Get Policy ──

export interface GetPolicyRequest {
  resource?: string;
  actionType?: ActionType;
  toolName?: string;
}

export interface PolicyRule {
  name: string;
  action: string;
  description: string;
  matchCriteria: Record<string, unknown>;
}

export interface GetPolicyResponse {
  rules: PolicyRule[];
  defaultAction: string;
}

// ── Connection ──

export type ConnectionMode = 'auto' | 'stdio' | 'http';

export interface ClawDefenderOptions {
  mode?: ConnectionMode;
  httpUrl?: string;
  command?: string;
}

// ── MCP JSON-RPC ──

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  method: string;
  params: Record<string, unknown>;
  id: number;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
  id: number;
}

// ── Middleware ──

export interface ToolMiddlewareConfig {
  requirePermission?: boolean;
  checkIntent?: boolean;
  skip?: boolean;
}

export interface MiddlewareOptions {
  autoCheck?: boolean;
  autoReport?: boolean;
  tools?: Record<string, ToolMiddlewareConfig>;
}
