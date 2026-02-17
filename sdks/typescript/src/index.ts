// Types
export type {
  ActionType,
  RiskLevel,
  Operation,
  PermissionScope,
  ActionResult,
  CheckIntentRequest,
  CheckIntentResponse,
  RequestPermissionRequest,
  RequestPermissionResponse,
  ReportActionRequest,
  ReportActionResponse,
  GetPolicyRequest,
  GetPolicyResponse,
  PolicyRule,
  ClawDefenderOptions,
  ConnectionMode,
  MiddlewareOptions,
  ToolMiddlewareConfig,
  JsonRpcRequest,
  JsonRpcResponse,
} from './types.js';

// Schemas
export {
  ActionTypeSchema,
  RiskLevelSchema,
  OperationSchema,
  PermissionScopeSchema,
  ActionResultSchema,
  CheckIntentRequestSchema,
  CheckIntentResponseSchema,
  RequestPermissionRequestSchema,
  RequestPermissionResponseSchema,
  ReportActionRequestSchema,
  ReportActionResponseSchema,
  GetPolicyRequestSchema,
  GetPolicyResponseSchema,
  PolicyRuleSchema,
} from './schemas.js';

// Client
export { ClawDefender } from './client.js';

// Connection
export type { Connection } from './connection.js';
export {
  StdioConnection,
  HttpConnection,
  AutoConnection,
  FailOpenConnection,
} from './connection.js';

// Middleware
export { clawdefenderMiddleware } from './middleware.js';
export type { ToolCallHandler } from './middleware.js';

// Wrappers
export { withPermission, withAudit, setSharedClient } from './wrappers.js';
