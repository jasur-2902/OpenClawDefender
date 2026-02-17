export { AgentGuard } from './guard.js';
export { withGuard, sandboxed } from './wrappers.js';
export { guardMiddleware } from './middleware.js';
export { DaemonConnection } from './connection.js';
export { FallbackEnforcer } from './fallback.js';
export { Monitor } from './monitor.js';
export { NodeHooks } from './hooks.js';
export { detectClawDefender, ensureInstalled } from './installer.js';

export type {
  GuardOptions,
  GuardStats,
  GuardStatus,
  BlockedOperation,
  CheckResult,
  SuggestedPermissions,
  MonitorRecord,
  DaemonGuardResponse,
  DaemonCheckResponse,
  DaemonStatsResponse,
} from './types.js';

export type {
  GuardMiddlewareOptions,
  GuardMiddleware,
} from './middleware.js';

export type {
  ConsentMode,
  InstallerOptions,
  DetectionResult,
} from './installer.js';
