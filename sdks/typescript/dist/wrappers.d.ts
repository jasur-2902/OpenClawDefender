import { ClawDefender } from './client.js';
import type { ActionType, Operation } from './types.js';
/** Override the shared ClawDefender client used by wrappers. */
export declare function setSharedClient(client: ClawDefender): void;
/**
 * Wraps an async function so that a permission request is made before execution.
 * If permission is denied, the function throws instead of executing.
 */
export declare function withPermission<T>(options: {
    operation: Operation;
    justification: string;
    targetParam?: string;
}, fn: (...args: unknown[]) => Promise<T>): (...args: unknown[]) => Promise<T>;
/**
 * Wraps an async function so that the action is reported to ClawDefender after execution.
 */
export declare function withAudit<T>(options: {
    actionType: ActionType;
    targetParam?: string;
}, fn: (...args: unknown[]) => Promise<T>): (...args: unknown[]) => Promise<T>;
//# sourceMappingURL=wrappers.d.ts.map