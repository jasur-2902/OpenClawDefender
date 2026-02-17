import { ClawDefender } from './client.js';
import type { ActionType, Operation } from './types.js';

let _sharedClient: ClawDefender | null = null;

function getSharedClient(): ClawDefender {
  if (!_sharedClient) {
    _sharedClient = new ClawDefender();
  }
  return _sharedClient;
}

/** Override the shared ClawDefender client used by wrappers. */
export function setSharedClient(client: ClawDefender): void {
  _sharedClient = client;
}

/**
 * Wraps an async function so that a permission request is made before execution.
 * If permission is denied, the function throws instead of executing.
 */
export function withPermission<T>(
  options: {
    operation: Operation;
    justification: string;
    targetParam?: string;
  },
  fn: (...args: unknown[]) => Promise<T>,
): (...args: unknown[]) => Promise<T> {
  return async (...args: unknown[]) => {
    const client = getSharedClient();
    const target = resolveTarget(args, options.targetParam);

    const response = await client.requestPermission({
      resource: target,
      operation: options.operation,
      justification: options.justification,
    });

    if (!response.granted) {
      throw new Error(
        `Permission denied for ${options.operation} on ${target}`,
      );
    }

    return fn(...args);
  };
}

/**
 * Wraps an async function so that the action is reported to ClawDefender after execution.
 */
export function withAudit<T>(
  options: {
    actionType: ActionType;
    targetParam?: string;
  },
  fn: (...args: unknown[]) => Promise<T>,
): (...args: unknown[]) => Promise<T> {
  return async (...args: unknown[]) => {
    const client = getSharedClient();
    const target = resolveTarget(args, options.targetParam);
    let result: T;
    let success = false;

    try {
      result = await fn(...args);
      success = true;
    } catch (err) {
      await client.reportAction({
        description: `${options.actionType} on ${target}`,
        actionType: options.actionType,
        target,
        result: 'failure',
        details: {
          error: err instanceof Error ? err.message : String(err),
        },
      });
      throw err;
    }

    await client.reportAction({
      description: `${options.actionType} on ${target}`,
      actionType: options.actionType,
      target,
      result: success ? 'success' : 'failure',
    });

    return result;
  };
}

function resolveTarget(args: unknown[], targetParam?: string): string {
  if (targetParam !== undefined) {
    // If targetParam is a number string, treat as positional index
    const idx = Number(targetParam);
    if (!isNaN(idx) && idx >= 0 && idx < args.length) {
      return String(args[idx]);
    }
    // If args[0] is an object, look for the key
    if (
      args[0] &&
      typeof args[0] === 'object' &&
      targetParam in (args[0] as Record<string, unknown>)
    ) {
      return String((args[0] as Record<string, unknown>)[targetParam]);
    }
    return targetParam;
  }
  // Default: use first argument as target
  return args.length > 0 ? String(args[0]) : 'unknown';
}
