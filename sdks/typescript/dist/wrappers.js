import { ClawDefender } from './client.js';
let _sharedClient = null;
function getSharedClient() {
    if (!_sharedClient) {
        _sharedClient = new ClawDefender();
    }
    return _sharedClient;
}
/** Override the shared ClawDefender client used by wrappers. */
export function setSharedClient(client) {
    _sharedClient = client;
}
/**
 * Wraps an async function so that a permission request is made before execution.
 * If permission is denied, the function throws instead of executing.
 */
export function withPermission(options, fn) {
    return async (...args) => {
        const client = getSharedClient();
        const target = resolveTarget(args, options.targetParam);
        const response = await client.requestPermission({
            resource: target,
            operation: options.operation,
            justification: options.justification,
        });
        if (!response.granted) {
            throw new Error(`Permission denied for ${options.operation} on ${target}`);
        }
        return fn(...args);
    };
}
/**
 * Wraps an async function so that the action is reported to ClawDefender after execution.
 */
export function withAudit(options, fn) {
    return async (...args) => {
        const client = getSharedClient();
        const target = resolveTarget(args, options.targetParam);
        let result;
        let success = false;
        try {
            result = await fn(...args);
            success = true;
        }
        catch (err) {
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
function resolveTarget(args, targetParam) {
    if (targetParam !== undefined) {
        // If targetParam is a number string, treat as positional index
        const idx = Number(targetParam);
        if (!isNaN(idx) && idx >= 0 && idx < args.length) {
            return String(args[idx]);
        }
        // If args[0] is an object, look for the key
        if (args[0] &&
            typeof args[0] === 'object' &&
            targetParam in args[0]) {
            return String(args[0][targetParam]);
        }
        return targetParam;
    }
    // Default: use first argument as target
    return args.length > 0 ? String(args[0]) : 'unknown';
}
//# sourceMappingURL=wrappers.js.map