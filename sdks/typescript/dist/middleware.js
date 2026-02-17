import { ClawDefender } from './client.js';
/**
 * Creates a tool handler wrapper that integrates ClawDefender checks.
 *
 * Since the MCP SDK does not expose a formal middleware interface,
 * this function wraps individual tool handlers with intent checking,
 * permission requests, and action reporting.
 *
 * Usage:
 * ```ts
 * const guard = clawdefenderMiddleware({ autoCheck: true, autoReport: true });
 * server.setRequestHandler(CallToolRequestSchema, async (request) => {
 *   const toolName = request.params.name;
 *   const handler = myToolHandlers[toolName];
 *   const guarded = guard(toolName, handler);
 *   return guarded(request.params.arguments ?? {});
 * });
 * ```
 */
export function clawdefenderMiddleware(options) {
    const autoCheck = options?.autoCheck ?? true;
    const autoReport = options?.autoReport ?? true;
    const toolConfigs = options?.tools ?? {};
    const client = options?.client ?? new ClawDefender();
    return (toolName, handler) => {
        const config = toolConfigs[toolName];
        if (config?.skip) {
            return handler;
        }
        return async (args) => {
            const target = String(args['target'] ?? args['path'] ?? args['url'] ?? toolName);
            const actionType = inferActionType(toolName);
            // Check intent
            if (autoCheck || config?.checkIntent) {
                const check = await client.checkIntent({
                    description: `Tool call: ${toolName}`,
                    actionType,
                    target,
                });
                if (!check.allowed) {
                    return {
                        content: [
                            {
                                type: 'text',
                                text: `Blocked by ClawDefender: ${check.explanation}`,
                            },
                        ],
                        isError: true,
                    };
                }
            }
            // Request permission if configured
            if (config?.requirePermission) {
                const perm = await client.requestPermission({
                    resource: target,
                    operation: 'execute',
                    justification: `Tool call: ${toolName}`,
                });
                if (!perm.granted) {
                    return {
                        content: [
                            {
                                type: 'text',
                                text: `Permission denied for ${toolName} on ${target}`,
                            },
                        ],
                        isError: true,
                    };
                }
            }
            // Execute the tool
            let result;
            let success = true;
            try {
                result = await handler(args);
            }
            catch (err) {
                success = false;
                if (autoReport) {
                    await client.reportAction({
                        description: `Tool call: ${toolName}`,
                        actionType,
                        target,
                        result: 'failure',
                        details: {
                            error: err instanceof Error ? err.message : String(err),
                        },
                    });
                }
                throw err;
            }
            // Report action
            if (autoReport) {
                await client.reportAction({
                    description: `Tool call: ${toolName}`,
                    actionType,
                    target,
                    result: success ? 'success' : 'failure',
                });
            }
            return result;
        };
    };
}
function inferActionType(toolName) {
    const lower = toolName.toLowerCase();
    if (lower.includes('read') || lower.includes('get') || lower.includes('list'))
        return 'file_read';
    if (lower.includes('write') || lower.includes('create') || lower.includes('update'))
        return 'file_write';
    if (lower.includes('delete') || lower.includes('remove'))
        return 'file_delete';
    if (lower.includes('exec') || lower.includes('run') || lower.includes('shell'))
        return 'shell_execute';
    if (lower.includes('fetch') || lower.includes('request') || lower.includes('http'))
        return 'network_request';
    return 'other';
}
//# sourceMappingURL=middleware.js.map