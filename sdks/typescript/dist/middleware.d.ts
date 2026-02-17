import { ClawDefender } from './client.js';
import type { MiddlewareOptions } from './types.js';
/**
 * MCP tool call handler signature (compatible with @modelcontextprotocol/sdk).
 */
export type ToolCallHandler = (args: Record<string, unknown>) => Promise<unknown>;
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
export declare function clawdefenderMiddleware(options?: MiddlewareOptions & {
    client?: ClawDefender;
}): (toolName: string, handler: ToolCallHandler) => ToolCallHandler;
//# sourceMappingURL=middleware.d.ts.map