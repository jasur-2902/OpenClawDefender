import { AgentGuard } from './guard.js';
import type { CheckResult } from './types.js';

export interface GuardMiddlewareOptions {
  allowedPaths?: string[];
  shellPolicy?: 'deny' | 'allowlist' | 'approve';
  networkAllowlist?: string[];
  allowedTools?: string[];
  allowedCommands?: string[];
  blockedPaths?: string[];
}

export interface GuardMiddleware {
  name: string;
  initialize(): Promise<void>;
  beforeToolCall(
    toolName: string,
    args: Record<string, unknown>,
  ): Promise<CheckResult>;
  shutdown(): Promise<void>;
}

export function guardMiddleware(options: GuardMiddlewareOptions): GuardMiddleware {
  let guard: AgentGuard | null = null;

  return {
    name: 'clawdefender-guard',

    async initialize(): Promise<void> {
      guard = new AgentGuard({
        name: 'mcp-server-guard',
        allowedPaths: options.allowedPaths,
        shellPolicy: options.shellPolicy,
        networkAllowlist: options.networkAllowlist,
        allowedTools: options.allowedTools,
        allowedCommands: options.allowedCommands,
        blockedPaths: options.blockedPaths,
      });
      await guard.activate({ fallback: true });
    },

    async beforeToolCall(
      toolName: string,
      args: Record<string, unknown>,
    ): Promise<CheckResult> {
      if (!guard) {
        return { allowed: true, reason: 'guard not initialized' };
      }

      // Check tool permission
      const toolCheck = await guard.checkAction('tool_call', toolName);
      if (!toolCheck.allowed) {
        return toolCheck;
      }

      // Infer additional checks from args
      const target = args['path'] ?? args['file'] ?? args['url'] ?? args['command'];
      if (typeof target === 'string') {
        if (args['path'] || args['file']) {
          return guard.checkAction('file_write', target);
        }
        if (args['url']) {
          try {
            const host = new URL(target).hostname;
            return guard.checkAction('network_request', host);
          } catch {
            return guard.checkAction('network_request', target);
          }
        }
        if (args['command']) {
          return guard.checkAction('shell_execute', target);
        }
      }

      return { allowed: true, reason: 'no specific check needed' };
    },

    async shutdown(): Promise<void> {
      if (guard) {
        await guard.deactivate();
        guard = null;
      }
    },
  };
}
