import type { GuardOptions, CheckResult } from './types.js';

function matchPattern(pattern: string, value: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*')
    .replace(/\?/g, '.');
  const regex = new RegExp(`^${escaped}$`);
  return regex.test(value);
}

function matchesAny(patterns: string[], value: string): boolean {
  return patterns.some((p) => matchPattern(p, value));
}

export class FallbackEnforcer {
  private options: GuardOptions;

  constructor(options: GuardOptions) {
    this.options = options;
    console.log(
      `AgentGuard running in embedded mode for agent "${options.name}"`,
    );
  }

  checkAction(action: string, target: string): CheckResult {
    if (this.options.mode === 'monitor') {
      return { allowed: true, reason: 'monitor mode', rule: 'monitor' };
    }

    if (action === 'file_read' || action === 'file_write' || action === 'file_delete') {
      return this.checkPath(action, target);
    }

    if (action === 'network_request') {
      return this.checkNetwork(target);
    }

    if (action === 'shell_execute') {
      return this.checkShell(target);
    }

    if (action === 'tool_call') {
      return this.checkTool(target);
    }

    return { allowed: true, reason: 'no rule matched', rule: 'default-allow' };
  }

  checkPath(action: string, filePath: string): CheckResult {
    const blocked = this.options.blockedPaths ?? [];
    if (blocked.length > 0 && matchesAny(blocked, filePath)) {
      return {
        allowed: false,
        reason: `path "${filePath}" is in blockedPaths`,
        rule: 'blocked-path',
      };
    }

    const allowed = this.options.allowedPaths ?? [];
    if (allowed.length > 0) {
      if (matchesAny(allowed, filePath)) {
        return { allowed: true, reason: 'path in allowedPaths', rule: 'allowed-path' };
      }
      return {
        allowed: false,
        reason: `path "${filePath}" not in allowedPaths`,
        rule: 'allowed-path',
      };
    }

    return { allowed: true, reason: 'no path restrictions', rule: 'default-allow' };
  }

  checkTool(toolName: string): CheckResult {
    const allowed = this.options.allowedTools ?? [];
    if (allowed.length === 0) {
      return { allowed: true, reason: 'no tool restrictions', rule: 'default-allow' };
    }
    if (allowed.includes(toolName)) {
      return { allowed: true, reason: 'tool in allowedTools', rule: 'allowed-tool' };
    }
    return {
      allowed: false,
      reason: `tool "${toolName}" not in allowedTools`,
      rule: 'allowed-tool',
    };
  }

  checkNetwork(host: string): CheckResult {
    const allowlist = this.options.networkAllowlist ?? [];
    if (allowlist.length === 0) {
      return { allowed: true, reason: 'no network restrictions', rule: 'default-allow' };
    }
    if (matchesAny(allowlist, host)) {
      return {
        allowed: true,
        reason: 'host in networkAllowlist',
        rule: 'network-allowlist',
      };
    }
    return {
      allowed: false,
      reason: `host "${host}" not in networkAllowlist`,
      rule: 'network-allowlist',
    };
  }

  checkShell(command: string): CheckResult {
    const policy = this.options.shellPolicy ?? 'deny';
    if (policy === 'deny') {
      return {
        allowed: false,
        reason: 'shell execution denied by policy',
        rule: 'shell-deny',
      };
    }
    if (policy === 'allowlist') {
      const allowed = this.options.allowedCommands ?? [];
      const executable = command.split(/\s+/)[0] ?? '';
      if (allowed.includes(executable)) {
        return {
          allowed: true,
          reason: 'command in allowedCommands',
          rule: 'shell-allowlist',
        };
      }
      return {
        allowed: false,
        reason: `command "${executable}" not in allowedCommands`,
        rule: 'shell-allowlist',
      };
    }
    // 'approve' — allow but flag for review
    return { allowed: true, reason: 'shell requires approval', rule: 'shell-approve' };
  }
}
