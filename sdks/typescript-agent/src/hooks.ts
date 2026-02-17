import type { FallbackEnforcer } from './fallback.js';

type PatchedModule = {
  _original?: Record<string, Function>;
  [key: string]: unknown;
};

export class NodeHooks {
  private enforcer: FallbackEnforcer;
  private originals: Map<string, Map<string, Function>> = new Map();
  private installed = false;

  constructor(enforcer: FallbackEnforcer) {
    this.enforcer = enforcer;
  }

  install(): void {
    if (this.installed) return;
    this.installed = true;
    this.hookFs();
    this.hookHttp();
    this.hookChildProcess();
  }

  uninstall(): void {
    if (!this.installed) return;
    this.installed = false;
    this.restoreModule('fs');
    this.restoreModule('http');
    this.restoreModule('https');
    this.restoreModule('child_process');
  }

  private patchFunction(
    moduleName: string,
    mod: PatchedModule,
    fnName: string,
    wrapper: (original: Function, ...args: unknown[]) => unknown,
  ): void {
    if (!this.originals.has(moduleName)) {
      this.originals.set(moduleName, new Map());
    }
    const original = mod[fnName];
    if (typeof original !== 'function') return;

    this.originals.get(moduleName)!.set(fnName, original);
    (mod as Record<string, unknown>)[fnName] = function (
      this: unknown,
      ...args: unknown[]
    ) {
      return wrapper(original.bind(this), ...args);
    };
  }

  private restoreModule(moduleName: string): void {
    const saved = this.originals.get(moduleName);
    if (!saved) return;

    let mod: PatchedModule;
    try {
      mod = require(moduleName) as PatchedModule;
    } catch {
      return;
    }
    for (const [fnName, original] of saved) {
      (mod as Record<string, unknown>)[fnName] = original;
    }
    this.originals.delete(moduleName);
  }

  private hookFs(): void {
    let fsMod: PatchedModule;
    try {
      fsMod = require('fs') as PatchedModule;
    } catch {
      return;
    }

    const enforcer = this.enforcer;

    for (const fn of ['readFile', 'readFileSync']) {
      this.patchFunction('fs', fsMod, fn, (original, ...args) => {
        const filePath = String(args[0]);
        const result = enforcer.checkPath('file_read', filePath);
        if (!result.allowed) {
          throw new Error(
            `AgentGuard blocked file read: ${result.reason}`,
          );
        }
        return original(...args);
      });
    }

    for (const fn of ['writeFile', 'writeFileSync']) {
      this.patchFunction('fs', fsMod, fn, (original, ...args) => {
        const filePath = String(args[0]);
        const result = enforcer.checkPath('file_write', filePath);
        if (!result.allowed) {
          throw new Error(
            `AgentGuard blocked file write: ${result.reason}`,
          );
        }
        return original(...args);
      });
    }

    for (const fn of ['unlink', 'unlinkSync']) {
      this.patchFunction('fs', fsMod, fn, (original, ...args) => {
        const filePath = String(args[0]);
        const result = enforcer.checkPath('file_delete', filePath);
        if (!result.allowed) {
          throw new Error(
            `AgentGuard blocked file delete: ${result.reason}`,
          );
        }
        return original(...args);
      });
    }
  }

  private hookHttp(): void {
    const enforcer = this.enforcer;

    for (const moduleName of ['http', 'https'] as const) {
      let mod: PatchedModule;
      try {
        mod = require(moduleName) as PatchedModule;
      } catch {
        continue;
      }

      this.patchFunction(moduleName, mod, 'request', (original, ...args) => {
        let host = '';
        const first = args[0];
        if (typeof first === 'string') {
          try {
            host = new URL(first).hostname;
          } catch {
            host = first;
          }
        } else if (first && typeof first === 'object') {
          host = String(
            (first as Record<string, unknown>)['hostname'] ??
              (first as Record<string, unknown>)['host'] ??
              '',
          );
        }

        if (host) {
          const result = enforcer.checkNetwork(host);
          if (!result.allowed) {
            throw new Error(
              `AgentGuard blocked network request to "${host}": ${result.reason}`,
            );
          }
        }
        return original(...args);
      });
    }
  }

  private hookChildProcess(): void {
    let cpMod: PatchedModule;
    try {
      cpMod = require('child_process') as PatchedModule;
    } catch {
      return;
    }

    const enforcer = this.enforcer;

    for (const fn of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync']) {
      this.patchFunction('child_process', cpMod, fn, (original, ...args) => {
        const command = String(args[0]);
        const result = enforcer.checkShell(command);
        if (!result.allowed) {
          throw new Error(
            `AgentGuard blocked shell execution: ${result.reason}`,
          );
        }
        return original(...args);
      });
    }
  }
}
