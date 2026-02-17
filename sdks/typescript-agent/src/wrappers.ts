import { AgentGuard } from './guard.js';
import type { GuardOptions } from './types.js';

export function withGuard<T>(
  options: Omit<GuardOptions, 'name'>,
  fn: (...args: any[]) => Promise<T>,
): (...args: any[]) => Promise<T> {
  return async (...args: any[]): Promise<T> => {
    const guard = new AgentGuard({
      name: fn.name || 'anonymous',
      ...options,
    });
    await guard.activate({ fallback: true });
    try {
      return await fn(...args);
    } finally {
      await guard.deactivate();
    }
  };
}

export function sandboxed<T>(
  options: { timeout?: number },
  fn: (...args: any[]) => Promise<T>,
): (...args: any[]) => Promise<T> {
  return async (...args: any[]): Promise<T> => {
    const guard = new AgentGuard({
      name: fn.name || 'sandboxed',
      shellPolicy: 'deny',
      networkAllowlist: [],
      blockedPaths: ['/**'],
    });
    await guard.activate({ fallback: true });

    const timeout = options.timeout ?? 30000;

    try {
      const result = await Promise.race([
        fn(...args),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error(`Sandboxed function timed out after ${timeout}ms`)),
            timeout,
          ),
        ),
      ]);
      return result;
    } finally {
      await guard.deactivate();
    }
  };
}
