import type {
  GuardOptions,
  GuardStats,
  GuardStatus,
  CheckResult,
  BlockedOperation,
  SuggestedPermissions,
} from './types.js';
import { DaemonConnection } from './connection.js';
import { FallbackEnforcer } from './fallback.js';
import { Monitor } from './monitor.js';
import { NodeHooks } from './hooks.js';

export class AgentGuard {
  private guardId?: string;
  private active = false;
  private options: GuardOptions;
  private connection: DaemonConnection;
  private fallback: FallbackEnforcer | null = null;
  private monitor: Monitor;
  private hooks: NodeHooks | null = null;
  private activatedAt: Date | null = null;
  private operationsAllowed = 0;
  private operationsBlocked = 0;
  private blockedDetails: BlockedOperation[] = [];
  private anomalyAlerts = 0;
  private status: GuardStatus = 'inactive';
  private useFallback = false;

  constructor(options: GuardOptions) {
    this.options = options;
    this.connection = new DaemonConnection();
    this.monitor = new Monitor();
  }

  async activate(opts?: { fallback?: boolean }): Promise<void> {
    if (this.active) return;

    const connected = await this.connection.connect();

    if (connected) {
      const result = await this.connection.registerGuard(this.options);
      if (result) {
        this.guardId = result.guard_id;
        this.active = true;
        this.activatedAt = new Date();
        this.status = 'active';
        this.useFallback = false;
        return;
      }
    }

    // Fall back to embedded enforcement
    if (opts?.fallback !== false) {
      this.fallback = new FallbackEnforcer(this.options);
      this.hooks = new NodeHooks(this.fallback);
      this.hooks.install();
      this.active = true;
      this.activatedAt = new Date();
      this.useFallback = true;
      this.status = { degraded: 'running in embedded mode' };
    } else {
      this.status = { failed: 'could not connect to daemon' };
      throw new Error(
        'AgentGuard: could not connect to ClawDefender daemon and fallback is disabled',
      );
    }
  }

  async deactivate(): Promise<void> {
    if (!this.active) return;

    if (this.hooks) {
      this.hooks.uninstall();
      this.hooks = null;
    }

    if (this.guardId) {
      await this.connection.deregisterGuard(this.guardId);
      this.guardId = undefined;
    }

    this.active = false;
    this.fallback = null;
    this.status = 'inactive';
  }

  async checkAction(action: string, target: string): Promise<CheckResult> {
    if (!this.active) {
      return { allowed: true, reason: 'guard not active' };
    }

    let result: CheckResult;

    if (!this.useFallback && this.guardId) {
      const daemonResult = await this.connection.checkAction(
        this.guardId,
        action,
        target,
      );
      if (daemonResult) {
        result = {
          allowed: daemonResult.allowed,
          reason: daemonResult.reason,
          rule: daemonResult.rule,
        };
      } else if (this.fallback) {
        result = this.fallback.checkAction(action, target);
      } else {
        result = { allowed: true, reason: 'daemon unavailable, no fallback' };
      }
    } else if (this.fallback) {
      result = this.fallback.checkAction(action, target);
    } else {
      result = { allowed: true, reason: 'no enforcer available' };
    }

    // Track stats
    if (result.allowed) {
      this.operationsAllowed++;
    } else {
      this.operationsBlocked++;
      this.blockedDetails.push({
        timestamp: new Date(),
        tool: action,
        target,
        reason: result.reason ?? 'blocked',
      });
    }

    // Record in monitor
    this.monitor.record(action, target, result.allowed, result.reason);

    return result;
  }

  stats(): GuardStats {
    return {
      activatedAt: this.activatedAt,
      operationsAllowed: this.operationsAllowed,
      operationsBlocked: this.operationsBlocked,
      blockedDetails: [...this.blockedDetails],
      anomalyAlerts: this.anomalyAlerts,
      status: this.status,
    };
  }

  isHealthy(): boolean {
    if (!this.active) return false;
    if (this.status === 'active') return true;
    if (typeof this.status === 'object' && 'degraded' in this.status) return true;
    return false;
  }

  suggestPermissions(): SuggestedPermissions {
    return this.monitor.suggestPermissions();
  }

  get blockedCount(): number {
    return this.operationsBlocked;
  }

  get allowedCount(): number {
    return this.operationsAllowed;
  }

  get isActive(): boolean {
    return this.active;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.deactivate();
  }
}
