import type { MonitorRecord, SuggestedPermissions } from './types.js';

export class Monitor {
  private records: MonitorRecord[] = [];

  record(action: string, target: string, allowed: boolean, reason?: string): void {
    this.records.push({
      timestamp: new Date(),
      action,
      target,
      allowed,
      reason,
    });
  }

  getRecords(): ReadonlyArray<MonitorRecord> {
    return this.records;
  }

  clear(): void {
    this.records = [];
  }

  get totalOperations(): number {
    return this.records.length;
  }

  get blockedOperations(): number {
    return this.records.filter((r) => !r.allowed).length;
  }

  suggestPermissions(): SuggestedPermissions {
    const paths = new Set<string>();
    const tools = new Set<string>();
    const hosts = new Set<string>();
    const commands = new Set<string>();

    for (const record of this.records) {
      switch (record.action) {
        case 'file_read':
        case 'file_write':
        case 'file_delete':
          paths.add(record.target);
          break;
        case 'tool_call':
          tools.add(record.target);
          break;
        case 'network_request':
          hosts.add(record.target);
          break;
        case 'shell_execute':
          commands.add(record.target.split(/\s+/)[0] ?? record.target);
          break;
      }
    }

    return {
      allowedPaths: [...paths],
      allowedTools: [...tools],
      networkAllowlist: [...hosts],
      shellCommands: [...commands],
    };
  }
}
