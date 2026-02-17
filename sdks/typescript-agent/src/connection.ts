import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type {
  DaemonGuardResponse,
  DaemonCheckResponse,
  DaemonStatsResponse,
  GuardOptions,
} from './types.js';

const DEFAULT_BASE_URL = 'http://127.0.0.1:3202/api/v1';

function getTokenPath(): string {
  const platform = os.platform();
  if (platform === 'win32') {
    const appData = process.env['APPDATA'] ?? path.join(os.homedir(), 'AppData', 'Roaming');
    return path.join(appData, 'clawdefender', 'server-token');
  }
  const dataDir =
    process.env['XDG_DATA_HOME'] ?? path.join(os.homedir(), '.local', 'share');
  return path.join(dataDir, 'clawdefender', 'server-token');
}

function readToken(): string | null {
  try {
    return fs.readFileSync(getTokenPath(), 'utf-8').trim();
  } catch {
    return null;
  }
}

export class DaemonConnection {
  private baseUrl: string;
  private token: string | null = null;
  private connected = false;

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl ?? DEFAULT_BASE_URL;
  }

  async connect(): Promise<boolean> {
    this.token = readToken();
    if (!this.token) {
      return false;
    }
    try {
      const res = await fetch(`${this.baseUrl}/health`, {
        headers: this.headers(),
        signal: AbortSignal.timeout(2000),
      });
      this.connected = res.ok;
      return this.connected;
    } catch {
      this.connected = false;
      return false;
    }
  }

  get isConnected(): boolean {
    return this.connected;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.token) {
      h['Authorization'] = `Bearer ${this.token}`;
    }
    return h;
  }

  async registerGuard(options: GuardOptions): Promise<DaemonGuardResponse | null> {
    if (!this.connected) return null;
    try {
      const res = await fetch(`${this.baseUrl}/guards`, {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify({
          name: options.name,
          allowed_paths: options.allowedPaths ?? [],
          allowed_tools: options.allowedTools ?? [],
          blocked_paths: options.blockedPaths ?? [],
          network_allowlist: options.networkAllowlist ?? [],
          shell_policy: options.shellPolicy ?? 'deny',
          allowed_commands: options.allowedCommands ?? [],
          max_file_size: options.maxFileSize,
          max_files_per_minute: options.maxFilesPerMinute,
          max_network_requests_per_minute: options.maxNetworkRequestsPerMinute,
          mode: options.mode ?? 'enforce',
        }),
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) return null;
      return (await res.json()) as DaemonGuardResponse;
    } catch {
      return null;
    }
  }

  async deregisterGuard(guardId: string): Promise<boolean> {
    if (!this.connected) return false;
    try {
      const res = await fetch(`${this.baseUrl}/guards/${guardId}`, {
        method: 'DELETE',
        headers: this.headers(),
        signal: AbortSignal.timeout(5000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  async checkAction(
    guardId: string,
    action: string,
    target: string,
  ): Promise<DaemonCheckResponse | null> {
    if (!this.connected) return null;
    try {
      const res = await fetch(`${this.baseUrl}/guards/${guardId}/check`, {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify({ action, target }),
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) return null;
      return (await res.json()) as DaemonCheckResponse;
    } catch {
      return null;
    }
  }

  async getStats(guardId: string): Promise<DaemonStatsResponse | null> {
    if (!this.connected) return null;
    try {
      const res = await fetch(`${this.baseUrl}/guards/${guardId}/stats`, {
        headers: this.headers(),
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) return null;
      return (await res.json()) as DaemonStatsResponse;
    } catch {
      return null;
    }
  }
}
