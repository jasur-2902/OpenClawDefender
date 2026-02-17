import { spawn, type ChildProcess } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { JsonRpcRequest, JsonRpcResponse } from './types.js';

export interface Connection {
  send(request: JsonRpcRequest): Promise<JsonRpcResponse>;
  close(): Promise<void>;
}

// ── Stdio Connection ──

export class StdioConnection implements Connection {
  private process: ChildProcess | null = null;
  private buffer = '';
  private nextId = 1;
  private pending = new Map<
    number,
    { resolve: (v: JsonRpcResponse) => void; reject: (e: Error) => void }
  >();
  private command: string;

  constructor(command = 'clawdefender') {
    this.command = command;
  }

  private ensureProcess(): ChildProcess {
    if (this.process && this.process.exitCode === null) {
      return this.process;
    }

    const proc = spawn(this.command, ['serve'], {
      stdio: ['pipe', 'pipe', 'ignore'],
    });

    proc.stdout!.on('data', (chunk: Buffer) => {
      this.buffer += chunk.toString();
      this.drainBuffer();
    });

    proc.on('error', (err) => {
      for (const p of this.pending.values()) {
        p.reject(err);
      }
      this.pending.clear();
    });

    proc.on('exit', () => {
      for (const p of this.pending.values()) {
        p.reject(new Error('ClawDefender process exited'));
      }
      this.pending.clear();
    });

    this.process = proc;
    return proc;
  }

  private drainBuffer(): void {
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop()!;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const response = JSON.parse(trimmed) as JsonRpcResponse;
        const pending = this.pending.get(response.id);
        if (pending) {
          this.pending.delete(response.id);
          pending.resolve(response);
        }
      } catch {
        // Ignore non-JSON lines (e.g. log output)
      }
    }
  }

  async send(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    const proc = this.ensureProcess();
    const id = this.nextId++;
    const req = { ...request, id };

    return new Promise<JsonRpcResponse>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      const data = JSON.stringify(req) + '\n';
      proc.stdin!.write(data, (err) => {
        if (err) {
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  async close(): Promise<void> {
    if (this.process) {
      this.process.kill();
      this.process = null;
    }
    this.pending.clear();
  }
}

// ── HTTP Connection ──

export class HttpConnection implements Connection {
  private url: string;
  private token: string | null = null;
  private tokenLoaded = false;

  constructor(url = 'http://127.0.0.1:3201') {
    this.url = url.replace(/\/$/, '');
  }

  private async loadToken(): Promise<string | null> {
    if (this.tokenLoaded) return this.token;
    this.tokenLoaded = true;
    try {
      const tokenPath = join(
        homedir(),
        '.local',
        'share',
        'clawdefender',
        'server-token',
      );
      this.token = (await readFile(tokenPath, 'utf-8')).trim();
    } catch {
      this.token = null;
    }
    return this.token;
  }

  async send(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    const token = await this.loadToken();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${this.url}/rpc`, {
      method: 'POST',
      headers,
      body: JSON.stringify(request),
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }

    return (await res.json()) as JsonRpcResponse;
  }

  async close(): Promise<void> {
    // Nothing to clean up
  }
}

// ── Auto Connection ──

export class AutoConnection implements Connection {
  private inner: Connection | null = null;
  private httpUrl: string;
  private command: string;

  constructor(httpUrl = 'http://127.0.0.1:3201', command = 'clawdefender') {
    this.httpUrl = httpUrl;
    this.command = command;
  }

  private async resolve(): Promise<Connection> {
    if (this.inner) return this.inner;

    // Try HTTP first
    const http = new HttpConnection(this.httpUrl);
    try {
      const ping: JsonRpcRequest = {
        jsonrpc: '2.0',
        method: 'ping',
        params: {},
        id: 0,
      };
      await http.send(ping);
      this.inner = http;
      return http;
    } catch {
      // HTTP unavailable, fall back to stdio
    }

    const stdio = new StdioConnection(this.command);
    this.inner = stdio;
    return stdio;
  }

  async send(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    const conn = await this.resolve();
    return conn.send(request);
  }

  async close(): Promise<void> {
    if (this.inner) {
      await this.inner.close();
      this.inner = null;
    }
  }
}

// ── Fail-open wrapper ──

export class FailOpenConnection implements Connection {
  constructor(private inner: Connection) {}

  async send(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    try {
      return await this.inner.send(request);
    } catch (err) {
      console.warn(
        `[clawdefender] Connection failed, fail-open: ${err instanceof Error ? err.message : String(err)}`,
      );
      return this.failOpenResponse(request);
    }
  }

  private failOpenResponse(request: JsonRpcRequest): JsonRpcResponse {
    const toolName = (request.params as { name?: string }).name;

    if (toolName === 'checkIntent') {
      return {
        jsonrpc: '2.0',
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                allowed: true,
                riskLevel: 'Low',
                explanation: 'ClawDefender unavailable — fail-open',
                policyRule: 'fail-open',
              }),
            },
          ],
        },
        id: request.id,
      };
    }

    if (toolName === 'requestPermission') {
      return {
        jsonrpc: '2.0',
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                granted: true,
                scope: 'once',
              }),
            },
          ],
        },
        id: request.id,
      };
    }

    if (toolName === 'reportAction') {
      return {
        jsonrpc: '2.0',
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                recorded: false,
                eventId: 'fail-open',
              }),
            },
          ],
        },
        id: request.id,
      };
    }

    if (toolName === 'getPolicy') {
      return {
        jsonrpc: '2.0',
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                rules: [],
                defaultAction: 'allow',
              }),
            },
          ],
        },
        id: request.id,
      };
    }

    return {
      jsonrpc: '2.0',
      result: {
        content: [{ type: 'text', text: '{}' }],
      },
      id: request.id,
    };
  }

  async close(): Promise<void> {
    await this.inner.close();
  }
}
