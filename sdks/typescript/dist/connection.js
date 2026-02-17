import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
// ── Stdio Connection ──
export class StdioConnection {
    process = null;
    buffer = '';
    nextId = 1;
    pending = new Map();
    command;
    constructor(command = 'clawdefender') {
        this.command = command;
    }
    ensureProcess() {
        if (this.process && this.process.exitCode === null) {
            return this.process;
        }
        const proc = spawn(this.command, ['serve'], {
            stdio: ['pipe', 'pipe', 'ignore'],
        });
        proc.stdout.on('data', (chunk) => {
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
    drainBuffer() {
        const lines = this.buffer.split('\n');
        this.buffer = lines.pop();
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed)
                continue;
            try {
                const response = JSON.parse(trimmed);
                const pending = this.pending.get(response.id);
                if (pending) {
                    this.pending.delete(response.id);
                    pending.resolve(response);
                }
            }
            catch {
                // Ignore non-JSON lines (e.g. log output)
            }
        }
    }
    async send(request) {
        const proc = this.ensureProcess();
        const id = this.nextId++;
        const req = { ...request, id };
        return new Promise((resolve, reject) => {
            this.pending.set(id, { resolve, reject });
            const data = JSON.stringify(req) + '\n';
            proc.stdin.write(data, (err) => {
                if (err) {
                    this.pending.delete(id);
                    reject(err);
                }
            });
        });
    }
    async close() {
        if (this.process) {
            this.process.kill();
            this.process = null;
        }
        this.pending.clear();
    }
}
// ── HTTP Connection ──
export class HttpConnection {
    url;
    token = null;
    tokenLoaded = false;
    constructor(url = 'http://127.0.0.1:3201') {
        this.url = url.replace(/\/$/, '');
    }
    async loadToken() {
        if (this.tokenLoaded)
            return this.token;
        this.tokenLoaded = true;
        try {
            const tokenPath = join(homedir(), '.local', 'share', 'clawdefender', 'server-token');
            this.token = (await readFile(tokenPath, 'utf-8')).trim();
        }
        catch {
            this.token = null;
        }
        return this.token;
    }
    async send(request) {
        const token = await this.loadToken();
        const headers = {
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
        return (await res.json());
    }
    async close() {
        // Nothing to clean up
    }
}
// ── Auto Connection ──
export class AutoConnection {
    inner = null;
    httpUrl;
    command;
    constructor(httpUrl = 'http://127.0.0.1:3201', command = 'clawdefender') {
        this.httpUrl = httpUrl;
        this.command = command;
    }
    async resolve() {
        if (this.inner)
            return this.inner;
        // Try HTTP first
        const http = new HttpConnection(this.httpUrl);
        try {
            const ping = {
                jsonrpc: '2.0',
                method: 'ping',
                params: {},
                id: 0,
            };
            await http.send(ping);
            this.inner = http;
            return http;
        }
        catch {
            // HTTP unavailable, fall back to stdio
        }
        const stdio = new StdioConnection(this.command);
        this.inner = stdio;
        return stdio;
    }
    async send(request) {
        const conn = await this.resolve();
        return conn.send(request);
    }
    async close() {
        if (this.inner) {
            await this.inner.close();
            this.inner = null;
        }
    }
}
// ── Fail-open wrapper ──
export class FailOpenConnection {
    inner;
    constructor(inner) {
        this.inner = inner;
    }
    async send(request) {
        try {
            return await this.inner.send(request);
        }
        catch (err) {
            console.warn(`[clawdefender] Connection failed, fail-open: ${err instanceof Error ? err.message : String(err)}`);
            return this.failOpenResponse(request);
        }
    }
    failOpenResponse(request) {
        const toolName = request.params.name;
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
    async close() {
        await this.inner.close();
    }
}
//# sourceMappingURL=connection.js.map