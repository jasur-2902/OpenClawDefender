/**
 * Test MCP server exercising the full ClawDefender TypeScript SDK.
 *
 * Demonstrates all four SDK checkpoints:
 *   1. getPolicy         -- on startup, query active policy
 *   2. checkIntent       -- before file reads
 *   3. requestPermission -- before shell execution
 *   4. reportAction      -- after every action
 *
 * Graceful degradation: if ClawDefender is unavailable, falls back to allow-all.
 *
 * Run with:
 *     npx tsx test_server.ts
 */

import { readFileSync, readdirSync } from 'fs';
import { execSync } from 'child_process';
import * as readline from 'readline';

// ---------------------------------------------------------------------------
// ClawDefender SDK — graceful degradation
// ---------------------------------------------------------------------------

interface ClawDefenderClient {
  checkIntent(req: {
    description: string;
    action_type: string;
    target: string;
    reason?: string;
  }): Promise<{ allowed: boolean; explanation: string }>;

  requestPermission(req: {
    resource: string;
    operation: string;
    justification: string;
  }): Promise<{ granted: boolean }>;

  reportAction(req: {
    description: string;
    action_type: string;
    target: string;
    result: string;
    details?: Record<string, unknown>;
  }): Promise<{ recorded: boolean; event_id: string }>;

  getPolicy(req?: {
    resource?: string;
    action_type?: string;
    tool_name?: string;
  }): Promise<{ rules: unknown[]; default_action: string }>;

  close(): Promise<void>;
}

let claw: ClawDefenderClient | null = null;
let clawAvailable = false;

async function initClawDefender(): Promise<void> {
  try {
    // Dynamic import to handle missing package gracefully
    const mod = await import('@clawdefender/sdk');
    claw = new mod.ClawDefender({ mode: 'auto' }) as unknown as ClawDefenderClient;
    clawAvailable = true;
  } catch {
    // SDK not installed or ClawDefender not running
    clawAvailable = false;
  }
}

// ---------------------------------------------------------------------------
// Guarded operations
// ---------------------------------------------------------------------------

async function startupPolicyCheck(): Promise<Record<string, unknown>> {
  if (!clawAvailable || !claw) {
    return { status: 'unavailable', default_action: 'allow' };
  }
  try {
    const policy = await claw.getPolicy();
    return {
      status: 'connected',
      rules: policy.rules,
      default_action: policy.default_action,
    };
  } catch (err) {
    return {
      status: 'degraded',
      error: String(err),
      default_action: 'allow',
    };
  }
}

async function guardedFileRead(path: string): Promise<string> {
  // checkIntent
  if (clawAvailable && claw) {
    try {
      const intent = await claw.checkIntent({
        description: `Read file: ${path}`,
        action_type: 'file_read',
        target: path,
        reason: 'Test server file read',
      });
      if (!intent.allowed) {
        return `BLOCKED: ${intent.explanation}`;
      }
    } catch {
      // fail-open
    }
  }

  // Perform action
  let content: string;
  let resultStatus: string;
  try {
    content = readFileSync(path, 'utf-8');
    resultStatus = 'success';
  } catch (err) {
    content = `Error: ${err}`;
    resultStatus = 'failure';
  }

  // reportAction
  if (clawAvailable && claw) {
    try {
      await claw.reportAction({
        description: `Read file: ${path}`,
        action_type: 'file_read',
        target: path,
        result: resultStatus,
      });
    } catch {
      // fail-open
    }
  }

  return content;
}

async function guardedShellExecute(command: string): Promise<string> {
  // requestPermission
  if (clawAvailable && claw) {
    try {
      const perm = await claw.requestPermission({
        resource: command,
        operation: 'execute',
        justification: `Test server needs to run: ${command}`,
      });
      if (!perm.granted) {
        return 'PERMISSION_DENIED';
      }
    } catch {
      // fail-open
    }
  }

  // Execute
  let output: string;
  let resultStatus: string;
  try {
    output = execSync(command, { timeout: 10000 }).toString();
    resultStatus = 'success';
  } catch (err) {
    output = `Error: ${err}`;
    resultStatus = 'failure';
  }

  // reportAction
  if (clawAvailable && claw) {
    try {
      await claw.reportAction({
        description: `Shell execute: ${command}`,
        action_type: 'shell_execute',
        target: command,
        result: resultStatus,
        details: { output_length: output.length },
      });
    } catch {
      // fail-open
    }
  }

  return output;
}

// ---------------------------------------------------------------------------
// JSON-RPC server over stdio
// ---------------------------------------------------------------------------

interface JsonRpcRequest {
  jsonrpc: string;
  id?: number | string;
  method: string;
  params?: Record<string, unknown>;
}

async function handleRequest(
  request: JsonRpcRequest,
): Promise<Record<string, unknown>> {
  const { method, params = {}, id } = request;

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: { listChanged: false } },
        serverInfo: {
          name: 'clawdefender-test-server-typescript',
          version: '0.5.0',
        },
      },
    };
  }

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        tools: [
          {
            name: 'read_file',
            description: 'Read file contents',
            inputSchema: {
              type: 'object',
              properties: { path: { type: 'string' } },
              required: ['path'],
            },
          },
          {
            name: 'run_command',
            description: 'Run a shell command',
            inputSchema: {
              type: 'object',
              properties: { command: { type: 'string' } },
              required: ['command'],
            },
          },
        ],
      },
    };
  }

  if (method === 'tools/call') {
    const toolName = params.name as string;
    const args = (params.arguments ?? {}) as Record<string, string>;

    if (toolName === 'read_file') {
      const content = await guardedFileRead(args.path ?? '');
      return {
        jsonrpc: '2.0',
        id,
        result: { content: [{ type: 'text', text: content }] },
      };
    }

    if (toolName === 'run_command') {
      const output = await guardedShellExecute(args.command ?? '');
      return {
        jsonrpc: '2.0',
        id,
        result: { content: [{ type: 'text', text: output }] },
      };
    }

    return {
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Unknown tool: ${toolName}` },
    };
  }

  if (method === 'ping') {
    return { jsonrpc: '2.0', id, result: {} };
  }

  return {
    jsonrpc: '2.0',
    id,
    error: { code: -32601, message: `Method not found: ${method}` },
  };
}

async function main(): Promise<void> {
  await initClawDefender();

  // Startup policy check
  const policy = await startupPolicyCheck();
  process.stderr.write(
    JSON.stringify({ type: 'startup', policy }) + '\n',
  );

  const rl = readline.createInterface({ input: process.stdin });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let request: JsonRpcRequest;
    try {
      request = JSON.parse(trimmed);
    } catch {
      continue;
    }

    // Skip notifications (no id)
    if (request.id === undefined) continue;

    const response = await handleRequest(request);
    process.stdout.write(JSON.stringify(response) + '\n');
  }
}

main().catch(console.error);
