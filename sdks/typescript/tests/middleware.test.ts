import { describe, it, expect, beforeEach } from 'vitest';
import { ClawDefender } from '../src/client.js';
import { clawdefenderMiddleware } from '../src/middleware.js';
import { MockConnection } from './helpers/mock-server.js';

describe('clawdefenderMiddleware', () => {
  let mock: MockConnection;
  let client: ClawDefender;

  beforeEach(() => {
    mock = new MockConnection();
    client = ClawDefender.withConnection(mock);
  });

  it('checks intent and reports action by default', async () => {
    const guard = clawdefenderMiddleware({ client });

    const handler = async (args: Record<string, unknown>) => ({
      content: [{ type: 'text', text: `Read ${args['path']}` }],
    });

    const guarded = guard('readFile', handler);
    const result = await guarded({ path: '/tmp/test.txt' });

    expect(result).toEqual({
      content: [{ type: 'text', text: 'Read /tmp/test.txt' }],
    });

    // Should have called checkIntent + reportAction
    expect(mock.calls).toHaveLength(2);
    expect(mock.calls[0].tool).toBe('checkIntent');
    expect(mock.calls[1].tool).toBe('reportAction');
  });

  it('blocks tool call when intent is denied', async () => {
    mock.responses['checkIntent'] = {
      allowed: false,
      riskLevel: 'Critical',
      explanation: 'Action blocked by policy',
      policyRule: 'deny-all',
    };

    const guard = clawdefenderMiddleware({ client });

    const handler = async () => ({ content: [{ type: 'text', text: 'ok' }] });
    const guarded = guard('deleteFile', handler);
    const result = await guarded({ path: '/etc/passwd' }) as {
      content: Array<{ type: string; text: string }>;
      isError: boolean;
    };

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Blocked by ClawDefender');

    // Should only have called checkIntent, not the handler or reportAction
    expect(mock.calls).toHaveLength(1);
    expect(mock.calls[0].tool).toBe('checkIntent');
  });

  it('skips checks for skipped tools', async () => {
    const guard = clawdefenderMiddleware({
      client,
      tools: { ping: { skip: true } },
    });

    const handler = async () => 'pong';
    const guarded = guard('ping', handler);
    const result = await guarded({});

    expect(result).toBe('pong');
    expect(mock.calls).toHaveLength(0);
  });

  it('requests permission when requirePermission is set', async () => {
    const guard = clawdefenderMiddleware({
      client,
      tools: { dangerousTool: { requirePermission: true } },
    });

    const handler = async () => ({ content: [{ type: 'text', text: 'done' }] });
    const guarded = guard('dangerousTool', handler);
    await guarded({ target: 'production-db' });

    const toolNames = mock.calls.map((c) => c.tool);
    expect(toolNames).toContain('checkIntent');
    expect(toolNames).toContain('requestPermission');
    expect(toolNames).toContain('reportAction');
  });

  it('denies tool call when permission is not granted', async () => {
    mock.responses['requestPermission'] = {
      granted: false,
      scope: 'once',
    };

    const guard = clawdefenderMiddleware({
      client,
      tools: { dangerousTool: { requirePermission: true } },
    });

    const handler = async () => ({ content: [{ type: 'text', text: 'done' }] });
    const guarded = guard('dangerousTool', handler);
    const result = await guarded({ target: 'production-db' }) as {
      content: Array<{ type: string; text: string }>;
      isError: boolean;
    };

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Permission denied');
  });

  it('reports failure when handler throws', async () => {
    const guard = clawdefenderMiddleware({ client });

    const handler = async () => {
      throw new Error('disk full');
    };

    const guarded = guard('writeFile', handler);

    await expect(guarded({ path: '/tmp/big.bin' })).rejects.toThrow('disk full');

    // Should have checkIntent + reportAction (failure)
    expect(mock.calls).toHaveLength(2);
    expect(mock.calls[1].tool).toBe('reportAction');
    expect(mock.calls[1].args.result).toBe('failure');
  });

  it('disables auto-check when autoCheck is false', async () => {
    const guard = clawdefenderMiddleware({
      client,
      autoCheck: false,
      autoReport: false,
    });

    const handler = async () => 'result';
    const guarded = guard('someTool', handler);
    await guarded({});

    expect(mock.calls).toHaveLength(0);
  });

  it('infers action type from tool name', async () => {
    const guard = clawdefenderMiddleware({ client });

    const handler = async () => 'ok';

    await guard('executeShellCommand', handler)({});
    expect(mock.calls[0].args.actionType).toBe('shell_execute');

    mock.reset();
    await guard('fetchData', handler)({});
    expect(mock.calls[0].args.actionType).toBe('network_request');

    mock.reset();
    await guard('deleteRecord', handler)({});
    expect(mock.calls[0].args.actionType).toBe('file_delete');
  });
});
