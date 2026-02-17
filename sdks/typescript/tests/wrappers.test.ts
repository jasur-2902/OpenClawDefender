import { describe, it, expect, beforeEach } from 'vitest';
import { ClawDefender } from '../src/client.js';
import { withPermission, withAudit, setSharedClient } from '../src/wrappers.js';
import { MockConnection } from './helpers/mock-server.js';

describe('withPermission', () => {
  let mock: MockConnection;

  beforeEach(() => {
    mock = new MockConnection();
    const client = ClawDefender.withConnection(mock);
    setSharedClient(client);
  });

  it('executes function when permission is granted', async () => {
    const fn = async (path: unknown) => `read ${path}`;
    const wrapped = withPermission(
      { operation: 'read', justification: 'Need to read file' },
      fn,
    );

    const result = await wrapped('/tmp/test.txt');
    expect(result).toBe('read /tmp/test.txt');

    expect(mock.calls).toHaveLength(1);
    expect(mock.calls[0].tool).toBe('requestPermission');
    expect(mock.calls[0].args.resource).toBe('/tmp/test.txt');
  });

  it('throws when permission is denied', async () => {
    mock.responses['requestPermission'] = {
      granted: false,
      scope: 'once',
    };

    const fn = async () => 'should not run';
    const wrapped = withPermission(
      { operation: 'write', justification: 'Writing output' },
      fn,
    );

    await expect(wrapped('/etc/passwd')).rejects.toThrow('Permission denied');
  });

  it('uses targetParam to resolve target from object argument', async () => {
    const fn = async (opts: unknown) => `processed ${(opts as { file: string }).file}`;
    const wrapped = withPermission(
      { operation: 'read', justification: 'Processing', targetParam: 'file' },
      fn,
    );

    await wrapped({ file: '/data/input.csv' });

    expect(mock.calls[0].args.resource).toBe('/data/input.csv');
  });
});

describe('withAudit', () => {
  let mock: MockConnection;

  beforeEach(() => {
    mock = new MockConnection();
    const client = ClawDefender.withConnection(mock);
    setSharedClient(client);
  });

  it('reports success after function executes', async () => {
    const fn = async (url: unknown) => `fetched ${url}`;
    const wrapped = withAudit({ actionType: 'network_request' }, fn);

    const result = await wrapped('https://api.example.com');
    expect(result).toBe('fetched https://api.example.com');

    expect(mock.calls).toHaveLength(1);
    expect(mock.calls[0].tool).toBe('reportAction');
    expect(mock.calls[0].args.result).toBe('success');
    expect(mock.calls[0].args.target).toBe('https://api.example.com');
  });

  it('reports failure when function throws', async () => {
    const fn = async () => {
      throw new Error('connection refused');
    };
    const wrapped = withAudit({ actionType: 'network_request' }, fn);

    await expect(wrapped('https://bad.example.com')).rejects.toThrow(
      'connection refused',
    );

    expect(mock.calls).toHaveLength(1);
    expect(mock.calls[0].tool).toBe('reportAction');
    expect(mock.calls[0].args.result).toBe('failure');
    expect(mock.calls[0].args.details).toEqual({
      error: 'connection refused',
    });
  });

  it('uses targetParam for positional argument', async () => {
    const fn = async (_a: unknown, target: unknown) => `deleted ${target}`;
    const wrapped = withAudit(
      { actionType: 'file_delete', targetParam: '1' },
      fn,
    );

    await wrapped('ignored', '/tmp/old.log');

    expect(mock.calls[0].args.target).toBe('/tmp/old.log');
  });
});
