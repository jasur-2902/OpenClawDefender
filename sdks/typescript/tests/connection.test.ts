import { describe, it, expect } from 'vitest';
import { FailOpenConnection } from '../src/connection.js';
import { MockConnection } from './helpers/mock-server.js';
import type { JsonRpcRequest } from '../src/types.js';

describe('FailOpenConnection', () => {
  it('passes through successful responses', async () => {
    const mock = new MockConnection();
    const conn = new FailOpenConnection(mock);

    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'checkIntent', arguments: {} },
      id: 1,
    };

    const response = await conn.send(request);
    expect(response.result).toBeDefined();
    expect(response.error).toBeUndefined();
  });

  it('returns fail-open checkIntent when connection fails', async () => {
    const mock = new MockConnection();
    mock.shouldFail = true;
    const conn = new FailOpenConnection(mock);

    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'checkIntent', arguments: {} },
      id: 1,
    };

    const response = await conn.send(request);
    expect(response.error).toBeUndefined();

    const result = response.result as {
      content: Array<{ type: string; text: string }>;
    };
    const data = JSON.parse(result.content[0].text);
    expect(data.allowed).toBe(true);
    expect(data.riskLevel).toBe('Low');
    expect(data.explanation).toContain('fail-open');
  });

  it('returns fail-open requestPermission when connection fails', async () => {
    const mock = new MockConnection();
    mock.shouldFail = true;
    const conn = new FailOpenConnection(mock);

    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'requestPermission', arguments: {} },
      id: 2,
    };

    const response = await conn.send(request);
    const result = response.result as {
      content: Array<{ type: string; text: string }>;
    };
    const data = JSON.parse(result.content[0].text);
    expect(data.granted).toBe(true);
    expect(data.scope).toBe('once');
  });

  it('returns fail-open reportAction when connection fails', async () => {
    const mock = new MockConnection();
    mock.shouldFail = true;
    const conn = new FailOpenConnection(mock);

    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'reportAction', arguments: {} },
      id: 3,
    };

    const response = await conn.send(request);
    const result = response.result as {
      content: Array<{ type: string; text: string }>;
    };
    const data = JSON.parse(result.content[0].text);
    expect(data.recorded).toBe(false);
    expect(data.eventId).toBe('fail-open');
  });

  it('returns fail-open getPolicy when connection fails', async () => {
    const mock = new MockConnection();
    mock.shouldFail = true;
    const conn = new FailOpenConnection(mock);

    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'getPolicy', arguments: {} },
      id: 4,
    };

    const response = await conn.send(request);
    const result = response.result as {
      content: Array<{ type: string; text: string }>;
    };
    const data = JSON.parse(result.content[0].text);
    expect(data.rules).toEqual([]);
    expect(data.defaultAction).toBe('allow');
  });

  it('returns generic fail-open for unknown tools', async () => {
    const mock = new MockConnection();
    mock.shouldFail = true;
    const conn = new FailOpenConnection(mock);

    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'unknownTool', arguments: {} },
      id: 5,
    };

    const response = await conn.send(request);
    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
  });
});
