import { describe, it, expect, beforeEach } from 'vitest';
import { ClawDefender } from '../src/client.js';
import { MockConnection } from './helpers/mock-server.js';

describe('ClawDefender client', () => {
  let mock: MockConnection;
  let client: ClawDefender;

  beforeEach(() => {
    mock = new MockConnection();
    client = ClawDefender.withConnection(mock);
  });

  describe('checkIntent', () => {
    it('returns allowed response for safe actions', async () => {
      const result = await client.checkIntent({
        description: 'Read a config file',
        actionType: 'file_read',
        target: '/etc/config.json',
      });

      expect(result.allowed).toBe(true);
      expect(result.riskLevel).toBe('Low');
      expect(result.explanation).toBe('Action is allowed');
      expect(result.policyRule).toBe('default-allow');
    });

    it('returns blocked response when configured', async () => {
      mock.responses['checkIntent'] = {
        allowed: false,
        riskLevel: 'Critical',
        explanation: 'Sensitive file access denied',
        policyRule: 'no-secrets',
        suggestions: ['Use a config file instead'],
      };

      const result = await client.checkIntent({
        description: 'Read secrets',
        actionType: 'file_read',
        target: '/etc/shadow',
      });

      expect(result.allowed).toBe(false);
      expect(result.riskLevel).toBe('Critical');
      expect(result.suggestions).toEqual(['Use a config file instead']);
    });

    it('sends correct MCP tool call', async () => {
      await client.checkIntent({
        description: 'Test action',
        actionType: 'shell_execute',
        target: 'rm -rf /',
        reason: 'testing',
      });

      expect(mock.calls).toHaveLength(1);
      expect(mock.calls[0].tool).toBe('checkIntent');
      expect(mock.calls[0].args).toEqual({
        description: 'Test action',
        actionType: 'shell_execute',
        target: 'rm -rf /',
        reason: 'testing',
      });
    });
  });

  describe('requestPermission', () => {
    it('returns granted permission', async () => {
      const result = await client.requestPermission({
        resource: '/tmp/output.txt',
        operation: 'write',
        justification: 'Need to save results',
      });

      expect(result.granted).toBe(true);
      expect(result.scope).toBe('session');
    });

    it('returns denied permission', async () => {
      mock.responses['requestPermission'] = {
        granted: false,
        scope: 'once',
      };

      const result = await client.requestPermission({
        resource: '/etc/passwd',
        operation: 'write',
        justification: 'Want to modify users',
      });

      expect(result.granted).toBe(false);
    });
  });

  describe('reportAction', () => {
    it('records successful action', async () => {
      const result = await client.reportAction({
        description: 'Wrote output file',
        actionType: 'file_write',
        target: '/tmp/output.txt',
        result: 'success',
      });

      expect(result.recorded).toBe(true);
      expect(result.eventId).toBe('evt-mock-001');
    });

    it('records action with details', async () => {
      await client.reportAction({
        description: 'Network request',
        actionType: 'network_request',
        target: 'https://api.example.com',
        result: 'failure',
        details: { statusCode: 500, body: 'Internal Server Error' },
      });

      expect(mock.calls[0].args.details).toEqual({
        statusCode: 500,
        body: 'Internal Server Error',
      });
    });
  });

  describe('getPolicy', () => {
    it('returns policy rules', async () => {
      const result = await client.getPolicy();

      expect(result.rules).toHaveLength(1);
      expect(result.rules[0].name).toBe('default');
      expect(result.defaultAction).toBe('allow');
    });

    it('sends filter parameters', async () => {
      await client.getPolicy({
        resource: '/tmp/*',
        actionType: 'file_write',
      });

      expect(mock.calls[0].args).toEqual({
        resource: '/tmp/*',
        actionType: 'file_write',
      });
    });
  });

  describe('error handling', () => {
    it('throws on JSON-RPC error response', async () => {
      // Override to return error
      const origSend = mock.send.bind(mock);
      mock.send = async (req) => {
        const resp = await origSend(req);
        return {
          jsonrpc: '2.0' as const,
          error: { code: -32600, message: 'Invalid request' },
          id: resp.id,
        };
      };

      await expect(
        client.checkIntent({
          description: 'test',
          actionType: 'other',
          target: 'test',
        }),
      ).rejects.toThrow('ClawDefender error [-32600]: Invalid request');
    });
  });
});
