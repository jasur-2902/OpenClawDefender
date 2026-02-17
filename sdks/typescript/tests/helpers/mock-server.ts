import type { Connection } from '../../src/connection.js';
import type { JsonRpcRequest, JsonRpcResponse } from '../../src/types.js';

/**
 * Mock ClawDefender MCP server for testing.
 * Handles tools/call requests and returns predefined responses.
 */
export class MockConnection implements Connection {
  public calls: Array<{ tool: string; args: Record<string, unknown> }> = [];
  public responses: Record<string, unknown> = {};
  public shouldFail = false;
  public failMessage = 'Mock connection failure';

  constructor() {
    this.setDefaults();
  }

  setDefaults(): void {
    this.responses = {
      checkIntent: {
        allowed: true,
        riskLevel: 'Low',
        explanation: 'Action is allowed',
        policyRule: 'default-allow',
      },
      requestPermission: {
        granted: true,
        scope: 'session',
      },
      reportAction: {
        recorded: true,
        eventId: 'evt-mock-001',
      },
      getPolicy: {
        rules: [
          {
            name: 'default',
            action: 'allow',
            description: 'Default allow rule',
            matchCriteria: {},
          },
        ],
        defaultAction: 'allow',
      },
    };
  }

  async send(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    if (this.shouldFail) {
      throw new Error(this.failMessage);
    }

    const params = request.params as { name?: string; arguments?: Record<string, unknown> };
    const toolName = params.name ?? 'unknown';
    const args = params.arguments ?? {};

    this.calls.push({ tool: toolName, args });

    const responseData = this.responses[toolName] ?? {};

    return {
      jsonrpc: '2.0',
      result: {
        content: [
          {
            type: 'text',
            text: JSON.stringify(responseData),
          },
        ],
      },
      id: request.id,
    };
  }

  async close(): Promise<void> {
    // No-op
  }

  reset(): void {
    this.calls = [];
    this.shouldFail = false;
    this.setDefaults();
  }
}
