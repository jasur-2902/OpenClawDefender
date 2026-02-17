import {
  AutoConnection,
  FailOpenConnection,
  HttpConnection,
  StdioConnection,
  type Connection,
} from './connection.js';
import {
  CheckIntentResponseSchema,
  GetPolicyResponseSchema,
  ReportActionResponseSchema,
  RequestPermissionResponseSchema,
} from './schemas.js';
import type {
  CheckIntentRequest,
  CheckIntentResponse,
  ClawDefenderOptions,
  GetPolicyRequest,
  GetPolicyResponse,
  JsonRpcRequest,
  ReportActionRequest,
  ReportActionResponse,
  RequestPermissionRequest,
  RequestPermissionResponse,
} from './types.js';

const MAX_FIELD_LENGTH = 4096;
const BIDI_REGEX =
  /[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f]/;

function validateStr(name: string, value: string): void {
  if (typeof value !== 'string') {
    throw new Error(`Parameter '${name}' must be a string`);
  }
  if (value.length > MAX_FIELD_LENGTH) {
    throw new Error(
      `Parameter '${name}' exceeds maximum length (${value.length} > ${MAX_FIELD_LENGTH})`,
    );
  }
  if (value.includes('\0')) {
    throw new Error(`Parameter '${name}' contains null byte`);
  }
  if (BIDI_REGEX.test(value)) {
    throw new Error(
      `Parameter '${name}' contains Unicode bidirectional control character`,
    );
  }
}

export class ClawDefender {
  private connection: Connection;
  private nextId = 1;

  constructor(options?: ClawDefenderOptions) {
    const mode = options?.mode ?? 'auto';
    const httpUrl = options?.httpUrl ?? 'http://127.0.0.1:3201';
    const command = options?.command ?? 'clawdefender';

    let conn: Connection;
    switch (mode) {
      case 'stdio':
        conn = new StdioConnection(command);
        break;
      case 'http':
        conn = new HttpConnection(httpUrl);
        break;
      case 'auto':
      default:
        conn = new AutoConnection(httpUrl, command);
        break;
    }

    this.connection = new FailOpenConnection(conn);
  }

  /**
   * Create a ClawDefender client with a custom connection.
   * Useful for testing or custom transports.
   */
  static withConnection(connection: Connection): ClawDefender {
    const client = Object.create(ClawDefender.prototype) as ClawDefender;
    client.connection = new FailOpenConnection(connection);
    client.nextId = 1;
    return client;
  }

  private async callTool<T>(
    toolName: string,
    args: Record<string, unknown>,
    schema: { parse: (data: unknown) => T },
  ): Promise<T> {
    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: toolName, arguments: args },
      id: this.nextId++,
    };

    const response = await this.connection.send(request);

    if (response.error) {
      throw new Error(
        `ClawDefender error [${response.error.code}]: ${response.error.message}`,
      );
    }

    const result = response.result as {
      content?: Array<{ type: string; text: string }>;
    };
    const text = result?.content?.[0]?.text;
    if (!text) {
      throw new Error('Empty response from ClawDefender');
    }

    return schema.parse(JSON.parse(text));
  }

  async checkIntent(request: CheckIntentRequest): Promise<CheckIntentResponse> {
    validateStr('description', request.description);
    validateStr('action_type', request.action_type);
    validateStr('target', request.target);
    if (request.reason) validateStr('reason', request.reason);
    return this.callTool('checkIntent', { ...request }, CheckIntentResponseSchema);
  }

  async requestPermission(
    request: RequestPermissionRequest,
  ): Promise<RequestPermissionResponse> {
    validateStr('resource', request.resource);
    validateStr('operation', request.operation);
    validateStr('justification', request.justification);
    return this.callTool(
      'requestPermission',
      { ...request },
      RequestPermissionResponseSchema,
    );
  }

  async reportAction(
    request: ReportActionRequest,
  ): Promise<ReportActionResponse> {
    validateStr('description', request.description);
    validateStr('action_type', request.action_type);
    validateStr('target', request.target);
    validateStr('result', request.result);
    return this.callTool('reportAction', { ...request }, ReportActionResponseSchema);
  }

  async getPolicy(request?: GetPolicyRequest): Promise<GetPolicyResponse> {
    if (request?.resource) validateStr('resource', request.resource);
    if (request?.action_type) validateStr('action_type', request.action_type);
    if (request?.tool_name) validateStr('tool_name', request.tool_name);
    return this.callTool(
      'getPolicy',
      { ...(request ?? {}) },
      GetPolicyResponseSchema,
    );
  }

  async close(): Promise<void> {
    await this.connection.close();
  }
}
