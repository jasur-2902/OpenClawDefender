import { AutoConnection, FailOpenConnection, HttpConnection, StdioConnection, } from './connection.js';
import { CheckIntentResponseSchema, GetPolicyResponseSchema, ReportActionResponseSchema, RequestPermissionResponseSchema, } from './schemas.js';
export class ClawDefender {
    connection;
    nextId = 1;
    constructor(options) {
        const mode = options?.mode ?? 'auto';
        const httpUrl = options?.httpUrl ?? 'http://127.0.0.1:3201';
        const command = options?.command ?? 'clawdefender';
        let conn;
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
    static withConnection(connection) {
        const client = Object.create(ClawDefender.prototype);
        client.connection = new FailOpenConnection(connection);
        client.nextId = 1;
        return client;
    }
    async callTool(toolName, args, schema) {
        const request = {
            jsonrpc: '2.0',
            method: 'tools/call',
            params: { name: toolName, arguments: args },
            id: this.nextId++,
        };
        const response = await this.connection.send(request);
        if (response.error) {
            throw new Error(`ClawDefender error [${response.error.code}]: ${response.error.message}`);
        }
        const result = response.result;
        const text = result?.content?.[0]?.text;
        if (!text) {
            throw new Error('Empty response from ClawDefender');
        }
        return schema.parse(JSON.parse(text));
    }
    async checkIntent(request) {
        return this.callTool('checkIntent', { ...request }, CheckIntentResponseSchema);
    }
    async requestPermission(request) {
        return this.callTool('requestPermission', { ...request }, RequestPermissionResponseSchema);
    }
    async reportAction(request) {
        return this.callTool('reportAction', { ...request }, ReportActionResponseSchema);
    }
    async getPolicy(request) {
        return this.callTool('getPolicy', { ...(request ?? {}) }, GetPolicyResponseSchema);
    }
    async close() {
        await this.connection.close();
    }
}
//# sourceMappingURL=client.js.map