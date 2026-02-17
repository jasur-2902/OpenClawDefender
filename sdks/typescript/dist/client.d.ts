import { type Connection } from './connection.js';
import type { CheckIntentRequest, CheckIntentResponse, ClawDefenderOptions, GetPolicyRequest, GetPolicyResponse, ReportActionRequest, ReportActionResponse, RequestPermissionRequest, RequestPermissionResponse } from './types.js';
export declare class ClawDefender {
    private connection;
    private nextId;
    constructor(options?: ClawDefenderOptions);
    /**
     * Create a ClawDefender client with a custom connection.
     * Useful for testing or custom transports.
     */
    static withConnection(connection: Connection): ClawDefender;
    private callTool;
    checkIntent(request: CheckIntentRequest): Promise<CheckIntentResponse>;
    requestPermission(request: RequestPermissionRequest): Promise<RequestPermissionResponse>;
    reportAction(request: ReportActionRequest): Promise<ReportActionResponse>;
    getPolicy(request?: GetPolicyRequest): Promise<GetPolicyResponse>;
    close(): Promise<void>;
}
//# sourceMappingURL=client.d.ts.map