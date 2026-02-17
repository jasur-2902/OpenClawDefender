import { z } from 'zod';
export declare const ActionTypeSchema: z.ZodEnum<["file_read", "file_write", "file_delete", "shell_execute", "network_request", "resource_access", "other"]>;
export declare const RiskLevelSchema: z.ZodEnum<["Low", "Medium", "High", "Critical"]>;
export declare const OperationSchema: z.ZodEnum<["read", "write", "execute", "delete", "connect"]>;
export declare const PermissionScopeSchema: z.ZodEnum<["once", "session", "permanent"]>;
export declare const ActionResultSchema: z.ZodEnum<["success", "failure", "partial"]>;
export declare const CheckIntentRequestSchema: z.ZodObject<{
    description: z.ZodString;
    actionType: z.ZodEnum<["file_read", "file_write", "file_delete", "shell_execute", "network_request", "resource_access", "other"]>;
    target: z.ZodString;
    reason: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    description: string;
    actionType: "file_read" | "file_write" | "file_delete" | "shell_execute" | "network_request" | "resource_access" | "other";
    target: string;
    reason?: string | undefined;
}, {
    description: string;
    actionType: "file_read" | "file_write" | "file_delete" | "shell_execute" | "network_request" | "resource_access" | "other";
    target: string;
    reason?: string | undefined;
}>;
export declare const CheckIntentResponseSchema: z.ZodObject<{
    allowed: z.ZodBoolean;
    riskLevel: z.ZodEnum<["Low", "Medium", "High", "Critical"]>;
    explanation: z.ZodString;
    policyRule: z.ZodString;
    suggestions: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
}, "strip", z.ZodTypeAny, {
    allowed: boolean;
    riskLevel: "Low" | "Medium" | "High" | "Critical";
    explanation: string;
    policyRule: string;
    suggestions?: string[] | undefined;
}, {
    allowed: boolean;
    riskLevel: "Low" | "Medium" | "High" | "Critical";
    explanation: string;
    policyRule: string;
    suggestions?: string[] | undefined;
}>;
export declare const RequestPermissionRequestSchema: z.ZodObject<{
    resource: z.ZodString;
    operation: z.ZodEnum<["read", "write", "execute", "delete", "connect"]>;
    justification: z.ZodString;
    timeoutSeconds: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    resource: string;
    operation: "read" | "write" | "execute" | "delete" | "connect";
    justification: string;
    timeoutSeconds?: number | undefined;
}, {
    resource: string;
    operation: "read" | "write" | "execute" | "delete" | "connect";
    justification: string;
    timeoutSeconds?: number | undefined;
}>;
export declare const RequestPermissionResponseSchema: z.ZodObject<{
    granted: z.ZodBoolean;
    scope: z.ZodEnum<["once", "session", "permanent"]>;
    expiresAt: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    granted: boolean;
    scope: "once" | "session" | "permanent";
    expiresAt?: string | undefined;
}, {
    granted: boolean;
    scope: "once" | "session" | "permanent";
    expiresAt?: string | undefined;
}>;
export declare const ReportActionRequestSchema: z.ZodObject<{
    description: z.ZodString;
    actionType: z.ZodEnum<["file_read", "file_write", "file_delete", "shell_execute", "network_request", "resource_access", "other"]>;
    target: z.ZodString;
    result: z.ZodEnum<["success", "failure", "partial"]>;
    details: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
}, "strip", z.ZodTypeAny, {
    description: string;
    actionType: "file_read" | "file_write" | "file_delete" | "shell_execute" | "network_request" | "resource_access" | "other";
    target: string;
    result: "success" | "failure" | "partial";
    details?: Record<string, unknown> | undefined;
}, {
    description: string;
    actionType: "file_read" | "file_write" | "file_delete" | "shell_execute" | "network_request" | "resource_access" | "other";
    target: string;
    result: "success" | "failure" | "partial";
    details?: Record<string, unknown> | undefined;
}>;
export declare const ReportActionResponseSchema: z.ZodObject<{
    recorded: z.ZodBoolean;
    eventId: z.ZodString;
}, "strip", z.ZodTypeAny, {
    recorded: boolean;
    eventId: string;
}, {
    recorded: boolean;
    eventId: string;
}>;
export declare const GetPolicyRequestSchema: z.ZodObject<{
    resource: z.ZodOptional<z.ZodString>;
    actionType: z.ZodOptional<z.ZodEnum<["file_read", "file_write", "file_delete", "shell_execute", "network_request", "resource_access", "other"]>>;
    toolName: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    actionType?: "file_read" | "file_write" | "file_delete" | "shell_execute" | "network_request" | "resource_access" | "other" | undefined;
    resource?: string | undefined;
    toolName?: string | undefined;
}, {
    actionType?: "file_read" | "file_write" | "file_delete" | "shell_execute" | "network_request" | "resource_access" | "other" | undefined;
    resource?: string | undefined;
    toolName?: string | undefined;
}>;
export declare const PolicyRuleSchema: z.ZodObject<{
    name: z.ZodString;
    action: z.ZodString;
    description: z.ZodString;
    matchCriteria: z.ZodRecord<z.ZodString, z.ZodUnknown>;
}, "strip", z.ZodTypeAny, {
    name: string;
    description: string;
    action: string;
    matchCriteria: Record<string, unknown>;
}, {
    name: string;
    description: string;
    action: string;
    matchCriteria: Record<string, unknown>;
}>;
export declare const GetPolicyResponseSchema: z.ZodObject<{
    rules: z.ZodArray<z.ZodObject<{
        name: z.ZodString;
        action: z.ZodString;
        description: z.ZodString;
        matchCriteria: z.ZodRecord<z.ZodString, z.ZodUnknown>;
    }, "strip", z.ZodTypeAny, {
        name: string;
        description: string;
        action: string;
        matchCriteria: Record<string, unknown>;
    }, {
        name: string;
        description: string;
        action: string;
        matchCriteria: Record<string, unknown>;
    }>, "many">;
    defaultAction: z.ZodString;
}, "strip", z.ZodTypeAny, {
    rules: {
        name: string;
        description: string;
        action: string;
        matchCriteria: Record<string, unknown>;
    }[];
    defaultAction: string;
}, {
    rules: {
        name: string;
        description: string;
        action: string;
        matchCriteria: Record<string, unknown>;
    }[];
    defaultAction: string;
}>;
//# sourceMappingURL=schemas.d.ts.map