import { z } from 'zod';
// ── Enums ──
export const ActionTypeSchema = z.enum([
    'file_read',
    'file_write',
    'file_delete',
    'shell_execute',
    'network_request',
    'resource_access',
    'other',
]);
export const RiskLevelSchema = z.enum(['Low', 'Medium', 'High', 'Critical']);
export const OperationSchema = z.enum([
    'read',
    'write',
    'execute',
    'delete',
    'connect',
]);
export const PermissionScopeSchema = z.enum(['once', 'session', 'permanent']);
export const ActionResultSchema = z.enum(['success', 'failure', 'partial']);
// ── Check Intent ──
export const CheckIntentRequestSchema = z.object({
    description: z.string(),
    actionType: ActionTypeSchema,
    target: z.string(),
    reason: z.string().optional(),
});
export const CheckIntentResponseSchema = z.object({
    allowed: z.boolean(),
    riskLevel: RiskLevelSchema,
    explanation: z.string(),
    policyRule: z.string(),
    suggestions: z.array(z.string()).optional(),
});
// ── Request Permission ──
export const RequestPermissionRequestSchema = z.object({
    resource: z.string(),
    operation: OperationSchema,
    justification: z.string(),
    timeoutSeconds: z.number().optional(),
});
export const RequestPermissionResponseSchema = z.object({
    granted: z.boolean(),
    scope: PermissionScopeSchema,
    expiresAt: z.string().optional(),
});
// ── Report Action ──
export const ReportActionRequestSchema = z.object({
    description: z.string(),
    actionType: ActionTypeSchema,
    target: z.string(),
    result: ActionResultSchema,
    details: z.record(z.unknown()).optional(),
});
export const ReportActionResponseSchema = z.object({
    recorded: z.boolean(),
    eventId: z.string(),
});
// ── Get Policy ──
export const GetPolicyRequestSchema = z.object({
    resource: z.string().optional(),
    actionType: ActionTypeSchema.optional(),
    toolName: z.string().optional(),
});
export const PolicyRuleSchema = z.object({
    name: z.string(),
    action: z.string(),
    description: z.string(),
    matchCriteria: z.record(z.unknown()),
});
export const GetPolicyResponseSchema = z.object({
    rules: z.array(PolicyRuleSchema),
    defaultAction: z.string(),
});
//# sourceMappingURL=schemas.js.map