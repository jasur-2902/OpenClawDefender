# @clawdefender/sdk

TypeScript SDK for [ClawDefender](https://github.com/clawdefender/clawai) -- AI agent guardrails via MCP.

## Installation

```bash
npm install @clawdefender/sdk
```

## Quick Start

```typescript
import { ClawDefender } from '@clawdefender/sdk';

const claw = new ClawDefender();

// Check if an action is allowed
const intent = await claw.checkIntent({
  description: 'Read user config',
  actionType: 'file_read',
  target: '~/.config/app.json',
});

if (intent.allowed) {
  // proceed
}

// Request permission for sensitive operations
const perm = await claw.requestPermission({
  resource: '/etc/hosts',
  operation: 'write',
  justification: 'Add development hostname',
});

// Report completed actions
await claw.reportAction({
  description: 'Modified hosts file',
  actionType: 'file_write',
  target: '/etc/hosts',
  result: 'success',
});

// Get policy rules
const policy = await claw.getPolicy({ actionType: 'shell_execute' });

await claw.close();
```

## Connection Modes

The client auto-detects the best connection method:

```typescript
// Auto (default): tries HTTP, falls back to stdio
const client = new ClawDefender();

// HTTP only
const client = new ClawDefender({ mode: 'http', httpUrl: 'http://127.0.0.1:3201' });

// Stdio only (spawns `clawdefender serve`)
const client = new ClawDefender({ mode: 'stdio' });

// Custom command
const client = new ClawDefender({ mode: 'stdio', command: '/usr/local/bin/clawdefender' });
```

## Fail-Open Behavior

If ClawDefender is unavailable, the SDK **fails open** by default:

- `checkIntent` returns `{ allowed: true }`
- `requestPermission` returns `{ granted: true }`
- `reportAction` returns `{ recorded: false }`
- `getPolicy` returns `{ rules: [], defaultAction: 'allow' }`

A warning is logged to the console when this occurs.

## MCP Server Middleware

Wrap your MCP tool handlers with ClawDefender checks:

```typescript
import { clawdefenderMiddleware } from '@clawdefender/sdk';

const guard = clawdefenderMiddleware({
  autoCheck: true,    // Check intent before every tool call
  autoReport: true,   // Report result after every tool call
  tools: {
    deleteFile: { requirePermission: true },  // Also request permission
    ping: { skip: true },                     // Skip all checks
  },
});

// In your MCP server handler:
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const handler = myToolHandlers[request.params.name];
  const guarded = guard(request.params.name, handler);
  return guarded(request.params.arguments ?? {});
});
```

## Wrapper Functions

Decorate individual functions with permission or audit checks:

```typescript
import { withPermission, withAudit } from '@clawdefender/sdk';

const safeWrite = withPermission(
  { operation: 'write', justification: 'Save output' },
  async (path: string, data: string) => {
    await fs.writeFile(path, data);
  },
);

const auditedFetch = withAudit(
  { actionType: 'network_request' },
  async (url: string) => {
    return fetch(url);
  },
);

await safeWrite('/tmp/output.txt', 'hello');
await auditedFetch('https://api.example.com/data');
```

## Zod Schemas

All request/response types have corresponding Zod schemas for runtime validation:

```typescript
import { CheckIntentRequestSchema, CheckIntentResponseSchema } from '@clawdefender/sdk';

const validated = CheckIntentRequestSchema.parse(untrustedInput);
```

## API Reference

### `ClawDefender`

| Method | Description |
|--------|-------------|
| `checkIntent(req)` | Check if an action is allowed by policy |
| `requestPermission(req)` | Request permission for a resource operation |
| `reportAction(req)` | Report a completed action for audit |
| `getPolicy(req?)` | Get applicable policy rules |
| `close()` | Close the connection |

### Types

- `ActionType`: `'file_read' | 'file_write' | 'file_delete' | 'shell_execute' | 'network_request' | 'resource_access' | 'other'`
- `RiskLevel`: `'Low' | 'Medium' | 'High' | 'Critical'`
- `Operation`: `'read' | 'write' | 'execute' | 'delete' | 'connect'`
- `PermissionScope`: `'once' | 'session' | 'permanent'`
- `ActionResult`: `'success' | 'failure' | 'partial'`

## License

Apache-2.0
