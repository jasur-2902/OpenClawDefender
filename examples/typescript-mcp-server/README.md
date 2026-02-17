# TypeScript MCP Server with ClawDefender (Level 3)

A complete example MCP server in TypeScript that integrates all three
ClawDefender security checkpoints, achieving Level 3 Claw Compliance.

## What this server does

Exposes three file-operation tools via MCP:

| Tool | Risk | ClawDefender checkpoints |
|---|---|---|
| `read_file` | Low | checkIntent, reportAction |
| `write_file` | Medium | checkIntent, requestPermission, reportAction |
| `list_directory` | Low | checkIntent, reportAction |

## Security checkpoints

### 1. checkIntent (before action)

```typescript
const intent = await claw.checkIntent({
  description: `Read file: ${filePath}`,
  actionType: "file_read",
  target: filePath,
  reason: "User requested file contents",
});
if (!intent.allowed) {
  return blockedResponse(intent.explanation);
}
```

### 2. requestPermission (before writes)

```typescript
const perm = await claw.requestPermission({
  resource: filePath,
  operation: "write",
  justification: `Writing ${content.length} bytes to ${filePath}`,
});
if (!perm.granted) {
  return deniedResponse();
}
```

### 3. reportAction (after action)

```typescript
await claw.reportAction({
  description: `Read file: ${filePath}`,
  actionType: "file_read",
  target: filePath,
  result: "success",
});
```

## Graceful degradation

If `@clawdefender/sdk` is not installed or the daemon is not running, the
server continues to function. All checkpoints are guarded with `if (claw)`.

## Setup

```bash
npm install
npm run build
npm start

# Or run directly in development:
npm run dev
```

## Using with ClawDefender

```bash
# Wrap for Claude Desktop
clawdefender wrap example-file-operations-ts

# Or run with the proxy
clawdefender proxy -- npx tsx server.ts
```

## Certifying

```bash
clawdefender certify .
# Expected: Level 3 Claw Compliant
```
