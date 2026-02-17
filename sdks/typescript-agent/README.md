# @clawdefender/agent

Agent Self-Protection API for ClawDefender. This package provides runtime guardrails for JavaScript/TypeScript AI agents — path restrictions, network allowlists, shell policies, and tool-level access control.

## Installation

```bash
npm install @clawdefender/agent
```

## Quick Start

```typescript
import { AgentGuard } from '@clawdefender/agent';

const guard = new AgentGuard({
  name: 'my-agent',
  allowedPaths: ['/tmp/**', './workspace/**'],
  blockedPaths: ['/etc/**', '/root/**'],
  networkAllowlist: ['api.openai.com', '*.github.com'],
  shellPolicy: 'allowlist',
  allowedCommands: ['git', 'npm'],
});

await guard.activate({ fallback: true });

const result = await guard.checkAction('file_read', '/etc/passwd');
// { allowed: false, reason: 'path "/etc/passwd" is in blockedPaths', rule: 'blocked-path' }

await guard.deactivate();
```

## Wrappers

```typescript
import { withGuard, sandboxed } from '@clawdefender/agent';

const protectedFn = withGuard(
  { allowedPaths: ['/tmp/**'], shellPolicy: 'deny' },
  async () => {
    // your agent logic here
  },
);

const sandboxedFn = sandboxed(
  { timeout: 5000 },
  async () => {
    // runs with all external access blocked
  },
);
```

## MCP Middleware

```typescript
import { guardMiddleware } from '@clawdefender/agent';

const middleware = guardMiddleware({
  allowedPaths: ['/workspace/**'],
  shellPolicy: 'deny',
  networkAllowlist: ['api.example.com'],
});

await middleware.initialize();
const check = await middleware.beforeToolCall('readFile', { path: '/etc/shadow' });
// check.allowed === false
await middleware.shutdown();
```

## Monitor Mode

```typescript
const guard = new AgentGuard({
  name: 'my-agent',
  mode: 'monitor',
});
await guard.activate({ fallback: true });

// ... run your agent ...

const suggested = guard.suggestPermissions();
// { allowedPaths: [...], networkAllowlist: [...], ... }
```

## Fallback Mode

When the ClawDefender daemon is unavailable, the guard runs in embedded mode with:
- Path matching against allowedPaths/blockedPaths
- Tool name checking against allowedTools
- Network host checking against networkAllowlist
- Shell policy enforcement
- Node.js API hooks (fs, http, child_process)
