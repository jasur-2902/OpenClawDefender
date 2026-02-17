# Agent Guard Guide

The Agent Self-Protection API lets AI agents declare and enforce their own security boundaries. Instead of relying solely on external monitoring, each agent carries a guard that restricts its own capabilities to the minimum needed for its task.

## Installation

**Python:**

```bash
pip install clawdefender-agent
```

**TypeScript / Node.js:**

```bash
npm install @clawdefender/agent
```

Both packages are lightweight wrappers that communicate with the ClawDefender daemon when available, and fall back to in-process enforcement when it is not.

## Quick start

### Python (30 seconds)

```python
from clawdefender.agent import AgentGuard

guard = AgentGuard(
    name="my-bot",
    allowed_paths=["~/workspace/"],
    shell_policy="deny",
)
guard.activate(fallback=True)

result = guard.check_action("file_read", "~/workspace/data.txt")
assert result.allowed

guard.deactivate()
```

### TypeScript (30 seconds)

```typescript
import { AgentGuard } from "@clawdefender/agent";

const guard = new AgentGuard({
  name: "my-bot",
  allowedPaths: ["~/workspace/"],
  shellPolicy: "deny",
});
await guard.activate({ fallback: true });

const result = await guard.checkAction("file_read", "~/workspace/data.txt");
console.log(result.allowed); // true

await guard.deactivate();
```

## Development workflow

The recommended workflow is:

1. **Monitor mode**: Start with `mode="monitor"` (Python) or `mode: "monitor"` (TypeScript). The guard logs every operation but blocks nothing.
2. **Observe**: Run your agent through its normal workload.
3. **Suggest**: Call `guard.suggest_permissions()` to get a minimal permission set based on what the agent actually tried to do.
4. **Enforce**: Update your constructor with the suggested permissions and switch to `mode="enforce"`.

```python
# Step 1: Monitor
guard = AgentGuard(name="my-bot", mode="monitor")
guard.activate(fallback=True)

# Step 2: Run workload
guard.check_action("file_read", "~/workspace/data.txt")
guard.check_action("shell_execute", "git status")

# Step 3: Suggest
suggestions = guard.suggest_permissions()
print(suggestions)
# {'file_read': ['~/workspace/data.txt'], 'shell_commands': ['shell_execute'], ...}

# Step 4: Use suggestions to configure enforce mode
```

## API reference

### AgentGuard constructor

**Python:**

```python
AgentGuard(
    name: str,                              # Unique agent name
    allowed_paths: list[str] | None,        # Glob patterns for readable/writable paths
    allowed_tools: list[str] | None,        # Tool names the agent may use
    blocked_paths: list[str] | None,        # Paths always blocked (overrides allowed_paths)
    network_allowlist: list[str] | None,    # Hosts the agent may contact
    shell_policy: str = "deny",             # "deny", "allowlist", or "approve"
    allowed_commands: list[str] | None,     # Shell commands (when shell_policy="allowlist")
    max_file_size: int | None,              # Max file size in bytes
    max_files_per_minute: int | None,       # Rate limit: files per minute
    max_network_requests_per_minute: int | None,  # Rate limit: requests per minute
    mode: str = "enforce",                  # "enforce" or "monitor"
)
```

**TypeScript:**

```typescript
new AgentGuard({
  name: string;
  allowedPaths?: string[];
  allowedTools?: string[];
  blockedPaths?: string[];
  networkAllowlist?: string[];
  shellPolicy?: "deny" | "allowlist" | "approve";
  allowedCommands?: string[];
  maxFileSize?: number;
  maxFilesPerMinute?: number;
  maxNetworkRequestsPerMinute?: number;
  mode?: "enforce" | "monitor";
})
```

### activate()

Connects to the ClawDefender daemon. If the daemon is unavailable, falls back to embedded enforcement (Python: `fallback=True`, TypeScript: `{ fallback: true }`).

### deactivate()

Disconnects from the daemon and releases resources. Safe to call multiple times.

### check_action(action, target)

Checks whether a specific action on a target is allowed.

- **action**: The operation type (e.g. `"file_read"`, `"file_write"`, `"shell_execute"`, `"network_request"`).
- **target**: The target (file path, host, command).
- **Returns**: `CheckResult` with `.allowed` (bool) and `.reason` (string).

### stats()

Returns current guard statistics including operation counts and blocked operation details.

**Python** returns a `GuardStats` dataclass with:
- `name`, `mode`, `active`
- `allowed_count`, `blocked_count`, `checked_count`
- `uptime_seconds`

**TypeScript** returns a `GuardStats` object with:
- `activatedAt`, `operationsAllowed`, `operationsBlocked`
- `blockedDetails`, `anomalyAlerts`, `status`

### is_healthy() / isHealthy()

Returns `True`/`true` if the guard is active and enforcing (either via daemon or fallback).

### suggest_permissions()

Analyzes operations recorded in monitor mode and returns the minimal permission set the agent would need. Only useful when `mode="monitor"`.

## Decorator patterns (Python)

### @restricted

Wraps a function so it runs inside a guard:

```python
from clawdefender.agent.decorators import restricted

@restricted(
    allowed_paths=["~/workspace/"],
    shell="deny",
    network_allowlist=["api.anthropic.com"],
)
def process_files():
    # This function runs with restricted permissions.
    pass
```

Works with both sync and async functions.

### @sandboxed

Blocks ALL external access with a timeout:

```python
from clawdefender.agent.decorators import sandboxed

@sandboxed(timeout=30)
def pure_computation():
    # No file access, no network, no shell. Killed after 30 seconds.
    return 42
```

## Wrapper patterns (TypeScript)

### withGuard

Wraps a function with guard protection:

```typescript
import { withGuard } from "@clawdefender/agent";

const safeFetch = withGuard(
  { networkAllowlist: ["api.example.com"], shellPolicy: "deny" },
  async () => {
    // Runs with restricted permissions
  },
);

await safeFetch();
```

### sandboxed

Blocks all external access with a timeout:

```typescript
import { sandboxed } from "@clawdefender/agent";

const pure = sandboxed({ timeout: 5000 }, async () => {
  return 42;
});

await pure();
```

## Middleware (TypeScript)

### guardMiddleware for MCP servers

Integrates with MCP server tool dispatch:

```typescript
import { guardMiddleware } from "@clawdefender/agent";

const middleware = guardMiddleware({
  allowedPaths: ["~/workspace/"],
  shellPolicy: "deny",
  networkAllowlist: ["api.anthropic.com"],
  allowedTools: ["read_file", "write_file"],
});

await middleware.initialize();

// Before each tool call:
const result = await middleware.beforeToolCall("read_file", { path: "~/workspace/data.txt" });
if (!result.allowed) {
  throw new Error(`Blocked: ${result.reason}`);
}

// On shutdown:
await middleware.shutdown();
```

## Context manager / async dispose

### Python context manager

```python
with AgentGuard(name="my-bot", allowed_paths=["~/workspace/"]) as guard:
    result = guard.check_action("file_read", "~/workspace/data.txt")
# Guard is automatically deactivated on exit.
```

Async version:

```python
async with AgentGuard(name="my-bot", allowed_paths=["~/workspace/"]) as guard:
    result = guard.check_action("file_read", "~/workspace/data.txt")
```

### TypeScript async dispose

```typescript
await using guard = new AgentGuard({ name: "my-bot", allowedPaths: ["~/workspace/"] });
await guard.activate({ fallback: true });
// Guard is automatically deactivated when the block exits.
```

## REST API overview

When the ClawDefender daemon is running, guards are managed via a REST API at `http://127.0.0.1:3202`. The Python and TypeScript packages use this API automatically.

Key endpoints:
- `POST /api/v1/guards` - Create a guard
- `GET /api/v1/guards` - List active guards
- `GET /api/v1/guards/:id` - Get guard details
- `DELETE /api/v1/guards/:id` - Deregister a guard
- `POST /api/v1/guards/:id/check` - Check an action
- `GET /api/v1/guards/:id/stats` - Get guard statistics
- `POST /api/v1/guards/:id/webhooks` - Register a webhook

See the [REST API Guide](rest-api-guide.md) for full documentation.

## Auto-installation

The Python and TypeScript packages can automatically install the ClawDefender daemon if it is not already present. When `activate()` is called and the daemon is not found, the package checks for the daemon binary and optionally downloads and installs it.

To disable auto-installation, set `fallback=True` (Python) or `{ fallback: true }` (TypeScript) when calling `activate()`. The guard will use embedded enforcement instead.

## Fallback mode

When the daemon is unavailable, guards operate in **embedded fallback mode**:

- Permission checks run in-process using the same rules
- Sensitive paths (`.ssh`, `.aws`, `.gnupg`, `.config/gcloud`) are always blocked
- No OS-level enforcement (only API-level checks)
- All stats are tracked locally

Fallback mode provides the same policy enforcement for API-level checks but cannot intercept direct system calls.

## Health checks

Use `is_healthy()` / `isHealthy()` to check if the guard is operating:

```python
if not guard.is_healthy():
    # Guard is degraded or failed — handle accordingly
    logger.warning("Guard is not healthy, stopping agent")
```

The guard reports healthy when it is in `Active` or `Degraded` status. It reports unhealthy when `Inactive` or `Failed`.

## Troubleshooting

### Guard fails to activate

- Check that the ClawDefender daemon is running: `claw status`
- Use `fallback=True` to fall back to embedded mode
- Check logs: the guard logs to `clawdefender.agent` (Python) or console (TypeScript)

### Operations unexpectedly blocked

- Switch to `mode="monitor"` to observe without blocking
- Check `guard.stats()` for `blocked_details` to see what was blocked and why
- Verify your glob patterns match the paths your agent accesses

### Daemon connection drops mid-session

- Python: the guard blocks all subsequent operations by default (fail-closed)
- TypeScript: falls back to the embedded enforcer if available
- Use `is_healthy()` to detect connection loss

### Performance concerns

- Guard activation: < 100ms without daemon, < 200ms with daemon
- Per-operation check: < 0.5ms in embedded mode
- Monitor mode has slightly higher overhead due to operation recording
