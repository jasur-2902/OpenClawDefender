# MCP Server Author Guide

This guide explains how to integrate ClawDefender into your MCP server, from
a single checkIntent call to full Level 3 certification.

## Why integrate ClawDefender?

**Trust signal.** Users see that your server has been independently verified
and can trust it with access to their system.

**User safety.** ClawDefender prevents your server from accidentally accessing
files or executing commands outside the scope the user intended.

**Ecosystem reputation.** Certified servers are listed in the ClawDefender
certified servers directory, increasing discoverability and adoption.

## Three compliance levels

| Level | Name | Requirements |
|---|---|---|
| 1 | Aware | Calls `checkIntent` before actions |
| 2 | Guarded | Level 1 + calls `requestPermission` before sensitive operations |
| 3 | Certified | Level 2 + calls `reportAction` after all actions + includes manifest |

Each level builds on the previous. Start with Level 1 and work up.

## Step-by-step Python integration

### Install the SDK

```bash
pip install clawdefender-sdk
```

### Level 1: checkIntent

Before performing any action, ask ClawDefender if the policy allows it:

```python
from clawdefender import ClawDefenderClient

claw = ClawDefenderClient()

async def read_file(path: str) -> str:
    # Check intent before acting
    intent = await claw.check_intent(
        description=f"Read file: {path}",
        action_type="file_read",
        target=path,
        reason="User requested file contents",
    )
    if not intent.allowed:
        raise PermissionError(f"Blocked: {intent.explanation}")

    return open(path).read()
```

### Level 2: requestPermission

For write operations and other sensitive actions, request explicit permission.
This may prompt the user for approval:

```python
async def write_file(path: str, content: str) -> None:
    # Check intent
    intent = await claw.check_intent(
        description=f"Write file: {path}",
        action_type="file_write",
        target=path,
    )
    if not intent.allowed:
        raise PermissionError(f"Blocked: {intent.explanation}")

    # Request permission for the write
    perm = await claw.request_permission(
        resource=path,
        operation="write",
        justification=f"Writing {len(content)} bytes",
    )
    if not perm.granted:
        raise PermissionError("User denied permission")

    with open(path, "w") as f:
        f.write(content)
```

### Level 3: reportAction

After every action, report the outcome so ClawDefender can maintain an
audit trail:

```python
async def write_file(path: str, content: str) -> None:
    intent = await claw.check_intent(
        description=f"Write file: {path}",
        action_type="file_write",
        target=path,
    )
    if not intent.allowed:
        raise PermissionError(f"Blocked: {intent.explanation}")

    perm = await claw.request_permission(
        resource=path,
        operation="write",
        justification=f"Writing {len(content)} bytes",
    )
    if not perm.granted:
        raise PermissionError("User denied permission")

    try:
        with open(path, "w") as f:
            f.write(content)
        result = "success"
    except Exception:
        result = "failure"
        raise
    finally:
        # Always report, even on failure
        await claw.report_action(
            description=f"Write file: {path}",
            action_type="file_write",
            target=path,
            result=result,
        )
```

## Step-by-step TypeScript integration

### Install the SDK

```bash
npm install @clawdefender/sdk
```

### Level 1: checkIntent

```typescript
import { ClawDefenderClient } from "@clawdefender/sdk";

const claw = new ClawDefenderClient();

async function readFile(path: string): Promise<string> {
  const intent = await claw.checkIntent({
    description: `Read file: ${path}`,
    actionType: "file_read",
    target: path,
    reason: "User requested file contents",
  });
  if (!intent.allowed) {
    throw new Error(`Blocked: ${intent.explanation}`);
  }

  return fs.readFileSync(path, "utf-8");
}
```

### Level 2: requestPermission

```typescript
async function writeFile(path: string, content: string): Promise<void> {
  const intent = await claw.checkIntent({
    description: `Write file: ${path}`,
    actionType: "file_write",
    target: path,
  });
  if (!intent.allowed) {
    throw new Error(`Blocked: ${intent.explanation}`);
  }

  const perm = await claw.requestPermission({
    resource: path,
    operation: "write",
    justification: `Writing ${content.length} bytes`,
  });
  if (!perm.granted) {
    throw new Error("User denied permission");
  }

  fs.writeFileSync(path, content, "utf-8");
}
```

### Level 3: reportAction

```typescript
async function writeFile(path: string, content: string): Promise<void> {
  const intent = await claw.checkIntent({
    description: `Write file: ${path}`,
    actionType: "file_write",
    target: path,
  });
  if (!intent.allowed) {
    throw new Error(`Blocked: ${intent.explanation}`);
  }

  const perm = await claw.requestPermission({
    resource: path,
    operation: "write",
    justification: `Writing ${content.length} bytes`,
  });
  if (!perm.granted) {
    throw new Error("User denied permission");
  }

  let result: "success" | "failure" = "success";
  try {
    fs.writeFileSync(path, content, "utf-8");
  } catch (err) {
    result = "failure";
    throw err;
  } finally {
    await claw.reportAction({
      description: `Write file: ${path}`,
      actionType: "file_write",
      target: path,
      result,
    });
  }
}
```

## Adding a clawdefender.toml manifest

Create a `clawdefender.toml` file in the root of your server project:

```toml
[manifest]
schema_version = "1.0"
server_name = "my-mcp-server"
server_version = "1.0.0"
compliance_level = 3
description = "Description of what your server does"

# Declare what permissions your server needs
[permissions]
file_read = ["~/workspace/**"]
file_write = ["/tmp/my-server/**"]
shell_execute = false
network = false

# Declare each tool with its risk level
[[tools]]
name = "my_tool"
description = "What this tool does"
risk_level = "Low"    # Low, Medium, High, or Critical
requires = ["file_read"]
```

The manifest serves two purposes:

1. **User transparency** -- users see what your server will access before
   granting permissions
2. **Certification** -- `clawdefender certify` validates the manifest against
   the actual server behavior

## Running clawdefender certify

```bash
cd my-mcp-server/
clawdefender certify .
```

The certifier checks:

- **Level 1:** manifest exists, `checkIntent` called before tool actions
- **Level 2:** `requestPermission` called before write/execute/delete operations
- **Level 3:** `reportAction` called after all tool actions, all tools declare
  risk levels

Output:

```
Checking my-mcp-server...
[PASS] clawdefender.toml manifest found
[PASS] All tools declare risk levels
[PASS] checkIntent called before all tool actions
[PASS] requestPermission called before write operations
[PASS] reportAction called after all tool actions
Result: Level 3 Claw Compliant
```

## Handling ClawDefender unavailable (fail-open)

Your server should work even when ClawDefender is not installed. Wrap SDK
calls in availability checks:

### Python

```python
try:
    from clawdefender import ClawDefenderClient
    claw = ClawDefenderClient()
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

async def read_file(path: str) -> str:
    if AVAILABLE:
        intent = await claw.check_intent(...)
        if not intent.allowed:
            raise PermissionError(intent.explanation)
    return open(path).read()
```

### TypeScript

```typescript
let claw: ClawDefenderClient | null = null;
try {
  const sdk = await import("@clawdefender/sdk");
  claw = new sdk.ClawDefenderClient();
} catch {
  // ClawDefender not available
}

async function readFile(path: string): Promise<string> {
  if (claw) {
    const intent = await claw.checkIntent({...});
    if (!intent.allowed) throw new Error(intent.explanation);
  }
  return fs.readFileSync(path, "utf-8");
}
```

## Common patterns

### File operations

```python
# Read: checkIntent + reportAction
intent = await claw.check_intent(action_type="file_read", target=path, ...)
# ... perform read ...
await claw.report_action(action_type="file_read", target=path, result="success")

# Write: checkIntent + requestPermission + reportAction
intent = await claw.check_intent(action_type="file_write", target=path, ...)
perm = await claw.request_permission(resource=path, operation="write", ...)
# ... perform write ...
await claw.report_action(action_type="file_write", target=path, result="success")

# Delete: checkIntent + requestPermission + reportAction
intent = await claw.check_intent(action_type="file_delete", target=path, ...)
perm = await claw.request_permission(resource=path, operation="delete", ...)
# ... perform delete ...
await claw.report_action(action_type="file_delete", target=path, result="success")
```

### Shell execution

```python
intent = await claw.check_intent(
    description=f"Execute: {command}",
    action_type="shell_execute",
    target=command,
)
perm = await claw.request_permission(
    resource=command,
    operation="execute",
    justification="Running build command",
)
# ... execute command ...
await claw.report_action(action_type="shell_execute", target=command, result="success")
```

### Network requests

```python
intent = await claw.check_intent(
    description=f"Fetch URL: {url}",
    action_type="network_request",
    target=url,
)
# ... make request ...
await claw.report_action(action_type="network_request", target=url, result="success")
```

### Handling denials

When ClawDefender denies an action, return a clear message to the user:

```python
intent = await claw.check_intent(...)
if not intent.allowed:
    # Return an MCP text response explaining the denial
    return [TextContent(
        type="text",
        text=f"Action blocked by security policy: {intent.explanation}\n"
             f"Suggestions: {', '.join(intent.suggestions)}",
    )]
```

## Requesting listing in the certified servers directory

Once your server passes `clawdefender certify`, you can request inclusion in
the certified servers directory:

1. Ensure your server repository is public
2. Include the `clawdefender.toml` manifest in the repo root
3. Open an issue at github.com/clawdefender/clawdefender with:
   - Server name and repository URL
   - Compliance level achieved
   - Output of `clawdefender certify .`
4. The ClawDefender team will review and add your server to
   `docs/certified-servers.md` and `certified-servers.json`
