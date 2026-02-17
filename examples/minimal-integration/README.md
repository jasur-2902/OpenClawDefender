# Minimal ClawDefender Integration

The simplest possible integration: a single `checkIntent` call before
performing an action. Copy-paste into your MCP server to get started.

## Python

```bash
pip install clawdefender-sdk
```

```python
from clawdefender import ClawDefenderClient

claw = ClawDefenderClient()

intent = claw.check_intent_sync(
    description="Read config file",
    action_type="file_read",
    target="/etc/app/config.yaml",
)

if intent.allowed:
    # proceed
else:
    # handle denial
```

See `python_example.py` for a runnable version.

## TypeScript

```bash
npm install @clawdefender/sdk
```

```typescript
import { ClawDefenderClient } from "@clawdefender/sdk";

const claw = new ClawDefenderClient();

const intent = await claw.checkIntent({
  description: "Read config file",
  actionType: "file_read",
  target: "/etc/app/config.yaml",
});

if (intent.allowed) {
  // proceed
} else {
  // handle denial
}
```

See `typescript_example.ts` for a runnable version.

## What this gives you

Even this single call provides:

- **Policy enforcement** -- your server respects user-defined security policies
- **Audit logging** -- ClawDefender records the intent check
- **Level 1 compliance** -- qualifies for Claw Compliant Level 1 certification

To reach higher compliance levels, add `requestPermission` (Level 2) and
`reportAction` (Level 3). See the full examples in `examples/python-mcp-server/`
and `examples/typescript-mcp-server/`.
