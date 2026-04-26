# clawdefender-agent

Self-protection package for autonomous Python agents. Enforces security
policies (file access, network, shell execution) via the Rookbot daemon
or an embedded fallback enforcer.

## Installation

```bash
pip install clawdefender-agent
```

## Quick Start

```python
from clawdefender.agent import AgentGuard

# Context manager — auto-activates and deactivates
with AgentGuard(
    name="my-agent",
    allowed_paths=["/tmp/workspace/*"],
    shell_policy="deny",
) as guard:
    result = guard.check_action("file_write", "/tmp/workspace/output.txt")
    if result.allowed:
        print("Write allowed")

# Decorator-based
from clawdefender.agent import restricted

@restricted(allowed_paths=["/tmp/*"], network="deny", shell="deny")
def safe_task():
    ...
```

## Features

- **Daemon mode**: Connects to Rookbot daemon REST API for full enforcement
- **Embedded fallback**: In-process enforcement when daemon is unavailable
- **Monitor mode**: Record operations and get suggested minimal permissions
- **Decorators**: `@restricted` and `@sandboxed` for function-level protection
- **Auto-installation**: Detect and optionally download the Rookbot binary

## License

Apache-2.0
