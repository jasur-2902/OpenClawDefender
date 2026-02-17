"""ClawDefender Agent — self-protection for autonomous Python agents."""

from clawdefender.agent.decorators import restricted, sandboxed
from clawdefender.agent.exceptions import (
    ClawDefenderAgentError,
    ClawDefenderNotInstalled,
    DaemonConnectionError,
    GuardActivationError,
    GuardNotActiveError,
)
from clawdefender.agent.guard import AgentGuard
from clawdefender.agent.types import CheckResult, GuardStats, PermissionConfig

__all__ = [
    "AgentGuard",
    "restricted",
    "sandboxed",
    "CheckResult",
    "GuardStats",
    "PermissionConfig",
    "ClawDefenderAgentError",
    "ClawDefenderNotInstalled",
    "DaemonConnectionError",
    "GuardActivationError",
    "GuardNotActiveError",
]
