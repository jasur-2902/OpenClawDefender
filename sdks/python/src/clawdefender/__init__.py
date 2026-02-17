"""ClawDefender Python SDK — AI agent guardrails via MCP."""

from __future__ import annotations

from typing import Any, Optional

from .client import ClawDefender
from .decorators import reports_action, requires_permission
from .exceptions import (
    ClawDefenderError,
    ConnectionError,
    PermissionDenied,
    ProtocolError,
)
from .types import (
    ActionResult,
    ActionType,
    CheckIntentResponse,
    GetPolicyResponse,
    Operation,
    PermissionScope,
    ReportActionResponse,
    RequestPermissionResponse,
    RiskLevel,
)

__all__ = [
    "ClawDefender",
    "requires_permission",
    "reports_action",
    "PermissionDenied",
    "ClawDefenderError",
    "ConnectionError",
    "ProtocolError",
    "ActionType",
    "RiskLevel",
    "Operation",
    "PermissionScope",
    "ActionResult",
    "CheckIntentResponse",
    "RequestPermissionResponse",
    "ReportActionResponse",
    "GetPolicyResponse",
]

# Module-level default client used by decorators
_default_client: Optional[Any] = None
