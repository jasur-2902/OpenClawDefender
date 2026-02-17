"""Core ClawDefender client."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Optional

from .connection import (
    AutoConnection,
    FailOpenConnection,
    HttpConnection,
    StdioConnection,
)
from .context import GuardedAction
from .types import (
    CheckIntentResponse,
    GetPolicyResponse,
    PermissionScope,
    ReportActionResponse,
    RequestPermissionResponse,
    RiskLevel,
)

logger = logging.getLogger("clawdefender")

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

_MAX_FIELD_LENGTH = 4096

# Unicode bidirectional control characters
_BIDI_CHARS = re.compile(
    "[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f]"
)


def _validate_str(name: str, value: str) -> None:
    """Validate a string parameter before sending to the server."""
    if not isinstance(value, str):
        raise ValueError(f"Parameter '{name}' must be a string")
    if len(value) > _MAX_FIELD_LENGTH:
        raise ValueError(
            f"Parameter '{name}' exceeds maximum length ({len(value)} > {_MAX_FIELD_LENGTH})"
        )
    if "\0" in value:
        raise ValueError(f"Parameter '{name}' contains null byte")
    if _BIDI_CHARS.search(value):
        raise ValueError(
            f"Parameter '{name}' contains Unicode bidirectional control character"
        )


class ClawDefender:
    """Python client for the ClawDefender MCP server.

    Parameters
    ----------
    mode:
        Connection strategy — ``"auto"`` (default), ``"stdio"``, or ``"http"``.
    http_url:
        Override HTTP endpoint (default ``http://127.0.0.1:3201``).
    command:
        Override the binary used for stdio (default ``clawdefender``).
    fail_open:
        If *True* (default), the SDK silently allows everything when
        ClawDefender is unreachable.
    """

    def __init__(
        self,
        mode: str = "auto",
        http_url: Optional[str] = None,
        command: Optional[str] = None,
        fail_open: bool = True,
    ) -> None:
        if mode == "stdio":
            factory = lambda: StdioConnection(command)
        elif mode == "http":
            factory = lambda: HttpConnection(http_url)
        else:
            factory = lambda: AutoConnection(http_url=http_url, command=command)

        if fail_open:
            self._conn = FailOpenConnection(factory)
        else:
            conn = factory()
            self._conn = conn

        # Register as the default client for decorators
        import clawdefender as _pkg

        _pkg._default_client = self  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Sync API
    # ------------------------------------------------------------------

    def check_intent(
        self,
        description: str,
        action_type: str,
        target: str,
        reason: Optional[str] = None,
    ) -> CheckIntentResponse:
        _validate_str("description", description)
        _validate_str("action_type", action_type)
        _validate_str("target", target)
        if reason:
            _validate_str("reason", reason)
        params: dict[str, Any] = {
            "description": description,
            "action_type": action_type,
            "target": target,
        }
        if reason:
            params["reason"] = reason
        data = self._conn.send("checkIntent", params)
        return _parse_check_intent(data)

    def request_permission(
        self,
        resource: str,
        operation: str,
        justification: str,
        timeout_seconds: int = 30,
    ) -> RequestPermissionResponse:
        _validate_str("resource", resource)
        _validate_str("operation", operation)
        _validate_str("justification", justification)
        data = self._conn.send(
            "requestPermission",
            {
                "resource": resource,
                "operation": operation,
                "justification": justification,
                "timeout_seconds": timeout_seconds,
            },
        )
        return _parse_request_permission(data)

    def report_action(
        self,
        description: str,
        action_type: str,
        target: str,
        result: str,
        details: Optional[dict[str, Any]] = None,
    ) -> ReportActionResponse:
        _validate_str("description", description)
        _validate_str("action_type", action_type)
        _validate_str("target", target)
        _validate_str("result", result)
        params: dict[str, Any] = {
            "description": description,
            "action_type": action_type,
            "target": target,
            "result": result,
        }
        if details:
            params["details"] = details
        data = self._conn.send("reportAction", params)
        return _parse_report_action(data)

    def get_policy(
        self,
        resource: Optional[str] = None,
        action_type: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> GetPolicyResponse:
        params: dict[str, Any] = {}
        if resource:
            _validate_str("resource", resource)
            params["resource"] = resource
        if action_type:
            _validate_str("action_type", action_type)
            params["action_type"] = action_type
        if tool_name:
            _validate_str("tool_name", tool_name)
            params["tool_name"] = tool_name
        data = self._conn.send("getPolicy", params)
        return _parse_get_policy(data)

    # ------------------------------------------------------------------
    # Async API
    # ------------------------------------------------------------------

    async def acheck_intent(
        self,
        description: str,
        action_type: str,
        target: str,
        reason: Optional[str] = None,
    ) -> CheckIntentResponse:
        _validate_str("description", description)
        _validate_str("action_type", action_type)
        _validate_str("target", target)
        if reason:
            _validate_str("reason", reason)
        params: dict[str, Any] = {
            "description": description,
            "action_type": action_type,
            "target": target,
        }
        if reason:
            params["reason"] = reason
        data = await self._conn.asend("checkIntent", params)
        return _parse_check_intent(data)

    async def arequest_permission(
        self,
        resource: str,
        operation: str,
        justification: str,
        timeout_seconds: int = 30,
    ) -> RequestPermissionResponse:
        _validate_str("resource", resource)
        _validate_str("operation", operation)
        _validate_str("justification", justification)
        data = await self._conn.asend(
            "requestPermission",
            {
                "resource": resource,
                "operation": operation,
                "justification": justification,
                "timeout_seconds": timeout_seconds,
            },
        )
        return _parse_request_permission(data)

    async def areport_action(
        self,
        description: str,
        action_type: str,
        target: str,
        result: str,
        details: Optional[dict[str, Any]] = None,
    ) -> ReportActionResponse:
        _validate_str("description", description)
        _validate_str("action_type", action_type)
        _validate_str("target", target)
        _validate_str("result", result)
        params: dict[str, Any] = {
            "description": description,
            "action_type": action_type,
            "target": target,
            "result": result,
        }
        if details:
            params["details"] = details
        data = await self._conn.asend("reportAction", params)
        return _parse_report_action(data)

    async def aget_policy(
        self,
        resource: Optional[str] = None,
        action_type: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> GetPolicyResponse:
        params: dict[str, Any] = {}
        if resource:
            _validate_str("resource", resource)
            params["resource"] = resource
        if action_type:
            _validate_str("action_type", action_type)
            params["action_type"] = action_type
        if tool_name:
            _validate_str("tool_name", tool_name)
            params["tool_name"] = tool_name
        data = await self._conn.asend("getPolicy", params)
        return _parse_get_policy(data)

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def guarded_action(
        self,
        description: str,
        action_type: str,
        target: str,
    ) -> GuardedAction:
        return GuardedAction(self, description, action_type, target)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> ClawDefender:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    async def __aenter__(self) -> ClawDefender:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------


def _parse_check_intent(data: dict[str, Any]) -> CheckIntentResponse:
    return CheckIntentResponse(
        allowed=data["allowed"],
        risk_level=RiskLevel(data["risk_level"]),
        explanation=data.get("explanation", ""),
        policy_rule=data.get("policy_rule", ""),
        suggestions=data.get("suggestions", []),
    )


def _parse_request_permission(data: dict[str, Any]) -> RequestPermissionResponse:
    expires_raw = data.get("expires_at")
    expires = datetime.fromisoformat(expires_raw) if expires_raw else None
    return RequestPermissionResponse(
        granted=data["granted"],
        scope=PermissionScope(data["scope"]),
        expires_at=expires,
    )


def _parse_report_action(data: dict[str, Any]) -> ReportActionResponse:
    return ReportActionResponse(
        recorded=data["recorded"],
        event_id=data.get("event_id", ""),
    )


def _parse_get_policy(data: dict[str, Any]) -> GetPolicyResponse:
    return GetPolicyResponse(
        rules=data.get("rules", []),
        default_action=data.get("default_action", "allow"),
    )
