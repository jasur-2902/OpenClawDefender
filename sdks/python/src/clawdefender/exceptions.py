"""ClawDefender SDK exceptions."""

from __future__ import annotations

from typing import Optional


class ClawDefenderError(Exception):
    """Base exception for all ClawDefender SDK errors."""


class PermissionDenied(ClawDefenderError):
    """Raised when a permission request is denied by ClawDefender."""

    def __init__(
        self,
        resource: str,
        operation: str,
        reason: Optional[str] = None,
    ) -> None:
        self.resource = resource
        self.operation = operation
        self.reason = reason
        msg = f"Permission denied: {operation} on {resource}"
        if reason:
            msg += f" — {reason}"
        super().__init__(msg)


class ConnectionError(ClawDefenderError):
    """Raised when the SDK cannot connect to ClawDefender."""


class ProtocolError(ClawDefenderError):
    """Raised on malformed MCP JSON-RPC responses."""
