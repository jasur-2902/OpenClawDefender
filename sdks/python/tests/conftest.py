"""Shared fixtures — mock ClawDefender MCP server."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import clawdefender
from clawdefender.connection import Connection


# ---------------------------------------------------------------------------
# Canned MCP responses
# ---------------------------------------------------------------------------

CANNED: dict[str, dict[str, Any]] = {
    "checkIntent": {
        "allowed": True,
        "risk_level": "Low",
        "explanation": "Action is safe",
        "policy_rule": "default-allow",
        "suggestions": [],
    },
    "requestPermission": {
        "granted": True,
        "scope": "session",
        "expires_at": None,
    },
    "reportAction": {
        "recorded": True,
        "event_id": "evt-001",
    },
    "getPolicy": {
        "rules": [{"id": "r1", "action": "allow"}],
        "default_action": "allow",
    },
}

DENIED_PERMISSION: dict[str, Any] = {
    "granted": False,
    "scope": "once",
    "expires_at": None,
}

BLOCKED_INTENT: dict[str, Any] = {
    "allowed": False,
    "risk_level": "High",
    "explanation": "Action blocked by policy",
    "policy_rule": "deny-shell",
    "suggestions": ["Use a safer alternative"],
}


class MockConnection(Connection):
    """In-memory connection that returns canned responses."""

    def __init__(self, overrides: dict[str, dict[str, Any]] | None = None) -> None:
        self._overrides = overrides or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((method, params))
        if method in self._overrides:
            return self._overrides[method]
        return CANNED.get(method, {})

    async def asend(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return self.send(method, params)

    def close(self) -> None:
        pass

    @property
    def is_connected(self) -> bool:
        return True


@pytest.fixture()
def mock_conn() -> MockConnection:
    return MockConnection()


@pytest.fixture()
def claw(mock_conn: MockConnection) -> clawdefender.ClawDefender:
    """Return a ClawDefender client wired to the mock connection."""
    client = clawdefender.ClawDefender.__new__(clawdefender.ClawDefender)
    client._conn = mock_conn
    # Also set as default for decorators
    clawdefender._default_client = client
    return client
