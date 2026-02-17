"""ClawDefender SDK types — request/response dataclasses and enums."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ActionType(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    SHELL_EXECUTE = "shell_execute"
    NETWORK_REQUEST = "network_request"
    RESOURCE_ACCESS = "resource_access"
    OTHER = "other"


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Operation(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    CONNECT = "connect"


class PermissionScope(str, Enum):
    ONCE = "once"
    SESSION = "session"
    PERMANENT = "permanent"


class ActionResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"


@dataclass
class CheckIntentResponse:
    allowed: bool
    risk_level: RiskLevel
    explanation: str
    policy_rule: str
    suggestions: list[str] = field(default_factory=list)


@dataclass
class RequestPermissionResponse:
    granted: bool
    scope: PermissionScope
    expires_at: Optional[datetime] = None


@dataclass
class ReportActionResponse:
    recorded: bool
    event_id: str


@dataclass
class GetPolicyResponse:
    rules: list[dict]
    default_action: str
