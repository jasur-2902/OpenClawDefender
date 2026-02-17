"""Types for the ClawDefender agent package."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ActionVerdict(str, Enum):
    """Result of a guard check."""
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"


class GuardMode(str, Enum):
    """Guard operating mode."""
    ENFORCE = "enforce"
    MONITOR = "monitor"


class ShellPolicy(str, Enum):
    """Shell execution policy."""
    DENY = "deny"
    ALLOWLIST = "allowlist"
    APPROVE = "approve"


@dataclass
class CheckResult:
    """Result of checking an action against the guard."""
    allowed: bool
    action: str
    target: str
    reason: str = ""
    verdict: ActionVerdict = ActionVerdict.ALLOW

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class GuardStats:
    """Statistics for a guard instance."""
    name: str
    mode: str
    active: bool
    allowed_count: int = 0
    blocked_count: int = 0
    checked_count: int = 0
    uptime_seconds: float = 0.0


@dataclass
class MonitorRecord:
    """A single recorded operation in monitor mode."""
    timestamp: float
    action: str
    target: str
    would_block: bool
    reason: str = ""


@dataclass
class PermissionConfig:
    """Suggested permission configuration from monitor mode analysis."""
    allowed_paths: list[str] = field(default_factory=list)
    blocked_paths: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    network_allowlist: list[str] = field(default_factory=list)
    allowed_commands: list[str] = field(default_factory=list)
    shell_policy: str = "deny"
    max_file_size: Optional[int] = None
    max_files_per_minute: Optional[int] = None
    max_network_requests_per_minute: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.allowed_paths:
            result["allowed_paths"] = self.allowed_paths
        if self.blocked_paths:
            result["blocked_paths"] = self.blocked_paths
        if self.allowed_tools:
            result["allowed_tools"] = self.allowed_tools
        if self.network_allowlist:
            result["network_allowlist"] = self.network_allowlist
        if self.allowed_commands:
            result["allowed_commands"] = self.allowed_commands
        result["shell_policy"] = self.shell_policy
        if self.max_file_size is not None:
            result["max_file_size"] = self.max_file_size
        if self.max_files_per_minute is not None:
            result["max_files_per_minute"] = self.max_files_per_minute
        if self.max_network_requests_per_minute is not None:
            result["max_network_requests_per_minute"] = self.max_network_requests_per_minute
        return result
