"""Embedded fallback enforcement when daemon is unavailable."""

from __future__ import annotations

import fnmatch
import logging
import os
import time
from typing import Optional

from .types import ActionVerdict, CheckResult, GuardStats

logger = logging.getLogger("clawdefender.agent")


class EmbeddedEnforcer:
    """In-process guard enforcement without the daemon.

    Implements path matching, tool allowlisting, and rate limiting
    purely in Python when the ClawDefender daemon is not available.
    """

    def __init__(
        self,
        name: str,
        allowed_paths: Optional[list[str]] = None,
        blocked_paths: Optional[list[str]] = None,
        allowed_tools: Optional[list[str]] = None,
        network_allowlist: Optional[list[str]] = None,
        shell_policy: str = "deny",
        allowed_commands: Optional[list[str]] = None,
        max_file_size: Optional[int] = None,
        max_files_per_minute: Optional[int] = None,
        max_network_requests_per_minute: Optional[int] = None,
        mode: str = "enforce",
    ) -> None:
        self.name = name
        self.allowed_paths = allowed_paths
        self.blocked_paths = blocked_paths or []
        self.allowed_tools = allowed_tools
        self.network_allowlist = network_allowlist
        self.shell_policy = shell_policy
        self.allowed_commands = allowed_commands or []
        self.max_file_size = max_file_size
        self.max_files_per_minute = max_files_per_minute
        self.max_network_requests_per_minute = max_network_requests_per_minute
        self.mode = mode

        self._allowed_count = 0
        self._blocked_count = 0
        self._active = False
        self._activated_at: float = 0.0

        # Rate limiting state
        self._file_ops: list[float] = []
        self._network_ops: list[float] = []

    def activate(self) -> None:
        logger.info("AgentGuard running in embedded mode (name=%s)", self.name)
        self._active = True
        self._activated_at = time.monotonic()

    def deactivate(self) -> None:
        self._active = False

    @property
    def active(self) -> bool:
        return self._active

    def check_action(self, action: str, target: str) -> CheckResult:
        """Check if an action is allowed under the current policy."""
        allowed = True
        reason = ""

        if action in ("file_read", "file_write", "file_delete"):
            allowed, reason = self._check_path(target)
            if allowed:
                allowed, reason = self._check_file_rate()

        elif action == "shell_execute":
            allowed, reason = self._check_shell(target)

        elif action == "network_request":
            allowed, reason = self._check_network(target)
            if allowed:
                allowed, reason = self._check_network_rate()

        elif action == "tool_use":
            allowed, reason = self._check_tool(target)

        if allowed:
            self._allowed_count += 1
        else:
            self._blocked_count += 1

        return CheckResult(
            allowed=allowed,
            action=action,
            target=target,
            reason=reason,
            verdict=ActionVerdict.ALLOW if allowed else ActionVerdict.BLOCK,
        )

    def stats(self) -> GuardStats:
        uptime = time.monotonic() - self._activated_at if self._active else 0.0
        return GuardStats(
            name=self.name,
            mode=self.mode,
            active=self._active,
            allowed_count=self._allowed_count,
            blocked_count=self._blocked_count,
            checked_count=self._allowed_count + self._blocked_count,
            uptime_seconds=uptime,
        )

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_path(self, path: str) -> tuple[bool, str]:
        resolved = os.path.abspath(path)

        # Check blocked paths first
        for pattern in self.blocked_paths:
            if fnmatch.fnmatch(resolved, pattern) or resolved.startswith(pattern):
                return False, f"Path blocked by pattern: {pattern}"

        # If allowed_paths is set, path must match at least one
        if self.allowed_paths is not None:
            for pattern in self.allowed_paths:
                if fnmatch.fnmatch(resolved, pattern) or resolved.startswith(pattern):
                    return True, ""
            return False, f"Path not in allowed list: {resolved}"

        return True, ""

    def _check_shell(self, command: str) -> tuple[bool, str]:
        if self.shell_policy == "deny":
            return False, "Shell execution denied by policy"

        if self.shell_policy == "allowlist":
            cmd_name = command.split()[0] if command.strip() else command
            for allowed in self.allowed_commands:
                if cmd_name == allowed or fnmatch.fnmatch(cmd_name, allowed):
                    return True, ""
            return False, f"Command not in allowlist: {cmd_name}"

        # "approve" mode — allow for embedded fallback (no daemon to prompt)
        return True, ""

    def _check_network(self, target: str) -> tuple[bool, str]:
        if self.network_allowlist is None:
            return True, ""

        for pattern in self.network_allowlist:
            if fnmatch.fnmatch(target, pattern) or target.startswith(pattern):
                return True, ""

        return False, f"Network target not in allowlist: {target}"

    def _check_tool(self, tool_name: str) -> tuple[bool, str]:
        if self.allowed_tools is None:
            return True, ""

        if tool_name in self.allowed_tools:
            return True, ""

        return False, f"Tool not in allowed list: {tool_name}"

    def _check_file_rate(self) -> tuple[bool, str]:
        if self.max_files_per_minute is None:
            return True, ""

        now = time.monotonic()
        self._file_ops = [t for t in self._file_ops if now - t < 60.0]
        if len(self._file_ops) >= self.max_files_per_minute:
            return False, f"File rate limit exceeded ({self.max_files_per_minute}/min)"
        self._file_ops.append(now)
        return True, ""

    def _check_network_rate(self) -> tuple[bool, str]:
        if self.max_network_requests_per_minute is None:
            return True, ""

        now = time.monotonic()
        self._network_ops = [t for t in self._network_ops if now - t < 60.0]
        if len(self._network_ops) >= self.max_network_requests_per_minute:
            return False, f"Network rate limit exceeded ({self.max_network_requests_per_minute}/min)"
        self._network_ops.append(now)
        return True, ""
