"""AgentGuard — main entry point for agent self-protection."""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from .connection import DaemonConnection
from .exceptions import (
    DaemonConnectionError,
    GuardActivationError,
    GuardNotActiveError,
)
from .fallback import EmbeddedEnforcer
from .monitor import MonitorLog
from .types import ActionVerdict, CheckResult, GuardMode, GuardStats

logger = logging.getLogger("clawdefender.agent")


class AgentGuard:
    """Guard that enforces security policies on an AI agent.

    Can operate in two modes:
    - **daemon mode**: Connects to the ClawDefender daemon REST API for full enforcement.
    - **embedded mode**: Falls back to in-process enforcement when daemon is unavailable.

    Supports both sync and async context manager protocols.
    """

    def __init__(
        self,
        name: str,
        allowed_paths: Optional[list[str]] = None,
        allowed_tools: Optional[list[str]] = None,
        blocked_paths: Optional[list[str]] = None,
        network_allowlist: Optional[list[str]] = None,
        shell_policy: str = "deny",
        allowed_commands: Optional[list[str]] = None,
        max_file_size: Optional[int] = None,
        max_files_per_minute: Optional[int] = None,
        max_network_requests_per_minute: Optional[int] = None,
        mode: str = "enforce",
    ) -> None:
        self.name = name
        self._config = {
            "name": name,
            "allowed_paths": allowed_paths,
            "allowed_tools": allowed_tools,
            "blocked_paths": blocked_paths,
            "network_allowlist": network_allowlist,
            "shell_policy": shell_policy,
            "allowed_commands": allowed_commands,
            "max_file_size": max_file_size,
            "max_files_per_minute": max_files_per_minute,
            "max_network_requests_per_minute": max_network_requests_per_minute,
            "mode": mode,
        }
        self._mode = GuardMode(mode)
        self._active = False
        self._guard_id: Optional[str] = None
        self._connection: Optional[DaemonConnection] = None
        self._enforcer: Optional[EmbeddedEnforcer] = None
        self._monitor: Optional[MonitorLog] = None
        self._embedded = False
        self._activated_at: float = 0.0

        # Stats for daemon mode
        self._allowed_count_local = 0
        self._blocked_count_local = 0

        if self._mode == GuardMode.MONITOR:
            self._monitor = MonitorLog()

    def activate(self, fallback: bool = False) -> None:
        """Activate the guard.

        Attempts to connect to the daemon REST API at port 3202.
        If the daemon is unavailable and ``fallback=True``, switches
        to embedded in-process enforcement.

        Parameters
        ----------
        fallback:
            If True, fall back to embedded mode when daemon is unavailable.
        """
        if self._active:
            return

        # Try daemon connection first
        try:
            self._connection = DaemonConnection()
            result = self._connection.create_guard(self._config)
            self._guard_id = result.get("id") or result.get("guard_id")
            self._embedded = False
            self._active = True
            self._activated_at = time.monotonic()
            logger.info("AgentGuard '%s' activated via daemon (id=%s)", self.name, self._guard_id)
            return
        except Exception as exc:
            if not fallback:
                raise GuardActivationError(
                    f"Failed to connect to daemon and fallback=False: {exc}"
                ) from exc
            logger.debug("Daemon unavailable, falling back to embedded mode: %s", exc)

        # Fallback to embedded enforcement
        self._enforcer = EmbeddedEnforcer(**self._config)
        self._enforcer.activate()
        self._embedded = True
        self._active = True
        self._activated_at = time.monotonic()

    def deactivate(self) -> None:
        """Deactivate the guard and release resources."""
        if not self._active:
            return

        if self._connection and self._guard_id:
            try:
                self._connection.delete_guard(self._guard_id)
            except Exception as exc:
                logger.warning("Failed to delete guard from daemon: %s", exc)
            finally:
                self._connection.close()
                self._connection = None
                self._guard_id = None

        if self._enforcer:
            self._enforcer.deactivate()
            self._enforcer = None

        self._active = False
        logger.info("AgentGuard '%s' deactivated", self.name)

    def check_action(self, action: str, target: str) -> CheckResult:
        """Check if an action is allowed by the guard.

        Parameters
        ----------
        action:
            The type of action (e.g. ``"file_read"``, ``"shell_execute"``).
        target:
            The target of the action (e.g. a file path, command, URL).

        Returns
        -------
        CheckResult
            Whether the action is allowed and why.
        """
        if not self._active:
            raise GuardNotActiveError("Guard is not active. Call activate() first.")

        if self._monitor and self._mode == GuardMode.MONITOR:
            # In monitor mode, run the check but always allow
            result = self._do_check(action, target)
            self._monitor.record(
                action=action,
                target=target,
                would_block=not result.allowed,
                reason=result.reason,
            )
            # Monitor mode allows everything
            return CheckResult(
                allowed=True,
                action=action,
                target=target,
                reason=f"[monitor] {result.reason}" if result.reason else "[monitor] allowed",
                verdict=ActionVerdict.WARN if not result.allowed else ActionVerdict.ALLOW,
            )

        return self._do_check(action, target)

    def _do_check(self, action: str, target: str) -> CheckResult:
        """Perform the actual check against daemon or embedded enforcer."""
        if self._embedded and self._enforcer:
            return self._enforcer.check_action(action, target)

        if self._connection and self._guard_id:
            try:
                data = self._connection.check_action(self._guard_id, action, target)
                allowed = data.get("allowed", True)
                if allowed:
                    self._allowed_count_local += 1
                else:
                    self._blocked_count_local += 1
                return CheckResult(
                    allowed=allowed,
                    action=action,
                    target=target,
                    reason=data.get("reason", ""),
                    verdict=ActionVerdict(data.get("verdict", "allow")),
                )
            except DaemonConnectionError:
                # If daemon drops mid-session, block by default
                self._blocked_count_local += 1
                return CheckResult(
                    allowed=False,
                    action=action,
                    target=target,
                    reason="Daemon connection lost — blocking by default",
                    verdict=ActionVerdict.BLOCK,
                )

        raise GuardNotActiveError("No enforcer or connection available")

    def stats(self) -> GuardStats:
        """Get guard statistics."""
        if not self._active:
            raise GuardNotActiveError("Guard is not active.")

        if self._embedded and self._enforcer:
            return self._enforcer.stats()

        if self._connection and self._guard_id:
            try:
                data = self._connection.get_stats(self._guard_id)
                return GuardStats(
                    name=data.get("name", self.name),
                    mode=data.get("mode", self._mode.value),
                    active=True,
                    allowed_count=data.get("allowed_count", self._allowed_count_local),
                    blocked_count=data.get("blocked_count", self._blocked_count_local),
                    checked_count=data.get("checked_count", self._allowed_count_local + self._blocked_count_local),
                    uptime_seconds=data.get("uptime_seconds", time.monotonic() - self._activated_at),
                )
            except DaemonConnectionError:
                pass

        uptime = time.monotonic() - self._activated_at if self._active else 0.0
        return GuardStats(
            name=self.name,
            mode=self._mode.value,
            active=self._active,
            allowed_count=self._allowed_count_local,
            blocked_count=self._blocked_count_local,
            checked_count=self._allowed_count_local + self._blocked_count_local,
            uptime_seconds=uptime,
        )

    def is_healthy(self) -> bool:
        """Check if the guard is still actively enforcing."""
        if not self._active:
            return False

        if self._embedded:
            return self._enforcer is not None and self._enforcer.active

        if self._connection:
            return self._connection.health()

        return False

    def suggest_permissions(self) -> dict:
        """Analyze monitor mode data and suggest minimal permissions.

        Only meaningful when ``mode="monitor"``.
        """
        if self._monitor is None:
            return {"error": "Not in monitor mode"}
        return self._monitor.suggest_permissions()

    @property
    def blocked_count(self) -> int:
        if self._embedded and self._enforcer:
            return self._enforcer.stats().blocked_count
        return self._blocked_count_local

    @property
    def allowed_count(self) -> int:
        if self._embedded and self._enforcer:
            return self._enforcer.stats().allowed_count
        return self._allowed_count_local

    @property
    def active(self) -> bool:
        return self._active

    # ------------------------------------------------------------------
    # Context manager protocols
    # ------------------------------------------------------------------

    def __enter__(self) -> AgentGuard:
        self.activate(fallback=True)
        return self

    def __exit__(self, *args: Any) -> None:
        self.deactivate()

    async def __aenter__(self) -> AgentGuard:
        self.activate(fallback=True)
        return self

    async def __aexit__(self, *args: Any) -> None:
        self.deactivate()

    def __del__(self) -> None:
        if self._active:
            try:
                self.deactivate()
            except Exception:
                pass
