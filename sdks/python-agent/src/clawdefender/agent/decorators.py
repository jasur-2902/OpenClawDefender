"""Decorators for wrapping functions with guard protection."""

from __future__ import annotations

import asyncio
import functools
import signal
from typing import Any, Callable, Optional

from .guard import AgentGuard


def restricted(
    allowed_paths: Optional[list[str]] = None,
    allowed_tools: Optional[list[str]] = None,
    blocked_paths: Optional[list[str]] = None,
    network: str = "deny",
    shell: str = "deny",
    allowed_commands: Optional[list[str]] = None,
    network_allowlist: Optional[list[str]] = None,
    max_file_size: Optional[int] = None,
    max_files_per_minute: Optional[int] = None,
    max_network_requests_per_minute: Optional[int] = None,
    mode: str = "enforce",
    **kwargs: Any,
) -> Callable:
    """Decorator that wraps a function with guard protection.

    The guard is activated before the function runs and deactivated after,
    regardless of whether the function succeeds or raises.

    Works with both sync and async functions.
    """
    # Handle network policy: "deny" means empty allowlist
    net_allowlist = network_allowlist
    if network == "deny" and net_allowlist is None:
        net_allowlist = []  # empty = block all
    elif network == "allow" and net_allowlist is None:
        net_allowlist = None  # None = allow all

    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kw: Any) -> Any:
                guard = AgentGuard(
                    name=func.__qualname__,
                    allowed_paths=allowed_paths,
                    allowed_tools=allowed_tools,
                    blocked_paths=blocked_paths,
                    network_allowlist=net_allowlist,
                    shell_policy=shell,
                    allowed_commands=allowed_commands,
                    max_file_size=max_file_size,
                    max_files_per_minute=max_files_per_minute,
                    max_network_requests_per_minute=max_network_requests_per_minute,
                    mode=mode,
                )
                guard.activate(fallback=True)
                try:
                    return await func(*args, **kw)
                finally:
                    guard.deactivate()
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kw: Any) -> Any:
                guard = AgentGuard(
                    name=func.__qualname__,
                    allowed_paths=allowed_paths,
                    allowed_tools=allowed_tools,
                    blocked_paths=blocked_paths,
                    network_allowlist=net_allowlist,
                    shell_policy=shell,
                    allowed_commands=allowed_commands,
                    max_file_size=max_file_size,
                    max_files_per_minute=max_files_per_minute,
                    max_network_requests_per_minute=max_network_requests_per_minute,
                    mode=mode,
                )
                guard.activate(fallback=True)
                try:
                    return func(*args, **kw)
                finally:
                    guard.deactivate()
            return sync_wrapper
    return decorator


def sandboxed(timeout: int = 30) -> Callable:
    """Decorator that blocks ALL external access with a timeout.

    The decorated function runs with no network, no shell, and no file
    access outside the current directory. A timeout kills execution.
    """
    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kw: Any) -> Any:
                guard = AgentGuard(
                    name=f"sandbox:{func.__qualname__}",
                    allowed_paths=[],
                    blocked_paths=["/*"],
                    network_allowlist=[],
                    shell_policy="deny",
                    mode="enforce",
                )
                guard.activate(fallback=True)
                try:
                    return await asyncio.wait_for(
                        func(*args, **kw),
                        timeout=timeout,
                    )
                finally:
                    guard.deactivate()
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kw: Any) -> Any:
                guard = AgentGuard(
                    name=f"sandbox:{func.__qualname__}",
                    allowed_paths=[],
                    blocked_paths=["/*"],
                    network_allowlist=[],
                    shell_policy="deny",
                    mode="enforce",
                )
                guard.activate(fallback=True)

                def _timeout_handler(signum: int, frame: Any) -> None:
                    raise TimeoutError(f"Sandboxed function timed out after {timeout}s")

                old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
                signal.alarm(timeout)
                try:
                    return func(*args, **kw)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
                    guard.deactivate()
            return sync_wrapper
    return decorator
