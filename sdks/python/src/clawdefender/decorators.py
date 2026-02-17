"""Decorators for declarative ClawDefender integration."""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
from typing import Any, Callable, Optional

from .exceptions import PermissionDenied

logger = logging.getLogger("clawdefender")

# Parameter names we inspect to auto-detect the *target* of an action.
_TARGET_PARAM_NAMES = ("path", "file", "filepath", "filename", "command", "cmd", "url")


def _resolve_target(
    func: Callable,
    args: tuple,
    kwargs: dict[str, Any],
    target_param: Optional[str],
) -> str:
    """Try to find the target string from function arguments."""
    sig = inspect.signature(func)
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()

    if target_param and target_param in bound.arguments:
        return str(bound.arguments[target_param])

    for name in _TARGET_PARAM_NAMES:
        if name in bound.arguments:
            return str(bound.arguments[name])

    # Fall back to the first positional string argument
    for val in bound.arguments.values():
        if isinstance(val, str):
            return val

    return "<unknown>"


def _get_client() -> Any:
    """Obtain the default ClawDefender client.

    Import here to avoid circular imports; the client module sets a module-level
    ``_default_client`` when :func:`clawdefender.init` is called or a
    ``ClawDefender`` instance is created.
    """
    from . import _default_client  # type: ignore[attr-defined]

    return _default_client


def requires_permission(
    operation: str,
    justification: str = "",
    target_param: Optional[str] = None,
    client: Optional[Any] = None,
) -> Callable:
    """Decorator that requests ClawDefender permission before executing.

    Raises :class:`PermissionDenied` if the permission is denied.

    Works with both sync and async functions.
    """

    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                claw = client or _get_client()
                target = _resolve_target(func, args, kwargs, target_param)
                resp = await claw.arequest_permission(
                    resource=target,
                    operation=operation,
                    justification=justification or f"Calling {func.__name__}",
                )
                if not resp.granted:
                    raise PermissionDenied(target, operation)
                return await func(*args, **kwargs)

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                claw = client or _get_client()
                target = _resolve_target(func, args, kwargs, target_param)
                resp = claw.request_permission(
                    resource=target,
                    operation=operation,
                    justification=justification or f"Calling {func.__name__}",
                )
                if not resp.granted:
                    raise PermissionDenied(target, operation)
                return func(*args, **kwargs)

            return sync_wrapper

    return decorator


def reports_action(
    action_type: str,
    target_param: Optional[str] = None,
    client: Optional[Any] = None,
) -> Callable:
    """Decorator that reports the action to ClawDefender after execution.

    Reports success or failure based on whether the function raises.

    Works with both sync and async functions.
    """

    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                claw = client or _get_client()
                target = _resolve_target(func, args, kwargs, target_param)
                result_status = "success"
                try:
                    result = await func(*args, **kwargs)
                except Exception:
                    result_status = "failure"
                    raise
                finally:
                    await claw.areport_action(
                        description=f"{func.__name__}({target})",
                        action_type=action_type,
                        target=target,
                        result=result_status,
                    )
                return result

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                claw = client or _get_client()
                target = _resolve_target(func, args, kwargs, target_param)
                result_status = "success"
                try:
                    result = func(*args, **kwargs)
                except Exception:
                    result_status = "failure"
                    raise
                finally:
                    claw.report_action(
                        description=f"{func.__name__}({target})",
                        action_type=action_type,
                        target=target,
                        result=result_status,
                    )
                return result

            return sync_wrapper

    return decorator
