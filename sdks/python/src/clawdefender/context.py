"""Context manager for guarded actions."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional

from .types import ActionResult, ActionType, CheckIntentResponse, RiskLevel

if TYPE_CHECKING:
    from .client import ClawDefender

logger = logging.getLogger("clawdefender")


class GuardedAction:
    """Returned by :meth:`ClawDefender.guarded_action`.

    Use as a sync or async context manager to check intent before performing
    an action, then report the outcome automatically.
    """

    def __init__(
        self,
        client: ClawDefender,
        description: str,
        action_type: str,
        target: str,
    ) -> None:
        self._client = client
        self._description = description
        self._action_type = action_type
        self._target = target
        self._intent: Optional[CheckIntentResponse] = None
        self._reported = False

    @property
    def allowed(self) -> bool:
        return self._intent.allowed if self._intent else False

    @property
    def explanation(self) -> str:
        return self._intent.explanation if self._intent else ""

    @property
    def risk_level(self) -> Optional[RiskLevel]:
        return self._intent.risk_level if self._intent else None

    # -- sync ---------------------------------------------------------------

    def __enter__(self) -> GuardedAction:
        self._intent = self._client.check_intent(
            description=self._description,
            action_type=self._action_type,
            target=self._target,
        )
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if not self._reported and self._intent and self._intent.allowed:
            result = ActionResult.FAILURE if exc_type else ActionResult.SUCCESS
            self._do_report(result.value)

    # -- async --------------------------------------------------------------

    async def __aenter__(self) -> GuardedAction:
        self._intent = await self._client.acheck_intent(
            description=self._description,
            action_type=self._action_type,
            target=self._target,
        )
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if not self._reported and self._intent and self._intent.allowed:
            result = ActionResult.FAILURE if exc_type else ActionResult.SUCCESS
            await self._client.areport_action(
                description=self._description,
                action_type=self._action_type,
                target=self._target,
                result=result.value,
            )
            self._reported = True

    # -- explicit reporting -------------------------------------------------

    def report_success(self, details: Optional[dict[str, Any]] = None) -> None:
        self._do_report(ActionResult.SUCCESS.value, details)

    def report_failure(self, details: Optional[dict[str, Any]] = None) -> None:
        self._do_report(ActionResult.FAILURE.value, details)

    def _do_report(
        self, result: str, details: Optional[dict[str, Any]] = None
    ) -> None:
        if self._reported:
            return
        self._client.report_action(
            description=self._description,
            action_type=self._action_type,
            target=self._target,
            result=result,
            details=details,
        )
        self._reported = True
