"""Connection to the ClawDefender daemon REST API."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

from .exceptions import DaemonConnectionError

logger = logging.getLogger("clawdefender.agent")

DEFAULT_API_URL = "http://127.0.0.1:3202/api/v1"
TOKEN_PATH = Path.home() / ".local" / "share" / "clawdefender" / "server-token"


def _read_auth_token() -> Optional[str]:
    """Read the daemon auth token from disk."""
    try:
        token_path = Path(os.environ.get("CLAWDEFENDER_TOKEN_PATH", str(TOKEN_PATH)))
        if token_path.exists():
            return token_path.read_text().strip()
    except OSError:
        pass
    return None


class DaemonConnection:
    """HTTP connection to the ClawDefender daemon."""

    def __init__(self, base_url: Optional[str] = None) -> None:
        self._base_url = (base_url or os.environ.get("CLAWDEFENDER_API_URL") or DEFAULT_API_URL).rstrip("/")
        self._token = _read_auth_token()
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            import httpx
            headers: dict[str, str] = {}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            self._client = httpx.Client(
                base_url=self._base_url,
                headers=headers,
                timeout=5.0,
            )
        return self._client

    def create_guard(self, config: dict[str, Any]) -> dict[str, Any]:
        """POST /guard — create a guard and return response data."""
        try:
            client = self._get_client()
            resp = client.post("/guard", json=config)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            raise DaemonConnectionError(f"Failed to create guard: {exc}") from exc

    def delete_guard(self, guard_id: str) -> None:
        """DELETE /guard/{id} — remove a guard."""
        try:
            client = self._get_client()
            resp = client.delete(f"/guard/{guard_id}")
            resp.raise_for_status()
        except Exception as exc:
            raise DaemonConnectionError(f"Failed to delete guard: {exc}") from exc

    def get_stats(self, guard_id: str) -> dict[str, Any]:
        """GET /guard/{id}/stats — get guard statistics."""
        try:
            client = self._get_client()
            resp = client.get(f"/guard/{guard_id}/stats")
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            raise DaemonConnectionError(f"Failed to get guard stats: {exc}") from exc

    def check_action(self, guard_id: str, action: str, target: str) -> dict[str, Any]:
        """POST /guard/{id}/check — check if an action is allowed."""
        try:
            client = self._get_client()
            resp = client.post(f"/guard/{guard_id}/check", json={"action": action, "target": target})
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            raise DaemonConnectionError(f"Failed to check action: {exc}") from exc

    def health(self) -> bool:
        """GET /health — check daemon health."""
        try:
            client = self._get_client()
            resp = client.get("/health")
            return resp.status_code == 200
        except Exception:
            return False

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
