"""Connection backends for communicating with the ClawDefender MCP server."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

import httpx

from .exceptions import ConnectionError, ProtocolError

logger = logging.getLogger("clawdefender")

_DEFAULT_HTTP_URL = "http://127.0.0.1:3201"
_TOKEN_PATH = Path.home() / ".local" / "share" / "clawdefender" / "server-token"


def _read_server_token() -> Optional[str]:
    try:
        return _TOKEN_PATH.read_text().strip()
    except OSError:
        return None


class Connection(ABC):
    """Abstract base for MCP transport connections."""

    @abstractmethod
    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        ...

    @abstractmethod
    async def asend(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        ...

    @abstractmethod
    def close(self) -> None:
        ...

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        ...


class StdioConnection(Connection):
    """Spawns ``clawdefender serve`` and communicates via JSON-RPC over stdin/stdout."""

    def __init__(self, command: Optional[str] = None) -> None:
        self._command = command or "clawdefender"
        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._msg_id = 0
        self._initialized = False

    def _ensure_started(self) -> subprocess.Popen:
        if self._process is None or self._process.poll() is not None:
            try:
                self._process = subprocess.Popen(
                    [self._command, "serve"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except FileNotFoundError as exc:
                raise ConnectionError(
                    f"ClawDefender binary not found: {self._command}"
                ) from exc
            self._do_initialize()
        return self._process

    def _next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    def _write_message(self, proc: subprocess.Popen, msg: dict) -> dict:
        assert proc.stdin and proc.stdout
        payload = json.dumps(msg) + "\n"
        proc.stdin.write(payload.encode())
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise ConnectionError("ClawDefender process closed stdout")
        return json.loads(line)

    def _do_initialize(self) -> None:
        proc = self._process
        assert proc is not None
        msg = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "clawdefender-python-sdk", "version": "0.5.0"},
            },
            "id": self._next_id(),
        }
        self._write_message(proc, msg)
        # Send initialized notification
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        assert proc.stdin
        proc.stdin.write((json.dumps(notif) + "\n").encode())
        proc.stdin.flush()
        self._initialized = True

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            proc = self._ensure_started()
            msg = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": method, "arguments": params},
                "id": self._next_id(),
            }
            resp = self._write_message(proc, msg)
            return _extract_result(resp)

    async def asend(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return await asyncio.to_thread(self.send, method, params)

    def close(self) -> None:
        if self._process and self._process.poll() is None:
            self._process.terminate()
            self._process.wait(timeout=5)
        self._process = None
        self._initialized = False

    @property
    def is_connected(self) -> bool:
        return self._process is not None and self._process.poll() is None


class HttpConnection(Connection):
    """Communicates with a running ClawDefender daemon over HTTP."""

    def __init__(self, url: Optional[str] = None) -> None:
        self._url = (url or _DEFAULT_HTTP_URL).rstrip("/")
        self._token = _read_server_token()
        self._client = httpx.Client(timeout=30)
        self._async_client: Optional[httpx.AsyncClient] = None
        self._msg_id = 0
        self._initialized = False

    def _next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _do_initialize(self) -> None:
        msg = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "clawdefender-python-sdk", "version": "0.5.0"},
            },
            "id": self._next_id(),
        }
        self._client.post(self._url, json=msg, headers=self._headers())
        # Send initialized notification
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self._client.post(self._url, json=notif, headers=self._headers())
        self._initialized = True

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._initialized:
            self._do_initialize()
        msg = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": method, "arguments": params},
            "id": self._next_id(),
        }
        resp = self._client.post(self._url, json=msg, headers=self._headers())
        resp.raise_for_status()
        return _extract_result(resp.json())

    async def asend(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(timeout=30)
        if not self._initialized:
            await self._async_initialize()
        msg = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": method, "arguments": params},
            "id": self._next_id(),
        }
        resp = await self._async_client.post(
            self._url, json=msg, headers=self._headers()
        )
        resp.raise_for_status()
        return _extract_result(resp.json())

    async def _async_initialize(self) -> None:
        assert self._async_client is not None
        msg = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "clawdefender-python-sdk", "version": "0.5.0"},
            },
            "id": self._next_id(),
        }
        await self._async_client.post(self._url, json=msg, headers=self._headers())
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        await self._async_client.post(self._url, json=notif, headers=self._headers())
        self._initialized = True

    def close(self) -> None:
        self._client.close()
        if self._async_client:
            # Best-effort close; caller should use async close in async contexts
            try:
                asyncio.get_running_loop().create_task(self._async_client.aclose())
            except RuntimeError:
                pass
        self._initialized = False

    @property
    def is_connected(self) -> bool:
        if not self._initialized:
            return False
        try:
            # Lightweight ping — just check the server answers
            resp = self._client.post(
                self._url,
                json={"jsonrpc": "2.0", "method": "ping", "id": self._next_id()},
                headers=self._headers(),
            )
            return resp.status_code < 500
        except httpx.HTTPError:
            return False


class AutoConnection(Connection):
    """Tries HTTP first; falls back to stdio if the daemon is not running."""

    def __init__(
        self,
        http_url: Optional[str] = None,
        command: Optional[str] = None,
    ) -> None:
        self._http_url = http_url
        self._command = command
        self._inner: Optional[Connection] = None

    def _resolve(self) -> Connection:
        if self._inner is not None:
            return self._inner
        # Try HTTP
        try:
            http = HttpConnection(self._http_url)
            http._do_initialize()
            self._inner = http
            return http
        except Exception:
            pass
        # Fallback to stdio
        try:
            stdio = StdioConnection(self._command)
            stdio._ensure_started()
            self._inner = stdio
            return stdio
        except Exception:
            raise ConnectionError(
                "Cannot connect to ClawDefender via HTTP or stdio"
            )

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return self._resolve().send(method, params)

    async def asend(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return self._resolve().asend(method, params)

    def close(self) -> None:
        if self._inner:
            self._inner.close()
        self._inner = None

    @property
    def is_connected(self) -> bool:
        return self._inner is not None and self._inner.is_connected


class FailOpenConnection(Connection):
    """Wraps any connection with fail-open behaviour.

    If the underlying connection is unavailable, all ``check_intent`` calls
    return ``allowed: true`` and other calls return safe defaults so that the
    host MCP server never crashes.
    """

    def __init__(self, inner_factory: Any) -> None:
        self._factory = inner_factory
        self._inner: Optional[Connection] = None
        self._failed = False

    def _try_connect(self) -> Optional[Connection]:
        if self._inner is not None:
            return self._inner
        try:
            self._inner = self._factory()
            self._failed = False
            return self._inner
        except Exception:
            self._failed = True
            logger.warning(
                "ClawDefender is not available — operating in fail-open mode"
            )
            return None

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        conn = self._try_connect()
        if conn is None:
            return _fail_open_response(method)
        try:
            return conn.send(method, params)
        except Exception:
            logger.warning("ClawDefender call failed — returning fail-open default")
            return _fail_open_response(method)

    async def asend(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        conn = self._try_connect()
        if conn is None:
            return _fail_open_response(method)
        try:
            return await conn.asend(method, params)
        except Exception:
            logger.warning("ClawDefender call failed — returning fail-open default")
            return _fail_open_response(method)

    def close(self) -> None:
        if self._inner:
            self._inner.close()

    @property
    def is_connected(self) -> bool:
        return self._inner is not None and self._inner.is_connected


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_result(resp: dict[str, Any]) -> dict[str, Any]:
    """Pull the tool result text out of an MCP tools/call response."""
    if "error" in resp:
        raise ProtocolError(f"MCP error: {resp['error']}")
    try:
        content = resp["result"]["content"]
        text = next(c["text"] for c in content if c["type"] == "text")
        return json.loads(text)
    except (KeyError, StopIteration, json.JSONDecodeError) as exc:
        raise ProtocolError(f"Unexpected MCP response structure: {resp}") from exc


def _fail_open_response(method: str) -> dict[str, Any]:
    """Return a safe default for any tool when ClawDefender is unreachable."""
    if method == "checkIntent":
        return {
            "allowed": True,
            "risk_level": "Low",
            "explanation": "ClawDefender unavailable — fail-open",
            "policy_rule": "fail-open",
            "suggestions": [],
        }
    if method == "requestPermission":
        return {"granted": True, "scope": "once", "expires_at": None}
    if method == "reportAction":
        return {"recorded": False, "event_id": ""}
    if method == "getPolicy":
        return {"rules": [], "default_action": "allow"}
    return {}
