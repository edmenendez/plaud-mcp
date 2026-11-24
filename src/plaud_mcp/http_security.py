"""Access control for HTTP mode.

Clients send ``Authorization: Bearer <token>``, where the token is the content
of ``PLAUD_MCP_HTTP_TOKEN_FILE`` (read at start). Requests with an ``Origin``
header (browsers) are refused, and on loopback the ``Host`` must be localhost,
which blocks DNS rebinding from web pages.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Paths that need no token. /health reveals nothing but "ok".
OPEN_PATHS = frozenset({"/health"})


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def load_token(path: str) -> str:
    try:
        token = Path(path).expanduser().read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"Cannot read token file {path}") from exc
    if len(token) < 32:
        raise RuntimeError(f"Token in {path} must be at least 32 characters")
    return token


class HttpAccessMiddleware:
    """ASGI middleware: refuse browsers, check Host on loopback, check the bearer token."""

    def __init__(self, app: Any, token: str | None, port: int, local_only: bool) -> None:
        self.app = app
        self.expected = f"Bearer {token}".encode() if token else None
        self.local_only = local_only
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope["headers"])

        # MCP clients send no Origin; browsers always do on POST.
        if b"origin" in headers:
            await _deny(send, 403, "Browser requests are not allowed")
            return
        host = headers.get(b"host", b"").decode("latin-1").lower()
        if self.local_only and host not in self.allowed_hosts:
            await _deny(send, 421, "Host not allowed")
            return

        if (
            self.expected is not None
            and scope["path"] not in OPEN_PATHS
            and not hmac.compare_digest(headers.get(b"authorization", b""), self.expected)
        ):
            await _deny(send, 401, "Missing or invalid token", bearer=True)
            return

        await self.app(scope, receive, send)


async def _deny(send: Any, status: int, message: str, bearer: bool = False) -> None:
    body = json.dumps({"error": message}).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    if bearer:
        headers.append((b"www-authenticate", b"Bearer"))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def http_settings() -> tuple[str, int, str | None]:
    """Host, port and token for HTTP mode. A token is required unless explicitly turned off."""
    host = os.environ.get("FASTMCP_HOST", "127.0.0.1")
    port = int(os.environ.get("FASTMCP_PORT", "8080"))
    token_file = os.environ.get("PLAUD_MCP_HTTP_TOKEN_FILE", "").strip()
    no_auth = os.environ.get("PLAUD_MCP_HTTP_NO_AUTH", "").strip().lower() in {"1", "true", "yes"}

    if token_file:
        return host, port, load_token(token_file)
    if no_auth:
        logger.warning("HTTP mode without a client token (PLAUD_MCP_HTTP_NO_AUTH=true)")
        return host, port, None
    raise RuntimeError(
        "HTTP mode needs PLAUD_MCP_HTTP_TOKEN_FILE. To run without a client token "
        "(for example behind a cluster network policy), set PLAUD_MCP_HTTP_NO_AUTH=true."
    )
