"""
Plaud MCP Server — package entrypoint.

Reads MCP_TRANSPORT env var (default: "stdio") and starts the server
on the appropriate transport.

  stdio        — MCP over stdin/stdout (Claude Code, Claude Desktop)
  http         — MCP over streamable-http. Listens on FASTMCP_HOST:FASTMCP_PORT
                 (default 127.0.0.1:8080) and needs PLAUD_MCP_HTTP_TOKEN_FILE,
                 or PLAUD_MCP_HTTP_NO_AUTH=true to run without a client token.
"""
import asyncio
import logging
import os

from starlette.middleware import Middleware as ASGIMiddleware

from .auth import TokenManager
from .config import settings
from .http_security import HttpAccessMiddleware, http_settings, is_loopback
from .server import mcp


def _bootstrap_token() -> None:
    """Ensure a valid token exists before the MCP server starts.

    Only relevant when ``PLAUD_AUTO_REFRESH=true``. Performs an initial
    password login if the token file is missing or expiring.
    """
    if not settings.plaud_auto_refresh:
        return

    manager = TokenManager(
        token_file=settings.plaud_token_file,
        base_url=settings.plaud_base_url,
        device_id=settings.plaud_device_id,
        app_version=settings.plaud_app_version,
        email=settings.plaud_email,
        password=settings.plaud_password,
    )
    asyncio.run(manager.ensure_valid_token())


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    _bootstrap_token()

    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower().strip()
    if transport == "http":
        host, port, token = http_settings()
        mcp.run(
            transport="streamable-http",
            host=host,
            port=port,
            # No tool keeps per-session state, and stateless mode lets clients
            # carry on after a server restart.
            stateless_http=True,
            middleware=[
                ASGIMiddleware(
                    HttpAccessMiddleware, token=token, port=port, local_only=is_loopback(host)
                )
            ],
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
