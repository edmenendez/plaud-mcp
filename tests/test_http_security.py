"""HTTP mode access control: bearer token, Host and Origin checks."""
import pytest
from starlette.middleware import Middleware as ASGIMiddleware
from starlette.testclient import TestClient

from plaud_mcp.http_security import HttpAccessMiddleware, http_settings, load_token
from plaud_mcp.server import mcp

PORT = 8781
TOKEN = "t" * 40
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def make_client(token=TOKEN, host="127.0.0.1", local_only=True):
    app = mcp.http_app(
        stateless_http=True,
        middleware=[ASGIMiddleware(HttpAccessMiddleware, token=token, port=PORT, local_only=local_only)],
    )
    return TestClient(app, base_url=f"http://{host}:{PORT}")


def list_tools(client, auth=f"Bearer {TOKEN}", **headers):
    headers = {"accept": "application/json, text/event-stream", **headers}
    if auth:
        headers["authorization"] = auth
    return client.post("/mcp", headers=headers, json=LIST_TOOLS)


def test_right_token_lists_tools():
    with make_client() as client:
        resp = list_tools(client)
    assert resp.status_code == 200
    assert "get_audio_url" in resp.text


@pytest.mark.parametrize("auth", [None, "Bearer " + "x" * 40, f"Basic {TOKEN}", TOKEN])
def test_missing_or_wrong_token_is_refused(auth):
    with make_client() as client:
        resp = list_tools(client, auth=auth)
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


def test_health_needs_no_token():
    with make_client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_no_auth_mode_needs_no_token():
    with make_client(token=None, local_only=False) as client:
        assert list_tools(client, auth=None).status_code == 200


def test_foreign_host_is_refused_on_loopback():
    with make_client(host="evil.example") as client:
        assert list_tools(client).status_code == 421
        assert client.get("/health").status_code == 421


def test_localhost_host_is_allowed():
    with make_client(host="localhost") as client:
        assert list_tools(client).status_code == 200


def test_host_check_off_when_not_loopback():
    with make_client(host="plaud-mcp.svc", local_only=False) as client:
        assert list_tools(client).status_code == 200


@pytest.mark.parametrize("local_only", [True, False])
def test_any_origin_is_refused(local_only):
    with make_client(local_only=local_only) as client:
        resp = list_tools(client, origin=f"http://127.0.0.1:{PORT}")
    assert resp.status_code == 403


def test_short_token_is_refused(tmp_path):
    path = tmp_path / "token"
    path.write_text("short\n")
    with pytest.raises(RuntimeError, match="at least 32"):
        load_token(str(path))


def test_token_file_is_trimmed(tmp_path):
    path = tmp_path / "token"
    path.write_text(f"{TOKEN}\n")
    assert load_token(str(path)) == TOKEN


def test_http_needs_token_or_explicit_opt_out(monkeypatch):
    monkeypatch.delenv("PLAUD_MCP_HTTP_TOKEN_FILE", raising=False)
    monkeypatch.delenv("PLAUD_MCP_HTTP_NO_AUTH", raising=False)
    with pytest.raises(RuntimeError, match="PLAUD_MCP_HTTP_NO_AUTH"):
        http_settings()


def test_token_file_wins_over_opt_out(monkeypatch, tmp_path):
    path = tmp_path / "token"
    path.write_text(TOKEN)
    monkeypatch.setenv("PLAUD_MCP_HTTP_TOKEN_FILE", str(path))
    monkeypatch.setenv("PLAUD_MCP_HTTP_NO_AUTH", "true")
    assert http_settings()[2] == TOKEN


def test_defaults_to_loopback_8080(monkeypatch):
    monkeypatch.delenv("FASTMCP_HOST", raising=False)
    monkeypatch.delenv("FASTMCP_PORT", raising=False)
    monkeypatch.delenv("PLAUD_MCP_HTTP_TOKEN_FILE", raising=False)
    monkeypatch.setenv("PLAUD_MCP_HTTP_NO_AUTH", "true")
    assert http_settings() == ("127.0.0.1", 8080, None)
