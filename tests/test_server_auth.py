"""Fail-closed HTTP auth guard (security regression).

The HTTP transport fronts the full tool surface (incl. destructive device
add/delete and PCAP download), so it must refuse to start unauthenticated unless
the operator explicitly opts out with MCP_ALLOW_NO_AUTH=true.
"""

from typing import Any

import pytest

import fortianalyzer_mcp.server as server


class TestHttpAuthFailClosed:
    def test_token_set_allows_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A configured token satisfies the guard."""
        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "secret-token")
        monkeypatch.setattr(server.settings, "MCP_ALLOW_NO_AUTH", False)
        server._ensure_http_auth_or_die()  # must not raise

    def test_no_token_no_optout_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No token + no opt-out => refuse to start (SystemExit)."""
        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", None)
        monkeypatch.setattr(server.settings, "MCP_ALLOW_NO_AUTH", False)
        with pytest.raises(SystemExit) as exc:
            server._ensure_http_auth_or_die()
        assert "MCP_AUTH_TOKEN" in str(exc.value)

    def test_no_token_empty_string_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty-string token (the Docker default) is treated as unset."""
        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "")
        monkeypatch.setattr(server.settings, "MCP_ALLOW_NO_AUTH", False)
        with pytest.raises(SystemExit):
            server._ensure_http_auth_or_die()

    def test_explicit_optout_allows_no_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Explicit MCP_ALLOW_NO_AUTH=true permits unauthenticated start (logged)."""
        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", None)
        monkeypatch.setattr(server.settings, "MCP_ALLOW_NO_AUTH", True)
        server._ensure_http_auth_or_die()  # must not raise


async def _status_for(
    monkeypatch: pytest.MonkeyPatch,
    authorization: bytes,
    path: str = "/mcp",
    token: str = "secret-token",
) -> int:
    """Status the HTTP app answers a request carrying this raw Authorization header.

    The app is the one run_http() hands to uvicorn. The header goes into the
    ASGI scope as bytes, the way the server passes it on, so nothing between
    the test and the middleware decodes it first.
    """
    import uvicorn

    monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", token)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(app=app))
    server.run_http()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"example.com"), (b"authorization", authorization)],
        "client": ("192.0.2.10", 40000),
        "server": ("192.0.2.1", 8000),
    }
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await captured["app"](scope, receive, send)
    return int(sent[0]["status"])


class TestBearerAuthMiddleware:
    @pytest.mark.parametrize(
        "authorization",
        [
            b"\xff",
            b"Bearer \xff\xfe",
            b"Bearer secret-token\xff",
            b"Bearer secret-token\xc3",
        ],
    )
    async def test_undecodable_header_is_unauthorized(
        self, monkeypatch: pytest.MonkeyPatch, authorization: bytes
    ) -> None:
        """A header that is not valid UTF-8 is a wrong token: 401, not a crash.

        Decoding it raised UnicodeDecodeError ahead of the comparison, so an
        unauthenticated request got a 500 and a traceback in the log. The last
        two carry the real token followed by an invalid byte and must not pass.
        """
        assert await _status_for(monkeypatch, authorization) == 401

    async def test_non_ascii_header_is_unauthorized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Valid UTF-8 beyond ASCII is compared like any other wrong token."""
        assert await _status_for(monkeypatch, "Bearer s\u00e9cret-token".encode()) == 401

    async def test_correct_token_reaches_the_app(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Control: the right token passes, and the 404 comes from the router behind it."""
        status = await _status_for(monkeypatch, b"Bearer secret-token", path="/no-such-route")
        assert status == 404

    async def test_non_ascii_token_accepts_only_its_utf8_bytes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A configured token beyond ASCII is matched as its UTF-8 bytes, as
        before. The same characters in another encoding are a wrong token."""
        token = "s\u00e9cret-token"
        utf8 = f"Bearer {token}".encode()
        latin1 = f"Bearer {token}".encode("latin-1")

        assert await _status_for(monkeypatch, utf8, path="/no-such-route", token=token) == 404
        assert await _status_for(monkeypatch, latin1, token=token) == 401

    async def test_invalid_byte_does_not_match_a_replacement_character(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U+FFFD is what a lenient decode puts in place of an invalid byte.
        A token that holds one must not be matched by that byte."""
        status = await _status_for(monkeypatch, b"Bearer tok\xff", token="tok\ufffd")
        assert status == 401
