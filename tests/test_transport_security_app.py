"""The host and origin checks of the HTTP app, through the app itself (#187 D20).

``run_http`` gives ``streamable_http_app()`` no ``host``, and the SDK's default
for it is ``127.0.0.1``. With no transport security passed, the SDK therefore
applied its loopback-only check whatever address the server was bound to. The
server now always passes settings of its own: the loopback entries, what
``MCP_ALLOWED_HOSTS`` lists and what ``MCP_ALLOWED_ORIGINS`` lists. These
tests send requests to the app ``run_http`` hands to uvicorn, bound to
``0.0.0.0``.
"""

import asyncio
import json
from typing import Any

import pytest

import fortianalyzer_mcp.server as server

INITIALIZE = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0"},
        },
    }
).encode()


async def _status(
    monkeypatch: pytest.MonkeyPatch,
    host: str,
    origin: str | None = None,
    *,
    allowed_hosts: list[str] | None = None,
    allowed_origins: list[str] | None = None,
    path: str = "/mcp",
) -> int:
    """The status the app answers an MCP ``initialize`` with."""
    import uvicorn

    monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "secret-token")
    monkeypatch.setattr(server.settings, "MCP_SERVER_HOST", "0.0.0.0")  # noqa: S104
    monkeypatch.setattr(server.settings, "MCP_ALLOWED_HOSTS", allowed_hosts or [])
    monkeypatch.setattr(server.settings, "MCP_ALLOWED_ORIGINS", allowed_origins or [])

    # No FortiAnalyzer behind this app: the lifespan starts the session
    # manager only.
    async def idle() -> None:
        return None

    async def no_stop(_task: Any) -> None:
        return None

    monkeypatch.setattr(server, "_start_faz_client", lambda: asyncio.ensure_future(idle()))
    monkeypatch.setattr(server, "_stop_faz_client", no_stop)

    captured: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(app=app))
    server.run_http()
    app = captured["app"]

    headers = [
        (b"host", host.encode()),
        (b"authorization", b"Bearer secret-token"),
        (b"accept", b"application/json, text/event-stream"),
        (b"content-type", b"application/json"),
    ]
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    get = path == "/health"
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET" if get else "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("192.0.2.10", 40000),
        "server": ("192.0.2.1", 8000),
    }
    sent: list[dict[str, Any]] = []
    pending = [{"type": "http.request", "body": b"" if get else INITIALIZE, "more_body": False}]
    answered = asyncio.Event()

    async def receive() -> dict[str, Any]:
        # The request, and then the client going away once it has its status:
        # a served request is answered as a stream that waits for that.
        if pending:
            return pending.pop()
        await answered.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)
        if message["type"] == "http.response.start":
            answered.set()

    async with app.router.lifespan_context(app):
        await asyncio.wait_for(app(scope, receive, send), timeout=10)
    return int(sent[0]["status"])


class TestNothingConfigured:
    """A server bound to 0.0.0.0 with neither setting: loopback only."""

    @pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "[::1]:8000"])
    async def test_a_loopback_host_is_served(
        self, monkeypatch: pytest.MonkeyPatch, host: str
    ) -> None:
        assert await _status(monkeypatch, host) == 200

    @pytest.mark.parametrize("host", ["evil.example", "192.0.2.1:8000", "mcp.example.com"])
    async def test_any_other_host_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, host: str
    ) -> None:
        assert await _status(monkeypatch, host) == 421

    async def test_a_loopback_origin_is_served(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert await _status(monkeypatch, "127.0.0.1:8000", "http://localhost:8000") == 200

    async def test_any_other_origin_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert await _status(monkeypatch, "127.0.0.1:8000", "https://other.example") == 403

    async def test_the_health_endpoint_is_not_checked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        status = await _status(monkeypatch, "evil.example", "https://other.example", path="/health")

        assert status == 200


class TestOriginsWithoutHosts:
    """``MCP_ALLOWED_ORIGINS`` works on its own, beside the loopback hosts."""

    ORIGINS = ["https://app.example.com"]

    async def test_a_listed_origin_is_served(self, monkeypatch: pytest.MonkeyPatch) -> None:
        status = await _status(
            monkeypatch, "127.0.0.1:8000", "https://app.example.com", allowed_origins=self.ORIGINS
        )

        assert status == 200

    async def test_another_origin_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        status = await _status(
            monkeypatch, "127.0.0.1:8000", "https://other.example", allowed_origins=self.ORIGINS
        )

        assert status == 403

    async def test_the_hosts_stay_loopback_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        status = await _status(
            monkeypatch, "app.example.com", "https://app.example.com", allowed_origins=self.ORIGINS
        )

        assert status == 421


class TestHostsAndOrigins:
    HOSTS = ["example.com"]
    ORIGINS = ["https://app.example.com"]

    @pytest.mark.parametrize("host", ["example.com", "127.0.0.1:8000", "localhost:8000"])
    async def test_the_listed_host_and_loopback_are_served(
        self, monkeypatch: pytest.MonkeyPatch, host: str
    ) -> None:
        assert await _status(monkeypatch, host, allowed_hosts=self.HOSTS) == 200

    async def test_another_host_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert await _status(monkeypatch, "evil.example", allowed_hosts=self.HOSTS) == 421

    async def test_a_listed_origin_is_served(self, monkeypatch: pytest.MonkeyPatch) -> None:
        status = await _status(
            monkeypatch,
            "example.com",
            "https://app.example.com",
            allowed_hosts=self.HOSTS,
            allowed_origins=self.ORIGINS,
        )

        assert status == 200

    async def test_another_origin_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        status = await _status(
            monkeypatch,
            "example.com",
            "https://other.example",
            allowed_hosts=self.HOSTS,
            allowed_origins=self.ORIGINS,
        )

        assert status == 403
