"""A reply that is not FortiAnalyzer's JSON-RPC answer is not FortiAnalyzer answering (#204, item 17).

A proxy in front of FortiAnalyzer that cannot reach it answers with its own
page (a 502 or 503). pyFMG hands that back as code 100 with the HTTP
response itself, and the raw request path refuses any status of 400 and up
without reading the body. The client took either for "FortiAnalyzer
answered", so ``/health`` kept saying ``fortianalyzer_connected: true`` while
every tool call failed, and the error a tool returned was ``<Response [502]>``.
The same rule and wording as fortimanager-mcp#141.
"""

import asyncio
import json
from typing import Any

import pytest

import fortianalyzer_mcp.server as server
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.tools import system_tools
from fortianalyzer_mcp.utils.errors import APIError, ResourceNotFoundError
from tests.appliance_wire import AUTH, BAD_GATEWAY, UNAVAILABLE, Wire, new_client

PAGES = pytest.mark.parametrize("page", [BAD_GATEWAY, UNAVAILABLE], ids=["502 page", "503 empty"])
WINDOW = {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}


@pytest.fixture(params=list(AUTH))
async def client(request: pytest.FixtureRequest, wire: Wire) -> FortiAnalyzerClient:
    """Connected over the wire, with token and with session authentication."""
    connected = new_client(request.param)
    await connected.connect()
    assert connected.is_reachable
    return connected


def built_app(monkeypatch: pytest.MonkeyPatch) -> Any:
    """The app run_http hands to uvicorn."""
    import uvicorn

    monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "secret-token")
    captured: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(app=app))
    server.run_http()
    return captured["app"]


async def health(app: Any) -> dict[str, Any]:
    """GET /health on that app."""
    sent: list[dict[str, Any]] = []
    pending = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive() -> dict[str, Any]:
        return pending.pop() if pending else {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/health",
        "raw_path": b"/health",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"127.0.0.1:8000")],
        "client": ("198.51.100.7", 55000),
        "server": ("127.0.0.1", 8000),
    }
    await asyncio.wait_for(app(scope, receive, send), timeout=10)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    answer: dict[str, Any] = json.loads(body)
    return answer


@PAGES
async def test_a_page_marks_fortianalyzer_unreachable(
    client: FortiAnalyzerClient, wire: Wire, page: tuple[int, bytes]
) -> None:
    wire.page = page
    with pytest.raises(APIError):
        await client.get_system_status()
    assert client.is_connected
    assert not client.is_reachable

    wire.page = None
    await client.get_system_status()
    assert client.is_reachable


@PAGES
async def test_on_the_raw_request_path_too(
    client: FortiAnalyzerClient, wire: Wire, page: tuple[int, bytes]
) -> None:
    wire.page = page
    with pytest.raises(APIError):
        await client.get_alerts(adom="root", time_range=WINDOW)
    assert client.is_connected
    assert not client.is_reachable

    wire.page = None
    await client.get_alerts(adom="root", time_range=WINDOW)
    assert client.is_reachable


@PAGES
async def test_health_follows_it(
    client: FortiAnalyzerClient,
    wire: Wire,
    page: tuple[int, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Through the tool and the app run_http serves, as an operator sees it."""
    app = built_app(monkeypatch)
    monkeypatch.setattr(server, "faz_client", client)
    monkeypatch.setattr(system_tools, "get_faz_client", lambda: client)
    assert (await health(app))["fortianalyzer_connected"] is True

    wire.page = page
    for _ in range(3):
        assert (await system_tools.get_system_status())["status"] == "error"
        assert (await health(app))["fortianalyzer_connected"] is False

    wire.page = None
    assert (await system_tools.get_system_status())["status"] == "success"
    assert (await health(app))["fortianalyzer_connected"] is True


#: What a tool answers per HTTP status. A proxy serves such a page, and so
#: may FortiAnalyzer's own web server while its JSON-RPC backend restarts.
TOOL_MESSAGE = {
    502: "The reply was not FortiAnalyzer's JSON-RPC answer (HTTP 502, its body is not JSON) "
    "(url: GET /sys/status)",
    503: "The reply was not FortiAnalyzer's JSON-RPC answer (HTTP 503, its body is not JSON) "
    "(url: GET /sys/status)",
}


@PAGES
async def test_a_tool_names_the_reply_for_what_it_is_not(
    client: FortiAnalyzerClient,
    wire: Wire,
    page: tuple[int, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(system_tools, "get_faz_client", lambda: client)
    wire.page = page
    result = await system_tools.get_system_status()
    assert result == {"status": "error", "message": TOOL_MESSAGE[page[0]]}


@PAGES
async def test_a_page_starts_no_new_login(
    client: FortiAnalyzerClient, wire: Wire, page: tuple[int, bytes]
) -> None:
    """It is not a session error: logging in again would only hit the same page."""
    logins = wire.logins()
    wire.page = page
    with pytest.raises(APIError):
        await client.get_system_status()
    assert wire.logins() == logins
    assert wire.calls[-1] == ("get", "/sys/status")


async def test_a_429_page_on_the_pyfmg_path_marks_unreachable(
    client: FortiAnalyzerClient, wire: Wire
) -> None:
    """On the pyFMG path the rule is the body: a page that is not JSON is
    code 100, whatever its status. What FortiAnalyzer's own rate limit
    answers was not measured."""
    wire.page = (429, b"<html>Too Many Requests</html>")
    with pytest.raises(APIError):
        await client.get_system_status()
    assert not client.is_reachable


ALERTS = "/eventmgmt/adom/root/alerts"


@pytest.mark.parametrize("status", [429, 403, 404, 499])
async def test_a_4xx_on_the_raw_path_is_fortianalyzer_answering(
    client: FortiAnalyzerClient, wire: Wire, status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """As on 2.18.0. FortiAnalyzer's own API rate limit answers 429, so a
    status below 500 is taken as its answer: the same error, and the flag
    /health reads is cleared as for any answer."""
    app = built_app(monkeypatch)
    monkeypatch.setattr(server, "faz_client", client)
    wire.replies[ALERTS] = (status, b'{"message": "refused"}')
    for unreachable_before in (True, False):
        client._unreachable = unreachable_before
        with pytest.raises(APIError) as refused:
            await client.get_alerts(adom="root", time_range=WINDOW)
        assert str(refused.value) == (
            f"HTTP {status} from FortiAnalyzer for GET {ALERTS}; the reply was not read"
        )
        assert refused.value.code is None
        assert (await health(app))["fortianalyzer_connected"] is True


@pytest.mark.parametrize("status", [500, 502, 503, 504])
async def test_a_5xx_on_the_raw_path_marks_unreachable(
    client: FortiAnalyzerClient, wire: Wire, status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = built_app(monkeypatch)
    monkeypatch.setattr(server, "faz_client", client)
    wire.replies[ALERTS] = (status, b'{"jsonrpc": "2.0", "id": 1}')
    with pytest.raises(APIError) as refused:
        await client.get_alerts(adom="root", time_range=WINDOW)
    assert str(refused.value) == (
        f"HTTP {status} from FortiAnalyzer for GET {ALERTS}; the reply was not read"
    )
    assert (await health(app))["fortianalyzer_connected"] is False

    del wire.replies[ALERTS]
    await client.get_alerts(adom="root", time_range=WINDOW)
    assert (await health(app))["fortianalyzer_connected"] is True


async def test_an_error_code_is_still_an_answer(client: FortiAnalyzerClient, wire: Wire) -> None:
    """A control: FortiAnalyzer answering with one of its own codes is reachable."""
    client._unreachable = True
    wire.answers["/sys/status"] = (-4, "Object not found", None)
    with pytest.raises(ResourceNotFoundError):
        await client.get_system_status()
    assert client.is_reachable
