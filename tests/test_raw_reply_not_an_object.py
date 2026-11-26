"""A raw reply whose JSON body is not an object is an error (#204, item 18).

The raw request path read the body with membership tests (``"error" in
result``, ``"result" not in result``). For a JSON array those test the list's
items, so ``[]`` read as the documented empty reply and ``get_alerts``
answered success with 0 rows. A string body ran the same tests on its
characters, and ``null`` or a number raised a ``TypeError``. A 200 object
without ``result`` stays the empty reply (tests/test_raw_request_http_status.py).
"""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.tools import event_tools
from fortianalyzer_mcp.utils.errors import APIError
from tests.appliance_wire import Wire, new_client

ALERTS = "/eventmgmt/adom/root/alerts"
WINDOW = {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}
#: Bodies that are JSON and not an object. The second is a JSON-RPC batch
#: reply, which a single request never gets.
BODIES = pytest.mark.parametrize(
    "body",
    [b"[]", b'[{"result": [{"status": {"code": 0}}]}]', b'"there was an error"', b"null", b"1"],
    ids=["empty array", "array", "string", "null", "number"],
)
MESSAGE = (
    "The reply was not FortiAnalyzer's JSON-RPC answer (HTTP 200, its body is not a JSON "
    f"object) (url: GET {ALERTS})"
)


@pytest.fixture
async def client(wire: Wire) -> FortiAnalyzerClient:
    connected = new_client("token")
    await connected.connect()
    return connected


@BODIES
async def test_it_is_an_error_not_an_empty_answer(
    client: FortiAnalyzerClient, wire: Wire, body: bytes
) -> None:
    wire.replies[ALERTS] = (200, body)
    with pytest.raises(APIError) as refused:
        await client.get_alerts(adom="root", time_range=WINDOW)
    assert str(refused.value) == MESSAGE
    assert not client.is_reachable


@BODIES
async def test_a_tool_answers_an_error(
    client: FortiAnalyzerClient, wire: Wire, body: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(event_tools, "get_faz_client", lambda: client)
    wire.replies[ALERTS] = (200, body)
    result = await event_tools.get_alerts(time_range="2024-01-01 00:00:00|2024-01-02 00:00:00")
    assert result == {"status": "error", "message": MESSAGE}


async def test_an_object_without_result_is_still_the_empty_reply(
    client: FortiAnalyzerClient, wire: Wire
) -> None:
    """A control: the documented case, through the real pyFMG session."""
    wire.replies["/report/adom/root/run"] = (200, b'{"jsonrpc": "2.0", "id": 1}')
    assert await client._raw_request("get", "/report/adom/root/run") == {"data": []}
