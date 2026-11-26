"""What answers on the wire instead of FortiAnalyzer, under the real pyFMG.

A test that swaps pyFMG's ``FortiManager`` for a mock decides itself what
pyFMG makes of a reply. These helpers leave pyFMG and ``requests`` in place
and answer the HTTP request pyFMG sends, so a test sees what the client does
with pyFMG's real outcome: its code 100 for a body that is not JSON, or the
exception it raises after a login that opened no session. The raw request
path posts on pyFMG's session too, so it is answered here as well. The
``wire`` fixture (conftest.py) puts a ``Wire`` in place for one test.
Ported from fortimanager-mcp's ``tests/appliance_wire.py``, with the open
sessions counted.
"""

import io
import json
from typing import Any

import requests

from fortianalyzer_mcp.api.client import FortiAnalyzerClient

HOST = "faz.example.com"
#: Constructor arguments per authentication mode.
AUTH: dict[str, dict[str, str]] = {
    "token": {"api_token": "token-for-tests"},
    "session": {"username": "admin", "password": "password-for-tests"},
}
BAD_GATEWAY = (502, b"<html><body><h1>502 Bad Gateway</h1></body></html>")
UNAVAILABLE = (503, b"")
LOGIN = ("exec", "sys/login/user")


class Wire:
    """Answers each JSON-RPC request the way a FortiAnalyzer would, until told otherwise."""

    def __init__(self) -> None:
        #: (method, url) of every request sent, in order.
        self.calls: list[tuple[str, str]] = []
        #: (HTTP status, body) sent in place of FortiAnalyzer's answer to
        #: every request, as a proxy in front of it does when it cannot reach it.
        self.page: tuple[int, bytes] | None = None
        #: The same, for every request but the login.
        self.page_after_login: tuple[int, bytes] | None = None
        #: url -> (HTTP status, body) sent as it is, as JSON.
        self.replies: dict[str, tuple[int, bytes]] = {}
        #: Nothing listens: the connection is refused.
        self.refuses = False
        #: FortiAnalyzer's status for a login; a rejected one opens no session.
        self.login = (0, "OK")
        #: Whether an accepted login opens a session.
        self.opens_session = True
        #: The sessions logged in and not logged out.
        self.live: set[str] = set()
        #: url -> (code, message, data) for everything that is not a login.
        self.answers: dict[str, tuple[int, str, Any]] = {
            "/sys/status": (0, "OK", {"Hostname": "faz-01", "Version": "v7.6.5-build3653"}),
        }
        self._opened = 0

    def logins(self) -> int:
        return self.calls.count(LOGIN)

    def send(self, request: requests.PreparedRequest) -> requests.Response:
        call = json.loads(request.body or b"{}")
        url = call["params"][0]["url"]
        self.calls.append((call["method"], url))
        if self.refuses:
            raise requests.exceptions.ConnectionError("connection refused")
        if self.page is not None:
            return _response(request, *self.page, "text/html")
        if self.page_after_login is not None and (call["method"], url) != LOGIN:
            return _response(request, *self.page_after_login, "text/html")
        if url in self.replies:
            return _response(request, *self.replies[url], "application/json")
        reply: dict[str, Any] = {"id": call["id"]}
        if (call["method"], url) == LOGIN:
            code, message = self.login
            result: dict[str, Any] = {"status": {"code": code, "message": message}, "url": url}
            if code == 0 and self.opens_session:
                self._opened += 1
                reply["session"] = f"session-{self._opened}"
                self.live.add(reply["session"])
        elif url == "sys/logout":
            self.live.discard(call.get("session"))
            result = {"status": {"code": 0, "message": "OK"}, "url": url}
        else:
            code, message, data = self.answers.get(url, (0, "OK", {}))
            result = {"status": {"code": code, "message": message}, "url": url}
            if code == 0:
                result["data"] = data
        reply["result"] = [result]
        return _response(request, 200, json.dumps(reply).encode(), "application/json")


def _response(
    request: requests.PreparedRequest, status: int, body: bytes, content_type: str
) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.raw = io.BytesIO(body)
    response.headers["Content-Type"] = content_type
    response.request = request
    response.url = request.url or ""
    return response


def new_client(auth: str) -> FortiAnalyzerClient:
    """A client as the server builds it, not yet connected."""
    return FortiAnalyzerClient(host=HOST, connect_on_demand=True, **AUTH[auth])
