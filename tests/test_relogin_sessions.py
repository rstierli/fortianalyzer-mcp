"""A re-login after -11 ends the old session first (#187 D21).

FortiAnalyzer answers -11 both for a session that is gone and for a call the
account may not make. The client cannot tell which, so it logs in again once.
It used to do that beside the old session: when -11 was a denial the old
session was still alive, and every denied call left one more on the appliance.
"""

import asyncio
import threading
from typing import Any

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.utils.errors import PermissionError as FazPermissionError

DENIED = (-11, {"status": {"code": -11, "message": "No permission for the resource"}})


class _Appliance:
    """The sessions it has open, and every call it was sent."""

    def __init__(self) -> None:
        self.live: set[str] = set()
        self.logins = 0
        self.logouts = 0
        self.calls: list[tuple[str, str, bool]] = []  # (session, url, session was live)
        self.timeouts: list[tuple[str, int]] = []  # (url or "logout", the handle's timeout)
        self.hold = threading.Event()
        self.holding = threading.Event()
        self.hold.set()
        self.logout_hold = threading.Event()
        self.in_logout = threading.Event()
        self.logout_hold.set()


class _Handle:
    """Stands in for pyFMG's FortiManager: one handle, one session."""

    def __init__(self, appliance: _Appliance, *, token: bool, timeout: int = 30) -> None:
        self._appliance = appliance
        self.api_key_used = token
        self.sid: str | None = None
        self.timeout = timeout
        self.req_id = 0

    def login(self) -> tuple[int, dict[str, Any]]:
        self._appliance.logins += 1
        self.sid = f"session-{self._appliance.logins}"
        if not self.api_key_used:
            self._appliance.live.add(self.sid)
        return 0, {"status": {"code": 0, "message": "OK"}}

    def logout(self) -> tuple[int, dict[str, Any]] | None:
        if self.sid is None:
            return None
        self._appliance.timeouts.append(("logout", self.timeout))
        self._appliance.in_logout.set()
        self._appliance.logout_hold.wait(5)
        self._appliance.logouts += 1
        self._appliance.live.discard(self.sid)
        self.sid = None
        return 0, {"status": {"code": 0, "message": "OK"}}

    def get(self, url: str, **_: Any) -> tuple[int, Any]:
        # pyFMG raises here, with the whole request in the message.
        assert self.sid is not None, f"{url} was sent on a handle whose session was ended"
        live = self.api_key_used or self.sid in self._appliance.live
        self._appliance.calls.append((self.sid, url, live))
        self._appliance.timeouts.append((url, self.timeout))
        if url == "/held":
            self._appliance.holding.set()
            self._appliance.hold.wait(5)
        if not live or url in ("/denied", "/held"):
            return DENIED
        return 0, {"url": url}


@pytest.fixture
def appliance(monkeypatch: pytest.MonkeyPatch) -> _Appliance:
    appliance = _Appliance()
    monkeypatch.setattr(
        "fortianalyzer_mcp.api.client.FortiManager",
        lambda *_a, **kw: _Handle(appliance, token="apikey" in kw, timeout=kw["timeout"]),
    )
    return appliance


def _password_client() -> FortiAnalyzerClient:
    return FortiAnalyzerClient(host="faz.example.com", username="admin", password="password")


class TestReloginEndsTheOldSession:
    async def test_five_denied_calls_leave_one_session(self, appliance: _Appliance) -> None:
        client = _password_client()
        await client.connect()

        for _ in range(5):
            with pytest.raises(FazPermissionError):
                await client.get("/denied")

        assert len(appliance.live) == 1
        assert appliance.logins - appliance.logouts == 1
        assert client.is_connected

    async def test_a_refusal_after_the_relogin_is_a_permission_error(
        self, appliance: _Appliance
    ) -> None:
        client = _password_client()
        await client.connect()

        with pytest.raises(FazPermissionError) as caught:
            await client.get("/denied")

        assert caught.value.code == -11
        # One re-login for the call, not one per attempt.
        assert appliance.logins == 2
        assert [url for _, url, _ in appliance.calls] == ["/denied", "/denied"]

    async def test_an_expired_session_is_replaced_and_the_call_succeeds(
        self, appliance: _Appliance
    ) -> None:
        client = _password_client()
        await client.connect()
        appliance.live.clear()  # the appliance closed the idle session

        assert await client.get("/ok") == {"url": "/ok"}

        assert len(appliance.live) == 1
        assert appliance.logins == 2

    async def test_a_call_queued_behind_the_denied_one_runs_on_a_live_session(
        self, appliance: _Appliance
    ) -> None:
        """No call is sent on a session that was ended, and none on a handle
        with no session: the queued call runs before the logout or after the
        new login, never between."""
        client = _password_client()
        await client.connect()
        appliance.hold.clear()

        denied = asyncio.create_task(client.get("/held"))
        assert await asyncio.to_thread(appliance.holding.wait, 2)
        queued = asyncio.create_task(client.get("/ok"))
        late = asyncio.create_task(client.get("/ok"))
        await asyncio.sleep(0)
        appliance.hold.set()

        assert await asyncio.wait_for(queued, 5) == {"url": "/ok"}
        assert await asyncio.wait_for(late, 5) == {"url": "/ok"}
        with pytest.raises(FazPermissionError):
            await asyncio.wait_for(denied, 5)

        assert all(live for _, _, live in appliance.calls), appliance.calls
        assert len(appliance.live) == 1

    async def test_a_call_that_arrives_during_the_logout_waits_for_the_new_session(
        self, appliance: _Appliance
    ) -> None:
        """The handle is dropped before the logout starts, so a call that
        arrives while the old session is being ended cannot pick it up."""
        client = _password_client()
        await client.connect()
        appliance.logout_hold.clear()

        denied = asyncio.create_task(client.get("/denied"))
        assert await asyncio.to_thread(appliance.in_logout.wait, 2)
        arrived = asyncio.create_task(client.get("/ok"))
        await asyncio.sleep(0.05)
        appliance.logout_hold.set()

        assert await asyncio.wait_for(arrived, 5) == {"url": "/ok"}
        with pytest.raises(FazPermissionError):
            await asyncio.wait_for(denied, 5)

        assert all(live for _, _, live in appliance.calls), appliance.calls
        assert ("session-2", "/ok", True) in appliance.calls
        assert len(appliance.live) == 1

    async def test_a_token_client_has_no_session_to_end(self, appliance: _Appliance) -> None:
        client = FortiAnalyzerClient(host="faz.example.com", api_token="t")
        await client.connect()

        with pytest.raises(FazPermissionError):
            await client.get("/denied")

        assert appliance.logouts == 0
        assert client.is_connected


class TestTheLogoutTimeoutStaysWithTheLogout:
    """The logout is sent with a short timeout, set on the handle. Set before
    the logout had its turn, it was also the timeout of a call that was queued
    on the same handle ahead of it: 5 seconds where the deployment had set
    120, and a write that times out is not retried."""

    def _client(self) -> FortiAnalyzerClient:
        return FortiAnalyzerClient(
            host="faz.example.com", username="admin", password="password", timeout=120
        )

    async def test_a_call_queued_ahead_of_the_logout_keeps_its_timeout(
        self, appliance: _Appliance
    ) -> None:
        client = self._client()
        await client.connect()
        appliance.hold.clear()

        denied = asyncio.create_task(client.get("/held"))
        assert await asyncio.to_thread(appliance.holding.wait, 2)
        queued = [asyncio.create_task(client.get("/ok")) for _ in range(3)]
        await asyncio.sleep(0)
        appliance.hold.set()

        for call in queued:
            assert await asyncio.wait_for(call, 5) == {"url": "/ok"}
        with pytest.raises(FazPermissionError):
            await asyncio.wait_for(denied, 5)

        assert ("logout", 5) in appliance.timeouts
        assert {seen for what, seen in appliance.timeouts if what != "logout"} == {120}

    async def test_the_handle_has_its_timeout_back_after_the_logout(
        self, appliance: _Appliance
    ) -> None:
        """A call queued behind the logout reads the handle's timeout too
        (the raw request path takes it from the handle when it runs)."""
        client = self._client()
        await client.connect()
        handle = client._fmg
        assert handle is not None

        await client._logout(handle, wait=None)

        assert appliance.timeouts == [("logout", 5)]
        assert handle.timeout == 120

    async def test_a_logout_that_is_skipped_leaves_the_timeout_alone(
        self, appliance: _Appliance
    ) -> None:
        client = self._client()
        await client.connect()
        handle = client._fmg
        assert handle is not None
        appliance.hold.clear()
        held = asyncio.create_task(client.get("/held"))
        assert await asyncio.to_thread(appliance.holding.wait, 2)

        await client._logout(handle, wait=0.05)

        assert handle.timeout == 120
        assert appliance.logouts == 0
        appliance.hold.set()
        with pytest.raises(FazPermissionError):
            await asyncio.wait_for(held, 5)
