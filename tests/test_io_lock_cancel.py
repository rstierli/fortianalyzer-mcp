"""The I/O lock is held until the worker thread returns (#187 D22).

A cancelled call left its ``async with`` block, which released the lock while
its worker thread was still inside pyFMG. The next call then ran beside it:
two threads on one ``requests.Session``, which is not thread-safe.
"""

import asyncio
import json
import threading
from typing import Any
from unittest.mock import MagicMock

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class _Appliance:
    """Counts the threads inside it, and can hold one call until released."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._inside = 0
        self.peak = 0
        self.entered = threading.Event()
        self.release = threading.Event()

    def call(self, hold: bool) -> None:
        with self._guard:
            self._inside += 1
            self.peak = max(self.peak, self._inside)
        try:
            if hold:
                self.entered.set()
                self.release.wait(5)
        finally:
            with self._guard:
                self._inside -= 1

    async def wait_entered(self) -> None:
        assert await asyncio.to_thread(self.entered.wait, 2), "the held call never started"


def _verbs(fmg: MagicMock, appliance: _Appliance) -> None:
    def get(url: str, **_: Any) -> tuple[int, Any]:
        appliance.call(hold=url == "/slow")
        return 0, {"url": url}

    def post(*_: Any, **kwargs: Any) -> MagicMock:
        url = json.loads(kwargs["data"])["params"][0]["url"]
        appliance.call(hold=url == "/slow")
        reply = MagicMock()
        reply.status_code = 200
        reply.json.return_value = {"result": {"url": url}}
        return reply

    fmg.get.side_effect = get
    fmg.sess = MagicMock()
    fmg.sess.post.side_effect = post


async def _cancel(task: "asyncio.Task[Any]") -> None:
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


class TestLockOutlivesACancelledCall:
    async def test_the_next_call_waits_for_the_cancelled_calls_worker(
        self, mock_client: FortiAnalyzerClient, mock_fmg_instance: MagicMock
    ) -> None:
        appliance = _Appliance()
        _verbs(mock_fmg_instance, appliance)

        first = asyncio.create_task(mock_client.get("/slow"))
        await appliance.wait_entered()
        await _cancel(first)

        second = asyncio.create_task(mock_client.get("/fast"))
        await asyncio.sleep(0.1)
        assert not second.done(), "the second call ran beside the abandoned worker"
        assert appliance.peak == 1

        appliance.release.set()
        assert await asyncio.wait_for(second, 2) == {"url": "/fast"}
        assert appliance.peak == 1

    async def test_the_raw_request_path_waits_too(
        self, mock_client: FortiAnalyzerClient, mock_fmg_instance: MagicMock
    ) -> None:
        appliance = _Appliance()
        _verbs(mock_fmg_instance, appliance)

        first = asyncio.create_task(mock_client._raw_request("get", "/slow"))
        await appliance.wait_entered()
        await _cancel(first)

        second = asyncio.create_task(mock_client._raw_request("get", "/fast"))
        await asyncio.sleep(0.1)
        assert not second.done()

        appliance.release.set()
        assert await asyncio.wait_for(second, 2) == {"url": "/fast"}
        assert appliance.peak == 1

    async def test_a_call_that_ends_normally_frees_the_lock_at_once(
        self, mock_client: FortiAnalyzerClient, mock_fmg_instance: MagicMock
    ) -> None:
        _verbs(mock_fmg_instance, _Appliance())

        assert await mock_client.get("/fast") == {"url": "/fast"}
        assert not mock_client._io_lock.locked()
        assert await mock_client.get("/fast") == {"url": "/fast"}

    async def test_a_call_that_fails_frees_the_lock(
        self, mock_client: FortiAnalyzerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.side_effect = ValueError("boom")

        with pytest.raises(ValueError):
            await mock_client.get("/x")

        assert not mock_client._io_lock.locked()


class TestDisconnectBehindAnAbandonedCall:
    async def test_it_does_not_wait_out_the_request_and_skips_the_logout(
        self,
        mock_client: FortiAnalyzerClient,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Shutdown must stay short, and a logout beside the abandoned worker
        would be the overlap again. The session is left to idle out."""
        appliance = _Appliance()
        _verbs(mock_fmg_instance, appliance)
        monkeypatch.setattr(FortiAnalyzerClient, "_LOGOUT_TIMEOUT", 0.2)

        call = asyncio.create_task(mock_client.get("/slow"))
        await appliance.wait_entered()
        await _cancel(call)

        await asyncio.wait_for(mock_client.disconnect(), 2)

        assert not mock_client.is_connected
        assert mock_fmg_instance.logout.call_count == 0
        assert appliance.peak == 1
        appliance.release.set()

    async def test_it_logs_out_once_the_worker_has_returned(
        self,
        mock_client: FortiAnalyzerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        appliance = _Appliance()
        _verbs(mock_fmg_instance, appliance)

        call = asyncio.create_task(mock_client.get("/slow"))
        await appliance.wait_entered()
        await _cancel(call)
        appliance.release.set()

        await asyncio.wait_for(mock_client.disconnect(), 2)

        assert mock_fmg_instance.logout.call_count == 1
        assert not mock_client.is_connected
