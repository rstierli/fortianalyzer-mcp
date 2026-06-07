"""Tests for log search pagination, tid lifecycle, and reuse.

These exercise query_logs / fetch_more_logs / cancel_log_search through a
stateful in-memory FortiAnalyzer fake that models the *real* appliance
contract discovered on the lab FAZ (7.6.x):

- ``logsearch_start(offset, limit)`` issues a task id (tid).
- The first ``logsearch_fetch`` returns ``data[offset:offset+limit]`` plus a
  ``total-count``; the task is then reaped, so a *second* fetch on the same tid
  raises "Invalid tid".
- Therefore pagination is done by running a *fresh* search per page (the tid is
  not reusable). For a fixed time window the row order is stable across
  searches, so offset/limit paging is consistent.

The tools expose a reusable *pagination handle* (still called ``tid`` for
compatibility) backed by an in-process registry of search parameters.
"""

from zoneinfo import ZoneInfo

import pytest

import fortianalyzer_mcp.tools.log_tools as log_tools
from fortianalyzer_mcp.utils.errors import ResourceNotFoundError

CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"


def _rows(n: int) -> list[dict[str, object]]:
    """Build n distinct, stably ordered traffic log rows."""
    return [
        {"id": i, "srcip": f"10.0.0.{i}", "dstport": 443, "proto": "6", "action": "accept"}
        for i in range(n)
    ]


class FakeFaz:
    """Faithful fake of the FortiAnalyzer log-search surface.

    Models single-use tids: the first fetch delivers an offset slice plus
    ``total-count`` and reaps the task; any later fetch on that tid raises
    "Invalid tid". ``complete_on_attempt`` simulates a task that reaps
    mid-poll before completing, forcing the tool to re-issue the search.
    """

    def __init__(
        self,
        dataset: list[dict[str, object]],
        *,
        tz: ZoneInfo | None = None,
        connected: bool = True,
        complete_on_attempt: int = 1,
        omit_total: bool = False,
    ) -> None:
        self.dataset = dataset
        self.tz = tz
        self.connected = connected
        self.complete_on_attempt = complete_on_attempt
        self.omit_total = omit_total
        self.reconnects = 0
        self._tasks: dict[int, dict[str, object]] = {}
        self._next_tid = 1000
        self._start_count = 0
        self.start_calls: list[dict[str, object]] = []
        self.cancelled: list[int] = []

    @property
    def is_connected(self) -> bool:
        return self.connected

    async def ensure_connected(self) -> None:
        if not self.connected:
            self.reconnects += 1
            self.connected = True

    async def get_system_timezone(self) -> ZoneInfo | None:
        return self.tz

    async def logsearch_start(
        self,
        adom: str,
        logtype: str,
        device: object,
        time_range: object,
        filter: str | None = None,
        limit: int = 100,
        offset: int = 0,
        **_kw: object,
    ) -> dict[str, object]:
        self._start_count += 1
        self.start_calls.append(
            {"adom": adom, "logtype": logtype, "filter": filter, "offset": offset, "limit": limit}
        )
        tid = self._next_tid
        self._next_tid += 1
        self._tasks[tid] = {"adom": adom, "alive": True, "attempt": self._start_count}
        return {"tid": tid}

    async def logsearch_fetch(
        self,
        adom: str,
        tid: int,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, object]:
        task = self._tasks.get(tid)
        if task is None or not task["alive"] or task["adom"] != adom:
            raise ResourceNotFoundError(f"Invalid tid {tid} for fetching result.", code=-1)
        task["alive"] = False  # single-use: task is reaped after one fetch
        page = self.dataset[offset : offset + limit]
        complete = int(task["attempt"]) >= self.complete_on_attempt
        result: dict[str, object] = {
            "percentage": 100 if complete else 50,
            "return-lines": len(page),
            "data": page,
            "tid": tid,
            "status": {"code": 0, "message": "succeeded"},
        }
        if not self.omit_total:
            result["total-count"] = len(self.dataset)
        return result

    async def logsearch_cancel(self, adom: str, tid: int) -> dict[str, object]:
        self.cancelled.append(tid)
        self._tasks.pop(tid, None)
        return {"status": {"code": 0, "message": "ok"}}


@pytest.fixture(autouse=True)
def _clear_registry() -> None:
    """Keep the module-level search registry isolated per test."""
    log_tools._SEARCH_REGISTRY.clear()
    yield
    log_tools._SEARCH_REGISTRY.clear()


def _install(monkeypatch: pytest.MonkeyPatch, fake: FakeFaz) -> None:
    monkeypatch.setattr(log_tools, "get_faz_client", lambda: fake)


class TestQueryLogsPagination:
    async def test_returns_handle_and_has_more(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A limit smaller than the total yields a handle and has_more=True."""
        fake = FakeFaz(_rows(25))
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(
            adom="root", logtype="traffic", time_range=CUSTOM_RANGE, limit=10
        )

        assert result["status"] == "success"
        assert result["count"] == 10
        assert [row["id"] for row in result["logs"]] == list(range(10))
        assert result["total"] == 25  # from total-count
        assert result["total_is_known"] is True
        assert result["has_more"] is True
        assert isinstance(result["tid"], int)
        assert result["adom"] == "root"
        assert result["logtype"] == "traffic"
        assert result["tid"] in log_tools._SEARCH_REGISTRY

    async def test_no_more_when_page_covers_all(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When the first page covers every match, has_more=False."""
        fake = FakeFaz(_rows(4))
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert result["count"] == 4
        assert result["total"] == 4
        assert result["has_more"] is False

    async def test_zero_results_is_clean_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty result set returns success/count=0, not an error."""
        fake = FakeFaz([])
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert result["status"] == "success"
        assert result["count"] == 0
        assert result["total"] == 0
        assert result["has_more"] is False
        assert result["logs"] == []

    async def test_surfaces_timezone_and_time_range(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Output names the FAZ timezone and the resolved time_range bounds."""
        fake = FakeFaz(_rows(3), tz=ZoneInfo("Europe/Zurich"))
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert result["timezone"] == "Europe/Zurich"
        assert result["time_range"] == {
            "start": "2024-01-01 00:00:00",
            "end": "2024-01-02 00:00:00",
        }
        assert "FAZ local time" in result["time_basis"]


class TestFetchMoreLogs:
    async def test_pagination_offset_limit_regression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: query_logs(limit=10) -> fetch_more_logs(offset=5, limit=5)."""
        fake = FakeFaz(_rows(25))
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)
        assert first["has_more"] is True
        tid = first["tid"]

        more = await log_tools.fetch_more_logs(tid=tid, offset=5, limit=5)

        assert more["status"] == "success"
        assert more["count"] == 5
        assert [row["id"] for row in more["logs"]] == [5, 6, 7, 8, 9]
        assert more["tid"] == tid
        # A fresh search must have been issued for the second page (tids are
        # single-use on the appliance).
        assert len(fake.start_calls) == 2
        assert fake.start_calls[1]["offset"] == 5

    async def test_reuses_query_context_from_handle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """fetch_more_logs reuses the ADOM and filter recorded for the handle."""
        fake = FakeFaz(_rows(25))
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(
            adom="lab", logtype="event", time_range=CUSTOM_RANGE, filter="srcip==10.0.0.1", limit=10
        )
        tid = first["tid"]

        more = await log_tools.fetch_more_logs(tid=tid, offset=10, limit=10)

        assert more["status"] == "success"
        assert more["adom"] == "lab"
        # The re-issued search reuses the recorded adom + filter + logtype.
        last = fake.start_calls[-1]
        assert last["adom"] == "lab"
        assert last["filter"] == "srcip==10.0.0.1"
        assert last["logtype"] == "event"

    async def test_unknown_handle_returns_structured_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unknown/expired handle yields a clear, classified error."""
        fake = FakeFaz(_rows(5))
        _install(monkeypatch, fake)

        result = await log_tools.fetch_more_logs(tid=999999, offset=0, limit=5)

        assert result["status"] == "error"
        assert result["error"] == "tid_invalid_or_expired"
        assert result["tid"] == 999999
        assert "recommendation" in result

    async def test_rejects_nonpositive_tid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-positive handle is rejected before any API call."""
        fake = FakeFaz(_rows(5))
        _install(monkeypatch, fake)

        result = await log_tools.fetch_more_logs(tid=0)

        assert result["status"] == "error"


class TestReissueOnReap:
    async def test_query_logs_reissues_when_task_reaped_midpoll(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If a task reaps mid-poll, the search is re-issued and still completes."""
        monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)
        fake = FakeFaz(_rows(8), complete_on_attempt=2)
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert result["status"] == "success"
        assert result["count"] == 8
        assert len(fake.start_calls) == 2  # first search reaped, re-issued once

    async def test_never_completing_search_times_out_cleanly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A search that never reaches 100% within timeout returns a clean
        search_timeout error (honoring the timeout budget), not a raw 'Invalid
        tid' string."""
        monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0.01)
        fake = FakeFaz(_rows(8), complete_on_attempt=10_000)
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(
            adom="root", time_range=CUSTOM_RANGE, limit=10, timeout=0.05
        )

        assert result["status"] == "error"
        assert result["error"] == "search_timeout"
        assert "invalid tid" not in result.get("message", "").lower()
        # The timeout (not a small fixed attempt cap) bounds the work.
        assert len(fake.start_calls) >= 2


class TestUnknownTotal:
    async def test_unknown_total_uses_full_page_heuristic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When total-count is absent, total is None and has_more uses the
        full-page heuristic (count == limit implies more)."""
        fake = FakeFaz(_rows(50), omit_total=True)
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert result["status"] == "success"
        assert result["count"] == 10
        assert result["total"] is None
        assert result["total_is_known"] is False
        assert result["has_more"] is True


class TestCancelLogSearch:
    async def test_cancel_clears_handle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Cancelling clears the registry handle."""
        fake = FakeFaz(_rows(25))
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)
        tid = first["tid"]
        assert tid in log_tools._SEARCH_REGISTRY

        result = await log_tools.cancel_log_search(tid=tid)

        assert result["status"] == "success"
        assert tid not in log_tools._SEARCH_REGISTRY


class TestReconnectOnce:
    async def test_query_logs_reconnects_when_session_dropped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A dropped session is reconnected once before the search proceeds."""
        fake = FakeFaz(_rows(5), connected=False)
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert result["status"] == "success"
        assert fake.reconnects == 1

    async def test_fetch_more_logs_reconnects_when_session_dropped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """fetch_more_logs also revives a dropped session before paging."""
        fake = FakeFaz(_rows(25))
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)
        tid = first["tid"]

        fake.connected = False
        more = await log_tools.fetch_more_logs(tid=tid, offset=10, limit=10)

        assert more["status"] == "success"
        assert fake.reconnects == 1
