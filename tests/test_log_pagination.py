"""Tests for log search pagination, tid lifecycle, and reuse.

These exercise query_logs / fetch_more_logs / cancel_log_search through a
stateful in-memory FortiAnalyzer fake that models the *real* appliance
contract discovered on the lab FAZ (7.6.x), under the poll-before-fetch rule:

- ``logsearch_start(offset, limit)`` issues a task id (tid).
- ``logsearch_count(adom, tid)`` is a cheap GET that does NOT reap the tid; its
  ``progress-percent`` climbs 0 -> 100 over a few polls.
- ``logsearch_fetch`` may only be called once the scan is complete: a fetch
  while the search is still running RAISES "Invalid tid" (the runner must poll
  ``logsearch_count`` first). The first valid fetch returns
  ``data[offset:offset+limit]`` plus ``total-count`` and reaps the task, so a
  *second* fetch on the same tid raises "Invalid tid".
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

# Number of logsearch_count polls a search reports as in-progress before it
# reads 100% (so a normal search makes >=1 count call before the single fetch).
_POLLS_TO_COMPLETE = 2


def _rows(n: int) -> list[dict[str, object]]:
    """Build n distinct, stably ordered traffic log rows."""
    return [
        {"id": i, "srcip": f"10.0.0.{i}", "dstport": 443, "proto": "6", "action": "accept"}
        for i in range(n)
    ]


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop the poll cadence to zero so the start->poll->fetch loop is fast."""
    monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
    monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)


class FakeFaz:
    """Faithful fake of the FortiAnalyzer log-search surface (poll-before-fetch).

    Each ``logsearch_start`` issues a fresh single-use tid. ``logsearch_count``
    climbs ``progress-percent`` 0 -> 100 over ``_POLLS_TO_COMPLETE`` polls and
    never reaps. ``logsearch_fetch`` raises "Invalid tid" if called before the
    scan is complete *or* a second time on a reaped tid; a valid fetch delivers
    the offset slice plus ``total-count`` and reaps the task.

    ``complete_on_attempt`` models an appliance that reaps a search mid-poll: a
    search whose start-attempt number is below it has its ``logsearch_count``
    raise an invalid-tid error, forcing the runner to re-issue from scratch.
    """

    def __init__(
        self,
        dataset: list[dict[str, object]],
        *,
        tz: ZoneInfo | None = None,
        connected: bool = True,
        complete_on_attempt: int = 1,
        omit_total: bool = False,
        stall: bool = False,
        total_overrides: list[int | None] | None = None,
    ) -> None:
        self.dataset = dataset
        self.tz = tz
        self.connected = connected
        self.complete_on_attempt = complete_on_attempt
        self.omit_total = omit_total
        self.stall = stall
        # Per-fetch ``total-count`` sequence (models the appliance re-counting a
        # frozen window across re-run page searches). Each successful fetch pops
        # the next entry: an int sets ``total-count``; ``None`` omits it entirely
        # (exercising the unknown path). Exhausted/absent -> len(dataset).
        self.total_overrides = list(total_overrides) if total_overrides is not None else None
        self.reconnects = 0
        self._tasks: dict[int, dict[str, object]] = {}
        self._next_tid = 1000
        self._start_count = 0
        self.start_calls: list[dict[str, object]] = []
        self.count_calls: list[int] = []
        self.fetch_calls: list[int] = []
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
            {
                "adom": adom,
                "logtype": logtype,
                "filter": filter,
                "offset": offset,
                "limit": limit,
                "time_range": time_range,
            }
        )
        tid = self._next_tid
        self._next_tid += 1
        self._tasks[tid] = {"adom": adom, "alive": True, "attempt": self._start_count, "polls": 0}
        return {"tid": tid}

    async def logsearch_fetch(
        self,
        adom: str,
        tid: int,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, object]:
        self.fetch_calls.append(tid)
        task = self._tasks.get(tid)
        if task is None or not task["alive"] or task["adom"] != adom:
            raise ResourceNotFoundError(f"Invalid tid {tid} for fetching result.", code=-1)
        # Model the appliance reaping a search mid-poll: a search whose
        # start-attempt number is below complete_on_attempt has its fetch raise
        # an invalid-tid error, forcing the runner to re-issue from scratch.
        if int(task["attempt"]) < self.complete_on_attempt:
            task["alive"] = False
            raise ResourceNotFoundError(f"Invalid tid {tid}: reaped mid-poll.", code=-1)
        task["polls"] = int(task["polls"]) + 1
        # Stalled scans never reach percentage=100 (deadline must bound them).
        if self.stall:
            return {
                "percentage": 20,
                "return-lines": 0,
                "data": [],
                "tid": tid,
                "status": {"code": 0, "message": "in-progress"},
            }
        # Spec-compliant polling: return percentage<100 with empty data until the
        # scan has completed (polls >= _POLLS_TO_COMPLETE), then a percentage=100
        # response with data. The tid stays alive for in-flight polls; it is
        # reaped only when a final result is delivered.
        if int(task["polls"]) < _POLLS_TO_COMPLETE:
            return {
                "percentage": 30,
                "return-lines": 0,
                "data": [],
                "tid": tid,
                "status": {"code": 0, "message": "in-progress"},
            }
        task["alive"] = False  # single-use: task is reaped after the final fetch
        page = self.dataset[offset : offset + limit]
        result: dict[str, object] = {
            "percentage": 100,
            "return-lines": len(page),
            "data": page,
            "tid": tid,
            "status": {"code": 0, "message": "succeeded"},
        }
        if self.total_overrides:
            override = self.total_overrides.pop(0)
            if override is not None:
                result["total-count"] = override
            # None -> omit total-count entirely (unknown path)
        elif not self.omit_total:
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

    async def test_timeout_is_forwarded_to_page_runner(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """fetch_more_logs(timeout=180) forwards 180 into _run_logsearch_page."""
        fake = FakeFaz(_rows(25))
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)
        tid = first["tid"]

        seen: dict[str, object] = {}
        real_runner = log_tools._run_logsearch_page

        async def recording_runner(client: object, **kwargs: object) -> dict[str, object]:
            seen.update(kwargs)
            return await real_runner(client, **kwargs)

        monkeypatch.setattr(log_tools, "_run_logsearch_page", recording_runner)

        more = await log_tools.fetch_more_logs(tid=tid, offset=10, limit=10, timeout=180)

        assert more["status"] == "success"
        assert seen["timeout"] == 180

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
        """If a task reaps mid-poll (invalid-tid during count), the search is
        re-issued exactly once and still completes."""
        fake = FakeFaz(_rows(8), complete_on_attempt=2)
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert result["status"] == "success"
        assert result["count"] == 8
        assert len(fake.start_calls) == 2  # first search reaped, re-issued once

    async def test_never_completing_search_times_out_cleanly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A search whose scan never reaches 100% within the timeout returns a
        clean search_timeout error (honoring the deadline), not a raw 'Invalid
        tid' string."""
        monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0.005)
        monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0.005)
        fake = FakeFaz(_rows(8), stall=True)  # count never reads 100%
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(
            adom="root", time_range=CUSTOM_RANGE, limit=10, timeout=1
        )

        assert result["status"] == "error"
        assert result["error"] == "search_timeout"
        assert "invalid tid" not in result.get("message", "").lower()
        # A stalled scan is bounded by the deadline: the single search is polled
        # via logsearch_fetch (which returns percentage<100 forever) but never
        # delivers a final page.
        assert len(fake.start_calls) == 1
        assert len(fake.fetch_calls) >= 1


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


class PrematureFaz:
    """Models the 7.6.7 premature-100 case under poll-before-fetch.

    ``logsearch_count`` always reports the scan complete (``progress-percent``
    100), but the fetch returns an *empty* ``data`` page while ``total-count``
    reports rows exist, until ``data_on_attempt`` searches have started -- at
    which point the page carries real data. Each search is a fresh single-use
    tid; the runner must therefore re-issue on a premature-empty-100 page.
    """

    def __init__(self, dataset: list[dict[str, object]], *, data_on_attempt: int) -> None:
        self.dataset = dataset
        self.data_on_attempt = data_on_attempt
        self.connected = True
        self.reconnects = 0
        self._next_tid = 2000
        self._attempt = 0
        self._tasks: dict[int, int] = {}
        self.count_calls: list[int] = []
        self.cancelled: list[int] = []

    @property
    def is_connected(self) -> bool:
        return self.connected

    async def ensure_connected(self) -> None:
        if not self.connected:
            self.reconnects += 1
            self.connected = True

    async def get_system_timezone(self):  # noqa: ANN201 - test fake
        return None

    async def logsearch_start(self, **_kw: object) -> dict[str, object]:
        self._attempt += 1
        tid = self._next_tid
        self._next_tid += 1
        self._tasks[tid] = self._attempt
        return {"tid": tid}

    async def logsearch_fetch(
        self, adom: str, tid: int, limit: int = 50, offset: int = 0
    ) -> dict[str, object]:
        attempt = self._tasks[tid]
        data = self.dataset[offset : offset + limit] if attempt >= self.data_on_attempt else []
        return {
            "percentage": 100,
            "data": data,
            "total-count": len(self.dataset),
            "tid": tid,
            "status": {"code": 0, "message": "succeeded"},
        }

    async def logsearch_cancel(self, adom: str, tid: int) -> dict[str, object]:
        self.cancelled.append(tid)
        return {"status": {"code": 0, "message": "ok"}}


class TestPremature100:
    async def test_empty_100pct_with_total_reissues_then_returns_rows(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """percentage:100 + empty data + total-count>0 must re-issue, not report 0."""
        fake = PrematureFaz(_rows(5), data_on_attempt=2)
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert result["status"] == "success"
        assert result["count"] == 5
        assert result["total"] == 5
        assert fake._attempt == 2  # first empty completion re-issued once

    async def test_persistent_empty_100pct_is_bounded_and_warns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A deterministically empty 100% page stops after a bounded re-issue
        count (it must not loop to the timeout) and surfaces the inconsistency."""
        fake = PrematureFaz(_rows(5), data_on_attempt=10_000)  # never yields data
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert result["status"] == "success"
        assert result["count"] == 0
        assert result["has_more"] is False
        assert any("beyond this offset" in w for w in result["warnings"])
        # Bounded by the shared recovery budget: one initial search +
        # MAX_SEARCH_REISSUES re-issues.
        assert fake._attempt == 1 + log_tools.MAX_SEARCH_REISSUES


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


class TestTotalStability:
    """Baseline-total contract across re-run pages (ADR-0002).

    A pagination handle's ``total`` is the first-page Baseline total and stays
    fixed; the raw per-page ``total-count`` is exposed as ``page_total`` and the
    page is labelled stable/drifted/unknown against the baseline.
    """

    async def test_stable_total_no_drift(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Equal page totals -> stable; total == baseline, no drift warning."""
        fake = FakeFaz(_rows(25), total_overrides=[25, 25])
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)
        more = await log_tools.fetch_more_logs(tid=first["tid"], offset=10, limit=10)

        assert more["status"] == "success"
        assert more["total"] == 25
        assert more["page_total"] == 25
        assert more["initial_total"] == 25
        assert more["total_count_stability"] == "stable"
        assert more["total_drift_detected"] is False
        assert more["total_delta"] == 0
        assert more["has_more_basis"] == "stable_total"
        assert not any("baseline" in w for w in more["warnings"])

    async def test_drifted_total_keeps_baseline(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A higher later total -> total stays the page-0 baseline; page_total is
        the latest; drift is flagged and warned (incl. row-shift caveat)."""
        fake = FakeFaz(_rows(25), total_overrides=[230071, 230741])
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=5)
        assert first["total"] == 230071
        assert first["initial_total"] == 230071
        assert first["page_total"] == 230071

        more = await log_tools.fetch_more_logs(tid=first["tid"], offset=5, limit=5)

        assert more["total"] == 230071
        assert more["page_total"] == 230741
        assert more["initial_total"] == 230071
        assert more["total_count_stability"] == "drifted"
        assert more["total_drift_detected"] is True
        assert more["total_delta"] == 670
        assert more["has_more_basis"] == "best_effort_max_observed_total"
        assert any("row offsets may also shift" in w for w in more["warnings"])
        assert any("baseline" in w for w in more["warnings"])

    async def test_drifted_has_more_uses_max_observed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """has_more on drift is computed from max(initial, page_total): a baseline
        of 10 must not stop paging when the page reports 1000 rows."""
        fake = FakeFaz(_rows(10), total_overrides=[10, 1000])
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=5)
        more = await log_tools.fetch_more_logs(tid=first["tid"], offset=5, limit=5)

        assert more["page_total"] == 1000
        assert more["total"] == 10  # baseline preserved
        assert more["has_more_basis"] == "best_effort_max_observed_total"
        # (offset+count)=10 < max(10,1000) -> keep paging (baseline alone would stop).
        assert more["has_more"] is True

    async def test_query_logs_unknown_total_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Page 0 with no total-count: total None, unknown stability, heuristic basis."""
        fake = FakeFaz(_rows(50), omit_total=True)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert r["total"] is None
        assert r["page_total"] is None
        assert r["initial_total"] is None
        assert r["total_count_stability"] == "unknown"
        assert r["total_drift_detected"] is False
        assert r["total_delta"] is None
        assert r["has_more_basis"] == "full_page_heuristic"

    async def test_query_logs_page0_single_observation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Page 0 with a known total -> single_observation, delta 0, stable_total basis."""
        fake = FakeFaz(_rows(25))
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert r["page_total"] == 25
        assert r["initial_total"] == 25
        assert r["total_count_stability"] == "single_observation"
        assert r["total_drift_detected"] is False
        assert r["total_delta"] == 0
        assert r["has_more_basis"] == "stable_total"

    async def test_no_baseline_never_promotes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Page 0 omits total-count: total stays None for the whole handle even
        when a later page returns a count (page_total still surfaced)."""
        fake = FakeFaz(_rows(8), total_overrides=[None, 230741])
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=5)
        assert first["total"] is None
        assert first["page_total"] is None

        more = await log_tools.fetch_more_logs(tid=first["tid"], offset=5, limit=5)

        assert more["total"] is None
        assert more["page_total"] == 230741
        assert more["initial_total"] is None
        assert more["total_count_stability"] == "unknown"
        assert more["total_drift_detected"] is False
        assert more["has_more_basis"] == "best_effort_page_total"

    async def test_no_baseline_short_page_does_not_stop_early(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No baseline + a short page must page off page_total, not the full-page
        heuristic (which would stop early and hide rows)."""
        fake = FakeFaz(_rows(8), total_overrides=[None, 1000])
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=5)
        more = await log_tools.fetch_more_logs(tid=first["tid"], offset=5, limit=5)

        assert more["count"] < 5  # rows[5:8] -> 3 rows, a short page
        assert more["total"] is None
        assert more["page_total"] == 1000
        assert more["has_more_basis"] == "best_effort_page_total"
        assert more["has_more"] is True  # 8 < 1000, would be False under the heuristic

    async def test_known_baseline_page_omits_total(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Known baseline + a later page missing total-count: total stays the
        baseline, stability unknown, has_more paged against the baseline."""
        fake = FakeFaz(_rows(25), total_overrides=[25, None])
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)
        more = await log_tools.fetch_more_logs(tid=first["tid"], offset=10, limit=10)

        assert more["total"] == 25
        assert more["page_total"] is None
        assert more["initial_total"] == 25
        assert more["total_count_stability"] == "unknown"
        assert more["total_drift_detected"] is False
        assert more["total_delta"] is None
        assert more["has_more_basis"] == "stable_total"

    async def test_adom_mismatch_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A differing ADOM is rejected (the handle is bound to its ADOM); reuse
        and exact-match proceed."""
        fake = FakeFaz(_rows(25))
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)
        tid = first["tid"]
        assert len(fake.start_calls) == 1

        bad = await log_tools.fetch_more_logs(tid=tid, adom="other", offset=10, limit=10)
        assert bad["status"] == "error"
        assert bad["error"] == "adom_mismatch"
        assert len(fake.start_calls) == 1  # no search was issued

        ok = await log_tools.fetch_more_logs(tid=tid, adom="root", offset=10, limit=10)
        assert ok["status"] == "success"
        assert len(fake.start_calls) == 2

    async def test_frozen_window_relative_preset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A relative preset is resolved to an absolute window at page 0 and the
        same absolute window is re-sent on later pages (frozen, not sliding)."""
        fake = FakeFaz(_rows(25), tz=ZoneInfo("UTC"))
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range="1-hour", limit=10)
        tid = first["tid"]
        ctx = log_tools._SEARCH_REGISTRY[tid]
        assert set(ctx["time_range"].keys()) == {"start", "end"}  # resolved, not "1-hour"

        await log_tools.fetch_more_logs(tid=tid, offset=10, limit=10)

        # The page-1 re-run search carries the same frozen absolute window.
        assert fake.start_calls[1]["time_range"] == ctx["time_range"]

    async def test_non_monotonic_drift_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """high -> low -> high totals: total stays the baseline, has_more pages
        against max(initial, current) each page, no crash, clean stop on empty."""
        fake = FakeFaz(_rows(20), total_overrides=[240000, 230000, 240500])
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=5)
        assert first["initial_total"] == 240000

        more1 = await log_tools.fetch_more_logs(tid=first["tid"], offset=5, limit=5)
        assert more1["total"] == 240000
        assert more1["page_total"] == 230000
        assert more1["total_delta"] == -10000
        assert more1["has_more_basis"] == "best_effort_max_observed_total"

        more2 = await log_tools.fetch_more_logs(tid=first["tid"], offset=10, limit=5)
        assert more2["total"] == 240000
        assert more2["page_total"] == 240500
        assert more2["total_delta"] == 500

        # Beyond the dataset: an empty page stops paging cleanly regardless of total.
        more3 = await log_tools.fetch_more_logs(tid=first["tid"], offset=20, limit=5)
        assert more3["count"] == 0
        assert more3["has_more"] is False
