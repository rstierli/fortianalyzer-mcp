"""Tests for the query_logs / fetch_more_logs response contract.

Covers the fields and edges added on top of the pagination work: total_is_known,
offset/limit/next_offset, the deterministic warnings channel, the count==0 guard,
and the unified error envelope (machine `error` code + retry_count).
"""

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

import fortianalyzer_mcp.tools.log_tools as log_tools
from fortianalyzer_mcp.utils.errors import ResourceNotFoundError

CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"
_PACIFIC = ZoneInfo("US/Pacific")


def _rows(n: int) -> list[dict[str, object]]:
    return [{"id": i, "srcip": f"10.0.0.{i}", "action": "accept"} for i in range(n)]


class ContractFaz:
    """Minimal log-search fake with a controllable total and forced errors.

    Honors poll-before-fetch: ``logsearch_count`` reports the scan complete (a
    cheap GET that does not reap), so the runner polls once and then fetches the
    page exactly once.
    """

    def __init__(
        self,
        *,
        page: list[dict[str, object]],
        total: int | None,
        tz: ZoneInfo | None = _PACIFIC,
        start_error: Exception | None = None,
    ) -> None:
        self.page = page
        self.total = total
        self.tz = tz
        self.start_error = start_error
        self.connected = True
        self.reconnects = 0
        self.start_calls: list[dict[str, object]] = []
        self.count_calls: list[int] = []
        self._complete_tids: set[int] = set()
        self._tid = 500

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
        self.start_calls.append({"offset": offset, "limit": limit, "filter": filter})
        if self.start_error is not None:
            raise self.start_error
        self._tid += 1
        return {"tid": self._tid}

    async def logsearch_count(self, adom: str, tid: int) -> dict[str, object]:
        """Report the scan complete (does not reap the tid)."""
        self.count_calls.append(tid)
        self._complete_tids.add(tid)
        rows = len(self.page)
        total = self.total if self.total is not None else rows
        return {
            "progress-percent": 100,
            "matched-logs": rows,
            "scanned-logs": total,
            "total-logs": total,
        }

    async def logsearch_fetch(
        self, adom: str, tid: int, limit: int = 50, offset: int = 0
    ) -> dict[str, object]:
        # Poll-before-fetch: a fetch before this tid's count has reported
        # complete is an invalid-tid error (the live appliance reaps an
        # un-ready single-use tid on a premature fetch).
        if tid not in self._complete_tids:
            raise ResourceNotFoundError(f"Invalid tid {tid}: not complete.", code=-1)
        result: dict[str, object] = {
            "percentage": 100,
            "data": list(self.page),
            "tid": tid,
            "status": {"code": 0, "message": "ok"},
        }
        if self.total is not None:
            result["total-count"] = self.total
        return result

    async def logsearch_cancel(self, adom: str, tid: int) -> dict[str, object]:
        return {"status": {"code": 0, "message": "ok"}}


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop the poll cadence to zero so start->poll->fetch is fast."""
    monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
    monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)


@pytest.fixture(autouse=True)
def _clear_registry():
    log_tools._SEARCH_REGISTRY.clear()
    yield
    log_tools._SEARCH_REGISTRY.clear()


def _install(monkeypatch: pytest.MonkeyPatch, fake: ContractFaz) -> None:
    monkeypatch.setattr(log_tools, "get_faz_client", lambda: fake)


class TestQueryLogsContractFields:
    async def test_new_fields_present_and_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = ContractFaz(page=_rows(10), total=25)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert r["total_is_known"] is True
        assert r["offset"] == 0
        assert r["limit"] == 10
        assert r["next_offset"] == 10  # offset + count, has_more
        assert r["warnings"] == []
        # Poll-before-fetch: the count probe ran before the fetch (the fetch now
        # raises invalid-tid if called before its count reports complete, so a
        # successful page proves count was polled first).
        assert len(fake.count_calls) >= 1
        # Old names are gone.
        assert "total_known" not in r
        assert "returned_offset" not in r
        assert "returned_limit" not in r

    async def test_time_basis_fields_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """query_logs surfaces the time-basis source and clock skew."""
        fake = ContractFaz(page=_rows(3), total=3)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        # A custom absolute range carries explicit bounds -> "custom" basis.
        assert r["time_basis_source"] == "custom"
        assert r["clock_skew_seconds"] is None
        # The FAZ tz is still reported for label purposes.
        assert r["timezone"] == "US/Pacific"

    async def test_clean_query_has_empty_warnings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = ContractFaz(page=_rows(3), total=3)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE)

        assert r["has_more"] is False
        assert r["next_offset"] is None
        assert r["warnings"] == []


class TestNextOffsetEdges:
    async def test_short_non_final_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """count < limit but more remain -> has_more, next_offset = offset+count."""
        fake = ContractFaz(page=_rows(5), total=25)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert r["count"] == 5
        assert r["has_more"] is True
        assert r["next_offset"] == 5

    async def test_zero_count_inconsistent_total_does_not_loop(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty page while total claims more must stop paging, with a warning."""
        fake = ContractFaz(page=[], total=25)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)

        assert r["count"] == 0
        assert r["has_more"] is False
        assert r["next_offset"] is None
        assert any("beyond this offset" in w for w in r["warnings"])


class TestWarningsTriggers:
    async def test_clamp_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = ContractFaz(page=_rows(3), total=3)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=5000)

        assert r["limit"] == 1000
        assert any("1000" in w for w in r["warnings"])

    async def test_unknown_timezone_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = ContractFaz(page=_rows(3), total=3, tz=None)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE)

        assert r["timezone"] == "unknown"
        assert any("time" in w.lower() for w in r["warnings"])

    async def test_high_volume_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = ContractFaz(page=_rows(10), total=200000)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE)

        assert r["has_more"] is True
        assert any("get_policy" in w for w in r["warnings"])


class TestErrorEnvelope:
    async def test_invalid_time_range_envelope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = ContractFaz(page=_rows(1), total=1)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(
            adom="root", time_range="2024-13-99 00:00:00|2024-01-02 00:00:00"
        )

        assert r["status"] == "error"
        assert r["error"] == "invalid_time_range"
        assert r["operation"] == "query_logs"

    async def test_generic_failure_carries_retry_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        boom = RuntimeError("backend exploded")
        boom.retries_attempted = 2  # type: ignore[attr-defined]
        fake = ContractFaz(page=[], total=None, start_error=boom)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", logtype="traffic", time_range=CUSTOM_RANGE)

        assert r["status"] == "error"
        assert r["error"] == "faz_operation_failed"
        assert r["operation"] == "query_logs"
        assert r["adom"] == "root"
        assert r["logtype"] == "traffic"
        assert r["retry_count"] == 2


class TestFetchMoreLogsContract:
    async def test_fetch_more_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = ContractFaz(page=_rows(10), total=25)
        _install(monkeypatch, fake)

        first = await log_tools.query_logs(adom="root", time_range=CUSTOM_RANGE, limit=10)
        more = await log_tools.fetch_more_logs(tid=first["tid"], offset=10, limit=10)

        assert more["offset"] == 10
        assert more["limit"] == 10
        assert more["total_is_known"] is True
        assert more["next_offset"] == 20  # offset + count, has_more
        assert more["warnings"] == []
        assert "returned_offset" not in more

    async def test_unknown_handle_error_uses_error_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = ContractFaz(page=_rows(5), total=5)
        _install(monkeypatch, fake)

        r = await log_tools.fetch_more_logs(tid=424242, offset=0, limit=5)

        assert r["status"] == "error"
        assert r["error"] == "tid_invalid_or_expired"
        assert "error_type" not in r
        assert r["tid"] == 424242


class TestSearchWrapperErrors:
    async def test_search_traffic_logs_bad_ip_uses_envelope(self) -> None:
        # Bad srcip fails during filter building, before any client call.
        r = await log_tools.search_traffic_logs(srcip="not-an-ip")

        assert r["status"] == "error"
        assert r["error"] == "validation_error"
        assert r["operation"] == "search_traffic_logs"


class TestSevenAndThirtyDayFlows:
    """Prove the existing surface covers first-class 7/30-day investigations."""

    @pytest.mark.parametrize("preset, days", [("7-day", 7), ("30-day", 30)])
    @pytest.mark.parametrize(
        "filt",
        [
            "action==accept",
            "action==deny",
            "policyid==7",
            "srcip==10.0.0.1 and dstport==443",
        ],
    )
    async def test_query_logs_preset_with_filters(
        self, monkeypatch: pytest.MonkeyPatch, preset: str, days: int, filt: str
    ) -> None:
        fake = ContractFaz(page=_rows(3), total=3)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(
            adom="root", logtype="traffic", time_range=preset, filter=filt
        )

        assert r["status"] == "success"
        start = datetime.strptime(r["time_range"]["start"], "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(r["time_range"]["end"], "%Y-%m-%d %H:%M:%S")
        assert (end - start).days == days
        assert fake.start_calls[0]["filter"] == filt

    @pytest.mark.parametrize("logtype", ["traffic", "event"])
    async def test_query_logs_30day_logtypes(
        self, monkeypatch: pytest.MonkeyPatch, logtype: str
    ) -> None:
        fake = ContractFaz(page=_rows(2), total=2)
        _install(monkeypatch, fake)

        r = await log_tools.query_logs(adom="root", logtype=logtype, time_range="30-day")

        assert r["status"] == "success"
        assert r["logtype"] == logtype

    async def test_search_traffic_logs_7day_denied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = ContractFaz(page=_rows(2), total=2)
        _install(monkeypatch, fake)

        r = await log_tools.search_traffic_logs(adom="root", action="deny", time_range="7-day")

        assert r["status"] == "success"
        assert "action==deny" in (fake.start_calls[0]["filter"] or "")
