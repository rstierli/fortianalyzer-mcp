"""The wait wrappers return the tid when a poll fails (#187 item A3).

run_and_wait_report, run_and_wait_ioc_rescan and get_fortiview_data start a
job on the appliance and then poll it. A poll that raised was answered with
an error that held no tid, so the caller could not look at the job it had
started, and a retry started a second one. The error now carries the tid and
says how to look the job up.

query_logs(group_by=...) runs the same FortiView polling. Its error envelope
does not change: a FortiView tid under ``tid`` there would read as a
fetch_more_logs handle.
"""

from __future__ import annotations

from typing import Any

import pytest

import fortianalyzer_mcp.tools.fortiview_tools as fortiview_tools
import fortianalyzer_mcp.tools.ioc_tools as ioc_tools
import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.report_tools as report_tools

CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"
POLL_ERROR = "FortiAnalyzer API error -11: no permission"


class ReportClient:
    async def get_report_schedules(self, adom: str, layout_id: int | None = None) -> dict[str, Any]:
        return {"data": []}

    async def report_run(
        self,
        adom: str,
        layout_id: int,
        time_period: str = "last-7-days",
        period_start: str | None = None,
        period_end: str | None = None,
        period_last_n: int | None = None,
        has_schedule: bool = False,
        device_name: str | None = None,
    ) -> dict[str, Any]:
        return {"tid": "tid-a3"}

    async def get_running_reports(self, adom: str) -> dict[str, Any]:
        raise RuntimeError(POLL_ERROR)

    async def report_fetch(self, adom: str, tid: str) -> dict[str, Any]:
        raise AssertionError("not reached")


class IocClient:
    async def get_system_timezone(self) -> None:
        return None

    async def ioc_rescan_run(
        self, adom: str, device: list[dict[str, str]], time_range: dict[str, str]
    ) -> dict[str, Any]:
        return {"tid": 4711}

    async def ioc_rescan_status(self, adom: str, tid: int) -> dict[str, Any]:
        raise RuntimeError(POLL_ERROR)


class FortiViewClient:
    def __init__(self) -> None:
        self.runs = 0

    async def ensure_connected(self) -> None:
        return None

    async def get_system_timezone(self) -> None:
        return None

    async def fortiview_run(self, **kwargs: Any) -> dict[str, Any]:
        self.runs += 1
        return {"tid": 4242}

    async def fortiview_fetch(self, **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError(POLL_ERROR)


class TestRunAndWaitReport:
    async def test_a_failed_poll_returns_the_tid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(report_tools, "get_faz_client", lambda: ReportClient())

        result = await report_tools.run_and_wait_report(layout="10", adom="root")

        assert result["status"] == "error"
        assert result["tid"] == "tid-a3"
        assert result["message"] == (
            f"{POLL_ERROR}. The report was started as tid 'tid-a3' before this error: "
            "look it up with get_running_reports() or fetch_report(tid='tid-a3') "
            "before starting another."
        )

    async def test_an_error_before_the_run_has_no_tid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class RunFails(ReportClient):
            async def report_run(self, **kwargs: Any) -> dict[str, Any]:
                raise RuntimeError("run refused")

        monkeypatch.setattr(report_tools, "get_faz_client", lambda: RunFails())

        result = await report_tools.run_and_wait_report(layout="10", adom="root")

        assert result == {"status": "error", "message": "run refused"}


class TestRunAndWaitIocRescan:
    async def test_a_failed_poll_returns_the_tid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ioc_tools, "get_faz_client", lambda: IocClient())

        result = await ioc_tools.run_and_wait_ioc_rescan(adom="root", time_range=CUSTOM_RANGE)

        assert result["status"] == "error"
        assert result["tid"] == 4711
        assert result["message"] == (
            f"{POLL_ERROR}. The rescan was started as tid 4711 before this error: "
            "look it up with get_ioc_rescan_status(tid=4711) before starting another."
        )

    async def test_an_error_before_the_run_has_no_tid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class RunFails(IocClient):
            async def ioc_rescan_run(self, **kwargs: Any) -> dict[str, Any]:
                raise RuntimeError("run refused")

        monkeypatch.setattr(ioc_tools, "get_faz_client", lambda: RunFails())

        result = await ioc_tools.run_and_wait_ioc_rescan(adom="root", time_range=CUSTOM_RANGE)

        assert result == {"status": "error", "message": "run refused"}


class TestGetFortiviewData:
    async def test_a_failed_poll_returns_the_tid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = FortiViewClient()
        monkeypatch.setattr(fortiview_tools, "get_faz_client", lambda: client)

        result = await fortiview_tools.get_fortiview_data(
            view_name="top-sources", adom="root", time_range=CUSTOM_RANGE
        )

        assert client.runs == 1
        assert result["status"] == "error"
        assert result["tid"] == 4242
        assert result["view_name"] == "top-sources"
        assert result["message"] == (
            f"{POLL_ERROR}. The query was started as tid 4242 before this error: "
            "look it up with fetch_fortiview(tid=4242, view_name='top-sources') "
            "before starting another."
        )

    async def test_an_error_before_the_run_has_no_tid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class RunFails(FortiViewClient):
            async def fortiview_run(self, **kwargs: Any) -> dict[str, Any]:
                raise RuntimeError("run refused")

        monkeypatch.setattr(fortiview_tools, "get_faz_client", lambda: RunFails())

        result = await fortiview_tools.get_fortiview_data(
            view_name="top-sources", adom="root", time_range=CUSTOM_RANGE
        )

        assert result == {"status": "error", "message": "run refused"}

    async def test_query_logs_group_by_keeps_its_error_envelope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Control: the same polling failure under query_logs is unchanged."""
        monkeypatch.setattr(log_tools, "get_faz_client", lambda: FortiViewClient())

        result = await log_tools.query_logs(
            logtype="traffic", time_range=CUSTOM_RANGE, group_by="srcip"
        )

        assert result["status"] == "error"
        assert result["error"] == "faz_operation_failed"
        assert result["message"] == POLL_ERROR
        assert "tid" not in result
