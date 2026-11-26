"""run_report and run_and_wait_report by layout title (#187 item A2).

A title is looked up in the layout list. Two things went wrong there:

* When the layout list could not be read, the error was swallowed and the
  answer was "Report layout 'X' not found".
* With no exact title, the first layout whose title contains the text was
  run, and the result echoed the caller's text, not the title that ran.

Now a failed read returns its own error and starts nothing, and a match by
substring carries a warning that names the title that ran.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

import fortianalyzer_mcp.tools.report_tools as report_tools

LAYOUTS = [
    {"layout-id": 7, "title": "Template - VPN", "is-template": 1},
    {"layout-id": 10, "title": "Secure SD-WAN Report", "is-template": 0},
    {"layout-id": 11, "title": "VPN Report", "is-template": 0},
]

BOTH_TOOLS = pytest.mark.parametrize(
    "tool",
    [report_tools.run_report, report_tools.run_and_wait_report],
    ids=["run_report", "run_and_wait_report"],
)


class FakeClient:
    """The report calls of FortiAnalyzerClient, with their signatures."""

    def __init__(self, layouts: list[dict[str, Any]] | Exception) -> None:
        self.layouts = layouts
        self.runs: list[int] = []

    async def get_report_layouts(
        self, adom: str, fields: list[str] | None = None, filter: list[Any] | None = None
    ) -> dict[str, Any]:
        if isinstance(self.layouts, Exception):
            raise self.layouts
        return {"data": self.layouts}

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
        self.runs.append(layout_id)
        return {"tid": "tid-a2"}

    async def get_running_reports(self, adom: str) -> dict[str, Any]:
        return {"data": []}

    async def report_fetch(self, adom: str, tid: str) -> dict[str, Any]:
        return {"state": "generated"}


def _use(monkeypatch: pytest.MonkeyPatch, client: FakeClient) -> FakeClient:
    monkeypatch.setattr(report_tools, "get_faz_client", lambda: client)
    return client


class TestFailedLayoutRead:
    @BOTH_TOOLS
    async def test_the_read_error_is_returned_and_nothing_runs(
        self, tool: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _use(monkeypatch, FakeClient(RuntimeError("FortiAnalyzer API error -3: timeout")))

        result = await tool(layout="VPN Report", adom="root")

        assert result["status"] == "error"
        assert "FortiAnalyzer API error -3: timeout" in result["message"]
        assert "not found" not in result["message"]
        assert client.runs == []

    @BOTH_TOOLS
    async def test_a_title_that_is_not_there_is_still_not_found(
        self, tool: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _use(monkeypatch, FakeClient(LAYOUTS))

        result = await tool(layout="Firewall Report", adom="root")

        assert result["status"] == "error"
        assert result["message"] == (
            "Report layout 'Firewall Report' not found. "
            "Use list_report_layouts() to see available reports."
        )
        assert client.runs == []


class TestMatchedTitle:
    @BOTH_TOOLS
    async def test_a_substring_match_names_the_title_that_ran(
        self, tool: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _use(monkeypatch, FakeClient(LAYOUTS))

        result = await tool(layout="sd-wan", adom="root")

        assert result["status"] == "success"
        assert client.runs == [10]
        assert result["layout"] == "sd-wan"
        assert result["layout_id"] == 10
        assert result["warnings"] == [
            "No layout is titled 'sd-wan'. Ran 'Secure SD-WAN Report' (layout-id 10), "
            "the first layout whose title contains it."
        ]

    @BOTH_TOOLS
    async def test_an_exact_title_carries_no_warning(
        self, tool: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _use(monkeypatch, FakeClient(LAYOUTS))

        result = await tool(layout="vpn report", adom="root")

        assert result["status"] == "success"
        assert client.runs == [11]
        assert "warnings" not in result

    @BOTH_TOOLS
    async def test_a_template_is_not_matched(
        self, tool: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _use(monkeypatch, FakeClient(LAYOUTS))

        result = await tool(layout="Template", adom="root")

        assert result["status"] == "error"
        assert client.runs == []

    async def test_the_warning_stays_on_a_report_that_did_not_complete(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Aborted(FakeClient):
            async def report_fetch(self, adom: str, tid: str) -> dict[str, Any]:
                return {"state": "aborted"}

        _use(monkeypatch, Aborted(LAYOUTS))

        result = await report_tools.run_and_wait_report(layout="sd-wan", adom="root")

        assert result["status"] == "error"
        assert result["layout"] == "sd-wan"
        assert result["warnings"] == [
            "No layout is titled 'sd-wan'. Ran 'Secure SD-WAN Report' (layout-id 10), "
            "the first layout whose title contains it."
        ]

    async def test_the_warning_stays_on_a_report_done_in_the_running_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Done(FakeClient):
            async def get_running_reports(self, adom: str) -> dict[str, Any]:
                return {"data": [{"tid": "tid-a2", "percent": 100}]}

        _use(monkeypatch, Done(LAYOUTS))

        result = await report_tools.run_and_wait_report(layout="sd-wan", adom="root")

        assert result["status"] == "success"
        assert result["warnings"] == [
            "No layout is titled 'sd-wan'. Ran 'Secure SD-WAN Report' (layout-id 10), "
            "the first layout whose title contains it."
        ]

    async def test_the_warning_stays_on_a_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = [0.0]

        class StillRunning(FakeClient):
            async def get_running_reports(self, adom: str) -> dict[str, Any]:
                clock[0] += 10.0  # each poll moves past the 1 s minimum timeout
                return {"data": [{"tid": "tid-a2", "percent": 10}]}

        async def no_sleep(_seconds: float) -> None:
            return None

        _use(monkeypatch, StillRunning(LAYOUTS))
        monkeypatch.setattr(report_tools.asyncio, "sleep", no_sleep)
        monkeypatch.setattr(asyncio.get_running_loop(), "time", lambda: clock[0])

        result = await report_tools.run_and_wait_report(layout="sd-wan", adom="root", timeout=1)

        assert result["status"] == "timeout"
        assert result["warnings"] == [
            "No layout is titled 'sd-wan'. Ran 'Secure SD-WAN Report' (layout-id 10), "
            "the first layout whose title contains it."
        ]
