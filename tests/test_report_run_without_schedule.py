"""run_report and run_and_wait_report never create a report schedule (#181).

Both tools are annotated READ_ONLY. They used to call
client.create_report_schedule, a ``set`` on
/report/adom/<adom>/config/schedule/<layout-id>, whenever the layout had no
schedule. That is a stored configuration write. They now only look the
schedule up: a layout that has one runs exactly as before, and a layout that
has none runs through the nested ``schedule-param`` object of the run request.

The expected requests come from the maintainer's measurement on 7.6.7 recorded
in issue #181, not from the code under test:

* ``schedule-param`` with layout-id, device "all", filter-logic "all" and
  time-period ran to ``generated`` on a layout without a schedule, and no
  schedule was created.
* ``schedule-param`` rejects ``last-1-hours``. It wants the time-period enum of
  the reference, so an hour window is ``last-n-hours`` plus ``period-last-n``.
* ``last-7-days`` and ``last-30-days`` are enum members as they are;
  ``last-n-days`` and ``last-n-weeks`` need ``period-last-n`` too.

Every test calls the registered tool function against a real
FortiAnalyzerClient whose pyfmg session is replaced by a recorder, so the
assertions are about the JSON-RPC requests that would reach the appliance.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

import fortianalyzer_mcp.tools.report_tools as report_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient

LAYOUT_ID = 10002
TID = "tid-181"
SCHEDULE_LIST_URL = "/config/adom/root/sql-report/schedule"
SCHEDULE_SET_URL = f"/report/adom/root/config/schedule/{LAYOUT_ID}"
RUN_URL = "/report/adom/root/run"

HAS_SCHEDULE: dict[str, Any] = {"data": [{"name": str(LAYOUT_ID)}]}
NO_SCHEDULE: dict[str, Any] = {"data": []}

CUSTOM_RANGE = "2026-06-27 00:00:00|2026-06-28 00:00:00"

BOTH_TOOLS = pytest.mark.parametrize(
    "tool",
    [report_tools.run_report, report_tools.run_and_wait_report],
    ids=["run_report", "run_and_wait_report"],
)


class _Appliance:
    """Answers a real FortiAnalyzerClient and records every request it sends.

    The report endpoints are raw JSON-RPC posts on the pyfmg session. Each one
    is recorded as (method, params, posted body). The pyfmg verbs are MagicMock
    attributes of ``fmg``, so ``writes`` sees a request made through one of
    those as well.

    A ``set`` on the schedule config path is answered with success, as the
    appliance answers it (issue #181: the schedule was created and was still
    there after the run). Only the recorded requests can show that none was
    sent.
    """

    def __init__(self, fmg: MagicMock, schedule_lookup: dict[str, Any] | Exception) -> None:
        self.fmg = fmg
        self.schedule_lookup = schedule_lookup
        self.posts: list[tuple[str, dict[str, Any], str]] = []
        fmg.sess.post.side_effect = self._post

    def _post(self, url: str, **kwargs: Any) -> MagicMock:
        body = kwargs["data"]
        request = json.loads(body)
        method = request["method"]
        params = request["params"][0]
        self.posts.append((method, params, body))
        response = MagicMock()
        response.json.return_value = {"result": self._answer(method, params["url"])}
        return response

    def _answer(self, method: str, url: str) -> dict[str, Any]:
        if (method, url) == ("get", SCHEDULE_LIST_URL):
            if isinstance(self.schedule_lookup, Exception):
                raise self.schedule_lookup
            return self.schedule_lookup
        if (method, url) == ("set", SCHEDULE_SET_URL):
            return {"status": {"code": 0, "message": "OK"}}
        if (method, url) == ("add", RUN_URL):
            return {"tid": TID}
        if (method, url) == ("get", RUN_URL):
            return {"data": []}  # not in the running list: the tool asks for the state
        if (method, url) == ("get", f"{RUN_URL}/{TID}"):
            return {"state": "generated"}
        raise AssertionError(f"unexpected request: {method} {url}")

    def writes(self) -> list[tuple[str, str]]:
        """Every request that is not a get, raw or through a pyfmg verb."""
        raw = [(method, params["url"]) for method, params, _ in self.posts if method != "get"]
        verbs = [
            (verb, call.args[0])
            for verb in ("add", "set", "update", "delete", "execute")
            for call in getattr(self.fmg, verb).call_args_list
        ]
        return raw + verbs

    def urls(self) -> list[str]:
        return [params["url"] for _, params, _ in self.posts]

    def _the_run(self) -> tuple[dict[str, Any], str]:
        runs = [
            (params, body)
            for method, params, body in self.posts
            if (method, params["url"]) == ("add", RUN_URL)
        ]
        assert len(runs) == 1, f"expected one run request, got {self.posts}"
        return runs[0]

    def run_params(self) -> dict[str, Any]:
        """The params of the one request that started the report."""
        return self._the_run()[0]

    def run_body(self) -> str:
        """The posted body of the one request that started the report."""
        return self._the_run()[1]


@pytest.fixture
def appliance(
    monkeypatch: pytest.MonkeyPatch,
    mock_client: FortiAnalyzerClient,
    mock_fmg_instance: MagicMock,
) -> Callable[[dict[str, Any] | Exception], _Appliance]:
    """Put a recording appliance behind the client the report tools use."""

    def _make(schedule_lookup: dict[str, Any] | Exception) -> _Appliance:
        monkeypatch.setattr(report_tools, "get_faz_client", lambda: mock_client)
        return _Appliance(mock_fmg_instance, schedule_lookup)

    return _make


def _schedule_param(**period: Any) -> dict[str, Any]:
    """The schedule-param object of issue #181 with the given period fields."""
    return {"layout-id": LAYOUT_ID, "device": "all", "filter-logic": "all", **period}


class TestLayoutWithoutSchedule:
    """No schedule for the layout: nothing is created, the run uses schedule-param."""

    @BOTH_TOOLS
    async def test_the_only_write_is_the_run_itself(
        self, tool: Any, appliance: Callable[..., _Appliance]
    ) -> None:
        faz = appliance(NO_SCHEDULE)

        result = await tool(layout=str(LAYOUT_ID), adom="root", time_range="7-day")

        assert result["status"] == "success"
        assert result["tid"] == TID
        # No set on the schedule path, and no other write either.
        assert faz.writes() == [("add", RUN_URL)]

    async def test_run_report_says_no_schedule_was_created(
        self, appliance: Callable[..., _Appliance]
    ) -> None:
        appliance(NO_SCHEDULE)

        result = await report_tools.run_report(
            layout=str(LAYOUT_ID), adom="root", time_range="7-day"
        )

        assert result["status"] == "success"
        assert result["schedule_created"] is False

    @BOTH_TOOLS
    @pytest.mark.parametrize(
        ("time_range", "period"),
        [
            pytest.param(
                "1-hour",
                {"time-period": "last-n-hours", "period-last-n": 1},
                id="hour preset",
            ),
            pytest.param(
                "last-1-hours",
                {"time-period": "last-n-hours", "period-last-n": 1},
                id="hour preset in the spelling schedule-param rejects",
            ),
            pytest.param(
                "24-hour",
                {"time-period": "last-n-hours", "period-last-n": 24},
                id="24 hours",
            ),
            pytest.param("7-day", {"time-period": "last-7-days"}, id="day preset in the enum"),
            pytest.param(
                "last-30-days", {"time-period": "last-30-days"}, id="30 days, in the enum"
            ),
            pytest.param(
                "90-day",
                {"time-period": "last-n-days", "period-last-n": 90},
                id="day preset not in the enum",
            ),
            pytest.param("1-day", {"time-period": "last-n-days", "period-last-n": 1}, id="1 day"),
            pytest.param(
                "last-4-weeks",
                {"time-period": "last-n-weeks", "period-last-n": 4},
                id="week preset",
            ),
        ],
    )
    async def test_preset_runs_through_schedule_param(
        self,
        tool: Any,
        time_range: str,
        period: dict[str, Any],
        appliance: Callable[..., _Appliance],
    ) -> None:
        faz = appliance(NO_SCHEDULE)

        result = await tool(layout=str(LAYOUT_ID), adom="root", time_range=time_range)

        assert result["status"] == "success"
        # The whole request: nothing names a schedule, and neither the period
        # nor the device is repeated in the flat form.
        assert faz.run_params() == {
            "url": RUN_URL,
            "apiver": 3,
            "runfrom": "GUI",
            "schedule-param": _schedule_param(**period),
        }

    @BOTH_TOOLS
    async def test_custom_window_runs_through_schedule_param(
        self, tool: Any, appliance: Callable[..., _Appliance]
    ) -> None:
        faz = appliance(NO_SCHEDULE)

        result = await tool(layout=str(LAYOUT_ID), adom="root", time_range=CUSTOM_RANGE)

        assert result["status"] == "success"
        params = faz.run_params()
        assert params["schedule-param"] == _schedule_param(
            **{
                "time-period": "other",
                "period-start": "00:00 2026/06/27",
                "period-end": "00:00 2026/06/28",
            }
        )
        assert "schedule" not in params
        assert faz.writes() == [("add", RUN_URL)]

    @BOTH_TOOLS
    async def test_response_keeps_the_period_the_caller_asked_for(
        self, tool: Any, appliance: Callable[..., _Appliance]
    ) -> None:
        """The reply names the window as before, not its schedule-param spelling."""
        appliance(NO_SCHEDULE)

        result = await tool(layout=str(LAYOUT_ID), adom="root", time_range="1-hour")

        assert result["time_period"] == "last-1-hours"

    @BOTH_TOOLS
    async def test_device_filter_is_kept(
        self, tool: Any, appliance: Callable[..., _Appliance]
    ) -> None:
        """A device filter is not widened to "all" because the form changed.

        Not measured: issue #181 ran device "all" only. The filter goes where
        the custom-window form already puts it.
        """
        faz = appliance(NO_SCHEDULE)

        result = await tool(
            layout=str(LAYOUT_ID), adom="root", device="fw-branch-01", time_range="7-day"
        )

        assert result["status"] == "success"
        assert faz.run_params()["schedule-param"]["device"] == [{"devname": "fw-branch-01"}]

    @BOTH_TOOLS
    async def test_month_period_is_sent_as_it_is(
        self, tool: Any, appliance: Callable[..., _Appliance]
    ) -> None:
        """A month count has no schedule-param spelling in issue #181.

        Not measured. It is sent unchanged, so the appliance answers for it
        instead of this code guessing a window.
        """
        faz = appliance(NO_SCHEDULE)

        await tool(layout=str(LAYOUT_ID), adom="root", time_range="last-1-months")

        assert faz.run_params()["schedule-param"] == _schedule_param(
            **{"time-period": "last-1-months"}
        )


class TestLayoutWithSchedule:
    """A layout that has a schedule runs with the request it always had.

    The bodies below are what the unchanged code posted; they pin the flat
    form (and the custom-window form) byte for byte.
    """

    @BOTH_TOOLS
    async def test_preset_request_is_unchanged(
        self, tool: Any, appliance: Callable[..., _Appliance]
    ) -> None:
        faz = appliance(HAS_SCHEDULE)

        result = await tool(layout=str(LAYOUT_ID), adom="root", time_range="1-hour")

        assert result["status"] == "success"
        assert faz.run_body() == (
            '{"method": "add", "params": [{"url": "/report/adom/root/run", "apiver": 3, '
            '"schedule": "10002", "time-period": "last-1-hours", "runfrom": "GUI"}], '
            '"id": 1, "jsonrpc": "2.0", "session": "mock-session-id"}'
        )
        assert faz.writes() == [("add", RUN_URL)]

    @BOTH_TOOLS
    async def test_preset_request_with_device_is_unchanged(
        self, tool: Any, appliance: Callable[..., _Appliance]
    ) -> None:
        faz = appliance(HAS_SCHEDULE)

        result = await tool(
            layout=str(LAYOUT_ID), adom="root", device="fw-branch-01", time_range="7-day"
        )

        assert result["status"] == "success"
        assert faz.run_body() == (
            '{"method": "add", "params": [{"url": "/report/adom/root/run", "apiver": 3, '
            '"schedule": "10002", "time-period": "last-7-days", "runfrom": "GUI", '
            '"device": [{"devname": "fw-branch-01"}]}], '
            '"id": 1, "jsonrpc": "2.0", "session": "mock-session-id"}'
        )

    @BOTH_TOOLS
    async def test_custom_window_request_is_unchanged(
        self, tool: Any, appliance: Callable[..., _Appliance]
    ) -> None:
        faz = appliance(HAS_SCHEDULE)

        result = await tool(layout=str(LAYOUT_ID), adom="root", time_range=CUSTOM_RANGE)

        assert result["status"] == "success"
        assert faz.run_body() == (
            '{"method": "add", "params": [{"url": "/report/adom/root/run", "apiver": 3, '
            '"runfrom": "GUI", "schedule-param": {"layout-id": 10002, "device": "all", '
            '"filter-logic": "all", "time-period": "other", '
            '"period-start": "00:00 2026/06/27", "period-end": "00:00 2026/06/28"}}], '
            '"id": 1, "jsonrpc": "2.0", "session": "mock-session-id"}'
        )

    async def test_run_report_says_no_schedule_was_created(
        self, appliance: Callable[..., _Appliance]
    ) -> None:
        appliance(HAS_SCHEDULE)

        result = await report_tools.run_report(
            layout=str(LAYOUT_ID), adom="root", time_range="7-day"
        )

        assert result["schedule_created"] is False


class TestScheduleLookupFails:
    """A failed lookup says nothing about the layout, so no report is started.

    Running through schedule-param would ignore the devices of a schedule that
    may exist; running the flat form would name a schedule that may not.
    """

    @BOTH_TOOLS
    @pytest.mark.parametrize(
        "failure",
        [
            pytest.param(
                {"status": {"code": -3, "message": "Permission denied"}},
                id="the appliance answers with an error",
            ),
            pytest.param(TimeoutError(), id="a failure that carries no text"),
        ],
    )
    async def test_no_report_is_started(
        self,
        tool: Any,
        failure: dict[str, Any] | Exception,
        appliance: Callable[..., _Appliance],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def no_sleep(_seconds: float) -> None:
            return None

        # The client retries a transport error with a backoff; do not wait it out.
        monkeypatch.setattr(asyncio, "sleep", no_sleep)
        faz = appliance(failure)

        result = await tool(layout=str(LAYOUT_ID), adom="root", time_range="7-day")

        assert result["status"] == "error"
        assert "tid" not in result
        assert RUN_URL not in faz.urls()
        assert faz.writes() == []

    @BOTH_TOOLS
    @pytest.mark.parametrize(
        ("failure", "reason"),
        [
            pytest.param(
                {"status": {"code": -3, "message": "Permission denied"}},
                f"Permission denied (url: GET {SCHEDULE_LIST_URL})",
                id="the appliance answers with an error",
            ),
            pytest.param(TimeoutError(), "TimeoutError", id="a failure that carries no text"),
            pytest.param(
                ConnectionError("login failed: password=not-a-real-secret"),
                "login failed: password=***REDACTED***",
                id="a failure whose text carries a secret",
            ),
        ],
    )
    async def test_the_reply_names_the_failure_and_says_nothing_started(
        self,
        tool: Any,
        failure: dict[str, Any] | Exception,
        reason: str,
        appliance: Callable[..., _Appliance],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def no_sleep(_seconds: float) -> None:
            return None

        monkeypatch.setattr(asyncio, "sleep", no_sleep)
        appliance(failure)

        result = await tool(layout=str(LAYOUT_ID), adom="root", time_range="7-day")

        assert result["message"] == (
            f"Failed to look up the schedule for layout-id {LAYOUT_ID}: {reason}. "
            "No report was started."
        )
