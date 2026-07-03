"""Regression tests for the correctness fixes from the 2026-07 review.

Covers: MCP_ALLOWED_HOSTS env parsing, numeric task-state handling,
device-filter serial-vs-hostname classification, report custom time windows
and unknown presets, string progress-percentage coercion, tid-less launches
returning errors, non-idempotent write retry suppression, negative timezone
caching, IPS-search unknown totals, policy_id=0 filtering, and the
search_devices connection-status map.
"""

from __future__ import annotations

from typing import Any

import pytest

import fortianalyzer_mcp.tools.dvm_tools as dvm_tools
import fortianalyzer_mcp.tools.fortiview_tools as fortiview_tools
import fortianalyzer_mcp.tools.ioc_tools as ioc_tools
import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.report_tools as report_tools
import fortianalyzer_mcp.tools.system_tools as system_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.tools.report_tools import (
    _convert_to_api_time_period,
    _format_period_timedate,
)
from fortianalyzer_mcp.utils.errors import ValidationError
from fortianalyzer_mcp.utils.responses import coerce_num
from fortianalyzer_mcp.utils.validation import build_device_filter


def _bare_client() -> FortiAnalyzerClient:
    return FortiAnalyzerClient(
        host="test-faz.example.com",
        username="admin",
        password="password",
    )


async def _no_sleep(_: float) -> None:
    return None


def _patch_client(monkeypatch: pytest.MonkeyPatch, module: Any, client: Any) -> None:
    monkeypatch.setattr(module, "get_faz_client", lambda: client)


class TestAllowedHostsParsing:
    """MCP_ALLOWED_HOSTS accepts the documented comma-separated env format."""

    def _settings(self, monkeypatch: pytest.MonkeyPatch, value: str) -> Any:
        from fortianalyzer_mcp.utils.config import Settings

        monkeypatch.setenv("FORTIANALYZER_HOST", "faz.example.com")
        monkeypatch.setenv("MCP_ALLOWED_HOSTS", value)
        return Settings()

    def test_comma_separated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        s = self._settings(monkeypatch, "faz.example.com,proxy.internal")
        assert s.MCP_ALLOWED_HOSTS == ["faz.example.com", "proxy.internal"]

    def test_single_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        s = self._settings(monkeypatch, "faz.example.com")
        assert s.MCP_ALLOWED_HOSTS == ["faz.example.com"]

    def test_json_array_still_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        s = self._settings(monkeypatch, '["faz.example.com"]')
        assert s.MCP_ALLOWED_HOSTS == ["faz.example.com"]

    def test_empty_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        s = self._settings(monkeypatch, "")
        assert s.MCP_ALLOWED_HOSTS == []


class TestNumericTaskState:
    """FAZ /task/task reports state as a numeric code; tools must handle it."""

    async def test_wait_for_task_completes_on_numeric_done(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        states = iter([1, 4])  # running -> done

        class FakeClient:
            async def get_task(self, task_id: int) -> dict[str, Any]:
                return {"id": task_id, "state": next(states)}

        async def fake_sleep(_: float) -> None:
            return None

        _patch_client(monkeypatch, system_tools, FakeClient())
        monkeypatch.setattr("asyncio.sleep", fake_sleep)

        result = await system_tools.wait_for_task(1, timeout=30, poll_interval=1)
        assert result["completed"] is True
        assert result["status"] == "success"

    async def test_wait_for_task_numeric_error_state(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeClient:
            async def get_task(self, task_id: int) -> dict[str, Any]:
                return {"id": task_id, "state": 5}  # error

        _patch_client(monkeypatch, system_tools, FakeClient())
        result = await system_tools.wait_for_task(1, timeout=30)
        assert result["completed"] is True
        assert result["status"] == "error"

    async def test_wait_for_task_still_accepts_string_state(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def get_task(self, task_id: int) -> dict[str, Any]:
                return {"id": task_id, "state": "done"}

        _patch_client(monkeypatch, system_tools, FakeClient())
        result = await system_tools.wait_for_task(1, timeout=30)
        assert result["completed"] is True
        assert result["status"] == "success"

    async def test_list_tasks_translates_state_name_to_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        class FakeClient:
            async def list_tasks(
                self, filter: list[list[Any]] | None = None
            ) -> list[dict[str, Any]]:
                captured["filter"] = filter
                return []

        _patch_client(monkeypatch, system_tools, FakeClient())
        result = await system_tools.list_tasks(filter_state="running")
        assert result["status"] == "success"
        assert captured["filter"] == [["state", "==", 1]]

    async def test_list_tasks_rejects_unknown_state(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeClient:
            async def list_tasks(
                self, filter: list[list[Any]] | None = None
            ) -> list[dict[str, Any]]:
                raise AssertionError("must not reach the API")

        _patch_client(monkeypatch, system_tools, FakeClient())
        result = await system_tools.list_tasks(filter_state="sleeping")
        assert result["status"] == "error"
        assert "Invalid filter_state" in result["message"]


class TestDeviceFilterClassification:
    """Hostnames that merely start with a serial prefix must go as devname."""

    def test_hostname_with_serial_prefix_is_devname(self) -> None:
        assert build_device_filter("FGT-HQ-01") == [{"devname": "FGT-HQ-01"}]
        assert build_device_filter("FG-BRANCH") == [{"devname": "FG-BRANCH"}]

    def test_real_serial_is_devid(self) -> None:
        assert build_device_filter("FG100FTK19001333") == [{"devid": "FG100FTK19001333"}]

    def test_vm_serial_is_devid(self) -> None:
        assert build_device_filter("FMG-VM0000000001") == [{"devid": "FMG-VM0000000001"}]
        assert build_device_filter("FAZ-VMTM23000001") == [{"devid": "FAZ-VMTM23000001"}]


class TestReportTimeRange:
    """Report custom windows are forwarded; unknown presets are rejected."""

    def test_unknown_preset_raises(self) -> None:
        with pytest.raises(ValidationError):
            _convert_to_api_time_period("14-day")

    def test_known_preset_maps(self) -> None:
        assert _convert_to_api_time_period("7-day") == "last-7-days"
        assert _convert_to_api_time_period("last-4-weeks") == "last-4-weeks"

    def test_custom_range_maps_to_other(self) -> None:
        assert _convert_to_api_time_period("2026-01-01 00:00:00|2026-01-02 00:00:00") == "other"

    def test_period_timedate_format(self) -> None:
        # FortiOS `timedate` fields are "HH:MM yyyy/mm/dd" (time first).
        assert _format_period_timedate("2026-01-02 12:30:00") == "12:30 2026/01/02"


class _ReportRunFakeClient:
    """Fake FAZ client recording report_run kwargs; completes immediately.

    The custom-window mechanism writes nothing to the schedule config, so the
    fake only needs the run + poll surface. ``run_calls`` captures how the
    window reached client.report_run.
    """

    def __init__(self) -> None:
        self.run_calls: list[dict[str, Any]] = []

    async def get_system_timezone(self) -> None:
        return None

    async def get_report_layouts(self, adom: str) -> dict[str, Any]:
        return {"data": [{"layout-id": 10002, "title": "Bandwidth and Applications"}]}

    async def get_report_schedules(self, adom: str, layout_id: int | None = None) -> dict[str, Any]:
        return {"data": [{"name": str(layout_id)}]}  # schedule already exists

    async def report_run(
        self,
        adom: str,
        layout_id: int,
        time_period: str | None = "last-7-days",
        device: list[dict[str, str]] | None = None,
        period_start: str | None = None,
        period_end: str | None = None,
    ) -> dict[str, Any]:
        self.run_calls.append(
            {
                "layout_id": layout_id,
                "time_period": time_period,
                "device": device,
                "period_start": period_start,
                "period_end": period_end,
            }
        )
        return {"tid": "tid-99"}

    async def get_running_reports(self, adom: str) -> dict[str, Any]:
        return {"data": []}  # not in running list -> verify via fetch

    async def report_fetch(self, adom: str, tid: str) -> dict[str, Any]:
        return {"tid": tid, "state": "generated"}


class TestReportCustomWindow:
    """Custom "start|end" ranges are delivered via the run's nested schedule-param.

    Live-verified on FAZ 7.6.7 and 8.0.0: the flat run form and the schedule
    config object both fail to scope a custom window (ignored / empty report);
    only the run's ``schedule-param`` with ``time-period="other"`` + FortiOS
    timedate bounds produces the requested period. No schedule config is written.
    """

    CUSTOM = "2026-06-27 00:00:00|2026-06-28 00:00:00"

    async def test_run_and_wait_passes_window_to_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _ReportRunFakeClient()
        _patch_client(monkeypatch, report_tools, fake)

        result = await report_tools.run_and_wait_report(layout="10002", time_range=self.CUSTOM)

        assert result["status"] == "success"
        assert result["tid"] == "tid-99"
        call = fake.run_calls[0]
        assert call["time_period"] == "other"
        assert call["period_start"] == "00:00 2026/06/27"
        assert call["period_end"] == "00:00 2026/06/28"
        assert result["requested_window"] == {
            "period-start": "00:00 2026/06/27",
            "period-end": "00:00 2026/06/28",
        }
        # Mechanism is confirmed, so no under-validation warning is attached.
        assert "warning" not in result

    async def test_run_report_supports_custom_range(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _ReportRunFakeClient()
        _patch_client(monkeypatch, report_tools, fake)

        result = await report_tools.run_report(layout="10002", time_range=self.CUSTOM)

        assert result["status"] == "success"
        call = fake.run_calls[0]
        assert call["time_period"] == "other"
        assert call["period_start"] == "00:00 2026/06/27"
        assert call["period_end"] == "00:00 2026/06/28"

    async def test_preset_range_sends_no_window(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _ReportRunFakeClient()
        _patch_client(monkeypatch, report_tools, fake)

        result = await report_tools.run_report(layout="10002", time_range="7-day")

        assert result["status"] == "success"
        call = fake.run_calls[0]
        assert call["time_period"] == "last-7-days"
        assert call["period_start"] is None
        assert call["period_end"] is None


class TestReportRunPayload:
    """client.report_run builds the JSON-RPC payload the FAZ mechanism requires."""

    def _client_capturing(self, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, dict[str, Any]]:
        from fortianalyzer_mcp.api.client import FortiAnalyzerClient

        client = FortiAnalyzerClient(host="faz.example.com", api_token="t")
        captured: dict[str, Any] = {}

        async def fake_raw(method: str, url: str, **params: Any) -> dict[str, Any]:
            captured["method"] = method
            captured["url"] = url
            captured["params"] = params
            return {"tid": "x"}

        monkeypatch.setattr(client, "_raw_request_dict", fake_raw)
        return client, captured

    async def test_custom_window_uses_nested_schedule_param(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, captured = self._client_capturing(monkeypatch)

        await client.report_run(
            "root",
            10002,
            period_start="00:00 2026/06/27",
            period_end="00:00 2026/06/28",
        )

        params = captured["params"]
        # The window lives inside schedule-param, NOT a top-level schedule.
        assert "schedule" not in params
        sp = params["schedule-param"]
        assert sp["time-period"] == "other"
        assert sp["period-start"] == "00:00 2026/06/27"
        assert sp["period-end"] == "00:00 2026/06/28"
        assert sp["layout-id"] == 10002
        assert params["runfrom"] == "GUI"

    async def test_preset_uses_flat_form(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client, captured = self._client_capturing(monkeypatch)

        await client.report_run("root", 10002, time_period="last-7-days")

        params = captured["params"]
        assert params["schedule"] == "10002"
        assert params["time-period"] == "last-7-days"
        assert "schedule-param" not in params


class TestPercentageCoercion:
    """FAZ may return progress fields as strings; comparisons must not crash."""

    def test_coerce_num_accepts_strings(self) -> None:
        assert coerce_num("100") == 100.0
        assert coerce_num("50.5") == 50.5
        assert coerce_num(None) is None
        assert coerce_num("n/a") is None
        assert coerce_num(True) is None

    async def test_get_fortiview_data_handles_string_percentage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def get_system_timezone(self) -> None:
                return None

            async def fortiview_run(self, **kwargs: Any) -> dict[str, Any]:
                return {"tid": 42}

            async def fortiview_fetch(self, **kwargs: Any) -> dict[str, Any]:
                return {"percentage": "100", "data": [{"srcip": "10.0.0.1"}]}

        _patch_client(monkeypatch, fortiview_tools, FakeClient())
        result = await fortiview_tools.get_fortiview_data("top-sources", timeout=5)
        assert result["status"] == "success"
        assert result["count"] == 1


class TestTidlessLaunchIsError:
    """A launch that returns no tid must not produce a success payload."""

    async def test_run_fortiview_without_tid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeClient:
            async def get_system_timezone(self) -> None:
                return None

            async def fortiview_run(self, **kwargs: Any) -> dict[str, Any]:
                return {}

        _patch_client(monkeypatch, fortiview_tools, FakeClient())
        result = await fortiview_tools.run_fortiview("top-sources")
        assert result["status"] == "error"

    async def test_run_ioc_rescan_without_tid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeClient:
            async def get_system_timezone(self) -> None:
                return None

            async def ioc_rescan_run(self, **kwargs: Any) -> dict[str, Any]:
                return {}

        _patch_client(monkeypatch, ioc_tools, FakeClient())
        result = await ioc_tools.run_ioc_rescan()
        assert result["status"] == "error"


class TestFetchFortiviewProgress:
    """fetch_fortiview surfaces completion state instead of silent partials."""

    async def test_partial_fetch_flagged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeClient:
            async def fortiview_fetch(self, **kwargs: Any) -> dict[str, Any]:
                return {"percentage": 40, "data": [{"srcip": "10.0.0.1"}]}

        _patch_client(monkeypatch, fortiview_tools, FakeClient())
        result = await fortiview_tools.fetch_fortiview(tid=1, view_name="top-sources")
        assert result["status"] == "success"
        assert result["complete"] is False
        assert "warning" in result

    async def test_complete_fetch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeClient:
            async def fortiview_fetch(self, **kwargs: Any) -> dict[str, Any]:
                return {"percentage": 100, "data": []}

        _patch_client(monkeypatch, fortiview_tools, FakeClient())
        result = await fortiview_tools.fetch_fortiview(tid=1, view_name="top-sources")
        assert result["complete"] is True
        assert "warning" not in result


class TestWriteRetryIdempotency:
    """Transient errors must not replay non-idempotent writes."""

    async def test_non_idempotent_oserror_not_retried(self) -> None:
        client = _bare_client()
        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            raise OSError("connection reset")

        with pytest.raises(OSError):
            await client._execute_resilient(factory, sleep=_no_sleep, idempotent=False)
        assert len(calls) == 1

    async def test_idempotent_oserror_still_retried(self) -> None:
        client = _bare_client()
        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            if len(calls) == 1:
                raise OSError("connection reset")
            return "ok"

        result = await client._execute_resilient(factory, sleep=_no_sleep, idempotent=True)
        assert result == "ok"
        assert len(calls) == 2


class TestTimezoneNegativeCache:
    """A definitive 'no TZ reported' answer is cached; probe failures are not."""

    async def test_missing_tz_probed_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _bare_client()
        probes: list[int] = []

        async def fake_status() -> dict[str, Any]:
            probes.append(1)
            return {"Hostname": "FAZ-TEST"}  # no TZ field

        monkeypatch.setattr(client, "get_system_status", fake_status)
        assert await client.get_system_timezone() is None
        assert await client.get_system_timezone() is None
        assert len(probes) == 1

    async def test_probe_failure_not_cached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _bare_client()
        probes: list[int] = []

        async def failing_status() -> dict[str, Any]:
            probes.append(1)
            raise ConnectionError("FAZ unreachable")

        monkeypatch.setattr(client, "get_system_status", failing_status)
        assert await client.get_system_timezone() is None
        assert await client.get_system_timezone() is None
        assert len(probes) == 2


class TestSearchIpsLogsUnknownTotal:
    """search_ips_logs must not fabricate total=len(logs) when FAZ omits it."""

    async def test_unknown_total_reported_honestly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import fortianalyzer_mcp.tools.pcap_tools as pcap_tools

        async def fake_page(client: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "logs": [{"pcapurl": "x"}, {}],
                "total": None,
                "tid": 7,
                "timed_out": False,
            }

        class FakeClient:
            async def get_system_timezone(self) -> None:
                return None

        monkeypatch.setattr(pcap_tools, "_run_logsearch_page", fake_page)
        _patch_client(monkeypatch, pcap_tools, FakeClient())

        result = await pcap_tools.search_ips_logs()
        assert result["status"] == "success"
        assert result["total"] is None
        assert result["total_is_known"] is False
        assert "warning" in result


class TestPolicyIdZero:
    """policy_id=0 (implicit deny) must produce a policyid filter."""

    async def test_policy_id_zero_included(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        async def fake_query_logs(**kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {"status": "success", "logs": [], "count": 0}

        monkeypatch.setattr(log_tools, "query_logs", fake_query_logs)
        result = await log_tools.search_traffic_logs(policy_id=0)
        assert result["status"] == "success"
        assert "policyid==0" in (captured.get("filter") or "")


class TestSearchDevicesConnectionStatus:
    """connection_status uses the DVMDB enum and rejects unknown values."""

    async def test_down_maps_to_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        class FakeClient:
            async def list_devices(
                self,
                adom: str,
                filter: list[list[Any]] | None = None,
                fields: list[str] | None = None,
            ) -> list[dict[str, Any]]:
                captured["filter"] = filter
                return []

        _patch_client(monkeypatch, dvm_tools, FakeClient())
        result = await dvm_tools.search_devices(connection_status="down")
        assert result["status"] == "success"
        assert ["conn_status", "==", 2] in captured["filter"]

    async def test_unknown_value_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeClient:
            async def list_devices(self, **kwargs: Any) -> list[dict[str, Any]]:
                raise AssertionError("must not reach the API")

        _patch_client(monkeypatch, dvm_tools, FakeClient())
        result = await dvm_tools.search_devices(connection_status="online")
        assert result["status"] == "error"
        assert "Invalid connection_status" in result["message"]
