"""Regression tests for uniform identifier validation and parameter clamping.

Covers the hardening pass that closed the gap between tools that already
validated ``adom`` (log/dvm/traffic/pcap) and those that interpolated it into
the JSON-RPC url path unvalidated (report/event/incident/ioc/fortiview/system),
plus the new incident-id and fortiview view-name checks, the documented
limit/offset clamps, the wait_for_task poll clamp, and quoted-key redaction.

Fake clients raise if a tool reaches the API with an unvalidated identifier,
so a regression fails loudly instead of silently passing bad input through.
"""

from __future__ import annotations

from typing import Any

import pytest

import fortianalyzer_mcp.tools.event_tools as event_tools
import fortianalyzer_mcp.tools.fortiview_tools as fortiview_tools
import fortianalyzer_mcp.tools.incident_tools as incident_tools
import fortianalyzer_mcp.tools.ioc_tools as ioc_tools
import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.report_tools as report_tools
import fortianalyzer_mcp.tools.system_tools as system_tools
from fortianalyzer_mcp.utils.responses import redact
from fortianalyzer_mcp.utils.validation import (
    MASK_VALUE,
    ValidationError,
    validate_incident_id,
)

INJECTED_ADOM = "root/../../rawlog"


class RejectingClient:
    """Fails the test if any API method is reached with unvalidated input."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"client.{name} was called before validation rejected the input")


def _patch_client(monkeypatch: pytest.MonkeyPatch, module: Any, client: Any) -> None:
    monkeypatch.setattr(module, "get_faz_client", lambda: client)


class TestAdomValidationConsistency:
    """Every tool family rejects a path-injection ADOM before touching the API."""

    async def test_report_list_layouts_rejects_injected_adom(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, report_tools, RejectingClient())
        result = await report_tools.list_report_layouts(adom=INJECTED_ADOM)
        assert result["status"] == "error"
        assert "Invalid ADOM" in result["message"]

    async def test_event_get_alerts_rejects_injected_adom(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, event_tools, RejectingClient())
        result = await event_tools.get_alerts(adom=INJECTED_ADOM)
        assert result["status"] == "error"
        assert "Invalid ADOM" in result["message"]

    async def test_incident_get_incidents_rejects_injected_adom(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, incident_tools, RejectingClient())
        result = await incident_tools.get_incidents(adom=INJECTED_ADOM)
        assert result["status"] == "error"
        assert "Invalid ADOM" in result["message"]

    async def test_ioc_acknowledge_rejects_injected_adom(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, ioc_tools, RejectingClient())
        result = await ioc_tools.acknowledge_ioc_events(
            ioc_ids=["IOC-001"], user="tester", adom=INJECTED_ADOM
        )
        assert result["status"] == "error"
        assert "Invalid ADOM" in result["message"]

    async def test_system_get_adom_rejects_injected_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, system_tools, RejectingClient())
        result = await system_tools.get_adom(name=INJECTED_ADOM)
        assert result["status"] == "error"
        assert "Invalid ADOM" in result["message"]

    async def test_system_get_device_rejects_injected_device_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, system_tools, RejectingClient())
        result = await system_tools.get_device(name="fgt/../../rawlog")
        assert result["status"] == "error"
        assert "Invalid device name" in result["message"]

    async def test_log_get_log_stats_rejects_injected_adom(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, log_tools, RejectingClient())
        result = await log_tools.get_log_stats(adom=INJECTED_ADOM)
        assert result["status"] == "error"
        assert "Invalid ADOM" in result["message"]

    async def test_fortiview_fetch_rejects_injected_adom(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, fortiview_tools, RejectingClient())
        result = await fortiview_tools.fetch_fortiview(
            tid=1, view_name="top-sources", adom=INJECTED_ADOM
        )
        assert result["status"] == "error"
        assert "Invalid ADOM" in result["message"]


class TestIncidentIdValidation:
    """Incident IDs are url-path components and must reject path injection."""

    def test_validator_accepts_normal_ids(self) -> None:
        assert validate_incident_id("IN00000001") == "IN00000001"
        assert validate_incident_id(" INC-001 ") == "INC-001"

    def test_validator_rejects_path_injection(self) -> None:
        with pytest.raises(ValidationError):
            validate_incident_id("1/../../adom/other")
        with pytest.raises(ValidationError):
            validate_incident_id("")

    async def test_get_incident_rejects_injected_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, incident_tools, RejectingClient())
        result = await incident_tools.get_incident(incident_id="1/../../rawlog")
        assert result["status"] == "error"
        assert "Invalid incident ID" in result["message"]

    async def test_update_incident_rejects_injected_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, incident_tools, RejectingClient())
        result = await incident_tools.update_incident(incident_id="1/../../rawlog", status="closed")
        assert result["status"] == "error"
        assert "Invalid incident ID" in result["message"]


class TestFortiviewViewValidation:
    """fetch_fortiview validates view_name like its sibling tools."""

    async def test_fetch_fortiview_rejects_bad_view(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, fortiview_tools, RejectingClient())
        result = await fortiview_tools.fetch_fortiview(tid=1, view_name="top-sources/../../etc")
        assert result["status"] == "error"


class TestLimitOffsetClamps:
    """Documented 1-2000 limit range and non-negative offset are enforced."""

    async def test_get_alerts_clamps_limit_and_offset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        class FakeClient:
            async def get_system_timezone(self) -> None:
                return None

            async def get_alerts(
                self,
                adom: str,
                time_range: dict[str, str],
                filter: str | None = None,
                limit: int = 100,
                offset: int = 0,
            ) -> list[dict[str, Any]]:
                captured["limit"] = limit
                captured["offset"] = offset
                return []

        _patch_client(monkeypatch, event_tools, FakeClient())
        result = await event_tools.get_alerts(limit=99999, offset=-5)
        assert result["status"] == "success"
        assert captured["limit"] == 2000
        assert captured["offset"] == 0

    async def test_get_incidents_clamps_limit_and_offset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        class FakeClient:
            async def get_system_timezone(self) -> None:
                return None

            async def get_incidents(
                self,
                adom: str,
                time_range: dict[str, str],
                filter: str | None = None,
                limit: int = 100,
                offset: int = 0,
            ) -> list[dict[str, Any]]:
                captured["limit"] = limit
                captured["offset"] = offset
                return []

        _patch_client(monkeypatch, incident_tools, FakeClient())
        result = await incident_tools.get_incidents(limit=0, offset=-1)
        assert result["status"] == "success"
        assert captured["limit"] == 1
        assert captured["offset"] == 0


class TestWaitForTaskClamps:
    """wait_for_task never tight-loops on a zero/negative poll interval."""

    async def test_poll_interval_clamped_to_one_second(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []
        states = iter(["running", "done"])

        class FakeClient:
            async def get_task(self, task_id: int) -> dict[str, Any]:
                return {"id": task_id, "state": next(states)}

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        _patch_client(monkeypatch, system_tools, FakeClient())
        monkeypatch.setattr("asyncio.sleep", fake_sleep)

        result = await system_tools.wait_for_task(1, timeout=30, poll_interval=0)

        assert result["completed"] is True
        assert sleeps and min(sleeps) >= 1


class TestRedactQuotedKeys:
    """redact() masks JSON/dict-style quoted keys, not just key=value."""

    def test_json_style_password_masked(self) -> None:
        out = redact('request failed: {"password": "hunter2", "user": "admin"}')
        assert "hunter2" not in out
        assert MASK_VALUE in out

    def test_python_dict_style_adm_pass_masked(self) -> None:
        out = redact("payload {'adm_pass': 's3cretvalue'} rejected")
        assert "s3cretvalue" not in out
        assert MASK_VALUE in out
