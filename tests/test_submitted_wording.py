"""A count of what was sent is called submitted (#187 D24).

The acknowledge tools return the number of ids the caller passed under a key
that says they were acknowledged. The key stays, so no caller breaks, and a
message beside it says what the number is. ``delete_device`` run as a task
said "deleted successfully" with the task still running.
"""

from typing import Any

import pytest

import fortianalyzer_mcp.tools.dvm_tools as dvm_tools
import fortianalyzer_mcp.tools.event_tools as event_tools
import fortianalyzer_mcp.tools.ioc_tools as ioc_tools


class _AlertClient:
    async def acknowledge_alerts(self, **_: Any) -> dict[str, Any]:
        return {"status": "ok"}

    async def unacknowledge_alerts(self, **_: Any) -> dict[str, Any]:
        return {"status": "ok"}


class _IocClient:
    async def acknowledge_ioc_events(self, **_: Any) -> dict[str, Any]:
        return {"status": "ok"}


class _DeviceClient:
    def __init__(self, answer: dict[str, Any]) -> None:
        self._answer = answer

    async def delete_device(self, **_: Any) -> dict[str, Any]:
        return self._answer


class TestAcknowledgeSaysWhatItsCountIs:
    async def test_acknowledge_alerts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(event_tools, "_get_client", lambda: _AlertClient())

        result = await event_tools.acknowledge_alerts(["a-1", "a-2"], user="soc", adom="root")

        assert result["status"] == "success"
        assert result["acknowledged_count"] == 2
        assert result["message"].startswith("Submitted 2 alert ids to FortiAnalyzer")
        assert "not of changes FortiAnalyzer confirmed" in result["message"]

    async def test_unacknowledge_alerts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(event_tools, "_get_client", lambda: _AlertClient())

        result = await event_tools.unacknowledge_alerts(["a-1"], user="soc", adom="root")

        assert result["status"] == "success"
        assert result["unacknowledged_count"] == 1
        assert result["message"].startswith("Submitted 1 alert id to FortiAnalyzer")
        assert "not of changes FortiAnalyzer confirmed" in result["message"]

    async def test_acknowledge_ioc_events(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ioc_tools, "get_faz_client", lambda: _IocClient())

        result = await ioc_tools.acknowledge_ioc_events(
            events=[ioc_tools.IocEventRef(source_ip="192.0.2.6", timestamp="2024-01-15 09:31:00")],
            adom="root",
        )

        assert result["status"] == "success"
        assert result["acknowledged_count"] == 1
        assert result["message"].startswith("Submitted 1 IOC event to FortiAnalyzer")
        assert "not of changes FortiAnalyzer confirmed" in result["message"]


class TestDeleteDeviceAsATask:
    async def test_a_task_delete_is_submitted_and_points_at_the_task(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(dvm_tools, "_get_client", lambda: _DeviceClient({"taskid": 77}))

        result = await dvm_tools.delete_device("root", "FGT-01", flags=["create_task"])

        assert result["status"] == "success"
        assert result["task_id"] == 77
        assert "deleted successfully" not in result["message"]
        assert "submitted" in result["message"]
        assert "wait_for_task(77)" in result["warning"]

    async def test_a_direct_delete_keeps_its_answer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(dvm_tools, "_get_client", lambda: _DeviceClient({}))

        result = await dvm_tools.delete_device("root", "FGT-01")

        assert result["status"] == "success"
        assert result["task_id"] is None
        assert result["message"] == "Device FGT-01 deleted successfully"
        assert "warning" not in result
