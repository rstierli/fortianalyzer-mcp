"""The ``device`` argument as a caller types it, on its way into a device filter (#187).

A serial with spaces around it was sent as a device name, a serial followed
by a newline matched the serial pattern (``$`` matches before a final
newline) and was sent as a devid with the newline in it, and a value of
whitespace only was sent as a device name. Each matched nothing.
"""

from __future__ import annotations

from typing import Any

import pytest

import fortianalyzer_mcp.server as server_module
import fortianalyzer_mcp.tools.fortiview_tools as fortiview_tools
import fortianalyzer_mcp.tools.ioc_tools as ioc_tools
import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.pcap_tools as pcap_tools
import fortianalyzer_mcp.tools.traffic_tools as traffic_tools
from fortianalyzer_mcp.utils.errors import ValidationError
from fortianalyzer_mcp.utils.validation import build_device_filter

SERIAL = "FG100FTK19001333"
RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"


class RecordingFaz:
    """Answers every appliance call with an empty success and keeps the calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)

        async def call(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, kwargs))
            if name == "get_system_timezone":
                return None
            return {
                "data": [],
                "status": {"code": 0, "message": "OK"},
                "tid": 4242,
                "percentage": 100,
                "total-count": 0,
            }

        return call

    def devices_sent(self) -> list[Any]:
        return [kwargs.get("device") for name, kwargs in self.calls if name == "logsearch_start"]


@pytest.fixture
def faz(monkeypatch: pytest.MonkeyPatch) -> RecordingFaz:
    fake = RecordingFaz()
    monkeypatch.setattr(server_module, "faz_client", fake)
    monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
    monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)
    return fake


class TestTheFilter:
    @pytest.mark.parametrize(
        "typed", [f"  {SERIAL}  ", f"{SERIAL}\n", f"\t{SERIAL}\r\n"], ids=["spaces", "lf", "crlf"]
    )
    def test_a_serial_with_whitespace_around_it_is_the_serial(self, typed: str) -> None:
        assert build_device_filter(typed) == [{"devid": SERIAL}]

    def test_a_name_with_whitespace_around_it_is_the_name(self) -> None:
        assert build_device_filter(" FGT-HQ-01\n") == [{"devname": "FGT-HQ-01"}]

    @pytest.mark.parametrize("typed", [" ", "\n", " \t "], ids=["space", "lf", "mixed"])
    def test_a_value_of_whitespace_only_is_refused(self, typed: str) -> None:
        with pytest.raises(ValidationError, match="blank"):
            build_device_filter(typed)

    @pytest.mark.parametrize("typed", [None, ""], ids=["none", "empty"])
    def test_no_device_is_every_fortigate_as_before(self, typed: str | None) -> None:
        assert build_device_filter(typed) == [{"devid": "All_FortiGate"}]

    def test_a_lower_case_serial_stays_a_name(self) -> None:
        """A device can be named like a serial, and without a lookup the two
        cannot be told apart; logsearch refuses a lower-case serial (#187)."""
        assert build_device_filter(SERIAL.lower()) == [{"devname": SERIAL.lower()}]


#: The three tools #187 names, each with the arguments it needs to search.
SEARCHES = {
    "query_logs": lambda device: log_tools.query_logs(time_range=RANGE, device=device),
    "search_ips_logs": lambda device: pcap_tools.search_ips_logs(time_range=RANGE, device=device),
    "analyze_policy_traffic": lambda device: traffic_tools.analyze_policy_traffic(
        policy_ids=[1], time_range=RANGE, device=device
    ),
}


class TestThroughTheTools:
    @pytest.mark.parametrize("tool", sorted(SEARCHES))
    @pytest.mark.parametrize("typed", [f" {SERIAL} ", f"{SERIAL}\n"], ids=["spaces", "lf"])
    async def test_the_serial_is_searched_as_the_serial(
        self, faz: RecordingFaz, tool: str, typed: str
    ) -> None:
        result = await SEARCHES[tool](typed)

        assert result["status"] == "success", result
        assert faz.devices_sent()
        assert all(device == [{"devid": SERIAL}] for device in faz.devices_sent())

    @pytest.mark.parametrize("tool", sorted(SEARCHES))
    async def test_a_blank_device_is_refused_and_nothing_is_searched(
        self, faz: RecordingFaz, tool: str
    ) -> None:
        result = await SEARCHES[tool]("   ")

        assert result["status"] == "error", result
        assert "blank" in str(result)
        assert faz.devices_sent() == []


#: Every other tool whose ``device`` goes through ``build_device_filter``.
OTHERS = {
    "get_log_stats": lambda device, out: log_tools.get_log_stats(device=device),
    "get_pcap_by_session": lambda device, out: pcap_tools.get_pcap_by_session(
        session_id=1, time_range=RANGE, device=device, output_dir=out
    ),
    "search_and_download_pcaps": lambda device, out: pcap_tools.search_and_download_pcaps(
        time_range=RANGE, device=device, output_dir=out
    ),
    "run_fortiview": lambda device, out: fortiview_tools.run_fortiview(
        view_name="top-sources", time_range=RANGE, device=device
    ),
    "get_fortiview_data": lambda device, out: fortiview_tools.get_fortiview_data(
        view_name="top-sources", time_range=RANGE, device=device
    ),
    "run_ioc_rescan": lambda device, out: ioc_tools.run_ioc_rescan(time_range=RANGE, device=device),
    "run_and_wait_ioc_rescan": lambda device, out: ioc_tools.run_and_wait_ioc_rescan(
        time_range=RANGE, device=device
    ),
}


@pytest.mark.parametrize("tool", sorted(OTHERS))
async def test_every_other_tool_answers_a_blank_device_with_an_error(
    faz: RecordingFaz, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, tool: str
) -> None:
    """The refusal is raised in the shared filter builder; each tool has to
    turn it into an answer, not let it out as an exception."""
    monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    result = await OTHERS[tool]("   ", str(tmp_path))

    assert isinstance(result, dict) and result["status"] == "error", result
    assert "blank" in str(result)
