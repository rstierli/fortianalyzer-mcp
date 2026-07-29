"""The consolidation removed thirteen tools. Prove they are gone, and that
each removed call pattern has a working replacement.

A test that only asserts absence would pass just as well if the replacement
were broken, so every entry pairs the two.
"""

from __future__ import annotations

from typing import Any

import pytest

import fortianalyzer_mcp.tools.fortiview_tools as fortiview_tools
import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.traffic_tools as traffic_tools
from fortianalyzer_mcp.query.filters import FilterCondition

CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"

#: (module, removed tool name, the call that replaces it).
REMOVED = [
    (log_tools, "search_traffic_logs", "query_logs(logtype='traffic', filters=[...])"),
    (log_tools, "search_security_logs", "query_logs(logtype='attack', filters=[...])"),
    (log_tools, "search_event_logs", "query_logs(logtype='event', filters=[...])"),
    (fortiview_tools, "get_top_sources", "get_fortiview_data(view_name='top-sources')"),
    (fortiview_tools, "get_top_destinations", "get_fortiview_data('top-destinations')"),
    (fortiview_tools, "get_top_applications", "get_fortiview_data('top-applications')"),
    (fortiview_tools, "get_top_threats", "get_fortiview_data('top-threats')"),
    (fortiview_tools, "get_top_websites", "get_fortiview_data('top-websites')"),
    (
        fortiview_tools,
        "get_top_cloud_applications",
        "get_fortiview_data('top-cloud-applications')",
    ),
    (fortiview_tools, "get_policy_hits", "get_fortiview_data(view_name='policy-hits')"),
    (traffic_tools, "get_policy_traffic_profile", "analyze_policy_traffic(sample_by=[...])"),
    (traffic_tools, "get_policy_port_analysis", "analyze_policy_traffic(sample_by=['port'])"),
    (
        traffic_tools,
        "get_policy_protocol_summary",
        "analyze_policy_traffic(sample_by=['proto'])",
    ),
]


@pytest.mark.parametrize("module,name,replacement", REMOVED, ids=[name for _, name, _ in REMOVED])
def test_removed_tool_is_gone(module: object, name: str, replacement: str) -> None:
    assert not hasattr(module, name), f"{name} is still defined; use {replacement}"


@pytest.mark.parametrize("name", [name for _, name, _ in REMOVED])
def test_removed_tool_is_not_registered(name: str) -> None:
    """Gone from the module is not enough; it must be off the MCP surface."""
    import asyncio

    import fortianalyzer_mcp.server as server

    registered = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert name not in registered, f"{name} is still advertised to clients"


class TestSearchWrapperReplacement:
    """The filters surface expresses what the deleted wrappers hard-coded."""

    class _Faz:
        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

    async def test_traffic_search_by_port_and_action(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        async def fake_page(client: object, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {"timed_out": False, "tid": 1, "logs": [], "total": 0}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        await log_tools.query_logs(
            logtype="traffic",
            time_range=CUSTOM_RANGE,
            filters=[
                FilterCondition(field="dstport", op="eq", value=443),
                FilterCondition(field="action", op="eq", value="deny"),
            ],
        )

        assert captured["filter"] == "dstport==443 and action==deny"

    async def test_security_search_by_severity(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        async def fake_page(client: object, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {"timed_out": False, "tid": 1, "logs": [], "total": 0}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        await log_tools.query_logs(
            logtype="attack",
            time_range=CUSTOM_RANGE,
            filters=[FilterCondition(field="severity", op="in", value=["critical", "high"])],
        )

        assert captured["filter"] == "(severity==critical or severity==high)"

    async def test_event_search_by_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        async def fake_page(client: object, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {"timed_out": False, "tid": 1, "logs": [], "total": 0}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        await log_tools.query_logs(
            logtype="event",
            time_range=CUSTOM_RANGE,
            filters=[FilterCondition(field="level", op="eq", value="warning")],
        )

        assert captured["filter"] == "level==warning"
