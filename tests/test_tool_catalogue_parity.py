"""The dynamic-mode catalogue must equal the registered tool set.

Dynamic mode keeps a hand-written catalogue so that searching for a tool does
not import every tool module -- which would register all of them and destroy
the minimal surface the mode exists for. The cost of hand-maintenance is drift,
and it had already drifted: the catalogue reported 72 tools against 85
registered, omitted the pcap/soar/ueba tools that dispatch could nonetheless
execute, and listed neither get_api_ratelimit nor update_api_ratelimit.

This test converts that drift into a failing suite.
"""

from __future__ import annotations

import pytest


def _registered_tool_names() -> set[str]:
    """Every tool name registered in full mode.

    Read from FastMCP, not from `tools.__all__`: that list holds the ten tool
    *modules*, never the tool functions, so using it here would compare the
    catalogue against the wrong thing and pass while saying nothing.
    """
    import asyncio

    import fortianalyzer_mcp.server as server

    return {tool.name for tool in asyncio.run(server.mcp.list_tools())}


def _catalogue_names() -> set[str]:
    from fortianalyzer_mcp.server import TOOL_CATALOGUE

    return {name for names in TOOL_CATALOGUE.values() for name in names}


def test_catalogue_lists_every_registered_tool() -> None:
    missing = _registered_tool_names() - _catalogue_names()
    assert not missing, f"registered but not in the catalogue: {sorted(missing)}"


def test_catalogue_lists_nothing_that_is_not_registered() -> None:
    extra = _catalogue_names() - _registered_tool_names()
    assert not extra, f"in the catalogue but not registered: {sorted(extra)}"


def test_no_tool_appears_in_two_categories() -> None:
    """A duplicate makes the reported count wrong even when both sets match."""
    from fortianalyzer_mcp.server import TOOL_CATALOGUE

    seen: set[str] = set()
    duplicated: set[str] = set()
    for names in TOOL_CATALOGUE.values():
        for name in names:
            if name in seen:
                duplicated.add(name)
            seen.add(name)
    assert not duplicated, f"listed in more than one category: {sorted(duplicated)}"


def test_reported_total_matches_the_catalogue() -> None:
    """The hardcoded 72 against 85 registered is the bug this closes."""
    from fortianalyzer_mcp.server import TOOL_CATALOGUE

    total = sum(len(names) for names in TOOL_CATALOGUE.values())
    assert total == len(_catalogue_names())
    assert total == len(_registered_tool_names())


@pytest.mark.parametrize(
    "removed",
    [
        "get_top_sources",
        "get_top_destinations",
        "get_top_applications",
        "get_top_threats",
        "get_top_websites",
        "get_top_cloud_applications",
        "get_policy_hits",
        "search_traffic_logs",
        "search_security_logs",
        "search_event_logs",
        "get_policy_traffic_profile",
        "get_policy_port_analysis",
        "get_policy_protocol_summary",
    ],
)
def test_consolidated_tools_are_absent_from_the_catalogue(removed: str) -> None:
    assert removed not in _catalogue_names()


def test_the_replacement_is_present() -> None:
    assert "analyze_policy_traffic" in _catalogue_names()
