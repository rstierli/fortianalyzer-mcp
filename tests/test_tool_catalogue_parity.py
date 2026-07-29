"""The dynamic-mode catalogue must equal the registered tool set.

Dynamic mode keeps a hand-written catalogue so that searching for a tool does
not import every tool module -- which would register all of them and destroy
the minimal surface the mode exists for. The cost of hand-maintenance is drift,
and it had already drifted: the catalogue reported 72 tools against 85
registered, omitted the pcap/soar/ueba tools that dispatch could nonetheless
execute, and listed neither get_api_ratelimit nor update_api_ratelimit.

This test converts that drift into a failing suite.

**This file's premise only holds when ``FAZ_TOOL_MODE`` is not ``dynamic``.**
``TOOL_CATALOGUE`` describes the full-mode surface (73 tools), and the three
tests that diff it against ``_registered_tool_names()`` assume that is what
``fortianalyzer_mcp.server.mcp`` actually has registered. Running the *whole
test suite* with ``FAZ_TOOL_MODE=dynamic`` breaks that assumption in a way
that is easy to misdiagnose as "3 discovery tools instead of 73": dynamic
mode's own ``execute_advanced_tool`` lazily imports all twelve tool modules
the first time anything actually calls it (``server.py``, by design -- see
the brief for Task 9), and every one of those modules' ``@mcp.tool()``
decorators binds unconditionally to the one process-global
``fortianalyzer_mcp.server.mcp`` singleton, the same object dynamic mode's 3
discovery tools already live on. If anything else collected in the same
pytest session exercises that dispatch path -- ``test_dynamic_mode_filters.py``
does, via its own ``execute_advanced_tool`` fixture -- the registered set
measured here is neither 3 nor 73 but 76 (73 + 3, both coexisting on the same
singleton), and whether that lazy import has already fired by the time a
given test runs depends on collection/execution order rather than on
anything this file controls. The three tests below are skipped under
``FAZ_TOOL_MODE=dynamic`` for exactly that reason -- not because dynamic mode
is broken, but because "does the full-mode catalogue equal what's
registered" is not a meaningful question to ask while the *entire test
session* (not just this file) is forced into dynamic mode.
"""

from __future__ import annotations

import os

import pytest

_DYNAMIC_MODE_REASON = (
    "TOOL_CATALOGUE describes full mode's 73 tools; under a session-wide "
    "FAZ_TOOL_MODE=dynamic, execute_advanced_tool's lazy tool-module import "
    "(triggered elsewhere in the suite, e.g. test_dynamic_mode_filters.py) "
    "registers all 73 full-mode tools alongside dynamic mode's 3 discovery "
    "tools on the same shared mcp singleton -- 76, not 3 and not 73 -- making "
    "a diff against the full-mode catalogue meaningless and order-dependent."
)
skip_if_dynamic_mode = pytest.mark.skipif(
    os.environ.get("FAZ_TOOL_MODE") == "dynamic", reason=_DYNAMIC_MODE_REASON
)


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


@skip_if_dynamic_mode
def test_catalogue_lists_every_registered_tool() -> None:
    missing = _registered_tool_names() - _catalogue_names()
    assert not missing, f"registered but not in the catalogue: {sorted(missing)}"


@skip_if_dynamic_mode
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


@skip_if_dynamic_mode
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
