"""Contract tests for MCP tool annotations.

Annotations are advertisement: a client reads them to decide what it may
auto-approve, what it must confirm and what it should surface to a human.
So a wrong hint is a safety bug -- a tool that mutates FortiAnalyzer while
advertising ``readOnlyHint=true`` is precisely the failure a gating client
cannot defend against. These tests exist so that failure has to be made
deliberately.

Four separate contracts, deliberately not collapsed into one assertion:

1. Every registered tool is annotated, with all four hint fields set.
   Catches a new tool added with a bare ``@mcp.tool()``.
2. Every tool's annotations are *identical to* one of the approved
   categories in ``tool_annotations.CATEGORIES``. Catches a hand-rolled
   ``ToolAnnotations(...)`` combination that nobody reviewed.
3. The set of non-read-only tool names equals a frozen expectation below.
   This is the one that matters: it catches a tool silently gaining or
   losing write semantics, in either direction. Flipping a reader to a
   writer fails here, and so does the reverse -- a writer mis-annotated
   as ``READ_ONLY``, which is the dangerous direction.
4. ``openWorldHint=False`` stays confined to the two in-process tools.

Both ``FAZ_TOOL_MODE`` surfaces are covered, because dynamic mode
registers three tools that full mode never sees. Reaching a registry means
re-importing ``server`` and the tool modules under a chosen mode, which is
global mutation of ``os.environ`` and ``sys.modules``; the ``registries``
fixture snapshots and restores both so nothing leaks into the test
modules collected after this one.
"""

import importlib
import os
import sys
from collections.abc import Iterator
from typing import Any

import pytest

from fortianalyzer_mcp import tool_annotations
from fortianalyzer_mcp.tool_annotations import (
    CATEGORIES,
    CREATES,
    DESTRUCTIVE,
    READ_ONLY,
    READ_ONLY_LOCAL,
    UNCONSTRAINED,
    UPDATES,
)

#: Every tool that changes FortiAnalyzer state, and the category it must
#: carry. Adding a mutating tool means adding it here in the same commit;
#: that is the point of the list. Local-filesystem writers (``save_report``
#: and the PCAP downloaders) are deliberately absent -- see
#: ``docs/adr/0003-mcp-tool-annotations.md`` for why they count as readers.
EXPECTED_MUTATING = {
    # dvm_tools
    "add_device": CREATES,
    "add_devices_bulk": CREATES,
    "delete_device": DESTRUCTIVE,
    "delete_devices_bulk": DESTRUCTIVE,
    # event_tools
    "acknowledge_alerts": UPDATES,
    "unacknowledge_alerts": UPDATES,
    "add_alert_comment": CREATES,
    # incident_tools
    "create_incident": CREATES,
    "update_incident": DESTRUCTIVE,
    # ioc_tools
    "acknowledge_ioc_events": UPDATES,
    "run_ioc_rescan": CREATES,
    "run_and_wait_ioc_rescan": CREATES,
    # log_tools
    "cancel_log_search": DESTRUCTIVE,
    # system_tools
    "update_api_ratelimit": DESTRUCTIVE,
}

#: Dynamic mode only. Dispatches to any tool by name, so it is a writer by
#: reachability rather than by its own body.
EXPECTED_MUTATING_DYNAMIC = {"execute_advanced_tool": UNCONSTRAINED}

#: The only tools that never leave the process, hence the only ones with
#: ``openWorldHint=False``.
EXPECTED_LOCAL = {"find_fortianalyzer_tool", "list_fortianalyzer_categories"}

#: The whole dynamic-mode surface. See ``test_dynamic_mode_surface_stays_minimal``.
EXPECTED_DYNAMIC_SURFACE = {
    "find_fortianalyzer_tool",
    "execute_advanced_tool",
    "list_fortianalyzer_categories",
}

HINT_FIELDS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")

#: Env vars the loader sets. Snapshotted and restored around the fixture.
_TOUCHED_ENV = (
    "FAZ_TOOL_MODE",
    "MASKING_ENABLED",
    "FAZ_SKILLS_ENABLED",
    "FORTIANALYZER_HOST",
    "FORTIANALYZER_API_TOKEN",
)


def _is_reloadable(name: str) -> bool:
    """Modules that register tools at import and so must be reloaded per mode."""
    return (
        name == "fortianalyzer_mcp.server"
        or name.startswith("fortianalyzer_mcp.tools")
        or name.startswith("fortianalyzer_mcp.skills")
    )


def _clear_reloadable() -> None:
    for name in [n for n in sys.modules if _is_reloadable(n)]:
        del sys.modules[name]


def _load_tools(mode: str) -> dict[str, Any]:
    """Re-import the server in ``mode`` and return ``{name: Tool}``.

    ``server`` and the tool modules register at import time and cache in
    ``sys.modules``, so the mode has to be set before a forced reload of
    every one of them. Masking is disabled: it patches ``mcp.tool`` and is
    orthogonal to what is asserted here, and leaving it on would demand a
    key in the environment. Skills are enabled so ``faz_skill`` is covered.
    """
    import fortianalyzer_mcp.utils.config as config

    os.environ["FAZ_TOOL_MODE"] = mode
    os.environ["MASKING_ENABLED"] = "false"
    os.environ["FAZ_SKILLS_ENABLED"] = "true"
    # A real deployment supplies these; the tools are never called here.
    os.environ.setdefault("FORTIANALYZER_HOST", "127.0.0.1")
    os.environ.setdefault("FORTIANALYZER_API_TOKEN", "not-used-no-call-is-made")

    config.get_settings.cache_clear()
    _clear_reloadable()
    server = importlib.import_module("fortianalyzer_mcp.server")
    return {tool.name: tool for tool in server.mcp._tool_manager.list_tools()}


@pytest.fixture(scope="module")
def registries() -> Iterator[dict[str, dict[str, Any]]]:
    """Both mode registries, with global state restored afterwards.

    Only ``.name`` and ``.annotations`` are read off the returned Tool
    objects, so they stay valid after the modules they came from are
    evicted from ``sys.modules``.
    """
    import fortianalyzer_mcp.utils.config as config

    saved_env = {key: os.environ.get(key) for key in _TOUCHED_ENV}
    saved_modules = {name: mod for name, mod in sys.modules.items() if _is_reloadable(name)}
    try:
        yield {"full": _load_tools("full"), "dynamic": _load_tools("dynamic")}
    finally:
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        _clear_reloadable()
        sys.modules.update(saved_modules)
        config.get_settings.cache_clear()


@pytest.fixture(scope="module")
def full_tools(registries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return registries["full"]


@pytest.fixture(scope="module")
def dynamic_tools(registries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return registries["dynamic"]


def test_categories_are_pairwise_distinct() -> None:
    """No two named categories may carry the same four hints.

    Two names for one hint combination would make the category a comment
    rather than a contract: the identity check below could not tell which
    one a tool meant, and a reviewer reading ``UPDATES`` would have no
    guarantee it differs from ``CREATES`` on the wire.
    """
    seen: dict[tuple[Any, ...], str] = {}
    for name, ann in CATEGORIES.items():
        key = tuple(getattr(ann, field) for field in HINT_FIELDS)
        assert key not in seen, f"{name} duplicates {seen[key]}: {key}"
        seen[key] = name


def test_every_category_sets_all_four_hints() -> None:
    """Including the two the spec calls meaningful only for writers.

    ``destructiveHint`` defaults to *true* on the wire, so a reader that
    omits it advertises "may perform destructive updates" to any client
    that reads the field without checking ``readOnlyHint`` first.
    """
    for name, ann in CATEGORIES.items():
        for field in HINT_FIELDS:
            assert getattr(ann, field) is not None, f"{name}.{field} is None"


@pytest.mark.parametrize("mode", ["full", "dynamic"])
def test_every_tool_is_annotated(mode: str, registries: dict[str, dict[str, Any]]) -> None:
    tools = registries[mode]
    assert tools, f"{mode} mode registered no tools at all"
    for name, tool in tools.items():
        ann = tool.annotations
        assert ann is not None, f"{name} has no annotations (bare @mcp.tool()?)"
        for field in HINT_FIELDS:
            assert getattr(ann, field) is not None, f"{name}.{field} is None"


@pytest.mark.parametrize("mode", ["full", "dynamic"])
def test_every_tool_uses_an_approved_category(
    mode: str, registries: dict[str, dict[str, Any]]
) -> None:
    """Hints must match a reviewed category exactly, not merely be plausible."""
    approved = {
        tuple(getattr(ann, field) for field in HINT_FIELDS): name
        for name, ann in CATEGORIES.items()
    }
    for name, tool in registries[mode].items():
        key = tuple(getattr(tool.annotations, field) for field in HINT_FIELDS)
        assert key in approved, (
            f"{name} carries an unapproved hint combination {key}; add a category "
            f"to tool_annotations.CATEGORIES instead of hand-rolling ToolAnnotations"
        )


def test_full_mode_registers_the_whole_surface(full_tools: dict[str, Any]) -> None:
    """Guard the premise of the frozen-set tests below.

    Every assertion about the write surface is vacuous if the tools never
    registered, so pin the count: 85 raw tools plus the ``faz_skill``
    dispatcher. A tool added or removed is expected to update this number
    together with the lists above.
    """
    assert len(full_tools) == 86, f"full mode registered {len(full_tools)} tools"
    assert "faz_skill" in full_tools, "skills dispatcher did not register"


def test_full_mode_mutating_set_is_frozen(full_tools: dict[str, Any]) -> None:
    """The write surface is exactly EXPECTED_MUTATING -- no more, no less."""
    actual = {
        name for name, tool in full_tools.items() if tool.annotations.readOnlyHint is not True
    }
    expected = set(EXPECTED_MUTATING)

    unexpected = actual - expected
    assert not unexpected, (
        f"tool(s) {sorted(unexpected)} became non-read-only; if that is intended, "
        f"add them to EXPECTED_MUTATING with a reviewed category"
    )
    missing = expected - actual
    assert not missing, (
        f"tool(s) {sorted(missing)} mutate FortiAnalyzer but no longer advertise it; "
        f"a writer annotated READ_ONLY is the dangerous direction of this bug"
    )


def test_full_mode_mutating_categories_match(full_tools: dict[str, Any]) -> None:
    for name, expected in EXPECTED_MUTATING.items():
        assert name in full_tools, f"{name} is no longer registered in full mode"
        assert full_tools[name].annotations == expected, (
            f"{name}: expected {expected!r}, got {full_tools[name].annotations!r}"
        )


def test_dynamic_mode_mutating_set_is_frozen(dynamic_tools: dict[str, Any]) -> None:
    """Dynamic mode's write surface is execute_advanced_tool alone."""
    actual = {
        name for name, tool in dynamic_tools.items() if tool.annotations.readOnlyHint is not True
    }
    assert actual == set(EXPECTED_MUTATING_DYNAMIC), (
        f"dynamic-mode write surface changed: {sorted(actual)}"
    )
    for name, expected in EXPECTED_MUTATING_DYNAMIC.items():
        assert dynamic_tools[name].annotations == expected


def test_open_world_is_false_only_for_the_local_catalogue_tools(
    full_tools: dict[str, Any], dynamic_tools: dict[str, Any]
) -> None:
    """Anything that reaches the appliance must advertise an open world."""
    closed = {
        name
        for tools in (full_tools, dynamic_tools)
        for name, tool in tools.items()
        if tool.annotations.openWorldHint is False
    }
    assert closed == EXPECTED_LOCAL, (
        f"openWorldHint=False set changed: {sorted(closed)}; a tool that queries "
        f"FortiAnalyzer interacts with an external entity and must not claim otherwise"
    )


def test_dynamic_mode_surface_stays_minimal(dynamic_tools: dict[str, Any]) -> None:
    """Regression guard on the import hazard this change had to route around.

    ``tool_annotations`` lives at package top level precisely because
    importing anything under ``fortianalyzer_mcp.tools`` executes
    ``tools/__init__.py``, which imports all twelve tool modules and
    registers all 85 raw tools. Had the constants been placed under
    ``tools/``, ``register_dynamic_tools`` importing them would have
    silently turned dynamic mode into full mode. This asserts it did not.
    """
    assert set(dynamic_tools) == EXPECTED_DYNAMIC_SURFACE, (
        f"dynamic mode registered {len(dynamic_tools)} tools: {sorted(dynamic_tools)}"
    )


def test_all_exported_categories_are_in_the_registry() -> None:
    """``CATEGORIES`` must not drift behind the module's public constants."""
    exported = {
        name
        for name in tool_annotations.__all__
        if name != "CATEGORIES" and isinstance(getattr(tool_annotations, name), type(READ_ONLY))
    }
    assert exported == set(CATEGORIES), (
        f"exported constants {sorted(exported)} != CATEGORIES keys {sorted(CATEGORIES)}"
    )
    # Registry values must be the constants themselves, not copies.
    assert CATEGORIES["READ_ONLY"] is READ_ONLY
    assert CATEGORIES["READ_ONLY_LOCAL"] is READ_ONLY_LOCAL
    assert CATEGORIES["UNCONSTRAINED"] is UNCONSTRAINED
