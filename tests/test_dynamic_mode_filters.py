"""Structured ``filters`` must survive the dynamic-mode dispatch path.

Full mode gets dict-to-model coercion for free: FastMCP validates a caller's
JSON into ``FilterCondition`` models before a tool body runs, which is the
assumption ``TestCompilerRequiresModelsNotDicts`` pins. Dynamic mode's
``execute_advanced_tool`` bypasses that layer -- it invokes the raw tool
function directly -- so ``filters`` arrived as raw dicts, the compilers'
attribute access raised ``AttributeError``, and the tools' broad handlers
buried it in a generic ``faz_operation_failed``. Structured filters were
silently unusable on the whole dynamic surface (``query_logs``,
``search_devices``, ``list_tasks``); found in review of #94.

The dispatch path therefore has to perform the validation FastMCP would
have: dicts become models before the tool runs, and a malformed condition
is rejected with the standard ``validation_error`` envelope instead of
reaching a compiler.
"""

from __future__ import annotations

from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from fortianalyzer_mcp.query.filters import FilterCondition
from fortianalyzer_mcp.server import register_dynamic_tools
from fortianalyzer_mcp.tools import dvm_tools


@pytest.fixture(scope="module")
def execute_advanced_tool() -> Any:
    """The dispatcher off a private FastMCP instance, not the global one.

    ``register_dynamic_tools`` only needs a server to hang tools on; using a
    fresh instance keeps this module independent of ``FAZ_TOOL_MODE`` in the
    test environment.
    """
    server = FastMCP("dynamic-filters-test")
    register_dynamic_tools(server)
    tools = {tool.name: tool for tool in server._tool_manager.list_tools()}
    return tools["execute_advanced_tool"].fn


class FakeDeviceClient:
    """Captures the array-dialect filter search_devices hands to the client."""

    def __init__(self) -> None:
        self.captured: list[list[Any]] | None = None
        self.calls: int = 0

    async def list_devices(
        self,
        adom: str,
        filter: list[list[Any]] | None = None,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        self.calls += 1
        self.captured = filter
        return []


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> FakeDeviceClient:
    fake = FakeDeviceClient()
    monkeypatch.setattr(dvm_tools, "_get_client", lambda: fake)
    return fake


class TestDictFiltersAreCoerced:
    """The raw-dict shape a JSON caller sends must reach the tool as models."""

    async def test_dict_filters_compile_and_reach_the_client(
        self, execute_advanced_tool: Any, fake_client: FakeDeviceClient
    ) -> None:
        result = await execute_advanced_tool(
            tool_name="search_devices",
            parameters={"filters": [{"field": "os_version", "op": "contains", "value": "7.6"}]},
        )

        assert fake_client.captured == [["os_ver", "like", "%7.6%"]]
        assert result["status"] == "success"

    async def test_op_defaults_to_eq_like_the_model_does(
        self, execute_advanced_tool: Any, fake_client: FakeDeviceClient
    ) -> None:
        await execute_advanced_tool(
            tool_name="search_devices",
            parameters={"filters": [{"field": "name", "value": "fgt-01"}]},
        )

        assert fake_client.captured == [["name", "==", "fgt-01"]]

    async def test_model_instances_pass_through_unchanged(
        self, execute_advanced_tool: Any, fake_client: FakeDeviceClient
    ) -> None:
        """An in-process caller may already hold models; both shapes mix."""
        await execute_advanced_tool(
            tool_name="search_devices",
            parameters={
                "filters": [
                    FilterCondition(field="os_version", op="contains", value="7.6"),
                    {"field": "conn_status", "op": "eq", "value": "down"},
                ]
            },
        )

        assert fake_client.captured is not None
        assert ["os_ver", "like", "%7.6%"] in fake_client.captured
        assert ["conn_status", "==", 2] in fake_client.captured

    async def test_absent_and_none_filters_stay_untouched(
        self, execute_advanced_tool: Any, fake_client: FakeDeviceClient
    ) -> None:
        result = await execute_advanced_tool(
            tool_name="search_devices",
            parameters={"filters": None},
        )

        assert result["status"] == "success"
        assert fake_client.captured is None


class TestMalformedFiltersAreRejectedAtDispatch:
    """A bad condition fails with the standard envelope, before the tool runs.

    This mirrors what full mode does at the protocol boundary: the caller
    gets told what is wrong with the condition, not a generic operation
    failure from deep inside a compiler.
    """

    async def test_unknown_op_returns_validation_error(
        self, execute_advanced_tool: Any, fake_client: FakeDeviceClient
    ) -> None:
        result = await execute_advanced_tool(
            tool_name="search_devices",
            parameters={"filters": [{"field": "name", "op": "matches", "value": "x"}]},
        )

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert "op" in result["message"]
        assert fake_client.calls == 0, "the tool must not run with a bad condition"

    async def test_unknown_key_returns_validation_error(
        self, execute_advanced_tool: Any, fake_client: FakeDeviceClient
    ) -> None:
        """``extra='forbid'`` on the model must hold on this path too."""
        result = await execute_advanced_tool(
            tool_name="search_devices",
            parameters={"filters": [{"field": "name", "op": "eq", "vlaue": "x"}]},
        )

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert fake_client.calls == 0

    async def test_bare_dict_instead_of_list_is_rejected_with_guidance(
        self, execute_advanced_tool: Any, fake_client: FakeDeviceClient
    ) -> None:
        """The likely LLM mistake: one condition object, no list wrapper."""
        result = await execute_advanced_tool(
            tool_name="search_devices",
            parameters={"filters": {"field": "name", "op": "eq", "value": "x"}},
        )

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert "list" in result["message"]
        assert fake_client.calls == 0

    async def test_error_envelope_names_the_dispatched_tool(
        self, execute_advanced_tool: Any, fake_client: FakeDeviceClient
    ) -> None:
        result = await execute_advanced_tool(
            tool_name="search_devices",
            parameters={"filters": [{"field": "name", "op": "matches", "value": "x"}]},
        )

        assert result["operation"] == "execute_advanced_tool"
        assert result["tool_name"] == "search_devices"
