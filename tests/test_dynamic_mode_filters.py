"""Structured ``filters`` must survive the dynamic-mode dispatch path.

Full mode gets dict-to-model coercion for free: MCPServer validates a caller's
JSON into ``FilterCondition`` models before a tool body runs, which is the
assumption ``TestCompilerRequiresModelsNotDicts`` pins. Dynamic mode's
``execute_advanced_tool`` bypasses that layer -- it invokes the raw tool
function directly -- so ``filters`` arrived as raw dicts, the compilers'
attribute access raised ``AttributeError``, and the tools' broad handlers
buried it in a generic ``faz_operation_failed``. Structured filters were
silently unusable on the whole dynamic surface (``query_logs``,
``search_devices``, ``list_tasks``); found in review of #94.

The dispatch path therefore has to perform the validation MCPServer would
have: dicts become models before the tool runs, and a malformed condition
is rejected with the standard ``validation_error`` envelope instead of
reaching a compiler.

This applies to every ``list[SomeModel]`` tool parameter, not just
``filters`` -- ``acknowledge_ioc_events``'s ``events`` is the second one, and
is covered further down. Registering a new one means adding it to
``server._structured_params``, which gives it the per-entry error message.

Scalar parameters cross the same boundary: the last class in this module
pins that ``int`` and ``bool`` arguments are validated against the tool's
signature the way full mode validates them.
"""

from __future__ import annotations

from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer

from fortianalyzer_mcp.masking.wrapper import install_masking
from fortianalyzer_mcp.query.filters import FilterCondition
from fortianalyzer_mcp.server import register_dynamic_tools
from fortianalyzer_mcp.tool_annotations import READ_ONLY
from fortianalyzer_mcp.tools import dvm_tools, ioc_tools, system_tools

# Throwaway test key, the same value tests/test_masking_wrapper.py uses.
MASKING_KEY = "2DE79D232DF5585D68CE47882AE256D6"


@pytest.fixture(scope="module")
def execute_advanced_tool() -> Any:
    """The dispatcher off a private MCPServer instance, not the global one.

    ``register_dynamic_tools`` only needs a server to hang tools on; using a
    fresh instance keeps this module independent of ``FAZ_TOOL_MODE`` in the
    test environment.
    """
    server = MCPServer("dynamic-filters-test")
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
            parameters={"filters": [{"field": "platform", "op": "contains", "value": "VM"}]},
        )

        assert fake_client.captured == [["platform_str", "like", "%VM%"]]
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
                    FilterCondition(field="platform", op="contains", value="VM"),
                    {"field": "conn_status", "op": "eq", "value": "down"},
                ]
            },
        )

        assert fake_client.captured == [
            ["platform_str", "like", "%VM%"],
            "&&",
            ["conn_status", "==", 2],
        ]

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


class FakeIocClient:
    """Captures the events payload acknowledge_ioc_events hands to the client."""

    def __init__(self) -> None:
        self.captured: list[dict[str, str]] | None = None
        self.calls: int = 0

    async def acknowledge_ioc_events(
        self,
        adom: str,
        events: list[dict[str, str]],
        comment: str | None = None,
    ) -> dict[str, Any]:
        self.calls += 1
        self.captured = events
        return {"status": "ok"}


@pytest.fixture
def fake_ioc_client(monkeypatch: pytest.MonkeyPatch) -> FakeIocClient:
    fake = FakeIocClient()
    monkeypatch.setattr(ioc_tools, "get_faz_client", lambda: fake)
    return fake


class TestIocEventsAreCoerced:
    """``events`` is the second ``list[SomeModel]`` parameter on this path.

    ``acknowledge_ioc_events`` takes ``list[IocEventRef]`` because an IOC event
    is addressed by endpoint plus timestamp, not by an id. Dynamic dispatch
    hands it raw dicts, so it needs the same coercion ``filters`` gets --
    otherwise ``IocEventRef.to_payload`` is called on a dict and the tool's
    broad handler buries the ``AttributeError``.
    """

    async def test_dict_events_reach_the_client_as_wire_payloads(
        self, execute_advanced_tool: Any, fake_ioc_client: FakeIocClient
    ) -> None:
        result = await execute_advanced_tool(
            tool_name="acknowledge_ioc_events",
            parameters={
                "events": [{"endpoint_id": "1234", "timestamp": "2024-01-15 09:30:00"}],
                "adom": "root",
            },
        )

        assert result["status"] == "success"
        assert fake_ioc_client.captured == [
            {"endpoint-id": "1234", "timestamp": "2024-01-15 09:30:00"}
        ]

    async def test_event_without_an_identity_is_rejected_before_dispatch(
        self, execute_advanced_tool: Any, fake_ioc_client: FakeIocClient
    ) -> None:
        """Neither endpoint_id nor source_ip identifies nothing -- catch it here."""
        result = await execute_advanced_tool(
            tool_name="acknowledge_ioc_events",
            parameters={"events": [{"timestamp": "2024-01-15 09:30:00"}], "adom": "root"},
        )

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert fake_ioc_client.calls == 0

    async def test_bare_dict_instead_of_list_is_rejected_with_guidance(
        self, execute_advanced_tool: Any, fake_ioc_client: FakeIocClient
    ) -> None:
        result = await execute_advanced_tool(
            tool_name="acknowledge_ioc_events",
            parameters={
                "events": {"endpoint_id": "1234", "timestamp": "2024-01-15 09:30:00"},
                "adom": "root",
            },
        )

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert "list" in result["message"]
        assert fake_ioc_client.calls == 0


class FakeTaskClient:
    """Captures what get_task hands to the client."""

    def __init__(self) -> None:
        self.task_ids: list[Any] = []
        self.line_calls: int = 0

    async def get_task(self, task_id: Any) -> dict[str, Any]:
        self.task_ids.append(task_id)
        return {"id": task_id, "state": "done"}

    async def get_task_line(self, task_id: Any) -> list[dict[str, Any]]:
        self.line_calls += 1
        return []


@pytest.fixture
def fake_task_client(monkeypatch: pytest.MonkeyPatch) -> FakeTaskClient:
    fake = FakeTaskClient()
    monkeypatch.setattr(system_tools, "_get_client", lambda: fake)
    return fake


class TestScalarArgumentsAreValidatedLikeFullMode:
    """Plain ``int`` and ``bool`` parameters need full mode's boundary too.

    ``get_task(task_id: int, include_details: bool = False)`` stands in for
    every scalar-typed tool. Full mode validates a caller's JSON against that
    signature before the body runs. Dynamic dispatch called the function with
    whatever arrived: a string id went into the request path as written,
    ``"false"`` was truthy, and a misspelt or missing argument escaped as a
    bare ``TypeError`` instead of the ``validation_error`` envelope.
    """

    async def test_numeric_string_reaches_the_client_as_an_int(
        self, execute_advanced_tool: Any, fake_task_client: FakeTaskClient
    ) -> None:
        result = await execute_advanced_tool(tool_name="get_task", parameters={"task_id": "12345"})

        assert fake_task_client.task_ids == [12345]
        assert result["status"] == "success"

    async def test_string_false_is_not_a_truthy_flag(
        self, execute_advanced_tool: Any, fake_task_client: FakeTaskClient
    ) -> None:
        await execute_advanced_tool(
            tool_name="get_task",
            parameters={"task_id": 12345, "include_details": "false"},
        )

        # Coerced, not refused: the task itself is still read.
        assert fake_task_client.task_ids == [12345]
        assert fake_task_client.line_calls == 0, "include_details='false' must not fetch lines"

    async def test_non_numeric_id_is_rejected_before_dispatch(
        self, execute_advanced_tool: Any, fake_task_client: FakeTaskClient
    ) -> None:
        """The client builds the request path from this value."""
        result = await execute_advanced_tool(
            tool_name="get_task", parameters={"task_id": "12345/line"}
        )

        assert fake_task_client.task_ids == [], "a non-integer id must not reach the client"
        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert "task_id" in result["message"]
        assert result["operation"] == "execute_advanced_tool"
        assert result["tool_name"] == "get_task"

    async def test_unknown_argument_returns_validation_error(
        self, execute_advanced_tool: Any, fake_task_client: FakeTaskClient
    ) -> None:
        """Refused by name, not dropped: a misspelt argument is a caller bug."""
        result = await execute_advanced_tool(
            tool_name="get_task", parameters={"task_id": 12345, "details": True}
        )

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert "details" in result["message"]
        assert fake_task_client.task_ids == []

    async def test_missing_required_argument_returns_validation_error(
        self, execute_advanced_tool: Any, fake_task_client: FakeTaskClient
    ) -> None:
        result = await execute_advanced_tool(tool_name="get_task", parameters={})

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert "task_id" in result["message"]
        assert fake_task_client.task_ids == []

    async def test_masked_tool_is_validated_through_its_wrapper(
        self, execute_advanced_tool: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With MASKING_ENABLED the module attribute is a ``(*args, **kwargs)`` wrapper.

        The tool's signature has to be read through it, or its real
        parameters would look unknown and nothing would be coerced.
        """
        monkeypatch.setenv("FAZ_MASKING_KEY", MASKING_KEY)
        masked_server = MCPServer("dynamic-masked-test")
        install_masking(masked_server)
        received: list[tuple[Any, Any]] = []

        @masked_server.tool(annotations=READ_ONLY)
        async def get_task(task_id: int, include_details: bool = False) -> dict[str, Any]:
            received.append((task_id, include_details))
            return {"status": "success"}

        monkeypatch.setattr(system_tools, "get_task", get_task)

        result = await execute_advanced_tool(
            tool_name="get_task",
            parameters={"task_id": "12345", "include_details": "false"},
        )

        assert received == [(12345, False)]
        assert result["status"] == "success"
