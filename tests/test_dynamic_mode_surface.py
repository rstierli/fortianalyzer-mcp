"""Dynamic mode lists its discovery tools only, also after a call (#204, item 19).

``execute_advanced_tool`` imports the tool modules to find the function it
runs. Importing them registers every tool on the server, so after one call,
even with an unknown tool name, ``list_tools`` listed all of them, write
tools included. The mode is fixed when the server module is imported, so the
server runs in a child process here.
"""

import json
import os
import subprocess
import sys
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer

import fortianalyzer_mcp.server as server

DISCOVERY = ["execute_advanced_tool", "find_fortianalyzer_tool", "list_fortianalyzer_categories"]
#: The throwaway key tests/test_dynamic_mode_filters.py uses.
MASKING_KEY = "2DE79D232DF5585D68CE47882AE256D6"

CHILD = r"""
import asyncio
import json

import fortianalyzer_mcp.server as server


class Client:
    async def get_alerts(self, **kwargs):
        return {"data": [{"alertid": "1", "epip": "198.51.100.7"}]}


async def listed():
    return sorted(tool.name for tool in await server.mcp.list_tools())


async def main():
    seen = {"at start": await listed()}
    await server.mcp.call_tool("execute_advanced_tool", {"tool_name": "no_such_tool"})
    seen["after an unknown name"] = await listed()
    server.faz_client = Client()
    answers = []
    for key in ("after a tool ran", "after it ran again"):
        answer = await server.mcp.call_tool(
            "execute_advanced_tool",
            {
                "tool_name": "get_alerts",
                "parameters": {"time_range": "2024-01-01 00:00:00|2024-01-02 00:00:00"},
            },
        )
        answers.append(answer.model_dump_json())
        seen[key] = await listed()
    print(json.dumps({"listed": seen, "answers": answers}))


asyncio.run(main())
"""


def run_dynamic(masking: bool) -> dict[str, Any]:
    env = {
        **os.environ,
        "FAZ_TOOL_MODE": "dynamic",
        "FORTIANALYZER_HOST": "ci-dummy.local",
        "MASKING_ENABLED": "true" if masking else "false",
        "FAZ_MASKING_KEY": MASKING_KEY,
        "FAZ_SKILLS_ENABLED": "false",
    }
    done = subprocess.run(
        [sys.executable, "-c", CHILD], env=env, capture_output=True, text=True, timeout=120
    )
    assert done.returncode == 0, done.stderr[-2000:]
    answer: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    return answer


@pytest.mark.parametrize("masking", [False, True], ids=["masking off", "masking on"])
def test_the_list_stays_the_discovery_tools(masking: bool) -> None:
    listed = run_dynamic(masking)["listed"]
    assert listed == {
        "at start": DISCOVERY,
        "after an unknown name": DISCOVERY,
        "after a tool ran": DISCOVERY,
        "after it ran again": DISCOVERY,
    }


@pytest.mark.parametrize("masking", [False, True], ids=["masking off", "masking on"])
def test_the_tool_still_runs(masking: bool) -> None:
    """Taken off the list, not out of reach: each call runs it, and with
    masking on its answer is masked."""
    answers = run_dynamic(masking)["answers"]
    assert len(answers) == 2
    for answer in answers:
        assert '\\"status\\": \\"success\\"' in answer
        assert ("198.51.100.7" in answer) is not masking


async def test_a_private_server_leaves_the_shared_one_alone() -> None:
    """A control: in this test process the tool modules are imported already
    (with the server module in full mode, by the test files in either mode),
    and the dispatch of a server made for a test removes none of their tools."""
    before = sorted(tool.name for tool in await server.mcp.list_tools())
    private = MCPServer("dynamic-surface-test")
    server.register_dynamic_tools(private)
    tools = {tool.name: tool for tool in private._tool_manager.list_tools()}
    await tools["execute_advanced_tool"].fn(tool_name="no_such_tool")
    assert sorted(tool.name for tool in await server.mcp.list_tools()) == before
    assert len(before) > len(DISCOVERY)
