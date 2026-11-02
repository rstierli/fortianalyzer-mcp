"""The server serves at once and connects to FortiAnalyzer in the background.

Awaiting the connect before serving made ``initialize`` wait out the whole
connect timeout when FortiAnalyzer was unreachable with username/password
auth, past Claude Code's own 30 s MCP connect timeout, and a failed startup
connect left every tool answering "Not connected" until a restart.
"""

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

import fortianalyzer_mcp.server as server
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.tools import system_tools
from fortianalyzer_mcp.utils.errors import ConnectionError

REPO_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
# RFC 5737 TEST-NET-1: never routed, so a connect to it hangs until the timeout.
UNREACHABLE_HOST = "192.0.2.1"
CONNECT_TIMEOUT = 20


@pytest.fixture(autouse=True)
def _restore_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "faz_client", None)


def _connected(client: FortiAnalyzerClient) -> None:
    fmg = MagicMock()
    fmg.get.return_value = (0, {"Hostname": "faz-01", "Version": "v7.6.5"})
    client._fmg = fmg
    client._connected = True
    client._ever_connected = True


class TestStartupDoesNotBlock:
    async def test_start_returns_before_the_connect_finishes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        release = asyncio.Event()

        async def slow_connect(self_: FortiAnalyzerClient) -> None:
            await release.wait()
            _connected(self_)

        monkeypatch.setattr(FortiAnalyzerClient, "connect", slow_connect)
        task = server._start_faz_client()
        await asyncio.sleep(0)
        assert not task.done()
        assert server.get_faz_client() is not None

        release.set()
        await task
        assert server.get_faz_client().is_connected

    async def test_stop_cancels_a_pending_connect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def hanging_connect(self_: FortiAnalyzerClient) -> None:
            await asyncio.Event().wait()

        monkeypatch.setattr(FortiAnalyzerClient, "connect", hanging_connect)
        task = server._start_faz_client()
        await asyncio.sleep(0)
        await asyncio.wait_for(server._stop_faz_client(task), timeout=2)
        assert task.cancelled()


class TestRecoveryAfterAFailedStartup:
    async def test_tool_connects_once_fortianalyzer_is_reachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reachable = False

        async def connect(self_: FortiAnalyzerClient) -> None:
            if not reachable:
                raise ConnectionError("Failed to connect to FortiAnalyzer: timed out")
            _connected(self_)

        monkeypatch.setattr(FortiAnalyzerClient, "connect", connect)
        task = server._start_faz_client()
        await task  # the startup attempt fails and only logs

        down: dict[str, Any] = await system_tools.get_system_status()
        assert down["status"] == "error"
        assert "Failed to connect" in down["message"]

        reachable = True
        up: dict[str, Any] = await system_tools.get_system_status()
        assert up["status"] == "success"


class TestStdioHandshake:
    async def test_initialize_does_not_wait_for_an_unreachable_fortianalyzer(self) -> None:
        """The real stdio path, with FortiAnalyzer unreachable.

        Username/password auth, because that login makes a network round-trip
        (API-token login does not). Before the fix ``initialize`` was answered
        only after the connect timeout. The dummy credentials also keep the
        repo's .env secrets from being sent anywhere.
        """
        env = {
            **os.environ,
            "PYTHONPATH": REPO_SRC,
            "MCP_SERVER_MODE": "stdio",
            "LOG_LEVEL": "WARNING",
            "FORTIANALYZER_HOST": UNREACHABLE_HOST,
            "FORTIANALYZER_API_TOKEN": "",
            "FORTIANALYZER_USERNAME": "dummy",
            "FORTIANALYZER_PASSWORD": "dummy",
            "FORTIANALYZER_TIMEOUT": str(CONNECT_TIMEOUT),
            "MASKING_ENABLED": "false",
        }
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "fortianalyzer_mcp"], env=env
        )
        with open(os.devnull, "w") as errlog:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    started = time.monotonic()
                    result = await session.initialize()
                    elapsed = time.monotonic() - started

        assert result.server_info.name
        assert elapsed < CONNECT_TIMEOUT / 2, f"initialize took {elapsed:.1f}s"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def _health(port: int) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as r:
            body: dict[str, Any] = json.loads(r.read())
            assert r.status == 200
            return body
    except OSError:  # not listening yet (URLError is an OSError)
        return None


class TestHealthInTokenMode:
    def test_health_reports_an_unreachable_fortianalyzer_as_not_connected(self) -> None:
        """API-token login makes no request, so the client called itself
        connected and /health said so against an appliance it never reached.
        The token connect now probes /sys/status first. /health stays HTTP
        200 (it is a liveness check); only the flag changes."""
        port = _free_port()
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("FORTIANALYZER_", "MCP_", "FAZ_"))
        }
        env.update(
            PYTHONPATH=REPO_SRC,
            MCP_SERVER_MODE="http",
            MCP_SERVER_HOST="127.0.0.1",
            MCP_SERVER_PORT=str(port),
            MCP_AUTH_TOKEN="dummy-mcp-auth",
            LOG_LEVEL="WARNING",
            FORTIANALYZER_HOST=UNREACHABLE_HOST,
            FORTIANALYZER_API_TOKEN="dummy-api-token",
            FORTIANALYZER_USERNAME="",
            FORTIANALYZER_PASSWORD="",
            FORTIANALYZER_CA_BUNDLE="",
            FORTIANALYZER_TIMEOUT=str(CONNECT_TIMEOUT),
            MASKING_ENABLED="false",
        )
        proc = subprocess.Popen(
            [sys.executable, "-m", "fortianalyzer_mcp"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        seen: list[dict[str, Any]] = []
        try:
            deadline = time.monotonic() + 30
            while not seen and time.monotonic() < deadline:
                assert proc.poll() is None, f"server exited early, rc={proc.returncode}"
                body = _health(port)
                if body is None:
                    time.sleep(0.2)
                else:
                    seen.append(body)
            assert seen, "/health never answered"
            # Before the fix the flag was true within a second of startup.
            for _ in range(4):
                time.sleep(0.5)
                body = _health(port)
                assert body is not None
                seen.append(body)
        finally:
            proc.kill()
            proc.wait()

        assert all(b["status"] == "healthy" for b in seen)
        assert [b["fortianalyzer_connected"] for b in seen] == [False] * len(seen)
