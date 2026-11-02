"""The HTTP transport's stop is bounded (availability regression).

uvicorn waits for open connections before the lifespan shutdown, with no limit
unless one is configured, and MCP clients keep a standing event stream open. So
a systemd stop waited out TimeoutStopSec and ended in SIGKILL.
"""

from typing import Any

import pytest

import fortianalyzer_mcp.server as server


class TestGracefulShutdownBound:
    def test_run_http_bounds_the_graceful_shutdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An open client stream must not hold the stop until the supervisor's SIGKILL.

        At shutdown uvicorn waits for every open connection before it runs the
        lifespan shutdown, with no limit unless one is configured ("Waiting for
        connections to close."). MCP clients hold a standing event stream per
        session, so under systemd every stop sat out TimeoutStopSec (90 s) and
        ended in SIGKILL. 5 s gives an in-flight response time to finish and
        still leaves room inside Docker's 10 s stop window.
        """
        import uvicorn

        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "secret-token")
        captured: dict[str, Any] = {}
        monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(kwargs=kw))
        server.run_http()

        assert captured["kwargs"]["timeout_graceful_shutdown"] == 5
