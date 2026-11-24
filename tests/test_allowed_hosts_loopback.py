"""Loopback stays allowed when MCP_ALLOWED_HOSTS is set (#187 D20).

The SDK adds its loopback entries only when it is handed no settings at all.
Passing our own list replaced them, so a request to 127.0.0.1 or localhost got
421 as soon as one proxy hostname was configured, and any request with an
``Origin`` header got 403 with no setting to allow one.
"""

import logging
from typing import Any

import pytest
from mcp.server.transport_security import TransportSecurityMiddleware
from starlette.requests import Request

from fortianalyzer_mcp.server import transport_security_for

HOSTS = ["example.com"]


async def _status(
    host: str,
    origin: str | None = None,
    *,
    allowed_origins: list[str] | None = None,
) -> int | None:
    """The refusal status for one request, or None when it is let through."""
    headers = [(b"host", host.encode())]
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": headers})
    settings = transport_security_for(HOSTS, allowed_origins or [])
    refusal = await TransportSecurityMiddleware(settings).validate_request(request)
    return None if refusal is None else refusal.status_code


class TestHostsWithAllowedHostsSet:
    @pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "[::1]:8000"])
    async def test_a_loopback_host_is_let_through(self, host: str) -> None:
        assert await _status(host) is None

    async def test_the_configured_host_is_let_through(self) -> None:
        assert await _status("example.com") is None

    async def test_another_host_is_still_refused(self) -> None:
        assert await _status("evil.example") == 421


class TestOriginsWithAllowedHostsSet:
    @pytest.mark.parametrize(
        "origin", ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"]
    )
    async def test_a_loopback_origin_is_let_through(self, origin: str) -> None:
        assert await _status("127.0.0.1:8000", origin) is None

    async def test_any_other_origin_is_refused(self) -> None:
        assert await _status("example.com", "https://app.example.com") == 403

    async def test_an_origin_listed_in_the_setting_is_let_through(self) -> None:
        listed = ["https://app.example.com"]

        assert (
            await _status("example.com", "https://app.example.com", allowed_origins=listed) is None
        )

    async def test_an_origin_that_is_not_listed_is_refused_all_the_same(self) -> None:
        listed = ["https://app.example.com"]

        assert await _status("example.com", "https://evil.example", allowed_origins=listed) == 403

    async def test_a_loopback_origin_stays_allowed_beside_a_listed_one(self) -> None:
        listed = ["https://app.example.com"]

        assert (
            await _status("127.0.0.1:8000", "http://localhost:8000", allowed_origins=listed) is None
        )


class TestWithoutAllowedHosts:
    """The checks are always on. ``run_http`` gives the SDK no ``host``, the
    SDK's default for it is 127.0.0.1, and so the SDK applied its loopback-only
    check for a server handed no settings, whatever address it was bound to.
    The settings are now always passed, with the same result when nothing is
    configured (``tests/test_transport_security_app.py`` sends the requests)."""

    def test_no_setting_is_the_loopback_only_check(self) -> None:
        security = transport_security_for([], [])

        assert security.enable_dns_rebinding_protection is True
        assert security.allowed_hosts == ["127.0.0.1:*", "localhost:*", "[::1]:*"]
        assert security.allowed_origins == [
            "http://127.0.0.1:*",
            "http://localhost:*",
            "http://[::1]:*",
        ]

    def test_origins_alone_are_applied(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="fortianalyzer_mcp.server"):
            security = transport_security_for([], ["https://app.example.com"])

        assert security.allowed_origins[-1] == "https://app.example.com"
        assert security.allowed_hosts == ["127.0.0.1:*", "localhost:*", "[::1]:*"]
        assert caplog.records == []

    def test_nothing_is_decided_or_logged_when_the_module_is_imported(self) -> None:
        """The settings are built where the HTTP app is, so a stdio server
        neither builds nor reports them."""
        import fortianalyzer_mcp.server as server

        assert not hasattr(server, "_transport_security")


class TestAllowedOriginsParsing:
    """MCP_ALLOWED_ORIGINS is read like MCP_ALLOWED_HOSTS."""

    def _settings(self, monkeypatch: pytest.MonkeyPatch, value: str | None) -> Any:
        from fortianalyzer_mcp.utils.config import Settings

        monkeypatch.setenv("FORTIANALYZER_HOST", "faz.example.com")
        if value is None:
            monkeypatch.delenv("MCP_ALLOWED_ORIGINS", raising=False)
        else:
            monkeypatch.setenv("MCP_ALLOWED_ORIGINS", value)
        return Settings(_env_file=None)

    def test_empty_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert self._settings(monkeypatch, None).MCP_ALLOWED_ORIGINS == []

    def test_comma_separated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = self._settings(monkeypatch, "https://app.example.com, https://b.example.com")

        assert settings.MCP_ALLOWED_ORIGINS == ["https://app.example.com", "https://b.example.com"]

    def test_json_array(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = self._settings(monkeypatch, '["https://app.example.com"]')

        assert settings.MCP_ALLOWED_ORIGINS == ["https://app.example.com"]
