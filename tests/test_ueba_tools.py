"""Tests for the UEBA reader tools (Wave-2 skills building blocks).

Two layers, matching the rest of the suite:
- tool-level: patch ``get_faz_client`` in ``ueba_tools`` with a fake client
  and assert the envelope, validation, and parameter forwarding;
- client-level: use the ``mock_client`` fixture and patch the request layer
  to assert the endpoint URL and JSON-RPC params.
"""

from typing import Any

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.tools import ueba_tools


class _FakeClient:
    """Records the last call and returns a canned payload."""

    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.calls: dict[str, dict[str, Any]] = {}

    async def get_endpoints(self, **kwargs: Any) -> Any:
        self.calls["get_endpoints"] = kwargs
        return self.payload

    async def get_endpoint_vulnerabilities(self, **kwargs: Any) -> Any:
        self.calls["get_endpoint_vulnerabilities"] = kwargs
        return self.payload

    async def get_endusers(self, **kwargs: Any) -> Any:
        self.calls["get_endusers"] = kwargs
        return self.payload


def _patch_client(monkeypatch: pytest.MonkeyPatch, payload: Any) -> _FakeClient:
    fake = _FakeClient(payload)
    monkeypatch.setattr(ueba_tools, "get_faz_client", lambda: fake)
    return fake


# --------------------------------------------------------------------- #
# get_endpoints                                                         #
# --------------------------------------------------------------------- #


class TestGetEndpoints:
    async def test_success_and_param_forwarding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch_client(monkeypatch, [{"epname": "host-1", "epip": "10.0.0.5"}])
        result = await ueba_tools.get_endpoints(adom="root", epids=[7], detail_level="basic")
        assert result["status"] == "success"
        assert result["data"][0]["epname"] == "host-1"
        sent = fake.calls["get_endpoints"]
        assert sent["adom"] == "root"
        assert sent["epids"] == [7]
        assert sent["detail_level"] == "basic"

    async def test_rejects_invalid_detail_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, [])
        result = await ueba_tools.get_endpoints(detail_level="everything")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_client_missing_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ueba_tools, "get_faz_client", lambda: None)
        result = await ueba_tools.get_endpoints()
        assert result["status"] == "error"


# --------------------------------------------------------------------- #
# get_endpoint_vulnerabilities                                          #
# --------------------------------------------------------------------- #


class TestGetEndpointVulnerabilities:
    async def test_success_and_param_forwarding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch_client(monkeypatch, [{"vulnid": "CVE-2024-0001"}])
        result = await ueba_tools.get_endpoint_vulnerabilities(epids=[1025], detectby="FortiClient")
        assert result["status"] == "success"
        assert result["data"][0]["vulnid"] == "CVE-2024-0001"
        sent = fake.calls["get_endpoint_vulnerabilities"]
        assert sent["epids"] == [1025]
        assert sent["detectby"] == "FortiClient"

    async def test_rejects_invalid_detectby(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, [])
        result = await ueba_tools.get_endpoint_vulnerabilities(detectby="FortiGuard")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_detectby_optional(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch_client(monkeypatch, [])
        result = await ueba_tools.get_endpoint_vulnerabilities()
        assert result["status"] == "success"
        assert fake.calls["get_endpoint_vulnerabilities"]["detectby"] is None


# --------------------------------------------------------------------- #
# get_endusers                                                          #
# --------------------------------------------------------------------- #


class TestGetEndusers:
    async def test_success_extended(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch_client(monkeypatch, [{"euname": "jdoe", "email": "jdoe@example.com"}])
        result = await ueba_tools.get_endusers(detail_level="extended")
        assert result["status"] == "success"
        assert result["data"][0]["email"] == "jdoe@example.com"
        assert fake.calls["get_endusers"]["detail_level"] == "extended"

    async def test_rejects_invalid_detail_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, [])
        result = await ueba_tools.get_endusers(
            detail_level="simple"
        )  # valid for endpoints, not endusers
        assert result["status"] == "error"
        assert "Validation error" in result["message"]


# --------------------------------------------------------------------- #
# client methods (endpoint URL + JSON-RPC params)                       #
# --------------------------------------------------------------------- #


class TestUebaClientMethods:
    async def test_get_endpoints_request_shape(self, mock_client: FortiAnalyzerClient) -> None:
        from unittest.mock import AsyncMock, patch

        with patch.object(
            mock_client, "_generic_request", AsyncMock(return_value=[{"epid": 1}])
        ) as req:
            await mock_client.get_endpoints(adom="root", epids=[1], detail_level="standard")
        assert req.await_args.args[0] == "get"
        assert req.await_args.args[1] == "/ueba/adom/root/endpoints"
        kwargs = req.await_args.kwargs
        assert kwargs["detail-level"] == "standard"
        assert kwargs["epids"] == [1]
        assert kwargs["apiver"] == 3

    async def test_get_endusers_request_shape(self, mock_client: FortiAnalyzerClient) -> None:
        from unittest.mock import AsyncMock, patch

        with patch.object(mock_client, "_generic_request", AsyncMock(return_value=[])) as req:
            await mock_client.get_endusers(adom="root", detail_level="extended")
        assert req.await_args.args[1] == "/ueba/adom/root/endusers"
        assert req.await_args.kwargs["detail-level"] == "extended"

    async def test_get_endpoint_vulnerabilities_request_shape(
        self, mock_client: FortiAnalyzerClient
    ) -> None:
        from unittest.mock import AsyncMock, patch

        with patch.object(mock_client, "_generic_request", AsyncMock(return_value=[])) as req:
            await mock_client.get_endpoint_vulnerabilities(adom="root", detectby="FortiGate")
        assert req.await_args.args[1] == "/ueba/adom/root/endpoints/vuln"
        assert req.await_args.kwargs["detectby"] == "FortiGate"
