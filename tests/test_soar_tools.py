"""Tests for the SOAR indicator reader tools (Wave-2 threat_intel readers).

Request shapes are verified live against a real appliance; the reference
estate has no populated SOAR indicators, so these tests pin the request
contract (endpoint URL + params + validation) rather than payload content.
"""

from typing import Any

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.tools import soar_tools


class _FakeClient:
    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.calls: dict[str, dict[str, Any]] = {}

    async def get_linked_indicators(self, **kwargs: Any) -> Any:
        self.calls["get_linked_indicators"] = kwargs
        return self.payload

    async def get_indicator_enrichment(self, **kwargs: Any) -> Any:
        self.calls["get_indicator_enrichment"] = kwargs
        return self.payload


def _patch(monkeypatch: pytest.MonkeyPatch, payload: Any) -> _FakeClient:
    fake = _FakeClient(payload)
    monkeypatch.setattr(soar_tools, "get_faz_client", lambda: fake)
    return fake


# --------------------------------------------------------------------- #
# get_linked_indicators                                                 #
# --------------------------------------------------------------------- #


class TestGetLinkedIndicators:
    async def test_incident_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch(monkeypatch, [{"type": "IP", "value": "203.0.113.5"}])
        result = await soar_tools.get_linked_indicators(incident_id="IN00000019")
        assert result["status"] == "success"
        assert result["data"][0]["value"] == "203.0.113.5"
        assert fake.calls["get_linked_indicators"]["incident_id"] == "IN00000019"

    async def test_alert_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch(monkeypatch, [])
        result = await soar_tools.get_linked_indicators(alert_id="a-1")
        assert result["status"] == "success"
        assert fake.calls["get_linked_indicators"]["alert_id"] == "a-1"

    async def test_requires_exactly_one_subject(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, [])
        both = await soar_tools.get_linked_indicators(alert_id="a", incident_id="i")
        assert both["status"] == "error"
        neither = await soar_tools.get_linked_indicators()
        assert neither["status"] == "error"


# --------------------------------------------------------------------- #
# get_indicator_enrichment                                              #
# --------------------------------------------------------------------- #


class TestGetIndicatorEnrichment:
    async def test_success_and_forwarding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch(monkeypatch, {"reputation": "Malicious", "confidence": 90})
        result = await soar_tools.get_indicator_enrichment(
            indicator_value="8.8.8.8", indicator_type="IP", detail_level="extended"
        )
        assert result["status"] == "success"
        assert result["data"]["reputation"] == "Malicious"
        sent = fake.calls["get_indicator_enrichment"]
        assert sent["indicator_value"] == "8.8.8.8"
        assert sent["indicator_type"] == "IP"
        assert sent["detail_level"] == "extended"

    async def test_rejects_invalid_type(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, {})
        result = await soar_tools.get_indicator_enrichment(
            indicator_value="x", indicator_type="Hash"
        )
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_rejects_invalid_detail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, {})
        result = await soar_tools.get_indicator_enrichment(
            indicator_value="8.8.8.8", indicator_type="IP", detail_level="full"
        )
        assert result["status"] == "error"
        assert "Validation error" in result["message"]


# --------------------------------------------------------------------- #
# client methods (endpoint URL + params)                                #
# --------------------------------------------------------------------- #


class TestSoarClientMethods:
    async def test_linked_indicators_incident_url(self, mock_client: FortiAnalyzerClient) -> None:
        from unittest.mock import AsyncMock, patch

        with patch.object(mock_client, "get", AsyncMock(return_value=[])) as req:
            await mock_client.get_linked_indicators(adom="root", incident_id="IN00000019")
        assert req.await_args.args[0] == "/soar/adom/root/incident/indicator"
        assert req.await_args.kwargs["incident-id"] == "IN00000019"

    async def test_linked_indicators_alert_url(self, mock_client: FortiAnalyzerClient) -> None:
        from unittest.mock import AsyncMock, patch

        with patch.object(mock_client, "get", AsyncMock(return_value=[])) as req:
            await mock_client.get_linked_indicators(adom="root", alert_id="a-1")
        assert req.await_args.args[0] == "/soar/adom/root/alert/indicator"
        assert req.await_args.kwargs["alert-id"] == "a-1"

    async def test_linked_indicators_requires_subject(
        self, mock_client: FortiAnalyzerClient
    ) -> None:
        with pytest.raises(ValueError, match="exactly one"):
            await mock_client.get_linked_indicators(adom="root")

    async def test_enrichment_resolves_via_list_filter(
        self, mock_client: FortiAnalyzerClient
    ) -> None:
        # Reputation lives on the indicator list endpoint (the enrichment/{uuid}
        # path only works with a real uuid); resolve by a value+type filter and
        # always send a time-range (SOAR defaults to 7 days otherwise).
        from unittest.mock import AsyncMock, patch

        with patch.object(mock_client, "get", AsyncMock(return_value=[])) as req:
            await mock_client.get_indicator_enrichment(
                adom="root", indicator_value="8.8.8.8", indicator_type="IP"
            )
        assert req.await_args.args[0] == "/soar/adom/root/indicator"
        kwargs = req.await_args.kwargs
        assert kwargs["filter"] == "value=='8.8.8.8' and type=='IP'"
        assert kwargs["time-range"] == mock_client._WIDE_TIME_RANGE

    async def test_enrichment_rejects_quote_in_value(
        self, mock_client: FortiAnalyzerClient
    ) -> None:
        # A single quote would break out of the value=='...' filter clause.
        with pytest.raises(ValueError, match="single quote"):
            await mock_client.get_indicator_enrichment(
                adom="root", indicator_value="x' or '1'=='1", indicator_type="URL"
            )

    async def test_enrichment_extended_follows_enrichment_uuid(
        self, mock_client: FortiAnalyzerClient
    ) -> None:
        # extended attaches the raw detail by following the row's real
        # enrichment-uuid to the enrichment/{uuid} endpoint.
        from unittest.mock import AsyncMock, patch

        async def fake_get(url: str, **_: object) -> object:
            if url == "/soar/adom/root/indicator":
                return [
                    {"value": "8.8.8.8", "enrichment-uuid": "e-9", "enrichment-reputation": "Good"}
                ]
            return [{"enrichment-detail": [{"source": "vt"}]}]

        with patch.object(mock_client, "get", AsyncMock(side_effect=fake_get)) as req:
            rows = await mock_client.get_indicator_enrichment(
                adom="root", indicator_value="8.8.8.8", indicator_type="IP", detail_level="extended"
            )
        assert rows[0]["enrichment-detail"] == [{"enrichment-detail": [{"source": "vt"}]}]
        assert req.await_args_list[1].args[0] == "/soar/adom/root/indicator/enrichment/e-9"

    async def test_linked_indicators_send_time_range(
        self, mock_client: FortiAnalyzerClient
    ) -> None:
        from unittest.mock import AsyncMock, patch

        with patch.object(mock_client, "get", AsyncMock(return_value=[])) as req:
            await mock_client.get_linked_indicators(adom="root", incident_id="IN00000019")
        assert req.await_args.kwargs["time-range"] == mock_client._WIDE_TIME_RANGE

    async def test_enrichment_uses_supplied_uuid(self, mock_client: FortiAnalyzerClient) -> None:
        from unittest.mock import AsyncMock, patch

        with patch.object(mock_client, "get", AsyncMock(return_value=[])) as req:
            await mock_client.get_indicator_enrichment(
                adom="root",
                indicator_value="8.8.8.8",
                indicator_type="IP",
                enrichment_uuid="abcd-1234",
            )
        assert req.await_args.args[0].endswith("/enrichment/abcd-1234")
