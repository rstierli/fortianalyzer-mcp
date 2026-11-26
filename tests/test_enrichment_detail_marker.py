"""A failed enrichment detail fetch is marked on its row (#187 item A6).

With detail_level="extended" each indicator row's enrichment-uuid is
followed to /indicator/enrichment/{uuid}. That fetch is best effort. When it
failed, the row came back without enrichment-detail and without any sign
that a fetch had been tried, so it read the same as a row with no detail.
The row now carries enrichment-detail-error, the class name of the error.
The error text stays in the log: it is appliance text, and the key is not
typed for masking.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

import fortianalyzer_mcp.tools.soar_tools as soar_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.wrapper import OutputMasker
from fortianalyzer_mcp.utils.errors import APIError

KEY = "2DE79D232DF5585D68CE47882AE256D6"
LIST_URL = "/soar/adom/root/indicator"
DETAIL = [{"source": "FortiGuard-CTS", "verdict": "Malicious"}]


def _rows() -> list[dict[str, Any]]:
    return [
        {"value": "192.0.2.10", "type": "IP", "enrichment-uuid": "e-fail"},
        {"value": "192.0.2.10", "type": "IP", "enrichment-uuid": "e-ok"},
    ]


async def _fake_get(url: str, **_: object) -> object:
    if url == LIST_URL:
        return _rows()
    if url.endswith("/e-fail"):
        raise APIError("FortiAnalyzer API error -6: invalid url 192.0.2.99")
    return DETAIL


async def _enrichment(
    monkeypatch: pytest.MonkeyPatch, mock_client: FortiAnalyzerClient
) -> dict[str, Any]:
    monkeypatch.setattr(soar_tools, "get_faz_client", lambda: mock_client)
    with patch.object(mock_client, "get", AsyncMock(side_effect=_fake_get)):
        return await soar_tools.get_indicator_enrichment(
            indicator_value="192.0.2.10",
            indicator_type="IP",
            adom="root",
            detail_level="extended",
        )


async def test_a_failed_fetch_is_marked_on_its_row(
    monkeypatch: pytest.MonkeyPatch, mock_client: FortiAnalyzerClient
) -> None:
    result = await _enrichment(monkeypatch, mock_client)

    assert result["status"] == "success"
    failed, fetched = result["data"]
    assert "enrichment-detail" not in failed
    assert failed["enrichment-detail-error"] == "APIError"
    assert fetched["enrichment-detail"] == DETAIL
    assert "enrichment-detail-error" not in fetched


async def test_the_marker_holds_no_error_text(
    monkeypatch: pytest.MonkeyPatch, mock_client: FortiAnalyzerClient
) -> None:
    result = await _enrichment(monkeypatch, mock_client)

    assert "192.0.2.99" not in repr(result)


async def test_the_marked_row_masks(
    monkeypatch: pytest.MonkeyPatch, mock_client: FortiAnalyzerClient
) -> None:
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    result = await _enrichment(monkeypatch, mock_client)

    masked = OutputMasker(FPEEngine(KEY)).mask_tool_result(result, "get_indicator_enrichment")

    assert masked["status"] == "success"
    assert "192.0.2.10" not in repr(masked)
    assert masked["data"][0]["enrichment-detail-error"] == "APIError"


async def test_standard_detail_fetches_nothing_and_marks_nothing(
    monkeypatch: pytest.MonkeyPatch, mock_client: FortiAnalyzerClient
) -> None:
    monkeypatch.setattr(soar_tools, "get_faz_client", lambda: mock_client)
    with patch.object(mock_client, "get", AsyncMock(side_effect=_fake_get)) as req:
        result = await soar_tools.get_indicator_enrichment(
            indicator_value="192.0.2.10", indicator_type="IP", adom="root"
        )

    assert req.await_count == 1
    assert all("enrichment-detail-error" not in row for row in result["data"])
