"""Integration tests for FortiView analytics operations.

These tests are READ-ONLY and safe to run against a production FortiAnalyzer.
They test various FortiView analytics queries.
"""

import asyncio

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


async def _run_fortiview_query(
    faz_client: FortiAnalyzerClient,
    adom: str,
    view_name: str,
    time_range: dict[str, str],
    limit: int = 10,
) -> dict:
    """Helper to run a FortiView query and wait for results."""
    # Start FortiView query
    start_result = await faz_client.fortiview_run(
        adom=adom,
        view_name=view_name,
        device=[],  # All devices
        time_range=time_range,
        limit=limit,
    )
    assert start_result is not None
    assert "tid" in start_result

    tid = start_result["tid"]

    # Poll for results (max 60 seconds)
    for _ in range(60):
        fetch_result = await faz_client.fortiview_fetch(
            adom=adom, view_name=view_name, tid=tid
        )
        assert fetch_result is not None

        # Check if complete
        percentage = fetch_result.get("percentage", 0)
        if percentage >= 100:
            return fetch_result
        await asyncio.sleep(1)

    return fetch_result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fortiview_top_sources(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_day: dict[str, str],
):
    """Test FortiView top-sources query."""
    result = await _run_fortiview_query(
        faz_client, test_adom, "top-sources", time_range_last_day
    )
    assert result is not None
    # Result should contain data array (may be empty if no traffic)
    assert "data" in result or "percentage" in result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fortiview_top_destinations(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_day: dict[str, str],
):
    """Test FortiView top-destinations query."""
    result = await _run_fortiview_query(
        faz_client, test_adom, "top-destinations", time_range_last_day
    )
    assert result is not None
    assert "data" in result or "percentage" in result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fortiview_top_applications(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_day: dict[str, str],
):
    """Test FortiView top-applications query."""
    result = await _run_fortiview_query(
        faz_client, test_adom, "top-applications", time_range_last_day
    )
    assert result is not None
    assert "data" in result or "percentage" in result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fortiview_top_threats(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test FortiView top-threats query.

    Uses weekly time range as threat data may be sparse.
    """
    result = await _run_fortiview_query(
        faz_client, test_adom, "top-threats", time_range_last_week
    )
    assert result is not None
    # May be empty if no threat data
    assert "data" in result or "percentage" in result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fortiview_top_websites(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_day: dict[str, str],
):
    """Test FortiView top-websites query."""
    result = await _run_fortiview_query(
        faz_client, test_adom, "top-websites", time_range_last_day
    )
    assert result is not None
    assert "data" in result or "percentage" in result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fortiview_top_cloud_applications(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_day: dict[str, str],
):
    """Test FortiView top-cloud-applications query."""
    try:
        result = await _run_fortiview_query(
            faz_client, test_adom, "top-cloud-applications", time_range_last_day
        )
        assert result is not None
    except Exception as e:
        # May not be available on all FAZ versions or if cloud app logging not enabled
        pytest.skip(f"top-cloud-applications not available: {e}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fortiview_with_filter(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_day: dict[str, str],
):
    """Test FortiView query with filter expression."""
    # Start FortiView query with filter
    start_result = await faz_client.fortiview_run(
        adom=test_adom,
        view_name="top-sources",
        device=[],
        time_range=time_range_last_day,
        filter="action==accept",
        limit=10,
    )
    assert start_result is not None
    assert "tid" in start_result

    tid = start_result["tid"]

    # Poll for results (max 30 seconds)
    for _ in range(30):
        fetch_result = await faz_client.fortiview_fetch(
            adom=test_adom, view_name="top-sources", tid=tid
        )
        percentage = fetch_result.get("percentage", 0)
        if percentage >= 100:
            break
        await asyncio.sleep(1)

    assert fetch_result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fortiview_with_sort(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_day: dict[str, str],
):
    """Test FortiView query with custom sort order."""
    # Start FortiView query with sort
    start_result = await faz_client.fortiview_run(
        adom=test_adom,
        view_name="top-sources",
        device=[],
        time_range=time_range_last_day,
        limit=10,
        sort_by=[{"field": "bandwidth", "order": "desc"}],
    )
    assert start_result is not None
    assert "tid" in start_result
