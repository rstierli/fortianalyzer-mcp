"""Integration tests for log search operations.

These tests are READ-ONLY and safe to run against a production FortiAnalyzer.
They test log search, field retrieval, and statistics functionality.
"""

import asyncio

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_log_fields_traffic(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test getting available log fields for traffic logs."""
    result = await faz_client.get_logfields(test_adom, logtype="traffic")
    assert result is not None
    # Result should contain field definitions
    if "data" in result:
        assert isinstance(result["data"], list)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_log_fields_event(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test getting available log fields for event logs."""
    result = await faz_client.get_logfields(test_adom, logtype="event")
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_log_statistics(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test getting log statistics."""
    result = await faz_client.get_logstats(test_adom)
    assert result is not None
    # Result should contain device logging stats


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_logfiles_state(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test getting log file state."""
    result = await faz_client.get_logfiles_state(test_adom)
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_search_traffic_logs(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_hour: dict[str, str],
):
    """Test searching traffic logs from the last hour."""
    # Start log search - use empty device list to search all devices
    start_result = await faz_client.logsearch_start(
        adom=test_adom,
        logtype="traffic",
        device=[],  # Search all devices
        time_range=time_range_last_hour,
        limit=10,
    )
    assert start_result is not None
    assert "tid" in start_result

    tid = start_result["tid"]

    # Poll for results (max 30 seconds)
    for _ in range(30):
        fetch_result = await faz_client.logsearch_fetch(adom=test_adom, tid=tid, limit=10)
        assert fetch_result is not None

        percentage = fetch_result.get("percentage", 0)
        if percentage >= 100:
            break
        await asyncio.sleep(1)

    # Verify we can get the result structure
    assert "data" in fetch_result or "return-lines" in fetch_result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_search_event_logs(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_hour: dict[str, str],
):
    """Test searching event logs from the last hour."""
    # Start log search
    start_result = await faz_client.logsearch_start(
        adom=test_adom,
        logtype="event",
        device=[],  # Search all devices
        time_range=time_range_last_hour,
        limit=10,
    )
    assert start_result is not None
    assert "tid" in start_result

    tid = start_result["tid"]

    # Poll for results (max 30 seconds)
    for _ in range(30):
        fetch_result = await faz_client.logsearch_fetch(adom=test_adom, tid=tid, limit=10)
        assert fetch_result is not None

        percentage = fetch_result.get("percentage", 0)
        if percentage >= 100:
            break
        await asyncio.sleep(1)

    # Verify result structure
    assert "data" in fetch_result or "return-lines" in fetch_result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_search_logs_with_filter(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_day: dict[str, str],
):
    """Test searching logs with a filter expression."""
    # Start log search with filter
    start_result = await faz_client.logsearch_start(
        adom=test_adom,
        logtype="traffic",
        device=[],
        time_range=time_range_last_day,
        filter="action==accept",  # Filter for accepted traffic
        limit=10,
    )
    assert start_result is not None
    assert "tid" in start_result

    tid = start_result["tid"]

    # Poll for results (max 30 seconds)
    for _ in range(30):
        fetch_result = await faz_client.logsearch_fetch(adom=test_adom, tid=tid, limit=10)
        percentage = fetch_result.get("percentage", 0)
        if percentage >= 100:
            break
        await asyncio.sleep(1)

    assert fetch_result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_logsearch_count(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_hour: dict[str, str],
):
    """Test getting log search count/progress."""
    # Start log search
    start_result = await faz_client.logsearch_start(
        adom=test_adom,
        logtype="traffic",
        device=[],
        time_range=time_range_last_hour,
        limit=10,
    )
    assert "tid" in start_result
    tid = start_result["tid"]

    # Get count/progress
    count_result = await faz_client.logsearch_count(test_adom, tid)
    assert count_result is not None
    # Should contain progress information
    assert (
        "progress-percent" in count_result
        or "percentage" in count_result
        or "matched-logs" in count_result
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_logsearch_cancel(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_hour: dict[str, str],
):
    """Test cancelling a log search."""
    # Start log search
    start_result = await faz_client.logsearch_start(
        adom=test_adom,
        logtype="traffic",
        device=[],
        time_range=time_range_last_hour,
        limit=10,
    )
    assert "tid" in start_result
    tid = start_result["tid"]

    # Cancel the search
    cancel_result = await faz_client.logsearch_cancel(test_adom, tid)
    # Cancel should succeed or return status
    assert cancel_result is not None or cancel_result == {}
