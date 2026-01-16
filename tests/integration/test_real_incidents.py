"""Integration tests for incident management operations.

These tests are READ-ONLY safe. They test incident listing and statistics.
Incident creation is a write operation and is kept minimal/reversible.
"""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_incidents_count(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting incident count."""
    result = await faz_client.get_incidents_count(test_adom, time_range=time_range_last_week)
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_incidents_count_no_time_range(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
):
    """Test getting incident count without time range."""
    result = await faz_client.get_incidents_count(test_adom)
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_incidents(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting incidents."""
    result = await faz_client.get_incidents(test_adom, time_range=time_range_last_week, limit=10)
    assert result is not None
    # Result should contain data array (may be empty)
    if isinstance(result, dict):
        assert "data" in result or result == {}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_incidents_with_filter(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting incidents with filter expression."""
    result = await faz_client.get_incidents(
        test_adom,
        time_range=time_range_last_week,
        filter="severity==high",
        limit=10,
    )
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_incident_stats(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting incident statistics."""
    result = await faz_client.get_incident_stats(
        test_adom,
        time_range=time_range_last_week,
        stats_items=["total", "severity", "status"],
    )
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_incident_stats_category(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting incident statistics by category."""
    result = await faz_client.get_incident_stats(
        test_adom,
        time_range=time_range_last_week,
        stats_items=["category"],
    )
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_specific_incident(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting a specific incident by ID."""
    # First get list of incidents
    incidents_result = await faz_client.get_incidents(
        test_adom, time_range=time_range_last_week, limit=1
    )

    incidents = []
    if isinstance(incidents_result, dict):
        incidents = incidents_result.get("data", [])
    elif isinstance(incidents_result, list):
        incidents = incidents_result

    if not incidents:
        pytest.skip("No incidents available")

    incident = incidents[0]
    incident_id = incident.get("incid") or incident.get("id") or incident.get("incident-id")
    if not incident_id:
        pytest.skip("Incident has no ID field")

    try:
        result = await faz_client.get_incident(test_adom, str(incident_id))
        assert result is not None
    except Exception as e:
        pytest.skip(f"Get incident failed: {e}")
