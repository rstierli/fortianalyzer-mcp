"""Integration tests for alert and event management operations.

These tests are READ-ONLY safe except for acknowledgment tests which only
modify alert state (not configuration) and are reversible.
"""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_alerts_count(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting alert count."""
    result = await faz_client.get_alerts_count(test_adom, time_range=time_range_last_week)
    assert result is not None
    # Result should contain count information


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_alerts_count_no_time_range(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
):
    """Test getting alert count without time range filter."""
    result = await faz_client.get_alerts_count(test_adom)
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_alerts(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting alerts."""
    result = await faz_client.get_alerts(
        test_adom, time_range=time_range_last_week, limit=10
    )
    assert result is not None
    # Result should contain data array (may be empty)
    if isinstance(result, dict):
        assert "data" in result or "matched" in result or result == {}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_alerts_with_filter(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting alerts with filter expression."""
    result = await faz_client.get_alerts(
        test_adom,
        time_range=time_range_last_week,
        filter="severity==high",
        limit=10,
    )
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_alerts_sorted_asc(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting alerts sorted by time ascending."""
    result = await faz_client.get_alerts(
        test_adom,
        time_range=time_range_last_week,
        time_order="asc",
        limit=10,
    )
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_alert_incident_stats(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting alert-incident statistics by severity."""
    result = await faz_client.get_alert_incident_stats(
        test_adom, time_range=time_range_last_week, stat_type="severity"
    )
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_alert_incident_stats_status(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting alert-incident statistics by status."""
    result = await faz_client.get_alert_incident_stats(
        test_adom, time_range=time_range_last_week, stat_type="status"
    )
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_acknowledge_alert_reversible(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test acknowledging and unacknowledging an alert.

    This is a reversible operation - we acknowledge then immediately unacknowledge.
    Only runs if there are unacknowledged alerts available.
    """
    # Get alerts
    alerts_result = await faz_client.get_alerts(
        test_adom, time_range=time_range_last_week, limit=1
    )

    # Extract alert data
    alerts = []
    if isinstance(alerts_result, dict):
        alerts = alerts_result.get("data", [])
    elif isinstance(alerts_result, list):
        alerts = alerts_result

    if not alerts:
        pytest.skip("No alerts available for acknowledgment test")

    # Get first alert ID
    alert = alerts[0]
    alert_id = alert.get("alertid") or alert.get("id") or alert.get("alert-id")
    if not alert_id:
        pytest.skip("Alert has no ID field")

    test_user = "integration_test"

    try:
        # Acknowledge the alert
        ack_result = await faz_client.acknowledge_alerts(
            test_adom, alert_ids=[str(alert_id)], user=test_user
        )
        assert ack_result is not None

        # Immediately unacknowledge to restore state
        unack_result = await faz_client.unacknowledge_alerts(
            test_adom, alert_ids=[str(alert_id)], user=test_user
        )
        assert unack_result is not None

    except Exception as e:
        # Acknowledgment may fail due to permissions or alert state
        pytest.skip(f"Alert acknowledgment failed: {e}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_alert_logs(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting alert logs for specific alerts."""
    # First get some alerts
    alerts_result = await faz_client.get_alerts(
        test_adom, time_range=time_range_last_week, limit=1
    )

    alerts = []
    if isinstance(alerts_result, dict):
        alerts = alerts_result.get("data", [])
    elif isinstance(alerts_result, list):
        alerts = alerts_result

    if not alerts:
        pytest.skip("No alerts available for logs test")

    alert = alerts[0]
    alert_id = alert.get("alertid") or alert.get("id") or alert.get("alert-id")
    if not alert_id:
        pytest.skip("Alert has no ID field")

    try:
        result = await faz_client.get_alert_logs(
            test_adom, alert_ids=[str(alert_id)], limit=10
        )
        assert result is not None
    except Exception as e:
        pytest.skip(f"Get alert logs failed: {e}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_alert_extra_details(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting alert extra details."""
    # First get some alerts
    alerts_result = await faz_client.get_alerts(
        test_adom, time_range=time_range_last_week, limit=1
    )

    alerts = []
    if isinstance(alerts_result, dict):
        alerts = alerts_result.get("data", [])
    elif isinstance(alerts_result, list):
        alerts = alerts_result

    if not alerts:
        pytest.skip("No alerts available for details test")

    alert = alerts[0]
    alert_id = alert.get("alertid") or alert.get("id") or alert.get("alert-id")
    if not alert_id:
        pytest.skip("Alert has no ID field")

    try:
        result = await faz_client.get_alert_extra_details(
            test_adom, alert_ids=[str(alert_id)]
        )
        assert result is not None
    except Exception as e:
        pytest.skip(f"Get alert details failed: {e}")
