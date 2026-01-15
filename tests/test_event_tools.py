"""Tests for FortiAnalyzer event tools.

Tests the client methods for alert and event management operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class TestEventToolsHelpers:
    """Tests for event tools helper functions.

    These test the helper function logic by reimplementing the tests
    without importing from tools module (which triggers server init).
    """

    def test_parse_time_range_custom_format(self) -> None:
        """Test parsing custom time range with pipe separator."""
        time_range = "2024-01-01 00:00:00|2024-01-02 00:00:00"
        parts = time_range.split("|")
        result = {"start": parts[0].strip(), "end": parts[1].strip()}
        assert result["start"] == "2024-01-01 00:00:00"
        assert result["end"] == "2024-01-02 00:00:00"

    def test_time_range_predefined_mapping(self) -> None:
        """Test predefined time range mapping logic."""
        from datetime import timedelta

        range_map = {
            "1-hour": timedelta(hours=1),
            "6-hour": timedelta(hours=6),
            "12-hour": timedelta(hours=12),
            "24-hour": timedelta(hours=24),
            "1-day": timedelta(days=1),
            "7-day": timedelta(days=7),
            "30-day": timedelta(days=30),
        }

        # Verify all expected ranges exist
        assert "1-hour" in range_map
        assert "24-hour" in range_map
        assert "7-day" in range_map
        assert "30-day" in range_map

        # Verify timedeltas are correct
        assert range_map["1-hour"] == timedelta(hours=1)
        assert range_map["24-hour"] == timedelta(hours=24)
        assert range_map["7-day"] == timedelta(days=7)

    def test_time_range_invalid_defaults(self) -> None:
        """Test invalid time range defaults to 24-hour."""
        from datetime import timedelta

        range_map = {
            "1-hour": timedelta(hours=1),
            "24-hour": timedelta(hours=24),
        }
        time_range = "invalid"
        # Default to 24-hour if not found
        delta = range_map.get(time_range, timedelta(hours=24))
        assert delta == timedelta(hours=24)


class TestAlertClient:
    """Tests for alert-related client methods."""

    @pytest.fixture
    def mock_client_with_events(
        self,
        mock_client: FortiAnalyzerClient,
        configure_mock_responses: None,
        configure_logview_responses: None,
    ) -> FortiAnalyzerClient:
        """Provide a mock client with event API responses configured."""
        return mock_client

    async def test_get_alerts_success(
        self, mock_client_with_events: FortiAnalyzerClient
    ) -> None:
        """Test get_alerts returns alert data."""
        result = await mock_client_with_events.get_alerts(
            adom="root",
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
        )
        assert "data" in result
        alerts = result["data"]
        assert len(alerts) == 2
        assert alerts[0]["alertid"] == "alert-001"
        assert alerts[0]["severity"] == "high"

    async def test_get_alerts_count_success(
        self, mock_client_with_events: FortiAnalyzerClient
    ) -> None:
        """Test get_alerts_count returns count data."""
        result = await mock_client_with_events.get_alerts_count(
            adom="root",
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
        )
        assert result["total"] == 150
        assert result["unacknowledged"] == 50

    async def test_get_alerts_not_connected(self) -> None:
        """Test get_alerts raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_alerts(
                adom="root",
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
            )

    async def test_get_alerts_count_not_connected(self) -> None:
        """Test get_alerts_count raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_alerts_count(
                adom="root",
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
            )

    async def test_acknowledge_alerts_not_connected(self) -> None:
        """Test acknowledge_alerts raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.acknowledge_alerts(
                adom="root",
                alert_ids=["alert-001"],
                user="admin",
            )

    async def test_unacknowledge_alerts_not_connected(self) -> None:
        """Test unacknowledge_alerts raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.unacknowledge_alerts(
                adom="root",
                alert_ids=["alert-001"],
                user="admin",
            )

    async def test_get_alert_logs_not_connected(self) -> None:
        """Test get_alert_logs raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_alert_logs(
                adom="root",
                alert_ids=["alert-001"],
            )

    async def test_add_alert_comment_not_connected(self) -> None:
        """Test add_alert_comment raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.add_alert_comment(
                adom="root",
                alert_id="alert-001",
                comment="Test comment",
                user="admin",
            )
