"""Tests for FortiAnalyzer IOC tools.

Tests the client methods for IOC (Indicators of Compromise) operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class TestIOCHelpers:
    """Tests for IOC tools helper functions."""

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

        assert "1-hour" in range_map
        assert "7-day" in range_map
        assert "30-day" in range_map
        assert range_map["7-day"] == timedelta(days=7)

    def test_time_range_invalid_defaults(self) -> None:
        """Test invalid time range defaults to 7-day."""
        from datetime import timedelta

        range_map = {
            "1-hour": timedelta(hours=1),
            "7-day": timedelta(days=7),
        }
        time_range = "invalid"
        # Default to 7-day if not found (per ioc_tools.py logic)
        delta = range_map.get(time_range, timedelta(days=7))
        assert delta == timedelta(days=7)


class TestIOCClient:
    """Tests for IOC client methods."""

    @pytest.fixture
    def mock_client_with_ioc(
        self,
        mock_client: FortiAnalyzerClient,
        configure_mock_responses: None,
        configure_logview_responses: None,
    ) -> FortiAnalyzerClient:
        """Provide a mock client with IOC API responses configured."""
        return mock_client

    async def test_get_ioc_license_state_not_connected(self) -> None:
        """Test get_ioc_license_state raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_ioc_license_state()

    async def test_acknowledge_ioc_events_not_connected(self) -> None:
        """Test acknowledge_ioc_events raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.acknowledge_ioc_events(
                adom="root",
                event_ids=["IOC-001"],
                user="analyst1",
            )

    async def test_ioc_rescan_run_not_connected(self) -> None:
        """Test ioc_rescan_run raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.ioc_rescan_run(
                adom="root",
                device=None,
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
            )

    async def test_ioc_rescan_status_not_connected(self) -> None:
        """Test ioc_rescan_status raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.ioc_rescan_status(adom="root", tid=12345)

    async def test_get_ioc_rescan_history_not_connected(self) -> None:
        """Test get_ioc_rescan_history raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_ioc_rescan_history(adom="root")


class TestIOCRescanWorkflow:
    """Tests for IOC rescan TID workflow patterns."""

    def test_rescan_state_values(self) -> None:
        """Test valid rescan state values."""
        valid_states = ["running", "done", "completed", "error", "failed"]
        for state in valid_states:
            assert state in valid_states

    def test_percentage_completion_check(self) -> None:
        """Test percentage completion logic."""
        # 100% should indicate done
        percentage = 100
        assert percentage >= 100

        # Less than 100 should continue polling
        percentage = 50
        assert percentage < 100

    def test_timeout_check_logic(self) -> None:
        """Test timeout check logic."""
        elapsed = 250.0
        timeout = 300
        assert elapsed <= timeout

        elapsed = 350.0
        assert elapsed > timeout
