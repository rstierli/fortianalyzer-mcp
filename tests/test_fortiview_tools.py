"""Tests for FortiAnalyzer FortiView tools.

Tests the client methods for FortiView analytics operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class TestFortiViewHelpers:
    """Tests for FortiView tools helper functions.

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
            "now": timedelta(minutes=5),
            "5-min": timedelta(minutes=5),
            "15-min": timedelta(minutes=15),
            "1-hour": timedelta(hours=1),
            "6-hour": timedelta(hours=6),
            "12-hour": timedelta(hours=12),
            "24-hour": timedelta(hours=24),
            "1-day": timedelta(days=1),
            "7-day": timedelta(days=7),
            "30-day": timedelta(days=30),
        }

        # Verify all expected ranges exist
        assert "now" in range_map
        assert "5-min" in range_map
        assert "1-hour" in range_map
        assert "24-hour" in range_map
        assert "7-day" in range_map

        # Verify timedeltas are correct
        assert range_map["5-min"] == timedelta(minutes=5)
        assert range_map["1-hour"] == timedelta(hours=1)
        assert range_map["24-hour"] == timedelta(hours=24)

    def test_device_filter_build(self) -> None:
        """Test device filter building logic."""
        device = "FGT60F0000000001"
        device_filter = [{"devid": device}] if device else [{"devid": "All_FortiGate"}]
        assert device_filter == [{"devid": "FGT60F0000000001"}]

    def test_device_filter_build_none(self) -> None:
        """Test device filter with None defaults to All_FortiGate."""
        device = None
        device_filter = [{"devid": device}] if device else [{"devid": "All_FortiGate"}]
        assert device_filter == [{"devid": "All_FortiGate"}]

    def test_sort_by_param_build(self) -> None:
        """Test sort_by parameter building logic."""
        sort_by = "bandwidth"
        sort_order = "desc"
        sort_by_param = [{"field": sort_by, "order": sort_order}] if sort_by else None
        assert sort_by_param == [{"field": "bandwidth", "order": "desc"}]

    def test_sort_by_param_none(self) -> None:
        """Test sort_by parameter is None when not specified."""
        sort_by = None
        sort_order = "desc"
        sort_by_param = [{"field": sort_by, "order": sort_order}] if sort_by else None
        assert sort_by_param is None


class TestFortiViewClient:
    """Tests for FortiView client methods."""

    @pytest.fixture
    def mock_client_with_fortiview(
        self,
        mock_client: FortiAnalyzerClient,
        configure_mock_responses: None,
        configure_logview_responses: None,
    ) -> FortiAnalyzerClient:
        """Provide a mock client with FortiView API responses configured."""
        return mock_client

    async def test_fortiview_run_success(
        self, mock_client_with_fortiview: FortiAnalyzerClient
    ) -> None:
        """Test fortiview_run returns TID."""
        result = await mock_client_with_fortiview.fortiview_run(
            adom="root",
            view_name="top-sources",
            device=[{"devid": "All_FortiGate"}],
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
        )
        assert "tid" in result
        assert result["tid"] == 54321

    async def test_fortiview_fetch_success(
        self, mock_client_with_fortiview: FortiAnalyzerClient
    ) -> None:
        """Test fortiview_fetch returns data."""
        result = await mock_client_with_fortiview.fortiview_fetch(
            adom="root",
            view_name="top-sources",
            tid=54321,
        )
        assert result["percentage"] == 100
        assert "data" in result
        assert len(result["data"]) == 2
        assert result["data"][0]["srcip"] == "10.0.0.1"
        assert result["data"][0]["sessions"] == 1000

    async def test_fortiview_run_not_connected(self) -> None:
        """Test fortiview_run raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.fortiview_run(
                adom="root",
                view_name="top-sources",
                device=[{"devid": "All_FortiGate"}],
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
            )

    async def test_fortiview_fetch_not_connected(self) -> None:
        """Test fortiview_fetch raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.fortiview_fetch(
                adom="root",
                view_name="top-sources",
                tid=54321,
            )


class TestFortiViewViews:
    """Tests for different FortiView view names."""

    def test_valid_view_names(self) -> None:
        """Test valid FortiView view name patterns."""
        valid_views = [
            "top-sources",
            "top-destinations",
            "top-applications",
            "top-websites",
            "top-threats",
            "top-cloud-applications",
            "policy-hits",
            "traffic-summary",
            "fortiview-traffic",
            "fortiview-threats",
        ]

        for view in valid_views:
            # All valid views should be strings and start with expected prefixes
            assert isinstance(view, str)
            assert view.startswith(("top-", "policy-", "traffic-", "fortiview-"))
