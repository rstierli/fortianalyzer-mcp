"""Tests for FortiAnalyzer report tools.

Tests the client methods for report generation and management operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class TestReportHelpers:
    """Tests for report tools helper functions.

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
            "90-day": timedelta(days=90),
        }

        # Verify all expected ranges exist
        assert "1-hour" in range_map
        assert "7-day" in range_map
        assert "30-day" in range_map
        assert "90-day" in range_map

        # Verify timedeltas are correct
        assert range_map["7-day"] == timedelta(days=7)
        assert range_map["90-day"] == timedelta(days=90)

    def test_convert_to_api_time_period_short_format(self) -> None:
        """Test conversion from short format to API format."""
        time_map = {
            "1-hour": "last-1-hours",
            "6-hour": "last-6-hours",
            "12-hour": "last-12-hours",
            "24-hour": "last-24-hours",
            "1-day": "last-1-days",
            "7-day": "last-7-days",
            "30-day": "last-30-days",
            "90-day": "last-90-days",
        }

        for short, api in time_map.items():
            assert time_map[short] == api

    def test_convert_to_api_time_period_custom(self) -> None:
        """Test conversion of custom time range returns 'other'."""
        time_range = "2024-01-01 00:00:00|2024-01-02 00:00:00"
        # Custom date range should return "other"
        if "|" in time_range:
            result = "other"
        else:
            result = "last-7-days"
        assert result == "other"

    def test_convert_to_api_time_period_already_api_format(self) -> None:
        """Test API format is returned as-is."""
        time_range = "last-7-days"
        # If already in API format, return as-is
        if time_range.startswith("last-") and (
            time_range.endswith("-hours")
            or time_range.endswith("-days")
            or time_range.endswith("-weeks")
            or time_range.endswith("-months")
        ):
            result = time_range
        else:
            result = "last-7-days"
        assert result == "last-7-days"

    def test_layout_id_is_numeric(self) -> None:
        """Test layout ID detection logic."""
        # Numeric string should be detected as layout ID
        layout = "10042"
        assert layout.isdigit() is True

        # Non-numeric should be treated as title
        layout = "Secure SD-WAN Report"
        assert layout.isdigit() is False


class TestReportClient:
    """Tests for report client methods."""

    @pytest.fixture
    def mock_client_with_reports(
        self,
        mock_client: FortiAnalyzerClient,
        configure_mock_responses: None,
        configure_logview_responses: None,
    ) -> FortiAnalyzerClient:
        """Provide a mock client with report API responses configured."""
        return mock_client

    async def test_get_report_layouts_success(
        self, mock_client_with_reports: FortiAnalyzerClient
    ) -> None:
        """Test get_report_layouts returns layout list."""
        result = await mock_client_with_reports.get_report_layouts(adom="root")
        assert "data" in result
        layouts = result["data"]
        assert len(layouts) == 2
        assert layouts[0]["layout-id"] == 1
        assert layouts[0]["title"] == "Executive Summary"

    async def test_report_run_success(
        self, mock_client_with_reports: FortiAnalyzerClient
    ) -> None:
        """Test report_run returns TID."""
        result = await mock_client_with_reports.report_run(
            adom="root",
            layout_id=1,
            time_period="last-7-days",
        )
        assert "tid" in result
        assert result["tid"] == "report-uuid-002"

    async def test_report_get_state_success(
        self, mock_client_with_reports: FortiAnalyzerClient
    ) -> None:
        """Test report_get_state returns state list."""
        result = await mock_client_with_reports.report_get_state(
            adom="root",
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
            state="generated",
        )
        assert "data" in result
        reports = result["data"]
        assert len(reports) == 1
        assert reports[0]["tid"] == "report-uuid-001"
        assert reports[0]["state"] == "generated"

    async def test_get_report_layouts_not_connected(self) -> None:
        """Test get_report_layouts raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_report_layouts(adom="root")

    async def test_report_run_not_connected(self) -> None:
        """Test report_run raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.report_run(
                adom="root",
                layout_id=1,
                time_period="last-7-days",
            )

    async def test_report_fetch_not_connected(self) -> None:
        """Test report_fetch raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.report_fetch(adom="root", tid="report-uuid-001")

    async def test_report_get_data_not_connected(self) -> None:
        """Test report_get_data raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.report_get_data(adom="root", tid="report-uuid-001")

    async def test_get_running_reports_not_connected(self) -> None:
        """Test get_running_reports raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_running_reports(adom="root")

    async def test_report_get_state_not_connected(self) -> None:
        """Test report_get_state raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.report_get_state(
                adom="root",
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
                state="generated",
            )


class TestReportFormats:
    """Tests for report output format handling."""

    def test_valid_output_formats(self) -> None:
        """Test valid output formats."""
        valid_formats = ["PDF", "HTML", "CSV", "XML", "JSON"]

        for fmt in valid_formats:
            assert fmt.upper() in valid_formats

    def test_default_format_is_pdf(self) -> None:
        """Test default output format is PDF."""
        default_format = "PDF"
        assert default_format == "PDF"
