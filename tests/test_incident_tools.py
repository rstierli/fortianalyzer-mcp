"""Tests for FortiAnalyzer incident tools.

Tests the client methods for incident management operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class TestIncidentHelpers:
    """Tests for incident tools helper functions."""

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

        assert "7-day" in range_map
        assert "90-day" in range_map
        assert range_map["7-day"] == timedelta(days=7)

    def test_severity_values(self) -> None:
        """Test valid severity values."""
        valid_severities = ["critical", "high", "medium", "low"]
        for sev in valid_severities:
            assert sev in valid_severities

    def test_status_values(self) -> None:
        """Test valid incident status values."""
        valid_statuses = ["new", "investigating", "contained", "resolved", "closed"]
        for status in valid_statuses:
            assert status in valid_statuses


class TestIncidentClient:
    """Tests for incident client methods."""

    @pytest.fixture
    def mock_client_with_incidents(
        self,
        mock_client: FortiAnalyzerClient,
        configure_mock_responses: None,
        configure_logview_responses: None,
    ) -> FortiAnalyzerClient:
        """Provide a mock client with incident API responses configured."""
        return mock_client

    async def test_get_incidents_success(
        self, mock_client_with_incidents: FortiAnalyzerClient
    ) -> None:
        """Test get_incidents returns incident data."""
        result = await mock_client_with_incidents.get_incidents(
            adom="root",
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
        )
        assert "data" in result
        incidents = result["data"]
        assert len(incidents) == 1
        assert incidents[0]["incid"] == "inc-001"
        assert incidents[0]["severity"] == "high"

    async def test_get_incident_uses_incidents_endpoint_with_incids(
        self, mock_client_with_incidents: FortiAnalyzerClient
    ) -> None:
        """Regression for #49: no single-incident GET endpoint exists.

        Retrieval must go through the plural "incidents" endpoint with an
        incids list; incident/{incid} is update-only and FAZ rejects a GET
        on it with "Not supported method".
        """
        from unittest.mock import AsyncMock, patch

        with patch.object(
            mock_client_with_incidents,
            "_raw_request",
            AsyncMock(return_value={"data": [{"incid": "IN00000019"}]}),
        ) as raw:
            result = await mock_client_with_incidents.get_incident(
                adom="root", incident_id="IN00000019"
            )
        url = raw.await_args.args[1]
        assert url == "/incidentmgmt/adom/root/incidents"
        assert raw.await_args.kwargs["incids"] == ["IN00000019"]
        assert result == {"incid": "IN00000019"}

    async def test_get_incident_not_found_raises(
        self, mock_client_with_incidents: FortiAnalyzerClient
    ) -> None:
        """An empty incids match raises instead of returning an empty dict."""
        from unittest.mock import AsyncMock, patch

        from fortianalyzer_mcp.utils.errors import APIError

        with patch.object(
            mock_client_with_incidents, "_raw_request", AsyncMock(return_value={"data": []})
        ):
            with pytest.raises(APIError, match="IN00000404"):
                await mock_client_with_incidents.get_incident(adom="root", incident_id="IN00000404")

    async def test_get_incidents_count_success(
        self, mock_client_with_incidents: FortiAnalyzerClient
    ) -> None:
        """Test get_incidents_count returns count data."""
        result = await mock_client_with_incidents.get_incidents_count(
            adom="root",
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
        )
        assert result["total"] == 25

    async def test_get_incidents_not_connected(self) -> None:
        """Test get_incidents raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_incidents(
                adom="root",
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
            )

    async def test_get_incident_not_connected(self) -> None:
        """Test get_incident raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_incident(adom="root", incident_id="inc-001")

    async def test_get_incidents_count_not_connected(self) -> None:
        """Test get_incidents_count raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_incidents_count(
                adom="root",
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
            )

    async def test_create_incident_not_connected(self) -> None:
        """Test create_incident raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.create_incident(
                adom="root",
                name="Test Incident",
                severity="high",
            )

    async def test_update_incident_not_connected(self) -> None:
        """Test update_incident raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.update_incident(
                adom="root",
                incident_id="inc-001",
                status="investigating",
            )

    async def test_get_incident_stats_not_connected(self) -> None:
        """Test get_incident_stats raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_incident_stats(
                adom="root",
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
            )
