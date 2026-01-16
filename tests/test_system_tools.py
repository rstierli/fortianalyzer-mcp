"""Tests for FortiAnalyzer system tools."""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class TestSystemTools:
    """Tests for system-related tools."""

    @pytest.fixture
    def mock_client_configured(
        self, mock_client: FortiAnalyzerClient, configure_mock_responses: None
    ) -> FortiAnalyzerClient:
        """Provide a mock client with configured responses."""
        return mock_client

    async def test_get_system_status_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test get_system_status returns system info."""
        result = await mock_client_configured.get_system_status()
        assert result["Hostname"] == "FAZ-TEST"
        assert result["Platform Type"] == "FAZ-VM64"
        assert result["Version"] == "v7.6.5"
        assert "Serial Number" in result

    async def test_get_system_status_not_connected(self) -> None:
        """Test get_system_status raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_system_status()

    async def test_get_ha_status_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test get_ha_status returns HA info."""
        result = await mock_client_configured.get_ha_status()
        assert result["mode"] == "standalone"
        assert "peer" in result

    async def test_list_adoms_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test list_adoms returns ADOM list."""
        result = await mock_client_configured.list_adoms()
        assert len(result) == 2
        assert result[0]["name"] == "root"
        assert result[1]["name"] == "demo"

    async def test_get_adom_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test get_adom returns specific ADOM."""
        result = await mock_client_configured.get_adom("root")
        assert result["name"] == "root"
        assert "oid" in result

    async def test_list_devices_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test list_devices returns device list."""
        result = await mock_client_configured.list_devices(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "FGT-01"
        assert result[0]["ip"] == "192.168.1.1"
        assert result[0]["platform_str"] == "FortiGate-60F"

    async def test_list_device_groups_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_device_groups returns groups."""
        result = await mock_client_configured.list_device_groups(adom="root")
        assert len(result) == 1
        assert result[0]["name"] == "All_FortiGate"

    async def test_list_tasks_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test list_tasks returns task list."""
        result = await mock_client_configured.list_tasks()
        assert len(result) == 2
        assert result[0]["title"] == "Log search"
        assert result[0]["state"] == 4  # Completed

    async def test_get_task_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test get_task returns task details."""
        result = await mock_client_configured.get_task(1)
        assert result["title"] == "Log search"
        assert result["percent"] == 100
