"""Tests for FortiAnalyzer DVM (Device Manager) tools."""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class TestDVMTools:
    """Tests for device management tools."""

    @pytest.fixture
    def mock_client_configured(
        self, mock_client: FortiAnalyzerClient, configure_mock_responses: None
    ) -> FortiAnalyzerClient:
        """Provide a mock client with configured responses."""
        return mock_client

    async def test_list_devices_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_devices returns device list."""
        result = await mock_client_configured.list_devices(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "FGT-01"
        assert result[0]["sn"] == "FGT60F0000000001"

    async def test_list_devices_with_fields(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_devices with field filter."""
        result = await mock_client_configured.list_devices(
            adom="root", fields=["name", "ip"]
        )
        assert len(result) == 2

    async def test_get_device_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test get_device returns device details."""
        result = await mock_client_configured.get_device("FGT-01", adom="root")
        assert result["name"] == "FGT-01"

    async def test_list_device_vdoms_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_device_vdoms returns VDOMs."""
        result = await mock_client_configured.list_device_vdoms(
            device="FGT-01", adom="root"
        )
        assert len(result) == 1
        assert result[0]["name"] == "root"

    async def test_list_device_groups_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_device_groups returns groups."""
        result = await mock_client_configured.list_device_groups(adom="root")
        assert len(result) == 1
        assert result[0]["name"] == "All_FortiGate"

    async def test_add_device_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test add_device creates device."""
        device = {
            "name": "FGT-NEW",
            "ip": "192.168.1.100",
            "adm_usr": "admin",
            "adm_pass": "password",
        }
        result = await mock_client_configured.add_device(
            adom="root", device=device
        )
        assert result is not None

    async def test_delete_device_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test delete_device removes device."""
        result = await mock_client_configured.delete_device(
            adom="root", device="FGT-01"
        )
        assert result is not None

    async def test_add_device_list_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test add_device_list adds multiple devices."""
        devices = [
            {"name": "FGT-A", "ip": "192.168.1.10"},
            {"name": "FGT-B", "ip": "192.168.1.11"},
        ]
        result = await mock_client_configured.add_device_list(
            adom="root", devices=devices
        )
        assert result is not None

    async def test_delete_device_list_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test delete_device_list removes multiple devices."""
        devices = [
            {"name": "FGT-A"},
            {"name": "FGT-B"},
        ]
        result = await mock_client_configured.delete_device_list(
            adom="root", devices=devices
        )
        assert result is not None
