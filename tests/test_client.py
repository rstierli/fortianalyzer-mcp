"""Tests for FortiAnalyzerClient."""

from unittest.mock import MagicMock

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.utils.errors import ConnectionError


class TestFortiAnalyzerClientInit:
    """Tests for client initialization."""

    def test_init_with_api_token(self) -> None:
        """Test client initialization with API token."""
        client = FortiAnalyzerClient(
            host="faz.example.com",
            api_token="test-token",
        )
        assert client.host == "faz.example.com"
        assert client.api_token == "test-token"
        assert client.username is None
        assert client.password is None

    def test_init_with_credentials(self) -> None:
        """Test client initialization with username/password."""
        client = FortiAnalyzerClient(
            host="faz.example.com",
            username="admin",
            password="secret",
        )
        assert client.host == "faz.example.com"
        assert client.api_token is None
        assert client.username == "admin"
        assert client.password == "secret"

    def test_init_default_values(self) -> None:
        """Test client initialization with default values."""
        client = FortiAnalyzerClient(
            host="faz.example.com",
            username="admin",
            password="secret",
        )
        assert client.verify_ssl is True
        assert client.timeout == 30
        assert client.max_retries == 3
        assert client._connected is False

    def test_init_strips_protocol(self) -> None:
        """Test that host strips https:// prefix."""
        client = FortiAnalyzerClient(
            host="https://faz.example.com",
            username="admin",
            password="secret",
        )
        assert client.host == "faz.example.com"

    def test_init_strips_http_protocol(self) -> None:
        """Test that host strips http:// prefix."""
        client = FortiAnalyzerClient(
            host="http://faz.example.com",
            username="admin",
            password="secret",
        )
        assert client.host == "faz.example.com"

    def test_init_strips_trailing_slash(self) -> None:
        """Test that host strips trailing slash."""
        client = FortiAnalyzerClient(
            host="faz.example.com/",
            username="admin",
            password="secret",
        )
        assert client.host == "faz.example.com"


class TestFortiAnalyzerClientConnection:
    """Tests for client connection management."""

    @pytest.fixture
    def mock_client(self, mock_fmg_instance: MagicMock) -> FortiAnalyzerClient:
        """Create a mock client for connection tests."""
        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        client._fmg = mock_fmg_instance
        client._connected = True
        return client

    async def test_connect_already_connected(self, mock_client: FortiAnalyzerClient) -> None:
        """Test connect when already connected returns early."""
        mock_client._connected = True
        await mock_client.connect()
        # Should not call login again
        mock_client._fmg.login.assert_not_called()

    async def test_disconnect(self, mock_client: FortiAnalyzerClient) -> None:
        """Test disconnect clears connection state."""
        await mock_client.disconnect()
        assert mock_client._connected is False
        assert mock_client._fmg is None

    async def test_ensure_connected_raises_when_disconnected(
        self,
    ) -> None:
        """Test _ensure_connected raises when not connected."""
        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            client._ensure_connected()

    def test_is_connected_property(self, mock_client: FortiAnalyzerClient) -> None:
        """Test is_connected property."""
        assert mock_client.is_connected is True
        mock_client._connected = False
        assert mock_client.is_connected is False


class TestFortiAnalyzerClientOperations:
    """Tests for client API operations."""

    @pytest.fixture
    def mock_client(
        self, mock_fmg_instance: MagicMock, configure_mock_responses: None
    ) -> FortiAnalyzerClient:
        """Create a configured mock client."""
        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        client._fmg = mock_fmg_instance
        client._connected = True
        return client

    async def test_get_system_status(self, mock_client: FortiAnalyzerClient) -> None:
        """Test get_system_status returns expected data."""
        result = await mock_client.get_system_status()
        assert result["Hostname"] == "FAZ-TEST"
        assert result["Version"] == "v7.6.5"

    async def test_get_ha_status(self, mock_client: FortiAnalyzerClient) -> None:
        """Test get_ha_status returns expected data."""
        result = await mock_client.get_ha_status()
        assert result["mode"] == "standalone"

    async def test_list_adoms(self, mock_client: FortiAnalyzerClient) -> None:
        """Test list_adoms returns list of ADOMs."""
        result = await mock_client.list_adoms()
        assert len(result) == 2
        assert result[0]["name"] == "root"
        assert result[1]["name"] == "demo"

    async def test_get_adom(self, mock_client: FortiAnalyzerClient) -> None:
        """Test get_adom returns specific ADOM."""
        result = await mock_client.get_adom("root")
        assert result["name"] == "root"

    async def test_list_devices(self, mock_client: FortiAnalyzerClient) -> None:
        """Test list_devices returns list of devices."""
        result = await mock_client.list_devices(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "FGT-01"
        assert result[1]["name"] == "FGT-02"

    async def test_list_device_groups(self, mock_client: FortiAnalyzerClient) -> None:
        """Test list_device_groups returns groups."""
        result = await mock_client.list_device_groups(adom="root")
        assert len(result) == 1
        assert result[0]["name"] == "All_FortiGate"

    async def test_list_tasks(self, mock_client: FortiAnalyzerClient) -> None:
        """Test list_tasks returns list of tasks."""
        result = await mock_client.list_tasks()
        assert len(result) == 2
        assert result[0]["title"] == "Log search"

    async def test_get_task(self, mock_client: FortiAnalyzerClient) -> None:
        """Test get_task returns task details."""
        result = await mock_client.get_task(1)
        assert result["title"] == "Log search"


class TestFortiAnalyzerClientErrorHandling:
    """Tests for client error handling."""

    def test_handle_response_success(self) -> None:
        """Test _handle_response returns data on success."""
        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        result = client._handle_response(0, {"data": "test"}, "test")
        assert result == {"data": "test"}

    def test_handle_response_error(self) -> None:
        """Test _handle_response raises on error."""
        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        from fortianalyzer_mcp.utils.errors import APIError

        with pytest.raises(APIError):
            client._handle_response(-1, {"status": {"message": "Error"}}, "test")
