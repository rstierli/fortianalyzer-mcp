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


async def _no_sleep(_seconds: float) -> None:
    """Sleep replacement that records nothing and returns immediately."""
    return None


def _bare_client() -> FortiAnalyzerClient:
    return FortiAnalyzerClient(
        host="test-faz.example.com",
        username="admin",
        password="password",
    )


class TestEnsureConnected:
    """Tests for the reconnect-once guard tools call before issuing requests."""

    async def test_reconnects_once_when_dropped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A dropped session is revived by exactly one connect() call."""
        client = _bare_client()  # _connected is False
        reconnects: list[int] = []

        async def fake_connect() -> None:
            reconnects.append(1)
            client._connected = True

        monkeypatch.setattr(client, "connect", fake_connect)

        await client.ensure_connected()

        assert reconnects == [1]

    async def test_noop_when_already_connected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An already-connected client is not reconnected."""
        client = _bare_client()
        client._connected = True
        client._fmg = MagicMock()
        reconnects: list[int] = []

        async def fake_connect() -> None:
            reconnects.append(1)

        monkeypatch.setattr(client, "connect", fake_connect)

        await client.ensure_connected()

        assert reconnects == []


class TestExecuteResilient:
    """Tests for transient retry behavior (reconnect is handled separately)."""

    async def test_transient_error_retried_then_succeeds(self) -> None:
        """A transient FAZ error (code -1) is retried and can then succeed."""
        from fortianalyzer_mcp.utils.errors import APIError

        client = _bare_client()
        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            if len(calls) == 1:
                raise APIError("internal error", code=-1)
            return "ok"

        result = await client._execute_resilient(factory, sleep=_no_sleep)

        assert result == "ok"
        assert len(calls) == 2

    async def test_transient_error_exhausts_retries(self) -> None:
        """A persistent transient error is retried a bounded number of times."""
        from fortianalyzer_mcp.utils.errors import APIError

        client = _bare_client()
        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            raise APIError("internal error", code=-1)

        with pytest.raises(APIError):
            await client._execute_resilient(factory, sleep=_no_sleep)

        assert len(calls) == 1 + client._TRANSIENT_RETRIES

    async def test_validation_error_not_retried(self) -> None:
        """A validation error (code -5) is never retried."""
        from fortianalyzer_mcp.utils.errors import ValidationError

        client = _bare_client()
        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            raise ValidationError("invalid param", code=-5)

        with pytest.raises(ValidationError):
            await client._execute_resilient(factory, sleep=_no_sleep)

        assert len(calls) == 1

    async def test_oserror_retried_then_succeeds(self) -> None:
        """A network OSError is transient and retried."""
        client = _bare_client()
        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            if len(calls) == 1:
                raise OSError("connection reset")
            return "ok"

        result = await client._execute_resilient(factory, sleep=_no_sleep)
        assert result == "ok"
        assert len(calls) == 2

    async def test_invalid_tid_not_retried(self) -> None:
        """An invalid-tid error is handled by the tool layer, not retried here,
        even though it can carry a transient-looking code."""
        from fortianalyzer_mcp.utils.errors import APIError

        client = _bare_client()
        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            raise APIError("Server error: Invalid tid 123 for fetching result.", code=-1)

        with pytest.raises(APIError):
            await client._execute_resilient(factory, sleep=_no_sleep)

        assert len(calls) == 1  # not retried

    async def test_exhausted_retries_records_count(self) -> None:
        """The final exception records how many transient retries were attempted."""
        from fortianalyzer_mcp.utils.errors import APIError

        client = _bare_client()

        async def factory() -> str:
            raise APIError("internal error", code=-1)

        with pytest.raises(APIError) as excinfo:
            await client._execute_resilient(factory, sleep=_no_sleep)

        assert getattr(excinfo.value, "retries_attempted", None) == client._TRANSIENT_RETRIES

    async def test_non_retried_error_records_zero_retries(self) -> None:
        """A non-retried error reports zero transient retries via the getattr default."""
        from fortianalyzer_mcp.utils.errors import ValidationError

        client = _bare_client()

        async def factory() -> str:
            raise ValidationError("invalid param", code=-5)

        with pytest.raises(ValidationError) as excinfo:
            await client._execute_resilient(factory, sleep=_no_sleep)

        assert getattr(excinfo.value, "retries_attempted", 0) == 0


class TestSessionReconnect:
    """Tests for reviving a server-dropped session mid-request."""

    async def test_session_error_reconnects_once_then_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stale-session error triggers one forced reconnect, then retries."""
        from fortianalyzer_mcp.utils.errors import AuthenticationError

        client = _bare_client()
        client._connected = True  # stale: server has dropped the session
        client._fmg = MagicMock()
        reconnects: list[int] = []

        async def fake_connect() -> None:
            reconnects.append(1)
            client._connected = True

        monkeypatch.setattr(client, "connect", fake_connect)

        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            if len(calls) == 1:
                raise AuthenticationError("Invalid session", code=-2)
            return "ok"

        result = await client._execute_resilient(factory, sleep=_no_sleep)

        assert result == "ok"
        assert len(calls) == 2
        assert len(reconnects) == 1
        # Forced reconnect cleared the stale connection state before reconnecting.

    async def test_session_error_reconnects_at_most_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A persistent session error reconnects once, then surfaces."""
        from fortianalyzer_mcp.utils.errors import AuthenticationError

        client = _bare_client()
        client._connected = True
        client._fmg = MagicMock()
        reconnects: list[int] = []

        async def fake_connect() -> None:
            reconnects.append(1)
            client._connected = True

        monkeypatch.setattr(client, "connect", fake_connect)

        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            raise AuthenticationError("Invalid session", code=-2)

        with pytest.raises(AuthenticationError):
            await client._execute_resilient(factory, sleep=_no_sleep)

        assert len(reconnects) == 1
        assert len(calls) == 2


class TestSystemTimezoneDetection:
    """Tests for FAZ system timezone field detection."""

    async def test_reads_tz_field(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The IANA name in the 'TZ' field is used when present."""
        client = _bare_client()

        async def fake_status() -> dict[str, str]:
            return {"TZ": "UTC"}

        monkeypatch.setattr(client, "get_system_status", fake_status)
        tz = await client.get_system_timezone()
        assert tz is not None
        assert str(tz) == "UTC"

    async def test_falls_back_to_time_zone_field(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When 'TZ' is absent, the 'Time Zone' field is used."""
        client = _bare_client()

        async def fake_status() -> dict[str, str]:
            return {"Time Zone": "America/New_York"}

        monkeypatch.setattr(client, "get_system_status", fake_status)
        tz = await client.get_system_timezone()
        assert tz is not None
        assert str(tz) == "America/New_York"

    async def test_unknown_tz_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-IANA timezone label degrades to None (naive fallback)."""
        client = _bare_client()

        async def fake_status() -> dict[str, str]:
            return {"Time Zone": "(GMT-08:00) Pacific Time"}

        monkeypatch.setattr(client, "get_system_status", fake_status)
        tz = await client.get_system_timezone()
        assert tz is None
