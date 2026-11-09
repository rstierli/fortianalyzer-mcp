"""Tests for FortiAnalyzerClient."""

from unittest.mock import MagicMock

import pytest
from pyFMG.fortimgr import FMGBaseException, FMGConnectionError

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.utils.errors import AuthenticationError, ConnectionError


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
    """ensure_connected() connects a client that is not connected; tools call
    it upfront, and with connect_on_demand (the server's client) every request
    runs it first."""

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

    async def test_concurrent_callers_share_one_failed_attempt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Callers queued behind a failed connect get its error instead of
        each waiting out another connect timeout of their own."""
        import asyncio

        client = _bare_client()
        connects: list[int] = []

        async def fake_connect() -> None:
            connects.append(1)
            await asyncio.sleep(0)
            raise ConnectionError("Failed to connect to FortiAnalyzer: timed out")

        monkeypatch.setattr(client, "connect", fake_connect)

        results = await asyncio.gather(
            client.ensure_connected(),
            client.ensure_connected(),
            client.ensure_connected(),
            return_exceptions=True,
        )

        assert connects == [1]
        assert all(isinstance(r, ConnectionError) for r in results)

    async def test_call_after_a_failed_attempt_tries_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed attempt is not cached: the next call connects anew, so the
        client recovers once FortiAnalyzer is reachable."""
        client = _bare_client()
        connects: list[int] = []

        async def fake_connect() -> None:
            connects.append(1)
            if len(connects) == 1:
                raise ConnectionError("Failed to connect to FortiAnalyzer: timed out")
            client._connected = True
            client._fmg = MagicMock()

        monkeypatch.setattr(client, "connect", fake_connect)

        with pytest.raises(ConnectionError):
            await client.ensure_connected()
        await client.ensure_connected()

        assert client.is_connected
        assert len(connects) == 2

    async def test_caller_behind_a_cancelled_attempt_connects_itself(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cancelled attempt has no outcome to share, not even an older
        failure: the caller waiting behind it makes its own attempt."""
        import asyncio

        client = _bare_client()
        connects: list[int] = []
        started = asyncio.Event()

        async def fake_connect() -> None:
            connects.append(1)
            if len(connects) == 1:
                raise ConnectionError("Failed to connect to FortiAnalyzer: timed out")
            if len(connects) == 2:
                started.set()
                await asyncio.Event().wait()  # hangs until cancelled
            client._connected = True
            client._fmg = MagicMock()

        monkeypatch.setattr(client, "connect", fake_connect)

        with pytest.raises(ConnectionError):
            await client.ensure_connected()
        first = asyncio.create_task(client.ensure_connected())
        await started.wait()
        second = asyncio.create_task(client.ensure_connected())
        await asyncio.sleep(0)
        first.cancel()
        await second

        assert first.cancelled()
        assert client.is_connected
        assert len(connects) == 3


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

    async def test_no_permission_forces_reconnect_not_dead_session_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Code -11 (No permission) is what an expired or closed FAZ session
        returns per request, so it must force a single re-login and retry rather
        than retrying the dead session as a transient error."""
        from fortianalyzer_mcp.utils.errors import APIError

        client = _bare_client()
        reconnects: list[int] = []

        async def fake_reconnect() -> None:
            reconnects.append(1)

        monkeypatch.setattr(client, "_force_reconnect", fake_reconnect)

        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            if len(calls) == 1:
                raise APIError("No permission for the resource", code=-11)
            return "ok"

        result = await client._execute_resilient(factory, sleep=_no_sleep)

        assert result == "ok"
        assert reconnects == [1]  # re-logged in once, did not retry the dead session
        assert len(calls) == 2

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


class TestNotConnectedReconnect:
    """A dropped session surfaces a local 'Not connected' error mid-request.

    It should be revived once -- but only if the client was ever connected; a
    never-connected client must still surface the raw error rather than silently
    attempt a first login on an arbitrary API call.
    """

    async def test_local_not_connected_reconnects_once_then_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _bare_client()
        client._connected = True
        client._fmg = MagicMock()
        client._ever_connected = True  # was connected before; session then dropped
        reconnects: list[int] = []

        async def fake_connect() -> None:
            reconnects.append(1)
            client._connected = True

        monkeypatch.setattr(client, "connect", fake_connect)

        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            if len(calls) == 1:
                raise ConnectionError("Not connected. Call connect() first.")
            return "ok"

        result = await client._execute_resilient(factory, sleep=_no_sleep)

        assert result == "ok"
        assert len(calls) == 2
        assert len(reconnects) == 1

    async def test_never_connected_does_not_reconnect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _bare_client()  # _ever_connected is False
        reconnects: list[int] = []

        async def fake_connect() -> None:
            reconnects.append(1)

        monkeypatch.setattr(client, "connect", fake_connect)

        calls: list[int] = []

        async def factory() -> str:
            calls.append(1)
            raise ConnectionError("Not connected. Call connect() first.")

        with pytest.raises(ConnectionError, match="Not connected"):
            await client._execute_resilient(factory, sleep=_no_sleep)

        assert len(calls) == 1
        assert reconnects == []

    async def test_connect_on_demand_connects_before_the_request(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The server's client, whose startup connect failed, connects on its
        next call instead of answering "Not connected" until a restart."""
        client = _bare_client()  # _ever_connected is False
        client.connect_on_demand = True
        order: list[str] = []

        async def fake_connect() -> None:
            order.append("connect")
            client._connected = True
            client._fmg = MagicMock()

        monkeypatch.setattr(client, "connect", fake_connect)

        async def factory() -> str:
            order.append("call")
            return "ok"

        result = await client._execute_resilient(factory, sleep=_no_sleep)

        assert result == "ok"
        assert order == ["connect", "call"]

    async def test_failed_connect_on_demand_skips_the_request(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One connect attempt per call; the request itself never runs."""
        client = _bare_client()
        client.connect_on_demand = True
        order: list[str] = []

        async def fake_connect() -> None:
            order.append("connect")
            raise ConnectionError("Failed to connect to FortiAnalyzer: timed out")

        monkeypatch.setattr(client, "connect", fake_connect)

        async def factory() -> str:
            order.append("call")
            return "ok"

        with pytest.raises(ConnectionError):
            await client._execute_resilient(factory, sleep=_no_sleep)

        assert order == ["connect"]


class TestConcurrentReconnect:
    """The reconnect lock + generation counter serialize concurrent reconnects."""

    async def test_concurrent_force_reconnect_logs_in_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        client = _bare_client()
        client._connected = True
        client._fmg = MagicMock()
        connects: list[int] = []

        async def fake_connect() -> None:
            # Yield so the second waiter blocks on the lock before we finish.
            await asyncio.sleep(0)
            connects.append(1)
            client._connected = True

        monkeypatch.setattr(client, "connect", fake_connect)

        await asyncio.gather(client._force_reconnect(), client._force_reconnect())

        # Only the first caller re-logs in; the second sees the bumped generation.
        assert len(connects) == 1
        assert client._reconnect_generation == 1


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


class TestCaBundleAndVerifyGuidance:
    """`FORTIANALYZER_CA_BUNDLE` and the warning that names it (#126).

    The warning told the operator to "trust the FAZ CA (set the CA bundle)".
    Two things were wrong with that. Trusting the CA is not sufficient: a
    factory FortiAnalyzer certificate is self-signed with the serial as CN and
    carries no subjectAltName, so with that certificate trusted as the CA
    bundle a request by IP still fails CERTIFICATE_VERIFY_FAILED on an address
    mismatch. And the setting it told the operator to set did not exist.
    """

    def test_ca_bundle_path_reaches_the_transport(self, tmp_path) -> None:
        bundle = tmp_path / "corp-ca.pem"
        bundle.write_text("-----BEGIN CERTIFICATE-----\n")

        client = FortiAnalyzerClient(
            host="faz.example.com", api_token="t", verify_ssl=True, ca_bundle=str(bundle)
        )

        assert client.resolve_verify() == str(bundle)

    def test_verify_disabled_beats_a_ca_bundle(self, tmp_path) -> None:
        """An explicit FORTIANALYZER_VERIFY_SSL=false is never silently upgraded."""
        bundle = tmp_path / "corp-ca.pem"
        bundle.write_text("-----BEGIN CERTIFICATE-----\n")

        client = FortiAnalyzerClient(
            host="faz.example.com", api_token="t", verify_ssl=False, ca_bundle=str(bundle)
        )

        assert client.resolve_verify() is False

    def test_no_bundle_keeps_the_system_trust_store(self) -> None:
        client = FortiAnalyzerClient(host="faz.example.com", api_token="t", verify_ssl=True)
        assert client.resolve_verify() is True

    def test_a_missing_bundle_fails_closed(self) -> None:
        """A typo'd path must not fall back to the system trust store, which
        would verify against the wrong root and look like success."""
        with pytest.raises(ValueError, match="CA bundle"):
            FortiAnalyzerClient(
                host="faz.example.com",
                api_token="t",
                verify_ssl=True,
                ca_bundle="/nonexistent/corp-ca.pem",
            )

    @pytest.mark.asyncio
    async def test_the_warning_names_a_setting_that_exists(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The old text pointed at a 'CA bundle' knob this server never had."""
        stub = MagicMock()
        stub.login.return_value = (0, {"status": {"code": 0, "message": "OK"}})
        stub.get.return_value = (0, {"status": {"code": 0}})
        monkeypatch.setattr("fortianalyzer_mcp.api.client.FortiManager", lambda *a, **kw: stub)

        client = FortiAnalyzerClient(host="faz.example.com", api_token="t", verify_ssl=False)

        caplog.clear()
        with caplog.at_level("WARNING", logger="fortianalyzer_mcp.api.client"):
            try:
                await client.connect()
            except Exception:
                pass

        blob = " ".join(r.getMessage() for r in caplog.records if r.levelname == "WARNING")

        assert "FORTIANALYZER_VERIFY_SSL=false" in blob
        # Names the setting that now exists, rather than a vague "the CA bundle".
        assert "FORTIANALYZER_CA_BUNDLE" in blob
        # States the real blocker.
        assert "subjectAltName" in blob or "SAN" in blob


def _token_client(*, connect_on_demand: bool = False) -> FortiAnalyzerClient:
    return FortiAnalyzerClient(
        host="faz.example.com", api_token="t", connect_on_demand=connect_on_demand
    )


def _stub_fortimanager(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    stub = MagicMock()
    stub.login.return_value = (0, {"status": {"code": 0, "message": "OK"}})
    monkeypatch.setattr("fortianalyzer_mcp.api.client.FortiManager", lambda *a, **kw: stub)
    return stub


class TestDisconnectDoesNotStallShutdown:
    """disconnect() runs on every shutdown. With an API token pyfmg's "session"
    is a UUID made up on the client, so a sys/logout ends nothing on the
    appliance and only blocks for FORTIANALYZER_TIMEOUT when it is unreachable."""

    async def test_token_disconnect_skips_the_logout(self) -> None:
        client = _token_client()
        fmg = MagicMock()
        client._fmg = fmg
        client._connected = True

        await client.disconnect()

        fmg.logout.assert_not_called()
        assert client._fmg is None
        assert not client.is_connected

    async def test_session_disconnect_logs_out_with_a_capped_timeout(self) -> None:
        """Username/password auth has a real server session, so it still logs
        out, but on pyfmg's own timeout (which bounds the request itself)
        capped well below the request timeout."""
        client = _bare_client()  # timeout defaults to 30
        fmg = MagicMock()
        fmg.timeout = client.timeout
        seen: list[int] = []
        fmg.logout.side_effect = lambda: seen.append(fmg.timeout)
        client._fmg = fmg
        client._connected = True

        await client.disconnect()

        assert seen == [client._LOGOUT_TIMEOUT]
        assert client._LOGOUT_TIMEOUT <= 5
        assert client._fmg is None
        assert not client.is_connected

    async def test_session_logout_keeps_a_shorter_configured_timeout(self) -> None:
        client = FortiAnalyzerClient(host="faz", username="admin", password="pw", timeout=2)
        fmg = MagicMock()
        fmg.timeout = 2
        seen: list[int] = []
        fmg.logout.side_effect = lambda: seen.append(fmg.timeout)
        client._fmg = fmg
        client._connected = True

        await client.disconnect()

        assert seen == [2]

    async def test_a_failed_session_logout_still_clears_the_state(self) -> None:
        client = _bare_client()
        fmg = MagicMock()
        fmg.logout.side_effect = OSError("connect timeout")
        client._fmg = fmg
        client._connected = True

        await client.disconnect()

        assert client._fmg is None
        assert not client.is_connected


class TestTokenAuthLivenessProbe:
    """API-token login makes no request in pyfmg, so connect() probes
    /sys/status once before reporting connected. Without it /health showed
    connected against an unreachable FortiAnalyzer (twin of fortimanager-mcp#31)."""

    async def test_token_connect_probes_sys_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stub = _stub_fortimanager(monkeypatch)
        client = _token_client()
        during: list[tuple[bool, bool]] = []

        def probe(url: str) -> tuple[int, dict[str, str]]:
            # The probe runs under the I/O lock and before the client calls
            # itself connected.
            during.append((client._io_lock.locked(), client._connected))
            return 0, {"Hostname": "faz-01", "Version": "v7.6.5"}

        stub.get.side_effect = probe

        await client.connect()

        assert client.is_connected
        stub.get.assert_called_once()
        assert stub.get.call_args.args[0] == "/sys/status"
        assert during == [(True, False)]

    @pytest.mark.parametrize(
        "error",
        [
            FMGConnectionError("Connection error: ConnectTimeout"),
            # pyfmg wraps a read timeout in its generic exception.
            FMGBaseException("Response parser error: ReadTimeout"),
        ],
        ids=["connect-error", "read-timeout"],
    )
    async def test_transport_error_fails_the_connect(
        self, monkeypatch: pytest.MonkeyPatch, error: Exception
    ) -> None:
        stub = _stub_fortimanager(monkeypatch)
        stub.get.side_effect = error
        client = _token_client()

        with pytest.raises(ConnectionError, match="Failed to connect to FortiAnalyzer"):
            await client.connect()

        assert not client.is_connected
        assert client._connected is False
        assert client._fmg is None
        assert client._ever_connected is False

    async def test_error_code_fails_closed_as_authentication_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """FortiAnalyzer answers an invalid token with "No permission" (-11)
        rather than a distinct auth error, and a token that cannot read
        /sys/status cannot run the tools that depend on it either."""
        stub = _stub_fortimanager(monkeypatch)
        stub.get.return_value = (
            -11,
            {"status": {"code": -11, "message": "No permission for the resource"}},
        )
        client = _token_client()

        with pytest.raises(AuthenticationError, match="No permission for the resource") as exc:
            await client.connect()

        assert exc.value.code == -11
        assert not client.is_connected
        assert client._fmg is None

    async def test_a_non_json_answer_is_a_connection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """pyfmg returns (100, <Response>) when the body is not JSON: something
        answered, but not FortiAnalyzer's JSON-RPC."""
        stub = _stub_fortimanager(monkeypatch)
        stub.get.return_value = (100, "<Response [502]>")
        client = _token_client()

        with pytest.raises(ConnectionError, match=r"Response \[502\]"):
            await client.connect()

        assert not client.is_connected
        assert client._fmg is None

    async def test_session_connect_does_not_probe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Username/password login already makes a round-trip."""
        stub = _stub_fortimanager(monkeypatch)
        client = _bare_client()

        await client.connect()

        assert client.is_connected
        stub.get.assert_not_called()

    async def test_a_failed_probe_counts_as_a_failed_connect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ensure_connected() records it like a failed password login, so
        callers queued behind it share the error instead of each probing."""
        import asyncio

        stub = _stub_fortimanager(monkeypatch)
        stub.get.side_effect = FMGConnectionError("Connection error: ConnectTimeout")
        client = _token_client()

        results = await asyncio.gather(
            client.ensure_connected(),
            client.ensure_connected(),
            client.ensure_connected(),
            return_exceptions=True,
        )

        assert all(isinstance(r, ConnectionError) for r in results)
        assert stub.get.call_count == 1
        assert client._failed_connects == 1
        assert isinstance(client._last_connect_error, ConnectionError)
        assert not client.is_connected

    async def test_connect_on_demand_recovers_once_the_probe_passes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stub = _stub_fortimanager(monkeypatch)
        stub.get.side_effect = [
            FMGConnectionError("Connection error: ConnectTimeout"),  # startup probe
            (0, {"Hostname": "faz-01"}),  # probe on the next call
            (0, {"Hostname": "faz-01"}),  # the call itself
        ]
        client = _token_client(connect_on_demand=True)

        with pytest.raises(ConnectionError):
            await client.ensure_connected()
        status = await client.get_system_status()

        assert status == {"Hostname": "faz-01"}
        assert client.is_connected
        assert stub.get.call_count == 3


def _read_timeout_from_pyfmg() -> FMGBaseException:
    """What pyfmg's verbs raise on a read timeout: the timeout is caught by
    their catch-all and re-raised as FMGBaseException, kept as __context__."""
    from requests.exceptions import ReadTimeout

    try:
        try:
            raise ReadTimeout("read timed out")
        except Exception as err:
            raise FMGBaseException(f"Response parser error: {type(err)} {err}")  # noqa: B904
    except FMGBaseException as wrapped:
        return wrapped


class TestReachability:
    """is_connected stays True through an outage: only a session error or
    disconnect clears it, and an API-token client never sees a session error.
    /health read it, so it said connected long after FortiAnalyzer dropped.
    is_reachable follows the last request instead."""

    async def _connected_token_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        stub = _stub_fortimanager(monkeypatch)
        stub.get.return_value = (0, {"Hostname": "faz-01"})  # connect probe
        self.client = _token_client()
        await self.client.connect()
        assert self.client.is_reachable
        return stub

    async def test_transport_error_marks_unreachable_and_success_clears_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stub = await self._connected_token_client(monkeypatch)
        stub.get.side_effect = FMGConnectionError("Connection error: ConnectTimeout")
        monkeypatch.setattr(self.client, "_TRANSIENT_BACKOFF_BASE", 0)

        with pytest.raises(FMGConnectionError):
            await self.client.get_system_status()

        assert self.client.is_connected  # the bug: this alone fed /health
        assert not self.client.is_reachable

        stub.get.side_effect = None
        await self.client.get_system_status()
        assert self.client.is_reachable

    async def test_pyfmg_wrapped_read_timeout_marks_unreachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stub = await self._connected_token_client(monkeypatch)
        stub.get.side_effect = _read_timeout_from_pyfmg()

        with pytest.raises(FMGBaseException):
            await self.client.get_system_status()

        assert not self.client.is_reachable

    async def test_faz_error_code_counts_as_reachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An error code is FortiAnalyzer answering."""
        from fortianalyzer_mcp.utils.errors import ResourceNotFoundError

        stub = await self._connected_token_client(monkeypatch)
        self.client._unreachable = True
        stub.get.return_value = (-4, {"status": {"code": -4, "message": "Object not found"}})

        with pytest.raises(ResourceNotFoundError):
            await self.client.get_system_status()

        assert self.client.is_reachable

    async def test_local_not_connected_leaves_the_flag_alone(self) -> None:
        """A local "Not connected" never reached the network, so it says
        nothing about FortiAnalyzer either way."""
        client = _bare_client()
        client._connected = True
        client._fmg = MagicMock()
        client._unreachable = True

        async def factory() -> str:
            raise ConnectionError("Not connected. Call connect() first.")

        async def failed_reconnect() -> None:
            raise ConnectionError("Failed to connect to FortiAnalyzer: down")

        client._force_reconnect = failed_reconnect  # type: ignore[method-assign]

        with pytest.raises(ConnectionError):
            await client._execute_resilient(factory, sleep=_no_sleep)

        assert client._unreachable

    async def test_reconnect_clears_the_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        await self._connected_token_client(monkeypatch)
        self.client._unreachable = True
        await self.client.disconnect()

        await self.client.connect()

        assert self.client.is_reachable
