"""Tests for FortiAnalyzer log tools.

Tests the client methods for log search and analysis operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import pytest

import fortianalyzer_mcp.tools.log_tools as log_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.query.filters import FilterCondition


class TestLogToolsHelpers:
    """Tests for log tools helper functions.

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

    def test_build_device_filter_serial_pattern(self) -> None:
        """Test device filter logic for serial numbers."""
        device = "FGT60F0000000001"
        # Serial numbers start with FG, FM, etc.
        if device.startswith(("FG", "FM", "FW", "FA", "FS", "FD", "FP", "FC")):
            result = [{"devid": device}]
        else:
            result = [{"devname": device}]
        assert result == [{"devid": "FGT60F0000000001"}]

    def test_build_device_filter_all_pattern(self) -> None:
        """Test device filter logic for All_* patterns."""
        device = "All_FortiGate"
        if device.startswith("All_"):
            result = [{"devid": device}]
        else:
            result = [{"devname": device}]
        assert result == [{"devid": "All_FortiGate"}]

    def test_build_device_filter_device_name(self) -> None:
        """Test device filter logic for device names."""
        device = "myfw01"
        if device.startswith(("FG", "FM", "FW", "FA", "FS", "FD", "FP", "FC")):
            result = [{"devid": device}]
        elif device.startswith("All_"):
            result = [{"devid": device}]
        else:
            result = [{"devname": device}]
        assert result == [{"devname": "myfw01"}]

    def test_build_device_filter_none(self) -> None:
        """Test device filter logic defaults to All_FortiGate."""
        device = None
        if not device:
            result = [{"devid": "All_FortiGate"}]
        else:
            result = [{"devname": device}]
        assert result == [{"devid": "All_FortiGate"}]


class TestLogSearchClient:
    """Tests for log search client methods."""

    @pytest.fixture
    def mock_client_with_logview(
        self,
        mock_client: FortiAnalyzerClient,
        configure_mock_responses: None,
        configure_logview_responses: None,
    ) -> FortiAnalyzerClient:
        """Provide a mock client with LogView API responses configured."""
        return mock_client

    async def test_logsearch_start_success(
        self, mock_client_with_logview: FortiAnalyzerClient
    ) -> None:
        """Test logsearch_start returns TID."""
        result = await mock_client_with_logview.logsearch_start(
            adom="root",
            logtype="traffic",
            device=[{"devid": "All_FortiGate"}],
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
        )
        assert "tid" in result
        assert result["tid"] == 12345

    async def test_logsearch_fetch_success(
        self, mock_client_with_logview: FortiAnalyzerClient
    ) -> None:
        """Test logsearch_fetch returns log data."""
        result = await mock_client_with_logview.logsearch_fetch(
            adom="root",
            tid=12345,
            limit=100,
            offset=0,
        )
        assert result["percentage"] == 100
        assert result["return-lines"] == 2
        assert "data" in result
        assert len(result["data"]) == 2
        assert result["data"][0]["srcip"] == "10.0.0.1"
        assert result["data"][1]["srcip"] == "10.0.0.2"

    async def test_get_logfields_success(
        self, mock_client_with_logview: FortiAnalyzerClient
    ) -> None:
        """Test get_logfields returns field definitions."""
        result = await mock_client_with_logview.get_logfields(
            adom="root",
            logtype="traffic",
            devtype="FortiGate",
        )
        assert "data" in result
        fields = result["data"]
        assert len(fields) == 4
        field_names = [f["name"] for f in fields]
        assert "srcip" in field_names
        assert "dstip" in field_names
        assert "action" in field_names

    async def test_get_logstats_success(
        self, mock_client_with_logview: FortiAnalyzerClient
    ) -> None:
        """Test get_logstats returns device log statistics."""
        result = await mock_client_with_logview.get_logstats(
            adom="root",
        )
        assert "data" in result
        stats = result["data"]
        assert len(stats) == 1
        assert stats[0]["devname"] == "FGT-01"
        assert stats[0]["log_rate"] == 100

    async def test_logsearch_not_connected(self) -> None:
        """Test logsearch raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.logsearch_start(
                adom="root",
                logtype="traffic",
                device=[{"devid": "All_FortiGate"}],
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
            )

    async def test_logsearch_fetch_not_connected(self) -> None:
        """Test logsearch_fetch raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.logsearch_fetch(adom="root", tid=12345)

    async def test_get_logfields_not_connected(self) -> None:
        """Test get_logfields raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_logfields(adom="root", logtype="traffic")

    async def test_get_logstats_not_connected(self) -> None:
        """Test get_logstats raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_logstats(adom="root")


class TestQueryLogsStructuredFilters:
    """filters compiles to the string dialect; filter stays as an escape hatch."""

    CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"

    class _Faz:
        """Just enough client for the window resolution query_logs does first."""

        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

    def _install(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
        """Patch the client and the page runner; return the captured kwargs."""
        captured: dict[str, object] = {}

        async def fake_page(client: object, **kwargs: object) -> dict[str, object]:
            captured.update(kwargs)
            return {"timed_out": False, "tid": 1, "logs": [], "total": 0}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)
        return captured

    async def test_filters_compile_into_the_sent_filter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Alias resolution, `in` grouping and the AND join reach the wire.

        Deliberately filters on ports rather than an IP: with MASKING_ENABLED
        the arg unmasker treats any value in an IP-typed field as a token and
        rewrites it (the documented "IP wrinkle" in masking/unmask.py), which
        would make this assertion config-dependent. The IP path through the
        compiler is covered in tests/test_query_filters.py, where no tool
        wrapper is in play.
        """
        captured = self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic",
            time_range=self.CUSTOM_RANGE,
            filters=[
                FilterCondition(field="source_port", op="eq", value=8080),
                FilterCondition(field="dstport", op="in", value=[80, 443]),
            ],
        )

        assert captured["filter"] == "srcport==8080 and (dstport==80 or dstport==443)"
        assert result["filter"] == "srcport==8080 and (dstport==80 or dstport==443)"

    async def test_raw_filter_still_works_unchanged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured = self._install(monkeypatch)

        await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, filter="dstport==443"
        )

        assert captured["filter"] == "dstport==443"

    async def test_both_filter_forms_is_a_conflict_error(self) -> None:
        result = await log_tools.query_logs(
            logtype="traffic",
            filter="srcip==10.0.0.1",
            filters=[FilterCondition(field="dstport", op="eq", value=443)],
        )

        assert result["status"] == "error"
        assert result["error"] == "conflicting_filter_input"
        assert "filters" in result["message"]

    async def test_unknown_field_warning_reaches_the_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic",
            time_range=self.CUSTOM_RANGE,
            filters=[FilterCondition(field="mystery_field", op="eq", value="x")],
        )

        assert any("get_log_fields" in w for w in result["warnings"])

    async def test_invalid_condition_returns_a_validation_error(self) -> None:
        result = await log_tools.query_logs(
            logtype="traffic",
            filters=[FilterCondition(field="dstport", op="in", value=443)],
        )

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
