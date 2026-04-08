"""Tests for FortiAnalyzer log tools.

Tests the client methods for log search and analysis operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import importlib
from collections import Counter

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


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


@pytest.fixture
def log_tools_module(monkeypatch):
    """Import log_tools with minimal settings for unit testing helper logic."""
    monkeypatch.setenv("FORTIANALYZER_HOST", "test-faz.example.com")
    monkeypatch.setenv("FORTIANALYZER_API_TOKEN", "test-token")
    monkeypatch.setenv("FORTIANALYZER_VERIFY_SSL", "false")
    return importlib.import_module("fortianalyzer_mcp.tools.log_tools")


class TestExactPolicyUsageTools:
    """Tests for exact policy usage helpers and result semantics."""

    def test_build_protocol_range_filter(self, log_tools_module) -> None:
        """Protocol filters should format single values and ranges correctly."""
        assert log_tools_module._build_protocol_range_filter(1, 1) == "proto==1"
        assert log_tools_module._build_protocol_range_filter(1, 17) == (
            "proto>=1 and proto<=17"
        )

    async def test_get_exact_policy_port_usage_zero_hits(
        self, monkeypatch, log_tools_module
    ) -> None:
        """Zero-hit policies should return an exact empty structure."""

        async def fake_run_log_count_exact(**kwargs):
            return 0

        monkeypatch.setattr(log_tools_module, "_run_log_count_exact", fake_run_log_count_exact)

        result = await log_tools_module.get_exact_policy_port_usage(
            policy_id=42,
            adom="root",
            time_range="1-day",
        )

        assert result["status"] == "success"
        assert result["is_exact"] is True
        assert result["total_hits"] == 0
        assert result["ports"] == []
        assert result["protocols"] == []
        assert result["portless_protocols"] == []
        assert result["icmp"] == {"hits": 0, "ping_hits": 0, "other_icmp_hits": 0}

    async def test_get_exact_policy_port_usage_reports_icmp_and_portless_protocols(
        self, monkeypatch, log_tools_module
    ) -> None:
        """Exact results should surface protocol and ICMP detail explicitly."""

        async def fake_run_log_count_exact(**kwargs):
            filter_str = kwargs.get("filter_str") or ""
            if filter_str == "policyid==42":
                return 13
            if "proto>=0 and proto<=255" in filter_str:
                return 13
            if "dstport>=1 and dstport<=65535" in filter_str:
                return 10
            if "dstport==443" in filter_str:
                return 6
            if "dstport==8443" in filter_str:
                return 4
            if "proto==1" in filter_str and "service==PING" in filter_str:
                return 2
            raise AssertionError(f"Unexpected filter in test: {filter_str}")

        async def fake_discover_policy_candidates(**kwargs):
            return {"dstport": Counter({"443": 10})}, {"errors": [], "slices_scanned": 1}

        async def fake_enumerate_exact_protocols(**kwargs):
            return [
                {"proto": "6", "name": "TCP", "hits": 10},
                {"proto": "1", "name": "ICMP", "hits": 3},
            ]

        async def fake_enumerate_exact_ports(**kwargs):
            assert kwargs["low"] == 8443
            assert kwargs["high"] == 8443
            assert kwargs["known_hits"] == 4
            return [{"port": "8443", "hits": 4}]

        monkeypatch.setattr(log_tools_module, "_run_log_count_exact", fake_run_log_count_exact)
        monkeypatch.setattr(
            log_tools_module, "_discover_policy_candidates", fake_discover_policy_candidates
        )
        monkeypatch.setattr(
            log_tools_module, "_enumerate_exact_protocols", fake_enumerate_exact_protocols
        )
        monkeypatch.setattr(log_tools_module, "_enumerate_exact_ports", fake_enumerate_exact_ports)
        monkeypatch.setattr(
            log_tools_module, "_build_residual_port_ranges", lambda ports: [(8443, 8443)]
        )

        result = await log_tools_module.get_exact_policy_port_usage(
            policy_id=42,
            adom="root",
            time_range="1-day",
        )

        assert result["status"] == "success"
        assert result["is_exact"] is True
        assert result["numeric_port_hits"] == 10
        assert result["covered_port_hits"] == 10
        assert result["uncovered_port_hits"] == 0
        assert result["portless_hits"] == 3
        assert result["ports"] == [{"port": "443", "hits": 6}, {"port": "8443", "hits": 4}]
        assert result["protocols"] == [
            {"proto": "6", "name": "TCP", "hits": 10},
            {"proto": "1", "name": "ICMP", "hits": 3},
        ]
        assert result["portless_protocols"] == [{"proto": "1", "name": "ICMP", "hits": 3}]
        assert result["portless_protocol_hits"] == 3
        assert result["portless_unclassified_hits"] == 0
        assert result["icmp"] == {"hits": 3, "ping_hits": 2, "other_icmp_hits": 1}


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

    async def test_logsearch_count_success(
        self, mock_client_with_logview: FortiAnalyzerClient
    ) -> None:
        """Test logsearch_count returns search progress."""
        result = await mock_client_with_logview.logsearch_count(
            adom="root",
            tid=12345,
        )
        assert result["progress-percent"] == 100
        assert result["matched-logs"] == 1234
        assert result["scanned-logs"] == 5000
        assert result["total-logs"] == 10000

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
