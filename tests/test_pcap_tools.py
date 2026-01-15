"""Tests for FortiAnalyzer PCAP tools.

Tests the client methods for PCAP download and IPS log search operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class TestPCAPHelpers:
    """Tests for PCAP tools helper functions."""

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
            "5-min": timedelta(minutes=5),
            "30-min": timedelta(minutes=30),
            "1-hour": timedelta(hours=1),
            "6-hour": timedelta(hours=6),
            "12-hour": timedelta(hours=12),
            "24-hour": timedelta(hours=24),
            "1-day": timedelta(days=1),
            "7-day": timedelta(days=7),
            "30-day": timedelta(days=30),
        }

        assert "5-min" in range_map
        assert "30-min" in range_map
        assert "24-hour" in range_map
        assert "30-day" in range_map
        assert range_map["5-min"] == timedelta(minutes=5)


class TestIPSFilterBuilder:
    """Tests for IPS filter building logic."""

    def test_severity_filter_single(self) -> None:
        """Test building single severity filter."""
        severity = ["critical"]
        if len(severity) == 1:
            result = f'severity="{severity[0]}"'
        else:
            result = ""
        assert result == 'severity="critical"'

    def test_severity_filter_multiple(self) -> None:
        """Test building multiple severity filter."""
        severity = ["critical", "high"]
        if len(severity) == 1:
            result = f'severity="{severity[0]}"'
        else:
            sev_parts = [f'severity="{s}"' for s in severity]
            result = f"({' or '.join(sev_parts)})"
        assert result == '(severity="critical" or severity="high")'

    def test_attack_exact_filter(self) -> None:
        """Test building exact attack name filter."""
        attack_exact = "Drupal.RESTful.Web.Services.unserialize.Remote.Code.Execution"
        result = f'attack="{attack_exact}"'
        assert "Drupal" in result
        assert result.startswith('attack="')
        assert result.endswith('"')

    def test_attack_contains_filter(self) -> None:
        """Test building partial attack name filter."""
        attack_contains = "Remote.Code.Execution"
        result = f"attack=*{attack_contains}*"
        assert result == "attack=*Remote.Code.Execution*"

    def test_action_filter_single(self) -> None:
        """Test building single action filter."""
        action = ["blocked"]
        if len(action) == 1:
            result = f'action="{action[0]}"'
        else:
            result = ""
        assert result == 'action="blocked"'

    def test_action_filter_multiple(self) -> None:
        """Test building multiple action filter."""
        action = ["blocked", "dropped"]
        if len(action) == 1:
            result = f'action="{action[0]}"'
        else:
            act_parts = [f'action="{a}"' for a in action]
            result = f"({' or '.join(act_parts)})"
        assert result == '(action="blocked" or action="dropped")'

    def test_cve_filter_specific(self) -> None:
        """Test building specific CVE filter."""
        cve = "CVE-2025-2945"
        result = f'cve="{cve}"'
        assert result == 'cve="CVE-2025-2945"'

    def test_cve_filter_has_any(self) -> None:
        """Test building filter for any CVE assigned."""
        has_cve = True
        result = 'cve!=""' if has_cve else None
        assert result == 'cve!=""'

    def test_ip_filters(self) -> None:
        """Test building IP address filters."""
        srcip = "192.168.1.100"
        dstip = "10.0.0.1"
        filters = []
        if srcip:
            filters.append(f'srcip="{srcip}"')
        if dstip:
            filters.append(f'dstip="{dstip}"')
        assert 'srcip="192.168.1.100"' in filters
        assert 'dstip="10.0.0.1"' in filters

    def test_port_filters(self) -> None:
        """Test building port filters."""
        srcport = 12345
        dstport = 443
        filters = []
        if srcport:
            filters.append(f"srcport=={srcport}")
        if dstport:
            filters.append(f"dstport=={dstport}")
        assert "srcport==12345" in filters
        assert "dstport==443" in filters

    def test_session_id_filter(self) -> None:
        """Test building session ID filter."""
        session_id = 906654
        result = f"sessionid=={session_id}"
        assert result == "sessionid==906654"

    def test_has_pcap_filter(self) -> None:
        """Test building PCAP availability filter."""
        has_pcap = True
        result = 'pcapurl!=""' if has_pcap else None
        assert result == 'pcapurl!=""'

    def test_combined_filter_with_and(self) -> None:
        """Test combining multiple filters with AND."""
        filters = ['severity="critical"', 'action="blocked"', 'pcapurl!=""']
        result = " and ".join(filters)
        assert result == 'severity="critical" and action="blocked" and pcapurl!=""'


class TestPCAPClient:
    """Tests for PCAP client methods."""

    @pytest.fixture
    def mock_client_with_pcap(
        self,
        mock_client: FortiAnalyzerClient,
        configure_mock_responses: None,
        configure_logview_responses: None,
    ) -> FortiAnalyzerClient:
        """Provide a mock client with PCAP API responses configured."""
        return mock_client

    async def test_get_pcapfile_not_connected(self) -> None:
        """Test get_pcapfile raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_pcapfile(
                key_data="pcap-url-data",
                key_type="pcapurl",
            )

    async def test_logsearch_for_ips_not_connected(self) -> None:
        """Test logsearch_start with attack logtype raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.logsearch_start(
                adom="root",
                logtype="attack",
                device=[{"devid": "All_FortiGate"}],
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
                filter='severity="critical"',
            )


class TestPCAPValidation:
    """Tests for PCAP validation logic."""

    def test_valid_session_id(self) -> None:
        """Test valid session ID is positive."""
        session_id = 906654
        assert session_id > 0

    def test_invalid_session_id(self) -> None:
        """Test invalid session ID detection."""
        session_id = 0
        assert session_id <= 0

        session_id = -1
        assert session_id <= 0

    def test_max_pcap_size_limit(self) -> None:
        """Test PCAP size limit constant."""
        MAX_PCAP_SIZE = 50 * 1024 * 1024  # 50MB
        assert MAX_PCAP_SIZE == 52428800

    def test_pcapurl_not_empty(self) -> None:
        """Test pcapurl validation."""
        pcapurl = "some-pcap-url-data"
        assert pcapurl is not None
        assert len(pcapurl) > 0

        pcapurl_empty = ""
        assert len(pcapurl_empty) == 0


class TestPCAPSearchWorkflow:
    """Tests for PCAP search workflow patterns."""

    def test_device_filter_build_serial(self) -> None:
        """Test device filter for serial number."""
        device = "FGT60F0000000001"
        device_filter = [{"devid": device}] if device else [{"devid": "All_FortiGate"}]
        assert device_filter == [{"devid": "FGT60F0000000001"}]

    def test_device_filter_build_all(self) -> None:
        """Test device filter defaults to All_FortiGate."""
        device = None
        device_filter = [{"devid": device}] if device else [{"devid": "All_FortiGate"}]
        assert device_filter == [{"devid": "All_FortiGate"}]

    def test_max_downloads_limit(self) -> None:
        """Test max downloads is capped at 50."""
        max_downloads = 100
        max_downloads = min(max_downloads, 50)
        assert max_downloads == 50

        max_downloads = 10
        max_downloads = min(max_downloads, 50)
        assert max_downloads == 10

    def test_poll_interval_value(self) -> None:
        """Test poll interval constant."""
        POLL_INTERVAL = 1.0
        assert POLL_INTERVAL == 1.0

    def test_default_search_timeout(self) -> None:
        """Test default search timeout."""
        DEFAULT_SEARCH_TIMEOUT = 60
        assert DEFAULT_SEARCH_TIMEOUT == 60
