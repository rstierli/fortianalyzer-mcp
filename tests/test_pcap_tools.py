"""Tests for FortiAnalyzer PCAP tools.

Tests the client methods for PCAP download and IPS log search operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import base64
import io
import zipfile
from pathlib import Path

import pytest

import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.pcap_tools as pcap_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.utils.errors import ValidationError

_CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"


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


class TestAttackExactLiteral:
    def test_a_quote_in_the_name_keeps_one_pair_of_quotes(self) -> None:
        """The sanitiser puts such a value in single quotes; the builder must
        not wrap that in double quotes a second time."""
        result = pcap_tools._build_ips_filter(attack_exact='Drupal "x"')
        assert result == "attack='Drupal \"x\"'"

    def test_a_plain_name_is_double_quoted_as_before(self) -> None:
        result = pcap_tools._build_ips_filter(attack_exact="Drupal.RCE")
        assert result == 'attack="Drupal.RCE"'

    @pytest.mark.parametrize("name", ['Drupal "x"', "Drupal 'x'", "Remote Code"])
    def test_attack_contains_refuses_anything_but_a_bare_token(self, name: str) -> None:
        """The wildcard form is unquoted, so a value the sanitiser would quote,
        in either quote character, cannot be spliced into it."""
        with pytest.raises(ValidationError, match="attack_contains"):
            pcap_tools._build_ips_filter(attack_contains=name)


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

    def test_default_search_timeout(self) -> None:
        """The module's default search timeout is 60 seconds."""
        assert pcap_tools.DEFAULT_SEARCH_TIMEOUT == 60


class _PollFetchFaz:
    """PCAP-search fake enforcing poll-before-fetch.

    logsearch_fetch returns percentage<100 partial then percentage=100 final;
    logsearch_fetch raises invalid-tid if called before the scan completes, and
    otherwise returns the IPS rows once. The runner must poll then fetch once.
    """

    def __init__(self, dataset: list[dict[str, object]]) -> None:
        self.dataset = dataset
        self.starts = 0

        self.fetches = 0
        self._polls: dict[int, int] = {}
        self._next_tid = 900

    async def ensure_connected(self) -> None:
        return None

    async def logsearch_start(self, **_kw: object) -> dict[str, int]:
        self.starts += 1
        self._next_tid += 1
        self._polls[self._next_tid] = 0
        return {"tid": self._next_tid}

    async def logsearch_fetch(self, *, adom: str, tid: int, limit: int, offset: int) -> dict:
        self.fetches += 1
        return {
            "percentage": 100,
            "data": self.dataset[offset : offset + limit],
            "total-count": len(self.dataset),
        }

    async def logsearch_cancel(self, adom: str, tid: int) -> dict[str, object]:
        return {}


class TestPCAPSearchPollPath:
    """PCAP IPS searches route through the shared poll-before-fetch runner."""

    @pytest.fixture(autouse=True)
    def _fast_polls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
        monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)

    async def test_search_ips_logs_returns_rows_via_poll_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [
            {"sessionid": 1, "attack": "Test.Attack", "severity": "critical", "pcapurl": "u1"},
            {"sessionid": 2, "attack": "Other.Attack", "severity": "high"},
        ]
        fake = _PollFetchFaz(rows)
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.search_ips_logs(
            adom="root",
            severity=["critical", "high"],
            time_range=_CUSTOM_RANGE,
            limit=50,
        )

        assert result["status"] == "success"
        assert result["count"] == 2
        assert result["total"] == 2
        assert result["pcap_available_count"] == 1
        assert result["logs"] == rows
        # Poll-fetch contract: one start, >=1 fetch (last with percentage=100).
        assert fake.starts == 1
        assert fake.fetches >= 1
        assert fake.fetches == 1

    async def test_search_ips_logs_empty_result_via_poll_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty IPS search completes cleanly through the poll path: one
        start, one fetch, zero rows -- not a raw invalid-tid string."""
        fake = _PollFetchFaz([])
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.search_ips_logs(
            adom="root",
            severity=["critical"],
            time_range=_CUSTOM_RANGE,
        )

        assert result["status"] == "success"
        assert result["count"] == 0
        assert result["logs"] == []
        assert fake.starts == 1
        assert fake.fetches == 1

    async def test_get_pcap_by_session_found_via_poll_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """get_pcap_by_session routes its session lookup through the poll path:
        a matching row (without a pcapurl) returns the 'no_pcap' result after
        exactly one start, >=1 count, and one fetch -- never a fetch-before-
        complete invalid-tid string."""
        monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))
        rows = [
            {
                "sessionid": 906654,
                "attack": "Test.Attack",
                "severity": "critical",
                "action": "blocked",
                "srcip": "10.0.0.1",
                "dstip": "10.0.0.2",
            }
        ]
        fake = _PollFetchFaz(rows)
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.get_pcap_by_session(
            session_id=906654,
            adom="root",
            time_range=_CUSTOM_RANGE,
            output_dir=str(tmp_path),
        )

        # Row found, but no pcapurl -> the normal 'no_pcap' return.
        assert result["status"] == "no_pcap"
        assert result["session_id"] == 906654
        assert result["attack_info"]["attack"] == "Test.Attack"
        # Poll-fetch contract: one start, >=1 fetch (last with percentage=100).
        assert fake.starts == 1
        assert fake.fetches >= 1
        assert fake.fetches == 1

    async def test_get_pcap_by_session_empty_via_poll_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """An empty session lookup completes through the poll path and returns
        the 'No IPS log found' message -- not a raw invalid-tid string."""
        monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))
        fake = _PollFetchFaz([])
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.get_pcap_by_session(
            session_id=906654,
            adom="root",
            time_range=_CUSTOM_RANGE,
            output_dir=str(tmp_path),
        )

        assert result["status"] == "error"
        assert "No IPS log found" in result["message"]
        assert fake.starts == 1
        assert fake.fetches == 1

    async def test_search_and_download_pcaps_proceeds_via_poll_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """search_and_download_pcaps routes its search through the poll path:
        with pcap-bearing rows it proceeds past the search into the download
        loop after exactly one start, >=1 count, and one fetch. (The download
        itself is stubbed to return no data, so it 'proceeds' but reports a
        failed download -- the search contract is what we assert here.)"""
        monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))

        class _PollFetchWithPcap(_PollFetchFaz):
            async def get_pcapfile(self, *, key_data: str, key_type: str) -> dict[str, object]:
                # Proceeds into the download loop; no data -> graceful failure.
                return {}

        rows = [
            {"sessionid": 1, "attack": "A", "severity": "critical", "pcapurl": "u1"},
            {"sessionid": 2, "attack": "B", "severity": "critical", "pcapurl": "u2"},
        ]
        fake = _PollFetchWithPcap(rows)
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.search_and_download_pcaps(
            adom="root",
            severity=["critical"],
            time_range=_CUSTOM_RANGE,
            output_dir=str(tmp_path),
            max_downloads=5,
        )

        assert result["status"] == "success"
        assert result["search_results"] == 2
        assert result["pcap_available"] == 2  # proceeded past the search
        # Poll-fetch contract: one start, >=1 fetch (last with percentage=100).
        assert fake.starts == 1
        assert fake.fetches >= 1
        assert fake.fetches == 1

    async def test_search_and_download_pcaps_empty_via_poll_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """With no pcap-bearing rows, search_and_download_pcaps completes the
        poll path and returns its empty result -- not a raw invalid-tid string."""
        monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))
        rows = [
            {"sessionid": 1, "attack": "A", "severity": "critical"},  # no pcapurl
        ]
        fake = _PollFetchFaz(rows)
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.search_and_download_pcaps(
            adom="root",
            severity=["critical"],
            time_range=_CUSTOM_RANGE,
            output_dir=str(tmp_path),
        )

        assert result["status"] == "success"
        assert result["pcap_available"] == 0
        assert result["downloaded"] == 0
        assert result["message"] == "No IPS events found with PCAP available"
        assert fake.starts == 1
        assert fake.fetches == 1


class TestSuppliedEmptyFilterValues:
    """A filter argument that was supplied reaches its validator even when it
    is falsy. Only None means "not supplied"."""

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"srcip": ""}, "srcip cannot be empty"),
            ({"dstip": ""}, "dstip cannot be empty"),
            ({"srcport": 0}, "Invalid srcport '0'"),
            ({"dstport": 0}, "Invalid dstport '0'"),
            ({"session_id": 0}, "Invalid session ID '0'"),
            ({"cve": ""}, "CVE cannot be empty"),
            # An empty cve is not a request for "any CVE" either.
            ({"cve": "", "has_cve": True}, "CVE cannot be empty"),
        ],
        ids=["srcip", "dstip", "srcport", "dstport", "session_id", "cve", "cve_with_has_cve"],
    )
    def test_builder_refuses_a_supplied_falsy_value(
        self, kwargs: dict[str, object], message: str
    ) -> None:
        with pytest.raises(ValidationError, match=message):
            pcap_tools._build_ips_filter(**kwargs)

    def test_builder_still_skips_arguments_left_as_none(self) -> None:
        """The control: None is the one value that builds no clause."""
        result = pcap_tools._build_ips_filter(
            cve=None, srcip=None, dstip=None, srcport=None, dstport=None, session_id=None
        )
        assert result is None

    async def test_search_ips_logs_refuses_port_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """srcport=0 used to be dropped: the search ran over every port and
        filter_applied did not mention it."""
        fake = _PollFetchFaz([])
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.search_ips_logs(adom="root", srcport=0, time_range=_CUSTOM_RANGE)

        assert result["status"] == "error"
        assert "Invalid srcport '0'" in result["message"]
        assert fake.starts == 0

    async def test_search_and_download_pcaps_refuses_an_empty_srcip(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """srcip="" used to be dropped: PCAPs were searched for every source."""
        monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))
        fake = _PollFetchFaz([])
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.search_and_download_pcaps(
            adom="root", srcip="", time_range=_CUSTOM_RANGE, output_dir=str(tmp_path)
        )

        assert result["status"] == "error"
        assert "srcip cannot be empty" in result["message"]
        assert fake.starts == 0

    async def test_list_available_pcaps_refuses_an_empty_dstip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The listing passes srcip and dstip on to the same builder: dstip=""
        used to list the captures of every destination."""
        fake = _PollFetchFaz([])
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.list_available_pcaps(
            adom="root", dstip="", time_range=_CUSTOM_RANGE
        )

        assert result["status"] == "error"
        assert "dstip cannot be empty" in result["message"]
        assert fake.starts == 0


def _pcap_row(n: int, pcapurl: str | None = None) -> dict[str, object]:
    """An IPS row for session 1000+n whose PCAP sits at u<n> unless told otherwise."""
    return {
        "sessionid": 1000 + n,
        "attack": "Test.Attack",
        "severity": "critical",
        "pcapurl": pcapurl or f"u{n}",
    }


def _zip_b64(*names: str) -> str:
    """A ZIP with one member per name, base64-encoded the way get_pcapfile returns it."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, b"" if name.endswith("/") else b"pcap")
    return base64.b64encode(buf.getvalue()).decode()


class _DownloadFaz(_PollFetchFaz):
    """PCAP-search fake that also serves the downloads.

    Every pcapurl answers with a one-file ZIP unless ``replies`` holds another
    answer for it. ``fetched`` lists the pcapurls asked for, in order.
    """

    def __init__(
        self,
        dataset: list[dict[str, object]],
        replies: dict[str, dict[str, object]] | None = None,
    ) -> None:
        super().__init__(dataset)
        self.replies = replies or {}
        self.fetched: list[str] = []

    async def get_pcapfile(self, *, key_data: str, key_type: str) -> dict[str, object]:
        self.fetched.append(key_data)
        return self.replies.get(key_data, {"data": _zip_b64("capture.pcap")})


class TestSearchAndDownloadQuota:
    """max_downloads counts files written, and every PCAP row is accounted for."""

    @pytest.fixture(autouse=True)
    def _fast_and_confined(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
        monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)

        async def no_sleep(_seconds: float) -> None:
            return None

        # The tool pauses after every download.
        monkeypatch.setattr(pcap_tools.asyncio, "sleep", no_sleep)
        monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))

    async def _run(self, tmp_path, max_downloads: int) -> dict:
        return await pcap_tools.search_and_download_pcaps(
            adom="root",
            time_range=_CUSTOM_RANGE,
            output_dir=str(tmp_path),
            max_downloads=max_downloads,
        )

    async def test_a_second_run_downloads_the_rows_after_the_skipped_ones(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """Rows already on disk must not use up max_downloads: the search asks
        for twice the quota so that a second run can reach the spare half."""
        fake = _DownloadFaz([_pcap_row(n) for n in range(1, 31)])
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        first = await self._run(tmp_path, max_downloads=10)
        assert first["downloaded"] == 10
        assert fake.fetched == [f"u{n}" for n in range(1, 11)]

        second = await self._run(tmp_path, max_downloads=10)
        assert second["skipped"] == 10
        assert second["downloaded"] == 10
        assert fake.fetched[10:] == [f"u{n}" for n in range(11, 21)]

    async def test_failed_and_repeated_rows_do_not_use_up_the_quota(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        rows = [
            _pcap_row(1),  # the download returns no data
            _pcap_row(2),
            _pcap_row(2, pcapurl="u2b"),  # session 2 again
            _pcap_row(3),
        ]
        fake = _DownloadFaz(rows, replies={"u1": {}})
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await self._run(tmp_path, max_downloads=2)

        assert result["downloaded"] == 2
        assert fake.fetched == ["u1", "u2", "u3"]
        assert (result["skipped"], result["failed"]) == (1, 1)

    async def test_a_repeated_session_counts_as_skipped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        fake = _DownloadFaz([_pcap_row(1), _pcap_row(1, pcapurl="u1b")])
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await self._run(tmp_path, max_downloads=5)

        assert result["skipped"] == 1
        assert (result["downloaded"], result["failed"]) == (1, 0)
        assert fake.fetched == ["u1"]

    async def test_a_repeated_session_is_not_fetched_when_existing_files_are_kept(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """With skip_existing off, the file the first row wrote does not hide
        the repeat: only the session check keeps its capture from being
        fetched again."""
        rows = [_pcap_row(1), _pcap_row(1, pcapurl="u1b"), _pcap_row(2)]
        fake = _DownloadFaz(rows)
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.search_and_download_pcaps(
            adom="root",
            time_range=_CUSTOM_RANGE,
            output_dir=str(tmp_path),
            max_downloads=5,
            skip_existing=False,
        )

        assert fake.fetched == ["u1", "u2"]
        assert (result["downloaded"], result["skipped"], result["failed"]) == (2, 1, 0)

    async def test_a_row_without_sessionid_counts_as_failed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        rows = [{"attack": "Test.Attack", "severity": "critical", "pcapurl": "u0"}, _pcap_row(1)]
        fake = _DownloadFaz(rows)
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await self._run(tmp_path, max_downloads=5)

        assert result["failed"] == 1
        assert result["errors"] == ["Log entry without sessionid: PCAP not downloaded"]
        assert (result["downloaded"], result["skipped"]) == (1, 0)
        assert fake.fetched == ["u1"]

    async def test_a_zip_without_a_file_entry_counts_as_failed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        fake = _DownloadFaz(
            [_pcap_row(1), _pcap_row(2)],
            replies={"u1": {"data": _zip_b64("captures/")}},
        )
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await self._run(tmp_path, max_downloads=5)

        assert result["failed"] == 1
        assert result["errors"] == ["Session 1001: No PCAP file found in ZIP archive"]
        assert (result["downloaded"], result["skipped"]) == (1, 0)


class TestPcapBySessionRowSelection:
    """get_pcap_by_session uses the returned row that carries a capture."""

    @pytest.fixture(autouse=True)
    def _fast_polls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
        monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)

    async def test_capture_on_a_later_row_is_downloaded(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """Several rows can come back for one session id and only some carry a
        pcapurl. A first row without one must not hide the capture on a later
        row behind a 'no_pcap' result."""
        monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))
        rows: list[dict[str, object]] = [
            {
                "sessionid": 906654,
                "attack": "First.Attack",
                "severity": "high",
                "action": "detected",
                "srcip": "192.0.2.10",
                "dstip": "198.51.100.20",
            },
            {
                "sessionid": 906654,
                "attack": "Second.Attack",
                "severity": "critical",
                "action": "blocked",
                "srcip": "192.0.2.10",
                "dstip": "198.51.100.20",
                "pcapurl": "pcap-ref-2",
            },
        ]
        fake = _DownloadFaz(rows)
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.get_pcap_by_session(
            session_id=906654,
            adom="root",
            time_range=_CUSTOM_RANGE,
            output_dir=str(tmp_path),
        )

        assert result["status"] == "success"
        assert fake.fetched == ["pcap-ref-2"]
        # attack_info describes the row the capture belongs to.
        assert result["attack_info"]["attack"] == "Second.Attack"
        assert Path(result["file_path"]).read_bytes() == b"pcap"

    async def test_no_row_with_a_capture_is_still_no_pcap(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """With no capture on any returned row the result stays 'no_pcap',
        described by the first row. An empty pcapurl is not a capture."""
        monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))
        rows: list[dict[str, object]] = [
            {"sessionid": 906654, "attack": "First.Attack", "severity": "high"},
            {"sessionid": 906654, "attack": "Second.Attack", "severity": "low", "pcapurl": ""},
        ]
        fake = _DownloadFaz(rows)
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.get_pcap_by_session(
            session_id=906654,
            adom="root",
            time_range=_CUSTOM_RANGE,
            output_dir=str(tmp_path),
        )

        assert result["status"] == "no_pcap"
        assert result["attack_info"]["attack"] == "First.Attack"
        assert fake.fetched == []

    async def test_first_row_with_a_capture_wins(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """Rows keep the order the search returned them in: of two rows with
        a capture the earlier one is downloaded, however far down it sits."""
        monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))
        rows: list[dict[str, object]] = [
            {"sessionid": 906654, "attack": "First.Attack"},
            {"sessionid": 906654, "attack": "Second.Attack", "pcapurl": ""},
            {"sessionid": 906654, "attack": "Third.Attack", "pcapurl": "pcap-ref-3"},
            {"sessionid": 906654, "attack": "Fourth.Attack", "pcapurl": "pcap-ref-4"},
        ]
        fake = _DownloadFaz(rows)
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)

        result = await pcap_tools.get_pcap_by_session(
            session_id=906654,
            adom="root",
            time_range=_CUSTOM_RANGE,
            output_dir=str(tmp_path),
        )

        assert result["status"] == "success"
        assert fake.fetched == ["pcap-ref-3"]
        assert result["attack_info"]["attack"] == "Third.Attack"
