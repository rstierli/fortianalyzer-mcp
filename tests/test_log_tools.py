"""Tests for FortiAnalyzer log tools.

Tests the client methods for log search and analysis operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

from typing import Any

import pytest

import fortianalyzer_mcp.tools.fortiview_tools as fortiview_tools
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


class TestQueryLogsProjection:
    """fields selects; the response says what it selected."""

    CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"

    class _Faz:
        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

    def _install(self, monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, Any]]) -> None:
        async def fake_page(client: object, **kwargs: object) -> dict[str, object]:
            return {"timed_out": False, "tid": 7, "logs": rows, "total": len(rows)}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

    ROW = {
        "date": "2024-01-01",
        "time": "00:00:01",
        "srcip": "10.0.0.1",
        "dstport": 443,
        "sessionid": 99,
        "noise": "unused",
        "another_noise": "also unused",
    }

    async def test_default_applies_the_curated_projection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await log_tools.query_logs(logtype="traffic", time_range=self.CUSTOM_RANGE)

        row = result["logs"][0]
        # Keys and non-PII values only. `srcip` is an IP-typed field, so its
        # value is rewritten by the arg unmasker under MASKING_ENABLED; the
        # projection question is which keys survived, which is flag-independent.
        assert "noise" not in row
        assert "another_noise" not in row
        assert "srcip" in row, "identity must survive the default"
        assert row["dstport"] == 443, "a real value, not a null-padded key"
        assert "sessionid" in row, "join key must survive the default"

    async def test_star_returns_the_full_row(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, fields=["*"]
        )

        assert result["logs"][0]["noise"] == "unused"
        assert result["fields_returned"] == sorted(self.ROW)

    async def test_explicit_fields_select_exactly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, fields=["srcip", "dstport"]
        )

        assert result["logs"][0].keys() == {"srcip", "dstport"}
        assert result["logs"][0]["dstport"] == 443
        assert result["fields_returned"] == ["dstport", "srcip"]

    async def test_alias_in_fields_resolves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, fields=["source_ip"]
        )

        assert result["fields_returned"] == ["srcip"]

    async def test_fields_returned_survives_a_zero_row_page(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The signal matters most when there is nothing else to go on."""
        self._install(monkeypatch, [])

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, fields=["srcip", "dstport"]
        )

        assert result["logs"] == []
        assert result["fields_returned"] == ["dstport", "srcip"]

    async def test_uncurated_logtype_returns_full_rows_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [{"a": 1, "b": 2}])

        result = await log_tools.query_logs(logtype="voip", time_range=self.CUSTOM_RANGE)

        assert result["logs"] == [{"a": 1, "b": 2}]
        assert any("fields" in w for w in result["warnings"])

    async def test_empty_fields_list_is_a_validation_error(self) -> None:
        result = await log_tools.query_logs(logtype="traffic", fields=[])

        assert result["status"] == "error"
        assert result["error"] == "validation_error"


class TestFetchMoreLogsProjection:
    """Page 2 keeps page 1's shape unless the caller asks otherwise."""

    async def test_stored_projection_is_reused_when_fields_is_omitted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [{"srcip": "10.0.0.1", "dstport": 443, "noise": "x"}]

        class _Faz:
            async def ensure_connected(self) -> None:
                return None

            async def get_system_timezone(self) -> None:
                return None

        async def fake_page(client: object, **kwargs: object) -> dict[str, object]:
            return {"timed_out": False, "tid": 7, "logs": rows, "total": 50}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: _Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        first = await log_tools.query_logs(
            logtype="traffic",
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
            fields=["srcip", "dstport"],
        )
        handle = first["tid"]

        second = await log_tools.fetch_more_logs(tid=handle, offset=1)

        assert "noise" not in second["logs"][0]
        assert second["fields_returned"] == ["dstport", "srcip"]

    async def test_fields_on_the_page_call_overrides_the_stored_projection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [{"srcip": "10.0.0.1", "dstport": 443, "noise": "x"}]

        class _Faz:
            async def ensure_connected(self) -> None:
                return None

            async def get_system_timezone(self) -> None:
                return None

        async def fake_page(client: object, **kwargs: object) -> dict[str, object]:
            return {"timed_out": False, "tid": 7, "logs": rows, "total": 50}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: _Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        first = await log_tools.query_logs(
            logtype="traffic",
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
            fields=["srcip"],
        )

        second = await log_tools.fetch_more_logs(tid=first["tid"], offset=1, fields=["dstport"])

        assert second["fields_returned"] == ["dstport"]


class TestQueryLogsAggregationModes:
    """Four modes, mutually exclusive, each labelled for what it is."""

    CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"
    ROWS = [
        {"app": "HTTPS", "proto": "6", "dstport": "443"},
        {"app": "HTTPS", "proto": "6", "dstport": "443"},
        {"app": "HTTP", "proto": "6", "dstport": "80"},
    ]

    class _Faz:
        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

    def _install(self, monkeypatch: pytest.MonkeyPatch, total: int | None = 3) -> None:
        async def fake_page(client: object, **kwargs: object) -> dict[str, object]:
            return {
                "timed_out": False,
                "tid": 11,
                "logs": [dict(r) for r in TestQueryLogsAggregationModes.ROWS],
                "total": total,
            }

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

    async def test_sample_by_returns_labelled_breakdowns_and_no_rows(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, sample_by=["app"]
        )

        assert "logs" not in result, "aggregation modes suppress raw rows"
        assert result["breakdowns"]["app"][0] == {"value": "HTTPS", "hits": 2}
        assert result["analysis_mode"] in ("bounded_sample", "exact")
        assert "is_exact" in result
        assert "total_hits_is_known" in result

    async def test_sample_by_accepts_several_dimensions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, sample_by=["app", "port"]
        )

        assert set(result["breakdowns"]) == {"app", "port"}

    async def test_sample_by_top_n_zero_keeps_every_bucket(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, sample_by=["app"], top_n=0
        )

        assert len(result["breakdowns"]["app"]) == 2

    async def test_count_only_returns_a_total_and_no_rows(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, count_only=True
        )

        assert "logs" not in result
        assert result["total"] == 3
        assert result["total_is_known"] is True
        assert result["count_source"]

    async def test_count_only_is_honest_when_the_appliance_gave_no_total(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, total=None)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, count_only=True
        )

        assert result["total_is_known"] is False

    async def test_group_by_and_sample_by_together_conflict(self) -> None:
        result = await log_tools.query_logs(logtype="traffic", group_by="srcip", sample_by=["app"])

        assert result["status"] == "error"
        assert result["error"] == "conflicting_aggregation"

    async def test_count_only_with_sample_by_conflicts(self) -> None:
        result = await log_tools.query_logs(logtype="traffic", sample_by=["app"], count_only=True)

        assert result["error"] == "conflicting_aggregation"

    async def test_an_unsupported_group_dimension_names_sample_by(self) -> None:
        result = await log_tools.query_logs(logtype="traffic", group_by="sentbyte")

        assert result["status"] == "error"
        assert result["error"] == "unsupported_group_dimension"
        assert "sample_by" in result["message"]

    async def test_a_dimension_whose_view_reads_other_logs_is_refused(self) -> None:
        """logtype="attack", group_by="srcip" dispatched to top-sources -- a
        traffic-log view -- and returned is_exact: true beside an echoed
        logtype: "attack". Exact counts, wrong population."""
        result = await log_tools.query_logs(logtype="attack", group_by="srcip")

        assert result["status"] == "error"
        assert result["error"] == "group_dimension_logtype_mismatch"
        assert "sample_by=['srcip']" in result["message"]
        assert "sample_by=['srcip']" in result["recommendation"]
        assert "top-sources" in result["message"]
        # No group answer of any kind came back with the refusal.
        assert "groups" not in result
        assert "is_exact" not in result

    async def test_the_two_group_refusals_carry_different_codes(self) -> None:
        """'never groupable' and 'not groupable for this logtype' are
        different facts; only the second is fixed by changing logtype."""
        never = await log_tools.query_logs(logtype="attack", group_by="sentbyte")
        wrong_logtype = await log_tools.query_logs(logtype="attack", group_by="srcip")

        assert never["error"] == "unsupported_group_dimension"
        assert wrong_logtype["error"] == "group_dimension_logtype_mismatch"

    async def test_a_logtype_no_view_serves_is_refused_for_every_dimension(self) -> None:
        for dimension in ("srcip", "dstip", "app", "hostname", "attack", "policyid"):
            result = await log_tools.query_logs(logtype="event", group_by=dimension)
            assert result["status"] == "error", dimension
            assert "sample_by" in result["message"], dimension

    # Include this test ONLY if Task 0 put you on the refusal branch -- i.e. the
    # probe found filters silently ignored for the target view, or you had no
    # appliance and took the conservative fallback. If Task 0 proved the view
    # honours filters, delete this test and assert the forwarding instead:
    # that the fake's fortiview_run received the compiled filter string.
    async def test_group_by_with_a_filter_is_refused_when_unverified(self) -> None:
        """An ignored filter would return an unfiltered top-N under is_exact."""
        result = await log_tools.query_logs(
            logtype="traffic", group_by="srcip", filter="dstport==443"
        )

        assert result["status"] == "error"
        assert result["error"] == "unsupported_view_filter"
        assert "sample_by" in result["recommendation"]

    async def test_fields_with_an_aggregation_warns_rather_than_erroring(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """fields describes a row shape no rows will be returned in."""
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic",
            time_range=self.CUSTOM_RANGE,
            sample_by=["app"],
            fields=["srcip"],
        )

        assert result["status"] == "success"
        assert any("fields" in w for w in result["warnings"])

    async def test_rows_mode_is_unchanged_when_no_aggregation_is_asked_for(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(logtype="traffic", time_range=self.CUSTOM_RANGE)

        assert "logs" in result
        assert "breakdowns" not in result


class TestQueryLogsGroupByDispatch:
    """The group_by success path: FortiView dispatch and its resolved window.

    query_logs resolves its own window via the log-clock-anchored
    resolve_time_window and must thread that exact {start, end} into the
    FortiView call -- not let get_fortiview_data's own FAZ-system-tz "now"
    anchor re-resolve it a second, potentially different way. These tests
    mock at the fortiview_tools boundary (_get_fortiview_data_impl, the
    function log_tools calls directly) rather than the client, so the
    assertions can inspect the exact kwargs query_logs passed across that
    boundary.
    """

    CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"
    RESOLVED_WINDOW = {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}

    class _Faz:
        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

    def _install_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())

    async def test_group_by_threads_the_resolved_window_into_the_fortiview_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install_client(monkeypatch)
        calls: list[dict[str, object]] = []

        async def fake_impl(**kwargs: object) -> dict[str, object]:
            calls.append(kwargs)
            return {
                "status": "success",
                "data": [{"app": "HTTPS", "sessions": 4}, {"app": "HTTP", "sessions": 1}],
            }

        monkeypatch.setattr(fortiview_tools, "_get_fortiview_data_impl", fake_impl)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="app"
        )

        assert result["status"] == "success"
        assert result["group_by"] == "app"
        assert result["groups"] == [{"app": "HTTPS", "sessions": 4}, {"app": "HTTP", "sessions": 1}]
        assert result["group_source"] == "fortiview:top-applications"
        assert result["is_exact"] is True
        assert result["time_range"] == self.RESOLVED_WINDOW

        # Exactly the window the response echoes -- not a second, independently
        # re-resolved one -- reached the FortiView call.
        assert len(calls) == 1
        assert calls[0]["view_name"] == "top-applications"
        assert calls[0]["tr"] == self.RESOLVED_WINDOW
        assert calls[0]["tr"] == result["time_range"]
        assert calls[0]["field_names"] == ["*"]
        # The token query_logs hands over. What the appliance actually receives
        # is one layer further down and is asserted in
        # TestQueryLogsGroupByDeviceFilter -- this assertion alone passed while
        # build_device_filter was re-encoding the token as devid: All_Device.
        assert calls[0]["device"] == "All_Device"

    async def test_a_logtype_specific_dimension_dispatches_under_its_own_logtype(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The population boundary refuses pairings; it must not break the
        pairings that are correct."""
        self._install_client(monkeypatch)
        calls: list[dict[str, object]] = []

        async def fake_impl(**kwargs: object) -> dict[str, object]:
            calls.append(kwargs)
            return {"status": "success", "data": [{"hostname": "example.test", "sessions": 2}]}

        monkeypatch.setattr(fortiview_tools, "_get_fortiview_data_impl", fake_impl)

        result = await log_tools.query_logs(
            logtype="webfilter", time_range=self.CUSTOM_RANGE, group_by="hostname"
        )

        assert result["status"] == "success"
        assert result["group_source"] == "fortiview:top-websites"
        assert result["is_exact"] is True
        assert calls[0]["view_name"] == "top-websites"

    async def test_a_full_length_ranking_is_flagged_rather_than_silently_capped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`limit` doubles as the top-N cap here, so a full list may be cut."""
        self._install_client(monkeypatch)

        async def fake_impl(**kwargs: object) -> dict[str, object]:
            return {
                "status": "success",
                "data": [{"srcip": f"10.0.0.{n}", "sessions": 10 - n} for n in range(3)],
            }

        monkeypatch.setattr(fortiview_tools, "_get_fortiview_data_impl", fake_impl)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="srcip", limit=3
        )

        assert result["group_limit"] == 3
        assert result["groups_truncated"] is True
        assert any("top 3 groups" in w for w in result["warnings"])
        # The cap hides groups, not accuracy: every count returned is still
        # the appliance's own.
        assert result["is_exact"] is True

    async def test_a_short_ranking_is_not_flagged_as_truncated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install_client(monkeypatch)

        async def fake_impl(**kwargs: object) -> dict[str, object]:
            return {"status": "success", "data": [{"srcip": "10.0.0.1", "sessions": 4}]}

        monkeypatch.setattr(fortiview_tools, "_get_fortiview_data_impl", fake_impl)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="srcip", limit=50
        )

        assert result["groups_truncated"] is False
        assert result["group_limit"] == 50
        assert not any("groups" in w for w in result["warnings"])

    async def test_group_by_dispatch_failure_gets_the_full_query_logs_envelope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-success FortiView result must not pass through unwrapped."""
        self._install_client(monkeypatch)

        async def fake_impl(**kwargs: object) -> dict[str, object]:
            return {
                "status": "timeout",
                "tid": 999,
                "message": "FortiView query timed out after 30s",
            }

        monkeypatch.setattr(fortiview_tools, "_get_fortiview_data_impl", fake_impl)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="app"
        )

        assert result["status"] == "error"
        assert result["error"] == "search_timeout"
        assert result["operation"] == "query_logs"
        assert "retry_count" in result
        assert "timed out" in result["message"]


class TestAggregationPathWarnings:
    """``build_warnings`` is the rows-path builder, and two of its four
    conditions are not about rows: the limit clamp bounds a grouping's top-N and
    a sample's row scan exactly as it bounds a page, and FAZ interprets a naive
    window in its own timezone whatever the query returns. Only the rows path
    emitted them, so a caller who passed ``limit=5000`` to ``sample_by`` was
    answered from 1000 scanned rows with nothing saying so.

    The other two conditions stay out on purpose, and the last test here is what
    keeps them out: a bare count reports ``total_is_known`` structurally, and
    "aggregate instead of paging rows" is absurd advice to someone aggregating.
    """

    CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"

    class _Faz:
        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

    def _install_rows(
        self, monkeypatch: pytest.MonkeyPatch, total: int | None = 3, row_count: int = 3
    ) -> None:
        async def fake_page(client: object, **kwargs: object) -> dict[str, object]:
            return {
                "timed_out": False,
                "tid": 11,
                "logs": [{"app": "HTTPS"} for _ in range(row_count)],
                "total": total,
            }

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

    def _install_view(self, monkeypatch: pytest.MonkeyPatch, group_count: int) -> None:
        async def fake_impl(**kwargs: object) -> dict[str, object]:
            return {
                "status": "success",
                "data": [{"app": f"app-{n}", "sessions": 1} for n in range(group_count)],
            }

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(fortiview_tools, "_get_fortiview_data_impl", fake_impl)

    @staticmethod
    def _clamp_notice(warnings: list[str]) -> str | None:
        return next((w for w in warnings if "was clamped to" in w), None)

    async def test_group_by_names_both_numbers_when_the_limit_was_clamped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install_view(monkeypatch, group_count=1000)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="app", limit=5000
        )

        notice = self._clamp_notice(result["warnings"])
        assert notice is not None, "a clamped group cap was reported by nothing"
        assert "5000" in notice and "1000" in notice
        # The echo is the cap actually applied, not the one asked for.
        assert result["group_limit"] == 1000
        assert result["groups_truncated"] is True

    async def test_a_ranking_cut_at_the_ceiling_does_not_blame_the_caller(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The old message called 1000 "the cap `limit` set" to a caller who set
        5000, then told them to raise it to a maximum they had already exceeded."""
        self._install_view(monkeypatch, group_count=1000)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="app", limit=5000
        )

        cut = next(w for w in result["warnings"] if "top 1000 groups" in w)
        assert "the cap `limit` set" not in cut
        assert "Raise limit" not in cut
        assert "the most this server requests" in cut
        assert "Each count shown is still exact." in cut

    async def test_a_ranking_cut_below_the_ceiling_still_advises_raising_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Where raising `limit` IS the remedy, it must still be offered."""
        self._install_view(monkeypatch, group_count=3)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="app", limit=3
        )

        cut = next(w for w in result["warnings"] if "top 3 groups" in w)
        assert "Raise limit (max 1000)" in cut
        assert self._clamp_notice(result["warnings"]) is None, "nothing was clamped"

    async def test_sample_by_reports_the_clamp_that_bounded_its_scan(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install_rows(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, sample_by=["app"], limit=5000
        )

        notice = self._clamp_notice(result["warnings"])
        assert notice is not None and "5000" in notice
        # The structured echo already agreed with the clamp; the prose now does.
        assert result["log_limit_per_slice"] == 1000

    async def test_count_only_reports_the_clamp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install_rows(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, count_only=True, limit=5000
        )

        assert self._clamp_notice(result["warnings"]) is not None

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"group_by": "app"},
            {"sample_by": ["app"]},
            {"count_only": True},
        ],
        ids=["group_by", "sample_by", "count_only"],
    )
    async def test_an_undetected_timezone_is_reported_on_every_path(
        self, monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, object]
    ) -> None:
        """FAZ reads a naive window in its own timezone, so an undetected one is
        a caveat on the window -- which every mode here has."""
        if "group_by" in kwargs:
            self._install_view(monkeypatch, group_count=2)
        else:
            self._install_rows(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, **kwargs
        )

        assert result["timezone"] == "unknown"
        assert any("timezone could not be detected" in w for w in result["warnings"])

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"group_by": "app"},
            {"sample_by": ["app"]},
            {"count_only": True},
        ],
        ids=["group_by", "sample_by", "count_only"],
    )
    async def test_no_aggregation_path_advises_aggregating(
        self, monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, object]
    ) -> None:
        """The rows-path high-volume advisory names group_by/sample_by as the
        remedy. Emitted here it would tell a caller to do what they just did."""
        if "group_by" in kwargs:
            self._install_view(monkeypatch, group_count=2)
        else:
            self._install_rows(monkeypatch, total=50_000, row_count=100)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, limit=100, **kwargs
        )

        assert not any("Aggregate instead of paging rows" in w for w in result["warnings"])


class TestQueryLogsGroupByDeviceFilter:
    """What reaches ``client.fortiview_run``, not what reaches the helper.

    The device token is translated twice on the ``group_by`` path -- once by
    ``GroupPlan.all_devices_group`` and once by
    ``build_fortiview_device_filter`` -- and only the second one produces the
    payload FortiAnalyzer sees. Asserting the string ``query_logs`` handed to
    ``_get_fortiview_data_impl`` (as ``TestQueryLogsGroupByDispatch`` does)
    passed cleanly while that helper re-encoded ``All_Device`` through
    logview's ``build_device_filter`` as ``[{"devid": "All_Device"}]`` -- a
    spelling FortiView answers with an empty top-N and no error, i.e. "no
    traffic" under ``is_exact: true``.

    So these tests mock the *client*, one layer below every translation.
    """

    CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"
    RESOLVED_WINDOW = {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}

    class _Faz:
        def __init__(self) -> None:
            self.run_calls: list[dict[str, Any]] = []

        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

        async def fortiview_run(self, **kwargs: Any) -> dict[str, Any]:
            self.run_calls.append(kwargs)
            return {"tid": 4242}

        async def fortiview_fetch(self, **kwargs: Any) -> dict[str, Any]:
            return {"percentage": 100, "data": [{"srcip": "10.0.0.1", "sessions": 7}]}

    def _install(self, monkeypatch: pytest.MonkeyPatch) -> "TestQueryLogsGroupByDeviceFilter._Faz":
        faz = self._Faz()
        monkeypatch.setattr(log_tools, "get_faz_client", lambda: faz)
        return faz

    async def test_the_default_reaches_the_client_as_fortiviews_own_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        faz = self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="srcip"
        )

        assert result["status"] == "success"
        assert len(faz.run_calls) == 1
        assert faz.run_calls[0]["device"] == [{"devname": "All_Device"}]

    async def test_the_resolved_window_reaches_the_client_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The window the response echoes is the window FortiView scanned."""
        faz = self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="srcip"
        )

        assert faz.run_calls[0]["time_range"] == self.RESOLVED_WINDOW
        assert faz.run_calls[0]["time_range"] == result["time_range"]

    @pytest.mark.parametrize("token", ["All_FortiGate", "All_FortiMail", "All_Device"])
    async def test_every_all_devices_spelling_is_translated(
        self, monkeypatch: pytest.MonkeyPatch, token: str
    ) -> None:
        """query_logs' own docstring advertises All_FortiGate; forwarded
        verbatim it is an empty top-N with no error."""
        faz = self._install(monkeypatch)

        await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="srcip", device=token
        )

        assert faz.run_calls[0]["device"] == [{"devname": "All_Device"}]

    async def test_a_named_device_is_sent_as_devname(self, monkeypatch: pytest.MonkeyPatch) -> None:
        faz = self._install(monkeypatch)

        await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, group_by="srcip", device="FGT1"
        )

        assert faz.run_calls[0]["device"] == [{"devname": "FGT1"}]

    async def test_a_serial_is_still_sent_as_devid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A serial under devname silently matches nothing; only the
        all-devices case is translated."""
        faz = self._install(monkeypatch)

        await log_tools.query_logs(
            logtype="traffic",
            time_range=self.CUSTOM_RANGE,
            group_by="srcip",
            device="FG100FTK19001333",
        )

        assert faz.run_calls[0]["device"] == [{"devid": "FG100FTK19001333"}]
