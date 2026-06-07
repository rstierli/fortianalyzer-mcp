"""Tests for FortiAnalyzer traffic analysis tools.

Tests validation functions, aggregation logic, and tool behavior
without triggering server initialization.
"""

import pytest

import fortianalyzer_mcp.tools.traffic_tools as traffic_tools
from fortianalyzer_mcp.tools.traffic_tools import (
    ANALYSIS_QUERY_BUDGET,
    LOG_FETCH_LIMIT,
    VALID_ACTIONS,
    _aggregate_port_analysis,
    _aggregate_protocol_summary,
    _aggregate_traffic_profile,
    _bounded_metadata,
    _build_bounded_time_slices,
    _build_policy_filter,
    _coerce_log_total,
    _plan_policy_slice_count,
    _query_policy_log_slice,
    _query_policy_total_count,
    sanitize_filter_value,
    validate_action,
    validate_policy_ids,
)
from fortianalyzer_mcp.utils.validation import ValidationError


async def _noop_sleep(_seconds: float) -> None:
    """Async no-op to skip real polling delays in slice-reliability tests."""


@pytest.fixture(autouse=True)
def _default_connected_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default a connected fake client so the policy driver's ensure_connected()
    succeeds in tests that mock the query layer. Tests needing specific client
    behavior override _get_client in their own body (which wins)."""

    class _ConnectedClient:
        @property
        def is_connected(self) -> bool:
            return True

        async def ensure_connected(self) -> None:
            return None

    monkeypatch.setattr(traffic_tools, "_get_client", lambda: _ConnectedClient())


# =============================================================================
# Validation: validate_action
# =============================================================================


class TestValidateAction:
    """Tests for action validation."""

    def test_valid_actions(self) -> None:
        """All allowed actions should pass validation."""
        for action in VALID_ACTIONS:
            assert validate_action(action) == action

    def test_none_action(self) -> None:
        """None action should return None."""
        assert validate_action(None) is None

    def test_action_case_insensitive(self) -> None:
        """Action validation should be case-insensitive."""
        assert validate_action("ACCEPT") == "accept"
        assert validate_action("Deny") == "deny"

    def test_action_stripped(self) -> None:
        """Action should be stripped of whitespace."""
        assert validate_action("  accept  ") == "accept"

    def test_invalid_action(self) -> None:
        """Invalid action should raise ValidationError."""
        with pytest.raises(ValidationError, match="Invalid action"):
            validate_action("allow")

    def test_action_with_spaces(self) -> None:
        """Action with embedded spaces should be rejected (injection attempt)."""
        with pytest.raises(ValidationError, match="Invalid action"):
            validate_action("accept or 1==1")

    def test_action_with_operators(self) -> None:
        """Action with filter operators should be rejected."""
        with pytest.raises(ValidationError, match="Invalid action"):
            validate_action("accept==true")

    def test_empty_action(self) -> None:
        """Empty string action should be rejected."""
        with pytest.raises(ValidationError, match="Invalid action"):
            validate_action("")


# =============================================================================
# Validation: validate_policy_ids
# =============================================================================


class TestValidatePolicyIds:
    """Tests for policy ID validation."""

    def test_valid_single_id(self) -> None:
        """Single valid policy ID."""
        assert validate_policy_ids([1]) == [1]

    def test_valid_multiple_ids(self) -> None:
        """Multiple valid policy IDs."""
        assert validate_policy_ids([1, 5, 10]) == [1, 5, 10]

    def test_empty_list(self) -> None:
        """Empty list should raise ValidationError."""
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_policy_ids([])

    def test_zero_id(self) -> None:
        """Zero policy ID should be rejected."""
        with pytest.raises(ValidationError, match="positive integer"):
            validate_policy_ids([0])

    def test_negative_id(self) -> None:
        """Negative policy ID should be rejected."""
        with pytest.raises(ValidationError, match="positive integer"):
            validate_policy_ids([-1])

    def test_too_many_ids(self) -> None:
        """More than the query budget should be rejected."""
        ids = list(range(1, ANALYSIS_QUERY_BUDGET + 2))
        with pytest.raises(ValidationError, match="Too many policy IDs"):
            validate_policy_ids(ids)

    def test_max_ids_allowed(self) -> None:
        """Exactly the query budget should be accepted."""
        ids = list(range(1, ANALYSIS_QUERY_BUDGET + 1))
        assert validate_policy_ids(ids) == ids

    def test_bool_rejected(self) -> None:
        """Booleans must be rejected even though bool is an int subclass."""
        with pytest.raises(ValidationError, match="positive integer"):
            validate_policy_ids([True])


# =============================================================================
# Bounded analysis planning
# =============================================================================


class TestBoundedAnalysisPlanning:
    """Tests for fixed bounded query planning."""

    def test_24_hour_window_uses_one_slice(self) -> None:
        """Windows up to 24 hours should use one slice per policy."""
        time_range = {
            "start": "2024-01-01 00:00:00",
            "end": "2024-01-02 00:00:00",
        }
        assert _plan_policy_slice_count(time_range, policy_count=1) == 1

    def test_30_day_single_policy_uses_four_slices(self) -> None:
        """Large single-policy windows should use the maximum four slices."""
        time_range = {
            "start": "2024-01-01 00:00:00",
            "end": "2024-01-31 00:00:00",
        }
        assert _plan_policy_slice_count(time_range, policy_count=1) == 4

    def test_30_day_many_policies_stays_within_query_budget(self) -> None:
        """Many-policy large windows should stay within the logsearch query budget."""
        time_range = {
            "start": "2024-01-01 00:00:00",
            "end": "2024-01-31 00:00:00",
        }
        policy_count = 12
        slices = _plan_policy_slice_count(time_range, policy_count=policy_count)
        assert slices == 2
        assert slices * policy_count <= ANALYSIS_QUERY_BUDGET

    def test_bounded_slices_cover_window(self) -> None:
        """Fixed slices should preserve the requested first and last timestamps."""
        time_range = {
            "start": "2024-01-01 00:00:00",
            "end": "2024-01-31 00:00:00",
        }
        slices = _build_bounded_time_slices(time_range, 4)
        assert len(slices) == 4
        assert slices[0]["start"] == time_range["start"]
        assert slices[-1]["end"] == time_range["end"]


# =============================================================================
# Validation: sanitize_filter_value
# =============================================================================


class TestSanitizeFilterValue:
    """Tests for filter value sanitization."""

    def test_simple_alphanumeric(self) -> None:
        """Simple alphanumeric values pass through."""
        assert sanitize_filter_value("accept") == "accept"
        assert sanitize_filter_value("10.0.0.1") == "10.0.0.1"
        assert sanitize_filter_value("my-device") == "my-device"

    def test_value_with_spaces_gets_quoted(self) -> None:
        """Values with spaces should be quoted."""
        result = sanitize_filter_value("some value")
        assert result == '"some value"'

    def test_value_with_quotes_escaped(self) -> None:
        """Values with double quotes should be escaped."""
        result = sanitize_filter_value('say "hello"')
        assert result == '"say \\"hello\\""'

    def test_value_with_backslash_escaped(self) -> None:
        """Values with backslashes should be escaped."""
        result = sanitize_filter_value("path\\to")
        assert result == '"path\\\\to"'

    def test_injection_attempt_quoted(self) -> None:
        """Filter injection attempts should be safely quoted."""
        result = sanitize_filter_value("accept or 1==1")
        assert result == '"accept or 1==1"'

    def test_empty_value(self) -> None:
        """Empty value should raise ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            sanitize_filter_value("")

    def test_whitespace_only_value(self) -> None:
        """Whitespace-only value should raise ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            sanitize_filter_value("   ")

    def test_special_characters_quoted(self) -> None:
        """Values with special characters should be quoted."""
        result = sanitize_filter_value("value;drop")
        assert result.startswith('"')
        assert result.endswith('"')


# =============================================================================
# Filter building
# =============================================================================


class TestBuildPolicyFilter:
    """Tests for filter string construction."""

    def test_policy_only(self) -> None:
        """Filter with only policy ID."""
        assert _build_policy_filter(5) == "policyid==5"

    def test_policy_with_action(self) -> None:
        """Filter with policy ID and action."""
        result = _build_policy_filter(5, "accept")
        assert result == "policyid==5 and action==accept"

    def test_policy_with_none_action(self) -> None:
        """Filter with None action should not include action."""
        assert _build_policy_filter(10, None) == "policyid==10"


# =============================================================================
# Aggregation: traffic profile
# =============================================================================


class TestAggregateTrafficProfile:
    """Tests for traffic profile aggregation."""

    def test_empty_logs(self) -> None:
        """Empty log list should return zero counts."""
        result = _aggregate_traffic_profile([], 10)
        assert result["total_hits"] == 0
        assert result["top_ports"] == []
        assert result["top_services"] == []
        assert result["top_applications"] == []

    def test_basic_aggregation(self) -> None:
        """Basic aggregation of ports, services, apps."""
        logs = [
            {"dstport": 443, "proto": "6", "service": "HTTPS", "app": "SSL"},
            {"dstport": 443, "proto": "6", "service": "HTTPS", "app": "SSL"},
            {"dstport": 80, "proto": "6", "service": "HTTP", "app": "HTTP"},
        ]
        result = _aggregate_traffic_profile(logs, 10)
        assert result["total_hits"] == 3
        assert len(result["top_ports"]) == 2
        # Port 443 should be first (2 hits)
        assert result["top_ports"][0]["port"] == "6/443"
        assert result["top_ports"][0]["hits"] == 2

    def test_top_n_limiting(self) -> None:
        """top_n should limit the number of returned items."""
        logs = [{"dstport": i, "proto": "6", "service": f"svc-{i}"} for i in range(20)]
        result = _aggregate_traffic_profile(logs, 5)
        assert len(result["top_ports"]) == 5
        assert len(result["top_services"]) == 5

    def test_residual_calculation(self) -> None:
        """Residual should be total minus top hits."""
        logs = [
            {"dstport": 443, "proto": "6"},
            {"dstport": 443, "proto": "6"},
            {"dstport": 80, "proto": "6"},
            {"dstport": 22, "proto": "6"},
        ]
        result = _aggregate_traffic_profile(logs, 1)
        # top_n=1 should return port 443 with 2 hits
        assert result["top_ports"][0]["hits"] == 2
        assert result["top_ports_residual"] == 2  # 4 total - 2 top hits

    def test_missing_fields(self) -> None:
        """Logs with missing fields should not crash."""
        logs = [
            {"srcip": "10.0.0.1"},  # No dstport, service, app
            {"dstport": 443, "proto": "6"},  # No service, app
        ]
        result = _aggregate_traffic_profile(logs, 10)
        assert result["total_hits"] == 2
        assert len(result["top_ports"]) == 1
        assert result["top_services"] == []
        assert result["top_applications"] == []


# =============================================================================
# Aggregation: port analysis
# =============================================================================


class TestAggregatePortAnalysis:
    """Tests for port analysis aggregation."""

    def test_empty_logs(self) -> None:
        """Empty logs should return zero counts."""
        result = _aggregate_port_analysis([])
        assert result["total_hits"] == 0
        assert "is_exact" not in result  # Exactness set by _bounded_metadata
        assert result["ports"] == []
        assert result["protocols"] == []
        assert result["uncovered_port_hits"] == 0

    def test_aggregation_does_not_include_is_exact(self) -> None:
        """_aggregate_port_analysis should not set is_exact (caller's responsibility)."""
        logs = [{"dstport": 80, "proto": "6"} for _ in range(100)]
        result = _aggregate_port_analysis(logs)
        assert "is_exact" not in result
        assert result["total_hits"] == 100

    def test_basic_port_enumeration(self) -> None:
        """Basic port/protocol enumeration."""
        logs = [
            {"dstport": 443, "proto": "6"},
            {"dstport": 80, "proto": "6"},
            {"dstport": 53, "proto": "17"},
        ]
        result = _aggregate_port_analysis(logs)
        assert result["total_hits"] == 3
        assert len(result["ports"]) == 3
        assert result["uncovered_port_hits"] == 0

    def test_icmp_handling(self) -> None:
        """ICMP logs should be tracked via service field (FAZ format)."""
        logs = [
            # FAZ encodes ICMP echo as service=PING
            {"proto": "1", "dstport": 0, "service": "PING"},
            {"proto": "1", "dstport": 0, "service": "PING"},
            # FAZ encodes ICMP type/code as service=icmp/T/C
            {"proto": "1", "dstport": 0, "service": "icmp/3/3"},
        ]
        result = _aggregate_port_analysis(logs)
        assert result["total_hits"] == 3
        assert "1" in result["portless_protocols"]
        assert len(result["icmp"]) == 2
        # PING (type=8/code=0) should be most common
        assert result["icmp"][0]["type_code"] == "type=8/code=0"
        assert result["icmp"][0]["hits"] == 2
        # icmp/3/3 → type=3/code=3
        assert result["icmp"][1]["type_code"] == "type=3/code=3"
        assert result["icmp"][1]["hits"] == 1

    def test_portless_protocols(self) -> None:
        """Protocols without ports (GRE, ESP) should be tracked."""
        logs = [
            {"proto": "47", "dstport": 0},  # GRE
            {"proto": "50"},  # ESP, no dstport at all
        ]
        result = _aggregate_port_analysis(logs)
        assert "47" in result["portless_protocols"]
        assert "50" in result["portless_protocols"]
        assert result["uncovered_port_hits"] == 2

    def test_uncovered_port_hits(self) -> None:
        """Logs without destination ports count as uncovered."""
        logs = [
            {"dstport": 443, "proto": "6"},  # Has port
            {"proto": "1"},  # No port
        ]
        result = _aggregate_port_analysis(logs)
        assert result["uncovered_port_hits"] == 1


# =============================================================================
# Tool behavior: bounded policy analysis
# =============================================================================


class TestPolicyPortAnalysisToolBounded:
    """Tests for bounded tool behavior without live FortiAnalyzer access."""

    async def test_policy_slice_returns_logs_and_total_count(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Slice fetches should preserve FAZ total-count for the same filter/window."""

        class FakeClient:
            async def logsearch_start(self, **_kwargs: object) -> dict[str, int]:
                return {"tid": 123}

            async def logsearch_fetch(self, **_kwargs: object) -> dict[str, object]:
                return {
                    "percentage": 100,
                    "total-count": "25",
                    "data": [{"dstport": 443, "proto": "6"}],
                }

        monkeypatch.setattr(traffic_tools, "_get_client", lambda: FakeClient())

        result = await _query_policy_log_slice(
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            policy_id=2,
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-01 01:00:00"},
            action="accept",
        )

        assert result["logs"] == [{"dstport": 443, "proto": "6"}]
        assert result["total_hits"] == 25
        assert result["total_hits_is_known"] is True

    async def test_policy_total_count_uses_full_window_with_small_fetch(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Whole-window total queries should not depend on bounded slice totals."""
        calls = []

        async def fake_slice(*_args: object, **kwargs: object) -> dict[str, object]:
            calls.append(kwargs)
            return {
                "logs": [{"dstport": 443, "proto": "6"}],
                "total_hits": 12609,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

        result = await _query_policy_total_count(
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            policy_id=29,
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-31 00:00:00"},
            action="accept",
        )

        assert result == {"total_hits": 12609, "total_hits_is_known": True}
        assert calls[0]["time_range"] == {
            "start": "2024-01-01 00:00:00",
            "end": "2024-01-31 00:00:00",
        }
        assert calls[0]["limit"] == 1

    async def test_large_request_returns_bounded_result(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Large windows should return bounded observations instead of failing."""
        call_count = 0

        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "logs": [{"dstport": 443, "proto": "6"} for _ in range(LOG_FETCH_LIMIT)],
                    "total_hits": 2500,
                    "total_hits_is_known": True,
                }
            return {
                "logs": [{"dstport": 80, "proto": "6"}],
                "total_hits": 1,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

        async def fake_total(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {"total_hits": 2503, "total_hits_is_known": True}

        monkeypatch.setattr(traffic_tools, "_query_policy_total_count", fake_total)

        result = await traffic_tools.get_policy_port_analysis(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[2],
            time_range="2024-01-01 00:00:00|2024-01-31 00:00:00",
        )

        assert result["status"] == "success"
        analysis = result["results"][0]
        assert call_count == 4
        assert analysis["policy_id"] == 2
        assert analysis["is_exact"] is False
        assert analysis["analysis_mode"] == "bounded_sample"
        assert analysis["observed_hits"] == LOG_FETCH_LIMIT + 3
        assert analysis["slices_scanned"] == 4
        assert analysis["truncated_slices"] == 1
        assert analysis["log_limit_per_slice"] == LOG_FETCH_LIMIT
        assert analysis["total_hits"] == 2503
        assert analysis["total_hits_is_known"] is True
        assert analysis["total_hit_source"] == "logsearch_total-count"
        assert "estimated_total_hits" not in analysis
        assert "estimate_available" not in analysis
        assert "recommendation" in analysis

    async def test_bounded_result_uses_whole_window_total_count(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Bounded metadata should not sum inflated per-slice totals."""

        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "logs": [{"dstport": 161, "proto": "17"}],
                "total_hits": 14000,
                "total_hits_is_known": True,
            }

        async def fake_total(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {"total_hits": 12609, "total_hits_is_known": True}

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)
        monkeypatch.setattr(traffic_tools, "_query_policy_total_count", fake_total, raising=False)

        result = await traffic_tools.get_policy_port_analysis(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[29],
            time_range="2024-01-01 00:00:00|2024-01-31 00:00:00",
            action="accept",
        )

        assert result["status"] == "success"
        analysis = result["results"][0]
        assert analysis["total_hits"] == 12609
        assert analysis["total_hits_is_known"] is True
        assert analysis["total_hit_source"] == "logsearch_total-count"
        assert analysis["observed_hits"] == 4
        assert analysis["ports"] == [{"port": "17/161", "hits": 4}]
        # An authoritative total that dwarfs the observed rows must NOT be
        # labelled "complete": the port breakdown only covers observed rows.
        assert analysis["is_exact"] is False
        assert analysis["analysis_mode"] == "bounded_sample"
        assert "recommendation" in analysis

    async def test_missing_slice_total_falls_back_to_observed_rows(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing total-count should be explicit and fall back to observed rows."""

        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "logs": [{"dstport": 443, "proto": "6"}],
                "total_hits": None,
                "total_hits_is_known": False,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

        result = await traffic_tools.get_policy_port_analysis(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[2],
            # Custom range (same 24-hour window) avoids touching the FAZ
            # client for TZ lookup, which isn't initialized in these
            # unit tests.
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
        )

        assert result["status"] == "success"
        analysis = result["results"][0]
        assert analysis["is_exact"] is True
        assert analysis["total_hits"] == 1
        assert analysis["total_hits_is_known"] is False
        assert analysis["total_hit_source"] == "observed_rows"
        assert "estimated_total_hits" not in analysis

    async def test_per_policy_exceptions_are_isolated(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """One policy failure should not hide successful peer-policy results."""

        async def fake_slice(
            *_args: object,
            policy_id: int,
            **_kwargs: object,
        ) -> dict[str, object]:
            if policy_id == 1:
                raise RuntimeError("policy failed")
            return {
                "logs": [{"dstport": 53, "proto": "17"}],
                "total_hits": 1,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

        result = await traffic_tools.get_policy_port_analysis(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[1, 2],
            # Custom range avoids the TZ client lookup in unit tests.
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
        )

        assert result["status"] == "success"
        assert result["results"][0]["policy_id"] == 1
        assert result["results"][0]["error"] == "policy_query_failed"
        assert result["results"][0]["message"] == "policy failed"
        assert result["results"][1]["policy_id"] == 2
        assert result["results"][1]["observed_hits"] == 1


class TestPolicyToolAuditMetadata:
    """Top-level audit metadata and per-policy filter echo."""

    async def test_top_level_audit_and_per_policy_filter(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "logs": [{"dstport": 443, "proto": "6"}],
                "total_hits": 1,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

        result = await traffic_tools.get_policy_port_analysis(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[2],
            action="accept",
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
        )

        assert result["status"] == "success"
        assert result["adom"] == "root"
        assert result["time_range"] == {
            "start": "2024-01-01 00:00:00",
            "end": "2024-01-02 00:00:00",
        }
        # Custom absolute range skips the TZ client lookup in unit tests.
        assert result["timezone"] == "unknown"
        assert result["results"][0]["filter"] == "policyid==2 and action==accept"


# =============================================================================
# Aggregation: protocol summary
# =============================================================================


class TestAggregateProtocolSummary:
    """Tests for protocol summary aggregation."""

    def test_empty_logs(self) -> None:
        """Empty logs should return zero hits."""
        result = _aggregate_protocol_summary([])
        assert result["total_hits"] == 0
        assert result["protocols"] == []

    def test_protocol_name_mapping(self) -> None:
        """Protocol numbers should be mapped to names."""
        logs = [
            {"proto": "6"},
            {"proto": "6"},
            {"proto": "17"},
            {"proto": "1"},
        ]
        result = _aggregate_protocol_summary(logs)
        assert result["total_hits"] == 4
        proto_map = {p["protocol"]: p["hits"] for p in result["protocols"]}
        assert proto_map["TCP"] == 2
        assert proto_map["UDP"] == 1
        assert proto_map["ICMP"] == 1

    def test_unknown_protocol(self) -> None:
        """Unknown protocol numbers should be labeled as other(N)."""
        logs = [{"proto": "99"}]
        result = _aggregate_protocol_summary(logs)
        assert result["protocols"][0]["protocol"] == "other(99)"

    def test_missing_proto_field(self) -> None:
        """Logs without proto field should use 'unknown'."""
        logs = [{"srcip": "10.0.0.1"}]
        result = _aggregate_protocol_summary(logs)
        assert result["protocols"][0]["protocol"] == "other(unknown)"

    def test_protocol_ordering(self) -> None:
        """Protocols should be ordered by hit count descending."""
        logs = [
            {"proto": "17"},
            {"proto": "6"},
            {"proto": "6"},
            {"proto": "6"},
            {"proto": "17"},
        ]
        result = _aggregate_protocol_summary(logs)
        assert result["protocols"][0]["protocol"] == "TCP"
        assert result["protocols"][0]["hits"] == 3
        assert result["protocols"][1]["protocol"] == "UDP"
        assert result["protocols"][1]["hits"] == 2


# =============================================================================
# Tool behavior: bounded traffic profile
# =============================================================================


class TestPolicyTrafficProfileToolBounded:
    """Tests for bounded traffic profile tool behavior."""

    async def test_large_request_returns_bounded_result(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Large windows should return bounded observations with metadata."""

        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "logs": [{"dstport": 443, "proto": "6", "service": "HTTPS", "app": "SSL"}],
                "total_hits": 1,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

        async def fake_total(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {"total_hits": 4, "total_hits_is_known": True}

        monkeypatch.setattr(traffic_tools, "_query_policy_total_count", fake_total)

        result = await traffic_tools.get_policy_traffic_profile(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[2],
            time_range="2024-01-01 00:00:00|2024-01-31 00:00:00",
        )

        assert result["status"] == "success"
        profile = result["results"][0]
        assert profile["policy_id"] == 2
        assert profile["is_exact"] is True
        assert profile["analysis_mode"] == "complete"
        assert profile["slices_scanned"] == 4
        assert profile["total_hits"] == 4
        assert profile["total_hits_is_known"] is True
        assert profile["total_hit_source"] == "logsearch_total-count"
        assert "estimated_total_hits" not in profile
        assert len(profile["top_ports"]) == 1


# =============================================================================
# Tool behavior: bounded protocol summary
# =============================================================================


class TestPolicyProtocolSummaryToolBounded:
    """Tests for bounded protocol summary tool behavior."""

    async def test_bounded_result_with_truncation(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Truncated slices should produce bounded_sample metadata."""
        call_count = 0

        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "logs": [{"proto": "6"} for _ in range(LOG_FETCH_LIMIT)],
                    "total_hits": 1200,
                    "total_hits_is_known": True,
                }
            return {
                "logs": [{"proto": "17"}],
                "total_hits": 1,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

        async def fake_total(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {"total_hits": 1203, "total_hits_is_known": True}

        monkeypatch.setattr(traffic_tools, "_query_policy_total_count", fake_total)

        result = await traffic_tools.get_policy_protocol_summary(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[5],
            time_range="2024-01-01 00:00:00|2024-01-31 00:00:00",
        )

        assert result["status"] == "success"
        summary = result["results"][0]
        assert summary["policy_id"] == 5
        assert summary["is_exact"] is False
        assert summary["analysis_mode"] == "bounded_sample"
        assert summary["truncated_slices"] == 1
        assert summary["observed_hits"] == LOG_FETCH_LIMIT + 3
        assert summary["total_hits"] == 1203
        assert summary["total_hits_is_known"] is True
        assert summary["total_hit_source"] == "logsearch_total-count"
        assert "estimated_total_hits" not in summary
        assert "recommendation" in summary


# =============================================================================
# total-count coercion
# =============================================================================


class TestCoerceLogTotal:
    """Direct coverage of the FAZ total-count coercion helper."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (25, 25),
            (0, 0),
            (-5, -5),  # ints pass through; the >=observed clamp floors bad totals
            ("25", 25),
            ("0", 0),
            ("", None),
            ("abc", None),
            ("12a", None),
            ("-5", None),  # not isdigit
            (None, None),
            (1.0, None),
            ([], None),
        ],
    )
    def test_coerce(self, value: object, expected: int | None) -> None:
        assert _coerce_log_total(value) == expected

    def test_bool_is_rejected_not_treated_as_int(self) -> None:
        """bool is an int subclass; True must coerce to None, never 1."""
        assert _coerce_log_total(True) is None
        assert _coerce_log_total(False) is None


# =============================================================================
# Slice query reliability: single-use tid -> re-issue per page
# =============================================================================


class TestQueryPolicySliceReliability:
    """A bounded slice query must re-issue a fresh search rather than re-fetch a
    single-use (reaped) FortiAnalyzer tid, matching log_tools._run_search_page."""

    _WINDOW = {"start": "2024-01-01 00:00:00", "end": "2024-01-01 01:00:00"}
    _DEVICE = [{"devid": "All_FortiGate"}]

    async def test_reissues_a_fresh_search_on_incomplete_fetch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        starts: list[dict[str, object]] = []
        fetches = {"n": 0}

        class FakeClient:
            async def logsearch_start(self, **kwargs: object) -> dict[str, int]:
                starts.append(kwargs)
                return {"tid": 100 + len(starts)}

            async def logsearch_fetch(self, **_kwargs: object) -> dict[str, object]:
                fetches["n"] += 1
                if fetches["n"] == 1:
                    return {"percentage": 40, "data": []}  # incomplete -> task reaped
                return {
                    "percentage": 100,
                    "total-count": "7",
                    "data": [{"dstport": 443, "proto": "6"}],
                }

            async def logsearch_cancel(self, *_a: object, **_k: object) -> dict[str, object]:
                return {}

        monkeypatch.setattr(traffic_tools.asyncio, "sleep", _noop_sleep)
        monkeypatch.setattr(traffic_tools, "_get_client", lambda: FakeClient())

        result = await _query_policy_log_slice(
            adom="root",
            device_filter=self._DEVICE,
            policy_id=2,
            time_range=self._WINDOW,
            action="accept",
        )

        assert len(starts) == 2  # re-issued, did NOT re-fetch a reaped tid
        assert result["logs"] == [{"dstport": 443, "proto": "6"}]
        assert result["total_hits"] == 7
        assert result["total_hits_is_known"] is True

    async def test_reissues_a_fresh_search_on_invalid_tid_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        starts: list[dict[str, object]] = []
        fetches = {"n": 0}

        class FakeClient:
            async def logsearch_start(self, **kwargs: object) -> dict[str, int]:
                starts.append(kwargs)
                return {"tid": 200 + len(starts)}

            async def logsearch_fetch(self, **_kwargs: object) -> dict[str, object]:
                fetches["n"] += 1
                if fetches["n"] == 1:
                    raise RuntimeError("Invalid tid 201 for fetching result.")
                return {
                    "percentage": 100,
                    "total-count": "3",
                    "data": [{"dstport": 22, "proto": "6"}],
                }

            async def logsearch_cancel(self, *_a: object, **_k: object) -> dict[str, object]:
                return {}

        monkeypatch.setattr(traffic_tools.asyncio, "sleep", _noop_sleep)
        monkeypatch.setattr(traffic_tools, "_get_client", lambda: FakeClient())

        result = await _query_policy_log_slice(
            adom="root",
            device_filter=self._DEVICE,
            policy_id=2,
            time_range=self._WINDOW,
            action=None,
        )

        assert len(starts) == 2
        assert result["logs"] == [{"dstport": 22, "proto": "6"}]
        assert result["total_hits"] == 3

    async def test_non_tid_errors_still_propagate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A genuine error (not invalid-tid) must NOT be silently retried away."""

        class FakeClient:
            async def logsearch_start(self, **_kwargs: object) -> dict[str, int]:
                return {"tid": 1}

            async def logsearch_fetch(self, **_kwargs: object) -> dict[str, object]:
                raise RuntimeError("connection reset by peer")

            async def logsearch_cancel(self, *_a: object, **_k: object) -> dict[str, object]:
                return {}

        monkeypatch.setattr(traffic_tools.asyncio, "sleep", _noop_sleep)
        monkeypatch.setattr(traffic_tools, "_get_client", lambda: FakeClient())

        with pytest.raises(RuntimeError, match="connection reset"):
            await _query_policy_log_slice(
                adom="root",
                device_filter=self._DEVICE,
                policy_id=2,
                time_range=self._WINDOW,
                action=None,
            )

    async def test_no_tid_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeClient:
            async def logsearch_start(self, **_kwargs: object) -> dict[str, object]:
                return {}

            async def logsearch_fetch(self, **_kwargs: object) -> dict[str, object]:
                raise AssertionError("must not fetch without a tid")

            async def logsearch_cancel(self, *_a: object, **_k: object) -> dict[str, object]:
                return {}

        monkeypatch.setattr(traffic_tools.asyncio, "sleep", _noop_sleep)
        monkeypatch.setattr(traffic_tools, "_get_client", lambda: FakeClient())

        result = await _query_policy_log_slice(
            adom="root",
            device_filter=self._DEVICE,
            policy_id=2,
            time_range=self._WINDOW,
            action=None,
        )

        assert result == {"logs": [], "total_hits": None, "total_hits_is_known": False}

    async def test_timeout_returns_empty_and_cancels(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cancels: list[int] = []

        class FakeClient:
            async def logsearch_start(self, **_kwargs: object) -> dict[str, int]:
                return {"tid": 5}

            async def logsearch_fetch(self, **_kwargs: object) -> dict[str, object]:
                return {"percentage": 10, "data": []}  # never completes

            async def logsearch_cancel(self, adom: str, tid: int) -> dict[str, object]:
                cancels.append(tid)
                return {}

        monkeypatch.setattr(traffic_tools.asyncio, "sleep", _noop_sleep)
        monkeypatch.setattr(traffic_tools, "_get_client", lambda: FakeClient())

        result = await _query_policy_log_slice(
            adom="root",
            device_filter=self._DEVICE,
            policy_id=2,
            time_range=self._WINDOW,
            action=None,
            timeout=0,
        )

        assert result == {"logs": [], "total_hits": None, "total_hits_is_known": False}
        assert cancels == [5]


# =============================================================================
# Whole-window total-count: best-effort enrichment
# =============================================================================


class TestTotalCountBestEffort:
    """The whole-window total-count is enrichment; its failure must not discard
    the per-policy observed breakdown."""

    async def test_total_count_failure_keeps_observed_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def good_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "logs": [{"dstport": 443, "proto": "6"}],
                "total_hits": None,
                "total_hits_is_known": False,
            }

        async def boom_total(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise RuntimeError("total-count search failed")

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", good_slice)
        monkeypatch.setattr(traffic_tools, "_query_policy_total_count", boom_total)

        result = await traffic_tools.get_policy_port_analysis(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[2],
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
        )

        assert result["status"] == "success"
        analysis = result["results"][0]
        assert "error" not in analysis
        assert analysis["observed_hits"] == 1
        assert analysis["total_hits_is_known"] is False
        assert analysis["total_hit_source"] == "observed_rows"
        assert analysis["total_hits"] == 1


# =============================================================================
# Bounded metadata: honesty gate + observed floor
# =============================================================================


class TestBoundedMetadata:
    """Exactness must reflect the authoritative total and fetched-row consistency."""

    def test_authoritative_total_far_above_observed_is_not_complete(self) -> None:
        md = _bounded_metadata(
            observed_hits=4,
            slices_scanned=1,
            truncated_slices=0,
            total_hits=100,
            total_hits_is_known=True,
        )
        assert md["total_hits"] == 100
        assert md["total_hit_source"] == "logsearch_total-count"
        assert md["is_exact"] is False
        assert md["analysis_mode"] == "bounded_sample"
        assert "recommendation" in md

    def test_unknown_total_cannot_flip_exactness(self) -> None:
        md = _bounded_metadata(
            observed_hits=4,
            slices_scanned=1,
            truncated_slices=0,
            total_hits=None,
            total_hits_is_known=False,
        )
        assert md["total_hits"] == 4
        assert md["total_hit_source"] == "observed_rows"
        assert md["is_exact"] is True

    def test_total_equal_to_observed_is_complete(self) -> None:
        md = _bounded_metadata(
            observed_hits=4,
            slices_scanned=1,
            truncated_slices=0,
            total_hits=4,
            total_hits_is_known=True,
        )
        assert md["is_exact"] is True
        assert md["analysis_mode"] == "complete"
        assert "recommendation" not in md

    def test_total_below_observed_keeps_authoritative_total(self) -> None:
        """A smaller authoritative total must not be relabeled as observed rows."""
        md = _bounded_metadata(
            observed_hits=5,
            slices_scanned=1,
            truncated_slices=0,
            total_hits=2,
            total_hits_is_known=True,
        )
        assert md["total_hits"] == 2
        assert md["total_hit_source"] == "logsearch_total-count"
        assert md["is_exact"] is False
        assert md["analysis_mode"] == "bounded_sample"
        assert "recommendation" in md


# =============================================================================
# Connection liveness: policy path revives an idle-closed session
# =============================================================================


class TestPolicyPathEnsuresConnection:
    """The bounded policy driver must revive an idle-closed session before
    querying, like query_logs — otherwise the first policy query after the
    streamable-HTTP session drops fails with 'Not connected'."""

    async def test_driver_calls_ensure_connected_before_querying(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[str] = []

        class FakeClient:
            def __init__(self) -> None:
                self.connected = False

            @property
            def is_connected(self) -> bool:
                return self.connected

            async def ensure_connected(self) -> None:
                events.append("ensure_connected")
                self.connected = True

            async def logsearch_start(self, **_kwargs: object) -> dict[str, int]:
                events.append("start")
                return {"tid": 1}

            async def logsearch_fetch(self, **_kwargs: object) -> dict[str, object]:
                return {
                    "percentage": 100,
                    "total-count": "3",
                    "data": [{"dstport": 443, "proto": "6"}],
                }

            async def logsearch_cancel(self, *_a: object, **_k: object) -> dict[str, object]:
                return {}

        fake = FakeClient()
        monkeypatch.setattr(traffic_tools, "_get_client", lambda: fake)
        monkeypatch.setattr(traffic_tools.asyncio, "sleep", _noop_sleep)

        result = await traffic_tools.get_policy_port_analysis(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[2],
            # Custom range skips the TZ client lookup; isolates the connection revive.
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
        )

        assert result["status"] == "success"
        assert "ensure_connected" in events  # session was revived
        assert events.index("ensure_connected") < events.index("start")  # before any query
        assert result["results"][0]["observed_hits"] == 1
