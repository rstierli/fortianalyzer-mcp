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
    _build_bounded_time_slices,
    _build_policy_filter,
    _plan_policy_slice_count,
    sanitize_filter_value,
    validate_action,
    validate_policy_ids,
)
from fortianalyzer_mcp.utils.validation import ValidationError

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
        """Empty logs should return zero counts with is_exact=True."""
        result = _aggregate_port_analysis([])
        assert result["total_hits"] == 0
        assert result["is_exact"] is True
        assert result["ports"] == []
        assert result["protocols"] == []
        assert result["uncovered_port_hits"] == 0

    def test_is_exact_false_when_at_limit(self) -> None:
        """is_exact should be False when log count equals the limit."""
        logs = [{"dstport": 80, "proto": "6"} for _ in range(100)]
        result = _aggregate_port_analysis(logs, limit=100)
        assert result["is_exact"] is False
        assert result["total_hits"] == 100

    def test_is_exact_true_when_below_limit(self) -> None:
        """is_exact should be True when log count is below the limit."""
        logs = [{"dstport": 80, "proto": "6"} for _ in range(50)]
        result = _aggregate_port_analysis(logs, limit=100)
        assert result["is_exact"] is True
        assert result["total_hits"] == 50

    def test_basic_port_enumeration(self) -> None:
        """Basic port/protocol enumeration."""
        logs = [
            {"dstport": 443, "proto": "6"},
            {"dstport": 80, "proto": "6"},
            {"dstport": 53, "proto": "17"},
        ]
        result = _aggregate_port_analysis(logs)
        assert result["total_hits"] == 3
        assert result["is_exact"] is True
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

    async def test_large_request_returns_bounded_result(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Large windows should return bounded observations instead of failing."""
        call_count = 0

        async def fake_estimate(*_args: object, **_kwargs: object) -> dict[int, int]:
            return {2: 448566}

        async def fake_slice(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [{"dstport": 443, "proto": "6"} for _ in range(LOG_FETCH_LIMIT)]
            return [{"dstport": 80, "proto": "6"}]

        monkeypatch.setattr(traffic_tools, "_estimate_policy_hits_best_effort", fake_estimate)
        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

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
        assert analysis["estimated_total_hits"] == 448566
        assert "recommendation" in analysis

    async def test_fortiview_estimate_failure_does_not_fail_tool(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """FortiView estimate failures should be metadata-only."""

        async def fake_estimate(*_args: object, **_kwargs: object) -> dict[int, int]:
            raise RuntimeError("FortiView unavailable")

        async def fake_slice(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
            return [{"dstport": 443, "proto": "6"}]

        monkeypatch.setattr(traffic_tools, "_estimate_policy_hits", fake_estimate)
        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

        result = await traffic_tools.get_policy_port_analysis(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[2],
            time_range="24-hour",
        )

        assert result["status"] == "success"
        analysis = result["results"][0]
        assert analysis["is_exact"] is True
        assert analysis["estimate_available"] is False

    async def test_per_policy_exceptions_are_isolated(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """One policy failure should not hide successful peer-policy results."""

        async def fake_estimate(*_args: object, **_kwargs: object) -> dict[int, int]:
            return {}

        async def fake_slice(
            *_args: object,
            policy_id: int,
            **_kwargs: object,
        ) -> list[dict[str, object]]:
            if policy_id == 1:
                raise RuntimeError("policy failed")
            return [{"dstport": 53, "proto": "17"}]

        monkeypatch.setattr(traffic_tools, "_estimate_policy_hits_best_effort", fake_estimate)
        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

        result = await traffic_tools.get_policy_port_analysis(
            adom="root",
            device="FGT70FTK22019321",
            policy_ids=[1, 2],
            time_range="24-hour",
        )

        assert result["status"] == "success"
        assert result["results"][0]["policy_id"] == 1
        assert result["results"][0]["error"] == "policy failed"
        assert result["results"][1]["policy_id"] == 2
        assert result["results"][1]["observed_hits"] == 1


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
