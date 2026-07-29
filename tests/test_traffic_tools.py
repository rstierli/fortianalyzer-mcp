"""Tests for FortiAnalyzer traffic analysis tools.

Tests validation functions, aggregation logic, and tool behavior
without triggering server initialization.
"""

import logging
from typing import Any

import pytest

import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.traffic_tools as traffic_tools
from fortianalyzer_mcp.tools.log_tools import _coerce_total as _coerce_log_total
from fortianalyzer_mcp.tools.traffic_tools import (
    ANALYSIS_QUERY_BUDGET,
    LOG_FETCH_LIMIT,
    VALID_ACTIONS,
    _bounded_metadata,
    _build_bounded_time_slices,
    _build_policy_filter,
    _plan_policy_slice_count,
    _query_policy_log_slice,
    sanitize_filter_value,
    validate_action,
    validate_policy_ids,
)
from fortianalyzer_mcp.utils.validation import ValidationError


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

    @pytest.mark.parametrize(
        ("label", "value"),
        [
            ("newline", "DN\nS"),
            ("carriage return", "DN\rS"),
            ("tab", "DN\tS"),
            ("NUL", "DN\x00S"),
            ("escape", "DN\x1bS"),
            ("delete", "DN\x7fS"),
        ],
    )
    def test_embedded_control_character_is_refused(self, label: str, value: str) -> None:
        """Refused at the boundary rather than quoted and shipped.

        Quoting one is not an injection risk -- it cannot terminate its clause --
        but FortiAnalyzer rejects the entire expression with ``Invalid filter``
        when one arrives. Verified live on 7.6.6: ``service=="DN\\nS"`` errors
        while the same filter without the newline returns rows. Failing here
        costs no round trip and names the offending field.
        """
        with pytest.raises(ValidationError, match="control character"):
            sanitize_filter_value(value, "service")

    def test_surrounding_whitespace_is_still_stripped_not_refused(self) -> None:
        """The strip runs first, so a value that is merely padded keeps working.

        Only *embedded* control characters are a filter-level problem.
        """
        assert sanitize_filter_value("\taccept\n") == "accept"


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
            async def ensure_connected(self) -> None:
                return None

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

        result = await traffic_tools.analyze_policy_traffic(
            adom="root",
            device="FGT60FTK00000001",
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

    async def test_bounded_result_sums_per_slice_totals(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Whole-window total_hits is the sum of per-slice total-counts (issue #30)."""
        call_count = 0

        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal call_count
            call_count += 1
            rows = call_count  # slices return 1, 2, 3, 4 rows, each fully scanned
            return {
                "logs": [{"dstport": 161, "proto": "17"} for _ in range(rows)],
                "total_hits": rows,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)

        result = await traffic_tools.analyze_policy_traffic(
            adom="root",
            device="FGT60FTK00000001",
            policy_ids=[29],
            time_range="2024-01-01 00:00:00|2024-01-31 00:00:00",
            action="accept",
            sample_by=["port"],
        )

        assert result["status"] == "success"
        analysis = result["results"][0]
        # 4 slices returned 1+2+3+4 rows, each with total-count == its rows.
        assert analysis["observed_hits"] == 10
        assert analysis["total_hits"] == 10
        assert analysis["total_hits_is_known"] is True
        assert analysis["total_hit_source"] == "logsearch_total-count"
        assert analysis["breakdowns"]["port"] == [{"value": "17/161", "hits": 10}]
        # Every slice fully scanned (total == rows, none truncated) -> complete.
        assert analysis["is_exact"] is True
        assert analysis["analysis_mode"] == "complete"
        assert "recommendation" not in analysis

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

        result = await traffic_tools.analyze_policy_traffic(
            adom="root",
            device="FGT60FTK00000001",
            policy_ids=[2],
            # Custom range (same 24-hour window) avoids touching the FAZ
            # client for TZ lookup, which isn't initialized in these
            # unit tests.
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
        )

        assert result["status"] == "success"
        analysis = result["results"][0]
        # An unproven slice total (omitted total-count) cannot be "complete".
        assert analysis["is_exact"] is False
        assert analysis["analysis_mode"] == "bounded_sample"
        assert analysis["total_hits"] == 1
        assert analysis["total_hits_is_known"] is False
        assert analysis["total_hit_source"] == "observed_rows"
        assert "recommendation" in analysis
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

        result = await traffic_tools.analyze_policy_traffic(
            adom="root",
            device="FGT60FTK00000001",
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

        result = await traffic_tools.analyze_policy_traffic(
            adom="root",
            device="FGT60FTK00000001",
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
        assert result["time_basis_source"] == "custom"
        assert result["clock_skew_seconds"] is None
        assert result["results"][0]["filter"] == "policyid==2 and action==accept"


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

        result = await traffic_tools.analyze_policy_traffic(
            adom="root",
            device="FGT60FTK00000001",
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
        # Default sample_by is ["port", "service", "app"] -- the three
        # get_policy_traffic_profile used to produce.
        assert len(profile["breakdowns"]["port"]) == 1


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

        result = await traffic_tools.analyze_policy_traffic(
            adom="root",
            device="FGT60FTK00000001",
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
    """A bounded slice query routes through log_tools._run_logsearch_page, so it
    polls logsearch_fetch until percentage=100, re-issuing a fresh search instead of re-fetching a
    single-use (reaped) FortiAnalyzer tid."""

    _WINDOW = {"start": "2024-01-01 00:00:00", "end": "2024-01-01 01:00:00"}
    _DEVICE = [{"devid": "All_FortiGate"}]

    @pytest.fixture(autouse=True)
    def _fast_polls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
        monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)

    async def test_reissues_a_fresh_search_on_invalid_tid_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An invalid-tid race during fetch (reaped between count-complete and
        the fetch) re-issues a fresh search and still completes."""
        starts: list[dict[str, object]] = []
        fetches = {"n": 0}

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

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
            async def ensure_connected(self) -> None:
                return None

            async def logsearch_start(self, **_kwargs: object) -> dict[str, int]:
                return {"tid": 1}

            async def logsearch_fetch(self, **_kwargs: object) -> dict[str, object]:
                raise RuntimeError("connection reset by peer")

            async def logsearch_cancel(self, *_a: object, **_k: object) -> dict[str, object]:
                return {}

        monkeypatch.setattr(traffic_tools, "_get_client", lambda: FakeClient())

        with pytest.raises(RuntimeError, match="connection reset"):
            await _query_policy_log_slice(
                adom="root",
                device_filter=self._DEVICE,
                policy_id=2,
                time_range=self._WINDOW,
                action=None,
            )

    async def test_no_tid_degrades_to_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A start that returns no tid degrades one slice to empty/unknown (the
        runner raises, but the policy slice swallows it) so the rest of the
        policy fan-out still reports rather than the whole policy aborting."""

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def logsearch_start(self, **_kwargs: object) -> dict[str, object]:
                return {}

            async def logsearch_fetch(self, **_kwargs: object) -> dict[str, object]:
                raise AssertionError("must not fetch without a tid")

            async def logsearch_cancel(self, *_a: object, **_k: object) -> dict[str, object]:
                return {}

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
        """A scan that never completes is bounded by the deadline; the slice
        returns an empty/unknown result and the live tid is cancelled."""
        cancels: list[int] = []

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def logsearch_start(self, **_kwargs: object) -> dict[str, int]:
                return {"tid": 5}

            async def logsearch_fetch(self, **_kwargs: object) -> dict[str, object]:
                # Spec-compliant polling: scan never reaches 100% within the
                # deadline; each poll returns percentage<100 with empty data.
                return {
                    "percentage": 20,
                    "return-lines": 0,
                    "data": [],
                    "tid": 5,
                    "status": {"code": 0, "message": "in-progress"},
                }

            async def logsearch_cancel(self, adom: str, tid: int) -> dict[str, object]:
                cancels.append(tid)
                return {}

        monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0.005)
        monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0.005)
        monkeypatch.setattr(traffic_tools, "_get_client", lambda: FakeClient())

        result = await _query_policy_log_slice(
            adom="root",
            device_filter=self._DEVICE,
            policy_id=2,
            time_range=self._WINDOW,
            action=None,
            timeout=1,
        )

        assert result == {"logs": [], "total_hits": None, "total_hits_is_known": False}
        assert cancels == [5]


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
            all_slices_exact=False,
        )
        assert md["total_hits"] == 100
        assert md["total_hit_source"] == "logsearch_total-count"
        assert md["is_exact"] is False
        assert md["analysis_mode"] == "bounded_sample"
        assert "recommendation" in md

    def test_unknown_total_is_never_complete(self) -> None:
        """An unproven total (slice timed out / omitted total) is never complete."""
        md = _bounded_metadata(
            observed_hits=4,
            slices_scanned=1,
            truncated_slices=0,
            total_hits=None,
            total_hits_is_known=False,
            all_slices_exact=False,
        )
        assert md["total_hits"] == 4
        assert md["total_hit_source"] == "observed_rows"
        assert md["is_exact"] is False
        assert md["analysis_mode"] == "bounded_sample"
        assert "recommendation" in md

    def test_total_equal_to_observed_is_complete(self) -> None:
        md = _bounded_metadata(
            observed_hits=4,
            slices_scanned=1,
            truncated_slices=0,
            total_hits=4,
            total_hits_is_known=True,
            all_slices_exact=True,
        )
        assert md["is_exact"] is True
        assert md["analysis_mode"] == "complete"
        assert "recommendation" not in md

    def test_total_below_observed_is_clamped_to_observed(self) -> None:
        """Schema contract: total_hits MUST be >= observed_hits.

        The authoritative total comes from a limit=1 logsearch whose total-count
        short-circuits unreliably under heavy traffic, sometimes under-reporting
        below what the breakdown itself counted. Returning a total smaller than
        observed_hits is a schema violation that breaks downstream audit
        decisions (e.g. policy port analysis). Defended at the response
        boundary: see issue #30. Becomes a no-op once _query_policy_total_count
        is reworked to sum per-slice totals (variant 2 in the issue body).
        """
        md = _bounded_metadata(
            observed_hits=5,
            slices_scanned=1,
            truncated_slices=0,
            total_hits=2,
            total_hits_is_known=True,
            all_slices_exact=False,
        )
        # Clamped up to observed (was the broken authoritative value of 2).
        assert md["total_hits"] == 5
        # Source still reports the authoritative origin — the value was just
        # defended against a known under-report failure mode.
        assert md["total_hit_source"] == "logsearch_total-count"
        # Mismatch between authoritative (2) and observed (5) keeps the
        # result bounded even though no slice was truncated.
        assert md["is_exact"] is False
        assert md["analysis_mode"] == "bounded_sample"
        assert "recommendation" in md

    def test_belt_clamp_below_observed_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """If the summed total ever lands below observed, clamp AND log it."""
        with caplog.at_level(logging.WARNING, logger="fortianalyzer_mcp.tools.traffic_tools"):
            md = _bounded_metadata(
                observed_hits=5,
                slices_scanned=1,
                truncated_slices=0,
                total_hits=2,
                total_hits_is_known=True,
                all_slices_exact=False,
                policy_id=7,
            )
        assert md["total_hits"] == 5
        assert any(
            "Policy 7" in record.message and "below" in record.message for record in caplog.records
        )


# =============================================================================
# issue #30: total_hits summed from per-slice totals; per-slice exactness
# =============================================================================


class TestPerSliceTotalSum:
    """`_query_policy_logs_bounded` sums per-slice total-counts and proves
    exactness per slice (issue #30)."""

    @staticmethod
    def _window_30d() -> dict[str, str]:
        return {"start": "2024-01-01 00:00:00", "end": "2024-01-31 00:00:00"}

    async def test_sums_known_slice_totals(self, monkeypatch: pytest.MonkeyPatch) -> None:
        totals = [10, 20, 30]
        idx = 0

        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal idx
            count = totals[idx]
            idx += 1
            return {
                "logs": [{"dstport": 443, "proto": "6"} for _ in range(count)],
                "total_hits": count,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)
        result = await traffic_tools._query_policy_logs_bounded(
            "root", "FGT60FTK00000001", 2, self._window_30d(), None, policy_count=8
        )
        assert result["slices_scanned"] == 3
        assert result["total_hits"] == 60
        assert result["total_hits_is_known"] is True
        assert result["all_slices_exact"] is True
        assert len(result["logs"]) == 60

    async def test_one_unknown_slice_makes_total_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        idx = 0

        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal idx
            idx += 1
            if idx == 2:
                return {
                    "logs": [{"dstport": 80, "proto": "6"}],
                    "total_hits": None,
                    "total_hits_is_known": False,
                }
            return {
                "logs": [{"dstport": 443, "proto": "6"}],
                "total_hits": 1,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)
        result = await traffic_tools._query_policy_logs_bounded(
            "root", "FGT60FTK00000001", 2, self._window_30d(), None, policy_count=8
        )
        assert result["total_hits"] is None
        assert result["total_hits_is_known"] is False
        assert result["all_slices_exact"] is False
        assert len(result["logs"]) == 3  # rows still accumulate

    async def test_nontruncated_total_above_rows_is_not_exact(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "logs": [{"dstport": 443, "proto": "6"}],
                "total_hits": 5,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)
        result = await traffic_tools._query_policy_logs_bounded(
            "root", "FGT60FTK00000001", 2, self._window_30d(), None, policy_count=8
        )
        assert result["truncated_slices"] == 0
        assert result["total_hits"] == 15
        assert result["all_slices_exact"] is False

    async def test_undercounting_slice_is_not_exact(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "logs": [{"dstport": 443, "proto": "6"} for _ in range(3)],
                "total_hits": 2,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)
        result = await traffic_tools._query_policy_logs_bounded(
            "root", "FGT60FTK00000001", 2, self._window_30d(), None, policy_count=8
        )
        assert result["all_slices_exact"] is False

    async def test_clamps_limit_with_runner_helper(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen_limits: list[int] = []

        async def fake_slice(*_args: object, limit: int, **_kwargs: object) -> dict[str, object]:
            seen_limits.append(limit)
            return {
                "logs": [{"dstport": 443, "proto": "6"}],
                "total_hits": 1,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)
        await traffic_tools._query_policy_logs_bounded(
            "root", "FGT60FTK00000001", 2, self._window_30d(), None, policy_count=8, limit=99999
        )
        # _clamp_limit caps at LOG_FETCH_LIMIT (1000); the slice never sees 99999.
        assert seen_limits and all(seen == LOG_FETCH_LIMIT for seen in seen_limits)

    async def test_timed_out_slice_makes_tool_bounded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        idx = 0

        async def fake_slice(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal idx
            idx += 1
            if idx == 1:
                return {"logs": [], "total_hits": None, "total_hits_is_known": False}
            return {
                "logs": [{"dstport": 443, "proto": "6"}],
                "total_hits": 1,
                "total_hits_is_known": True,
            }

        monkeypatch.setattr(traffic_tools, "_query_policy_log_slice", fake_slice)
        result = await traffic_tools.analyze_policy_traffic(
            adom="root",
            device="FGT60FTK00000001",
            policy_ids=[2],
            time_range="2024-01-01 00:00:00|2024-01-31 00:00:00",
        )
        analysis = result["results"][0]
        assert analysis["is_exact"] is False
        assert analysis["analysis_mode"] == "bounded_sample"
        assert analysis["total_hits_is_known"] is False
        assert analysis["total_hit_source"] == "observed_rows"


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
        monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
        monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)

        result = await traffic_tools.analyze_policy_traffic(
            adom="root",
            device="FGT60FTK00000001",
            policy_ids=[2],
            # Custom range skips the TZ client lookup; isolates the connection revive.
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
        )

        assert result["status"] == "success"
        assert "ensure_connected" in events  # session was revived
        assert events.index("ensure_connected") < events.index("start")  # before any query
        assert result["results"][0]["observed_hits"] == 1


class TestSanitiserIsShared:
    """traffic_tools carried its own copy whose safe class omitted ':'."""

    def test_traffic_sanitiser_is_the_shared_implementation(self) -> None:
        from fortianalyzer_mcp.tools import traffic_tools
        from fortianalyzer_mcp.utils import validation

        assert traffic_tools.sanitize_filter_value is validation.sanitize_filter_value

    def test_ipv6_literal_is_not_quoted(self) -> None:
        """The old copy quoted every IPv6 address because ':' was unsafe to it."""
        from fortianalyzer_mcp.tools import traffic_tools

        assert traffic_tools.sanitize_filter_value("2001:db8::1") == "2001:db8::1"


class TestAnalyzePolicyTraffic:
    """One tool replaces three, and keeps the bounded-honesty contract."""

    async def test_default_sample_by_reproduces_the_profile_breakdowns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [
            {"proto": "6", "dstport": "443", "service": "HTTPS", "app": "HTTPS"},
            {"proto": "6", "dstport": "80", "service": "HTTP", "app": "HTTP"},
        ]

        async def fake_analysis(**kwargs: Any) -> dict[str, Any]:
            return {
                "logs": rows,
                "total_hits": 2,
                "total_hits_is_known": True,
                "all_slices_exact": True,
                "slices_scanned": 1,
                "truncated_slices": 0,
            }

        monkeypatch.setattr(traffic_tools, "_run_bounded_policy_analysis", fake_analysis)

        result = await traffic_tools.analyze_policy_traffic(policy_ids=[7])

        breakdowns = result["results"][0]["breakdowns"]
        assert set(breakdowns) == {"port", "service", "app"}
        assert {"value": "6/443", "hits": 1} in breakdowns["port"]

    async def test_explicit_sample_by_selects_dimensions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [{"proto": "1", "dstport": "0", "service": "PING"}]

        async def fake_analysis(**kwargs: Any) -> dict[str, Any]:
            return {
                "logs": rows,
                "total_hits": 1,
                "total_hits_is_known": True,
                "all_slices_exact": True,
                "slices_scanned": 1,
                "truncated_slices": 0,
            }

        monkeypatch.setattr(traffic_tools, "_run_bounded_policy_analysis", fake_analysis)

        result = await traffic_tools.analyze_policy_traffic(
            policy_ids=[7], sample_by=["icmp_type_code"]
        )

        assert result["results"][0]["breakdowns"]["icmp_type_code"] == [
            {"value": "type=8/code=0", "hits": 1}
        ]

    async def test_the_bounded_contract_is_reported_per_policy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_analysis(**kwargs: Any) -> dict[str, Any]:
            return {
                "logs": [{"proto": "6", "dstport": "443"}],
                "total_hits": 5000,
                "total_hits_is_known": True,
                "all_slices_exact": False,
                "slices_scanned": 4,
                "truncated_slices": 4,
            }

        monkeypatch.setattr(traffic_tools, "_run_bounded_policy_analysis", fake_analysis)

        result = await traffic_tools.analyze_policy_traffic(policy_ids=[7])

        entry = result["results"][0]
        assert entry["is_exact"] is False
        assert entry["analysis_mode"] == "bounded_sample"
        assert entry["total_hits_is_known"] is True
        assert entry["truncated_slices"] == 4
        assert entry["recommendation"]

    async def test_top_n_zero_keeps_the_complete_port_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """get_policy_port_analysis returned every port; that must survive."""
        rows = [{"proto": "6", "dstport": str(p)} for p in range(1000, 1030)]

        async def fake_analysis(**kwargs: Any) -> dict[str, Any]:
            return {
                "logs": rows,
                "total_hits": len(rows),
                "total_hits_is_known": True,
                "all_slices_exact": True,
                "slices_scanned": 1,
                "truncated_slices": 0,
            }

        monkeypatch.setattr(traffic_tools, "_run_bounded_policy_analysis", fake_analysis)

        result = await traffic_tools.analyze_policy_traffic(
            policy_ids=[7], sample_by=["port"], top_n=0
        )

        assert len(result["results"][0]["breakdowns"]["port"]) == 30

    async def test_an_unknown_dimension_is_rejected_before_the_scan(self) -> None:
        result = await traffic_tools.analyze_policy_traffic(
            policy_ids=[7], sample_by=["not_a_dimension_at_all"]
        )

        assert result["status"] == "error"
        assert result["error"] == "unknown_field"

    async def test_too_many_policies_is_still_refused(self) -> None:
        result = await traffic_tools.analyze_policy_traffic(
            policy_ids=list(range(1, traffic_tools.MAX_POLICY_IDS + 5))
        )

        assert result["status"] == "error"
