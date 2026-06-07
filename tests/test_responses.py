"""Tests for the shared tool response helpers (error envelope, warnings, redaction)."""

from fortianalyzer_mcp.utils.responses import build_warnings, error_response, redact
from fortianalyzer_mcp.utils.validation import MASK_VALUE


class TestRedact:
    """redact() scrubs secrets from free text before it is logged or returned."""

    def test_masks_token_key_value(self):
        out = redact("auth failed token=abcdef0123456789abcdef0123")
        assert "abcdef0123456789abcdef0123" not in out
        assert MASK_VALUE in out

    def test_masks_password_colon(self):
        out = redact("login error password: hunter2 retrying")
        assert "hunter2" not in out
        assert MASK_VALUE in out

    def test_masks_long_hex_session(self):
        out = redact("sid 9f8e7d6c5b4a3928170655443322110099aabbcc dropped")
        assert "9f8e7d6c5b4a3928170655443322110099aabbcc" not in out
        assert MASK_VALUE in out

    def test_leaves_normal_filter_untouched(self):
        text = "srcip==10.0.0.1 and action==deny and dstport==443"
        assert redact(text) == text

    def test_empty_string(self):
        assert redact("") == ""


class TestBuildWarnings:
    """build_warnings() emits a message for each of four deterministic triggers."""

    def test_empty_when_nothing_notable(self):
        assert (
            build_warnings(
                requested_limit=100,
                limit=100,
                total=42,
                total_is_known=True,
                timezone="US/Pacific",
                has_more=False,
            )
            == []
        )

    def test_warns_on_clamp(self):
        w = build_warnings(
            requested_limit=5000,
            limit=1000,
            total=10,
            total_is_known=True,
            timezone="US/Pacific",
            has_more=False,
        )
        assert len(w) == 1
        assert "1000" in w[0]

    def test_warns_on_unknown_total(self):
        w = build_warnings(
            requested_limit=100,
            limit=100,
            total=None,
            total_is_known=False,
            timezone="US/Pacific",
            has_more=False,
        )
        assert any("total" in m.lower() for m in w)

    def test_warns_on_unknown_timezone(self):
        w = build_warnings(
            requested_limit=100,
            limit=100,
            total=10,
            total_is_known=True,
            timezone="unknown",
            has_more=False,
        )
        assert any("time" in m.lower() for m in w)

    def test_warns_on_high_volume(self):
        w = build_warnings(
            requested_limit=100,
            limit=100,
            total=200000,
            total_is_known=True,
            timezone="US/Pacific",
            has_more=True,
        )
        assert any("get_policy" in m or "aggregat" in m.lower() or "narrow" in m.lower() for m in w)

    def test_no_high_volume_below_threshold(self):
        w = build_warnings(
            requested_limit=100,
            limit=100,
            total=500,
            total_is_known=True,
            timezone="US/Pacific",
            has_more=True,
        )
        assert w == []


class TestErrorResponse:
    """error_response() builds one structured envelope for every error path."""

    def test_minimal_shape(self):
        r = error_response(error="faz_operation_failed", message="boom", operation="query_logs")
        assert r["status"] == "error"
        assert r["error"] == "faz_operation_failed"
        assert r["message"] == "boom"
        assert r["operation"] == "query_logs"
        assert r["retry_count"] == 0
        assert "adom" not in r
        assert "tid" not in r

    def test_includes_context_and_extra(self):
        r = error_response(
            error="tid_invalid_or_expired",
            message="gone",
            operation="fetch_more_logs",
            adom="root",
            logtype="traffic",
            tid=123,
            retry_count=2,
            recommendation="re-run query_logs",
        )
        assert r["adom"] == "root"
        assert r["logtype"] == "traffic"
        assert r["tid"] == 123
        assert r["retry_count"] == 2
        assert r["recommendation"] == "re-run query_logs"

    def test_redacts_message(self):
        r = error_response(
            error="faz_operation_failed",
            message="failed token=abcdef0123456789abcdef0123",
            operation="query_logs",
        )
        assert "abcdef0123456789abcdef0123" not in r["message"]
        assert MASK_VALUE in r["message"]

    def test_truncates_long_message(self):
        r = error_response(error="faz_operation_failed", message="x" * 2000, operation="query_logs")
        assert len(r["message"]) < 600
