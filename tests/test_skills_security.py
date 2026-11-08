"""Security-hardening regression tests for the skills layer (issue #68).

Covers:
- M4: caller-facing ``warnings`` must be redacted — at the ``_call`` /
  ``_fetch_attached_alerts`` source, and at the dispatcher success-path
  chokepoint (which does not route through ``error_response``).
- L5: ``triage`` must sanitize ``alert_id`` before it enters a FAZ filter
  expression, so a quote/operator cannot rewrite the clause.
"""

import dataclasses
from typing import Any
from unittest.mock import patch

import pytest

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.catalog import SKILLS
from fortianalyzer_mcp.skills.models import LogSearchResult, TriageParams
from tests.conftest import import_dispatcher_isolated

(faz_skill,) = import_dispatcher_isolated("faz_skill")

# A secret shaped exactly like what redact() scrubs (key=value + long hex run).
SECRET_KV = "session=0123456789abcdef0123456789abcdef"
SECRET_HEX = "deadbeefdeadbeefdeadbeefdeadbeef"

GET_ALERTS = "fortianalyzer_mcp.tools.event_tools.get_alerts"
GET_ALERT_DETAILS = "fortianalyzer_mcp.tools.event_tools.get_alert_details"
GET_ALERT_LOGS = "fortianalyzer_mcp.tools.event_tools.get_alert_logs"
GET_ALERT_INCIDENT_STATS = "fortianalyzer_mcp.tools.event_tools.get_alert_incident_stats"
GET_INCIDENTS = "fortianalyzer_mcp.tools.incident_tools.get_incidents"


def t(target: str, **kwargs: Any) -> Any:
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    return {"status": "success", **fields}


# --------------------------------------------------------------------- #
# M4 — warnings redaction                                               #
# --------------------------------------------------------------------- #


class TestWarningsRedaction:
    async def test_call_redacts_raised_exception_reason(self):
        async def boom(**_: Any) -> dict[str, Any]:
            raise RuntimeError(f"Failed to connect: {SECRET_KV}")

        boom.__name__ = "boom"
        result, reason = await handlers._call(boom)
        assert result is None
        assert reason is not None
        assert SECRET_KV not in reason
        assert "***REDACTED***" in reason

    async def test_call_redacts_error_envelope_reason(self):
        async def failing(**_: Any) -> dict[str, Any]:
            return {"status": "error", "message": f"token={SECRET_HEX}"}

        failing.__name__ = "failing"
        result, reason = await handlers._call(failing)
        assert result is None
        assert reason is not None
        assert SECRET_HEX not in reason
        assert "***REDACTED***" in reason

    async def test_dispatcher_redacts_success_path_warnings(self, monkeypatch: pytest.MonkeyPatch):
        # A warning that never went through _call (so it is not redacted at
        # source) must still be scrubbed at the dispatcher chokepoint.
        async def leaky_handler(parsed: Any) -> LogSearchResult:
            return LogSearchResult(
                tid=1,
                logtype="traffic",
                rows=[],
                row_count=0,
                warnings=[f"raw sub-call failure: {SECRET_KV}"],
            )

        monkeypatch.setitem(
            SKILLS, "log_search", dataclasses.replace(SKILLS["log_search"], handler=leaky_handler)
        )
        result = await faz_skill(skill="log_search", params={})
        assert result["status"] == "success"
        warnings = result["result"]["warnings"]
        assert warnings and SECRET_KV not in warnings[0]
        assert "***REDACTED***" in warnings[0]


# --------------------------------------------------------------------- #
# L5 — triage alert_id filter sanitization                              #
# --------------------------------------------------------------------- #


class TestTriageFilterSanitization:
    async def test_malicious_alert_id_cannot_break_the_clause(self):
        # An alert_id crafted to break out of the alertid=="..." clause must
        # be quoted as one literal, not spliced raw.
        malicious = '1" or 1=="1'
        with (
            t(GET_ALERTS, return_value=ok(data=[])) as get_alerts,
            t(GET_ALERT_DETAILS, return_value=ok(data=[{"alertid": malicious}])),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_INCIDENTS, return_value=ok(data=[])),
        ):
            await handlers.run_triage(TriageParams(alert_id=malicious))

        # First get_alerts call is the filter-first subject lookup.
        first_filter = get_alerts.call_args_list[0].kwargs["filter"]
        # The raw breakout form must NOT appear...
        assert 'alertid=="1" or 1=="1"' not in first_filter
        # ...and the value must sit in the quote character it does not
        # contain: FortiAnalyzer has no escape for a quote (issue #164).
        assert first_filter == "alertid=='1\" or 1==\"1'"

    async def test_benign_alert_id_unquoted_fast_path(self):
        with (
            t(
                GET_ALERTS, return_value=ok(data=[{"alertid": "alert-001", "severity": "high"}])
            ) as g,
            t(GET_ALERT_DETAILS, return_value=ok(data=[])),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_INCIDENTS, return_value=ok(data=[])),
        ):
            await handlers.run_triage(TriageParams(alert_id="alert-001"))
        # A safe alphanumeric id is passed through unquoted (self-quoting
        # sanitizer only wraps when metacharacters are present).
        assert g.call_args_list[0].kwargs["filter"] == "alertid==alert-001"


# --------------------------------------------------------------------- #
# A value no filter literal can hold (#164)                              #
# --------------------------------------------------------------------- #


class TestUnwritableFilterValues:
    def test_record_pivot_writes_a_plain_name(self):
        assert handlers._record_pivot("user", "alice", "euname") == ("user==alice", None)

    def test_record_pivot_reports_why_a_name_cannot_be_written(self):
        pivot, reason = handlers._record_pivot("user", "value\\", "euname")
        assert pivot is None
        assert reason is not None
        assert "backslash" in reason
        # The sanitiser's advice is for a caller; this value came from a record.
        assert "drop the backslash" not in reason

    async def test_a_refusal_from_a_record_site_is_a_fault_not_a_caller_error(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Only ``_param_value`` may turn a refusal into ``invalid_skill_params``.
        A record site that let the sanitiser's error out would blame the
        caller for the appliance's data; the dispatcher reports it as a fault."""
        from fortianalyzer_mcp.utils.errors import ValidationError as FilterValidationError

        def leaks(field: str, value: object, label: str) -> tuple[str | None, str | None]:
            raise FilterValidationError(f"{label} ends in a backslash")

        monkeypatch.setattr(handlers, "_record_pivot", leaks)
        user = {"euid": 12, "euname": "value\\", "eugroup": "services"}
        with (
            t("fortianalyzer_mcp.tools.ueba_tools.get_endusers", return_value=ok(data=[user])),
            t("fortianalyzer_mcp.tools.ueba_tools.get_endpoints", return_value=ok(data=[])),
        ):
            result = await faz_skill("identity_profile", {"euid": 12})
        assert result["status"] == "error"
        assert result["error"] == "skill_error"

    async def test_direct_parameter_refusal_is_an_invalid_parameter(self):
        """A caller-supplied value the sanitiser refuses is their input error,
        reported as such and not as an unexpected skill failure."""
        with (
            t(GET_ALERTS, return_value=ok(data=[])),
            t(GET_ALERT_DETAILS, return_value=ok(data=[])),
        ):
            result = await faz_skill("triage", {"alert_id": "accept\\"})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
        assert "backslash" in result["message"]
