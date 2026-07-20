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
from fortianalyzer_mcp.skills.dispatcher import faz_skill
from fortianalyzer_mcp.skills.models import LogSearchResult, TriageParams

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
        # be escaped/quoted, not spliced raw.
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
        # ...and the value must be escaped+quoted as one literal.
        assert first_filter == 'alertid=="1\\" or 1==\\"1"'

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
