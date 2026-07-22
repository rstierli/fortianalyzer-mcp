"""Tests for the skills layer (RFC #44, Wave 1).

Handlers are tested by patching the underlying tool functions at their
defining modules (the handlers import them lazily per call, so patching
the module attribute is authoritative). All patches use ``autospec=True``
so a handler calling a tool with a signature the real function does not
accept fails here, not against a live FAZ — the exact drift the first
live validation run caught.

Every assertion runs against the validated pydantic output models — the
same contract the dispatcher enforces.
"""

from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.catalog import SKILLS, catalogue
from fortianalyzer_mcp.skills.dispatcher import _redact_warnings, faz_skill
from fortianalyzer_mcp.skills.models import (
    SCHEMA_VERSION,
    FeatureGap,
    IncidentsParams,
    IncidentSummaryParams,
    LogSearchParams,
    ReportsParams,
    TriageParams,
)

WAVE1_SKILL_IDS = {"incidents", "reports", "log_search", "triage", "incident_summary"}
WAVE2_DATA_ACCESS_IDS = {"asset_lookup", "identity_lookup", "alert_rules"}
WAVE2_ENRICHMENT_IDS = {
    "threat_intel",
    "identity_profile",
    "app_usage",
    "network_context",
    "risk_assessment",
}
WAVE2_ANALYSIS_IDS = {"investigate"}
REGISTERED_SKILL_IDS = (
    WAVE1_SKILL_IDS | WAVE2_DATA_ACCESS_IDS | WAVE2_ENRICHMENT_IDS | WAVE2_ANALYSIS_IDS
)

GET_INCIDENTS = "fortianalyzer_mcp.tools.incident_tools.get_incidents"
GET_INCIDENT = "fortianalyzer_mcp.tools.incident_tools.get_incident"
GET_ALERTS = "fortianalyzer_mcp.tools.event_tools.get_alerts"
GET_ALERT_DETAILS = "fortianalyzer_mcp.tools.event_tools.get_alert_details"
GET_ALERT_LOGS = "fortianalyzer_mcp.tools.event_tools.get_alert_logs"
GET_ALERT_INCIDENT_STATS = "fortianalyzer_mcp.tools.event_tools.get_alert_incident_stats"
GET_REPORT_HISTORY = "fortianalyzer_mcp.tools.report_tools.get_report_history"
GET_REPORT_DATA = "fortianalyzer_mcp.tools.report_tools.get_report_data"
QUERY_LOGS = "fortianalyzer_mcp.tools.log_tools.query_logs"
GET_TOP_THREATS = "fortianalyzer_mcp.tools.fortiview_tools.get_top_threats"


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


def attachment_client(records: list[dict[str, Any]]) -> Any:
    """Patch get_faz_client with a client whose GET returns attachments."""
    from unittest.mock import AsyncMock, MagicMock

    client = MagicMock()
    client.get = AsyncMock(return_value={"data": records})
    return patch("fortianalyzer_mcp.server.get_faz_client", return_value=client)


def attachment_client_by_incid(mapping: dict[str, list[dict[str, Any]]]) -> Any:
    """Like ``attachment_client`` but answering per requested ``incid``."""
    from unittest.mock import AsyncMock, MagicMock

    async def _get(path: str, **kwargs: Any) -> dict[str, Any]:
        return {"data": mapping.get(str(kwargs.get("incid")), [])}

    client = MagicMock()
    client.get = AsyncMock(side_effect=_get)
    return patch("fortianalyzer_mcp.server.get_faz_client", return_value=client)


def alertevent_attachment(alertid: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    import json as _json

    return {
        "attachtype": "alertevent",
        "attachsrcid": alertid,
        "attachsrc": "manual",
        "data": _json.dumps(snapshot),
    }


ALERT_LINKED = {
    "alertid": "alert-001",
    "name": "Malware C2 traffic",
    "severity": "critical",
    "timestamp": 1704067300,
    "incids": ["inc-001"],
    "acknowledged": False,
}
ALERT_UNLINKED = {
    "alertid": "alert-002",
    "name": "Login failed",
    "severity": "medium",
    "timestamp": 1704067100,
    "acknowledged": True,
}
INCIDENT = {
    "incid": "inc-001",
    "name": "Malware Detection",
    "severity": "high",
    "status": "new",
    "timestamp": 1704067200,
}


# --------------------------------------------------------------------- #
# Catalogue / registry                                                  #
# --------------------------------------------------------------------- #


class TestCatalog:
    def test_wave1_skills_registered(self):
        assert set(SKILLS) == REGISTERED_SKILL_IDS

    def test_catalogue_entries_have_schemas(self):
        for entry in catalogue():
            assert entry["id"] in SKILLS
            assert entry["tier"] in ("data_access", "enrichment", "analysis")
            assert entry["params_schema"]["type"] == "object"
            assert entry["output_schema"]["type"] == "object"

    def test_params_models_forbid_unknown_keys(self):
        for spec in SKILLS.values():
            with pytest.raises(ValidationError):
                spec.params_model(definitely_not_a_param=1)


# --------------------------------------------------------------------- #
# Dispatcher                                                            #
# --------------------------------------------------------------------- #


class TestDispatcher:
    async def test_list_mode(self):
        result = await faz_skill(skill="list")
        assert result["status"] == "success"
        assert result["schema_version"] == SCHEMA_VERSION
        assert {s["id"] for s in result["skills"]} == REGISTERED_SKILL_IDS

    async def test_unknown_skill(self):
        result = await faz_skill(skill="does_not_exist")
        assert result["status"] == "error"
        assert result["error"] == "unknown_skill"
        assert "incidents" in result["message"]

    async def test_invalid_params(self):
        result = await faz_skill(skill="triage", params={})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
        assert result["skill"] == "triage"

    async def test_subject_failure_maps_to_skill_failed(self):
        with t(GET_INCIDENTS, return_value={"status": "error", "message": "boom"}):
            result = await faz_skill(skill="incidents", params={"include_alerts": False})
        assert result["status"] == "error"
        assert result["error"] == "skill_failed"

    async def test_success_envelope(self):
        with (
            t(GET_INCIDENTS, return_value=ok(data=[INCIDENT])),
            t(GET_ALERTS, return_value=ok(data=[ALERT_LINKED])),
        ):
            result = await faz_skill(skill="incidents", params={})
        assert result["status"] == "success"
        assert result["skill"] == "incidents"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["incident_count"] == 1

    async def test_describe_alias(self):
        result = await faz_skill(skill="describe")
        assert result["status"] == "success"
        assert {s["id"] for s in result["skills"]} == REGISTERED_SKILL_IDS

    async def test_invalid_output_maps_to_skill_output_invalid(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        # A handler whose output violates the documented contract must
        # surface as an error, never as a malformed passthrough.
        import dataclasses

        from fortianalyzer_mcp.skills.models import IncidentsResult

        async def bad_handler(parsed: Any) -> Any:
            return IncidentsResult()  # type: ignore[call-arg]  # missing required fields

        monkeypatch.setitem(
            SKILLS, "incidents", dataclasses.replace(SKILLS["incidents"], handler=bad_handler)
        )
        result = await faz_skill(skill="incidents", params={})
        assert result["status"] == "error"
        assert result["error"] == "skill_output_invalid"
        assert result["skill"] == "incidents"

    async def test_unexpected_exception_maps_to_skill_error(self, monkeypatch: pytest.MonkeyPatch):
        import dataclasses

        async def exploding_handler(parsed: Any) -> Any:
            raise RuntimeError("kaboom")

        monkeypatch.setitem(
            SKILLS, "incidents", dataclasses.replace(SKILLS["incidents"], handler=exploding_handler)
        )
        result = await faz_skill(skill="incidents", params={})
        assert result["status"] == "error"
        assert result["error"] == "skill_error"
        assert result["skill"] == "incidents"


# --------------------------------------------------------------------- #
# incidents                                                             #
# --------------------------------------------------------------------- #


class TestIncidentsSkill:
    async def test_correlates_alerts_by_linkage_field(self):
        with (
            t(GET_INCIDENTS, return_value=ok(data=[INCIDENT])),
            t(GET_ALERTS, return_value=ok(data=[ALERT_LINKED, ALERT_UNLINKED])),
        ):
            result = await handlers.run_incidents(IncidentsParams())
        assert result.incident_count == 1
        record = result.incidents[0]
        assert record.incident == INCIDENT
        assert record.correlated_alerts == [ALERT_LINKED]
        assert record.correlation_basis == "alert.incids"
        assert result.alerts_scanned == 2

    async def test_no_linkage_fields_warns(self):
        with (
            t(GET_INCIDENTS, return_value=ok(data=[INCIDENT])),
            t(GET_ALERTS, return_value=ok(data=[ALERT_UNLINKED])),
        ):
            result = await handlers.run_incidents(IncidentsParams())
        assert result.incidents[0].correlated_alerts == []
        assert any("correlated_alerts are empty" in w for w in result.warnings)

    async def test_alert_fetch_failure_degrades(self):
        with (
            t(GET_INCIDENTS, return_value=ok(data=[INCIDENT])),
            t(GET_ALERTS, side_effect=RuntimeError("faz down")),
        ):
            result = await handlers.run_incidents(IncidentsParams())
        assert result.incident_count == 1
        assert result.alerts_scanned == 0
        assert any("correlation skipped" in w for w in result.warnings)

    async def test_include_alerts_false_skips_scan(self):
        with (
            t(GET_INCIDENTS, return_value=ok(data=[INCIDENT])),
            t(GET_ALERTS) as alerts_mock,
        ):
            result = await handlers.run_incidents(IncidentsParams(include_alerts=False))
        alerts_mock.assert_not_awaited()
        assert result.alerts_scanned == 0

    async def test_incidents_failure_raises(self):
        with t(GET_INCIDENTS, return_value={"status": "error", "error": "no_permission"}):
            with pytest.raises(handlers.SkillExecutionError):
                await handlers.run_incidents(IncidentsParams())


class TestAttachmentCorrelation:
    """Attachment-based alert<->incident correlation (the authoritative
    linkage on live FAZ — alerts/incidents carry no linkage fields)."""

    SNAPSHOT = {"severity": "critical", "alerttime": "1704067300", "subject": "C2 traffic"}

    async def test_incidents_prefers_attachments(self):
        with (
            t(GET_INCIDENTS, return_value=ok(data=[INCIDENT])),
            t(GET_ALERTS, return_value=ok(data=[ALERT_UNLINKED])),
            attachment_client([alertevent_attachment("alert-001", self.SNAPSHOT)]),
        ):
            result = await handlers.run_incidents(IncidentsParams())
        rec = result.incidents[0]
        assert rec.correlation_basis == "incident.attachments.alertevent"
        assert rec.correlated_alerts == [{**self.SNAPSHOT, "alertid": "alert-001"}]
        assert result.warnings == []

    async def test_full_attachment_page_warns_about_truncation(self):
        page = [alertevent_attachment(f"alert-{i}", self.SNAPSHOT) for i in range(200)]
        with (
            t(GET_INCIDENTS, return_value=ok(data=[INCIDENT])),
            t(GET_ALERTS, return_value=ok(data=[])),
            attachment_client(page),
        ):
            result = await handlers.run_incidents(IncidentsParams())
        assert any("may be incomplete" in w for w in result.warnings)

    async def test_incidents_falls_back_when_attachments_unavailable(self):
        # No get_faz_client patch -> reader reports the client as missing.
        with (
            t(GET_INCIDENTS, return_value=ok(data=[INCIDENT])),
            t(GET_ALERTS, return_value=ok(data=[ALERT_LINKED])),
        ):
            result = await handlers.run_incidents(IncidentsParams())
        rec = result.incidents[0]
        assert rec.correlation_basis == "alert.incids"
        assert rec.correlated_alerts == [ALERT_LINKED]
        assert any("attachment-based correlation unavailable" in w for w in result.warnings)

    async def test_scan_deferred_when_attachments_cover_all_incidents(self):
        # The window scan exists only for the fallback: when attachments
        # correlate every incident it must not run, and alerts_scanned
        # reports 0 rather than a count that never influenced anything.
        with (
            t(GET_INCIDENTS, return_value=ok(data=[INCIDENT])),
            t(GET_ALERTS) as alerts_mock,
            attachment_client([alertevent_attachment("alert-001", self.SNAPSHOT)]),
        ):
            result = await handlers.run_incidents(IncidentsParams())
        alerts_mock.assert_not_awaited()
        assert result.alerts_scanned == 0
        assert result.incidents[0].correlation_basis == "incident.attachments.alertevent"

    async def test_attachment_fanout_covers_every_incident_in_order(self):
        # The bounded gather must query each incident and keep results
        # aligned with the incident order.
        incidents = [
            {"incid": "inc-001", "severity": "high"},
            {"incid": "inc-002", "severity": "low"},
            {"incid": "inc-003", "severity": "medium"},
        ]
        mapping = {
            "inc-001": [alertevent_attachment("alert-a", self.SNAPSHOT)],
            "inc-002": [],
            "inc-003": [alertevent_attachment("alert-c", self.SNAPSHOT)],
        }
        with (
            t(GET_INCIDENTS, return_value=ok(data=incidents)),
            t(GET_ALERTS, return_value=ok(data=[])),
            attachment_client_by_incid(mapping),
        ):
            result = await handlers.run_incidents(IncidentsParams())
        first, second, third = result.incidents
        assert first.correlated_alerts[0]["alertid"] == "alert-a"
        assert second.correlated_alerts == []
        assert third.correlated_alerts[0]["alertid"] == "alert-c"

    async def test_triage_incident_related_from_attachments(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            attachment_client([alertevent_attachment("alert-001", self.SNAPSHOT)]),
        ):
            result = await handlers.run_triage(TriageParams(incident_id="inc-001"))
        assert result.related == [{**self.SNAPSHOT, "alertid": "alert-001"}]
        assert not any("fell back" in w for w in result.warnings)

    async def test_incident_summary_evidence_from_attachments(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERT_LOGS, return_value=ok(data=[{"logid": "l-9"}])),
            attachment_client([alertevent_attachment("alert-001", self.SNAPSHOT)]),
        ):
            result = await handlers.run_incident_summary(
                IncidentSummaryParams(incident_id="inc-001", include_top_threats=False)
            )
        assert len(result.alerts) == 1
        assert result.alerts[0].alert["alertid"] == "alert-001"
        assert result.alerts[0].logs == [{"logid": "l-9"}]
        # Timeline picks up the snapshot's alerttime.
        assert any(e.source == "alert" for e in result.timeline)


# --------------------------------------------------------------------- #
# reports                                                               #
# --------------------------------------------------------------------- #


class TestReportsSkill:
    async def test_list(self):
        history = [{"tid": "t-1", "title": "Weekly"}, {"tid": "t-2", "title": "Monthly"}]
        with t(GET_REPORT_HISTORY, return_value=ok(data=history)) as mock:
            result = await handlers.run_reports(ReportsParams())
        assert result.action == "list"
        assert result.report_count == 2
        assert result.reports == history
        mock.assert_awaited_once_with(adom=None, time_range="7-day", title=None)

    async def test_list_applies_client_side_limit(self):
        history = [{"tid": f"t-{i}"} for i in range(5)]
        with t(GET_REPORT_HISTORY, return_value=ok(data=history)):
            result = await handlers.run_reports(ReportsParams(limit=2))
        assert result.report_count == 2
        assert any("first 2" in w for w in result.warnings)

    async def test_fetch(self):
        fetched = ok(tid="t-1", format="CSV", data="...")
        with t(GET_REPORT_DATA, return_value=fetched) as mock:
            result = await handlers.run_reports(
                ReportsParams(action="fetch", tid="t-1", output_format="CSV")
            )
        assert result.action == "fetch"
        assert result.fetched == fetched
        mock.assert_awaited_once_with(tid="t-1", adom=None, output_format="CSV")

    def test_fetch_requires_tid(self):
        with pytest.raises(ValidationError, match="tid"):
            ReportsParams(action="fetch")


# --------------------------------------------------------------------- #
# log_search                                                            #
# --------------------------------------------------------------------- #


class TestLogSearchSkill:
    async def test_rows_pass_through_verbatim(self):
        rows = [{"srcip": "192.0.2.1", "dstip": "198.51.100.2", "action": "deny"}]
        with t(
            QUERY_LOGS,
            return_value=ok(
                tid=99, logs=rows, total=1, total_is_known=True, has_more=False, warnings=[]
            ),
        ) as mock:
            result = await handlers.run_log_search(
                LogSearchParams(logtype="traffic", filter="action==deny")
            )
        assert result.tid == 99
        assert result.rows == rows
        assert result.row_count == 1
        assert result.total == 1 and result.total_is_known
        assert mock.await_args.kwargs["filter"] == "action==deny"

    async def test_search_failure_raises(self):
        with t(QUERY_LOGS, return_value={"status": "error", "error": "search_timeout"}):
            with pytest.raises(handlers.SkillExecutionError):
                await handlers.run_log_search(LogSearchParams())


# --------------------------------------------------------------------- #
# triage                                                                #
# --------------------------------------------------------------------- #


class TestTriageSkill:
    DETAILS = ok(
        data={"data": [{"alertid": "alert-001", "devs": ["FGT-01"], "epids": [7], "euids": [3]}]}
    )

    def test_requires_exactly_one_subject(self):
        with pytest.raises(ValidationError, match="exactly one"):
            TriageParams()
        with pytest.raises(ValidationError, match="exactly one"):
            TriageParams(alert_id="a", incident_id="i")

    async def test_alert_path(self):
        with (
            t(GET_ALERTS, return_value=ok(data=[ALERT_LINKED, ALERT_UNLINKED])),
            t(GET_ALERT_DETAILS, return_value=self.DETAILS) as details_mock,
            t(GET_ALERT_LOGS, return_value=ok(data=[{"logid": "l-1"}])) as logs_mock,
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={"alerts": 5, "incidents": 1})),
        ):
            result = await handlers.run_triage(TriageParams(alert_id="alert-001"))
        details_mock.assert_awaited_once_with(alert_ids=["alert-001"], adom=None)
        logs_mock.assert_awaited_once_with(alert_ids=["alert-001"], adom=None)
        assert result.subject_type == "alert"
        assert result.subject == ALERT_LINKED  # full row from the window scan
        assert result.subject_details == self.DETAILS["data"]["data"][0]
        assert result.triggering_logs == [{"logid": "l-1"}]
        assert result.related == [INCIDENT]  # via the alert's incids linkage
        assert result.context_stats == {"alerts": 5, "incidents": 1}
        assert result.assessment.priority == "urgent"  # critical -> urgent
        assert result.assessment.acknowledged is False
        assert isinstance(result.enrichment, FeatureGap)
        assert "Wave 2" in result.enrichment.reason

    async def test_alert_not_in_window_falls_back_to_details(self):
        with (
            t(GET_ALERTS, return_value=ok(data=[ALERT_UNLINKED])),  # subject not in window
            t(GET_ALERT_DETAILS, return_value=self.DETAILS),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
            t(GET_INCIDENTS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
        ):
            result = await handlers.run_triage(TriageParams(alert_id="alert-001"))
        assert result.subject == self.DETAILS["data"]["data"][0]
        assert result.assessment.priority == "informational"  # no severity on details
        assert any("not in the" in w for w in result.warnings)

    async def test_alert_unresolvable_raises(self):
        with (
            t(GET_ALERTS, return_value=ok(data=[])),
            t(GET_ALERT_DETAILS, side_effect=RuntimeError("down")),
        ):
            with pytest.raises(handlers.SkillExecutionError):
                await handlers.run_triage(TriageParams(alert_id="alert-404"))

    async def test_incident_path_correlates_alerts(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERTS, return_value=ok(data=[ALERT_LINKED, ALERT_UNLINKED])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={"alerts": 5})),
        ):
            result = await handlers.run_triage(TriageParams(incident_id="inc-001"))
        assert result.subject_type == "incident"
        assert result.subject_details is None
        assert result.related == [ALERT_LINKED]
        assert result.assessment.priority == "high"
        assert any("status" in b for b in result.assessment.basis)

    async def test_context_failures_degrade_not_fail(self):
        with (
            t(GET_ALERTS, return_value=ok(data=[ALERT_UNLINKED])),  # subject found
            t(GET_ALERT_DETAILS, side_effect=RuntimeError("nope")),
            t(GET_ALERT_LOGS, side_effect=RuntimeError("nope")),
            t(GET_INCIDENTS, return_value={"status": "error", "error": "denied"}),
            t(GET_ALERT_INCIDENT_STATS, side_effect=RuntimeError("nope")),
        ):
            result = await handlers.run_triage(TriageParams(alert_id="alert-002"))
        assert result.subject == ALERT_UNLINKED
        assert result.subject_details is None
        assert result.triggering_logs == []
        assert result.context_stats is None
        assert len(result.warnings) == 4  # details, logs, incidents, stats
        assert result.assessment.priority == "medium"

    async def test_alert_subject_found_by_filter_first(self):
        # The subject must come from the alertid filter lookup over the
        # wide window (live-verified on both versions), with no 500-row
        # window scan when the filter hits.
        with (
            t(GET_ALERTS, return_value=ok(data=[ALERT_LINKED])) as alerts_mock,
            t(GET_ALERT_DETAILS, return_value=self.DETAILS),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
        ):
            result = await handlers.run_triage(TriageParams(alert_id="alert-001"))
        assert result.subject == ALERT_LINKED
        alerts_mock.assert_awaited_once()
        kwargs = alerts_mock.await_args.kwargs
        # sanitize_filter_value leaves a safe alphanumeric id unquoted.
        assert kwargs["filter"] == "alertid==alert-001"
        assert kwargs["time_range"] == "30-day"

    async def test_alert_filter_miss_falls_back_to_window_scan(self):
        with (
            t(
                GET_ALERTS,
                side_effect=[ok(data=[]), ok(data=[ALERT_LINKED, ALERT_UNLINKED])],
            ) as alerts_mock,
            t(GET_ALERT_DETAILS, return_value=self.DETAILS),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
        ):
            result = await handlers.run_triage(TriageParams(alert_id="alert-001"))
        assert result.subject == ALERT_LINKED
        assert alerts_mock.await_count == 2
        scan_kwargs = alerts_mock.await_args_list[1].kwargs
        assert "filter" not in scan_kwargs
        assert scan_kwargs["time_range"] == "24-hour"

    async def test_alert_id_with_quote_is_sanitized_not_skipped(self):
        # A quote in the id is escaped and quoted (issue #68 L5), so the
        # filter-first lookup still runs — with a clause that cannot break
        # out — rather than being skipped by a blocklist.
        with (
            t(GET_ALERTS, return_value=ok(data=[])) as alerts_mock,
            t(GET_ALERT_DETAILS, return_value=self.DETAILS),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
            t(GET_INCIDENTS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
        ):
            await handlers.run_triage(TriageParams(alert_id='alert"-x'))
        # The filter-first lookup runs (call 0) with an escaped, quoted
        # clause; an empty result then falls back to the window scan (call 1).
        assert alerts_mock.await_args_list[0].kwargs["filter"] == 'alertid=="alert\\"-x"'

    async def test_alert_related_incidents_by_attachment_membership(self):
        # Live alerts carry no incident-linkage fields; the authoritative
        # relation is which context incidents attach this alertid.
        candidates = [
            {"incid": "inc-001", "name": "one"},
            {"incid": "inc-002", "name": "two"},
        ]
        snapshot = {"severity": "medium"}
        mapping = {
            "inc-001": [alertevent_attachment("alert-002", snapshot)],
            "inc-002": [alertevent_attachment("alert-999", snapshot)],
        }
        with (
            t(GET_ALERTS, return_value=ok(data=[ALERT_UNLINKED])),
            t(GET_ALERT_DETAILS, return_value=self.DETAILS),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
            t(GET_INCIDENTS, return_value=ok(data=candidates)),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            attachment_client_by_incid(mapping),
        ):
            result = await handlers.run_triage(TriageParams(alert_id="alert-002"))
        assert result.related == [candidates[0]]
        assert not any("lists all incidents" in w for w in result.warnings)

    async def test_alert_not_attached_to_any_context_incident(self):
        candidates = [{"incid": "inc-001", "name": "one"}]
        with (
            t(GET_ALERTS, return_value=ok(data=[ALERT_UNLINKED])),
            t(GET_ALERT_DETAILS, return_value=self.DETAILS),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
            t(GET_INCIDENTS, return_value=ok(data=candidates)),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            attachment_client_by_incid({"inc-001": []}),
        ):
            result = await handlers.run_triage(TriageParams(alert_id="alert-002"))
        assert result.related == []
        assert any("not attached to any" in w for w in result.warnings)

    async def test_alert_related_falls_back_noisy_when_attachments_unavailable(self):
        # No get_faz_client patch -> every membership check fails; the old
        # honest-but-noisy fallback (all context incidents) is preserved.
        candidates = [{"incid": "inc-001"}, {"incid": "inc-002"}]
        with (
            t(GET_ALERTS, return_value=ok(data=[ALERT_UNLINKED])),
            t(GET_ALERT_DETAILS, return_value=self.DETAILS),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
            t(GET_INCIDENTS, return_value=ok(data=candidates)),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
        ):
            result = await handlers.run_triage(TriageParams(alert_id="alert-002"))
        assert result.related == candidates
        assert any("lists all incidents" in w for w in result.warnings)


# --------------------------------------------------------------------- #
# incident_summary                                                  #
# --------------------------------------------------------------------- #


class TestIncidentSummarySkill:
    async def test_full_report(self):
        threats = [{"threat": "Backdoor.X", "threatweight": 900}]
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERTS, return_value=ok(data=[ALERT_LINKED, ALERT_UNLINKED])),
            t(
                GET_ALERT_LOGS, return_value=ok(data=[{"logid": "l-1"}, {"logid": "l-2"}])
            ) as logs_mock,
            t(GET_TOP_THREATS, return_value=ok(data=threats)),
        ):
            result = await handlers.run_incident_summary(
                IncidentSummaryParams(incident_id="inc-001")
            )
        logs_mock.assert_awaited_once_with(alert_ids=["alert-001"], adom=None, limit=20)
        assert result.incident == INCIDENT
        assert len(result.alerts) == 1
        assert result.alerts[0].alert == ALERT_LINKED
        assert len(result.alerts[0].logs) == 2
        assert result.threat_landscape == threats
        assert result.counts == {"alerts": 1, "evidence_logs": 2}
        # Timeline: incident (1704067200) precedes alert (1704067300).
        assert [e.source for e in result.timeline] == ["incident", "alert"]

    async def test_threats_failure_becomes_gap(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(GET_TOP_THREATS, side_effect=RuntimeError("fortiview down")),
        ):
            result = await handlers.run_incident_summary(
                IncidentSummaryParams(incident_id="inc-001")
            )
        assert isinstance(result.threat_landscape, FeatureGap)
        assert "unavailable" in result.threat_landscape.reason

    async def test_max_alerts_cap_warns(self):
        linked_alerts = [
            {"alertid": f"alert-{i}", "incids": ["inc-001"], "timestamp": 1704067000 + i}
            for i in range(5)
        ]
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERTS, return_value=ok(data=linked_alerts)),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
        ):
            result = await handlers.run_incident_summary(
                IncidentSummaryParams(
                    incident_id="inc-001", max_alerts=2, include_top_threats=False
                )
            )
        assert len(result.alerts) == 2
        assert any("only the first 2" in w for w in result.warnings)
        assert isinstance(result.threat_landscape, FeatureGap)

    async def test_incident_failure_raises(self):
        with t(GET_INCIDENT, return_value={"status": "error", "error": "not_found"}):
            with pytest.raises(handlers.SkillExecutionError):
                await handlers.run_incident_summary(IncidentSummaryParams(incident_id="inc-404"))

    async def test_timeline_orders_int_and_string_timestamps(self):
        """The shape this repo's own fixtures produce: int + epoch string.

        The old key sorted on (isinstance(ts, str), str(ts)), which groups
        every int before every string regardless of when the events happened.
        An incident with an int ``timestamp`` therefore always preceded an
        alert whose snapshot carries ``alerttime`` as a string, even when the
        alert came first.
        """
        incident = {"incid": "inc-001", "name": "Later incident", "timestamp": 1704067200}
        alerts = [{"alertid": "a-early", "incids": ["inc-001"], "alerttime": "1704067100"}]
        with (
            t(GET_INCIDENT, return_value=ok(data=incident)),
            t(GET_ALERTS, return_value=ok(data=alerts)),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
        ):
            result = await handlers.run_incident_summary(
                IncidentSummaryParams(incident_id="inc-001", include_top_threats=False)
            )
        # The alert (1704067100) precedes the incident (1704067200).
        assert [e.source for e in result.timeline] == ["alert", "incident"]

    async def test_timeline_orders_datetime_strings_defensively(self):
        """Defensive: a datetime string sorts lexicographically against an
        epoch string. Not observed on live FAZ (7.6.7 and 8.0.0 return epoch
        strings for createtime/lastupdate), but the key must not depend on
        that remaining true.
        """
        incident = {
            "incid": "inc-001",
            "name": "Late incident",
            "createtime": "2026-07-08 10:22:41",
        }
        alerts = [
            {"alertid": "a-early", "incids": ["inc-001"], "alerttime": "1704067300"},  # 2024
            {"alertid": "a-late", "incids": ["inc-001"], "alerttime": "1783629554"},  # 2026, after
        ]
        with (
            t(GET_INCIDENT, return_value=ok(data=incident)),
            t(GET_ALERTS, return_value=ok(data=alerts)),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
        ):
            result = await handlers.run_incident_summary(
                IncidentSummaryParams(incident_id="inc-001", include_top_threats=False)
            )
        # 2024 alert, then the 2026-07-08 incident, then the 2026-07-09 alert.
        assert [e.source for e in result.timeline] == ["alert", "incident", "alert"]

    async def test_timeline_unparseable_timestamp_sorts_last(self):
        incident = {"incid": "inc-001", "timestamp": 1704067200}
        alerts = [{"alertid": "a-1", "incids": ["inc-001"], "alerttime": "not-a-time"}]
        with (
            t(GET_INCIDENT, return_value=ok(data=incident)),
            t(GET_ALERTS, return_value=ok(data=alerts)),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
        ):
            result = await handlers.run_incident_summary(
                IncidentSummaryParams(incident_id="inc-001", include_top_threats=False)
            )
        assert [e.source for e in result.timeline] == ["incident", "alert"]


# --------------------------------------------------------------------- #
# Config flag                                                           #
# --------------------------------------------------------------------- #


class TestSkillsFlag:
    def test_flag_defaults_off(self, monkeypatch: pytest.MonkeyPatch):
        from fortianalyzer_mcp.utils.config import Settings

        monkeypatch.delenv("FAZ_SKILLS_ENABLED", raising=False)
        assert Settings(FORTIANALYZER_HOST="192.0.2.1").FAZ_SKILLS_ENABLED is False


class TestNestedWarningRedaction:
    """A composed skill keeps a copy of each section's warnings.

    The dispatcher scrubs what it is handed. While it read one top-level
    key, only the composing handler's prefixed copies were scrubbed and
    every original shipped verbatim alongside them.
    """

    SECRET = "session=SECRET123 expired"

    def test_top_level_warnings_still_redacted(self):
        out = _redact_warnings({"warnings": [self.SECRET]})

        assert "SECRET123" not in out["warnings"][0]
        assert "REDACTED" in out["warnings"][0]

    def test_nested_warnings_are_redacted(self):
        out = _redact_warnings(
            {
                "warnings": [f"triage: {self.SECRET}"],
                "triage": {"warnings": [self.SECRET]},
                "threat_intel": {"warnings": [self.SECRET]},
            }
        )

        assert "SECRET123" not in str(out)

    def test_warnings_inside_a_list_of_sections_are_redacted(self):
        out = _redact_warnings({"sections": [{"warnings": [self.SECRET]}]})

        assert "SECRET123" not in str(out)

    def test_deeply_nested_warnings_are_redacted(self):
        out = _redact_warnings({"a": {"b": {"c": {"warnings": [self.SECRET]}}}})

        assert "SECRET123" not in str(out)

    def test_non_warning_fields_are_untouched(self):
        # Redaction is deliberately narrow: it rewrites this one key and
        # nothing else, so a field that happens to contain a key=value pair
        # keeps its exact content.
        payload = {"headline": self.SECRET, "reason": self.SECRET, "count": 3}

        assert _redact_warnings(payload) == payload

    def test_non_string_warning_elements_survive(self):
        payload = {"warnings": [{"structured": "shape"}, 7, None]}

        assert _redact_warnings(payload) == payload

    def test_a_warnings_key_that_is_not_a_list_is_left_alone(self):
        payload = {"warnings": "not a list"}

        assert _redact_warnings(payload) == payload

    def test_returns_a_new_structure_rather_than_mutating_in_place(self):
        # The preservation tests below compare against the same object, so
        # they would all pass an implementation that edited the caller's
        # dict and handed it back. Pin purity explicitly.
        payload = {"warnings": [self.SECRET]}
        result = _redact_warnings(payload)

        assert result is not payload
        assert payload["warnings"] == [self.SECRET]

    def test_warnings_nested_inside_a_list_of_lists(self):
        # Recursion has to go through every list level, not just the first.
        out = _redact_warnings({"a": [[{"warnings": [self.SECRET]}]]})

        assert "SECRET123" not in str(out)

    def test_a_warnings_suffixed_key_is_not_rewritten(self):
        # The docstring promises only `warnings` is touched. A suffix match
        # would silently start rewriting neighbouring fields.
        payload = {"suppressed_warnings": [self.SECRET]}

        assert _redact_warnings(payload) == payload

    def test_a_warnings_key_holding_a_dict_is_still_recursed_into(self):
        # Not a shape any model produces today, but the branch that skips a
        # non-list `warnings` must recurse rather than return it untouched.
        out = _redact_warnings({"warnings": {"nested": {"warnings": [self.SECRET]}}})

        assert "SECRET123" not in str(out)

    def test_shape_is_otherwise_preserved(self):
        payload = {
            "subject_type": "alert",
            "counts": {"endpoints": 2},
            "rows": [{"a": 1}, {"b": [1, 2]}],
        }

        assert _redact_warnings(payload) == payload

    async def test_dispatcher_scrubs_a_nested_section_end_to_end(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """The helper is wired in, not just present.

        Uses a stub skill whose output nests another section's warnings,
        which is the shape a composing skill produces.
        """
        from pydantic import BaseModel

        from fortianalyzer_mcp.skills import dispatcher as dispatcher_module

        class Section(BaseModel):
            warnings: list[str] = []

        class Composed(BaseModel):
            warnings: list[str] = []
            section: Section

        class StubParams(BaseModel):
            pass

        async def handler(_params: StubParams) -> Composed:
            return Composed(
                warnings=[f"section: {self.SECRET}"],
                section=Section(warnings=[self.SECRET]),
            )

        from fortianalyzer_mcp.skills.catalog import SkillSpec

        spec = SkillSpec(
            id="stub_composed",
            tier="analysis",
            description="stub",
            params_model=StubParams,
            output_model=Composed,
            handler=handler,
        )
        monkeypatch.setitem(dispatcher_module.SKILLS, "stub_composed", spec)

        result = await faz_skill(skill="stub_composed", params={})

        assert result["status"] == "success"
        assert "SECRET123" not in str(result)
