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
from fortianalyzer_mcp.skills.dispatcher import faz_skill
from fortianalyzer_mcp.skills.models import (
    SCHEMA_VERSION,
    FeatureGap,
    IncidentsParams,
    InvestigationReportParams,
    LogSearchParams,
    ReportsParams,
    TriageParams,
)

WAVE1_SKILL_IDS = {"incidents", "reports", "log_search", "triage", "investigation_report"}

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
        assert set(SKILLS) == WAVE1_SKILL_IDS

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
        assert {s["id"] for s in result["skills"]} == WAVE1_SKILL_IDS

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
        assert any("best-effort" in w for w in result.warnings)

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


# --------------------------------------------------------------------- #
# investigation_report                                                  #
# --------------------------------------------------------------------- #


class TestInvestigationReportSkill:
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
            result = await handlers.run_investigation_report(
                InvestigationReportParams(incident_id="inc-001")
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
            result = await handlers.run_investigation_report(
                InvestigationReportParams(incident_id="inc-001")
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
            result = await handlers.run_investigation_report(
                InvestigationReportParams(
                    incident_id="inc-001", max_alerts=2, include_top_threats=False
                )
            )
        assert len(result.alerts) == 2
        assert any("only the first 2" in w for w in result.warnings)
        assert isinstance(result.threat_landscape, FeatureGap)

    async def test_incident_failure_raises(self):
        with t(GET_INCIDENT, return_value={"status": "error", "error": "not_found"}):
            with pytest.raises(handlers.SkillExecutionError):
                await handlers.run_investigation_report(
                    InvestigationReportParams(incident_id="inc-404")
                )


# --------------------------------------------------------------------- #
# Config flag                                                           #
# --------------------------------------------------------------------- #


class TestSkillsFlag:
    def test_flag_defaults_off(self, monkeypatch: pytest.MonkeyPatch):
        from fortianalyzer_mcp.utils.config import Settings

        monkeypatch.delenv("FAZ_SKILLS_ENABLED", raising=False)
        assert Settings(FORTIANALYZER_HOST="192.0.2.1").FAZ_SKILLS_ENABLED is False
