"""Wave-3 analysis skill: investigate_deep.

Same conventions as ``test_skills_investigate.py``: composed handlers
import their tool functions lazily, so they are patched at their defining
modules with ``autospec=True``; the dispatcher path is exercised through
``faz_skill``. investigate_deep composes the whole ``investigate`` bundle
(reused as the base) plus a backward root-cause chain and a forward
per-entity lateral log_search fan-out, so the mocks are the union of the
base composition's readers plus ``query_logs`` for the forward pass.
"""

from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.catalog import SKILLS
from fortianalyzer_mcp.skills.dispatcher import faz_skill
from fortianalyzer_mcp.skills.models import (
    SCHEMA_VERSION,
    DeepInvestigateParams,
    FeatureGap,
    Impact,
    Investigation,
    RootCause,
)

GET_INCIDENT = "fortianalyzer_mcp.tools.incident_tools.get_incident"
GET_ALERTS = "fortianalyzer_mcp.tools.event_tools.get_alerts"
GET_ALERT_DETAILS = "fortianalyzer_mcp.tools.event_tools.get_alert_details"
GET_ALERT_LOGS = "fortianalyzer_mcp.tools.event_tools.get_alert_logs"
GET_ALERT_INCIDENT_STATS = "fortianalyzer_mcp.tools.event_tools.get_alert_incident_stats"
GET_TOP_THREATS = "fortianalyzer_mcp.tools.fortiview_tools.get_top_threats"
GET_LINKED = "fortianalyzer_mcp.tools.soar_tools.get_linked_indicators"
GET_ENRICH = "fortianalyzer_mcp.tools.soar_tools.get_indicator_enrichment"
GET_ENDPOINTS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoints"
GET_VULNS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoint_vulnerabilities"
GET_ENDUSERS = "fortianalyzer_mcp.tools.ueba_tools.get_endusers"
QUERY_LOGS = "fortianalyzer_mcp.tools.log_tools.query_logs"


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


def logs_ok(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """A successful query_logs envelope."""
    return {"status": "success", "tid": 1, "logs": rows, "total": len(rows)}


INCIDENT = {
    "incid": "inc-001",
    "name": "Malware Detection",
    "severity": "high",
    "status": "new",
    "timestamp": 1704067200,
    "epid": 6676,
    "euid": 42,
}
ALERT = {
    "alertid": "alert-001",
    "name": "Malware C2 traffic",
    "severity": "critical",
    "timestamp": 1704067300,
    "incids": ["inc-001"],
    "acknowledged": False,
}
TRIG_LOG = {"logid": "l-1", "itime": 1704067100, "logdesc": "C2 beacon"}
THREATS = [{"threat": "Backdoor.Agent", "threatweight": 500, "incidents": 3}]
ENDPOINT = {"epid": 6676, "epname": "EU-83LP4Y2", "epip": "192.0.2.7"}
ENDUSER = {"euid": 42, "euname": "chutter", "epid": [6676]}


class TestDeepCatalog:
    def test_registered_as_analysis_tier(self):
        assert "investigate_deep" in SKILLS
        assert SKILLS["investigate_deep"].tier == "analysis"

    def test_params_forbid_unknown_keys(self):
        with pytest.raises(ValidationError):
            DeepInvestigateParams(incident_id="inc-001", no_such_parameter=True)

    def test_requires_exactly_one_subject(self):
        with pytest.raises(ValidationError, match="exactly one"):
            DeepInvestigateParams()
        with pytest.raises(ValidationError, match="exactly one"):
            DeepInvestigateParams(alert_id="a", incident_id="i")
        with pytest.raises(ValidationError, match="exactly one"):
            DeepInvestigateParams(incident_id="i", entity="epid:1")


class TestDeepReactive:
    async def test_incident_subject_full_pass(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERTS, return_value=ok(data=[ALERT])),
            t(GET_ALERT_LOGS, return_value=ok(data=[TRIG_LOG])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={"alerts": 5})),
            t(GET_LINKED, return_value=ok(data=[])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_VULNS, return_value=ok(data=[])),
            t(GET_ENDUSERS, return_value=ok(data=[ENDUSER])),
            t(QUERY_LOGS, return_value=logs_ok([{"srcip": "192.0.2.7", "dstip": "203.0.113.9"}])),
        ):
            result = await handlers.run_investigate_deep(
                DeepInvestigateParams(incident_id="inc-001")
            )
        assert result.subject_type == "incident"
        assert isinstance(result.base, Investigation)
        assert result.base.triage.assessment.priority == "high"

        # Backward: root cause chain, ordered oldest-first to the earliest signal.
        assert isinstance(result.root_cause, RootCause)
        assert result.root_cause.event_count >= 1
        first = result.root_cause.earliest_signal
        assert first is not None
        assert result.root_cause.chain[0] is first
        # Incident subject (ts 1704067200) is earlier than its related alert
        # (ts 1704067300); triggering logs are attached to alert subjects, not
        # incidents, so the chain here is incident-then-alert.
        assert first.source == "incident"
        assert result.root_cause.chain[-1].source == "alert"

        # Forward: impact over the entity ids the subject carries (epid+euid).
        assert isinstance(result.impact, Impact)
        assert result.impact.entity_count == 2
        assert result.impact.lateral_searches_run > 0
        refs = {e.entity_ref for e in result.impact.entities}
        assert refs == {"6676", "42"}
        assert "priority high" in result.headline
        assert "root cause:" in result.headline
        assert "impact:" in result.headline

    async def test_alert_subject_root_cause_includes_triggering_log(self):
        # Alert subjects carry triggering logs; the log (itime 1704067100)
        # predates the alert (1704067300), so it is the earliest signal.
        with (
            t(GET_ALERTS, return_value=ok(data=[ALERT])),
            t(GET_ALERT_DETAILS, return_value=ok(data={"data": [{"alertid": "alert-001"}]})),
            t(GET_ALERT_LOGS, return_value=ok(data=[TRIG_LOG])),
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_LINKED, return_value=ok(data=[])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
            t(GET_ENDPOINTS, return_value=ok(data=[])),
            t(GET_ENDUSERS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_investigate_deep(
                DeepInvestigateParams(alert_id="alert-001", impact_logtypes=["traffic"])
            )
        assert result.subject_type == "alert"
        assert isinstance(result.root_cause, RootCause)
        first = result.root_cause.earliest_signal
        assert first is not None
        assert first.source == "log"
        assert first.reference == "l-1"

    async def test_lateral_pivots_on_epip_and_username(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_LINKED, return_value=ok(data=[])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_VULNS, return_value=ok(data=[])),
            t(GET_ENDUSERS, return_value=ok(data=[ENDUSER])),
            t(QUERY_LOGS, return_value=logs_ok([])) as ql,
        ):
            await handlers.run_investigate_deep(
                DeepInvestigateParams(
                    incident_id="inc-001", impact_logtypes=["traffic"], max_lateral_searches=8
                )
            )
        pivots = {c.kwargs["filter"] for c in ql.call_args_list}
        assert "srcip==192.0.2.7" in pivots
        assert "user==chutter" in pivots


class TestDeepForwardOnly:
    async def test_entity_epid_forward_only(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_VULNS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([{"srcip": "192.0.2.7"}])) as ql,
        ):
            result = await handlers.run_investigate_deep(
                DeepInvestigateParams(entity="epid:6676", impact_logtypes=["traffic", "dns"])
            )
        assert result.subject_type == "entity"
        # No incident to trace: base + root_cause are gaps.
        assert isinstance(result.base, FeatureGap)
        assert isinstance(result.root_cause, FeatureGap)
        # Only the forward pass runs, on the single endpoint.
        assert isinstance(result.impact, Impact)
        assert result.impact.entity_count == 1
        ent = result.impact.entities[0]
        assert ent.entity_type == "endpoint"
        assert ent.pivot == "srcip==192.0.2.7"
        assert ql.call_count == 2  # traffic + dns

    async def test_entity_bare_ip_forward_only(self):
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_investigate_deep(
                DeepInvestigateParams(entity="203.0.113.9", impact_logtypes=["traffic"])
            )
        assert result.subject_type == "entity"
        assert isinstance(result.impact, Impact)
        ent = result.impact.entities[0]
        assert ent.entity_type == "ip"
        assert ent.pivot == "srcip==203.0.113.9"
        assert ql.call_args.kwargs["filter"] == "srcip==203.0.113.9"

    async def test_unrecognized_entity_raises(self):
        with pytest.raises(handlers.SkillExecutionError, match="unrecognized entity"):
            await handlers.run_investigate_deep(DeepInvestigateParams(entity="not-an-entity"))


class TestDeepBounds:
    async def test_fanout_cap_drops_and_warns(self):
        # 1 entity × 4 logtypes but a cap of 2 → 2 run, 2 dropped, no silent loss.
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_VULNS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])) as ql,
        ):
            result = await handlers.run_investigate_deep(
                DeepInvestigateParams(
                    entity="epid:6676",
                    impact_logtypes=["traffic", "dns", "app-ctrl", "dlp"],
                    max_lateral_searches=2,
                )
            )
        assert ql.call_count == 2
        assert isinstance(result.impact, Impact)
        assert result.impact.lateral_searches_run == 2
        assert result.impact.lateral_searches_dropped == 2
        assert any("dropped by the fan-out cap" in w for w in result.warnings)
        ent = result.impact.entities[0]
        dropped = [k for k, v in ent.lateral_activity.items() if isinstance(v, FeatureGap)]
        assert set(dropped) == {"app-ctrl", "dlp"}

    async def test_window_capped_to_seven_day(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_VULNS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])) as ql,
        ):
            result = await handlers.run_investigate_deep(
                DeepInvestigateParams(
                    entity="epid:6676", impact_logtypes=["traffic"], time_range="30-day"
                )
            )
        assert result.time_range == "7-day"
        assert ql.call_args.kwargs["time_range"] == "7-day"
        assert any("capped to '7-day'" in w for w in result.warnings)

    async def test_impact_disabled(self):
        with (
            t(GET_ENDPOINTS) as endpoints_mock,
            t(QUERY_LOGS) as ql,
        ):
            result = await handlers.run_investigate_deep(
                DeepInvestigateParams(entity="epid:6676", include_impact=False)
            )
        ql.assert_not_called()
        endpoints_mock.assert_not_called()
        assert isinstance(result.impact, FeatureGap)
        assert "include_impact" in result.impact.reason


class TestDeepDegradation:
    async def test_subject_without_entities_gaps_impact(self):
        no_entities = {k: v for k, v in INCIDENT.items() if k not in ("epid", "euid")}
        with (
            t(GET_INCIDENT, return_value=ok(data=no_entities)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_LINKED, return_value=ok(data=[])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
            t(QUERY_LOGS) as ql,
        ):
            result = await handlers.run_investigate_deep(
                DeepInvestigateParams(incident_id="inc-001")
            )
        ql.assert_not_called()
        assert isinstance(result.impact, FeatureGap)
        assert "would be a guess" in result.impact.reason
        # The base + root_cause survive: a subject with no entities still has a timeline.
        assert isinstance(result.base, Investigation)
        assert isinstance(result.root_cause, RootCause)

    async def test_base_subject_failure_raises(self):
        with t(GET_INCIDENT, return_value={"status": "error", "error": "not_found"}):
            with pytest.raises(handlers.SkillExecutionError, match="inc-404"):
                await handlers.run_investigate_deep(DeepInvestigateParams(incident_id="inc-404"))

    async def test_lateral_search_failure_degrades_to_gap(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_VULNS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value={"status": "error", "message": "logview unavailable"}),
        ):
            result = await handlers.run_investigate_deep(
                DeepInvestigateParams(entity="epid:6676", impact_logtypes=["traffic"])
            )
        assert isinstance(result.impact, Impact)
        section = result.impact.entities[0].lateral_activity["traffic"]
        assert isinstance(section, FeatureGap)
        assert any("traffic search unavailable" in w for w in result.warnings)

    async def test_endpoint_without_epip_pivot_gaps(self):
        no_epip = {"epid": 6676, "epname": "EU-83LP4Y2"}  # no epip
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[no_epip])),
            t(GET_VULNS, return_value=ok(data=[])),
            t(QUERY_LOGS) as ql,
        ):
            result = await handlers.run_investigate_deep(
                DeepInvestigateParams(entity="epid:6676", impact_logtypes=["traffic"])
            )
        ql.assert_not_called()
        assert isinstance(result.impact, Impact)
        ent = result.impact.entities[0]
        assert ent.pivot is None
        section = ent.lateral_activity["traffic"]
        assert isinstance(section, FeatureGap)
        assert "would be a guess" in section.reason


class TestDeepDispatch:
    async def test_success_envelope(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_VULNS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await faz_skill(
                skill="investigate_deep",
                params={"entity": "epid:6676", "impact_logtypes": ["traffic"]},
            )
        assert result["status"] == "success"
        assert result["skill"] == "investigate_deep"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["subject_type"] == "entity"
        assert result["result"]["impact"]["entity_count"] == 1

    async def test_missing_subject_rejected(self):
        result = await faz_skill(skill="investigate_deep", params={})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
