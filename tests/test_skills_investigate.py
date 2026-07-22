"""Wave-2 analysis skill: investigate.

Same conventions as ``test_skills_threat_intel.py``: handlers are tested
by patching the underlying tool functions at their defining modules with
``autospec=True`` (the composed handlers import them lazily per call),
and the dispatcher path is exercised end-to-end through ``faz_skill``.
``investigate`` is pure composition, so the mocks are the union of the
composed skills' readers; attachment lookups are left unpatched where the
linkage-key fallback keeps the fixture small (the composed skills' own
suites cover the attachment path).
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
    AssetLookupResult,
    FeatureGap,
    IdentityLookupResult,
    IncidentSummary,
    InvestigateParams,
    ThreatIntelResult,
)

GET_INCIDENT = "fortianalyzer_mcp.tools.incident_tools.get_incident"
GET_INCIDENTS = "fortianalyzer_mcp.tools.incident_tools.get_incidents"
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


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


ALERT = {
    "alertid": "alert-001",
    "name": "Malware C2 traffic",
    "severity": "critical",
    "timestamp": 1704067300,
    "incids": ["inc-001"],
    "acknowledged": False,
}
INCIDENT = {
    "incid": "inc-001",
    "name": "Malware Detection",
    "severity": "high",
    "status": "new",
    "timestamp": 1704067200,
}
# Incident subject variant carrying entity ids for the asset/identity path.
INCIDENT_WITH_ENTITIES = {**INCIDENT, "epid": 7, "euid": 3}
DETAILS = ok(
    data={"data": [{"alertid": "alert-001", "devs": ["FGT-01"], "epids": [7], "euids": [3]}]}
)
LINKED_INDICATORS = [{"value": "203.0.113.7", "type": "IP", "indicator-uuid": "iu-0001"}]
ENRICHED_IP = {
    "value": "203.0.113.7",
    "type": "IP",
    "enrichment-reputation": "Malicious",
    "enrichment-confidence": 92,
    "enrichment-status": "Completed",
    "indicator-uuid": "iu-0001",
    "enrichment-uuid": "eu-0001",
}
THREATS = [{"threat": "Backdoor.Agent", "threatweight": 500, "incidents": 3}]
ENDPOINT = {"epid": 7, "epname": "ws-finance-01", "epip": "192.0.2.7"}
ENDUSER = {"euid": 3, "euname": "roland"}


class TestInvestigateCatalog:
    def test_registered_as_analysis_tier(self):
        assert "investigate" in SKILLS
        assert SKILLS["investigate"].tier == "analysis"

    def test_params_forbid_unknown_keys(self):
        with pytest.raises(ValidationError):
            InvestigateParams(incident_id="inc-001", no_such_parameter=True)

    def test_requires_exactly_one_subject(self):
        with pytest.raises(ValidationError, match="exactly one"):
            InvestigateParams()
        with pytest.raises(ValidationError, match="exactly one"):
            InvestigateParams(alert_id="a", incident_id="i")


class TestInvestigate:
    async def test_incident_subject_composes_all_sections(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT_WITH_ENTITIES)),
            t(GET_ALERTS, return_value=ok(data=[ALERT])),
            t(GET_ALERT_LOGS, return_value=ok(data=[{"logid": "l-1"}])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={"alerts": 5})),
            t(GET_LINKED, return_value=ok(data=LINKED_INDICATORS)) as linked_mock,
            t(GET_ENRICH, return_value=ok(data=[ENRICHED_IP])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])) as endpoints_mock,
            t(GET_VULNS, return_value=ok(data=[])),
            t(GET_ENDUSERS, return_value=ok(data=[ENDUSER])) as endusers_mock,
        ):
            result = await handlers.run_investigate(InvestigateParams(incident_id="inc-001"))
        assert result.subject_type == "incident"
        assert result.triage.subject == INCIDENT_WITH_ENTITIES
        assert result.triage.assessment.priority == "high"
        assert isinstance(result.summary, IncidentSummary)
        assert result.summary.counts["alerts"] == 1
        # The summary never re-fetches the landscape; threat_intel owns it.
        assert isinstance(result.summary.threat_landscape, FeatureGap)
        assert isinstance(result.threat_intel, ThreatIntelResult)
        assert result.threat_intel.indicators[0].reputation == "Malicious"
        assert result.threat_intel.threat_landscape == THREATS
        assert linked_mock.call_args.kwargs["incident_id"] == "inc-001"
        assert linked_mock.call_args.kwargs["time_range"] == "7-day"
        assert isinstance(result.assets, AssetLookupResult)
        assert result.assets.endpoint_count == 1
        assert endpoints_mock.call_args.kwargs["epids"] == [7]
        assert isinstance(result.identities, IdentityLookupResult)
        assert result.identities.user_count == 1
        assert endusers_mock.call_args.kwargs["euids"] == [3]
        assert result.headline == (
            "incident inc-001: priority high; 1 linked indicators (1 malicious); "
            "1 linked endpoints; 1 linked users"
        )
        assert result.time_range == "7-day"

    async def test_alert_subject_summarizes_attached_incident(self):
        with (
            t(GET_ALERTS, return_value=ok(data=[ALERT])),
            t(GET_ALERT_DETAILS, return_value=DETAILS),
            t(GET_ALERT_LOGS, return_value=ok(data=[{"logid": "l-1"}])),
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)) as incident_mock,
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_LINKED, return_value=ok(data=LINKED_INDICATORS)) as linked_mock,
            t(GET_ENRICH, return_value=ok(data=[ENRICHED_IP])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])) as endpoints_mock,
            t(GET_VULNS, return_value=ok(data=[])),
            t(GET_ENDUSERS, return_value=ok(data=[ENDUSER])),
        ):
            result = await handlers.run_investigate(InvestigateParams(alert_id="alert-001"))
        assert result.subject_type == "alert"
        assert result.triage.assessment.priority == "urgent"  # critical -> urgent
        # The alert's incids linkage resolved incident inc-001; the summary
        # section is that incident's deep summary.
        assert isinstance(result.summary, IncidentSummary)
        assert result.summary.incident == INCIDENT
        assert any(c.kwargs["incident_id"] == "inc-001" for c in incident_mock.call_args_list)
        assert linked_mock.call_args.kwargs["alert_id"] == "alert-001"
        # Entity ids come from the alert's extra-details (epids/euids).
        assert endpoints_mock.call_args.kwargs["epids"] == [7]
        assert isinstance(result.identities, IdentityLookupResult)

    async def test_subject_resolution_failure_raises(self):
        with t(GET_INCIDENT, return_value={"status": "error", "error": "not_found"}):
            with pytest.raises(handlers.SkillExecutionError, match="inc-404"):
                await handlers.run_investigate(InvestigateParams(incident_id="inc-404"))

    async def test_soar_failure_degrades_to_gap(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_LINKED, return_value={"status": "error", "message": "SOAR not licensed"}),
        ):
            result = await handlers.run_investigate(InvestigateParams(incident_id="inc-001"))
        assert isinstance(result.threat_intel, FeatureGap)
        assert "SOAR not licensed" in result.threat_intel.reason
        assert any("indicator enrichment unavailable" in w for w in result.warnings)
        # The subject sections survive the enrichment failure.
        assert result.triage.subject == INCIDENT
        assert isinstance(result.summary, IncidentSummary)

    async def test_subject_without_entity_ids_gaps_not_guesses(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),  # no epid/euid fields
            t(GET_ALERTS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_LINKED, return_value=ok(data=[])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
            t(GET_ENDPOINTS) as endpoints_mock,
            t(GET_ENDUSERS) as endusers_mock,
        ):
            result = await handlers.run_investigate(InvestigateParams(incident_id="inc-001"))
        endpoints_mock.assert_not_called()
        endusers_mock.assert_not_called()
        assert isinstance(result.assets, FeatureGap)
        assert "would be a guess" in result.assets.reason
        assert isinstance(result.identities, FeatureGap)
        assert "would be a guess" in result.identities.reason

    async def test_entities_disabled_skips_readers(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT_WITH_ENTITIES)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_LINKED, return_value=ok(data=[])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
            t(GET_ENDPOINTS) as endpoints_mock,
            t(GET_ENDUSERS) as endusers_mock,
        ):
            result = await handlers.run_investigate(
                InvestigateParams(incident_id="inc-001", include_entities=False)
            )
        endpoints_mock.assert_not_called()
        endusers_mock.assert_not_called()
        assert isinstance(result.assets, FeatureGap)
        assert "include_entities" in result.assets.reason

    async def test_warnings_aggregate_with_section_prefixes(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_LINKED, return_value=ok(data=[])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
        ):
            result = await handlers.run_investigate(InvestigateParams(incident_id="inc-001"))
        # threat_intel's own "no indicators linked" warning surfaces prefixed.
        assert any(w.startswith("threat_intel: no indicators linked") for w in result.warnings)
        # ... and stays verbatim on the nested result too.
        assert isinstance(result.threat_intel, ThreatIntelResult)
        assert any("no indicators linked" in w for w in result.threat_intel.warnings)


class TestInvestigateDispatch:
    async def test_success_envelope(self):
        with (
            t(GET_INCIDENT, return_value=ok(data=INCIDENT)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_LINKED, return_value=ok(data=[])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
        ):
            result = await faz_skill(skill="investigate", params={"incident_id": "inc-001"})
        assert result["status"] == "success"
        assert result["skill"] == "investigate"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["subject_type"] == "incident"
        assert result["result"]["headline"].startswith("incident inc-001: priority high")
        assert result["result"]["triage"]["subject"] == INCIDENT

    async def test_missing_subject_rejected(self):
        result = await faz_skill(skill="investigate", params={})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
