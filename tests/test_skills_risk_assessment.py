"""risk_assessment enrichment skill.

Same conventions as ``test_skills_wave2.py``: handlers are tested by
patching the underlying tool functions at their defining modules with
``autospec=True`` (the handler imports them lazily per call), and the
dispatcher path is exercised end-to-end through ``faz_skill``.

Scoring is deterministic, so the happy-path tests assert exact composite
values derived by hand from the documented formula.
"""

from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.catalog import SKILLS
from fortianalyzer_mcp.skills.dispatcher import faz_skill
from fortianalyzer_mcp.skills.models import SCHEMA_VERSION, RiskAssessmentParams

GET_ENDPOINTS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoints"
GET_ENDPOINT_VULNS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoint_vulnerabilities"
GET_ENDUSERS = "fortianalyzer_mcp.tools.ueba_tools.get_endusers"
GET_FORTIVIEW = "fortianalyzer_mcp.tools.fortiview_tools.get_fortiview_data"
QUERY_LOGS = "fortianalyzer_mcp.tools.log_tools.query_logs"


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


def logs_ok(failures: int, **overrides: Any) -> dict[str, Any]:
    """A successful query_logs envelope with a known failure total."""
    payload = {
        "logs": [{"action": "failure"}] * failures,
        "total": failures,
        "total_is_known": True,
        "has_more": False,
    }
    payload.update(overrides)
    return ok(**payload)


ENDPOINT = {"epid": 1025, "epname": "WS-ALPHA", "epip": "192.0.2.10"}
ENDUSER = {"euid": 7, "euname": "alice"}

# crit 1 / high 1 / med 1 / low 1 -> vuln = 25 + 10 + 3 + 1 = 39
VULN_PAYLOAD = [
    {
        "epid": 1025,
        "vuln": [
            {"vulnid": "CVE-2024-0001", "severity": "Critical"},
            {"vulnid": "CVE-2024-0002", "severity": "high"},
            {"vulnid": "CVE-2024-0003", "severity": "Medium"},
            {"vulnid": "CVE-2024-0004", "severity": "low"},
        ],
    }
]
# crit 1 / high 1 -> threat = 25 + 10 = 35
THREAT_ROWS = [
    {"threat": "Backdoor.Rat", "severity": "Critical"},
    {"threat": "Adware.Gen", "severity": "high"},
]
# failures 4 -> auth = 20
# composite = round(0.40*39 + 0.35*35 + 0.25*20) = round(32.85) = 33 -> "medium"
EXPECTED_COMPOSITE = 33


class TestCatalog:
    def test_registered_as_enrichment(self):
        assert "risk_assessment" in SKILLS
        assert SKILLS["risk_assessment"].tier == "enrichment"

    def test_params_forbid_unknown_keys(self):
        with pytest.raises(ValidationError):
            RiskAssessmentParams(epid=1, no_such_parameter=True)

    def test_exactly_one_entity_required(self):
        with pytest.raises(ValidationError, match="exactly one"):
            RiskAssessmentParams()
        with pytest.raises(ValidationError, match="exactly one"):
            RiskAssessmentParams(epid=1, euid=2)


class TestEndpointScoring:
    async def test_exact_composite_from_known_inputs(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])) as eps,
            t(GET_ENDPOINT_VULNS, return_value=ok(data=VULN_PAYLOAD)) as vulns,
            t(GET_FORTIVIEW, return_value=ok(data=THREAT_ROWS)) as fortiview,
            t(QUERY_LOGS, return_value=logs_ok(4)) as logs,
        ):
            result = await handlers.run_risk_assessment(RiskAssessmentParams(epid=1025))

        assert eps.call_args.kwargs["epids"] == [1025]
        assert eps.call_args.kwargs["detail_level"] == "simple"
        assert vulns.call_args.kwargs["epids"] == [1025]
        assert fortiview.call_args.kwargs["view_name"] == "top-threats"
        assert fortiview.call_args.kwargs["filter"] == "srcip==192.0.2.10"
        assert logs.call_args.kwargs["logtype"] == "event"
        assert logs.call_args.kwargs["filter"] == "action==failure and srcip==192.0.2.10"

        assert result.entity == {"type": "endpoint", "epid": 1025, "record": ENDPOINT}
        assert result.vulnerability.raw_counts == {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
        }
        assert result.vulnerability.subscore == 39
        assert result.vulnerability.weight == handlers._W_VULN
        assert result.threat.raw_counts == {"critical": 1, "high": 1}
        assert result.threat.subscore == 35
        assert result.threat.weight == handlers._W_THREAT
        assert result.auth_failure.raw_counts == {"failures": 4}
        assert result.auth_failure.subscore == 20
        assert result.auth_failure.weight == handlers._W_AUTH
        assert result.composite_score == EXPECTED_COMPOSITE
        assert result.band == "medium"
        assert result.time_range == "7-day"
        assert result.warnings == []

    async def test_subscores_cap_at_100(self):
        heavy_vulns = [{"epid": 1025, "vuln": [{"severity": "critical"}] * 5}]  # 125 -> 100
        heavy_threats = [{"severity": "critical"}] * 5  # 125 -> 100
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=heavy_vulns)),
            t(GET_FORTIVIEW, return_value=ok(data=heavy_threats)),
            t(QUERY_LOGS, return_value=logs_ok(30)),  # 150 -> 100
        ):
            result = await handlers.run_risk_assessment(RiskAssessmentParams(epid=1025))
        assert result.vulnerability.subscore == 100
        assert result.threat.subscore == 100
        assert result.auth_failure.subscore == 100
        assert result.composite_score == 100
        assert result.band == "critical"

    async def test_unknown_severity_reported_but_scores_zero(self):
        odd = [{"epid": 1025, "vuln": [{"severity": "Info"}, {"severity": "high"}]}]
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=odd)),
            t(GET_FORTIVIEW, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok(0)),
        ):
            result = await handlers.run_risk_assessment(RiskAssessmentParams(epid=1025))
        assert result.vulnerability.raw_counts == {"info": 1, "high": 1}
        assert result.vulnerability.subscore == 10  # only "high" scores

    async def test_detectby_forwarded_to_vuln_reader(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=[])) as vulns,
            t(GET_FORTIVIEW, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok(0)),
        ):
            await handlers.run_risk_assessment(
                RiskAssessmentParams(epid=1025, detectby="FortiClient")
            )
        assert vulns.call_args.kwargs["detectby"] == "FortiClient"

    async def test_unknown_total_falls_back_to_row_count_with_bound_warning(self):
        partial = logs_ok(0, logs=[{}] * 3, total=None, total_is_known=False, has_more=True)
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=[])),
            t(GET_FORTIVIEW, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=partial),
        ):
            result = await handlers.run_risk_assessment(RiskAssessmentParams(epid=1025))
        assert result.auth_failure.raw_counts == {"failures": 3}
        assert result.auth_failure.subscore == 15
        assert any("lower bound" in w for w in result.warnings)


class TestEnduserScoring:
    async def test_user_without_endpoint_link_degrades_vuln_dimension(self):
        with (
            t(GET_ENDUSERS, return_value=ok(data=[ENDUSER])) as users,
            t(GET_ENDPOINT_VULNS) as vulns,
            t(GET_FORTIVIEW, return_value=ok(data=[])) as fortiview,
            t(QUERY_LOGS, return_value=logs_ok(3)) as logs,
        ):
            result = await handlers.run_risk_assessment(RiskAssessmentParams(euid=7))
        assert users.call_args.kwargs["euids"] == [7]
        vulns.assert_not_called()
        assert fortiview.call_args.kwargs["filter"] == "user==alice"
        assert logs.call_args.kwargs["filter"] == "action==failure and user==alice"
        assert result.entity == {"type": "enduser", "euid": 7, "record": ENDUSER}
        assert result.vulnerability.subscore == 0
        assert result.vulnerability.raw_counts == {}
        assert any("no endpoint id associated" in w for w in result.warnings)
        # composite = round(0.40*0 + 0.35*0 + 0.25*15) = round(3.75) = 4
        assert result.auth_failure.subscore == 15
        assert result.composite_score == 4
        assert result.band == "low"

    async def test_user_with_endpoint_link_scopes_vuln_reader(self):
        linked = {"euid": 7, "euname": "alice", "epids": [1025, 2048]}
        with (
            t(GET_ENDUSERS, return_value=ok(data=[linked])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=[])) as vulns,
            t(GET_FORTIVIEW, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok(0)),
        ):
            await handlers.run_risk_assessment(RiskAssessmentParams(euid=7))
        assert vulns.call_args.kwargs["epids"] == [1025, 2048]


class TestSubjectFailures:
    async def test_endpoint_not_found_raises(self):
        with t(GET_ENDPOINTS, return_value=ok(data=[])):
            with pytest.raises(handlers.SkillExecutionError, match="endpoint 1025 not found"):
                await handlers.run_risk_assessment(RiskAssessmentParams(epid=1025))

    async def test_endpoint_read_failure_raises(self):
        with t(GET_ENDPOINTS, return_value={"status": "error", "message": "no UEBA license"}):
            with pytest.raises(handlers.SkillExecutionError, match="could not resolve endpoint"):
                await handlers.run_risk_assessment(RiskAssessmentParams(epid=1025))

    async def test_enduser_not_found_raises(self):
        with t(GET_ENDUSERS, return_value=ok(data=[{"euid": 99, "euname": "other"}])):
            with pytest.raises(handlers.SkillExecutionError, match="end-user 7 not found"):
                await handlers.run_risk_assessment(RiskAssessmentParams(euid=7))


class TestDimensionDegradation:
    async def test_vuln_read_failure_scores_zero_with_warning(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_ENDPOINT_VULNS, return_value={"status": "error", "message": "UEBA off"}),
            t(GET_FORTIVIEW, return_value=ok(data=[{"severity": "critical"}])),  # 25
            t(QUERY_LOGS, return_value=logs_ok(2)),  # 10
        ):
            result = await handlers.run_risk_assessment(RiskAssessmentParams(epid=1025))
        assert result.vulnerability.subscore == 0
        assert result.vulnerability.raw_counts == {}
        assert any("vulnerability dimension unavailable" in w for w in result.warnings)
        # composite = round(0.40*0 + 0.35*25 + 0.25*10) = round(11.25) = 11
        assert result.composite_score == 11
        assert result.band == "low"

    async def test_threat_read_failure_scores_zero_with_warning(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=VULN_PAYLOAD)),
            t(GET_FORTIVIEW, return_value={"status": "error", "message": "timeout"}),
            t(QUERY_LOGS, return_value=logs_ok(4)),
        ):
            result = await handlers.run_risk_assessment(RiskAssessmentParams(epid=1025))
        assert result.threat.subscore == 0
        assert any("threat dimension unavailable" in w for w in result.warnings)
        # composite = round(0.40*39 + 0.35*0 + 0.25*20) = round(20.6) = 21
        assert result.composite_score == 21

    async def test_auth_read_exception_scores_zero_with_warning(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=[])),
            t(GET_FORTIVIEW, return_value=ok(data=[])),
            t(QUERY_LOGS, side_effect=RuntimeError("search slot exhausted")),
        ):
            result = await handlers.run_risk_assessment(RiskAssessmentParams(epid=1025))
        assert result.auth_failure.subscore == 0
        assert result.auth_failure.raw_counts == {}
        assert any("auth-failure dimension unavailable" in w for w in result.warnings)
        assert result.composite_score == 0
        assert result.band == "low"


class TestBands:
    @pytest.mark.parametrize(
        ("score", "band"),
        [
            (0, "low"),
            (24, "low"),
            (25, "medium"),
            (49, "medium"),
            (50, "high"),
            (74, "high"),
            (75, "critical"),
            (100, "critical"),
        ],
    )
    def test_band_boundaries(self, score: int, band: str):
        assert handlers._risk_band(score) == band


class TestDispatch:
    async def test_success_envelope(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=VULN_PAYLOAD)),
            t(GET_FORTIVIEW, return_value=ok(data=THREAT_ROWS)),
            t(QUERY_LOGS, return_value=logs_ok(4)),
        ):
            result = await faz_skill(skill="risk_assessment", params={"epid": 1025})
        assert result["status"] == "success"
        assert result["skill"] == "risk_assessment"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["composite_score"] == EXPECTED_COMPOSITE
        assert result["result"]["band"] == "medium"

    async def test_subject_failure_maps_to_skill_failed(self):
        with t(GET_ENDPOINTS, return_value=ok(data=[])):
            result = await faz_skill(skill="risk_assessment", params={"epid": 1025})
        assert result["status"] == "error"
        assert result["error"] == "skill_failed"

    async def test_invalid_params_rejected(self):
        result = await faz_skill(skill="risk_assessment", params={"epid": 1, "euid": 2})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
