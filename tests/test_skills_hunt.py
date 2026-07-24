"""Wave-3 analysis skill: hunt.

Same conventions as ``test_skills_investigate_deep.py``: composed handlers
import their tool functions lazily, so they are patched at their defining
modules with ``autospec=True``; the dispatcher path is exercised through
``faz_skill``. ``hunt`` has two halves — a log_search + threat_intel sweep
and a percentile-calibrated UEBA behaviour profile — so the mocks are
``query_logs`` (sweep), the SOAR readers (threat_intel), and the UEBA
endpoint/end-user + alert readers (behaviour). The estate-stats readers are
optional and absent on this branch, so that section degrades to a gap.
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
    EntityBehavior,
    FeatureGap,
    HuntParams,
    HuntSweep,
    IndicatorSubject,
)

GET_ALERTS = "fortianalyzer_mcp.tools.event_tools.get_alerts"
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


# The fixture host: risk_score 0.248 among a crowd of ~0.1x hosts, plus
# critical/high vuln-stats — the RFC's "genuinely high-risk entity" case.
HOT_ENDPOINT = {
    "epid": 6676,
    "epname": "EU-83LP4Y2",
    "epip": "192.0.2.7",
    "risk_score": 0.248,
    "importance": "high",
    "vuln-stats": {"cnt_cri": 3, "cnt_hig": 12, "cnt_med": 8, "cnt_low": 10},
}
# The low-risk crowd (0.1x) the hot host must be distinguished from.
CROWD = [
    {"epid": i, "epname": f"host-{i}", "epip": f"10.0.0.{i}", "risk_score": 0.10 + (i % 5) * 0.01}
    for i in range(1, 40)
]
ESTATE = CROWD + [HOT_ENDPOINT]

ENDUSER = {"euid": 42, "euname": "chutter", "importance": "high"}
BOTNET_ALERT = {
    "alertid": "a-1",
    "alerttype": "Default-Botnet-Communication-Detection-By-Endpoint",
    "severity": "critical",
}
BENIGN_ALERT = {"alertid": "a-2", "alerttype": "Traffic-Baseline", "severity": "low"}
THREATS = [{"threat": "Backdoor.Agent", "threatweight": 500}]


class TestHuntCatalog:
    def test_registered_as_analysis_tier(self):
        assert "hunt" in SKILLS
        assert SKILLS["hunt"].tier == "analysis"

    def test_params_forbid_unknown_keys(self):
        with pytest.raises(ValidationError):
            HuntParams(entity="epid:6676", no_such_parameter=True)

    def test_requires_exactly_one_subject(self):
        with pytest.raises(ValidationError, match="exactly one subject"):
            HuntParams()
        with pytest.raises(ValidationError, match="exactly one subject"):
            HuntParams(entity="epid:1", indicator=IndicatorSubject(value="1.2.3.4", type="IP"))
        with pytest.raises(ValidationError, match="exactly one subject"):
            HuntParams(indicator=IndicatorSubject(value="1.2.3.4", type="IP"), filter="x==y")

    def test_filter_and_ttp_together_are_one_subject(self):
        # filter+ttp count as a single (hypothesis) shape, not two subjects.
        HuntParams(filter="attack=~x", ttp="T1071")


class TestHuntSweep:
    async def test_indicator_ip_sweep_and_threat_intel(self):
        with (
            t(QUERY_LOGS, return_value=logs_ok([{"srcip": "198.21.33.3"}])) as ql,
            t(GET_LINKED, return_value=ok(data=[])),
            t(
                GET_ENRICH,
                return_value=ok(
                    data=[{"value": "198.21.33.3", "enrichment-reputation": "Malicious"}]
                ),
            ),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
        ):
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="198.21.33.3", type="IP"),
                    sweep_logtypes=["traffic", "attack"],
                )
            )
        assert result.subject_type == "indicator"
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == "srcip==198.21.33.3"
        assert result.sweep.sweep_searches_run == 2
        assert result.sweep.total_matches == 2  # one row per logtype
        # Every sweep search ran on the indicator pivot.
        assert all(c.kwargs["filter"] == "srcip==198.21.33.3" for c in ql.call_args_list)
        # An IP indicator gets SOAR reputation; behaviour half is a gap.
        assert not isinstance(result.sweep.threat_intel, FeatureGap)
        assert isinstance(result.behavior, FeatureGap)

    async def test_hash_indicator_has_no_soar_reputation(self):
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="deadbeef", type="Hash"),
                    sweep_logtypes=["traffic"],
                )
            )
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == "checksum=~deadbeef"
        assert isinstance(result.sweep.threat_intel, FeatureGap)
        assert ql.call_args.kwargs["filter"] == "checksum=~deadbeef"

    async def test_filter_hypothesis_sweep(self):
        with t(QUERY_LOGS, return_value=logs_ok([{"x": 1}])) as ql:
            result = await handlers.run_hunt(
                HuntParams(filter="dstport==4444", ttp="T1571", sweep_logtypes=["traffic"])
            )
        assert result.subject_type == "hypothesis"
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == "dstport==4444"
        assert result.sweep.ttp == "T1571"
        assert ql.call_args.kwargs["filter"] == "dstport==4444"

    async def test_sweep_fanout_cap_drops_and_warns(self):
        # 4 logtypes but a cap of 2 -> 2 run, 2 dropped, no silent loss.
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(
                    filter="x==y",
                    sweep_logtypes=["traffic", "attack", "app-ctrl", "dns"],
                    max_sweep_searches=2,
                )
            )
        assert ql.call_count == 2
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.sweep_searches_run == 2
        assert result.sweep.sweep_searches_dropped == 2
        assert any("dropped by the fan-out cap" in w for w in result.warnings)
        dropped = [m.logtype for m in result.sweep.matches if isinstance(m.rows, FeatureGap)]
        assert set(dropped) == {"app-ctrl", "dns"}

    async def test_window_capped_to_seven_day(self):
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(filter="x==y", sweep_logtypes=["traffic"], time_range="30-day")
            )
        assert result.time_range == "7-day"
        assert ql.call_args.kwargs["time_range"] == "7-day"
        assert any("capped to '7-day'" in w for w in result.warnings)

    async def test_sweep_search_failure_degrades_to_gap(self):
        with t(QUERY_LOGS, return_value={"status": "error", "message": "logview unavailable"}):
            result = await handlers.run_hunt(HuntParams(filter="x==y", sweep_logtypes=["traffic"]))
        assert isinstance(result.sweep, HuntSweep)
        assert isinstance(result.sweep.matches[0].rows, FeatureGap)
        assert any("search unavailable" in w for w in result.warnings)


class TestHuntBehaviorPercentile:
    async def test_high_risk_entity_flagged_among_low_risk_peers(self):
        # THE calibration test: 0.248 among ~40 hosts at 0.10-0.14 must land at
        # a high percentile and be flagged anomalous — a fixed "risk>0.5" cut
        # would never fire on 0.248.
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ALERTS, return_value=ok(data=[BOTNET_ALERT, BENIGN_ALERT])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(
                HuntParams(entity="epid:6676", sweep_logtypes=["traffic"])
            )
        assert result.subject_type == "entity"
        assert isinstance(result.behavior, EntityBehavior)
        b = result.behavior
        assert b.entity_type == "endpoint"
        assert b.risk_score == 0.248
        # 0.248 is the max of the estate -> 100th percentile, >= default 90.
        assert b.risk_percentile == 100.0
        assert b.anomalous is True
        # Percentile is the driving flag, and the basis is auditable.
        assert any("percentile" in reason and "ANOMALOUS" in reason for reason in b.anomaly_basis)
        # vuln-stats surfaced per severity.
        assert b.vuln_stats["critical"] == 3
        assert b.vuln_stats["high"] == 12
        # Only the behavioural alert is kept (benign one filtered out).
        assert not isinstance(b.behavioral_detections, FeatureGap)
        assert b.detection_count == 1
        assert b.behavioral_detections[0]["alertid"] == "a-1"

    async def test_low_risk_entity_not_flagged_by_percentile(self):
        # A mid-pack host with no vulns and no detections is NOT anomalous —
        # proves the percentile actually discriminates.
        target = {"epid": 5, "epname": "host-5", "epip": "10.0.0.5", "risk_score": 0.11}
        estate = CROWD + [HOT_ENDPOINT]  # target already in CROWD (epid 5)
        assert target["risk_score"] < 0.15
        with (
            t(GET_ENDPOINTS, return_value=ok(data=estate)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:5"))
        assert isinstance(result.behavior, EntityBehavior)
        b = result.behavior
        assert b.risk_percentile is not None
        assert b.risk_percentile < 90.0
        assert b.anomalous is False

    async def test_serious_vuln_fires_even_if_mid_percentile(self):
        # A host mid-pack on risk but carrying a critical CVE is still flagged.
        vuln_host = {
            "epid": 900,
            "epname": "host-900",
            "epip": "10.0.9.0",
            "risk_score": 0.11,
            "vuln-stats": {"cnt_cri": 1},
        }
        with (
            t(GET_ENDPOINTS, return_value=ok(data=CROWD + [vuln_host, HOT_ENDPOINT])),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:900"))
        assert isinstance(result.behavior, EntityBehavior)
        assert result.behavior.anomalous is True
        assert any("serious vulnerabilities" in r for r in result.behavior.anomaly_basis)

    async def test_single_endpoint_estate_yields_no_percentile(self):
        # A one-host estate cannot be ranked; no false "100th percentile".
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[HOT_ENDPOINT])),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:6676"))
        assert isinstance(result.behavior, EntityBehavior)
        assert result.behavior.risk_percentile is None
        # Still anomalous — the serious vuln-stats flag carries it.
        assert result.behavior.anomalous is True
        assert any("too small to rank" in r for r in result.behavior.anomaly_basis)

    async def test_enduser_has_no_risk_score(self):
        with (
            t(GET_ENDUSERS, return_value=ok(data=[ENDUSER])),
            t(GET_ALERTS, return_value=ok(data=[BOTNET_ALERT])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="euid:42"))
        assert isinstance(result.behavior, EntityBehavior)
        b = result.behavior
        assert b.entity_type == "enduser"
        assert b.risk_score is None
        assert b.risk_percentile is None
        assert b.importance == "high"
        # importance high + a detection -> anomalous.
        assert b.anomalous is True

    async def test_entity_subject_runs_entity_scoped_sweep(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])) as ql,
        ):
            result = await handlers.run_hunt(
                HuntParams(entity="epid:6676", sweep_logtypes=["traffic"])
            )
        # The entity subject also sweeps on its own srcip pivot.
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == "srcip==192.0.2.7"
        assert ql.call_args.kwargs["filter"] == "srcip==192.0.2.7"

    async def test_estate_read_is_unwindowed(self):
        # The percentile denominator is the full inventory: the estate read
        # must NOT pass a time_range (which filters by first-seen and would
        # shrink the population / drop the target). Live-verified regression.
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)) as eps,
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            await handlers.run_hunt(HuntParams(entity="epid:6676", time_range="30-day"))
        assert eps.call_args.kwargs.get("time_range") is None

    async def test_string_risk_scores_are_ranked(self):
        # Live FAZ returns risk_score as a float-valued string; the population
        # and the target value must both coerce, or nothing ranks.
        estate = [
            {"epid": 1, "epname": "a", "epip": "10.0.0.1", "risk_score": "0.10"},
            {"epid": 2, "epname": "b", "epip": "10.0.0.2", "risk_score": "0.11"},
            {"epid": 3, "epname": "c", "epip": "10.0.0.3", "risk_score": "0.25"},
        ]
        with (
            t(GET_ENDPOINTS, return_value=ok(data=estate)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:3"))
        assert isinstance(result.behavior, EntityBehavior)
        assert result.behavior.risk_score == 0.25
        assert result.behavior.risk_percentile == 100.0
        assert result.behavior.anomalous is True

    async def test_endpoint_not_found_raises(self):
        with t(GET_ENDPOINTS, return_value=ok(data=CROWD)):  # no epid 6676
            with pytest.raises(handlers.SkillExecutionError, match="not found"):
                await handlers.run_hunt(HuntParams(entity="epid:6676"))

    async def test_unrecognized_entity_raises(self):
        with pytest.raises(handlers.SkillExecutionError, match="unrecognized entity"):
            await handlers.run_hunt(HuntParams(entity="host:foo"))


class TestHuntEstateContext:
    async def test_estate_stats_absent_reader_degrades_to_gap(self):
        # The estate-stats readers ship on a separate branch; absent here, the
        # estate section is a gap (never a hard fail).
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:6676"))
        assert isinstance(result.estate, FeatureGap)

    async def test_estate_disabled(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(
                HuntParams(entity="epid:6676", include_estate_stats=False)
            )
        assert isinstance(result.estate, FeatureGap)
        assert "include_estate_stats" in result.estate.reason


class TestHuntDispatch:
    async def test_success_envelope(self):
        with t(QUERY_LOGS, return_value=logs_ok([])):
            result = await faz_skill(
                skill="hunt",
                params={"filter": "dstport==4444", "sweep_logtypes": ["traffic"]},
            )
        assert result["status"] == "success"
        assert result["skill"] == "hunt"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["subject_type"] == "hypothesis"

    async def test_missing_subject_rejected(self):
        result = await faz_skill(skill="hunt", params={})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
