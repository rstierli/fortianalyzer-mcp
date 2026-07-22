"""Wave-2 enrichment skill: threat_intel.

Same conventions as ``test_skills_wave2.py``: handlers are tested by
patching the underlying tool functions at their defining modules with
``autospec=True`` (the handlers import them lazily per call), and the
dispatcher path is exercised end-to-end through ``faz_skill``.
"""

from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.catalog import SKILLS
from fortianalyzer_mcp.skills.dispatcher import faz_skill
from fortianalyzer_mcp.skills.models import SCHEMA_VERSION, FeatureGap, ThreatIntelParams

GET_LINKED = "fortianalyzer_mcp.tools.soar_tools.get_linked_indicators"
GET_ENRICH = "fortianalyzer_mcp.tools.soar_tools.get_indicator_enrichment"
GET_TOP_THREATS = "fortianalyzer_mcp.tools.fortiview_tools.get_top_threats"


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


ENRICHED_IP = {
    "value": "203.0.113.7",
    "type": "IP",
    "enrichment-reputation": "Malicious",
    "enrichment-confidence": 92,
    "enrichment-status": "Completed",
    "indicator-uuid": "iu-0001",
    "enrichment-uuid": "eu-0001",
}
ENRICHED_DOMAIN = {
    "value": "good.example.com",
    "type": "Domain",
    "enrichment-reputation": "Good",
    "enrichment-confidence": 80,
    "enrichment-status": "Completed",
    "indicator-uuid": "iu-0002",
    "enrichment-uuid": "eu-0002",
}
THREATS = [{"threat": "Backdoor.Agent", "threatweight": 500, "incidents": 3}]

# Extended record with the real two-engine detail shape (FortiGuard + VirusTotal).
EXTENDED_URL = {
    "value": "http://mal.example/x",
    "type": "URL",
    "enrichment-reputation": "Malicious",
    "enrichment-confidence": 90,
    "enrichment-status": "Completed",
    "indicator-uuid": "iu-x",
    "enrichment-uuid": "eu-x",
    "enrichment-detail": [
        {
            "enrichment-reputation": "Malicious",
            "enrichment-detail": [
                {
                    "data": {
                        "response": [
                            {
                                "wf_cate": "Malicious Websites",
                                "confidence": "High",
                                "reference_url": "https://ioc.fortiguard.com/search?query=x",
                            }
                        ]
                    },
                    "source": "FortiGuard-CTS",
                },
                {
                    "data": {
                        "type": "url",
                        "links": {"self": "https://www.virustotal.com/gui/url/abc/detection"},
                        "attributes": {
                            "categories": {"alphaMountain.ai": "Malicious"},
                            "total_votes": {"harmless": 1, "malicious": 1},
                            "web_category": "domain_parking",
                            "last_analysis_stats": {
                                "harmless": 56,
                                "malicious": 3,
                                "suspicious": 0,
                                "undetected": 33,
                            },
                            "reputation": 0,
                        },
                    }
                },
            ],
        }
    ],
}

EXPLICIT_TWO = [
    {"value": "203.0.113.7", "type": "IP"},
    {"value": "good.example.com", "type": "Domain"},
]


def enrich_map(mapping: dict[str, list[dict[str, Any]]]) -> Any:
    """side_effect keyed by indicator_value (fan-out order independent)."""

    def _lookup(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return ok(data=mapping.get(kwargs["indicator_value"], []))

    return _lookup


class TestThreatIntelCatalog:
    def test_registered_as_enrichment_tier(self):
        assert "threat_intel" in SKILLS
        assert SKILLS["threat_intel"].tier == "enrichment"

    def test_params_forbid_unknown_keys(self):
        with pytest.raises(ValidationError):
            ThreatIntelParams(alert_id="AL1", no_such_parameter=True)

    def test_at_least_one_subject_required(self):
        with pytest.raises(ValidationError):
            ThreatIntelParams()

    def test_alert_and_incident_are_mutually_exclusive(self):
        with pytest.raises(ValidationError):
            ThreatIntelParams(alert_id="AL1", incident_id="IN1")


class TestThreatIntel:
    async def test_explicit_indicators_enriched(self):
        mapping = {"203.0.113.7": [ENRICHED_IP], "good.example.com": [ENRICHED_DOMAIN]}
        with (
            t(GET_ENRICH, side_effect=enrich_map(mapping)) as enrich,
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)) as threats,
        ):
            result = await handlers.run_threat_intel(
                ThreatIntelParams(indicators=EXPLICIT_TWO, detail_level="extended")
            )
        assert result.indicator_count == 2
        ip, domain = result.indicators
        assert (ip.reputation, ip.confidence, ip.status) == ("Malicious", 92, "Completed")
        assert ip.record == ENRICHED_IP
        assert domain.reputation == "Good"
        assert enrich.call_args.kwargs["detail_level"] == "extended"
        assert enrich.call_args.kwargs["time_range"] is None
        assert threats.call_args.kwargs["time_range"] == "24-hour"
        assert result.threat_landscape == THREATS
        assert result.warnings == []

    async def test_extended_summarizes_per_source_verdicts(self):
        with (
            t(GET_ENRICH, return_value=ok(data=[EXTENDED_URL])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
        ):
            result = await handlers.run_threat_intel(
                ThreatIntelParams(
                    indicators=[{"value": "http://mal.example/x", "type": "URL"}],
                    detail_level="extended",
                )
            )
        rec = result.indicators[0]
        assert rec.reputation == "Malicious"
        by_source = {s.source: s.model_dump() for s in rec.sources}
        assert set(by_source) == {"FortiGuard-CTS", "VirusTotal"}
        assert by_source["FortiGuard-CTS"]["verdict"] == "Malicious Websites"
        assert by_source["FortiGuard-CTS"]["confidence"] == "High"
        assert by_source["FortiGuard-CTS"]["link"].startswith("https://ioc.fortiguard.com/")
        vt = by_source["VirusTotal"]
        assert vt["link"].startswith("https://www.virustotal.com/")
        # Headline verdict is the detection ratio (malicious+suspicious / total),
        # not the web_category label.
        assert vt["verdict"] == "3/92 engines flagged"
        assert vt["detections"]["malicious"] == 3
        assert vt["web_category"] == "domain_parking"
        # extra="allow" preserves engine-specific detail (votes/categories)
        assert vt["votes"] == {"harmless": 1, "malicious": 1}
        assert vt["categories"] == {"alphaMountain.ai": "Malicious"}

    async def test_standard_detail_has_no_source_breakdown(self):
        with (
            t(GET_ENRICH, return_value=ok(data=[ENRICHED_IP])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
        ):
            result = await handlers.run_threat_intel(
                ThreatIntelParams(indicators=[{"value": "203.0.113.7", "type": "IP"}])
            )
        assert result.indicators[0].sources == []

    async def test_alert_resolution_feeds_enrichment(self):
        linked = [
            {"value": "203.0.113.7", "type": "IP", "indicator-uuid": "iu-0001"},
            {"value": "good.example.com", "type": "domain", "indicator-uuid": "iu-0002"},
            {"value": "cafebabe", "type": "Hash", "indicator-uuid": "iu-0003"},
        ]
        mapping = {"203.0.113.7": [ENRICHED_IP], "good.example.com": [ENRICHED_DOMAIN]}
        with (
            t(GET_LINKED, return_value=ok(data=linked)) as linked_mock,
            t(GET_ENRICH, side_effect=enrich_map(mapping)) as enrich,
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
        ):
            result = await handlers.run_threat_intel(
                ThreatIntelParams(alert_id="AL0001", time_range="7-day")
            )
        assert linked_mock.call_args.kwargs["alert_id"] == "AL0001"
        assert linked_mock.call_args.kwargs["time_range"] == "7-day"
        assert result.indicator_count == 2
        assert [(r.value, r.type) for r in result.indicators] == [
            ("203.0.113.7", "IP"),
            ("good.example.com", "Domain"),
        ]
        called_types = {c.kwargs["indicator_type"] for c in enrich.call_args_list}
        assert called_types == {"IP", "Domain"}
        assert any("iu-0003" in w and "skipped" in w for w in result.warnings)

    async def test_explicit_and_linked_union_deduplicates(self):
        linked = [{"value": "203.0.113.7", "type": "IP"}]
        with (
            t(GET_LINKED, return_value=ok(data=linked)),
            t(GET_ENRICH, side_effect=enrich_map({"203.0.113.7": [ENRICHED_IP]})) as enrich,
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
        ):
            result = await handlers.run_threat_intel(
                ThreatIntelParams(
                    indicators=[{"value": "203.0.113.7", "type": "IP"}], incident_id="IN0019"
                )
            )
        assert result.indicator_count == 1
        assert enrich.call_count == 1

    async def test_linked_resolution_failure_raises(self):
        with t(GET_LINKED, return_value={"status": "error", "message": "SOAR not licensed"}):
            with pytest.raises(handlers.SkillExecutionError, match="incident IN0019"):
                await handlers.run_threat_intel(ThreatIntelParams(incident_id="IN0019"))

    async def test_per_indicator_failure_degrades_to_warning(self):
        def flaky(*args: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs["indicator_value"] == "203.0.113.7":
                return {"status": "error", "message": "backend timeout"}
            return ok(data=[ENRICHED_DOMAIN])

        with (
            t(GET_ENRICH, side_effect=flaky),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
        ):
            result = await handlers.run_threat_intel(ThreatIntelParams(indicators=EXPLICIT_TWO))
        assert result.indicator_count == 2
        failed, enriched = result.indicators
        assert failed.reputation is None and failed.record is None
        assert enriched.reputation == "Good"
        assert any("enrichment unavailable" in w and "203.0.113.7" in w for w in result.warnings)

    async def test_empty_enrichment_row_is_marked_not_fatal(self):
        with (
            t(GET_ENRICH, return_value=ok(data=[])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
        ):
            result = await handlers.run_threat_intel(
                ThreatIntelParams(indicators=[{"value": "203.0.113.7", "type": "IP"}])
            )
        assert result.indicator_count == 1
        assert result.indicators[0].record is None
        assert any("no stored enrichment" in w for w in result.warnings)

    async def test_threat_landscape_failure_degrades_to_gap(self):
        with (
            t(GET_ENRICH, return_value=ok(data=[ENRICHED_IP])),
            t(GET_TOP_THREATS, return_value={"status": "error", "message": "fortiview off"}),
        ):
            result = await handlers.run_threat_intel(
                ThreatIntelParams(indicators=[{"value": "203.0.113.7", "type": "IP"}])
            )
        assert isinstance(result.threat_landscape, FeatureGap)
        assert result.indicators[0].reputation == "Malicious"
        assert any("threat landscape unavailable" in w for w in result.warnings)

    async def test_landscape_disabled_skips_reader(self):
        with (
            t(GET_ENRICH, return_value=ok(data=[ENRICHED_IP])),
            t(GET_TOP_THREATS) as threats,
        ):
            result = await handlers.run_threat_intel(
                ThreatIntelParams(
                    indicators=[{"value": "203.0.113.7", "type": "IP"}],
                    include_threat_landscape=False,
                )
            )
        threats.assert_not_called()
        assert isinstance(result.threat_landscape, FeatureGap)
        assert "include_threat_landscape" in result.threat_landscape.reason


class TestThreatIntelDispatch:
    async def test_success_envelope(self):
        with (
            t(GET_ENRICH, return_value=ok(data=[ENRICHED_IP])),
            t(GET_TOP_THREATS, return_value=ok(data=THREATS)),
        ):
            result = await faz_skill(
                skill="threat_intel",
                params={"indicators": [{"value": "203.0.113.7", "type": "IP"}]},
            )
        assert result["status"] == "success"
        assert result["skill"] == "threat_intel"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["indicator_count"] == 1
        assert result["result"]["indicators"][0]["reputation"] == "Malicious"

    async def test_missing_subject_rejected(self):
        result = await faz_skill(skill="threat_intel", params={})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
