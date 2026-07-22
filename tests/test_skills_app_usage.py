"""Wave-2 enrichment skill: app_usage.

Same conventions as ``test_skills_wave2.py``: handlers are tested by
patching the underlying tool functions at their defining modules with
``autospec=True`` (the handler imports them lazily per call), and the
dispatcher path is exercised end-to-end through ``faz_skill``.
"""

from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.catalog import SKILLS
from fortianalyzer_mcp.skills.dispatcher import faz_skill
from fortianalyzer_mcp.skills.models import SCHEMA_VERSION, AppUsageParams, FeatureGap

GET_TOP_APPS = "fortianalyzer_mcp.tools.fortiview_tools.get_top_applications"
GET_TOP_WEBSITES = "fortianalyzer_mcp.tools.fortiview_tools.get_top_websites"
GET_TOP_CLOUD = "fortianalyzer_mcp.tools.fortiview_tools.get_top_cloud_applications"
QUERY_LOGS = "fortianalyzer_mcp.tools.log_tools.query_logs"


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


ERR = {"status": "error", "message": "fortiview backend down"}

APPS = [
    {"app": "YouTube", "bandwidth": 999_000},
    {"app": "Microsoft.Teams", "bandwidth": 500_000},
]
WEBSITES = [{"domain": "youtube.com", "bandwidth": 800_000}]
CLOUD_APPS = [{"app": "Dropbox", "bandwidth": 123_456}]
DLP_LOGS = [{"filename": "payroll.xlsx", "action": "block", "srcip": "192.0.2.10"}]


class TestAppUsageCatalog:
    def test_registered_as_enrichment(self):
        assert "app_usage" in SKILLS
        assert SKILLS["app_usage"].tier == "enrichment"

    def test_params_model_forbids_unknown_keys(self):
        with pytest.raises(ValidationError):
            AppUsageParams(no_such_parameter=True)


class TestAppUsage:
    async def test_all_sections_verbatim(self):
        with (
            t(GET_TOP_APPS, return_value=ok(data=APPS)) as apps,
            t(GET_TOP_WEBSITES, return_value=ok(data=WEBSITES)),
            t(GET_TOP_CLOUD, return_value=ok(data=CLOUD_APPS)),
            t(QUERY_LOGS, return_value=ok(logs=DLP_LOGS, tid=7)) as logs,
        ):
            result = await handlers.run_app_usage(
                AppUsageParams(device="FGT60F0000000000", top_limit=25, dlp_limit=50)
            )
        assert apps.call_args.kwargs["limit"] == 25
        assert apps.call_args.kwargs["device"] == "FGT60F0000000000"
        assert apps.call_args.kwargs["time_range"] == "24-hour"
        assert logs.call_args.kwargs["logtype"] == "dlp"
        assert logs.call_args.kwargs["limit"] == 50
        assert result.applications == APPS
        assert result.websites == WEBSITES
        assert result.cloud_applications == CLOUD_APPS
        assert result.dlp_events == DLP_LOGS
        assert result.counts == {
            "applications": 2,
            "websites": 1,
            "cloud_applications": 1,
            "dlp_events": 1,
        }
        assert result.time_range == "24-hour"
        assert result.warnings == []

    async def test_one_section_failure_degrades_to_gap(self):
        with (
            t(GET_TOP_APPS, return_value=ok(data=APPS)),
            t(GET_TOP_WEBSITES, return_value=ok(data=WEBSITES)),
            t(GET_TOP_CLOUD, return_value=ERR),
            t(QUERY_LOGS, return_value=ok(logs=DLP_LOGS)),
        ):
            result = await handlers.run_app_usage(AppUsageParams())
        assert isinstance(result.cloud_applications, FeatureGap)
        assert "fortiview backend down" in result.cloud_applications.reason
        assert result.applications == APPS
        assert result.counts["cloud_applications"] == 0
        assert any("top cloud applications unavailable" in w for w in result.warnings)

    async def test_dlp_failure_degrades_to_gap(self):
        with (
            t(GET_TOP_APPS, return_value=ok(data=APPS)),
            t(GET_TOP_WEBSITES, return_value=ok(data=WEBSITES)),
            t(GET_TOP_CLOUD, return_value=ok(data=CLOUD_APPS)),
            t(QUERY_LOGS, return_value={"status": "error", "message": "no slots"}),
        ):
            result = await handlers.run_app_usage(AppUsageParams())
        assert isinstance(result.dlp_events, FeatureGap)
        assert any("DLP log search unavailable" in w for w in result.warnings)

    async def test_include_dlp_false_skips_search(self):
        with (
            t(GET_TOP_APPS, return_value=ok(data=APPS)),
            t(GET_TOP_WEBSITES, return_value=ok(data=WEBSITES)),
            t(GET_TOP_CLOUD, return_value=ok(data=CLOUD_APPS)),
            t(QUERY_LOGS) as logs,
        ):
            result = await handlers.run_app_usage(AppUsageParams(include_dlp=False))
        logs.assert_not_called()
        assert isinstance(result.dlp_events, FeatureGap)
        assert "include_dlp" in result.dlp_events.reason
        assert result.warnings == []

    async def test_dlp_truncation_warns(self):
        with (
            t(GET_TOP_APPS, return_value=ok(data=APPS)),
            t(GET_TOP_WEBSITES, return_value=ok(data=WEBSITES)),
            t(GET_TOP_CLOUD, return_value=ok(data=CLOUD_APPS)),
            t(QUERY_LOGS, return_value=ok(logs=DLP_LOGS, has_more=True)),
        ):
            result = await handlers.run_app_usage(AppUsageParams(dlp_limit=1))
        assert any("truncated" in w for w in result.warnings)

    async def test_dlp_only_partial_result_still_succeeds(self):
        with (
            t(GET_TOP_APPS, return_value=ERR),
            t(GET_TOP_WEBSITES, return_value=ERR),
            t(GET_TOP_CLOUD, return_value=ERR),
            t(QUERY_LOGS, return_value=ok(logs=DLP_LOGS)),
        ):
            result = await handlers.run_app_usage(AppUsageParams())
        assert isinstance(result.applications, FeatureGap)
        assert result.dlp_events == DLP_LOGS
        assert len(result.warnings) == 3

    async def test_all_sections_failing_raises(self):
        with (
            t(GET_TOP_APPS, return_value=ERR),
            t(GET_TOP_WEBSITES, return_value=ERR),
            t(GET_TOP_CLOUD, return_value=ERR),
            t(QUERY_LOGS, return_value={"status": "error", "message": "no slots"}),
        ):
            with pytest.raises(handlers.SkillExecutionError, match="every app_usage section"):
                await handlers.run_app_usage(AppUsageParams())

    async def test_all_fortiview_failing_with_dlp_disabled_raises(self):
        with (
            t(GET_TOP_APPS, return_value=ERR),
            t(GET_TOP_WEBSITES, return_value=ERR),
            t(GET_TOP_CLOUD, return_value=ERR),
            t(QUERY_LOGS) as logs,
        ):
            with pytest.raises(handlers.SkillExecutionError, match="every app_usage section"):
                await handlers.run_app_usage(AppUsageParams(include_dlp=False))
        logs.assert_not_called()


class TestAppUsageDispatch:
    async def test_success_envelope(self):
        with (
            t(GET_TOP_APPS, return_value=ok(data=APPS)),
            t(GET_TOP_WEBSITES, return_value=ok(data=WEBSITES)),
            t(GET_TOP_CLOUD, return_value=ERR),
            t(QUERY_LOGS, return_value=ok(logs=DLP_LOGS)),
        ):
            result = await faz_skill(skill="app_usage", params={"time_range": "7-day"})
        assert result["status"] == "success"
        assert result["skill"] == "app_usage"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["applications"] == APPS
        assert result["result"]["cloud_applications"]["available"] is False
        assert result["result"]["counts"]["dlp_events"] == 1
        assert result["result"]["time_range"] == "7-day"

    async def test_total_failure_maps_to_skill_failed(self):
        with (
            t(GET_TOP_APPS, return_value=ERR),
            t(GET_TOP_WEBSITES, return_value=ERR),
            t(GET_TOP_CLOUD, return_value=ERR),
            t(QUERY_LOGS, return_value=ERR),
        ):
            result = await faz_skill(skill="app_usage", params={})
        assert result["status"] == "error"
        assert result["error"] == "skill_failed"

    async def test_invalid_params_rejected(self):
        result = await faz_skill(skill="app_usage", params={"top_limit": 0})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
