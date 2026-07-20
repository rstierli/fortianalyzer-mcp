"""Wave-2 data-access skills: asset_lookup, identity_lookup, alert_rules.

Same conventions as ``test_skills.py``: handlers are tested by patching
the underlying tool functions at their defining modules with
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
from fortianalyzer_mcp.skills.models import (
    SCHEMA_VERSION,
    AlertRulesParams,
    AssetLookupParams,
    IdentityLookupParams,
)

WAVE2_DATA_ACCESS_IDS = {"asset_lookup", "identity_lookup", "alert_rules"}

GET_ENDPOINTS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoints"
GET_ENDPOINT_VULNS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoint_vulnerabilities"
GET_ENDUSERS = "fortianalyzer_mcp.tools.ueba_tools.get_endusers"
GET_ALERT_HANDLERS = "fortianalyzer_mcp.tools.event_tools.get_alert_handlers"


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


ENDPOINT_WS = {
    "epid": 1025,
    "epname": "WS-ALPHA",
    "epip": "192.168.1.10",
    "os": "Windows 11",
}
ENDPOINT_SRV = {
    "epid": 2048,
    "epname": "srv-db-01",
    "epip": "192.168.1.20",
    "os": "Ubuntu 24.04",
}
VULN_PAYLOAD = [
    {
        "epid": 1025,
        "vuln-group": [
            {
                "vuln": [
                    {"vulnid": "CVE-2024-0001", "severity": "Critical"},
                    {"vulnid": "CVE-2024-0002", "severity": "high"},
                ]
            },
            {"vuln": [{"vulnid": "CVE-2024-0003", "severity": "high"}]},
        ],
    },
    {"epid": 2048, "vuln": [{"vulnid": "CVE-2023-9999", "severity": "medium"}]},
]
ENDUSER_ALICE = {"euid": 7, "euname": "alice", "eugroup": "engineering"}
ENDUSER_BOB = {"euid": 8, "euname": "Bob-Admin", "eugroup": "it"}
HANDLER_BASIC = {
    "name": "Malware Detected",
    "handler-id": 11,
    "rule": [{"severity": "critical", "filter": []}, {"severity": "high", "filter": []}],
}
HANDLER_CORR = {"name": "Brute Force Correlation", "handler-id": 42, "rule": [{"severity": "high"}]}


# --------------------------------------------------------------------- #
# Catalogue / registry                                                  #
# --------------------------------------------------------------------- #


class TestWave2Catalog:
    def test_wave2_data_access_skills_registered(self):
        assert WAVE2_DATA_ACCESS_IDS <= set(SKILLS)
        for skill_id in WAVE2_DATA_ACCESS_IDS:
            assert SKILLS[skill_id].tier == "data_access"

    @pytest.mark.parametrize(
        "params_model", [AssetLookupParams, IdentityLookupParams, AlertRulesParams]
    )
    def test_params_models_forbid_unknown_keys(self, params_model: Any):
        with pytest.raises(ValidationError):
            params_model(no_such_parameter=True)


# --------------------------------------------------------------------- #
# asset_lookup                                                          #
# --------------------------------------------------------------------- #


class TestAssetLookup:
    async def test_endpoints_with_attributed_vulnerabilities(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT_WS, ENDPOINT_SRV])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=VULN_PAYLOAD)) as vulns,
        ):
            result = await handlers.run_asset_lookup(AssetLookupParams())
        assert result.endpoint_count == result.matched_total == 2
        assert vulns.call_args.kwargs["epids"] == [1025, 2048]
        ws, srv = result.endpoints
        assert [v["vulnid"] for v in ws.vulnerabilities] == [
            "CVE-2024-0001",
            "CVE-2024-0002",
            "CVE-2024-0003",
        ]
        assert ws.vulnerability_counts == {"critical": 1, "high": 2}
        assert srv.vulnerability_counts == {"medium": 1}
        assert result.warnings == []

    async def test_hostname_filter_is_ci_substring(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data={"data": [ENDPOINT_WS, ENDPOINT_SRV]})),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=[])),
        ):
            result = await handlers.run_asset_lookup(AssetLookupParams(hostname="SRV-DB"))
        assert result.matched_total == 1
        assert result.endpoints[0].endpoint["epname"] == "srv-db-01"

    async def test_ip_filter_is_exact(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT_WS, ENDPOINT_SRV])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=[])),
        ):
            result = await handlers.run_asset_lookup(AssetLookupParams(ip="192.168.1.2"))
        assert result.matched_total == 0
        assert result.endpoints == []

    async def test_ip_filter_without_epip_field_warns(self):
        # basic/standard detail omit epip (live-verified); filtering on ip
        # there must warn, not silently return an empty match.
        no_epip = [{"epid": 1, "epname": "ws-alpha"}]
        with (
            t(GET_ENDPOINTS, return_value=ok(data=no_epip)),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=[])),
        ):
            result = await handlers.run_asset_lookup(AssetLookupParams(ip="192.168.1.10"))
        assert result.matched_total == 0
        assert any("detail_level='simple'" in w for w in result.warnings)

    async def test_limit_truncates_with_warning_and_scopes_vuln_call(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT_WS, ENDPOINT_SRV])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=[])) as vulns,
        ):
            result = await handlers.run_asset_lookup(AssetLookupParams(limit=1))
        assert result.matched_total == 2
        assert result.endpoint_count == 1
        assert vulns.call_args.kwargs["epids"] == [1025]
        assert any("first 1" in w for w in result.warnings)

    async def test_include_vulnerabilities_false_skips_reader(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT_WS])),
            t(GET_ENDPOINT_VULNS) as vulns,
        ):
            result = await handlers.run_asset_lookup(
                AssetLookupParams(include_vulnerabilities=False)
            )
        vulns.assert_not_called()
        assert result.endpoints[0].vulnerabilities == []

    async def test_vulnerability_failure_degrades_to_warning(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT_WS])),
            t(GET_ENDPOINT_VULNS, return_value={"status": "error", "message": "UEBA off"}),
        ):
            result = await handlers.run_asset_lookup(AssetLookupParams())
        assert result.endpoint_count == 1
        assert any("vulnerability context unavailable" in w for w in result.warnings)

    async def test_orphan_vulnerabilities_are_reported_not_guessed(self):
        orphan_payload = [{"vuln": [{"vulnid": "CVE-2020-1111", "severity": "low"}]}]
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT_WS])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=orphan_payload)),
        ):
            result = await handlers.run_asset_lookup(AssetLookupParams())
        assert result.endpoints[0].vulnerabilities == []
        assert [v["vulnid"] for v in result.unattributed_vulnerabilities] == ["CVE-2020-1111"]
        assert any("no attributable endpoint id" in w for w in result.warnings)

    async def test_endpoints_without_epid_skip_vuln_lookup(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[{"epname": "ghost"}])),
            t(GET_ENDPOINT_VULNS) as vulns,
        ):
            result = await handlers.run_asset_lookup(AssetLookupParams())
        vulns.assert_not_called()
        assert any("vulnerability lookup skipped" in w for w in result.warnings)

    async def test_endpoints_failure_raises(self):
        with t(GET_ENDPOINTS, return_value={"status": "error", "message": "no UEBA license"}):
            with pytest.raises(handlers.SkillExecutionError, match="UEBA endpoints"):
                await handlers.run_asset_lookup(AssetLookupParams())


# --------------------------------------------------------------------- #
# identity_lookup                                                       #
# --------------------------------------------------------------------- #


class TestIdentityLookup:
    async def test_returns_verbatim_users(self):
        with t(GET_ENDUSERS, return_value=ok(data=[ENDUSER_ALICE, ENDUSER_BOB])) as users:
            result = await handlers.run_identity_lookup(
                IdentityLookupParams(detail_level="extended")
            )
        assert users.call_args.kwargs["detail_level"] == "extended"
        assert result.user_count == result.matched_total == 2
        assert result.users == [ENDUSER_ALICE, ENDUSER_BOB]
        assert result.detail_level == "extended"

    async def test_username_filter_is_ci_substring(self):
        with t(GET_ENDUSERS, return_value=ok(data=[ENDUSER_ALICE, ENDUSER_BOB])):
            result = await handlers.run_identity_lookup(IdentityLookupParams(username="bob"))
        assert result.matched_total == 1
        assert result.users[0]["euname"] == "Bob-Admin"

    async def test_limit_truncates_with_warning(self):
        with t(GET_ENDUSERS, return_value=ok(data=[ENDUSER_ALICE, ENDUSER_BOB])):
            result = await handlers.run_identity_lookup(IdentityLookupParams(limit=1))
        assert result.matched_total == 2
        assert result.user_count == 1
        assert any("first 1" in w for w in result.warnings)

    async def test_endusers_failure_raises(self):
        with t(GET_ENDUSERS, return_value={"status": "error", "message": "denied"}):
            with pytest.raises(handlers.SkillExecutionError, match="end-users"):
                await handlers.run_identity_lookup(IdentityLookupParams())


# --------------------------------------------------------------------- #
# alert_rules                                                           #
# --------------------------------------------------------------------- #


class TestAlertRules:
    async def test_both_classes_flatten_with_labels(self):
        payload = ok(data={"basic": {"data": [HANDLER_BASIC]}, "correlation": [HANDLER_CORR]})
        with t(GET_ALERT_HANDLERS, return_value=payload):
            result = await handlers.run_alert_rules(AlertRulesParams())
        assert result.handler_count == result.matched_total == 2
        assert [(h.handler_class, h.handler["name"]) for h in result.handlers] == [
            ("basic", "Malware Detected"),
            ("correlation", "Brute Force Correlation"),
        ]
        assert result.rule_count == 3

    async def test_name_filter_is_ci_substring(self):
        payload = ok(data={"basic": [HANDLER_BASIC], "correlation": [HANDLER_CORR]})
        with t(GET_ALERT_HANDLERS, return_value=payload):
            result = await handlers.run_alert_rules(AlertRulesParams(name="brute"))
        assert result.handler_count == 1
        assert result.handlers[0].handler_class == "correlation"

    async def test_single_class_response_tolerated(self):
        with t(GET_ALERT_HANDLERS, return_value=ok(data={"basic": [HANDLER_BASIC]})) as reader:
            result = await handlers.run_alert_rules(AlertRulesParams(handler_type="basic"))
        assert reader.call_args.kwargs["handler_type"] == "basic"
        assert result.handler_count == 1
        assert result.handlers[0].handler_class == "basic"

    async def test_unrecognized_section_shape_warns(self):
        payload = ok(data={"basic": {"unexpected": "shape"}, "correlation": [HANDLER_CORR]})
        with t(GET_ALERT_HANDLERS, return_value=payload):
            result = await handlers.run_alert_rules(AlertRulesParams())
        assert result.handler_count == 1
        assert any("unrecognized shape" in w for w in result.warnings)

    async def test_limit_truncates_with_warning(self):
        payload = ok(data={"basic": [HANDLER_BASIC], "correlation": [HANDLER_CORR]})
        with t(GET_ALERT_HANDLERS, return_value=payload):
            result = await handlers.run_alert_rules(AlertRulesParams(limit=1))
        assert result.matched_total == 2
        assert result.handler_count == 1
        assert any("first 1" in w for w in result.warnings)

    async def test_handlers_failure_raises(self):
        with t(GET_ALERT_HANDLERS, return_value={"status": "error", "message": "denied"}):
            with pytest.raises(handlers.SkillExecutionError, match="alert handlers"):
                await handlers.run_alert_rules(AlertRulesParams())


# --------------------------------------------------------------------- #
# Dispatcher end-to-end                                                 #
# --------------------------------------------------------------------- #


class TestWave2Dispatch:
    async def test_asset_lookup_success_envelope(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT_WS])),
            t(GET_ENDPOINT_VULNS, return_value=ok(data=VULN_PAYLOAD)),
        ):
            result = await faz_skill(skill="asset_lookup", params={"hostname": "ws-"})
        assert result["status"] == "success"
        assert result["skill"] == "asset_lookup"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["endpoint_count"] == 1

    async def test_subject_failure_maps_to_skill_failed(self):
        with t(GET_ENDUSERS, return_value={"status": "error", "message": "UEBA disabled"}):
            result = await faz_skill(skill="identity_lookup", params={})
        assert result["status"] == "error"
        assert result["error"] == "skill_failed"

    async def test_invalid_params_rejected(self):
        result = await faz_skill(skill="alert_rules", params={"handler_type": "bogus"})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
