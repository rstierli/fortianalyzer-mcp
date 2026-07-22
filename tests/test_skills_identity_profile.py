"""Wave-2 enrichment skill: identity_profile.

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
from fortianalyzer_mcp.skills.models import (
    SCHEMA_VERSION,
    FeatureGap,
    IdentityProfileParams,
)

GET_ENDUSERS = "fortianalyzer_mcp.tools.ueba_tools.get_endusers"
GET_ENDPOINTS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoints"
QUERY_LOGS = "fortianalyzer_mcp.tools.log_tools.query_logs"


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


USER_ALICE = {
    "euid": 7,
    "euname": "alice",
    "eugroup": "engineering",
    "firstseen": 1700000000,
    "lastseen": 1700100000,
}
USER_ALICE_ADMIN = {"euid": 8, "euname": "alice-admin", "eugroup": "it"}
USER_SVC = {"euid": 11, "euname": "svc account", "eugroup": "services"}
EP_ALICE = {
    "epid": 1025,
    "epname": "WS-ALPHA",
    "os": "Windows 11",
    "user": [{"euid": 7, "euname": "alice", "lastseen": 1700100000}],
}
EP_OTHER = {
    "epid": 2048,
    "epname": "srv-db-01",
    "os": "Ubuntu 24.04",
    "user": [{"euid": 8, "euname": "alice-admin"}],
}
LOG_FAIL = {"logid": "0100032002", "user": "alice", "action": "failure"}
LOG_VPN = {"logid": "0101037127", "user": "alice", "subtype": "vpn"}


class TestIdentityProfileCatalog:
    def test_registered_as_enrichment(self):
        assert "identity_profile" in SKILLS
        assert SKILLS["identity_profile"].tier == "enrichment"

    def test_requires_exactly_one_identifier(self):
        with pytest.raises(ValidationError):
            IdentityProfileParams()
        with pytest.raises(ValidationError):
            IdentityProfileParams(euid=7, username="alice")

    def test_forbids_unknown_keys(self):
        with pytest.raises(ValidationError):
            IdentityProfileParams(euid=7, no_such_parameter=True)


class TestIdentityProfile:
    async def test_profile_by_euid(self):
        with (
            t(GET_ENDUSERS, return_value=ok(data=[USER_ALICE])) as users,
            t(GET_ENDPOINTS, return_value=ok(data=[EP_ALICE, EP_OTHER])),
            t(QUERY_LOGS, return_value=ok(logs=[LOG_FAIL, LOG_VPN])) as logs,
        ):
            result = await handlers.run_identity_profile(IdentityProfileParams(euid=7))
        assert users.call_args.kwargs["euids"] == [7]
        assert result.user == USER_ALICE
        assert [ep["epname"] for ep in result.endpoints] == ["WS-ALPHA"]
        assert result.recent_activity == [LOG_FAIL, LOG_VPN]
        assert result.counts == {"endpoints": 1, "activity_rows": 2}
        assert result.time_range == "24-hour"
        kwargs = logs.call_args.kwargs
        assert kwargs["logtype"] == "event"
        assert kwargs["filter"] == "user==alice and (action==failure or subtype==vpn)"
        assert kwargs["limit"] == 100
        assert result.warnings == []

    async def test_username_match_is_ci_exact(self):
        with (
            t(GET_ENDUSERS, return_value=ok(data=[USER_ALICE, USER_ALICE_ADMIN])) as users,
            t(GET_ENDPOINTS, return_value=ok(data=[EP_ALICE, EP_OTHER])),
            t(QUERY_LOGS, return_value=ok(logs=[])),
        ):
            result = await handlers.run_identity_profile(IdentityProfileParams(username="ALICE"))
        assert users.call_args.kwargs["euids"] is None
        assert result.user == USER_ALICE
        assert [ep["epname"] for ep in result.endpoints] == ["WS-ALPHA"]

    async def test_username_partial_match_is_not_found(self):
        with t(GET_ENDUSERS, return_value=ok(data=[USER_ALICE, USER_ALICE_ADMIN])):
            with pytest.raises(handlers.SkillExecutionError, match="no UEBA end-user") as exc:
                await handlers.run_identity_profile(IdentityProfileParams(username="alic"))
        # The error names the parameter, never the caller's value: with masking
        # on, unmask_args has already resolved a token to the real username, so
        # echoing it here would leak cleartext on the empty-mapping failure path.
        assert "alic" not in str(exc.value)

    async def test_unknown_euid_raises(self):
        with t(GET_ENDUSERS, return_value=ok(data=[USER_ALICE])):
            with pytest.raises(handlers.SkillExecutionError, match="euid 999"):
                await handlers.run_identity_profile(IdentityProfileParams(euid=999))

    async def test_endusers_failure_raises(self):
        with t(GET_ENDUSERS, return_value={"status": "error", "message": "UEBA disabled"}):
            with pytest.raises(handlers.SkillExecutionError, match="end-users"):
                await handlers.run_identity_profile(IdentityProfileParams(euid=7))

    async def test_unsafe_euname_is_sanitized_in_filter(self):
        with (
            t(GET_ENDUSERS, return_value=ok(data=[USER_SVC])),
            t(GET_ENDPOINTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=ok(logs=[])) as logs,
        ):
            await handlers.run_identity_profile(IdentityProfileParams(euid=11))
        assert logs.call_args.kwargs["filter"].startswith('user=="svc account" and ')

    async def test_endpoint_failure_degrades_to_warning(self):
        with (
            t(GET_ENDUSERS, return_value=ok(data=[USER_ALICE])),
            t(GET_ENDPOINTS, return_value={"status": "error", "message": "denied"}),
            t(QUERY_LOGS, return_value=ok(logs=[LOG_FAIL])),
        ):
            result = await handlers.run_identity_profile(IdentityProfileParams(euid=7))
        assert result.endpoints == []
        assert result.recent_activity == [LOG_FAIL]
        assert any("endpoint context unavailable" in w for w in result.warnings)

    async def test_activity_failure_degrades_to_gap(self):
        with (
            t(GET_ENDUSERS, return_value=ok(data=[USER_ALICE])),
            t(GET_ENDPOINTS, return_value=ok(data=[EP_ALICE])),
            t(QUERY_LOGS, return_value={"status": "error", "message": "no slots"}),
        ):
            result = await handlers.run_identity_profile(IdentityProfileParams(euid=7))
        assert isinstance(result.recent_activity, FeatureGap)
        assert "activity search unavailable" in result.recent_activity.reason
        assert result.counts == {"endpoints": 1, "activity_rows": 0}

    async def test_endpoints_without_user_association_warn(self):
        no_user = [{"epid": 1, "epname": "ghost"}]
        with (
            t(GET_ENDUSERS, return_value=ok(data=[USER_ALICE])),
            t(GET_ENDPOINTS, return_value=ok(data=no_user)),
            t(QUERY_LOGS, return_value=ok(logs=[])),
        ):
            result = await handlers.run_identity_profile(IdentityProfileParams(euid=7))
        assert result.endpoints == []
        assert any("'user' association" in w for w in result.warnings)

    async def test_include_flags_false_skip_context(self):
        with (
            t(GET_ENDUSERS, return_value=ok(data=[USER_ALICE])),
            t(GET_ENDPOINTS) as eps,
            t(QUERY_LOGS) as logs,
        ):
            result = await handlers.run_identity_profile(
                IdentityProfileParams(euid=7, include_endpoints=False, include_activity=False)
            )
        eps.assert_not_called()
        logs.assert_not_called()
        assert result.endpoints == []
        assert isinstance(result.recent_activity, FeatureGap)
        assert "include_activity" in result.recent_activity.reason


class TestIdentityProfileDispatch:
    async def test_success_envelope(self):
        with (
            t(GET_ENDUSERS, return_value=ok(data=[USER_ALICE])),
            t(GET_ENDPOINTS, return_value=ok(data=[EP_ALICE, EP_OTHER])),
            t(QUERY_LOGS, return_value=ok(logs=[LOG_FAIL])),
        ):
            result = await faz_skill(skill="identity_profile", params={"username": "Alice"})
        assert result["status"] == "success"
        assert result["skill"] == "identity_profile"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["counts"] == {"endpoints": 1, "activity_rows": 1}

    async def test_missing_identifier_rejected(self):
        result = await faz_skill(skill="identity_profile", params={})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"

    async def test_subject_failure_maps_to_skill_failed(self):
        with t(GET_ENDUSERS, return_value={"status": "error", "message": "UEBA disabled"}):
            result = await faz_skill(skill="identity_profile", params={"euid": 7})
        assert result["status"] == "error"
        assert result["error"] == "skill_failed"
