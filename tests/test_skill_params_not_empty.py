"""Empty selectors are refused by the skill models (#187 item A8).

Each of these was accepted and widened the call to everything:

* ``hunt`` with ``filter=""`` swept with no filter.
* ``hunt`` with ``sweep_logtypes=[]`` and ``investigate_deep`` with
  ``impact_logtypes=[]`` ran no search and said nothing.
* ``asset_lookup`` with ``epids=[]`` returned the whole inventory.

The models now set a minimum length, so the dispatcher refuses them as
invalid parameters before any read.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from tests.conftest import import_dispatcher_isolated

(faz_skill,) = import_dispatcher_isolated("faz_skill")

QUERY_LOGS = "fortianalyzer_mcp.tools.log_tools.query_logs"
GET_ENDPOINTS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoints"
GET_VULNS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoint_vulnerabilities"
GET_ALERTS = "fortianalyzer_mcp.tools.event_tools.get_alerts"
GET_FORTIVIEW_DATA = "fortianalyzer_mcp.tools.fortiview_tools.get_fortiview_data"

ENDPOINT = {"epid": 1001, "epname": "host-a.example.com", "epip": "192.0.2.7"}


def _ok(**fields: Any) -> dict[str, Any]:
    return {"status": "success", **fields}


@pytest.mark.parametrize(
    ("skill", "params", "field"),
    [
        ("hunt", {"filter": ""}, "filter"),
        ("hunt", {"filter": "srcip==192.0.2.7", "sweep_logtypes": []}, "sweep_logtypes"),
        ("investigate_deep", {"entity": "epid:1001", "impact_logtypes": []}, "impact_logtypes"),
        ("asset_lookup", {"epids": []}, "epids"),
    ],
    ids=["hunt filter", "hunt sweep_logtypes", "investigate_deep impact_logtypes", "asset epids"],
)
async def test_an_empty_selector_is_refused_before_any_read(
    skill: str, params: dict[str, Any], field: str
) -> None:
    with (
        patch(QUERY_LOGS, autospec=True, return_value=_ok(tid=1, logs=[], total=0)) as logs,
        patch(GET_ENDPOINTS, autospec=True, return_value=_ok(data=[ENDPOINT])) as endpoints,
        patch(GET_VULNS, autospec=True, return_value=_ok(data=[])) as vulns,
        patch(GET_ALERTS, autospec=True, return_value=_ok(data=[])) as alerts,
        patch(GET_FORTIVIEW_DATA, autospec=True, return_value=_ok(data=[])) as views,
    ):
        result = await faz_skill(skill=skill, params=params)

    assert result["status"] == "error"
    assert result["error"] == "invalid_skill_params"
    assert field in result["message"]
    for read in (logs, endpoints, vulns, alerts, views):
        read.assert_not_called()


@pytest.mark.parametrize(
    ("skill", "params"),
    [
        ("hunt", {"filter": "srcip==192.0.2.7", "sweep_logtypes": ["traffic"]}),
        ("investigate_deep", {"entity": "epid:1001", "impact_logtypes": ["traffic"]}),
        ("asset_lookup", {"epids": [1001]}),
        ("asset_lookup", {}),
    ],
    ids=["hunt", "investigate_deep", "asset epids", "asset unscoped"],
)
async def test_a_selector_with_one_entry_or_none_still_runs(
    skill: str, params: dict[str, Any]
) -> None:
    with (
        patch(QUERY_LOGS, autospec=True, return_value=_ok(tid=1, logs=[], total=0)),
        patch(GET_ENDPOINTS, autospec=True, return_value=_ok(data=[ENDPOINT])),
        patch(GET_VULNS, autospec=True, return_value=_ok(data=[])),
        patch(GET_ALERTS, autospec=True, return_value=_ok(data=[])),
        patch(GET_FORTIVIEW_DATA, autospec=True, return_value=_ok(data=[])),
    ):
        result = await faz_skill(skill=skill, params=params)

    assert result["status"] == "success", result
