"""The alert filters the skills send are known to get_alerts's field check.

#184: ``get_alerts`` warns when a filter names a field outside the alert
vocabulary, because FortiAnalyzer answers such a filter with 0 rows and no
error. The skills filter alerts on pivots of their own (``triage`` on the
alert id, ``hunt`` on the entity's address or name), and the tool must not
warn about a filter this server wrote.

Each skill path that filters alerts is driven here through its entry point
against the real ``get_alerts`` over a fake client, and what the tool
answered is read for warnings. Every other reader is patched the way the
skill suites patch it.
"""

from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.models import HuntParams, TriageParams
from fortianalyzer_mcp.tools import event_tools

GET_ALERTS = "fortianalyzer_mcp.tools.event_tools.get_alerts"
GET_ALERT_DETAILS = "fortianalyzer_mcp.tools.event_tools.get_alert_details"
GET_ALERT_LOGS = "fortianalyzer_mcp.tools.event_tools.get_alert_logs"
GET_ALERT_INCIDENT_STATS = "fortianalyzer_mcp.tools.event_tools.get_alert_incident_stats"
GET_INCIDENTS = "fortianalyzer_mcp.tools.incident_tools.get_incidents"
GET_ENDPOINTS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoints"
GET_ENDUSERS = "fortianalyzer_mcp.tools.ueba_tools.get_endusers"
QUERY_LOGS = "fortianalyzer_mcp.tools.log_tools.query_logs"

ALERT = {"alertid": "alert-001", "severity": "high"}
ENDPOINT = {"epid": 7, "epname": "ws-finance-01", "epip": "192.0.2.7", "risk_score": 0.2}
ENDUSER = {"euid": 42, "euname": "jdoe", "importance": "low"}


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


@pytest.fixture
def alert_reads(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[Any, Any, Any]]]:
    """Run the real ``get_alerts`` over a fake client.

    Yields one ``(filter, status, warnings)`` per call a skill made, in order.
    """

    class FakeClient:
        async def get_system_timezone(self) -> None:
            return None

        async def get_alerts(self, **kwargs: object) -> object:
            return [dict(ALERT)]

    monkeypatch.setattr(event_tools, "_get_client", lambda: FakeClient())
    real_get_alerts = event_tools.get_alerts
    reads: list[tuple[Any, Any, Any]] = []

    async def spy(**kwargs: Any) -> dict[str, Any]:
        result = await real_get_alerts(**kwargs)
        reads.append((kwargs.get("filter"), result["status"], result.get("warnings")))
        return result

    with t(GET_ALERTS, side_effect=spy):
        yield reads


class TestSkillAlertFiltersDoNotWarn:
    async def test_triage_looks_the_alert_up_by_alertid(self, alert_reads: list[Any]) -> None:
        with (
            t(GET_ALERT_DETAILS, return_value=ok(data=[])),
            t(GET_ALERT_LOGS, return_value=ok(data=[])),
            t(GET_ALERT_INCIDENT_STATS, return_value=ok(data={})),
            t(GET_INCIDENTS, return_value=ok(data=[])),
        ):
            result = await handlers.run_triage(TriageParams(alert_id="alert-001"))

        assert result.subject == ALERT
        assert alert_reads == [("alertid==alert-001", "success", [])]

    async def test_hunt_ties_alerts_to_an_endpoint_by_srcip(self, alert_reads: list[Any]) -> None:
        """srcip is in no alert reference; measured, it returns the same
        alerts as epip."""
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
            t(QUERY_LOGS, return_value=ok(tid=1, logs=[], total=0)),
        ):
            await handlers.run_hunt(
                HuntParams(entity="epid:7", sweep_logtypes=["traffic"], include_estate_stats=False)
            )

        assert alert_reads == [("srcip==192.0.2.7", "success", [])]

    async def test_hunt_ties_alerts_to_an_end_user_by_user(self, alert_reads: list[Any]) -> None:
        with (
            t(GET_ENDUSERS, return_value=ok(data=[ENDUSER])),
            t(QUERY_LOGS, return_value=ok(tid=1, logs=[], total=0)),
        ):
            await handlers.run_hunt(
                HuntParams(entity="euid:42", sweep_logtypes=["traffic"], include_estate_stats=False)
            )

        assert alert_reads == [("user==jdoe", "success", [])]
