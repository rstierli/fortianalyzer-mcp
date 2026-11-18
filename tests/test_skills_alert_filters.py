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

    async def test_hunt_ties_alerts_to_an_end_user_by_euid(self, alert_reads: list[Any]) -> None:
        """Alerts are tied to an end-user by ``euid``, the id the caller gave.

        ``user`` is not read on alerts on 7.6.7 or 7.6.8: ``user=="N/A"`` and
        ``user!="N/A"`` both return nothing there, which is how a field that
        alerts do not have behaves. ``euid`` is read on 7.6.7, 7.6.8 and
        8.0.2 (on 7.6.7 ``euid==3`` gave 867 of 1256 alerts and ``euid!=3``
        the other 389). Only that the field is read was measured: no lab
        alert belongs to a real end-user.
        """
        with (
            t(GET_ENDUSERS, return_value=ok(data=[ENDUSER])),
            t(QUERY_LOGS, return_value=ok(tid=1, logs=[], total=0)),
        ):
            await handlers.run_hunt(
                HuntParams(entity="euid:42", sweep_logtypes=["traffic"], include_estate_stats=False)
            )

        assert alert_reads == [("euid==42", "success", [])]

    async def test_an_end_user_without_a_name_is_still_tied_to_its_alerts(
        self, alert_reads: list[Any]
    ) -> None:
        """The alert pivot no longer needs ``euname``. The log sweep does."""
        nameless = {"euid": 42, "importance": "low"}
        with (
            t(GET_ENDUSERS, return_value=ok(data=[nameless])),
            t(QUERY_LOGS, return_value=ok(tid=1, logs=[], total=0)),
        ):
            result = await handlers.run_hunt(
                HuntParams(entity="euid:42", sweep_logtypes=["traffic"], include_estate_stats=False)
            )

        assert alert_reads == [("euid==42", "success", [])]
        assert isinstance(result.behavior.behavioral_detections, list)


class TestUserIsNotAKnownAlertField:
    """``user`` was listed so that the hunt's own filter did not warn.

    The hunt no longer writes it, and on 7.6 it is a field alerts do not
    have, so a filter on it returns 0 rows with no error. The warning is
    the only sign of that. On 8.0.2 the appliance does read ``user`` on
    alerts, so a caller there gets the warning for a filter that works.
    """

    async def test_a_filter_on_user_warns(self, alert_reads: list[Any]) -> None:
        result = await event_tools.get_alerts(filter="user==jdoe")

        assert result["status"] == "success"
        assert len(result["warnings"]) == 1
        assert "'user'" in result["warnings"][0]

    @pytest.mark.parametrize("clause", ["euid==42", "euname==jdoe", "srcip==192.0.2.7"])
    async def test_the_fields_alerts_do_carry_do_not_warn(
        self, alert_reads: list[Any], clause: str
    ) -> None:
        result = await event_tools.get_alerts(filter=clause)

        assert result["warnings"] == []
