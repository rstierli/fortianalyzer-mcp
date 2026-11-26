"""triage names why an alert was not found (#187 item A11).

For an alert id found by neither the filter lookup nor the window scan, the
error ended with "and the details lookup failed (<reason>)". When the
details read succeeded and returned no record there was no reason, and the
text read "the details lookup failed (None)". It now says the read returned
no record. A read that did fail keeps its reason.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from tests.conftest import import_dispatcher_isolated

(faz_skill,) = import_dispatcher_isolated("faz_skill")

GET_ALERTS = "fortianalyzer_mcp.tools.event_tools.get_alerts"
GET_ALERT_DETAILS = "fortianalyzer_mcp.tools.event_tools.get_alert_details"
GET_ALERT_LOGS = "fortianalyzer_mcp.tools.event_tools.get_alert_logs"

NOT_FOUND = "alert a-404 not found in the 30-day filter lookup or the 24-hour window, and "


def _ok(**fields: Any) -> dict[str, Any]:
    return {"status": "success", **fields}


async def _triage(details: dict[str, Any]) -> dict[str, Any]:
    with (
        patch(GET_ALERTS, autospec=True, return_value=_ok(data=[])),
        patch(GET_ALERT_DETAILS, autospec=True, return_value=details),
        patch(GET_ALERT_LOGS, autospec=True, return_value=_ok(data=[])),
    ):
        return await faz_skill(skill="triage", params={"alert_id": "a-404"})


async def test_an_empty_details_read_is_named_as_empty() -> None:
    result = await _triage(_ok(data=[]))

    assert result["status"] == "error"
    assert result["error"] == "skill_failed"
    assert result["message"] == NOT_FOUND + "the details lookup returned no record"


async def test_a_failed_details_read_keeps_its_reason() -> None:
    result = await _triage({"status": "error", "message": "FortiAnalyzer API error -6"})

    assert result["status"] == "error"
    assert result["error"] == "skill_failed"
    assert result["message"] == (
        NOT_FOUND + "the details lookup failed (get_alert_details: FortiAnalyzer API error -6)"
    )
