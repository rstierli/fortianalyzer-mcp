"""update_incident sends the status in the spelling of the spec (#187 item A5).

The local check compared the lower-cased status, so "Closed" passed it, and
then the caller's text was sent as written. create_incident strips and
lower-cases the status before sending it; update_incident now does the same.
What the appliance does with "Closed" was not measured: the spec enum is
lower case.
"""

from __future__ import annotations

from typing import Any

import pytest

import fortianalyzer_mcp.tools.incident_tools as incident_tools


class FakeClient:
    def __init__(self) -> None:
        self.updates: list[dict[str, Any]] = []

    async def update_incident(
        self,
        adom: str,
        incident_id: str,
        status: str | None = None,
        severity: str | None = None,
        last_user: str | None = None,
    ) -> dict[str, Any]:
        self.updates.append({"status": status, "severity": severity, "last_user": last_user})
        return {"status": {"code": 0, "message": "OK"}}


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> FakeClient:
    fake = FakeClient()
    monkeypatch.setattr(incident_tools, "get_faz_client", lambda: fake)
    return fake


@pytest.mark.parametrize("given", ["Closed", "CLOSED", " closed ", "closed"])
async def test_the_status_is_sent_lower_case(client: FakeClient, given: str) -> None:
    result = await incident_tools.update_incident(
        incident_id="IN00000001", adom="root", status=given
    )

    assert result["status"] == "success"
    assert client.updates == [{"status": "closed", "severity": None, "last_user": None}]


async def test_an_unknown_status_is_still_refused(client: FakeClient) -> None:
    result = await incident_tools.update_incident(
        incident_id="IN00000001", adom="root", status="Resolved"
    )

    assert result["status"] == "error"
    assert client.updates == []


async def test_no_status_sends_none(client: FakeClient) -> None:
    result = await incident_tools.update_incident(
        incident_id="IN00000001", adom="root", last_user="analyst1"
    )

    assert result["status"] == "success"
    assert client.updates == [{"status": None, "severity": None, "last_user": "analyst1"}]
