"""Payload conformance against the FNDN JSON API reference.

Each test here pins one request shape that was previously wrong in a way no
existing test could see: the suite mocks the client, so a parameter the
appliance does not define was accepted by the mock and never surfaced. The
defects were found by diffing every ``client.py`` call site against the FNDN
HTML reference in ``docs/fndn/`` (7.6.6 and 8.0.0 — the folder named "7.6.7"
declares 7.6.6 in its page titles), and confirmed live where a read path
allowed it.

The point of these tests is not that the payloads *work* — that needs an
appliance — but that they keep matching what Fortinet documents. A silently
ignored parameter is the failure mode being guarded: it makes a tool report a
narrowing it never applied.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


@pytest.fixture
def client() -> FortiAnalyzerClient:
    return FortiAnalyzerClient(host="test-faz.example.com", username="admin", password="password")


async def _capture(client: FortiAnalyzerClient, call: Any) -> tuple[str, str, dict[str, Any]]:
    """Run ``call`` with ``_raw_request`` stubbed; return (method, url, params)."""
    with patch.object(client, "_raw_request", AsyncMock(return_value={"data": []})) as raw:
        await call()
    args, kwargs = raw.call_args
    return args[0], args[1], kwargs


class TestEventMgmt:
    async def test_alert_comment_uses_update_verb_and_array_alertid(
        self, client: FortiAnalyzerClient
    ) -> None:
        """`update /eventmgmt/adom/{adom}/alerts/comment`, alertid is an array.

        The spec heading reads "Add Alert Comment" but documents the `update`
        method; this was sent as `add` with a scalar alertid.
        """
        method, url, params = await _capture(
            client,
            lambda: client.add_alert_comment(
                adom="root", alert_id="alert-001", comment="triaged", user="analyst1"
            ),
        )
        assert method == "update"
        assert url == "/eventmgmt/adom/root/alerts/comment"
        assert params["alertid"] == ["alert-001"]
        assert params["update-by"] == "analyst1"

    async def test_alert_incident_stats_sends_timescale_not_type(
        self, client: FortiAnalyzerClient
    ) -> None:
        """That endpoint defines timescale/timezone/time-range and nothing else.

        A `type` parameter was being sent; live, a nonsense value and
        "severity" returned byte-identical responses because it is not a
        parameter of this endpoint.
        """
        method, url, params = await _capture(
            client,
            lambda: client.get_alert_incident_stats(
                adom="root",
                time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
                timescale="hour",
            ),
        )
        assert method == "get"
        assert url == "/eventmgmt/adom/root/alert-incident/stats"
        assert params["timescale"] == "hour"
        assert "type" not in params


class TestIncidentMgmt:
    @pytest.mark.parametrize(
        ("call_name", "url"),
        [
            ("get_incidents", "/incidentmgmt/adom/root/incidents"),
            ("get_incidents_count", "/incidentmgmt/adom/root/incidents/count"),
        ],
    )
    async def test_incident_reads_still_send_undocumented_time_range(
        self, client: FortiAnalyzerClient, call_name: str, url: str
    ) -> None:
        """time-range is undocumented on these two, and sent deliberately.

        The parameter tables list only incids/filter/sort-by/limit/offset/
        detail-level and incids/filter respectively -- `/incident/stats` and
        `/eventmgmt/alerts` do list it. It could not be settled live (the
        test appliance holds no incidents and its token cannot create one),
        and the failure modes are asymmetric: if FAZ ignores it, sending it
        is harmless once the response stops claiming the window applied; if
        FAZ honours it undocumented -- as it does for logtypes 20-28, which
        are absent from the same document -- dropping it would silently
        widen every incident query. Honesty is carried by
        `time_range_verified: False` on the tool response instead.
        """
        window = {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}
        method, called_url, params = await _capture(
            client, lambda: getattr(client, call_name)(adom="root", time_range=window)
        )
        assert method == "get"
        assert called_url == url
        assert params["time-range"] == window

    async def test_update_incident_sends_lastuser_not_assignee(
        self, client: FortiAnalyzerClient
    ) -> None:
        """There is no assignee field; lastuser is the record's audit stamp."""
        method, url, params = await _capture(
            client,
            lambda: client.update_incident(
                adom="root", incident_id="INC-001", status="analysis", last_user="analyst1"
            ),
        )
        assert method == "update"
        assert url == "/incidentmgmt/adom/root/incident/INC-001"
        assert params["lastuser"] == "analyst1"
        assert "assignee" not in params

    async def test_incident_stats_still_sends_time_range(self, client: FortiAnalyzerClient) -> None:
        """/incident/stats *does* take time-range — it is the windowed one.

        Guards the fix above from being over-applied: dropping time-range
        here would remove the only windowed incident read.
        """
        _, url, params = await _capture(
            client,
            lambda: client.get_incident_stats(
                adom="root",
                time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
            ),
        )
        assert url == "/incidentmgmt/adom/root/incident/stats"
        assert params["time-range"]["start"] == "2024-01-01 00:00:00"
        assert params["stats-item"]


class TestIoc:
    async def test_event_ack_sends_events_array(self, client: FortiAnalyzerClient) -> None:
        """An IOC event is identified by endpoint + timestamp, not an id.

        `eventid` and `update-by` occur nowhere in the IOC spec on either
        version; the documented payload is an `events` array of
        {endpoint-id, source-ip, timestamp, comment} objects.
        """
        method, url, params = await _capture(
            client,
            lambda: client.acknowledge_ioc_events(
                adom="root",
                events=[{"endpoint-id": "1234", "timestamp": "2024-01-15 09:30:00"}],
                comment="triaged",
            ),
        )
        assert method == "update"
        assert url == "/ioc/adom/root/events/ack"
        assert params["events"] == [
            {"endpoint-id": "1234", "timestamp": "2024-01-15 09:30:00", "comment": "triaged"}
        ]
        assert "eventid" not in params
        assert "update-by" not in params

    async def test_per_event_comment_wins_over_shared_comment(
        self, client: FortiAnalyzerClient
    ) -> None:
        _, _, params = await _capture(
            client,
            lambda: client.acknowledge_ioc_events(
                adom="root",
                events=[
                    {"endpoint-id": "1", "timestamp": "t", "comment": "specific"},
                    {"endpoint-id": "2", "timestamp": "t"},
                ],
                comment="shared",
            ),
        )
        assert [e["comment"] for e in params["events"]] == ["specific", "shared"]

    async def test_ack_does_not_mutate_caller_events(self, client: FortiAnalyzerClient) -> None:
        """The shared-comment default must not write back into the argument."""
        events = [{"endpoint-id": "1", "timestamp": "t"}]
        await _capture(
            client,
            lambda: client.acknowledge_ioc_events(adom="root", events=events, comment="shared"),
        )
        assert events == [{"endpoint-id": "1", "timestamp": "t"}]


class TestLogTypes:
    """VALID_LOG_TYPES mirrors the appliance's own catalogue.

    Read off live 7.6.6: an unrecognised logtype makes /logview/logfields
    return every logtype it knows, each with its index. The FNDN appendix
    stops at index 19 and under-reports, so the appliance wins here.
    """

    LIVE_CATALOGUE = {
        "app-ctrl", "attack", "content", "dlp", "emailfilter", "event", "generic",
        "history", "im", "sniffer", "traffic", "virus", "voip", "webfilter", "netscan",
        "fct-event", "fct-traffic", "fct-netscan", "waf", "gtp", "dns", "ssh", "ssl",
        "file-filter", "asset", "protocol", "siem", "ztna", "security",
    }  # fmt: skip

    def test_valid_log_types_is_exactly_the_live_catalogue(self) -> None:
        from fortianalyzer_mcp.utils.validation import VALID_LOG_TYPES

        assert VALID_LOG_TYPES == self.LIVE_CATALOGUE

    def test_utm_is_rejected(self) -> None:
        """`utm` is not a logtype and not an alias.

        Live, a `utm` logfields request returns the entire 29-logtype
        catalogue — it silently means "no logtype filter", which turned an
        unscoped search into one wearing a scoped label.
        """
        from fortianalyzer_mcp.utils.errors import ValidationError
        from fortianalyzer_mcp.utils.validation import validate_log_type

        with pytest.raises(ValidationError, match="Invalid log type"):
            validate_log_type("utm")

    @pytest.mark.parametrize(
        ("alias", "resolved"),
        [("anomaly", "attack"), ("icap", "protocol"), ("virtual-patch", "security")],
    )
    def test_aliases_resolve_to_catalogue_names(self, alias: str, resolved: str) -> None:
        """The appliance resolves these onto a catalogue entry; so do we."""
        from fortianalyzer_mcp.utils.validation import validate_log_type

        assert validate_log_type(alias) == resolved

    @pytest.mark.parametrize("logtype", ["waf", "netscan", "gtp", "ztna", "security", "content"])
    def test_real_logtypes_are_not_rejected(self, logtype: str) -> None:
        """These are served by the appliance and used to fail local validation."""
        from fortianalyzer_mcp.utils.validation import validate_log_type

        assert validate_log_type(logtype) == logtype
