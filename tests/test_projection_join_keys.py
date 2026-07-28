"""A projection must never drop a field another tool takes as input.

These keys are how one tool's output becomes another tool's argument. Curating
`sessionid` out of the traffic projection breaks `get_pcap_by_session` with no
error that traces back to the projection -- the caller just never finds the
field to pass. Each entry below is a real hand-off in this repo, named by the
consumer that would break.
"""

from __future__ import annotations

import pytest

from fortianalyzer_mcp.query.fields import get_vocabulary

#: (vocabulary, row key, the tool that consumes it).
JOIN_KEYS = [
    ("traffic", "sessionid", "get_pcap_by_session(session_id=...)"),
    ("traffic", "policyid", "analyze_policy_traffic(policy_ids=[...])"),
    ("traffic", "dstport", "analyze_policy_traffic port breakdown"),
    ("traffic", "proto", "analyze_policy_traffic protocol breakdown"),
    ("traffic", "service", "analyze_policy_traffic ICMP type/code decoding"),
    ("attack", "pcapurl", "download_pcap_by_url(pcapurl=...)"),
    ("attack", "sessionid", "search_and_download_pcaps"),
    ("alert", "alertid", "get_alert_logs(alert_ids=[...]) / add_alert_comment"),
    ("alert", "epid", "get_endpoint_vulnerabilities(epids=[...])"),
    ("alert", "euid", "get_endusers(euids=[...])"),
    ("incident", "alertid", "get_alert_logs(alert_ids=[...])"),
    ("incident", "epid", "get_endpoint_vulnerabilities(epids=[...])"),
    ("incident", "euid", "get_endusers(euids=[...])"),
    ("endpoint", "epid", "get_endpoint_vulnerabilities(epids=[...])"),
    ("endpoint", "euid", "get_endusers(euids=[...])"),
    ("enduser", "euid", "get_endusers(euids=[...])"),
    ("enduser", "epids", "get_endpoints(epids=[...])"),
    ("report", "id", "get_report_data(...) / save_report(...)"),
    ("device", "sn", "query_logs(device=...) / get_device(...)"),
    ("device", "name", "get_device(name=...) / delete_device(device=...)"),
    ("task", "id", "get_task(task_id=...)"),
]


@pytest.mark.parametrize(
    "vocabulary,key,consumer",
    JOIN_KEYS,
    ids=[f"{v}.{k}" for v, k, _ in JOIN_KEYS],
)
def test_join_key_survives_the_curated_projection(vocabulary: str, key: str, consumer: str) -> None:
    projection = get_vocabulary(vocabulary).projection
    assert projection, f"{vocabulary} lost its curated projection"
    assert key in projection, (
        f"{vocabulary} projection drops '{key}', which {consumer} needs. "
        "Add it back: a caller cannot pass a field the projection removed."
    )


@pytest.mark.parametrize(
    "vocabulary,key,consumer",
    JOIN_KEYS,
    ids=[f"{v}.{k}" for v, k, _ in JOIN_KEYS],
)
def test_join_key_is_a_real_field_of_its_vocabulary(
    vocabulary: str, key: str, consumer: str
) -> None:
    """Guards the guard: a typo here would make the assertion above vacuous."""
    canonical = get_vocabulary(vocabulary).canonical
    assert key in canonical, f"'{key}' is not a known {vocabulary} field"
