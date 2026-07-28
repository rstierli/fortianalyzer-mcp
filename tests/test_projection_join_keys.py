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
    ("report", "tid", "fetch_report(tid=...) / get_report_data(tid=...) / save_report(tid=...)"),
    ("device", "sn", "query_logs(device=...) / get_device(...)"),
    ("device", "name", "get_device(name=...) / delete_device(device=...)"),
    ("task", "id", "get_task(task_id=...)"),
]

#: Vocabularies deliberately left uncurated: no verified catalogue of what the
#: appliance emits exists for them, so the tool returns full rows plus a
#: warning and the join key survives because nothing is dropped.
#:
#: Listed rather than skipped, because both directions are regressions. A
#: vocabulary that silently LOSES its curation still fails the assertion
#: below; a vocabulary that GAINS one has to be removed from this set, which
#: is exactly the moment someone has to re-check that the join key is in it.
#: ``report`` is here because the first curated report set was guessed from
#: names no report record carries and dropped ``tid``, the only usable handle.
UNCURATED = frozenset({"report"})


@pytest.mark.parametrize(
    "vocabulary,key,consumer",
    JOIN_KEYS,
    ids=[f"{v}.{k}" for v, k, _ in JOIN_KEYS],
)
def test_join_key_survives_the_curated_projection(vocabulary: str, key: str, consumer: str) -> None:
    projection = get_vocabulary(vocabulary).projection
    if vocabulary in UNCURATED:
        assert not projection, (
            f"{vocabulary} gained a curated projection but is still listed as "
            f"UNCURATED. Drop it from that set so this test checks '{key}' is in "
            f"the new projection -- {consumer} needs it."
        )
        return
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
