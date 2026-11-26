"""investigate_deep takes a bare entity only when it is an address (#187 item A9).

A bare entity was typed ``ip`` when it held a dot or a colon and no space,
so ``host.example.com`` ran every impact search as
``srcip==host.example.com``. The value now has to pass the address check
the IPS filters use (``validate_ip_or_cidr``); anything else gets the
existing "entity must be ..." refusal. A CIDR network passed before and
still passes.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from tests.conftest import import_dispatcher_isolated

(faz_skill,) = import_dispatcher_isolated("faz_skill")

QUERY_LOGS = "fortianalyzer_mcp.tools.log_tools.query_logs"
REFUSAL = "entity must be 'epid:N', 'euid:N' or a bare IP address"


def _logs_ok() -> dict[str, Any]:
    return {"status": "success", "tid": 1, "logs": [], "total": 0}


@pytest.mark.parametrize(
    "entity",
    ["host.example.com", "db01.example", "fe80::1%eth0", "192.0.2.300"],
    ids=["fqdn", "short name", "zone id", "octet out of range"],
)
async def test_a_value_that_is_not_an_address_is_refused(entity: str) -> None:
    with patch(QUERY_LOGS, autospec=True, return_value=_logs_ok()) as logs:
        result = await faz_skill(
            skill="investigate_deep",
            params={"entity": entity, "impact_logtypes": ["traffic"]},
        )

    assert result["status"] == "error"
    assert result["error"] == "skill_failed"
    assert result["message"] == REFUSAL
    logs.assert_not_called()


@pytest.mark.parametrize(
    ("entity", "pivot"),
    [
        ("203.0.113.9", "srcip==203.0.113.9"),
        ("2001:db8::1", "srcip==2001:db8::1"),
        ("198.51.100.0/24", 'srcip=="198.51.100.0/24"'),
    ],
    ids=["ipv4", "ipv6", "cidr"],
)
async def test_an_address_still_runs_as_an_ip(entity: str, pivot: str) -> None:
    with patch(QUERY_LOGS, autospec=True, return_value=_logs_ok()) as logs:
        result = await faz_skill(
            skill="investigate_deep",
            params={"entity": entity, "impact_logtypes": ["traffic"]},
        )

    assert result["status"] == "success", result
    (impact,) = result["result"]["impact"]["entities"]
    assert impact["entity_type"] == "ip"
    # The search, not the echo: with masking on the echo is a token.
    assert logs.call_count == 1
    assert logs.call_args.kwargs["filter"] == pivot
