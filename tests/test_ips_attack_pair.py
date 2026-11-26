"""search_ips_logs refuses attack_exact and attack_contains together (#187 item A7).

The filter takes one attack clause. With both arguments the exact match was
used and attack_contains was dropped without a word; filter_applied showed
what ran, nothing else did. The pair is now refused before any search, the
way query_logs refuses filter together with filters.
"""

from __future__ import annotations

from typing import Any

import pytest

import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.pcap_tools as pcap_tools

CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"


class FakeFaz:
    def __init__(self) -> None:
        self.starts: list[dict[str, Any]] = []

    async def ensure_connected(self) -> None:
        return None

    async def logsearch_start(self, **kwargs: Any) -> dict[str, int]:
        self.starts.append(kwargs)
        return {"tid": 901}

    async def logsearch_fetch(self, *, adom: str, tid: int, limit: int, offset: int) -> dict:
        return {"percentage": 100, "data": [], "total-count": 0}

    async def logsearch_cancel(self, adom: str, tid: int) -> dict[str, Any]:
        return {}


@pytest.fixture
def faz(monkeypatch: pytest.MonkeyPatch) -> FakeFaz:
    monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
    monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)
    fake = FakeFaz()
    monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: fake)
    return fake


async def test_the_pair_is_refused_and_nothing_is_searched(faz: FakeFaz) -> None:
    result = await pcap_tools.search_ips_logs(
        adom="root",
        attack_exact="Example.Attack.Exact",
        attack_contains="Remote.Code",
        time_range=CUSTOM_RANGE,
    )

    assert result == {
        "status": "error",
        "message": "Validation error: pass attack_exact or attack_contains, not both",
    }
    assert faz.starts == []


@pytest.mark.parametrize(
    ("kwargs", "clause"),
    [
        ({"attack_exact": "Example.Attack.Exact"}, 'attack="Example.Attack.Exact"'),
        ({"attack_contains": "Remote.Code"}, "attack=*Remote.Code*"),
    ],
    ids=["exact", "contains"],
)
async def test_either_one_alone_still_runs(
    faz: FakeFaz, kwargs: dict[str, str], clause: str
) -> None:
    result = await pcap_tools.search_ips_logs(adom="root", time_range=CUSTOM_RANGE, **kwargs)

    assert result["status"] == "success"
    assert result["filter_applied"] == clause
    assert len(faz.starts) == 1
