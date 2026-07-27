"""``get_log_fields`` name filtering.

The tool is the one place a caller can learn what a logtype lets them filter
on, and before this it was a raw passthrough: a live 7.6.x traffic response
carries roughly 200 entries across two lists, which costs more context than
reading a sample log row and guessing. A catalogue too large to consult is
not a catalogue.

The shapes exercised here follow the *live* appliance rather than the
simplified ``MOCK_LOG_FIELDS`` in conftest, in two ways that matter:

* the payload carries more than one list of field dicts (the public list and
  a private-field list), so filtering one and returning the other whole
  would defeat the point;
* ``type`` is an undocumented numeric discriminator, not the tidy ``"ip"`` /
  ``"string"`` of the fixture. Nothing here asserts a meaning for those
  codes -- Fortinet publishes no legend, and inventing one would be worse
  than the silence.
"""

from typing import Any

import pytest

from fortianalyzer_mcp.tools import log_tools


class FakeFaz:
    """Minimal client stub returning a live-shaped logfields payload."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.calls: list[tuple[str, str, str]] = []

    async def get_logfields(
        self, adom: str, logtype: str, devtype: str = "FortiGate"
    ) -> dict[str, Any]:
        self.calls.append((adom, logtype, devtype))
        return self.payload


#: Two lists of field dicts under different keys, numeric type codes, plus a
#: scalar sibling key -- the shape the appliance actually returns.
LIVE_SHAPE: dict[str, Any] = {
    "data": [
        {"name": "srcip", "type": 6},
        {"name": "dstip", "type": 6},
        {"name": "srcport", "type": 4},
        {"name": "action", "type": 0},
    ],
    "private-data": [
        {"name": "srcintfrole", "type": 0},
        {"name": "dstintfrole", "type": 0},
    ],
    "logtype": "traffic",
}


#: The wrapping the live 7.6.x appliance actually returns: the field lists sit
#: one level deeper, inside a ``data[0]`` wrapper object that carries scalar
#: siblings and no ``name`` key of its own. Probed live; the flatter
#: ``LIVE_SHAPE`` above is kept as the degenerate case, not the common one.
NESTED_LIVE_SHAPE: dict[str, Any] = {
    "data": [
        {
            "index": 0,
            "logtype": "traffic",
            "field": [
                {"name": "srcip", "type": 6},
                {"name": "dstip", "type": 6},
                {"name": "srcport", "type": 4},
                {"name": "action", "type": 0},
            ],
            "private-field": [
                {"name": "srcintfrole", "type": 0},
                {"name": "dstintfrole", "type": 0},
            ],
        }
    ]
}


def _install(monkeypatch: pytest.MonkeyPatch, fake: FakeFaz) -> None:
    monkeypatch.setattr(log_tools, "get_faz_client", lambda: fake)


def _names(result: dict[str, Any], key: str = "data") -> list[str]:
    return [entry["name"] for entry in result["fields"][key]]


class TestNameFilter:
    async def test_keeps_only_matching_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A substring filter drops every non-matching entry."""
        _install(monkeypatch, FakeFaz(LIVE_SHAPE))

        result = await log_tools.get_log_fields(adom="root", name_filter="src")

        assert result["status"] == "success"
        assert _names(result) == ["srcip", "srcport"]

    async def test_match_is_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Callers should not have to guess the appliance's casing."""
        _install(monkeypatch, FakeFaz(LIVE_SHAPE))

        result = await log_tools.get_log_fields(adom="root", name_filter="SRCIP")

        assert _names(result) == ["srcip"]

    async def test_filters_every_field_list_not_just_the_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The private-field list is filtered too.

        Returning it unfiltered would leave most of the bloat in place, since
        it is a field list like any other.
        """
        _install(monkeypatch, FakeFaz(LIVE_SHAPE))

        result = await log_tools.get_log_fields(adom="root", name_filter="dst")

        assert _names(result) == ["dstip"]
        assert _names(result, "private-data") == ["dstintfrole"]

    async def test_reports_what_the_filter_removed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Counts make the omission visible instead of implying completeness."""
        _install(monkeypatch, FakeFaz(LIVE_SHAPE))

        result = await log_tools.get_log_fields(adom="root", name_filter="src")

        assert result["name_filter"] == "src"
        # 3, not 2: the count spans every field list, so srcintfrole in the
        # private list counts alongside srcip/srcport in the public one.
        assert result["field_count"] == 3
        assert result["total_field_count"] == 6

    async def test_no_match_returns_empty_not_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A filter matching nothing is a valid answer, not a failure."""
        _install(monkeypatch, FakeFaz(LIVE_SHAPE))

        result = await log_tools.get_log_fields(adom="root", name_filter="nonexistent")

        assert result["status"] == "success"
        assert result["field_count"] == 0
        assert _names(result) == []

    async def test_scalar_siblings_survive_filtering(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-list keys in the payload pass through untouched."""
        _install(monkeypatch, FakeFaz(LIVE_SHAPE))

        result = await log_tools.get_log_fields(adom="root", name_filter="src")

        assert result["fields"]["logtype"] == "traffic"

    async def test_does_not_mutate_the_client_payload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Filtering copies; the caller's payload is not edited in place.

        The registry-style bugs in this codebase all trace to shared mutable
        state, so a filter that rewrote the response dict would be a trap for
        any future caching layer.
        """
        payload = {"data": [{"name": "srcip", "type": 6}, {"name": "action", "type": 0}]}
        _install(monkeypatch, FakeFaz(payload))

        await log_tools.get_log_fields(adom="root", name_filter="src")

        assert [entry["name"] for entry in payload["data"]] == ["srcip", "action"]


class TestUnfilteredBehaviourUnchanged:
    async def test_omitting_the_filter_returns_everything(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression guard: the default is still a full passthrough."""
        _install(monkeypatch, FakeFaz(LIVE_SHAPE))

        result = await log_tools.get_log_fields(adom="root")

        assert result["fields"] == LIVE_SHAPE
        assert result["name_filter"] is None
        assert result["field_count"] == 6
        assert result["total_field_count"] == 6

    async def test_empty_filter_is_treated_as_no_filter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty string must not filter everything out."""
        _install(monkeypatch, FakeFaz(LIVE_SHAPE))

        result = await log_tools.get_log_fields(adom="root", name_filter="")

        assert result["field_count"] == 6


class TestMalformedPayloads:
    async def test_entries_without_a_name_are_dropped_by_a_filter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An entry with no name cannot match, and must not raise."""
        _install(monkeypatch, FakeFaz({"data": [{"type": 6}, {"name": "srcip", "type": 6}]}))

        result = await log_tools.get_log_fields(adom="root", name_filter="src")

        assert _names(result) == ["srcip"]

    async def test_non_dict_list_entries_do_not_crash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A list of scalars is not a field list; leave it alone."""
        _install(monkeypatch, FakeFaz({"data": ["srcip", "dstip"], "n": 2}))

        result = await log_tools.get_log_fields(adom="root", name_filter="src")

        assert result["status"] == "success"
        assert result["fields"]["data"] == ["srcip", "dstip"]

    async def test_a_non_dict_response_passes_through(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Some FAZ endpoints answer with a bare list; do not assume a dict."""
        fake = FakeFaz([{"name": "srcip", "type": 6}, {"name": "action", "type": 0}])  # type: ignore[arg-type]
        _install(monkeypatch, fake)

        result = await log_tools.get_log_fields(adom="root", name_filter="src")

        assert result["status"] == "success"
        assert [entry["name"] for entry in result["fields"]] == ["srcip"]


class TestNestedLiveShape:
    """The 7.6.x wrapper: field lists nested inside a data[0] object.

    The wrapper dict carries no ``name`` key, so a walk that only inspects a
    list's direct entries judges ``data`` "not a field list" and passes the
    whole payload through -- zero counts, no filtering. Measured live: 234
    public + 26 private traffic fields, all unreachable to name_filter.
    """

    async def test_counts_reach_nested_field_lists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch, FakeFaz(NESTED_LIVE_SHAPE))

        result = await log_tools.get_log_fields(adom="root")

        assert result["total_field_count"] == 6
        assert result["field_count"] == 6

    async def test_filter_narrows_nested_field_lists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch, FakeFaz(NESTED_LIVE_SHAPE))

        result = await log_tools.get_log_fields(adom="root", name_filter="src")

        wrapper = result["fields"]["data"][0]
        assert [e["name"] for e in wrapper["field"]] == ["srcip", "srcport"]
        assert [e["name"] for e in wrapper["private-field"]] == ["srcintfrole"]
        assert wrapper["logtype"] == "traffic", "non-list siblings must survive"
        assert result["field_count"] == 3
        assert result["total_field_count"] == 6
