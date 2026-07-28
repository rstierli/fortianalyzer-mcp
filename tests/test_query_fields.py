"""Tests for the query vocabulary registry."""

from __future__ import annotations

import pytest

from fortianalyzer_mcp.query.fields import (
    coerce_value,
    get_vocabulary,
    has_projection,
    resolve_field,
)
from fortianalyzer_mcp.utils.errors import ValidationError


class TestResolveField:
    """Canonical names, aliases, and the strict/non-strict split."""

    def test_canonical_name_resolves_to_itself(self) -> None:
        assert resolve_field("traffic", "srcip") == ("srcip", None)

    def test_alias_resolves_to_canonical(self) -> None:
        assert resolve_field("traffic", "source_ip") == ("srcip", None)

    def test_alias_resolution_is_case_insensitive(self) -> None:
        assert resolve_field("traffic", "Source_IP") == ("srcip", None)

    def test_canonical_wins_over_alias(self) -> None:
        """An alias may never shadow a real field name."""
        vocab = get_vocabulary("device")
        for alias in vocab.aliases:
            assert alias not in vocab.canonical, f"alias {alias!r} shadows a canonical field"

    def test_unknown_field_on_incomplete_vocabulary_warns_and_passes_through(self) -> None:
        canonical, warning = resolve_field("traffic", "some_unlisted_field")
        assert canonical == "some_unlisted_field"
        assert warning is not None
        assert "get_log_fields" in warning

    def test_unknown_field_on_complete_vocabulary_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            resolve_field("device", "definitely_not_a_field")
        assert "conn_status" in str(exc.value)

    def test_malformed_field_name_is_rejected_even_on_incomplete_vocabularies(self) -> None:
        """Pass-through is for plausible field names, not for filter fragments.

        The string dialect interpolates the resolved name raw, so anything
        carrying whitespace, quotes or operator characters is an injection
        attempt, not a spelling the appliance might know.
        """
        with pytest.raises(ValidationError):
            resolve_field("traffic", 'srcip==1.1.1.1 or msg contain "')

    def test_unregistered_logtype_falls_back_to_the_generic_log_vocabulary(self) -> None:
        canonical, warning = resolve_field("voip", "srcip")
        assert canonical == "srcip"
        assert warning is None


class TestCoerceValue:
    """LLM-friendly enum names become the codes FortiAnalyzer stores."""

    def test_device_connection_status_name_becomes_code(self) -> None:
        assert coerce_value("device", "conn_status", "down") == 2

    def test_coercion_is_case_insensitive(self) -> None:
        assert coerce_value("device", "conn_status", "UP") == 1

    def test_task_state_name_becomes_code(self) -> None:
        assert coerce_value("task", "state", "running") == 1

    def test_already_numeric_value_passes_through(self) -> None:
        assert coerce_value("device", "conn_status", 2) == 2

    def test_unknown_enum_name_raises_listing_valid_values(self) -> None:
        with pytest.raises(ValidationError) as exc:
            coerce_value("device", "conn_status", "sideways")
        message = str(exc.value)
        assert "up" in message and "down" in message

    def test_field_without_coercions_passes_value_through(self) -> None:
        assert coerce_value("traffic", "srcip", "10.0.0.1") == "10.0.0.1"


class TestRegistryMatchesTheToolsItReplaces:
    """The registry is the single source for the enum maps the tools consume."""

    def test_task_state_codes_are_single_sourced(self) -> None:
        """system_tools must consume the registry's table, not carry a copy.

        Two equal-but-separate tables let the legacy filter_state path and the
        structured filters path drift apart inside the same function.
        """
        from fortianalyzer_mcp.query.fields import TASK_STATE_CODES
        from fortianalyzer_mcp.tools import system_tools

        assert system_tools.TASK_STATE_CODES is TASK_STATE_CODES
        assert system_tools._TASK_STATE_NAMES == {
            code: name for name, code in TASK_STATE_CODES.items()
        }

    def test_conn_status_codes_cover_the_documented_names(self) -> None:
        from fortianalyzer_mcp.query.fields import _CONN_STATUS_CODES

        assert dict(_CONN_STATUS_CODES) == {"unknown": 0, "up": 1, "down": 2}


class TestCuratedProjections:
    """Every curated set is a subset of what the vocabulary says exists."""

    CURATED = (
        "traffic",
        "event",
        "attack",
        "device",
        "task",
        "alert",
        "incident",
        "endpoint",
        "enduser",
    )

    @pytest.mark.parametrize("name", CURATED)
    def test_curated_vocabularies_have_a_projection(self, name: str) -> None:
        assert get_vocabulary(name).projection, f"{name} has no curated projection"

    @pytest.mark.parametrize("name", CURATED)
    def test_projection_is_a_subset_of_canonical(self, name: str) -> None:
        """A curated name the vocabulary does not know is a typo, not a field."""
        vocab = get_vocabulary(name)
        unknown = vocab.projection - vocab.canonical
        assert not unknown, f"{name} projects unknown fields: {sorted(unknown)}"

    def test_an_uncurated_logtype_has_an_empty_projection(self) -> None:
        """voip has no curated set; that must read as absence, not as {}."""
        assert get_vocabulary("voip").projection == frozenset()

    def test_has_projection_reports_curation(self) -> None:
        assert has_projection("traffic") is True
        assert has_projection("voip") is False

    def test_traffic_projection_carries_identity_magnitude_and_summary(self) -> None:
        """The spec's shape requirement, asserted rather than assumed."""
        traffic = get_vocabulary("traffic").projection
        assert {"srcip", "dstip"} <= traffic, "identity missing"
        assert "action" in traffic, "discriminator missing"
        assert {"sentbyte", "rcvdbyte"} <= traffic, "magnitude missing"
        assert {"service", "app"} <= traffic, "summary missing"
