"""Tests for the projection resolver."""

from __future__ import annotations

from typing import Any

import pytest

from fortianalyzer_mcp.query.fields import resolve_field
from fortianalyzer_mcp.query.shape import (
    fields_returned,
    project_payload,
    project_rows,
    resolve_projection,
)
from fortianalyzer_mcp.utils.errors import ValidationError


def _row(**kw: Any) -> dict[str, Any]:
    base = {"srcip": "10.0.0.1", "dstip": "10.0.0.2", "dstport": 443, "noise": "x"}
    base.update(kw)
    return base


class TestResolveProjection:
    """None -> curated, ["*"] -> everything, a list -> that list."""

    def test_none_gives_the_curated_set(self) -> None:
        keys, warnings = resolve_projection("traffic", None)
        assert keys is not None
        assert "srcip" in keys and "sessionid" in keys
        assert warnings == []

    def test_none_on_an_uncurated_vocabulary_gives_everything_and_warns(self) -> None:
        keys, warnings = resolve_projection("voip", None)
        assert keys is None, "uncurated must degrade to full rows, not to an empty set"
        assert len(warnings) == 1
        assert "fields" in warnings[0]

    def test_the_uncurated_warning_names_the_requested_vocabulary(self) -> None:
        """An unregistered name falls back to the generic log vocabulary, whose
        own name is "log". The warning must still say "voip" -- naming the
        fallback would describe something the caller never asked about."""
        _, warnings = resolve_projection("voip", None)
        assert "voip" in warnings[0]
        assert "for log yet" not in warnings[0]

    def test_star_gives_everything(self) -> None:
        keys, warnings = resolve_projection("traffic", ["*"])
        assert keys is None
        assert warnings == []

    def test_explicit_list_selects_exactly_those_keys(self) -> None:
        keys, _ = resolve_projection("traffic", ["srcip", "dstport"])
        assert keys == frozenset({"srcip", "dstport"})

    def test_aliases_resolve_to_canonical_names(self) -> None:
        keys, _ = resolve_projection("traffic", ["source_ip", "destination_port"])
        assert keys == frozenset({"srcip", "dstport"})

    def test_star_mixed_with_names_is_rejected(self) -> None:
        """ "* plus srcip" has no coherent meaning; refuse rather than guess."""
        with pytest.raises(ValidationError) as exc:
            resolve_projection("traffic", ["*", "srcip"])
        assert "'*'" in str(exc.value)

    def test_empty_list_is_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            resolve_projection("traffic", [])
        assert "empty" in str(exc.value).lower()

    def test_unknown_field_on_a_complete_vocabulary_warns_rather_than_raises(self) -> None:
        """``complete=True`` is a filter boundary, not a projection one.

        The dvmdb sets here enumerate 16 names; the appliance defines roughly
        sixty. Enforcing them on the projection path turned real device fields
        that worked before projection existed -- ``oid``, ``ha_mode``,
        ``os_type``, ``last_checked``, ``devvds`` -- into ValidationErrors, and
        ``oid`` is named in search_devices' own docstring as a field the
        appliance always adds. A filter interpolates the name into an
        expression, so rejecting an unknown one there is a security decision;
        a projection only chooses which keys come back.
        """
        keys, warnings = resolve_projection("device", ["name", "oid"])

        assert keys == frozenset({"name", "oid"})
        assert len(warnings) == 1
        assert "oid" in warnings[0]
        # The logview catalogue hint would be a dead end for a dvmdb object.
        assert "get_log_fields" not in warnings[0]

    def test_a_malformed_name_is_still_rejected_on_the_projection_path(self) -> None:
        """Permissive is not unguarded: the shape check applies to both paths."""
        with pytest.raises(ValidationError):
            resolve_projection("device", ['name" or 1=1'])

    def test_the_filter_path_still_rejects_an_unknown_device_field(self) -> None:
        """Guards the split: loosening projection must not loosen filters."""
        with pytest.raises(ValidationError):
            resolve_field("device", "not_a_device_field")

    def test_unknown_field_on_an_incomplete_vocabulary_warns_and_passes(self) -> None:
        keys, warnings = resolve_projection("traffic", ["srcip", "mystery"])
        assert keys == frozenset({"srcip", "mystery"})
        assert len(warnings) == 1
        assert "get_log_fields" in warnings[0]


class TestProjectRows:
    """Selecting is subtractive: it never renames, invents or reorders keys."""

    def test_only_selected_keys_survive(self) -> None:
        rows = project_rows([_row()], frozenset({"srcip", "dstport"}))
        assert rows == [{"srcip": "10.0.0.1", "dstport": 443}]

    def test_none_returns_rows_untouched(self) -> None:
        original = _row()
        rows = project_rows([original], None)
        assert rows == [original]

    def test_a_selected_key_absent_from_the_row_is_not_invented(self) -> None:
        """No null padding -- an absent key means the appliance did not send it."""
        rows = project_rows([{"srcip": "10.0.0.1"}], frozenset({"srcip", "sessionid"}))
        assert rows == [{"srcip": "10.0.0.1"}]

    def test_nested_values_are_kept_whole(self) -> None:
        """Selecting a key with a nested structure keeps the structure intact.

        Alerts carry subject_details and target[]; masking handles those
        composites specially, so splitting them here would break it.
        """
        row = {"alertid": "1", "target": [{"name": "srcip", "value": "10.0.0.1"}]}
        rows = project_rows([row], frozenset({"alertid", "target"}))
        assert rows[0]["target"] == [{"name": "srcip", "value": "10.0.0.1"}]

    def test_a_non_dict_row_passes_through(self) -> None:
        """Some FAZ endpoints answer with bare scalars in the data list."""
        assert project_rows(["raw"], frozenset({"srcip"})) == ["raw"]

    def test_projection_does_not_mutate_the_input(self) -> None:
        original = _row()
        project_rows([original], frozenset({"srcip"}))
        assert "noise" in original


class TestFieldsReturned:
    """The echo that tells a caller what is queryable next."""

    def test_reports_the_projection_even_when_no_rows_came_back(self) -> None:
        """A zero-row page is exactly when this signal matters most."""
        assert fields_returned([], frozenset({"srcip", "dstport"})) == ["dstport", "srcip"]

    def test_reports_observed_keys_when_no_projection_applied(self) -> None:
        assert fields_returned([{"b": 1, "a": 2}], None) == ["a", "b"]

    def test_unions_observed_keys_across_rows(self) -> None:
        rows = [{"a": 1}, {"b": 2}]
        assert fields_returned(rows, None) == ["a", "b"]

    def test_no_projection_and_no_rows_is_empty(self) -> None:
        assert fields_returned([], None) == []


class TestProjectPayload:
    """The tool-facing entry: only a row list is projected, everything else
    passes through and reports no fields_returned -- claiming a projection
    that did not happen is worse than reporting none."""

    def test_a_row_list_is_projected_and_echoed(self) -> None:
        payload = [_row(), _row(srcip="10.0.0.3")]

        rows, echoed, warnings = project_payload("traffic", payload, ["srcip", "dstport"])

        assert rows == [
            {"srcip": "10.0.0.1", "dstport": 443},
            {"srcip": "10.0.0.3", "dstport": 443},
        ]
        assert echoed == ["dstport", "srcip"]
        assert warnings == []

    def test_a_dict_payload_passes_through_with_no_echo(self) -> None:
        payload = {"count": 3, "status": {"code": 0}}

        result, echoed, _ = project_payload("traffic", payload, ["srcip"])

        assert result is payload
        assert echoed == []

    def test_a_scalar_payload_passes_through_with_no_echo(self) -> None:
        for payload in (7, "three rows", None):
            result, echoed, _ = project_payload("traffic", payload, ["srcip"])
            assert result == payload
            assert echoed == []

    def test_non_dict_rows_inside_the_list_survive(self) -> None:
        """project_rows leaves a non-dict element alone rather than dropping
        it; the payload stays list-shaped either way."""
        payload = [_row(), "not-a-row"]

        rows, _, _ = project_payload("traffic", payload, ["srcip"])

        assert rows[0] == {"srcip": "10.0.0.1"}
        assert rows[1] == "not-a-row"

    def test_an_invalid_field_name_raises_for_the_tool_envelope(self) -> None:
        with pytest.raises(ValidationError):
            project_payload("traffic", [_row()], ['srcip=="x"'])
