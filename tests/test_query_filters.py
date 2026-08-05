"""Tests for the structured filter compiler."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from fortianalyzer_mcp.query.filters import (
    FilterCondition,
    compile_to_array,
    compile_to_string,
)
from fortianalyzer_mcp.utils.errors import ValidationError


def _c(field: str, op: str = "eq", value: object = "x") -> FilterCondition:
    """Build one condition without repeating the keyword names everywhere."""
    return FilterCondition(field=field, op=op, value=value)  # type: ignore[arg-type]


class TestStringDialectOperators:
    """Each op emits the spelling this repo has working evidence for."""

    @pytest.mark.parametrize(
        "op,expected",
        [
            ("eq", "srcip==10.0.0.1"),
            ("ne", "srcip!=10.0.0.1"),
            ("gt", "srcip>10.0.0.1"),
            ("gte", "srcip>=10.0.0.1"),
            ("lt", "srcip<10.0.0.1"),
            ("lte", "srcip<=10.0.0.1"),
        ],
    )
    def test_symbol_operators_emit_without_spaces(self, op: str, expected: str) -> None:
        result, _ = compile_to_string([_c("srcip", op, "10.0.0.1")], "traffic")
        assert result == expected

    def test_contains_compiles_to_like_with_wildcards(self) -> None:
        """``contain`` is inert on the string dialect, exactly as on the array
        one: the parser accepts it and silently matches zero rows, so a caller
        gets a confident empty answer. ``like`` with wildcards is the form that
        works, live-checked on 7.6.7 and 8.0.0."""
        result, _ = compile_to_string([_c("attack", "contains", "Botnet")], "attack")
        assert result == 'attack like "%Botnet%"'

    def test_not_contains_wraps_the_like_clause(self) -> None:
        """Negation has to wrap the clause. ``not like``, ``!like`` and
        ``nlike`` are each rejected live with ``Invalid filter``; the wrapped
        form is a true complement (12052 + 476392 == 488444 over one fixed
        hour), not a match-everything."""
        result, _ = compile_to_string([_c("attack", "not_contains", "Botnet")], "attack")
        assert result == '!(attack like "%Botnet%")'

    def test_a_substring_value_is_escaped_inside_the_pattern(self) -> None:
        """The wildcards go through the sanitiser with the value, so a quote in
        the value cannot terminate the pattern's own literal."""
        result, _ = compile_to_string([_c("attack", "contains", 'a" or 1==1 or "')], "attack")
        assert result == 'attack like "%a\\" or 1==1 or \\"%"'
        assert result.count('"') - result.count('\\"') == 2


class TestStringDialectCombination:
    """AND across conditions, parenthesised OR within one field."""

    def test_multiple_conditions_are_anded(self) -> None:
        result, _ = compile_to_string(
            [_c("srcip", "eq", "10.0.0.1"), _c("dstport", "eq", 443)], "traffic"
        )
        assert result == "srcip==10.0.0.1 and dstport==443"

    def test_in_emits_a_parenthesised_or_group(self) -> None:
        result, _ = compile_to_string([_c("dstport", "in", [80, 443])], "traffic")
        assert result == "(dstport==80 or dstport==443)"

    def test_not_in_emits_a_parenthesised_and_group(self) -> None:
        result, _ = compile_to_string([_c("dstport", "not_in", [80, 443])], "traffic")
        assert result == "(dstport!=80 and dstport!=443)"

    def test_in_combines_with_a_sibling_condition(self) -> None:
        result, _ = compile_to_string(
            [_c("srcip", "eq", "10.0.0.1"), _c("dstport", "in", [80, 443])], "traffic"
        )
        assert result == "srcip==10.0.0.1 and (dstport==80 or dstport==443)"

    def test_no_conditions_compiles_to_an_empty_filter(self) -> None:
        result, warnings = compile_to_string([], "traffic")
        assert result == ""
        assert warnings == []


class TestValueHandling:
    """Quoting is the string dialect's injection boundary."""

    def test_plain_values_are_left_unquoted(self) -> None:
        result, _ = compile_to_string([_c("srcip", "eq", "10.0.0.1")], "traffic")
        assert result == "srcip==10.0.0.1"

    def test_ipv6_literals_are_not_quoted(self) -> None:
        """The traffic_tools sanitiser copy quoted these; the survivor does not."""
        result, _ = compile_to_string([_c("srcip", "eq", "2001:db8::1")], "traffic")
        assert result == "srcip==2001:db8::1"

    def test_values_with_spaces_are_quoted(self) -> None:
        result, _ = compile_to_string([_c("attack", "contains", "Remote Code")], "attack")
        assert result == 'attack like "%Remote Code%"'

    def test_injection_attempt_is_neutralised_by_quoting(self) -> None:
        result, _ = compile_to_string([_c("srcip", "eq", '1.1.1.1" or 1==1 or "')], "traffic")
        assert result.startswith('srcip=="')
        assert result.count('\\"') >= 1

    def test_integer_values_survive_as_numbers(self) -> None:
        result, _ = compile_to_string([_c("dstport", "eq", 443)], "traffic")
        assert result == "dstport==443"


class TestInputRejection:
    """Bad input fails locally with a message that says what to do."""

    def test_scalar_op_with_a_list_value_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("dstport", "eq", [80, 443])], "traffic")
        assert "'in'" in str(exc.value)

    def test_in_with_a_scalar_value_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("dstport", "in", 80)], "traffic")
        assert "list" in str(exc.value)

    def test_in_with_an_empty_list_raises(self) -> None:
        with pytest.raises(ValidationError):
            compile_to_string([_c("dstport", "in", [])], "traffic")

    def test_boolean_value_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("srcip", "eq", True)], "traffic")
        assert "boolean" in str(exc.value).lower()

    def test_a_boolean_inside_a_list_raises_the_same_way(self) -> None:
        """The list arm has to admit ``bool`` for the guard to see one.

        While it did not, pydantic coerced True to 1 on the way in and the
        same boolean that errors as a scalar compiled to a silent
        ``dstport==1``: one input shape, two opposite behaviours.
        """
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("dstport", "in", [True, False])], "traffic")
        assert "boolean" in str(exc.value).lower()

    def test_a_boolean_inside_a_list_raises_on_the_array_dialect_too(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_array([_c("name", "not_in", [True])], "device")
        assert "boolean" in str(exc.value).lower()

    def test_unknown_op_is_rejected_by_the_model(self) -> None:
        with pytest.raises(PydanticValidationError):
            FilterCondition(field="srcip", op="matches", value="x")  # type: ignore[arg-type]

    @pytest.mark.parametrize("op", ["contains", "not_contains"])
    def test_substring_on_a_code_valued_field_is_refused_here_too(self, op: str) -> None:
        """The same refusal guards the string dialect.

        No string-dialect vocabulary carries coercions today, so this is reached
        only through a code-valued vocabulary -- which is exactly what makes it
        worth pinning: it keeps the guard in place for the day a logview field
        gains an enum mapping, rather than leaving one compiler exempt.
        """
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("state", op, "running")], "task")
        assert "numeric code" in str(exc.value)

    def test_extra_keys_are_rejected_by_the_model(self) -> None:
        with pytest.raises(PydanticValidationError):
            FilterCondition(field="srcip", op="eq", value="x", extra="nope")  # type: ignore[call-arg]


class TestFieldResolution:
    """The compiler resolves names through the registry."""

    def test_alias_is_compiled_to_the_canonical_name(self) -> None:
        result, _ = compile_to_string([_c("source_ip", "eq", "10.0.0.1")], "traffic")
        assert result == "srcip==10.0.0.1"

    def test_unknown_log_field_passes_through_with_a_warning(self) -> None:
        result, warnings = compile_to_string([_c("weird_field", "eq", "x")], "traffic")
        assert result == "weird_field==x"
        assert len(warnings) == 1
        assert "get_log_fields" in warnings[0]

    def test_malicious_field_name_is_rejected(self) -> None:
        """The value slot is quoted; the field slot must be shape-gated.

        Incomplete vocabularies pass unknown names through verbatim, and the
        string dialect interpolates the field name raw -- without a shape gate
        the field slot re-opens the injection class the value-side sanitiser
        closed (issue #16), one slot to the left.
        """
        smuggled = 'srcip==1.1.1.1 or dstport!=0 or msg contain "'
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c(smuggled, "eq", "x")], "traffic")
        assert "field name" in str(exc.value).lower()

    def test_field_name_with_whitespace_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            compile_to_string([_c("srcip or 1", "eq", "x")], "traffic")


class TestStringEnumValues:
    """Enum-valued fields warn on a value outside their known set (#109 review).

    The retired search_* wrappers validated these client-side; the
    consolidation left validate_traffic_action and friends with zero callers,
    and `filters` validated field names and operators but passed values
    through verbatim. Measured on 7.6.7 over one fixed hour: action==deny
    returned 5833 rows and action==denied returned 0, status success, no
    error. That is a loud client-side rejection turned into a confident empty
    answer.
    """

    def test_a_known_member_is_silent(self) -> None:
        result, warnings = compile_to_string([_c("action", "eq", "deny")], "traffic")
        assert result == "action==deny"
        assert warnings == []

    def test_an_unknown_member_warns_and_names_the_set(self) -> None:
        result, warnings = compile_to_string([_c("action", "eq", "denied")], "traffic")

        assert result == "action==denied"
        assert len(warnings) == 1
        assert "'denied' is not a known 'action' value" in warnings[0]
        assert "deny" in warnings[0]
        assert "status success" in warnings[0]

    def test_an_unknown_member_is_NOT_rejected(self) -> None:
        """Deliberately a warning, not an error. VALID_TRAFFIC_ACTIONS has six
        members and FortiGate emits others (client-rst, server-rst), so
        rejecting would make a real value unqueryable -- the failure 8beb7c5
        had to undo for field names on the projection path."""
        result, warnings = compile_to_string([_c("action", "eq", "client-rst")], "traffic")

        assert result == "action==client-rst"
        assert warnings  # told, not blocked

    def test_case_and_whitespace_do_not_trigger_a_false_warning(self) -> None:
        _, warnings = compile_to_string([_c("action", "eq", " Deny ")], "traffic")
        assert warnings == []

    def test_a_substring_match_does_not_warn(self) -> None:
        """`action contains "den"` is a legitimate partial match; warning that
        "den" is not an action would be noise about a correct query."""
        _, warnings = compile_to_string([_c("action", "contains", "den")], "traffic")
        assert warnings == []

    def test_each_member_of_an_in_list_is_checked(self) -> None:
        _, warnings = compile_to_string([_c("action", "in", ["deny", "denied", "drop"])], "traffic")
        assert len(warnings) == 1
        assert "'denied'" in warnings[0]

    def test_event_level_and_subtype_carry_their_own_sets(self) -> None:
        _, level = compile_to_string([_c("level", "eq", "criticel")], "event")
        _, subtype = compile_to_string([_c("subtype", "eq", "systemm")], "event")

        assert "critical" in level[0]
        assert "system" in subtype[0]

    def test_attack_action_uses_the_ips_set_not_the_traffic_one(self) -> None:
        """`action` means different things per logtype: an IPS action is
        detected/blocked/dropped/reset, not accept/deny."""
        _, blocked = compile_to_string([_c("action", "eq", "blocked")], "attack")
        _, deny = compile_to_string([_c("action", "eq", "deny")], "attack")

        assert blocked == []
        assert deny and "detected" in deny[0]

    def test_a_vocabulary_with_no_enum_set_is_unaffected(self) -> None:
        _, warnings = compile_to_string([_c("action", "eq", "anything-at-all")], "webfilter")
        assert warnings == []


class TestArrayDialect:
    """dvmdb/config/task take a list of [field, op, value] entries, ANDed."""

    def test_eq_emits_one_entry(self) -> None:
        result, _ = compile_to_array([_c("name", "eq", "fgt-01")], "device")
        assert result == [["name", "==", "fgt-01"]]

    def test_contains_compiles_to_like_with_wildcards(self) -> None:
        """``contain`` is accepted by live dvmdb and silently matches zero
        rows; ``like`` with ``%`` wildcards is the spelling that works."""
        result, _ = compile_to_array([_c("name", "contains", "fgt")], "device")
        assert result == [["name", "like", "%fgt%"]]

    def test_multiple_conditions_become_multiple_entries(self) -> None:
        result, _ = compile_to_array(
            [_c("name", "contains", "fgt"), _c("os_ver", "contains", "7.")], "device"
        )
        assert result == [["name", "like", "%fgt%"], ["os_ver", "like", "%7.%"]]

    def test_not_contains_is_refused_rather_than_guessed(self) -> None:
        """``!contain`` and ``not like`` both silently match zero rows live,
        so there is no working spelling to emit."""
        with pytest.raises(ValidationError) as exc:
            compile_to_array([_c("name", "not_contains", "fgt")], "device")
        assert "'ne'" in str(exc.value)

    def test_enum_name_is_coerced_to_its_code(self) -> None:
        result, _ = compile_to_array([_c("conn_status", "eq", "down")], "device")
        assert result == [["conn_status", "==", 2]]

    def test_contains_on_a_code_valued_field_is_refused(self) -> None:
        """Coercion runs before the wildcards attach, so the pattern would wrap
        the *code*. Measured live on 7.6.6: this compiled to
        ``[["state", "like", "%1%"]]``, and TASK_STATE_CODES runs 0..10, so
        ``%1%`` matches running (1) and unknown (10) alike."""
        with pytest.raises(ValidationError) as exc:
            compile_to_array([_c("state", "contains", "running")], "task")
        message = str(exc.value)
        assert "numeric code" in message
        # The refusal names the values that do work, so the caller can recover
        # in one step rather than guessing a second spelling.
        assert "running" in message
        assert "'eq'" in message

    def test_contains_on_conn_status_is_refused_too(self) -> None:
        """conn_status escaped notice only because its codes are 0/1/2; the
        defect is the operator, not the width of the code range."""
        with pytest.raises(ValidationError) as exc:
            compile_to_array([_c("conn_status", "contains", "up")], "device")
        assert "numeric code" in str(exc.value)

    def test_contains_on_a_free_text_field_still_compiles(self) -> None:
        """Regression guard: the refusal is scoped to code-valued fields and
        must not swallow substring matching on ordinary text."""
        result, _ = compile_to_array([_c("desc", "contains", "branch")], "device")
        assert result == [["desc", "like", "%branch%"]]

    def test_task_state_name_is_coerced_to_its_code(self) -> None:
        result, _ = compile_to_array([_c("state", "eq", "running")], "task")
        assert result == [["state", "==", 1]]

    def test_alias_resolves_before_emitting(self) -> None:
        result, _ = compile_to_array([_c("serial_number", "eq", "FG100F0000")], "device")
        assert result == [["sn", "==", "FG100F0000"]]

    def test_values_are_not_quoted_because_they_travel_as_json(self) -> None:
        result, _ = compile_to_array([_c("desc", "eq", 'has "quotes" and spaces')], "device")
        assert result == [["desc", "==", 'has "quotes" and spaces']]

    def test_not_in_becomes_one_negated_entry_per_value(self) -> None:
        result, _ = compile_to_array([_c("name", "not_in", ["a", "b"])], "device")
        assert result == [["name", "!=", "a"], ["name", "!=", "b"]]

    def test_in_is_refused_rather_than_guessed(self) -> None:
        """The refusal states its reason, like not_contains does -- a caller
        who knows ``in`` works on query_logs deserves the why, not just a no."""
        with pytest.raises(ValidationError) as exc:
            compile_to_array([_c("name", "in", ["a", "b"])], "device")
        assert "one call per value" in str(exc.value)
        assert "OR form" in str(exc.value)

    def test_no_conditions_compiles_to_an_empty_list(self) -> None:
        result, warnings = compile_to_array([], "device")
        assert result == []
        assert warnings == []

    def test_unknown_device_field_raises_because_the_set_is_complete(self) -> None:
        with pytest.raises(ValidationError):
            compile_to_array([_c("not_a_device_field", "eq", "x")], "device")
