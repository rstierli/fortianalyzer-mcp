"""Masked values inside structured filter conditions must resolve.

A masked IP is format-preserving and unmarked, so only the sibling `field` key
identifies it as an IP. Without that, a masked filter reaches the appliance as
a valid-but-different address and returns real logs for the wrong host.
"""

from __future__ import annotations

import pytest

from fortianalyzer_mcp.masking.fields import FIELD_TYPES, IP, IP_OR_HOST, MAC
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.unmask import ArgUnmasker
from fortianalyzer_mcp.query.fields import (
    _DEVICE_ALIASES,
    _DEVICE_FIELDS,
    _TASK_ALIASES,
    _TASK_FIELDS,
    canonical_log_field,
)
from fortianalyzer_mcp.query.filters import FilterCondition, compile_to_array, compile_to_string

KEY = "0" * 64


def _engine() -> FPEEngine:
    return FPEEngine(KEY)


class TestFilterConditionDicts:
    """The dict form, as the argument walk can meet it before model validation.

    This pins the *unmasker's* tolerance for a dict, not a claim that the whole
    stack accepts one: the compilers below use attribute access and reject it.
    See ``TestCompilerRequiresModelsNotDicts``.
    """

    def test_masked_ip_resolves_using_the_sibling_field(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_ip("192.0.2.5")
        assert token != "192.0.2.5", "precondition: the IP must actually be masked"

        result = unmasker.unmask_args({"filters": [{"field": "srcip", "op": "eq", "value": token}]})

        assert result["filters"][0]["value"] == "192.0.2.5"

    def test_masked_username_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")

        result = unmasker.unmask_args({"filters": [{"field": "user", "op": "eq", "value": token}]})

        assert result["filters"][0]["value"] == "jdoe"

    def test_masked_mac_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_mac("00:11:22:33:44:55")

        result = unmasker.unmask_args(
            {"filters": [{"field": "srcmac", "op": "eq", "value": token}]}
        )

        assert result["filters"][0]["value"] == "00:11:22:33:44:55"

    def test_list_values_resolve_elementwise(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        tokens = [engine.mask_ip("192.0.2.5"), engine.mask_ip("192.0.2.6")]

        result = unmasker.unmask_args(
            {"filters": [{"field": "srcip", "op": "in", "value": tokens}]}
        )

        assert result["filters"][0]["value"] == ["192.0.2.5", "192.0.2.6"]

    def test_unmasked_value_is_left_alone(self) -> None:
        unmasker = ArgUnmasker(_engine())
        result = unmasker.unmask_args({"filters": [{"field": "dstport", "op": "eq", "value": 443}]})
        assert result["filters"][0]["value"] == 443


class TestAliasFieldNames:
    """The advertised English aliases must type a value like their canonical target.

    The compilers resolve ``source_ip`` to ``srcip``, and the server guide
    advertises exactly that. A masked IP is unmarked, so if unmasking types the
    value by the raw alias spelling instead of the canonical target, the token
    rides through to the appliance as a valid-but-different address.
    """

    @pytest.mark.parametrize(
        "alias", ["source_ip", "destination_ip", "dest_ip", "src_ip", "dst_ip"]
    )
    def test_masked_ip_resolves_under_an_ip_typed_alias(self, alias: str) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_ip("192.0.2.5")
        assert token != "192.0.2.5", "precondition: the IP must actually be masked"

        result = unmasker.unmask_args({"filters": [{"field": alias, "op": "eq", "value": token}]})

        assert result["filters"][0]["value"] == "192.0.2.5"

    def test_model_form_resolves_under_an_alias(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_ip("192.0.2.5")

        result = unmasker.unmask_args(
            {"filters": [FilterCondition(field="destination_ip", op="eq", value=token)]}
        )

        condition = result["filters"][0]
        assert isinstance(condition, FilterCondition)
        assert condition.value == "192.0.2.5"
        assert condition.field == "destination_ip"


class TestFilterConditionModels:
    """The model form, which is what FastMCP passes to the tool."""

    def test_model_instance_is_resolved_and_stays_a_model(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_ip("192.0.2.5")

        result = unmasker.unmask_args(
            {"filters": [FilterCondition(field="srcip", op="eq", value=token)]}
        )

        condition = result["filters"][0]
        assert isinstance(condition, FilterCondition)
        assert condition.value == "192.0.2.5"
        assert condition.field == "srcip"
        assert condition.op == "eq"


class TestMeasuredStringFilterBehaviour:
    """Freeze what unmask_filter does today, including what it cannot do.

    The embedded-token case is asserted as broken on purpose: it predates this
    work, a compiler cannot turn a phrase into a token, and fixing it needs
    substring resolution inside resolve_scalar. Asserting it keeps the
    limitation visible and forces a future fix to update this test knowingly.
    """

    def test_quoted_token_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")
        assert unmasker.unmask_filter(f'user=="{token}"') == 'user=="jdoe"'

    def test_bare_token_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")
        assert unmasker.unmask_filter(f"user=={token}") == "user==jdoe"

    def test_token_embedded_in_a_quoted_phrase_does_not_resolve(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")
        expression = f'msg contain "login failed for {token}"'
        assert unmasker.unmask_filter(expression) == expression


class TestCompilerRequiresModelsNotDicts:
    """Where the dict tolerance stops.

    ``TestFilterConditionDicts`` above pins the *unmask* layer's handling of a
    plain dict, because that is the shape an argument walk can legitimately
    meet. The compilers below it cannot consume one -- both use attribute
    access -- so the dict form is supported at one layer and rejected at the
    next. That is harmless in production, where FastMCP validates into models
    before a tool body runs, but it is worth pinning so the two layers are not
    mistaken for having the same contract.
    """

    @pytest.mark.parametrize(
        ("compiler", "vocabulary"),
        [(compile_to_string, "traffic"), (compile_to_array, "device")],
    )
    def test_a_plain_dict_raises_attribute_error(self, compiler: object, vocabulary: str) -> None:
        with pytest.raises(AttributeError, match="'dict' object has no attribute 'field'"):
            compiler([{"field": "name", "op": "eq", "value": "x"}], vocabulary)  # type: ignore[operator]

    def test_the_model_form_of_the_same_condition_compiles(self) -> None:
        """Control: the shape FastMCP actually hands over works fine."""
        result, _ = compile_to_array([FilterCondition(field="name", op="eq", value="x")], "device")
        assert result == [["name", "==", "x"]]


class TestArrayDialectConditions:
    """The array-dialect tools were unpinned here.

    ``search_devices`` and ``list_tasks`` take the same ``filters`` parameter
    through the same unmasker, but every test above compiles to the string
    dialect. A masked value has to survive the round trip on this path too:
    inbound resolution first, then compilation into ``[field, op, value]``
    entries that reach the appliance.
    """

    def test_masked_ip_in_a_device_filter_resolves_and_compiles(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_ip("192.0.2.5")
        assert token != "192.0.2.5", "precondition: the IP must actually be masked"

        resolved = unmasker.unmask_args(
            {"filters": [FilterCondition(field="ip", op="eq", value=token)]}
        )
        entries, _ = compile_to_array(resolved["filters"], "device")

        assert entries == [["ip", "==", "192.0.2.5"]]

    def test_masked_hostname_survives_a_contains_condition(self) -> None:
        """``contains`` is the operator the masking guidance steers callers to
        for device identifiers, because the appliance's ``like`` is
        case-insensitive while ``==`` is not. So this is the path that has to
        work, not merely the ``eq`` one."""
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_hostname("host.example.com")

        resolved = unmasker.unmask_args(
            {"filters": [FilterCondition(field="hostname", op="contains", value=token)]}
        )
        entries, _ = compile_to_array(resolved["filters"], "device")

        assert entries == [["hostname", "like", "%host.example.com%"]]

    def test_an_unmasked_task_filter_is_untouched(self) -> None:
        unmasker = ArgUnmasker(_engine())
        resolved = unmasker.unmask_args(
            {"filters": [FilterCondition(field="state", op="eq", value="running")]}
        )
        entries, _ = compile_to_array(resolved["filters"], "task")
        assert entries == [["state", "==", 1]]


class TestAliasTypingInvariant:
    """No device or task field may reach an IP/MAC type the log table cannot see.

    ``unmask_filter_conditions`` canonicalises the sibling field through
    ``canonical_log_field``, which reads the *log* alias table only. That is
    exhaustively fine today. It stops being fine the moment a device or task
    alias targets a canonical that ``FIELD_TYPES`` types as IP, MAC or
    IP_OR_HOST: the log table would not know the alias, the type lookup would
    miss, and an unmarked IP token -- which is indistinguishable from a real
    address -- would travel to the appliance verbatim and return real rows for
    the wrong host.

    Pinning it here catches that at the suite rather than at the appliance.
    """

    @pytest.mark.parametrize(
        ("label", "aliases"),
        [("device", _DEVICE_ALIASES), ("task", _TASK_ALIASES)],
    )
    def test_an_alias_onto_a_masked_address_type_also_types_that_way(
        self, label: str, aliases: dict[str, str]
    ) -> None:
        risky = {IP, MAC, IP_OR_HOST}
        for alias, canonical in aliases.items():
            if FIELD_TYPES.get(canonical.lower()) not in risky:
                continue
            assert FIELD_TYPES.get(canonical_log_field(alias).lower()) in risky, (
                f"{label} alias {alias!r} targets {canonical!r}, which masking types as an "
                f"address, but canonical_log_field({alias!r}) does not reach that type -- "
                "an unmarked token under this alias would reach the appliance in clear"
            )

    def test_the_guard_above_actually_detects_a_violation(self) -> None:
        """The alias sweep is vacuous today -- no device or task alias targets an
        address type -- so without this the assertion could rot into something
        that can never fail and nobody would notice.

        ``mgmt_ip -> ip`` is the shape of the alias that would break it: the
        canonical is IP-typed, but the log alias table has never heard of
        ``mgmt_ip``, so the type lookup misses and the token stays unresolved.
        """
        risky = {IP, MAC, IP_OR_HOST}
        alias, canonical = "mgmt_ip", "ip"

        assert FIELD_TYPES.get(canonical) in risky, "precondition: the target is address-typed"
        # The log table cannot resolve a device-only alias, so the type is lost.
        assert FIELD_TYPES.get(canonical_log_field(alias).lower()) not in risky

    @pytest.mark.parametrize(
        ("label", "fields"),
        [("device", _DEVICE_FIELDS), ("task", _TASK_FIELDS)],
    )
    def test_canonical_names_keep_their_masked_type_through_the_log_table(
        self, label: str, fields: frozenset[str]
    ) -> None:
        """The canonical spellings must survive the same lookup.

        ``device.ip`` is IP-typed and is the live example, so this is not
        hypothetical: it passes only because ``canonical_log_field`` leaves an
        unknown name alone and ``FIELD_TYPES`` keys on it directly.
        """
        risky = {IP, MAC, IP_OR_HOST}
        for name in fields:
            if FIELD_TYPES.get(name.lower()) not in risky:
                continue
            assert FIELD_TYPES.get(canonical_log_field(name).lower()) in risky, (
                f"{label} field {name!r} is address-typed but loses that type through "
                "canonical_log_field, so a token under it would not be resolved"
            )
