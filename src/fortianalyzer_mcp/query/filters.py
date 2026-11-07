"""Structured filter conditions, compiled to FortiAnalyzer's filter dialects.

FortiAnalyzer speaks two unrelated filter syntaxes and this module owns both:

* the **string dialect** -- logview, fortiview, eventmgmt, incidentmgmt:
  ``"srcip==10.0.0.1 and dstport==443"``, with parenthesised OR groups.
* the **array dialect** -- dvmdb, config, task:
  ``[["name", "like", "%fgt%"], "&&", ["conn_status", "==", 2]]``. A bare
  list of entries is an OR on the appliance, so entries are joined with
  ``"&&"``.

Callers describe a query once as ``FilterCondition`` objects; this module emits
whichever dialect the endpoint speaks. That is what makes operator spelling
consistent: before this existed the repo spelled "contains" two ways
(``attack contain X`` in log_tools, ``attack=*X*`` in pcap_tools) and carried
two sanitisers with different safe-character classes.

Only operator spellings with working evidence against a live appliance are
emitted. FortiAnalyzer 7.0.1 also documents ``~``, ``!~``, ``isnull``,
``isnotnull`` and ``<>`` for its Log View parser, but none is exercised through
JSON-RPC on the *string* dialect, so they are deliberately absent there until a
live check confirms them -- see the spec's verification items. ``like`` IS now
proven on both dialects and is how ``contains`` compiles on each: the
documented ``contain`` spelling silently matches zero rows on both. The op set
is data, so adding one later is a one-line change.

Quoting is a *string-dialect* concern only. Array-dialect values travel as JSON
scalars and are never interpolated into a string, so they need no escaping.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict

from fortianalyzer_mcp.query.fields import (
    coerce_value,
    enum_names,
    enum_value_warning,
    is_integer_field,
    resolve_field,
)
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    like_filter_pattern,
    sanitize_filter_value,
)

FilterOp = Literal[
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "contains",
    "not_contains",
    "in",
    "not_in",
]

#: Ops that emit as a symbol with no surrounding spaces (``srcip==1.2.3.4``).
_SYMBOL_OPS: dict[str, str] = {
    "eq": "==",
    "ne": "!=",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
}

#: Substring ops. The string dialect compiles these to ``like`` with ``%``
#: wildcards for the same reason the array dialect already does: the documented
#: ``contain``/``!contain`` spellings are accepted by the parser and silently
#: match zero rows, so a caller filtering with them gets a confident empty
#: answer instead of an error.
#:
#: Probed live on 7.6.7 and 8.0.0 over one fixed hour of traffic, 488444 rows:
#:
#:     service==DNS              12052      service contain DNS        0
#:     service like "%DNS%"      12052      service !contain DNS       0
#:     !(service like "%DNS%")  476392
#:
#: 12052 + 476392 is exactly 488444, so the wrapped form is a true complement
#: rather than a match-everything. A predicate and its negation BOTH returning
#: zero is what proves ``contain`` inert rather than merely strict: the parser
#: does not reject operators it does not know, and a nonsense ``service zzqq
#: DNS`` behaves identically. Genuine syntax errors do surface, which is why
#: negation has to wrap the clause: ``not like``, ``!like`` and ``nlike`` are
#: each rejected with ``Invalid filter``.
_LIKE_OPS = frozenset({"contains", "not_contains"})

_MULTI_VALUE_OPS = frozenset({"in", "not_in"})


class FilterCondition(BaseModel):
    """One field/operator/value condition, independent of dialect.

    A Pydantic model rather than a dict so MCPServer publishes a real JSON schema
    for it -- including the ``op`` enum, which is what stops an invalid operator
    at the protocol boundary instead of at the appliance.
    """

    model_config = ConfigDict(extra="forbid")

    field: str
    op: FilterOp = "eq"
    # ``bool`` is listed in the list arm as well as the scalar arm so that
    # ``_reject_bool`` can actually see one. Without it pydantic coerces True
    # to 1 on the way in, and the same boolean that errors as a scalar becomes
    # a silent ``dstport==1`` inside a list.
    value: str | bool | int | float | list[str | bool | int]


def _reject_bool(field: str, value: object) -> None:
    """Reject booleans. ``bool`` is a subclass of ``int``, so check it first."""
    if isinstance(value, bool):
        raise ValidationError(
            f"Filter on '{field}' has a boolean value. FortiAnalyzer filters compare "
            "against text or numbers -- pass the concrete value instead."
        )


def _reject_substring_on_enum(vocabulary: str, field: str, op: str) -> None:
    """Refuse a substring op on a field FortiAnalyzer stores as an enum code.

    ``coerce_value`` runs before the wildcards are attached, so the pattern ends
    up wrapping the *code* rather than the name the caller wrote. Measured live
    on 7.6.6, ``list_tasks(filters=[{"field": "state", "op": "contains",
    "value": "running"}])`` echoed ``[["state", "like", "%1%"]]`` -- and
    ``TASK_STATE_CODES`` runs 0..10, so ``%1%`` matches state 1 (running) *and*
    state 10 (unknown), while ``%0%`` matches 0 (pending) and 10.

    There is nothing correct to emit: the stored value is an integer and the
    caller asked for a substring of a name. So this is refused rather than
    guessed, the same call the array dialect already makes for ``not_contains``.
    """
    if op not in _LIKE_OPS:
        return
    names = enum_names(vocabulary, field)
    if names is None:
        return
    raise ValidationError(
        f"Filter on '{field}' with op '{op}' is not supported: FortiAnalyzer stores "
        f"'{field}' as a numeric code, so a substring match would compare against the "
        f"code and not the name -- '%1%' matches both 1 and 10. Use op 'eq' or 'ne' "
        f"with one of: {', '.join(names)}."
    )


def _reject_substring_on_integer(vocabulary: str, field: str, op: str) -> None:
    """Refuse a substring op on a field FortiAnalyzer stores as a plain integer.

    ``like`` does not text-match an integer. dvmdb splits a firmware version
    across ``os_ver`` (7), ``mr`` (6) and ``patch`` (7); measured on 7.6.7
    (#146), ``os_ver like "%7%"`` returned seven devices, every one with
    ``os_ver=0``, and none of the four on 7. No single field holds "7.6"
    either, so there is no substring to look for in the first place.
    """
    if op not in _LIKE_OPS or not is_integer_field(vocabulary, field):
        return
    raise ValidationError(
        f"Filter on '{field}' with op '{op}' is not supported: FortiAnalyzer stores "
        f"'{field}' as an integer, and a substring match does not text-match an "
        "integer. Use op 'eq' (or gt/gte/lt/lte) with a whole number. For a firmware "
        "version, dvmdb splits it across os_ver, mr and patch -- 7.6 is os_ver eq 7 "
        'and mr eq 6, which search_devices\' os_version_filter="7.6" builds for you.'
    )


def _scalar(condition: FilterCondition) -> str | int | float:
    """Return the single value for a scalar op."""
    value = condition.value
    if isinstance(value, list):
        raise ValidationError(
            f"Filter on '{condition.field}' with op '{condition.op}' takes one value, not "
            "a list. Use op 'in' or 'not_in' for multiple values."
        )
    _reject_bool(condition.field, value)
    return value


def _values(condition: FilterCondition) -> list[str | int]:
    """Return the value list for ``in``/``not_in``."""
    value = condition.value
    if not isinstance(value, list):
        raise ValidationError(
            f"Filter on '{condition.field}' with op '{condition.op}' takes a list of "
            "values, not a single value."
        )
    if not value:
        raise ValidationError(
            f"Filter on '{condition.field}' has an empty value list; nothing to match."
        )
    for item in value:
        _reject_bool(condition.field, item)
    return list(value)


def _quote(value: str | int | float, field: str) -> str:
    """Sanitise one value for interpolation into the string dialect."""
    return sanitize_filter_value(str(value), field)


def compile_to_string(
    conditions: Sequence[FilterCondition],
    vocabulary: str,
) -> tuple[str, list[str]]:
    """Compile conditions into the string dialect, ANDed together.

    ``in``/``not_in`` become parenthesised groups. Parentheses are supported:
    the administration guide documents
    ``dstip==192.168.1.168 and ( dstport == 514 or dstport == 515 )``, and this
    repo already ships ``(severity="critical" or severity="high")``.

    Args:
        conditions: The conditions to compile. Empty yields an empty filter.
        vocabulary: The logtype or object type whose field names apply.

    Returns:
        ``(filter_string, warnings)``. ``warnings`` holds one entry per field
        name that was passed through unrecognised.

    Raises:
        ValidationError: on a value/op mismatch, a boolean value, a substring op
            against a field stored as an enum code, or an unknown field in a
            vocabulary that enumerates its fields.
    """
    clauses: list[str] = []
    warnings: list[str] = []

    for condition in conditions:
        field, warning = resolve_field(vocabulary, condition.field)
        if warning:
            warnings.append(warning)

        op = condition.op
        # Before coercion, so the message is about the operator rather than
        # about a partial enum name failing to coerce.
        _reject_substring_on_enum(vocabulary, field, op)

        if op in _MULTI_VALUE_OPS:
            raw_values = list(_values(condition))
            warnings.extend(
                w
                for w in (enum_value_warning(vocabulary, field, v) for v in raw_values)
                if w is not None
            )
            values = [coerce_value(vocabulary, field, v) for v in raw_values]
            if op == "in":
                inner = " or ".join(f"{field}=={_quote(v, field)}" for v in values)
            else:
                inner = " and ".join(f"{field}!={_quote(v, field)}" for v in values)
            clauses.append(f"({inner})")
            continue

        raw_scalar = _scalar(condition)
        # Only for exact comparison: `action contains "den"` is a legitimate
        # partial match, and warning that "den" is not an action would be
        # noise about a query that is doing exactly what it says.
        if op not in _LIKE_OPS:
            enum_warning = enum_value_warning(vocabulary, field, raw_scalar)
            if enum_warning:
                warnings.append(enum_warning)

        value = coerce_value(vocabulary, field, raw_scalar)
        if op in _SYMBOL_OPS:
            clauses.append(f"{field}{_SYMBOL_OPS[op]}{_quote(value, field)}")
        elif op in _LIKE_OPS:
            # The value is written for ``like`` (backslash doubled, ``%`` and
            # ``_`` escaped) and quoted as one literal with the wildcards, so
            # it cannot terminate its own clause. Live-checked that a quoted
            # pattern matches identically to a bare one.
            clause = f"{field} like {like_filter_pattern(str(value), field)}"
            clauses.append(f"!({clause})" if op == "not_contains" else clause)
        else:  # pragma: no cover - every op in the enum is handled above
            raise ValidationError(f"Filter op '{op}' is not supported on the string dialect.")

    return " and ".join(clauses), warnings


#: Array-dialect operator spellings with working live evidence: ``==``, ``!=``
#: and the comparisons behave (probed against live dvmdb and task endpoints).
#: The word operators are traps -- ``contain``, ``!contain`` and ``not like``
#: are all *accepted* by the endpoint and silently match zero rows -- so
#: ``contains`` compiles to ``like`` with ``%`` wildcards below, and
#: ``not_contains`` is refused outright: there is no spelling that works.
_ARRAY_OPS: dict[str, str] = {
    "eq": "==",
    "ne": "!=",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
}


def _chain(terms: Sequence[list[object]], separator: str) -> list[object]:
    """``[t1, separator, t2, separator, ...]``; ``[t1]`` for one term."""
    joined: list[object] = []
    for term in terms:
        if joined:
            joined.append(separator)
        joined.append(term)
    return joined


def _is_group(term: list[object]) -> bool:
    """An ``"||"`` group leads with an entry; an entry leads with its field."""
    return bool(term) and isinstance(term[0], list)


def _and_join(terms: list[list[object]]) -> list[object]:
    """Join terms so a row must match all of them: ``[t1, "&&", t2, ...]``.

    A term is an entry or an ``"||"`` group from ``in``. A lone entry goes out
    unchanged as ``[c1]`` and a lone group as itself, ``[c1, "||", c2]``; no
    terms give ``[]``. Beside other terms a group stays nested rather than
    spliced into the chain: the precedence of ``"&&"`` against ``"||"`` in one
    flat list is undocumented, and ``[[a, "||", b], "&&", c]`` is the
    documented form.
    """
    if len(terms) == 1 and _is_group(terms[0]):
        return terms[0]
    return _chain(terms, "&&")


def compile_to_array(
    conditions: Sequence[FilterCondition],
    vocabulary: str,
) -> tuple[list[object], list[str]]:
    """Compile conditions into the array dialect (dvmdb, config, task).

    The appliance reads a bare list of entries as an OR, not an AND. Measured
    on 7.6.7 build 3737 (#146): ``[["name", "==", a], ["name", "==", b]]``
    returned both devices, and two ``!=`` entries excluded nothing. Entries are
    therefore joined with ``"&&"`` -- ``[c1, "&&", c2, "&&", c3]`` returns the
    intersection, in a flat chain of any length. This is the only place the
    join happens: ``search_devices`` and ``list_tasks`` pass their narrow
    parameters in here as conditions, so those and ``filters`` always end up
    in the same chain.

    Values are *not* quoted or escaped: they travel as JSON scalars and are
    never interpolated into a filter string, so the string dialect's injection
    boundary does not apply.

    ``contains`` compiles to ``like`` with ``%`` wildcards: the documented
    ``contain`` spelling is accepted by live dvmdb and task endpoints and
    silently matches zero rows. ``like`` treats ``%`` and ``_`` as SQL
    wildcards, so a needle containing ``_`` can over-match by one character --
    accepted, since the alternative is an operator that never matches at all.

    ``in`` compiles to ``==`` entries joined with ``"||"``, the array
    dialect's OR, and goes into the ``"&&"`` chain as one nested group --
    see ``_and_join``. ``not_contains`` is refused rather than guessed: every
    candidate spelling (``!contain``, ``not like``) silently matches zero rows
    live, so there is nothing correct to emit.

    ``contains`` against a field stored as an enum code (``state``,
    ``conn_status``) is refused for the same reason -- the wildcards would wrap
    the code rather than the name. See ``_reject_substring_on_enum``. So is
    ``contains`` against a plain integer (``os_ver``, ``mr``, ``patch``), which
    ``like`` does not text-match. See ``_reject_substring_on_integer``.

    Returns:
        ``(filter, warnings)``. ``filter`` is ``[]`` for no conditions,
        ``[c1]`` for one, and ``[c1, "&&", c2, ...]`` otherwise. ``not_in``
        contributes one ``!=`` entry per value to the same chain; ``in``
        contributes one ``[c1, "||", c2, ...]`` group, or a plain entry for a
        single value.

    Raises:
        ValidationError: on ``not_contains``, a substring op against a field
            stored as an enum code or a plain integer, a value/op mismatch, a
            boolean value, or an unknown field.
    """
    entries: list[list[object]] = []
    warnings: list[str] = []

    for condition in conditions:
        field, warning = resolve_field(vocabulary, condition.field)
        if warning:
            warnings.append(warning)

        op = condition.op
        # Before coercion, so the message is about the operator rather than
        # about a partial enum name failing to coerce. ``not_contains`` is
        # refused wholesale below, so on this dialect only ``contains`` can
        # reach a code-valued or integer field.
        _reject_substring_on_enum(vocabulary, field, op)
        _reject_substring_on_integer(vocabulary, field, op)

        if op in _ARRAY_OPS:
            value = coerce_value(vocabulary, field, _scalar(condition))
            entries.append([field, _ARRAY_OPS[op], value])
            continue

        if op == "contains":
            value = coerce_value(vocabulary, field, _scalar(condition))
            entries.append([field, "like", f"%{value}%"])
            continue

        if op == "not_in":
            for item in _values(condition):
                entries.append([field, "!=", coerce_value(vocabulary, field, item)])
            continue

        if op == "in":
            alternatives = [
                [field, "==", coerce_value(vocabulary, field, item)] for item in _values(condition)
            ]
            entries.append(
                alternatives[0] if len(alternatives) == 1 else _chain(alternatives, "||")
            )
            continue

        if op == "not_contains":
            raise ValidationError(
                f"Filter op 'not_contains' on '{field}' is not supported against this "
                "endpoint: every candidate spelling silently matches zero rows. Use 'ne' "
                "with exact values, or filter with 'contains' and exclude the matches "
                "yourself."
            )

        raise ValidationError(  # pragma: no cover - every op in the enum is handled above
            f"Filter op '{op}' is not supported on the array dialect."
        )

    return _and_join(entries), warnings
