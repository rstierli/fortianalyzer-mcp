"""Which keys survive a response row, and the echo that reports them.

FortiAnalyzer projects nothing for logs, alerts, incidents or FortiView rows --
there is no server-side field list on those endpoints -- so projection here is
in-process: the appliance sends the whole row, this module decides what the
caller sees. That still pays for itself, because the cost this addresses is
context, not bandwidth: a traffic row is roughly sixty keys and an answer
usually needs eight.

Two invariants keep the other layers correct, and both are subtractive:

* **Selects, never renames.** The masking allowlist in ``masking/fields.py`` is
  keyed on live field names verified against 7.6.7/8.0.0 schemas. Renaming a
  key on the way out would move a value out from under its allowlist entry and
  silently unmask it. Selecting a subset can only shrink what masking must
  cover, never move it.
* **Top-level keys only.** Alerts carry nested ``subject_details`` and
  ``target[]``; selecting such a key keeps the structure whole. There is
  deliberately no dotted-path language -- that would be a second query dialect
  to learn, and ``target[]`` is one of the composite structures masking handles
  specially.

Projection runs inside the tool, so it happens *before* the masking wrapper
sees the response. A field curated away is a field masking never has to
consider.
"""

from __future__ import annotations

from typing import Any

from fortianalyzer_mcp.query.fields import get_vocabulary, resolve_field
from fortianalyzer_mcp.utils.errors import ValidationError

#: The opt-out token. ``fields=["*"]`` returns the full object as before.
ALL_FIELDS = "*"


def resolve_projection(
    vocabulary: str,
    fields: list[str] | None,
) -> tuple[frozenset[str] | None, list[str]]:
    """Decide which keys a response should carry.

    Args:
        vocabulary: The logtype or object type whose field names apply.
        fields: ``None`` for the curated default, ``["*"]`` for everything, or
            an explicit list of names (aliases accepted).

    Returns:
        ``(keys, warnings)``. ``keys`` is ``None`` when every key should
        survive -- either because the caller asked for ``["*"]`` or because the
        vocabulary has no curated set and degrading to full rows is the honest
        answer.

    Raises:
        ValidationError: on an empty list, ``"*"`` mixed with real names, or an
            unknown name in a vocabulary that enumerates its fields.
    """
    if fields is None:
        vocab = get_vocabulary(vocabulary)
        if vocab.projection:
            return vocab.projection, []
        # Name what the CALLER asked for, not vocab.name. An unregistered
        # vocabulary falls back to _GENERIC_LOG, whose name is "log", so
        # reporting vocab.name here would tell a caller who queried voip that
        # "log" has no curated set -- true of neither thing they asked about.
        return None, [
            f"no curated field set exists for {vocabulary} yet, so the full row is "
            f"returned. Pass fields=[...] to select what you need."
        ]

    if not fields:
        raise ValidationError(
            "fields was an empty list; omit it for the curated default or pass "
            'fields=["*"] for the full object.'
        )

    if ALL_FIELDS in fields:
        if len(fields) > 1:
            raise ValidationError(
                "fields cannot mix '*' with named fields. Use '*' alone for the full "
                "object, or list only the fields you want."
            )
        return None, []

    keys: set[str] = set()
    warnings: list[str] = []
    for name in fields:
        canonical, warning = resolve_field(vocabulary, name)
        if warning:
            warnings.append(warning)
        keys.add(canonical)

    return frozenset(keys), warnings


def project_rows(
    rows: list[Any],
    keys: frozenset[str] | None,
) -> list[Any]:
    """Return ``rows`` with only ``keys`` retained on each mapping.

    A key absent from a row is not invented: no null padding, because an
    absent key means the appliance did not send it and a null would claim it
    did. Non-mapping entries pass through untouched -- some FAZ endpoints
    answer with bare scalars in the data list.
    """
    if keys is None:
        return rows
    return [
        {key: value for key, value in row.items() if key in keys} if isinstance(row, dict) else row
        for row in rows
    ]


def fields_returned(
    rows: list[Any],
    keys: frozenset[str] | None,
) -> list[str]:
    """The sorted key list to echo back to the caller.

    When a projection applied, this is the projection itself -- reported even
    for a zero-row page, which is exactly when a caller most needs to know what
    is queryable next. With no projection there is nothing to report but what
    the rows actually carried, so it is the union of observed keys.
    """
    if keys is not None:
        return sorted(keys)
    observed: set[str] = set()
    for row in rows:
        if isinstance(row, dict):
            observed.update(row)
    return sorted(observed)


def project_payload(
    vocabulary: str,
    payload: Any,
    fields: list[str] | None,
) -> tuple[Any, list[str], list[str]]:
    """Project a response payload that may or may not be a row list.

    Several FortiAnalyzer readers answer with a list of rows under ``data``,
    but some answer with an object instead (a count, a status envelope). Only
    a list is projected; anything else passes through untouched and reports no
    ``fields_returned``, because claiming a projection that did not happen is
    worse than reporting none.

    Returns:
        ``(payload, fields_returned, warnings)``.

    Raises:
        ValidationError: from :func:`resolve_projection`.
    """
    keys, warnings = resolve_projection(vocabulary, fields)
    if not isinstance(payload, list):
        return payload, [], warnings
    rows = project_rows(payload, keys)
    return rows, fields_returned(rows, keys), warnings
