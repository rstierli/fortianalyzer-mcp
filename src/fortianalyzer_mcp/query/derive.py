"""Group dimensions FortiAnalyzer does not store as fields.

Two of the aggregations this repo performs are over values that no log field
holds. They were computed inline inside ``get_policy_port_analysis``, and when
that tool folded into ``analyze_policy_traffic`` the domain knowledge would
have gone with it. As dimensions they survive the merge and become available
to every caller rather than to one tool.

``icmp_type_code`` is the substantive one. FortiAnalyzer does not populate
``icmptype``/``icmpcode`` on traffic logs; it encodes the pair in the
``service`` field as ``PING`` (echo request) or ``icmp/<type>/<code>``. A
FortiGate running an SD-WAN SLA probe muddies that further by tagging the ICMP
packet with the *probed application's* service name, so a proto-1 row can
arrive reading ``DNS``. Recording that as a type would invent an ICMP type that
never crossed the wire, so anything that is not one of the two known encodings
becomes ``type=unknown``. That choice is also what keeps the ICMP bucket sum
equal to the proto=1 count in a protocol breakdown.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

#: Values that mean "the appliance sent nothing here", not "a bucket named X".
_ABSENT = {"", "n/a", "null", "none", "unknown"}


def _port(row: Mapping[str, Any]) -> str | None:
    """``"{proto}/{dstport}"``, or None for a portless protocol.

    A ``dstport`` of 0 is how FortiAnalyzer spells "this protocol has no
    ports" (ICMP, GRE, ESP). Bucketing those under port 0 would invent
    traffic to a port that does not exist.
    """
    proto = row.get("proto")
    dstport = row.get("dstport")
    if proto is None or dstport is None:
        return None
    port_str = str(dstport).strip()
    if not port_str or port_str == "0":
        return None
    return f"{str(proto).strip()}/{port_str}"


def _icmp_type_code(row: Mapping[str, Any]) -> str | None:
    """Decode the ICMP type/code FortiAnalyzer hides in ``service``.

    Returns None for a non-ICMP row so it does not land in the ICMP
    breakdown at all; returns ``type=unknown`` for an ICMP row whose service
    is not one of the two known encodings.
    """
    if str(row.get("proto", "")).strip() != "1":
        return None

    service = str(row.get("service", "")).strip()
    if service.upper() == "PING":
        return "type=8/code=0"
    if service.lower().startswith("icmp/"):
        parts = service.split("/")
        if len(parts) == 3:
            return f"type={parts[1]}/code={parts[2]}"
        # Malformed "icmp/..." value: do not leak the raw string as a label.
        return "type=unknown"
    # An application name (an SD-WAN SLA probe tag) or an empty service.
    return "type=unknown"


#: Dimension name -> the function that computes it from one row.
DERIVED: Mapping[str, Callable[[Mapping[str, Any]], str | None]] = {
    "port": _port,
    "icmp_type_code": _icmp_type_code,
}


def is_derived(dimension: str) -> bool:
    """Whether this dimension is computed rather than read from a field."""
    return dimension.strip().lower() in DERIVED


def derive(dimension: str, row: Mapping[str, Any]) -> str | None:
    """Compute a derived dimension for one row.

    Raises:
        KeyError: if ``dimension`` is not derived. Callers should route
            through :func:`dimension_value`, which handles both kinds.
    """
    return DERIVED[dimension.strip().lower()](row)


def dimension_value(dimension: str, row: Mapping[str, Any]) -> str | None:
    """The bucket label for one row under one dimension, or None to skip it.

    None means "this row does not belong in this breakdown" -- an absent
    field, an empty value, or a nested structure. A nested value is excluded
    rather than stringified because a bucket labelled with a dict repr is one
    the caller cannot filter on afterwards, which makes the breakdown a dead
    end.
    """
    name = dimension.strip().lower()
    if name in DERIVED:
        return DERIVED[name](row)

    value = row.get(name)
    if value is None or isinstance(value, dict | list):
        return None
    text = str(value).strip()
    if not text or text.lower() in _ABSENT:
        return None
    return text
