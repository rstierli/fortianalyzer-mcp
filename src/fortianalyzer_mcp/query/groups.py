"""Where an exact grouping can actually come from.

``group_by`` promises an exact answer, so it may only resolve to a surface the
appliance itself aggregated. For logs every such surface is a FortiView view;
for alerts and incidents it is a stats endpoint. A dimension with no native
surface is refused rather than answered by scanning a bounded sample, because a
top-N over a 1000-row sample reads as fact and gets quoted as fact. The refusal
names ``sample_by``, which makes exactly that trade-off explicitly and labels
the result.

Three translations the plan carries, each of which silently returns zero rows
if missed:

* FortiView's all-devices group is ``All_Device``; logview's is
  ``All_FortiGate``. Forwarding the logview default to a view yields an empty
  top-N with no error.
* The compiled filter has to be re-emitted against the view's own filterable
  vocabulary, which is not provably identical to logview's. Until that is
  verified live, the caller of this module is expected to refuse a filter on a
  field the view is not known to accept rather than silently returning an
  unfiltered top-N.
* The already-resolved ``{start, end}`` window is reused rather than
  re-derived, preserving the "resolve the window once at tool entry"
  invariant across the hand-off.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from fortianalyzer_mcp.query.fields import resolve_field
from fortianalyzer_mcp.utils.errors import ValidationError

#: FortiView's spelling of "every device". Logview says All_FortiGate.
FORTIVIEW_ALL_DEVICES = "All_Device"

#: Log dimension -> the FortiView view that aggregates it natively.
LOG_GROUP_SURFACES: Mapping[str, str] = {
    "srcip": "top-sources",
    "dstip": "top-destinations",
    "app": "top-applications",
    "hostname": "top-websites",
    "website": "top-websites",
    "attack": "top-threats",
    "threat": "top-threats",
    "policyid": "policy-hits",
    "dstcountry": "top-countries",
}

#: Alert dimensions served by /eventmgmt/adom/{adom}/alert-incident/stats.
ALERT_GROUP_DIMENSIONS: frozenset[str] = frozenset({"severity", "status"})

#: Incident dimensions served by /incidentmgmt/adom/{adom}/incident/stats.
INCIDENT_GROUP_DIMENSIONS: frozenset[str] = frozenset({"severity", "status", "category"})


class UnsupportedGroupDimension(ValidationError):
    """Raised when a dimension has no native surface to group on.

    Subclasses ValidationError so existing handlers still catch it, but carries
    the dimension and the supported set so a tool can build a structured
    envelope without re-parsing the message.
    """

    def __init__(self, dimension: str, supported: list[str], vocabulary: str) -> None:
        self.dimension = dimension
        self.supported = supported
        valid = ", ".join(supported)
        super().__init__(
            f"group_by='{dimension}' has no exact surface for {vocabulary}. "
            f"Dimensions the appliance can group exactly: {valid}. "
            f"For any other dimension use sample_by=['{dimension}'], which scans a "
            "bounded sample and labels the result as one."
        )


@dataclass(frozen=True)
class GroupPlan:
    """How to obtain an exact grouping for one dimension."""

    #: The canonical dimension name, after alias resolution.
    dimension: str
    #: Which executor handles it: "fortiview", "alert_stats", "incident_stats".
    surface: str
    #: The view name or stats item the executor should request.
    target: str
    #: The device-group token the target surface understands.
    all_devices_group: str = FORTIVIEW_ALL_DEVICES


def _supported_for(vocabulary: str) -> list[str]:
    if vocabulary == "alert":
        return sorted(ALERT_GROUP_DIMENSIONS)
    if vocabulary == "incident":
        return sorted(INCIDENT_GROUP_DIMENSIONS)
    return sorted(LOG_GROUP_SURFACES)


def resolve_group_plan(vocabulary: str, dimension: str) -> GroupPlan:
    """Resolve a ``group_by`` dimension to the surface that answers it exactly.

    Args:
        vocabulary: The logtype, or ``"alert"``/``"incident"``.
        dimension: The caller's dimension name; aliases are accepted.

    Returns:
        The plan an executor can act on.

    Raises:
        UnsupportedGroupDimension: when no native surface exists. The message
            names ``sample_by`` as the way to ask the same question with an
            honest label.
    """
    # Resolve aliases first so source_ip and srcip are the same question. An
    # unknown name on an incomplete vocabulary passes through with a warning
    # we discard here: an unmapped dimension is refused below regardless.
    try:
        canonical, _ = resolve_field(vocabulary, dimension)
    except ValidationError:
        canonical = dimension.strip().lower()

    if vocabulary == "alert":
        if canonical in ALERT_GROUP_DIMENSIONS:
            return GroupPlan(dimension=canonical, surface="alert_stats", target=canonical)
        raise UnsupportedGroupDimension(dimension, _supported_for("alert"), "alerts")

    if vocabulary == "incident":
        if canonical in INCIDENT_GROUP_DIMENSIONS:
            return GroupPlan(dimension=canonical, surface="incident_stats", target=canonical)
        raise UnsupportedGroupDimension(dimension, _supported_for("incident"), "incidents")

    view = LOG_GROUP_SURFACES.get(canonical)
    if view is None:
        raise UnsupportedGroupDimension(dimension, _supported_for(vocabulary), vocabulary)
    return GroupPlan(dimension=canonical, surface="fortiview", target=view)
