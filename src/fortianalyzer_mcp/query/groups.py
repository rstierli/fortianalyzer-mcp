"""Where an exact grouping can actually come from.

``group_by`` promises an exact answer, so it may only resolve to a surface the
appliance itself aggregated. For logs every such surface is a FortiView view;
for alerts and incidents it is a stats endpoint. A dimension with no native
surface is refused rather than answered by scanning a bounded sample, because a
top-N over a 1000-row sample reads as fact and gets quoted as fact. The refusal
names ``sample_by``, which makes exactly that trade-off explicitly and labels
the result.

A FortiView view aggregates *its own* log source. The view, not the caller's
``logtype``, therefore decides the population the top-N describes: dispatching
``logtype="attack", group_by="srcip"`` to ``top-sources`` would answer a
question about traffic logs and label it exact under an echoed
``logtype: "attack"``. So every entry in :data:`LOG_GROUP_SURFACES` records the
log population its view serves, and a dimension whose view serves a different
population is refused rather than answered. The populations encoded here are
the ones defensible from each view's documented purpose in this repo (the
traffic views serve traffic; ``top-threats`` attack; ``top-websites``
webfilter) -- no live probe has confirmed a view's source, so where a view's
source is genuinely uncertain it is treated as serving only its evident
logtype. ``sample_by`` covers every other logtype/dimension pair, bounded and
labelled as such, which is what each refusal names.

Three translations the plan carries, each of which silently returns zero rows
if missed:

* FortiView's all-devices group is ``All_Device``; logview's is
  ``All_FortiGate``. Forwarding the logview default to a view yields an empty
  top-N with no error. :func:`~fortianalyzer_mcp.tools.fortiview_tools.\
build_fortiview_device_filter` performs that translation at the FortiView
  boundary, so both the ``group_by`` dispatch and ``get_fortiview_data``
  itself emit ``[{"devname": "All_Device"}]``.
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

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from fortianalyzer_mcp.query.derive import dimension_value
from fortianalyzer_mcp.query.fields import resolve_field
from fortianalyzer_mcp.utils.errors import ValidationError

#: FortiView's spelling of "every device". Logview says All_FortiGate.
FORTIVIEW_ALL_DEVICES = "All_Device"


@dataclass(frozen=True)
class LogGroupSurface:
    """One FortiView view, and the log population it aggregates.

    ``serves`` is the whole point: a view's top-N describes the logs that view
    reads, so requesting it for a different ``logtype`` produces a confident
    answer about the wrong population. It is a conservative claim, not a
    measurement -- see the module docstring and
    ``docs/probes/2026-07-fortiview-surface.md``.
    """

    #: The FortiView view name; must be in ``VALID_FORTIVIEW_VIEWS``.
    view: str
    #: The logtypes whose population this view is defensibly known to serve.
    serves: frozenset[str]


#: Log dimension -> the FortiView view that aggregates it natively, and the log
#: population that view serves.
#:
#: Why each ``serves`` is what it is, from the views' documented purpose here:
#:   top-sources / top-destinations  traffic volume per address -> traffic
#:   top-applications                "top applications by bandwidth"; app-ctrl
#:                                   logs carry no byte counts (see
#:                                   get_fortiview_data's own docstring), so a
#:                                   bandwidth ranking reads traffic logs
#:   policy-hits                     per-firewall-policy hit counts -> traffic
#:   top-countries                   destination geo of traffic -> traffic
#:   top-websites                    web CATEGORIES of webfilter logs
#:   top-threats                     detected threats -> attack
#: ``top-cloud-applications`` (app-ctrl, Shadow IT) is deliberately unmapped:
#: no dimension resolves to it unambiguously, and guessing between it and
#: top-applications for ``group_by="app"`` is exactly the confusion this table
#: exists to prevent. Reach it through get_fortiview_data by name.
#:
#: Two dimensions were removed here after live probing on 7.6.7 and 8.0.0
#: (#109 review) showed the view does not serve what the dimension name
#: promised:
#:
#: * ``hostname``/``website`` -> ``top-websites``. The view returns rows keyed
#:   ``catdesc``/``catid`` and carries no hostname column at all, so the
#:   response labelled web-category buckets ``group_by: "hostname"`` under
#:   ``is_exact: true`` -- an exact answer to a question nobody asked, which
#:   is the one failure an exactness promise cannot survive. ``catdesc`` is
#:   what the view actually aggregates and is mapped in their place;
#:   ``hostname`` now refuses, and the refusal recommends
#:   ``sample_by=["hostname"]``, which genuinely groups webfilter rows.
#: * ``app`` -> ``top-applications``. The view labels its rows ``app_group``,
#:   so the buckets are application groups rather than applications. Unlike
#:   the websites case there is no honest dimension name to swap in
#:   (``app_group`` is in no vocabulary), so the dimension is refused and
#:   ``sample_by=["app"]`` or ``get_fortiview_data(view_name=
#:   "top-applications")`` are the two honest routes.
LOG_GROUP_SURFACES: Mapping[str, LogGroupSurface] = {
    "srcip": LogGroupSurface("top-sources", frozenset({"traffic"})),
    "dstip": LogGroupSurface("top-destinations", frozenset({"traffic"})),
    "catdesc": LogGroupSurface("top-websites", frozenset({"webfilter"})),
    "attack": LogGroupSurface("top-threats", frozenset({"attack"})),
    "threat": LogGroupSurface("top-threats", frozenset({"attack"})),
    "policyid": LogGroupSurface("policy-hits", frozenset({"traffic"})),
    "dstcountry": LogGroupSurface("top-countries", frozenset({"traffic"})),
}

#: The sort column each FortiView view is ranked by when the caller asks for
#: none. Every retired ``get_top_*`` wrapper hard-coded one of these, and the
#: consolidation dropped them: the ``group_by`` dispatch sent ``sort_by=None``
#: and the migrated skill call sites sent nothing, while the responses still
#: said "top N groups" and set ``groups_truncated`` -- ranking claims about a
#: sort that was never requested (#109 review).
#:
#: ``docs/probes/2026-07-fortiview-surface.md`` withheld these on the belief
#: that an unknown sort column "would be ignored by FortiAnalyzer, not
#: rejected", which would have made a wrong entry silently reorder results.
#: That was measured the other way on 7.6.7 and 8.0.0 --
#: ``sort_by='notacolumn'`` returns a loud ``Missing columns: 'notacolumn'``
#: -- so a wrong name here fails visibly rather than silently, and restoring
#: the defaults is safe.
#:
#: ``top-countries`` is absent deliberately: no retired wrapper served it, so
#: there is no measured default to restore and the appliance's own ordering
#: stands. Callers of ``get_fortiview_data`` are unaffected -- that tool is
#: the generic passthrough and keeps ``sort_by=None``; these defaults belong
#: to the dispatch and skill layers that replaced named wrappers.
VIEW_SORT_DEFAULTS: Mapping[str, str] = {
    "top-sources": "bandwidth",
    "top-destinations": "bandwidth",
    "top-applications": "bandwidth",
    "top-websites": "bandwidth",
    "top-threats": "threatweight",
    "top-cloud-applications": "sessions",
    "policy-hits": "counts",
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

    def __init__(
        self,
        dimension: str,
        supported: list[str],
        vocabulary: str,
        detail: str = "",
    ) -> None:
        self.dimension = dimension
        self.supported = supported
        self.vocabulary = vocabulary
        if supported:
            works = (
                f"Dimensions the appliance can group exactly for {vocabulary}: "
                f"{', '.join(supported)}. "
            )
        else:
            # An empty list is a real answer for logtypes no FortiView view
            # serves (event, dns, dlp, ...). Saying "the ones that work: " and
            # then nothing reads as a bug in the refusal.
            works = f"No dimension can be grouped exactly for {vocabulary}. "
        super().__init__(
            f"group_by='{dimension}' has no exact surface for {vocabulary}. "
            + (f"{detail} " if detail else "")
            + works
            + f"Use sample_by=['{dimension}'] instead: it scans a bounded sample, "
            "works for every logtype, and labels the result as one."
        )


class GroupSurfacePopulationMismatch(UnsupportedGroupDimension):
    """The dimension has a native view, but that view reads other logs.

    Every FortiView view aggregates its own log source, so dispatching
    ``logtype="attack", group_by="srcip"`` to ``top-sources`` would return a
    ranking of *traffic* sources under an echoed ``logtype: "attack"`` and
    ``is_exact: true`` -- exact about a population nobody asked for. Refusing
    is the only honest answer available without a live probe of each view's
    source.

    Subclasses :class:`UnsupportedGroupDimension` so one ``except`` still
    catches both, while ``isinstance`` lets a tool emit a distinct machine
    code: "not groupable at all" and "not groupable for *this* logtype" are
    different facts, and only the second is fixed by changing ``logtype``.
    """

    def __init__(
        self,
        dimension: str,
        canonical: str,
        view: str,
        serves: frozenset[str],
        supported: list[str],
        vocabulary: str,
    ) -> None:
        self.view = view
        self.serves = serves
        super().__init__(
            dimension,
            supported,
            vocabulary,
            detail=(
                f"The only exact surface for '{canonical}' is the FortiView view "
                f"'{view}', which aggregates {'/'.join(sorted(serves))} logs -- a "
                f"different population than logtype='{vocabulary}', so its top-N "
                "would not answer what was asked."
            ),
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
    """The dimensions groupable exactly for one vocabulary.

    For a logtype this is not the whole dimension table: a view only answers
    for the population it reads, so the list is filtered by ``serves`` and can
    legitimately be empty.
    """
    if vocabulary == "alert":
        return sorted(ALERT_GROUP_DIMENSIONS)
    if vocabulary == "incident":
        return sorted(INCIDENT_GROUP_DIMENSIONS)
    return sorted(
        dimension
        for dimension, surface in LOG_GROUP_SURFACES.items()
        if vocabulary in surface.serves
    )


def resolve_group_plan(vocabulary: str, dimension: str) -> GroupPlan:
    """Resolve a ``group_by`` dimension to the surface that answers it exactly.

    Args:
        vocabulary: The logtype, or ``"alert"``/``"incident"``.
        dimension: The caller's dimension name; aliases are accepted.

    Returns:
        The plan an executor can act on.

    Raises:
        UnsupportedGroupDimension: when no native surface exists for this
            vocabulary. The message names ``sample_by`` as the way to ask the
            same question with an honest label.
        GroupSurfacePopulationMismatch: a subclass of the above, raised when
            the dimension *is* mapped but only to a view that aggregates a
            different log population than ``vocabulary``.
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

    surface = LOG_GROUP_SURFACES.get(canonical)
    if surface is None:
        raise UnsupportedGroupDimension(dimension, _supported_for(vocabulary), vocabulary)
    if vocabulary not in surface.serves:
        # Mapped, but to a view that reads other logs. Answering would echo the
        # caller's logtype over the wrong population under is_exact: true.
        raise GroupSurfacePopulationMismatch(
            dimension,
            canonical,
            surface.view,
            surface.serves,
            _supported_for(vocabulary),
            vocabulary,
        )
    return GroupPlan(dimension=canonical, surface="fortiview", target=surface.view)


def aggregate_breakdowns(
    rows: list[Any],
    dimensions: list[str],
    top_n: int = 10,
) -> dict[str, list[dict[str, Any]]]:
    """Count rows per dimension, independently.

    One scan yields one breakdown per requested dimension. This is deliberately
    not a cross-tab: ``get_policy_traffic_profile`` wants ports *and* services
    *and* applications from a single scan, and the product of three dimensions
    would explode in cardinality to answer a question nobody asked.

    Args:
        rows: The sampled rows.
        dimensions: Dimension names; plain fields and derived dimensions both
            work.
        top_n: Buckets to keep per dimension. ``0`` keeps every bucket, which
            is what ``get_policy_port_analysis``'s complete port list needed.

    Returns:
        ``{dimension: [{"value": str, "hits": int}, ...]}``, each list ordered
        by hits descending then value ascending, so equal counts come back in
        a stable order rather than one that depends on scan order.
    """
    breakdowns: dict[str, list[dict[str, Any]]] = {}

    for dimension in dimensions:
        counter: Counter[str] = Counter()
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = dimension_value(dimension, row)
            # None means the row does not belong in this breakdown -- an
            # absent field or a portless protocol -- rather than belonging in
            # an "unknown" bucket that would inflate the total.
            if value is not None:
                counter[value] += 1

        ordered = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        if top_n > 0:
            ordered = ordered[:top_n]
        breakdowns[dimension] = [{"value": value, "hits": hits} for value, hits in ordered]

    return breakdowns
