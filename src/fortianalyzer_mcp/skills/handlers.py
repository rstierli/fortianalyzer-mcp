"""Wave-1 skill handlers: orchestrations over existing read-only tools.

Design constraints (RFC #44):
- Compose existing tool functions only — no new client methods, no writes.
- Graceful degradation: a failed *context* call becomes a warning and a
  partial result; only a failed *subject* call fails the skill.
- Slot-safety: the only skill that consumes a logview search slot is
  ``log_search`` (exactly one search, bounded by the global logsearch
  semaphore in ``log_tools``). Triage and investigation compose
  eventmgmt/incidentmgmt/fortiview reads, which do not use search slots.

Tool modules are imported lazily inside each handler: importing them at
module scope would register every raw tool as a side effect (they attach
to the shared FastMCP instance on import), which must not happen before
the server's tool-mode branch has run.
"""

import asyncio
import json
import logging
from collections.abc import Awaitable, Coroutine
from datetime import datetime
from typing import Any

from fortianalyzer_mcp.skills.models import (
    AlertEvidence,
    FeatureGap,
    IncidentRecord,
    IncidentsParams,
    IncidentsResult,
    IncidentSummary,
    IncidentSummaryParams,
    LogSearchParams,
    LogSearchResult,
    ReportsParams,
    ReportsResult,
    TimelineEntry,
    TriageAssessment,
    TriageParams,
    TriageResult,
)
from fortianalyzer_mcp.utils.responses import redact

logger = logging.getLogger(__name__)

# Candidate FAZ field names for alert<->incident linkage. FAZ builds vary;
# correlation is best-effort over these keys and the result names which
# key matched (correlation_basis) so consumers can judge confidence.
_ALERT_INCIDENT_KEYS = ("incids", "incid", "incidentid", "incident_id")
_INCIDENT_ALERT_KEYS = ("alertids", "alertid", "alert_ids")

_SEVERITY_TO_PRIORITY = {
    "critical": "urgent",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

# Concurrent attachment lookups per skill invocation. Attachments are
# plain incidentmgmt GETs (no logview search slots), so the bound exists
# to keep FAZ comfortable, not to protect the slot pool.
_ATTACH_CONCURRENCY = 5

# Window for the filter-first triage subject lookup. get_alerts filtering
# on alertid is live-verified on 7.6.7 and 8.0.0 over a 30-day window
# (exact match; a missing id returns a clean empty success).
_SUBJECT_LOOKUP_WINDOW = "30-day"


async def _gather_bounded[T](
    coros: list[Coroutine[Any, Any, T]], limit: int = _ATTACH_CONCURRENCY
) -> list[T]:
    """Run coroutines concurrently, at most ``limit`` at a time, in order."""
    semaphore = asyncio.Semaphore(limit)

    async def _bounded(coro: Awaitable[T]) -> T:
        async with semaphore:
            return await coro

    return list(await asyncio.gather(*(_bounded(c) for c in coros)))


_WAVE2_ENRICHMENT_GAP = FeatureGap(
    reason="Indicator enrichment requires the SOAR reader planned for Wave 2."
)


class SkillExecutionError(Exception):
    """A skill's subject data could not be retrieved."""


async def _call(tool_fn: Any, **kwargs: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Await a tool function, normalizing failure to ``(None, reason)``.

    Tool functions return the standard response envelope; a dict with
    ``status != "success"`` counts as failure. Exceptions are captured,
    never propagated — the caller decides whether the miss is fatal
    (subject) or a degradation warning (context).
    """
    name = getattr(tool_fn, "__name__", str(tool_fn))
    try:
        result = await tool_fn(**kwargs)
    except Exception as exc:
        logger.warning("skill sub-call %s raised: %s", name, exc)
        # Reasons surface to the caller via result.warnings on the success
        # path (which the dispatcher does not route through error_response),
        # so scrub secrets/tokens/session ids at the source. See issue #68 M4.
        return None, redact(f"{name}: {exc}")
    if isinstance(result, dict) and result.get("status") != "success":
        return None, redact(f"{name}: {result.get('message') or result.get('error') or 'failed'}")
    return result, None


def _ids_of(obj: dict[str, Any], keys: tuple[str, ...]) -> set[str]:
    """Collect identifier values from the first present candidate key."""
    for key in keys:
        if key not in obj:
            continue
        value = obj[key]
        if value is None:
            return set()
        if isinstance(value, list):
            return {str(v) for v in value}
        if isinstance(value, str) and "," in value:
            return {part.strip() for part in value.split(",") if part.strip()}
        return {str(value)}
    return set()


def _link_key(obj: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """Name of the first linkage key present on the object."""
    return next((k for k in keys if k in obj), None)


def _records(payload: Any) -> list[dict[str, Any]]:
    """Record list from a FAZ payload of varying nesting.

    Tolerates a bare list of records or a dict wrapping a ``data`` list
    (alertlogs comes back as the latter).
    """
    if isinstance(payload, dict):
        payload = payload.get("data")
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def _first_record(payload: Any) -> dict[str, Any] | None:
    """First record from a FAZ payload of varying nesting.

    Tolerates the shapes seen live: a bare record dict, a list of
    records, or a dict wrapping a ``data`` list (extra-details).
    """
    if isinstance(payload, dict):
        inner = payload.get("data")
        if isinstance(inner, list):
            return inner[0] if inner and isinstance(inner[0], dict) else None
        return payload
    if isinstance(payload, list):
        return payload[0] if payload and isinstance(payload[0], dict) else None
    return None


async def _fetch_attached_alerts(
    adom: str | None, incid: str, limit: int = 200, warnings: list[str] | None = None
) -> tuple[list[dict[str, Any]], str | None]:
    """Alerts attached to an incident, via incident attachments.

    FAZ associates alerts with incidents through incident *attachments*
    (``attachtype="alertevent"``) — not through fields on either object
    (verified live; alert and incident records carry no linkage keys).
    Each attachment's ``attachsrcid`` is the alertid and ``data`` holds a
    verbatim alert-event snapshot.

    This is a thin read-only ``client.get()`` wrapper as sanctioned by
    RFC #44's constraints; it lives here pending the RFC's open question
    on reader placement. Returns ``(alerts, None)`` or ``([], reason)``.
    When ``warnings`` is given, a full attachment page appends a truncation
    warning to it.
    """
    from fortianalyzer_mcp.api.client import API_VERSION
    from fortianalyzer_mcp.server import get_faz_client
    from fortianalyzer_mcp.utils.validation import get_default_adom, validate_adom

    try:
        adom_validated = validate_adom(adom or get_default_adom())
        client = get_faz_client()
        if client is None:
            return [], "FortiAnalyzer client not initialized"
        res = await client.get(
            f"/incidentmgmt/adom/{adom_validated}/attachments",
            apiver=API_VERSION,
            incid=incid,
            attachtype="alertevent",
            limit=limit,
        )
    except Exception as exc:
        return [], redact(f"attachments lookup: {exc}")

    records = _records(res)
    alerts: list[dict[str, Any]] = []
    for rec in records:
        if rec.get("attachtype") != "alertevent":
            continue
        snapshot: dict[str, Any] = {}
        raw = rec.get("data")
        if isinstance(raw, str) and raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    snapshot = parsed
            except ValueError:
                pass
        elif isinstance(raw, dict):
            snapshot = raw
        snapshot.setdefault("alertid", rec.get("attachsrcid"))
        alerts.append(snapshot)
    if warnings is not None and len(records) >= limit:
        # A full page means FAZ may hold more attachments than we asked for;
        # say so rather than presenting a truncated set as complete.
        warnings.append(
            f"incident {incid}: attachment page filled at limit {limit}; "
            "correlated alerts may be incomplete"
        )
    return alerts, None


# --------------------------------------------------------------------- #
# incidents                                                             #
# --------------------------------------------------------------------- #


async def run_incidents(params: IncidentsParams) -> IncidentsResult:
    """Incidents in the window, each with best-effort correlated alerts."""
    from fortianalyzer_mcp.tools.event_tools import get_alerts
    from fortianalyzer_mcp.tools.incident_tools import get_incidents

    warnings: list[str] = []

    incidents_res, err = await _call(
        get_incidents,
        adom=params.adom,
        time_range=params.time_range,
        filter=params.filter,
        limit=params.limit,
    )
    if incidents_res is None:
        raise SkillExecutionError(f"could not retrieve incidents ({err})")
    incidents: list[dict[str, Any]] = incidents_res.get("data") or []

    # Authoritative source: incident attachments (attachtype=alertevent),
    # fetched with a bounded concurrent fan-out (one GET per incident).
    correlated_by_index: dict[int, list[dict[str, Any]]] = {}
    basis_by_index: dict[int, str] = {}
    attachments_failed: str | None = None
    if params.include_alerts and incidents:
        attach_results = await _gather_bounded(
            [
                _fetch_attached_alerts(params.adom, str(incident.get("incid")), warnings=warnings)
                for incident in incidents
                if incident.get("incid")
            ]
        )
        indices_with_incid = [i for i, inc in enumerate(incidents) if inc.get("incid")]
        for index, (attached, attach_err) in zip(indices_with_incid, attach_results, strict=True):
            if attach_err is not None:
                attachments_failed = attach_err
            elif attached:
                correlated_by_index[index] = attached
                basis_by_index[index] = "incident.attachments.alertevent"

    # The window scan exists only for the linkage-key fallback, and
    # attachments are the authoritative path (live-verified) — so the scan
    # is deferred until an incident actually lacks attachment correlation.
    alerts: list[dict[str, Any]] = []
    scan_ran = False
    needs_fallback = params.include_alerts and any(
        i not in correlated_by_index for i in range(len(incidents))
    )
    if needs_fallback:
        alerts_res, err = await _call(
            get_alerts,
            adom=params.adom,
            time_range=params.time_range,
            limit=params.alerts_scan_limit,
        )
        if alerts_res is None:
            warnings.append(f"alert correlation skipped: {err}")
        else:
            alerts = alerts_res.get("data") or []
            scan_ran = True

    records: list[IncidentRecord] = []
    for index, incident in enumerate(incidents):
        correlated = correlated_by_index.get(index, [])
        basis = basis_by_index.get(index)

        # Fallback: candidate linkage keys against the window scan.
        if not correlated:
            incident_ids = _ids_of(incident, ("incid",))
            declared_alert_ids = _ids_of(incident, _INCIDENT_ALERT_KEYS)
            for alert in alerts:
                alert_id = next(iter(_ids_of(alert, ("alertid",))), None)
                if declared_alert_ids and alert_id in declared_alert_ids:
                    correlated.append(alert)
                    basis = f"incident.{_link_key(incident, _INCIDENT_ALERT_KEYS)}"
                elif incident_ids & _ids_of(alert, _ALERT_INCIDENT_KEYS):
                    correlated.append(alert)
                    basis = f"alert.{_link_key(alert, _ALERT_INCIDENT_KEYS)}"
        records.append(
            IncidentRecord(incident=incident, correlated_alerts=correlated, correlation_basis=basis)
        )

    if attachments_failed is not None:
        warnings.append(
            f"attachment-based correlation unavailable ({attachments_failed}); "
            "fell back to linkage-key matching"
        )
    if params.include_alerts and incidents and not any(r.correlated_alerts for r in records):
        warnings.append(
            "no attached or linkage-matched alerts found for these incidents; "
            "correlated_alerts are empty"
        )

    return IncidentsResult(
        incidents=records,
        incident_count=len(records),
        alerts_scanned=len(alerts) if scan_ran else 0,
        time_range=params.time_range,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# reports                                                               #
# --------------------------------------------------------------------- #


async def run_reports(params: ReportsParams) -> ReportsResult:
    """List generated reports, or fetch one by task ID."""
    from fortianalyzer_mcp.tools.report_tools import get_report_data, get_report_history

    if params.action == "list":
        history_res, err = await _call(
            get_report_history,
            adom=params.adom,
            time_range=params.time_range,
            title=params.title,
        )
        if history_res is None:
            raise SkillExecutionError(f"could not retrieve report history ({err})")
        reports = history_res.get("data") or []
        warnings: list[str] = []
        if len(reports) > params.limit:
            warnings.append(f"{len(reports)} history entries; returning the first {params.limit}")
            reports = reports[: params.limit]
        return ReportsResult(
            action="list", reports=reports, report_count=len(reports), warnings=warnings
        )

    fetched_res, err = await _call(
        get_report_data,
        tid=params.tid,
        adom=params.adom,
        output_format=params.output_format,
    )
    if fetched_res is None:
        raise SkillExecutionError(f"could not fetch report {params.tid} ({err})")
    return ReportsResult(action="fetch", fetched=fetched_res)


# --------------------------------------------------------------------- #
# log_search                                                            #
# --------------------------------------------------------------------- #


async def run_log_search(params: LogSearchParams) -> LogSearchResult:
    """Filter-based log search returning verbatim rows.

    Exactly one logview search; concurrency is bounded by the global
    logsearch semaphore inside ``query_logs``.
    """
    from fortianalyzer_mcp.tools.log_tools import query_logs

    search_res, err = await _call(
        query_logs,
        adom=params.adom,
        logtype=params.logtype,
        device=params.device,
        time_range=params.time_range,
        filter=params.filter,
        limit=params.limit,
        timeout=params.timeout,
    )
    if search_res is None:
        raise SkillExecutionError(f"log search failed ({err})")

    return LogSearchResult(
        tid=search_res.get("tid"),
        logtype=params.logtype,
        rows=search_res.get("logs") or [],
        row_count=len(search_res.get("logs") or []),
        total=search_res.get("total"),
        total_is_known=bool(search_res.get("total_is_known", search_res.get("total") is not None)),
        has_more=bool(search_res.get("has_more")),
        warnings=list(search_res.get("warnings") or []),
    )


# --------------------------------------------------------------------- #
# triage                                                                #
# --------------------------------------------------------------------- #


def _assess(subject: dict[str, Any], subject_type: str) -> TriageAssessment:
    """Derive the deterministic assessment from fields present on the subject."""
    severity_raw = subject.get("severity")
    severity = str(severity_raw).lower() if severity_raw is not None else None
    priority = _SEVERITY_TO_PRIORITY.get(severity or "", "informational")

    basis = [
        f"{subject_type} severity is {severity!r} -> priority {priority!r}"
        if severity
        else f"{subject_type} has no severity field -> priority 'informational'"
    ]

    acknowledged: bool | None = None
    if "acknowledged" in subject:
        acknowledged = bool(subject["acknowledged"])
        basis.append(f"alert acknowledged: {acknowledged}")
    elif "ackflag" in subject:
        # Live FAZ alerts carry "ackflag" instead; its value semantics are
        # not documented, so it is reported verbatim, not interpreted.
        basis.append(f"alert ackflag: {subject['ackflag']!r}")
    if subject.get("status"):
        basis.append(f"{subject_type} status: {subject['status']!r}")

    return TriageAssessment(
        priority=priority,  # type: ignore[arg-type]
        severity=severity,
        acknowledged=acknowledged,
        basis=basis,
    )


async def run_triage(params: TriageParams) -> TriageResult:
    """Evidence bundle + deterministic assessment for one alert or incident."""
    from fortianalyzer_mcp.tools.event_tools import (
        get_alert_details,
        get_alert_incident_stats,
        get_alert_logs,
        get_alerts,
    )
    from fortianalyzer_mcp.tools.incident_tools import get_incident, get_incidents
    from fortianalyzer_mcp.utils.validation import sanitize_filter_value

    warnings: list[str] = []
    triggering_logs: list[dict[str, Any]] = []
    related: list[dict[str, Any]] = []

    if params.alert_id:
        subject_type = "alert"

        # Subject = the full alert row (it carries severity/status/ack).
        # Filter-first: get_alerts filtering on alertid over a wide window
        # is live-verified on both supported versions and avoids the
        # degraded no-severity path for alerts older than the context
        # window. The window scan stays as the fallback. extra-details is
        # entity enrichment only — live FAZ returns just {alertid, devs,
        # epids, euids} there.
        subject: dict[str, Any] = {}
        # alert_id is attacker-influenceable free text; sanitize it before it
        # enters the filter expression (self-quotes and escapes any quote /
        # operator / backslash so it cannot rewrite the clause). Replaces the
        # earlier no-double-quote blocklist. See issue #68 L5.
        safe_alert_id = sanitize_filter_value(params.alert_id, "alert_id")
        lookup_res, err = await _call(
            get_alerts,
            adom=params.adom,
            time_range=_SUBJECT_LOOKUP_WINDOW,
            filter=f"alertid=={safe_alert_id}",
            limit=5,
        )
        if lookup_res is None:
            warnings.append(f"alert filter lookup unavailable: {err}")
        else:
            subject = next(
                (
                    a
                    for a in lookup_res.get("data") or []
                    if str(a.get("alertid")) == str(params.alert_id)
                ),
                {},
            )
        if not subject:
            alerts_res, err = await _call(
                get_alerts, adom=params.adom, time_range=params.context_time_range, limit=500
            )
            if alerts_res is None:
                warnings.append(f"alert window scan unavailable: {err}")
            else:
                subject = next(
                    (
                        a
                        for a in alerts_res.get("data") or []
                        if str(a.get("alertid")) == str(params.alert_id)
                    ),
                    {},
                )

        details_res, err = await _call(
            get_alert_details, alert_ids=[params.alert_id], adom=params.adom
        )
        subject_details: dict[str, Any] | None = None
        if details_res is None:
            warnings.append(f"alert entity details unavailable: {err}")
        else:
            subject_details = _first_record(details_res.get("data"))

        if not subject:
            if subject_details is None:
                raise SkillExecutionError(
                    f"alert {params.alert_id} not found in the {_SUBJECT_LOOKUP_WINDOW} "
                    f"filter lookup or the {params.context_time_range} window, and the "
                    f"details lookup failed ({err})"
                )
            subject = subject_details
            warnings.append(
                f"alert {params.alert_id} not in the {_SUBJECT_LOOKUP_WINDOW} filter lookup "
                f"or the {params.context_time_range} window; subject is the entity-details "
                "record (no severity -> priority 'informational')."
            )

        logs_res, err = await _call(get_alert_logs, alert_ids=[params.alert_id], adom=params.adom)
        if logs_res is None:
            warnings.append(f"triggering logs unavailable: {err}")
        else:
            triggering_logs = _records(logs_res.get("data"))

        # Related incidents: best-effort via linkage ids on the alert.
        linked_incidents = _ids_of(subject, _ALERT_INCIDENT_KEYS)
        if linked_incidents:
            for incident_id in sorted(linked_incidents):
                inc_res, err = await _call(get_incident, incident_id=incident_id, adom=params.adom)
                if inc_res is None:
                    warnings.append(f"linked incident {incident_id} unavailable: {err}")
                else:
                    data = inc_res.get("data")
                    related.extend(data if isinstance(data, list) else [data] if data else [])
        else:
            # No linkage fields on live alerts (verified) — resolve the
            # authoritative relation by checking each context incident's
            # attachments for this alertid. A pure reverse attachment query
            # (attachsrcid without incid) is rejected by FAZ, and with incid
            # present the attachsrcid param is ignored (both live-verified
            # on 7.6.7), so membership is checked per candidate incident.
            inc_res, err = await _call(
                get_incidents, adom=params.adom, time_range=params.context_time_range, limit=50
            )
            if inc_res is None:
                warnings.append(f"incident context unavailable: {err}")
            else:
                candidates = [
                    c for c in inc_res.get("data") or [] if isinstance(c, dict) and c.get("incid")
                ]
                if candidates:
                    checks = await _gather_bounded(
                        [_fetch_attached_alerts(params.adom, str(c["incid"])) for c in candidates]
                    )
                    failed = sum(1 for _, check_err in checks if check_err is not None)
                    if failed == len(candidates):
                        # Attachments wholly unavailable: keep the old
                        # (noisy but honest) fallback.
                        related = candidates
                        warnings.append(
                            "alert carries no incident linkage field and attachment "
                            "lookups failed; 'related' lists all incidents in the "
                            "context window instead"
                        )
                    else:
                        related = [
                            candidate
                            for candidate, (attached, check_err) in zip(
                                candidates, checks, strict=True
                            )
                            if check_err is None
                            and any(str(a.get("alertid")) == str(params.alert_id) for a in attached)
                        ]
                        if failed:
                            warnings.append(
                                f"attachment check failed for {failed} of "
                                f"{len(candidates)} context incidents; membership "
                                "for those is unknown"
                            )
                        if not related:
                            warnings.append(
                                f"alert {params.alert_id} is not attached to any of the "
                                f"{len(candidates)} incidents in the context window"
                            )
    else:
        subject_type = "incident"
        subject_details = None
        inc_res, err = await _call(get_incident, incident_id=params.incident_id, adom=params.adom)
        if inc_res is None:
            raise SkillExecutionError(f"could not retrieve incident {params.incident_id} ({err})")
        subject = _first_record(inc_res.get("data")) or {}

        incid = str(subject.get("incid") or params.incident_id)
        related, attach_err = await _fetch_attached_alerts(params.adom, incid, warnings=warnings)
        if attach_err is not None or not related:
            if attach_err is not None:
                warnings.append(
                    f"attachment-based correlation unavailable ({attach_err}); "
                    "fell back to linkage-key matching"
                )
            alerts_res, err = await _call(
                get_alerts, adom=params.adom, time_range=params.context_time_range, limit=200
            )
            if alerts_res is None:
                warnings.append(f"alert context unavailable: {err}")
            else:
                incident_ids = _ids_of(subject, ("incid",)) or {incid}
                declared = _ids_of(subject, _INCIDENT_ALERT_KEYS)
                for alert in alerts_res.get("data") or []:
                    alert_id = next(iter(_ids_of(alert, ("alertid",))), None)
                    if (declared and alert_id in declared) or (
                        incident_ids & _ids_of(alert, _ALERT_INCIDENT_KEYS)
                    ):
                        related.append(alert)

    stats_res, err = await _call(
        get_alert_incident_stats, adom=params.adom, time_range=params.context_time_range
    )
    context_stats: dict[str, Any] | None = None
    if stats_res is None:
        warnings.append(f"context stats unavailable: {err}")
    else:
        context_stats = (
            stats_res.get("data")
            if isinstance(stats_res.get("data"), dict)
            else {k: v for k, v in stats_res.items() if k not in ("status",)}
        )

    return TriageResult(
        subject_type=subject_type,  # type: ignore[arg-type]
        subject=subject,
        subject_details=subject_details,
        triggering_logs=triggering_logs,
        related=related,
        context_stats=context_stats,
        assessment=_assess(subject, subject_type),
        enrichment=_WAVE2_ENRICHMENT_GAP,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# incident_summary                                                  #
# --------------------------------------------------------------------- #


def _sort_key(timestamp: int | str) -> tuple[int, float, str]:
    """Total order over the timestamp shapes FAZ actually returns.

    Live data mixes epoch ints, epoch-digit strings ("1704067300", from the
    attachment alert snapshots) and FAZ datetime strings ("2026-07-08
    10:22:41", from an incident's createtime/lastupdate). Comparing those
    lexicographically puts every epoch string before every datetime string
    regardless of when the events happened, so both forms are normalized to
    epoch seconds first. Datetimes are read as FAZ-local wall-clock, which
    is the same clock the epoch values come from. Anything unparseable sorts
    last, in stable string order, rather than corrupting the ordering of the
    entries that are parseable.
    """
    if isinstance(timestamp, int):
        return (0, float(timestamp), "")
    text = timestamp.strip()
    if text.isdigit():
        return (0, float(text), "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return (0, datetime.strptime(text, fmt).timestamp(), "")
        except ValueError:
            continue
    return (1, 0.0, text)


def _timeline(incident: dict[str, Any], evidence: list[AlertEvidence]) -> list[TimelineEntry]:
    """Chronological entries from whatever timestamp fields are present."""
    entries: list[TimelineEntry] = []
    ts = incident.get("timestamp") or incident.get("createtime") or incident.get("lastupdate")
    if ts is not None:
        entries.append(
            TimelineEntry(
                timestamp=ts,
                source="incident",
                description=f"incident {incident.get('incid', '?')}: "
                f"{incident.get('name') or incident.get('description') or 'created'}",
            )
        )
    for item in evidence:
        alert_ts = (
            item.alert.get("timestamp")
            or item.alert.get("alerttime")
            or item.alert.get("createtime")
        )
        if alert_ts is None:
            continue
        entries.append(
            TimelineEntry(
                timestamp=alert_ts,
                source="alert",
                description=f"alert {item.alert.get('alertid', '?')}: "
                f"{item.alert.get('name') or item.alert.get('description') or 'raised'}",
            )
        )
    return sorted(entries, key=lambda e: _sort_key(e.timestamp))


async def run_incident_summary(params: IncidentSummaryParams) -> IncidentSummary:
    """Structured investigation summary for one incident."""
    from fortianalyzer_mcp.tools.event_tools import get_alert_logs, get_alerts
    from fortianalyzer_mcp.tools.fortiview_tools import get_top_threats
    from fortianalyzer_mcp.tools.incident_tools import get_incident

    warnings: list[str] = []

    inc_res, err = await _call(get_incident, incident_id=params.incident_id, adom=params.adom)
    if inc_res is None:
        raise SkillExecutionError(f"could not retrieve incident {params.incident_id} ({err})")
    incident = inc_res.get("data") or {}
    if isinstance(incident, list):
        incident = incident[0] if incident else {}

    # Related alerts: incident attachments first, linkage keys as fallback.
    evidence: list[AlertEvidence] = []
    incid = str(incident.get("incid") or params.incident_id)
    linked, attach_err = await _fetch_attached_alerts(params.adom, incid, warnings=warnings)
    if attach_err is not None or not linked:
        if attach_err is not None:
            warnings.append(
                f"attachment-based correlation unavailable ({attach_err}); "
                "fell back to linkage-key matching"
            )
        alerts_res, err = await _call(
            get_alerts, adom=params.adom, time_range=params.time_range, limit=500
        )
        if alerts_res is None:
            warnings.append(f"related alerts unavailable: {err}")
        else:
            incident_ids = _ids_of(incident, ("incid",)) or {incid}
            declared = _ids_of(incident, _INCIDENT_ALERT_KEYS)
            for alert in alerts_res.get("data") or []:
                alert_id = next(iter(_ids_of(alert, ("alertid",))), None)
                if (declared and alert_id in declared) or (
                    incident_ids & _ids_of(alert, _ALERT_INCIDENT_KEYS)
                ):
                    linked.append(alert)
    if linked:
        if len(linked) > params.max_alerts:
            warnings.append(
                f"{len(linked)} linked alerts found; only the first "
                f"{params.max_alerts} include evidence logs"
            )
            linked = linked[: params.max_alerts]

        for alert in linked:
            logs: list[dict[str, Any]] = []
            alert_id = next(iter(_ids_of(alert, ("alertid",))), None)
            if alert_id:
                logs_res, err = await _call(
                    get_alert_logs,
                    alert_ids=[alert_id],
                    adom=params.adom,
                    limit=params.max_logs_per_alert,
                )
                if logs_res is None:
                    warnings.append(f"logs for alert {alert_id} unavailable: {err}")
                else:
                    logs = _records(logs_res.get("data"))[: params.max_logs_per_alert]
            evidence.append(AlertEvidence(alert=alert, logs=logs))
    else:
        warnings.append(
            "no attached or linkage-matched alerts found for this incident; "
            "the alerts section is empty"
        )

    # Threat landscape (context; degrades to a gap marker).
    threat_landscape: list[dict[str, Any]] | FeatureGap
    if params.include_top_threats:
        threats_res, err = await _call(
            get_top_threats, adom=params.adom, time_range=params.time_range, limit=10
        )
        if threats_res is None:
            threat_landscape = FeatureGap(reason=f"top threats unavailable: {err}")
        else:
            threat_landscape = threats_res.get("data") or []
    else:
        threat_landscape = FeatureGap(reason="disabled by include_top_threats=false")

    return IncidentSummary(
        incident=incident,
        alerts=evidence,
        threat_landscape=threat_landscape,
        timeline=_timeline(incident, evidence),
        counts={
            "alerts": len(evidence),
            "evidence_logs": sum(len(e.logs) for e in evidence),
        },
        time_range=params.time_range,
        warnings=warnings,
    )
