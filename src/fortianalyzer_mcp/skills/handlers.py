"""Wave-1 skill handlers: orchestrations over existing read-only tools.

Design constraints (RFC #44):
- Compose existing tool functions only — no new client methods, no writes.
- Graceful degradation: a failed *context* call becomes a warning and a
  partial result; only a failed *subject* call fails the skill.
- Slot-safety: the skills that consume a logview search slot each run
  exactly one search, bounded by the global logsearch semaphore in
  ``log_tools`` — ``log_search``, and (when their activity/DLP section is
  enabled) ``identity_profile``, ``app_usage`` and ``risk_assessment``.
  Every other read (eventmgmt/incidentmgmt/fortiview/ueba/soar) is a
  plain GET and uses no search slot.

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
    AlertRuleHandler,
    AlertRulesParams,
    AlertRulesResult,
    AppUsageParams,
    AppUsageResult,
    AssetLookupParams,
    AssetLookupResult,
    AssetRecord,
    EntityBehavior,
    EstateContext,
    FeatureGap,
    HuntParams,
    HuntResult,
    HuntSweep,
    IdentityLookupParams,
    IdentityLookupResult,
    IdentityProfileParams,
    IdentityProfileResult,
    IncidentRecord,
    IncidentsParams,
    IncidentsResult,
    IncidentSummary,
    IncidentSummaryParams,
    IndicatorEnrichmentRecord,
    IndicatorSpec,
    InvestigateParams,
    Investigation,
    LogSearchParams,
    LogSearchResult,
    NetworkContextParams,
    NetworkContextResult,
    ReportsParams,
    ReportsResult,
    RiskAssessmentParams,
    RiskAssessmentResult,
    RiskDimension,
    SweepMatch,
    ThreatIntelParams,
    ThreatIntelResult,
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


# --------------------------------------------------------------------- #
# asset_lookup (Wave 2)                                                 #
# --------------------------------------------------------------------- #


def _match_endpoint(endpoint: dict[str, Any], hostname: str | None, ip: str | None) -> bool:
    """Client-side endpoint filter over the live UEBA field names."""
    if hostname is not None and hostname.lower() not in str(endpoint.get("epname") or "").lower():
        return False
    if ip is not None and str(endpoint.get("epip") or "") != ip:
        return False
    return True


def _flatten_vuln_records(
    payload: Any,
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    """Group the vulnerability reader's records by endpoint id.

    Tolerates the shapes the UEBA spec allows: records carrying a
    ``vuln-group`` list (each group wrapping a ``vuln`` list), a flat
    ``vuln`` list, or bare CVE rows. Rows whose record carries no ``epid``
    land in the orphan list instead of being guessed onto an endpoint.
    """
    by_endpoint: dict[str, list[dict[str, Any]]] = {}
    orphans: list[dict[str, Any]] = []
    for record in _records(payload):
        epid = record.get("epid")
        rows: list[dict[str, Any]] = []
        groups = record.get("vuln-group")
        if isinstance(groups, list):
            for group in groups:
                if not isinstance(group, dict):
                    continue
                vulns = group.get("vuln")
                if isinstance(vulns, list):
                    rows.extend(v for v in vulns if isinstance(v, dict))
                else:
                    rows.append(group)
        elif isinstance(record.get("vuln"), list):
            rows.extend(v for v in record["vuln"] if isinstance(v, dict))
        else:
            rows.append(record)
        if epid is None:
            orphans.extend(rows)
        else:
            by_endpoint.setdefault(str(epid), []).extend(rows)
    return by_endpoint, orphans


def _severity_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Vulnerability count per lowercased severity label."""
    counts: dict[str, int] = {}
    for row in rows:
        severity = str(row.get("severity") or "unknown").lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


async def run_asset_lookup(params: AssetLookupParams) -> AssetLookupResult:
    """Endpoint (asset) profiles with attributed CVE context.

    One UEBA endpoints read plus, when requested, one vulnerability read
    scoped to the matched endpoint ids. Both are plain GETs — no logview
    search slots. The endpoints read is the subject; a failed
    vulnerability read degrades to a warning.
    """
    from fortianalyzer_mcp.tools.ueba_tools import get_endpoint_vulnerabilities, get_endpoints

    endpoints_res, err = await _call(
        get_endpoints,
        adom=params.adom,
        epids=params.epids,
        detail_level=params.detail_level,
        time_range=params.time_range,
    )
    if endpoints_res is None:
        raise SkillExecutionError(f"could not retrieve UEBA endpoints ({err})")

    warnings: list[str] = []
    all_endpoints = _records(endpoints_res.get("data"))
    if params.ip is not None and not any("epip" in endpoint for endpoint in all_endpoints):
        # The appliance only returns epip at "simple" detail (live-verified:
        # basic/standard omit it), so an ip filter at any other level would
        # silently match nothing. Name it rather than return a false empty.
        warnings.append(
            "ip filter set but no endpoint carries 'epip' at this detail_level; "
            "use detail_level='simple' to filter by IP"
        )
    matched = [
        endpoint
        for endpoint in all_endpoints
        if _match_endpoint(endpoint, params.hostname, params.ip)
    ]
    matched_total = len(matched)
    if matched_total > params.limit:
        warnings.append(f"{matched_total} endpoints matched; returning the first {params.limit}")
        matched = matched[: params.limit]

    vulns_by_endpoint: dict[str, list[dict[str, Any]]] = {}
    orphans: list[dict[str, Any]] = []
    if params.include_vulnerabilities and matched:
        known_epids: list[int] = []
        for endpoint in matched:
            epid = endpoint.get("epid")
            if isinstance(epid, int):
                known_epids.append(epid)
            elif isinstance(epid, str) and epid.isdigit():
                known_epids.append(int(epid))
        if not known_epids:
            warnings.append("no matched endpoint carries an 'epid'; vulnerability lookup skipped")
        else:
            vuln_res, err = await _call(
                get_endpoint_vulnerabilities,
                adom=params.adom,
                epids=known_epids,
                detectby=params.detectby,
            )
            if vuln_res is None:
                warnings.append(f"vulnerability context unavailable ({err})")
            else:
                vulns_by_endpoint, orphans = _flatten_vuln_records(vuln_res.get("data"))
                if orphans:
                    warnings.append(
                        f"{len(orphans)} vulnerability records had no attributable endpoint id"
                    )

    records = []
    for endpoint in matched:
        rows = vulns_by_endpoint.get(str(endpoint.get("epid")), [])
        records.append(
            AssetRecord(
                endpoint=endpoint,
                vulnerabilities=rows,
                vulnerability_counts=_severity_counts(rows),
            )
        )
    return AssetLookupResult(
        endpoints=records,
        endpoint_count=len(records),
        matched_total=matched_total,
        unattributed_vulnerabilities=orphans,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# identity_lookup (Wave 2)                                              #
# --------------------------------------------------------------------- #


async def run_identity_lookup(params: IdentityLookupParams) -> IdentityLookupResult:
    """End-user identity records, verbatim from the UEBA directory.

    Exactly one UEBA end-users read (a plain GET); the username filter is
    applied client-side over the live ``euname`` field.
    """
    from fortianalyzer_mcp.tools.ueba_tools import get_endusers

    users_res, err = await _call(
        get_endusers,
        adom=params.adom,
        euids=params.euids,
        detail_level=params.detail_level,
    )
    if users_res is None:
        raise SkillExecutionError(f"could not retrieve UEBA end-users ({err})")

    warnings: list[str] = []
    users = _records(users_res.get("data"))
    if params.username is not None:
        needle = params.username.lower()
        users = [user for user in users if needle in str(user.get("euname") or "").lower()]
    matched_total = len(users)
    if matched_total > params.limit:
        warnings.append(f"{matched_total} users matched; returning the first {params.limit}")
        users = users[: params.limit]

    return IdentityLookupResult(
        users=users,
        user_count=len(users),
        matched_total=matched_total,
        detail_level=params.detail_level,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# alert_rules (Wave 2)                                                  #
# --------------------------------------------------------------------- #


async def run_alert_rules(params: AlertRulesParams) -> AlertRulesResult:
    """The appliance's detection-rule catalogue (alert handlers).

    One eventmgmt config read per requested handler class (plain GETs,
    batched by the reader). Handlers flatten into records labelled with
    their class so consumers never have to know the two-endpoint split.
    """
    from fortianalyzer_mcp.tools.event_tools import get_alert_handlers

    handlers_res, err = await _call(
        get_alert_handlers,
        adom=params.adom,
        handler_type=params.handler_type,
    )
    if handlers_res is None:
        raise SkillExecutionError(f"could not retrieve alert handlers ({err})")

    warnings: list[str] = []
    data = handlers_res.get("data")
    flattened: list[AlertRuleHandler] = []
    for handler_class in ("basic", "correlation"):
        section = data.get(handler_class) if isinstance(data, dict) else None
        if section is None:
            continue
        section_records = _records(section)
        if not section_records and section:
            warnings.append(f"{handler_class} handler payload had an unrecognized shape")
            continue
        flattened.extend(
            AlertRuleHandler(handler_class=handler_class, handler=handler)
            for handler in section_records
        )

    if params.name is not None:
        needle = params.name.lower()
        flattened = [
            entry for entry in flattened if needle in str(entry.handler.get("name") or "").lower()
        ]
    matched_total = len(flattened)
    if matched_total > params.limit:
        warnings.append(f"{matched_total} handlers matched; returning the first {params.limit}")
        flattened = flattened[: params.limit]

    rule_count = sum(
        len(entry.handler["rule"])
        for entry in flattened
        if isinstance(entry.handler.get("rule"), list)
    )
    return AlertRulesResult(
        handlers=flattened,
        handler_count=len(flattened),
        matched_total=matched_total,
        rule_count=rule_count,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# Wave-2 enrichment skills — shared constants + helpers                 #
# --------------------------------------------------------------------- #

# SOAR indicator types the enrichment reader accepts, keyed lowercase so
# linked-indicator rows normalize regardless of the appliance's casing.
_INDICATOR_TYPE_CANONICAL = {"ip": "IP", "url": "URL", "domain": "Domain"}

# Event-log clause for identity_profile's recent-activity search:
# authentication failures plus VPN activity. Follows the FortiGate
# event-log schema (action/subtype); the exact field values vary by build
# and this clause is the single place to adjust once live-verified.
_IDENTITY_ACTIVITY_CLAUSE = "(action==failure or subtype==vpn)"

# risk_assessment weights and per-severity points (one-line adjustable).
# Composite = round(_W_VULN*vuln + _W_THREAT*threat + _W_AUTH*auth).
_W_VULN = 0.40
_W_THREAT = 0.35
_W_AUTH = 0.25
_VULN_POINTS = {"critical": 25, "high": 10, "medium": 3, "low": 1}
_THREAT_POINTS = {"critical": 25, "high": 10, "medium": 3}
_AUTH_POINTS_PER_FAILURE = 5
# Candidate end-user fields that may carry associated endpoint ids (the
# UEBA end-user record's endpoint linkage is not pinned down across
# builds; misses degrade the vulnerability dimension with a warning).
_ENDUSER_EPID_KEYS = ("epid", "epids", "eplist")


def _endpoint_belongs_to(endpoint: dict[str, Any], euid: Any, euname: Any) -> bool:
    """Whether the endpoint's ``user`` association list names this user.

    The UEBA spec associates users to endpoints on the endpoint side:
    each endpoint record carries a ``user`` list of ``{euid, euname,
    lastseen}`` entries. Match on euid first, with a case-insensitive
    exact euname fallback for entries missing an euid.
    """
    entries = endpoint.get("user")
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if euid is not None and str(entry.get("euid")) == str(euid):
            return True
        if euname and str(entry.get("euname") or "").lower() == str(euname).lower():
            return True
    return False


def _risk_band(score: int) -> str:
    """Band for a composite: 0-24 low, 25-49 medium, 50-74 high, 75-100 critical."""
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _severity_points(counts: dict[str, int], points: dict[str, int]) -> int:
    """min(100, sum of points per severity count) over the scoring severities."""
    return min(100, sum(value * counts.get(severity, 0) for severity, value in points.items()))


# --------------------------------------------------------------------- #
# threat_intel (Wave 2)                                                 #
# --------------------------------------------------------------------- #


def _summarize_enrichment_sources(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize the per-engine verdicts from an extended enrichment record.

    Each reputation source (``FortiGuard-CTS``, ``VirusTotal``, ...) reports
    in its own shape; this flattens them to a uniform ``{source, verdict,
    confidence, link, ...}`` summary a SOC analyst can read at a glance. The
    verbatim per-source payload stays under ``record['enrichment-detail']``.
    Best-effort and defensive — an unrecognized shape is summarized as far
    as possible, never dropped and never raised on. Empty when the record
    carries no per-source detail (i.e. not ``detail_level='extended'``).
    """
    entries: list[dict[str, Any]] = []

    def _collect(node: Any) -> None:
        # A source entry is a dict carrying a ``data`` payload; do not recurse
        # into it (its own ``data`` is the payload, not another source).
        if isinstance(node, dict):
            if isinstance(node.get("data"), dict):
                entries.append(node)
            else:
                for value in node.values():
                    _collect(value)
        elif isinstance(node, list):
            for value in node:
                _collect(value)

    _collect(record.get("enrichment-detail"))

    summaries: list[dict[str, Any]] = []
    for entry in entries:
        data = entry.get("data") or {}
        raw_links = data.get("links")
        links: dict[str, Any] = raw_links if isinstance(raw_links, dict) else {}
        raw_attrs = data.get("attributes")
        attrs: dict[str, Any] | None = raw_attrs if isinstance(raw_attrs, dict) else None
        summary: dict[str, Any]
        if attrs is not None or "virustotal.com" in str(links.get("self", "")):
            # VirusTotal shape: data.attributes + data.links.self.
            summary = {"source": entry.get("source") or "VirusTotal"}
            if attrs:
                # The headline verdict is the engine detection ratio, not the
                # web_category label (which is a taxonomy tag, e.g.
                # "domain_parking", and reads as benign next to a real verdict).
                stats = attrs.get("last_analysis_stats")
                if isinstance(stats, dict):
                    total = sum(v for v in stats.values() if isinstance(v, int))
                    flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                    if total:
                        summary["verdict"] = f"{flagged}/{total} engines flagged"
                    summary["detections"] = stats
                if attrs.get("categories"):
                    summary["categories"] = attrs["categories"]
                if attrs.get("web_category"):
                    summary["web_category"] = attrs["web_category"]
                if attrs.get("total_votes"):
                    summary["votes"] = attrs["total_votes"]
                if "reputation" in attrs:
                    summary["reputation_score"] = attrs["reputation"]
            if links.get("self"):
                summary["link"] = links["self"]
        else:
            # FortiGuard / generic ``data.response[]`` shape.
            summary = {"source": entry.get("source") or "unknown"}
            response = data.get("response")
            first = (
                response[0]
                if isinstance(response, list) and response and isinstance(response[0], dict)
                else {}
            )
            verdict = first.get("wf_cate") or first.get("ioc_cate") or first.get("av_cate")
            if verdict:
                summary["verdict"] = verdict
            if first.get("confidence"):
                summary["confidence"] = first["confidence"]
            if first.get("malware_name"):
                summary["malware"] = first["malware_name"]
            if first.get("reference_url"):
                summary["link"] = first["reference_url"]
        summaries.append(summary)
    return summaries


async def run_threat_intel(params: ThreatIntelParams) -> ThreatIntelResult:
    """Stored SOAR reputation for a set of IP/URL/Domain indicators.

    Subjects are the explicit ``indicators`` list plus, when an
    ``alert_id``/``incident_id`` is given, the indicators linked to it —
    that linked-indicator resolution is the subject call and fails the
    skill. Each unique indicator is then enriched with one read; a failed
    per-indicator read degrades to a warning with the record kept
    unenriched. The FortiView threat landscape is context and degrades to
    a gap marker. All reads are plain GETs — no logview search slots.
    """
    from fortianalyzer_mcp.tools.fortiview_tools import get_top_threats
    from fortianalyzer_mcp.tools.soar_tools import get_indicator_enrichment, get_linked_indicators

    warnings: list[str] = []
    subjects: list[tuple[str, str]] = [(spec.value, spec.type) for spec in params.indicators or []]

    if params.alert_id or params.incident_id:
        subject = (
            f"alert {params.alert_id}" if params.alert_id else f"incident {params.incident_id}"
        )
        linked_res, err = await _call(
            get_linked_indicators,
            adom=params.adom,
            alert_id=params.alert_id,
            incident_id=params.incident_id,
            time_range=params.time_range,
        )
        if linked_res is None:
            raise SkillExecutionError(f"could not resolve indicators linked to {subject} ({err})")
        linked_rows = _records(linked_res.get("data"))
        if not linked_rows:
            warnings.append(f"no indicators linked to {subject}")
        for row in linked_rows:
            value = row.get("value")
            canonical = _INDICATOR_TYPE_CANONICAL.get(str(row.get("type") or "").lower())
            if not value or canonical is None:
                warnings.append(
                    f"linked indicator {row.get('indicator-uuid') or value!r} skipped: "
                    f"type {row.get('type')!r} is not IP/URL/Domain or value is missing"
                )
                continue
            subjects.append((str(value), canonical))

    # De-duplicate preserving order (explicit first, then linked).
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for pair in subjects:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)

    # Per-indicator enrichment: bounded concurrent fan-out of plain GETs.
    enrich_results = await _gather_bounded(
        [
            _call(
                get_indicator_enrichment,
                indicator_value=value,
                indicator_type=indicator_type,
                adom=params.adom,
                detail_level=params.detail_level,
                time_range=params.time_range,
            )
            for value, indicator_type in unique
        ]
    )

    records: list[IndicatorEnrichmentRecord] = []
    for (value, indicator_type), (enrich_res, err) in zip(unique, enrich_results, strict=True):
        if enrich_res is None:
            warnings.append(f"enrichment unavailable for {indicator_type} {value!r}: {err}")
            records.append(IndicatorEnrichmentRecord(value=value, type=indicator_type))
            continue
        rows = _records(enrich_res.get("data"))
        matched: dict[str, Any] | None = next(
            (r for r in rows if str(r.get("value")) == value), None
        )
        if matched is None and rows:
            matched = rows[0]
        if matched is None:
            warnings.append(
                f"no stored enrichment for {indicator_type} {value!r} "
                "(unknown to SOAR or not yet enriched — the reader does not trigger lookups)"
            )
            records.append(IndicatorEnrichmentRecord(value=value, type=indicator_type))
            continue
        records.append(
            IndicatorEnrichmentRecord(
                value=value,
                type=indicator_type,
                reputation=matched.get("enrichment-reputation"),
                confidence=matched.get("enrichment-confidence"),
                status=matched.get("enrichment-status"),
                sources=_summarize_enrichment_sources(matched),  # type: ignore[arg-type]
                record=matched,
            )
        )

    # Threat landscape (context; degrades to a gap marker).
    threat_landscape: list[dict[str, Any]] | FeatureGap
    if params.include_threat_landscape:
        threats_res, err = await _call(
            get_top_threats,
            adom=params.adom,
            time_range=params.time_range or "24-hour",
            limit=10,
        )
        if threats_res is None:
            warnings.append(f"threat landscape unavailable: {err}")
            threat_landscape = FeatureGap(reason=f"top threats unavailable: {err}")
        else:
            threat_landscape = threats_res.get("data") or []
    else:
        threat_landscape = FeatureGap(reason="disabled by include_threat_landscape=false")

    return ThreatIntelResult(
        indicators=records,
        indicator_count=len(records),
        threat_landscape=threat_landscape,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# identity_profile (Wave 2)                                             #
# --------------------------------------------------------------------- #


async def run_identity_profile(params: IdentityProfileParams) -> IdentityProfileResult:
    """Context bundle for one user: identity record, endpoints, activity.

    The UEBA end-users read (plus the euid/euname match) is the subject;
    the endpoint association scan and the activity search are context and
    degrade to warnings / a gap marker. When ``include_activity`` is true
    this skill consumes exactly one logview search slot (bounded by the
    global logsearch semaphore inside ``query_logs``); the UEBA reads are
    plain GETs.
    """
    from fortianalyzer_mcp.tools.log_tools import query_logs
    from fortianalyzer_mcp.tools.ueba_tools import get_endpoints, get_endusers
    from fortianalyzer_mcp.utils.validation import sanitize_filter_value

    warnings: list[str] = []

    users_res, err = await _call(
        get_endusers,
        adom=params.adom,
        euids=[params.euid] if params.euid is not None else None,
        detail_level=params.detail_level,
    )
    if users_res is None:
        raise SkillExecutionError(f"could not retrieve UEBA end-users ({err})")
    users = _records(users_res.get("data"))

    if params.euid is not None:
        matches = [u for u in users if str(u.get("euid")) == str(params.euid)]
        wanted = f"euid {params.euid}"
    else:
        needle = str(params.username).lower()
        matches = [u for u in users if str(u.get("euname") or "").lower() == needle]
        # Name the parameter, never echo the caller's value: with masking on,
        # unmask_args has already resolved a token to the real username, and a
        # no-match error/warning here would hand that cleartext back to the
        # model on the empty-mapping failure path masking cannot re-cover.
        wanted = "the requested username"
    if not matches:
        raise SkillExecutionError(f"no UEBA end-user matches {wanted}")
    user = matches[0]
    if len(matches) > 1:
        warnings.append(
            f"{len(matches)} end-users match {wanted}; profiling euid {user.get('euid')}"
        )

    euid = user.get("euid")
    euname = user.get("euname")

    endpoints: list[dict[str, Any]] = []
    if params.include_endpoints:
        eps_res, err = await _call(get_endpoints, adom=params.adom, detail_level="standard")
        if eps_res is None:
            warnings.append(f"endpoint context unavailable ({err})")
        else:
            all_endpoints = _records(eps_res.get("data"))
            endpoints = [ep for ep in all_endpoints if _endpoint_belongs_to(ep, euid, euname)]
            if all_endpoints and not any(isinstance(ep.get("user"), list) for ep in all_endpoints):
                warnings.append(
                    "no endpoint record carries a 'user' association list at this "
                    "detail level; endpoint matching had nothing to match against"
                )

    activity_rows: list[dict[str, Any]] = []
    recent_activity: list[dict[str, Any]] | FeatureGap
    if not params.include_activity:
        recent_activity = FeatureGap(reason="disabled by include_activity=false")
    elif not euname:
        recent_activity = FeatureGap(
            reason="user record carries no 'euname'; event logs are keyed by username"
        )
    else:
        safe_user = sanitize_filter_value(str(euname), "euname")
        logs_res, err = await _call(
            query_logs,
            adom=params.adom,
            logtype="event",
            time_range=params.time_range,
            filter=f"user=={safe_user} and {_IDENTITY_ACTIVITY_CLAUSE}",
            limit=params.activity_limit,
        )
        if logs_res is None:
            recent_activity = FeatureGap(reason=f"activity search unavailable: {err}")
        else:
            activity_rows = logs_res.get("logs") or []
            recent_activity = activity_rows
            warnings.extend(str(w) for w in logs_res.get("warnings") or [])

    return IdentityProfileResult(
        user=user,
        endpoints=endpoints,
        recent_activity=recent_activity,
        counts={"endpoints": len(endpoints), "activity_rows": len(activity_rows)},
        time_range=params.time_range,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# app_usage (Wave 2)                                                    #
# --------------------------------------------------------------------- #


async def run_app_usage(params: AppUsageParams) -> AppUsageResult:
    """Application / shadow-IT / DLP usage profile for a time window.

    Composes three FortiView top-N reads (no logview search slots) plus,
    when requested, one DLP log search (the only slot-consuming call). A
    context bundle with no single subject: each section degrades
    independently to a warning plus a ``FeatureGap``; the skill fails only
    when every attempted section fails.
    """
    from fortianalyzer_mcp.tools.fortiview_tools import (
        get_top_applications,
        get_top_cloud_applications,
        get_top_websites,
    )
    from fortianalyzer_mcp.tools.log_tools import query_logs

    warnings: list[str] = []
    attempted = 0
    failed = 0

    top_results = await _gather_bounded(
        [
            _call(
                get_top_applications,
                adom=params.adom,
                device=params.device,
                time_range=params.time_range,
                limit=params.top_limit,
            ),
            _call(
                get_top_websites,
                adom=params.adom,
                device=params.device,
                time_range=params.time_range,
                limit=params.top_limit,
            ),
            _call(
                get_top_cloud_applications,
                adom=params.adom,
                device=params.device,
                time_range=params.time_range,
                limit=params.top_limit,
            ),
        ],
        limit=3,
    )

    sections: dict[str, list[dict[str, Any]] | FeatureGap] = {}
    labels = ("top applications", "top websites", "top cloud applications")
    for name, label, (res, err) in zip(
        ("applications", "websites", "cloud_applications"), labels, top_results, strict=True
    ):
        attempted += 1
        if res is None:
            warnings.append(f"{label} unavailable: {err}")
            sections[name] = FeatureGap(reason=f"{label} unavailable: {err}")
            failed += 1
        else:
            sections[name] = res.get("data") or []

    dlp_events: list[dict[str, Any]] | FeatureGap
    if params.include_dlp:
        attempted += 1
        search_res, err = await _call(
            query_logs,
            adom=params.adom,
            logtype="dlp",
            device=params.device,
            time_range=params.time_range,
            limit=params.dlp_limit,
        )
        if search_res is None:
            warnings.append(f"DLP log search unavailable: {err}")
            dlp_events = FeatureGap(reason=f"DLP log search unavailable: {err}")
            failed += 1
        else:
            dlp_events = search_res.get("logs") or []
            warnings.extend(str(w) for w in search_res.get("warnings") or [])
            if search_res.get("has_more"):
                warnings.append(
                    f"more than {params.dlp_limit} DLP events in the window; "
                    "dlp_events is truncated"
                )
    else:
        dlp_events = FeatureGap(reason="disabled by include_dlp=false")

    if attempted and failed == attempted:
        raise SkillExecutionError(
            "every app_usage section failed; nothing to return (" + "; ".join(warnings) + ")"
        )

    def _count(section: list[dict[str, Any]] | FeatureGap) -> int:
        return len(section) if isinstance(section, list) else 0

    return AppUsageResult(
        applications=sections["applications"],
        websites=sections["websites"],
        cloud_applications=sections["cloud_applications"],
        dlp_events=dlp_events,
        counts={
            "applications": _count(sections["applications"]),
            "websites": _count(sections["websites"]),
            "cloud_applications": _count(sections["cloud_applications"]),
            "dlp_events": _count(dlp_events),
        },
        time_range=params.time_range,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# network_context (Wave 2)                                              #
# --------------------------------------------------------------------- #

# FortiView view names for the geo and VPN sections (in VALID_FORTIVIEW_VIEWS).
_GEO_VIEW = "top-countries"
_VPN_VIEW = "site-to-site-ipsec"

# The site-to-site IPsec FortiView buckets by tunnel session, not by traffic
# in the window, so long-lived low-traffic tunnels only surface over a wide
# lookback (live-observed: absent at 24h/7-day, present at 30-90 days on
# FAZ 7.6.7/8.0.0). The VPN section is therefore floored to a wide window
# independent of the short window the traffic/geo sections want.
_VPN_MIN_WINDOW = "90-day"
_WINDOW_RANK = {
    "now": 0,
    "5-min": 1,
    "15-min": 2,
    "30-min": 3,
    "1-hour": 4,
    "2-hour": 5,
    "6-hour": 6,
    "12-hour": 7,
    "24-hour": 8,
    "1-day": 8,
    "2-day": 9,
    "7-day": 10,
    "30-day": 11,
    "90-day": 12,
}


def _vpn_window(time_range: str) -> str:
    """Floor a requested window to ``_VPN_MIN_WINDOW`` for the VPN section.

    A custom ``start|end`` range is the caller's explicit intent and passes
    through unchanged; a preset shorter than the floor is widened, and a
    preset at or above the floor (or an unrecognized token) is kept as-is.
    """
    if "|" in time_range:
        return time_range
    requested = _WINDOW_RANK.get(time_range)
    if requested is None or requested >= _WINDOW_RANK[_VPN_MIN_WINDOW]:
        return time_range
    return _VPN_MIN_WINDOW


async def run_network_context(params: NetworkContextParams) -> NetworkContextResult:
    """Network-layer context bundle: top destinations/sources, geo, VPN.

    Up to four FortiView reads run concurrently (bounded by
    ``_gather_bounded``); FortiView queries do not consume logview search
    slots. Every section is context — best-effort: a failed or unavailable
    section becomes a warning plus a ``FeatureGap``. The skill fails only
    when every attempted section fails. Rows pass through verbatim.
    """
    from fortianalyzer_mcp.tools.fortiview_tools import (
        get_fortiview_data,
        get_top_destinations,
        get_top_sources,
    )

    warnings: list[str] = []
    common: dict[str, Any] = {
        "adom": params.adom,
        "device": params.device,
        "time_range": params.time_range,
        "limit": params.top_limit,
    }

    attempted = ["top_destinations", "top_sources"]
    coros = [
        _call(get_top_destinations, **common),
        _call(get_top_sources, **common),
    ]
    if params.include_geo:
        attempted.append("top_countries")
        coros.append(_call(get_fortiview_data, view_name=_GEO_VIEW, **common))
    vpn_window = params.time_range
    if params.include_vpn:
        attempted.append("vpn_tunnels")
        # The VPN view is session-bucketed; a short window silently returns
        # nothing even for active tunnels, so it runs over a widened window
        # (an explicit vpn_time_range wins).
        vpn_window = params.vpn_time_range or _vpn_window(params.time_range)
        coros.append(
            _call(get_fortiview_data, view_name=_VPN_VIEW, **{**common, "time_range": vpn_window})
        )

    results = await _gather_bounded(coros)

    sections: dict[str, list[dict[str, Any]] | FeatureGap] = {}
    failures: list[str] = []
    for label, (res, err) in zip(attempted, results, strict=True):
        if res is None:
            failures.append(f"{label}: {err}")
            warnings.append(f"{label} unavailable: {err}")
            sections[label] = FeatureGap(reason=f"{label} unavailable: {err}")
        else:
            sections[label] = _records(res.get("data"))

    if len(failures) == len(attempted):
        raise SkillExecutionError(
            "all network-context sections failed (" + "; ".join(failures) + ")"
        )

    if not params.include_geo:
        sections["top_countries"] = FeatureGap(reason="disabled by include_geo=false")
    if not params.include_vpn:
        sections["vpn_tunnels"] = FeatureGap(reason="disabled by include_vpn=false")
    elif isinstance(sections.get("vpn_tunnels"), list):
        if vpn_window != params.time_range:
            warnings.append(
                f"vpn_tunnels queried over {vpn_window}, not the requested "
                f"{params.time_range}: the site-to-site IPsec FortiView is "
                "session-bucketed and does not surface tunnels in short windows"
            )
        if not sections["vpn_tunnels"]:
            warnings.append(f"no site-to-site IPsec tunnels in the {vpn_window} window")

    counts = {
        label: (len(rows) if isinstance(rows, list) else 0) for label, rows in sections.items()
    }
    return NetworkContextResult(
        top_destinations=sections["top_destinations"],
        top_sources=sections["top_sources"],
        top_countries=sections["top_countries"],
        vpn_tunnels=sections["vpn_tunnels"],
        counts=counts,
        time_range=params.time_range,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# risk_assessment (Wave 2)                                              #
# --------------------------------------------------------------------- #


async def run_risk_assessment(params: RiskAssessmentParams) -> RiskAssessmentResult:
    """Transparent composite 0-100 risk score for one endpoint or end-user.

    Entity resolution (one UEBA read) is the subject; each of the three
    dimension reads is context and degrades to a subscore of 0 plus a
    warning naming the gap. The auth-failure dimension runs exactly one
    logview search; every other read is a plain GET. Scoring is fully
    deterministic — the formula lives in the ``RiskAssessmentResult``
    docstring and the weights in the module constants above.
    """
    from fortianalyzer_mcp.tools.fortiview_tools import get_fortiview_data
    from fortianalyzer_mcp.tools.log_tools import query_logs
    from fortianalyzer_mcp.tools.ueba_tools import (
        get_endpoint_vulnerabilities,
        get_endpoints,
        get_endusers,
    )
    from fortianalyzer_mcp.utils.validation import sanitize_filter_value

    warnings: list[str] = []

    vuln_epids: list[int] = []
    entity_filter: str | None = None
    entity_filter_gap: str | None = None
    if params.epid is not None:
        eps_res, err = await _call(
            get_endpoints, adom=params.adom, epids=[params.epid], detail_level="simple"
        )
        if eps_res is None:
            raise SkillExecutionError(f"could not resolve endpoint {params.epid} ({err})")
        record = next(
            (ep for ep in _records(eps_res.get("data")) if str(ep.get("epid")) == str(params.epid)),
            None,
        )
        if record is None:
            raise SkillExecutionError(f"endpoint {params.epid} not found in the UEBA inventory")
        entity: dict[str, Any] = {"type": "endpoint", "epid": params.epid, "record": record}
        vuln_epids = [params.epid]
        epip = record.get("epip")
        if epip:
            entity_filter = f"srcip=={sanitize_filter_value(str(epip), 'epip')}"
        else:
            entity_filter_gap = f"endpoint {params.epid} carries no 'epip'"
    else:
        users_res, err = await _call(get_endusers, adom=params.adom, euids=[params.euid])
        if users_res is None:
            raise SkillExecutionError(f"could not resolve end-user {params.euid} ({err})")
        record = next(
            (
                user
                for user in _records(users_res.get("data"))
                if str(user.get("euid")) == str(params.euid)
            ),
            None,
        )
        if record is None:
            raise SkillExecutionError(f"end-user {params.euid} not found in the UEBA directory")
        entity = {"type": "enduser", "euid": params.euid, "record": record}
        for key in _ENDUSER_EPID_KEYS:
            value = record.get(key)
            for candidate in value if isinstance(value, list) else [value]:
                if isinstance(candidate, int):
                    vuln_epids.append(candidate)
                elif isinstance(candidate, str) and candidate.isdigit():
                    vuln_epids.append(int(candidate))
            if vuln_epids:
                break
        euname = record.get("euname")
        if euname:
            entity_filter = f"user=={sanitize_filter_value(str(euname), 'euname')}"
        else:
            entity_filter_gap = f"end-user {params.euid} carries no 'euname'"

    vuln_counts: dict[str, int] = {}
    if not vuln_epids:
        warnings.append(
            "vulnerability dimension unavailable (no endpoint id associated with "
            "this entity); its subscore is 0"
        )
    else:
        vuln_res, err = await _call(
            get_endpoint_vulnerabilities,
            adom=params.adom,
            epids=vuln_epids,
            detectby=params.detectby,
        )
        if vuln_res is None:
            warnings.append(f"vulnerability dimension unavailable ({err}); its subscore is 0")
        else:
            by_endpoint, orphans = _flatten_vuln_records(vuln_res.get("data"))
            rows = [row for group in by_endpoint.values() for row in group] + orphans
            vuln_counts = _severity_counts(rows)
    vuln_sub = _severity_points(vuln_counts, _VULN_POINTS)

    threat_counts: dict[str, int] = {}
    if entity_filter is None:
        warnings.append(
            f"threat dimension unavailable ({entity_filter_gap}; nothing to tie "
            "threat detections to); its subscore is 0"
        )
    else:
        threats_res, err = await _call(
            get_fortiview_data,
            view_name="top-threats",
            adom=params.adom,
            time_range=params.time_range,
            filter=entity_filter,
            limit=100,
        )
        if threats_res is None:
            warnings.append(f"threat dimension unavailable ({err}); its subscore is 0")
        else:
            threat_counts = _severity_counts(_records(threats_res.get("data")))
    threat_sub = _severity_points(threat_counts, _THREAT_POINTS)

    failures = 0
    auth_available = False
    if entity_filter is None:
        warnings.append(
            f"auth-failure dimension unavailable ({entity_filter_gap}; nothing to "
            "tie event logs to); its subscore is 0"
        )
    else:
        logs_res, err = await _call(
            query_logs,
            adom=params.adom,
            logtype="event",
            time_range=params.time_range,
            filter=f"action==failure and {entity_filter}",
            limit=1000,
        )
        if logs_res is None:
            warnings.append(f"auth-failure dimension unavailable ({err}); its subscore is 0")
        else:
            auth_available = True
            total = logs_res.get("total")
            if logs_res.get("total_is_known") and isinstance(total, int):
                failures = total
            else:
                failures = len(logs_res.get("logs") or [])
                if logs_res.get("has_more"):
                    warnings.append(
                        f"auth-failure count is a lower bound ({failures} rows "
                        "returned; more available and total unknown)"
                    )
    auth_sub = min(100, failures * _AUTH_POINTS_PER_FAILURE)

    composite = int(round(_W_VULN * vuln_sub + _W_THREAT * threat_sub + _W_AUTH * auth_sub))
    return RiskAssessmentResult(
        entity=entity,
        vulnerability=RiskDimension(raw_counts=vuln_counts, subscore=vuln_sub, weight=_W_VULN),
        threat=RiskDimension(raw_counts=threat_counts, subscore=threat_sub, weight=_W_THREAT),
        auth_failure=RiskDimension(
            raw_counts={"failures": failures} if auth_available else {},
            subscore=auth_sub,
            weight=_W_AUTH,
        ),
        composite_score=composite,
        band=_risk_band(composite),  # type: ignore[arg-type]
        time_range=params.time_range,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# investigate (Wave 2)                                                  #
# --------------------------------------------------------------------- #

# Candidate subject fields that may carry linked entity ids. Alert
# extra-details carry "epids"/"euids" (live-verified: triage's
# subject_details is {alertid, devs, epids, euids}); which fields an
# incident record carries is not pinned down across builds, so the
# singular forms are candidates and a miss degrades to a FeatureGap
# rather than a guess.
_SUBJECT_EPID_KEYS = ("epids", "epid")
_SUBJECT_EUID_KEYS = ("euids", "euid")


def _subject_entity_ids(carriers: list[dict[str, Any]], keys: tuple[str, ...]) -> list[int]:
    """Integer entity ids from the first carrier/key that yields any.

    Follows the risk_assessment id-coercion convention: ints and digit
    strings count, anything else is dropped rather than guessed at.
    """
    for carrier in carriers:
        for key in keys:
            if key not in carrier:
                continue
            value = carrier[key]
            ids: list[int] = []
            for candidate in value if isinstance(value, list) else [value]:
                if isinstance(candidate, bool):
                    continue
                if isinstance(candidate, int):
                    ids.append(candidate)
                elif isinstance(candidate, str) and candidate.isdigit():
                    ids.append(int(candidate))
            if ids:
                return ids
    return []


def _investigation_headline(
    subject_type: str,
    subject_id: str,
    triage: TriageResult,
    threat_intel: ThreatIntelResult | FeatureGap,
    assets: AssetLookupResult | FeatureGap,
    identities: IdentityLookupResult | FeatureGap,
) -> str:
    """Deterministic one-line rollup: the mapped priority plus counts.

    Built only from values already present in the composed results — no
    inference; gap sections are simply omitted.
    """
    parts = [f"{subject_type} {subject_id}: priority {triage.assessment.priority}"]
    if isinstance(threat_intel, ThreatIntelResult):
        malicious = sum(
            1
            for record in threat_intel.indicators
            if str(record.reputation or "").lower() == "malicious"
        )
        parts.append(f"{threat_intel.indicator_count} linked indicators ({malicious} malicious)")
    if isinstance(assets, AssetLookupResult):
        parts.append(f"{assets.endpoint_count} linked endpoints")
    if isinstance(identities, IdentityLookupResult):
        parts.append(f"{identities.user_count} linked users")
    return "; ".join(parts)


async def run_investigate(params: InvestigateParams) -> Investigation:
    """One consolidated investigation view for one alert or incident.

    Pure composition over existing skills — no reads of its own:
    ``run_triage`` resolves the subject (the only hard fail), then
    ``run_incident_summary`` (the subject incident, or the incident the
    alert is attached to), ``run_threat_intel`` (linked-indicator
    enrichment) and ``run_asset_lookup``/``run_identity_lookup`` (for
    entity ids the subject itself carries) each degrade independently to
    a ``FeatureGap`` plus a prefixed warning.
    """
    warnings: list[str] = []
    subject_type = "alert" if params.alert_id else "incident"
    subject_id = str(params.alert_id or params.incident_id)

    triage = await run_triage(
        TriageParams(
            adom=params.adom,
            alert_id=params.alert_id,
            incident_id=params.incident_id,
            context_time_range=params.time_range,
        )
    )
    warnings.extend(f"triage: {w}" for w in triage.warnings)

    # Deep incident summary: the subject incident, or the incident the
    # alert is attached to (resolved authoritatively by triage).
    summary: IncidentSummary | FeatureGap
    summary_incid = params.incident_id
    if summary_incid is None:
        related_incids = [
            str(rel["incid"])
            for rel in triage.related
            if isinstance(rel, dict) and rel.get("incid")
        ]
        summary_incid = related_incids[0] if related_incids else None
        if len(related_incids) > 1:
            warnings.append(
                f"{len(related_incids)} incidents linked to alert {params.alert_id}; "
                f"summarizing incident {summary_incid}"
            )
    if summary_incid is None:
        summary = FeatureGap(
            reason=f"alert {params.alert_id} is not attached to any incident; nothing to summarize"
        )
    else:
        try:
            summary = await run_incident_summary(
                IncidentSummaryParams(
                    adom=params.adom,
                    incident_id=summary_incid,
                    time_range=params.time_range,
                    # The threat landscape lives on the threat_intel section;
                    # fetching it here too would duplicate the FortiView read.
                    include_top_threats=False,
                )
            )
            warnings.extend(f"summary: {w}" for w in summary.warnings)
        except SkillExecutionError as exc:
            warnings.append(f"incident summary unavailable: {exc}")
            summary = FeatureGap(reason=f"incident summary unavailable: {exc}")

    # Indicator enrichment: threat_intel on the same subject. Its subject
    # call (linked-indicator resolution) is enrichment from this skill's
    # point of view, so its hard fail degrades to a gap here.
    threat_intel: ThreatIntelResult | FeatureGap
    try:
        threat_intel = await run_threat_intel(
            ThreatIntelParams(
                adom=params.adom,
                alert_id=params.alert_id,
                incident_id=params.incident_id,
                detail_level=params.detail_level,
                time_range=params.time_range,
                include_threat_landscape=params.include_threat_landscape,
            )
        )
        warnings.extend(f"threat_intel: {w}" for w in threat_intel.warnings)
    except SkillExecutionError as exc:
        warnings.append(f"indicator enrichment unavailable: {exc}")
        threat_intel = FeatureGap(reason=f"indicator enrichment unavailable: {exc}")

    # Asset / identity context: only for entity ids the subject itself
    # carries; anything less direct would be a guess and degrades to a
    # gap instead.
    assets: AssetLookupResult | FeatureGap
    identities: IdentityLookupResult | FeatureGap
    if not params.include_entities:
        assets = FeatureGap(reason="disabled by include_entities=false")
        identities = FeatureGap(reason="disabled by include_entities=false")
    else:
        carriers = [triage.subject]
        if triage.subject_details is not None:
            carriers.append(triage.subject_details)
        epids = _subject_entity_ids(carriers, _SUBJECT_EPID_KEYS)
        euids = _subject_entity_ids(carriers, _SUBJECT_EUID_KEYS)

        if not epids:
            assets = FeatureGap(
                reason=f"{subject_type} {subject_id} carries no endpoint ids "
                f"({'/'.join(_SUBJECT_EPID_KEYS)}); asset linkage would be a guess"
            )
        else:
            try:
                assets = await run_asset_lookup(AssetLookupParams(adom=params.adom, epids=epids))
                warnings.extend(f"assets: {w}" for w in assets.warnings)
            except SkillExecutionError as exc:
                warnings.append(f"asset context unavailable: {exc}")
                assets = FeatureGap(reason=f"asset context unavailable: {exc}")

        if not euids:
            identities = FeatureGap(
                reason=f"{subject_type} {subject_id} carries no end-user ids "
                f"({'/'.join(_SUBJECT_EUID_KEYS)}); identity linkage would be a guess"
            )
        else:
            try:
                identities = await run_identity_lookup(
                    IdentityLookupParams(adom=params.adom, euids=euids)
                )
                warnings.extend(f"identities: {w}" for w in identities.warnings)
            except SkillExecutionError as exc:
                warnings.append(f"identity context unavailable: {exc}")
                identities = FeatureGap(reason=f"identity context unavailable: {exc}")

    return Investigation(
        subject_type=subject_type,  # type: ignore[arg-type]
        headline=_investigation_headline(
            subject_type, subject_id, triage, threat_intel, assets, identities
        ),
        triage=triage,
        summary=summary,
        threat_intel=threat_intel,
        assets=assets,
        identities=identities,
        time_range=params.time_range,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# hunt (Wave 3)                                                         #
# --------------------------------------------------------------------- #

# The sweep's log searches consume logview slots and per
# [[feedback_real_world_test_window]] must stay bounded; a preset window
# wider than a week is capped here. Custom start|end ranges are the
# caller's explicit intent and pass through. Reuses _WINDOW_RANK above.
_HUNT_MAX_WINDOW = "7-day"

# UEBA endpoint 'vuln-stats' keys mapped to the readable severity labels the
# result exposes. The appliance keys them cnt_<sev>; anything else is kept
# verbatim under its own key so an unrecognised counter is never dropped.
_VULN_STAT_LABELS = {
    "cnt_cri": "critical",
    "cnt_hig": "high",
    "cnt_med": "medium",
    "cnt_low": "low",
    "cnt_inf": "info",
}
# vuln-stats severities that count as "serious" for the anomaly call.
_SERIOUS_VULN_LABELS = ("critical", "high")

# Behavioural alert-handler / IOC detection markers. FAZ's own anomaly
# detections surface as alerts whose handler names carry these substrings
# (e.g. Default-Botnet-Communication-Detection-By-Endpoint,
# Compromised-Host-Detection-IOC-By-Threat). Matched case-insensitively
# against the alert's handler/name fields — this is the single place to
# widen the vocabulary once more handlers are live-verified.
_BEHAVIORAL_MARKERS = (
    "botnet",
    "compromised",
    "ioc",
    "beacon",
    "c2",
    "command-and-control",
    "anomaly",
    "lateral",
    "exfil",
)
# Alert fields that may name the handler / detection rule (build-varying).
_ALERT_HANDLER_KEYS = ("alerttype", "eventtype", "triggername", "name", "logdesc")


def _cap_hunt_window(time_range: str) -> tuple[str, bool]:
    """Cap a preset window at ``_HUNT_MAX_WINDOW``; report whether it was capped.

    Custom ``start|end`` ranges and unrecognized tokens pass through
    unchanged (the caller owns them); a preset wider than the floor is
    narrowed to the floor. Mirrors ``investigate_deep``'s ``_cap_window``.
    """
    if "|" in time_range:
        return time_range, False
    requested = _WINDOW_RANK.get(time_range)
    if requested is None or requested <= _WINDOW_RANK[_HUNT_MAX_WINDOW]:
        return time_range, False
    return _HUNT_MAX_WINDOW, True


def _vuln_stats_counts(record: dict[str, Any]) -> dict[str, int]:
    """Per-severity vulnerability counts from a UEBA record's ``vuln-stats``.

    Reads the endpoint's own FAZ-computed counters (not a CVE re-count).
    Tolerates the counters living directly on the record or nested under a
    ``vuln-stats`` dict. Non-integer / zero counters are dropped; unknown
    counter keys are kept under their raw key so nothing is silently lost.
    """
    source = record.get("vuln-stats")
    if not isinstance(source, dict):
        source = record
    counts: dict[str, int] = {}
    for key, value in source.items():
        # Live FAZ returns the counters as ints at detail_level='basic' but as
        # digit strings at 'standard' (live-verified 7.6.7 + 8.0.0), so coerce.
        count = _as_int(value)
        if count is None or count <= 0:
            continue
        if key in _VULN_STAT_LABELS:
            counts[_VULN_STAT_LABELS[key]] = count
        elif str(key).startswith("cnt_"):
            counts[str(key)] = count
    return counts


def _as_int(value: Any) -> int | None:
    """Coerce an int or a digit string to int; anything else -> None.

    UEBA vuln-stats counters arrive as ints or digit strings depending on
    the detail level; ``scan_time`` and other non-numeric values are dropped.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _as_float(value: Any) -> float | None:
    """Coerce a number or numeric string to float; anything else -> None.

    UEBA ``risk_score`` arrives as a float-valued string (e.g.
    "0.2479...") on live 7.6.7/8.0.0, so a plain isinstance(float) check
    would miss every host; this coerces it.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _risk_percentile(target: float, population: list[float]) -> float | None:
    """Percentile rank of ``target`` within ``population`` (0–100).

    The share of the population scoring at or below ``target`` — a standard
    "percentile rank" (weak inequality, so the max scores 100.0). Returns
    ``None`` for a population too small to rank meaningfully (< 2 scored
    endpoints), so a one-host estate never reports a false "100th
    percentile". Deterministic; no inference.
    """
    if len(population) < 2:
        return None
    at_or_below = sum(1 for value in population if value <= target)
    return round(100.0 * at_or_below / len(population), 1)


def _is_behavioral_alert(alert: dict[str, Any]) -> bool:
    """Whether an alert reads as a FAZ behavioural / IOC detection.

    Best-effort substring match of the behavioural markers against the
    alert's handler/name fields. Case-insensitive; a miss simply excludes
    the alert (it is not guessed onto the entity).
    """
    haystack = " ".join(str(alert.get(key) or "") for key in _ALERT_HANDLER_KEYS).lower()
    return any(marker in haystack for marker in _BEHAVIORAL_MARKERS)


async def _entity_behavioral_alerts(
    adom: str | None,
    pivot: str | None,
    time_range: str,
    warnings: list[str],
    entity_ref: str,
) -> list[dict[str, Any]] | FeatureGap:
    """The entity's behavioural alert-handler / IOC alerts in the window.

    One eventmgmt GET (no logview slot): alerts in the window filtered to
    the entity's pivot (srcip==<epip> / user==<euname>), then narrowed to
    the ones whose handler reads as a behavioural / IOC detection. FAZ's own
    anomaly detections — the RFC's "strongest FAZ-provided behavioural
    signal". Degrades to a ``FeatureGap`` when the read fails or the entity
    yields no pivot to tie alerts to.
    """
    from fortianalyzer_mcp.tools.event_tools import get_alerts

    if pivot is None:
        return FeatureGap(
            reason=f"entity {entity_ref} yields no srcip/user pivot; "
            "behavioural detections cannot be tied to it"
        )
    alerts_res, err = await _call(
        get_alerts, adom=adom, time_range=time_range, filter=pivot, limit=200
    )
    if alerts_res is None:
        warnings.append(f"behavior[{entity_ref}]: behavioural alert lookup unavailable: {err}")
        return FeatureGap(reason=f"behavioural alert lookup unavailable: {err}")
    behavioral = [a for a in alerts_res.get("data") or [] if _is_behavioral_alert(a)]
    return behavioral


async def _hunt_behavior(
    adom: str | None,
    entity: str,
    time_range: str,
    anomaly_percentile: float,
    warnings: list[str],
) -> tuple[EntityBehavior, int]:
    """The behaviour half for one entity. Returns (behaviour, ranked_total).

    Endpoint: resolve the whole UEBA endpoint estate (one plain GET), rank
    the entity's ``risk_score`` as a percentile within that distribution,
    read its per-severity ``vuln-stats``, and pull its behavioural / IOC
    alerts. The anomaly verdict is percentile-based — the RFC-confirmed
    calibration, since risk_score runs low in absolute terms.

    End-user: no ``risk_score`` — lean on ``importance`` + behavioural
    alerts.

    ``ranked_total`` is the number of endpoints carrying a numeric
    risk_score (the real denominator behind the percentile); 0 for an
    end-user subject.
    """
    from fortianalyzer_mcp.tools.ueba_tools import get_endpoints, get_endusers
    from fortianalyzer_mcp.utils.validation import sanitize_filter_value

    kind, _, raw = entity.partition(":")
    kind = kind.strip().lower()
    ref = raw.strip()
    if kind not in ("epid", "euid") or not ref.isdigit():
        raise SkillExecutionError(f"unrecognized entity {entity!r}; use 'epid:N' or 'euid:N'")
    entity_id = int(ref)

    if kind == "epid":
        # No time_range: get_endpoints' window filters by *first-seen*, which
        # would shrink the estate to hosts first-seen in the window and can
        # drop the target itself. The percentile denominator must be the full
        # current inventory (live-verified: a 7-day first-seen filter excluded
        # long-standing hosts on 8.0.0), so the estate read is unwindowed.
        eps_res, err = await _call(get_endpoints, adom=adom, detail_level="standard")
        if eps_res is None:
            raise SkillExecutionError(f"could not retrieve UEBA endpoints ({err})")
        estate = _records(eps_res.get("data"))
        record = next((ep for ep in estate if str(ep.get("epid")) == str(entity_id)), None)
        if record is None:
            raise SkillExecutionError(f"endpoint {entity_id} not found in the UEBA inventory")

        # Percentile: rank this endpoint's risk_score against every other
        # endpoint's — the anomaly signal is relative, not a fixed cut. Live
        # FAZ returns risk_score as a float-valued string, so coerce.
        population = [
            score for ep in estate if (score := _as_float(ep.get("risk_score"))) is not None
        ]
        ranked_total = len(population)
        risk_score = _as_float(record.get("risk_score"))
        percentile = _risk_percentile(risk_score, population) if risk_score is not None else None
        vuln_stats = _vuln_stats_counts(record)
        importance = record.get("importance")

        pivot = None
        epip = record.get("epip")
        if epip:
            pivot = f"srcip=={sanitize_filter_value(str(epip), 'epip')}"
        else:
            warnings.append(
                f"behavior[{entity_id}]: endpoint carries no 'epip'; behavioural "
                "detections cannot be tied to it"
            )
        detections = await _entity_behavioral_alerts(
            adom, pivot, time_range, warnings, str(entity_id)
        )

        anomalous, basis = _score_endpoint_anomaly(
            percentile, ranked_total, vuln_stats, detections, anomaly_percentile
        )
        detection_count = len(detections) if isinstance(detections, list) else 0
        return (
            EntityBehavior(
                entity_type="endpoint",
                entity_ref=str(entity_id),
                record=record,
                risk_score=risk_score,
                risk_percentile=percentile,
                importance=importance,
                vuln_stats=vuln_stats,
                behavioral_detections=detections,
                detection_count=detection_count,
                anomalous=anomalous,
                anomaly_basis=basis,
            ),
            ranked_total,
        )

    # End-user: no risk_score — importance + behavioural alerts only.
    users_res, err = await _call(get_endusers, adom=adom, euids=[entity_id])
    if users_res is None:
        raise SkillExecutionError(f"could not retrieve UEBA end-users ({err})")
    record = next(
        (u for u in _records(users_res.get("data")) if str(u.get("euid")) == str(entity_id)),
        None,
    )
    if record is None:
        raise SkillExecutionError(f"end-user {entity_id} not found in the UEBA directory")

    importance = record.get("importance")
    pivot = None
    euname = record.get("euname")
    if euname:
        pivot = f"user=={sanitize_filter_value(str(euname), 'euname')}"
    else:
        warnings.append(
            f"behavior[{entity_id}]: end-user carries no 'euname'; behavioural "
            "detections cannot be tied to it"
        )
    detections = await _entity_behavioral_alerts(adom, pivot, time_range, warnings, str(entity_id))

    anomalous, basis = _score_enduser_anomaly(importance, detections)
    detection_count = len(detections) if isinstance(detections, list) else 0
    return (
        EntityBehavior(
            entity_type="enduser",
            entity_ref=str(entity_id),
            record=record,
            risk_score=None,
            risk_percentile=None,
            importance=importance,
            vuln_stats={},
            behavioral_detections=detections,
            detection_count=detection_count,
            anomalous=anomalous,
            anomaly_basis=basis,
        ),
        0,
    )


def _score_endpoint_anomaly(
    percentile: float | None,
    ranked_total: int,
    vuln_stats: dict[str, int],
    detections: list[dict[str, Any]] | FeatureGap,
    anomaly_percentile: float,
) -> tuple[bool, list[str]]:
    """Derive an endpoint's anomaly verdict + auditable basis.

    Percentile-first (never a fixed risk cut): an endpoint at or above the
    ``anomaly_percentile`` of the estate risk distribution is anomalous.
    Serious vuln-stats (critical/high) and any behavioural detection are
    independent flags — either alone also fires the verdict, since a host
    with a live IOC detection or a critical CVE is worth surfacing even if
    its raw risk_score sits mid-pack.
    """
    basis: list[str] = []
    flags: list[bool] = []

    if percentile is None:
        basis.append(
            "risk_score percentile unavailable "
            f"(estate too small to rank, {ranked_total} scored endpoint(s)); "
            "percentile flag not applied"
        )
    else:
        hit = percentile >= anomaly_percentile
        flags.append(hit)
        basis.append(
            f"risk_score at {percentile}th percentile of {ranked_total} scored "
            f"endpoints (threshold {anomaly_percentile}) -> "
            f"{'ANOMALOUS' if hit else 'normal'}"
        )

    serious = {s: vuln_stats[s] for s in _SERIOUS_VULN_LABELS if vuln_stats.get(s)}
    if serious:
        flags.append(True)
        detail = ", ".join(f"{count} {sev}" for sev, count in serious.items())
        basis.append(f"carries serious vulnerabilities ({detail}) -> ANOMALOUS")
    else:
        basis.append("no critical/high vuln-stats")

    if isinstance(detections, list) and detections:
        flags.append(True)
        basis.append(f"{len(detections)} behavioural/IOC detection(s) in the window -> ANOMALOUS")
    elif isinstance(detections, list):
        basis.append("no behavioural/IOC detections in the window")
    else:
        basis.append("behavioural detections unavailable; that flag not applied")

    return (any(flags), basis)


def _score_enduser_anomaly(
    importance: Any, detections: list[dict[str, Any]] | FeatureGap
) -> tuple[bool, list[str]]:
    """Derive an end-user's anomaly verdict + basis (no risk_score exists).

    End-users carry no ``risk_score``, so the signal is ``importance`` +
    behavioural detections: a high-importance user or any behavioural
    detection fires the verdict.
    """
    basis: list[str] = []
    flags: list[bool] = []

    importance_str = str(importance).lower() if importance is not None else ""
    if importance_str in ("high", "critical"):
        flags.append(True)
        basis.append(f"importance is {importance!r} -> ANOMALOUS")
    elif importance is not None:
        basis.append(f"importance is {importance!r}")
    else:
        basis.append("end-user carries no 'importance'")

    if isinstance(detections, list) and detections:
        flags.append(True)
        basis.append(f"{len(detections)} behavioural/IOC detection(s) in the window -> ANOMALOUS")
    elif isinstance(detections, list):
        basis.append("no behavioural/IOC detections in the window")
    else:
        basis.append("behavioural detections unavailable; that flag not applied")

    return (any(flags), basis)


def _sweep_pivot(params: HuntParams) -> str | None:
    """The filter clause the sweep searches run on — auditable, never a guess.

    - indicator: an equality on the field the indicator's type maps to
      (IP -> srcip, Domain -> hostname, URL -> url, Hash -> a 'checksum'
      substring). Sanitised.
    - filter: passed through verbatim (the caller owns its correctness).
    - ttp only: folded into an 'attack' substring match.

    Returns ``None`` when no usable pivot can be derived (the sweep then
    degrades to a gap rather than sweeping on nothing).
    """
    from fortianalyzer_mcp.utils.validation import sanitize_filter_value

    if params.filter is not None:
        # The caller's raw filter is authoritative; a ttp hint is recorded
        # but not merged (merging free-form clauses risks a malformed filter).
        return params.filter

    if params.indicator is not None:
        value = sanitize_filter_value(params.indicator.value, "indicator")
        field = {
            "IP": "srcip",
            "Domain": "hostname",
            "URL": "url",
            "Hash": "checksum",
        }[params.indicator.type]
        # Hash is matched as a substring (the checksum field name varies by
        # logtype); IP/Domain/URL as equality.
        if params.indicator.type == "Hash":
            return f"{field}=~{value}"
        return f"{field}=={value}"

    if params.ttp is not None:
        return f"attack=~{sanitize_filter_value(params.ttp, 'ttp')}"

    return None


async def _hunt_sweep(
    params: HuntParams, time_range: str, warnings: list[str]
) -> HuntSweep | FeatureGap:
    """The hunt half: sweep the estate for the indicator/TTP/filter.

    One logview search slot per swept log type (capped by
    ``max_sweep_searches``; excess dropped and named in ``warnings``), plus
    ``threat_intel`` for an IP/URL/Domain indicator (plain GETs, no slot).
    Degrades to a ``FeatureGap`` when no sweep pivot can be derived.
    """
    from fortianalyzer_mcp.tools.log_tools import query_logs

    pivot = _sweep_pivot(params)
    if pivot is None:
        return FeatureGap(
            reason="no sweep pivot could be derived from the subject; nothing to hunt on"
        )

    matches: list[SweepMatch] = []
    consumed = 0
    dropped = 0
    budget = params.max_sweep_searches
    for logtype in params.sweep_logtypes:
        if consumed >= budget:
            dropped += 1
            matches.append(
                SweepMatch(
                    logtype=logtype,
                    rows=FeatureGap(
                        reason=f"dropped by max_sweep_searches cap (budget {budget} exhausted)"
                    ),
                )
            )
            warnings.append(
                f"sweep: '{logtype}' search dropped by the fan-out cap (budget {budget})"
            )
            continue
        consumed += 1
        logs_res, err = await _call(
            query_logs,
            adom=params.adom,
            logtype=logtype,
            time_range=time_range,
            filter=pivot,
            limit=params.sweep_limit,
        )
        if logs_res is None:
            matches.append(
                SweepMatch(
                    logtype=logtype,
                    rows=FeatureGap(reason=f"sweep '{logtype}' search unavailable: {err}"),
                )
            )
            warnings.append(f"sweep[{logtype}]: search unavailable: {err}")
        else:
            rows = logs_res.get("logs") or []
            matches.append(SweepMatch(logtype=logtype, rows=rows, row_count=len(rows)))
            warnings.extend(f"sweep[{logtype}]: {w}" for w in logs_res.get("warnings") or [])

    # Threat-intel: reputation for an IP/URL/Domain indicator (a hash is not
    # a SOAR reputation type; a bare filter/ttp has no single indicator).
    threat_intel: ThreatIntelResult | FeatureGap
    ti_type = (
        _INDICATOR_TYPE_CANONICAL.get(params.indicator.type.lower())
        if params.indicator is not None
        else None
    )
    if ti_type is not None and params.indicator is not None:
        try:
            # ti_type is a value of _INDICATOR_TYPE_CANONICAL, i.e. exactly one
            # of "IP"/"URL"/"Domain" — the IndicatorSpec.type Literal.
            spec = IndicatorSpec.model_validate({"value": params.indicator.value, "type": ti_type})
            threat_intel = await run_threat_intel(
                ThreatIntelParams(
                    adom=params.adom,
                    indicators=[spec],
                    detail_level=params.detail_level,
                    time_range=time_range,
                    include_threat_landscape=params.include_threat_landscape,
                )
            )
            warnings.extend(f"threat_intel: {w}" for w in threat_intel.warnings)
        except SkillExecutionError as exc:
            warnings.append(f"indicator enrichment unavailable: {exc}")
            threat_intel = FeatureGap(reason=f"indicator enrichment unavailable: {exc}")
    elif params.indicator is not None:
        threat_intel = FeatureGap(
            reason=f"{params.indicator.type} indicators carry no SOAR reputation type"
        )
    else:
        threat_intel = FeatureGap(reason="no single indicator to enrich (filter/ttp hunt)")

    total = sum(m.row_count for m in matches)
    return HuntSweep(
        pivot_filter=pivot,
        ttp=params.ttp,
        matches=matches,
        threat_intel=threat_intel,
        total_matches=total,
        sweep_searches_run=consumed,
        sweep_searches_dropped=dropped,
    )


async def _hunt_estate(
    adom: str | None,
    time_range: str,
    want_endpoints: bool,
    want_endusers: bool,
    ranked_endpoint_total: int,
    warnings: list[str],
) -> EstateContext | FeatureGap:
    """Estate-scale denominators for the window — context, never a baseline.

    Composes the Layer-1 ``get_endpoint_stats`` / ``get_enduser_stats``
    readers (ADOM-wide count snapshots) when they are available. Those
    readers ship on a separate additive branch; when they are not present
    (``ImportError``/``AttributeError``) the section degrades to a
    ``FeatureGap`` rather than failing — the estate context is optional and
    the percentile denominator (``ranked_endpoint_total``) comes from the
    behaviour half's own ``get_endpoints`` read regardless.
    """
    try:
        from fortianalyzer_mcp.tools.ueba_tools import (  # type: ignore[attr-defined]
            get_endpoint_stats,
            get_enduser_stats,
        )
    except ImportError:
        return FeatureGap(
            reason="estate-stats readers not available in this build; "
            "denominators skipped (optional context)"
        )

    endpoints: dict[str, Any] | FeatureGap = FeatureGap(reason="not requested for this subject")
    if want_endpoints:
        eps_res, err = await _call(get_endpoint_stats, adom=adom, time_range=time_range)
        if eps_res is None:
            warnings.append(f"estate: endpoint stats unavailable: {err}")
            endpoints = FeatureGap(reason=f"endpoint stats unavailable: {err}")
        else:
            data = eps_res.get("data")
            first = _first_record(data)
            endpoints = first if first is not None else {"data": data}

    endusers: dict[str, Any] | FeatureGap = FeatureGap(reason="not requested for this subject")
    if want_endusers:
        eu_res, err = await _call(get_enduser_stats, adom=adom, time_range=time_range)
        if eu_res is None:
            warnings.append(f"estate: end-user stats unavailable: {err}")
            endusers = FeatureGap(reason=f"end-user stats unavailable: {err}")
        else:
            data = eu_res.get("data")
            endusers = data if isinstance(data, dict) else {"data": data}

    return EstateContext(
        endpoints=endpoints,
        endusers=endusers,
        ranked_endpoint_total=ranked_endpoint_total,
    )


def _hunt_headline(
    subject_type: str,
    subject_id: str,
    sweep: HuntSweep | FeatureGap,
    behavior: EntityBehavior | FeatureGap,
) -> str:
    """Deterministic one-line rollup for the hunt — built only from present values."""
    parts = [f"{subject_type} {subject_id}"]
    if isinstance(sweep, HuntSweep):
        parts.append(
            f"sweep: {sweep.total_matches} matches across {sweep.sweep_searches_run} searches"
        )
    if isinstance(behavior, EntityBehavior):
        verdict = "ANOMALOUS" if behavior.anomalous else "normal"
        pct = (
            f"{behavior.risk_percentile}th pct"
            if behavior.risk_percentile is not None
            else "no percentile"
        )
        parts.append(f"behavior: {verdict} ({pct}, {behavior.detection_count} detections)")
    return "; ".join(parts)


async def run_hunt(params: HuntParams) -> HuntResult:
    """Proactive hunt: sweep the estate for an IOC/TTP and/or score one
    entity's behaviour for anomaly.

    Two halves, driven by the subject:

    - **Sweep (indicator / filter / ttp):** ``log_search`` fan-out across
      ``sweep_logtypes`` for where the subject appears (verbatim rows,
      capped), plus ``threat_intel`` reputation for an IP/URL/Domain
      indicator. One logview search slot per swept log type, hard-capped by
      ``max_sweep_searches``; excess dropped and named in ``warnings``.
    - **Behaviour (entity = epid:N / euid:N):** the entity's FAZ-provided
      behavioural signals, anomaly-scored **by percentile, not a fixed
      threshold** — for an endpoint, its ``risk_score`` ranked within the
      estate's current risk distribution (``get_endpoints``), its
      per-severity ``vuln-stats``, and its behavioural alert-handler / IOC
      detections in the window; for an end-user (no ``risk_score``), its
      ``importance`` + those detections. The verdict fires on percentile OR
      a serious vuln OR any detection, and every input is in
      ``anomaly_basis``.

    An entity subject also runs a light entity-scoped sweep (on its
    srcip/user) so "look at this host" still surfaces where it appears.
    Windows are capped to 7-day for the slot-consuming sweep. The UEBA /
    alert / stats reads are plain GETs (no search slots).
    """
    warnings: list[str] = []
    time_range, capped = _cap_hunt_window(params.time_range)
    if capped:
        warnings.append(
            f"time_range {params.time_range!r} capped to {time_range!r} for the "
            "slot-consuming sweep searches"
        )

    if params.indicator is not None:
        subject_type = "indicator"
        subject_id = f"{params.indicator.type} {params.indicator.value}"
    elif params.entity is not None:
        subject_type = "entity"
        subject_id = params.entity
    else:
        subject_type = "hypothesis"
        subject_id = params.filter or f"ttp:{params.ttp}"

    # --- Behaviour half (entity subjects) ------------------------------- #
    behavior: EntityBehavior | FeatureGap
    ranked_total = 0
    entity_pivot: str | None = None
    if params.entity is not None:
        behavior, ranked_total = await _hunt_behavior(
            params.adom, params.entity, time_range, params.anomaly_percentile, warnings
        )
        # Reuse the resolved record's pivot for the entity-scoped sweep.
        from fortianalyzer_mcp.utils.validation import sanitize_filter_value

        record = behavior.record
        if behavior.entity_type == "endpoint" and record.get("epip"):
            entity_pivot = f"srcip=={sanitize_filter_value(str(record['epip']), 'epip')}"
        elif behavior.entity_type == "enduser" and record.get("euname"):
            entity_pivot = f"user=={sanitize_filter_value(str(record['euname']), 'euname')}"
    else:
        behavior = FeatureGap(
            reason="no entity subject; behaviour half runs only for an epid:/euid: subject"
        )

    # --- Sweep half ----------------------------------------------------- #
    sweep: HuntSweep | FeatureGap
    if params.entity is not None:
        # Entity subject: sweep on the entity's own pivot so "look at this
        # host" surfaces where it appears. No indicator to enrich.
        if entity_pivot is None:
            sweep = FeatureGap(
                reason="entity yields no srcip/user pivot; entity-scoped sweep skipped"
            )
        else:
            sweep = await _hunt_sweep(
                HuntParams(
                    adom=params.adom,
                    filter=entity_pivot,
                    time_range=params.time_range,
                    sweep_logtypes=params.sweep_logtypes,
                    max_sweep_searches=params.max_sweep_searches,
                    sweep_limit=params.sweep_limit,
                    include_threat_landscape=params.include_threat_landscape,
                ),
                time_range,
                warnings,
            )
    else:
        sweep = await _hunt_sweep(params, time_range, warnings)

    # --- Estate context (denominators, optional) ------------------------ #
    estate: EstateContext | FeatureGap
    if not params.include_estate_stats:
        estate = FeatureGap(reason="disabled by include_estate_stats=false")
    else:
        want_endpoints = params.entity is None or (
            isinstance(behavior, EntityBehavior) and behavior.entity_type == "endpoint"
        )
        want_endusers = isinstance(behavior, EntityBehavior) and behavior.entity_type == "enduser"
        estate = await _hunt_estate(
            params.adom,
            time_range,
            want_endpoints,
            want_endusers,
            ranked_total,
            warnings,
        )

    return HuntResult(
        subject_type=subject_type,  # type: ignore[arg-type]
        headline=_hunt_headline(subject_type, subject_id, sweep, behavior),
        sweep=sweep,
        behavior=behavior,
        estate=estate,
        time_range=time_range,
        warnings=warnings,
    )
