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

import logging
from typing import Any

from fortianalyzer_mcp.skills.models import (
    AlertEvidence,
    FeatureGap,
    IncidentRecord,
    IncidentsParams,
    IncidentsResult,
    InvestigationReport,
    InvestigationReportParams,
    LogSearchParams,
    LogSearchResult,
    ReportsParams,
    ReportsResult,
    TimelineEntry,
    TriageAssessment,
    TriageParams,
    TriageResult,
)

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

_WAVE2_ENRICHMENT_GAP = FeatureGap(
    reason="Indicator enrichment requires the SOAR reader planned for Wave 2 (3.0.0-beta.2)."
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
        return None, f"{name}: {exc}"
    if isinstance(result, dict) and result.get("status") != "success":
        return None, f"{name}: {result.get('message') or result.get('error') or 'failed'}"
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

    alerts: list[dict[str, Any]] = []
    if params.include_alerts and incidents:
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

    records: list[IncidentRecord] = []
    for incident in incidents:
        incident_ids = _ids_of(incident, ("incid",))
        declared_alert_ids = _ids_of(incident, _INCIDENT_ALERT_KEYS)
        correlated: list[dict[str, Any]] = []
        basis: str | None = None
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

    if params.include_alerts and alerts and not any(r.correlated_alerts for r in records):
        warnings.append(
            "no alert<->incident linkage fields found in this window; "
            "correlated_alerts are empty (correlation is best-effort by shared identifiers)"
        )

    return IncidentsResult(
        incidents=records,
        incident_count=len(records),
        alerts_scanned=len(alerts),
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
        history_res, err = await _call(get_report_history, adom=params.adom, limit=params.limit)
        if history_res is None:
            raise SkillExecutionError(f"could not retrieve report history ({err})")
        reports = history_res.get("data") or []
        return ReportsResult(action="list", reports=reports, report_count=len(reports))

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

    warnings: list[str] = []
    triggering_logs: list[dict[str, Any]] = []
    related: list[dict[str, Any]] = []

    if params.alert_id:
        subject_type = "alert"
        details_res, err = await _call(
            get_alert_details, alert_id=params.alert_id, adom=params.adom
        )
        if details_res is None:
            raise SkillExecutionError(f"could not retrieve alert {params.alert_id} ({err})")
        subject = details_res.get("data") or {}
        if isinstance(subject, list):  # some FAZ builds wrap the object in a list
            subject = subject[0] if subject else {}

        logs_res, err = await _call(get_alert_logs, alert_id=params.alert_id, adom=params.adom)
        if logs_res is None:
            warnings.append(f"triggering logs unavailable: {err}")
        else:
            triggering_logs = logs_res.get("data") or []

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
            inc_res, err = await _call(
                get_incidents, adom=params.adom, time_range=params.context_time_range, limit=50
            )
            if inc_res is None:
                warnings.append(f"incident context unavailable: {err}")
            else:
                related = inc_res.get("data") or []
                if related:
                    warnings.append(
                        "alert carries no incident linkage field; 'related' lists all "
                        "incidents in the context window instead"
                    )
    else:
        subject_type = "incident"
        inc_res, err = await _call(get_incident, incident_id=params.incident_id, adom=params.adom)
        if inc_res is None:
            raise SkillExecutionError(f"could not retrieve incident {params.incident_id} ({err})")
        subject = inc_res.get("data") or {}
        if isinstance(subject, list):
            subject = subject[0] if subject else {}

        alerts_res, err = await _call(
            get_alerts, adom=params.adom, time_range=params.context_time_range, limit=200
        )
        if alerts_res is None:
            warnings.append(f"alert context unavailable: {err}")
        else:
            incident_ids = _ids_of(subject, ("incid",)) or (
                {str(params.incident_id)} if params.incident_id else set()
            )
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
        triggering_logs=triggering_logs,
        related=related,
        context_stats=context_stats,
        assessment=_assess(subject, subject_type),
        enrichment=_WAVE2_ENRICHMENT_GAP,
        warnings=warnings,
    )


# --------------------------------------------------------------------- #
# investigation_report                                                  #
# --------------------------------------------------------------------- #


def _timeline(incident: dict[str, Any], evidence: list[AlertEvidence]) -> list[TimelineEntry]:
    """Chronological entries from whatever timestamp fields are present."""
    entries: list[TimelineEntry] = []
    ts = incident.get("timestamp") or incident.get("createtime")
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
        alert_ts = item.alert.get("timestamp") or item.alert.get("createtime")
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
    # Mixed int/str timestamps sort as strings of their repr to stay total.
    return sorted(entries, key=lambda e: (isinstance(e.timestamp, str), str(e.timestamp)))


async def run_investigation_report(params: InvestigationReportParams) -> InvestigationReport:
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

    # Related alerts (same linkage strategy as the incidents skill).
    evidence: list[AlertEvidence] = []
    alerts_res, err = await _call(
        get_alerts, adom=params.adom, time_range=params.time_range, limit=500
    )
    if alerts_res is None:
        warnings.append(f"related alerts unavailable: {err}")
    else:
        incident_ids = _ids_of(incident, ("incid",)) or {str(params.incident_id)}
        declared = _ids_of(incident, _INCIDENT_ALERT_KEYS)
        linked: list[dict[str, Any]] = []
        for alert in alerts_res.get("data") or []:
            alert_id = next(iter(_ids_of(alert, ("alertid",))), None)
            if (declared and alert_id in declared) or (
                incident_ids & _ids_of(alert, _ALERT_INCIDENT_KEYS)
            ):
                linked.append(alert)
        if len(linked) > params.max_alerts:
            warnings.append(
                f"{len(linked)} linked alerts found; only the first "
                f"{params.max_alerts} include evidence logs"
            )
            linked = linked[: params.max_alerts]
        if not linked:
            warnings.append(
                "no alerts in the window carry a linkage field for this incident; "
                "the alerts section is empty (correlation is best-effort)"
            )

        for alert in linked:
            logs: list[dict[str, Any]] = []
            alert_id = next(iter(_ids_of(alert, ("alertid",))), None)
            if alert_id:
                logs_res, err = await _call(get_alert_logs, alert_id=alert_id, adom=params.adom)
                if logs_res is None:
                    warnings.append(f"logs for alert {alert_id} unavailable: {err}")
                else:
                    logs = (logs_res.get("data") or [])[: params.max_logs_per_alert]
            evidence.append(AlertEvidence(alert=alert, logs=logs))

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

    return InvestigationReport(
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
