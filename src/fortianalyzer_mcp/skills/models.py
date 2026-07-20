"""Pydantic parameter and output schemas for the skills layer.

The output models are the documented contract downstream automation
depends on: field names and shapes are versioned via ``SCHEMA_VERSION``
and kept stable across releases. Values sourced from FAZ pass through
verbatim inside ``dict`` fields — the skill layer never renames or
invents FAZ log/alert/incident fields; it adds structure *around* them.

All parameter models use ``extra="forbid"`` so a mistyped parameter is a
validation error instead of a silent no-op.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

#: Version of the skill output schemas. Bumped only on breaking contract
#: changes; additive fields do not bump it.
SCHEMA_VERSION = 1


# --------------------------------------------------------------------- #
# Shared blocks                                                         #
# --------------------------------------------------------------------- #


class FeatureGap(BaseModel):
    """Marks a sub-capability that is not available in this result.

    Used for graceful degradation: when a backing feature is not
    licensed/enabled (or not yet implemented in this wave), the skill
    reports the gap explicitly instead of failing or silently omitting.
    """

    model_config = ConfigDict(extra="forbid")

    available: Literal[False] = False
    reason: str


# --------------------------------------------------------------------- #
# incidents (Data Access)                                               #
# --------------------------------------------------------------------- #


class IncidentsParams(BaseModel):
    """Parameters for the ``incidents`` skill."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    time_range: str = Field(
        default="7-day",
        description='Preset ("1-hour".."90-day") or custom "start|end"',
    )
    filter: str | None = Field(default=None, description='e.g. "severity==critical"')
    limit: int = Field(default=50, ge=1, le=200, description="Max incidents returned")
    include_alerts: bool = Field(
        default=True, description="Correlate alerts from the same window to each incident"
    )
    alerts_scan_limit: int = Field(
        default=200, ge=1, le=2000, description="Max alerts scanned for correlation"
    )


class IncidentRecord(BaseModel):
    """One incident with best-effort correlated alerts."""

    model_config = ConfigDict(extra="forbid")

    incident: dict[str, Any] = Field(description="FAZ incident object, verbatim")
    correlated_alerts: list[dict[str, Any]] = Field(
        default_factory=list, description="FAZ alert objects linked to this incident, verbatim"
    )
    correlation_basis: str | None = Field(
        default=None, description="Which shared identifier linked the alerts (None if none found)"
    )


class IncidentsResult(BaseModel):
    """Output of the ``incidents`` skill."""

    model_config = ConfigDict(extra="forbid")

    incidents: list[IncidentRecord]
    incident_count: int
    alerts_scanned: int = Field(
        description="Alerts examined by the linkage-key fallback scan (0 when correlation "
        "is disabled or attachments already correlated every incident)"
    )
    time_range: str
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# reports (Data Access)                                                 #
# --------------------------------------------------------------------- #


class ReportsParams(BaseModel):
    """Parameters for the ``reports`` skill."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    action: Literal["list", "fetch"] = Field(
        default="list", description='"list" = report history; "fetch" = download one report'
    )
    time_range: str = Field(default="7-day", description="History window (list)")
    title: str | None = Field(default=None, description="Filter history by report title (list)")
    limit: int = Field(
        default=50, ge=1, le=500, description="Max history entries returned (applied client-side)"
    )
    tid: str | int | None = Field(default=None, description="Report task ID (fetch)")
    output_format: Literal["PDF", "HTML", "CSV", "XML"] = Field(
        default="PDF", description="Download format (fetch)"
    )

    @model_validator(mode="after")
    def _fetch_requires_tid(self) -> "ReportsParams":
        if self.action == "fetch" and self.tid is None:
            raise ValueError('action="fetch" requires "tid"')
        return self


class ReportsResult(BaseModel):
    """Output of the ``reports`` skill."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["list", "fetch"]
    reports: list[dict[str, Any]] | None = Field(
        default=None, description="Report history entries, verbatim (list mode)"
    )
    report_count: int | None = None
    fetched: dict[str, Any] | None = Field(
        default=None, description="get_report_data result, verbatim (fetch mode)"
    )
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# log_search (Data Access)                                              #
# --------------------------------------------------------------------- #


class LogSearchParams(BaseModel):
    """Parameters for the ``log_search`` skill."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    logtype: str = Field(default="traffic", description="FAZ log type (traffic, event, ips, ...)")
    filter: str | None = Field(default=None, description="FAZ filter expression")
    device: str | None = Field(default=None, description="Device name or serial")
    time_range: str = "1-hour"
    limit: int = Field(default=100, ge=1, le=1000)
    timeout: int = Field(default=60, ge=1, le=300, description="Search timeout in seconds")


class LogSearchResult(BaseModel):
    """Output of the ``log_search`` skill. Rows are verbatim FAZ log rows."""

    model_config = ConfigDict(extra="forbid")

    tid: int | None = Field(description="Search task ID (reusable with fetch_more_logs)")
    logtype: str
    rows: list[dict[str, Any]]
    row_count: int
    total: int | None = None
    total_is_known: bool = False
    has_more: bool = False
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# asset_lookup (Data Access)                                            #
# --------------------------------------------------------------------- #


class AssetLookupParams(BaseModel):
    """Parameters for the ``asset_lookup`` skill."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    epids: list[int] | None = Field(
        default=None, description="Endpoint IDs to scope the query server-side"
    )
    hostname: str | None = Field(
        default=None, description="Case-insensitive substring match on the endpoint name"
    )
    ip: str | None = Field(
        default=None,
        description="Exact match on the endpoint IP (the 'epip' field, which the "
        "appliance returns only at detail_level='simple'; a warning is emitted "
        "if it is filtered on at a level that omits it)",
    )
    detail_level: Literal["simple", "basic", "standard"] = "standard"
    time_range: str | None = Field(
        default=None, description='Optional first-seen window, e.g. "7-day" or "start|end"'
    )
    include_vulnerabilities: bool = Field(
        default=True, description="Attach per-endpoint CVE records and severity counts"
    )
    detectby: Literal["FortiClient", "FortiGate"] | None = Field(
        default=None, description="Vulnerability detector filter"
    )
    limit: int = Field(default=50, ge=1, le=500, description="Max endpoints returned")


class AssetRecord(BaseModel):
    """One endpoint (asset) profile with its vulnerability context."""

    model_config = ConfigDict(extra="forbid")

    endpoint: dict[str, Any] = Field(description="FAZ UEBA endpoint record, verbatim")
    vulnerabilities: list[dict[str, Any]] = Field(
        default_factory=list, description="CVE records attributed to this endpoint, verbatim"
    )
    vulnerability_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Vulnerability count per severity (lowercased), derived",
    )


class AssetLookupResult(BaseModel):
    """Output of the ``asset_lookup`` skill."""

    model_config = ConfigDict(extra="forbid")

    endpoints: list[AssetRecord]
    endpoint_count: int
    matched_total: int = Field(description="Endpoints matching the filters before the limit")
    unattributed_vulnerabilities: list[dict[str, Any]] = Field(
        default_factory=list,
        description="CVE records the reader returned without an attributable endpoint id",
    )
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# identity_lookup (Data Access)                                         #
# --------------------------------------------------------------------- #


class IdentityLookupParams(BaseModel):
    """Parameters for the ``identity_lookup`` skill."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    euids: list[int] | None = Field(
        default=None, description="End-user IDs to scope the query server-side"
    )
    username: str | None = Field(
        default=None, description="Case-insensitive substring match on the user name"
    )
    detail_level: Literal["basic", "standard", "extended"] = Field(
        default="standard", description='"extended" adds email/department/title/phone'
    )
    limit: int = Field(default=50, ge=1, le=500, description="Max users returned")


class IdentityLookupResult(BaseModel):
    """Output of the ``identity_lookup`` skill. Records are verbatim."""

    model_config = ConfigDict(extra="forbid")

    users: list[dict[str, Any]] = Field(description="FAZ UEBA end-user records, verbatim")
    user_count: int
    matched_total: int = Field(description="Users matching the filters before the limit")
    detail_level: str
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# alert_rules (Data Access)                                             #
# --------------------------------------------------------------------- #


class AlertRulesParams(BaseModel):
    """Parameters for the ``alert_rules`` skill."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    handler_type: Literal["basic", "correlation", "both"] = "both"
    name: str | None = Field(
        default=None, description="Case-insensitive substring match on the handler name"
    )
    limit: int = Field(default=100, ge=1, le=500, description="Max handlers returned")


class AlertRuleHandler(BaseModel):
    """One alert handler (detection rule set) with its class."""

    model_config = ConfigDict(extra="forbid")

    handler_class: Literal["basic", "correlation"]
    handler: dict[str, Any] = Field(description="FAZ alert-handler definition, verbatim")


class AlertRulesResult(BaseModel):
    """Output of the ``alert_rules`` skill."""

    model_config = ConfigDict(extra="forbid")

    handlers: list[AlertRuleHandler]
    handler_count: int
    matched_total: int = Field(description="Handlers matching the filters before the limit")
    rule_count: int = Field(description="Total rules across the returned handlers, derived")
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# triage (Analysis)                                                     #
# --------------------------------------------------------------------- #


class TriageParams(BaseModel):
    """Parameters for the ``triage`` skill. Exactly one subject required."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    alert_id: str | None = None
    incident_id: str | None = None
    context_time_range: str = Field(
        default="24-hour", description="Window for surrounding-activity context"
    )

    @model_validator(mode="after")
    def _exactly_one_subject(self) -> "TriageParams":
        if bool(self.alert_id) == bool(self.incident_id):
            raise ValueError('provide exactly one of "alert_id" or "incident_id"')
        return self


class TriageAssessment(BaseModel):
    """Deterministic, rule-derived assessment — no inference, no fabrication.

    ``priority`` maps 1:1 from the FAZ severity field (critical→urgent,
    high→high, medium→medium, low→low, other/absent→informational);
    ``basis`` lists every observation that fed the mapping so the
    assessment is fully auditable.
    """

    model_config = ConfigDict(extra="forbid")

    priority: Literal["urgent", "high", "medium", "low", "informational"]
    severity: str | None = Field(description="FAZ severity, verbatim")
    acknowledged: bool | None = Field(description="Alert ack state if known")
    basis: list[str] = Field(description="Observations the priority was derived from")


class TriageResult(BaseModel):
    """Output of the ``triage`` skill: an evidence bundle plus a
    deterministic assessment scaffold."""

    model_config = ConfigDict(extra="forbid")

    subject_type: Literal["alert", "incident"]
    subject: dict[str, Any] = Field(description="FAZ alert or incident object, verbatim")
    subject_details: dict[str, Any] | None = Field(
        default=None,
        description="Entity enrichment for an alert subject (devs/epids/euids from "
        "alerts/extra-details), verbatim; None for incident subjects",
    )
    triggering_logs: list[dict[str, Any]] = Field(
        default_factory=list, description="Logs attached to the subject alert, verbatim"
    )
    related: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Related objects (incidents for an alert; alerts for an incident), verbatim",
    )
    context_stats: dict[str, Any] | None = Field(
        default=None, description="Alert/incident stats for the context window, verbatim"
    )
    assessment: TriageAssessment
    enrichment: FeatureGap = Field(
        description="Indicator enrichment slot — unavailable until the Wave-2 SOAR reader"
    )
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# incident_summary (Analysis)                                       #
# --------------------------------------------------------------------- #


class IncidentSummaryParams(BaseModel):
    """Parameters for the ``incident_summary`` skill."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    incident_id: str
    time_range: str = Field(default="7-day", description="Window for related alerts and threats")
    max_alerts: int = Field(default=10, ge=1, le=50, description="Max related alerts included")
    max_logs_per_alert: int = Field(default=20, ge=1, le=100)
    include_top_threats: bool = Field(
        default=True, description="Include the FortiView threat landscape section"
    )


class AlertEvidence(BaseModel):
    """One related alert with its triggering logs."""

    model_config = ConfigDict(extra="forbid")

    alert: dict[str, Any]
    logs: list[dict[str, Any]] = Field(default_factory=list)


class TimelineEntry(BaseModel):
    """One dated observation, derived from timestamps present in the data."""

    model_config = ConfigDict(extra="forbid")

    timestamp: int | str
    source: Literal["incident", "alert"]
    description: str


class IncidentSummary(BaseModel):
    """Output of the ``incident_summary`` skill."""

    model_config = ConfigDict(extra="forbid")

    incident: dict[str, Any] = Field(description="FAZ incident object, verbatim")
    alerts: list[AlertEvidence] = Field(default_factory=list)
    threat_landscape: list[dict[str, Any]] | FeatureGap = Field(
        description="Top threats in the window, verbatim — or the gap marker"
    )
    timeline: list[TimelineEntry] = Field(
        default_factory=list,
        description="Chronological view derived from available timestamps (best-effort)",
    )
    counts: dict[str, int] = Field(description="alerts / evidence_logs totals")
    time_range: str
    warnings: list[str] = Field(default_factory=list)
