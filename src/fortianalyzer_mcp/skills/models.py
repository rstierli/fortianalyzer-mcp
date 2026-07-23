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


# --------------------------------------------------------------------- #
# threat_intel (Enrichment)                                             #
# --------------------------------------------------------------------- #


class IndicatorSpec(BaseModel):
    """One explicit indicator to enrich."""

    model_config = ConfigDict(extra="forbid")

    value: str = Field(description="The indicator value (an IP, URL or domain)")
    type: Literal["IP", "URL", "Domain"]


class ThreatIntelParams(BaseModel):
    """Parameters for the ``threat_intel`` skill.

    Subjects come from ``indicators`` (explicit) and/or from the SOAR
    indicators linked to ``alert_id``/``incident_id`` (resolved); at
    least one source is required, and both may be combined (the union is
    enriched, de-duplicated).
    """

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    indicators: list[IndicatorSpec] | None = Field(
        default=None, description="Explicit indicators to enrich (IP/URL/Domain)"
    )
    alert_id: str | None = Field(
        default=None, description="Resolve and enrich the indicators linked to this alert"
    )
    incident_id: str | None = Field(
        default=None, description="Resolve and enrich the indicators linked to this incident"
    )
    detail_level: Literal["standard", "extended"] = Field(
        default="standard",
        description='"extended" attaches the raw enrichment-detail from the reputation source',
    )
    time_range: str | None = Field(
        default=None,
        description='Optional window ("7-day" or "start|end") for the linked-indicator '
        "and enrichment lookups; omit to search all time (SOAR otherwise drops "
        "indicators older than 7 days). The threat-landscape context uses this window "
        'too ("24-hour" when omitted).',
    )
    include_threat_landscape: bool = Field(
        default=True, description="Include the FortiView top-threats context section"
    )

    @model_validator(mode="after")
    def _subject_sources(self) -> "ThreatIntelParams":
        if not self.indicators and not self.alert_id and not self.incident_id:
            raise ValueError('provide "indicators", "alert_id" or "incident_id"')
        if self.alert_id and self.incident_id:
            raise ValueError('provide at most one of "alert_id" or "incident_id"')
        return self


class EnrichmentSource(BaseModel):
    """One reputation engine's verdict, normalized from the raw detail.

    FortiGuard and VirusTotal (and any other configured connector) each
    report in their own shape; this flattens the signal a SOC analyst
    reads first — the source name, its category/verdict, confidence, and a
    link to the source's own page. Extra fields vary by engine (e.g.
    VirusTotal's per-vendor ``categories`` and community ``votes``), so
    unknown keys are allowed. The verbatim per-source payload always
    remains under ``record['enrichment-detail']``.
    """

    model_config = ConfigDict(extra="allow")

    source: str = Field(description="Reputation engine, e.g. 'FortiGuard-CTS' or 'VirusTotal'")
    verdict: str | None = Field(
        default=None, description="This engine's category/verdict for the indicator"
    )
    confidence: str | int | None = Field(default=None, description="This engine's confidence")
    link: str | None = Field(default=None, description="URL to this engine's own report")


class IndicatorEnrichmentRecord(BaseModel):
    """One indicator with its stored SOAR reputation.

    ``reputation``/``confidence``/``status`` are verbatim convenience
    copies of the row's ``enrichment-*`` fields (FAZ's fused verdict across
    engines); ``sources`` breaks that verdict down per reputation engine
    (populated only at ``detail_level='extended'``, where the raw per-source
    detail is fetched); ``record`` is the full matched indicator row. The
    reputation fields are ``None`` (and ``record`` is ``None``) when the
    lookup failed or SOAR holds no row for the value — the accompanying
    warning names which.
    """

    model_config = ConfigDict(extra="forbid")

    value: str
    type: str
    reputation: str | None = Field(
        default=None,
        description="FAZ fused 'enrichment-reputation', verbatim "
        "(Good/Suspicious/Malicious/NoReputationAvailable)",
    )
    confidence: int | str | None = Field(
        default=None, description="Fused 'enrichment-confidence' (0-100), verbatim"
    )
    status: str | None = Field(default=None, description="'enrichment-status', verbatim")
    sources: list[EnrichmentSource] = Field(
        default_factory=list,
        description="Per-engine verdict breakdown (extended detail only; empty otherwise)",
    )
    record: dict[str, Any] | None = Field(
        default=None,
        description="Matched FAZ indicator row, verbatim (uuids; plus "
        "'enrichment-detail' at detail_level='extended')",
    )


class ThreatIntelResult(BaseModel):
    """Output of the ``threat_intel`` skill.

    Honest caveat: this reads *stored* SOAR enrichment only — it never
    triggers a new reputation lookup. An indicator FAZ has not yet
    enriched comes back with reputation ``NoReputationAvailable`` or with
    no matched row at all; that means "not looked up", not "clean".
    """

    model_config = ConfigDict(extra="forbid")

    indicators: list[IndicatorEnrichmentRecord]
    indicator_count: int
    threat_landscape: list[dict[str, Any]] | FeatureGap = Field(
        description="Top threats in the window, verbatim — or the gap marker"
    )
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# identity_profile (Enrichment)                                         #
# --------------------------------------------------------------------- #


class IdentityProfileParams(BaseModel):
    """Parameters for the ``identity_profile`` skill. Exactly one of
    ``euid`` or ``username`` identifies the user."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    euid: int | None = Field(default=None, description="End-user ID (scoped server-side)")
    username: str | None = Field(
        default=None,
        description="Case-insensitive EXACT match on the user name ('euname'); "
        "use the identity_lookup skill for substring discovery",
    )
    detail_level: Literal["basic", "standard", "extended"] = Field(
        default="standard",
        description='Detail for the user record; "extended" adds contact fields',
    )
    time_range: str = Field(default="24-hour", description="Window for the recent-activity search")
    activity_limit: int = Field(
        default=100, ge=1, le=1000, description="Max activity log rows returned"
    )
    include_endpoints: bool = Field(
        default=True, description="Attach the user's associated endpoints"
    )
    include_activity: bool = Field(
        default=True,
        description="Attach recent auth-failure/VPN event logs (consumes one logview search slot)",
    )

    @model_validator(mode="after")
    def _exactly_one_identifier(self) -> "IdentityProfileParams":
        if (self.euid is None) == (self.username is None):
            raise ValueError('provide exactly one of "euid" or "username"')
        return self


class IdentityProfileResult(BaseModel):
    """Output of the ``identity_profile`` skill."""

    model_config = ConfigDict(extra="forbid")

    user: dict[str, Any] = Field(description="FAZ UEBA end-user record, verbatim")
    endpoints: list[dict[str, Any]] = Field(
        default_factory=list,
        description="UEBA endpoint records whose 'user' association list names this user, verbatim",
    )
    recent_activity: list[dict[str, Any]] | FeatureGap = Field(
        description="Auth-failure / VPN event-log rows for the user in the "
        "window, verbatim — or the gap marker"
    )
    counts: dict[str, int] = Field(description="endpoints / activity_rows totals")
    time_range: str
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# app_usage (Enrichment)                                                #
# --------------------------------------------------------------------- #


class AppUsageParams(BaseModel):
    """Parameters for the ``app_usage`` skill."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    time_range: str = Field(
        default="24-hour",
        description='Preset ("1-hour".."30-day") or custom "start|end"',
    )
    device: str | None = Field(
        default=None,
        description="Device filter (serial number or name), forwarded to every section",
    )
    top_limit: int = Field(
        default=20, ge=1, le=100, description="Top-N size for each FortiView section"
    )
    include_dlp: bool = Field(
        default=True,
        description="Include the DLP events section (the skill's only slot-bounded log search)",
    )
    dlp_limit: int = Field(default=100, ge=1, le=1000, description="Max DLP events returned")


class AppUsageResult(BaseModel):
    """Output of the ``app_usage`` skill.

    A context bundle with no single subject: every section is best-effort
    and degrades independently to a ``FeatureGap``, so a partial result is
    still a success. Rows are verbatim FAZ records.
    """

    model_config = ConfigDict(extra="forbid")

    applications: list[dict[str, Any]] | FeatureGap = Field(
        description="Top applications in the window, verbatim — or the gap marker"
    )
    websites: list[dict[str, Any]] | FeatureGap = Field(
        description="Top websites in the window, verbatim — or the gap marker"
    )
    cloud_applications: list[dict[str, Any]] | FeatureGap = Field(
        description="Top cloud/SaaS applications (shadow-IT signal), verbatim — or the gap marker"
    )
    dlp_events: list[dict[str, Any]] | FeatureGap = Field(
        description="DLP log rows in the window, verbatim — or the gap marker"
    )
    counts: dict[str, int] = Field(description="Row count per section (0 for gap sections)")
    time_range: str
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# network_context (Enrichment)                                          #
# --------------------------------------------------------------------- #


class NetworkContextParams(BaseModel):
    """Parameters for the ``network_context`` skill."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    time_range: str = Field(
        default="24-hour",
        description='Preset ("1-hour".."30-day") or custom "start|end"',
    )
    vpn_time_range: str | None = Field(
        default=None,
        description="Window for the VPN section only. The site-to-site IPsec "
        "FortiView is session-bucketed, so long-lived tunnels only appear over "
        "a wide lookback; when unset the section is floored to 90-day "
        "independent of time_range.",
    )
    device: str | None = Field(
        default=None, description="Device filter (name or serial), forwarded to every read"
    )
    top_limit: int = Field(default=20, ge=1, le=100, description="Max rows per section")
    include_geo: bool = Field(default=True, description="Include the top-countries (geo) section")
    include_vpn: bool = Field(default=True, description="Include the IPsec VPN tunnel section")


class NetworkContextResult(BaseModel):
    """Output of the ``network_context`` skill. Rows are verbatim FortiView rows."""

    model_config = ConfigDict(extra="forbid")

    top_destinations: list[dict[str, Any]] | FeatureGap = Field(
        description="Top destination IPs in the window, verbatim — or the gap marker"
    )
    top_sources: list[dict[str, Any]] | FeatureGap = Field(
        description="Top source IPs in the window, verbatim — or the gap marker"
    )
    top_countries: list[dict[str, Any]] | FeatureGap = Field(
        description="Top destination countries (geo), verbatim — or the gap marker"
    )
    vpn_tunnels: list[dict[str, Any]] | FeatureGap = Field(
        description="Site-to-site IPsec tunnel rows, verbatim — or the gap marker"
    )
    counts: dict[str, int] = Field(description="Rows per section (0 for a gap section)")
    time_range: str
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# risk_assessment (Enrichment)                                          #
# --------------------------------------------------------------------- #


class RiskAssessmentParams(BaseModel):
    """Parameters for the ``risk_assessment`` skill. Exactly one entity required."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    epid: int | None = Field(default=None, description="UEBA endpoint ID to score")
    euid: int | None = Field(default=None, description="UEBA end-user ID to score")
    time_range: str = Field(
        default="7-day", description="Window for the threat and auth-failure dimensions"
    )
    detectby: Literal["FortiClient", "FortiGate"] | None = Field(
        default=None, description="Vulnerability detector filter, forwarded to the CVE reader"
    )

    @model_validator(mode="after")
    def _exactly_one_entity(self) -> "RiskAssessmentParams":
        if (self.epid is None) == (self.euid is None):
            raise ValueError('provide exactly one of "epid" or "euid"')
        return self


class RiskDimension(BaseModel):
    """One scored risk dimension: raw inputs, normalized subscore, weight.

    ``raw_counts`` holds the exact inputs the subscore was computed from
    (severity counts, or ``{"failures": n}``). It is empty when the
    dimension's read was unavailable — that case is always named in the
    result's ``warnings``, so an empty read is distinguishable from a
    genuine zero.
    """

    model_config = ConfigDict(extra="forbid")

    raw_counts: dict[str, int] = Field(
        description="Raw inputs behind the subscore (empty when the read was unavailable)"
    )
    subscore: int = Field(ge=0, le=100, description="Normalized 0-100 dimension score")
    weight: float = Field(description="This dimension's weight in the composite")


class RiskAssessmentResult(BaseModel):
    """Output of the ``risk_assessment`` skill — a fully auditable score.

    Formula (deterministic, no inference; weights are the module-level
    constants ``_W_VULN``/``_W_THREAT``/``_W_AUTH`` in ``handlers``):

    - vulnerability = min(100, critical*25 + high*10 + medium*3 + low*1)
      over CVE severity counts for the entity's endpoint(s)
    - threat = min(100, critical*25 + high*10 + medium*3) over threat
      detections tied to the entity in the window
    - auth_failure = min(100, failures*5) over event-log auth failures
      (``action==failure``) tied to the entity in the window
    - composite_score = round(0.40*vulnerability + 0.35*threat
      + 0.25*auth_failure)
    - band: 0-24 "low", 25-49 "medium", 50-74 "high", 75-100 "critical"

    Severity labels are matched case-insensitively; labels outside the
    scoring table still appear in ``raw_counts`` but contribute 0 points.
    A dimension whose read failed scores 0 **and is named in warnings** —
    the composite then covers only the available dimensions and is never
    silently presented as complete.
    """

    model_config = ConfigDict(extra="forbid")

    entity: dict[str, Any] = Field(
        description="The scored entity: type, id, and the verbatim UEBA record"
    )
    vulnerability: RiskDimension
    threat: RiskDimension
    auth_failure: RiskDimension
    composite_score: int = Field(ge=0, le=100, description="Weighted composite, rounded")
    band: Literal["low", "medium", "high", "critical"]
    time_range: str
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- #
# investigate (Analysis)                                                #
# --------------------------------------------------------------------- #


class InvestigateParams(BaseModel):
    """Parameters for the ``investigate`` skill. Exactly one subject required."""

    model_config = ConfigDict(extra="forbid")

    adom: str | None = None
    alert_id: str | None = None
    incident_id: str | None = None
    time_range: str = Field(
        default="7-day",
        description="Window for the summary, indicator and threat-landscape "
        "sections (and the triage surrounding-activity context)",
    )
    detail_level: Literal["standard", "extended"] = Field(
        default="standard",
        description="Indicator-enrichment detail, passed through to the threat_intel composition",
    )
    include_threat_landscape: bool = Field(
        default=True, description="Include the FortiView top-threats context section"
    )
    include_entities: bool = Field(
        default=True,
        description="Attach UEBA asset/identity context for endpoint/user ids "
        "carried by the subject",
    )

    @model_validator(mode="after")
    def _exactly_one_subject(self) -> "InvestigateParams":
        if bool(self.alert_id) == bool(self.incident_id):
            raise ValueError('provide exactly one of "alert_id" or "incident_id"')
        return self


class Investigation(BaseModel):
    """Output of the ``investigate`` skill — one consolidated analyst view.

    Pure composition: every section is the validated output of an existing
    skill (triage / incident_summary / threat_intel / asset_lookup /
    identity_lookup), nested by reference — no fields are renamed or
    re-shaped. ``triage`` is the subject section and the skill's only hard
    fail; every other section degrades independently to a ``FeatureGap``.
    Each nested result keeps its own ``warnings``; the top-level
    ``warnings`` list aggregates them all with a section prefix. The nested
    triage result's ``enrichment`` slot stays a gap by design — this
    skill's ``threat_intel`` section is its Wave-2 replacement.
    """

    model_config = ConfigDict(extra="forbid")

    subject_type: Literal["alert", "incident"]
    headline: str = Field(
        description="Deterministic one-line rollup (mapped priority plus "
        "per-section counts) — derived, no inference"
    )
    triage: TriageResult = Field(
        description="Evidence bundle + deterministic assessment for the subject"
    )
    summary: IncidentSummary | FeatureGap = Field(
        description="Deep summary of the subject incident (or the incident the "
        "alert is attached to) — or the gap marker"
    )
    threat_intel: ThreatIntelResult | FeatureGap = Field(
        description="Reputation enrichment of the subject's linked indicators, "
        "with the threat-landscape context — or the gap marker"
    )
    assets: AssetLookupResult | FeatureGap = Field(
        description="UEBA asset profiles for endpoint ids carried by the "
        "subject — or the gap marker"
    )
    identities: IdentityLookupResult | FeatureGap = Field(
        description="UEBA identity records for end-user ids carried by the "
        "subject — or the gap marker"
    )
    time_range: str
    warnings: list[str] = Field(default_factory=list)
