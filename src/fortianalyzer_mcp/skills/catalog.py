"""Skill catalogue: the dispatcher's registry of available skills.

Each entry binds a skill id to its tier, description, parameter model,
output model, and handler. Adding a skill is adding an entry here (plus
its models/handler) — the tool surface never grows.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.models import (
    AlertRulesParams,
    AlertRulesResult,
    AssetLookupParams,
    AssetLookupResult,
    IdentityLookupParams,
    IdentityLookupResult,
    IncidentsParams,
    IncidentsResult,
    IncidentSummary,
    IncidentSummaryParams,
    LogSearchParams,
    LogSearchResult,
    ReportsParams,
    ReportsResult,
    TriageParams,
    TriageResult,
)


@dataclass(frozen=True)
class SkillSpec:
    """One skill's contract and implementation."""

    id: str
    tier: str  # "data_access" | "enrichment" | "analysis"
    description: str
    params_model: type[BaseModel]
    output_model: type[BaseModel]
    handler: Callable[[Any], Awaitable[BaseModel]]


SKILLS: dict[str, SkillSpec] = {
    spec.id: spec
    for spec in (
        SkillSpec(
            id="incidents",
            tier="data_access",
            description="Security incidents in a time window, each with "
            "best-effort correlated alerts.",
            params_model=IncidentsParams,
            output_model=IncidentsResult,
            handler=handlers.run_incidents,
        ),
        SkillSpec(
            id="reports",
            tier="data_access",
            description="List generated reports, or fetch one report by task ID "
            "in PDF/HTML/CSV/XML.",
            params_model=ReportsParams,
            output_model=ReportsResult,
            handler=handlers.run_reports,
        ),
        SkillSpec(
            id="log_search",
            tier="data_access",
            description="Filter-based log search returning verbatim log rows "
            "(one slot-bounded search).",
            params_model=LogSearchParams,
            output_model=LogSearchResult,
            handler=handlers.run_log_search,
        ),
        SkillSpec(
            id="asset_lookup",
            tier="data_access",
            description="Endpoint (asset) profiles from the UEBA inventory, each "
            "with attributed CVE records and severity counts. Requires UEBA.",
            params_model=AssetLookupParams,
            output_model=AssetLookupResult,
            handler=handlers.run_asset_lookup,
        ),
        SkillSpec(
            id="identity_lookup",
            tier="data_access",
            description="End-user identity records from the UEBA directory "
            "(groups, VPN IP, seen window; extended adds contact fields). "
            "Requires UEBA.",
            params_model=IdentityLookupParams,
            output_model=IdentityLookupResult,
            handler=handlers.run_identity_lookup,
        ),
        SkillSpec(
            id="alert_rules",
            tier="data_access",
            description="The appliance's detection-rule catalogue: basic and "
            "correlation alert handlers with their per-rule severity, filters, "
            "groupby and tags.",
            params_model=AlertRulesParams,
            output_model=AlertRulesResult,
            handler=handlers.run_alert_rules,
        ),
        SkillSpec(
            id="triage",
            tier="analysis",
            description="Rapid triage of one alert or incident: subject, triggering "
            "logs, related objects, context stats, and a deterministic "
            "severity-derived assessment.",
            params_model=TriageParams,
            output_model=TriageResult,
            handler=handlers.run_triage,
        ),
        SkillSpec(
            id="incident_summary",
            tier="analysis",
            description="Structured investigation summary for one incident: related "
            "alerts with evidence logs, threat landscape, and a derived timeline.",
            params_model=IncidentSummaryParams,
            output_model=IncidentSummary,
            handler=handlers.run_incident_summary,
        ),
    )
}


def catalogue() -> list[dict[str, Any]]:
    """Machine-readable skill catalogue (the ``skill="list"`` response)."""
    return [
        {
            "id": spec.id,
            "tier": spec.tier,
            "description": spec.description,
            "params_schema": spec.params_model.model_json_schema(),
            "output_schema": spec.output_model.model_json_schema(),
        }
        for spec in SKILLS.values()
    ]
