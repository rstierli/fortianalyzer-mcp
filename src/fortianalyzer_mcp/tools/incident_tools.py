"""Incident management tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 Incident Management API specifications.
Provides incident creation, tracking, and SOC workflow operations.
"""

import logging
from typing import Any

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.responses import redact
from fortianalyzer_mcp.utils.time_range import parse_time_range
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    get_default_adom,
    validate_adom,
    validate_incident_id,
    validate_severity,
)

# FAZ incident workflow states, from the incidentmgmt spec enum. Verified
# live on 7.6.7 and 8.0.0: the appliance rejects anything else with
# "not a valid enum value for 'status'".
_VALID_INCIDENT_STATUSES = {"draft", "analysis", "response", "closed", "cancelled"}

# The incident spec's severity enum is narrower than the shared
# VALID_SEVERITIES set (no "critical", no "info").
_VALID_INCIDENT_SEVERITIES = {"high", "medium", "low"}

logger = logging.getLogger(__name__)


def _get_client() -> FortiAnalyzerClient:
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


async def _parse_time_range(time_range: str) -> dict[str, str]:
    """Parse time range using FAZ system TZ for alignment.

    Custom absolute ranges (``"start|end"``) skip the TZ lookup since
    the caller is already supplying explicit timestamps. Relative
    presets pull the cached FAZ timezone off the client so naive
    timestamps land in FAZ's local TZ.
    """
    if "|" in time_range:
        return parse_time_range(time_range)
    client = _get_client()
    faz_tz = await client.get_system_timezone()
    return parse_time_range(time_range, faz_tz=faz_tz)


@mcp.tool()
async def get_incidents(
    adom: str | None = None,
    time_range: str = "7-day",
    filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Get security incidents from FortiAnalyzer.

    Retrieves incidents from the incident management module.
    Incidents can be created manually or automatically from alerts.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        time_range: Time range for incidents. Options:
            - "1-hour", "6-hour", "12-hour", "24-hour"
            - "1-day", "7-day", "30-day", "90-day"
            - Custom: "2024-01-01 00:00:00|2024-01-02 00:00:00"
        filter: Filter expression (e.g., "severity==critical")
        limit: Maximum number of incidents to return (1-2000)
        offset: Record offset for pagination

    Returns:
        dict with incidents data

    Example:
        >>> result = await get_incidents(time_range="24-hour", limit=50)
        >>> print(f"Found {result.get('count', 0)} incidents")
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        # Enforce the documented 1-2000 range and non-negative offset.
        limit = max(1, min(limit, 2000))
        offset = max(0, offset)
        client = _get_client()
        tr = await _parse_time_range(time_range)

        logger.info(f"Getting incidents from ADOM {adom}")

        result = await client.get_incidents(
            adom=adom,
            time_range=tr,
            filter=filter,
            limit=limit,
            offset=offset,
        )

        data = result.get("data", []) if isinstance(result, dict) else result
        if not isinstance(data, list):
            data = [data] if data else []

        return {
            "status": "success",
            "adom": adom,
            "time_range": tr,
            "count": len(data),
            "data": data,
        }
    except Exception as e:
        logger.error(f"Failed to get incidents: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool()
async def get_incident(
    incident_id: str,
    adom: str | None = None,
) -> dict[str, Any]:
    """Get a specific incident by ID.

    Retrieves detailed information about a single incident.

    Args:
        incident_id: Incident ID to retrieve
        adom: ADOM name (default: from config DEFAULT_ADOM)

    Returns:
        dict with incident details

    Example:
        >>> result = await get_incident("INC-001")
        >>> print(f"Incident: {result['data']['name']}")
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        incident_id = validate_incident_id(incident_id)
        client = _get_client()

        logger.info(f"Getting incident {incident_id} from ADOM {adom}")

        result = await client.get_incident(
            adom=adom,
            incident_id=incident_id,
        )

        return {
            "status": "success",
            "adom": adom,
            "incident_id": incident_id,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get incident {incident_id}: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool()
async def get_incident_count(
    adom: str | None = None,
    time_range: str = "7-day",
    filter: str | None = None,
) -> dict[str, Any]:
    """Get count of incidents matching criteria.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        time_range: Time range for incidents
        filter: Filter expression (optional)

    Returns:
        dict with incident count

    Example:
        >>> result = await get_incident_count(time_range="24-hour")
        >>> print(f"Total incidents: {result['data']['count']}")
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        client = _get_client()
        tr = await _parse_time_range(time_range)

        logger.info(f"Getting incident count from ADOM {adom}")

        result = await client.get_incidents_count(
            adom=adom,
            time_range=tr,
            filter=filter,
        )

        return {
            "status": "success",
            "adom": adom,
            "time_range": tr,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get incident count: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool()
async def create_incident(
    endpoint: str,
    category: str,
    severity: str = "medium",
    adom: str | None = None,
    status: str | None = None,
    description: str | None = None,
    reporter: str = "faz-mcp",
    name: str | None = None,
    epid: int | None = None,
    euid: int | None = None,
) -> dict[str, Any]:
    """Create a new security incident.

    Creates a manual incident for SOC tracking and investigation.

    Args:
        endpoint: What the incident is about - an endpoint name or a
            plain IP address. Required by the FAZ API.
        category: FAZ incident category value. Required by the FAZ API.
            The valid set is defined on the appliance (numeric strings
            like "1"), not by the API spec, so it is passed through
            unvalidated.
        severity: Incident severity: "high", "medium" or "low"
            (default: "medium").
        adom: ADOM name (default: from config DEFAULT_ADOM)
        status: Initial workflow status (optional): "draft", "analysis",
            "response", "closed" or "cancelled".
        description: Detailed description (optional)
        reporter: Reporting user recorded on the incident
            (default: "faz-mcp").
        name: Incident name/title (optional). Not in the API spec, but
            the appliance persists it on the incident record.
        epid: Endpoint ID, for the UEBA tie-in (optional).
        euid: Enduser ID, for the UEBA tie-in (optional).

    Returns:
        dict with created incident details. The FAZ response carries the
        new incident id at the top level of "data" (as "incid").

    Example:
        >>> result = await create_incident(
        ...     endpoint="192.0.2.10",
        ...     category="1",
        ...     severity="high",
        ...     description="Multiple failed login attempts detected",
        ... )
        >>> print(f"Created incident: {result['data']['incid']}")
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        severity = validate_severity(severity)
        if severity not in _VALID_INCIDENT_SEVERITIES:
            valid = ", ".join(sorted(_VALID_INCIDENT_SEVERITIES))
            return {
                "status": "error",
                "message": f"Validation error: Invalid severity '{severity}' for an "
                f"incident. Must be one of: {valid}",
            }
        if status is not None:
            status = status.strip().lower()
            if status not in _VALID_INCIDENT_STATUSES:
                valid = ", ".join(sorted(_VALID_INCIDENT_STATUSES))
                return {
                    "status": "error",
                    "message": f"Validation error: Invalid status '{status}'. "
                    f"Must be one of: {valid}",
                }
        client = _get_client()

        logger.info(f"Creating incident in ADOM {adom}")

        result = await client.create_incident(
            adom=adom,
            endpoint=endpoint,
            category=category,
            reporter=reporter,
            severity=severity,
            status=status,
            description=description,
            epid=epid,
            euid=euid,
            name=name,
        )

        return {
            "status": "success",
            "adom": adom,
            "endpoint": endpoint,
            "severity": severity,
            "data": result,
        }
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to create incident: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool()
async def update_incident(
    incident_id: str,
    adom: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    assignee: str | None = None,
) -> dict[str, Any]:
    """Update an existing incident.

    Modifies incident properties for SOC workflow management.

    Args:
        incident_id: Incident ID to update
        adom: ADOM name (default: from config DEFAULT_ADOM)
        status: New status (optional):
            - "draft": Draft incident
            - "analysis": Under analysis
            - "response": In response
            - "closed": Incident closed
            - "cancelled": Incident cancelled
        severity: New severity (optional)
        assignee: Assign to user (optional)

    Returns:
        dict with update result

    Example:
        >>> result = await update_incident(
        ...     incident_id="INC-001",
        ...     status="analysis",
        ...     assignee="analyst1"
        ... )
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        incident_id = validate_incident_id(incident_id)
        if severity is not None:
            severity = validate_severity(severity)
        if status is not None and status.lower() not in _VALID_INCIDENT_STATUSES:
            valid = ", ".join(sorted(_VALID_INCIDENT_STATUSES))
            return {
                "status": "error",
                "message": f"Validation error: Invalid status '{status}'. Must be one of: {valid}",
            }
        client = _get_client()

        logger.info(f"Updating incident {incident_id} in ADOM {adom}")

        result = await client.update_incident(
            adom=adom,
            incident_id=incident_id,
            status=status,
            severity=severity,
            assignee=assignee,
        )

        return {
            "status": "success",
            "adom": adom,
            "incident_id": incident_id,
            "data": result,
        }
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to update incident {incident_id}: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool()
async def get_incident_stats(
    adom: str | None = None,
    time_range: str = "30-day",
    stats_items: list[str] | None = None,
) -> dict[str, Any]:
    """Get incident statistics.

    Retrieves aggregated statistics for SOC dashboards
    including counts by severity, status, and trends.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        time_range: Time range for statistics (default: "30-day")
        stats_items: List of stats to retrieve. Options:
            - "total": Total incident count
            - "severity": Counts by severity (high/medium/low)
            - "category": Counts by category
            - "status": Counts by status
            - "outbreak": Outbreak incidents
            Default: ["total", "severity", "status"]

    Returns:
        dict with incident statistics

    Example:
        >>> result = await get_incident_stats(time_range="7-day")
        >>> print(f"High severity: {result['data']['severity']['high']}")
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        client = _get_client()
        tr = await _parse_time_range(time_range)

        logger.info(f"Getting incident stats from ADOM {adom}")

        result = await client.get_incident_stats(
            adom=adom,
            time_range=tr,
            stats_items=stats_items,
        )

        return {
            "status": "success",
            "adom": adom,
            "time_range": tr,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get incident stats: {e}")
        return {"status": "error", "message": redact(str(e))}
