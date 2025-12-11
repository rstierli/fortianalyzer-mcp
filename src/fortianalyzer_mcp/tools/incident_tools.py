"""Incident management tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 Incident Management API specifications.
Provides incident creation, tracking, and SOC workflow operations.
"""

import logging
from datetime import datetime, timedelta
from typing import Any

from fortianalyzer_mcp.server import get_faz_client, mcp

logger = logging.getLogger(__name__)


def _get_client():
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


def _parse_time_range(time_range: str) -> dict[str, str]:
    """Parse time range string to API format."""
    now = datetime.now()
    fmt = "%Y-%m-%d %H:%M:%S"

    if "|" in time_range:
        parts = time_range.split("|")
        return {"start": parts[0].strip(), "end": parts[1].strip()}

    range_map = {
        "1-hour": timedelta(hours=1),
        "6-hour": timedelta(hours=6),
        "12-hour": timedelta(hours=12),
        "24-hour": timedelta(hours=24),
        "1-day": timedelta(days=1),
        "7-day": timedelta(days=7),
        "30-day": timedelta(days=30),
        "90-day": timedelta(days=90),
    }

    delta = range_map.get(time_range, timedelta(days=7))
    start = now - delta

    return {"start": start.strftime(fmt), "end": now.strftime(fmt)}


@mcp.tool()
async def get_incidents(
    adom: str = "root",
    time_range: str = "7-day",
    filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Get security incidents from FortiAnalyzer.

    Retrieves incidents from the incident management module.
    Incidents can be created manually or automatically from alerts.

    Args:
        adom: ADOM name (default: "root")
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
        client = _get_client()
        tr = _parse_time_range(time_range)

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
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_incident(
    incident_id: str,
    adom: str = "root",
) -> dict[str, Any]:
    """Get a specific incident by ID.

    Retrieves detailed information about a single incident.

    Args:
        incident_id: Incident ID to retrieve
        adom: ADOM name (default: "root")

    Returns:
        dict with incident details

    Example:
        >>> result = await get_incident("INC-001")
        >>> print(f"Incident: {result['data']['name']}")
    """
    try:
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
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_incident_count(
    adom: str = "root",
    time_range: str = "7-day",
    filter: str | None = None,
) -> dict[str, Any]:
    """Get count of incidents matching criteria.

    Args:
        adom: ADOM name (default: "root")
        time_range: Time range for incidents
        filter: Filter expression (optional)

    Returns:
        dict with incident count

    Example:
        >>> result = await get_incident_count(time_range="24-hour")
        >>> print(f"Total incidents: {result['data']['count']}")
    """
    try:
        client = _get_client()
        tr = _parse_time_range(time_range)

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
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def create_incident(
    name: str,
    severity: str,
    adom: str = "root",
    category: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    """Create a new security incident.

    Creates a manual incident for SOC tracking and investigation.

    Args:
        name: Incident name/title
        severity: Incident severity:
            - "critical": Critical severity
            - "high": High severity
            - "medium": Medium severity
            - "low": Low severity
        adom: ADOM name (default: "root")
        category: Incident category (optional)
        description: Detailed description (optional)

    Returns:
        dict with created incident details

    Example:
        >>> result = await create_incident(
        ...     name="Suspicious Login Activity",
        ...     severity="high",
        ...     description="Multiple failed login attempts detected"
        ... )
        >>> print(f"Created incident: {result['data']['id']}")
    """
    try:
        client = _get_client()

        logger.info(f"Creating incident '{name}' in ADOM {adom}")

        result = await client.create_incident(
            adom=adom,
            name=name,
            severity=severity,
            category=category,
            description=description,
        )

        return {
            "status": "success",
            "adom": adom,
            "name": name,
            "severity": severity,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to create incident: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def update_incident(
    incident_id: str,
    adom: str = "root",
    status: str | None = None,
    severity: str | None = None,
    assignee: str | None = None,
) -> dict[str, Any]:
    """Update an existing incident.

    Modifies incident properties for SOC workflow management.

    Args:
        incident_id: Incident ID to update
        adom: ADOM name (default: "root")
        status: New status (optional):
            - "new": New incident
            - "investigating": Under investigation
            - "contained": Threat contained
            - "resolved": Incident resolved
            - "closed": Incident closed
        severity: New severity (optional)
        assignee: Assign to user (optional)

    Returns:
        dict with update result

    Example:
        >>> result = await update_incident(
        ...     incident_id="INC-001",
        ...     status="investigating",
        ...     assignee="analyst1"
        ... )
    """
    try:
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
    except Exception as e:
        logger.error(f"Failed to update incident {incident_id}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_incident_stats(
    adom: str = "root",
    time_range: str = "30-day",
    stats_items: list[str] | None = None,
) -> dict[str, Any]:
    """Get incident statistics.

    Retrieves aggregated statistics for SOC dashboards
    including counts by severity, status, and trends.

    Args:
        adom: ADOM name (default: "root")
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
        client = _get_client()
        tr = _parse_time_range(time_range)

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
        return {"status": "error", "message": str(e)}
