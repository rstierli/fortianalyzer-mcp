"""FortiView analytics tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 FortiView API specifications.
Provides network visibility, threat analysis, and traffic analytics using TID-based workflow.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any

from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    validate_adom,
    validate_fortiview_view,
)

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
        "now": timedelta(minutes=5),
        "5-min": timedelta(minutes=5),
        "15-min": timedelta(minutes=15),
        "1-hour": timedelta(hours=1),
        "6-hour": timedelta(hours=6),
        "12-hour": timedelta(hours=12),
        "24-hour": timedelta(hours=24),
        "1-day": timedelta(days=1),
        "7-day": timedelta(days=7),
        "30-day": timedelta(days=30),
    }

    delta = range_map.get(time_range, timedelta(hours=1))
    start = now - delta

    return {"start": start.strftime(fmt), "end": now.strftime(fmt)}


@mcp.tool()
async def run_fortiview(
    view_name: str,
    adom: str = "root",
    device: str | None = None,
    time_range: str = "1-hour",
    filter: str | None = None,
    limit: int = 20,
    offset: int = 0,
    sort_by: str | None = None,
    sort_order: str = "desc",
) -> dict[str, Any]:
    """Start a FortiView analytics query.

    FortiView provides real-time visibility and analytics dashboards.
    This starts an async query and returns a TID for fetching results.

    Args:
        view_name: FortiView view type. Options:
            - "top-sources": Top traffic sources by IP
            - "top-destinations": Top traffic destinations
            - "top-applications": Top applications by bandwidth
            - "top-websites": Top websites accessed
            - "top-threats": Top security threats detected
            - "top-cloud-applications": Top cloud/SaaS apps
            - "policy-hits": Per-policy hit counts (recommended)
            - "policy-line": Time-series policy data
            - "traffic-summary": Overall traffic summary
            - "fortiview-traffic": Detailed traffic view
            - "fortiview-threats": Threat analysis view
        adom: ADOM name (default: "root")
        device: Device filter (serial number or name, optional)
        time_range: Time range. Options:
            - "now", "5-min", "15-min": Real-time
            - "1-hour", "6-hour", "12-hour", "24-hour"
            - "1-day", "7-day", "30-day"
            - Custom: "2024-01-01 00:00:00|2024-01-02 00:00:00"
        filter: Filter expression (optional). Examples:
            - "srcintf!=wan1" - Exclude specific interface
            - "bandwidth>0" - Only entries with bandwidth
        limit: Maximum results (default: 20)
        offset: Record offset for pagination
        sort_by: Sort field (optional). Common fields:
            - "bandwidth": Sort by total bytes (traffic_in + traffic_out)
            - "counts": Sort by hit count
            - "threatweight": Sort by threat score
        sort_order: Sort order "asc" or "desc" (default: "desc")

    Returns:
        dict with TID for fetching results

    Example:
        >>> result = await run_fortiview("top-sources", time_range="24-hour", sort_by="bandwidth")
        >>> tid = result["tid"]
        >>> # Use fetch_fortiview to get results
    """
    try:
        # Validate inputs
        adom = validate_adom(adom)
        view_name = validate_fortiview_view(view_name)

        client = _get_client()
        tr = _parse_time_range(time_range)

        # Convert device string to API format
        device_filter = [{"devname": device}] if device else [{"devname": "All_Device"}]

        # Build sort_by parameter in API format: [{"field": "...", "order": "..."}]
        sort_by_param = None
        if sort_by:
            sort_by_param = [{"field": sort_by, "order": sort_order}]

        logger.info(f"Starting FortiView query: {view_name} in ADOM {adom}")

        result = await client.fortiview_run(
            adom=adom,
            view_name=view_name,
            device=device_filter,
            time_range=tr,
            filter=filter,
            limit=limit,
            offset=offset,
            sort_by=sort_by_param,
        )

        tid = result.get("tid") if isinstance(result, dict) else None

        return {
            "status": "success",
            "tid": tid,
            "view_name": view_name,
            "adom": adom,
            "time_range": tr,
        }
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to start FortiView query: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def fetch_fortiview(
    tid: int,
    view_name: str,
    adom: str = "root",
) -> dict[str, Any]:
    """Fetch FortiView query results by TID.

    Retrieves results from a previously started FortiView query.

    Args:
        tid: Task ID from run_fortiview
        view_name: Same view name used in run_fortiview
        adom: ADOM name (default: "root")

    Returns:
        dict with FortiView analytics data

    Example:
        >>> result = await fetch_fortiview(tid=12345, view_name="top-sources")
        >>> for item in result["data"]:
        ...     print(f"{item['srcip']}: {item['bytes']} bytes")
    """
    try:
        client = _get_client()

        logger.info(f"Fetching FortiView results for TID {tid}")

        result = await client.fortiview_fetch(
            adom=adom,
            view_name=view_name,
            tid=tid,
        )

        data = result.get("data", []) if isinstance(result, dict) else result
        if not isinstance(data, list):
            data = [data] if data else []

        return {
            "status": "success",
            "tid": tid,
            "view_name": view_name,
            "count": len(data),
            "data": data,
        }
    except Exception as e:
        logger.error(f"Failed to fetch FortiView results: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_fortiview_data(
    view_name: str,
    adom: str = "root",
    device: str | None = None,
    time_range: str = "1-hour",
    filter: str | None = None,
    limit: int = 20,
    timeout: int = 30,
    sort_by: str | None = None,
    sort_order: str = "desc",
) -> dict[str, Any]:
    """Get FortiView data with automatic TID handling.

    Convenience function that runs FortiView query and waits for results.
    Handles the two-step TID workflow automatically.

    Args:
        view_name: FortiView view type (see run_fortiview for options)
        adom: ADOM name (default: "root")
        device: Device filter (serial number or name, optional)
        time_range: Time range (default: "1-hour")
        filter: Filter expression (optional). Examples:
            - "srcintf!=wan1" - Exclude specific interface
            - "bandwidth>0" - Only entries with bandwidth
        limit: Maximum results (default: 20)
        timeout: Maximum wait time in seconds (default: 30)
        sort_by: Sort field (optional). Common fields:
            - "bandwidth": Sort by total bytes
            - "sessions": Sort by session count
            - "threatweight": Sort by threat score
        sort_order: Sort order "asc" or "desc" (default: "desc")

    Returns:
        dict with FortiView analytics data

    Example:
        >>> result = await get_fortiview_data(
        ...     "top-sources",
        ...     time_range="24-hour",
        ...     limit=10,
        ...     sort_by="bandwidth"
        ... )
        >>> for item in result["data"]:
        ...     print(f"{item['srcip']}: {item['bandwidth']} bytes")
    """
    try:
        # Validate inputs
        adom = validate_adom(adom)
        view_name = validate_fortiview_view(view_name)

        client = _get_client()
        tr = _parse_time_range(time_range)

        # Convert device string to API format
        device_filter = [{"devname": device}] if device else [{"devname": "All_Device"}]

        # Build sort_by parameter in API format
        sort_by_param = None
        if sort_by:
            sort_by_param = [{"field": sort_by, "order": sort_order}]

        logger.info(f"Running FortiView query: {view_name}")

        # Start the query
        run_result = await client.fortiview_run(
            adom=adom,
            view_name=view_name,
            device=device_filter,
            time_range=tr,
            filter=filter,
            limit=limit,
            sort_by=sort_by_param,
        )

        tid = run_result.get("tid") if isinstance(run_result, dict) else None
        if not tid:
            return {
                "status": "error",
                "message": "Failed to get TID from FortiView query",
            }

        # Poll for results
        start_time = asyncio.get_event_loop().time()
        poll_interval = 0.5

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                return {
                    "status": "timeout",
                    "tid": tid,
                    "message": f"FortiView query timed out after {timeout}s",
                }

            fetch_result = await client.fortiview_fetch(
                adom=adom,
                view_name=view_name,
                tid=tid,
            )

            # Check if we have data
            if isinstance(fetch_result, dict):
                data = fetch_result.get("data", [])
                percentage = fetch_result.get("percentage", 100)

                if percentage >= 100 or data:
                    if not isinstance(data, list):
                        data = [data] if data else []

                    return {
                        "status": "success",
                        "tid": tid,
                        "view_name": view_name,
                        "count": len(data),
                        "data": data,
                    }

            await asyncio.sleep(poll_interval)

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to get FortiView data: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_top_sources(
    adom: str = "root",
    device: str | None = None,
    time_range: str = "1-hour",
    limit: int = 10,
    sort_by: str = "bandwidth",
) -> dict[str, Any]:
    """Get top traffic sources (bandwidth consumers).

    Returns the top source IP addresses by traffic volume.

    Args:
        adom: ADOM name (default: "root")
        device: Device filter (serial number or name, optional)
        time_range: Time range (default: "1-hour")
        limit: Number of top sources to return (default: 10)
        sort_by: Sort field (default: "bandwidth"). Options:
            - "bandwidth": Sort by total bytes (recommended)
            - "sessions": Sort by session count
            - "threatweight": Sort by threat score

    Returns:
        dict with top sources data

    Example:
        >>> result = await get_top_sources(time_range="24-hour", limit=5)
        >>> for source in result["data"]:
        ...     print(f"{source['srcip']}: {source['bandwidth']} bytes")
    """
    return await get_fortiview_data(
        view_name="top-sources",
        adom=adom,
        device=device,
        time_range=time_range,
        limit=limit,
        sort_by=sort_by,
    )


@mcp.tool()
async def get_top_destinations(
    adom: str = "root",
    device: str | None = None,
    time_range: str = "1-hour",
    limit: int = 10,
    sort_by: str = "bandwidth",
) -> dict[str, Any]:
    """Get top traffic destinations.

    Returns the top destination IP addresses by traffic volume.

    Args:
        adom: ADOM name (default: "root")
        device: Device filter (serial number or name, optional)
        time_range: Time range (default: "1-hour")
        limit: Number of top destinations to return (default: 10)
        sort_by: Sort field (default: "bandwidth")

    Returns:
        dict with top destinations data
    """
    return await get_fortiview_data(
        view_name="top-destinations",
        adom=adom,
        device=device,
        time_range=time_range,
        limit=limit,
        sort_by=sort_by,
    )


@mcp.tool()
async def get_top_applications(
    adom: str = "root",
    device: str | None = None,
    time_range: str = "1-hour",
    limit: int = 10,
    sort_by: str = "bandwidth",
) -> dict[str, Any]:
    """Get top applications by bandwidth usage.

    Returns the top applications detected based on traffic analysis.

    Args:
        adom: ADOM name (default: "root")
        device: Device filter (serial number or name, optional)
        time_range: Time range (default: "1-hour")
        limit: Number of top applications to return (default: 10)
        sort_by: Sort field (default: "bandwidth")

    Returns:
        dict with top applications data

    Example:
        >>> result = await get_top_applications(time_range="24-hour")
        >>> for app in result["data"]:
        ...     print(f"{app['app']}: {app['bandwidth']} bytes")
    """
    return await get_fortiview_data(
        view_name="top-applications",
        adom=adom,
        device=device,
        time_range=time_range,
        limit=limit,
        sort_by=sort_by,
    )


@mcp.tool()
async def get_top_threats(
    adom: str = "root",
    device: str | None = None,
    time_range: str = "24-hour",
    limit: int = 10,
    sort_by: str = "threatweight",
) -> dict[str, Any]:
    """Get top security threats detected.

    Returns the most frequently detected security threats
    including IPS attacks, malware, and other security events.

    Args:
        adom: ADOM name (default: "root")
        device: Device filter (serial number or name, optional)
        time_range: Time range (default: "24-hour")
        limit: Number of top threats to return (default: 10)
        sort_by: Sort field (default: "threatweight"). Options:
            - "threatweight": Sort by threat severity/score
            - "incidents": Sort by incident count

    Returns:
        dict with top threats data

    Example:
        >>> result = await get_top_threats(time_range="7-day")
        >>> for threat in result["data"]:
        ...     print(f"{threat['threat']}: {threat['threatweight']} score")
    """
    return await get_fortiview_data(
        view_name="top-threats",
        adom=adom,
        device=device,
        time_range=time_range,
        limit=limit,
        sort_by=sort_by,
    )


@mcp.tool()
async def get_top_websites(
    adom: str = "root",
    device: str | None = None,
    time_range: str = "1-hour",
    limit: int = 10,
    sort_by: str = "bandwidth",
) -> dict[str, Any]:
    """Get top websites accessed.

    Returns the most frequently accessed websites by traffic volume.

    Args:
        adom: ADOM name (default: "root")
        device: Device filter (serial number or name, optional)
        time_range: Time range (default: "1-hour")
        limit: Number of top websites to return (default: 10)
        sort_by: Sort field (default: "bandwidth")

    Returns:
        dict with top websites data
    """
    return await get_fortiview_data(
        view_name="top-websites",
        adom=adom,
        device=device,
        time_range=time_range,
        limit=limit,
        sort_by=sort_by,
    )


@mcp.tool()
async def get_top_cloud_applications(
    adom: str = "root",
    device: str | None = None,
    time_range: str = "1-hour",
    limit: int = 10,
    sort_by: str = "bandwidth",
) -> dict[str, Any]:
    """Get top cloud/SaaS applications.

    Returns the most used cloud and SaaS applications.

    Args:
        adom: ADOM name (default: "root")
        device: Device filter (serial number or name, optional)
        time_range: Time range (default: "1-hour")
        limit: Number of top cloud apps to return (default: 10)
        sort_by: Sort field (default: "bandwidth")

    Returns:
        dict with top cloud applications data
    """
    return await get_fortiview_data(
        view_name="top-cloud-applications",
        adom=adom,
        device=device,
        time_range=time_range,
        limit=limit,
        sort_by=sort_by,
    )


@mcp.tool()
async def get_policy_hits(
    adom: str = "root",
    device: str | None = None,
    time_range: str = "24-hour",
    limit: int = 20,
    sort_by: str = "counts",
) -> dict[str, Any]:
    """Get policy hit statistics.

    Returns firewall policy usage and hit counts per policy ID.

    Args:
        adom: ADOM name (default: "root")
        device: Device filter (serial number or name, optional)
        time_range: Time range (default: "24-hour")
        limit: Number of policies to return (default: 20)
        sort_by: Sort field (default: "counts"). Options:
            - "counts": Sort by hit count
            - "bandwidth": Sort by total bytes

    Returns:
        dict with policy hit statistics including policyid
    """
    return await get_fortiview_data(
        view_name="policy-hits",
        adom=adom,
        device=device,
        time_range=time_range,
        limit=limit,
        sort_by=sort_by,
    )
