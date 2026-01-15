"""IOC (Indicators of Compromise) tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 IOC API specifications.
Provides IOC detection, acknowledgment, and rescan operations.
"""

import asyncio
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
    }

    delta = range_map.get(time_range, timedelta(days=7))
    start = now - delta

    return {"start": start.strftime(fmt), "end": now.strftime(fmt)}


@mcp.tool()
async def get_ioc_license_state() -> dict[str, Any]:
    """Get IOC license state.

    Checks the current IOC license status and capabilities.
    IOC detection requires an active FortiGuard IOC license.

    Returns:
        dict with license state information

    Example:
        >>> result = await get_ioc_license_state()
        >>> if result["data"]["valid"]:
        ...     print("IOC license is valid")
    """
    try:
        client = _get_client()

        logger.info("Getting IOC license state")

        result = await client.get_ioc_license_state()

        return {
            "status": "success",
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get IOC license state: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def acknowledge_ioc_events(
    ioc_ids: list[str],
    user: str,
    adom: str = "root",
) -> dict[str, Any]:
    """Acknowledge IOC events.

    Marks IOC detection events as acknowledged for SOC tracking.

    Args:
        ioc_ids: List of IOC event IDs to acknowledge
        user: Username performing the acknowledgment
        adom: ADOM name (default: "root")

    Returns:
        dict with acknowledgment result

    Example:
        >>> result = await acknowledge_ioc_events(
        ...     ioc_ids=["IOC-001", "IOC-002"],
        ...     user="analyst1"
        ... )
    """
    try:
        client = _get_client()

        logger.info(f"Acknowledging {len(ioc_ids)} IOC events in ADOM {adom}")

        result = await client.acknowledge_ioc_events(
            adom=adom,
            ioc_ids=ioc_ids,
            user=user,
        )

        return {
            "status": "success",
            "adom": adom,
            "acknowledged_count": len(ioc_ids),
            "user": user,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to acknowledge IOC events: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def run_ioc_rescan(
    adom: str = "root",
    device: str | None = None,
    time_range: str = "7-day",
) -> dict[str, Any]:
    """Start an IOC rescan.

    Initiates a rescan of historical logs against current IOC database.
    Returns a TID for tracking the rescan progress.

    Args:
        adom: ADOM name (default: "root")
        device: Device filter (optional)
        time_range: Time range for logs to rescan. Options:
            - "1-day", "7-day", "30-day"
            - Custom: "2024-01-01 00:00:00|2024-01-02 00:00:00"

    Returns:
        dict with TID for tracking rescan

    Example:
        >>> result = await run_ioc_rescan(time_range="7-day")
        >>> tid = result["tid"]
        >>> # Check progress with get_ioc_rescan_status
    """
    try:
        client = _get_client()
        tr = _parse_time_range(time_range)

        logger.info(f"Starting IOC rescan in ADOM {adom}")

        result = await client.ioc_rescan_run(
            adom=adom,
            device=device,
            time_range=tr,
        )

        tid = result.get("tid") if isinstance(result, dict) else None

        return {
            "status": "success",
            "tid": tid,
            "adom": adom,
            "time_range": tr,
        }
    except Exception as e:
        logger.error(f"Failed to start IOC rescan: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_ioc_rescan_status(
    tid: int,
    adom: str = "root",
) -> dict[str, Any]:
    """Get IOC rescan status.

    Check the progress of an IOC rescan operation.

    Args:
        tid: Task ID from run_ioc_rescan
        adom: ADOM name (default: "root")

    Returns:
        dict with rescan status

    Example:
        >>> result = await get_ioc_rescan_status(tid=12345)
        >>> print(f"Progress: {result['data'].get('percentage', 0)}%")
    """
    try:
        client = _get_client()

        logger.info(f"Getting IOC rescan status for TID {tid}")

        result = await client.ioc_rescan_status(
            adom=adom,
            tid=tid,
        )

        return {
            "status": "success",
            "tid": tid,
            "adom": adom,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get IOC rescan status: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_ioc_rescan_history(
    adom: str = "root",
) -> dict[str, Any]:
    """Get IOC rescan history.

    Retrieves history of previous IOC rescan operations.

    Args:
        adom: ADOM name (default: "root")

    Returns:
        dict with rescan history

    Example:
        >>> result = await get_ioc_rescan_history()
        >>> for scan in result["data"]:
        ...     print(f"{scan['time-begin']}: {scan['status']}")
    """
    try:
        client = _get_client()

        logger.info(f"Getting IOC rescan history for ADOM {adom}")

        result = await client.get_ioc_rescan_history(adom=adom)

        # Handle various response formats
        if isinstance(result, dict):
            data = result.get("data", [])
        elif isinstance(result, list):
            data = result
        elif isinstance(result, str):
            # API may return empty string or status message
            data = []
        else:
            data = []

        if not isinstance(data, list):
            data = [data] if data else []

        return {
            "status": "success",
            "adom": adom,
            "count": len(data),
            "data": data,
        }
    except Exception as e:
        logger.error(f"Failed to get IOC rescan history: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def run_and_wait_ioc_rescan(
    adom: str = "root",
    device: str | None = None,
    time_range: str = "7-day",
    timeout: int = 300,
) -> dict[str, Any]:
    """Run IOC rescan and wait for completion.

    Convenience function that starts an IOC rescan and polls until completion.
    Handles the TID workflow automatically.

    Args:
        adom: ADOM name (default: "root")
        device: Device filter (optional)
        time_range: Time range for logs to rescan (default: "7-day")
        timeout: Maximum wait time in seconds (default: 300)

    Returns:
        dict with rescan result

    Example:
        >>> result = await run_and_wait_ioc_rescan(time_range="7-day")
        >>> if result["status"] == "success":
        ...     print(f"Found {result['data'].get('hits', 0)} IOC matches")
    """
    try:
        client = _get_client()
        tr = _parse_time_range(time_range)

        logger.info("Running IOC rescan and waiting for completion")

        # Start the rescan
        run_result = await client.ioc_rescan_run(
            adom=adom,
            device=device,
            time_range=tr,
        )

        tid = run_result.get("tid") if isinstance(run_result, dict) else None
        if not tid:
            return {
                "status": "error",
                "message": "Failed to get TID from IOC rescan",
            }

        # Poll for completion
        start_time = asyncio.get_event_loop().time()
        poll_interval = 2.0

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                return {
                    "status": "timeout",
                    "tid": tid,
                    "message": f"IOC rescan timed out after {timeout}s",
                }

            status_result = await client.ioc_rescan_status(adom=adom, tid=tid)

            if isinstance(status_result, dict):
                state = status_result.get("state", status_result.get("status", ""))
                percentage = status_result.get("percentage", status_result.get("percent", 0))

                if state in ("done", "completed") or percentage >= 100:
                    return {
                        "status": "success",
                        "tid": tid,
                        "adom": adom,
                        "time_range": tr,
                        "data": status_result,
                    }

                if state in ("error", "failed"):
                    return {
                        "status": "error",
                        "tid": tid,
                        "message": f"IOC rescan failed with state: {state}",
                        "data": status_result,
                    }

            await asyncio.sleep(poll_interval)

    except Exception as e:
        logger.error(f"Failed to run and wait for IOC rescan: {e}")
        return {"status": "error", "message": str(e)}
