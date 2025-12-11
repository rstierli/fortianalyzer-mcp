"""Log query and analysis tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 LogView API specifications.
Implements the two-step TID-based log search workflow.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any

from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    validate_adom,
    validate_log_type,
)

logger = logging.getLogger(__name__)

# Default search timeout in seconds
DEFAULT_SEARCH_TIMEOUT = 60
# Poll interval for search progress
POLL_INTERVAL = 1.0


def _get_client():
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


def _parse_time_range(time_range: str) -> dict[str, str]:
    """Parse time range string to API format.

    Args:
        time_range: Time range string like "1-hour", "24-hour", "7-day", "30-day"
                   or a custom range in format "start|end" with ISO format.

    Returns:
        dict with "start" and "end" keys in FortiAnalyzer format.
    """
    now = datetime.now()
    fmt = "%Y-%m-%d %H:%M:%S"

    if "|" in time_range:
        # Custom range: "2024-01-01 00:00:00|2024-01-02 00:00:00"
        parts = time_range.split("|")
        return {"start": parts[0].strip(), "end": parts[1].strip()}

    # Predefined ranges
    range_map = {
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


def _build_device_filter(device: str | None) -> list[dict[str, str]]:
    """Build device filter for API.

    Args:
        device: Device serial number, name, or None for all FortiGate devices.
                - Serial number format: FGxxxxxxxxxxxxxx (e.g., FG100FTK19001333)
                - Device name format: device-name or device-name[vdom]
                - None: Uses All_FortiGate to search all FortiGate devices

    Returns:
        Device filter list for API.

    Note:
        The FAZ API requires a device filter. Without one, searches return 0 results.
        Use the device serial number for best results. Device names may not work
        if they don't match exactly in the FAZ database.
    """
    if not device:
        # Default to all FortiGate devices - empty list returns 0 results
        return [{"devid": "All_FortiGate"}]

    # Check if it looks like a serial number (starts with FG, FM, etc.)
    if device.startswith(("FG", "FM", "FW", "FA", "FS", "FD", "FP", "FC")):
        return [{"devid": device}]

    # Check for special "All_*" device types
    if device.startswith("All_"):
        return [{"devid": device}]

    # Otherwise, try as device name (devname)
    return [{"devname": device}]


@mcp.tool()
async def query_logs(
    adom: str = "root",
    logtype: str = "traffic",
    device: str | None = None,
    time_range: str = "1-hour",
    filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Query logs from FortiAnalyzer log database.

    This implements the two-step TID-based log search workflow:
    1. Start search task (returns TID)
    2. Poll for results until complete

    Args:
        adom: ADOM name (default: "root")
        logtype: Log type to query. Options:
            - "traffic": Firewall traffic logs
            - "event": System event logs
            - "attack": IPS/IDS attack logs
            - "virus": Antivirus logs
            - "webfilter": Web filter logs
            - "app-ctrl": Application control logs
            - "dlp": DLP logs
            - "emailfilter": Email filter logs
        device: Device filter (optional). Options:
            - Serial number (recommended): "FG100FTK19001333"
            - Device name: "myfw01" or "myfw01[root]" (with VDOM)
            - All devices: "All_FortiGate", "All_FortiMail", etc.
            - Default (None): Searches all FortiGate devices
        time_range: Time range for logs. Options:
            - "1-hour": Last 1 hour
            - "6-hour": Last 6 hours
            - "12-hour": Last 12 hours
            - "24-hour": Last 24 hours
            - "7-day": Last 7 days
            - "30-day": Last 30 days
            - Custom: "start_time|end_time" (e.g., "2024-01-01 00:00:00|2024-01-02 00:00:00")
        filter: Log filter expression (optional).
            Example: "srcip==10.0.0.1 and dstport==443"
            Operators: ==, !=, <, >, <=, >=, contain, !contain
        limit: Maximum logs to return (default: 100, max: 1000)
        offset: Offset for pagination (default: 0)
        timeout: Search timeout in seconds (default: 60)

    Returns:
        dict: Log query results with keys:
            - status: "success" or "error"
            - count: Number of logs returned
            - total: Total logs matching query
            - percentage: Search completion percentage
            - logs: List of log entries
            - tid: Task ID (for pagination)
            - message: Error message if failed

    Example:
        >>> # Get last hour of traffic logs
        >>> result = await query_logs(logtype="traffic", time_range="1-hour")
        >>> print(f"Found {result['count']} logs")

        >>> # Search for specific source IP
        >>> result = await query_logs(
        ...     logtype="traffic",
        ...     filter="srcip==192.168.1.100",
        ...     limit=50
        ... )
    """
    try:
        # Validate inputs
        adom = validate_adom(adom)
        logtype = validate_log_type(logtype)

        client = _get_client()

        # Parse time range
        time_range_dict = _parse_time_range(time_range)

        # Build device filter
        device_filter = _build_device_filter(device)

        # Step 1: Start log search
        logger.info(f"Starting log search: adom={adom}, logtype={logtype}, filter={filter}")
        start_result = await client.logsearch_start(
            adom=adom,
            logtype=logtype,
            device=device_filter,
            time_range=time_range_dict,
            filter=filter,
            limit=limit,
            offset=offset,
        )

        # Extract TID
        tid = start_result.get("tid")
        if not tid:
            return {
                "status": "error",
                "message": f"Failed to start search: no TID returned. Response: {start_result}",
            }

        logger.info(f"Log search started with TID: {tid}")

        # Step 2: Poll for results
        start_time = asyncio.get_event_loop().time()
        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                # Cancel the search
                try:
                    await client.logsearch_cancel(adom, tid)
                except Exception:
                    pass
                return {
                    "status": "error",
                    "message": f"Search timed out after {timeout} seconds",
                    "tid": tid,
                }

            # Fetch results
            fetch_result = await client.logsearch_fetch(
                adom=adom,
                tid=tid,
                limit=limit,
                offset=offset,
            )

            percentage = fetch_result.get("percentage", 0)
            logger.debug(f"Search progress: {percentage}%")

            # Check if complete
            if percentage >= 100:
                logs = fetch_result.get("data", [])
                if not isinstance(logs, list):
                    logs = [logs] if logs else []

                return {
                    "status": "success",
                    "count": len(logs),
                    "total": fetch_result.get("total-lines", len(logs)),
                    "percentage": percentage,
                    "logs": logs,
                    "tid": tid,
                }

            # Wait before polling again
            await asyncio.sleep(POLL_INTERVAL)

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to query logs: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_log_search_progress(
    adom: str = "root",
    tid: int = 0,
) -> dict[str, Any]:
    """Get progress of an ongoing log search.

    Args:
        adom: ADOM name (default: "root")
        tid: Task ID from a previous query_logs call

    Returns:
        dict: Search progress with keys:
            - status: "success" or "error"
            - progress_percent: Search progress (0-100)
            - matched_logs: Number of matching logs found
            - scanned_logs: Number of logs scanned so far
            - total_logs: Total logs to scan
            - message: Error message if failed

    Example:
        >>> result = await get_log_search_progress("root", 12345)
        >>> print(f"Progress: {result['progress_percent']}%")
    """
    try:
        if tid <= 0:
            return {"status": "error", "message": "Invalid TID"}

        client = _get_client()
        result = await client.logsearch_count(adom, tid)

        return {
            "status": "success",
            "progress_percent": result.get("progress-percent", 0),
            "matched_logs": result.get("matched-logs", 0),
            "scanned_logs": result.get("scanned-logs", 0),
            "total_logs": result.get("total-logs", 0),
        }
    except Exception as e:
        logger.error(f"Failed to get search progress: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def fetch_more_logs(
    adom: str = "root",
    tid: int = 0,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Fetch more logs from a completed search using TID.

    Use this for pagination after an initial query_logs call.

    Args:
        adom: ADOM name (default: "root")
        tid: Task ID from a previous query_logs call
        limit: Maximum logs to return (default: 100, max: 500)
        offset: Offset for pagination (default: 0)

    Returns:
        dict: Additional log results with keys:
            - status: "success" or "error"
            - count: Number of logs returned
            - logs: List of log entries
            - message: Error message if failed

    Example:
        >>> # Get first 100 logs
        >>> result = await query_logs(logtype="traffic", limit=100)
        >>> tid = result['tid']
        >>>
        >>> # Get next 100 logs
        >>> more = await fetch_more_logs(tid=tid, offset=100)
    """
    try:
        if tid <= 0:
            return {"status": "error", "message": "Invalid TID"}

        client = _get_client()
        result = await client.logsearch_fetch(
            adom=adom,
            tid=tid,
            limit=limit,
            offset=offset,
        )

        logs = result.get("data", [])
        if not isinstance(logs, list):
            logs = [logs] if logs else []

        return {
            "status": "success",
            "count": len(logs),
            "logs": logs,
        }
    except Exception as e:
        logger.error(f"Failed to fetch more logs: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def cancel_log_search(
    adom: str = "root",
    tid: int = 0,
) -> dict[str, Any]:
    """Cancel an ongoing log search.

    Args:
        adom: ADOM name (default: "root")
        tid: Task ID from a previous query_logs call

    Returns:
        dict: Cancellation result with keys:
            - status: "success" or "error"
            - message: Status message

    Example:
        >>> result = await cancel_log_search("root", 12345)
    """
    try:
        if tid <= 0:
            return {"status": "error", "message": "Invalid TID"}

        client = _get_client()
        await client.logsearch_cancel(adom, tid)

        return {
            "status": "success",
            "message": f"Search {tid} cancelled",
        }
    except Exception as e:
        logger.error(f"Failed to cancel search: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_log_stats(
    adom: str = "root",
    device: str | None = None,
) -> dict[str, Any]:
    """Get log statistics for an ADOM.

    Returns statistics about log storage, rates, and device logging status.

    Args:
        adom: ADOM name (default: "root")
        device: Specific device name (optional)

    Returns:
        dict: Log statistics with keys:
            - status: "success" or "error"
            - stats: Log statistics data
            - message: Error message if failed

    Example:
        >>> result = await get_log_stats("root")
        >>> print(result['stats'])
    """
    try:
        client = _get_client()
        device_filter = _build_device_filter(device) if device else None
        stats = await client.get_logstats(adom, device_filter)
        return {
            "status": "success",
            "stats": stats,
        }
    except Exception as e:
        logger.error(f"Failed to get log stats for ADOM {adom}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_log_fields(
    adom: str = "root",
    logtype: str = "traffic",
    devtype: str = "FortiGate",
) -> dict[str, Any]:
    """Get available log fields for a log type.

    Useful for understanding what fields can be used in filters.

    Args:
        adom: ADOM name (default: "root")
        logtype: Log type (traffic, event, attack, etc.)
        devtype: Device type (default: "FortiGate")

    Returns:
        dict: Log fields with keys:
            - status: "success" or "error"
            - fields: List of available field definitions
            - message: Error message if failed

    Example:
        >>> result = await get_log_fields(logtype="traffic")
        >>> for field in result['fields']:
        ...     print(f"{field['name']}: {field['description']}")
    """
    try:
        client = _get_client()
        result = await client.get_logfields(adom, logtype, devtype)
        return {
            "status": "success",
            "fields": result,
        }
    except Exception as e:
        logger.error(f"Failed to get log fields: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def search_traffic_logs(
    adom: str = "root",
    srcip: str | None = None,
    dstip: str | None = None,
    srcport: int | None = None,
    dstport: int | None = None,
    action: str | None = None,
    policy_id: int | None = None,
    device: str | None = None,
    time_range: str = "1-hour",
    limit: int = 100,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Search traffic logs with common filter criteria.

    Convenience function for searching traffic logs with typical
    network-based filters.

    Args:
        adom: ADOM name (default: "root")
        srcip: Source IP address filter
        dstip: Destination IP address filter
        srcport: Source port filter
        dstport: Destination port filter
        action: Action filter ("accept", "deny", "drop", "close")
        policy_id: Policy ID filter
        device: Device filter (serial number like "FG100FTK19001333" or name like "myfw01")
        time_range: Time range (default: "1-hour")
        limit: Maximum logs to return (default: 100)
        timeout: Search timeout in seconds (default: 60)

    Returns:
        dict: Log search results with keys:
            - status: "success" or "error"
            - count: Number of logs found
            - logs: List of traffic log entries
            - filter_applied: Filter string used
            - tid: Task ID for pagination
            - message: Error message if failed

    Example:
        >>> # Find denied traffic from specific IP
        >>> result = await search_traffic_logs(
        ...     srcip="192.168.1.100",
        ...     action="deny",
        ...     time_range="24-hour"
        ... )
    """
    try:
        # Build filter string using FortiAnalyzer syntax
        filters = []
        if srcip:
            filters.append(f"srcip=={srcip}")
        if dstip:
            filters.append(f"dstip=={dstip}")
        if srcport:
            filters.append(f"srcport=={srcport}")
        if dstport:
            filters.append(f"dstport=={dstport}")
        if action:
            filters.append(f"action=={action}")
        if policy_id:
            filters.append(f"policyid=={policy_id}")

        filter_str = " and ".join(filters) if filters else None

        result = await query_logs(
            adom=adom,
            logtype="traffic",
            device=device,
            time_range=time_range,
            filter=filter_str,
            limit=limit,
            timeout=timeout,
        )

        if result.get("status") == "success":
            result["filter_applied"] = filter_str or "none"

        return result

    except Exception as e:
        logger.error(f"Failed to search traffic logs: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def search_security_logs(
    adom: str = "root",
    attack_name: str | None = None,
    severity: str | None = None,
    srcip: str | None = None,
    dstip: str | None = None,
    device: str | None = None,
    time_range: str = "24-hour",
    limit: int = 100,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Search security logs (IPS, AV, etc.) with common filters.

    Search for security events including intrusion attempts,
    malware detections, and other security-related logs.

    Args:
        adom: ADOM name (default: "root")
        attack_name: Attack/signature name filter
        severity: Severity filter ("critical", "high", "medium", "low", "info")
        srcip: Source IP address filter
        dstip: Destination IP address filter
        device: Device filter (serial number like "FG100FTK19001333" or name like "myfw01")
        time_range: Time range (default: "24-hour")
        limit: Maximum logs to return (default: 100)
        timeout: Search timeout in seconds (default: 60)

    Returns:
        dict: Security log results with keys:
            - status: "success" or "error"
            - count: Number of security events found
            - logs: List of security log entries
            - filter_applied: Filter string used
            - tid: Task ID for pagination
            - message: Error message if failed

    Example:
        >>> # Find critical security events
        >>> result = await search_security_logs(
        ...     severity="critical",
        ...     time_range="7-day"
        ... )
    """
    try:
        # Build filter string
        filters = []
        if attack_name:
            filters.append(f"attack contain {attack_name}")
        if severity:
            filters.append(f"severity=={severity}")
        if srcip:
            filters.append(f"srcip=={srcip}")
        if dstip:
            filters.append(f"dstip=={dstip}")

        filter_str = " and ".join(filters) if filters else None

        result = await query_logs(
            adom=adom,
            logtype="attack",
            device=device,
            time_range=time_range,
            filter=filter_str,
            limit=limit,
            timeout=timeout,
        )

        if result.get("status") == "success":
            result["filter_applied"] = filter_str or "none"

        return result

    except Exception as e:
        logger.error(f"Failed to search security logs: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def search_event_logs(
    adom: str = "root",
    subtype: str | None = None,
    level: str | None = None,
    device: str | None = None,
    time_range: str = "24-hour",
    limit: int = 100,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Search system event logs.

    Search for system events including configuration changes,
    admin actions, system status changes, and VPN events.

    Args:
        adom: ADOM name (default: "root")
        subtype: Event subtype filter. Options:
            - "system": System events
            - "vpn": VPN events
            - "user": User/auth events
            - "router": Routing events
            - "wireless": Wireless events
        level: Event level filter ("emergency", "alert", "critical",
               "error", "warning", "notice", "information", "debug")
        device: Device filter (serial number like "FG100FTK19001333" or name like "myfw01")
        time_range: Time range (default: "24-hour")
        limit: Maximum logs to return (default: 100)
        timeout: Search timeout in seconds (default: 60)

    Returns:
        dict: Event log results with keys:
            - status: "success" or "error"
            - count: Number of events found
            - logs: List of event log entries
            - filter_applied: Filter string used
            - tid: Task ID for pagination
            - message: Error message if failed

    Example:
        >>> # Find VPN-related events
        >>> result = await search_event_logs(
        ...     subtype="vpn",
        ...     time_range="7-day"
        ... )
    """
    try:
        # Build filter string
        filters = []
        if subtype:
            filters.append(f"subtype=={subtype}")
        if level:
            filters.append(f"level=={level}")

        filter_str = " and ".join(filters) if filters else None

        result = await query_logs(
            adom=adom,
            logtype="event",
            device=device,
            time_range=time_range,
            filter=filter_str,
            limit=limit,
            timeout=timeout,
        )

        if result.get("status") == "success":
            result["filter_applied"] = filter_str or "none"

        return result

    except Exception as e:
        logger.error(f"Failed to search event logs: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_logfiles_state(
    adom: str = "root",
    device: str | None = None,
    vdom: str | None = None,
    time_range: str | None = None,
) -> dict[str, Any]:
    """Get log file state information.

    Lists available log files on disk for a device/VDOM.

    Args:
        adom: ADOM name (default: "root")
        device: Device ID (optional)
        vdom: VDOM name (optional)
        time_range: Time range filter (optional)

    Returns:
        dict: Log file state with keys:
            - status: "success" or "error"
            - data: Log file state information
            - message: Error message if failed

    Example:
        >>> result = await get_logfiles_state("root", "FGT-001")
    """
    try:
        client = _get_client()

        time_range_dict = None
        if time_range:
            time_range_dict = _parse_time_range(time_range)

        result = await client.get_logfiles_state(
            adom=adom,
            devid=device,
            vdom=vdom,
            time_range=time_range_dict,
        )

        return {
            "status": "success",
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get log files state: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_pcap_file(
    log_data: str,
    key_type: str = "log-data",
) -> dict[str, Any]:
    """Get PCAP file associated with a log entry.

    Some logs (like IPS) include associated packet captures.
    This retrieves the PCAP file data.

    Args:
        log_data: Log data JSON string or pcapurl value
        key_type: Type of key_data - "log-data" or "pcapurl"

    Returns:
        dict: PCAP data with keys:
            - status: "success" or "error"
            - data: PCAP file data (base64 encoded)
            - message: Error message if failed

    Example:
        >>> # Get PCAP from log entry that has pcapurl
        >>> result = await get_pcap_file(log_entry['pcapurl'], key_type="pcapurl")
    """
    try:
        client = _get_client()
        result = await client.get_pcapfile(log_data, key_type)

        return {
            "status": "success",
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get PCAP file: {e}")
        return {"status": "error", "message": str(e)}
