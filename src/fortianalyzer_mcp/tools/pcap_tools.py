"""PCAP download tools for FortiAnalyzer.

Provides tools for searching IPS/attack logs and downloading associated
PCAP (packet capture) files for forensic analysis and incident response.

Based on the fortianalyzer-pcap-downloader project workflow.
"""

import asyncio
import base64
import io
import logging
import os
import zipfile
from datetime import datetime, timedelta
from typing import Any

from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    validate_adom,
    validate_output_path,
)

logger = logging.getLogger(__name__)

# Constants
DEFAULT_SEARCH_TIMEOUT = 60
POLL_INTERVAL = 1.0
MAX_PCAP_SIZE = 50 * 1024 * 1024  # 50MB per PCAP file


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
        "5-min": timedelta(minutes=5),
        "30-min": timedelta(minutes=30),
        "1-hour": timedelta(hours=1),
        "6-hour": timedelta(hours=6),
        "12-hour": timedelta(hours=12),
        "24-hour": timedelta(hours=24),
        "1-day": timedelta(days=1),
        "7-day": timedelta(days=7),
        "30-day": timedelta(days=30),
    }

    delta = range_map.get(time_range, timedelta(hours=24))
    start = now - delta

    return {"start": start.strftime(fmt), "end": now.strftime(fmt)}


def _build_ips_filter(
    severity: list[str] | None = None,
    attack_contains: str | None = None,
    attack_exact: str | None = None,
    action: list[str] | None = None,
    has_cve: bool = False,
    cve: str | None = None,
    srcip: str | None = None,
    dstip: str | None = None,
    srcport: int | None = None,
    dstport: int | None = None,
    session_id: int | None = None,
    has_pcap: bool = False,
) -> str | None:
    """Build FortiAnalyzer filter string for IPS log search.

    Args:
        severity: List of severities ["critical", "high", "medium", "low"]
        attack_contains: Partial match on attack name
        attack_exact: Exact match on attack name
        action: List of actions ["detected", "blocked", "dropped", "reset"]
        has_cve: Only return entries with CVE assigned
        cve: Specific CVE identifier (e.g., "CVE-2025-2945")
        srcip: Source IP address
        dstip: Destination IP address
        srcport: Source port
        dstport: Destination port
        session_id: Specific session ID
        has_pcap: Only return entries with PCAP available

    Returns:
        Filter string for FortiAnalyzer API, or None if no filters
    """
    filters = []

    # Severity filter: (severity="critical" or severity="high")
    if severity:
        if len(severity) == 1:
            filters.append(f'severity="{severity[0]}"')
        else:
            sev_parts = [f'severity="{s}"' for s in severity]
            filters.append(f"({' or '.join(sev_parts)})")

    # Attack name filter
    if attack_exact:
        filters.append(f'attack="{attack_exact}"')
    elif attack_contains:
        # Wildcard search: attack=*Remote.Code.Execution*
        filters.append(f"attack=*{attack_contains}*")

    # Action filter: (action="blocked" or action="dropped")
    if action:
        if len(action) == 1:
            filters.append(f'action="{action[0]}"')
        else:
            act_parts = [f'action="{a}"' for a in action]
            filters.append(f"({' or '.join(act_parts)})")

    # CVE filters
    if cve:
        filters.append(f'cve="{cve}"')
    elif has_cve:
        filters.append('cve!=""')

    # IP filters
    if srcip:
        filters.append(f'srcip="{srcip}"')
    if dstip:
        filters.append(f'dstip="{dstip}"')

    # Port filters
    if srcport:
        filters.append(f"srcport=={srcport}")
    if dstport:
        filters.append(f"dstport=={dstport}")

    # Session ID filter
    if session_id:
        filters.append(f"sessionid=={session_id}")

    # PCAP availability filter
    if has_pcap:
        filters.append('pcapurl!=""')

    if not filters:
        return None

    return " and ".join(filters)


@mcp.tool()
async def search_ips_logs(
    adom: str = "root",
    severity: list[str] | None = None,
    attack_contains: str | None = None,
    attack_exact: str | None = None,
    action: list[str] | None = None,
    has_cve: bool = False,
    cve: str | None = None,
    srcip: str | None = None,
    dstip: str | None = None,
    srcport: int | None = None,
    dstport: int | None = None,
    has_pcap: bool = False,
    device: str | None = None,
    time_range: str = "24-hour",
    limit: int = 100,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Search IPS/attack logs with advanced filtering.

    Search FortiAnalyzer for IPS (Intrusion Prevention System) events
    with flexible filtering options. Returns log entries that can be
    used to download associated PCAP files.

    Args:
        adom: ADOM name (default: "root")
        severity: Filter by severity levels. Options:
            - "critical": Critical severity attacks
            - "high": High severity attacks
            - "medium": Medium severity attacks
            - "low": Low severity attacks
            - "info": Informational
            Can provide multiple: ["critical", "high"]
        attack_contains: Partial match on attack name (e.g., "Remote.Code.Execution")
        attack_exact: Exact match on attack name
        action: Filter by action taken. Options:
            - "detected": Attack detected but allowed
            - "blocked": Attack blocked
            - "dropped": Packet dropped
            - "reset": Connection reset
            Can provide multiple: ["blocked", "dropped"]
        has_cve: Only return attacks with CVE identifiers assigned
        cve: Filter by specific CVE (e.g., "CVE-2025-2945")
        srcip: Filter by source IP address
        dstip: Filter by destination IP address
        srcport: Filter by source port
        dstport: Filter by destination port
        has_pcap: Only return entries that have PCAP files available
        device: Device filter (serial number or "All_FortiGate")
        time_range: Time range for search. Options:
            - "5-min", "30-min": Recent minutes
            - "1-hour", "6-hour", "12-hour", "24-hour": Hours
            - "1-day", "7-day", "30-day": Days
            - Custom: "2024-01-01 00:00:00|2024-01-02 00:00:00"
        limit: Maximum results to return (default: 100, max: 1000)
        timeout: Search timeout in seconds (default: 60)

    Returns:
        dict with keys:
            - status: "success" or "error"
            - count: Number of logs found
            - logs: List of IPS log entries with fields:
                - sessionid: Session ID (use for PCAP download)
                - attack: Attack/signature name
                - severity: Attack severity
                - action: Action taken
                - srcip, dstip: Source and destination IPs
                - srcport, dstport: Source and destination ports
                - cve: CVE identifier (if available)
                - pcapurl: PCAP URL (if available, use for download)
                - date, time: Event timestamp
            - filter_applied: Filter string used
            - tid: Task ID for pagination
            - message: Error message if failed

    Example:
        >>> # Find critical and high severity attacks
        >>> result = await search_ips_logs(
        ...     severity=["critical", "high"],
        ...     time_range="7-day"
        ... )

        >>> # Find attacks with PCAP available from specific source
        >>> result = await search_ips_logs(
        ...     srcip="192.168.1.100",
        ...     has_pcap=True,
        ...     time_range="24-hour"
        ... )

        >>> # Find specific CVE attacks
        >>> result = await search_ips_logs(
        ...     cve="CVE-2025-2945",
        ...     action=["blocked", "dropped"]
        ... )
    """
    try:
        # Validate inputs
        adom = validate_adom(adom)

        client = _get_client()

        # Build filter string
        filter_str = _build_ips_filter(
            severity=severity,
            attack_contains=attack_contains,
            attack_exact=attack_exact,
            action=action,
            has_cve=has_cve,
            cve=cve,
            srcip=srcip,
            dstip=dstip,
            srcport=srcport,
            dstport=dstport,
            has_pcap=has_pcap,
        )

        # Parse time range
        time_range_dict = _parse_time_range(time_range)

        # Build device filter
        device_filter = [{"devid": device}] if device else [{"devid": "All_FortiGate"}]

        logger.info(f"Searching IPS logs: adom={adom}, filter={filter_str}")

        # Start search - use logtype "attack" for IPS logs
        start_result = await client.logsearch_start(
            adom=adom,
            logtype="attack",
            device=device_filter,
            time_range=time_range_dict,
            filter=filter_str,
            limit=limit,
            offset=0,
        )

        tid = start_result.get("tid")
        if not tid:
            return {
                "status": "error",
                "message": f"Failed to start search: no TID returned. Response: {start_result}",
            }

        logger.info(f"IPS search started with TID: {tid}")

        # Poll for results
        start_time = asyncio.get_event_loop().time()
        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
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
                offset=0,
            )

            percentage = fetch_result.get("percentage", 0)
            logger.debug(f"Search progress: {percentage}%")

            if percentage >= 100:
                logs = fetch_result.get("data", [])
                if not isinstance(logs, list):
                    logs = [logs] if logs else []

                # Count how many have PCAP available
                pcap_available = sum(1 for log in logs if log.get("pcapurl"))

                return {
                    "status": "success",
                    "count": len(logs),
                    "pcap_available_count": pcap_available,
                    "total": fetch_result.get("total-lines", len(logs)),
                    "logs": logs,
                    "filter_applied": filter_str or "none",
                    "tid": tid,
                    "time_range": time_range_dict,
                }

            await asyncio.sleep(POLL_INTERVAL)

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to search IPS logs: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_pcap_by_session(
    session_id: int,
    adom: str = "root",
    device: str | None = None,
    time_range: str = "24-hour",
    output_dir: str = "~/Downloads",
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Download PCAP file for a specific session ID.

    Searches for an IPS log entry by session ID and downloads the
    associated PCAP file if available.

    Args:
        session_id: The session ID to download PCAP for
        adom: ADOM name (default: "root")
        device: Device filter (optional, defaults to All_FortiGate)
        time_range: Time range to search for the session. Options:
            - "1-hour", "6-hour", "12-hour", "24-hour"
            - "1-day", "7-day", "30-day"
            - Custom: "start_time|end_time"
        output_dir: Directory to save PCAP file (default: ~/Downloads)
        timeout: Search timeout in seconds (default: 60)

    Returns:
        dict with keys:
            - status: "success", "no_pcap", or "error"
            - session_id: The session ID
            - file_path: Path to saved PCAP file (if successful)
            - file_size: Size of PCAP file in bytes
            - attack_info: Attack details from log entry
            - message: Status or error message

    Example:
        >>> result = await get_pcap_by_session(
        ...     session_id=906654,
        ...     time_range="7-day"
        ... )
        >>> if result["status"] == "success":
        ...     print(f"PCAP saved to: {result['file_path']}")
    """
    try:
        # Validate inputs
        adom = validate_adom(adom)
        output_path = validate_output_path(output_dir)

        if session_id <= 0:
            return {"status": "error", "message": "Invalid session ID"}

        client = _get_client()

        # Build filter for specific session ID
        filter_str = f"sessionid=={session_id}"
        time_range_dict = _parse_time_range(time_range)
        device_filter = [{"devid": device}] if device else [{"devid": "All_FortiGate"}]

        logger.info(f"Searching for session {session_id} in ADOM {adom}")

        # Start search
        start_result = await client.logsearch_start(
            adom=adom,
            logtype="attack",
            device=device_filter,
            time_range=time_range_dict,
            filter=filter_str,
            limit=10,
            offset=0,
        )

        tid = start_result.get("tid")
        if not tid:
            return {
                "status": "error",
                "session_id": session_id,
                "message": "Failed to start search: no TID returned",
            }

        # Poll for results
        start_time = asyncio.get_event_loop().time()
        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                try:
                    await client.logsearch_cancel(adom, tid)
                except Exception:
                    pass
                return {
                    "status": "error",
                    "session_id": session_id,
                    "message": f"Search timed out after {timeout} seconds",
                }

            fetch_result = await client.logsearch_fetch(adom=adom, tid=tid, limit=10, offset=0)

            if fetch_result.get("percentage", 0) >= 100:
                break

            await asyncio.sleep(POLL_INTERVAL)

        # Check results
        logs = fetch_result.get("data", [])
        if not logs:
            return {
                "status": "error",
                "session_id": session_id,
                "message": f"No IPS log found for session ID {session_id} in time range {time_range}",
            }

        # Get first matching log
        log_entry = logs[0] if isinstance(logs, list) else logs
        pcapurl = log_entry.get("pcapurl")

        if not pcapurl:
            return {
                "status": "no_pcap",
                "session_id": session_id,
                "attack_info": {
                    "attack": log_entry.get("attack"),
                    "severity": log_entry.get("severity"),
                    "action": log_entry.get("action"),
                    "srcip": log_entry.get("srcip"),
                    "dstip": log_entry.get("dstip"),
                },
                "message": "Log entry found but no PCAP available for this session",
            }

        # Download PCAP
        logger.info(f"Downloading PCAP for session {session_id}")
        pcap_result = await client.get_pcapfile(key_data=pcapurl, key_type="pcapurl")

        if not isinstance(pcap_result, dict):
            return {
                "status": "error",
                "session_id": session_id,
                "message": "Unexpected response format from PCAP download",
            }

        # Extract base64 data
        data_b64 = pcap_result.get("data")
        if not data_b64:
            return {
                "status": "error",
                "session_id": session_id,
                "message": "No PCAP data in response",
            }

        # Decode and extract PCAP
        try:
            zip_data = base64.b64decode(data_b64)
        except Exception as e:
            return {
                "status": "error",
                "session_id": session_id,
                "message": f"Failed to decode base64 data: {e}",
            }

        # Create output directory
        output_path.mkdir(parents=True, exist_ok=True)

        # Extract from ZIP
        saved_file = None
        file_size = 0
        try:
            with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
                for filename in zf.namelist():
                    if filename.endswith("/"):
                        continue

                    # Check file size
                    info = zf.getinfo(filename)
                    if info.file_size > MAX_PCAP_SIZE:
                        return {
                            "status": "error",
                            "session_id": session_id,
                            "message": f"PCAP file too large: {info.file_size} bytes",
                        }

                    content = zf.read(filename)
                    file_size = len(content)

                    # Generate filename with session ID and timestamp
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    base_name = os.path.basename(filename)
                    name_part = os.path.splitext(base_name)[0]
                    out_filename = f"{name_part}_{session_id}_{timestamp}.pcap"

                    out_file = output_path / out_filename
                    with open(out_file, "wb") as f:
                        f.write(content)

                    saved_file = str(out_file)
                    logger.info(f"Saved PCAP: {saved_file}")
                    break  # Only save first file

        except zipfile.BadZipFile:
            return {
                "status": "error",
                "session_id": session_id,
                "message": "Invalid ZIP data received",
            }

        if not saved_file:
            return {
                "status": "error",
                "session_id": session_id,
                "message": "No PCAP file found in ZIP archive",
            }

        return {
            "status": "success",
            "session_id": session_id,
            "file_path": saved_file,
            "file_size": file_size,
            "attack_info": {
                "attack": log_entry.get("attack"),
                "severity": log_entry.get("severity"),
                "action": log_entry.get("action"),
                "srcip": log_entry.get("srcip"),
                "dstip": log_entry.get("dstip"),
                "cve": log_entry.get("cve"),
            },
            "message": f"PCAP downloaded successfully to {saved_file}",
        }

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to download PCAP for session {session_id}: {e}")
        return {"status": "error", "session_id": session_id, "message": str(e)}


@mcp.tool()
async def download_pcap_by_url(
    pcapurl: str,
    output_dir: str = "~/Downloads",
    filename_prefix: str | None = None,
) -> dict[str, Any]:
    """Download PCAP file using a pcapurl from search results.

    Use this when you already have the pcapurl from a previous
    search_ips_logs call.

    Args:
        pcapurl: The pcapurl value from an IPS log entry
        output_dir: Directory to save PCAP file (default: ~/Downloads)
        filename_prefix: Optional prefix for filename (e.g., session ID)

    Returns:
        dict with keys:
            - status: "success" or "error"
            - file_path: Path to saved PCAP file
            - file_size: Size in bytes
            - message: Status or error message

    Example:
        >>> # First search for logs
        >>> logs = await search_ips_logs(severity=["critical"], has_pcap=True)
        >>> # Then download PCAP for first result
        >>> if logs["logs"][0].get("pcapurl"):
        ...     result = await download_pcap_by_url(
        ...         pcapurl=logs["logs"][0]["pcapurl"],
        ...         filename_prefix=str(logs["logs"][0]["sessionid"])
        ...     )
    """
    try:
        output_path = validate_output_path(output_dir)

        if not pcapurl:
            return {"status": "error", "message": "pcapurl cannot be empty"}

        client = _get_client()

        logger.info("Downloading PCAP by URL")
        pcap_result = await client.get_pcapfile(key_data=pcapurl, key_type="pcapurl")

        if not isinstance(pcap_result, dict):
            return {"status": "error", "message": "Unexpected response format"}

        data_b64 = pcap_result.get("data")
        if not data_b64:
            return {"status": "error", "message": "No PCAP data in response"}

        # Decode
        try:
            zip_data = base64.b64decode(data_b64)
        except Exception as e:
            return {"status": "error", "message": f"Failed to decode base64: {e}"}

        # Create output directory
        output_path.mkdir(parents=True, exist_ok=True)

        # Extract
        saved_file = None
        file_size = 0
        try:
            with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
                for filename in zf.namelist():
                    if filename.endswith("/"):
                        continue

                    info = zf.getinfo(filename)
                    if info.file_size > MAX_PCAP_SIZE:
                        return {
                            "status": "error",
                            "message": f"PCAP too large: {info.file_size} bytes",
                        }

                    content = zf.read(filename)
                    file_size = len(content)

                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    base_name = os.path.basename(filename)
                    name_part = os.path.splitext(base_name)[0]

                    if filename_prefix:
                        out_filename = f"{name_part}_{filename_prefix}_{timestamp}.pcap"
                    else:
                        out_filename = f"{name_part}_{timestamp}.pcap"

                    out_file = output_path / out_filename
                    with open(out_file, "wb") as f:
                        f.write(content)

                    saved_file = str(out_file)
                    break

        except zipfile.BadZipFile:
            return {"status": "error", "message": "Invalid ZIP data received"}

        if not saved_file:
            return {"status": "error", "message": "No PCAP file found in archive"}

        return {
            "status": "success",
            "file_path": saved_file,
            "file_size": file_size,
            "message": f"PCAP downloaded to {saved_file}",
        }

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to download PCAP: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def search_and_download_pcaps(
    adom: str = "root",
    severity: list[str] | None = None,
    attack_contains: str | None = None,
    action: list[str] | None = None,
    has_cve: bool = False,
    cve: str | None = None,
    srcip: str | None = None,
    dstip: str | None = None,
    device: str | None = None,
    time_range: str = "24-hour",
    output_dir: str = "~/Downloads",
    max_downloads: int = 10,
    skip_existing: bool = True,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Search for IPS events and download all matching PCAPs.

    Convenience function that combines search_ips_logs and PCAP download
    into a single operation. Useful for bulk forensic collection.

    Args:
        adom: ADOM name (default: "root")
        severity: Filter by severity ["critical", "high", "medium", "low"]
        attack_contains: Partial match on attack name
        action: Filter by action ["detected", "blocked", "dropped", "reset"]
        has_cve: Only attacks with CVE identifiers
        cve: Specific CVE to search for
        srcip: Source IP address filter
        dstip: Destination IP address filter
        device: Device filter
        time_range: Time range for search (default: "24-hour")
        output_dir: Directory to save PCAP files (default: ~/Downloads)
        max_downloads: Maximum PCAPs to download (default: 10, max: 50)
        skip_existing: Skip if PCAP for session already exists (default: True)
        timeout: Search timeout in seconds

    Returns:
        dict with keys:
            - status: "success" or "error"
            - search_results: Number of IPS logs found
            - pcap_available: Number with PCAP available
            - downloaded: Number successfully downloaded
            - skipped: Number skipped (already exists)
            - failed: Number that failed to download
            - files: List of downloaded file paths
            - errors: List of error messages for failed downloads
            - message: Summary message

    Example:
        >>> # Download all critical attack PCAPs from last 7 days
        >>> result = await search_and_download_pcaps(
        ...     severity=["critical"],
        ...     time_range="7-day",
        ...     max_downloads=20
        ... )
        >>> print(f"Downloaded {result['downloaded']} PCAPs")

        >>> # Download PCAPs for attacks from specific IP
        >>> result = await search_and_download_pcaps(
        ...     srcip="192.168.1.100",
        ...     time_range="24-hour"
        ... )
    """
    try:
        # Validate inputs
        adom = validate_adom(adom)
        output_path = validate_output_path(output_dir)

        # Limit max downloads
        max_downloads = min(max_downloads, 50)

        client = _get_client()

        # Build filter - force has_pcap=True since we're downloading
        filter_str = _build_ips_filter(
            severity=severity,
            attack_contains=attack_contains,
            action=action,
            has_cve=has_cve,
            cve=cve,
            srcip=srcip,
            dstip=dstip,
            has_pcap=True,  # Only get entries with PCAP
        )

        time_range_dict = _parse_time_range(time_range)
        device_filter = [{"devid": device}] if device else [{"devid": "All_FortiGate"}]

        logger.info(f"Searching IPS logs for PCAP download: {filter_str}")

        # Start search
        start_result = await client.logsearch_start(
            adom=adom,
            logtype="attack",
            device=device_filter,
            time_range=time_range_dict,
            filter=filter_str,
            limit=max_downloads * 2,  # Get extra in case some fail
            offset=0,
        )

        tid = start_result.get("tid")
        if not tid:
            return {
                "status": "error",
                "message": "Failed to start search: no TID returned",
            }

        # Poll for results
        start_time = asyncio.get_event_loop().time()
        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                try:
                    await client.logsearch_cancel(adom, tid)
                except Exception:
                    pass
                return {"status": "error", "message": f"Search timed out after {timeout}s"}

            fetch_result = await client.logsearch_fetch(
                adom=adom, tid=tid, limit=max_downloads * 2, offset=0
            )

            if fetch_result.get("percentage", 0) >= 100:
                break

            await asyncio.sleep(POLL_INTERVAL)

        logs = fetch_result.get("data", [])
        if not isinstance(logs, list):
            logs = [logs] if logs else []

        # Filter to only those with pcapurl
        logs_with_pcap = [log for log in logs if log.get("pcapurl")]

        if not logs_with_pcap:
            return {
                "status": "success",
                "search_results": len(logs),
                "pcap_available": 0,
                "downloaded": 0,
                "skipped": 0,
                "failed": 0,
                "files": [],
                "errors": [],
                "message": "No IPS events found with PCAP available",
            }

        # Create output directory
        output_path.mkdir(parents=True, exist_ok=True)

        # Track unique session IDs to avoid duplicates
        seen_sessions = set()
        downloaded_files = []
        skipped_count = 0
        failed_count = 0
        errors = []

        for log in logs_with_pcap[:max_downloads]:
            session_id = log.get("sessionid")
            if not session_id or session_id in seen_sessions:
                continue

            seen_sessions.add(session_id)

            # Check if already exists
            if skip_existing:
                existing = list(output_path.glob(f"*_{session_id}_*.pcap"))
                if existing:
                    logger.info(f"Skipping session {session_id} - already exists")
                    skipped_count += 1
                    continue

            # Download PCAP
            try:
                pcapurl = log.get("pcapurl")
                pcap_result = await client.get_pcapfile(key_data=pcapurl, key_type="pcapurl")

                if not isinstance(pcap_result, dict) or not pcap_result.get("data"):
                    errors.append(f"Session {session_id}: No data in response")
                    failed_count += 1
                    continue

                zip_data = base64.b64decode(pcap_result["data"])

                with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
                    for filename in zf.namelist():
                        if filename.endswith("/"):
                            continue

                        info = zf.getinfo(filename)
                        if info.file_size > MAX_PCAP_SIZE:
                            errors.append(f"Session {session_id}: File too large")
                            failed_count += 1
                            break

                        content = zf.read(filename)
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        base_name = os.path.basename(filename)
                        name_part = os.path.splitext(base_name)[0]
                        out_filename = f"{name_part}_{session_id}_{timestamp}.pcap"

                        out_file = output_path / out_filename
                        with open(out_file, "wb") as f:
                            f.write(content)

                        downloaded_files.append(str(out_file))
                        logger.info(f"Downloaded: {out_file}")
                        break

            except Exception as e:
                errors.append(f"Session {session_id}: {str(e)}")
                failed_count += 1

            # Small delay between downloads
            await asyncio.sleep(0.5)

        return {
            "status": "success",
            "search_results": len(logs),
            "pcap_available": len(logs_with_pcap),
            "downloaded": len(downloaded_files),
            "skipped": skipped_count,
            "failed": failed_count,
            "files": downloaded_files,
            "errors": errors if errors else None,
            "output_dir": str(output_path),
            "message": f"Downloaded {len(downloaded_files)} PCAPs, skipped {skipped_count}, failed {failed_count}",
        }

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to search and download PCAPs: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def list_available_pcaps(
    adom: str = "root",
    severity: list[str] | None = None,
    attack_contains: str | None = None,
    srcip: str | None = None,
    dstip: str | None = None,
    device: str | None = None,
    time_range: str = "24-hour",
    limit: int = 50,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """List IPS events that have PCAP files available.

    Quick way to see what PCAPs are available before downloading.
    Returns a summary of each event with session ID for targeted download.

    Args:
        adom: ADOM name (default: "root")
        severity: Filter by severity levels
        attack_contains: Partial match on attack name
        srcip: Source IP filter
        dstip: Destination IP filter
        device: Device filter
        time_range: Time range (default: "24-hour")
        limit: Maximum results (default: 50)
        timeout: Search timeout in seconds

    Returns:
        dict with keys:
            - status: "success" or "error"
            - count: Number of events with PCAP
            - events: List of event summaries with:
                - session_id: Use for get_pcap_by_session
                - attack: Attack name
                - severity: Severity level
                - action: Action taken
                - srcip, dstip: Source/dest IPs
                - timestamp: Event time
            - message: Error message if failed

    Example:
        >>> # List critical attacks with PCAP available
        >>> result = await list_available_pcaps(
        ...     severity=["critical"],
        ...     time_range="7-day"
        ... )
        >>> for event in result["events"]:
        ...     print(f"Session {event['session_id']}: {event['attack']}")
    """
    try:
        adom = validate_adom(adom)

        # Use search_ips_logs with has_pcap=True
        search_result = await search_ips_logs(
            adom=adom,
            severity=severity,
            attack_contains=attack_contains,
            srcip=srcip,
            dstip=dstip,
            device=device,
            time_range=time_range,
            has_pcap=True,
            limit=limit,
            timeout=timeout,
        )

        if search_result.get("status") != "success":
            return search_result

        # Format results for easy reading
        events = []
        for log in search_result.get("logs", []):
            events.append(
                {
                    "session_id": log.get("sessionid"),
                    "attack": log.get("attack"),
                    "severity": log.get("severity"),
                    "action": log.get("action"),
                    "srcip": log.get("srcip"),
                    "dstip": log.get("dstip"),
                    "srcport": log.get("srcport"),
                    "dstport": log.get("dstport"),
                    "cve": log.get("cve"),
                    "timestamp": f"{log.get('date', '')} {log.get('time', '')}".strip(),
                }
            )

        return {
            "status": "success",
            "count": len(events),
            "events": events,
            "time_range": search_result.get("time_range"),
            "message": f"Found {len(events)} IPS events with PCAP available",
        }

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to list available PCAPs: {e}")
        return {"status": "error", "message": str(e)}
