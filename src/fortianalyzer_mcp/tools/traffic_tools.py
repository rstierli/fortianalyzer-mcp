"""Policy traffic analysis tools for FortiAnalyzer.

Provides tools for analyzing traffic patterns per firewall policy:
- Traffic profiling (top ports, services, applications)
- Exact port/protocol enumeration
- Protocol breakdown summaries

These tools query FortiAnalyzer traffic logs filtered by policy ID and
aggregate results for policy hardening workflows.
"""

import asyncio
import logging
import re
import time
from collections import Counter
from typing import Any

from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    get_default_adom,
    validate_adom,
)

logger = logging.getLogger(__name__)

# Concurrency limit for parallel policy queries
_QUERY_SEMAPHORE = asyncio.Semaphore(5)

# Default and max search parameters
DEFAULT_SEARCH_TIMEOUT = 120
POLL_INTERVAL = 1.0
MAX_POLICY_IDS = 25
DEFAULT_TOP_N = 10

# Valid action values for FortiGate traffic logs
VALID_ACTIONS = frozenset({"accept", "deny", "close", "drop", "ip-conn", "timeout"})

# Regex for safe unquoted filter values: alphanumeric, dots, hyphens
_SAFE_UNQUOTED_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")


# =============================================================================
# Validation helpers
# =============================================================================


def validate_action(action: str | None) -> str | None:
    """Validate traffic log action value against allowlist.

    Args:
        action: Action string to validate, or None.

    Returns:
        Validated action string (lowercase) or None.

    Raises:
        ValidationError: If action is not in the allowlist.
    """
    if action is None:
        return None
    action = action.strip().lower()
    if action not in VALID_ACTIONS:
        raise ValidationError(
            f"Invalid action '{action}'. "
            f"Allowed values: {', '.join(sorted(VALID_ACTIONS))}"
        )
    return action


def validate_policy_ids(policy_ids: list[int]) -> list[int]:
    """Validate a list of policy IDs.

    Args:
        policy_ids: List of integer policy IDs.

    Returns:
        Validated list of policy IDs.

    Raises:
        ValidationError: If list is empty, too large, or contains invalid IDs.
    """
    if not policy_ids:
        raise ValidationError("policy_ids must not be empty")
    if len(policy_ids) > MAX_POLICY_IDS:
        raise ValidationError(
            f"Too many policy IDs ({len(policy_ids)}). Maximum is {MAX_POLICY_IDS}."
        )
    for pid in policy_ids:
        if not isinstance(pid, int) or pid <= 0:
            raise ValidationError(
                f"Invalid policy ID: {pid}. Must be a positive integer."
            )
    return policy_ids


def sanitize_filter_value(value: str) -> str:
    """Sanitize a value for use in FAZ log filter expressions.

    Safe alphanumeric values (including dots and hyphens) are returned as-is.
    All other values are quoted with internal backslashes and double quotes escaped.

    Args:
        value: Raw filter value.

    Returns:
        Sanitized value safe for use in filter expressions.

    Raises:
        ValidationError: If value is empty.
    """
    if not value:
        raise ValidationError("Filter value cannot be empty")
    value = value.strip()
    if not value:
        raise ValidationError("Filter value cannot be empty after stripping")
    if _SAFE_UNQUOTED_RE.match(value):
        return value
    # Escape backslashes first, then double quotes, then wrap in quotes
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


# =============================================================================
# Internal query helpers
# =============================================================================


def _get_client():
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


def _build_policy_filter(policy_id: int, action: str | None = None) -> str:
    """Build a FAZ filter string for a policy ID and optional action.

    Args:
        policy_id: Firewall policy ID.
        action: Optional validated action value.

    Returns:
        Filter expression string.
    """
    parts = [f"policyid=={policy_id}"]
    if action:
        parts.append(f"action=={sanitize_filter_value(action)}")
    return " and ".join(parts)


def _parse_time_range(time_range: str) -> dict[str, str]:
    """Parse time range string to API format.

    Reuses the same format as log_tools._parse_time_range.
    """
    from datetime import datetime, timedelta

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

    delta = range_map.get(time_range, timedelta(hours=1))
    start = now - delta

    return {"start": start.strftime(fmt), "end": now.strftime(fmt)}


def _build_device_filter(device: str | None) -> list[dict[str, str]]:
    """Build device filter for API. Mirrors log_tools._build_device_filter."""
    if not device:
        return [{"devid": "All_FortiGate"}]
    if device.startswith(("FG", "FM", "FW", "FA", "FS", "FD", "FP", "FC")):
        return [{"devid": device}]
    if device.startswith("All_"):
        return [{"devid": device}]
    return [{"devname": device}]


async def _query_policy_logs(
    adom: str,
    device: str | None,
    policy_id: int,
    time_range: str,
    action: str | None,
    limit: int = 1000,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> list[dict[str, Any]]:
    """Query traffic logs for a single policy ID.

    Uses the TID-based log search workflow with semaphore-bounded concurrency.

    Args:
        adom: ADOM name.
        device: Device filter.
        policy_id: Policy ID to query.
        time_range: Time range string.
        action: Optional action filter.
        limit: Max logs to return.
        timeout: Search timeout in seconds.

    Returns:
        List of log entries.
    """
    async with _QUERY_SEMAPHORE:
        client = _get_client()
        time_range_dict = _parse_time_range(time_range)
        device_filter = _build_device_filter(device)
        filter_str = _build_policy_filter(policy_id, action)

        start_result = await client.logsearch_start(
            adom=adom,
            logtype="traffic",
            device=device_filter,
            time_range=time_range_dict,
            filter=filter_str,
            limit=limit,
        )

        tid = start_result.get("tid")
        if not tid:
            logger.warning(f"No TID returned for policy {policy_id}: {start_result}")
            return []

        start_time = time.monotonic()
        while True:
            elapsed = time.monotonic() - start_time
            if elapsed > timeout:
                try:
                    await client.logsearch_cancel(adom, tid)
                except (OSError, RuntimeError):
                    pass
                logger.warning(f"Search timed out for policy {policy_id}")
                return []

            fetch_result = await client.logsearch_fetch(
                adom=adom,
                tid=tid,
                limit=limit,
                offset=0,
            )

            percentage = fetch_result.get("percentage", 0)
            if percentage >= 100:
                logs = fetch_result.get("data", [])
                if not isinstance(logs, list):
                    logs = [logs] if logs else []
                return logs

            await asyncio.sleep(POLL_INTERVAL)


# =============================================================================
# Aggregation helpers
# =============================================================================


def _aggregate_traffic_profile(
    logs: list[dict[str, Any]], top_n: int
) -> dict[str, Any]:
    """Aggregate log entries into a traffic profile.

    Returns top ports, services, and applications with hit counts.
    """
    port_counter: Counter[str] = Counter()
    service_counter: Counter[str] = Counter()
    app_counter: Counter[str] = Counter()

    for log in logs:
        dstport = log.get("dstport")
        proto = log.get("proto", "")
        if dstport is not None:
            port_counter[f"{proto}/{dstport}"] += 1

        service = log.get("service")
        if service:
            service_counter[str(service)] += 1

        app = log.get("app") or log.get("appcat")
        if app:
            app_counter[str(app)] += 1

    total = len(logs)
    top_ports = port_counter.most_common(top_n)
    top_services = service_counter.most_common(top_n)
    top_apps = app_counter.most_common(top_n)

    top_port_hits = sum(c for _, c in top_ports)
    top_service_hits = sum(c for _, c in top_services)
    top_app_hits = sum(c for _, c in top_apps)

    return {
        "total_hits": total,
        "top_ports": [{"port": p, "hits": c} for p, c in top_ports],
        "top_ports_residual": total - top_port_hits,
        "top_services": [{"service": s, "hits": c} for s, c in top_services],
        "top_services_residual": total - top_service_hits,
        "top_applications": [{"application": a, "hits": c} for a, c in top_apps],
        "top_applications_residual": total - top_app_hits,
    }


def _aggregate_port_analysis(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate logs into exact port/protocol enumeration.

    Returns complete port list, protocol breakdown, ICMP summary,
    and is_exact indicator.
    """
    port_counter: Counter[str] = Counter()
    protocol_counter: Counter[str] = Counter()
    portless_protocols: set[str] = set()
    icmp_types: Counter[str] = Counter()
    total = len(logs)
    port_hits = 0

    for log in logs:
        proto_num = log.get("proto", "")
        proto_str = str(proto_num)
        protocol_counter[proto_str] += 1

        dstport = log.get("dstport")
        if dstport is not None and str(dstport) != "0":
            port_key = f"{proto_str}/{dstport}"
            port_counter[port_key] += 1
            port_hits += 1
        else:
            # Portless protocol (ICMP, GRE, ESP, etc.)
            portless_protocols.add(proto_str)

        # Track ICMP types
        icmp_type = log.get("icmptype")
        if icmp_type is not None:
            icmp_code = log.get("icmpcode", 0)
            icmp_types[f"type={icmp_type}/code={icmp_code}"] += 1

    uncovered = total - port_hits

    return {
        "total_hits": total,
        "is_exact": True,
        "ports": [{"port": p, "hits": c} for p, c in port_counter.most_common()],
        "protocols": [
            {"protocol": p, "hits": c} for p, c in protocol_counter.most_common()
        ],
        "portless_protocols": sorted(portless_protocols),
        "uncovered_port_hits": uncovered,
        "icmp": (
            [{"type_code": tc, "hits": c} for tc, c in icmp_types.most_common()]
            if icmp_types
            else []
        ),
    }


def _aggregate_protocol_summary(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate logs into a lightweight protocol breakdown.

    Maps protocol numbers to names for common protocols.
    """
    PROTO_NAMES = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "58": "ICMPv6",
        "47": "GRE",
        "50": "ESP",
        "51": "AH",
        "89": "OSPF",
        "132": "SCTP",
    }

    protocol_counter: Counter[str] = Counter()
    total = len(logs)

    for log in logs:
        proto_num = str(log.get("proto", "unknown"))
        proto_name = PROTO_NAMES.get(proto_num, f"other({proto_num})")
        protocol_counter[proto_name] += 1

    return {
        "total_hits": total,
        "protocols": [
            {"protocol": p, "hits": c} for p, c in protocol_counter.most_common()
        ],
    }


# =============================================================================
# MCP Tool Functions
# =============================================================================


@mcp.tool()
async def get_policy_traffic_profile(
    adom: str | None = None,
    device: str | None = None,
    policy_ids: list[int] | None = None,
    time_range: str = "24-hour",
    action: str | None = None,
    top_n: int = DEFAULT_TOP_N,
) -> dict[str, Any]:
    """Get sampled traffic summary per firewall policy.

    Queries traffic logs filtered by policy ID and aggregates top destination
    ports, services, and applications. Useful for understanding what traffic
    a policy is actually handling.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        device: Device filter (serial number like "FG100FTK19001333" or name).
            Default: All FortiGate devices.
        policy_ids: List of firewall policy IDs to analyze (1-25 IDs, each > 0).
        time_range: Time range for log query. Options:
            - "1-hour", "6-hour", "12-hour", "24-hour" (default)
            - "7-day", "30-day"
            - Custom: "start_time|end_time"
        action: Filter by action (optional). Valid values:
            "accept", "deny", "close", "drop", "ip-conn", "timeout"
        top_n: Number of top items to return per category (default: 10)

    Returns:
        dict with keys:
            - status: "success" or "error"
            - results: Per-policy traffic profiles with top ports, services, apps
            - query_time_seconds: Total query duration
            - message: Error message if failed

    Example:
        >>> result = await get_policy_traffic_profile(
        ...     policy_ids=[1, 5, 10],
        ...     time_range="7-day",
        ...     action="accept"
        ... )
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        if policy_ids is None:
            return {"status": "error", "message": "policy_ids is required"}
        policy_ids = validate_policy_ids(policy_ids)
        action = validate_action(action)

        if top_n < 1:
            top_n = DEFAULT_TOP_N

        start = time.monotonic()

        # Query all policies concurrently
        tasks = [
            _query_policy_logs(adom, device, pid, time_range, action)
            for pid in policy_ids
        ]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        per_policy = []
        for pid, result in zip(policy_ids, results_list, strict=True):
            if isinstance(result, Exception):
                per_policy.append({
                    "policy_id": pid,
                    "error": str(result),
                })
            else:
                profile = _aggregate_traffic_profile(result, top_n)
                profile["policy_id"] = pid
                per_policy.append(profile)

        elapsed = time.monotonic() - start

        return {
            "status": "success",
            "results": per_policy,
            "query_time_seconds": round(elapsed, 2),
        }

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except RuntimeError as e:
        return {"status": "error", "message": str(e)}
    except (OSError, TimeoutError) as e:
        logger.error(f"Network error in get_policy_traffic_profile: {e}")
        return {"status": "error", "message": f"Network error: {e}"}


@mcp.tool()
async def get_policy_port_analysis(
    adom: str | None = None,
    device: str | None = None,
    policy_ids: list[int] | None = None,
    time_range: str = "24-hour",
    action: str | None = None,
) -> dict[str, Any]:
    """Get exact port/protocol enumeration per firewall policy.

    Enumerates all destination ports and protocols observed in traffic logs
    for each policy. Returns complete lists (not sampled) with an is_exact
    indicator. Useful for identifying exactly which ports are in use for
    policy tightening.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        device: Device filter (serial number like "FG100FTK19001333" or name).
            Default: All FortiGate devices.
        policy_ids: List of firewall policy IDs to analyze (1-25 IDs, each > 0).
        time_range: Time range for log query. Options:
            - "1-hour", "6-hour", "12-hour", "24-hour" (default)
            - "7-day", "30-day"
            - Custom: "start_time|end_time"
        action: Filter by action (optional). Valid values:
            "accept", "deny", "close", "drop", "ip-conn", "timeout"

    Returns:
        dict with keys:
            - status: "success" or "error"
            - results: Per-policy port analysis with:
                - is_exact: Whether the port list is complete
                - ports: List of port/protocol pairs with hit counts
                - protocols: Protocol breakdown
                - portless_protocols: Protocols without ports (ICMP, GRE, etc.)
                - uncovered_port_hits: Hits without a destination port
                - icmp: ICMP type/code breakdown (if applicable)
            - query_time_seconds: Total query duration
            - message: Error message if failed

    Example:
        >>> result = await get_policy_port_analysis(
        ...     policy_ids=[1],
        ...     time_range="7-day"
        ... )
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        if policy_ids is None:
            return {"status": "error", "message": "policy_ids is required"}
        policy_ids = validate_policy_ids(policy_ids)
        action = validate_action(action)

        start = time.monotonic()

        tasks = [
            _query_policy_logs(adom, device, pid, time_range, action)
            for pid in policy_ids
        ]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        per_policy = []
        for pid, result in zip(policy_ids, results_list, strict=True):
            if isinstance(result, Exception):
                per_policy.append({
                    "policy_id": pid,
                    "error": str(result),
                })
            else:
                analysis = _aggregate_port_analysis(result)
                analysis["policy_id"] = pid
                per_policy.append(analysis)

        elapsed = time.monotonic() - start

        return {
            "status": "success",
            "results": per_policy,
            "query_time_seconds": round(elapsed, 2),
        }

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except RuntimeError as e:
        return {"status": "error", "message": str(e)}
    except (OSError, TimeoutError) as e:
        logger.error(f"Network error in get_policy_port_analysis: {e}")
        return {"status": "error", "message": f"Network error: {e}"}


@mcp.tool()
async def get_policy_protocol_summary(
    adom: str | None = None,
    device: str | None = None,
    policy_ids: list[int] | None = None,
    time_range: str = "24-hour",
    action: str | None = None,
) -> dict[str, Any]:
    """Get lightweight protocol breakdown per firewall policy.

    Returns TCP/UDP/ICMP/other hit counts per policy. This is a faster,
    less detailed alternative to get_policy_port_analysis when only the
    protocol distribution is needed.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        device: Device filter (serial number like "FG100FTK19001333" or name).
            Default: All FortiGate devices.
        policy_ids: List of firewall policy IDs to analyze (1-25 IDs, each > 0).
        time_range: Time range for log query. Options:
            - "1-hour", "6-hour", "12-hour", "24-hour" (default)
            - "7-day", "30-day"
            - Custom: "start_time|end_time"
        action: Filter by action (optional). Valid values:
            "accept", "deny", "close", "drop", "ip-conn", "timeout"

    Returns:
        dict with keys:
            - status: "success" or "error"
            - results: Per-policy protocol summaries with hit counts
            - query_time_seconds: Total query duration
            - message: Error message if failed

    Example:
        >>> result = await get_policy_protocol_summary(
        ...     policy_ids=[1, 5],
        ...     time_range="24-hour"
        ... )
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        if policy_ids is None:
            return {"status": "error", "message": "policy_ids is required"}
        policy_ids = validate_policy_ids(policy_ids)
        action = validate_action(action)

        start = time.monotonic()

        tasks = [
            _query_policy_logs(adom, device, pid, time_range, action)
            for pid in policy_ids
        ]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        per_policy = []
        for pid, result in zip(policy_ids, results_list, strict=True):
            if isinstance(result, Exception):
                per_policy.append({
                    "policy_id": pid,
                    "error": str(result),
                })
            else:
                summary = _aggregate_protocol_summary(result)
                summary["policy_id"] = pid
                per_policy.append(summary)

        elapsed = time.monotonic() - start

        return {
            "status": "success",
            "results": per_policy,
            "query_time_seconds": round(elapsed, 2),
        }

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except RuntimeError as e:
        return {"status": "error", "message": str(e)}
    except (OSError, TimeoutError) as e:
        logger.error(f"Network error in get_policy_protocol_summary: {e}")
        return {"status": "error", "message": f"Network error: {e}"}
