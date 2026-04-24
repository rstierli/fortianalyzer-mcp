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
from datetime import datetime, timedelta
from typing import Any, cast

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
LOG_FETCH_LIMIT = 1000
ANALYSIS_QUERY_BUDGET = 24
MAX_SLICES_PER_POLICY = 4
MAX_POLICY_IDS = ANALYSIS_QUERY_BUDGET
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
            f"Invalid action '{action}'. Allowed values: {', '.join(sorted(VALID_ACTIONS))}"
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
            raise ValidationError(f"Invalid policy ID: {pid}. Must be a positive integer.")
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


def _get_client() -> Any:
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
    now = datetime.now()
    fmt = "%Y-%m-%d %H:%M:%S"

    if "|" in time_range:
        parts = time_range.split("|", maxsplit=1)
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


def _parse_time_range_bounds(time_range: dict[str, str]) -> tuple[datetime, datetime]:
    """Parse a FortiAnalyzer time range dict into datetime bounds."""
    fmt = "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(time_range["start"], fmt), datetime.strptime(time_range["end"], fmt)


def _format_time_range(start: datetime, end: datetime) -> dict[str, str]:
    """Format datetime bounds for FortiAnalyzer APIs."""
    fmt = "%Y-%m-%d %H:%M:%S"
    return {"start": start.strftime(fmt), "end": end.strftime(fmt)}


def _plan_policy_slice_count(
    time_range: dict[str, str],
    policy_count: int,
) -> int:
    """Plan a fixed bounded slice count per policy for a tool call."""
    start, end = _parse_time_range_bounds(time_range)
    if end - start <= timedelta(hours=24):
        return 1
    return min(MAX_SLICES_PER_POLICY, max(1, ANALYSIS_QUERY_BUDGET // max(policy_count, 1)))


def _build_bounded_time_slices(
    time_range: dict[str, str],
    slice_count: int,
) -> list[dict[str, str]]:
    """Split a time range into a fixed number of non-overlapping slices."""
    start, end = _parse_time_range_bounds(time_range)
    if slice_count <= 1 or end <= start:
        return [time_range]

    total_seconds = max(1, int((end - start).total_seconds()) + 1)
    effective_count = min(max(slice_count, 1), total_seconds)
    slices = []

    for index in range(effective_count):
        slice_start = start + timedelta(seconds=(total_seconds * index) // effective_count)
        slice_end = start + timedelta(seconds=(total_seconds * (index + 1)) // effective_count - 1)
        slices.append(_format_time_range(slice_start, min(slice_end, end)))

    return slices


def _build_device_filter(device: str | None) -> list[dict[str, str]]:
    """Build device filter for API. Mirrors log_tools._build_device_filter."""
    if not device:
        return [{"devid": "All_FortiGate"}]
    if device.startswith(("FG", "FM", "FW", "FA", "FS", "FD", "FP", "FC")):
        return [{"devid": device}]
    if device.startswith("All_"):
        return [{"devid": device}]
    return [{"devname": device}]


async def _query_policy_log_slice(
    adom: str,
    device_filter: list[dict[str, str]],
    policy_id: int,
    time_range: dict[str, str],
    action: str | None,
    limit: int = LOG_FETCH_LIMIT,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> list[dict[str, Any]]:
    """Query traffic logs for a single policy/time slice."""
    client = _get_client()
    filter_str = _build_policy_filter(policy_id, action)

    start_result = await client.logsearch_start(
        adom=adom,
        logtype="traffic",
        device=device_filter,
        time_range=time_range,
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
            return [log for log in logs if isinstance(log, dict)]

        await asyncio.sleep(POLL_INTERVAL)


async def _query_policy_logs(
    adom: str,
    device: str | None,
    policy_id: int,
    time_range: str,
    action: str | None,
    limit: int = LOG_FETCH_LIMIT,
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
        time_range_dict = _parse_time_range(time_range)
        device_filter = _build_device_filter(device)
        return await _query_policy_log_slice(
            adom=adom,
            device_filter=device_filter,
            policy_id=policy_id,
            time_range=time_range_dict,
            limit=limit,
            action=action,
            timeout=timeout,
        )


async def _query_policy_logs_bounded(
    adom: str,
    device: str | None,
    policy_id: int,
    time_range: str,
    action: str | None,
    policy_count: int,
    limit: int = LOG_FETCH_LIMIT,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Query fixed bounded slices for one policy and report truncation metadata."""
    async with _QUERY_SEMAPHORE:
        full_time_range = _parse_time_range(time_range)
        device_filter = _build_device_filter(device)
        slice_count = _plan_policy_slice_count(full_time_range, policy_count)
        time_slices = _build_bounded_time_slices(full_time_range, slice_count)
        logs: list[dict[str, Any]] = []
        truncated_slices = 0

        for time_slice in time_slices:
            slice_logs = await _query_policy_log_slice(
                adom=adom,
                device_filter=device_filter,
                policy_id=policy_id,
                time_range=time_slice,
                action=action,
                limit=limit,
                timeout=timeout,
            )
            logs.extend(slice_logs)
            if len(slice_logs) >= limit:
                truncated_slices += 1

        return {
            "logs": logs,
            "slices_scanned": len(time_slices),
            "truncated_slices": truncated_slices,
        }


def _extract_policy_hit_count(row: dict[str, Any], action: str | None) -> int | None:
    """Extract a best-effort hit count from a FortiView policy-hits row."""
    key = "counts"
    if action == "accept":
        key = "count_pass"
    elif action in {"deny", "drop"}:
        key = "count_block"

    value = row.get(key)
    if value is None and key != "counts":
        value = row.get("counts")
    if value is None:
        return None
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return None


async def _estimate_policy_hits(
    adom: str,
    device: str | None,
    policy_ids: list[int],
    time_range: str,
    action: str | None,
    timeout: int = 30,
) -> dict[int, int]:
    """Fetch one bounded FortiView policy-hits page as optional metadata."""
    client = _get_client()
    device_filter = _build_device_filter(device)
    time_range_dict = _parse_time_range(time_range)

    run_result = await client.fortiview_run(
        adom=adom,
        view_name="policy-hits",
        device=device_filter,
        time_range=time_range_dict,
        limit=1000,
        sort_by=[{"field": "counts", "order": "desc"}],
    )
    tid = run_result.get("tid")
    if not tid:
        return {}

    start_time = time.monotonic()
    while True:
        if time.monotonic() - start_time > timeout:
            return {}

        result = await client.fortiview_fetch(
            adom=adom,
            view_name="policy-hits",
            tid=tid,
        )
        rows = result.get("data", [])
        if not isinstance(rows, list):
            rows = [rows] if rows else []

        if result.get("percentage", 100) >= 100 or rows:
            wanted = set(policy_ids)
            estimates: dict[int, int] = {}
            for row in rows:
                if not isinstance(row, dict):
                    continue
                raw_policy_id = row.get("agg_policyid", row.get("policyid"))
                if raw_policy_id is None or not str(raw_policy_id).isdigit():
                    continue
                policy_id = int(raw_policy_id)
                if policy_id not in wanted:
                    continue
                hits = _extract_policy_hit_count(row, action)
                if hits is not None:
                    estimates[policy_id] = hits
            return estimates

        await asyncio.sleep(POLL_INTERVAL)


async def _estimate_policy_hits_best_effort(
    adom: str,
    device: str | None,
    policy_ids: list[int],
    time_range: str,
    action: str | None,
) -> dict[int, int]:
    """Return FortiView estimates when available without failing the caller."""
    try:
        return await _estimate_policy_hits(adom, device, policy_ids, time_range, action)
    except Exception as exc:
        logger.info(f"FortiView policy-hit estimate unavailable: {exc}")
        return {}


def _bounded_metadata(
    observed_hits: int,
    slices_scanned: int,
    truncated_slices: int,
    estimated_total_hits: int | None = None,
) -> dict[str, Any]:
    """Build common bounded-analysis response metadata."""
    is_exact = truncated_slices == 0
    metadata: dict[str, Any] = {
        "is_exact": is_exact,
        "analysis_mode": "complete" if is_exact else "bounded_sample",
        "observed_hits": observed_hits,
        "slices_scanned": slices_scanned,
        "truncated_slices": truncated_slices,
        "log_limit_per_slice": LOG_FETCH_LIMIT,
        "estimate_available": estimated_total_hits is not None,
    }
    if estimated_total_hits is not None:
        metadata["estimated_total_hits"] = estimated_total_hits
    if not is_exact:
        metadata["recommendation"] = (
            "Narrow the request to 24-hour, 6-hour, or a custom shorter window for exact proof."
        )
    return metadata


# =============================================================================
# Aggregation helpers
# =============================================================================


def _aggregate_traffic_profile(logs: list[dict[str, Any]], top_n: int) -> dict[str, Any]:
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


def _aggregate_port_analysis(logs: list[dict[str, Any]], limit: int = LOG_FETCH_LIMIT) -> dict[str, Any]:
    """Aggregate logs into port/protocol enumeration.

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

        # Track ICMP types from service field
        # FAZ logs encode ICMP info in service field, not icmptype/icmpcode:
        #   "PING" = echo request (type=8/code=0)
        #   "icmp/3/3" = type=3/code=3
        if proto_str == "1":
            service = str(log.get("service", ""))
            if service.upper() == "PING":
                icmp_types["type=8/code=0"] += 1
            elif service.startswith("icmp/"):
                parts = service.split("/")
                if len(parts) == 3:
                    icmp_types[f"type={parts[1]}/code={parts[2]}"] += 1
                else:
                    icmp_types[f"service={service}"] += 1
            elif service:
                icmp_types[f"service={service}"] += 1

    uncovered = total - port_hits

    return {
        "total_hits": total,
        "is_exact": len(logs) < limit,
        "ports": [{"port": p, "hits": c} for p, c in port_counter.most_common()],
        "protocols": [{"protocol": p, "hits": c} for p, c in protocol_counter.most_common()],
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
        "protocols": [{"protocol": p, "hits": c} for p, c in protocol_counter.most_common()],
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
        policy_ids: List of firewall policy IDs to analyze (1-24 IDs, each > 0).
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
        estimates = await _estimate_policy_hits_best_effort(adom, device, policy_ids, time_range, action)

        # Query all policies concurrently
        tasks = [
            _query_policy_logs_bounded(
                adom,
                device,
                pid,
                time_range,
                action,
                policy_count=len(policy_ids),
            )
            for pid in policy_ids
        ]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        per_policy = []
        for pid, result in zip(policy_ids, results_list, strict=True):
            if isinstance(result, Exception):
                per_policy.append(
                    {
                        "policy_id": pid,
                        "error": str(result),
                    }
                )
            else:
                policy_result = cast(dict[str, Any], result)
                logs = policy_result["logs"]
                profile = _aggregate_traffic_profile(logs, top_n)
                profile.update(
                    _bounded_metadata(
                        observed_hits=len(logs),
                        slices_scanned=policy_result["slices_scanned"],
                        truncated_slices=policy_result["truncated_slices"],
                        estimated_total_hits=estimates.get(pid),
                    )
                )
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
    """Get bounded port/protocol enumeration per firewall policy.

    Enumerates destination ports and protocols observed in fixed bounded traffic
    log slices for each policy. The result is exact only when no queried slice
    reaches the log fetch limit; otherwise it returns observed values with
    limitation metadata and a recommendation to narrow the time window.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        device: Device filter (serial number like "FG100FTK19001333" or name).
            Default: All FortiGate devices.
        policy_ids: List of firewall policy IDs to analyze (1-24 IDs, each > 0).
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
                - is_exact: Whether the port list is complete for queried window
                - analysis_mode: "complete" or "bounded_sample"
                - observed_hits: Number of log rows aggregated
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
        estimates = await _estimate_policy_hits_best_effort(adom, device, policy_ids, time_range, action)

        tasks = [
            _query_policy_logs_bounded(
                adom,
                device,
                pid,
                time_range,
                action,
                policy_count=len(policy_ids),
            )
            for pid in policy_ids
        ]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        per_policy = []
        for pid, result in zip(policy_ids, results_list, strict=True):
            if isinstance(result, Exception):
                per_policy.append(
                    {
                        "policy_id": pid,
                        "error": str(result),
                    }
                )
            else:
                policy_result = cast(dict[str, Any], result)
                logs = policy_result["logs"]
                analysis = _aggregate_port_analysis(logs, limit=LOG_FETCH_LIMIT)
                analysis.update(
                    _bounded_metadata(
                        observed_hits=len(logs),
                        slices_scanned=policy_result["slices_scanned"],
                        truncated_slices=policy_result["truncated_slices"],
                        estimated_total_hits=estimates.get(pid),
                    )
                )
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
        policy_ids: List of firewall policy IDs to analyze (1-24 IDs, each > 0).
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
        estimates = await _estimate_policy_hits_best_effort(adom, device, policy_ids, time_range, action)

        tasks = [
            _query_policy_logs_bounded(
                adom,
                device,
                pid,
                time_range,
                action,
                policy_count=len(policy_ids),
            )
            for pid in policy_ids
        ]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        per_policy = []
        for pid, result in zip(policy_ids, results_list, strict=True):
            if isinstance(result, Exception):
                per_policy.append(
                    {
                        "policy_id": pid,
                        "error": str(result),
                    }
                )
            else:
                policy_result = cast(dict[str, Any], result)
                logs = policy_result["logs"]
                summary = _aggregate_protocol_summary(logs)
                summary.update(
                    _bounded_metadata(
                        observed_hits=len(logs),
                        slices_scanned=policy_result["slices_scanned"],
                        truncated_slices=policy_result["truncated_slices"],
                        estimated_total_hits=estimates.get(pid),
                    )
                )
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
