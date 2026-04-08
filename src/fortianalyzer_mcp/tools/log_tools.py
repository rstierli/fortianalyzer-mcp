"""Log query and analysis tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 LogView API specifications.
Implements the two-step TID-based log search workflow.
"""

import asyncio
import logging
import math
import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    get_default_adom,
    validate_adom,
    validate_log_type,
)

logger = logging.getLogger(__name__)

# Default search timeout in seconds
DEFAULT_SEARCH_TIMEOUT = 60
# Poll interval for search progress
POLL_INTERVAL = 1.0
# Policy usage profiling defaults
DEFAULT_POLICY_PROFILE_TIMEOUT = 20
DEFAULT_POLICY_SAMPLE_LIMIT = 25
DEFAULT_POLICY_CANDIDATE_LIMIT = 12
DEFAULT_POLICY_MAX_DISCOVERY_SLICES = 4
DEFAULT_BATCH_DISCOVERY_QUERY_BUDGET = 24
DEFAULT_EXACT_MIN_SPLIT_HOURS = 6

PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    33: "DCCP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# Protocols that normally carry numeric source/destination ports.
PORT_BEARING_PROTOCOLS = {6, 17, 33, 132}


def _get_client():
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


async def _get_connected_client():
    """Get the FortiAnalyzer client and reconnect if needed."""
    client = _get_client()
    if not client.is_connected:
        await client.connect()
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


def _combine_filters(*filters: str | None) -> str | None:
    """Combine filter fragments using FortiAnalyzer syntax."""
    parts = [item.strip() for item in filters if item and item.strip()]
    return " and ".join(parts) if parts else None


def _parse_time_range_bounds(time_range: str) -> tuple[datetime, datetime]:
    """Parse time range into datetime bounds."""
    parsed = _parse_time_range(time_range)
    fmt = "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(parsed["start"], fmt), datetime.strptime(parsed["end"], fmt)


def _format_time_range(start: datetime, end: datetime) -> dict[str, str]:
    """Format datetime bounds for FortiAnalyzer APIs."""
    fmt = "%Y-%m-%d %H:%M:%S"
    return {"start": start.strftime(fmt), "end": end.strftime(fmt)}


def _parse_time_range_dict(time_range: dict[str, str]) -> tuple[datetime, datetime]:
    """Parse a FortiAnalyzer time-range dict into datetime bounds."""
    fmt = "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(time_range["start"], fmt), datetime.strptime(time_range["end"], fmt)


def _split_time_range_non_overlapping(
    time_range: dict[str, str],
) -> tuple[dict[str, str], dict[str, str]] | None:
    """Split a time range into two non-overlapping second-aligned ranges."""
    start, end = _parse_time_range_dict(time_range)
    span_seconds = int((end - start).total_seconds())
    if span_seconds <= 0:
        return None

    left_end = start + timedelta(seconds=span_seconds // 2)
    right_start = left_end + timedelta(seconds=1)
    if right_start > end:
        return None

    return _format_time_range(start, left_end), _format_time_range(right_start, end)


def _build_exact_time_slices(
    time_range: dict[str, str],
    slice_days: int,
) -> list[dict[str, str]]:
    """Build non-overlapping exact-count slices with second-level boundaries."""
    if slice_days <= 0:
        return [time_range]

    start, end = _parse_time_range_dict(time_range)
    if end <= start:
        return [time_range]

    step_seconds = max(int(timedelta(days=slice_days).total_seconds()), 1)
    cursor = start
    slices = []
    while cursor <= end:
        slice_end = min(cursor + timedelta(seconds=step_seconds - 1), end)
        slices.append(_format_time_range(cursor, slice_end))
        cursor = slice_end + timedelta(seconds=1)
    return slices


def _build_exact_slice_day_candidates(preferred_slice_days: int) -> list[int]:
    """Build descending exact slice-day candidates ending at 1 day."""
    days = max(preferred_slice_days, 1)
    candidates = []
    while days > 1:
        candidates.append(days)
        next_days = max(days // 2, 1)
        if next_days == days:
            break
        days = next_days
    candidates.append(1)
    return list(dict.fromkeys(candidates))


def _estimate_slice_count(start: datetime, end: datetime, slice_days: int) -> int:
    """Estimate how many slices a time range would produce."""
    if end <= start:
        return 1

    step_seconds = max(int(timedelta(days=max(slice_days, 1)).total_seconds()), 1)
    span_seconds = max(int((end - start).total_seconds()), 0)
    return max(1, math.ceil(span_seconds / step_seconds))


def _build_time_slices(
    time_range: str,
    slice_days: int,
    max_slices: int = DEFAULT_POLICY_MAX_DISCOVERY_SLICES,
) -> list[dict[str, str]]:
    """Split a time range into smaller slices for discovery sampling."""
    start, end = _parse_time_range_bounds(time_range)
    if end <= start:
        return [_format_time_range(start, end)]

    requested_slice_days = max(slice_days, 1)
    requested_slices = _estimate_slice_count(start, end, requested_slice_days)

    effective_slice_days = requested_slice_days
    if max_slices > 0 and requested_slices > max_slices:
        span_days = max((end - start).total_seconds() / 86400, 0)
        effective_slice_days = max(1, math.ceil(span_days / max_slices))

    step = timedelta(days=effective_slice_days)
    cursor = start
    slices = []
    while cursor < end:
        next_cursor = min(cursor + step, end)
        slices.append(_format_time_range(cursor, next_cursor))
        cursor = next_cursor
    return slices


def _estimate_discovery_queries_per_slice(fields: tuple[str, ...]) -> int:
    """Estimate discovery query fan-out for one time slice."""
    return 3 if "dstport" in fields else 1


def _plan_batch_slice_days(
    *,
    time_range: str,
    slice_days: int,
    policy_count: int,
    fields: tuple[str, ...],
) -> int:
    """Increase slice size for large batch requests to keep discovery bounded."""
    if policy_count <= 1:
        return max(slice_days, 1)

    start, end = _parse_time_range_bounds(time_range)
    requested_slice_days = max(slice_days, 1)
    requested_slices = _estimate_slice_count(start, end, requested_slice_days)
    per_slice_queries = _estimate_discovery_queries_per_slice(fields)
    max_slices_per_policy = max(
        1,
        DEFAULT_BATCH_DISCOVERY_QUERY_BUDGET // max(policy_count * per_slice_queries, 1),
    )

    if requested_slices <= max_slices_per_policy:
        return requested_slice_days

    span_days = max((end - start).total_seconds() / 86400, 0)
    return max(requested_slice_days, math.ceil(span_days / max_slices_per_policy))


def _normalize_sample_value(field: str, value: Any) -> str | None:
    """Normalize a sampled log value for counting/filtering."""
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    if field == "dstport":
        if not text.isdigit():
            return None
        port = int(text)
        if port <= 0:
            return None
        return str(port)

    if text == "0":
        return None

    return text


def _format_filter_value(value: str) -> str:
    """Format a FortiAnalyzer filter value."""
    if value.isdigit():
        return value

    if re.fullmatch(r"[A-Za-z0-9._:/-]+", value):
        return value

    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _build_policy_filter(policy_ids: list[int], action: str | None = None) -> str:
    """Build a policy filter for one or more policy IDs."""
    policy_terms = [f"policyid=={policy_id}" for policy_id in policy_ids]
    if len(policy_terms) == 1:
        policy_filter = policy_terms[0]
    else:
        policy_filter = f"({' or '.join(policy_terms)})"
    return _combine_filters(policy_filter, f"action=={action}" if action else None) or ""


def _build_port_range_filter(low: int, high: int) -> str:
    """Build a dstport filter for a single port or inclusive range."""
    if low == high:
        return f"dstport=={low}"
    return f"dstport>={low} and dstport<={high}"


def _build_protocol_range_filter(low: int, high: int) -> str:
    """Build a proto filter for a single IP protocol or inclusive range."""
    if low == high:
        return f"proto=={low}"
    return f"proto>={low} and proto<={high}"


def _build_port_exclusion_filter(ports: list[str]) -> str | None:
    """Build a dstport exclusion filter for known ports."""
    if not ports:
        return None
    return " and ".join(f"dstport!={port}" for port in ports)


def _build_residual_port_ranges(
    excluded_ports: list[int],
    low: int = 1,
    high: int = 65535,
) -> list[tuple[int, int]]:
    """Build non-overlapping port ranges excluding known ports."""
    ranges: list[tuple[int, int]] = []
    cursor = low
    for port in sorted(set(port for port in excluded_ports if low <= port <= high)):
        if cursor <= port - 1:
            ranges.append((cursor, port - 1))
        cursor = port + 1
    if cursor <= high:
        ranges.append((cursor, high))
    return ranges


async def _run_log_count(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    retries: int = 3,
) -> int:
    """Run a log search and return the exact matched log count."""
    last_error: Exception | None = None

    for attempt in range(retries):
        tid: int | None = None
        try:
            client = await _get_connected_client()
            start_result = await client.logsearch_start(
                adom=adom,
                logtype="traffic",
                device=device_filter,
                time_range=time_range,
                filter=filter_str,
                limit=1,
                offset=0,
            )
            tid = start_result.get("tid")
            if not tid:
                raise RuntimeError(f"No TID returned for count query: {start_result}")

            started = asyncio.get_event_loop().time()
            while True:
                if asyncio.get_event_loop().time() - started > timeout:
                    raise TimeoutError(
                        f"Count query timed out after {timeout}s for filter {filter_str}"
                    )

                result = await client.logsearch_count(adom, tid)
                if result.get("progress-percent", 0) >= 100:
                    return int(result.get("matched-logs", 0))

                await asyncio.sleep(POLL_INTERVAL)
        except Exception as exc:
            last_error = exc
            if attempt + 1 < retries:
                await asyncio.sleep(POLL_INTERVAL)
        finally:
            if tid:
                try:
                    await client.logsearch_cancel(adom, tid)
                except Exception:
                    pass

    raise RuntimeError(f"Count query failed for filter {filter_str}: {last_error}")


async def _run_log_count_resilient(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    stats: dict[str, int] | None = None,
    min_split_hours: int = DEFAULT_EXACT_MIN_SPLIT_HOURS,
) -> int:
    """Run an exact count query, splitting the time range if FAZ rejects long tasks."""
    if stats is not None:
        stats["count_attempts"] = stats.get("count_attempts", 0) + 1

    try:
        return await _run_log_count(
            adom=adom,
            device_filter=device_filter,
            time_range=time_range,
            filter_str=filter_str,
            timeout=timeout,
        )
    except Exception:
        start, end = _parse_time_range_dict(time_range)
        span = end - start
        if span <= timedelta(hours=max(min_split_hours, 1)):
            raise

        split_ranges = _split_time_range_non_overlapping(time_range)
        if not split_ranges:
            raise
        left_range, right_range = split_ranges

        if stats is not None:
            stats["fallback_splits"] = stats.get("fallback_splits", 0) + 1

        left_hits = await _run_log_count_resilient(
            adom=adom,
            device_filter=device_filter,
            time_range=left_range,
            filter_str=filter_str,
            timeout=timeout,
            stats=stats,
            min_split_hours=min_split_hours,
        )
        right_hits = await _run_log_count_resilient(
            adom=adom,
            device_filter=device_filter,
            time_range=right_range,
            filter_str=filter_str,
            timeout=timeout,
            stats=stats,
            min_split_hours=min_split_hours,
        )
        return left_hits + right_hits


async def _run_log_count_over_slices(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_slices: list[dict[str, str]],
    filter_str: str | None,
    timeout: int,
    stats: dict[str, int] | None = None,
) -> int:
    """Run exact counts over a fixed slice partition and sum the results."""
    total = 0
    for time_slice in time_slices:
        if stats is not None:
            stats["count_attempts"] = stats.get("count_attempts", 0) + 1
        total += await _run_log_count(
            adom=adom,
            device_filter=device_filter,
            time_range=time_slice,
            filter_str=filter_str,
            timeout=timeout,
        )
    return total


async def _run_log_count_exact(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    stats: dict[str, int] | None = None,
    slice_day_candidates: list[int] | None = None,
) -> int:
    """Run an exact count using progressively smaller fixed slice partitions."""
    candidates = slice_day_candidates or [1]
    last_error: Exception | None = None

    for slice_days in candidates:
        try:
            return await _run_log_count_over_slices(
                adom=adom,
                device_filter=device_filter,
                time_slices=_build_exact_time_slices(time_range, slice_days),
                filter_str=filter_str,
                timeout=timeout,
                stats=stats,
            )
        except Exception as exc:
            last_error = exc

    raise RuntimeError(f"Count query failed for filter {filter_str}: {last_error}")


async def _run_log_sample(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    limit: int,
    offset: int,
    timeout: int,
    retries: int = 2,
) -> list[dict[str, Any]]:
    """Run a bounded log query and return sampled log rows."""
    last_error: Exception | None = None

    for attempt in range(retries):
        tid: int | None = None
        try:
            client = await _get_connected_client()
            start_result = await client.logsearch_start(
                adom=adom,
                logtype="traffic",
                device=device_filter,
                time_range=time_range,
                filter=filter_str,
                limit=limit,
                offset=offset,
            )
            tid = start_result.get("tid")
            if not tid:
                raise RuntimeError(f"No TID returned for sample query: {start_result}")

            started = asyncio.get_event_loop().time()
            while True:
                if asyncio.get_event_loop().time() - started > timeout:
                    raise TimeoutError(
                        f"Sample query timed out after {timeout}s for filter {filter_str}"
                    )

                result = await client.logsearch_fetch(
                    adom=adom,
                    tid=tid,
                    limit=limit,
                    offset=offset,
                )
                if result.get("percentage", 0) >= 100:
                    rows = result.get("data", [])
                    if not isinstance(rows, list):
                        rows = [rows] if rows else []
                    return rows

                await asyncio.sleep(POLL_INTERVAL)
        except Exception as exc:
            last_error = exc
            if attempt + 1 < retries:
                await asyncio.sleep(POLL_INTERVAL)
        finally:
            if tid:
                try:
                    await client.logsearch_cancel(adom, tid)
                except Exception:
                    pass

    logger.warning(f"Sample query failed for filter {filter_str}: {last_error}")
    return []


async def _discover_policy_candidates(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    policy_filter: str,
    time_range: str,
    slice_days: int,
    sample_limit: int,
    timeout: int,
    fields: tuple[str, ...],
) -> tuple[dict[str, Counter[str]], dict[str, Any]]:
    """Sample logs across time slices to discover candidate values."""
    start, end = _parse_time_range_bounds(time_range)
    requested_slices = _estimate_slice_count(start, end, slice_days)
    slices = _build_time_slices(time_range, slice_days)
    base_offsets = [0, sample_limit] if len(slices) == 1 else [0]
    discovery_filters = [{"name": "base", "extra_filter": None, "offsets": base_offsets}]
    if "dstport" in fields:
        discovery_filters.extend(
            [
                {"name": "low-port", "extra_filter": "dstport<1024", "offsets": [0]},
                {
                    "name": "mid-port",
                    "extra_filter": "dstport>=1024 and dstport<=10000",
                    "offsets": [0],
                },
            ]
        )

    counters = {field: Counter() for field in fields}
    discovery = {
        "requested_slices": requested_slices,
        "slices_scanned": 0,
        "adaptive_sampling": len(slices) < requested_slices,
        "queries_attempted": 0,
        "sampled_logs": 0,
        "errors": [],
    }

    for time_slice in slices:
        discovery["slices_scanned"] += 1
        for query_shape in discovery_filters:
            filter_str = _combine_filters(policy_filter, query_shape["extra_filter"])
            for offset in query_shape["offsets"]:
                discovery["queries_attempted"] += 1
                rows = await _run_log_sample(
                    adom=adom,
                    device_filter=device_filter,
                    time_range=time_slice,
                    filter_str=filter_str,
                    limit=sample_limit,
                    offset=offset,
                    timeout=timeout,
                )

                if not rows:
                    continue

                discovery["sampled_logs"] += len(rows)
                for row in rows:
                    for field in counters:
                        normalized = _normalize_sample_value(field, row.get(field))
                        if normalized:
                            counters[field][normalized] += 1

    discovery["discovered_candidates"] = {
        field: len(counter) for field, counter in counters.items()
    }
    return counters, discovery


async def _count_discovered_values(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    base_filter: str,
    field: str,
    counter: Counter[str],
    candidate_limit: int,
    timeout: int,
    result_key: str,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], int]:
    """Count exact hits for the strongest discovered candidates."""
    ranked = []
    errors = []

    for value, _sample_hits in counter.most_common(candidate_limit):
        field_filter = f"{field}=={_format_filter_value(value)}"
        try:
            hits = await _run_log_count(
                adom=adom,
                device_filter=device_filter,
                time_range=time_range,
                filter_str=_combine_filters(base_filter, field_filter),
                timeout=timeout,
            )
        except Exception as exc:
            errors.append({"field": field, "value": value, "message": str(exc)})
            continue

        if hits > 0:
            ranked.append({result_key: value, "hits": hits})

    ranked.sort(key=lambda item: item["hits"], reverse=True)
    return ranked, errors, sum(item["hits"] for item in ranked)


async def _discover_multi_policy_candidates(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    policy_ids: list[int],
    action: str | None,
    time_range: str,
    slice_days: int,
    sample_limit: int,
    timeout: int,
    fields: tuple[str, ...],
) -> tuple[dict[int, dict[str, Counter[str]]], dict[str, Any]]:
    """Sample logs once for multiple policies and build per-policy counters."""
    policy_filter = _build_policy_filter(policy_ids, action)
    start, end = _parse_time_range_bounds(time_range)
    requested_slices = _estimate_slice_count(start, end, slice_days)
    slices = _build_time_slices(time_range, slice_days)
    base_offsets = [0, sample_limit] if len(slices) == 1 else [0]
    low_port_offsets = [0, sample_limit] if len(policy_ids) > 1 else [0]
    discovery_filters = [{"name": "base", "extra_filter": None, "offsets": base_offsets}]
    if "dstport" in fields:
        discovery_filters.extend(
            [
                {
                    "name": "low-port",
                    "extra_filter": "dstport<1024",
                    "offsets": low_port_offsets,
                },
                {
                    "name": "mid-port",
                    "extra_filter": "dstport>=1024 and dstport<=10000",
                    "offsets": [0],
                },
            ]
        )

    counters = {
        policy_id: {field: Counter() for field in fields} for policy_id in policy_ids
    }
    discovery = {
        "requested_slices": requested_slices,
        "slices_scanned": 0,
        "adaptive_sampling": len(slices) < requested_slices,
        "queries_attempted": 0,
        "sampled_logs": 0,
        "errors": [],
        "shared_across_policies": True,
        "policy_count": len(policy_ids),
    }

    active_policies = set(policy_ids)

    for time_slice in slices:
        discovery["slices_scanned"] += 1
        for query_shape in discovery_filters:
            filter_str = _combine_filters(policy_filter, query_shape["extra_filter"])
            for offset in query_shape["offsets"]:
                discovery["queries_attempted"] += 1
                rows = await _run_log_sample(
                    adom=adom,
                    device_filter=device_filter,
                    time_range=time_slice,
                    filter_str=filter_str,
                    limit=sample_limit,
                    offset=offset,
                    timeout=timeout,
                )

                if not rows:
                    continue

                discovery["sampled_logs"] += len(rows)
                for row in rows:
                    policy_value = _normalize_sample_value("policyid", row.get("policyid"))
                    if not policy_value or not policy_value.isdigit():
                        continue

                    policy_id = int(policy_value)
                    if policy_id not in active_policies:
                        continue

                    for field in counters[policy_id]:
                        normalized = _normalize_sample_value(field, row.get(field))
                        if normalized:
                            counters[policy_id][field][normalized] += 1

    discovery["discovered_candidates"] = {
        str(policy_id): {
            field: len(counter) for field, counter in field_counters.items()
        }
        for policy_id, field_counters in counters.items()
    }
    return counters, discovery


def _build_empty_policy_profile_result(
    *,
    policy_id: int,
    base_filter: str,
    time_range: dict[str, str],
    requested_fields: list[str],
    include_ports: bool,
    include_services: bool,
    include_applications: bool,
) -> dict[str, Any]:
    """Build a successful empty policy profile result."""
    return {
        "status": "success",
        "policy_id": policy_id,
        "filter_applied": base_filter,
        "time_range": time_range,
        "requested_fields": requested_fields,
        "total_hits": 0,
        "top_destination_ports": [],
        "top_services": [],
        "top_applications": [],
        "port_residual_hits": 0 if include_ports else None,
        "service_residual_hits": 0 if include_services else None,
        "application_residual_hits": 0 if include_applications else None,
        "discovery": {
            "requested_slices": 0,
            "slices_scanned": 0,
            "adaptive_sampling": False,
            "queries_attempted": 0,
            "sampled_logs": 0,
            "errors": [],
            "discovered_candidates": {field: 0 for field in requested_fields},
            "skipped_reason": "no_matching_logs",
        },
        "errors": [],
    }


async def _enumerate_exact_ports(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    slice_day_candidates: list[int] | None,
    base_filter: str,
    low: int,
    high: int,
    known_hits: int,
    timeout: int,
    stats: dict[str, int],
    min_split_hours: int = DEFAULT_EXACT_MIN_SPLIT_HOURS,
) -> list[dict[str, int | str]]:
    """Enumerate exact destination ports using recursive range counts."""
    if known_hits <= 0:
        return []

    if low == high:
        return [{"port": str(low), "hits": known_hits}]

    mid = (low + high) // 2
    stats["count_queries"] += 1
    left_filter = _combine_filters(base_filter, _build_port_range_filter(low, mid))
    left_hits = await _run_log_count_exact(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        filter_str=left_filter,
        timeout=timeout,
        stats=stats,
        slice_day_candidates=slice_day_candidates or [1],
    )
    right_hits = max(known_hits - left_hits, 0)

    left_results = await _enumerate_exact_ports(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        slice_day_candidates=slice_day_candidates,
        base_filter=base_filter,
        low=low,
        high=mid,
        known_hits=left_hits,
        timeout=timeout,
        stats=stats,
        min_split_hours=min_split_hours,
    )
    right_results = await _enumerate_exact_ports(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        slice_day_candidates=slice_day_candidates,
        base_filter=base_filter,
        low=mid + 1,
        high=high,
        known_hits=right_hits,
        timeout=timeout,
        stats=stats,
        min_split_hours=min_split_hours,
    )
    return left_results + right_results


async def _enumerate_exact_protocols(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    slice_day_candidates: list[int] | None,
    base_filter: str,
    low: int,
    high: int,
    known_hits: int,
    timeout: int,
    stats: dict[str, int],
) -> list[dict[str, int | str]]:
    """Enumerate exact IP protocols using recursive range counts."""
    if known_hits <= 0:
        return []

    if low == high:
        return [
            {
                "proto": str(low),
                "name": PROTOCOL_NAMES.get(low, f"IP_{low}"),
                "hits": known_hits,
            }
        ]

    mid = (low + high) // 2
    stats["protocol_range_queries"] = stats.get("protocol_range_queries", 0) + 1
    left_filter = _combine_filters(base_filter, _build_protocol_range_filter(low, mid))
    left_hits = await _run_log_count_exact(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        filter_str=left_filter,
        timeout=timeout,
        stats=stats,
        slice_day_candidates=slice_day_candidates or [1],
    )
    right_hits = max(known_hits - left_hits, 0)

    left_results = await _enumerate_exact_protocols(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        slice_day_candidates=slice_day_candidates,
        base_filter=base_filter,
        low=low,
        high=mid,
        known_hits=left_hits,
        timeout=timeout,
        stats=stats,
    )
    right_results = await _enumerate_exact_protocols(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        slice_day_candidates=slice_day_candidates,
        base_filter=base_filter,
        low=mid + 1,
        high=high,
        known_hits=right_hits,
        timeout=timeout,
        stats=stats,
    )
    return left_results + right_results


@mcp.tool()
async def query_logs(
    adom: str | None = None,
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
        adom: ADOM name (default: from config DEFAULT_ADOM)
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
        adom = validate_adom(adom or get_default_adom())
        logtype = validate_log_type(logtype)

        client = await _get_connected_client()

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
    adom: str | None = None,
    tid: int = 0,
) -> dict[str, Any]:
    """Get progress of an ongoing log search.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
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

        adom = adom or get_default_adom()
        client = await _get_connected_client()
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
    adom: str | None = None,
    tid: int = 0,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Fetch more logs from a completed search using TID.

    Use this for pagination after an initial query_logs call.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
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

        adom = adom or get_default_adom()
        client = await _get_connected_client()
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
    adom: str | None = None,
    tid: int = 0,
) -> dict[str, Any]:
    """Cancel an ongoing log search.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
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

        adom = adom or get_default_adom()
        client = await _get_connected_client()
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
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Get log statistics for an ADOM.

    Returns statistics about log storage, rates, and device logging status.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
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
        adom = adom or get_default_adom()
        client = await _get_connected_client()
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
    adom: str | None = None,
    logtype: str = "traffic",
    devtype: str = "FortiGate",
) -> dict[str, Any]:
    """Get available log fields for a log type.

    Useful for understanding what fields can be used in filters.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
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
        adom = adom or get_default_adom()
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
    adom: str | None = None,
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
        adom: ADOM name (default: from config DEFAULT_ADOM)
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
        adom = adom or get_default_adom()
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
async def get_policy_usage_profile(
    policy_id: int,
    adom: str | None = None,
    device: str | None = None,
    time_range: str = "7-day",
    action: str | None = None,
    slice_days: int = 1,
    sample_limit: int = DEFAULT_POLICY_SAMPLE_LIMIT,
    top_n: int = 10,
    candidate_limit: int = DEFAULT_POLICY_CANDIDATE_LIMIT,
    count_timeout: int = DEFAULT_POLICY_PROFILE_TIMEOUT,
    include_ports: bool = True,
    include_services: bool = True,
    include_applications: bool = True,
) -> dict[str, Any]:
    """Profile observed traffic for a firewall policy.

    This tool samples traffic logs across time slices to discover candidate
    destination ports, services, and applications, then uses exact log-search
    counts for those candidates across the full time window.

    Args:
        policy_id: Firewall policy ID to analyze
        adom: ADOM name (default: from config DEFAULT_ADOM)
        device: Device filter (serial number or device name)
        time_range: Time range, such as "7-day", "30-day", or "start|end"
        action: Optional traffic action filter ("accept", "deny", "close")
        slice_days: Discovery slice size in days (default: 1)
        sample_limit: Logs to sample per discovery query (default: 25)
        top_n: Number of exact results to return per category (default: 10)
        candidate_limit: Max discovered values to count exactly per category
        count_timeout: Timeout per exact count query in seconds (default: 20)

    Returns:
        dict with exact counts for discovered ports, services, and applications

    Example:
        >>> result = await get_policy_usage_profile(
        ...     policy_id=2,
        ...     device="MTL4DIF001",
        ...     time_range="30-day",
        ...     include_services=False,
        ...     include_applications=False,
        ... )
        >>> print(result["top_destination_ports"])
    """
    try:
        if policy_id <= 0:
            return {"status": "error", "message": "policy_id must be greater than 0"}

        requested_fields = []
        if include_ports:
            requested_fields.append("dstport")
        if include_services:
            requested_fields.append("service")
        if include_applications:
            requested_fields.append("app")

        if not requested_fields:
            return {
                "status": "error",
                "message": "At least one of include_ports, include_services, or include_applications must be true",
            }

        adom = validate_adom(adom or get_default_adom())
        device_filter = _build_device_filter(device)
        full_time_range = _parse_time_range(time_range)
        base_filter = _combine_filters(
            f"policyid=={policy_id}",
            f"action=={action}" if action else None,
        )

        total_hits = await _run_log_count(
            adom=adom,
            device_filter=device_filter,
            time_range=full_time_range,
            filter_str=base_filter,
            timeout=count_timeout,
        )

        if total_hits == 0:
            return _build_empty_policy_profile_result(
                policy_id=policy_id,
                base_filter=base_filter,
                time_range=full_time_range,
                requested_fields=requested_fields,
                include_ports=include_ports,
                include_services=include_services,
                include_applications=include_applications,
            )

        candidate_counters, discovery = await _discover_policy_candidates(
            adom=adom,
            device_filter=device_filter,
            policy_filter=base_filter,
            time_range=time_range,
            slice_days=slice_days,
            sample_limit=sample_limit,
            timeout=min(count_timeout, DEFAULT_SEARCH_TIMEOUT),
            fields=tuple(requested_fields),
        )

        candidate_limit = max(top_n, candidate_limit)
        ports, port_errors, ports_total = [], [], 0
        if include_ports:
            ports, port_errors, ports_total = await _count_discovered_values(
                adom=adom,
                device_filter=device_filter,
                time_range=full_time_range,
                base_filter=base_filter,
                field="dstport",
                counter=candidate_counters["dstport"],
                candidate_limit=candidate_limit,
                timeout=count_timeout,
                result_key="port",
            )

        services, service_errors, services_total = [], [], 0
        if include_services:
            services, service_errors, services_total = await _count_discovered_values(
                adom=adom,
                device_filter=device_filter,
                time_range=full_time_range,
                base_filter=base_filter,
                field="service",
                counter=candidate_counters["service"],
                candidate_limit=candidate_limit,
                timeout=count_timeout,
                result_key="service",
            )

        applications, app_errors, apps_total = [], [], 0
        if include_applications:
            applications, app_errors, apps_total = await _count_discovered_values(
                adom=adom,
                device_filter=device_filter,
                time_range=full_time_range,
                base_filter=base_filter,
                field="app",
                counter=candidate_counters["app"],
                candidate_limit=candidate_limit,
                timeout=count_timeout,
                result_key="application",
            )

        errors = port_errors + service_errors + app_errors + discovery["errors"]

        return {
            "status": "success",
            "policy_id": policy_id,
            "filter_applied": base_filter,
            "time_range": full_time_range,
            "requested_fields": requested_fields,
            "total_hits": total_hits,
            "top_destination_ports": ports[:top_n],
            "top_services": services[:top_n],
            "top_applications": applications[:top_n],
            "port_residual_hits": max(total_hits - ports_total, 0) if include_ports else None,
            "service_residual_hits": max(total_hits - services_total, 0) if include_services else None,
            "application_residual_hits": max(total_hits - apps_total, 0)
            if include_applications
            else None,
            "discovery": discovery,
            "errors": errors,
        }

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to profile policy {policy_id}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_multi_policy_usage_profile(
    policy_ids: list[int],
    adom: str | None = None,
    device: str | None = None,
    time_range: str = "7-day",
    action: str | None = None,
    slice_days: int = 1,
    sample_limit: int = DEFAULT_POLICY_SAMPLE_LIMIT,
    top_n: int = 10,
    candidate_limit: int = DEFAULT_POLICY_CANDIDATE_LIMIT,
    count_timeout: int = DEFAULT_POLICY_PROFILE_TIMEOUT,
    continue_on_error: bool = True,
    include_ports: bool = True,
    include_services: bool = True,
    include_applications: bool = True,
) -> dict[str, Any]:
    """Profile observed traffic for multiple firewall policies.

    This is a batch wrapper around get_policy_usage_profile so you can analyze
    several policies in one MCP call and get one combined response.

    Args:
        policy_ids: List of firewall policy IDs to analyze
        adom: ADOM name (default: from config DEFAULT_ADOM)
        device: Device filter (serial number or device name)
        time_range: Time range, such as "7-day", "30-day", or "start|end"
        action: Optional traffic action filter ("accept", "deny", "close")
        slice_days: Discovery slice size in days (default: 1)
        sample_limit: Logs to sample per discovery query (default: 25)
        top_n: Number of exact results to return per category (default: 10)
        candidate_limit: Max discovered values to count exactly per category
        count_timeout: Timeout per exact count query in seconds (default: 20)
        continue_on_error: Continue profiling other policies if one fails

    Returns:
        dict containing per-policy profiling results and a batch summary
    """
    try:
        if not policy_ids:
            return {"status": "error", "message": "policy_ids must not be empty"}

        unique_policy_ids = list(dict.fromkeys(policy_ids))
        if len(unique_policy_ids) > 25:
            return {
                "status": "error",
                "message": "policy_ids is too large; submit 25 or fewer policies per call",
            }

        requested_fields = []
        if include_ports:
            requested_fields.append("dstport")
        if include_services:
            requested_fields.append("service")
        if include_applications:
            requested_fields.append("app")

        if not requested_fields:
            return {
                "status": "error",
                "message": "At least one of include_ports, include_services, or include_applications must be true",
            }

        effective_slice_days = _plan_batch_slice_days(
            time_range=time_range,
            slice_days=slice_days,
            policy_count=len(unique_policy_ids),
            fields=tuple(requested_fields),
        )

        adom = validate_adom(adom or get_default_adom())
        device_filter = _build_device_filter(device)
        full_time_range = _parse_time_range(time_range)
        candidate_limit = max(top_n, candidate_limit)

        total_hits_by_policy = {}
        for policy_id in unique_policy_ids:
            base_filter = _build_policy_filter([policy_id], action)
            total_hits_by_policy[policy_id] = await _run_log_count(
                adom=adom,
                device_filter=device_filter,
                time_range=full_time_range,
                filter_str=base_filter,
                timeout=count_timeout,
            )

        active_policy_ids = [
            policy_id for policy_id in unique_policy_ids if total_hits_by_policy[policy_id] > 0
        ]

        shared_counters = {
            policy_id: {field: Counter() for field in requested_fields}
            for policy_id in active_policy_ids
        }
        shared_discovery = {
            "requested_slices": 0,
            "slices_scanned": 0,
            "adaptive_sampling": False,
            "queries_attempted": 0,
            "sampled_logs": 0,
            "errors": [],
            "shared_across_policies": len(active_policy_ids) > 1,
            "policy_count": len(active_policy_ids),
        }

        if active_policy_ids:
            shared_counters, shared_discovery = await _discover_multi_policy_candidates(
                adom=adom,
                device_filter=device_filter,
                policy_ids=active_policy_ids,
                action=action,
                time_range=time_range,
                slice_days=effective_slice_days,
                sample_limit=sample_limit,
                timeout=min(count_timeout, DEFAULT_SEARCH_TIMEOUT),
                fields=tuple(requested_fields),
            )

        results = []
        failed_policy_ids = []

        for policy_id in unique_policy_ids:
            base_filter = _build_policy_filter([policy_id], action)
            total_hits = total_hits_by_policy[policy_id]

            if total_hits == 0:
                result = _build_empty_policy_profile_result(
                    policy_id=policy_id,
                    base_filter=base_filter,
                    time_range=full_time_range,
                    requested_fields=requested_fields,
                    include_ports=include_ports,
                    include_services=include_services,
                    include_applications=include_applications,
                )
                result["discovery"]["shared_across_policies"] = len(active_policy_ids) > 1
                result["discovery"]["policy_count"] = len(active_policy_ids)
            else:
                counters = shared_counters[policy_id]
                ports, port_errors, ports_total = [], [], 0
                if include_ports:
                    ports, port_errors, ports_total = await _count_discovered_values(
                        adom=adom,
                        device_filter=device_filter,
                        time_range=full_time_range,
                        base_filter=base_filter,
                        field="dstport",
                        counter=counters["dstport"],
                        candidate_limit=candidate_limit,
                        timeout=count_timeout,
                        result_key="port",
                    )

                services, service_errors, services_total = [], [], 0
                if include_services:
                    services, service_errors, services_total = await _count_discovered_values(
                        adom=adom,
                        device_filter=device_filter,
                        time_range=full_time_range,
                        base_filter=base_filter,
                        field="service",
                        counter=counters["service"],
                        candidate_limit=candidate_limit,
                        timeout=count_timeout,
                        result_key="service",
                    )

                applications, app_errors, apps_total = [], [], 0
                if include_applications:
                    applications, app_errors, apps_total = await _count_discovered_values(
                        adom=adom,
                        device_filter=device_filter,
                        time_range=full_time_range,
                        base_filter=base_filter,
                        field="app",
                        counter=counters["app"],
                        candidate_limit=candidate_limit,
                        timeout=count_timeout,
                        result_key="application",
                    )

                discovery = {
                    "requested_slices": shared_discovery["requested_slices"],
                    "slices_scanned": shared_discovery["slices_scanned"],
                    "adaptive_sampling": shared_discovery["adaptive_sampling"],
                    "queries_attempted": shared_discovery["queries_attempted"],
                    "sampled_logs": shared_discovery["sampled_logs"],
                    "errors": list(shared_discovery["errors"]),
                    "shared_across_policies": True,
                    "policy_count": len(active_policy_ids),
                    "discovered_candidates": {
                        field: len(counter) for field, counter in counters.items()
                    },
                }
                errors = port_errors + service_errors + app_errors + list(
                    shared_discovery["errors"]
                )
                result = {
                    "status": "success",
                    "policy_id": policy_id,
                    "filter_applied": base_filter,
                    "time_range": full_time_range,
                    "requested_fields": requested_fields,
                    "total_hits": total_hits,
                    "top_destination_ports": ports[:top_n],
                    "top_services": services[:top_n],
                    "top_applications": applications[:top_n],
                    "port_residual_hits": max(total_hits - ports_total, 0)
                    if include_ports
                    else None,
                    "service_residual_hits": max(total_hits - services_total, 0)
                    if include_services
                    else None,
                    "application_residual_hits": max(total_hits - apps_total, 0)
                    if include_applications
                    else None,
                    "discovery": discovery,
                    "errors": errors,
                }

            results.append(result)

            if result.get("status") != "success":
                failed_policy_ids.append(policy_id)
                if not continue_on_error:
                    break

        return {
            "status": "success" if not failed_policy_ids else "partial_success",
            "policy_count": len(unique_policy_ids),
            "successful_policies": len(unique_policy_ids) - len(failed_policy_ids),
            "failed_policies": failed_policy_ids,
            "effective_slice_days": effective_slice_days,
            "results": results,
        }

    except Exception as e:
        logger.error(f"Failed to profile multiple policies {policy_ids}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_exact_policy_port_usage(
    policy_id: int,
    adom: str | None = None,
    device: str | None = None,
    time_range: str = "7-day",
    action: str | None = None,
    count_timeout: int = DEFAULT_POLICY_PROFILE_TIMEOUT,
    min_split_hours: int = DEFAULT_EXACT_MIN_SPLIT_HOURS,
    exact_slice_days: int = 15,
    seed_slice_days: int = 1,
    seed_sample_limit: int = DEFAULT_POLICY_SAMPLE_LIMIT,
    seed_candidate_limit: int = DEFAULT_POLICY_CANDIDATE_LIMIT,
    seed_ports_override: list[int] | None = None,
) -> dict[str, Any]:
    """Get exact destination-port usage for a firewall policy.

    Unlike sampling-based profile tools, this enumerates ports exactly by
    recursively splitting the dstport space and verifying coverage against the
    policy's total hit count for the fixed time window.
    """
    try:
        if policy_id <= 0:
            return {"status": "error", "message": "policy_id must be greater than 0"}

        adom = validate_adom(adom or get_default_adom())
        device_filter = _build_device_filter(device)
        full_time_range = _parse_time_range(time_range)
        exact_slice_day_candidates = _build_exact_slice_day_candidates(exact_slice_days)
        base_filter = _build_policy_filter([policy_id], action)
        stats = {"count_queries": 0, "count_attempts": 0, "fallback_splits": 0}
        total_hits = await _run_log_count_exact(
            adom=adom,
            device_filter=device_filter,
            time_range=full_time_range,
            filter_str=base_filter,
            timeout=count_timeout,
            stats=stats,
            slice_day_candidates=exact_slice_day_candidates,
        )

        if total_hits == 0:
            return {
                "status": "success",
                "policy_id": policy_id,
                "filter_applied": base_filter,
                "time_range": full_time_range,
                "total_hits": 0,
                "numeric_protocol_hits": 0,
                "protocolless_hits": 0,
                "numeric_port_hits": 0,
                "covered_port_hits": 0,
                "uncovered_port_hits": 0,
                "portless_hits": 0,
                "protocols": [],
                "portless_protocols": [],
                "portless_protocol_hits": 0,
                "portless_unclassified_hits": 0,
                "icmp": {
                    "hits": 0,
                    "ping_hits": 0,
                    "other_icmp_hits": 0,
                },
                "is_exact": True,
                "ports": [],
                "seed_ports": [],
                "query_stats": {
                    "preflight_queries": 1,
                    "range_queries": 0,
                    "protocol_range_queries": 0,
                    "count_attempts": stats["count_attempts"],
                    "fallback_splits": stats["fallback_splits"],
                    "total_queries": 1,
                },
            }

        numeric_protocol_filter = _build_protocol_range_filter(0, 255)
        protocol_filter = _combine_filters(base_filter, numeric_protocol_filter)
        numeric_protocol_hits = await _run_log_count_exact(
            adom=adom,
            device_filter=device_filter,
            time_range=full_time_range,
            filter_str=protocol_filter,
            timeout=count_timeout,
            stats=stats,
            slice_day_candidates=exact_slice_day_candidates,
        )
        exact_protocols = await _enumerate_exact_protocols(
            adom=adom,
            device_filter=device_filter,
            time_range=full_time_range,
            slice_day_candidates=exact_slice_day_candidates,
            base_filter=base_filter,
            low=0,
            high=255,
            known_hits=numeric_protocol_hits,
            timeout=count_timeout,
            stats=stats,
        )
        exact_protocols.sort(
            key=lambda item: (-int(item["hits"]), int(item["proto"]))
        )
        portless_protocols = [
            item
            for item in exact_protocols
            if int(item["proto"]) not in PORT_BEARING_PROTOCOLS
        ]
        portless_protocol_hits = sum(int(item["hits"]) for item in portless_protocols)
        protocolless_hits = max(total_hits - numeric_protocol_hits, 0)

        numeric_port_filter = _build_port_range_filter(1, 65535)
        numeric_filter = _combine_filters(base_filter, numeric_port_filter)
        numeric_port_hits = await _run_log_count_exact(
            adom=adom,
            device_filter=device_filter,
            time_range=full_time_range,
            filter_str=numeric_filter,
            timeout=count_timeout,
            stats=stats,
            slice_day_candidates=exact_slice_day_candidates,
        )

        candidate_counters, discovery = await _discover_policy_candidates(
            adom=adom,
            device_filter=device_filter,
            policy_filter=base_filter,
            time_range=time_range,
            slice_days=seed_slice_days,
            sample_limit=seed_sample_limit,
            timeout=min(count_timeout, DEFAULT_SEARCH_TIMEOUT),
            fields=("dstport",),
        )

        discovered_seed_ports = [
            value
            for value, _sample_hits in candidate_counters["dstport"].most_common(seed_candidate_limit)
        ]
        manual_seed_ports = [
            str(port)
            for port in (seed_ports_override or [])
            if isinstance(port, int) and 1 <= port <= 65535
        ]
        seed_ports = list(dict.fromkeys(discovered_seed_ports + manual_seed_ports))
        seeded_ports = []
        seeded_total_hits = 0
        for port in seed_ports:
            port_filter = _combine_filters(base_filter, f"dstport=={port}")
            hits = await _run_log_count_exact(
                adom=adom,
                device_filter=device_filter,
                time_range=full_time_range,
                filter_str=port_filter,
                timeout=count_timeout,
                stats=stats,
                slice_day_candidates=exact_slice_day_candidates,
            )
            if hits > 0:
                seeded_ports.append({"port": port, "hits": hits})
                seeded_total_hits += hits

        residual_ports = []
        residual_ranges = _build_residual_port_ranges(
            [int(item["port"]) for item in seeded_ports]
        )
        for range_low, range_high in residual_ranges:
            range_filter = _combine_filters(base_filter, _build_port_range_filter(range_low, range_high))
            range_hits = await _run_log_count_exact(
                adom=adom,
                device_filter=device_filter,
                time_range=full_time_range,
                filter_str=range_filter,
                timeout=count_timeout,
                stats=stats,
                slice_day_candidates=exact_slice_day_candidates,
            )

            if range_hits <= 0:
                continue

            residual_ports.extend(
                await _enumerate_exact_ports(
                    adom=adom,
                    device_filter=device_filter,
                    time_range=full_time_range,
                    slice_day_candidates=exact_slice_day_candidates,
                    base_filter=base_filter,
                    low=range_low,
                    high=range_high,
                    known_hits=range_hits,
                    timeout=count_timeout,
                    stats=stats,
                    min_split_hours=min_split_hours,
                )
            )

        ports = seeded_ports + residual_ports
        merged_ports: dict[str, int] = {}
        for item in ports:
            port = str(item["port"])
            merged_ports[port] = merged_ports.get(port, 0) + int(item["hits"])
        exact_ports = [
            {"port": port, "hits": hits}
            for port, hits in merged_ports.items()
            if hits > 0
        ]
        exact_ports.sort(key=lambda item: (-int(item["hits"]), int(item["port"])))

        covered_port_hits = sum(int(item["hits"]) for item in exact_ports)
        uncovered_port_hits = max(numeric_port_hits - covered_port_hits, 0)
        portless_hits = max(total_hits - numeric_port_hits, 0)
        portless_unclassified_hits = max(portless_hits - portless_protocol_hits, 0)

        icmp_hits = next(
            (int(item["hits"]) for item in exact_protocols if item["proto"] == "1"),
            0,
        )
        ping_hits = 0
        if icmp_hits > 0:
            ping_hits = await _run_log_count_exact(
                adom=adom,
                device_filter=device_filter,
                time_range=full_time_range,
                filter_str=_combine_filters(base_filter, "proto==1", "service==PING"),
                timeout=count_timeout,
                stats=stats,
                slice_day_candidates=exact_slice_day_candidates,
            )

        return {
            "status": "success",
            "policy_id": policy_id,
            "filter_applied": base_filter,
            "time_range": full_time_range,
            "total_hits": total_hits,
            "numeric_protocol_hits": numeric_protocol_hits,
            "protocolless_hits": protocolless_hits,
            "numeric_port_hits": numeric_port_hits,
            "covered_port_hits": covered_port_hits,
            "uncovered_port_hits": uncovered_port_hits,
            "portless_hits": portless_hits,
            "protocols": exact_protocols,
            "portless_protocols": portless_protocols,
            "portless_protocol_hits": portless_protocol_hits,
            "portless_unclassified_hits": portless_unclassified_hits,
            "icmp": {
                "hits": icmp_hits,
                "ping_hits": ping_hits,
                "other_icmp_hits": max(icmp_hits - ping_hits, 0),
            },
            "is_exact": uncovered_port_hits == 0,
            "ports": exact_ports,
            "seed_ports": [item["port"] for item in seeded_ports],
            "seed_discovery": discovery,
            "query_stats": {
                "preflight_queries": 3,
                "slice_day_candidates": exact_slice_day_candidates,
                "range_queries": stats["count_queries"],
                "protocol_range_queries": stats.get("protocol_range_queries", 0),
                "count_attempts": stats["count_attempts"],
                "fallback_splits": stats["fallback_splits"],
                "total_queries": stats["count_attempts"],
            },
        }

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to get exact port usage for policy {policy_id}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_exact_multi_policy_port_usage(
    policy_ids: list[int],
    adom: str | None = None,
    device: str | None = None,
    time_range: str = "7-day",
    action: str | None = None,
    count_timeout: int = DEFAULT_POLICY_PROFILE_TIMEOUT,
    min_split_hours: int = DEFAULT_EXACT_MIN_SPLIT_HOURS,
    exact_slice_days: int = 15,
    seed_slice_days: int = 1,
    seed_sample_limit: int = DEFAULT_POLICY_SAMPLE_LIMIT,
    seed_candidate_limit: int = DEFAULT_POLICY_CANDIDATE_LIMIT,
    seed_ports_override: list[int] | None = None,
    continue_on_error: bool = True,
) -> dict[str, Any]:
    """Get exact destination-port usage for multiple firewall policies."""
    try:
        if not policy_ids:
            return {"status": "error", "message": "policy_ids must not be empty"}

        unique_policy_ids = list(dict.fromkeys(policy_ids))
        if len(unique_policy_ids) > 25:
            return {
                "status": "error",
                "message": "policy_ids is too large; submit 25 or fewer policies per call",
            }

        results = []
        failed_policy_ids = []

        for policy_id in unique_policy_ids:
            result = await get_exact_policy_port_usage(
                policy_id=policy_id,
                adom=adom,
                device=device,
                time_range=time_range,
                action=action,
                count_timeout=count_timeout,
                min_split_hours=min_split_hours,
                exact_slice_days=exact_slice_days,
                seed_slice_days=seed_slice_days,
                seed_sample_limit=seed_sample_limit,
                seed_candidate_limit=seed_candidate_limit,
                seed_ports_override=seed_ports_override,
            )
            results.append(result)
            if result.get("status") != "success":
                failed_policy_ids.append(policy_id)
                if not continue_on_error:
                    break

        return {
            "status": "success" if not failed_policy_ids else "partial_success",
            "policy_count": len(unique_policy_ids),
            "successful_policies": len(unique_policy_ids) - len(failed_policy_ids),
            "failed_policies": failed_policy_ids,
            "results": results,
        }

    except Exception as e:
        logger.error(f"Failed to get exact multi-policy port usage for {policy_ids}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def search_security_logs(
    adom: str | None = None,
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
        adom: ADOM name (default: from config DEFAULT_ADOM)
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
        adom = adom or get_default_adom()
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
    adom: str | None = None,
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
        adom: ADOM name (default: from config DEFAULT_ADOM)
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
        adom = adom or get_default_adom()
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
    adom: str | None = None,
    device: str | None = None,
    vdom: str | None = None,
    time_range: str | None = None,
) -> dict[str, Any]:
    """Get log file state information.

    Lists available log files on disk for a device/VDOM.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
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
        adom = adom or get_default_adom()
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
