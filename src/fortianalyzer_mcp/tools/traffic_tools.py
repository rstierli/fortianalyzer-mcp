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
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, cast

from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.tools.log_tools import (
    _run_logsearch_page,
)
from fortianalyzer_mcp.utils.log_clock import resolve_time_window
from fortianalyzer_mcp.utils.responses import error_response
from fortianalyzer_mcp.utils.time_range import (
    parse_time_range,
    parse_time_range_bounds,
)
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    build_device_filter,
    get_default_adom,
    validate_adom,
)

logger = logging.getLogger(__name__)

# Concurrency limit for parallel policy queries
_QUERY_SEMAPHORE = asyncio.Semaphore(5)

# Default and max search parameters
DEFAULT_SEARCH_TIMEOUT = 120
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
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
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


# parse_time_range_bounds is re-exported from utils.time_range above.
_parse_time_range_bounds = parse_time_range_bounds


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


# Shared device-filter construction (see utils.validation.build_device_filter).
_build_device_filter = build_device_filter


async def _query_policy_log_slice(
    adom: str,
    device_filter: list[dict[str, str]],
    policy_id: int,
    time_range: dict[str, str],
    action: str | None,
    limit: int = LOG_FETCH_LIMIT,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Query traffic logs and total-count for a single policy/time slice.

    Delegates to the shared :func:`_run_logsearch_page` runner, which polls
    ``logsearch_fetch`` against the official spec endpoint until ``percentage``
    reaches 100. The runner owns connection revival, limit/timeout clamping, the
    global concurrency guard, and all bounded re-issue/cancel recovery
    (invalid-tid races and premature-100% empty pages). On a timed-out page an
    empty result with an unknown total is returned.
    """
    client = _get_client()
    filter_str = _build_policy_filter(policy_id, action)

    try:
        page = await _run_logsearch_page(
            client,
            adom=adom,
            logtype="traffic",
            device_filter=device_filter,
            time_range=time_range,
            filter=filter_str,
            offset=0,
            limit=limit,
            timeout=timeout,
        )
    except RuntimeError as exc:
        # An abnormal start with no TID would abort the whole policy fan-out;
        # for one slice, degrade to an empty/unknown result (as the prior
        # fetch-first slice did) so other slices/policies still report.
        if "no TID returned" not in str(exc):
            raise
        logger.warning(f"No TID returned for policy {policy_id}: {exc}")
        return {"logs": [], "total_hits": None, "total_hits_is_known": False}

    if page["timed_out"]:
        logger.warning(f"Search timed out for policy {policy_id}")
        return {"logs": [], "total_hits": None, "total_hits_is_known": False}

    logs = [log for log in page["logs"] if isinstance(log, dict)]
    total_hits = page["total"]
    return {
        "logs": logs,
        "total_hits": total_hits,
        "total_hits_is_known": total_hits is not None,
    }


async def _query_policy_total_count(
    adom: str,
    device_filter: list[dict[str, str]],
    policy_id: int,
    time_range: dict[str, str],
    action: str | None,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Query authoritative log-search total-count for one full policy window."""
    result = await _query_policy_log_slice(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        time_range=time_range,
        action=action,
        limit=1,
        timeout=timeout,
    )
    total_hits = result.get("total_hits")
    total_hits_is_known = result.get("total_hits_is_known") is True
    return {
        "total_hits": total_hits if total_hits_is_known else None,
        "total_hits_is_known": total_hits_is_known,
    }


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
        time_range_dict = await _parse_time_range(time_range)
        device_filter = _build_device_filter(device)
        result = await _query_policy_log_slice(
            adom=adom,
            device_filter=device_filter,
            policy_id=policy_id,
            time_range=time_range_dict,
            limit=limit,
            action=action,
            timeout=timeout,
        )
        logs = result.get("logs", [])
        return logs if isinstance(logs, list) else []


async def _query_policy_logs_bounded(
    adom: str,
    device: str | None,
    policy_id: int,
    time_range: dict[str, str],
    action: str | None,
    policy_count: int,
    limit: int = LOG_FETCH_LIMIT,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Query fixed bounded slices for one policy and report truncation metadata.

    ``time_range`` is the already-resolved ``{start, end}`` window (resolved once
    by the caller) so slices and reported metadata share one window.
    """
    async with _QUERY_SEMAPHORE:
        full_time_range = time_range
        device_filter = _build_device_filter(device)
        slice_count = _plan_policy_slice_count(full_time_range, policy_count)
        time_slices = _build_bounded_time_slices(full_time_range, slice_count)
        logs: list[dict[str, Any]] = []
        truncated_slices = 0
        # The whole-window total-count is best-effort enrichment: its failure must
        # never discard the per-slice observations (degrade to observed_rows).
        try:
            total_result = await _query_policy_total_count(
                adom=adom,
                device_filter=device_filter,
                policy_id=policy_id,
                time_range=full_time_range,
                action=action,
                timeout=timeout,
            )
        except Exception as exc:
            logger.info(f"Total-count unavailable for policy {policy_id}: {exc}")
            total_result = {"total_hits": None, "total_hits_is_known": False}
        total_hits = total_result.get("total_hits")
        total_hits_is_known = total_result.get("total_hits_is_known") is True

        for time_slice in time_slices:
            slice_result = await _query_policy_log_slice(
                adom=adom,
                device_filter=device_filter,
                policy_id=policy_id,
                time_range=time_slice,
                action=action,
                limit=limit,
                timeout=timeout,
            )
            slice_logs = slice_result.get("logs", [])
            if not isinstance(slice_logs, list):
                slice_logs = []
            logs.extend(slice_logs)
            if len(slice_logs) >= limit:
                truncated_slices += 1

        return {
            "logs": logs,
            "slices_scanned": len(time_slices),
            "truncated_slices": truncated_slices,
            "total_hits": total_hits if total_hits_is_known else None,
            "total_hits_is_known": total_hits_is_known,
        }


def _bounded_metadata(
    observed_hits: int,
    slices_scanned: int,
    truncated_slices: int,
    total_hits: int | None = None,
    total_hits_is_known: bool = False,
) -> dict[str, Any]:
    """Build common bounded-analysis response metadata."""
    authoritative = total_hits if (total_hits_is_known and total_hits is not None) else None
    if authoritative is not None:
        resolved_total_hits = authoritative
        # "complete" must mean the breakdown covers exactly the authoritative
        # matching log count. Any mismatch keeps the result bounded.
        is_exact = truncated_slices == 0 and observed_hits == authoritative
    else:
        resolved_total_hits = observed_hits
        is_exact = truncated_slices == 0
    metadata: dict[str, Any] = {
        "is_exact": is_exact,
        "analysis_mode": "complete" if is_exact else "bounded_sample",
        "total_hits": resolved_total_hits,
        "total_hits_is_known": total_hits_is_known,
        "total_hit_source": "logsearch_total-count" if total_hits_is_known else "observed_rows",
        "observed_hits": observed_hits,
        "slices_scanned": slices_scanned,
        "truncated_slices": truncated_slices,
        "log_limit_per_slice": LOG_FETCH_LIMIT,
    }
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


def _aggregate_port_analysis(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate logs into port/protocol enumeration.

    Returns complete port list, protocol breakdown, and ICMP summary.
    Exactness metadata is added by the caller via _bounded_metadata().
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


async def _run_bounded_policy_analysis(
    *,
    operation: str,
    adom: str | None,
    device: str | None,
    policy_ids: list[int] | None,
    time_range: str,
    action: str | None,
    aggregate: Callable[[list[dict[str, Any]]], dict[str, Any]],
) -> dict[str, Any]:
    """Shared driver for the bounded per-policy analysis tools.

    Resolves the time window once so the reported time_range and bounded slices
    share one window, then assembles top-level audit metadata plus per-policy
    results. ``aggregate`` turns one policy's log rows into the tool-specific
    summary dict.
    """
    adom_value: str | None = adom
    try:
        adom_value = validate_adom(adom or get_default_adom())
        if policy_ids is None:
            return error_response(
                error="validation_error",
                message="policy_ids is required",
                operation=operation,
                adom=adom_value,
            )
        policy_ids = validate_policy_ids(policy_ids)
        action = validate_action(action)

        # Revive an idle-closed streamable-HTTP session before any FAZ call, like
        # query_logs; otherwise the first policy query after the session drops
        # fails with a raw "Not connected" error.
        await _get_client().ensure_connected()

        try:
            resolved = await resolve_time_window(
                _get_client(), adom_value, time_range, device, faz_tz_for_custom=False
            )
        except ValueError as e:
            return error_response(
                error="invalid_time_range",
                message=f"Invalid time_range: {e}",
                operation=operation,
                adom=adom_value,
            )
        window = resolved.time_range
        tz_name = resolved.timezone

        start = time.monotonic()
        query_tasks = [
            _query_policy_logs_bounded(
                adom_value, device, pid, window, action, policy_count=len(policy_ids)
            )
            for pid in policy_ids
        ]
        results_list = await asyncio.gather(*query_tasks, return_exceptions=True)

        per_policy = []
        for pid, result in zip(policy_ids, results_list, strict=True):
            policy_filter = _build_policy_filter(pid, action)
            if isinstance(result, Exception):
                per_policy.append(
                    {
                        "policy_id": pid,
                        "error": "policy_query_failed",
                        "message": str(result),
                        "filter": policy_filter,
                    }
                )
            else:
                policy_result = cast(dict[str, Any], result)
                logs = policy_result["logs"]
                entry = aggregate(logs)
                entry.update(
                    _bounded_metadata(
                        observed_hits=len(logs),
                        slices_scanned=policy_result["slices_scanned"],
                        truncated_slices=policy_result["truncated_slices"],
                        total_hits=policy_result.get("total_hits"),
                        total_hits_is_known=policy_result.get("total_hits_is_known") is True,
                    )
                )
                entry["policy_id"] = pid
                entry["filter"] = policy_filter
                per_policy.append(entry)

        elapsed = time.monotonic() - start
        return {
            "status": "success",
            "adom": adom_value,
            "time_range": window,
            "timezone": tz_name,
            "time_basis_source": resolved.time_basis_source,
            "clock_skew_seconds": resolved.clock_skew_seconds,
            "results": per_policy,
            "query_time_seconds": round(elapsed, 2),
        }

    except ValidationError as e:
        return error_response(
            error="validation_error",
            message=f"Validation error: {e}",
            operation=operation,
            adom=adom_value,
        )
    except (OSError, TimeoutError) as e:
        logger.error(f"Network error in {operation}: {e}")
        return error_response(
            error="network_error",
            message=f"Network error: {e}",
            operation=operation,
            adom=adom_value,
            retry_count=getattr(e, "retries_attempted", 0),
        )
    except Exception as e:
        logger.error(f"Error in {operation}: {e}")
        return error_response(
            error="faz_operation_failed",
            message=str(e),
            operation=operation,
            adom=adom_value,
            retry_count=getattr(e, "retries_attempted", 0),
        )


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
            - adom, time_range, timezone: resolved query-window audit metadata
            - results: Per-policy traffic profiles with top ports, services, apps,
              plus per-policy total accounting:
                - total_hits: authoritative whole-window match count when
                  total_hits_is_known, else the observed row count
                - total_hits_is_known / total_hit_source: True with
                  "logsearch_total-count" when the total came from a FAZ
                  whole-window total-count; False with "observed_rows" otherwise
                - observed_hits: rows actually fetched and aggregated
                Top ports/services/applications and their residuals describe the
                observed rows only, not total_hits.
            - query_time_seconds: Total query duration
            - message: Error message if failed

    Example:
        >>> result = await get_policy_traffic_profile(
        ...     policy_ids=[1, 5, 10],
        ...     time_range="7-day",
        ...     action="accept"
        ... )
    """
    if top_n < 1:
        top_n = DEFAULT_TOP_N
    return await _run_bounded_policy_analysis(
        operation="get_policy_traffic_profile",
        adom=adom,
        device=device,
        policy_ids=policy_ids,
        time_range=time_range,
        action=action,
        aggregate=lambda logs: _aggregate_traffic_profile(logs, top_n),
    )


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
            - adom, time_range, timezone: resolved query-window audit metadata
            - results: Per-policy port analysis with:
                - is_exact: True only when the breakdown covers every matching
                  log (no truncated slice AND total_hits == observed_hits)
                - analysis_mode: "complete" or "bounded_sample"
                - total_hits: authoritative whole-window match count when
                  total_hits_is_known, else the observed row count
                - total_hits_is_known / total_hit_source: True with
                  "logsearch_total-count" when the total came from a FAZ
                  whole-window total-count; False with "observed_rows" otherwise
                - observed_hits: Number of log rows fetched and aggregated
                - ports: List of port/protocol pairs with hit counts
                - protocols: Protocol breakdown
                - portless_protocols: Protocols without ports (ICMP, GRE, etc.)
                - uncovered_port_hits: Hits without a destination port
                - icmp: ICMP type/code breakdown (if applicable)
              ports/protocols/uncovered counts describe observed rows only.
            - query_time_seconds: Total query duration
            - message: Error message if failed

    Example:
        >>> result = await get_policy_port_analysis(
        ...     policy_ids=[1],
        ...     time_range="7-day"
        ... )
    """
    return await _run_bounded_policy_analysis(
        operation="get_policy_port_analysis",
        adom=adom,
        device=device,
        policy_ids=policy_ids,
        time_range=time_range,
        action=action,
        aggregate=_aggregate_port_analysis,
    )


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
            - adom, time_range, timezone: resolved query-window audit metadata
            - results: Per-policy protocol summaries with hit counts, plus
              total_hits / total_hits_is_known / total_hit_source and
              observed_hits (the protocol breakdown describes observed rows only;
              total_hits is the authoritative whole-window count when known)
            - query_time_seconds: Total query duration
            - message: Error message if failed

    Example:
        >>> result = await get_policy_protocol_summary(
        ...     policy_ids=[1, 5],
        ...     time_range="24-hour"
        ... )
    """
    return await _run_bounded_policy_analysis(
        operation="get_policy_protocol_summary",
        adom=adom,
        device=device,
        policy_ids=policy_ids,
        time_range=time_range,
        action=action,
        aggregate=_aggregate_protocol_summary,
    )
