"""Policy traffic analysis tools for FortiAnalyzer.

Provides `analyze_policy_traffic`: fans out over up to MAX_POLICY_IDS firewall
policies under a shared bounded-scan budget and reports independent
per-dimension breakdowns (port, service, app, ...) for each. It replaces three
tools that differed only in which breakdowns they produced
(`get_policy_traffic_profile`, `get_policy_port_analysis`,
`get_policy_protocol_summary`); that difference is now the `sample_by`
parameter, and the aggregation itself is `query.groups.aggregate_breakdowns_with_residuals`
over `query.derive.dimension_value` rather than a bespoke Counter per tool.

It queries FortiAnalyzer traffic logs filtered by policy ID and aggregates
results for policy hardening workflows.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Any, cast

from fortianalyzer_mcp.query.derive import is_derived
from fortianalyzer_mcp.query.fields import resolve_field
from fortianalyzer_mcp.query.groups import aggregate_breakdowns_with_residuals
from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.tool_annotations import READ_ONLY
from fortianalyzer_mcp.tools.log_tools import (
    _clamp_limit,
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
    sanitize_filter_value,
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

    The whole-window ``total_hits`` is the sum of the per-slice ``total-count``s
    that the breakdown searches already return (issue #30). Slices are contiguous
    and non-overlapping, so the sum is a valid whole-window count and is at least
    the rows fetched. ``all_slices_exact`` is True only when every slice reported a
    total equal to the rows it returned and below the fetch limit (every slice was
    fully scanned); that is what makes a result "complete". A slice that timed out,
    returned no TID, or omitted its total leaves the total unproven and forces a
    bounded result.
    """
    async with _QUERY_SEMAPHORE:
        full_time_range = time_range
        device_filter = _build_device_filter(device)
        # Clamp once with the runner's own helper so the truncation test below
        # compares against the limit the runner actually applies.
        effective_limit = _clamp_limit(limit)
        slice_count = _plan_policy_slice_count(full_time_range, policy_count)
        time_slices = _build_bounded_time_slices(full_time_range, slice_count)
        logs: list[dict[str, Any]] = []
        truncated_slices = 0
        summed_total = 0
        total_hits_is_known = True
        all_slices_exact = True

        for time_slice in time_slices:
            slice_result = await _query_policy_log_slice(
                adom=adom,
                device_filter=device_filter,
                policy_id=policy_id,
                time_range=time_slice,
                action=action,
                limit=effective_limit,
                timeout=timeout,
            )
            slice_logs = slice_result.get("logs", [])
            if not isinstance(slice_logs, list):
                slice_logs = []
            logs.extend(slice_logs)
            rows = len(slice_logs)
            truncated = rows >= effective_limit
            if truncated:
                truncated_slices += 1

            slice_total = slice_result.get("total_hits")
            slice_known = slice_result.get("total_hits_is_known") is True and isinstance(
                slice_total, int
            )
            if slice_known:
                summed_total += cast(int, slice_total)
            else:
                total_hits_is_known = False
            # A slice is exact only if it proved its total and was fully scanned.
            all_slices_exact = (
                all_slices_exact and slice_known and not truncated and slice_total == rows
            )

        return {
            "logs": logs,
            "slices_scanned": len(time_slices),
            "truncated_slices": truncated_slices,
            "total_hits": summed_total if total_hits_is_known else None,
            "total_hits_is_known": total_hits_is_known,
            "all_slices_exact": all_slices_exact,
        }


# analyze_policy_traffic's per-policy fan-out target. Collapsing the three
# get_policy_* tools into one retired the generic aggregate-callback driver
# that used to own this name -- it only ever had those three tools as
# callers -- so the name now labels the per-policy bounded-query runner it
# fans out over instead.
_run_bounded_policy_analysis = _query_policy_logs_bounded


def _bounded_metadata(
    observed_hits: int,
    slices_scanned: int,
    truncated_slices: int,
    total_hits: int | None = None,
    total_hits_is_known: bool = False,
    all_slices_exact: bool = False,
    policy_id: int | None = None,
) -> dict[str, Any]:
    """Build common bounded-analysis response metadata.

    ``total_hits`` is the sum of per-slice ``total-count``s (issue #30); it is at
    least ``observed_hits`` by construction. A result is exact ("complete") only
    when ``all_slices_exact`` -- every slice proved a total equal to its rows and
    was fully scanned. Exactness is decided from that per-slice proof, not from an
    aggregate ``observed == total`` comparison, so an over/under-count cancellation
    across slices cannot fabricate completeness.
    """
    authoritative = total_hits if (total_hits_is_known and total_hits is not None) else None
    if authoritative is not None:
        # Belt (the v2.4.1 defensive shim): the summed total is >= observed by
        # construction, so this is normally a no-op. If it ever fires, the
        # appliance under-reported a slice total; surface it, do not silently
        # floor it.
        resolved_total_hits = max(authoritative, observed_hits)
        if authoritative < observed_hits:
            logger.warning(
                f"Policy {policy_id}: summed total-count {authoritative} below "
                f"observed rows {observed_hits}; clamping to observed"
            )
    else:
        resolved_total_hits = observed_hits
    # Exactness comes purely from per-slice proof. An unknown/unproven slice
    # (timeout, no TID, omitted total) leaves all_slices_exact False, so a bounded
    # result can never be mislabeled "complete".
    is_exact = all_slices_exact
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
# MCP Tool Functions
# =============================================================================


@mcp.tool(annotations=READ_ONLY)
async def analyze_policy_traffic(
    adom: str | None = None,
    device: str | None = None,
    policy_ids: list[int] | None = None,
    time_range: str = "24-hour",
    action: str | None = None,
    sample_by: list[str] | None = None,
    top_n: int = DEFAULT_TOP_N,
) -> dict[str, Any]:
    """Break down what traffic each firewall policy actually carried.

    Replaces get_policy_traffic_profile, get_policy_port_analysis and
    get_policy_protocol_summary: the three differed only in which breakdowns
    they produced, which is now the sample_by parameter.

    This is a *bounded sample*, not a census. It scans a fixed number of time
    slices per policy and stops at a row cap, so check `is_exact` before
    quoting any number. When it is False, `analysis_mode` is "bounded_sample"
    and `total_hits` is a floor, not a total.

    Use query_logs(sample_by=[...]) instead when you want one aggregate set for
    one query; this tool fans out across up to MAX_POLICY_IDS policies under a
    shared query budget and reports each separately.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        device: Device filter (serial, name, or an All_* group)
        policy_ids: Firewall policy IDs to analyse (1-24 IDs, each > 0).
        time_range: Preset token or "start|end"
        action: Optional traffic action filter (accept, deny, ...)
        sample_by: Dimensions to break down. Defaults to
            ["port", "service", "app"] -- what get_policy_traffic_profile
            returned. "port" is proto/dstport; "icmp_type_code" decodes the
            ICMP type/code FortiAnalyzer hides in the service field.
        top_n: Buckets per dimension (default 10). 0 returns every bucket,
            which is what get_policy_port_analysis's complete port list needed.

    Returns:
        dict with per-policy entries under `results`, each carrying
        `breakdowns` plus the bounded metadata block (`is_exact`,
        `analysis_mode`, `total_hits`, `total_hits_is_known`,
        `total_hit_source`, `observed_hits`, `slices_scanned`,
        `truncated_slices`, `log_limit_per_slice`, `recommendation`), the
        echoed `filter`, and `query_time_seconds` / `adom` / `time_range` /
        `timezone` audit metadata at the top level. A policy whose query
        failed reports `error`/`message` instead of `breakdowns`.

    Example:
        >>> result = await analyze_policy_traffic(
        ...     policy_ids=[1, 5, 10],
        ...     time_range="7-day",
        ...     action="accept",
        ... )
    """
    operation = "analyze_policy_traffic"
    dimensions = list(sample_by) if sample_by else ["port", "service", "app"]
    adom_value: str | None = adom

    try:
        adom_value = validate_adom(adom or get_default_adom())
        action = validate_action(action)
        policy_ids = validate_policy_ids(policy_ids or [])

        # Validate dimensions before any appliance work: a typo should cost
        # nothing. Derived dimensions bypass the field registry, which only
        # knows stored fields. The traffic vocabulary is not "complete"
        # (arbitrary FAZ fields can be requested), so resolve_field never
        # raises for an unknown-but-shaped name -- it returns a passthrough
        # warning instead. That is the right call for a filter field but the
        # wrong one for a breakdown key that would just always come back
        # empty, so a non-None warning here is treated as a hard rejection.
        # Accepted names are kept in *canonical* spelling: an alias would
        # extract nothing from the rows, and as a breakdown key it would sit
        # outside the masking allowlist, so resolution and emission go
        # together.
        #
        # The two failure modes get two codes, decided structurally rather
        # than by sniffing the message for the word "field". The sniff read
        # resolve_field's shape rejection ("'x' cannot be a FortiAnalyzer
        # field name") as unknown_field, while query_logs called the identical
        # input validation_error -- one malformed input, two machine codes,
        # and machine codes are a contract (#109 review).
        resolved_dimensions: list[str] = []
        seen_dimensions: set[str] = set()
        for dimension in dimensions:
            if is_derived(dimension):
                canonical = dimension.strip().lower()
            else:
                canonical, warning = resolve_field("traffic", dimension)
                if warning is not None:
                    return error_response(
                        error="unknown_field",
                        message=(
                            f"Unknown sample_by dimension '{dimension}': not a known "
                            "traffic field and not a derived dimension (port, "
                            "icmp_type_code)."
                        ),
                        operation=operation,
                        adom=adom_value,
                    )
            # An alias and its canonical name are one dimension; without this
            # they were echoed twice and the rows scanned twice for the same
            # breakdown, which collapsed to one key anyway.
            if canonical not in seen_dimensions:
                seen_dimensions.add(canonical)
                resolved_dimensions.append(canonical)
        dimensions = resolved_dimensions
    except ValidationError as e:
        return error_response(
            error="validation_error",
            message=str(e),
            operation=operation,
            adom=adom_value,
        )

    try:
        # Revive an idle-closed streamable-HTTP session before any FAZ call,
        # like query_logs; otherwise the first policy query after the session
        # drops fails with a raw "Not connected" error.
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
            _run_bounded_policy_analysis(
                adom=adom_value,
                device=device,
                policy_id=pid,
                time_range=window,
                action=action,
                policy_count=len(policy_ids),
            )
            for pid in policy_ids
        ]
        results_list = await asyncio.gather(*query_tasks, return_exceptions=True)

        per_policy: list[dict[str, Any]] = []
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
                continue

            policy_result = cast(dict[str, Any], result)
            logs = policy_result["logs"]
            policy_breakdowns, policy_residuals = aggregate_breakdowns_with_residuals(
                logs, dimensions, top_n=top_n
            )
            entry: dict[str, Any] = {
                "policy_id": pid,
                "breakdowns": policy_breakdowns,
                # The retired get_policy_* tools reported this as
                # top_ports_residual / top_services_residual /
                # top_applications_residual; it came back with #109's review.
                "breakdown_residuals": policy_residuals,
            }
            entry.update(
                _bounded_metadata(
                    observed_hits=len(logs),
                    slices_scanned=policy_result["slices_scanned"],
                    truncated_slices=policy_result["truncated_slices"],
                    total_hits=policy_result.get("total_hits"),
                    total_hits_is_known=policy_result.get("total_hits_is_known") is True,
                    all_slices_exact=policy_result.get("all_slices_exact") is True,
                    policy_id=pid,
                )
            )
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
