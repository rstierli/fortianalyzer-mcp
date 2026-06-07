"""Log query and analysis tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 LogView API specifications.
Implements the two-step TID-based log search workflow.
"""

import asyncio
import logging
from typing import Any

from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.responses import build_warnings, error_response, redact
from fortianalyzer_mcp.utils.time_range import parse_time_range
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    get_default_adom,
    sanitize_filter_value,
    validate_adom,
    validate_event_level,
    validate_event_subtype,
    validate_ip_or_cidr,
    validate_log_type,
    validate_pcapurl,
    validate_port,
    validate_severity,
    validate_traffic_action,
)

logger = logging.getLogger(__name__)

# Default search timeout in seconds
DEFAULT_SEARCH_TIMEOUT = 60
# Poll interval for search progress
POLL_INTERVAL = 1.0
# Appliance maximum for the logsearch fetch limit (rejects > 1000).
LOG_FETCH_LIMIT_MAX = 1000


# In-process registry of log-search context, keyed by a pagination handle.
#
# IMPORTANT (verified against the lab appliance): a FortiAnalyzer logsearch tid
# is single-use -- the first fetch delivers the requested offset/limit slice and
# the task is then reaped, so a second fetch on the same tid raises "Invalid
# tid". Pagination therefore works by running a *fresh* search per page (results
# are stably ordered across searches for a fixed time window). query_logs records
# the search parameters here under a handle (the first page's tid value) so
# fetch_more_logs can reconstruct and re-run the same query at a new offset
# without the caller re-supplying ADOM/filter/time_range.
#
# This is ephemeral process state (not a persisted job-state file or queue) and
# assumes the server runs as a single process (uvicorn with no workers), so the
# global client and this registry are shared across requests.
_SEARCH_REGISTRY: dict[int, dict[str, Any]] = {}

# Cap the registry so a long-lived process cannot accumulate handles without
# bound; evict the oldest handle past the cap (FIFO, dict is insertion-ordered).
_SEARCH_REGISTRY_MAX = 512


def _register_search(tid: int, context: dict[str, Any]) -> None:
    """Record the search context for a pagination handle (bounded, FIFO)."""
    _SEARCH_REGISTRY[tid] = context
    while len(_SEARCH_REGISTRY) > _SEARCH_REGISTRY_MAX:
        oldest = next(iter(_SEARCH_REGISTRY))
        del _SEARCH_REGISTRY[oldest]


def _get_search_context(tid: int) -> dict[str, Any] | None:
    """Return the stored search context for a tid, if known to this process."""
    return _SEARCH_REGISTRY.get(tid)


def _unregister_search(tid: int) -> None:
    """Drop a tid from the registry (after cancel or expiry)."""
    _SEARCH_REGISTRY.pop(tid, None)


def _is_invalid_tid_error(exc: Exception) -> bool:
    """Heuristically detect a FortiAnalyzer 'invalid/expired tid' error.

    FAZ surfaces an expired or unknown log-search task as an error mentioning the
    tid. We classify by message because the exact error code varies by version;
    this is verified/tightened against the live appliance.
    """
    msg = str(exc).lower()
    if "tid" not in msg:
        return False
    return any(
        marker in msg
        for marker in ("invalid", "not found", "no such", "expired", "unknown", "does not exist")
    )


def _tid_error_response(
    tid: int, adom: str, detail: object, operation: str = "fetch_more_logs"
) -> dict[str, Any]:
    """Build a structured error response for an invalid/expired tid/handle."""
    return error_response(
        error="tid_invalid_or_expired",
        message=(
            f"Search handle {tid} is no longer valid on FortiAnalyzer "
            f"(adom={adom}). It may have expired or been cancelled. Detail: {detail}"
        ),
        operation=operation,
        adom=adom,
        tid=tid,
        recommendation="Re-run query_logs to start a new search and obtain a fresh tid.",
    )


def _clamp_limit(limit: int) -> int:
    """Clamp a caller-supplied limit to the appliance-accepted range [1, 1000].

    FortiAnalyzer rejects ``limit > 1000`` for the logsearch fetch endpoint, and
    an unbounded limit would also let a caller pull an arbitrarily large raw-log
    slice into the response. Non-int/negative values fall back to the default.
    """
    if not isinstance(limit, int) or isinstance(limit, bool):
        return 100
    return max(1, min(limit, LOG_FETCH_LIMIT_MAX))


def _compute_has_more(offset: int, count: int, limit: int, total: int | None) -> bool:
    """Decide whether more results remain beyond the current page.

    When the total is known, compare against the consumed range. When it is
    unknown, fall back to the full-page heuristic: a page filled to the limit
    implies more rows may exist.
    """
    if count == 0:
        return False
    if total is not None:
        return (offset + count) < total
    return limit > 0 and count >= limit


def _coerce_total(value: Any) -> int | None:
    """Coerce a FAZ ``total-count`` value to int, or None if unavailable."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


async def _run_search_page(
    client: Any,
    *,
    adom: str,
    logtype: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter: str | None,
    offset: int,
    limit: int,
    timeout: int,
) -> dict[str, Any]:
    """Run one self-contained search page: start, fetch, return the page.

    Each page is its own search because a FAZ logsearch tid is single-use: the
    first fetch delivers the slice plus ``total-count`` and the task is reaped.
    The fetch blocks server-side until the search completes, so it usually
    returns ``percentage>=100`` on the first try. If it returns incomplete, or
    the task was reaped before our fetch, the search is re-issued from scratch.
    Re-issues are bounded by the wall-clock ``timeout`` (not a fixed attempt
    count), so the caller's timeout budget is honored; on expiry the page is
    returned as ``timed_out`` rather than raising a raw appliance error.

    Returns ``{"timed_out": bool, "tid": int, "logs": list, "total": int|None}``.
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    tid: int | None = None

    while True:
        start_result = await client.logsearch_start(
            adom=adom,
            logtype=logtype,
            device=device_filter,
            time_range=time_range,
            filter=filter,
            limit=limit,
            offset=offset,
        )
        tid = start_result.get("tid")
        if not tid:
            raise RuntimeError(f"Failed to start search: no TID returned. Response: {start_result}")

        fetch_result: dict[str, Any] | None
        try:
            fetch_result = await client.logsearch_fetch(
                adom=adom, tid=tid, limit=limit, offset=offset
            )
        except Exception as exc:
            # Task reaped before our fetch -> re-issue (bounded by deadline).
            if not _is_invalid_tid_error(exc):
                raise
            fetch_result = None

        if fetch_result is not None and fetch_result.get("percentage", 0) >= 100:
            logs = fetch_result.get("data", [])
            if not isinstance(logs, list):
                logs = [logs] if logs else []
            return {
                "timed_out": False,
                "tid": tid,
                "logs": logs,
                "total": _coerce_total(fetch_result.get("total-count")),
            }

        # Incomplete (the single-use task is now reaped) or reaped before fetch:
        # re-issue a fresh search until the timeout budget is exhausted.
        remaining = deadline - loop.time()
        if remaining <= 0:
            try:
                await client.logsearch_cancel(adom, tid)
            except Exception:
                pass
            return {"timed_out": True, "tid": tid, "logs": [], "total": None}
        await asyncio.sleep(min(POLL_INTERVAL, remaining))


def _get_client():
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


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
            - count: Number of logs returned in this page
            - total: Total logs matching the query (int), or None if unknown
            - total_is_known: Whether `total` is authoritative (False => unknown)
            - percentage: Search completion percentage (100 on success)
            - tid: Reusable pagination handle (pass to fetch_more_logs)
            - has_more: Whether more results remain beyond this page
            - next_offset: Offset to pass to fetch_more_logs, or None when has_more is False
            - logs: List of log entries (bounded by `limit`)
            - adom, logtype, filter, device: Echoed query context (auditability)
            - time_range: Resolved {start, end} bounds actually sent to FAZ
            - timezone: FAZ system timezone the timestamps are interpreted in
            - time_basis: Human note clarifying timestamps are FAZ local time
            - offset, limit: Paging echoes (the clamped values actually used)
            - warnings: Advisory strings (clamp, unknown total/timezone, high volume)
        On error, a structured envelope: {status: "error", error: <machine code>,
        message, operation, retry_count, plus adom/logtype/tid where relevant}.

    Note on pagination: a FortiAnalyzer logsearch task id is single-use (it is
    reaped after the first fetch). The `tid` returned here is a reusable handle
    backed by an in-process record of the search parameters; fetch_more_logs
    re-runs the same query at a new offset. For a fixed time window the result
    order is stable, so paging is consistent.

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

        client = _get_client()
        await client.ensure_connected()

        # Resolve the FAZ system timezone once: used both to align relative
        # time ranges and to label the returned timestamps (FAZ interprets the
        # naive bounds in its own local TZ).
        faz_tz = await client.get_system_timezone()
        tz_name = str(faz_tz) if faz_tz else "unknown"
        try:
            time_range_dict = parse_time_range(time_range, faz_tz=faz_tz)
        except ValueError as e:
            return error_response(
                error="invalid_time_range",
                message=f"Invalid time_range: {e}",
                operation="query_logs",
                adom=adom,
                logtype=logtype,
            )

        # Build device filter
        device_filter = _build_device_filter(device)

        requested_limit = limit
        limit = _clamp_limit(limit)
        offset = max(0, offset)

        # Run this page as a self-contained search (FAZ tids are single-use).
        logger.info(
            f"Starting log search: adom={adom}, logtype={logtype}, "
            f"filter={redact(str(filter))[:200]}"
        )
        page = await _run_search_page(
            client,
            adom=adom,
            logtype=logtype,
            device_filter=device_filter,
            time_range=time_range_dict,
            filter=filter,
            offset=offset,
            limit=limit,
            timeout=timeout,
        )

        if page["timed_out"]:
            return error_response(
                error="search_timeout",
                message=f"Search timed out after {timeout} seconds",
                operation="query_logs",
                adom=adom,
                logtype=logtype,
                time_range=time_range_dict,
                timezone=tz_name,
            )

        logs = page["logs"]
        count = len(logs)
        total = page["total"]
        total_is_known = total is not None
        has_more = _compute_has_more(offset, count, limit, total)
        next_offset = offset + count if has_more else None
        handle = page["tid"]

        warnings = build_warnings(
            requested_limit=requested_limit,
            limit=limit,
            total=total,
            total_is_known=total_is_known,
            timezone=tz_name,
            has_more=has_more,
        )
        if count == 0 and total_is_known and total is not None and total > offset:
            warnings.append(
                "FortiAnalyzer reports more matching rows beyond this offset but returned "
                "an empty page; the search task may have been reaped -- re-run query_logs."
            )

        # Record the search parameters under the handle so fetch_more_logs can
        # reconstruct and re-run the query at a new offset (the appliance tid is
        # already reaped). cancel_log_search clears the handle.
        _register_search(
            handle,
            {
                "adom": adom,
                "logtype": logtype,
                "filter": filter,
                "device": device,
                "time_range": time_range_dict,
                "timezone": tz_name,
            },
        )

        return {
            "status": "success",
            "count": count,
            "total": total,
            "total_is_known": total_is_known,
            "percentage": 100,
            "tid": handle,
            "has_more": has_more,
            "next_offset": next_offset,
            "logs": logs,
            "adom": adom,
            "logtype": logtype,
            "filter": filter,
            "device": device,
            "time_range": time_range_dict,
            "timezone": tz_name,
            "time_basis": (
                f"time_range and log timestamps are interpreted in FAZ local time ({tz_name})"
            ),
            "offset": offset,
            "limit": limit,
            "warnings": warnings,
        }

    except ValidationError as e:
        return error_response(
            error="validation_error",
            message=f"Validation error: {e}",
            operation="query_logs",
            adom=adom,
            logtype=logtype,
        )
    except Exception as e:
        logger.error(f"Failed to query logs: {e}")
        return error_response(
            error="faz_operation_failed",
            message=str(e),
            operation="query_logs",
            adom=adom,
            logtype=logtype,
            retry_count=getattr(e, "retries_attempted", 0),
        )


@mcp.tool()
async def get_log_search_progress(
    adom: str | None = None,
    tid: int = 0,
) -> dict[str, Any]:
    """Report status of a query_logs pagination handle.

    query_logs runs each search synchronously (it returns only after the page
    has completed), and a FortiAnalyzer logsearch task is single-use and reaped
    on completion. There is therefore no separately pollable in-progress task:
    a known handle is already complete. Use fetch_more_logs(tid=...) to retrieve
    further pages.

    Args:
        adom: Unused (kept for backward compatibility)
        tid: Pagination handle from a previous query_logs call

    Returns:
        dict: status, progress_percent, note, and tid; or a structured
        tid_invalid_or_expired error if the handle is unknown to this process.
    """
    if tid <= 0:
        return error_response(
            error="invalid_tid", message="Invalid TID", operation="get_log_search_progress"
        )

    context = _get_search_context(tid)
    if context is None:
        return _tid_error_response(
            tid,
            get_default_adom(),
            "search handle is not known",
            operation="get_log_search_progress",
        )

    return {
        "status": "success",
        "progress_percent": 100,
        "tid": tid,
        "adom": context.get("adom"),
        "note": (
            "query_logs completes searches synchronously; there is no separately "
            "pollable in-progress task. Use fetch_more_logs(tid=...) to page results."
        ),
    }


@mcp.tool()
async def fetch_more_logs(
    adom: str | None = None,
    tid: int = 0,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Fetch another page of a previous query_logs search using its handle.

    Because a FortiAnalyzer logsearch tid is single-use, this re-runs the same
    query (same ADOM, logtype, filter, device, and time window) at the requested
    offset/limit using the search parameters recorded for `tid`. You normally
    only pass tid/offset/limit. If the handle is unknown to this server process
    (expired or from another process), the response is a structured error with
    error="tid_invalid_or_expired" and a recommendation to re-run query_logs.

    Args:
        adom: ADOM name (default: reuse the ADOM query_logs used for this handle)
        tid: Reusable pagination handle from a previous query_logs call
        limit: Maximum logs to return (default: 100)
        offset: Offset for pagination (default: 0)

    Returns:
        dict: Additional log results with keys:
            - status: "success" or "error"
            - count: Number of logs returned in this page
            - logs: List of log entries
            - tid, adom, logtype, filter, device: Echoed pagination context
            - total, total_is_known, has_more: Pagination metadata
            - next_offset: Offset for the next page, or None when has_more is False
            - offset, limit: Paging echoes (the clamped values actually used)
            - timezone, time_basis: FAZ timezone context
            - warnings: Advisory strings
        On error, a structured envelope: {status: "error", error: <machine code>,
        message, operation, retry_count, plus tid/adom/recommendation where relevant}.

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
            return error_response(
                error="invalid_tid",
                message="Invalid TID. Provide the tid returned by query_logs.",
                operation="fetch_more_logs",
            )

        # Reconstruct the search from the parameters recorded for this handle.
        context = _get_search_context(tid)
        if context is None:
            return _tid_error_response(
                tid,
                adom or get_default_adom(),
                "search handle is not known to this server process",
            )

        if adom is None:
            adom = context["adom"]
        adom = validate_adom(adom)

        requested_limit = limit
        limit = _clamp_limit(limit)
        offset = max(0, offset)

        client = _get_client()
        await client.ensure_connected()

        page = await _run_search_page(
            client,
            adom=adom,
            logtype=context["logtype"],
            device_filter=_build_device_filter(context.get("device")),
            time_range=context["time_range"],
            filter=context.get("filter"),
            offset=offset,
            limit=limit,
            timeout=DEFAULT_SEARCH_TIMEOUT,
        )

        if page["timed_out"]:
            return error_response(
                error="search_timeout",
                message=f"Search timed out after {DEFAULT_SEARCH_TIMEOUT} seconds",
                operation="fetch_more_logs",
                adom=adom,
                logtype=context.get("logtype"),
                tid=tid,
            )

        logs = page["logs"]
        count = len(logs)
        total = page["total"]
        total_is_known = total is not None
        has_more = _compute_has_more(offset, count, limit, total)
        next_offset = offset + count if has_more else None
        timezone = context.get("timezone", "unknown")

        warnings = build_warnings(
            requested_limit=requested_limit,
            limit=limit,
            total=total,
            total_is_known=total_is_known,
            timezone=timezone,
            has_more=has_more,
        )
        if count == 0 and total_is_known and total is not None and total > offset:
            warnings.append(
                "FortiAnalyzer reports more matching rows beyond this offset but returned "
                "an empty page; the search task may have been reaped -- re-run query_logs."
            )

        return {
            "status": "success",
            "count": count,
            "logs": logs,
            "tid": tid,
            "adom": adom,
            "logtype": context.get("logtype"),
            "filter": context.get("filter"),
            "device": context.get("device"),
            "time_range": context.get("time_range"),
            "total": total,
            "total_is_known": total_is_known,
            "has_more": has_more,
            "next_offset": next_offset,
            "offset": offset,
            "limit": limit,
            "timezone": timezone,
            "time_basis": f"log timestamps are interpreted in FAZ local time ({timezone})",
            "warnings": warnings,
        }
    except ValidationError as e:
        return error_response(
            error="validation_error",
            message=f"Validation error: {e}",
            operation="fetch_more_logs",
            tid=tid,
        )
    except Exception as e:
        logger.error(f"Failed to fetch more logs: {e}")
        return error_response(
            error="faz_operation_failed",
            message=str(e),
            operation="fetch_more_logs",
            adom=adom,
            tid=tid,
            retry_count=getattr(e, "retries_attempted", 0),
        )


@mcp.tool()
async def cancel_log_search(
    adom: str | None = None,
    tid: int = 0,
) -> dict[str, Any]:
    """Release a pagination handle (and the FAZ task if still alive).

    Call this when you are done paging a query_logs result to free the in-process
    handle. FortiAnalyzer reaps a completed logsearch task on its own, so the
    appliance-side cancel is best-effort; clearing the handle always succeeds.

    Args:
        adom: ADOM name (default: reuse the ADOM recorded for this handle)
        tid: Pagination handle from a previous query_logs call

    Returns:
        dict: Cancellation result with keys:
            - status: "success" or "error"
            - message: Status message
            - tid, adom: Echoed context

    Example:
        >>> result = await cancel_log_search(tid=12345)
    """
    try:
        if tid <= 0:
            return error_response(
                error="invalid_tid", message="Invalid TID", operation="cancel_log_search"
            )

        # Use the ADOM query_logs ran under when the caller omits it.
        context = _get_search_context(tid)
        if adom is None:
            adom = context["adom"] if context else get_default_adom()
        adom = validate_adom(adom)

        client = _get_client()
        await client.ensure_connected()
        # Best-effort: the task is usually already reaped by the appliance.
        try:
            await client.logsearch_cancel(adom, tid)
        except Exception as exc:  # noqa: BLE001 - handle cleanup must still succeed
            logger.debug(f"logsearch_cancel best-effort failed for handle {tid}: {exc}")
        _unregister_search(tid)

        return {
            "status": "success",
            "message": f"Search {tid} released",
            "tid": tid,
            "adom": adom,
        }
    except Exception as e:
        logger.error(f"Failed to cancel search: {e}")
        return error_response(
            error="faz_operation_failed",
            message=str(e),
            operation="cancel_log_search",
            tid=tid,
            retry_count=getattr(e, "retries_attempted", 0),
        )


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
        # Build filter string using FortiAnalyzer syntax.
        # Every caller-supplied value is validated/sanitized before
        # interpolation to prevent filter injection.
        filters = []
        if srcip:
            filters.append(f"srcip=={validate_ip_or_cidr(srcip, 'srcip')}")
        if dstip:
            filters.append(f"dstip=={validate_ip_or_cidr(dstip, 'dstip')}")
        if srcport:
            filters.append(f"srcport=={validate_port(srcport, 'srcport')}")
        if dstport:
            filters.append(f"dstport=={validate_port(dstport, 'dstport')}")
        if action:
            filters.append(f"action=={validate_traffic_action(action)}")
        if policy_id:
            if isinstance(policy_id, bool) or not isinstance(policy_id, int) or policy_id < 0:
                raise ValidationError(
                    f"Invalid policy_id '{policy_id}'. Must be a non-negative integer."
                )
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

    except ValidationError as e:
        return error_response(
            error="validation_error",
            message=f"Validation error: {e}",
            operation="search_traffic_logs",
            adom=adom,
        )
    except Exception as e:
        logger.error(f"Failed to search traffic logs: {e}")
        return error_response(
            error="faz_operation_failed",
            message=str(e),
            operation="search_traffic_logs",
            adom=adom,
            retry_count=getattr(e, "retries_attempted", 0),
        )


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
        # Build filter string. Every caller-supplied value is validated or
        # sanitized before interpolation to prevent filter injection.
        filters = []
        if attack_name:
            filters.append(f"attack contain {sanitize_filter_value(attack_name, 'attack_name')}")
        if severity:
            filters.append(f"severity=={validate_severity(severity)}")
        if srcip:
            filters.append(f"srcip=={validate_ip_or_cidr(srcip, 'srcip')}")
        if dstip:
            filters.append(f"dstip=={validate_ip_or_cidr(dstip, 'dstip')}")

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

    except ValidationError as e:
        return error_response(
            error="validation_error",
            message=f"Validation error: {e}",
            operation="search_security_logs",
            adom=adom,
        )
    except Exception as e:
        logger.error(f"Failed to search security logs: {e}")
        return error_response(
            error="faz_operation_failed",
            message=str(e),
            operation="search_security_logs",
            adom=adom,
            retry_count=getattr(e, "retries_attempted", 0),
        )


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
        # Build filter string. Caller-supplied values are validated against
        # allowlists before interpolation to prevent filter injection.
        filters = []
        if subtype:
            filters.append(f"subtype=={validate_event_subtype(subtype)}")
        if level:
            filters.append(f"level=={validate_event_level(level)}")

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

    except ValidationError as e:
        return error_response(
            error="validation_error",
            message=f"Validation error: {e}",
            operation="search_event_logs",
            adom=adom,
        )
    except Exception as e:
        logger.error(f"Failed to search event logs: {e}")
        return error_response(
            error="faz_operation_failed",
            message=str(e),
            operation="search_event_logs",
            adom=adom,
            retry_count=getattr(e, "retries_attempted", 0),
        )


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
            time_range_dict = await _parse_time_range(time_range)

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
        # Validate key_type against the allowlist FAZ accepts.
        if key_type not in ("log-data", "pcapurl"):
            raise ValidationError(
                f"Invalid key_type '{key_type}'. Must be 'log-data' or 'pcapurl'."
            )

        if not log_data:
            raise ValidationError("log_data cannot be empty")

        # When key_type is a pcapurl, constrain it to a FAZ resource reference
        # rather than an arbitrary external URL before forwarding to FAZ.
        if key_type == "pcapurl":
            log_data = validate_pcapurl(log_data)

        client = _get_client()
        result = await client.get_pcapfile(log_data, key_type)

        return {
            "status": "success",
            "data": result,
        }
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to get PCAP file: {e}")
        return {"status": "error", "message": str(e)}
