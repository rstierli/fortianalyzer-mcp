"""Log query and analysis tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 LogView API specifications.
Implements the two-step TID-based log search workflow.
"""

import asyncio
import logging
from typing import Any

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.query.filters import FilterCondition, compile_to_string
from fortianalyzer_mcp.query.groups import (
    GroupPlan,
    UnsupportedGroupDimension,
    aggregate_breakdowns,
    resolve_group_plan,
)
from fortianalyzer_mcp.query.shape import fields_returned, project_rows, resolve_projection
from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.tool_annotations import DESTRUCTIVE, READ_ONLY
from fortianalyzer_mcp.utils.log_clock import resolve_time_window
from fortianalyzer_mcp.utils.responses import build_warnings, coerce_num, error_response, redact
from fortianalyzer_mcp.utils.time_range import parse_time_range
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    build_device_filter,
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
# Hard upper bound on a single search's wall-clock budget. Because a search now
# *holds* a concurrency slot for its whole budget (poll-before-fetch), a caller
# passing a huge timeout must not be able to monopolize the slot pool.
MAX_SEARCH_TIMEOUT = 300
# Poll cadence: the first logsearch_fetch is immediate, then the delay backs
# off from _INITIAL_POLL_DELAY doubling up to POLL_INTERVAL. Sub-second searches
# return on the first poll without a fixed 1s floor.
POLL_INTERVAL = 1.0
_INITIAL_POLL_DELAY = 0.25
# Appliance maximum for the logsearch fetch limit (rejects > 1000).
LOG_FETCH_LIMIT_MAX = 1000
# Shared recovery budget for ALL re-issue causes within one page (invalid-tid
# during count, invalid-tid race during fetch, and the 7.6.7 "premature 100%"
# empty page). Contract: at most 1 initial start + MAX_SEARCH_REISSUES recovery
# starts per page, and no new start/fetch past the deadline -- so a reaping
# appliance can never spin logsearch_start and re-create slot exhaustion.
MAX_SEARCH_REISSUES = 3
# Bound concurrent in-flight appliance searches across every call site in this
# process (query_logs, fetch_more_logs, policy fan-out, PCAP). Poll-before-fetch
# holds a search slot until readiness, so the appliance-slot guard lives here at
# the shared page runner rather than only in the policy fan-out.
LOGSEARCH_CONCURRENCY_LIMIT = 4
_LOGSEARCH_SEMAPHORE = asyncio.Semaphore(LOGSEARCH_CONCURRENCY_LIMIT)
# Bounded best-effort cleanup-cancel budget (seconds). Kept short so a
# non-delivered exit cannot meaningfully extend the concurrency-slot hold past
# the search's own timeout budget.
_CLEANUP_CANCEL_TIMEOUT = 2.0


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


def _normalize_logs(data: Any) -> list[Any]:
    """Normalize a logsearch ``data`` field to a list."""
    if isinstance(data, list):
        return data
    return [data] if data else []


def _clamp_timeout(timeout: int) -> int:
    """Clamp a caller-supplied search timeout to ``[1, MAX_SEARCH_TIMEOUT]``.

    Non-int/non-positive values fall back to the default. The upper bound keeps a
    single search from holding a concurrency slot indefinitely.
    """
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        return DEFAULT_SEARCH_TIMEOUT
    return max(1, min(timeout, MAX_SEARCH_TIMEOUT))


def _page_is_final(logs: list[Any], total: int | None, offset: int) -> bool:
    """Decide whether a ``percentage>=100`` fetch is genuinely complete.

    FortiAnalyzer 7.6.7 can report ``percentage:100`` with an *empty* ``data``
    page even though ``total-count`` says matching rows exist at/after the
    requested offset. That is not a real completion -- treating it as one returns
    a misleading zero-result success. Such a page is reported as non-final so the
    caller re-issues a fresh search (bounded). A page is final when it carries
    rows, or when the total is unknown, or when the total does not claim rows
    beyond this offset (a genuine empty result).
    """
    if logs:
        return True
    if total is not None and total > offset:
        return False
    return True


async def _run_logsearch_page(
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
    """Run one self-contained search page under the global concurrency guard.

    Acquires ``_LOGSEARCH_SEMAPHORE`` around the whole start -> poll -> fetch
    lifecycle so total in-flight appliance searches across every call site stay
    bounded, then delegates to :func:`_run_logsearch_page_unlocked`.
    """
    async with _LOGSEARCH_SEMAPHORE:
        return await _run_logsearch_page_unlocked(
            client,
            adom=adom,
            logtype=logtype,
            device_filter=device_filter,
            time_range=time_range,
            filter=filter,
            offset=offset,
            limit=limit,
            timeout=timeout,
        )


# Backward-compatible alias for the previous fetch-first page-runner name.
_run_search_page = _run_logsearch_page


async def _run_logsearch_page_unlocked(
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
    """Run one search page: start -> poll ``logsearch_fetch`` until complete.

    The official FAZ JSON-RPC API exposes a single read endpoint
    (``GET /logview/adom/{adom}/logsearch/{tid}``) that returns BOTH progress
    (``percentage``) AND the data slice in the same response. We loop on this
    endpoint, returning when ``percentage`` reaches 100. ``percentage`` is the
    only spec-documented readiness signal; per the FAZ docs it equals 100 when
    either the requested number of matching logs has been found, or all matching
    logs have been scanned.

    Recovery (invalid-tid race during fetch, premature 100% empty page) shares
    one budget of ``MAX_SEARCH_REISSUES`` and is also bounded by the wall-clock
    ``deadline``; no new start or fetch is issued past the deadline, and every
    ``fetch`` await is bounded by the remaining budget. On a non-delivered exit
    the started tid is best-effort (shielded, bounded) cancelled so a search is
    never leaked.

    Returns ``{"timed_out": bool, "tid": int|None, "logs": list, "total": int|None}``.
    """
    await client.ensure_connected()
    loop = asyncio.get_running_loop()
    timeout = _clamp_timeout(timeout)
    limit = _clamp_limit(limit)
    deadline = loop.time() + timeout
    reissues_left = MAX_SEARCH_REISSUES

    while True:
        # No new start once the budget is spent.
        if loop.time() >= deadline:
            return {"timed_out": True, "tid": None, "logs": [], "total": None}

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

        delivered = False  # True once a fetch returned percentage>=100
        try:
            reissue = False
            poll_delay = _INITIAL_POLL_DELAY
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return {"timed_out": True, "tid": tid, "logs": [], "total": None}
                try:
                    fetch_result = await asyncio.wait_for(
                        client.logsearch_fetch(adom=adom, tid=tid, limit=limit, offset=offset),
                        timeout=remaining,
                    )
                except TimeoutError:
                    return {"timed_out": True, "tid": tid, "logs": [], "total": None}
                except Exception as exc:
                    if _is_invalid_tid_error(exc):
                        # Appliance reaped the tid mid-poll -> recover.
                        reissue = True
                        break
                    raise

                # Per spec: scan complete iff percentage >= 100.
                percentage = coerce_num(fetch_result.get("percentage"))
                if percentage is not None and percentage >= 100:
                    delivered = True
                    logs = _normalize_logs(fetch_result.get("data"))
                    total = _coerce_total(fetch_result.get("total-count"))
                    if _page_is_final(logs, total, offset):
                        return {"timed_out": False, "tid": tid, "logs": logs, "total": total}
                    # Premature 100%: empty page while total claims rows here -> recover.
                    if reissues_left <= 0:
                        return {"timed_out": False, "tid": tid, "logs": logs, "total": total}
                    reissue = True
                    break

                # Still streaming: sleep, then re-poll the same tid.
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return {"timed_out": True, "tid": tid, "logs": [], "total": None}
                await asyncio.sleep(min(poll_delay, remaining))
                poll_delay = min(poll_delay * 2, POLL_INTERVAL)

            if reissue:
                if reissues_left <= 0:
                    return {"timed_out": True, "tid": tid, "logs": [], "total": None}
                reissues_left -= 1
                continue
        finally:
            # Any exit without a delivered fetch (generic count/fetch error,
            # cancellation, or deadline) may leave the started search running:
            # best-effort cancel it. The cancel is shielded so it is dispatched
            # even while this task is being cancelled, and bounded by a short
            # budget so it cannot meaningfully extend the slot hold past the
            # search budget. Non-cancel exceptions are swallowed; on a real
            # CancelledError the shielded cancel is dispatched and the
            # CancelledError then propagates (it is a BaseException, not caught
            # by ``except Exception``) -- if even the dispatch cannot run, the
            # appliance reaps the single-use task on its own.
            if not delivered and tid:
                try:
                    await asyncio.shield(
                        asyncio.wait_for(
                            client.logsearch_cancel(adom, tid),
                            timeout=_CLEANUP_CANCEL_TIMEOUT,
                        )
                    )
                except Exception:  # noqa: BLE001 - cleanup must not mask the real exit
                    pass


def _get_client() -> FortiAnalyzerClient:
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


# Device filter construction is shared across the log, traffic, and pcap tools;
# the single implementation lives in utils.validation. Kept as a module alias so
# existing call sites (and any callers importing this name) keep working.
_build_device_filter = build_device_filter


@mcp.tool(annotations=READ_ONLY)
async def query_logs(
    adom: str | None = None,
    logtype: str = "traffic",
    device: str | None = None,
    time_range: str = "1-hour",
    filter: str | None = None,
    filters: list[FilterCondition] | None = None,
    fields: list[str] | None = None,
    group_by: str | None = None,
    sample_by: list[str] | None = None,
    count_only: bool = False,
    top_n: int = 10,
    limit: int = 100,
    offset: int = 0,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
    """Query logs from FortiAnalyzer log database.

    This implements the two-step TID-based log search workflow:
    1. Start search task (returns TID)
    2. Poll for results until complete

    Prefer a narrower tool where one fits:
        - Filtering only on srcip/dstip/srcport/dstport/action/policy_id ->
          search_traffic_logs builds the filter string for you.
        - "How much traffic did policy N carry" -> analyze_policy_traffic. It
          fans out per policy under its own bounded-scan budget and reports
          its own exactness; paging raw rows to answer a volume question
          wastes the context it costs. For one aggregate over a single query
          with no policy fan-out, group_by/sample_by right here do the same
          job.
        - IPS/attack events, especially with PCAP -> search_ips_logs.
        - Unsure what is filterable -> get_log_fields(name_filter="...").

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
        time_range: Time range for logs. Presets: "5-min", "15-min",
            "30-min", "1-hour", "2-hour", "6-hour", "12-hour", "24-hour",
            "1-day", "2-day", "7-day", "30-day", "90-day" (plus "now", a
            5-min alias). Custom: "start_time|end_time"
            (e.g., "2024-01-01 00:00:00|2024-01-02 00:00:00")
        filter: Log filter expression (optional).
            Example: "srcip==10.0.0.1 and dstport==443"
            Operators: ==, !=, <, >, <=, >= and `like` with % wildcards
            (e.g. 'service like "%DNS%"'); negate by wrapping the whole
            clause, '!(service like "%DNS%")'. Do NOT write `contain` or
            `!contain`: the parser accepts both and then matches nothing,
            so they fail silently rather than erroring. Prefer `filters`,
            which emits the working spelling for you.
        filters: Structured filter conditions, each {field, op, value} —
            preferred over `filter` because the field names are validated here
            and the operator spelling is handled for you. Mutually exclusive
            with `filter`.
            Ops: eq, ne, gt, gte, lt, lte, contains, not_contains, in, not_in.
            Example: [{"field": "srcip", "op": "eq", "value": "10.0.0.1"},
                      {"field": "dstport", "op": "in", "value": [80, 443]}]
            English field names are accepted where unambiguous (source_ip,
            destination_port, application); get_log_fields lists the rest.
        fields: Which keys each returned row should carry. Omit for a curated
            default (the fields that answer most questions about this logtype,
            including the ones other tools take as input); pass ["*"] for the
            full row as before; or name the fields you want. English aliases
            work here exactly as they do in `filters`.
            Example: fields=["srcip", "dstip", "action", "sentbyte"]
        group_by: Return exact per-value counts for one dimension instead of
            rows. Only dimensions the appliance aggregates natively are
            accepted (srcip, dstip, app, hostname, attack, policyid,
            dstcountry); anything else is an error naming sample_by. The
            answer is exact because the appliance counted it.
        sample_by: Return per-value counts for one or more dimensions from a
            bounded row scan. Unlike group_by this is a *sample*, and the
            response says so: check is_exact and analysis_mode before quoting
            any number. Derived dimensions work here: "port" is proto/dstport,
            "icmp_type_code" decodes the ICMP pair FAZ hides in `service`.
        count_only: Return just the total row count for the query.
        top_n: Buckets per dimension for sample_by (default 10). 0 returns
            every bucket.
        limit: Maximum logs to return (default: 100, max: 1000)
        offset: Offset for pagination (default: 0)
        timeout: Search timeout in seconds (default: 60)

    Returns:
        dict: Log query results with keys:
            - status: "success" or "error"
            - count: Number of logs returned in this page
            - total: The handle's first-page Baseline total (int), or None if unknown.
              Stays fixed across fetch_more_logs pages so it does not wobble as the
              appliance re-counts a frozen window (see page_total for the live count).
            - total_is_known: Whether `total` is authoritative (False => unknown)
            - page_total: The raw FortiAnalyzer total-count observed for this page's
              search (the live per-page figure; equals total on page 0)
            - initial_total: The first-page baseline (equals total on page 0)
            - total_count_stability: "single_observation" on page 0 (or "unknown" when
              no count was returned)
            - total_drift_detected: False on page 0; see fetch_more_logs for drift
            - total_delta: 0 on page 0 when known, else None
            - has_more_basis: which figure has_more was computed against
              ("stable_total" | "best_effort_max_observed_total" |
              "best_effort_page_total" | "full_page_heuristic")
            - percentage: Search completion percentage (100 on success)
            - tid: Reusable pagination handle (pass to fetch_more_logs)
            - has_more: Whether more results remain beyond this page
            - next_offset: Offset to pass to fetch_more_logs, or None when has_more is False
            - logs: List of log entries (bounded by `limit`)
            - fields_returned: The keys each row carries. Reported even for a
              zero-row page, so it still says what is queryable next.
            - adom, logtype, filter, device: Echoed query context (auditability)
            - filter: The filter string actually sent to FortiAnalyzer (the
              compiled form when `filters` was used)
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

        filter_warnings: list[str] = []
        if filters and filter:
            return error_response(
                error="conflicting_filter_input",
                message=(
                    "Pass either 'filters' (structured conditions) or 'filter' (a raw "
                    "FortiAnalyzer filter string), not both."
                ),
                operation="query_logs",
                adom=adom,
                logtype=logtype,
                recommendation=(
                    "Use 'filters' unless you need syntax it cannot express, such as a regex match."
                ),
            )
        if filters:
            filter, filter_warnings = compile_to_string(filters, logtype)

        # Exactly one aggregation mode, or none. Two would each describe a
        # different response shape and there is no sensible merge.
        chosen = [
            name
            for name, active in (
                ("group_by", group_by is not None),
                ("sample_by", bool(sample_by)),
                ("count_only", count_only),
            )
            if active
        ]
        if len(chosen) > 1:
            return error_response(
                error="conflicting_aggregation",
                message=(
                    f"Pass at most one of group_by, sample_by or count_only; got "
                    f"{', '.join(chosen)}. Each returns a different response shape."
                ),
                operation="query_logs",
                adom=adom,
                logtype=logtype,
                recommendation=(
                    "Use group_by for an exact grouping the appliance computes, "
                    "sample_by for a bounded breakdown over a row scan, or count_only "
                    "for just the total."
                ),
            )

        aggregating = bool(chosen)
        if aggregating and fields is not None:
            # Inert rather than fatal: it describes a row shape that no rows
            # will be returned in, which is a harmless mistake, not a wrong
            # query.
            filter_warnings.append(
                f"'fields' is ignored with {chosen[0]}: no raw rows are returned."
            )

        projection: frozenset[str] | None
        projection_warnings: list[str]
        if aggregating:
            projection, projection_warnings = None, []
        else:
            projection, projection_warnings = resolve_projection(logtype, fields)

        # Validate group_by before touching the client: an unsupported dimension
        # or an unverified filter combination is a pure input error and should
        # be refused without ever starting a session.
        group_plan: GroupPlan | None = None
        if group_by is not None:
            try:
                group_plan = resolve_group_plan(logtype, group_by)
            except UnsupportedGroupDimension as e:
                return error_response(
                    error="unsupported_group_dimension",
                    message=str(e),
                    operation="query_logs",
                    adom=adom,
                    logtype=logtype,
                    recommendation=f"Use sample_by=['{group_by}'] for a bounded breakdown.",
                )

            # Task 0 could not prove this view honours a logview filter. Forwarding
            # it would return an unfiltered top-N under is_exact: true -- a
            # confident answer about a population nobody asked for.
            if filter:
                return error_response(
                    error="unsupported_view_filter",
                    message=(
                        f"group_by='{group_by}' dispatches to the FortiView view "
                        f"'{group_plan.target}', and this server has not verified that the "
                        "view applies a logview filter rather than ignoring it. Refusing "
                        "rather than returning a top-N that may cover unfiltered traffic."
                    ),
                    operation="query_logs",
                    adom=adom,
                    logtype=logtype,
                    recommendation=(
                        f"Drop the filter to group the whole window, or use "
                        f"sample_by=['{group_by}'] which applies the filter and labels the "
                        "result as a bounded sample."
                    ),
                )

        client = _get_client()
        await client.ensure_connected()

        # Resolve the query window. Relative presets are anchored on the detected
        # LogView ingest clock (so a post-upgrade clock skew does not miss recent
        # logs); custom ranges pass through verbatim. tz_name labels the returned
        # timestamps (FAZ interprets the naive bounds in its own local TZ).
        try:
            window = await resolve_time_window(
                client, adom, time_range, device, faz_tz_for_custom=True
            )
        except ValueError as e:
            return error_response(
                error="invalid_time_range",
                message=f"Invalid time_range: {e}",
                operation="query_logs",
                adom=adom,
                logtype=logtype,
            )
        time_range_dict = window.time_range
        tz_name = window.timezone
        time_basis_source = window.time_basis_source
        clock_skew_seconds = window.clock_skew_seconds

        # Build device filter
        device_filter = _build_device_filter(device)

        requested_limit = limit
        limit = _clamp_limit(limit)
        offset = max(0, offset)
        timeout = _clamp_timeout(timeout)

        if group_plan is not None:
            # Call the run/poll/fetch implementation directly, not the
            # get_fortiview_data tool wrapper: the wrapper re-resolves
            # time_range itself via _parse_time_range, which anchors relative
            # presets on FortiView's own FAZ-system-tz "now" -- a different
            # clock than resolve_time_window's log-clock anchor already used
            # above. Passing the raw time_range string through would let
            # FortiView scan a window that silently differs from the
            # time_range_dict/tz_name this response echoes, which is_exact:
            # true cannot afford. Threading time_range_dict keeps the two in
            # lockstep.
            from fortianalyzer_mcp.tools.fortiview_tools import _get_fortiview_data_impl

            view: dict[str, Any] = await _get_fortiview_data_impl(
                client=client,
                adom=adom,
                view_name=group_plan.target,
                # The plan carries FortiView's own all-devices token; passing
                # logview's All_FortiGate here returns an empty top-N silently.
                device=device or group_plan.all_devices_group,
                tr=time_range_dict,
                filter=filter,
                limit=limit,
                timeout=30,
                sort_by=None,
                sort_order="desc",
                field_names=["*"],
            )
            if view.get("status") != "success":
                # Re-wrap rather than pass through verbatim: the FortiView
                # helper's own failure shapes ({"status": "error"|"timeout",
                # "message": ...}) carry none of query_logs's envelope fields
                # (error code, operation, retry_count), and forwarding them
                # unwrapped would break that contract on this one path.
                return error_response(
                    error=(
                        "search_timeout"
                        if view.get("status") == "timeout"
                        else "fortiview_query_failed"
                    ),
                    message=(
                        view.get("message")
                        or f"FortiView query for view '{group_plan.target}' did not succeed."
                    ),
                    operation="query_logs",
                    adom=adom,
                    logtype=logtype,
                    time_range=time_range_dict,
                    timezone=tz_name,
                )

            return {
                "status": "success",
                "adom": adom,
                "logtype": logtype,
                "group_by": group_plan.dimension,
                "groups": view.get("data", []),
                "group_source": f"fortiview:{group_plan.target}",
                # The appliance aggregated this. That is the whole reason
                # group_by refuses dimensions with no native surface.
                "is_exact": True,
                "time_range": time_range_dict,
                "timezone": tz_name,
                "filter": filter,
                "warnings": filter_warnings,
            }

        # Run this page as a self-contained search (FAZ tids are single-use).
        logger.info(
            f"Starting log search: adom={adom}, logtype={logtype}, "
            f"filter={redact(str(filter))[:200]}"
        )
        page = await _run_logsearch_page(
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

        if count_only:
            total = page["total"]
            return {
                "status": "success",
                "adom": adom,
                "logtype": logtype,
                "total": total,
                "total_is_known": total is not None,
                "count_source": "logsearch_total_count",
                "time_range": time_range_dict,
                "timezone": tz_name,
                "filter": filter,
                "warnings": filter_warnings,
            }

        if sample_by:
            rows = page["logs"]
            observed = len(rows)
            total = page["total"]
            total_known = total is not None
            # One page, one window: exact only when the appliance's own total
            # equals what we actually scanned. A full page means rows were
            # left behind, so nothing here may claim exactness.
            truncated = observed >= limit
            is_exact = total_known and not truncated and total == observed
            return {
                "status": "success",
                "adom": adom,
                "logtype": logtype,
                "sample_by": list(sample_by),
                "breakdowns": aggregate_breakdowns(rows, list(sample_by), top_n=top_n),
                "is_exact": is_exact,
                "analysis_mode": "exact" if is_exact else "bounded_sample",
                "total_hits": total if total_known else observed,
                "total_hits_is_known": total_known,
                "total_hit_source": "logsearch_total_count" if total_known else "observed_rows",
                "observed_hits": observed,
                "log_limit_per_slice": limit,
                "slices_scanned": 1,
                "truncated_slices": 1 if truncated else 0,
                "recommendation": (
                    "Narrow the time window or raise limit for a closer count."
                    if not is_exact
                    else ""
                ),
                "time_range": time_range_dict,
                "timezone": tz_name,
                "filter": filter,
                "warnings": filter_warnings,
            }

        logs = project_rows(page["logs"], projection)
        count = len(logs)
        total = page["total"]
        total_is_known = total is not None
        has_more = _compute_has_more(offset, count, limit, total)
        next_offset = offset + count if has_more else None
        handle = page["tid"]

        # Page 0 is the Baseline total for this handle; there is nothing to
        # compare against yet (see ADR-0002 / fetch_more_logs for drift handling).
        page0_stability = "single_observation" if total_is_known else "unknown"
        page0_basis = "stable_total" if total_is_known else "full_page_heuristic"
        page0_delta = 0 if total_is_known else None

        warnings = build_warnings(
            requested_limit=requested_limit,
            limit=limit,
            total=total,
            total_is_known=total_is_known,
            timezone=tz_name,
            has_more=has_more,
        )
        warnings.extend(filter_warnings)
        warnings.extend(projection_warnings)
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
                "time_basis_source": time_basis_source,
                "clock_skew_seconds": clock_skew_seconds,
                "initial_total": total,
                "fields": fields,
            },
        )

        return {
            "status": "success",
            "count": count,
            "total": total,
            "total_is_known": total_is_known,
            "page_total": total,
            "initial_total": total,
            "total_count_stability": page0_stability,
            "total_drift_detected": False,
            "total_delta": page0_delta,
            "has_more_basis": page0_basis,
            "percentage": 100,
            "tid": handle,
            "has_more": has_more,
            "next_offset": next_offset,
            "logs": logs,
            "fields_returned": fields_returned(logs, projection),
            "adom": adom,
            "logtype": logtype,
            "filter": filter,
            "device": device,
            "time_range": time_range_dict,
            "timezone": tz_name,
            "time_basis": (
                f"time_range and log timestamps are interpreted in FAZ local time ({tz_name})"
            ),
            "time_basis_source": time_basis_source,
            "clock_skew_seconds": clock_skew_seconds,
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


@mcp.tool(annotations=READ_ONLY)
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


@mcp.tool(annotations=READ_ONLY)
async def fetch_more_logs(
    adom: str | None = None,
    tid: int = 0,
    limit: int = 100,
    offset: int = 0,
    fields: list[str] | None = None,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
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
        fields: Override the projection for this page. Omit to reuse the
            projection the original query_logs call resolved, so a later page
            has the same shape as the first.
        timeout: Search timeout in seconds (default: 60) -- raise it to page over
            large windows (e.g. 30-day) that take longer than the default to scan

    Returns:
        dict: Additional log results with keys:
            - status: "success" or "error"
            - count: Number of logs returned in this page
            - logs: List of log entries
            - fields_returned: The keys each row carries. Reported even for a
              zero-row page, so it still says what is queryable next.
            - tid, adom, logtype, filter, device: Echoed pagination context
            - total: The handle's first-page Baseline total (stays fixed across pages;
              None if no baseline was ever captured). It is NOT this page's live count.
            - page_total: The raw FortiAnalyzer total-count observed for THIS page's
              re-run search (the live figure; may differ from total on a busy window)
            - initial_total: The first-page baseline `total` was derived from
            - total_count_stability: "stable" (page == baseline) | "drifted" (page !=
              baseline) | "unknown" (no comparable count this page)
            - total_drift_detected: True when this page's count disagrees with the baseline
            - total_delta: page_total - initial_total when both known, else None
            - has_more_basis: which figure has_more was computed against
              ("stable_total" | "best_effort_max_observed_total" |
              "best_effort_page_total" | "full_page_heuristic")
            - total_is_known, has_more: Pagination metadata (total_is_known reflects the
              baseline `total`)
            - next_offset: Offset for the next page, or None when has_more is False
            - offset, limit: Paging echoes (the clamped values actually used)
            - timezone, time_basis: FAZ timezone context
            - warnings: Advisory strings (incl. a drift notice when total_drift_detected)
        On error, a structured envelope: {status: "error", error: <machine code>,
        message, operation, retry_count, plus tid/adom/recommendation where relevant}.
        A handle is bound to its ADOM: passing a different `adom` returns
        error="adom_mismatch".

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

        effective_fields = fields if fields is not None else context.get("fields")
        projection, projection_warnings = resolve_projection(context["logtype"], effective_fields)

        # The handle is bound to the ADOM query_logs ran under: comparing a
        # baseline from one ADOM against a page from another is meaningless.
        if adom is None:
            adom = context["adom"]
        elif adom != context["adom"]:
            return error_response(
                error="adom_mismatch",
                message=(
                    f"This handle is bound to ADOM {context['adom']!r}; it cannot be paged under "
                    f"ADOM {adom!r}. Re-run query_logs to search a different ADOM."
                ),
                operation="fetch_more_logs",
                adom=adom,
                tid=tid,
            )
        adom = validate_adom(adom)

        requested_limit = limit
        limit = _clamp_limit(limit)
        offset = max(0, offset)
        timeout = _clamp_timeout(timeout)

        client = _get_client()
        await client.ensure_connected()

        page = await _run_logsearch_page(
            client,
            adom=adom,
            logtype=context["logtype"],
            device_filter=_build_device_filter(context.get("device")),
            time_range=context["time_range"],
            filter=context.get("filter"),
            offset=offset,
            limit=limit,
            timeout=timeout,
        )

        if page["timed_out"]:
            return error_response(
                error="search_timeout",
                message=f"Search timed out after {timeout} seconds",
                operation="fetch_more_logs",
                adom=adom,
                logtype=context.get("logtype"),
                tid=tid,
            )

        logs = project_rows(page["logs"], projection)
        count = len(logs)
        page_total = page["total"]
        initial_total = context.get("initial_total")
        timezone = context.get("timezone", "unknown")
        time_basis_source = context.get("time_basis_source", "unknown")
        clock_skew_seconds = context.get("clock_skew_seconds")

        # Compare this page's raw total-count against the first-page Baseline
        # total. The response `total` is always the baseline (or None when no
        # baseline was ever captured); `page_total` carries the live observation.
        # See ADR-0002 for the full branch table.
        if initial_total is not None and page_total is not None and page_total != initial_total:
            response_total = initial_total
            total_count_stability = "drifted"
            total_drift_detected = True
            total_delta = page_total - initial_total
        elif initial_total is not None and page_total == initial_total:
            response_total = initial_total
            total_count_stability = "stable"
            total_drift_detected = False
            total_delta = 0
        else:
            # No comparable pair: either no baseline, or this page omitted the
            # count. Keep the baseline if we have one, else stay None (unknown).
            response_total = initial_total
            total_count_stability = "unknown"
            total_drift_detected = False
            total_delta = None
        total_is_known = response_total is not None

        # has_more is decoupled from the response `total`: page against the best
        # available figure so a short page never stops paging early (favor
        # completeness, best-effort -- see ADR-0002).
        if total_drift_detected:
            paging_total = max(initial_total, page_total)
            has_more_basis = "best_effort_max_observed_total"
        elif initial_total is not None:
            paging_total = initial_total
            has_more_basis = "stable_total"
        elif page_total is not None:
            paging_total = page_total
            has_more_basis = "best_effort_page_total"
        else:
            paging_total = None
            has_more_basis = "full_page_heuristic"
        has_more = _compute_has_more(offset, count, limit, paging_total)
        next_offset = offset + count if has_more else None

        # Size the high-volume warning on the largest observed total, not the
        # (possibly smaller) baseline returned as `total`.
        warnings = build_warnings(
            requested_limit=requested_limit,
            limit=limit,
            total=paging_total,
            total_is_known=paging_total is not None,
            timezone=timezone,
            has_more=has_more,
        )
        warnings.extend(projection_warnings)
        if count == 0 and paging_total is not None and paging_total > offset:
            warnings.append(
                "FortiAnalyzer reports more matching rows beyond this offset but returned "
                "an empty page; the search task may have been reaped -- re-run query_logs."
            )
        if total_drift_detected:
            warnings.append(
                "FortiAnalyzer total-count changed between pages for this fixed window; total is "
                "the first-page baseline and page_total is the latest observation. Because this "
                "query is being re-run for pagination, row offsets may also shift, so duplicate or "
                "skipped rows are possible. Treat this broad/high-volume result as non-exact."
            )
            logger.info(
                "logsearch total-count drift on handle %s: adom=%s logtype=%s offset=%s "
                "initial_total=%s page_total=%s delta=%s window=%s",
                tid,
                adom,
                context.get("logtype"),
                offset,
                initial_total,
                page_total,
                total_delta,
                redact(str(context.get("time_range"))),
            )

        return {
            "status": "success",
            "count": count,
            "logs": logs,
            "fields_returned": fields_returned(logs, projection),
            "tid": tid,
            "adom": adom,
            "logtype": context.get("logtype"),
            "filter": context.get("filter"),
            "device": context.get("device"),
            "time_range": context.get("time_range"),
            "total": response_total,
            "total_is_known": total_is_known,
            "page_total": page_total,
            "initial_total": initial_total,
            "total_count_stability": total_count_stability,
            "total_drift_detected": total_drift_detected,
            "total_delta": total_delta,
            "has_more_basis": has_more_basis,
            "has_more": has_more,
            "next_offset": next_offset,
            "offset": offset,
            "limit": limit,
            "timezone": timezone,
            "time_basis": f"log timestamps are interpreted in FAZ local time ({timezone})",
            "time_basis_source": time_basis_source,
            "clock_skew_seconds": clock_skew_seconds,
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


@mcp.tool(annotations=DESTRUCTIVE)
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


@mcp.tool(annotations=READ_ONLY)
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
        adom = validate_adom(adom or get_default_adom())
        client = _get_client()
        device_filter = _build_device_filter(device) if device else None
        stats = await client.get_logstats(adom, device_filter)
        return {
            "status": "success",
            "stats": stats,
        }
    except Exception as e:
        logger.error(f"Failed to get log stats for ADOM {adom}: {e}")
        return {"status": "error", "message": redact(str(e))}


def _is_field_list(payload: list[Any]) -> bool:
    """A field list is a list holding dicts that carry ``name``."""
    return any(isinstance(entry, dict) and "name" in entry for entry in payload)


def _count_field_entries(payload: Any) -> int:
    """Count field definitions across every field list in a logfields payload.

    The appliance returns more than one list (a public ``field`` list and a
    ``private-field`` list), and on live 7.6.x both sit *inside* a wrapper
    object under ``data`` (``data[0].field``) whose own keys carry no ``name``
    -- so the walk must recurse into list elements, not just count a list's
    direct entries, or the whole catalogue counts as zero.
    """
    if isinstance(payload, dict):
        return sum(_count_field_entries(value) for value in payload.values())
    if isinstance(payload, list):
        if _is_field_list(payload):
            return sum(1 for entry in payload if isinstance(entry, dict) and "name" in entry)
        return sum(_count_field_entries(entry) for entry in payload)
    return 0


def _filter_field_entries(payload: Any, needle: str) -> Any:
    """Return a copy of ``payload`` keeping only fields whose name matches.

    Copies rather than editing in place: the payload belongs to the client
    call, and a future caching layer would inherit any mutation. A list that
    is not itself a field list is recursed element-wise -- the live 7.6.x
    payload nests the field lists inside ``data[0]`` -- while scalar entries
    pass through untouched, so a shape change on the appliance degrades to a
    no-op, never a crash.
    """
    if isinstance(payload, dict):
        return {key: _filter_field_entries(value, needle) for key, value in payload.items()}
    if isinstance(payload, list):
        if _is_field_list(payload):
            return [
                entry
                for entry in payload
                if isinstance(entry, dict) and needle in str(entry.get("name", "")).lower()
            ]
        return [
            _filter_field_entries(entry, needle) if isinstance(entry, dict | list) else entry
            for entry in payload
        ]
    return payload


@mcp.tool(annotations=READ_ONLY)
async def get_log_fields(
    adom: str | None = None,
    logtype: str = "traffic",
    devtype: str = "FortiGate",
    name_filter: str | None = None,
) -> dict[str, Any]:
    """Get available log fields for a log type -- what you can filter on.

    A live traffic response runs to roughly 200 definitions across two lists,
    which is more context than it is worth reading in full. Pass
    ``name_filter`` to narrow it to the fields you are actually after
    ("src", "port", "app"); the counts in the response say how much was
    dropped so a narrow answer is never mistaken for the whole catalogue.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        logtype: Log type (traffic, event, attack, etc.)
        devtype: Device type (default: "FortiGate")
        name_filter: Case-insensitive substring; keep only fields whose name
            contains it. Omit (or pass "") for the full catalogue.

    Returns:
        dict: Log fields with keys:
            - status: "success" or "error"
            - fields: The appliance's field payload, filtered when
              ``name_filter`` was given. On live 7.6.x the
              ``{"name": ..., "type": ...}`` entries sit nested one level
              down: ``fields["data"][0]["field"]`` (public) and
              ``fields["data"][0]["private-field"]``. Some endpoints answer
              flatter shapes; filtering and counts reach the lists wherever
              they nest.
            - name_filter: The filter applied, or None
            - field_count: Field definitions returned after filtering
            - total_field_count: Field definitions before filtering
            - message: Error message if failed

    Note:
        ``type`` is FortiAnalyzer's own discriminator and on 7.6.x it is an
        undocumented small integer (values such as 0, 4, 6 and 10 are
        observed). Fortinet publishes no legend for it, so treat it as
        opaque: to learn a field's real shape, read the field in a sample row
        from ``query_logs`` rather than trying to decode the code. The value
        is passed through unchanged in case a future firmware documents it.
        ``desc`` mirrors ``name`` on live 7.6.x -- the catalogue names fields
        but does not describe them, so this tool answers "does this field
        exist", not "what does it mean".

    Example:
        >>> result = await get_log_fields(logtype="traffic", name_filter="src")
        >>> print(f"{result['field_count']} of {result['total_field_count']}")
        >>> for field in result["fields"]["data"][0]["field"]:
        ...     print(field["name"])
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        client = _get_client()
        result = await client.get_logfields(adom, logtype, devtype)
        total = _count_field_entries(result)
        if name_filter:
            fields = _filter_field_entries(result, name_filter.lower())
        else:
            fields = result
        return {
            "status": "success",
            "fields": fields,
            "name_filter": name_filter or None,
            "field_count": _count_field_entries(fields) if name_filter else total,
            "total_field_count": total,
        }
    except Exception as e:
        logger.error(f"Failed to get log fields: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=READ_ONLY)
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
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Search traffic logs with common filter criteria.

    Convenience function for searching traffic logs with typical
    network-based filters. Wraps query_logs, so the returned `tid` is the same
    reusable pagination handle and works with fetch_more_logs.

    Prefer analyze_policy_traffic over this when the question is how much
    a policy carried rather than which rows matched -- it aggregates on the
    appliance instead of returning rows to be counted here.

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
        fields: Which keys each returned row should carry. Omit for the
            curated traffic default, ["*"] for the full row, or name the fields
            you want -- forwarded to query_logs unchanged, English aliases and
            all.

    Returns:
        dict: Log search results with keys:
            - status: "success" or "error"
            - count: Number of logs found
            - logs: List of traffic log entries, carrying the keys
              `fields` selected (the curated traffic set by default)
            - fields_returned: Those keys, echoed for a zero-row page too
            - filter_applied: Filter string used
            - tid: Reusable pagination handle -- this tool wraps query_logs,
              so the tid pages onward with fetch_more_logs like any
              query_logs tid (it is NOT an appliance task id)
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
        adom = validate_adom(adom or get_default_adom())
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
        if policy_id is not None:
            if isinstance(policy_id, bool) or not isinstance(policy_id, int) or policy_id < 0:
                raise ValidationError(
                    f"Invalid policy_id '{policy_id}'. Must be a non-negative integer."
                )
            filters.append(f"policyid=={policy_id}")

        filter_str = " and ".join(filters) if filters else None

        result: dict[str, Any] = await query_logs(
            adom=adom,
            logtype="traffic",
            device=device,
            time_range=time_range,
            filter=filter_str,
            limit=limit,
            timeout=timeout,
            fields=fields,
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


@mcp.tool(annotations=READ_ONLY)
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
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Search security logs (IPS, AV, etc.) with common filters.

    Search for security events including intrusion attempts,
    malware detections, and other security-related logs.

    For IPS specifically, search_ips_logs filters on more dimensions (CVE,
    PCAP availability, multiple severities at once) and its results feed the
    PCAP downloaders. Use this one when you want a single logtype's events
    across the broader security vocabularies.

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
        fields: Which keys each returned row should carry. Omit for the
            curated attack default, ["*"] for the full row, or name the fields
            you want -- forwarded to query_logs unchanged, English aliases and
            all.

    Returns:
        dict: Security log results with keys:
            - status: "success" or "error"
            - count: Number of security events found
            - logs: List of security log entries, carrying the keys
              `fields` selected (the curated attack set by default)
            - fields_returned: Those keys, echoed for a zero-row page too
            - filter_applied: Filter string used
            - tid: Reusable pagination handle -- this tool wraps query_logs,
              so the tid pages onward with fetch_more_logs like any
              query_logs tid (it is NOT an appliance task id)
            - message: Error message if failed

    Example:
        >>> # Find critical security events
        >>> result = await search_security_logs(
        ...     severity="critical",
        ...     time_range="7-day"
        ... )
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        # Build filter string. Every caller-supplied value is validated or
        # sanitized before interpolation to prevent filter injection.
        filters = []
        if attack_name:
            # ``contain`` is inert: the logview parser accepts it and then
            # matches nothing, so this answered "no such attack" with total
            # confidence. Same remedy and same emitted form as
            # query.filters.compile_to_string -- ``like`` with ``%`` wildcards,
            # the wildcards sanitised together with the value so the pattern is
            # one escaped literal that cannot terminate its own clause.
            # Measured on 7.6.6 over one fixed hour (289391 rows):
            # ``service contain DNS`` -> 0, ``service like "%DNS%"`` -> 120671.
            pattern = sanitize_filter_value(f"%{attack_name}%", "attack_name")
            filters.append(f"attack like {pattern}")
        if severity:
            filters.append(f"severity=={validate_severity(severity)}")
        if srcip:
            filters.append(f"srcip=={validate_ip_or_cidr(srcip, 'srcip')}")
        if dstip:
            filters.append(f"dstip=={validate_ip_or_cidr(dstip, 'dstip')}")

        filter_str = " and ".join(filters) if filters else None

        result: dict[str, Any] = await query_logs(
            adom=adom,
            logtype="attack",
            device=device,
            time_range=time_range,
            filter=filter_str,
            limit=limit,
            timeout=timeout,
            fields=fields,
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


@mcp.tool(annotations=READ_ONLY)
async def search_event_logs(
    adom: str | None = None,
    subtype: str | None = None,
    level: str | None = None,
    device: str | None = None,
    time_range: str = "24-hour",
    limit: int = 100,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
    fields: list[str] | None = None,
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
        fields: Which keys each returned row should carry. Omit for the
            curated event default, ["*"] for the full row, or name the fields
            you want -- forwarded to query_logs unchanged, English aliases and
            all.

    Returns:
        dict: Event log results with keys:
            - status: "success" or "error"
            - count: Number of events found
            - logs: List of event log entries, carrying the keys `fields`
              selected (the curated event set by default)
            - fields_returned: Those keys, echoed for a zero-row page too
            - filter_applied: Filter string used
            - tid: Reusable pagination handle -- this tool wraps query_logs,
              so the tid pages onward with fetch_more_logs like any
              query_logs tid (it is NOT an appliance task id)
            - message: Error message if failed

    Example:
        >>> # Find VPN-related events
        >>> result = await search_event_logs(
        ...     subtype="vpn",
        ...     time_range="7-day"
        ... )
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        # Build filter string. Caller-supplied values are validated against
        # allowlists before interpolation to prevent filter injection.
        filters = []
        if subtype:
            filters.append(f"subtype=={validate_event_subtype(subtype)}")
        if level:
            filters.append(f"level=={validate_event_level(level)}")

        filter_str = " and ".join(filters) if filters else None

        result: dict[str, Any] = await query_logs(
            adom=adom,
            logtype="event",
            device=device,
            time_range=time_range,
            filter=filter_str,
            limit=limit,
            timeout=timeout,
            fields=fields,
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


@mcp.tool(annotations=READ_ONLY)
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
        adom = validate_adom(adom or get_default_adom())
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
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=READ_ONLY)
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
        return {"status": "error", "message": redact(str(e))}
