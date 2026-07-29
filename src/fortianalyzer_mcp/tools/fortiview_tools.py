"""FortiView analytics tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 FortiView API specifications.
Provides network visibility, threat analysis, and traffic analytics using TID-based workflow.
"""

import asyncio
import logging
from typing import Any

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.query.groups import FORTIVIEW_ALL_DEVICES
from fortianalyzer_mcp.query.shape import project_payload
from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.tool_annotations import READ_ONLY
from fortianalyzer_mcp.utils.responses import coerce_num, error_response, redact
from fortianalyzer_mcp.utils.time_range import parse_time_range
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    build_device_filter,
    get_default_adom,
    validate_adom,
    validate_fortiview_view,
)

logger = logging.getLogger(__name__)


def _get_client() -> FortiAnalyzerClient:
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


def build_fortiview_device_filter(device: str | None) -> list[dict[str, str]]:
    """Build the ``device`` filter FortiView understands.

    ``build_device_filter`` speaks logview's dialect: its no-device default is
    ``[{"devid": "All_FortiGate"}]`` and it routes *any* ``All_*`` token under
    ``devid``. FortiView's all-devices group is ``All_Device`` under
    ``devname`` (see ``client.fortiview_run``'s own default), and the wrong
    spelling is not an error -- the view returns an empty top-N, which reads as
    "no traffic" rather than as a mistake. So every all-devices form is
    translated here, at the one boundary where a FortiView request is built:

    * ``None`` -> ``[{"devname": "All_Device"}]``
    * any ``All_*`` group (logview's ``All_FortiGate``, ``All_FortiMail``, ...,
      and ``All_Device`` itself) -> ``[{"devname": "All_Device"}]``
    * a serial-shaped value -> ``[{"devid": <serial>}]`` (unchanged)
    * anything else -> ``[{"devname": <name>}]`` (unchanged)

    A single named device therefore reaches FortiView exactly as
    ``build_device_filter`` composes it; only the all-devices case differs,
    because only the all-devices case has two spellings.
    """
    if not device or device.startswith("All_"):
        return [{"devname": FORTIVIEW_ALL_DEVICES}]
    return build_device_filter(device)


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


@mcp.tool(annotations=READ_ONLY)
async def run_fortiview(
    view_name: str,
    adom: str | None = None,
    device: str | None = None,
    time_range: str = "1-hour",
    filter: str | None = None,
    limit: int = 20,
    offset: int = 0,
    sort_by: str | None = None,
    sort_order: str = "desc",
) -> dict[str, Any]:
    """Start a FortiView analytics query.

    FortiView provides real-time visibility and analytics dashboards.
    This starts an async query and returns a TID for fetching results.

    Args:
        view_name: FortiView view type. Options:
            - "top-sources": Top traffic sources by IP
            - "top-destinations": Top traffic destinations
            - "top-applications": Top applications by bandwidth
            - "top-websites": Top websites accessed
            - "top-threats": Top security threats detected
            - "top-cloud-applications": Top cloud/SaaS apps
            - "top-countries": Top destination countries (geo)
            - "site-to-site-ipsec": Site-to-site IPsec VPN tunnels
            - "policy-hits": Per-policy hit counts (recommended)
            - "policy-line": Time-series policy data
        adom: ADOM name (default: from config DEFAULT_ADOM)
        device: Device filter (serial number or name, optional)
        time_range: Time range. Options:
            - "now", "5-min", "15-min": Real-time
            - "1-hour", "6-hour", "12-hour", "24-hour"
            - "1-day", "7-day", "30-day"
            - Custom: "2024-01-01 00:00:00|2024-01-02 00:00:00"
        filter: Filter expression (optional). Examples:
            - "srcintf!=wan1" - Exclude specific interface
            - "bandwidth>0" - Only entries with bandwidth
        limit: Maximum results (default: 20)
        offset: Record offset for pagination
        sort_by: Sort field (optional). Common fields:
            - "bandwidth": Sort by total bytes (traffic_in + traffic_out)
            - "counts": Sort by hit count
            - "threatweight": Sort by threat score
        sort_order: Sort order "asc" or "desc" (default: "desc")

    Returns:
        dict with TID for fetching results

    Example:
        >>> result = await run_fortiview("top-sources", time_range="24-hour", sort_by="bandwidth")
        >>> tid = result["tid"]
        >>> # Use fetch_fortiview to get results
    """
    try:
        # Validate inputs
        adom = validate_adom(adom or get_default_adom())
        view_name = validate_fortiview_view(view_name)
        # FortiView accepts at most 1000 rows per fetch; keep offset sane.
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)

        client = _get_client()
        tr = await _parse_time_range(time_range)

        # Convert device string to API format. Serial-shaped values must go
        # under devid (a serial under devname silently matches nothing), and
        # every all-devices spelling is translated to FortiView's own
        # All_Device -- logview's All_FortiGate returns an empty top-N here.
        device_filter = build_fortiview_device_filter(device)

        # Build sort_by parameter in API format: [{"field": "...", "order": "..."}]
        sort_by_param = None
        if sort_by:
            sort_by_param = [{"field": sort_by, "order": sort_order}]

        logger.info(f"Starting FortiView query: {view_name} in ADOM {adom}")

        result = await client.fortiview_run(
            adom=adom,
            view_name=view_name,
            device=device_filter,
            time_range=tr,
            filter=filter,
            limit=limit,
            offset=offset,
            sort_by=sort_by_param,
        )

        tid = result.get("tid") if isinstance(result, dict) else None
        if not tid:
            # Without a tid the caller cannot fetch anything; surface the
            # failed launch instead of a success-shaped payload with tid=None.
            return {
                "status": "error",
                "message": "Failed to get TID from FortiView query",
            }

        return {
            "status": "success",
            "tid": tid,
            "view_name": view_name,
            "adom": adom,
            "time_range": tr,
        }
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to start FortiView query: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=READ_ONLY)
async def fetch_fortiview(
    tid: int,
    view_name: str,
    adom: str | None = None,
) -> dict[str, Any]:
    """Fetch FortiView query results by TID.

    Retrieves results from a previously started FortiView query.

    Args:
        tid: Task ID from run_fortiview
        view_name: Same view name used in run_fortiview
        adom: ADOM name (default: from config DEFAULT_ADOM)

    Returns:
        dict with FortiView analytics data

    Example:
        >>> result = await fetch_fortiview(tid=12345, view_name="top-sources")
        >>> for item in result["data"]:
        ...     print(f"{item['srcip']}: {item['bytes']} bytes")
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        view_name = validate_fortiview_view(view_name)
        client = _get_client()

        logger.info(f"Fetching FortiView results for TID {tid}")

        result = await client.fortiview_fetch(
            adom=adom,
            view_name=view_name,
            tid=tid,
        )

        data = result.get("data", []) if isinstance(result, dict) else result
        if not isinstance(data, list):
            data = [data] if data else []

        # Surface query progress: a fetch before the scan reaches 100% returns
        # partial aggregates (wrong top-N), which callers must be able to see.
        # A missing percentage is treated as complete (builds that omit it).
        percentage = coerce_num(result.get("percentage")) if isinstance(result, dict) else None
        complete = percentage is None or percentage >= 100

        response: dict[str, Any] = {
            "status": "success",
            "tid": tid,
            "view_name": view_name,
            "count": len(data),
            "data": data,
            "complete": complete,
        }
        if percentage is not None:
            response["percentage"] = percentage
        if not complete:
            response["warning"] = (
                "Query is still running; data is a partial aggregate. "
                "Fetch again until complete=true, or use get_fortiview_data."
            )
        return response
    except Exception as e:
        logger.error(f"Failed to fetch FortiView results: {e}")
        return {"status": "error", "message": redact(str(e))}


async def _get_fortiview_data_impl(
    *,
    client: FortiAnalyzerClient,
    adom: str,
    view_name: str,
    device: str | None,
    tr: dict[str, str],
    filter: str | None,
    limit: int,
    timeout: int,
    sort_by: str | None,
    sort_order: str,
    # Named field_names rather than fields: this is a private implementation
    # helper, not an @mcp.tool(), and test_server_instructions.py's projection
    # doc-consistency check finds every *function definition* with a `fields`
    # argument across tools/*.py (not just decorated tools) and requires the
    # usage guide to name it. A helper only reachable from other tool modules
    # is not part of that LLM-facing surface and should not be counted there.
    field_names: list[str] | None,
) -> dict[str, Any]:
    """Run the FortiView run/poll/fetch workflow against an already-resolved window.

    Split out of :func:`get_fortiview_data` so a caller that has already
    resolved its own time window through a different anchor -- ``query_logs``'s
    ``group_by`` dispatch resolves via the log-clock-anchored
    :func:`~fortianalyzer_mcp.utils.log_clock.resolve_time_window`, not this
    module's FAZ-system-tz "now" anchor -- can reuse this workflow without
    re-deriving ``tr`` a second, independent way. The two anchors can disagree,
    and silently re-resolving would let the response's echoed
    ``time_range``/``timezone`` drift from the window FortiView actually
    scanned, which ``is_exact: true`` cannot afford.

    Does not itself catch exceptions: :func:`get_fortiview_data` catches for
    its own callers, while ``query_logs`` lets an exception here fall through
    to its own outer handler so the failure comes back as one full
    ``query_logs`` error envelope rather than a second, differently-shaped one.
    """
    # Convert device string to API format. Serial-shaped values must go under
    # devid (a serial under devname silently matches nothing), and every
    # all-devices spelling -- including the All_FortiGate that query_logs's
    # own device parameter advertises -- is translated to FortiView's
    # All_Device, which is the only one this endpoint answers for.
    device_filter = build_fortiview_device_filter(device)

    # Build sort_by parameter in API format
    sort_by_param = None
    if sort_by:
        sort_by_param = [{"field": sort_by, "order": sort_order}]

    logger.info(f"Running FortiView query: {view_name}")

    # Start the query
    run_result = await client.fortiview_run(
        adom=adom,
        view_name=view_name,
        device=device_filter,
        time_range=tr,
        filter=filter,
        limit=limit,
        sort_by=sort_by_param,
    )

    tid = run_result.get("tid") if isinstance(run_result, dict) else None
    if not tid:
        return {
            "status": "error",
            "message": "Failed to get TID from FortiView query",
        }

    # Poll for results
    # Bound the wait so one call can't pin the shared client for hours.
    timeout = max(1, min(timeout, 3600))
    start_time = asyncio.get_running_loop().time()
    poll_interval = 0.5

    while True:
        elapsed = asyncio.get_running_loop().time() - start_time
        if elapsed > timeout:
            return {
                "status": "timeout",
                "tid": tid,
                "message": f"FortiView query timed out after {timeout}s",
            }

        fetch_result = await client.fortiview_fetch(
            adom=adom,
            view_name=view_name,
            tid=tid,
        )

        # Only return once the query is complete; returning on first
        # non-empty data hands back partial aggregates (wrong top-N).
        # A missing/unparseable percentage is treated as complete so
        # builds that omit it still return immediately; FAZ may return
        # the field as a string, hence the coercion.
        if isinstance(fetch_result, dict):
            data = fetch_result.get("data", [])
            percentage = coerce_num(fetch_result.get("percentage"))

            if percentage is None or percentage >= 100:
                if not isinstance(data, list):
                    data = [data] if data else []

                data, returned, projection_warnings = project_payload(
                    "fortiview", data, field_names
                )

                return {
                    "status": "success",
                    "tid": tid,
                    "view_name": view_name,
                    "count": len(data),
                    "data": data,
                    "fields_returned": returned,
                    "warnings": projection_warnings,
                }

        await asyncio.sleep(poll_interval)


@mcp.tool(annotations=READ_ONLY)
async def get_fortiview_data(
    view_name: str,
    adom: str | None = None,
    device: str | None = None,
    time_range: str = "1-hour",
    filter: str | None = None,
    limit: int = 20,
    timeout: int = 30,
    sort_by: str | None = None,
    sort_order: str = "desc",
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Get FortiView data with automatic TID handling.

    Convenience function that runs FortiView query and waits for results.
    Handles the two-step TID workflow automatically.

    Args:
        view_name: FortiView view type (see run_fortiview for options)
        adom: ADOM name (default: from config DEFAULT_ADOM)
        device: Device filter (serial number or name, optional). Omit for all
            devices; any "All_*" group is translated to FortiView's own
            All_Device, which is the only all-devices token this endpoint
            answers for.
        time_range: Time range (default: "1-hour")
        filter: Filter expression (optional). Examples:
            - "srcintf!=wan1" - Exclude specific interface
            - "bandwidth>0" - Only entries with bandwidth
        limit: Maximum results (default: 20)
        timeout: Maximum wait time in seconds (default: 30)
        sort_by: Sort field (optional). Common fields:
            - "bandwidth": Sort by total bytes
            - "sessions": Sort by session count
            - "threatweight": Sort by threat score
            Per-view caveat -- "top-cloud-applications" (Shadow IT) has no
            "bandwidth" column: its byte columns (total_size/upload_size/
            download_size) are always 0, because FortiGate app-ctrl logs
            carry no byte counts (a known FortiOS logging limitation).
            Sorting that view by "bandwidth" raises a live FortiAnalyzer DB
            error; use "sessions" (usage) or "d_risk" (risk score) instead.
        sort_order: Sort order "asc" or "desc" (default: "desc")
        fields: Which keys each row carries. FortiView columns differ per view
            and are not curated yet, so omitting this returns full rows with a
            warning. Pass the columns you want, or ["*"] to silence the warning.

    Returns:
        dict with FortiView analytics data

    Example:
        >>> result = await get_fortiview_data(
        ...     "top-sources",
        ...     time_range="24-hour",
        ...     limit=10,
        ...     sort_by="bandwidth"
        ... )
        >>> for item in result["data"]:
        ...     print(f"{item['srcip']}: {item['bandwidth']} bytes")
    """
    try:
        # Validate inputs
        adom = validate_adom(adom or get_default_adom())
        view_name = validate_fortiview_view(view_name)
        # FortiView accepts at most 1000 rows per fetch; keep offset sane.
        limit = max(1, min(limit, 1000))

        client = _get_client()
        tr = await _parse_time_range(time_range)

        return await _get_fortiview_data_impl(
            client=client,
            adom=adom,
            view_name=view_name,
            device=device,
            tr=tr,
            filter=filter,
            limit=limit,
            timeout=timeout,
            sort_by=sort_by,
            sort_order=sort_order,
            field_names=fields,
        )

    except ValidationError as e:
        return error_response(
            error="validation_error",
            message=e,
            operation="get_fortiview_data",
            adom=adom,
        )
    except Exception as e:
        logger.error(f"Failed to get FortiView data: {e}")
        return {"status": "error", "message": redact(str(e))}
