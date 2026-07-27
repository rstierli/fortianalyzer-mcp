"""System and ADOM management tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.5 SYS, DVMDB, CLI, and TASK API specifications.
"""

import logging
from typing import Any

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.query.fields import TASK_STATE_CODES
from fortianalyzer_mcp.query.filters import FilterCondition, compile_to_array
from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.tool_annotations import DESTRUCTIVE, READ_ONLY
from fortianalyzer_mcp.utils.responses import error_response, redact
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    get_default_adom,
    sanitize_for_logging,
    validate_adom,
    validate_device_name,
)

logger = logging.getLogger(__name__)

# FAZ /task/task returns ``state`` as a numeric code on the wire (FNDN task
# schema); some builds/endpoints use the string names instead. Keep both forms
# working by normalizing to the lowercase name. The name<->code table itself is
# single-sourced from query.fields, so the legacy filter_state parameter and
# the structured ``filters`` path translate identically by construction.
_TASK_STATE_NAMES = {code: name for name, code in TASK_STATE_CODES.items()}
_TASK_TERMINAL_STATES = {"done", "error", "cancelled", "aborted", "warning"}


def _normalize_task_state(state: Any) -> str:
    """Normalize a FAZ task state (numeric code or string name) to its name."""
    if isinstance(state, bool):
        return "unknown"
    if isinstance(state, int):
        return _TASK_STATE_NAMES.get(state, "unknown")
    if isinstance(state, str):
        return state.strip().lower()
    return "unknown"


def _get_client() -> FortiAnalyzerClient:
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


# =============================================================================
# System Status
# =============================================================================


@mcp.tool(annotations=READ_ONLY)
async def get_system_status() -> dict[str, Any]:
    """Get FortiAnalyzer system status and version information.

    Returns comprehensive system status including:
    - FortiAnalyzer version and build
    - System hostname
    - Serial number
    - Admin domain mode
    - Platform information
    - Uptime and load

    Returns:
        dict: System status with keys:
            - status: "success" or "error"
            - data: System status information
            - message: Error message if failed

    Example:
        >>> result = await get_system_status()
        >>> print(f"Version: {result['data']['Version']}")
        >>> print(f"Hostname: {result['data']['Hostname']}")
    """
    try:
        client = _get_client()
        data = await client.get_system_status()
        return {
            "status": "success",
            "data": data,
        }
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=READ_ONLY)
async def get_ha_status() -> dict[str, Any]:
    """Get FortiAnalyzer High Availability (HA) status.

    Returns HA cluster status including:
    - HA mode (standalone, cluster)
    - Cluster members and their status
    - Sync status
    - Primary/secondary role

    Returns:
        dict: HA status with keys:
            - status: "success" or "error"
            - data: HA status information
            - message: Error message if failed

    Example:
        >>> result = await get_ha_status()
        >>> print(f"HA Mode: {result['data']['mode']}")
    """
    try:
        client = _get_client()
        data = await client.get_ha_status()
        return {
            "status": "success",
            "data": data,
        }
    except Exception as e:
        logger.error(f"Failed to get HA status: {e}")
        return {"status": "error", "message": redact(str(e))}


# =============================================================================
# ADOM Management
# =============================================================================


@mcp.tool(annotations=READ_ONLY)
async def list_adoms(
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """List all Administrative Domains (ADOMs) in FortiAnalyzer.

    ADOMs are used to partition FortiAnalyzer into separate management
    domains, each with its own devices, logs, and configurations.

    Pass `fields` unless you genuinely need the full object. The default is
    every field the appliance defines -- around 35 per ADOM, most of them
    empty placeholders (unused IPv6 DNS slots, blank descriptions,
    tab_status, logview_customize). fields=["name", "state"] answers "which
    ADOMs exist and are they enabled" for a fraction of the response.

    Args:
        fields: Specific fields to return. Recommended: ["name", "state"].
            Omitting this returns every field, which is rarely what you want.

    Returns:
        dict: ADOM list with keys:
            - status: "success" or "error"
            - count: Number of ADOMs
            - adoms: List of ADOM objects with name, desc, state, etc. The
              appliance always includes ``oid`` in each object, even under a
              ``fields`` projection that does not request it. ``state`` is the
              appliance's numeric enable flag -- live 7.6.x returns 1 for an
              enabled ADOM; Fortinet publishes no legend for other values, so
              treat anything else as not-enabled rather than guessing a
              meaning.
            - message: Error message if failed

    Example:
        >>> result = await list_adoms()
        >>> for adom in result["adoms"]:
        ...     print(f"{adom['name']}: {adom.get('desc', 'No description')}")
    """
    try:
        client = _get_client()
        adoms = await client.list_adoms(fields=fields)
        return {
            "status": "success",
            "count": len(adoms),
            "adoms": adoms,
        }
    except Exception as e:
        logger.error(f"Failed to list ADOMs: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=READ_ONLY)
async def get_adom(
    name: str,
    include_details: bool = False,
) -> dict[str, Any]:
    """Get detailed information about a specific ADOM.

    Args:
        name: ADOM name (e.g., "root", "customer-a")
        include_details: Include sub-objects like policies (default: False)

    Returns:
        dict: ADOM details with keys:
            - status: "success" or "error"
            - adom: ADOM object with full configuration
            - message: Error message if failed

    Example:
        >>> result = await get_adom("root")
        >>> print(f"State: {result['adom']['state']}")
        >>> print(f"Mode: {result['adom'].get('mode', 'N/A')}")
    """
    try:
        name = validate_adom(name)
        client = _get_client()
        loadsub = 1 if include_details else 0
        adom = await client.get_adom(name, loadsub=loadsub)
        return {
            "status": "success",
            "adom": adom,
        }
    except Exception as e:
        logger.error(f"Failed to get ADOM {name}: {e}")
        return {"status": "error", "message": redact(str(e))}


# =============================================================================
# Device Listing (from DVMDB)
# =============================================================================


@mcp.tool(annotations=READ_ONLY)
async def list_devices(
    adom: str | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """List all devices registered in an ADOM.

    FortiAnalyzer collects logs from FortiGate and other Fortinet devices.
    This lists all devices configured to send logs to this ADOM.

    Pass `fields` unless you genuinely need the full object. The default is
    roughly 60 fields per device, including credential keys returned as
    "***REDACTED***" placeholders and unused mgmt.__data zero-arrays.
    fields=["name", "ip", "os_ver", "platform_str"] covers most inventory
    questions; add "sn" for serial numbers, which is also what `device`
    filters on elsewhere in this server.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        fields: Specific fields to return. Recommended:
            ["name", "ip", "os_ver", "platform_str"]. Omitting this returns
            every field, which is rarely what you want.

    Returns:
        dict: Device list with keys:
            - status: "success" or "error"
            - count: Number of devices
            - devices: List of device objects with name, ip, os_ver, etc.
            - message: Error message if failed

    Example:
        >>> result = await list_devices("root")
        >>> for device in result["devices"]:
        ...     print(f"{device['name']}: {device.get('ip', 'N/A')}")
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        client = _get_client()
        devices = await client.list_devices(adom, fields=fields)
        return {
            "status": "success",
            "count": len(devices),
            # DVMDB device objects carry credential material (adm_pass, etc.);
            # mask it before returning over MCP.
            "devices": sanitize_for_logging(devices),
        }
    except Exception as e:
        logger.error(f"Failed to list devices in ADOM {adom}: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=READ_ONLY)
async def get_device(
    name: str,
    adom: str | None = None,
    include_details: bool = False,
) -> dict[str, Any]:
    """Get detailed information about a specific device.

    Args:
        name: Device name
        adom: ADOM name (default: from config DEFAULT_ADOM)
        include_details: Include sub-objects like VDOMs (default: False)

    Returns:
        dict: Device details with keys:
            - status: "success" or "error"
            - device: Device object with full configuration
            - message: Error message if failed

    Example:
        >>> result = await get_device("FGT-HQ", "root")
        >>> print(f"Version: {result['device']['os_ver']}")
        >>> print(f"Platform: {result['device']['platform_str']}")
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        name = validate_device_name(name)
        client = _get_client()
        loadsub = 1 if include_details else 0
        device = await client.get_device(name, adom, loadsub=loadsub)
        return {
            "status": "success",
            # DVMDB device objects carry credential material (adm_pass, etc.);
            # mask it before returning over MCP.
            "device": sanitize_for_logging(device),
        }
    except Exception as e:
        logger.error(f"Failed to get device {name}: {e}")
        return {"status": "error", "message": redact(str(e))}


# =============================================================================
# Task Management
# =============================================================================


@mcp.tool(annotations=READ_ONLY)
async def list_tasks(
    filter_state: str | None = None,
    filters: list[FilterCondition] | None = None,
) -> dict[str, Any]:
    """List all tasks in FortiAnalyzer.

    Tasks represent background operations like report generation,
    log queries, device synchronization, and other long-running processes.

    Args:
        filter_state: Filter by task state (optional). Valid names, mapped to
            the numeric codes the appliance stores: pending, running,
            cancelling, cancelled, done, error, aborting, aborted, warning,
            to_continue, unknown.
        filters: Structured conditions, each {field, op, value}, ANDed with
            filter_state. Fields: id, title, src, user, adom, state, percent,
            num_done, num_err, num_lines, num_warn, start_tm, end_tm.
            Ops: eq, ne, gt, gte, lt, lte, contains, not_in. Not supported
            here (hard error): "in" (issue one call per value) and
            "not_contains" (no spelling works against this endpoint; use "ne"
            with exact values or exclude matches yourself).
            Example: [{"field": "state", "op": "eq", "value": "running"}]

    Returns:
        dict: Task list with keys:
            - status: "success" or "error"
            - count: Number of tasks
            - tasks: List of task objects with id, state, progress, etc.
            - filter_applied: The compiled filter entries sent to the
              appliance, or None when nothing narrowed the listing
            - message: Error message if failed

    Example:
        >>> # Get all tasks
        >>> result = await list_tasks()
        >>> for task in result["tasks"]:
        ...     print(f"Task {task['id']}: {task.get('state', 'unknown')}")

        >>> # Get only running tasks
        >>> result = await list_tasks(filter_state="running")
    """
    try:
        client = _get_client()

        # Build filter if state specified. FAZ stores state as a numeric code,
        # so translate the documented state names before filtering; a name the
        # enum doesn't know is rejected instead of silently matching nothing.
        entries: list[list[Any]] = []
        if filter_state:
            state_code = TASK_STATE_CODES.get(filter_state.strip().lower())
            if state_code is None:
                valid = ", ".join(sorted(TASK_STATE_CODES))
                return error_response(
                    error="validation_error",
                    message=f"Invalid filter_state '{filter_state}'. Must be one of: {valid}",
                    operation="list_tasks",
                )
            entries.append(["state", "==", state_code])
        if filters:
            structured, _ = compile_to_array(filters, "task")
            entries.extend(structured)
        filter_list = entries or None

        tasks = await client.list_tasks(filter=filter_list)
        return {
            "status": "success",
            "count": len(tasks),
            "tasks": tasks,
            # Echo what was actually sent so a caller can verify the compiled
            # filter instead of inferring it from which rows came back.
            "filter_applied": filter_list,
        }
    except ValidationError as e:
        return error_response(error="validation_error", message=e, operation="list_tasks")
    except Exception as e:
        logger.error(f"Failed to list tasks: {e}")
        return error_response(error="faz_operation_failed", message=e, operation="list_tasks")


@mcp.tool(annotations=READ_ONLY)
async def get_task(
    task_id: int,
    include_details: bool = False,
) -> dict[str, Any]:
    """Get detailed status of a specific task.

    Args:
        task_id: Task ID number
        include_details: Include task line details (default: False)

    Returns:
        dict: Task details with keys:
            - status: "success" or "error"
            - task: Task object with id, state, progress, result, etc.
            - lines: Task line details (if include_details=True)
            - message: Error message if failed

    Example:
        >>> result = await get_task(12345)
        >>> print(f"State: {result['task']['state']}")
        >>> print(f"Progress: {result['task'].get('percent', 0)}%")
    """
    try:
        client = _get_client()
        task = await client.get_task(task_id)

        result: dict[str, Any] = {
            "status": "success",
            "task": task,
        }

        if include_details:
            lines = await client.get_task_line(task_id)
            result["lines"] = lines

        return result
    except Exception as e:
        logger.error(f"Failed to get task {task_id}: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=READ_ONLY)
async def wait_for_task(
    task_id: int,
    timeout: int = 300,
    poll_interval: int = 5,
) -> dict[str, Any]:
    """Wait for a task to complete.

    Polls the task status until it completes or times out.

    Args:
        task_id: Task ID number
        timeout: Maximum wait time in seconds (default: 300)
        poll_interval: Seconds between status checks (default: 5)

    Returns:
        dict: Final task status with keys:
            - status: "success" or "error"
            - task: Final task object
            - completed: Whether task completed (vs timeout)
            - message: Error message if failed

    Example:
        >>> # Wait for report generation
        >>> result = await wait_for_task(12345, timeout=600)
        >>> if result['completed']:
        ...     print("Task finished!")
    """
    import asyncio

    try:
        # Clamp caller-supplied values: a zero/negative poll_interval would turn
        # the loop below into a tight spin against the shared FAZ client, and an
        # oversized timeout would pin it for hours.
        poll_interval = max(1, poll_interval)
        timeout = max(1, min(timeout, 3600))
        client = _get_client()
        start_time = asyncio.get_running_loop().time()

        while True:
            elapsed = asyncio.get_running_loop().time() - start_time
            if elapsed > timeout:
                return {
                    "status": "error",
                    "completed": False,
                    "message": f"Task {task_id} timed out after {timeout} seconds",
                }

            task = await client.get_task(task_id)
            state = _normalize_task_state(task.get("state"))

            # Check if completed ("warning" = finished with warnings)
            if state in _TASK_TERMINAL_STATES:
                return {
                    "status": "success" if state in ("done", "warning") else "error",
                    "task": task,
                    "completed": True,
                    "message": f"Task completed with state: {state}",
                }

            # Wait before next poll
            await asyncio.sleep(poll_interval)

    except Exception as e:
        logger.error(f"Failed to wait for task {task_id}: {e}")
        return {"status": "error", "completed": False, "message": redact(str(e))}


# =============================================================================
# API Rate Limiting (FAZ 7.6.5+)
# =============================================================================


@mcp.tool(annotations=READ_ONLY)
async def get_api_ratelimit() -> dict[str, Any]:
    """Get the current API rate limiting configuration.

    Returns the configured rate limits for API read and write operations.
    This feature is available in FortiAnalyzer 7.6.5 and later.

    Rate limiting helps protect the FortiAnalyzer from API abuse by limiting
    the number of requests that can be made per second.

    Returns:
        dict: Rate limit configuration with keys:
            - status: "success" or "error"
            - data: Rate limit settings containing:
                - read-limit: Max read requests per second (default: 1000)
                - write-limit: Max write requests per second (default: 100)
            - message: Error message if failed

    Example:
        >>> result = await get_api_ratelimit()
        >>> print(f"Read limit: {result['data']['read-limit']} req/s")
        >>> print(f"Write limit: {result['data']['write-limit']} req/s")
    """
    try:
        client = _get_client()
        data = await client.get("/cli/global/system/log/api-ratelimit")
        return {
            "status": "success",
            "data": data,
        }
    except Exception as e:
        logger.error(f"Failed to get API rate limit: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=DESTRUCTIVE)
async def update_api_ratelimit(
    read_limit: int | None = None,
    write_limit: int | None = None,
) -> dict[str, Any]:
    """Update the API rate limiting configuration.

    Configures rate limits for API read and write operations.
    This feature is available in FortiAnalyzer 7.6.5 and later.

    Args:
        read_limit: Max read requests per second (1-10000, default: 1000)
        write_limit: Max write requests per second (1-10000, default: 100)

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Success or error message
            - data: Updated configuration

    Example:
        >>> # Set stricter rate limits
        >>> result = await update_api_ratelimit(read_limit=500, write_limit=50)
        >>> if result['status'] == 'success':
        ...     print("Rate limits updated successfully")

        >>> # Only update read limit
        >>> result = await update_api_ratelimit(read_limit=2000)
    """
    try:
        if read_limit is None and write_limit is None:
            return {
                "status": "error",
                "message": "At least one of read_limit or write_limit must be provided",
            }

        # Build update data
        data: dict[str, Any] = {}
        if read_limit is not None:
            if not 1 <= read_limit <= 10000:
                return {
                    "status": "error",
                    "message": "read_limit must be between 1 and 10000",
                }
            data["read-limit"] = read_limit
        if write_limit is not None:
            if not 1 <= write_limit <= 10000:
                return {
                    "status": "error",
                    "message": "write_limit must be between 1 and 10000",
                }
            data["write-limit"] = write_limit

        client = _get_client()
        result = await client.update("/cli/global/system/log/api-ratelimit", data=data)

        return {
            "status": "success",
            "message": "API rate limits updated successfully",
            "data": result if result else data,
        }
    except Exception as e:
        logger.error(f"Failed to update API rate limit: {e}")
        return {"status": "error", "message": redact(str(e))}
