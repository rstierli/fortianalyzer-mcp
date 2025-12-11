"""System and ADOM management tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 SYS, DVMDB, and TASK API specifications.
"""

import logging
from typing import Any

from fortianalyzer_mcp.server import get_faz_client, mcp

logger = logging.getLogger(__name__)


def _get_client():
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


# =============================================================================
# System Status
# =============================================================================


@mcp.tool()
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
        return {"status": "error", "message": str(e)}


@mcp.tool()
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
        return {"status": "error", "message": str(e)}


# =============================================================================
# ADOM Management
# =============================================================================


@mcp.tool()
async def list_adoms(
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """List all Administrative Domains (ADOMs) in FortiAnalyzer.

    ADOMs are used to partition FortiAnalyzer into separate management
    domains, each with its own devices, logs, and configurations.

    Args:
        fields: Specific fields to return (optional, returns all if not specified)

    Returns:
        dict: ADOM list with keys:
            - status: "success" or "error"
            - count: Number of ADOMs
            - adoms: List of ADOM objects with name, desc, state, etc.
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
        return {"status": "error", "message": str(e)}


@mcp.tool()
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
        client = _get_client()
        loadsub = 1 if include_details else 0
        adom = await client.get_adom(name, loadsub=loadsub)
        return {
            "status": "success",
            "adom": adom,
        }
    except Exception as e:
        logger.error(f"Failed to get ADOM {name}: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Device Listing (from DVMDB)
# =============================================================================


@mcp.tool()
async def list_devices(
    adom: str = "root",
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """List all devices registered in an ADOM.

    FortiAnalyzer collects logs from FortiGate and other Fortinet devices.
    This lists all devices configured to send logs to this ADOM.

    Args:
        adom: ADOM name (default: "root")
        fields: Specific fields to return (optional)

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
        client = _get_client()
        devices = await client.list_devices(adom, fields=fields)
        return {
            "status": "success",
            "count": len(devices),
            "devices": devices,
        }
    except Exception as e:
        logger.error(f"Failed to list devices in ADOM {adom}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_device(
    name: str,
    adom: str = "root",
    include_details: bool = False,
) -> dict[str, Any]:
    """Get detailed information about a specific device.

    Args:
        name: Device name
        adom: ADOM name (default: "root")
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
        client = _get_client()
        loadsub = 1 if include_details else 0
        device = await client.get_device(name, adom, loadsub=loadsub)
        return {
            "status": "success",
            "device": device,
        }
    except Exception as e:
        logger.error(f"Failed to get device {name}: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Task Management
# =============================================================================


@mcp.tool()
async def list_tasks(
    filter_state: str | None = None,
) -> dict[str, Any]:
    """List all tasks in FortiAnalyzer.

    Tasks represent background operations like report generation,
    log queries, device synchronization, and other long-running processes.

    Args:
        filter_state: Filter by task state (optional):
            - "pending": Not started
            - "running": Currently executing
            - "done": Completed
            - "error": Failed
            - "cancelling": Being cancelled
            - "cancelled": Cancelled

    Returns:
        dict: Task list with keys:
            - status: "success" or "error"
            - count: Number of tasks
            - tasks: List of task objects with id, state, progress, etc.
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

        # Build filter if state specified
        filter_list = None
        if filter_state:
            filter_list = [["state", "==", filter_state]]

        tasks = await client.list_tasks(filter=filter_list)
        return {
            "status": "success",
            "count": len(tasks),
            "tasks": tasks,
        }
    except Exception as e:
        logger.error(f"Failed to list tasks: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
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
        return {"status": "error", "message": str(e)}


@mcp.tool()
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
        client = _get_client()
        start_time = asyncio.get_event_loop().time()

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                return {
                    "status": "error",
                    "completed": False,
                    "message": f"Task {task_id} timed out after {timeout} seconds",
                }

            task = await client.get_task(task_id)
            state = task.get("state", "").lower()

            # Check if completed
            if state in ("done", "error", "cancelled"):
                return {
                    "status": "success" if state == "done" else "error",
                    "task": task,
                    "completed": True,
                    "message": f"Task completed with state: {state}",
                }

            # Wait before next poll
            await asyncio.sleep(poll_interval)

    except Exception as e:
        logger.error(f"Failed to wait for task {task_id}: {e}")
        return {"status": "error", "completed": False, "message": str(e)}
