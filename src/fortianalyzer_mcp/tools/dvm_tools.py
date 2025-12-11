"""Device Manager (DVM) tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 DVM and DVMDB API specifications.
Provides device management operations including add/delete devices
and device group management.
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
# Device Query Operations (DVMDB)
# =============================================================================


@mcp.tool()
async def list_device_groups(
    adom: str = "root",
) -> dict[str, Any]:
    """List all device groups in an ADOM.

    Device groups allow organizing devices for policy and log management.

    Args:
        adom: ADOM name (default: "root")

    Returns:
        dict: Device groups with keys:
            - status: "success" or "error"
            - count: Number of groups
            - groups: List of device group objects
            - message: Error message if failed

    Example:
        >>> result = await list_device_groups("root")
        >>> for group in result['groups']:
        ...     print(f"Group: {group['name']}")
    """
    try:
        client = _get_client()
        groups = await client.list_device_groups(adom)

        return {
            "status": "success",
            "count": len(groups),
            "groups": groups,
        }
    except Exception as e:
        logger.error(f"Failed to list device groups: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def list_device_vdoms(
    device: str,
    adom: str = "root",
) -> dict[str, Any]:
    """List VDOMs for a specific device.

    Virtual Domains (VDOMs) are independent virtual instances
    within a FortiGate device.

    Args:
        device: Device name
        adom: ADOM name (default: "root")

    Returns:
        dict: VDOM list with keys:
            - status: "success" or "error"
            - count: Number of VDOMs
            - vdoms: List of VDOM objects
            - message: Error message if failed

    Example:
        >>> result = await list_device_vdoms("FGT-HQ", "root")
        >>> for vdom in result['vdoms']:
        ...     print(f"VDOM: {vdom['name']}")
    """
    try:
        client = _get_client()
        vdoms = await client.list_device_vdoms(device, adom)

        return {
            "status": "success",
            "count": len(vdoms),
            "vdoms": vdoms,
        }
    except Exception as e:
        logger.error(f"Failed to list VDOMs for device {device}: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Device Management Operations (DVM)
# =============================================================================


@mcp.tool()
async def add_device(
    adom: str,
    name: str,
    ip: str | None = None,
    serial_number: str | None = None,
    admin_user: str | None = None,
    admin_pass: str | None = None,
    description: str | None = None,
    platform: str = "FortiGate-VM64",
    os_version: str | None = None,
    mgmt_mode: str = "faz",
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Add a new device to FortiAnalyzer.

    Registers a device with FortiAnalyzer for log collection.
    Can add either a real device (with IP) or a model device (with SN).

    Args:
        adom: ADOM name where device will be added
        name: Device display name
        ip: Device IP address (for real device connection)
        serial_number: Device serial number (for model device or validation)
        admin_user: Admin username for device connection
        admin_pass: Admin password for device connection
        description: Device description
        platform: Platform type (default: "FortiGate-VM64")
        os_version: FortiOS version string
        mgmt_mode: Management mode - "faz" (FortiAnalyzer only),
                   "fmg" (FortiManager), or "fmgfaz" (both)
        flags: Additional flags like "create_task" to run as background task

    Returns:
        dict: Add result with keys:
            - status: "success" or "error"
            - device: Added device information
            - task_id: Task ID if run as background task
            - message: Error message if failed

    Example:
        >>> # Add a FortiGate with IP
        >>> result = await add_device(
        ...     adom="root",
        ...     name="FGT-Branch1",
        ...     ip="192.168.1.1",
        ...     admin_user="admin",
        ...     admin_pass="password123"
        ... )

        >>> # Add a model device
        >>> result = await add_device(
        ...     adom="root",
        ...     name="FGT-Lab",
        ...     serial_number="FGVM020000123456"
        ... )
    """
    try:
        client = _get_client()

        # Build device configuration
        device_config: dict[str, Any] = {
            "name": name,
            "mgmt_mode": mgmt_mode,
        }

        # Real device with IP
        if ip:
            device_config["ip"] = ip
            if admin_user:
                device_config["adm_usr"] = admin_user
            if admin_pass:
                device_config["adm_pass"] = admin_pass

        # Model device with serial number
        if serial_number:
            device_config["sn"] = serial_number

        # Optional fields
        if description:
            device_config["desc"] = description
        if platform:
            device_config["platform_str"] = platform
        if os_version:
            device_config["os_ver"] = os_version

        result = await client.add_device(
            adom=adom,
            device=device_config,
            flags=flags,
        )

        return {
            "status": "success",
            "device": result.get("device", device_config),
            "task_id": result.get("taskid"),
        }
    except Exception as e:
        logger.error(f"Failed to add device {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def delete_device(
    adom: str,
    device: str,
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Delete a device from FortiAnalyzer.

    Removes a device registration. Does not affect the actual device.

    WARNING: This operation cannot be undone. Historical logs for
    this device may still be retained based on log retention policy.

    Args:
        adom: ADOM name where device is located
        device: Device name to delete
        flags: Additional flags like "create_task" to run as background task

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - task_id: Task ID if run as background task
            - message: Status or error message

    Example:
        >>> result = await delete_device("root", "FGT-OldBranch")
        >>> if result['status'] == 'success':
        ...     print("Device removed from FortiAnalyzer")
    """
    try:
        client = _get_client()

        result = await client.delete_device(
            adom=adom,
            device=device,
            flags=flags,
        )

        return {
            "status": "success",
            "task_id": result.get("taskid"),
            "message": f"Device {device} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete device {device}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def add_devices_bulk(
    adom: str,
    devices: list[dict[str, Any]],
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Add multiple devices to FortiAnalyzer in bulk.

    Registers multiple devices at once for efficiency.

    Args:
        adom: ADOM name where devices will be added
        devices: List of device configurations. Each device dict can contain:
            - name: Device display name (required)
            - ip: Device IP address
            - sn: Serial number
            - adm_usr: Admin username
            - adm_pass: Admin password
            - desc: Description
            - platform_str: Platform type
            - os_ver: OS version
        flags: Additional flags like "create_task"

    Returns:
        dict: Bulk add result with keys:
            - status: "success" or "error"
            - added_count: Number of devices added
            - task_id: Task ID if run as background task
            - message: Error message if failed

    Example:
        >>> devices = [
        ...     {"name": "FGT-Site1", "ip": "10.0.1.1", "adm_usr": "admin", "adm_pass": "pass1"},
        ...     {"name": "FGT-Site2", "ip": "10.0.2.1", "adm_usr": "admin", "adm_pass": "pass2"},
        ... ]
        >>> result = await add_devices_bulk("root", devices)
    """
    try:
        if not devices:
            return {"status": "error", "message": "No devices provided"}

        client = _get_client()

        result = await client.add_device_list(
            adom=adom,
            devices=devices,
            flags=flags,
        )

        return {
            "status": "success",
            "added_count": len(devices),
            "task_id": result.get("taskid"),
        }
    except Exception as e:
        logger.error(f"Failed to add devices in bulk: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def delete_devices_bulk(
    adom: str,
    devices: list[str],
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Delete multiple devices from FortiAnalyzer in bulk.

    Removes multiple device registrations at once.

    WARNING: This operation cannot be undone.

    Args:
        adom: ADOM name where devices are located
        devices: List of device names to delete
        flags: Additional flags like "create_task"

    Returns:
        dict: Bulk delete result with keys:
            - status: "success" or "error"
            - deleted_count: Number of devices deleted
            - task_id: Task ID if run as background task
            - message: Error message if failed

    Example:
        >>> result = await delete_devices_bulk("root", ["FGT-Old1", "FGT-Old2"])
    """
    try:
        if not devices:
            return {"status": "error", "message": "No devices provided"}

        client = _get_client()

        # Convert device names to the expected format
        device_list = [{"name": name} for name in devices]

        result = await client.delete_device_list(
            adom=adom,
            devices=device_list,
            flags=flags,
        )

        return {
            "status": "success",
            "deleted_count": len(devices),
            "task_id": result.get("taskid"),
        }
    except Exception as e:
        logger.error(f"Failed to delete devices in bulk: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_device_info(
    device: str,
    adom: str = "root",
    include_vdoms: bool = False,
) -> dict[str, Any]:
    """Get detailed information about a specific device.

    Retrieves full device configuration and status.

    Args:
        device: Device name
        adom: ADOM name (default: "root")
        include_vdoms: Include VDOM information (default: False)

    Returns:
        dict: Device details with keys:
            - status: "success" or "error"
            - device: Full device configuration object
            - vdoms: VDOM list (if include_vdoms=True)
            - message: Error message if failed

    Example:
        >>> result = await get_device_info("FGT-HQ", include_vdoms=True)
        >>> print(f"Version: {result['device']['os_ver']}")
        >>> print(f"Platform: {result['device']['platform_str']}")
    """
    try:
        client = _get_client()
        device_data = await client.get_device(device, adom, loadsub=1)

        result: dict[str, Any] = {
            "status": "success",
            "device": device_data,
        }

        if include_vdoms:
            vdoms = await client.list_device_vdoms(device, adom)
            result["vdoms"] = vdoms

        return result
    except Exception as e:
        logger.error(f"Failed to get device info for {device}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def search_devices(
    adom: str = "root",
    name_filter: str | None = None,
    platform_filter: str | None = None,
    os_version_filter: str | None = None,
    connection_status: str | None = None,
) -> dict[str, Any]:
    """Search for devices with filters.

    Args:
        adom: ADOM name (default: "root")
        name_filter: Filter by device name (partial match)
        platform_filter: Filter by platform type
        os_version_filter: Filter by OS version
        connection_status: Filter by connection status ("up", "down")

    Returns:
        dict: Search results with keys:
            - status: "success" or "error"
            - count: Number of matching devices
            - devices: List of matching device objects
            - message: Error message if failed

    Example:
        >>> # Find all FortiGate VMs
        >>> result = await search_devices(platform_filter="FortiGate-VM")

        >>> # Find offline devices
        >>> result = await search_devices(connection_status="down")
    """
    try:
        client = _get_client()

        # Build filter list
        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])
        if platform_filter:
            filters.append(["platform_str", "contain", platform_filter])
        if os_version_filter:
            filters.append(["os_ver", "contain", os_version_filter])
        if connection_status:
            # Connection status is typically 1 (up) or 0 (down)
            status_val = 1 if connection_status.lower() == "up" else 0
            filters.append(["conn_status", "==", status_val])

        devices = await client.list_devices(
            adom=adom,
            filter=filters if filters else None,
        )

        return {
            "status": "success",
            "count": len(devices),
            "devices": devices,
        }
    except Exception as e:
        logger.error(f"Failed to search devices: {e}")
        return {"status": "error", "message": str(e)}
