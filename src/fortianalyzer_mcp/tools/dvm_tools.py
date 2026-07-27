"""Device Manager (DVM) tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 DVM and DVMDB API specifications.
Provides device management operations including add/delete devices
and device group management.
"""

import logging
from typing import Any

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.query.fields import coerce_value, get_vocabulary
from fortianalyzer_mcp.query.filters import FilterCondition, compile_to_array
from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.tool_annotations import CREATES, DESTRUCTIVE, READ_ONLY
from fortianalyzer_mcp.utils.responses import error_response, redact
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    get_default_adom,
    sanitize_for_logging,
    validate_adom,
    validate_device_name,
)

logger = logging.getLogger(__name__)


def _get_client() -> FortiAnalyzerClient:
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


# =============================================================================
# Device Query Operations (DVMDB)
# =============================================================================


@mcp.tool(annotations=READ_ONLY)
async def list_device_groups(
    adom: str | None = None,
) -> dict[str, Any]:
    """List all device groups in an ADOM.

    Device groups allow organizing devices for policy and log management.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)

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
        adom = validate_adom(adom or get_default_adom())
        client = _get_client()
        groups = await client.list_device_groups(adom)

        return {
            "status": "success",
            "count": len(groups),
            "groups": groups,
        }
    except Exception as e:
        logger.error(f"Failed to list device groups: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=READ_ONLY)
async def list_device_vdoms(
    device: str,
    adom: str | None = None,
) -> dict[str, Any]:
    """List VDOMs for a specific device.

    Virtual Domains (VDOMs) are independent virtual instances
    within a FortiGate device.

    Args:
        device: Device name
        adom: ADOM name (default: from config DEFAULT_ADOM)

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
        adom = validate_adom(adom or get_default_adom())
        device = validate_device_name(device)
        client = _get_client()
        vdoms = await client.list_device_vdoms(device, adom)

        return {
            "status": "success",
            "count": len(vdoms),
            "vdoms": vdoms,
        }
    except Exception as e:
        logger.error(f"Failed to list VDOMs for device {device}: {e}")
        return {"status": "error", "message": redact(str(e))}


# =============================================================================
# Device Management Operations (DVM)
# =============================================================================


@mcp.tool(annotations=CREATES)
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
        adom = validate_adom(adom)
        name = validate_device_name(name)
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

        # Sanitize device config to avoid leaking credentials
        sensitive_keys = {"adm_pass", "adm_passwd"}
        device_result = result.get("device", device_config)
        if isinstance(device_result, dict):
            device_result = {k: v for k, v in device_result.items() if k not in sensitive_keys}

        return {
            "status": "success",
            "device": device_result,
            "task_id": result.get("taskid"),
        }
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to add device {name}: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=DESTRUCTIVE)
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
        adom = validate_adom(adom)
        device = validate_device_name(device)
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
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to delete device {device}: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=CREATES)
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

        adom = validate_adom(adom)
        client = _get_client()

        result = await client.add_device_list(
            adom=adom,
            devices=devices,
            flags=flags,
        )

        # Sanitize device configs to avoid leaking credentials
        sensitive_keys = {"adm_pass", "adm_passwd"}
        devices_safe = [{k: v for k, v in d.items() if k not in sensitive_keys} for d in devices]

        task_id = result.get("taskid") if isinstance(result, dict) else None
        response: dict[str, Any] = {
            "status": "success",
            # Count of devices submitted; with a task_id the adds complete
            # asynchronously and per-device results live on the task.
            "added_count": len(devices),
            "devices": devices_safe,
            "task_id": task_id,
        }
        if task_id:
            response["warning"] = (
                "Bulk add runs as a background task; per-device results are on "
                f"the task. Verify with wait_for_task({task_id})."
            )
        return response
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to add devices in bulk: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=DESTRUCTIVE)
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

        adom = validate_adom(adom)
        client = _get_client()

        # Convert device names to the expected format
        device_list = [{"name": validate_device_name(name)} for name in devices]

        result = await client.delete_device_list(
            adom=adom,
            devices=device_list,
            flags=flags,
        )

        task_id = result.get("taskid") if isinstance(result, dict) else None
        response = {
            "status": "success",
            # Count of devices submitted; with a task_id the deletes complete
            # asynchronously and per-device results live on the task.
            "deleted_count": len(devices),
            "task_id": task_id,
        }
        if task_id:
            response["warning"] = (
                "Bulk delete runs as a background task; per-device results are "
                f"on the task. Verify with wait_for_task({task_id})."
            )
        return response
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to delete devices in bulk: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=READ_ONLY)
async def get_device_info(
    device: str,
    adom: str | None = None,
    include_vdoms: bool = False,
) -> dict[str, Any]:
    """Get detailed information about a specific device.

    Retrieves full device configuration and status.

    Args:
        device: Device name
        adom: ADOM name (default: from config DEFAULT_ADOM)
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
        adom = validate_adom(adom or get_default_adom())
        device = validate_device_name(device)
        client = _get_client()
        device_data = await client.get_device(device, adom, loadsub=1)

        result: dict[str, Any] = {
            "status": "success",
            # DVMDB device objects carry credential material (adm_pass, etc.);
            # mask it before returning over MCP.
            "device": sanitize_for_logging(device_data),
        }

        if include_vdoms:
            vdoms = await client.list_device_vdoms(device, adom)
            result["vdoms"] = vdoms

        return result
    except Exception as e:
        logger.error(f"Failed to get device info for {device}: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool(annotations=READ_ONLY)
async def search_devices(
    adom: str | None = None,
    name_filter: str | None = None,
    platform_filter: str | None = None,
    os_version_filter: str | None = None,
    connection_status: str | None = None,
    filters: list[FilterCondition] | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Search for devices with filters.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        name_filter: Filter by device name (partial match)
        platform_filter: Filter by platform type
        os_version_filter: Filter by OS version
        connection_status: Filter by connection status ("up", "down").
            Caution: FortiAnalyzer commonly stores conn_status 0 ("unknown")
            for log-only devices, so filtering "up"/"down" can match nothing
            even when every device is healthy and logging. Check the raw
            conn_status values in an unfiltered call before relying on this.
        filters: Structured conditions, each {field, op, value}, ANDed with the
            narrow parameters above. Fields: name, ip, sn, hostname, desc,
            os_ver, mr, patch, platform_str, conn_status, dev_status,
            mgmt_mode, adm_usr, vdom, hdisk_size, build.
            Ops: eq, ne, gt, gte, lt, lte, contains, not_in. Not supported
            here (hard error): "in" (issue one call per value) and
            "not_contains" (no spelling works against this endpoint; use "ne"
            with exact values or exclude matches yourself).
            Aliases accepted for field names: device_name (name),
            serial/serial_number (sn), os_version (os_ver),
            platform (platform_str), connection_status (conn_status),
            description (desc).
            Example: [{"field": "os_ver", "op": "contains", "value": "7.6"}]
        fields: Specific fields to return per device, e.g.
            ["name", "ip", "os_ver", "platform_str"]. Omitting this returns
            every field the appliance defines -- roughly 60 per device, most
            empty placeholders -- so pass a projection unless you genuinely
            need the full object.

    Returns:
        dict: Search results with keys:
            - status: "success" or "error"
            - count: Number of matching devices
            - devices: List of matching device objects. The appliance always
              includes ``oid`` in each object, even under a ``fields``
              projection that does not request it.
            - filter_applied: The compiled filter entries sent to the
              appliance, or None when nothing narrowed the search
            - message: Error message if failed

    Example:
        >>> # Find all FortiGate VMs
        >>> result = await search_devices(platform_filter="FortiGate-VM")

        >>> # Find offline devices
        >>> result = await search_devices(connection_status="down")
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        client = _get_client()

        # Build filter list. Substring matching is ``like`` with % wildcards:
        # the documented ``contain`` spelling is accepted by live dvmdb and
        # silently matches zero rows, which made every one of these narrow
        # parameters return an empty result against a populated fleet.
        entries: list[list[Any]] = []
        if name_filter:
            entries.append(["name", "like", f"%{name_filter}%"])
        if platform_filter:
            entries.append(["platform_str", "like", f"%{platform_filter}%"])
        if os_version_filter:
            entries.append(["os_ver", "like", f"%{os_version_filter}%"])
        if connection_status:
            # Coercion lives in the query vocabulary now, so "down" means 2
            # here and everywhere else that filters on conn_status. The
            # rejection is re-phrased in terms of this parameter's own name:
            # a caller who passed connection_status= should not be told about
            # a field called conn_status they never mentioned.
            try:
                status_val = coerce_value("device", "conn_status", connection_status)
            except ValidationError:
                valid = ", ".join(sorted(get_vocabulary("device").coercions["conn_status"]))
                return error_response(
                    error="validation_error",
                    message=(
                        f"Invalid connection_status '{connection_status}'. Must be one of: {valid}"
                    ),
                    operation="search_devices",
                    adom=adom,
                )
            entries.append(["conn_status", "==", status_val])
        if filters:
            structured, _ = compile_to_array(filters, "device")
            entries.extend(structured)

        devices = await client.list_devices(
            adom=adom,
            filter=entries if entries else None,
            fields=fields,
        )

        return {
            "status": "success",
            "count": len(devices),
            # DVMDB device objects carry credential material (adm_pass, etc.);
            # mask it before returning over MCP.
            "devices": sanitize_for_logging(devices),
            # Echo what was actually sent so a caller can verify the compiled
            # filter instead of inferring it from which rows came back.
            "filter_applied": entries if entries else None,
        }
    except ValidationError as e:
        return error_response(
            error="validation_error", message=e, operation="search_devices", adom=adom
        )
    except Exception as e:
        logger.error(f"Failed to search devices: {e}")
        return error_response(
            error="faz_operation_failed", message=e, operation="search_devices", adom=adom
        )
