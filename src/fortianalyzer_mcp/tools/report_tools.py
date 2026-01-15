"""Report management tools for FortiAnalyzer.

Based on FNDN FortiAnalyzer 7.6.4 Report API specifications.
Provides report generation, template management, and report retrieval using TID-based workflow.
"""

import asyncio
import base64
import io
import logging
import os
import zipfile
from datetime import datetime, timedelta
from typing import Any

from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    validate_adom,
    validate_output_path,
)

logger = logging.getLogger(__name__)


def _get_client():
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


def _parse_time_range(time_range: str) -> dict[str, str]:
    """Parse time range string to start/end format for log searches.

    This is used for log-based APIs that require start/end timestamps.
    """
    now = datetime.now()
    fmt = "%Y-%m-%d %H:%M:%S"

    if "|" in time_range:
        parts = time_range.split("|")
        return {"start": parts[0].strip(), "end": parts[1].strip()}

    range_map = {
        "1-hour": timedelta(hours=1),
        "6-hour": timedelta(hours=6),
        "12-hour": timedelta(hours=12),
        "24-hour": timedelta(hours=24),
        "1-day": timedelta(days=1),
        "7-day": timedelta(days=7),
        "30-day": timedelta(days=30),
        "90-day": timedelta(days=90),
    }

    delta = range_map.get(time_range, timedelta(days=7))
    start = now - delta

    return {"start": start.strftime(fmt), "end": now.strftime(fmt)}


def _convert_to_api_time_period(time_range: str) -> str:
    """Convert user-friendly time range to FortiAnalyzer API time-period format.

    FortiAnalyzer report API expects time-period in format like:
    - "last-n-hours" (e.g., "last-1-hours", "last-6-hours")
    - "last-n-days" (e.g., "last-7-days", "last-30-days")
    - "last-n-weeks" (e.g., "last-4-weeks")
    - "last-n-months" (e.g., "last-1-months")
    - "other" for custom date range

    Args:
        time_range: User input like "1-hour", "7-day", "30-day", or custom "YYYY-MM-DD|YYYY-MM-DD"

    Returns:
        API-compatible time-period string
    """
    # If already in API format, return as-is
    if time_range.startswith("last-") and (
        time_range.endswith("-hours")
        or time_range.endswith("-days")
        or time_range.endswith("-weeks")
        or time_range.endswith("-months")
    ):
        return time_range

    # If custom date range, return "other"
    if "|" in time_range:
        return "other"

    # Map common formats to API format
    time_map = {
        "1-hour": "last-1-hours",
        "6-hour": "last-6-hours",
        "12-hour": "last-12-hours",
        "24-hour": "last-24-hours",
        "1-day": "last-1-days",
        "7-day": "last-7-days",
        "30-day": "last-30-days",
        "90-day": "last-90-days",
    }

    return time_map.get(time_range, "last-7-days")


async def _get_layout_id_by_title(client: Any, adom: str, title: str) -> int | None:
    """Look up layout-id by report title.

    Searches LAYOUTS (not templates). Only layouts can be run.

    Args:
        client: FortiAnalyzer client
        adom: ADOM name
        title: Report layout title to search for

    Returns:
        layout-id if found, None otherwise
    """
    try:
        result = await client.get_report_layouts(adom=adom)
        layouts = result.get("data", []) if isinstance(result, dict) else result
        if not isinstance(layouts, list):
            layouts = [layouts] if layouts else []

        # Filter out templates - only search actual layouts
        layouts = [layout for layout in layouts if layout.get("is-template") != 1]

        # Search for matching title (case-insensitive)
        title_lower = title.lower()
        for layout in layouts:
            layout_title = layout.get("title", "")
            if layout_title.lower() == title_lower:
                return layout.get("layout-id")

        # Try partial match if exact match fails
        for layout in layouts:
            layout_title = layout.get("title", "")
            if title_lower in layout_title.lower():
                return layout.get("layout-id")

        return None
    except Exception as e:
        logger.warning(f"Failed to lookup layout by title: {e}")
        return None


async def _ensure_schedule_exists(client: Any, adom: str, layout_id: int) -> dict[str, Any]:
    """Ensure a schedule exists for the given layout.

    FortiAnalyzer requires a schedule to exist before running a report.
    If no schedule exists, one is created automatically.

    Args:
        client: FortiAnalyzer client
        adom: ADOM name
        layout_id: Layout ID to check/create schedule for

    Returns:
        dict with schedule info or creation result
    """
    try:
        # Check if schedule already exists
        result = await client.get_report_schedules(adom=adom, layout_id=layout_id)
        schedules = result.get("data", []) if isinstance(result, dict) else result
        if not isinstance(schedules, list):
            schedules = [schedules] if schedules else []

        if schedules:
            logger.info(f"Schedule exists for layout-id {layout_id}")
            return {"exists": True, "schedule": schedules[0]}

        # Create schedule if it doesn't exist
        logger.info(f"Creating schedule for layout-id {layout_id}")
        create_result = await client.create_report_schedule(adom=adom, layout_id=layout_id)
        return {"exists": False, "created": True, "result": create_result}

    except Exception as e:
        logger.warning(f"Failed to ensure schedule exists: {e}")
        return {"exists": False, "created": False, "error": str(e)}


@mcp.tool()
async def list_report_layouts(adom: str = "root") -> dict[str, Any]:
    """List available report layouts in FortiAnalyzer.

    IMPORTANT: Layouts are runnable reports. Templates are read-only blueprints.
    When a user asks to "run a report", you need to search layouts, not templates.

    Each layout has a layout-id which is required to run reports.
    A schedule must exist for the layout before it can be run (created automatically).

    Args:
        adom: ADOM name (default: "root")

    Returns:
        dict with report layouts list including:
        - layout-id: Unique ID for running reports
        - title: Human-readable name
        - description: Layout description
        - category: Report category

    Example:
        >>> result = await list_report_layouts("root")
        >>> for layout in result["data"]:
        ...     print(f"[{layout['layout-id']}] {layout['title']}")
    """
    try:
        client = _get_client()

        logger.info(f"Listing report layouts in ADOM {adom}")

        result = await client.get_report_layouts(adom=adom)

        data = result.get("data", []) if isinstance(result, dict) else result
        if not isinstance(data, list):
            data = [data] if data else []

        # Simplify output to most useful fields, filter out templates (is-template=1)
        simplified = []
        for layout in data:
            # Skip templates - only show actual layouts
            if layout.get("is-template") == 1:
                continue
            simplified.append(
                {
                    "layout-id": layout.get("layout-id"),
                    "title": layout.get("title"),
                    "description": layout.get("description", ""),
                    "category": layout.get("category", ""),
                }
            )

        return {
            "status": "success",
            "adom": adom,
            "count": len(simplified),
            "data": simplified,
        }
    except Exception as e:
        logger.error(f"Failed to list report layouts: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def run_report(
    layout: str,
    adom: str = "root",
    device: str | None = None,
    time_range: str = "7-day",
) -> dict[str, Any]:
    """Run a report in FortiAnalyzer.

    IMPORTANT: This runs a LAYOUT, not a template. Templates are read-only blueprints.
    Use list_report_layouts() to see available reports.

    This function:
    1. Looks up the layout-id by title (or uses directly if numeric)
    2. Ensures a schedule exists for the layout (creates one if needed)
    3. Runs the report and returns the TID for tracking

    Reports run asynchronously. Use get_running_reports() to check progress
    and get_report_data() to download the completed report.

    Args:
        layout: Report layout identifier - can be either:
            - Layout ID (number as string, e.g., "10042")
            - Layout title (e.g., "Secure SD-WAN Report", "VPN Report")
            Use list_report_layouts() to see available layouts.
        adom: ADOM name (default: "root")
        device: Device ID filter (optional - run for specific device)
        time_range: Time range. Options:
            - Short format: "1-hour", "6-hour", "12-hour", "24-hour",
              "1-day", "7-day", "30-day", "90-day"
            - API format: "last-7-days", "last-30-days", "last-4-weeks"
            - Custom: "2024-01-01 00:00:00|2024-01-02 00:00:00"

    Returns:
        dict with TID for tracking report progress

    Example:
        >>> # Run by layout title
        >>> result = await run_report(layout="Secure SD-WAN Report", time_range="30-day")
        >>> # Or run by layout ID
        >>> result = await run_report(layout="10042", time_range="last-30-days")
        >>> print(f"TID: {result['tid']}")
    """
    try:
        client = _get_client()

        # Step 1: Determine layout_id
        layout_id: int | None = None
        if layout.isdigit():
            layout_id = int(layout)
            logger.info(f"Using layout-id {layout_id}")
        else:
            # Look up layout-id by title
            layout_id = await _get_layout_id_by_title(client, adom, layout)
            if layout_id is None:
                return {
                    "status": "error",
                    "message": f"Report layout '{layout}' not found. Use list_report_layouts() to see available reports.",
                }
            logger.info(f"Found layout-id {layout_id} for '{layout}'")

        # Step 2: Ensure schedule exists for this layout
        schedule_result = await _ensure_schedule_exists(client, adom, layout_id)
        if schedule_result.get("error"):
            return {
                "status": "error",
                "message": f"Failed to ensure schedule exists: {schedule_result['error']}",
            }

        schedule_created = not schedule_result.get("exists", False)
        if schedule_created:
            logger.info(f"Created new schedule for layout-id {layout_id}")

        # Step 3: Convert time range to API format
        time_period = _convert_to_api_time_period(time_range)

        # Step 4: Build device filter if specified
        device_filter = None
        if device:
            device_filter = [{"devid": device}]

        # Step 5: Run the report
        logger.info(f"Running report with layout-id {layout_id}, time-period: {time_period}")
        result = await client.report_run(
            adom=adom,
            layout_id=layout_id,
            time_period=time_period,
            device=device_filter,
        )

        tid = result.get("tid") if isinstance(result, dict) else None

        if not tid:
            return {
                "status": "error",
                "message": "Failed to get TID from report execution",
                "api_response": result,
            }

        return {
            "status": "success",
            "tid": tid,
            "layout": layout,
            "layout_id": layout_id,
            "adom": adom,
            "time_period": time_period,
            "schedule_created": schedule_created,
            "message": f"Report started. Use get_running_reports() to check progress, then get_report_data(tid='{tid}') to download.",
        }
    except Exception as e:
        logger.error(f"Failed to run report '{layout}': {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def fetch_report(
    tid: str,
    adom: str = "root",
) -> dict[str, Any]:
    """Fetch report status and progress by TID.

    Check the progress of a running report.

    Args:
        tid: Task ID (UUID string) from run_report
        adom: ADOM name (default: "root")

    Returns:
        dict with report status including progress percentage

    Example:
        >>> result = await fetch_report(tid="97c1a1c2-d11a-11f0-9ae2-bc2411fc5515")
        >>> print(f"Progress: {result.get('data', {}).get('percentage', 0)}%")
    """
    try:
        client = _get_client()

        logger.info(f"Fetching report status for TID {tid}")

        result = await client.report_fetch(adom=adom, tid=tid)

        return {
            "status": "success",
            "tid": tid,
            "adom": adom,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to fetch report status: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_report_data(
    tid: str,
    adom: str = "root",
    output_format: str = "PDF",
) -> dict[str, Any]:
    """Download completed report data.

    Retrieves the generated report content after completion.
    The report data is returned as base64-encoded content.

    Args:
        tid: Task ID (UUID string) from run_report
        adom: ADOM name (default: "root")
        output_format: Output format - "PDF", "HTML", "CSV", "XML" (default: "PDF")

    Returns:
        dict with report data including:
        - name: Report filename
        - data: Base64-encoded report content
        - data-type: Content type (e.g., "zip/base64")
        - checksum: MD5 hash for verification

    Example:
        >>> result = await get_report_data(tid="97c1a1c2-d11a-11f0...")
        >>> # Decode and save the report
        >>> import base64
        >>> data = result["data"]["data"]
        >>> with open("report.zip", "wb") as f:
        ...     f.write(base64.b64decode(data))
    """
    try:
        client = _get_client()

        logger.info(f"Downloading report data for TID {tid}")

        result = await client.report_get_data(adom=adom, tid=tid, output_format=output_format)

        return {
            "status": "success",
            "tid": tid,
            "adom": adom,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get report data: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_running_reports(
    adom: str = "root",
) -> dict[str, Any]:
    """Get currently running reports.

    Check the status of reports that are currently being generated.
    Use this after run_report() to monitor progress.

    Args:
        adom: ADOM name (default: "root")

    Returns:
        dict with list of running reports and their progress

    Example:
        >>> result = await get_running_reports()
        >>> for report in result["data"]:
        ...     print(f"TID: {report['tid']} - {report.get('percent', 0)}%")
    """
    try:
        client = _get_client()

        logger.info(f"Getting running reports in ADOM {adom}")

        result = await client.get_running_reports(adom=adom)

        data = result.get("data", []) if isinstance(result, dict) else result
        if not isinstance(data, list):
            data = [data] if data else []

        return {
            "status": "success",
            "adom": adom,
            "count": len(data),
            "data": data,
        }
    except Exception as e:
        logger.error(f"Failed to get running reports: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_report_history(
    adom: str = "root",
    time_range: str = "30-day",
    title: str | None = None,
) -> dict[str, Any]:
    """Get report history - list of generated reports.

    Retrieves list of completed/generated reports.

    Args:
        adom: ADOM name (default: "root")
        time_range: Time range to search (default: "30-day")
        title: Filter by report title (optional)

    Returns:
        dict with report history

    Example:
        >>> result = await get_report_history(time_range="7-day")
        >>> for report in result["data"]:
        ...     print(f"{report['title']}: {report['state']}")
    """
    try:
        client = _get_client()
        tr = _parse_time_range(time_range)

        logger.info(f"Getting report history in ADOM {adom}")

        result = await client.report_get_state(
            adom=adom,
            time_range=tr,
            state="generated",  # Only "generated" is supported by the API
            title=title,
        )

        data = result.get("data", []) if isinstance(result, dict) else result
        if not isinstance(data, list):
            data = [data] if data else []

        return {
            "status": "success",
            "adom": adom,
            "count": len(data),
            "data": data,
        }
    except Exception as e:
        logger.error(f"Failed to get report history: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def run_and_wait_report(
    layout: str,
    adom: str = "root",
    device: str | None = None,
    time_range: str = "7-day",
    timeout: int = 300,
) -> dict[str, Any]:
    """Run a report and wait for completion.

    IMPORTANT: This runs a LAYOUT, not a template. Use list_report_layouts() to see available reports.

    Convenience function that:
    1. Looks up the layout-id by title
    2. Ensures a schedule exists
    3. Runs the report
    4. Polls until completion or timeout

    Args:
        layout: Report layout identifier - can be either:
            - Layout ID (number as string, e.g., "10042")
            - Layout title (e.g., "Secure SD-WAN Report", "VPN Report")
            Use list_report_layouts() to see available layouts.
        adom: ADOM name (default: "root")
        device: Device ID filter (optional - run for specific device)
        time_range: Time range. Options:
            - Short format: "1-hour", "6-hour", "12-hour", "24-hour",
              "1-day", "7-day", "30-day", "90-day"
            - API format: "last-7-days", "last-30-days", "last-4-weeks"
            - Custom: "2024-01-01 00:00:00|2024-01-02 00:00:00"
        timeout: Maximum wait time in seconds (default: 300)

    Returns:
        dict with report result including TID for downloading data

    Example:
        >>> result = await run_and_wait_report(
        ...     layout="Secure SD-WAN Report",
        ...     time_range="30-day",
        ...     timeout=600
        ... )
        >>> if result["status"] == "success":
        ...     print(f"Report completed! TID: {result['tid']}")
        ...     # Use get_report_data(tid=result['tid']) to download
    """
    try:
        client = _get_client()

        # Step 1: Determine layout_id
        layout_id: int | None = None
        if layout.isdigit():
            layout_id = int(layout)
            logger.info(f"Using layout-id {layout_id}")
        else:
            layout_id = await _get_layout_id_by_title(client, adom, layout)
            if layout_id is None:
                return {
                    "status": "error",
                    "message": f"Report layout '{layout}' not found. Use list_report_layouts() to see available reports.",
                }
            logger.info(f"Found layout-id {layout_id} for '{layout}'")

        # Step 2: Ensure schedule exists
        schedule_result = await _ensure_schedule_exists(client, adom, layout_id)
        if schedule_result.get("error"):
            return {
                "status": "error",
                "message": f"Failed to ensure schedule exists: {schedule_result['error']}",
            }

        # Step 3: Convert time range and build device filter
        time_period = _convert_to_api_time_period(time_range)
        device_filter = [{"devid": device}] if device else None

        # Step 4: Start the report
        logger.info(f"Running report with layout-id {layout_id}, time-period: {time_period}")
        run_result = await client.report_run(
            adom=adom,
            layout_id=layout_id,
            time_period=time_period,
            device=device_filter,
        )

        tid = run_result.get("tid") if isinstance(run_result, dict) else None
        if not tid:
            return {
                "status": "error",
                "message": "Failed to get TID from report execution",
                "api_response": run_result,
            }

        # Step 5: Poll for completion using get_running_reports
        start_time = asyncio.get_event_loop().time()
        poll_interval = 3.0

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                return {
                    "status": "timeout",
                    "tid": tid,
                    "layout": layout,
                    "layout_id": layout_id,
                    "message": f"Report timed out after {timeout}s. Use get_report_data(tid='{tid}') to check if it completed.",
                }

            # Check running reports to see if our TID is still in progress
            running_result = await client.get_running_reports(adom=adom)
            running_data = (
                running_result.get("data", []) if isinstance(running_result, dict) else []
            )
            if not isinstance(running_data, list):
                running_data = [running_data] if running_data else []

            # Find our report in the running list
            our_report = None
            for report in running_data:
                if report.get("tid") == tid:
                    our_report = report
                    break

            if our_report:
                # Report is still running
                percentage = our_report.get("percent", our_report.get("percentage", 0))
                logger.info(f"Report {tid} progress: {percentage}%")

                if percentage >= 100:
                    return {
                        "status": "success",
                        "tid": tid,
                        "layout": layout,
                        "layout_id": layout_id,
                        "adom": adom,
                        "time_period": time_period,
                        "message": "Report completed. Use get_report_data() to download.",
                    }
            else:
                # Report not in running list - either completed or failed
                # Try to get report data to confirm completion
                logger.info(f"Report {tid} no longer in running list, checking if completed")
                return {
                    "status": "success",
                    "tid": tid,
                    "layout": layout,
                    "layout_id": layout_id,
                    "adom": adom,
                    "time_period": time_period,
                    "message": "Report completed. Use get_report_data() to download.",
                }

            await asyncio.sleep(poll_interval)

    except Exception as e:
        logger.error(f"Failed to run and wait for report '{layout}': {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def save_report(
    tid: str,
    output_dir: str = "~/Downloads",
    output_format: str = "PDF",
    adom: str = "root",
) -> dict[str, Any]:
    """Download, extract, and save a completed report to disk.

    FortiAnalyzer returns reports as base64-encoded ZIP files.
    This tool downloads the report, decodes it, extracts the contents,
    and saves the report file(s) to the specified directory.

    Args:
        tid: Task ID (UUID string) from run_report
        output_dir: Directory to save the report (default: ~/Downloads)
        output_format: Report format - "PDF", "HTML", "JSON", "CSV", "XML" (default: "PDF")
        adom: ADOM name (default: "root")

    Returns:
        dict with saved file paths and status

    Example:
        >>> # After running a report and getting TID
        >>> result = await save_report(
        ...     tid="14fa6624-d12f-11f0-923d-bc2411fc5515",
        ...     output_format="PDF"
        ... )
        >>> print(f"Saved to: {result['files']}")
    """
    try:
        # Validate inputs
        adom = validate_adom(adom)
        output_path = validate_output_path(output_dir)

        client = _get_client()

        # Create output directory if it doesn't exist
        output_path.mkdir(parents=True, exist_ok=True)

        logger.info(f"Downloading report {tid} in {output_format} format")

        # Get report data from FortiAnalyzer
        result = await client.report_get_data(adom=adom, tid=tid, output_format=output_format)

        if not isinstance(result, dict):
            return {"status": "error", "message": "Unexpected response format"}

        report_name = result.get("name", f"report_{tid}")
        data_b64 = result.get("data")

        if not data_b64:
            return {"status": "error", "message": "No report data received"}

        # Decode base64 data
        logger.info("Decoding base64 data")
        try:
            zip_data = base64.b64decode(data_b64)
        except Exception as e:
            return {"status": "error", "message": f"Failed to decode base64: {e}"}

        # Extract ZIP contents with size limit for security
        MAX_EXTRACT_SIZE = 100 * 1024 * 1024  # 100MB per file
        MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500MB total
        saved_files = []
        total_extracted = 0

        try:
            with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
                # List contents
                file_list = zf.namelist()
                logger.info(f"ZIP contains {len(file_list)} files: {file_list}")

                # Extract all files
                for filename in file_list:
                    # Skip directories
                    if filename.endswith("/"):
                        continue

                    # Check file size before extraction (ZIP bomb protection)
                    info = zf.getinfo(filename)
                    if info.file_size > MAX_EXTRACT_SIZE:
                        return {
                            "status": "error",
                            "message": f"File too large: {filename} ({info.file_size} bytes, max {MAX_EXTRACT_SIZE})",
                        }
                    if total_extracted + info.file_size > MAX_TOTAL_SIZE:
                        return {
                            "status": "error",
                            "message": f"Total extraction size exceeds limit ({MAX_TOTAL_SIZE} bytes)",
                        }

                    # Read file content
                    content = zf.read(filename)
                    total_extracted += len(content)

                    # Determine output filename
                    # Use original filename or create based on report name
                    base_filename = os.path.basename(filename)
                    if not base_filename:
                        base_filename = f"{report_name}.{output_format.lower()}"

                    output_file = output_path / base_filename

                    # Handle duplicate filenames
                    counter = 1
                    original_output = output_file
                    while output_file.exists():
                        stem = original_output.stem
                        suffix = original_output.suffix
                        output_file = output_path / f"{stem}_{counter}{suffix}"
                        counter += 1

                    # Write file
                    with open(output_file, "wb") as f:
                        f.write(content)

                    saved_files.append(str(output_file))
                    logger.info(f"Saved: {output_file}")

        except zipfile.BadZipFile:
            # Not a ZIP file - save raw data directly
            logger.info("Data is not a ZIP file, saving directly")
            ext = output_format.lower()
            output_file = output_path / f"{report_name}.{ext}"

            counter = 1
            original_output = output_file
            while output_file.exists():
                stem = original_output.stem
                suffix = original_output.suffix
                output_file = output_path / f"{stem}_{counter}{suffix}"
                counter += 1

            with open(output_file, "wb") as f:
                f.write(zip_data)

            saved_files.append(str(output_file))
            logger.info(f"Saved: {output_file}")

        return {
            "status": "success",
            "tid": tid,
            "format": output_format,
            "output_dir": str(output_path),
            "files": saved_files,
            "file_count": len(saved_files),
            "message": f"Report saved to {output_path}",
        }

    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except Exception as e:
        logger.error(f"Failed to save report: {e}")
        return {"status": "error", "message": str(e)}
