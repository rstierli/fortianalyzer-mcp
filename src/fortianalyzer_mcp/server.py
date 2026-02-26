"""FortiAnalyzer MCP Server implementation."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.utils.config import get_settings

logger = logging.getLogger(__name__)

# Get settings
settings = get_settings()
settings.configure_logging()

# Create FortiAnalyzer client (will be initialized on lifespan)
faz_client: FortiAnalyzerClient | None = None


def get_faz_client() -> FortiAnalyzerClient | None:
    """Get the global FortiAnalyzer client instance.

    Returns:
        FortiAnalyzer client or None if not initialized
    """
    return faz_client


@asynccontextmanager
async def server_lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """Manage server startup and shutdown.

    Args:
        server: FastMCP server instance

    Yields:
        Dictionary with FortiAnalyzer client
    """
    global faz_client

    logger.info("Starting FortiAnalyzer MCP server")

    # Initialize and connect FortiAnalyzer client
    faz_client = FortiAnalyzerClient.from_settings(settings)
    await faz_client.connect()

    logger.info("FortiAnalyzer MCP server started successfully")

    try:
        yield {"faz_client": faz_client}
    finally:
        # Cleanup on shutdown
        logger.info("Shutting down FortiAnalyzer MCP server")
        if faz_client:
            await faz_client.disconnect()
        logger.info("FortiAnalyzer MCP server shut down")


# Create FastMCP server
mcp = FastMCP(
    "FortiAnalyzer API Server",
    stateless_http=True,  # Stateless for Docker deployment
    lifespan=server_lifespan,
)


# Health check resource
@mcp.resource("health://status")
def health_check() -> str:
    """Health check resource for monitoring.

    Returns:
        Health status message
    """
    mode = settings.FAZ_TOOL_MODE
    if mode == "full":
        tool_info = "All tools loaded"
    else:
        tool_info = "Discovery tools + dynamic execution"
    return f"FortiAnalyzer MCP Server is healthy (mode: {mode}, {tool_info})"


# Dynamic mode: lightweight discovery tools
def register_dynamic_tools(mcp_server: FastMCP) -> None:
    """Register discovery tools for dynamic mode only."""

    @mcp_server.tool()
    async def find_fortianalyzer_tool(operation: str) -> dict[str, Any]:
        """Discover FortiAnalyzer tools by operation name/keywords.

        Args:
            operation: Search term or operation description

        Returns:
            Matching tools with usage instructions
        """
        op = operation.lower().strip()

        # Define available tools and their categories
        tool_catalog = {
            "system": [
                ("get_system_status", "Get FortiAnalyzer system status"),
                ("get_ha_status", "Get HA cluster status"),
                ("list_adoms", "List administrative domains"),
                ("get_adom", "Get ADOM details"),
                ("list_devices", "List devices in ADOM"),
                ("get_device", "Get device details"),
                ("list_tasks", "List background tasks"),
                ("get_task", "Get task status"),
                ("wait_for_task", "Wait for task to complete"),
            ],
            "logs": [
                ("query_logs", "Query logs with two-step TID workflow"),
                ("get_log_search_progress", "Get search progress by TID"),
                ("fetch_more_logs", "Fetch more logs using TID"),
                ("cancel_log_search", "Cancel a running search"),
                ("get_log_stats", "Get log statistics"),
                ("get_log_fields", "Get available log fields"),
                ("search_traffic_logs", "Search traffic logs"),
                ("search_security_logs", "Search security logs"),
                ("search_event_logs", "Search event logs"),
                ("get_logfiles_state", "Get log file state info"),
                ("get_pcap_file", "Get PCAP file from log"),
            ],
            "dvm": [
                ("add_device", "Add device to FortiAnalyzer"),
                ("delete_device", "Delete device from FortiAnalyzer"),
                ("add_devices_bulk", "Add multiple devices"),
                ("delete_devices_bulk", "Delete multiple devices"),
                ("get_device_info", "Get detailed device info"),
                ("search_devices", "Search devices with filters"),
                ("list_device_groups", "List device groups"),
                ("list_device_vdoms", "List device VDOMs"),
            ],
            "events": [
                ("get_alerts", "Get alert events"),
                ("get_alert_count", "Get alert count"),
                ("acknowledge_alerts", "Acknowledge alerts"),
                ("unacknowledge_alerts", "Unacknowledge alerts"),
                ("get_alert_logs", "Get logs for alerts"),
                ("get_alert_details", "Get alert details"),
                ("add_alert_comment", "Add comment to alert"),
                ("get_alert_incident_stats", "Get alert-incident statistics"),
            ],
            "fortiview": [
                ("run_fortiview", "Start FortiView query (returns TID)"),
                ("fetch_fortiview", "Fetch FortiView results by TID"),
                ("get_fortiview_data", "Get FortiView data with auto TID"),
                ("get_top_sources", "Get top traffic sources"),
                ("get_top_destinations", "Get top traffic destinations"),
                ("get_top_applications", "Get top applications"),
                ("get_top_threats", "Get top security threats"),
                ("get_top_websites", "Get top websites"),
                ("get_top_cloud_applications", "Get top cloud apps"),
                ("get_policy_hits", "Get policy hit statistics"),
            ],
            "reports": [
                ("list_report_templates", "List report templates"),
                ("run_report", "Run a report"),
                ("fetch_report", "Fetch report status"),
                ("get_report_data", "Download report data"),
                ("get_report_history", "Get report history"),
                ("run_and_wait_report", "Run report and wait"),
            ],
            "incidents": [
                ("get_incidents", "Get security incidents"),
                ("get_incident", "Get incident by ID"),
                ("get_incident_count", "Get incident count"),
                ("create_incident", "Create new incident"),
                ("update_incident", "Update incident"),
                ("get_incident_stats", "Get incident statistics"),
            ],
            "ioc": [
                ("get_ioc_license_state", "Get IOC license state"),
                ("acknowledge_ioc_events", "Acknowledge IOC events"),
                ("run_ioc_rescan", "Start IOC rescan"),
                ("get_ioc_rescan_status", "Get IOC rescan status"),
                ("get_ioc_rescan_history", "Get IOC rescan history"),
                ("run_and_wait_ioc_rescan", "Run IOC rescan and wait"),
            ],
        }

        results = []
        for category, tools in tool_catalog.items():
            for tool_name, description in tools:
                search_text = f"{tool_name} {category} {description}".lower()
                if all(tok in search_text for tok in op.split()):
                    results.append(
                        {
                            "name": tool_name,
                            "category": category,
                            "description": description,
                            "how_to_use": f"execute_advanced_tool(tool_name='{tool_name}', ...)",
                        }
                    )

        return {
            "status": "success" if results else "not_found",
            "operation": operation,
            "found": len(results),
            "tools": results,
        }

    @mcp_server.tool()
    async def execute_advanced_tool(
        tool_name: str,
        parameters: dict | None = None,
    ) -> Any:
        """Execute a FortiAnalyzer operation dynamically by tool name.

        Args:
            tool_name: Name of the tool to execute
            parameters: Dictionary of parameters for the tool

        Returns:
            Tool execution result
        """
        params = parameters or {}

        # Import tools dynamically and execute
        from fortianalyzer_mcp.tools import (
            dvm_tools,
            event_tools,
            fortiview_tools,
            incident_tools,
            ioc_tools,
            log_tools,
            pcap_tools,
            report_tools,
            system_tools,
        )

        # Map tool names to functions
        tool_map = {
            # System tools
            "get_system_status": system_tools.get_system_status,
            "get_ha_status": system_tools.get_ha_status,
            "list_adoms": system_tools.list_adoms,
            "get_adom": system_tools.get_adom,
            "list_devices": system_tools.list_devices,
            "get_device": system_tools.get_device,
            "list_tasks": system_tools.list_tasks,
            "get_task": system_tools.get_task,
            "wait_for_task": system_tools.wait_for_task,
            # Log tools
            "query_logs": log_tools.query_logs,
            "get_log_search_progress": log_tools.get_log_search_progress,
            "fetch_more_logs": log_tools.fetch_more_logs,
            "cancel_log_search": log_tools.cancel_log_search,
            "get_log_stats": log_tools.get_log_stats,
            "get_log_fields": log_tools.get_log_fields,
            "search_traffic_logs": log_tools.search_traffic_logs,
            "search_security_logs": log_tools.search_security_logs,
            "search_event_logs": log_tools.search_event_logs,
            "get_logfiles_state": log_tools.get_logfiles_state,
            "get_pcap_file": log_tools.get_pcap_file,
            # DVM tools
            "add_device": dvm_tools.add_device,
            "delete_device": dvm_tools.delete_device,
            "add_devices_bulk": dvm_tools.add_devices_bulk,
            "delete_devices_bulk": dvm_tools.delete_devices_bulk,
            "get_device_info": dvm_tools.get_device_info,
            "search_devices": dvm_tools.search_devices,
            "list_device_groups": dvm_tools.list_device_groups,
            "list_device_vdoms": dvm_tools.list_device_vdoms,
            # Event tools
            "get_alerts": event_tools.get_alerts,
            "get_alert_count": event_tools.get_alert_count,
            "acknowledge_alerts": event_tools.acknowledge_alerts,
            "unacknowledge_alerts": event_tools.unacknowledge_alerts,
            "get_alert_logs": event_tools.get_alert_logs,
            "get_alert_details": event_tools.get_alert_details,
            "add_alert_comment": event_tools.add_alert_comment,
            "get_alert_incident_stats": event_tools.get_alert_incident_stats,
            # FortiView tools
            "run_fortiview": fortiview_tools.run_fortiview,
            "fetch_fortiview": fortiview_tools.fetch_fortiview,
            "get_fortiview_data": fortiview_tools.get_fortiview_data,
            "get_top_sources": fortiview_tools.get_top_sources,
            "get_top_destinations": fortiview_tools.get_top_destinations,
            "get_top_applications": fortiview_tools.get_top_applications,
            "get_top_threats": fortiview_tools.get_top_threats,
            "get_top_websites": fortiview_tools.get_top_websites,
            "get_top_cloud_applications": fortiview_tools.get_top_cloud_applications,
            "get_policy_hits": fortiview_tools.get_policy_hits,
            # Report tools
            "list_report_templates": report_tools.list_report_templates,
            "run_report": report_tools.run_report,
            "fetch_report": report_tools.fetch_report,
            "get_report_data": report_tools.get_report_data,
            "get_report_history": report_tools.get_report_history,
            "run_and_wait_report": report_tools.run_and_wait_report,
            # Incident tools
            "get_incidents": incident_tools.get_incidents,
            "get_incident": incident_tools.get_incident,
            "get_incident_count": incident_tools.get_incident_count,
            "create_incident": incident_tools.create_incident,
            "update_incident": incident_tools.update_incident,
            "get_incident_stats": incident_tools.get_incident_stats,
            # IOC tools
            "get_ioc_license_state": ioc_tools.get_ioc_license_state,
            "acknowledge_ioc_events": ioc_tools.acknowledge_ioc_events,
            "run_ioc_rescan": ioc_tools.run_ioc_rescan,
            "get_ioc_rescan_status": ioc_tools.get_ioc_rescan_status,
            "get_ioc_rescan_history": ioc_tools.get_ioc_rescan_history,
            "run_and_wait_ioc_rescan": ioc_tools.run_and_wait_ioc_rescan,
            # PCAP tools
            "search_ips_logs": pcap_tools.search_ips_logs,
            "get_pcap_by_session": pcap_tools.get_pcap_by_session,
            "download_pcap_by_url": pcap_tools.download_pcap_by_url,
            "search_and_download_pcaps": pcap_tools.search_and_download_pcaps,
            "list_available_pcaps": pcap_tools.list_available_pcaps,
        }

        if tool_name not in tool_map:
            return {
                "status": "error",
                "message": f"Unknown tool: {tool_name}",
                "available_tools": list(tool_map.keys()),
            }

        tool_func = tool_map[tool_name]
        return await tool_func(**params)

    @mcp_server.tool()
    def list_fortianalyzer_categories() -> dict[str, Any]:
        """List FortiAnalyzer operation categories.

        Returns:
            Categories with tool counts and descriptions
        """
        return {
            "status": "success",
            "categories": {
                "system": {
                    "description": "System status, HA, ADOMs, devices, and tasks",
                    "tool_count": 9,
                },
                "logs": {
                    "description": "Log search with TID workflow, analytics",
                    "tool_count": 11,
                },
                "dvm": {
                    "description": "Device management, add/delete, groups",
                    "tool_count": 8,
                },
                "events": {
                    "description": "Alert management and SOC operations",
                    "tool_count": 8,
                },
                "fortiview": {
                    "description": "FortiView analytics with TID workflow",
                    "tool_count": 10,
                },
                "reports": {
                    "description": "Report templates and execution with TID workflow",
                    "tool_count": 6,
                },
                "incidents": {
                    "description": "Incident management and tracking",
                    "tool_count": 6,
                },
                "ioc": {
                    "description": "IOC detection and rescan operations",
                    "tool_count": 6,
                },
                "pcap": {
                    "description": "IPS log search and PCAP download for forensics",
                    "tool_count": 5,
                },
            },
            "total_tools": 69,
            "note": "Use find_fortianalyzer_tool() to search, execute_advanced_tool() to run",
        }


# Conditional tool loading based on FAZ_TOOL_MODE
if settings.FAZ_TOOL_MODE == "dynamic":
    # Dynamic mode: register discovery tools only
    logger.info("Loading in DYNAMIC mode - discovery tools only")
    register_dynamic_tools(mcp)

else:
    # Full mode: Load all tools (default behavior)
    logger.info("Loading in FULL mode - all tools")

    # Import all tool modules (registers them with the server)
    from fortianalyzer_mcp.tools import (  # noqa: E402, F401
        dvm_tools,
        event_tools,
        fortiview_tools,
        incident_tools,
        ioc_tools,
        log_tools,
        pcap_tools,
        report_tools,
        system_tools,
    )


def main() -> None:
    """Entry point for the MCP server."""
    import os
    import sys

    # Determine server mode from settings
    server_mode = settings.MCP_SERVER_MODE

    if server_mode == "auto":
        # Auto-detect mode based on environment
        is_docker = os.path.exists("/.dockerenv") or os.getenv("DOCKER_CONTAINER") == "1"

        if is_docker or sys.stdin.isatty():
            # Docker or TTY → HTTP mode
            server_mode = "http"
        else:
            # Pipe stdin → stdio mode (Claude Desktop, etc.)
            server_mode = "stdio"

    if server_mode == "stdio":
        # Run in stdio mode for MCP clients (Claude Desktop, LM Studio, etc.)
        logger.info("Starting MCP server in stdio mode")
        run_stdio()
    else:
        # Run in HTTP mode for Docker deployment
        logger.info(
            f"Starting MCP server in HTTP mode on {settings.MCP_SERVER_HOST}:{settings.MCP_SERVER_PORT}"
        )
        run_http()


def run_stdio() -> None:
    """Run MCP server in stdio mode for LM Studio and similar clients."""
    import asyncio

    async def stdio_main() -> None:
        """Main coroutine for stdio mode."""
        global faz_client

        # Initialize FortiAnalyzer connection
        logger.info("Initializing FortiAnalyzer connection")
        faz_client = FortiAnalyzerClient.from_settings(settings)

        try:
            await faz_client.connect()
            logger.info("FortiAnalyzer connection established")
        except Exception as e:
            logger.warning(f"FortiAnalyzer connection failed: {e}. Server will still start.")

        try:
            # Run FastMCP in stdio mode
            await mcp.run_stdio_async()
        finally:
            # Cleanup
            logger.info("Closing FortiAnalyzer connection")
            if faz_client:
                await faz_client.disconnect()

    # Run the async main
    asyncio.run(stdio_main())


def run_http() -> None:
    """Run MCP server in HTTP mode for Docker deployment."""
    import json
    from contextlib import asynccontextmanager

    import uvicorn
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Mount, Route
    from starlette.types import ASGIApp, Receive, Scope, Send

    class AuthMiddleware:
        """ASGI middleware for Bearer token authentication."""

        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] != "http":
                await self.app(scope, receive, send)
                return

            # Skip auth if no token configured (backwards compatible)
            if not settings.MCP_AUTH_TOKEN:
                await self.app(scope, receive, send)
                return

            # Allow /health without auth
            path = scope.get("path", "")
            if path == "/health":
                await self.app(scope, receive, send)
                return

            # Check Authorization header
            headers = dict(scope.get("headers", []))
            auth_value = headers.get(b"authorization", b"").decode()
            expected = f"Bearer {settings.MCP_AUTH_TOKEN}"

            if auth_value != expected:
                response = Response(
                    content=json.dumps({"error": "Unauthorized", "detail": "Invalid or missing Bearer token"}),
                    status_code=401,
                    media_type="application/json",
                )
                await response(scope, receive, send)
                return

            await self.app(scope, receive, send)

    # Health check endpoint
    async def health_endpoint(request: Request) -> JSONResponse:
        """HTTP health check endpoint for Docker health checks."""
        global faz_client

        # Check if client is connected
        is_connected = faz_client is not None and faz_client.is_connected

        health_status = {
            "status": "healthy",
            "service": "fortianalyzer-mcp",
            "fortianalyzer_connected": is_connected,
        }

        return JSONResponse(health_status, status_code=200)

    # Create Starlette app with lifespan
    @asynccontextmanager
    async def app_lifespan(app: Starlette) -> AsyncIterator[None]:
        """Ensure MCP session manager and FortiAnalyzer client start."""
        # Start MCP session manager
        async with mcp.session_manager.run():
            # Initialize FortiAnalyzer connection
            global faz_client
            logger.info("Initializing FortiAnalyzer connection")
            faz_client = FortiAnalyzerClient.from_settings(settings)
            try:
                await faz_client.connect()
                logger.info("FortiAnalyzer connection established")
                yield
            except Exception as e:
                logger.warning(f"FortiAnalyzer connection failed: {e}. Server will still start.")
                yield
            finally:
                logger.info("Closing FortiAnalyzer connection")
                if faz_client:
                    await faz_client.disconnect()

    # Build middleware stack
    middleware = [Middleware(AuthMiddleware)]

    # Create app with MCP mounted and proper lifespan
    app = Starlette(
        routes=[
            Route("/health", health_endpoint, methods=["GET"]),
            Mount("/", app=mcp.streamable_http_app()),
        ],
        lifespan=app_lifespan,
        middleware=middleware,
    )

    # Run with uvicorn
    uvicorn.run(
        app,
        host=settings.MCP_SERVER_HOST,
        port=settings.MCP_SERVER_PORT,
        log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    main()
