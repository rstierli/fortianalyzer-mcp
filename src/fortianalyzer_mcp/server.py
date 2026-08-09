"""FortiAnalyzer MCP Server implementation."""

import hashlib
import hmac
import logging
from collections.abc import AsyncIterator, Mapping
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.instructions import build_instructions
from fortianalyzer_mcp.query.filters import FilterCondition
from fortianalyzer_mcp.tool_annotations import READ_ONLY_LOCAL, UNCONSTRAINED
from fortianalyzer_mcp.utils.config import get_settings
from fortianalyzer_mcp.utils.responses import error_response
from fortianalyzer_mcp.utils.validation import ValidationError

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


# Configure transport security for reverse proxy deployments
_transport_security = None
if settings.MCP_ALLOWED_HOSTS:
    _transport_security = TransportSecuritySettings(
        allowed_hosts=settings.MCP_ALLOWED_HOSTS,
    )

# Create the MCP server.
#
# Lifecycle ownership of the process-global ``faz_client`` is deliberately held
# by exactly one path: ``run_http``'s ``app_lifespan`` in HTTP mode and
# ``run_stdio`` in stdio mode. We do NOT pass a ``lifespan`` here: with
# ``stateless_http=True`` that lifespan runs per request/session, so it would
# connect and then *disconnect* the shared client around every call, dropping the
# session out from under concurrent requests.
#
# ``stateless_http`` and ``transport_security`` are NOT constructor arguments on
# mcp 2.x -- they moved to the transport layer, so they are passed to
# ``streamable_http_app()`` in ``run_http`` instead. Both still have to be set:
# dropping them here without setting them there would silently make the HTTP
# deployment stateful and unbound by the allowed-hosts list.
mcp = MCPServer(
    "FortiAnalyzer API Server",
    # Cross-cutting usage guidance that no single tool docstring can carry --
    # chiefly that ``tid`` means five incompatible things across the async
    # families. See ``instructions.py`` for why it is server-level. The masking
    # section is appended only when masking is on, so a default deployment does
    # not pay handshake tokens for advice about tokens it will never emit.
    instructions=build_instructions(masking_enabled=settings.MASKING_ENABLED),
)

if settings.MASKING_ENABLED:
    # RFC #40 Phase 1: wrap tool registration BEFORE any tool module is
    # imported (tools self-register at import). Raises at startup if
    # FAZ_MASKING_KEY is missing/invalid: a deployment that asked for
    # masking must not run without it.
    from fortianalyzer_mcp.masking.wrapper import install_masking  # noqa: E402

    install_masking(mcp)
    logger.info("MASKING_ENABLED - tool args are unmasked and outputs masked (RFC #40 Phases 1+2)")


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


def _coerce_model_list(
    raw: object, model: type[BaseModel], param: str, shape: str
) -> list[BaseModel]:
    """Validate a caller's list-of-models parameter, as MCPServer would have.

    ``execute_advanced_tool`` invokes tool functions directly, so the protocol
    layer that turns JSON arguments into typed parameters never runs and a
    model-typed parameter arrives as raw dicts. Consumers are models-only by
    contract (attribute access; see ``TestCompilerRequiresModelsNotDicts``), so
    without this the dicts surfaced as an ``AttributeError`` that the tools'
    broad handlers buried in a generic ``faz_operation_failed``. This mirrors
    full mode's boundary: coerce before the tool runs, and reject a malformed
    entry with a message about that entry.

    Any tool parameter typed ``list[SomeModel]`` needs an entry in
    ``_STRUCTURED_PARAMS`` or it breaks in dynamic mode only — full mode keeps
    working because MCPServer coerces there, which is what made this class of bug
    easy to ship.

    Raises:
        ValidationError: If ``raw`` is not a list, or an entry fails model
            validation (unknown key, wrong type, non-dict entry).
    """
    if not isinstance(raw, list):
        raise ValidationError(
            f"'{param}' must be a list of {shape} -- got {type(raw).__name__}. "
            f"Wrap it in a list: {param}=[{{...}}]."
        )
    coerced: list[BaseModel] = []
    for index, item in enumerate(raw):
        if isinstance(item, model):
            coerced.append(item)
            continue
        try:
            coerced.append(model.model_validate(item))
        except PydanticValidationError as exc:
            details = "; ".join(
                f"{'.'.join(str(loc) for loc in err['loc']) or 'entry'}: {err['msg']}"
                for err in exc.errors()
            )
            raise ValidationError(f"{param}[{index}] is invalid: {details}") from exc
    return coerced


def _structured_params() -> dict[str, tuple[type[BaseModel], str]]:
    """Tool parameters typed ``list[SomeModel]``, by parameter name.

    ``IocEventRef`` is imported lazily: it lives in a tool module, and tool
    modules import this one at registration time, so a module-level import
    would be circular.
    """
    from fortianalyzer_mcp.tools.ioc_tools import IocEventRef

    return {
        "filters": (FilterCondition, "conditions, each {field, op, value}"),
        "events": (IocEventRef, "IOC events, each {endpoint_id/source_ip, timestamp}"),
    }


#: Category -> tool names, for dynamic mode's search surface.
#:
#: Static on purpose. find_fortianalyzer_tool must not import the tool modules
#: to build this, because importing them registers every tool and destroys the
#: minimal surface dynamic mode exists for. The cost is that it can drift from
#: what is registered -- and it had, badly -- so
#: tests/test_tool_catalogue_parity.py asserts the two match exactly.
TOOL_CATALOGUE: Mapping[str, tuple[str, ...]] = {
    "system": (
        "get_system_status",
        "get_ha_status",
        "list_adoms",
        "get_adom",
        "list_devices",
        "get_device",
        "list_tasks",
        "get_task",
        "wait_for_task",
        "get_api_ratelimit",
        "update_api_ratelimit",
    ),
    "logs": (
        "query_logs",
        "get_log_search_progress",
        "fetch_more_logs",
        "cancel_log_search",
        "get_log_stats",
        "get_log_fields",
        "get_logfiles_state",
        "get_pcap_file",
    ),
    "dvm": (
        "add_device",
        "delete_device",
        "add_devices_bulk",
        "delete_devices_bulk",
        "get_device_info",
        "search_devices",
        "list_device_groups",
        "list_device_vdoms",
    ),
    "events": (
        "get_alerts",
        "get_alert_count",
        "acknowledge_alerts",
        "unacknowledge_alerts",
        "get_alert_logs",
        "get_alert_details",
        "add_alert_comment",
        "get_alert_incident_stats",
        "get_alert_handlers",
    ),
    "fortiview": (
        "run_fortiview",
        "fetch_fortiview",
        "get_fortiview_data",
    ),
    "reports": (
        "list_report_layouts",
        "list_report_templates",
        "run_report",
        "fetch_report",
        "get_report_data",
        "get_running_reports",
        "get_report_history",
        "run_and_wait_report",
        "save_report",
    ),
    "incidents": (
        "get_incidents",
        "get_incident",
        "get_incident_count",
        "create_incident",
        "update_incident",
        "get_incident_stats",
    ),
    "ioc": (
        "get_ioc_license_state",
        "acknowledge_ioc_events",
        "run_ioc_rescan",
        "get_ioc_rescan_status",
        "get_ioc_rescan_history",
        "run_and_wait_ioc_rescan",
    ),
    "pcap": (
        "search_ips_logs",
        "get_pcap_by_session",
        "download_pcap_by_url",
        "search_and_download_pcaps",
        "list_available_pcaps",
    ),
    "soar": (
        "get_linked_indicators",
        "get_indicator_enrichment",
    ),
    "ueba": (
        "get_endpoints",
        "get_endpoint_vulnerabilities",
        "get_endusers",
        "get_endpoint_stats",
        "get_enduser_stats",
    ),
    "traffic": ("analyze_policy_traffic",),
}

#: All registered tool names, flattened. Used both to build ``tool_map`` in
#: ``execute_advanced_tool`` and by the parity test.
TOOL_CATALOGUE_NAMES: frozenset[str] = frozenset(
    name for names in TOOL_CATALOGUE.values() for name in names
)

#: Human-readable blurb per category, for ``list_fortianalyzer_categories`` and
#: search results. Purely descriptive text -- unlike ``TOOL_CATALOGUE`` this
#: cannot drift into a wrong *count*, so it stays hand-written.
_CATEGORY_DESCRIPTIONS: Mapping[str, str] = {
    "system": "System status, HA, ADOMs, devices, and tasks",
    "logs": "Log search with TID workflow, analytics",
    "dvm": "Device management, add/delete, groups",
    "events": "Alert management and SOC operations",
    "fortiview": "FortiView analytics with TID workflow",
    "reports": "Report templates and execution with TID workflow",
    "incidents": "Incident management and tracking",
    "ioc": "IOC detection and rescan operations",
    "pcap": "IPS log search and PCAP download for forensics",
    "soar": "Threat-intel indicator lookups (SOAR)",
    "ueba": "Endpoint and end-user behavior analytics (UEBA)",
    "traffic": "Policy traffic analysis (profile, ports, protocols)",
}


# Dynamic mode: lightweight discovery tools
def register_dynamic_tools(mcp_server: MCPServer) -> None:
    """Register discovery tools for dynamic mode only."""

    @mcp_server.tool(annotations=READ_ONLY_LOCAL)
    async def find_fortianalyzer_tool(operation: str) -> dict[str, Any]:
        """Discover FortiAnalyzer tools by operation name/keywords.

        Args:
            operation: Search term or operation description

        Returns:
            Matching tools with usage instructions
        """
        op = operation.lower().strip()

        results = []
        for category, tool_names in TOOL_CATALOGUE.items():
            description = _CATEGORY_DESCRIPTIONS.get(category, "")
            for tool_name in tool_names:
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

    # Annotated as the union of everything it can dispatch to, not as the
    # reader it superficially resembles: ``tool_name`` selects any tool in
    # the catalogue below, ``delete_device`` included.
    @mcp_server.tool(annotations=UNCONSTRAINED)
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
        # Copied so the coercion below never mutates the caller's dict.
        params = dict(parameters) if parameters else {}

        # Import tools dynamically and execute. This already imports every tool
        # module, so -- unlike TOOL_CATALOGUE, which must stay static to avoid
        # exactly this import -- tool_map below can be derived from it for free.
        from fortianalyzer_mcp.tools import (
            dvm_tools,
            event_tools,
            fortiview_tools,
            incident_tools,
            ioc_tools,
            log_tools,
            pcap_tools,
            report_tools,
            soar_tools,
            system_tools,
            traffic_tools,
            ueba_tools,
        )

        tool_modules = (
            system_tools,
            log_tools,
            dvm_tools,
            event_tools,
            fortiview_tools,
            report_tools,
            incident_tools,
            ioc_tools,
            pcap_tools,
            soar_tools,
            ueba_tools,
            traffic_tools,
        )
        tool_map: dict[str, Any] = {}
        for module in tool_modules:
            tool_map.update(
                (name, getattr(module, name))
                for name in TOOL_CATALOGUE_NAMES
                if name not in tool_map and hasattr(module, name)
            )

        if tool_name not in tool_map:
            return {
                "status": "error",
                "message": f"Unknown tool: {tool_name}",
                "available_tools": list(tool_map.keys()),
            }

        for param, (model, shape) in _structured_params().items():
            if params.get(param) is None:
                continue
            try:
                params[param] = _coerce_model_list(params[param], model, param, shape)
            except ValidationError as e:
                return error_response(
                    error="validation_error",
                    message=e,
                    operation="execute_advanced_tool",
                    tool_name=tool_name,
                )

        tool_func = tool_map[tool_name]
        return await tool_func(**params)

    @mcp_server.tool(annotations=READ_ONLY_LOCAL)
    def list_fortianalyzer_categories() -> dict[str, Any]:
        """List FortiAnalyzer operation categories.

        Returns:
            Categories with tool counts and descriptions
        """
        return {
            "status": "success",
            "categories": {
                category: {
                    "description": _CATEGORY_DESCRIPTIONS.get(category, ""),
                    "tool_count": len(tool_names),
                }
                for category, tool_names in TOOL_CATALOGUE.items()
            },
            "total_tools": sum(len(names) for names in TOOL_CATALOGUE.values()),
            "note": "Use find_fortianalyzer_tool() to search, execute_advanced_tool() to run",
        }


# Conditional tool loading based on FAZ_TOOL_MODE
if settings.FAZ_TOOL_MODE == "dynamic":
    # Dynamic mode: register discovery tools only
    logger.info("Loading in DYNAMIC mode - discovery tools only")
    register_dynamic_tools(mcp)

    if settings.FAZ_SKILLS_ENABLED:
        # Skills lazily import full tool modules per call, which would
        # register raw tools mid-session and defeat dynamic mode's
        # minimal surface — unsupported in the skills beta.
        logger.warning("FAZ_SKILLS_ENABLED is ignored in dynamic mode (beta limitation)")

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
        soar_tools,
        system_tools,
        traffic_tools,
        ueba_tools,
    )

    if settings.FAZ_SKILLS_ENABLED:
        # Skills layer (RFC #44): one additional dispatcher tool, beta.
        logger.info("FAZ_SKILLS_ENABLED - registering faz_skill dispatcher (beta)")
        from fortianalyzer_mcp.skills import dispatcher  # noqa: E402, F401


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
            # Run MCPServer in stdio mode
            await mcp.run_stdio_async()
        finally:
            # Cleanup
            logger.info("Closing FortiAnalyzer connection")
            if faz_client:
                await faz_client.disconnect()

    # Run the async main
    asyncio.run(stdio_main())


def _ensure_http_auth_or_die() -> None:
    """Fail closed: refuse to expose the HTTP transport without authentication.

    The HTTP server fronts the full tool surface (including destructive device
    add/delete and PCAP download), so it must never run unauthenticated. Require
    ``MCP_AUTH_TOKEN`` unless the operator explicitly opts out with
    ``MCP_ALLOW_NO_AUTH=true`` (only safe on a trusted, isolated bind such as
    127.0.0.1 behind a gateway), in which case we log a CRITICAL warning.

    Raises ``SystemExit`` when no token is configured and the opt-out is not set.
    """
    if settings.MCP_AUTH_TOKEN:
        return
    if not settings.MCP_ALLOW_NO_AUTH:
        raise SystemExit(
            "FATAL: refusing to start the HTTP transport without MCP_AUTH_TOKEN -- every "
            "tool (including device add/delete and PCAP download) would be exposed "
            "unauthenticated. Set a token (e.g. `openssl rand -hex 32`), or set "
            "MCP_ALLOW_NO_AUTH=true to explicitly run without auth (not recommended; only "
            "safe on a trusted, isolated bind such as 127.0.0.1 behind a gateway)."
        )
    logger.critical(
        "MCP_ALLOW_NO_AUTH=true: HTTP transport is running WITHOUT authentication on "
        "%s:%s -- every tool is exposed to anyone who can reach this port.",
        settings.MCP_SERVER_HOST,
        settings.MCP_SERVER_PORT,
    )


def run_http() -> None:
    """Run MCP server in HTTP mode for Docker deployment."""
    _ensure_http_auth_or_die()

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

            # No token => unauthenticated mode. run_http() only reaches here when
            # the operator explicitly set MCP_ALLOW_NO_AUTH=true (otherwise it
            # refuses to start), so this is an acknowledged, logged opt-out.
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

            # Hash both sides before comparing: compare_digest short-circuits on
            # length mismatch, which would leak the token length as a timing
            # side-channel. Equal-length digests keep it constant-time.
            if not hmac.compare_digest(
                hashlib.sha256(auth_value.encode()).digest(),
                hashlib.sha256(expected.encode()).digest(),
            ):
                response = Response(
                    content=json.dumps(
                        {"error": "Unauthorized", "detail": "Invalid or missing Bearer token"}
                    ),
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
            # stateless_http/transport_security live here on mcp 2.x; see the
            # MCPServer construction above.
            Mount(
                "/",
                app=mcp.streamable_http_app(
                    stateless_http=True,  # Stateless for Docker deployment
                    transport_security=_transport_security,
                ),
            ),
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
