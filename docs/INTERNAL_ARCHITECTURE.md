# FortiAnalyzer MCP Server - Internal Architecture Documentation

This document provides a deep technical understanding of how the FortiAnalyzer MCP Server is built and how all components interact.

---

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Component Overview](#component-overview)
3. [Data Flow](#data-flow)
4. [API Client Layer](#api-client-layer)
5. [MCP Tools Layer](#mcp-tools-layer)
6. [Server Implementation](#server-implementation)
7. [Configuration System](#configuration-system)
8. [Error Handling](#error-handling)
9. [Key Design Decisions](#key-design-decisions)
10. [File Reference](#file-reference)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Claude Desktop / MCP Client                    │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ stdio / HTTP
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                              MCP Server Layer                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                         server.py                                │   │
│  │  - FastMCP server instance                                       │   │
│  │  - Lifespan management (connect/disconnect FAZ)                  │   │
│  │  - Tool mode selection (full/dynamic)                            │   │
│  │  - HTTP/stdio transport selection                                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                              MCP Tools Layer                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │
│  │ system_tools │ │  log_tools   │ │report_tools  │ │fortiview_    │   │
│  │              │ │              │ │              │ │    tools     │   │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │
│  │ event_tools  │ │incident_tools│ │  ioc_tools   │ │  dvm_tools   │   │
│  │              │ │              │ │              │ │              │   │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            API Client Layer                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      client.py (FortiAnalyzerClient)             │   │
│  │  - Connection management (connect/disconnect)                    │   │
│  │  - Authentication (API token or username/password)               │   │
│  │  - Generic CRUD operations (get/add/set/update/delete/execute)   │   │
│  │  - Raw request handling for non-standard APIs (_raw_request)     │   │
│  │  - Response parsing and error handling                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ HTTPS / JSON-RPC
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         FortiAnalyzer Appliance                          │
│                           /jsonrpc endpoint                              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Overview

### Directory Structure

```
src/fortianalyzer_mcp/
├── __init__.py           # Package initialization
├── __main__.py           # Entry point for `python -m fortianalyzer_mcp`
├── server.py             # MCP server implementation (519 lines)
├── api/
│   ├── __init__.py
│   └── client.py         # FortiAnalyzer API client (1451 lines)
├── tools/
│   ├── __init__.py       # Tool exports
│   ├── system_tools.py   # System/ADOM/device tools (13K)
│   ├── log_tools.py      # Log search tools (24K)
│   ├── report_tools.py   # Report generation tools (28K)
│   ├── fortiview_tools.py # FortiView analytics (17K)
│   ├── event_tools.py    # Alert management (10K)
│   ├── incident_tools.py # Incident management (10K)
│   ├── ioc_tools.py      # IOC analysis (10K)
│   └── dvm_tools.py      # Device management (15K)
└── utils/
    ├── __init__.py
    ├── config.py         # Settings/configuration (205 lines)
    └── errors.py         # Exception classes (103 lines)
```

---

## Data Flow

### Request Flow (Claude → FortiAnalyzer)

```
1. User asks Claude: "Show me top bandwidth consumers"

2. Claude Desktop invokes MCP tool: get_top_sources()
   └─> tools/fortiview_tools.py

3. Tool function calls API client method:
   └─> client.fortiview_run() then client.fortiview_fetch()

4. API client builds JSON-RPC request:
   {
     "method": "add",
     "params": [{"url": "/fortiview/adom/root/top-sources/run", ...}],
     "session": "abc123",
     "id": 1,
     "jsonrpc": "2.0"
   }

5. Request sent via pyfmg library to FortiAnalyzer /jsonrpc

6. Response parsed, errors handled, data returned up the chain

7. Claude receives structured response, formats for user
```

### Two-Step TID Workflow

Several FortiAnalyzer APIs use asynchronous task-based operations:

```
Step 1: Start Operation (returns TID)
┌────────────┐      ┌─────────────────┐      ┌──────────────┐
│ MCP Tool   │ ───► │ client.*_run()  │ ───► │ FortiAnalyzer│
│            │ ◄─── │                 │ ◄─── │              │
└────────────┘      └─────────────────┘      └──────────────┘
                         {"tid": 12345}

Step 2: Fetch Results (using TID)
┌────────────┐      ┌─────────────────┐      ┌──────────────┐
│ MCP Tool   │ ───► │ client.*_fetch()│ ───► │ FortiAnalyzer│
│            │ ◄─── │                 │ ◄─── │              │
└────────────┘      └─────────────────┘      └──────────────┘
                         {"data": [...]}

APIs using TID workflow:
- Log Search: logsearch_start → logsearch_fetch
- FortiView: fortiview_run → fortiview_fetch
- Reports: report_run → report_fetch → report_get_data
- IOC Rescan: ioc_rescan_run → ioc_rescan_status
```

---

## API Client Layer

### File: `api/client.py`

The `FortiAnalyzerClient` class is the core API interface. It wraps the `pyfmg` library (which was originally for FortiManager but works with FortiAnalyzer).

#### Key Design Patterns

**1. Two Request Methods:**

```python
# Standard pyfmg methods (for simple APIs)
async def get(self, url, **kwargs):
    fmg = self._ensure_connected()
    code, response = fmg.get(url, **kwargs)
    return self._handle_response(code, response, f"GET {url}")

# Raw request method (for complex APIs like LogView, Reports)
async def _raw_request(self, method, url, **kwargs):
    # Builds JSON-RPC manually
    # Handles non-standard response formats
    # Used for: logsearch, fortiview, reports, events, incidents, ioc
```

**Why two methods?**
- pyfmg's built-in methods expect standard FortiManager response format
- FortiAnalyzer's LogView/Report APIs return different formats
- `_raw_request` handles these variations

**2. Response Format Handling:**

FortiAnalyzer returns different response formats:

```python
# Format 1: Standard (dvmdb, sys, task)
{"result": [{"status": {"code": 0}, "data": [...]}]}

# Format 2: LogView/FortiView
{"result": {"percentage": 100, "data": [...]}}

# Format 3: Empty (no running reports)
{"jsonrpc": "2.0", "id": 2}  # No "result" field!

# The _raw_request method handles all three
```

**3. Authentication:**

```python
# API Token (preferred)
FortiManager(host, apikey=token, ...)

# Username/Password (fallback)
FortiManager(host, username, password, ...)
```

#### API Methods by Category

| Category | Methods | Notes |
|----------|---------|-------|
| DVMDB | `list_adoms`, `get_adom`, `list_devices`, `get_device`, `list_device_vdoms`, `list_device_groups` | Uses standard `get()` |
| DVM | `add_device`, `delete_device`, `add_device_list`, `delete_device_list` | Uses `execute()` |
| LogView | `logsearch_start`, `logsearch_fetch`, `logsearch_count`, `logsearch_cancel`, `get_logfields`, `get_logstats`, `get_logfiles_state`, `get_pcapfile` | Uses `_raw_request()` |
| FortiView | `fortiview_run`, `fortiview_fetch` | Uses `_raw_request()` |
| Reports | `get_report_layouts`, `report_run`, `report_fetch`, `report_get_data`, `report_get_state`, `get_report_schedules`, `create_report_schedule`, `get_running_reports` | Uses `_raw_request()` |
| Events | `get_alerts`, `get_alerts_count`, `acknowledge_alerts`, `unacknowledge_alerts`, `get_alert_logs`, `get_alert_extra_details`, `add_alert_comment`, `get_alert_incident_stats` | Uses `_raw_request()` |
| Incidents | `get_incidents`, `get_incident`, `get_incidents_count`, `create_incident`, `update_incident`, `get_incident_stats` | Uses `_raw_request()` |
| IOC | `get_ioc_license_state`, `acknowledge_ioc_events`, `ioc_rescan_run`, `ioc_rescan_status`, `get_ioc_rescan_history` | Uses `_raw_request()` |
| System | `get_system_status`, `get_ha_status` | Uses standard `get()` |
| Tasks | `list_tasks`, `get_task`, `get_task_line` | Uses standard `get()` |

---

## MCP Tools Layer

### File: `tools/*.py`

Each tool file contains:
1. `@mcp.tool()` decorated async functions
2. Helper functions (e.g., time parsing, ID lookup)
3. Docstrings that become tool descriptions for Claude

#### Tool Pattern

```python
@mcp.tool()
async def tool_name(
    param1: str,
    param2: str = "default",
    adom: str = "root",
) -> dict[str, Any]:
    """Tool description shown to Claude.

    Args:
        param1: Description
        param2: Description
        adom: ADOM name

    Returns:
        dict with result
    """
    try:
        client = _get_client()  # Get global FAZ client

        # Call API method(s)
        result = await client.some_method(...)

        # Process/simplify result
        return {
            "status": "success",
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed: {e}")
        return {"status": "error", "message": str(e)}
```

#### Helper Functions

**Time Parsing (`_parse_time_range`):**
```python
# Converts user-friendly formats to API format
"1-hour"  → {"start": "2024-12-05 09:00:00", "end": "2024-12-05 10:00:00"}
"7-day"   → {"start": "2024-11-28 10:00:00", "end": "2024-12-05 10:00:00"}
"custom"  → "2024-01-01 00:00:00|2024-01-02 00:00:00"
```

**Layout/Template Lookup:**
```python
# Reports use layout-id (integer), but users provide title (string)
async def _get_layout_id_by_title(client, adom, title):
    result = await client.get_report_layouts(adom=adom)
    for layout in result.get("data", []):
        if layout.get("title", "").lower() == title.lower():
            return layout.get("layout-id")
    return None
```

**Schedule Management:**
```python
# FortiAnalyzer requires a schedule before running reports
async def _ensure_schedule_exists(client, adom, layout_id):
    schedules = await client.get_report_schedules(adom, layout_id)
    if not schedules.get("data"):
        await client.create_report_schedule(adom, layout_id)
```

---

## Server Implementation

### File: `server.py`

#### Initialization Sequence

```python
# 1. Load settings from environment
settings = get_settings()
settings.configure_logging()

# 2. Create FastMCP server instance
mcp = FastMCP(
    "FortiAnalyzer API Server",
    stateless_http=True,
    lifespan=server_lifespan,
)

# 3. Register tools based on mode
if settings.FAZ_TOOL_MODE == "dynamic":
    register_dynamic_tools(mcp)  # Only 3 discovery tools
else:
    # Import all tool modules (67 tools)
    from fortianalyzer_mcp.tools import (
        dvm_tools, event_tools, fortiview_tools,
        incident_tools, ioc_tools, log_tools,
        report_tools, system_tools,
    )
```

#### Server Modes

**stdio mode (Claude Desktop):**
```python
def run_stdio():
    async def stdio_main():
        global faz_client
        faz_client = FortiAnalyzerClient.from_settings(settings)
        await faz_client.connect()
        await mcp.run_stdio_async()
        await faz_client.disconnect()

    asyncio.run(stdio_main())
```

**HTTP mode (Docker):**
```python
def run_http():
    # Create Starlette app with:
    # - /health endpoint for Docker health checks
    # - / mounted to MCP's streamable HTTP app
    # - Lifespan manages FAZ connection
    app = Starlette(routes=[...], lifespan=app_lifespan)
    uvicorn.run(app, host=..., port=...)
```

#### Tool Modes

**Full Mode (default):**
- All 67 tools loaded
- ~50K+ tokens context
- Best for large context windows

**Dynamic Mode:**
- Only 3 tools loaded:
  - `find_fortianalyzer_tool(operation)` - Search for tools
  - `execute_advanced_tool(tool_name, parameters)` - Run any tool
  - `list_fortianalyzer_categories()` - Show categories
- ~3K tokens context
- 97% reduction

---

## Configuration System

### File: `utils/config.py`

Uses Pydantic Settings for configuration management:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
    )

    # Required
    FORTIANALYZER_HOST: str

    # Auth (one required)
    FORTIANALYZER_API_TOKEN: str | None = None
    FORTIANALYZER_USERNAME: str | None = None
    FORTIANALYZER_PASSWORD: str | None = None

    # Optional with defaults
    FORTIANALYZER_VERIFY_SSL: bool = True
    FORTIANALYZER_TIMEOUT: int = 30
    LOG_LEVEL: Literal["DEBUG", "INFO", ...] = "INFO"
    FAZ_TOOL_MODE: Literal["full", "dynamic"] = "full"
    MCP_SERVER_MODE: Literal["http", "stdio", "auto"] = "auto"
```

**Singleton Pattern:**
```python
@lru_cache()
def get_settings() -> Settings:
    return Settings()  # Cached, only created once
```

---

## Error Handling

### File: `utils/errors.py`

**Exception Hierarchy:**
```
FortiAnalyzerError (base)
├── AuthenticationError     # Login failed, token expired
├── ConnectionError         # Network issues
├── APIError               # Generic API errors
├── ResourceNotFoundError  # Object not found (-4)
├── PermissionError        # Access denied (-3)
├── TimeoutError           # Request timeout (-11)
├── ValidationError        # Invalid parameters (-5)
└── WorkspaceError         # Workspace locked (-8, -9)
```

**Error Code Mapping:**
```python
ERROR_CODE_MAP = {
    -1: APIError,           # Internal error
    -2: AuthenticationError, # Invalid session
    -3: PermissionError,     # Permission denied
    -4: ResourceNotFoundError,
    -5: ValidationError,
    -20: AuthenticationError, # Invalid credentials
    -21: AuthenticationError, # Token expired
    ...
}
```

---

## Key Design Decisions

### 1. Why pyfmg instead of raw httpx/requests?

- pyfmg handles session management automatically
- Manages authentication token refresh
- Already proven for FortiManager/FortiAnalyzer
- We extended it with `_raw_request` for non-standard APIs

### 2. Why async when pyfmg is sync?

- FastMCP requires async tools
- Allows future migration to async HTTP client
- Current implementation wraps sync pyfmg calls
- No blocking issues because FAZ API calls are I/O bound

### 3. Why global client instead of per-request?

```python
faz_client: FortiAnalyzerClient | None = None

def get_faz_client():
    return faz_client
```

- FortiAnalyzer sessions are expensive to create
- API tokens maintain persistent sessions
- Client initialized once at server start
- All tools share the same authenticated session

### 4. Why separate `_raw_request` method?

- pyfmg expects FortiManager response format
- FortiAnalyzer LogView/Reports return different formats
- `_raw_request` handles:
  - Manual JSON-RPC construction
  - Multiple response format parsing
  - Empty response handling (no `result` field)

### 5. Report Workflow Complexity

FortiAnalyzer reports require:
1. **Layout** (report definition) - read-only blueprints
2. **Schedule** (must exist before running)
3. **Run** (starts generation, returns TID)
4. **Poll** (check progress via `get_running_reports`)
5. **Download** (get data as base64 ZIP)

We abstracted this into `run_and_wait_report` + `save_report`.

---

## File Reference

| File | Lines | Purpose |
|------|-------|---------|
| `server.py` | 519 | MCP server, modes, tool registration |
| `api/client.py` | 1451 | FortiAnalyzer API client |
| `tools/report_tools.py` | 828 | Report generation |
| `tools/log_tools.py` | 700 | Log search |
| `tools/fortiview_tools.py` | 500 | FortiView analytics |
| `tools/system_tools.py` | 400 | System/ADOM/device |
| `tools/dvm_tools.py` | 450 | Device management |
| `tools/event_tools.py` | 300 | Alert management |
| `tools/incident_tools.py` | 300 | Incident management |
| `tools/ioc_tools.py` | 300 | IOC analysis |
| `utils/config.py` | 205 | Configuration |
| `utils/errors.py` | 103 | Exceptions |

**Total: ~6,000 lines of Python code**

---

## Testing Notes

Current test coverage focuses on:
- API client connection/authentication
- Individual tool execution
- Response parsing

To run tests:
```bash
pytest tests/ -v --cov=src/fortianalyzer_mcp
```

---

## Future Improvements

1. **Connection Pooling** - Multiple FAZ connections for parallel requests
2. **Retry Logic** - Automatic retry on transient failures
3. **Caching** - Cache static data (layouts, templates)
4. **Metrics** - Prometheus metrics for monitoring
5. **WebSocket** - Real-time log streaming
