# FortiAnalyzer MCP Server

[![CI](https://github.com/rstierli/fortianalyzer-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rstierli/fortianalyzer-mcp/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.3.0-green)](CHANGELOG.md)
[![FortiAnalyzer](https://img.shields.io/badge/FortiAnalyzer-7.0%20%7C%207.2%20%7C%207.4%20%7C%207.6%20%7C%208.0-red)](README.md)

A Model Context Protocol (MCP) server for FortiAnalyzer JSON-RPC API. This server enables AI assistants like Claude to interact with FortiAnalyzer for log analysis, reporting, security monitoring, and SOC operations.

> **Note**: This is an independent open-source project and is not affiliated with, endorsed by, or supported by Fortinet, Inc. FortiAnalyzer is a trademark of Fortinet, Inc.

> **Disclaimer:** This is an independent community project, not affiliated with or supported by Fortinet. Use at your own risk. Always validate changes in a non-production environment before applying to production systems.

## Overview

This MCP server provides a comprehensive interface to FortiAnalyzer's capabilities, allowing AI assistants to:

- Query and analyze security logs (traffic, threat, event logs)
- Generate and download reports
- Monitor real-time analytics via FortiView
- Manage security alerts and incidents
- Perform IOC (Indicators of Compromise) analysis
- Manage devices and ADOMs

## Features

| Category | Capabilities |
|----------|-------------|
| **Log Analysis** | Query traffic, security, and event logs with filters; get log statistics |
| **PCAP Downloads** | Search IPS logs, download PCAP files by session ID or bulk download matching criteria |
| **Reports** | List layouts, run reports, monitor progress, download in PDF/HTML/CSV/XML |
| **FortiView Analytics** | Top sources, destinations, applications, threats, websites, cloud apps |
| **Alerts & Events** | Get alerts, acknowledge, add comments, view alert logs and statistics |
| **Incident Management** | Create, update, track incidents; get incident statistics |
| **IOC Analysis** | Run IOC rescans, check license status, view rescan history |
| **Device Management** | List/add/delete devices, manage device groups and VDOMs |
| **System** | System status, HA status, ADOM management, task monitoring |

## Requirements

- **Python**: 3.12 or higher
- **FortiAnalyzer**: 7.x with JSON-RPC API access enabled
- **Authentication**: API token (recommended) or username/password
- **Network**: HTTPS access to FortiAnalyzer management interface

## Installation

### Using uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/rstierli/fortianalyzer-mcp.git
cd fortianalyzer-mcp

# Create and activate virtual environment
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
uv sync
```

### Using pip

```bash
# Clone the repository
git clone https://github.com/rstierli/fortianalyzer-mcp.git
cd fortianalyzer-mcp

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install package
pip install -e .
```

### Using Docker

Pre-built images are available on GitHub Container Registry:

```bash
docker pull ghcr.io/rstierli/fortianalyzer-mcp:latest
```

Quick start with Docker Compose:

```yaml
# docker-compose.yml
services:
  fortianalyzer-mcp:
    image: ghcr.io/rstierli/fortianalyzer-mcp:latest
    container_name: fortianalyzer-mcp
    restart: unless-stopped
    ports:
      - "8001:8001"
    env_file:
      - .env
    environment:
      - MCP_SERVER_MODE=http
      - MCP_SERVER_HOST=0.0.0.0
      - MCP_SERVER_PORT=8001
      - FORTIANALYZER_HOST=your-faz-hostname
      - FORTIANALYZER_VERIFY_SSL=true
      - DEFAULT_ADOM=root
      - FAZ_TOOL_MODE=full
      - LOG_LEVEL=INFO
```

> **Security:** Keep `FORTIANALYZER_VERIFY_SSL=true`. For a self-signed FAZ,
> import the FAZ CA certificate into the container trust store rather than
> disabling verification (disabling it exposes the FAZ API token to MITM).
> In HTTP mode, binding to `0.0.0.0` with no `MCP_AUTH_TOKEN` leaves every tool
> unauthenticated — always set a strong token (below) and, where possible,
> publish the port only on an internal interface (e.g. `127.0.0.1:8001:8001`).

Create a `.env` file for secrets (not tracked in git):

```bash
# .env
FORTIANALYZER_API_TOKEN=your-api-token
# Required when running HTTP mode reachable beyond localhost — without it,
# every tool is exposed unauthenticated. Generate with: openssl rand -hex 32
MCP_AUTH_TOKEN=your-secret-bearer-token
```

```bash
chmod 600 .env
docker compose up -d
```

Verify the server is running:

```bash
curl http://localhost:8001/health
# {"status": "healthy", "service": "fortianalyzer-mcp", "fortianalyzer_connected": true}
```

## Configuration

### Environment Variables

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Edit `.env` with your FortiAnalyzer settings:

```bash
# FortiAnalyzer Connection (Required)
FORTIANALYZER_HOST=192.168.1.100

# Authentication Option 1: API Token (Recommended for FAZ 7.2.2+)
FORTIANALYZER_API_TOKEN=your-api-token-here

# Authentication Option 2: Username/Password
# FORTIANALYZER_USERNAME=admin
# FORTIANALYZER_PASSWORD=your-password

# SSL Verification (keep true; import the FAZ CA for self-signed certs
# instead of disabling — see the security note above)
FORTIANALYZER_VERIFY_SSL=true

# Request Settings
FORTIANALYZER_TIMEOUT=30
FORTIANALYZER_MAX_RETRIES=3

# Default ADOM (optional, defaults to "root")
DEFAULT_ADOM=root

# Logging
LOG_LEVEL=INFO  # DEBUG for troubleshooting

# HTTP Authentication (optional, recommended for Docker/HTTP deployments)
# MCP_AUTH_TOKEN=your-secret-token

# Allowed Host headers for HTTP/Docker deployments (optional)
# Set to the value clients use in their connection URL — NOT the client's IP.
# The MCP SDK rejects non-localhost Host headers by default for DNS rebinding protection.
# Examples: ["mcp.example.com"], ["10.1.5.62:8001"], or wildcard ["10.1.5.62:*"]
# MCP_ALLOWED_HOSTS=["mcp.example.com"]
```

### Generating an API Token

1. Log into FortiAnalyzer web interface
2. Go to **System Settings** > **Admin** > **Administrators**
3. Edit your admin user or create a new one
4. Under **JSON API Access**, click **Regenerate** or **New API Key**
5. Copy the generated token

## Running the Server

### Standalone Mode

```bash
# Using the installed command
fortianalyzer-mcp

# Or using Python module
python -m fortianalyzer_mcp
```

### Claude Desktop Integration

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "fortianalyzer": {
      "command": "/path/to/fortianalyzer-mcp/.venv/bin/fortianalyzer-mcp",
      "env": {
        "FORTIANALYZER_HOST": "your-faz-hostname",
        "FORTIANALYZER_API_TOKEN": "your-api-token",
        "FORTIANALYZER_VERIFY_SSL": "true",
        "DEFAULT_ADOM": "root",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Note**: Use the full path to the `fortianalyzer-mcp` executable in your virtual environment. The `DEFAULT_ADOM` setting is optional and defaults to "root" if not specified.

### Claude Code Integration

Add to `~/.claude/mcp_servers.json`:

```json
{
  "mcpServers": {
    "fortianalyzer": {
      "command": "/path/to/fortianalyzer-mcp/.venv/bin/fortianalyzer-mcp",
      "env": {
        "FORTIANALYZER_HOST": "your-faz-hostname",
        "FORTIANALYZER_API_TOKEN": "your-api-token",
        "FORTIANALYZER_VERIFY_SSL": "true",
        "DEFAULT_ADOM": "root",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Docker Mode

```bash
# Start the server
docker compose up -d

# View logs
docker compose logs -f

# Stop the server
docker compose down
```

### HTTP Mode (Remote Access)

When running in HTTP mode (Docker or standalone with `MCP_SERVER_MODE=http`), MCP clients connect via the Streamable HTTP transport:

**Claude Code** (`~/.claude/mcp_servers.json`):

```json
{
  "mcpServers": {
    "fortianalyzer": {
      "type": "streamable-http",
      "url": "https://your-mcp-host.example.com/mcp",
      "headers": {
        "Authorization": "Bearer your-mcp-auth-token"
      }
    }
  }
}
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "fortianalyzer": {
      "type": "streamable-http",
      "url": "https://your-mcp-host.example.com/mcp",
      "headers": {
        "Authorization": "Bearer your-mcp-auth-token"
      }
    }
  }
}
```

### Production Deployment (Reverse Proxy)

For production deployments behind a TLS-terminating reverse proxy:

```
MCP Client → HTTPS → Reverse Proxy (Traefik/nginx) → HTTP → MCP Container → FortiAnalyzer
```

**Key considerations:**

1. **MCP_ALLOWED_HOSTS** — The MCP SDK validates the Host header to prevent DNS rebinding attacks. By default only `localhost` and `127.0.0.1` are accepted. Set this to the value clients put in their connection URL (NOT the client's IP):

   ```bash
   # Reverse-proxy hostname (Traefik/nginx):
   MCP_ALLOWED_HOSTS=["mcp.example.com"]
   # Direct Docker exposure on IP+port:
   MCP_ALLOWED_HOSTS=["10.1.5.62:8001"]
   # Port wildcard (any port on the host):
   MCP_ALLOWED_HOSTS=["10.1.5.62:*"]
   ```

2. **MCP_AUTH_TOKEN** — Always set a Bearer token for HTTP deployments. If it is unset, the server runs **fail-open**: every tool (log search, device add/delete, PCAP download) is exposed unauthenticated to anyone who can reach the port.

   ```bash
   MCP_AUTH_TOKEN=$(openssl rand -hex 32)
   ```

3. **Secrets management** — Keep API tokens and auth tokens in an `env_file` (`.env`), not inline in `docker-compose.yml`.

**Example with Traefik:**

```yaml
services:
  fortianalyzer-mcp:
    image: ghcr.io/rstierli/fortianalyzer-mcp:latest
    container_name: fortianalyzer-mcp
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    env_file:
      - .env
    environment:
      - MCP_SERVER_MODE=http
      - MCP_SERVER_HOST=0.0.0.0
      - MCP_SERVER_PORT=8001
      - FORTIANALYZER_HOST=your-faz-hostname
      - FORTIANALYZER_VERIFY_SSL=true
      - MCP_ALLOWED_HOSTS=["mcp.example.com"]
      - DEFAULT_ADOM=root
      - FAZ_TOOL_MODE=full
      - LOG_LEVEL=INFO
    networks:
      - frontend
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.faz-mcp-secure.entrypoints=https"
      - "traefik.http.routers.faz-mcp-secure.rule=Host(`mcp.example.com`)"
      - "traefik.http.routers.faz-mcp-secure.tls=true"
      - "traefik.http.services.faz-mcp.loadbalancer.server.port=8001"
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  frontend:
    external: true
```

## Available Tools

### System Tools (11 tools)

| Tool | Description |
|------|-------------|
| `get_system_status` | Get FortiAnalyzer system status and version info |
| `get_ha_status` | Get High Availability cluster status |
| `list_adoms` | List all Administrative Domains |
| `get_adom` | Get specific ADOM details |
| `list_devices` | List devices in an ADOM |
| `get_device` | Get specific device information |
| `list_tasks` | List background tasks |
| `get_task` | Get task details by ID |
| `wait_for_task` | Wait for a task to complete |
| `get_api_ratelimit` | Get API rate limiting configuration (FAZ 7.6.5+) |
| `update_api_ratelimit` | Update API rate limits (FAZ 7.6.5+) |

### Device Management Tools (8 tools)

| Tool | Description |
|------|-------------|
| `list_device_groups` | List device groups in an ADOM |
| `list_device_vdoms` | List VDOMs for a device |
| `add_device` | Add a new device to FortiAnalyzer |
| `delete_device` | Remove a device from FortiAnalyzer |
| `add_devices_bulk` | Add multiple devices at once |
| `delete_devices_bulk` | Remove multiple devices at once |
| `get_device_info` | Get detailed device information |
| `search_devices` | Search devices with filters |

### Log Tools (12 tools)

| Tool | Description |
|------|-------------|
| `query_logs` | Query logs; returns a page plus a reusable pagination handle, `total`, `has_more`, and FAZ timezone |
| `get_log_search_progress` | Check log search progress |
| `fetch_more_logs` | Fetch another page for a `query_logs` handle (re-runs the query at a new offset) |
| `cancel_log_search` | Release a pagination handle |
| `get_log_stats` | Get log statistics |
| `get_log_fields` | Get available log fields for a log type |
| `search_traffic_logs` | Search traffic/firewall logs |
| `search_security_logs` | Search IPS/AV/web filter logs |
| `search_event_logs` | Search system event logs |
| `get_logfiles_state` | Get log file state information |
| `get_pcap_file` | Download PCAP file for an IPS event |

> **Paginating log results:** call `query_logs(..., limit=N)`, then page with
> `fetch_more_logs(tid=<handle>, offset=next_offset, limit=...)`. The returned
> `tid` is a reusable pagination handle — FortiAnalyzer logsearch task ids are
> single-use, so `fetch_more_logs` re-runs the same query at the new offset
> (results are stably ordered for a fixed time window). Both tools return
> `total` / `total_is_known`, `has_more`, `next_offset` (the offset for the next
> page, or `null` when exhausted), `offset`/`limit`, and a `warnings` list (set
> when the limit was clamped, the total is unknown, the timezone is undetected,
> or the result set is large enough that the bounded policy tools are a better
> fit). A 0-result search is a clean `status:"success"` with `count:0` and
> `has_more:false`. Call `cancel_log_search(tid=<handle>)` when finished; an
> expired/unknown handle returns `error:"tid_invalid_or_expired"`.
>
> **Time & timezone:** `time_range` accepts presets (`1-hour` … `24-hour`,
> `7-day`, `30-day`, `90-day`) or a custom
> `"YYYY-MM-DD HH:MM:SS|YYYY-MM-DD HH:MM:SS"` window. Timestamps are interpreted
> in the FAZ system timezone reported as `timezone`. For a 7-day or 30-day
> investigation, set `time_range="7-day"` / `"30-day"` on `query_logs`, the
> `search_*` helpers, or the policy tools and add the filters you need
> (`action==accept`/`deny`, `policyid==N`, `srcip`/`dstip`/`dstport`, …).
>
> **Errors:** every tool error returns one envelope —
> `{status:"error", error:<code>, message, operation, retry_count}` plus
> `adom`/`logtype`/`tid` where relevant.
>
> **Filters:** the `search_*` helpers validate/sanitize their typed arguments;
> the raw `filter=` argument on `query_logs` is a caller-controlled expert escape
> hatch and is **not** parsed for injection safety — pass trusted input only.

### Report Tools (8 tools)

| Tool | Description |
|------|-------------|
| `list_report_layouts` | List available report layouts |
| `run_report` | Start a report generation |
| `fetch_report` | Check report generation status |
| `get_report_data` | Download completed report data |
| `get_running_reports` | List currently running reports |
| `get_report_history` | Get report generation history |
| `run_and_wait_report` | Run report and wait for completion |
| `save_report` | Download and save report to disk |

### FortiView Analytics Tools (10 tools)

| Tool | Description |
|------|-------------|
| `run_fortiview` | Start a FortiView analytics query |
| `fetch_fortiview` | Fetch FortiView query results |
| `get_fortiview_data` | Run FortiView and get results (auto-wait) |
| `get_top_sources` | Get top traffic sources |
| `get_top_destinations` | Get top traffic destinations |
| `get_top_applications` | Get top applications by bandwidth |
| `get_top_threats` | Get top security threats |
| `get_top_websites` | Get top accessed websites |
| `get_top_cloud_applications` | Get top cloud/SaaS applications |
| `get_policy_hits` | Get firewall policy hit counts |

### Event/Alert Tools (8 tools)

| Tool | Description |
|------|-------------|
| `get_alerts` | Get security alerts |
| `get_alert_count` | Get alert count |
| `acknowledge_alerts` | Mark alerts as acknowledged |
| `unacknowledge_alerts` | Remove acknowledgment from alerts |
| `get_alert_logs` | Get logs associated with alerts |
| `get_alert_details` | Get detailed alert information |
| `add_alert_comment` | Add comment to an alert |
| `get_alert_incident_stats` | Get alert and incident statistics |

### Incident Management Tools (6 tools)

| Tool | Description |
|------|-------------|
| `get_incidents` | List incidents |
| `get_incident` | Get specific incident details |
| `get_incident_count` | Get incident count |
| `create_incident` | Create a new incident |
| `update_incident` | Update incident status/details |
| `get_incident_stats` | Get incident statistics |

### IOC Tools (6 tools)

| Tool | Description |
|------|-------------|
| `get_ioc_license_state` | Check IOC license status |
| `acknowledge_ioc_events` | Acknowledge IOC events |
| `run_ioc_rescan` | Start an IOC rescan |
| `get_ioc_rescan_status` | Check rescan progress |
| `get_ioc_rescan_history` | Get rescan history |
| `run_and_wait_ioc_rescan` | Run rescan and wait for completion |

### Traffic Analysis Tools (3 tools)

| Tool | Description |
|------|-------------|
| `get_policy_traffic_profile` | Get sampled traffic summary per policy (top ports, services, apps) |
| `get_policy_port_analysis` | Get bounded port/protocol enumeration per policy with conservative `is_exact` semantics |
| `get_policy_protocol_summary` | Get lightweight protocol breakdown (TCP/UDP/ICMP/other) per policy |

Traffic analysis tools keep large windows practical by scanning a fixed, bounded
number of log slices per request. A result is marked `is_exact=true` only when
every queried slice returns below the per-slice log limit. If any slice reaches
the limit, the tool returns observed results with `analysis_mode=bounded_sample`,
truncation metadata, and a recommendation to narrow the time window for exact proof.
For bounded samples, `total_hits` comes from a whole-window FortiAnalyzer
log-search `total-count` for the same policy/action/device/time filter when
available, but port, protocol, service, and application breakdowns still
describe only the fetched rows. Use `observed_hits`, `total_hits_is_known`, and
`total_hit_source` to distinguish observed row counts from authoritative
matching-log totals.

### PCAP Tools (5 tools)

| Tool | Description |
|------|-------------|
| `search_ips_logs` | Search IPS/attack logs with filters (severity, attack, CVE, IPs) |
| `get_pcap_by_session` | Download PCAP file for a specific session ID |
| `download_pcap_by_url` | Download PCAP using pcapurl from search results |
| `search_and_download_pcaps` | Search and automatically download all matching PCAPs |
| `list_available_pcaps` | List IPS events that have PCAP files available |

## Usage Examples

### Querying Logs

```
"Show me the last 50 traffic logs from the past hour"
"Search for any blocked traffic to IP 10.0.0.1"
"Find all IPS attack logs with critical severity"
```

### Running Reports

```
"List available report layouts"
"Run the 'Bandwidth and Applications Report' for the last 7 days"
"Download the completed report as PDF"
```

### FortiView Analytics

```
"Show me the top 10 bandwidth consumers"
"What are the top threats detected in the last 24 hours?"
"List the most accessed websites today"
```

### Alert Management

```
"Show me all unacknowledged alerts"
"Acknowledge alert ID 12345"
"Add a comment to the alert: 'Investigating this issue'"
```

### PCAP Downloads

```
"Search for critical IPS attacks in the last 7 days"
"Download the PCAP file for session ID 906654"
"Download all PCAPs for attacks from IP 192.168.1.100"
"List all attacks that have PCAP files available"
"Download all critical severity attack PCAPs from the last 24 hours"
```

### System Information

```
"What is the FortiAnalyzer system status?"
"List all devices in the root ADOM"
"Show me the HA cluster status"
```

## Tool Modes

### Full Mode (Default)

All tools are loaded, providing complete functionality. Best for environments with large context windows.

```bash
FAZ_TOOL_MODE=full
```

### Dynamic Mode

Only discovery tools are loaded initially, reducing context usage by ~90%. Use `find_fortianalyzer_tool()` to discover available tools and `execute_advanced_tool()` to run them.

```bash
FAZ_TOOL_MODE=dynamic
```

## Architecture

```
fortianalyzer-mcp/
├── src/fortianalyzer_mcp/
│   ├── api/
│   │   └── client.py          # FortiAnalyzer API client (JSON-RPC)
│   ├── tools/
│   │   ├── dvm_tools.py       # Device management tools
│   │   ├── event_tools.py     # Alert and event tools
│   │   ├── fortiview_tools.py # FortiView analytics tools
│   │   ├── incident_tools.py  # Incident management tools
│   │   ├── ioc_tools.py       # IOC analysis tools
│   │   ├── log_tools.py       # Log query tools
│   │   ├── pcap_tools.py      # PCAP download tools
│   │   ├── report_tools.py    # Report generation tools
│   │   ├── system_tools.py    # System and ADOM tools
│   │   └── traffic_tools.py   # Policy traffic analysis tools
│   ├── utils/
│   │   ├── config.py          # Configuration management
│   │   ├── errors.py          # Error handling
│   │   └── validation.py      # Input validation and log sanitization
│   └── server.py              # MCP server implementation
├── tests/                     # Test suite
├── docs/                      # Additional documentation
├── .env.example               # Example configuration
├── pyproject.toml             # Project configuration
├── Dockerfile                 # Container image definition
└── docker-compose.yml         # Container orchestration
```

## API Reference

The server communicates with FortiAnalyzer using the JSON-RPC API over HTTPS. All requests are sent to the `/jsonrpc` endpoint.

### Supported FortiAnalyzer Versions

- FortiAnalyzer 7.0.x
- FortiAnalyzer 7.2.x
- FortiAnalyzer 7.4.x
- FortiAnalyzer 7.6.x (tested)
- FortiAnalyzer 8.0.x (tested against 8.0.0 GA)

### Authentication Methods

1. **API Token** (Recommended)
   - More secure, no session management
   - Tokens can be revoked without changing passwords
   - Required for FortiAnalyzer 7.2.2+

2. **Username/Password**
   - Traditional session-based authentication
   - Session automatically managed by the client

## Troubleshooting

### Enable Debug Logging

Set `LOG_LEVEL=DEBUG` in your environment to see detailed API requests and responses:

```bash
LOG_LEVEL=DEBUG fortianalyzer-mcp
```

### Common Issues

**Connection Failed**
- Verify FortiAnalyzer hostname/IP is correct
- Check network connectivity and firewall rules
- Ensure HTTPS port (443) is accessible

**Authentication Failed**
- Verify API token or credentials are correct
- Check if the admin account has API access enabled
- Ensure the account has sufficient permissions

**SSL Certificate Errors**
- Preferred fix: import the FortiAnalyzer CA certificate into your system/container trust store so verification succeeds
- `FORTIANALYZER_VERIFY_SSL=false` works around self-signed certs but is insecure — it exposes the FAZ API token and all log/PCAP data to man-in-the-middle interception. Avoid it outside isolated lab use.
- For production, use a valid (CA-trusted) SSL certificate on the FAZ

**Report Generation Issues**
- Ensure the report layout exists (use `list_report_layouts`)
- Verify the ADOM has the required data for the report
- Check FortiAnalyzer has sufficient disk space

### MCP Transport Issues

**`Invalid Host header` (HTTP/Docker mode)**

Symptom — server logs show:

```
mcp.server.transport_security - WARNING - Invalid Host header: 10.x.y.z:8001
INFO:     ... "POST /mcp HTTP/1.1" 421 Misdirected Request
```

Cause: the MCP SDK validates the Host header for DNS rebinding protection. By default only `localhost` and `127.0.0.1` are accepted. The header value is whatever the **client** puts in its connection URL — not the client's IP.

Fix: add the URL value (with port, if used) to `MCP_ALLOWED_HOSTS`:

```bash
# If the client connects to http://10.1.5.62:8001/mcp:
MCP_ALLOWED_HOSTS=["10.1.5.62:8001"]
# Or use a port wildcard to allow any port on that host:
MCP_ALLOWED_HOSTS=["10.1.5.62:*"]
# For a reverse-proxy hostname:
MCP_ALLOWED_HOSTS=["mcp.example.com"]
```

**`PermissionError: pyvenv.cfg` (macOS stdio mode)**

Symptom — Claude Desktop MCP logs show:

```
Fatal Python error: init_import_site: Failed to import the site module
PermissionError: [Errno 1] Operation not permitted: '.../.venv/pyvenv.cfg'
```

Cause: macOS TCC (Transparency, Consent, Control) blocks Claude Desktop from launching executables from inside `~/Documents`, `~/Desktop`, or `~/Downloads`.

Fix (preferred): move the project out of those folders, recreate the venv, and update Claude Desktop's MCP config to the new path:

```bash
mv ~/Documents/mcp ~/mcp
cd ~/mcp/fortianalyzer-mcp
rm -rf .venv && uv sync
# Then update the "command" path in claude_desktop_config.json
```

Fix (alternative): grant Claude Desktop **Full Disk Access** — System Settings → Privacy & Security → Full Disk Access → add Claude. Broader permission; only use if relocation isn't feasible.

### Viewing Logs

**Claude Desktop MCP Server Logs**:
- macOS: `~/Library/Logs/Claude/mcp-server-fortianalyzer.log`
- Windows: `%APPDATA%\Claude\logs\mcp-server-fortianalyzer.log`

## Development

### Running Tests

The project includes 290+ tests covering all tool modules, error handling, and validation logic.

```bash
# Install dev dependencies
uv sync --all-extras

# Run all unit tests
pytest

# Run with coverage report
pytest --cov=src/fortianalyzer_mcp --cov-report=html

# Run specific test file
pytest tests/test_log_tools.py -v

# Run tests with verbose output
pytest -v
```

### Integration Tests

Integration tests require a real FortiAnalyzer instance and are not run in CI.

```bash
# Set up environment
export FORTIANALYZER_HOST=your-faz-host
export FORTIANALYZER_API_TOKEN=your-token
# Only for an isolated lab FAZ with a self-signed cert; keep true otherwise.
export FORTIANALYZER_VERIFY_SSL=false

# Run integration tests (requires live FAZ)
pytest tests/integration/ -v
```

**Note**: Integration tests are verified against FortiAnalyzer 7.6.2. Some features (like API rate limiting) require FAZ 7.6.5+.

### CI Workflow

The project uses GitHub Actions for continuous integration:

- **Linting**: ruff check on all source files
- **Type checking**: mypy with strict mode
- **Unit tests**: pytest with coverage reporting
- **Python versions**: 3.12+

All CI checks must pass before merging pull requests.

### Code Quality

```bash
# Linting
ruff check src/

# Type checking
mypy src/

# Formatting
ruff format src/
```

## Security Considerations

### HTTP Authentication

When running in HTTP mode (Docker), you can secure the MCP endpoint with Bearer token authentication:

```bash
# Set in .env or environment
MCP_AUTH_TOKEN=your-secret-token
```

When configured, all HTTP requests (except `/health`) must include the `Authorization: Bearer <token>` header. If not set, the server runs **fail-open**: it accepts all requests without authentication (kept for backwards compatibility). In HTTP mode this means every tool — including device add/delete and PCAP download — is reachable by anyone who can connect to the port. Always set `MCP_AUTH_TOKEN` for any HTTP deployment reachable beyond `127.0.0.1`, and prefer binding to an internal interface.

### Environment File Permissions

Protect your `.env` files containing API tokens:

```bash
chmod 600 .env .env.*
```

### General Security

- **API Tokens**: Store tokens securely, never commit to version control
- **SSL Verification**: Enable SSL verification in production environments
- **Least Privilege**: Use FortiAnalyzer accounts with minimal required permissions
- **Network Security**: Restrict access to FortiAnalyzer management interface
- **Credential Sanitization**: Device credentials are automatically stripped from API responses

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to submit bug reports, feature requests, and pull requests.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Anthropic](https://anthropic.com) for the [Model Context Protocol](https://modelcontextprotocol.io)
- [Fortinet](https://fortinet.com) for FortiAnalyzer
- [@inxbit](https://github.com/inxbit) for policy usage analysis design concepts (exact-vs-sampled semantics, `is_exact` fail-closed model)

## Related Projects

- [fortimanager-mcp](https://github.com/rstierli/fortimanager-mcp) - MCP server for FortiManager with 100+ tools
