# FortiAnalyzer MCP Server

[![CI](https://github.com/rstierli/fortianalyzer-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rstierli/fortianalyzer-mcp/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.10.0-green)](CHANGELOG.md)
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
- Run higher-level SOC workflows via the skills layer (beta): incident correlation, triage, indicator/threat-intel enrichment, asset & identity lookups, risk scoring, and full incident investigation
- Optionally pseudonymize IOC/PII data before it reaches the model, reversibly (beta)

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
| **Skills Layer** *(beta)* | `faz_skill` dispatcher: 14 opinionated multi-tool orchestrations across data-access, enrichment, and analysis tiers (incident correlation, triage, threat-intel, asset/identity lookups, risk scoring, full investigation) with validated, versioned output schemas — off by default |
| **Data Masking** *(beta)* | Reversible FPE masking of IOC/PII fields (IPs, MACs, hostnames, usernames, domains, emails) in tool outputs, with automatic unmasking of tokens in tool arguments — off by default |

## Requirements

- **Python**: 3.12 or higher
- **FortiAnalyzer**: 7.x with JSON-RPC API access enabled (skills layer requires 7.6.7+)
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

# Skills layer (beta, optional — see "Skills Layer" below)
# FAZ_SKILLS_ENABLED=true

# Reversible data masking (beta, optional — see "Data Masking" below)
# MASKING_ENABLED=true
# FAZ_MASKING_KEY=<32/48/64 hex chars, e.g. from: openssl rand -hex 16>
# FAZ_MASK_DEVICE_IDENTITY=false
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

### Log Tools (11 tools)

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
> **Totals across pages (`total` vs `page_total`):** because `fetch_more_logs`
> re-runs the search for each page, FortiAnalyzer may report a different
> `total-count` from one page to the next even for the same fixed window (rows
> indexed after page 0). To keep the headline figure stable, `total` is the
> handle's **first-page baseline** and stays fixed for every page; `page_total`
> is the raw count observed on the current page. `total_count_stability` is
> `single_observation` (page 0), `stable` (page matches the baseline), `drifted`
> (it differs), or `unknown`; `total_drift_detected` and `total_delta`
> (`page_total - initial_total`) quantify it. `has_more_basis` reports which
> figure drove `has_more` (`stable_total`, `best_effort_max_observed_total`,
> `best_effort_page_total`, or `full_page_heuristic`); it answers a different
> question than `total_count_stability` and the two may legitimately differ. A
> handle is bound to the ADOM `query_logs` ran under — paging it with a different
> `adom` returns `error:"adom_mismatch"`. When a broad/high-volume window reports
> `drifted`, treat the total as **non-exact**: the window is **not
> snapshot-consistent**, so row offsets may shift and individual rows can be
> duplicated or skipped across pages. For exact investigations prefer narrow
> filters and fixed absolute windows away from "now", and rerun controls rather
> than deep offset paging through a drifting high-volume window.
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

### Report Tools (9 tools)

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
`total_hits` is the sum of the per-slice `total-count`s the breakdown searches
already fetch for the same policy/action/device/time filter, so it is at least
`observed_hits` by construction. On heavy policies it is a floor near
`observed_hits`, not the true total; port, protocol, service, and application
breakdowns describe only the fetched rows. Use `observed_hits`,
`total_hits_is_known`, and `total_hit_source` to tell observed row counts from
the summed per-slice total.

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

## Skills Layer (beta)

With `FAZ_SKILLS_ENABLED=true`, one additional tool is registered: `faz_skill(skill, params)` — a dispatcher for opinionated multi-tool orchestrations that return validated, versioned structured results (`schema_version` in every response). Off by default; no behavior change unless enabled.

This is **Waves 1–2** of the skills roadmap — **14 of 18 planned skills**. Wave 3 (behavioral analysis: hunt, root-cause, impact) is designed but not yet implemented; see [RFC #44](https://github.com/rstierli/fortianalyzer-mcp/issues/44). The 14 shipped, grouped by tier:

| Skill | Tier | What it does |
|---|---|---|
| `incidents` | data access | Incidents in a time window, each with attachment-correlated alerts |
| `reports` | data access | List generated reports, or fetch one by task ID (PDF/HTML/CSV/XML) |
| `log_search` | data access | Filter-based log search returning verbatim rows (slot-safe: one search per call) |
| `asset_lookup` | data access | UEBA endpoint profiles with attributed CVE records and per-severity counts |
| `identity_lookup` | data access | Verbatim UEBA end-user records (`extended` detail adds contact fields) |
| `alert_rules` | data access | Detection-rule catalogue: basic + correlation handlers as class-labelled records |
| `threat_intel` | enrichment | Stored SOAR reputation for explicit indicators or those linked to an alert/incident, with a normalized multi-source verdict breakdown (FortiGuard + VirusTotal) and the threat landscape |
| `identity_profile` | enrichment | A user's UEBA record + their endpoints + recent auth-failure/VPN activity |
| `app_usage` | enrichment | Top applications / websites / cloud apps (shadow-IT signal) + DLP events |
| `network_context` | enrichment | Top destinations / sources + geo (top-countries) + site-to-site IPsec tunnels |
| `risk_assessment` | enrichment | Transparent, fully-auditable composite 0-100 score over CVE / threat / auth-failure dimensions |
| `triage` | analysis | Evidence bundle + deterministic severity-derived assessment for one alert or incident |
| `incident_summary` | analysis | Structured incident summary: related alerts with evidence logs, threat landscape, timeline |
| `investigate` | analysis | One consolidated investigation of an alert/incident — triage + summary + indicator enrichment + asset/identity context, composed from the skills above; each section degrades independently |

Every skill returns a versioned pydantic result (`schema_version` in every response), takes `extra="forbid"` params, and is read-only. Enrichment/context sections degrade independently to a documented `FeatureGap` marker when a data source is unlicensed or unavailable — only a failed *subject* fails the skill.

In normal use you describe the task in natural language and the model builds the `faz_skill` call; the JSON forms below are what that produces (all parameters except the ones noted are optional, with sensible defaults).

**`incidents`** — incidents in a window with correlated alerts:
```jsonc
faz_skill(skill="incidents")                                    // last 7 days, up to 50
faz_skill(skill="incidents", params={"time_range": "24-hour", "filter": "severity==high"})
faz_skill(skill="incidents", params={"limit": 100, "include_alerts": false})  // faster, no correlation
```

**`reports`** — list report history or fetch one:
```jsonc
faz_skill(skill="reports")                                      // list the last 7 days of reports
faz_skill(skill="reports", params={"action": "list", "title": "Weekly Security"})
faz_skill(skill="reports", params={"action": "fetch", "tid": 528613989, "output_format": "PDF"})
```

**`log_search`** — one filter-based search, verbatim rows:
```jsonc
faz_skill(skill="log_search", params={"filter": "srcip==10.0.0.5", "time_range": "1-hour"})
faz_skill(skill="log_search", params={"logtype": "ips", "filter": "severity==critical", "limit": 200})
```

**`triage`** — evidence + assessment for exactly one subject (`alert_id` **or** `incident_id`):
```jsonc
faz_skill(skill="triage", params={"incident_id": "IN00000019"})
faz_skill(skill="triage", params={"alert_id": "202606121000000041", "context_time_range": "7-day"})
```

**`incident_summary`** — structured writeup of one incident (`incident_id` required):
```jsonc
faz_skill(skill="incident_summary", params={"incident_id": "IN00000019"})
faz_skill(skill="incident_summary", params={"incident_id": "IN00000019", "time_range": "30-day", "max_alerts": 25})
```

**`asset_lookup` / `identity_lookup` / `alert_rules`** — UEBA and detection-rule data access:
```jsonc
faz_skill(skill="asset_lookup", params={"hostname": "ws-finance"})       // endpoints + attributed CVEs
faz_skill(skill="asset_lookup", params={"epids": [4561], "include_vulnerabilities": true})
faz_skill(skill="identity_lookup", params={"username": "roland", "detail_level": "extended"})
faz_skill(skill="alert_rules", params={"handler_type": "correlation"})
```

**`threat_intel`** — stored SOAR reputation (needs SOAR licensed); explicit indicators or those linked to a subject:
```jsonc
faz_skill(skill="threat_intel", params={"indicators": [{"value": "203.0.113.7", "type": "IP"}]})
faz_skill(skill="threat_intel", params={"incident_id": "IN00000019", "detail_level": "extended"})
```
With `detail_level="extended"`, each indicator carries a `sources[]` breakdown normalizing every reputation engine — e.g. FortiGuard-CTS verdict alongside the VirusTotal detection ratio — while the verbatim per-engine payload stays under `record.enrichment-detail`.

**`identity_profile` / `app_usage` / `network_context` / `risk_assessment`** — enrichment bundles:
```jsonc
faz_skill(skill="identity_profile", params={"euid": 3})                  // user + endpoints + auth activity
faz_skill(skill="app_usage", params={"time_range": "24-hour"})          // apps/websites/cloud + DLP
faz_skill(skill="network_context", params={"time_range": "7-day"})      // top dests/sources + geo + IPsec
faz_skill(skill="risk_assessment", params={"euid": 3})                   // transparent composite 0-100 score
```

**`investigate`** — one consolidated view of a subject, composed from the skills above (`alert_id` **or** `incident_id`):
```jsonc
faz_skill(skill="investigate", params={"incident_id": "IN00000019"})
faz_skill(skill="investigate", params={"alert_id": "202606121000000041", "detail_level": "extended"})
```

- `faz_skill(skill="list")` (alias `"describe"`) returns the machine-readable catalogue including each skill's parameter and output JSON schema.
- All skills are read-only and additive — zero changes to the existing tools.
- Requires FortiAnalyzer **7.6.7+**. Not available in `FAZ_TOOL_MODE=dynamic` (beta limitation).
- Skill ids and output schemas are a stable contract; breaking changes bump `schema_version`.

## Data Masking (beta)

With `MASKING_ENABLED=true` (requires `FAZ_MASKING_KEY`), sensitive identifiers are pseudonymized before they leave the server toward the LLM, and masked tokens the model sends back as tool arguments are resolved to real values before input validation and the FortiAnalyzer API. Off by default; no behavior change unless enabled.

- **What masks:** IPv4/IPv6, MACs, hostnames, usernames (case-preserving), domains and emails across allowlisted fields at any nesting depth, composite keys (`groupby1`, `grpby`, `target[]`, `devvds`, `http_url`, the fortiview `threat`/`obf_url` pair), and free-text fields (`msg`, `subject`, echoed filters, ...).
- **Token design:** deterministic format-preserving encryption (NIST FF3-1) — the same value always yields the same token, so the model can correlate across calls, and values are recoverable from the key alone (no token vault). Hostname/username/domain/email tokens carry recognizable markers plus a short key-id, so tokens from a rotated key fail loudly instead of decrypting to plausible wrong values.
- **Fail-closed:** an unmaskable value becomes an irreversible placeholder; if masking a response fails entirely, the raw result is withheld behind a `masking_failed` error.
- **Device identity** (`devname`, `devid`, `sn`, ...) stays readable by default so the model can reason about which appliance saw what; set `FAZ_MASK_DEVICE_IDENTITY=true` to mask it too.
- **Key handling:** `FAZ_MASKING_KEY` is a 32/48/64-hex-char AES key (`openssl rand -hex 16`). Rotating the key invalidates previously issued tokens by design.
- **Documented limits (beta):** masked IPs/MACs carry no marker (a full address space cannot be marked), so an operator-typed real IP in an argument is indistinguishable from a token; URL *hosts* are masked inside `http_url` but URL paths/queries are not; the model's final prose is outside the MCP's reach and needs a client-side companion (planned).

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

Note: the skills layer is not available in dynamic mode (beta limitation); `FAZ_SKILLS_ENABLED` is ignored there with a warning.

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
│   ├── skills/                # Skills layer (beta, FAZ_SKILLS_ENABLED)
│   │   ├── catalog.py         # Skill registry + machine-readable catalogue
│   │   ├── dispatcher.py      # The faz_skill dispatcher tool
│   │   ├── handlers.py        # Skill orchestrations over the raw tools
│   │   └── models.py          # Pydantic parameter/output schemas (versioned)
│   ├── masking/               # Reversible data masking (beta, MASKING_ENABLED)
│   │   ├── fields.py          # Verified field allowlist + type tables
│   │   ├── fpe_engine.py      # FF3-1 format-preserving token engine
│   │   ├── unmask.py          # Tool-argument unmasking (tokens -> real values)
│   │   └── wrapper.py         # Tool-boundary output masking
│   ├── utils/
│   │   ├── config.py          # Configuration management
│   │   ├── errors.py          # Error handling
│   │   ├── log_clock.py       # FAZ time-basis handling
│   │   ├── responses.py       # Shared response helpers
│   │   ├── time_range.py      # Time-range parsing (single source of truth)
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
