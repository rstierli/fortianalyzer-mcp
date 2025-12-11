# FortiAnalyzer MCP Server - Setup Guide

This guide explains how to set up and use the FortiAnalyzer MCP server with Claude Desktop and other MCP clients.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Claude Desktop Setup](#claude-desktop-setup)
5. [Testing the Connection](#testing-the-connection)
6. [Available Tools](#available-tools)
7. [Example Conversations](#example-conversations)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **Python 3.12+** installed
- **FortiAnalyzer** instance (7.4.x, 7.6.x, or 8.0.x supported)
- **FortiAnalyzer API credentials** (API token recommended, or username/password)
- **Claude Desktop** application installed

### FortiAnalyzer API Token Setup

1. Log in to FortiAnalyzer GUI as admin
2. Navigate to **System Settings** → **Admin** → **Administrators**
3. Edit your admin user or create a new API user
4. Enable **JSON API Access**
5. Generate an **API Key** (recommended over password auth)
6. Copy the API key - you'll need it for configuration

---

## Installation

### Option 1: Using uv (Recommended)

[uv](https://github.com/astral-sh/uv) is a fast Python package manager. Install it first if you don't have it:

```bash
# Install uv (macOS/Linux)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or with Homebrew
brew install uv
```

Then install the FortiAnalyzer MCP server:

```bash
cd /Users/rstierli/myCoding/API/fortianalyzer-mcp

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate
uv pip install -e .
```

### Option 2: Using pip

```bash
cd /Users/rstierli/myCoding/API/fortianalyzer-mcp

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the package in development mode
pip install -e .
```

---

## Configuration

The MCP server is configured via environment variables. You can set these in:
- A `.env` file in the project directory
- Shell environment variables
- Claude Desktop's MCP configuration

### Required Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `FORTIANALYZER_HOST` | FortiAnalyzer hostname/IP | `faz.example.com` |
| `FORTIANALYZER_API_TOKEN` | API token (recommended) | `your-api-token` |

### Optional Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `FORTIANALYZER_USERNAME` | Username (if not using token) | - |
| `FORTIANALYZER_PASSWORD` | Password (if not using token) | - |
| `FORTIANALYZER_VERIFY_SSL` | Verify SSL certificates | `true` |
| `FORTIANALYZER_TIMEOUT` | Request timeout (seconds) | `30` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `FAZ_TOOL_MODE` | Tool loading mode (`full`/`dynamic`) | `full` |

### Example .env File

Create a `.env` file in the project root:

```bash
# FortiAnalyzer Connection
FORTIANALYZER_HOST=faz-prod-02.home.mystier.li
FORTIANALYZER_API_TOKEN=your-api-token-here
FORTIANALYZER_VERIFY_SSL=false

# Logging
LOG_LEVEL=INFO
```

---

## Claude Desktop Setup

### Step 1: Locate Claude Desktop Configuration

The Claude Desktop configuration file is located at:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### Step 2: Configure the MCP Server

Edit `claude_desktop_config.json` to add the FortiAnalyzer MCP server.

**Option A: Using the script entry point (Recommended)**

```json
{
  "mcpServers": {
    "fortianalyzer": {
      "command": "/Users/rstierli/myCoding/API/fortianalyzer-mcp/.venv/bin/fortianalyzer-mcp",
      "env": {
        "FORTIANALYZER_HOST": "faz-prod-02.home.mystier.li",
        "FORTIANALYZER_API_TOKEN": "your-api-token-here",
        "FORTIANALYZER_VERIFY_SSL": "false",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Option B: Using Python module**

```json
{
  "mcpServers": {
    "fortianalyzer": {
      "command": "/Users/rstierli/myCoding/API/fortianalyzer-mcp/.venv/bin/python",
      "args": [
        "-m",
        "fortianalyzer_mcp"
      ],
      "env": {
        "FORTIANALYZER_HOST": "faz-prod-02.home.mystier.li",
        "FORTIANALYZER_API_TOKEN": "your-api-token-here",
        "FORTIANALYZER_VERIFY_SSL": "false",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Important Notes:**
- Use the **full path** to the command in your virtual environment
- Replace credentials with your actual FortiAnalyzer details
- Set `FORTIANALYZER_VERIFY_SSL` to `false` if using self-signed certificates

### Step 3: Restart Claude Desktop

After saving the configuration:
1. Completely quit Claude Desktop (Cmd+Q on macOS)
2. Reopen Claude Desktop
3. The FortiAnalyzer MCP server should now be available

---

## Testing the Connection

### Test from Command Line First

Before configuring Claude Desktop, test the server manually:

```bash
cd /Users/rstierli/myCoding/API/fortianalyzer-mcp
source .venv/bin/activate

# Set environment variables
export FORTIANALYZER_HOST="faz-prod-02.home.mystier.li"
export FORTIANALYZER_API_TOKEN="your-api-token"
export FORTIANALYZER_VERIFY_SSL="false"

# Run the server using the script entry point
fortianalyzer-mcp

# Or using Python module
python -m fortianalyzer_mcp
```

The server will start in stdio mode and wait for an MCP client connection. You'll see output like:
```
INFO - Loading in FULL mode - all tools
INFO - Starting MCP server in stdio mode
INFO - Initializing FortiAnalyzer connection
INFO - FortiAnalyzer connection established
```

Press Ctrl+C to stop the server.

### Verify in Claude Desktop

Once configured, ask Claude:

> "What FortiAnalyzer tools are available?"

or

> "Get the system status of the FortiAnalyzer"

Claude should respond using the MCP tools.

---

## Available Tools

The MCP server provides **64 tools** across 8 categories:

### System Tools (9)
- `get_system_status` - Get FortiAnalyzer system status
- `get_ha_status` - Get HA cluster status
- `list_adoms` / `get_adom` - ADOM management
- `list_devices` / `get_device` - Device listing
- `list_tasks` / `get_task` / `wait_for_task` - Task management

### Log Tools (11)
- `query_logs` - Full log search with TID workflow
- `search_traffic_logs` - Search firewall traffic logs
- `search_security_logs` - Search IPS/attack logs
- `search_event_logs` - Search system event logs
- `get_log_fields` - Get available log fields
- `get_log_stats` - Get log statistics
- `fetch_more_logs` - Pagination for log results
- `cancel_log_search` - Cancel running search

### FortiView Tools (10)
- `get_top_sources` - Top traffic sources
- `get_top_destinations` - Top traffic destinations
- `get_top_applications` - Top applications by bandwidth
- `get_top_threats` - Top security threats
- `get_top_websites` - Most accessed websites
- `get_top_cloud_applications` - Top cloud/SaaS apps
- `get_policy_hits` - Policy hit statistics
- `run_fortiview` / `fetch_fortiview` - Raw FortiView queries

### Event Tools (8)
- `get_alerts` - Get alert events
- `get_alert_count` - Count alerts
- `acknowledge_alerts` / `unacknowledge_alerts` - Manage alerts
- `get_alert_logs` - Get logs for alerts
- `add_alert_comment` - Add comments to alerts
- `get_alert_incident_stats` - Alert statistics

### Report Tools (6)
- `list_report_templates` - Available report templates
- `run_report` - Generate a report
- `get_report_history` - Past report runs
- `get_report_data` - Download report data

### Incident Tools (6)
- `get_incidents` - List security incidents
- `create_incident` / `update_incident` - Manage incidents
- `get_incident_count` / `get_incident_stats` - Statistics

### IOC Tools (6)
- `get_ioc_license_state` - IOC license status
- `run_ioc_rescan` - Trigger IOC rescan
- `get_ioc_rescan_history` - Past rescans
- `acknowledge_ioc_events` - Acknowledge IOC alerts

### DVM Tools (8)
- `add_device` / `delete_device` - Device management
- `add_devices_bulk` / `delete_devices_bulk` - Bulk operations
- `get_device_info` - Detailed device info
- `search_devices` - Search devices with filters
- `list_device_groups` / `list_device_vdoms` - Groups and VDOMs

---

## Example Conversations

### Security Analysis

> **You:** Show me the top 10 security threats from the last 24 hours

Claude will use `get_top_threats` and provide a summary.

### Log Search

> **You:** Search for traffic from IP 192.168.1.100 in the last hour

Claude will use `search_traffic_logs` with the srcip filter.

### System Health

> **You:** What's the current status of the FortiAnalyzer? Is HA working?

Claude will use `get_system_status` and `get_ha_status`.

### Incident Investigation

> **You:** Show me all high-severity incidents from the past week

Claude will use `get_incidents` with severity filter.

### Report Generation

> **You:** List available report templates and run a security summary report

Claude will use `list_report_templates` and `run_report`.

---

## Troubleshooting

### Server Won't Start

1. **Check Python path**: Ensure you're using the virtual environment Python
   ```bash
   which python  # Should show .venv/bin/python
   ```

2. **Verify environment variables**:
   ```bash
   echo $FORTIANALYZER_HOST
   echo $FORTIANALYZER_API_TOKEN
   ```

3. **Test FortiAnalyzer connectivity**:
   ```bash
   curl -k https://your-faz-host/jsonrpc
   ```

### Authentication Errors

- **API Token**: Ensure the token has JSON API access enabled
- **SSL Errors**: Set `FORTIANALYZER_VERIFY_SSL=false` for self-signed certs
- **Session Auth**: If using username/password, ensure the user has API permissions

### Claude Desktop Not Seeing Tools

1. **Check config file syntax**: Validate JSON in `claude_desktop_config.json`
2. **Restart Claude Desktop**: Completely quit and reopen
3. **Check logs**: Look for errors in Claude Desktop's developer console

### Connection Timeouts

- Increase `FORTIANALYZER_TIMEOUT` to 60 or higher
- Check network connectivity to FortiAnalyzer
- Verify firewall rules allow HTTPS (443) access

### Log Search Returns No Results

- Verify the time range includes data
- Check that devices are logging to FortiAnalyzer
- Use `get_log_stats` to verify log availability

---

## Running Tests

To verify your setup works correctly:

```bash
cd /Users/rstierli/myCoding/API/fortianalyzer-mcp
source .venv/bin/activate

# Copy and configure test credentials
cp tests/.env.test.example tests/.env.test
# Edit tests/.env.test with your API tokens

# Load test credentials
source tests/.env.test

# Run all MCP tools tests (23 tests)
python tests/test_mcp_tools.py

# Run specific category
python tests/test_mcp_tools.py --category log
python tests/test_mcp_tools.py --category fortiview

# Run on different FortiAnalyzer environment
python tests/test_mcp_tools.py --env prod-ai  # FAZ 8.0.0

# List available test categories
python tests/test_mcp_tools.py --list
```

---

## Security Considerations

1. **API Tokens**: Store tokens securely, never commit to git
2. **SSL Verification**: Enable in production (`FORTIANALYZER_VERIFY_SSL=true`)
3. **Least Privilege**: Create a dedicated API user with minimal required permissions
4. **Network Security**: Restrict access to FortiAnalyzer API port

---

## Support

For issues or questions:
- Check the [SESSION_PROGRESS.md](../SESSION_PROGRESS.md) for development notes
- Review test files for usage examples
- FNDN documentation: `/Users/rstierli/myCoding/API/FortiAnalyzer/FNDN/7.6.4/`
