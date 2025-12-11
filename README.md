# FortiAnalyzer MCP Server

A Model Context Protocol (MCP) server for FortiAnalyzer JSON-RPC API. This server enables AI assistants like Claude to interact with FortiAnalyzer for log analysis, reporting, security monitoring, and SOC operations.

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
git clone https://github.com/yourusername/fortianalyzer-mcp.git
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
git clone https://github.com/yourusername/fortianalyzer-mcp.git
cd fortianalyzer-mcp

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install package
pip install -e .
```

### Using Docker

```bash
# Build and run with Docker Compose
docker-compose up -d
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

# SSL Verification (set to false for self-signed certificates)
FORTIANALYZER_VERIFY_SSL=false

# Request Settings
FORTIANALYZER_TIMEOUT=30
FORTIANALYZER_MAX_RETRIES=3

# Logging
LOG_LEVEL=INFO  # DEBUG for troubleshooting
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
        "FORTIANALYZER_VERIFY_SSL": "false",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Note**: Use the full path to the `fortianalyzer-mcp` executable in your virtual environment.

### Docker Mode

```bash
# Start the server
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the server
docker-compose down
```

## Available Tools

### System Tools (9 tools)

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
| `query_logs` | Query logs with custom filters |
| `get_log_search_progress` | Check log search progress |
| `fetch_more_logs` | Fetch additional log results |
| `cancel_log_search` | Cancel a running log search |
| `get_log_stats` | Get log statistics |
| `get_log_fields` | Get available log fields for a log type |
| `search_traffic_logs` | Search traffic/firewall logs |
| `search_security_logs` | Search IPS/AV/web filter logs |
| `search_event_logs` | Search system event logs |
| `get_logfiles_state` | Get log file state information |
| `get_pcap_file` | Download PCAP file for an IPS event |

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
│   │   └── system_tools.py    # System and ADOM tools
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
- Set `FORTIANALYZER_VERIFY_SSL=false` for self-signed certificates
- For production, use valid SSL certificates

**Report Generation Issues**
- Ensure the report layout exists (use `list_report_layouts`)
- Verify the ADOM has the required data for the report
- Check FortiAnalyzer has sufficient disk space

### Viewing Logs

**Claude Desktop MCP Server Logs**:
- macOS: `~/Library/Logs/Claude/mcp-server-fortianalyzer.log`
- Windows: `%APPDATA%\Claude\logs\mcp-server-fortianalyzer.log`

## Development

### Running Tests

```bash
# Install dev dependencies
uv sync --all-extras

# Run tests
pytest

# Run with coverage
pytest --cov=src/fortianalyzer_mcp --cov-report=html
```

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

- **API Tokens**: Store tokens securely, never commit to version control
- **SSL Verification**: Enable SSL verification in production environments
- **Least Privilege**: Use FortiAnalyzer accounts with minimal required permissions
- **Network Security**: Restrict access to FortiAnalyzer management interface

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Acknowledgments

- [jmpijll/fortimanager-mcp](https://github.com/jmpijll/fortimanager-mcp) - Architectural inspiration and reference implementation for FortiManager MCP server
- [Anthropic](https://anthropic.com) for the Model Context Protocol
- [Fortinet](https://fortinet.com) for FortiAnalyzer
- [pyfmg](https://github.com/ftntcorecse/pyfmg) library for FortiManager/FortiAnalyzer API

## Related Projects

- [fortimanager-mcp](https://github.com/jmpijll/fortimanager-mcp) - MCP server for FortiManager with 590+ tools
