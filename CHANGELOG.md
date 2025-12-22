# Changelog

All notable changes to FortiAnalyzer MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0-beta] - 2025-12-22

### Added
- **FortiAnalyzer 7.6.5 Support**
- **API Rate Limiting Tools** (2 tools) - Configure API rate limits to protect FortiAnalyzer from API abuse
  - `get_api_ratelimit`: Get current API rate limiting configuration (read/write limits per second)
  - `update_api_ratelimit`: Update API rate limits (requires FAZ 7.6.5+)

### Changed
- Total tools increased from 72 to 74 (2 new API rate limiting tools)
- Updated API specifications to FortiAnalyzer 7.6.5

### Developer Tools
- Added `tools/compare_api_versions.py` - Compare FortiAnalyzer API documentation between versions
  - Detects new/removed endpoints, definitions, and tags
  - Generates markdown reports for easy review
  - Helps contributors identify required code changes

### FortiAnalyzer 7.6.5 API Changes (Not Yet Implemented)
The following new 7.6.5 features are available in the FortiAnalyzer API but not yet exposed as MCP tools.
Contributions welcome:

- **TACACS+ Accounting** (6 endpoints) - Configure TACACS+ accounting log filtering
  - `/cli/global/system/locallog/tacacs+accounting/filter`
  - `/cli/global/system/locallog/tacacs+accounting/setting`

- **Client Certificate Authentication** (11 endpoints) - Configure client certificate auth for API access
  - `/cli/global/system/log/settings/client-cert-auth`
  - `/cli/global/system/log/settings/client-cert-auth/trusted-client`

## [0.2.0-beta] - 2025-12-11

### Added
- **PCAP Tools** (5 tools) - IPS log search and PCAP download for forensic analysis
  - `search_ips_logs`: Search IPS/attack logs with advanced filtering (severity, attack name, CVE, IPs, action)
  - `get_pcap_by_session`: Download PCAP file for a specific session ID
  - `download_pcap_by_url`: Download PCAP using pcapurl from search results
  - `search_and_download_pcaps`: Search and automatically download all matching PCAPs
  - `list_available_pcaps`: List IPS events that have PCAP files available

### Security Improvements
- Log sanitization for debug output - sensitive fields (passwords, tokens, sessions) now masked
- Input validation for ADOM and device names
- Report output directory restriction with `FAZ_ALLOWED_OUTPUT_DIRS` environment variable
- ZIP extraction size limits (100MB per file, 500MB total) to prevent ZIP bomb attacks

### Changed
- Total tools increased from 67 to 72 (5 new PCAP tools)

## [0.1.0-beta] - 2025-12-04

### Added
- Initial release with 67 MCP tools
- **System Tools** (9 tools)
  - `get_system_status`, `get_ha_status`
  - `list_adoms`, `get_adom`
  - `list_devices`, `get_device`
  - `list_tasks`, `get_task`, `wait_for_task`
- **Device Management Tools** (8 tools)
  - `list_device_groups`, `list_device_vdoms`
  - `add_device`, `delete_device`
  - `add_devices_bulk`, `delete_devices_bulk`
  - `get_device_info`, `search_devices`
- **Log Tools** (12 tools)
  - `query_logs`, `get_log_search_progress`, `fetch_more_logs`, `cancel_log_search`
  - `get_log_stats`, `get_log_fields`
  - `search_traffic_logs`, `search_security_logs`, `search_event_logs`
  - `get_logfiles_state`, `get_pcap_file`
- **Report Tools** (8 tools)
  - `list_report_layouts`, `run_report`, `fetch_report`
  - `get_report_data`, `get_running_reports`, `get_report_history`
  - `run_and_wait_report`, `save_report`
- **FortiView Analytics Tools** (10 tools)
  - `run_fortiview`, `fetch_fortiview`, `get_fortiview_data`
  - `get_top_sources`, `get_top_destinations`, `get_top_applications`
  - `get_top_threats`, `get_top_websites`, `get_top_cloud_applications`
  - `get_policy_hits`
- **Event/Alert Tools** (8 tools)
  - `get_alerts`, `get_alert_count`
  - `acknowledge_alerts`, `unacknowledge_alerts`
  - `get_alert_logs`, `get_alert_details`, `add_alert_comment`
  - `get_alert_incident_stats`
- **Incident Management Tools** (6 tools)
  - `get_incidents`, `get_incident`, `get_incident_count`
  - `create_incident`, `update_incident`, `get_incident_stats`
- **IOC Tools** (6 tools)
  - `get_ioc_license_state`, `acknowledge_ioc_events`
  - `run_ioc_rescan`, `get_ioc_rescan_status`, `get_ioc_rescan_history`
  - `run_and_wait_ioc_rescan`

### Features
- Support for FortiAnalyzer 7.0.x, 7.2.x, 7.4.x, 7.6.x
- API Token authentication (recommended) and username/password support
- Full mode (all tools loaded) and Dynamic mode (discovery tools only)
- Docker deployment support
- Claude Desktop integration via stdio transport
- Comprehensive debug logging (configurable)
- Report generation with automatic schedule creation
- Report download with ZIP extraction (PDF, HTML, CSV, XML formats)

### Technical
- Built on FastMCP framework
- Uses pyfmg library for FortiAnalyzer JSON-RPC communication
- Async/await throughout for efficient resource utilization
- Type hints with Pydantic validation
- Comprehensive error handling with FortiAnalyzer-specific error codes

### Fixed
- Report API now correctly uses `schedule` parameter (string layout-id)
- Empty API responses handled gracefully (no more "Unexpected response format" errors)
- Report polling logic handles empty running reports list

## [0.0.1] - 2025-12-03

### Added
- Initial project structure
- Basic API client implementation
- Core tool modules
