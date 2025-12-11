"""MCP Tools for FortiAnalyzer operations.

Based on FNDN FortiAnalyzer 7.6.4 API specifications.

Tool modules:
- system_tools: System status, ADOM management, device listing, task management
- log_tools: Log search and analysis (LogView API with TID-based workflow)
- dvm_tools: Device management (add/delete devices, device groups)
- event_tools: Alert management and SOC operations
- fortiview_tools: FortiView analytics (TID-based workflow)
- report_tools: Report generation and management (TID-based workflow)
- incident_tools: Incident management and tracking
- ioc_tools: IOC (Indicators of Compromise) operations
- pcap_tools: IPS log search and PCAP file download for forensics
"""

# Import all tool modules to register with MCP
from . import (
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

__all__ = [
    "system_tools",
    "log_tools",
    "dvm_tools",
    "event_tools",
    "fortiview_tools",
    "report_tools",
    "incident_tools",
    "ioc_tools",
    "pcap_tools",
]
